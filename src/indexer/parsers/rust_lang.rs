use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;

use super::{count_lines, hash_source, LanguageParser};
use crate::indexer::store::{normalize_api_path, IndexStore};
use crate::indexer::types::{
    ApiEndpoint, DbWriteOp, DbWriteRef, EnvRef, FileInfo, Framework, HardcodedCredential,
    HttpMethod, ImportEdge, Language,
};

pub struct RustParser;

impl LanguageParser for RustParser {
    fn extensions(&self) -> &[&str] {
        &["rs"]
    }

    fn parse_file(&self, path: &Path, source: &[u8], store: &IndexStore) -> Result<()> {
        let file_info = FileInfo {
            path: path.to_path_buf(),
            language: Language::Rust,
            lines: count_lines(source),
            hash: hash_source(source),
        };
        store.files.insert(path.to_path_buf(), file_info);

        let source_str = match std::str::from_utf8(source) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };

        scan_api_routes(path, source_str, store);
        scan_env_refs(path, source_str, store);
        scan_imports(path, source_str, store);
        scan_db_writes(path, source_str, store);
        scan_hardcoded_creds(path, source_str, store);

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// API route extraction
// ---------------------------------------------------------------------------

/// Actix/Rocket attribute macros: #[get("/path")], #[post("/path")], etc.
fn attr_route_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"#\[\s*(get|post|put|patch|delete)\s*\(\s*"([^"]+)"\s*"#).unwrap()
    })
}

/// Axum-style: .route("/path", get(handler)), .route("/path", post(handler))
fn axum_route_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\.route\(\s*"([^"]+)"\s*,\s*(get|post|put|patch|delete)\s*\("#).unwrap()
    })
}

/// Actix web::resource("/path").route(web::get().to(handler))
fn actix_resource_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"web::resource\(\s*"([^"]+)"\s*\).*?web::(get|post|put|patch|delete)\s*\("#)
            .unwrap()
    })
}

fn parse_method(name: &str) -> Option<HttpMethod> {
    match name.to_lowercase().as_str() {
        "get" => Some(HttpMethod::Get),
        "post" => Some(HttpMethod::Post),
        "put" => Some(HttpMethod::Put),
        "patch" => Some(HttpMethod::Patch),
        "delete" => Some(HttpMethod::Delete),
        _ => None,
    }
}

/// Detect framework from context clues in the source line.
fn detect_framework(line: &str) -> Framework {
    if line.contains("web::resource") || line.contains("web::get") || line.contains("web::post") {
        Framework::Actix
    } else if line.contains(".route(") && line.contains("get(")
        || line.contains(".route(") && line.contains("post(")
    {
        Framework::Axum
    } else {
        // Attribute macros could be Actix or Rocket; check for nearby hints
        Framework::Unknown
    }
}

fn scan_api_routes(path: &Path, source: &str, store: &IndexStore) {
    let attr_re = attr_route_re();
    let axum_re = axum_route_re();
    let resource_re = actix_resource_re();

    for (line_num, line_text) in source.lines().enumerate() {
        // Attribute-style routes: #[get("/...")]
        for cap in attr_re.captures_iter(line_text) {
            if let (Some(method_match), Some(path_match)) = (cap.get(1), cap.get(2)) {
                if let Some(method) = parse_method(method_match.as_str()) {
                    let route_path = path_match.as_str().to_string();
                    let framework = if line_text.contains("rocket") {
                        Framework::Rocket
                    } else {
                        detect_framework(line_text)
                    };
                    let normalized = normalize_api_path(&route_path);

                    let endpoint = ApiEndpoint {
                        method,
                        path: route_path,
                        file: path.to_path_buf(),
                        line: line_num + 1,
                        framework,
                    };

                    store
                        .api_endpoints
                        .entry(normalized)
                        .or_default()
                        .push(endpoint);
                }
            }
        }

        // Axum-style: .route("/path", get(handler))
        for cap in axum_re.captures_iter(line_text) {
            if let (Some(path_match), Some(method_match)) = (cap.get(1), cap.get(2)) {
                if let Some(method) = parse_method(method_match.as_str()) {
                    let route_path = path_match.as_str().to_string();
                    let normalized = normalize_api_path(&route_path);

                    let endpoint = ApiEndpoint {
                        method,
                        path: route_path,
                        file: path.to_path_buf(),
                        line: line_num + 1,
                        framework: Framework::Axum,
                    };

                    store
                        .api_endpoints
                        .entry(normalized)
                        .or_default()
                        .push(endpoint);
                }
            }
        }

        // Actix web::resource("/path").route(web::get().to(handler))
        for cap in resource_re.captures_iter(line_text) {
            if let (Some(path_match), Some(method_match)) = (cap.get(1), cap.get(2)) {
                if let Some(method) = parse_method(method_match.as_str()) {
                    let route_path = path_match.as_str().to_string();
                    let normalized = normalize_api_path(&route_path);

                    let endpoint = ApiEndpoint {
                        method,
                        path: route_path,
                        file: path.to_path_buf(),
                        line: line_num + 1,
                        framework: Framework::Actix,
                    };

                    store
                        .api_endpoints
                        .entry(normalized)
                        .or_default()
                        .push(endpoint);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Environment variable extraction
// ---------------------------------------------------------------------------

/// std::env::var("VAR") or env::var("VAR")
fn env_var_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?:std::)?env::var(?:_os)?\(\s*"([^"]+)"\s*\)"#).unwrap())
}

/// env!("VAR") compile-time macro
fn env_macro_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"env!\(\s*"([^"]+)"\s*\)"#).unwrap())
}

/// option_env!("VAR")
fn option_env_macro_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"option_env!\(\s*"([^"]+)"\s*\)"#).unwrap())
}

/// dotenvy::var("VAR")
fn dotenvy_var_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"dotenvy::var\(\s*"([^"]+)"\s*\)"#).unwrap())
}

fn scan_env_refs(path: &Path, source: &str, store: &IndexStore) {
    let env_re = env_var_re();
    let env_macro = env_macro_re();
    let option_env = option_env_macro_re();
    let dotenvy = dotenvy_var_re();

    for (line_num, line_text) in source.lines().enumerate() {
        for cap in env_re.captures_iter(line_text) {
            if let Some(var) = cap.get(1) {
                let has_default = line_text.contains(".unwrap_or");
                let env_ref = EnvRef {
                    var_name: var.as_str().to_string(),
                    file: path.to_path_buf(),
                    line: line_num + 1,
                    has_default,
                    default_value: None,
                };
                store
                    .env_refs
                    .entry(var.as_str().to_string())
                    .or_default()
                    .push(env_ref);
            }
        }

        for cap in env_macro.captures_iter(line_text) {
            if let Some(var) = cap.get(1) {
                let env_ref = EnvRef {
                    var_name: var.as_str().to_string(),
                    file: path.to_path_buf(),
                    line: line_num + 1,
                    has_default: false,
                    default_value: None,
                };
                store
                    .env_refs
                    .entry(var.as_str().to_string())
                    .or_default()
                    .push(env_ref);
            }
        }

        for cap in option_env.captures_iter(line_text) {
            if let Some(var) = cap.get(1) {
                let env_ref = EnvRef {
                    var_name: var.as_str().to_string(),
                    file: path.to_path_buf(),
                    line: line_num + 1,
                    has_default: true,
                    default_value: None,
                };
                store
                    .env_refs
                    .entry(var.as_str().to_string())
                    .or_default()
                    .push(env_ref);
            }
        }

        for cap in dotenvy.captures_iter(line_text) {
            if let Some(var) = cap.get(1) {
                let env_ref = EnvRef {
                    var_name: var.as_str().to_string(),
                    file: path.to_path_buf(),
                    line: line_num + 1,
                    has_default: false,
                    default_value: None,
                };
                store
                    .env_refs
                    .entry(var.as_str().to_string())
                    .or_default()
                    .push(env_ref);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Import extraction
// ---------------------------------------------------------------------------

/// use crate::module or use super::module
fn use_import_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^\s*use\s+((?:crate|super|self)::[\w:]+)"#).unwrap())
}

/// mod module_name;
fn mod_decl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^\s*(?:pub\s+)?mod\s+(\w+)\s*;"#).unwrap())
}

/// External crate imports: use some_crate::path
fn external_use_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^\s*use\s+(\w[\w:]*)"#).unwrap())
}

fn scan_imports(path: &Path, source: &str, store: &IndexStore) {
    let use_re = use_import_re();
    let mod_re = mod_decl_re();
    let ext_re = external_use_re();

    for line_text in source.lines() {
        // Internal use statements (crate/super/self)
        if let Some(cap) = use_re.captures(line_text) {
            if let Some(module) = cap.get(1) {
                let edge = ImportEdge {
                    source_file: path.to_path_buf(),
                    target_module: module.as_str().to_string(),
                    symbols: Vec::new(),
                    is_type_only: false,
                };
                store
                    .imports
                    .entry(path.to_path_buf())
                    .or_default()
                    .push(edge);
            }
        }
        // mod declarations
        else if let Some(cap) = mod_re.captures(line_text) {
            if let Some(module) = cap.get(1) {
                let edge = ImportEdge {
                    source_file: path.to_path_buf(),
                    target_module: module.as_str().to_string(),
                    symbols: Vec::new(),
                    is_type_only: false,
                };
                store
                    .imports
                    .entry(path.to_path_buf())
                    .or_default()
                    .push(edge);
            }
        }
        // External crate use (skip std/core/alloc as noise)
        else if let Some(cap) = ext_re.captures(line_text) {
            if let Some(module) = cap.get(1) {
                let mod_str = module.as_str();
                if !mod_str.starts_with("std")
                    && !mod_str.starts_with("core")
                    && !mod_str.starts_with("alloc")
                {
                    let edge = ImportEdge {
                        source_file: path.to_path_buf(),
                        target_module: mod_str.to_string(),
                        symbols: Vec::new(),
                        is_type_only: false,
                    };
                    store
                        .imports
                        .entry(path.to_path_buf())
                        .or_default()
                        .push(edge);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DB write detection
// ---------------------------------------------------------------------------

/// SQL write patterns in strings: INSERT INTO, UPDATE, DELETE FROM
fn db_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[`"']?(\w+)[`"']?"#).unwrap()
    })
}

/// diesel::insert_into(table)
fn diesel_insert_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"diesel::insert_into\(\s*(\w+)"#).unwrap())
}

fn scan_db_writes(path: &Path, source: &str, store: &IndexStore) {
    let sql_re = db_write_re();
    let diesel_re = diesel_insert_re();

    for (line_num, line_text) in source.lines().enumerate() {
        for cap in sql_re.captures_iter(line_text) {
            if let (Some(op_match), Some(table_match)) = (cap.get(1), cap.get(2)) {
                let op_str = op_match.as_str().to_uppercase();
                let operation = if op_str.starts_with("INSERT") {
                    DbWriteOp::Insert
                } else if op_str.starts_with("UPDATE") {
                    DbWriteOp::Update
                } else {
                    DbWriteOp::Delete
                };

                let table_name = table_match.as_str().to_string();
                let entry = DbWriteRef {
                    table_name: table_name.clone(),
                    operation,
                    file: path.to_path_buf(),
                    line: line_num + 1,
                };
                store
                    .db_write_refs
                    .entry(table_name)
                    .or_default()
                    .push(entry);
            }
        }

        for cap in diesel_re.captures_iter(line_text) {
            if let Some(table_match) = cap.get(1) {
                let table_name = table_match.as_str().to_string();
                let entry = DbWriteRef {
                    table_name: table_name.clone(),
                    operation: DbWriteOp::Insert,
                    file: path.to_path_buf(),
                    line: line_num + 1,
                };
                store
                    .db_write_refs
                    .entry(table_name)
                    .or_default()
                    .push(entry);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Hardcoded credential detection
// ---------------------------------------------------------------------------

fn hardcoded_cred_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(password|secret|api_key|access_key|token)\s*[:=]\s*["']([^"']{4,})["']"#)
            .unwrap()
    })
}

fn scan_hardcoded_creds(path: &Path, source: &str, store: &IndexStore) {
    let re = hardcoded_cred_re();

    for (line_num, line_text) in source.lines().enumerate() {
        // Skip lines referencing env vars
        if line_text.contains("env::var")
            || line_text.contains("env!(")
            || line_text.contains("option_env!(")
            || line_text.contains("dotenvy")
        {
            continue;
        }

        for cap in re.captures_iter(line_text) {
            if let (Some(key), Some(val)) = (cap.get(1), cap.get(2)) {
                let val_str = val.as_str();
                if val_str.is_empty() {
                    continue;
                }
                let hint = if val_str.len() > 4 {
                    format!("{}***", &val_str[..4])
                } else {
                    format!("{val_str}***")
                };

                let entry = HardcodedCredential {
                    key_name: key.as_str().to_string(),
                    value_hint: hint,
                    file: path.to_path_buf(),
                    line: line_num + 1,
                };
                store
                    .hardcoded_creds
                    .entry(path.to_path_buf())
                    .or_default()
                    .push(entry);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/rust")
            .join(name)
    }

    fn parse_fixture(name: &str) -> Arc<IndexStore> {
        let path = fixture_path(name);
        let source = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
        let store = IndexStore::new();
        RustParser.parse_file(&path, &source, &store).unwrap();
        store
    }

    #[test]
    fn detects_actix_routes() {
        let store = parse_fixture("routes.rs");
        let endpoints = store.all_api_endpoints();
        let actix_gets: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Get && e.path.contains("/users"))
            .collect();
        assert!(!actix_gets.is_empty(), "Should find Actix GET /users route");

        let posts: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Post)
            .collect();
        assert!(!posts.is_empty(), "Should find POST routes");
    }

    #[test]
    fn detects_axum_routes() {
        let store = parse_fixture("routes.rs");
        let endpoints = store.all_api_endpoints();
        let axum: Vec<_> = endpoints
            .iter()
            .filter(|e| e.framework == Framework::Axum)
            .collect();
        assert!(!axum.is_empty(), "Should find Axum routes");
    }

    #[test]
    fn parses_env_refs() {
        let store = parse_fixture("routes.rs");
        assert!(
            store.env_refs.contains_key("DATABASE_URL"),
            "Should find DATABASE_URL env ref"
        );
        assert!(
            store.env_refs.contains_key("RUST_LOG"),
            "Should find RUST_LOG env ref"
        );
        assert!(
            store.env_refs.contains_key("CARGO_MANIFEST_DIR"),
            "Should find CARGO_MANIFEST_DIR compile-time env ref"
        );
    }

    #[test]
    fn detects_rust_hardcoded_creds() {
        let store = parse_fixture("routes.rs");
        let creds = store.all_hardcoded_creds();
        assert!(!creds.is_empty(), "Should detect hardcoded credentials");
        assert!(
            creds
                .iter()
                .any(|c| c.key_name.to_lowercase() == "password"),
            "Should find hardcoded password"
        );
    }
}
