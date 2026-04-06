use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;

use super::{
    count_lines, create_parser, find_capture, hash_source, parse_source, run_query,
    LanguageParser,
};
use crate::indexer::store::{normalize_api_path, IndexStore};
use crate::indexer::types::{
    ApiCall, ApiEndpoint, DbPoolRef, DbWriteOp, DbWriteRef, ErrorHandlingRef, ErrorHandlingType,
    FileInfo, Framework, FunctionSignature, HardcodedCredential, HttpMethod, ImportEdge, Language,
    MiddlewareScope, RedisKeyRef, RedisOp, RlsContextRef, RoleCheckRef, RoleCheckType,
    SecondaryAuthRef, SecondaryAuthType, SessionInvalidationRef, SessionInvalidationType,
    EnvRef, SqlQueryOp, SqlQueryRef, StubIndicator, StubType,
};

const ROUTES_QUERY: &str = include_str!("../queries/typescript/routes.scm");
const IMPORTS_QUERY: &str = include_str!("../queries/typescript/imports.scm");
const API_CALLS_QUERY: &str = include_str!("../queries/typescript/api_calls.scm");
const ENV_REFS_QUERY: &str = include_str!("../queries/typescript/env_refs.scm");
const MIDDLEWARE_QUERY: &str = include_str!("../queries/typescript/middleware.scm");

pub struct TypeScriptParser;

impl LanguageParser for TypeScriptParser {
    fn extensions(&self) -> &[&str] {
        &["ts", "tsx"]
    }

    fn parse_file(&self, path: &Path, source: &[u8], store: &IndexStore) -> Result<()> {
        let file_info = FileInfo {
            path: path.to_path_buf(),
            language: Language::TypeScript,
            lines: count_lines(source),
            hash: hash_source(source),
        };
        store.files.insert(path.to_path_buf(), file_info);

        let is_tsx = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "tsx")
            .unwrap_or(false);

        let ts_language: tree_sitter::Language = if is_tsx {
            tree_sitter_typescript::LANGUAGE_TSX.into()
        } else {
            tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
        };

        let mut parser = create_parser(&ts_language)?;
        let tree = parse_source(&mut parser, source)?;

        parse_routes(path, source, &tree, &ts_language, store);
        parse_imports(path, source, &tree, &ts_language, store);
        parse_api_calls(path, source, &tree, &ts_language, store);
        parse_env_refs(path, source, &tree, &ts_language, store);
        parse_middleware(path, source, &tree, &ts_language, store);
        scan_stub_indicators(path, source, store);
        scan_db_writes_ts(path, source, store);
        scan_redis_patterns_ts(path, source, store);
        scan_hardcoded_creds_ts(path, source, store);
        scan_sql_query_refs_ts(path, source, store);
        scan_rls_context_ts(path, source, store);
        scan_db_pool_refs_ts(path, source, store);
        scan_secondary_auth_ts(path, source, store);
        scan_error_handling_ts(path, source, store);
        scan_role_checks_ts(path, source, store);
        scan_function_signatures_ts(path, source, &tree, &ts_language, store);
        scan_session_invalidation_ts(path, source, store);

        Ok(())
    }
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

fn detect_framework(captures: &[(String, String, usize)]) -> Framework {
    if find_capture(captures, "decorator_name").is_some() {
        return Framework::NestJS;
    }
    if find_capture(captures, "router_var").is_some() {
        return Framework::Express;
    }
    Framework::Unknown
}

fn parse_routes(
    path: &Path,
    source: &[u8],
    tree: &tree_sitter::Tree,
    language: &tree_sitter::Language,
    store: &IndexStore,
) {
    // First pass: collect controller paths keyed by line number.
    // Each @Controller decorator line maps to its prefix so that method
    // decorators appearing after it (within the same class) can look up
    // the nearest preceding controller prefix.
    let mut controller_lines: Vec<(usize, String)> = Vec::new();

    run_query(ROUTES_QUERY, language, source, tree, |_m, captures| {
        if let Some((_, ctrl_path, line)) = find_capture(captures, "controller_path") {
            controller_lines.push((*line, ctrl_path.clone()));
        }
    });

    // Sort by line so binary search works correctly
    controller_lines.sort_by_key(|(line, _)| *line);

    // Second pass: resolve method routes, prepending controller prefix
    run_query(ROUTES_QUERY, language, source, tree, |_m, captures| {
        // Skip controller-only matches
        if find_capture(captures, "controller_path").is_some() {
            return;
        }

        let method_cap = find_capture(captures, "decorator_name")
            .or_else(|| find_capture(captures, "method_name"));
        let route_cap = find_capture(captures, "route_path");

        if let (Some((_, method_text, _)), Some((_, route_text, line))) =
            (method_cap, route_cap)
        {
            let method = match parse_method(method_text) {
                Some(m) => m,
                None => return,
            };
            let framework = detect_framework(captures);

            // For NestJS routes, find the nearest controller prefix
            // that appears before this line
            let full_path = if framework == Framework::NestJS {
                find_controller_prefix(&controller_lines, *line, route_text)
            } else {
                route_text.clone()
            };

            let normalized = normalize_api_path(&full_path);

            let endpoint = ApiEndpoint {
                method,
                path: full_path,
                file: path.to_path_buf(),
                line: *line,
                framework,
            };

            store
                .api_endpoints
                .entry(normalized)
                .or_default()
                .push(endpoint);
        }
    });
}

/// Find the nearest @Controller prefix that appears before the given line
/// and prepend it to the route path. Returns a new combined path string.
fn find_controller_prefix(
    controller_lines: &[(usize, String)],
    route_line: usize,
    route_path: &str,
) -> String {
    // Find the last controller line that is before route_line
    let prefix = controller_lines
        .iter()
        .rev()
        .find(|(line, _)| *line < route_line)
        .map(|(_, path)| path.as_str());

    match prefix {
        Some(ctrl) => {
            let ctrl_trimmed = ctrl.trim_end_matches('/');
            let route_trimmed = route_path.trim_start_matches('/');
            if ctrl_trimmed.is_empty() {
                format!("/{route_trimmed}")
            } else if route_trimmed.is_empty() {
                ctrl_trimmed.to_string()
            } else {
                format!("{ctrl_trimmed}/{route_trimmed}")
            }
        }
        None => route_path.to_string(),
    }
}

fn parse_imports(
    path: &Path,
    source: &[u8],
    tree: &tree_sitter::Tree,
    language: &tree_sitter::Language,
    store: &IndexStore,
) {
    run_query(IMPORTS_QUERY, language, source, tree, |_m, captures| {
        let source_cap = find_capture(captures, "source_path")
            .or_else(|| find_capture(captures, "template_source"));
        let (source_path, is_dynamic_template) = match source_cap {
            Some((name, text, _)) => {
                let clean = text.trim_matches('`').to_string();
                (clean, name == "template_source")
            }
            None => return,
        };
        let _ = is_dynamic_template; // available for future use

        let mut symbols = Vec::new();
        let mut is_type_only = false;

        for (name, text, _) in captures {
            match name.as_str() {
                "imported_name" | "default_import" | "namespace_import" => {
                    symbols.push(text.clone());
                }
                _ => {}
            }
        }

        // Detect type-only imports by checking the raw source around the match
        if let Some((_, _, line)) = find_capture(captures, "source_path") {
            let line_text = source_line_at(source, *line);
            if line_text.contains("import type") {
                is_type_only = true;
            }
        }

        let edge = ImportEdge {
            source_file: path.to_path_buf(),
            target_module: source_path,
            symbols,
            is_type_only,
        };

        store
            .imports
            .entry(path.to_path_buf())
            .or_default()
            .push(edge);
    });
}

fn parse_api_calls(
    path: &Path,
    source: &[u8],
    tree: &tree_sitter::Tree,
    language: &tree_sitter::Language,
    store: &IndexStore,
) {
    run_query(API_CALLS_QUERY, language, source, tree, |_m, captures| {
        let url_cap = find_capture(captures, "url")
            .or_else(|| find_capture(captures, "template_url"));

        if let Some((cap_name, url_text, line)) = url_cap {
            let is_template = cap_name == "template_url";
            let clean_url = url_text.trim_matches('`').to_string();

            let method_cap = find_capture(captures, "method");
            let method = method_cap
                .and_then(|(_, text, _)| parse_method(text))
                .unwrap_or(HttpMethod::Get);

            let normalized = normalize_api_path(&clean_url);

            let call = ApiCall {
                method,
                url: clean_url,
                file: path.to_path_buf(),
                line: *line,
                is_template,
            };

            store
                .api_calls
                .entry(normalized)
                .or_default()
                .push(call);
        }
    });
}

fn parse_env_refs(
    path: &Path,
    source: &[u8],
    tree: &tree_sitter::Tree,
    language: &tree_sitter::Language,
    store: &IndexStore,
) {
    run_query(ENV_REFS_QUERY, language, source, tree, |_m, captures| {
        if let Some((_, var_name, line)) = find_capture(captures, "var_name") {
            let line_text = source_line_at(source, *line);
            let has_default = line_text.contains("||") || line_text.contains("??");

            let default_value = if has_default {
                extract_ts_default(&line_text)
            } else {
                None
            };

            let env_ref = EnvRef {
                var_name: var_name.clone(),
                file: path.to_path_buf(),
                line: *line,
                has_default,
                default_value,
            };

            store
                .env_refs
                .entry(var_name.clone())
                .or_default()
                .push(env_ref);
        }
    });
}

fn parse_middleware(
    path: &Path,
    source: &[u8],
    tree: &tree_sitter::Tree,
    language: &tree_sitter::Language,
    store: &IndexStore,
) {
    run_query(MIDDLEWARE_QUERY, language, source, tree, |_m, captures| {
        let router_cap = find_capture(captures, "router_var");
        let mw_cap = find_capture(captures, "middleware_name");

        if let (Some((_, router_var, line)), Some((_, mw_name, _))) = (router_cap, mw_cap) {
            // For member expression calls like passport.authenticate("jwt"),
            // produce a qualified name: "passport.authenticate"
            let qualified_name = match find_capture(captures, "middleware_obj") {
                Some((_, obj_name, _)) => format!("{obj_name}.{mw_name}"),
                None => mw_name.clone(),
            };

            let scope = MiddlewareScope {
                router_var: router_var.clone(),
                middleware_name: qualified_name,
                file: path.to_path_buf(),
                line_start: *line,
                line_end: *line,
            };

            store
                .middleware_scopes
                .entry(path.to_path_buf())
                .or_default()
                .push(scope);
        }
    });
}

fn ts_stub_patterns() -> &'static [(Regex, StubType)] {
    static PATTERNS: OnceLock<Vec<(Regex, StubType)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (Regex::new(r"(?i)\bTODO\b").unwrap(), StubType::Todo),
            (Regex::new(r"(?i)\bFIXME\b").unwrap(), StubType::Fixme),
            (Regex::new(r"(?i)\bHACK\b").unwrap(), StubType::Hack),
            (Regex::new(r"(?i)\bmockData\b").unwrap(), StubType::MockData),
            (Regex::new(r"(?i)\bstubData\b").unwrap(), StubType::StubData),
            (Regex::new(r"(?i)\bplaceholder\b").unwrap(), StubType::Placeholder),
            (Regex::new(r"(?i)\bhardcoded\b").unwrap(), StubType::Hardcoded),
            (Regex::new(r"(?i)\bfakeData\b").unwrap(), StubType::Fake),
            (Regex::new(r"(?i)\bdummyData\b").unwrap(), StubType::Dummy),
        ]
    })
}

fn scan_stub_indicators(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let patterns = ts_stub_patterns();

    for (line_num, line_text) in source_str.lines().enumerate() {
        for (regex, stub_type) in patterns {
            if let Some(mat) = regex.find(line_text) {
                let indicator = StubIndicator {
                    file: path.to_path_buf(),
                    line: line_num + 1,
                    indicator_type: *stub_type,
                    matched_text: mat.as_str().to_string(),
                };

                store
                    .stub_indicators
                    .entry(path.to_path_buf())
                    .or_default()
                    .push(indicator);
            }
        }
    }
}

/// Extract the text of a specific 1-based line number from source bytes.
fn source_line_at(source: &[u8], line: usize) -> String {
    let text = std::str::from_utf8(source).unwrap_or("");
    text.lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("")
        .to_string()
}

fn ts_default_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?:\?\?|\|\|)\s*["']([^"']*)["']"#).unwrap())
}

/// Extract the default value from a TypeScript env access pattern like:
/// `process.env.KEY || "default"` or `process.env.KEY ?? "default"`
fn extract_ts_default(line: &str) -> Option<String> {
    ts_default_re()
        .captures(line)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
}

fn ts_db_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[`"']?(\w+)[`"']?"#).unwrap()
    })
}

fn ts_redis_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"redis\.\s*(set|hset|zadd|lpush|rpush|sadd)\s*\(\s*[`"']([^`"']+)[`"']"#)
            .unwrap()
    })
}

fn ts_redis_read_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"redis\.\s*(get|hget|hgetall|lrange|smembers|zrange)\s*\(\s*[`"']([^`"']+)[`"']"#,
        )
        .unwrap()
    })
}

fn ts_redis_delete_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"redis\.\s*(del|hdel)\s*\(\s*[`"']([^`"']+)[`"']"#).unwrap()
    })
}

fn ts_redis_ttl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)['"](?:EX|PX|EXAT|PXAT)['"]|,\s*\d+\s*\)"#).unwrap()
    })
}

fn ts_hardcoded_cred_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(password|secret|api_key|access_key|token)\s*[:=]\s*["']([^"']{4,})["']"#)
            .unwrap()
    })
}

fn scan_db_writes_ts(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = ts_db_write_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        for cap in re.captures_iter(line_text) {
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
                store.db_write_refs.entry(table_name).or_default().push(entry);
            }
        }
    }
}

fn scan_redis_patterns_ts(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let write_re = ts_redis_write_re();
    let read_re = ts_redis_read_re();
    let delete_re = ts_redis_delete_re();
    let ttl_re = ts_redis_ttl_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        for cap in write_re.captures_iter(line_text) {
            if let Some(key) = cap.get(2) {
                let has_ttl = ttl_re.is_match(line_text);
                let entry = RedisKeyRef {
                    key_pattern: key.as_str().to_string(),
                    operation: RedisOp::Write,
                    has_ttl,
                    file: path.to_path_buf(),
                    line: line_num + 1,
                };
                store
                    .redis_key_refs
                    .entry(key.as_str().to_string())
                    .or_default()
                    .push(entry);
            }
        }

        for cap in read_re.captures_iter(line_text) {
            if let Some(key) = cap.get(2) {
                let entry = RedisKeyRef {
                    key_pattern: key.as_str().to_string(),
                    operation: RedisOp::Read,
                    has_ttl: false,
                    file: path.to_path_buf(),
                    line: line_num + 1,
                };
                store
                    .redis_key_refs
                    .entry(key.as_str().to_string())
                    .or_default()
                    .push(entry);
            }
        }

        for cap in delete_re.captures_iter(line_text) {
            if let Some(key) = cap.get(2) {
                let entry = RedisKeyRef {
                    key_pattern: key.as_str().to_string(),
                    operation: RedisOp::Delete,
                    has_ttl: false,
                    file: path.to_path_buf(),
                    line: line_num + 1,
                };
                store
                    .redis_key_refs
                    .entry(key.as_str().to_string())
                    .or_default()
                    .push(entry);
            }
        }
    }
}

fn scan_hardcoded_creds_ts(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = ts_hardcoded_cred_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        // Skip lines that are env var references
        if line_text.contains("process.env") || line_text.contains("getenv") {
            continue;
        }

        for cap in re.captures_iter(line_text) {
            if let (Some(key), Some(val)) = (cap.get(1), cap.get(2)) {
                let val_str = val.as_str();
                // Skip empty or placeholder values
                if val_str.is_empty() || val_str == "undefined" || val_str == "null" {
                    continue;
                }
                let hint = if val_str.len() > 4 {
                    format!("{}***", &val_str[..4])
                } else {
                    format!("{}***", val_str)
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

fn ts_sql_query_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[\s\S]*?\b(?:FROM\s+)?[`"']?(\w+)[`"']?"#).unwrap()
    })
}

fn ts_tenant_filter_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\bWHERE\b[\s\S]*?\b(user_id|owner_id|tenant_id|project_id|org_id)\b"#).unwrap()
    })
}

fn ts_rls_context_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(?:SET\s+LOCAL\s+(\S+)\s*=|set_config\s*\(\s*['"]([^'"]+)['"]|\$executeRaw[Unsafe]*\s*`[^`]*SET\s+LOCAL\s+(\S+)\s*=)"#,
        )
        .unwrap()
    })
}

fn scan_rls_context_ts(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = ts_rls_context_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        for cap in re.captures_iter(line_text) {
            let var = cap
                .get(1)
                .or_else(|| cap.get(2))
                .or_else(|| cap.get(3));
            if let Some(var_match) = var {
                let entry = RlsContextRef {
                    session_var: var_match.as_str().to_string(),
                    file: path.to_path_buf(),
                    line: line_num + 1,
                };
                store
                    .rls_context_refs
                    .entry(path.to_path_buf())
                    .or_default()
                    .push(entry);
            }
        }
    }
}

fn scan_sql_query_refs_ts(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let query_re = ts_sql_query_re();
    let tenant_re = ts_tenant_filter_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        for cap in query_re.captures_iter(line_text) {
            if let (Some(op_match), Some(table_match)) = (cap.get(1), cap.get(2)) {
                let op_str = op_match.as_str().to_uppercase();
                let operation = if op_str.starts_with("SELECT") {
                    SqlQueryOp::Select
                } else if op_str.starts_with("INSERT") {
                    SqlQueryOp::Insert
                } else if op_str.starts_with("UPDATE") {
                    SqlQueryOp::Update
                } else {
                    SqlQueryOp::Delete
                };

                let table_name = table_match.as_str().to_string();
                let has_tenant_filter = tenant_re.is_match(line_text);

                let entry = SqlQueryRef {
                    table_name: table_name.clone(),
                    operation,
                    has_tenant_filter,
                    file: path.to_path_buf(),
                    line: line_num + 1,
                };
                store.sql_query_refs.entry(table_name).or_default().push(entry);
            }
        }
    }
}

fn ts_db_pool_re() -> &'static [(Regex, &'static str)] {
    static PATTERNS: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (
                Regex::new(r#"new\s+Pool\(\{[^}]*connectionString[^}]*(DATABASE_URL\w*|process\.env\.(\w+))"#).unwrap(),
                "pg_pool",
            ),
            (
                Regex::new(r#"new\s+PrismaClient\("#).unwrap(),
                "prisma",
            ),
            (
                Regex::new(r#"createPool\([^)]*(DATABASE_URL\w*)"#).unwrap(),
                "create_pool",
            ),
        ]
    })
}

fn ts_db_pool_var_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:const|let|var)\s+(\w+)\s*=\s*(?:new\s+Pool|new\s+PrismaClient|createPool)"#).unwrap()
    })
}

fn scan_db_pool_refs_ts(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let patterns = ts_db_pool_re();
    let var_re = ts_db_pool_var_re();

    let mut refs: Vec<DbPoolRef> = Vec::new();

    for (line_num, line_text) in source_str.lines().enumerate() {
        for (regex, pattern_kind) in patterns {
            if !regex.is_match(line_text) {
                continue;
            }

            // Extract pool variable name from assignment
            let pool_name = var_re
                .captures(line_text)
                .and_then(|cap| cap.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "anonymous".to_string());

            // Extract connection env var
            let connection_var = match *pattern_kind {
                "pg_pool" => {
                    let cap = regex.captures(line_text);
                    cap.and_then(|c| {
                        c.get(2)
                            .or_else(|| c.get(1))
                            .map(|m| m.as_str().to_string())
                    })
                }
                "create_pool" => {
                    let cap = regex.captures(line_text);
                    cap.and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
                }
                _ => None,
            };

            let entry = DbPoolRef {
                pool_name,
                role_hint: None,
                connection_var,
                file: path.to_path_buf(),
                line: line_num + 1,
            };
            refs.push(entry);
        }
    }

    if !refs.is_empty() {
        store.db_pool_refs.entry(path.to_path_buf()).or_default().extend(refs);
    }
}

fn ts_secondary_auth_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(verify_?otp|verify_?code|verify_?2fa|confirm_?password|validate_?csrf|check_?totp|verify_?totp)\s*\(").unwrap()
    })
}

fn ts_secondary_auth_param_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(otp|totp|verification_?code|csrf_?token|two_?factor_?code|mfa_?code)\b").unwrap()
    })
}

fn classify_secondary_auth(text: &str) -> SecondaryAuthType {
    let lower = text.to_lowercase();
    if lower.contains("csrf") {
        SecondaryAuthType::CsrfToken
    } else if lower.contains("2fa") || lower.contains("two_factor") || lower.contains("mfa") {
        SecondaryAuthType::TwoFactor
    } else if lower.contains("password") || lower.contains("confirm") {
        SecondaryAuthType::PasswordConfirm
    } else {
        SecondaryAuthType::Otp
    }
}

fn scan_secondary_auth_ts(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let call_re = ts_secondary_auth_call_re();
    let param_re = ts_secondary_auth_param_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        let matched = call_re.find(line_text).or_else(|| param_re.find(line_text));
        if let Some(mat) = matched {
            let auth_type = classify_secondary_auth(mat.as_str());
            let entry = SecondaryAuthRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                auth_type,
                near_endpoint: None,
            };
            store
                .secondary_auth_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

fn ts_empty_catch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"catch\s*\([^)]*\)\s*\{\s*\}").unwrap()
    })
}

fn ts_catch_noop_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\.catch\s*\(\s*\(\s*\)\s*=>\s*(?:\{\s*\}|undefined|null)\s*\)").unwrap()
    })
}

fn scan_error_handling_ts(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let empty_catch_re = ts_empty_catch_re();
    let catch_noop_re = ts_catch_noop_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        if empty_catch_re.is_match(line_text) {
            let entry = ErrorHandlingRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                error_type: ErrorHandlingType::EmptyCatch,
                context: "empty catch block".to_string(),
            };
            store
                .error_handling_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }

        if catch_noop_re.is_match(line_text) {
            let entry = ErrorHandlingRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                error_type: ErrorHandlingType::EmptyCatch,
                context: ".catch(() => {}) noop handler".to_string(),
            };
            store
                .error_handling_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

fn ts_role_single_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\brole\s*[!=]==?\s*["']([^"']+)["']"#).unwrap()
    })
}

fn ts_role_includes_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:\[.*?\]\.includes\s*\(\s*role|roles?\.includes\s*\(\s*["']([^"']+)["'])"#).unwrap()
    })
}

fn is_middleware_file(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("middleware")
        || path_str.contains("guard")
        || path_str.contains("auth")
}

fn scan_role_checks_ts(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let single_re = ts_role_single_re();
    let includes_re = ts_role_includes_re();
    let in_middleware = is_middleware_file(path);

    for (line_num, line_text) in source_str.lines().enumerate() {
        for cap in single_re.captures_iter(line_text) {
            if let Some(role_val) = cap.get(1) {
                let entry = RoleCheckRef {
                    file: path.to_path_buf(),
                    line: line_num + 1,
                    check_type: RoleCheckType::SingleValue,
                    role_value: role_val.as_str().to_string(),
                    is_middleware: in_middleware,
                };
                store
                    .role_check_refs
                    .entry(path.to_path_buf())
                    .or_default()
                    .push(entry);
            }
        }

        if includes_re.is_match(line_text) {
            let role_value = includes_re
                .captures(line_text)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| "array_check".to_string());

            let entry = RoleCheckRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                check_type: RoleCheckType::ArrayIncludes,
                role_value,
                is_middleware: in_middleware,
            };
            store
                .role_check_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

const TS_FUNCTIONS_QUERY: &str = r#"
(export_statement
  declaration: (function_declaration
    name: (identifier) @func_name
    parameters: (formal_parameters) @params
    body: (statement_block) @body))

(export_statement
  declaration: (lexical_declaration
    (variable_declarator
      name: (identifier) @func_name
      value: (arrow_function
        parameters: (formal_parameters) @params
        body: (statement_block) @body))))

(method_definition
  name: (property_identifier) @func_name
  parameters: (formal_parameters) @params
  body: (statement_block) @body)
"#;

fn scan_function_signatures_ts(
    path: &Path,
    source: &[u8],
    tree: &tree_sitter::Tree,
    language: &tree_sitter::Language,
    store: &IndexStore,
) {
    run_query(TS_FUNCTIONS_QUERY, language, source, tree, |_m, captures| {
        let name_cap = find_capture(captures, "func_name");
        let params_cap = find_capture(captures, "params");
        let body_cap = find_capture(captures, "body");

        if let (Some((_, name, line)), Some((_, params_text, _)), Some((_, body_text, _))) =
            (name_cap, params_cap, body_cap)
        {
            let params: Vec<String> = params_text
                .trim_matches(|c| c == '(' || c == ')')
                .split(',')
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();

            let body_hash = hash_source(body_text.as_bytes());

            let entry = FunctionSignature {
                file: path.to_path_buf(),
                line: *line,
                name: name.clone(),
                params,
                body_hash,
                service_name: None,
            };
            store
                .function_signatures
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    });
}

fn ts_jwt_blacklist_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:blacklist|revoke\s*[\.(].*token|token\s*[\.(].*revoke|invalidate\s*[\.(].*token|add\s*[\.(].*blacklist)").unwrap()
    })
}

fn ts_redis_session_del_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:del\s*[\.(].*session|session\s*[\.(].*del|redis\s*[\.(].*del|destroy\s*[\.(].*session)").unwrap()
    })
}

fn ts_cookie_clear_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:clearCookie|delete_cookie|set_cookie.*expires\s*=\s*0|remove_cookie|res\.cookie\s*\(.*maxAge\s*:\s*0)").unwrap()
    })
}

fn ts_session_destroy_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:session\.destroy|session\.invalidate|logout.*session|session\.clear)").unwrap()
    })
}

fn classify_session_invalidation(line: &str) -> Option<SessionInvalidationType> {
    if ts_jwt_blacklist_re().is_match(line) {
        Some(SessionInvalidationType::JwtBlacklist)
    } else if ts_redis_session_del_re().is_match(line) {
        Some(SessionInvalidationType::RedisSessionDelete)
    } else if ts_cookie_clear_re().is_match(line) {
        Some(SessionInvalidationType::CookieClear)
    } else if ts_session_destroy_re().is_match(line) {
        Some(SessionInvalidationType::SessionDestroy)
    } else {
        None
    }
}

fn scan_session_invalidation_ts(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    for (line_num, line_text) in source_str.lines().enumerate() {
        if let Some(inv_type) = classify_session_invalidation(line_text) {
            let entry = SessionInvalidationRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                invalidation_type: inv_type,
            };
            store
                .session_invalidation_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
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
            .join("tests/fixtures/typescript")
            .join(name)
    }

    fn parse_fixture(name: &str) -> Arc<IndexStore> {
        let path = fixture_path(name);
        let source = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("Failed to read fixture {}: {e}", path.display()));
        let store = IndexStore::new();
        let parser = TypeScriptParser;
        parser.parse_file(&path, &source, &store).unwrap();
        store
    }

    #[test]
    fn parses_express_routes() {
        let store = parse_fixture("routes.ts");
        let endpoints = store.all_api_endpoints();
        let get_users: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Get && e.path.contains("/api/users"))
            .collect();
        assert!(!get_users.is_empty(), "Should find GET /api/users route");
    }

    #[test]
    fn parses_post_route() {
        let store = parse_fixture("routes.ts");
        let endpoints = store.all_api_endpoints();
        let posts: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Post)
            .collect();
        assert!(!posts.is_empty(), "Should find POST routes");
    }

    #[test]
    fn parses_delete_route() {
        let store = parse_fixture("routes.ts");
        let endpoints = store.all_api_endpoints();
        let deletes: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Delete)
            .collect();
        assert!(!deletes.is_empty(), "Should find DELETE routes");
    }

    #[test]
    fn parses_imports() {
        let store = parse_fixture("imports.ts");
        let path = fixture_path("imports.ts");
        let imports = store.imports_for_file(&path);
        assert!(!imports.is_empty(), "Should extract imports");

        let react_import = imports.iter().find(|i| i.target_module == "react");
        assert!(react_import.is_some(), "Should find react import");
        if let Some(ri) = react_import {
            assert!(
                ri.symbols.contains(&"useState".to_string()),
                "Should extract useState symbol"
            );
        }
    }

    #[test]
    fn parses_default_import() {
        let store = parse_fixture("imports.ts");
        let path = fixture_path("imports.ts");
        let imports = store.imports_for_file(&path);
        let axios_import = imports.iter().find(|i| i.target_module == "axios");
        assert!(axios_import.is_some(), "Should find axios default import");
    }

    #[test]
    fn parses_namespace_import() {
        let store = parse_fixture("imports.ts");
        let path = fixture_path("imports.ts");
        let imports = store.imports_for_file(&path);
        let path_import = imports.iter().find(|i| i.target_module == "path");
        assert!(path_import.is_some(), "Should find namespace import for path");
    }

    #[test]
    fn parses_fetch_api_calls() {
        let store = parse_fixture("api_calls.ts");
        let calls = store.all_api_calls();
        assert!(!calls.is_empty(), "Should extract API calls");

        let fetch_users = calls
            .iter()
            .find(|c| c.url.contains("/api/users"));
        assert!(fetch_users.is_some(), "Should find fetch /api/users call");
    }

    #[test]
    fn parses_axios_api_calls() {
        let store = parse_fixture("api_calls.ts");
        let calls = store.all_api_calls();
        let post_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.method == HttpMethod::Post)
            .collect();
        assert!(!post_calls.is_empty(), "Should find axios POST calls");
    }

    #[test]
    fn parses_env_refs() {
        let store = parse_fixture("env_refs.ts");
        assert!(
            store.env_refs.contains_key("DATABASE_URL"),
            "Should find DATABASE_URL env ref"
        );
        assert!(
            store.env_refs.contains_key("API_KEY"),
            "Should find API_KEY env ref"
        );
    }

    #[test]
    fn parses_env_refs_with_defaults() {
        let store = parse_fixture("env_refs.ts");
        let has_default = store
            .env_refs
            .get("PORT")
            .map(|port_refs| port_refs[0].has_default)
            .unwrap_or(false);
        assert!(has_default, "PORT should have a default value");
    }

    #[test]
    fn parses_middleware_scopes() {
        let store = parse_fixture("middleware.ts");
        let path = fixture_path("middleware.ts");
        let scopes = store
            .middleware_scopes
            .get(&path)
            .map(|s| s.value().clone())
            .unwrap_or_default();
        assert!(!scopes.is_empty(), "Should extract middleware scopes");

        let auth = scopes
            .iter()
            .find(|s| s.middleware_name.contains("auth"));
        assert!(auth.is_some(), "Should find auth middleware");
    }

    #[test]
    fn extract_ts_default_nullish() {
        let result = extract_ts_default(r#"const port = process.env.PORT ?? "3000";"#);
        assert_eq!(result, Some("3000".to_string()));
    }

    #[test]
    fn extract_ts_default_logical_or() {
        let result = extract_ts_default(r#"const host = process.env.HOST || "localhost";"#);
        assert_eq!(result, Some("localhost".to_string()));
    }

    #[test]
    fn extract_ts_default_none() {
        let result = extract_ts_default("const key = process.env.API_KEY;");
        assert_eq!(result, None);
    }

    #[test]
    fn detects_db_writes() {
        let store = parse_fixture("data_isolation.ts");
        let writes = store.all_db_write_refs();
        let inserts: Vec<_> = writes.iter().filter(|w| w.operation == DbWriteOp::Insert).collect();
        let updates: Vec<_> = writes.iter().filter(|w| w.operation == DbWriteOp::Update).collect();
        let deletes: Vec<_> = writes.iter().filter(|w| w.operation == DbWriteOp::Delete).collect();
        assert!(!inserts.is_empty(), "Should detect INSERT");
        assert!(!updates.is_empty(), "Should detect UPDATE");
        assert!(!deletes.is_empty(), "Should detect DELETE");
    }

    #[test]
    fn detects_redis_patterns() {
        let store = parse_fixture("data_isolation.ts");
        let refs = store.all_redis_key_refs();
        let writes: Vec<_> = refs.iter().filter(|r| r.operation == RedisOp::Write).collect();
        let reads: Vec<_> = refs.iter().filter(|r| r.operation == RedisOp::Read).collect();
        assert!(!writes.is_empty(), "Should detect Redis writes");
        assert!(!reads.is_empty(), "Should detect Redis reads");
    }

    #[test]
    fn detects_hardcoded_credentials() {
        let store = parse_fixture("data_isolation.ts");
        let creds = store.all_hardcoded_creds();
        assert!(
            creds.len() >= 2,
            "Should detect at least 2 hardcoded credentials, found {}",
            creds.len()
        );
        // Should NOT flag env var references
        assert!(
            !creds.iter().any(|c| c.key_name.to_lowercase() == "jwt_token"),
            "Should not flag env var references"
        );
    }

    #[test]
    fn detects_sql_query_refs() {
        let store = parse_fixture("data_isolation.ts");
        let refs = store.all_sql_query_refs();
        assert!(!refs.is_empty(), "Should detect SQL query references");
        let without_tenant: Vec<_> = refs.iter().filter(|r| !r.has_tenant_filter).collect();
        assert!(!without_tenant.is_empty(), "Should find queries without tenant filter");
    }

    #[test]
    fn detects_ts_rls_context() {
        let store = parse_fixture("data_isolation.ts");
        let refs = store.all_rls_context_refs();
        assert!(!refs.is_empty(), "Should detect SET LOCAL / set_config calls");
        assert!(
            refs.iter()
                .any(|r| r.session_var.contains("app.current_user_id")),
            "Should extract app.current_user_id session var"
        );
    }

    #[test]
    fn detects_ts_db_pool_refs() {
        let store = parse_fixture("dual_pool.ts");
        let all_pools = store.all_db_pool_refs();
        let refs: Vec<_> = all_pools
            .iter()
            .flat_map(|(_, pools)| pools.iter())
            .collect();
        assert!(
            refs.len() >= 2,
            "Should detect at least 2 DB pool refs, found {}",
            refs.len()
        );
        assert!(
            refs.iter().any(|r| r.pool_name == "rlsPool"),
            "Should find rlsPool"
        );
        assert!(
            refs.iter().any(|r| r.pool_name == "adminPool"),
            "Should find adminPool"
        );
        // Verify connection vars are extracted
        let admin = refs.iter().find(|r| r.pool_name == "adminPool").unwrap();
        assert_eq!(
            admin.connection_var.as_deref(),
            Some("DATABASE_URL_ADMIN"),
            "Should extract DATABASE_URL_ADMIN env var"
        );
    }
}
