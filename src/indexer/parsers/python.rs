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
    ApiEndpoint, DbWriteOp, DbWriteRef, EnvRef, EventConsumer, EventProducer, FileInfo, Framework,
    HardcodedCredential, HttpMethod, Language, RedisKeyRef, RedisOp, RlsContextRef, SqlQueryOp,
    SqlQueryRef, StubIndicator, StubType,
};

const ROUTES_QUERY: &str = include_str!("../queries/python/routes.scm");
const ENV_REFS_QUERY: &str = include_str!("../queries/python/env_refs.scm");

pub struct PythonParser;

impl LanguageParser for PythonParser {
    fn extensions(&self) -> &[&str] {
        &["py"]
    }

    fn parse_file(&self, path: &Path, source: &[u8], store: &IndexStore) -> Result<()> {
        let file_info = FileInfo {
            path: path.to_path_buf(),
            language: Language::Python,
            lines: count_lines(source),
            hash: hash_source(source),
        };
        store.files.insert(path.to_path_buf(), file_info);

        let py_language: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
        let mut parser = create_parser(&py_language)?;
        let tree = parse_source(&mut parser, source)?;

        parse_routes(path, source, &tree, &py_language, store);
        parse_env_refs(path, source, &tree, &py_language, store);
        scan_stub_indicators(path, source, store);
        scan_event_patterns(path, source, store);
        scan_db_writes_py(path, source, store);
        scan_redis_patterns_py(path, source, store);
        scan_rls_context_py(path, source, store);
        scan_hardcoded_creds_py(path, source, store);
        scan_sql_query_refs_py(path, source, store);

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

fn parse_routes(
    path: &Path,
    source: &[u8],
    tree: &tree_sitter::Tree,
    language: &tree_sitter::Language,
    store: &IndexStore,
) {
    run_query(ROUTES_QUERY, language, source, tree, |_m, captures| {
        let method_cap = find_capture(captures, "method");
        let route_cap = find_capture(captures, "route_path");

        if let (Some((_, method_text, _)), Some((_, route_text, line))) =
            (method_cap, route_cap)
        {
            let method = match parse_method(method_text) {
                Some(m) => m,
                None => return,
            };

            let framework = detect_framework(captures);
            let normalized = normalize_api_path(route_text);

            let endpoint = ApiEndpoint {
                method,
                path: route_text.clone(),
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

fn detect_framework(captures: &[(String, String, usize)]) -> Framework {
    if let Some((_, var, _)) = find_capture(captures, "router_var") {
        if var == "app" || var == "router" {
            return Framework::FastAPI;
        }
    }
    Framework::Unknown
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
            // Determine has_default from the query capture names:
            // - os.environ["KEY"] has @environ_attr but no @get_method / @getenv_method
            // - os.environ.get("KEY") has @get_method => implies default parameter
            // - os.getenv("KEY") has @getenv_method => implies default parameter
            let has_default = find_capture(captures, "get_method").is_some()
                || find_capture(captures, "getenv_method").is_some();

            let default_value = if has_default {
                let line_text = source_line_at(source, *line);
                extract_python_default(&line_text)
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

fn py_stub_patterns() -> &'static [(Regex, StubType)] {
    static PATTERNS: OnceLock<Vec<(Regex, StubType)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        vec![
            (Regex::new(r"(?i)\bTODO\b").unwrap(), StubType::Todo),
            (Regex::new(r"(?i)\bFIXME\b").unwrap(), StubType::Fixme),
            (Regex::new(r"(?i)\bHACK\b").unwrap(), StubType::Hack),
            (Regex::new(r"(?i)\bmock_data\b").unwrap(), StubType::MockData),
            (Regex::new(r"(?i)\bstub_data\b").unwrap(), StubType::StubData),
            (Regex::new(r"(?i)\bplaceholder\b").unwrap(), StubType::Placeholder),
            (Regex::new(r"(?i)\bhardcoded\b").unwrap(), StubType::Hardcoded),
            (Regex::new(r"(?i)\bfake_data\b").unwrap(), StubType::Fake),
            (Regex::new(r"(?i)\bdummy_data\b").unwrap(), StubType::Dummy),
        ]
    })
}

fn scan_stub_indicators(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let patterns = py_stub_patterns();

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

fn py_producer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:publish|produce|send_message|emit)\s*\(\s*["']([^"']+)["']"#).unwrap()
    })
}

fn py_consumer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:subscribe|consume|on_message|listen)\s*\(\s*["']([^"']+)["']"#).unwrap()
    })
}

fn py_group_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"group\s*=\s*["']([^"']+)["']"#).unwrap())
}

fn scan_event_patterns(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let producer_re = py_producer_re();
    let consumer_re = py_consumer_re();
    let group_re = py_group_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        for cap in producer_re.captures_iter(line_text) {
            if let Some(topic) = cap.get(1) {
                let entry = EventProducer {
                    topic: topic.as_str().to_string(),
                    file: path.to_path_buf(),
                    line: line_num + 1,
                };
                store
                    .event_producers
                    .entry(topic.as_str().to_string())
                    .or_default()
                    .push(entry);
            }
        }

        for cap in consumer_re.captures_iter(line_text) {
            if let Some(topic) = cap.get(1) {
                let group = group_re
                    .captures(line_text)
                    .and_then(|gc| gc.get(1))
                    .map(|g| g.as_str().to_string())
                    .unwrap_or_else(|| "default".to_string());

                let entry = EventConsumer {
                    topic: topic.as_str().to_string(),
                    group,
                    file: path.to_path_buf(),
                    line: line_num + 1,
                };
                store
                    .event_consumers
                    .entry(topic.as_str().to_string())
                    .or_default()
                    .push(entry);
            }
        }
    }
}

fn py_db_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[`"']?(\w+)[`"']?"#).unwrap()
    })
}

fn py_redis_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:redis[_client]*|rdb)\.\s*(set|hset|zadd|lpush|rpush|sadd)\s*\(\s*(?:f?["']([^"']+)["'])"#).unwrap()
    })
}

fn py_redis_read_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:redis[_client]*|rdb)\.\s*(get|hget|hgetall|lrange|smembers)\s*\(\s*(?:f?["']([^"']+)["'])"#).unwrap()
    })
}

fn py_redis_delete_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:redis[_client]*|rdb)\.\s*(delete|hdel)\s*\(\s*(?:f?["']([^"']+)["'])"#).unwrap()
    })
}

fn py_redis_ttl_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?:ex|px|timeout)\s*=\s*\d+"#).unwrap())
}

fn py_set_local_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"SET\s+LOCAL\s+(\S+)\s*="#).unwrap())
}

fn py_set_config_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"set_config\s*\(\s*['"]([^'"]+)['"]"#).unwrap())
}

fn py_hardcoded_cred_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(password|secret|api_key|access_key|token)\s*[:=]\s*["']([^"']{4,})["']"#)
            .unwrap()
    })
}

fn scan_db_writes_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = py_db_write_re();

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
                store
                    .db_write_refs
                    .entry(table_name)
                    .or_default()
                    .push(entry);
            }
        }
    }
}

fn scan_redis_patterns_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let write_re = py_redis_write_re();
    let read_re = py_redis_read_re();
    let delete_re = py_redis_delete_re();
    let ttl_re = py_redis_ttl_re();

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

fn scan_rls_context_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let set_local_re = py_set_local_re();
    let set_config_re = py_set_config_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        for cap in set_local_re.captures_iter(line_text) {
            if let Some(var) = cap.get(1) {
                let entry = RlsContextRef {
                    session_var: var.as_str().to_string(),
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

        for cap in set_config_re.captures_iter(line_text) {
            if let Some(var) = cap.get(1) {
                let entry = RlsContextRef {
                    session_var: var.as_str().to_string(),
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

fn scan_hardcoded_creds_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = py_hardcoded_cred_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        // Skip lines with env var references
        if line_text.contains("os.getenv")
            || line_text.contains("os.environ")
            || line_text.contains("env(")
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

fn source_line_at(source: &[u8], line: usize) -> String {
    let text = std::str::from_utf8(source).unwrap_or("");
    text.lines()
        .nth(line.saturating_sub(1))
        .unwrap_or("")
        .to_string()
}

fn py_default_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:environ\.get|getenv)\s*\(\s*["'][^"']*["']\s*,\s*["']([^"']*)["']"#)
            .unwrap()
    })
}

/// Extract the default value from a Python env access pattern like:
/// `os.environ.get("KEY", "default_value")` or `os.getenv("KEY", "default_value")`
fn extract_python_default(line: &str) -> Option<String> {
    py_default_re()
        .captures(line)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().to_string())
}

fn py_sql_query_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[\s\S]*?\b(?:FROM\s+)?[`"']?(\w+)[`"']?"#).unwrap()
    })
}

fn py_tenant_filter_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\bWHERE\b[\s\S]*?\b(user_id|owner_id|tenant_id|project_id|org_id)\b"#).unwrap()
    })
}

fn scan_sql_query_refs_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let query_re = py_sql_query_re();
    let tenant_re = py_tenant_filter_re();

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/python")
            .join(name)
    }

    fn parse_fixture(name: &str) -> Arc<IndexStore> {
        let path = fixture_path(name);
        let source = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
        let store = IndexStore::new();
        PythonParser
            .parse_file(&path, &source, &store)
            .unwrap();
        store
    }

    #[test]
    fn parses_fastapi_get_routes() {
        let store = parse_fixture("routes.py");
        let endpoints = store.all_api_endpoints();
        let gets: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Get)
            .collect();
        assert!(gets.len() >= 2, "Expected >= 2 GET routes, got {}", gets.len());
    }

    #[test]
    fn parses_fastapi_post_routes() {
        let store = parse_fixture("routes.py");
        let endpoints = store.all_api_endpoints();
        let posts: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Post)
            .collect();
        assert!(!posts.is_empty(), "Should find POST routes");
    }

    #[test]
    fn parses_fastapi_delete_routes() {
        let store = parse_fixture("routes.py");
        let endpoints = store.all_api_endpoints();
        let deletes: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Delete)
            .collect();
        assert!(!deletes.is_empty(), "Should find DELETE routes");
    }

    #[test]
    fn detects_fastapi_framework() {
        let store = parse_fixture("routes.py");
        let endpoints = store.all_api_endpoints();
        let fastapi: Vec<_> = endpoints
            .iter()
            .filter(|e| e.framework == Framework::FastAPI)
            .collect();
        assert!(!fastapi.is_empty(), "Should detect FastAPI framework");
    }

    #[test]
    fn parses_env_refs_direct_access() {
        let store = parse_fixture("env_refs.py");
        assert!(store.env_refs.contains_key("DATABASE_URL"), "Missing DATABASE_URL");
    }

    #[test]
    fn parses_env_refs_with_default() {
        let store = parse_fixture("env_refs.py");
        let has_default = store
            .env_refs
            .get("PORT")
            .map(|refs| refs[0].has_default)
            .unwrap_or(false);
        assert!(has_default, "PORT should have a default");
    }

    #[test]
    fn extract_python_default_environ_get() {
        let line = r#"port = os.environ.get("PORT", "5432")"#;
        assert_eq!(extract_python_default(line), Some("5432".to_string()));
    }

    #[test]
    fn extract_python_default_none_when_no_default() {
        let line = r#"key = os.getenv("API_KEY")"#;
        assert_eq!(extract_python_default(line), None);
    }

    #[test]
    fn detects_python_db_writes() {
        let store = parse_fixture("data_isolation.py");
        let writes = store.all_db_write_refs();
        let inserts: Vec<_> = writes
            .iter()
            .filter(|w| w.operation == DbWriteOp::Insert)
            .collect();
        let updates: Vec<_> = writes
            .iter()
            .filter(|w| w.operation == DbWriteOp::Update)
            .collect();
        assert!(!inserts.is_empty(), "Should detect INSERT");
        assert!(!updates.is_empty(), "Should detect UPDATE");
    }

    #[test]
    fn detects_python_rls_context() {
        let store = parse_fixture("data_isolation.py");
        let refs = store.all_rls_context_refs();
        assert!(!refs.is_empty(), "Should detect SET LOCAL calls");
        assert!(
            refs.iter()
                .any(|r| r.session_var.contains("app.current_user_id")),
            "Should extract app.current_user_id session var"
        );
    }

    #[test]
    fn detects_python_redis_patterns() {
        let store = parse_fixture("data_isolation.py");
        let refs = store.all_redis_key_refs();
        assert!(!refs.is_empty(), "Should detect Redis operations");
    }

    #[test]
    fn detects_python_hardcoded_creds() {
        let store = parse_fixture("data_isolation.py");
        let creds = store.all_hardcoded_creds();
        assert!(
            creds.len() >= 2,
            "Should detect hardcoded credentials, found {}",
            creds.len()
        );
    }

    #[test]
    fn detects_python_sql_query_refs() {
        let store = parse_fixture("data_isolation.py");
        let refs = store.all_sql_query_refs();
        assert!(!refs.is_empty(), "Should detect SQL query references");
        let with_tenant: Vec<_> = refs.iter().filter(|r| r.has_tenant_filter).collect();
        let without_tenant: Vec<_> = refs.iter().filter(|r| !r.has_tenant_filter).collect();
        // The fixture has both kinds
        assert!(!without_tenant.is_empty(), "Should find queries without tenant filter");
        let _ = with_tenant; // available for future assertions
    }
}
