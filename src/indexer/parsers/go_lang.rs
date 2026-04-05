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

const ROUTES_QUERY: &str = include_str!("../queries/go/routes.scm");

pub struct GoParser;

impl LanguageParser for GoParser {
    fn extensions(&self) -> &[&str] {
        &["go"]
    }

    fn parse_file(&self, path: &Path, source: &[u8], store: &IndexStore) -> Result<()> {
        let file_info = FileInfo {
            path: path.to_path_buf(),
            language: Language::Go,
            lines: count_lines(source),
            hash: hash_source(source),
        };
        store.files.insert(path.to_path_buf(), file_info);

        let go_language: tree_sitter::Language = tree_sitter_go::LANGUAGE.into();
        let mut parser = create_parser(&go_language)?;
        let tree = parse_source(&mut parser, source)?;

        parse_routes(path, source, &tree, &go_language, store);
        scan_env_refs(path, source, store);
        scan_stub_indicators(path, source, store);
        scan_event_patterns(path, source, store);
        scan_db_writes_go(path, source, store);
        scan_redis_patterns_go(path, source, store);
        scan_rls_context_go(path, source, store);
        scan_hardcoded_creds_go(path, source, store);
        scan_sql_query_refs_go(path, source, store);

        Ok(())
    }
}

fn parse_method(name: &str) -> Option<HttpMethod> {
    match name.to_uppercase().as_str() {
        "GET" => Some(HttpMethod::Get),
        "POST" => Some(HttpMethod::Post),
        "PUT" => Some(HttpMethod::Put),
        "PATCH" => Some(HttpMethod::Patch),
        "DELETE" => Some(HttpMethod::Delete),
        _ => None,
    }
}

fn detect_framework(router_var: &str, method: &str) -> Framework {
    match method.to_uppercase().as_str() {
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" => {
            // Gin and Echo both use uppercase method names
            // Heuristic: Gin typically uses `r` or `router`, Echo uses `e`
            if router_var == "e" {
                Framework::Echo
            } else {
                Framework::Gin
            }
        }
        "HANDLE" | "HANDLEFUNC" => Framework::Unknown,
        _ => Framework::Unknown,
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
        let method_cap = find_capture(captures, "method")
            .or_else(|| find_capture(captures, "method_name"));
        let route_cap = find_capture(captures, "route_path");
        let router_cap = find_capture(captures, "router_var");

        if let (Some((_, method_text, _)), Some((_, route_text, line))) =
            (method_cap, route_cap)
        {
            // Go string literals include quotes — strip them
            let route_clean = route_text.trim_matches('"').to_string();
            let method = match parse_method(method_text) {
                Some(m) => m,
                None => return,
            };

            let router_var = router_cap
                .map(|(_, v, _)| v.as_str())
                .unwrap_or("");
            let framework = detect_framework(router_var, method_text);
            let normalized = normalize_api_path(&route_clean);

            let endpoint = ApiEndpoint {
                method,
                path: route_clean,
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

fn go_getenv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"os\.Getenv\(\s*"([^"]+)"\s*\)"#).unwrap())
}

fn go_lookup_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"os\.LookupEnv\(\s*"([^"]+)"\s*\)"#).unwrap())
}

fn scan_env_refs(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let getenv_re = go_getenv_re();
    let lookup_re = go_lookup_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        for cap in getenv_re.captures_iter(line_text) {
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

        for cap in lookup_re.captures_iter(line_text) {
            if let Some(var) = cap.get(1) {
                // LookupEnv returns (value, ok) — caller typically provides a default
                let env_ref = EnvRef {
                    var_name: var.as_str().to_string(),
                    file: path.to_path_buf(),
                    line: line_num + 1,
                    has_default: true,
                    default_value: None, // Go LookupEnv default is in surrounding code, not extractable here
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

fn go_stub_patterns() -> &'static [(Regex, StubType)] {
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

    let patterns = go_stub_patterns();

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

fn go_producer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:Publish|Produce|SendMessage)\s*\(\s*(?:ctx\s*,\s*)?["']([^"']+)["']"#)
            .unwrap()
    })
}

fn go_consumer_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:Subscribe|Consume|AddHandler)\s*\(\s*["']([^"']+)["']"#).unwrap()
    })
}

fn go_group_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?:GroupId|ConsumerGroup|group)\s*[:=]\s*["']([^"']+)["']"#).unwrap()
    })
}

fn scan_event_patterns(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let producer_re = go_producer_re();
    let consumer_re = go_consumer_re();
    let group_re = go_group_re();

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

fn go_db_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[`"']?(\w+)[`"']?"#).unwrap()
    })
}

fn go_redis_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\.\s*(Set|HSet|ZAdd|LPush|RPush|SAdd)\s*\(\s*\w+\s*,\s*(?:fmt\.Sprintf\s*\(\s*)?["']([^"']+)["']"#).unwrap()
    })
}

fn go_redis_read_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\.\s*(Get|HGet|HGetAll|LRange|SMembers|ZRange)\s*\(\s*\w+\s*,\s*(?:fmt\.Sprintf\s*\(\s*)?["']([^"']+)["']"#).unwrap()
    })
}

fn go_redis_delete_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"\.\s*(Del|HDel)\s*\(\s*\w+\s*,\s*(?:fmt\.Sprintf\s*\(\s*)?["']([^"']+)["']"#).unwrap()
    })
}

fn go_set_local_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"SET\s+LOCAL\s+(\S+)\s*="#).unwrap())
}

fn go_hardcoded_cred_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(Password|Secret|ApiKey|AccessKey|Token|MinioAccessKey|MinioSecretKey|FederationSecret)\s*[:=]\s*["']([^"']{4,})["']"#).unwrap()
    })
}

fn scan_db_writes_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = go_db_write_re();

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

fn scan_redis_patterns_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let write_re = go_redis_write_re();
    let read_re = go_redis_read_re();
    let delete_re = go_redis_delete_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        for cap in write_re.captures_iter(line_text) {
            if let Some(key) = cap.get(2) {
                let has_ttl = line_text.contains("time.")
                    || line_text.contains("Expiration")
                    || line_text.ends_with(')')
                        && line_text.contains(", ");
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

fn scan_rls_context_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = go_set_local_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        for cap in re.captures_iter(line_text) {
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

fn scan_hardcoded_creds_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = go_hardcoded_cred_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        // Skip lines with env var references
        if line_text.contains("os.Getenv")
            || line_text.contains("os.LookupEnv")
            || line_text.contains("viper.")
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

fn go_sql_query_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+[\s\S]*?\b(?:FROM\s+)?[`"']?(\w+)[`"']?"#).unwrap()
    })
}

fn go_tenant_filter_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\bWHERE\b[\s\S]*?\b(user_id|owner_id|tenant_id|project_id|org_id)\b"#).unwrap()
    })
}

fn scan_sql_query_refs_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let query_re = go_sql_query_re();
    let tenant_re = go_tenant_filter_re();

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
            .join("tests/fixtures/go")
            .join(name)
    }

    fn parse_fixture(name: &str) -> Arc<IndexStore> {
        let path = fixture_path(name);
        let source = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
        let store = IndexStore::new();
        GoParser.parse_file(&path, &source, &store).unwrap();
        store
    }

    #[test]
    fn parses_gin_get_route() {
        let store = parse_fixture("routes.go");
        let endpoints = store.all_api_endpoints();
        let gets: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Get)
            .collect();
        assert!(!gets.is_empty(), "Should find GET routes");
    }

    #[test]
    fn parses_gin_post_route() {
        let store = parse_fixture("routes.go");
        let endpoints = store.all_api_endpoints();
        let posts: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Post)
            .collect();
        assert!(!posts.is_empty(), "Should find POST routes");
    }

    #[test]
    fn parses_gin_put_route() {
        let store = parse_fixture("routes.go");
        let endpoints = store.all_api_endpoints();
        let puts: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Put)
            .collect();
        assert!(!puts.is_empty(), "Should find PUT routes");
    }

    #[test]
    fn parses_gin_delete_route() {
        let store = parse_fixture("routes.go");
        let endpoints = store.all_api_endpoints();
        let deletes: Vec<_> = endpoints
            .iter()
            .filter(|e| e.method == HttpMethod::Delete)
            .collect();
        assert!(!deletes.is_empty(), "Should find DELETE routes");
    }

    #[test]
    fn detects_gin_framework() {
        let store = parse_fixture("routes.go");
        let endpoints = store.all_api_endpoints();
        let gin: Vec<_> = endpoints
            .iter()
            .filter(|e| e.framework == Framework::Gin)
            .collect();
        assert!(!gin.is_empty(), "Should detect Gin framework");
    }

    #[test]
    fn route_paths_are_clean() {
        let store = parse_fixture("routes.go");
        let endpoints = store.all_api_endpoints();
        for ep in &endpoints {
            assert!(
                !ep.path.contains('"'),
                "Route path should not contain quotes: {}",
                ep.path
            );
        }
    }

    #[test]
    fn detects_go_db_writes() {
        let store = parse_fixture("data_isolation.go");
        let writes = store.all_db_write_refs();
        let inserts: Vec<_> = writes
            .iter()
            .filter(|w| w.operation == DbWriteOp::Insert)
            .collect();
        let updates: Vec<_> = writes
            .iter()
            .filter(|w| w.operation == DbWriteOp::Update)
            .collect();
        let deletes: Vec<_> = writes
            .iter()
            .filter(|w| w.operation == DbWriteOp::Delete)
            .collect();
        assert!(!inserts.is_empty(), "Should detect INSERT");
        assert!(!updates.is_empty(), "Should detect UPDATE");
        assert!(!deletes.is_empty(), "Should detect DELETE");
    }

    #[test]
    fn detects_go_rls_context() {
        let store = parse_fixture("data_isolation.go");
        let refs = store.all_rls_context_refs();
        assert!(!refs.is_empty(), "Should detect SET LOCAL calls");
    }

    #[test]
    fn detects_go_hardcoded_creds() {
        let store = parse_fixture("data_isolation.go");
        let creds = store.all_hardcoded_creds();
        assert!(
            creds.len() >= 2,
            "Should detect hardcoded credentials, found {}",
            creds.len()
        );
    }

    #[test]
    fn detects_go_sql_query_refs() {
        let store = parse_fixture("data_isolation.go");
        let refs = store.all_sql_query_refs();
        assert!(!refs.is_empty(), "Should detect SQL query references");
    }
}
