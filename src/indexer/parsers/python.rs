use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;

use super::{
    count_lines, create_parser, find_capture, hash_source, parse_source, run_query, LanguageParser,
};
use crate::indexer::store::{normalize_api_path, IndexStore};
use crate::indexer::types::{
    ApiEndpoint, AuditLogRef, ConcurrencySafetyRef, ConcurrencySafetyType, DbPoolRef, DbWriteOp,
    DbWriteRef, EnvRef, ErrorHandlingRef, ErrorHandlingType, EventConsumer, EventProducer,
    FileInfo, Framework, FunctionSignature, HardcodedCredential, HttpMethod, Language,
    RateLimitRef, RateLimitType, RedisKeyRef, RedisOp, RlsContextRef, RoleCheckRef, RoleCheckType,
    SecondaryAuthRef, SecondaryAuthType, SensitiveLogRef, SensitiveLogType, SessionInvalidationRef,
    SessionInvalidationType, SqlQueryOp, SqlQueryRef, StubIndicator, StubType, TestBypassRef,
    TestBypassType, TokenRefreshRef,
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
        scan_db_pool_refs_py(path, source, store);
        scan_secondary_auth_py(path, source, store);
        scan_error_handling_py(path, source, store);
        scan_role_checks_py(path, source, store);
        scan_function_signatures_py(path, source, &tree, &py_language, store);
        scan_session_invalidation_py(path, source, store);
        scan_sensitive_logging_py(path, source, store);
        scan_rate_limit_py(path, source, store);
        scan_audit_log_py(path, source, store);
        scan_test_bypass_py(path, source, store);
        scan_token_refresh_py(path, source, store);
        scan_concurrency_safety_py(path, source, store);

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

        if let (Some((_, method_text, _)), Some((_, route_text, line))) = (method_cap, route_cap) {
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
                .api
                .endpoints
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
                .infra
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
            (
                Regex::new(r"(?i)\bmock_data\b").unwrap(),
                StubType::MockData,
            ),
            (
                Regex::new(r"(?i)\bstub_data\b").unwrap(),
                StubType::StubData,
            ),
            (
                Regex::new(r"(?i)\bplaceholder\b").unwrap(),
                StubType::Placeholder,
            ),
            (
                Regex::new(r"(?i)\bhardcoded\b").unwrap(),
                StubType::Hardcoded,
            ),
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
                    .code_quality
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
                    .events
                    .producers
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
                    .events
                    .consumers
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
        Regex::new(r#"(?:redis[_client]*|rdb)\.\s*(delete|hdel)\s*\(\s*(?:f?["']([^"']+)["'])"#)
            .unwrap()
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
                    .data
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
                    .data
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
                    .data
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
                    .data
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
                    .security
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
                    .security
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
                    .security
                    .hardcoded_creds
                    .entry(path.to_path_buf())
                    .or_default()
                    .push(entry);
            }
        }
    }
}

fn py_db_pool_re() -> &'static [Regex; 3] {
    static RE: OnceLock<[Regex; 3]> = OnceLock::new();
    RE.get_or_init(|| {
        [
            // SQLAlchemy engine with env var
            Regex::new(r#"create_engine\(.*?(DATABASE_URL\w*)"#).unwrap(),
            // SQLAlchemy engine with literal connection string
            Regex::new(r#"create_engine\(.*?(postgres://\S+)"#).unwrap(),
            // asyncpg pool with env var
            Regex::new(r#"asyncpg\.create_pool\(.*?(DATABASE_URL\w*)"#).unwrap(),
        ]
    })
}

fn py_pool_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(\w+)\s*=\s*create_engine"#).unwrap())
}

fn scan_db_pool_refs_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let pool_patterns = py_db_pool_re();
    let name_re = py_pool_name_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        let mut connection_var: Option<String> = None;

        for pattern in pool_patterns {
            if let Some(cap) = pattern.captures(line_text) {
                if let Some(var_match) = cap.get(1) {
                    connection_var = Some(var_match.as_str().to_string());
                    break;
                }
            }
        }

        if connection_var.is_none() {
            continue;
        }

        let pool_name = name_re
            .captures(line_text)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "unnamed_pool".to_string());

        let entry = DbPoolRef {
            pool_name,
            role_hint: None,
            connection_var,
            file: path.to_path_buf(),
            line: line_num + 1,
        };

        store
            .data
            .db_pool_refs
            .entry(path.to_path_buf())
            .or_default()
            .push(entry);
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
        Regex::new(r#"(?i)\bWHERE\b[\s\S]*?\b(user_id|owner_id|tenant_id|project_id|org_id)\b"#)
            .unwrap()
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
                store
                    .data
                    .sql_query_refs
                    .entry(table_name)
                    .or_default()
                    .push(entry);
            }
        }
    }
}

fn py_secondary_auth_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(verify_otp|check_otp|validate_2fa|confirm_password|validate_csrf|check_totp|verify_totp|verify_code)\s*\(").unwrap()
    })
}

fn py_secondary_auth_param_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(otp|totp|verification_code|csrf_token|two_factor_code|mfa_code)\b")
            .unwrap()
    })
}

fn classify_secondary_auth_py(text: &str) -> SecondaryAuthType {
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

fn scan_secondary_auth_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let call_re = py_secondary_auth_call_re();
    let param_re = py_secondary_auth_param_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        let matched = call_re.find(line_text).or_else(|| param_re.find(line_text));
        if let Some(mat) = matched {
            let auth_type = classify_secondary_auth_py(mat.as_str());
            let entry = SecondaryAuthRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                auth_type,
                near_endpoint: None,
            };
            store
                .security
                .secondary_auth_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

fn py_except_pass_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"except(?:\s+\w+(?:\s+as\s+\w+)?)?\s*:\s*(?:pass\s*$|\.\.\.\s*$)").unwrap()
    })
}

fn scan_error_handling_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let except_pass_re = py_except_pass_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        if except_pass_re.is_match(line_text.trim()) {
            let entry = ErrorHandlingRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                error_type: ErrorHandlingType::EmptyExcept,
                context: "except: pass".to_string(),
            };
            store
                .code_quality
                .error_handling_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

fn py_role_single_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)\brole\s*==\s*["']([^"']+)["']"#).unwrap())
}

fn py_role_in_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)\brole\s+in\s+\["#).unwrap())
}

fn is_middleware_file_py(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("middleware")
        || path_str.contains("guard")
        || path_str.contains("auth")
        || path_str.contains("permission")
}

fn scan_role_checks_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let single_re = py_role_single_re();
    let in_re = py_role_in_re();
    let in_middleware = is_middleware_file_py(path);

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
                    .security
                    .role_check_refs
                    .entry(path.to_path_buf())
                    .or_default()
                    .push(entry);
            }
        }

        if in_re.is_match(line_text) {
            let entry = RoleCheckRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                check_type: RoleCheckType::SetCheck,
                role_value: "set_check".to_string(),
                is_middleware: in_middleware,
            };
            store
                .security
                .role_check_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

const PY_FUNCTIONS_QUERY: &str = r#"
(function_definition
  name: (identifier) @func_name
  parameters: (parameters) @params
  body: (block) @body)
"#;

fn scan_function_signatures_py(
    path: &Path,
    source: &[u8],
    tree: &tree_sitter::Tree,
    language: &tree_sitter::Language,
    store: &IndexStore,
) {
    run_query(
        PY_FUNCTIONS_QUERY,
        language,
        source,
        tree,
        |_m, captures| {
            let name_cap = find_capture(captures, "func_name");
            let params_cap = find_capture(captures, "params");
            let body_cap = find_capture(captures, "body");

            if let (Some((_, name, line)), Some((_, params_text, _)), Some((_, body_text, _))) =
                (name_cap, params_cap, body_cap)
            {
                // Skip private/dunder methods
                if name.starts_with('_') && !name.starts_with("__") {
                    return;
                }

                let params: Vec<String> = params_text
                    .trim_matches(|c| c == '(' || c == ')')
                    .split(',')
                    .map(|p| p.trim().to_string())
                    .filter(|p| !p.is_empty() && p != "self" && p != "cls")
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
                    .code_quality
                    .function_signatures
                    .entry(path.to_path_buf())
                    .or_default()
                    .push(entry);
            }
        },
    );
}

fn py_jwt_blacklist_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:blacklist|revoke\s*[\.(].*token|token\s*[\.(].*revoke|invalidate\s*[\.(].*token|add\s*[\.(].*blacklist)").unwrap()
    })
}

fn py_redis_session_del_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:del\s*[\.(].*session|session\s*[\.(].*del|redis\s*[\.(].*del|destroy\s*[\.(].*session)").unwrap()
    })
}

fn py_cookie_clear_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:delete_cookie|set_cookie.*expires\s*=\s*0|remove_cookie|response\.set_cookie\s*\(.*max_age\s*=\s*0)").unwrap()
    })
}

fn py_session_destroy_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:session\.destroy|session\.invalidate|logout.*session|session\.clear|session\.flush|request\.session\.flush)").unwrap()
    })
}

fn classify_session_invalidation_py(line: &str) -> Option<SessionInvalidationType> {
    if py_jwt_blacklist_re().is_match(line) {
        Some(SessionInvalidationType::JwtBlacklist)
    } else if py_redis_session_del_re().is_match(line) {
        Some(SessionInvalidationType::RedisSessionDelete)
    } else if py_cookie_clear_re().is_match(line) {
        Some(SessionInvalidationType::CookieClear)
    } else if py_session_destroy_re().is_match(line) {
        Some(SessionInvalidationType::SessionDestroy)
    } else {
        None
    }
}

fn scan_session_invalidation_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    for (line_num, line_text) in source_str.lines().enumerate() {
        if let Some(inv_type) = classify_session_invalidation_py(line_text) {
            let entry = SessionInvalidationRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                invalidation_type: inv_type,
            };
            store
                .security
                .session_invalidation_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

// ---------------------------------------------------------------------------
// S20: Sensitive data logging detection (Python)
// ---------------------------------------------------------------------------

fn sensitive_log_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(logging\.\w+|logger\.\w+|print)\s*\(.*\b(password|passwd|secret|token|api_?key|access_?token|refresh_?token|otp|verification_?code|credit_?card|cvv|ssn)\b").unwrap()
    })
}

fn classify_sensitive_log_py(text: &str) -> Option<SensitiveLogType> {
    let lower = text.to_lowercase();
    if lower.contains("password") || lower.contains("passwd") {
        Some(SensitiveLogType::Password)
    } else if lower.contains("access_token")
        || lower.contains("refresh_token")
        || lower.contains("token")
    {
        Some(SensitiveLogType::Token)
    } else if lower.contains("secret") {
        Some(SensitiveLogType::Secret)
    } else if lower.contains("otp") || lower.contains("verification_code") {
        Some(SensitiveLogType::OtpCode)
    } else if lower.contains("api_key") || lower.contains("apikey") {
        Some(SensitiveLogType::ApiKey)
    } else if lower.contains("credit_card") || lower.contains("cvv") || lower.contains("ssn") {
        Some(SensitiveLogType::CreditCard)
    } else {
        None
    }
}

fn scan_sensitive_logging_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = sensitive_log_py_re();
    for (line_num, line_text) in source_str.lines().enumerate() {
        let trimmed = line_text.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if re.is_match(line_text) {
            if let Some(log_type) = classify_sensitive_log_py(line_text) {
                let entry = SensitiveLogRef {
                    file: path.to_path_buf(),
                    line: line_num + 1,
                    log_type,
                    matched_text: trimmed.chars().take(120).collect(),
                };
                store
                    .security
                    .sensitive_log_refs
                    .entry(path.to_path_buf())
                    .or_default()
                    .push(entry);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// S22: Rate limiting detection (Python)
// ---------------------------------------------------------------------------

fn rate_limit_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(@(limiter\.limit|rate_limit|throttle|slowapi)|Depends\s*\(\s*RateLimiter|from\s+(slowapi|flask_limiter|django_ratelimit))").unwrap()
    })
}

fn scan_rate_limit_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = rate_limit_py_re();
    let lines: Vec<&str> = source_str.lines().collect();
    for (line_num, line_text) in lines.iter().enumerate() {
        let trimmed = line_text.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if re.is_match(line_text) {
            let limit_type = if line_text.contains('@') {
                RateLimitType::Decorator
            } else if line_text.contains("from") || line_text.contains("import") {
                RateLimitType::Library
            } else {
                RateLimitType::Middleware
            };
            let has_retry_after = has_retry_after_nearby_py(&lines, line_num, 15);
            let entry = RateLimitRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                endpoint_hint: None,
                limit_type,
                has_retry_after,
            };
            store
                .security
                .rate_limit_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

fn has_retry_after_nearby_py(lines: &[&str], center: usize, window: usize) -> bool {
    let start = center.saturating_sub(window);
    let end = (center + window).min(lines.len());
    lines[start..end]
        .iter()
        .any(|l| {
            let lower = l.to_lowercase();
            lower.contains("retry-after") || lower.contains("retry_after")
        })
}

// ---------------------------------------------------------------------------
// S23: Audit log detection (Python)
// ---------------------------------------------------------------------------

fn audit_log_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(audit_(log|service|trail|event|logger)\.\w+|audit_log|create_audit|log_audit|record_audit|emit_audit)\s*\(").unwrap()
    })
}

fn scan_audit_log_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = audit_log_py_re();
    for (line_num, line_text) in source_str.lines().enumerate() {
        let trimmed = line_text.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if re.is_match(line_text) {
            let entry = AuditLogRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                event_name: None,
            };
            store
                .security
                .audit_log_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

// ---------------------------------------------------------------------------
// S25: Test bypass detection (Python)
// ---------------------------------------------------------------------------

fn test_bypass_phone_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(if|elif|case)\s*.*?(phone|mobile|tel)\s*==\s*['""]\+?(\d{7,15})['""]\s*"#,
        )
        .unwrap()
    })
}

fn test_bypass_email_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(email|mail)\s*==\s*['"](test@|admin@|demo@|debug@)[^'"]*['"]\s*"#)
            .unwrap()
    })
}

fn test_bypass_password_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(password|passwd|pwd)\s*==\s*['"][^'"]{4,}['"]\s*"#).unwrap()
    })
}

fn test_bypass_debug_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(request\.(args|headers)\.(get|__getitem__)\s*\(\s*['"](debug|bypass|skip.auth)['"]\)|\.get\s*\(\s*['"](X-Bypass|X-Debug)['"])"#).unwrap()
    })
}

fn test_bypass_list_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(phone|email|mobile)\s+in\s+(TRIAL|TEST|DEBUG|BYPASS)_"#).unwrap()
    })
}

fn scan_test_bypass_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let phone_re = test_bypass_phone_py_re();
    let email_re = test_bypass_email_py_re();
    let pwd_re = test_bypass_password_py_re();
    let debug_re = test_bypass_debug_py_re();
    let list_re = test_bypass_list_py_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        let trimmed = line_text.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        let bypass = if let Some(cap) = phone_re.captures(line_text) {
            Some((
                TestBypassType::HardcodedPhone,
                cap.get(3)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default(),
            ))
        } else if let Some(cap) = email_re.captures(line_text) {
            Some((
                TestBypassType::HardcodedEmail,
                cap.get(2)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default(),
            ))
        } else if pwd_re.is_match(line_text) {
            Some((
                TestBypassType::MasterPassword,
                trimmed.chars().take(80).collect(),
            ))
        } else if debug_re.is_match(line_text) {
            Some((
                TestBypassType::DebugFlag,
                trimmed.chars().take(80).collect(),
            ))
        } else if list_re.is_match(line_text) {
            Some((
                TestBypassType::TestAccountList,
                trimmed.chars().take(80).collect(),
            ))
        } else {
            None
        };

        if let Some((bypass_type, matched_value)) = bypass {
            let entry = TestBypassRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                bypass_type,
                matched_value,
            };
            store
                .security
                .test_bypass_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

// ---------------------------------------------------------------------------
// S26: Token refresh detection (Python)
// ---------------------------------------------------------------------------

fn token_refresh_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(refresh.?token|token.?refresh|/auth/refresh|/token/refresh)"#).unwrap()
    })
}

fn token_revocation_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(blacklist|revoke|invalidate|delete.*token|remove.*token|redis.*delete)"#)
            .unwrap()
    })
}

fn scan_token_refresh_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let refresh_re = token_refresh_py_re();
    let revoke_re = token_revocation_py_re();

    let has_refresh = source_str.lines().any(|l| refresh_re.is_match(l));
    if !has_refresh {
        return;
    }

    let revocation_lines: Vec<usize> = source_str
        .lines()
        .enumerate()
        .filter(|(_, l)| revoke_re.is_match(l))
        .map(|(i, _)| i)
        .collect();

    const PROXIMITY: usize = 50;

    for (line_num, line_text) in source_str.lines().enumerate() {
        if refresh_re.is_match(line_text) {
            let has_nearby_revocation = revocation_lines.iter().any(|&rl| {
                let diff = rl.abs_diff(line_num);
                diff <= PROXIMITY
            });

            let entry = TokenRefreshRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                has_old_token_revocation: has_nearby_revocation,
            };
            store
                .security
                .token_refresh_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// S27: Concurrency safety detection (Python)
// ---------------------------------------------------------------------------

fn transaction_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(\.begin\s*\(|session\.commit|atomic|BEGIN\b|@transaction)"#).unwrap()
    })
}

fn on_conflict_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(ON\s+CONFLICT|on_conflict|INSERT\s+.*OR\s+REPLACE|merge\s*\()"#).unwrap()
    })
}

fn lock_py_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(FOR\s+UPDATE|LOCK\s+TABLE|advisory_lock|select_for_update|Lock\s*\(|asyncio\.Lock)"#).unwrap()
    })
}

fn scan_concurrency_safety_py(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let tx_re = transaction_py_re();
    let conflict_re = on_conflict_py_re();
    let lk_re = lock_py_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        let trimmed = line_text.trim();
        if trimmed.starts_with('#') {
            continue;
        }

        let safety = if tx_re.is_match(line_text) {
            Some(ConcurrencySafetyType::Transaction)
        } else if conflict_re.is_match(line_text) {
            Some(ConcurrencySafetyType::OnConflict)
        } else if lk_re.is_match(line_text) {
            Some(ConcurrencySafetyType::Lock)
        } else {
            None
        };

        if let Some(safety_type) = safety {
            let entry = ConcurrencySafetyRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                safety_type,
            };
            store
                .code_quality
                .concurrency_safety_refs
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
            .join("tests/fixtures/python")
            .join(name)
    }

    fn parse_fixture(name: &str) -> Arc<IndexStore> {
        let path = fixture_path(name);
        let source = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
        let store = IndexStore::new();
        PythonParser.parse_file(&path, &source, &store).unwrap();
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
        assert!(
            gets.len() >= 2,
            "Expected >= 2 GET routes, got {}",
            gets.len()
        );
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
        assert!(
            store.infra.env_refs.contains_key("DATABASE_URL"),
            "Missing DATABASE_URL"
        );
    }

    #[test]
    fn parses_env_refs_with_default() {
        let store = parse_fixture("env_refs.py");
        let has_default = store
            .infra
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
        assert!(
            !without_tenant.is_empty(),
            "Should find queries without tenant filter"
        );
        let _ = with_tenant; // available for future assertions
    }

    #[test]
    fn detects_python_db_pool_refs() {
        let store = parse_fixture("dual_pool.py");
        let all_refs = store.all_db_pool_refs();
        let refs: Vec<_> = all_refs
            .iter()
            .flat_map(|(_, entries)| entries.iter())
            .collect();
        assert!(
            refs.len() >= 2,
            "Should detect at least 2 DB pool refs, found {}",
            refs.len()
        );
        assert!(
            refs.iter().any(|r| r.pool_name == "app_engine"),
            "Should detect app_engine pool"
        );
        assert!(
            refs.iter().any(|r| r.pool_name == "admin_engine"),
            "Should detect admin_engine pool"
        );
        assert!(
            refs.iter()
                .any(|r| r.connection_var.as_deref() == Some("DATABASE_URL_APP")),
            "Should extract DATABASE_URL_APP connection var"
        );
        assert!(
            refs.iter()
                .any(|r| r.connection_var.as_deref() == Some("DATABASE_URL_ADMIN")),
            "Should extract DATABASE_URL_ADMIN connection var"
        );
    }
}
