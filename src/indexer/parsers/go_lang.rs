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
        scan_db_pool_refs_go(path, source, store);
        scan_secondary_auth_go(path, source, store);
        scan_error_handling_go(path, source, store);
        scan_role_checks_go(path, source, store);
        scan_function_signatures_go(path, source, &tree, &go_language, store);
        scan_session_invalidation_go(path, source, store);
        scan_sensitive_logging_go(path, source, store);
        scan_rate_limit_go(path, source, store);
        scan_audit_log_go(path, source, store);
        scan_test_bypass_go(path, source, store);
        scan_token_refresh_go(path, source, store);
        scan_concurrency_safety_go(path, source, store);

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
        let method_cap =
            find_capture(captures, "method").or_else(|| find_capture(captures, "method_name"));
        let route_cap = find_capture(captures, "route_path");
        let router_cap = find_capture(captures, "router_var");

        if let (Some((_, method_text, _)), Some((_, route_text, line))) = (method_cap, route_cap) {
            // Go string literals include quotes — strip them
            let route_clean = route_text.trim_matches('"').to_string();
            let method = match parse_method(method_text) {
                Some(m) => m,
                None => return,
            };

            let router_var = router_cap.map(|(_, v, _)| v.as_str()).unwrap_or("");
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
            (
                Regex::new(r"(?i)\bplaceholder\b").unwrap(),
                StubType::Placeholder,
            ),
            (
                Regex::new(r"(?i)\bhardcoded\b").unwrap(),
                StubType::Hardcoded,
            ),
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
        Regex::new(r#"\.\s*(Del|HDel)\s*\(\s*\w+\s*,\s*(?:fmt\.Sprintf\s*\(\s*)?["']([^"']+)["']"#)
            .unwrap()
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
                    || line_text.ends_with(')') && line_text.contains(", ");
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
        Regex::new(r#"(?i)\bWHERE\b[\s\S]*?\b(user_id|owner_id|tenant_id|project_id|org_id)\b"#)
            .unwrap()
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
                store
                    .sql_query_refs
                    .entry(table_name)
                    .or_default()
                    .push(entry);
            }
        }
    }
}

fn go_db_pool_re() -> &'static [Regex; 4] {
    static RE: OnceLock<[Regex; 4]> = OnceLock::new();
    RE.get_or_init(|| {
        [
            // pgxpool.New with env var
            Regex::new(r#"pgxpool\.New\(.*?(?:(DATABASE_URL\w*)|Getenv\("(\w+)"\))"#).unwrap(),
            // pgxpool.Connect with env var
            Regex::new(r#"pgxpool\.Connect\(.*?(DATABASE_URL\w*)"#).unwrap(),
            // sql.Open("postgres", ...) with env var
            Regex::new(r#"sql\.Open\("postgres",.*?(DATABASE_URL\w*)"#).unwrap(),
            // Variable name from assignment
            Regex::new(r#"(?:var\s+)?(\w+)(?:Pool|pool)?\s*(?:,\s*_)?\s*=\s*pgxpool"#).unwrap(),
        ]
    })
}

fn scan_db_pool_refs_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let patterns = go_db_pool_re();
    let env_patterns = &patterns[..3];
    let var_pattern = &patterns[3];

    for (line_num, line_text) in source_str.lines().enumerate() {
        // Check if this line has a pgxpool assignment at all
        if !line_text.contains("pgxpool") {
            continue;
        }

        // Extract pool variable name
        let pool_name = var_pattern
            .captures(line_text)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Extract connection env var from any of the env patterns
        let mut connection_var = None;
        for re in env_patterns {
            if let Some(cap) = re.captures(line_text) {
                // Try group 1 first (direct DATABASE_URL ref), then group 2 (Getenv arg)
                if let Some(m) = cap.get(1) {
                    connection_var = Some(m.as_str().to_string());
                    break;
                }
                if let Some(m) = cap.get(2) {
                    connection_var = Some(m.as_str().to_string());
                    break;
                }
            }
        }

        // Only emit a ref if we matched a pool creation pattern
        if connection_var.is_some() || var_pattern.is_match(line_text) {
            let entry = DbPoolRef {
                pool_name,
                role_hint: None,
                connection_var,
                file: path.to_path_buf(),
                line: line_num + 1,
            };
            store
                .db_pool_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

fn go_secondary_auth_call_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(VerifyOTP|ValidateOTP|CheckTOTP|VerifyTOTP|Verify2FA|ConfirmPassword|ValidateCSRF|VerifyCode)\s*\(").unwrap()
    })
}

fn classify_secondary_auth_go(text: &str) -> SecondaryAuthType {
    if text.contains("CSRF") || text.contains("Csrf") {
        SecondaryAuthType::CsrfToken
    } else if text.contains("2FA") || text.contains("TwoFactor") {
        SecondaryAuthType::TwoFactor
    } else if text.contains("Password") || text.contains("Confirm") {
        SecondaryAuthType::PasswordConfirm
    } else {
        SecondaryAuthType::Otp
    }
}

fn scan_secondary_auth_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let call_re = go_secondary_auth_call_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        if let Some(mat) = call_re.find(line_text) {
            let auth_type = classify_secondary_auth_go(mat.as_str());
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

fn go_ignored_error_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b_\s*(?:,\s*_\s*)?=\s*\w+").unwrap())
}

fn go_empty_err_branch_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"if\s+err\s*!=\s*nil\s*\{\s*\}").unwrap())
}

fn scan_error_handling_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let ignored_re = go_ignored_error_re();
    let empty_branch_re = go_empty_err_branch_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        if ignored_re.is_match(line_text) {
            let entry = ErrorHandlingRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                error_type: ErrorHandlingType::IgnoredError,
                context: "ignored error with _ assignment".to_string(),
            };
            store
                .error_handling_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }

        if empty_branch_re.is_match(line_text) {
            let entry = ErrorHandlingRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                error_type: ErrorHandlingType::EmptyErrorBranch,
                context: "empty if err != nil block".to_string(),
            };
            store
                .error_handling_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

fn go_role_single_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)\brole\s*==\s*"([^"]+)""#).unwrap())
}

fn go_role_map_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:allowedRoles|roleMap|roleSet)\[role\]|slices\.Contains\(.*role"#)
            .unwrap()
    })
}

fn is_middleware_file_go(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("middleware") || path_str.contains("guard") || path_str.contains("auth")
}

fn scan_role_checks_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let single_re = go_role_single_re();
    let map_re = go_role_map_re();
    let in_middleware = is_middleware_file_go(path);

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

        if map_re.is_match(line_text) {
            let entry = RoleCheckRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                check_type: RoleCheckType::SetCheck,
                role_value: "map_check".to_string(),
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

const GO_FUNCTIONS_QUERY: &str = r#"
(function_declaration
  name: (identifier) @func_name
  parameters: (parameter_list) @params
  body: (block) @body)

(method_declaration
  name: (field_identifier) @func_name
  parameters: (parameter_list) @params
  body: (block) @body)
"#;

fn scan_function_signatures_go(
    path: &Path,
    source: &[u8],
    tree: &tree_sitter::Tree,
    language: &tree_sitter::Language,
    store: &IndexStore,
) {
    run_query(
        GO_FUNCTIONS_QUERY,
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
                // Only exported functions (capitalized first letter)
                if name.starts_with(|c: char| c.is_lowercase()) {
                    return;
                }

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
        },
    );
}

fn go_jwt_blacklist_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:blacklist|revoke\s*[\.(].*token|token\s*[\.(].*revoke|invalidate\s*[\.(].*token|add\s*[\.(].*blacklist)").unwrap()
    })
}

fn go_redis_session_del_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:del\s*[\.(].*session|session\s*[\.(].*del|redis\s*[\.(].*del|destroy\s*[\.(].*session)").unwrap()
    })
}

fn go_cookie_clear_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:delete_cookie|SetCookie\s*\(.*MaxAge\s*:\s*-1|remove_cookie|http\.SetCookie\s*\(.*MaxAge\s*:\s*(?:0|-1))").unwrap()
    })
}

fn go_session_destroy_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:session\.Destroy|session\.Invalidate|session\.Clear|session\.Options\s*\(.*MaxAge\s*:\s*-1|sessions\.Save)").unwrap()
    })
}

fn classify_session_invalidation_go(line: &str) -> Option<SessionInvalidationType> {
    if go_jwt_blacklist_re().is_match(line) {
        Some(SessionInvalidationType::JwtBlacklist)
    } else if go_redis_session_del_re().is_match(line) {
        Some(SessionInvalidationType::RedisSessionDelete)
    } else if go_cookie_clear_re().is_match(line) {
        Some(SessionInvalidationType::CookieClear)
    } else if go_session_destroy_re().is_match(line) {
        Some(SessionInvalidationType::SessionDestroy)
    } else {
        None
    }
}

fn scan_session_invalidation_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    for (line_num, line_text) in source_str.lines().enumerate() {
        if let Some(inv_type) = classify_session_invalidation_go(line_text) {
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

// ---------------------------------------------------------------------------
// S20: Sensitive data logging detection (Go)
// ---------------------------------------------------------------------------

fn sensitive_log_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(log\.\w+|logger\.\w+|fmt\.Print\w*|zap\.\w+|logrus\.\w+)\s*\(.*\b(password|passwd|secret|token|api_?key|access_?token|refresh_?token|otp|verification_?code|credit_?card|cvv|ssn)\b").unwrap()
    })
}

fn classify_sensitive_log_go(text: &str) -> Option<SensitiveLogType> {
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

fn scan_sensitive_logging_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = sensitive_log_go_re();
    for (line_num, line_text) in source_str.lines().enumerate() {
        let trimmed = line_text.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if re.is_match(line_text) {
            if let Some(log_type) = classify_sensitive_log_go(line_text) {
                let entry = SensitiveLogRef {
                    file: path.to_path_buf(),
                    line: line_num + 1,
                    log_type,
                    matched_text: trimmed.chars().take(120).collect(),
                };
                store
                    .sensitive_log_refs
                    .entry(path.to_path_buf())
                    .or_default()
                    .push(entry);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// S22: Rate limiting detection (Go)
// ---------------------------------------------------------------------------

fn rate_limit_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(tollbooth|limiter\.New|rate\.NewLimiter|ratelimit\.|throttle\.|httprate\.|"golang.org/x/time/rate"|"github.com/didip/tollbooth"|"github.com/ulule/limiter")"#).unwrap()
    })
}

fn scan_rate_limit_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = rate_limit_go_re();
    for (line_num, line_text) in source_str.lines().enumerate() {
        let trimmed = line_text.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if re.is_match(line_text) {
            let limit_type = if line_text.contains("import") || line_text.contains('"') {
                RateLimitType::Library
            } else {
                RateLimitType::Middleware
            };
            let entry = RateLimitRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                endpoint_hint: None,
                limit_type,
            };
            store
                .rate_limit_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

// ---------------------------------------------------------------------------
// S23: Audit log detection (Go)
// ---------------------------------------------------------------------------

fn audit_log_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(Audit(Log|Service|Trail|Event|Logger)\.\w+|AuditLog|audit_log|CreateAuditEntry|LogAudit|RecordAudit|EmitAudit)\s*\(").unwrap()
    })
}

fn scan_audit_log_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let re = audit_log_go_re();
    for (line_num, line_text) in source_str.lines().enumerate() {
        let trimmed = line_text.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if re.is_match(line_text) {
            let entry = AuditLogRef {
                file: path.to_path_buf(),
                line: line_num + 1,
                event_name: None,
            };
            store
                .audit_log_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

// ---------------------------------------------------------------------------
// S25: Test bypass detection (Go)
// ---------------------------------------------------------------------------

fn test_bypass_phone_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(if|switch|case)\s*.*?(phone|mobile|tel)\s*==\s*"\+?(\d{7,15})""#)
            .unwrap()
    })
}

fn test_bypass_email_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(email|mail)\s*==\s*"(test@|admin@|demo@|debug@)[^"]*""#).unwrap()
    })
}

fn test_bypass_password_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)(password|passwd|pwd)\s*==\s*"[^"]{4,}""#).unwrap())
}

fn test_bypass_debug_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(r\.(Query|Header)\.(Get|Values)\s*\(\s*"(debug|bypass|skip-auth|x-bypass)")"#,
        )
        .unwrap()
    })
}

fn scan_test_bypass_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let phone_re = test_bypass_phone_go_re();
    let email_re = test_bypass_email_go_re();
    let pwd_re = test_bypass_password_go_re();
    let debug_re = test_bypass_debug_go_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        let trimmed = line_text.trim();
        if trimmed.starts_with("//") {
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
                .test_bypass_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
        }
    }
}

// ---------------------------------------------------------------------------
// S26: Token refresh detection (Go)
// ---------------------------------------------------------------------------

fn token_refresh_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(RefreshToken|refreshToken|/auth/refresh|/token/refresh)"#).unwrap()
    })
}

fn token_revocation_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(Blacklist|Revoke|Invalidate|Delete.*Token|Remove.*Token|\.Del\s*\()"#)
            .unwrap()
    })
}

fn scan_token_refresh_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let refresh_re = token_refresh_go_re();
    let revoke_re = token_revocation_go_re();

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
                .token_refresh_refs
                .entry(path.to_path_buf())
                .or_default()
                .push(entry);
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// S27: Concurrency safety detection (Go)
// ---------------------------------------------------------------------------

fn transaction_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(\.Begin\w*\s*\(|tx\.(Exec|Query|Commit|Rollback|Prepare)\s*\(|BEGIN\b|\.Transaction\s*\()"#).unwrap()
    })
}

fn on_conflict_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(ON\s+CONFLICT|INSERT\s+.*OR\s+REPLACE|\.Clauses\s*\(\s*clause\.OnConflict)"#,
        )
        .unwrap()
    })
}

fn lock_go_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(FOR\s+UPDATE|LOCK\s+TABLE|advisory_lock|sync\.Mutex|sync\.RWMutex|\.Lock\s*\()"#).unwrap()
    })
}

fn scan_concurrency_safety_go(path: &Path, source: &[u8], store: &IndexStore) {
    let source_str = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return,
    };

    let tx_re = transaction_go_re();
    let conflict_re = on_conflict_go_re();
    let lk_re = lock_go_re();

    for (line_num, line_text) in source_str.lines().enumerate() {
        let trimmed = line_text.trim();
        if trimmed.starts_with("//") {
            continue;
        }

        let safety = if tx_re.is_match(line_text) {
            Some(ConcurrencySafetyType::Transaction)
        } else if conflict_re.is_match(line_text) {
            Some(ConcurrencySafetyType::OnConflict)
        } else if lk_re.is_match(line_text) {
            if line_text.contains("sync.Mutex") || line_text.contains("sync.RWMutex") {
                Some(ConcurrencySafetyType::Mutex)
            } else {
                Some(ConcurrencySafetyType::Lock)
            }
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

    #[test]
    fn detects_go_db_pool_refs() {
        let store = parse_fixture("dual_pool.go");
        let all_pools: Vec<DbPoolRef> = store
            .db_pool_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect();
        assert!(
            all_pools.len() >= 2,
            "Should detect at least 2 DB pool refs, found {}",
            all_pools.len()
        );

        let names: Vec<&str> = all_pools.iter().map(|p| p.pool_name.as_str()).collect();
        assert!(
            names.contains(&"appPool"),
            "Should detect appPool, found: {names:?}"
        );
        assert!(
            names.contains(&"adminPool"),
            "Should detect adminPool, found: {names:?}"
        );

        let has_app_url = all_pools
            .iter()
            .any(|p| p.connection_var.as_deref() == Some("DATABASE_URL_APP"));
        let has_admin_url = all_pools
            .iter()
            .any(|p| p.connection_var.as_deref() == Some("DATABASE_URL_ADMIN"));
        assert!(has_app_url, "Should detect DATABASE_URL_APP connection var");
        assert!(
            has_admin_url,
            "Should detect DATABASE_URL_ADMIN connection var"
        );
    }
}
