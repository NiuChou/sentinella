use crate::config::schema::DataIsolationConfig;
use crate::scanners::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S12";
const SCANNER_NAME: &str = "DataIsolationAudit";
const SCANNER_DESC: &str = "Detects data isolation gaps: ghost tables, inactive RLS, missing ownership filters, cache-only data, and hardcoded credentials.";

pub struct DataIsolationAudit;

impl Scanner for DataIsolationAudit {
    fn id(&self) -> &str {
        SCANNER_ID
    }

    fn name(&self) -> &str {
        SCANNER_NAME
    }

    fn description(&self) -> &str {
        SCANNER_DESC
    }

    fn scan(&self, ctx: &ScanContext) -> ScanResult {
        let di_config = &ctx.config.data_isolation;

        if !di_config.enabled {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "Data isolation scanning is disabled.".to_string(),
            };
        }

        let mut findings = Vec::new();

        // Dimension A: Schema-Code Alignment
        let d1_findings = check_ghost_tables(ctx, di_config);
        let d2_findings = check_rls_activation(ctx, di_config);
        let d3_findings = check_force_rls(ctx, di_config);

        // Dimension B: Query Isolation
        let d4_findings = check_missing_ownership(ctx, di_config);
        let d5_findings = check_idor_prone_gets(ctx, di_config);

        // Dimension C: Infrastructure
        let d6_findings = check_cache_only(ctx, di_config);
        let d7_findings = check_hardcoded_creds(ctx);

        findings.extend(d1_findings);
        findings.extend(d2_findings);
        findings.extend(d3_findings);
        findings.extend(d4_findings);
        findings.extend(d5_findings);
        findings.extend(d6_findings);
        findings.extend(d7_findings);

        let score = compute_score(&findings);
        let summary = build_summary(&findings, score);

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

// ---------------------------------------------------------------------------
// D1: Ghost Table — table in migration but never written to by app code
// ---------------------------------------------------------------------------

fn is_excluded_table(table_name: &str, exclude_list: &[String]) -> bool {
    exclude_list
        .iter()
        .any(|exc| table_name == exc || table_name.ends_with(&format!(".{}", exc)))
}

fn check_ghost_tables(ctx: &ScanContext, di_config: &DataIsolationConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    let store = ctx.index;

    for entry in store.db_tables.iter() {
        let table_name = &entry.value().table_name;

        if is_excluded_table(table_name, &di_config.exclude_tables) {
            continue;
        }

        let has_writes = store
            .db_write_refs
            .get(table_name)
            .map(|v| !v.is_empty())
            .unwrap_or(false);

        if !has_writes {
            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Critical,
                    format!(
                        "Table '{}' defined in migration but never written to by application code",
                        table_name
                    ),
                )
                .with_suggestion(format!(
                    "Add INSERT/UPDATE operations for '{}' in application code, or add it to data_isolation.exclude_tables if intentional.",
                    table_name
                )),
            );
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// D2: RLS Not Activated — policy uses session var but app never calls SET LOCAL
// ---------------------------------------------------------------------------

fn check_rls_activation(ctx: &ScanContext, di_config: &DataIsolationConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    let store = ctx.index;

    // Collect tables that have RLS policies with session variables
    let rls_tables_with_session_var: Vec<String> = store
        .rls_policies
        .iter()
        .filter(|entry| entry.value().iter().any(|p| p.session_var.is_some()))
        .map(|entry| entry.key().clone())
        .collect();

    if rls_tables_with_session_var.is_empty() {
        return findings;
    }

    // Check if ANY application code sets the RLS session variable
    let expected_var = &di_config.rls_session_var;
    let rls_context_found = store.rls_context_refs.iter().any(|entry| {
        entry
            .value()
            .iter()
            .any(|r| r.session_var.contains(expected_var.as_str()))
    });

    if !rls_context_found {
        for table_key in &rls_tables_with_session_var {
            if is_excluded_table(table_key, &di_config.exclude_tables) {
                continue;
            }

            let session_var = store
                .rls_policies
                .get(table_key)
                .and_then(|policies| {
                    policies
                        .value()
                        .iter()
                        .find_map(|p| p.session_var.clone())
                })
                .unwrap_or_else(|| expected_var.clone());

            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Critical,
                    format!(
                        "Table '{}' has RLS policy using '{}' but application code never calls SET LOCAL",
                        table_key, session_var
                    ),
                )
                .with_suggestion(
                    "Add SET LOCAL <session_var> = <user_id> in middleware or db_factory before queries.".to_string(),
                ),
            );
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// D3: ENABLE Without FORCE — table owner can bypass RLS
// ---------------------------------------------------------------------------

fn check_force_rls(ctx: &ScanContext, di_config: &DataIsolationConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    let store = ctx.index;

    for entry in store.db_tables.iter() {
        let table_info = entry.value();

        if !table_info.has_rls {
            continue;
        }

        if is_excluded_table(&table_info.table_name, &di_config.exclude_tables) {
            continue;
        }

        let key = entry.key().clone();
        let has_force = store
            .rls_policies
            .get(&key)
            .map(|policies| policies.value().iter().any(|p| p.has_force))
            .unwrap_or(false);

        if !has_force {
            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Warning,
                    format!(
                        "Table '{}' has ENABLE RLS but not FORCE RLS — table owner role can bypass",
                        table_info.table_name
                    ),
                )
                .with_suggestion(format!(
                    "Add: ALTER TABLE {} FORCE ROW LEVEL SECURITY;",
                    table_info.table_name
                )),
            );
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// D4: Missing Ownership Filter — write on user-scoped table without tenant column
// ---------------------------------------------------------------------------

fn check_missing_ownership(ctx: &ScanContext, di_config: &DataIsolationConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    let store = ctx.index;

    // Collect user-scoped tables (has_rls or has app_role)
    let user_scoped_tables: Vec<String> = store
        .db_tables
        .iter()
        .filter(|entry| entry.value().has_rls || entry.value().app_role.is_some())
        .map(|entry| entry.value().table_name.clone())
        .collect();

    if user_scoped_tables.is_empty() {
        return findings;
    }

    use crate::indexer::types::{HttpMethod, SqlQueryOp};

    let write_endpoints = store.all_api_endpoints();
    let write_endpoint_files: Vec<_> = write_endpoints
        .iter()
        .filter(|ep| {
            matches!(
                ep.method,
                HttpMethod::Post | HttpMethod::Put | HttpMethod::Delete | HttpMethod::Patch
            )
        })
        .map(|ep| ep.file.clone())
        .collect();

    for entry in store.sql_query_refs.iter() {
        let table_name = entry.key();
        if !user_scoped_tables.contains(table_name) {
            continue;
        }

        for query_ref in entry.value().iter() {
            if query_ref.has_tenant_filter {
                continue;
            }

            // Only flag write operations (D4)
            if !matches!(
                query_ref.operation,
                SqlQueryOp::Insert | SqlQueryOp::Update | SqlQueryOp::Delete
            ) {
                continue;
            }

            // Check if the query is in a file that has write endpoints
            let in_write_endpoint_file =
                write_endpoint_files.iter().any(|f| f == &query_ref.file);
            if !in_write_endpoint_file {
                continue;
            }

            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Warning,
                    format!(
                        "Write query on user-scoped table '{}' without tenant column filter",
                        table_name
                    ),
                )
                .with_file(&query_ref.file)
                .with_line(query_ref.line)
                .with_suggestion(format!(
                    "Add WHERE {} = :uid to the query on '{}'.",
                    di_config.tenant_column, table_name
                )),
            );
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// D5: IDOR-Prone GET — SELECT on user-scoped table without tenant filter
// ---------------------------------------------------------------------------

fn check_idor_prone_gets(ctx: &ScanContext, di_config: &DataIsolationConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    let store = ctx.index;

    let user_scoped_tables: Vec<String> = store
        .db_tables
        .iter()
        .filter(|entry| entry.value().has_rls || entry.value().app_role.is_some())
        .map(|entry| entry.value().table_name.clone())
        .collect();

    if user_scoped_tables.is_empty() {
        return findings;
    }

    use crate::indexer::types::SqlQueryOp;

    for entry in store.sql_query_refs.iter() {
        let table_name = entry.key();
        if !user_scoped_tables.contains(table_name) {
            continue;
        }

        for query_ref in entry.value().iter() {
            if query_ref.has_tenant_filter {
                continue;
            }

            if query_ref.operation != SqlQueryOp::Select {
                continue;
            }

            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Info,
                    format!(
                        "SELECT on user-scoped table '{}' without tenant filter — potential IDOR",
                        table_name
                    ),
                )
                .with_file(&query_ref.file)
                .with_line(query_ref.line)
                .with_suggestion(format!(
                    "Add WHERE {} = :uid or verify the endpoint requires ownership.",
                    di_config.tenant_column
                )),
            );
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// D6: Cache-Only Persistence — Redis write with TTL but no DB write in same file
// ---------------------------------------------------------------------------

fn check_cache_only(ctx: &ScanContext, di_config: &DataIsolationConfig) -> Vec<Finding> {
    let mut findings = Vec::new();
    let store = ctx.index;

    use crate::indexer::types::RedisOp;

    for entry in store.redis_key_refs.iter() {
        let key_pattern = entry.key();

        // Check exclude patterns
        let excluded = di_config.exclude_redis_patterns.iter().any(|excl: &String| {
            let excl_prefix = excl.trim_end_matches('*');
            key_pattern.starts_with(excl_prefix)
        });

        if excluded {
            continue;
        }

        let writes_with_ttl: Vec<_> = entry
            .value()
            .iter()
            .filter(|r| r.operation == RedisOp::Write && r.has_ttl)
            .collect();

        if writes_with_ttl.is_empty() {
            continue;
        }

        // Check if any DB write exists in the same file
        let write_files: Vec<_> = writes_with_ttl.iter().map(|r| &r.file).collect();
        let has_db_write_in_same_file = write_files.iter().any(|file| {
            store
                .db_write_refs
                .iter()
                .any(|db_entry| db_entry.value().iter().any(|w| &w.file == *file))
        });

        if !has_db_write_in_same_file {
            let first_write = &writes_with_ttl[0];
            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Warning,
                    format!(
                        "Redis key '{}' written with TTL but no DB persistence found in same file",
                        key_pattern
                    ),
                )
                .with_file(&first_write.file)
                .with_line(first_write.line)
                .with_suggestion(
                    "Add a corresponding DB write (INSERT/UPSERT) alongside the Redis cache write."
                        .to_string(),
                ),
            );
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// D7: Hardcoded Credentials — literal secrets in source code
// ---------------------------------------------------------------------------

fn check_hardcoded_creds(ctx: &ScanContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let store = ctx.index;

    for entry in store.hardcoded_creds.iter() {
        for cred in entry.value().iter() {
            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Critical,
                    format!(
                        "Hardcoded credential '{}' = '{}' — use environment variable or secret manager",
                        cred.key_name, cred.value_hint
                    ),
                )
                .with_file(&cred.file)
                .with_line(cred.line)
                .with_suggestion(format!(
                    "Replace hardcoded '{}' with an environment variable reference.",
                    cred.key_name
                )),
            );
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Scoring & Summary
// ---------------------------------------------------------------------------

fn compute_score(findings: &[Finding]) -> u8 {
    if findings.is_empty() {
        return 100;
    }

    let mut deductions: f64 = 0.0;

    for f in findings {
        let penalty = match f.severity {
            Severity::Critical => 15.0,
            Severity::Warning => 5.0,
            Severity::Info => 2.0,
        };
        deductions += penalty;
    }

    let score = (100.0 - deductions).max(0.0);
    score.round() as u8
}

fn build_summary(findings: &[Finding], score: u8) -> String {
    if findings.is_empty() {
        return "No data isolation issues found.".to_string();
    }

    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let warning = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity == Severity::Info)
        .count();

    format!(
        "{} issue(s) found ({} critical, {} warning, {} info). Score: {}%.",
        findings.len(),
        critical,
        warning,
        info,
        score
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::*;
    use std::path::{Path, PathBuf};

    fn default_config() -> Config {
        Config {
            version: "1.0".into(),
            project: "test".into(),
            r#type: Default::default(),
            layers: Default::default(),
            modules: Default::default(),
            flows: Default::default(),
            deploy: Default::default(),
            integration_tests: Default::default(),
            events: Default::default(),
            env: Default::default(),
            output: Default::default(),
            dispatch: Default::default(),
            data_isolation: Default::default(),
        }
    }

    #[test]
    fn test_disabled_scanner() {
        let mut config = default_config();
        config.data_isolation.enabled = false;
        let store = IndexStore::new();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_no_data_gives_perfect_score() {
        let config = default_config();
        let store = IndexStore::new();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        assert_eq!(result.score, 100);
    }

    #[test]
    fn test_d1_ghost_table_is_critical() {
        let config = default_config();
        let store = IndexStore::new();

        // Table exists in migration but no writes
        store.db_tables.insert(
            "factor_results".into(),
            TableInfo {
                schema_name: None,
                table_name: "factor_results".into(),
                has_rls: false,
                app_role: None,
            },
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let critical: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert!(
            !critical.is_empty(),
            "Ghost table should produce Critical finding"
        );
        assert!(critical[0].message.contains("factor_results"));
    }

    #[test]
    fn test_d1_written_table_passes() {
        let config = default_config();
        let store = IndexStore::new();

        store.db_tables.insert(
            "users".into(),
            TableInfo {
                schema_name: None,
                table_name: "users".into(),
                has_rls: false,
                app_role: None,
            },
        );

        store.db_write_refs.insert(
            "users".into(),
            vec![DbWriteRef {
                table_name: "users".into(),
                operation: DbWriteOp::Insert,
                file: PathBuf::from("app.py"),
                line: 10,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let ghost_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("never written"))
            .collect();
        assert!(
            ghost_findings.is_empty(),
            "Written table should not be flagged"
        );
    }

    #[test]
    fn test_d2_rls_not_activated_is_critical() {
        let config = default_config();
        let store = IndexStore::new();

        store.db_tables.insert(
            "sessions".into(),
            TableInfo {
                schema_name: None,
                table_name: "sessions".into(),
                has_rls: true,
                app_role: Some("app_role".into()),
            },
        );

        store.rls_policies.insert(
            "sessions".into(),
            vec![RlsPolicyInfo {
                table_name: "sessions".into(),
                policy_name: "sessions_isolation".into(),
                session_var: Some("app.current_user_id".into()),
                has_force: true,
                role: Some("app_role".into()),
            }],
        );

        // No rls_context_refs — SET LOCAL never called

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let rls_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("SET LOCAL"))
            .collect();
        assert!(
            !rls_findings.is_empty(),
            "Should flag RLS not activated"
        );
        assert_eq!(rls_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_d3_enable_without_force() {
        let config = default_config();
        let store = IndexStore::new();

        store.db_tables.insert(
            "audit_logs".into(),
            TableInfo {
                schema_name: None,
                table_name: "audit_logs".into(),
                has_rls: true,
                app_role: None,
            },
        );

        // No rls_policies entry or policies without has_force

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let force_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("FORCE RLS"))
            .collect();
        assert!(
            !force_findings.is_empty(),
            "Should flag ENABLE without FORCE"
        );
        assert_eq!(force_findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_d7_hardcoded_creds_is_critical() {
        let config = default_config();
        let store = IndexStore::new();

        store.hardcoded_creds.insert(
            PathBuf::from("config.go"),
            vec![HardcodedCredential {
                key_name: "MinioAccessKey".into(),
                value_hint: "mini***".into(),
                file: PathBuf::from("config.go"),
                line: 15,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let cred_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("Hardcoded credential"))
            .collect();
        assert!(
            !cred_findings.is_empty(),
            "Should flag hardcoded credentials"
        );
        assert_eq!(cred_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_excluded_table_is_skipped() {
        let mut config = default_config();
        config.data_isolation.exclude_tables = vec!["_prisma_migrations".into()];
        let store = IndexStore::new();

        store.db_tables.insert(
            "_prisma_migrations".into(),
            TableInfo {
                schema_name: None,
                table_name: "_prisma_migrations".into(),
                has_rls: false,
                app_role: None,
            },
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        assert!(
            result.findings.is_empty(),
            "Excluded table should not produce findings"
        );
    }

    #[test]
    fn test_scoring_multiple_findings() {
        let findings = vec![
            Finding::new(SCANNER_ID, Severity::Critical, "ghost table"),
            Finding::new(SCANNER_ID, Severity::Critical, "rls not activated"),
            Finding::new(SCANNER_ID, Severity::Warning, "no force rls"),
            Finding::new(SCANNER_ID, Severity::Info, "idor risk"),
        ];
        let score = compute_score(&findings);
        // 100 - 15 - 15 - 5 - 2 = 63
        assert_eq!(score, 63);
    }
}
