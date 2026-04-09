use std::collections::{HashMap, HashSet};

use crate::config::schema::DataIsolationConfig;
use crate::indexer::types::StatusLiteralRef;
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
        // Dimension D: Pool & Service Isolation
        let d8_findings = check_dual_pool(ctx, di_config);
        let d9_findings = check_redis_enumeration(ctx, di_config);
        let d10_findings = check_cross_service_access(ctx, di_config);

        // Dimension E: Status Value Consistency
        let d11_findings = check_d11_status_value_drift(ctx);

        findings.extend(d6_findings);
        findings.extend(d7_findings);
        findings.extend(d8_findings);
        findings.extend(d9_findings);
        findings.extend(d10_findings);
        findings.extend(d11_findings);

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

    for entry in store.data.db_tables.iter() {
        let table_name = &entry.value().table_name;

        if is_excluded_table(table_name, &di_config.exclude_tables) {
            continue;
        }

        let has_writes = store
            .data
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
        .security
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
    let rls_context_found = store.security.rls_context_refs.iter().any(|entry| {
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
                .security
                .rls_policies
                .get(table_key)
                .and_then(|policies| policies.value().iter().find_map(|p| p.session_var.clone()))
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

    for entry in store.data.db_tables.iter() {
        let table_info = entry.value();

        if !table_info.has_rls {
            continue;
        }

        if is_excluded_table(&table_info.table_name, &di_config.exclude_tables) {
            continue;
        }

        let key = entry.key().clone();
        let has_force = store
            .security
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
        .data
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

    for entry in store.data.sql_query_refs.iter() {
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
            let in_write_endpoint_file = write_endpoint_files.iter().any(|f| f == &query_ref.file);
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
        .data
        .db_tables
        .iter()
        .filter(|entry| entry.value().has_rls || entry.value().app_role.is_some())
        .map(|entry| entry.value().table_name.clone())
        .collect();

    if user_scoped_tables.is_empty() {
        return findings;
    }

    use crate::indexer::types::SqlQueryOp;

    for entry in store.data.sql_query_refs.iter() {
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

    for entry in store.data.redis_key_refs.iter() {
        let key_pattern = entry.key();

        // Check exclude patterns
        let excluded = di_config
            .exclude_redis_patterns
            .iter()
            .any(|excl: &String| {
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
                .data
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

    for entry in store.security.hardcoded_creds.iter() {
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
// D8: Dual-Pool Detection — user-facing code using admin DB pool
// ---------------------------------------------------------------------------

const BACKGROUND_PATH_SEGMENTS: &[&str] = &["/worker/", "/job/", "/cron/", "/migration/", "/seed/"];

fn is_admin_pool(
    pool_ref: &crate::indexer::types::DbPoolRef,
    config: &DataIsolationConfig,
) -> bool {
    let conn_var_upper = pool_ref
        .connection_var
        .as_deref()
        .unwrap_or("")
        .to_uppercase();

    let pool_name_lower = pool_ref.pool_name.to_lowercase();

    conn_var_upper.contains("ADMIN")
        || config
            .admin_pool_env_vars
            .iter()
            .any(|v| pool_ref.connection_var.as_deref() == Some(v.as_str()))
        || pool_name_lower.contains("admin")
}

fn is_user_facing_file(file: &std::path::Path, store: &crate::indexer::store::IndexStore) -> bool {
    let file_str = file.to_string_lossy();

    // If the file defines API endpoints, it's user-facing
    let defines_routes = store
        .api
        .endpoints
        .iter()
        .any(|entry| entry.value().iter().any(|ep| ep.file == file));

    if defines_routes {
        return true;
    }

    // If the file path does NOT contain background segments, treat as user-facing
    !BACKGROUND_PATH_SEGMENTS
        .iter()
        .any(|seg| file_str.contains(seg))
}

fn check_dual_pool(ctx: &ScanContext, config: &DataIsolationConfig) -> Vec<Finding> {
    if config.admin_roles.is_empty() && config.admin_pool_env_vars.is_empty() {
        return Vec::new();
    }

    let store = ctx.index;
    let mut findings = Vec::new();

    for entry in store.data.db_pool_refs.iter() {
        let file = entry.key();
        for pool_ref in entry.value().iter() {
            if !is_admin_pool(pool_ref, config) {
                continue;
            }

            if !is_user_facing_file(file, store) {
                continue;
            }

            let conn_var_display = pool_ref.connection_var.as_deref().unwrap_or("(none)");

            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Critical,
                    format!(
                        "User-facing code in '{}' uses admin DB pool '{}' (env: {}) \
                         — should use restricted RLS-aware pool",
                        file.display(),
                        pool_ref.pool_name,
                        conn_var_display,
                    ),
                )
                .with_file(file)
                .with_line(pool_ref.line)
                .with_suggestion(
                    "Switch to a restricted, RLS-aware connection pool for user-facing code."
                        .to_string(),
                ),
            );
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// D9: Redis Key Enumeration Risk — session key without user-id prefix
// ---------------------------------------------------------------------------

fn is_excluded_redis_key(key_pattern: &str, exclude_patterns: &[String]) -> bool {
    exclude_patterns.iter().any(|excl| {
        let excl_prefix = excl.trim_end_matches('*');
        key_pattern.starts_with(excl_prefix)
    })
}

fn check_redis_enumeration(ctx: &ScanContext, config: &DataIsolationConfig) -> Vec<Finding> {
    let store = ctx.index;

    if store.data.redis_key_refs.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();

    for entry in store.data.redis_key_refs.iter() {
        let key_pattern = entry.key();

        if is_excluded_redis_key(key_pattern, &config.exclude_redis_patterns) {
            continue;
        }

        let segments: Vec<&str> = key_pattern.split(':').collect();

        // Find the first segment containing "session" or "sid"
        let session_index = segments.iter().position(|seg| {
            let lower = seg.to_lowercase();
            lower.contains("session") || lower.contains("sid")
        });

        let Some(session_idx) = session_index else {
            continue;
        };

        // Check if any EARLIER segment contains "user" or "uid"
        let has_user_prefix = segments[..session_idx].iter().any(|seg| {
            let lower = seg.to_lowercase();
            lower.contains("user") || lower.contains("uid")
        });

        if has_user_prefix {
            continue;
        }

        // Pick a representative ref for file/line context
        let first_ref = entry.value().first();

        let mut finding = Finding::new(
            SCANNER_ID,
            Severity::Warning,
            format!(
                "Redis key '{}' uses session identifier without user_id prefix \
                 — enumerable by session guessing",
                key_pattern,
            ),
        )
        .with_suggestion(
            "Prefix the key with a user_id segment, e.g. user:{uid}:session:{sid}".to_string(),
        );

        if let Some(r) = first_ref {
            finding = finding.with_file(&r.file).with_line(r.line);
        }

        findings.push(finding);
    }

    findings
}

// ---------------------------------------------------------------------------
// D10: Cross-Service Data Leak — service queries another service's table
// ---------------------------------------------------------------------------

fn build_table_ownership(
    config: &DataIsolationConfig,
    store: &crate::indexer::store::IndexStore,
) -> HashMap<String, String> {
    let mut ownership: HashMap<String, String> = HashMap::new();

    // 1. Explicit table mappings from config
    for svc in &config.service_patterns {
        for table in &svc.tables {
            ownership.insert(table.clone(), svc.name.clone());
        }
    }

    // 2. Infer from db_write_refs: file path -> service directory -> table ownership
    for entry in store.data.db_write_refs.iter() {
        let table_name = entry.key().clone();
        if ownership.contains_key(&table_name) {
            continue;
        }

        for write_ref in entry.value().iter() {
            let file_str = write_ref.file.to_string_lossy();
            if let Some(svc) = config
                .service_patterns
                .iter()
                .find(|s| file_str.starts_with(&s.directory))
            {
                ownership.insert(table_name.clone(), svc.name.clone());
                break;
            }
        }
    }

    ownership
}

fn file_to_service(file: &std::path::Path, config: &DataIsolationConfig) -> Option<String> {
    let file_str = file.to_string_lossy();
    config
        .service_patterns
        .iter()
        .find(|s| file_str.starts_with(&s.directory))
        .map(|s| s.name.clone())
}

fn check_cross_service_access(ctx: &ScanContext, config: &DataIsolationConfig) -> Vec<Finding> {
    if config.service_patterns.is_empty() {
        return Vec::new();
    }

    let store = ctx.index;
    let ownership = build_table_ownership(config, store);
    let mut findings = Vec::new();

    for entry in store.data.sql_query_refs.iter() {
        let table_name = entry.key();

        let owning_service = match ownership.get(table_name.as_str()) {
            Some(s) => s.clone(),
            None => continue,
        };

        for query_ref in entry.value().iter() {
            let querying_service = match file_to_service(&query_ref.file, config) {
                Some(s) => s,
                None => continue,
            };

            if querying_service == owning_service {
                continue;
            }

            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Warning,
                    format!(
                        "Service '{}' directly accesses table '{}' owned by service '{}' \
                         — use API or shared event instead",
                        querying_service, table_name, owning_service,
                    ),
                )
                .with_file(&query_ref.file)
                .with_line(query_ref.line)
                .with_suggestion(format!(
                    "Call {}'s API or emit an event instead of querying '{}' directly.",
                    owning_service, table_name,
                )),
            );
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// D11: Status Value Drift — inconsistent status literals across services
// ---------------------------------------------------------------------------

fn group_refs_by_column(refs: &[StatusLiteralRef]) -> HashMap<String, Vec<&StatusLiteralRef>> {
    let mut by_column: HashMap<String, Vec<&StatusLiteralRef>> = HashMap::new();
    for r in refs {
        by_column.entry(r.column_name.clone()).or_default().push(r);
    }
    by_column
}

fn check_casing_drift(col: &str, refs: &[&StatusLiteralRef]) -> Option<Finding> {
    let all_values: HashSet<&str> = refs.iter().map(|r| r.literal_value.as_str()).collect();
    let normalized: HashSet<String> = all_values.iter().map(|v: &&str| v.to_lowercase()).collect();

    if normalized.len() >= all_values.len() {
        return None;
    }

    let mut variants: Vec<&str> = all_values.into_iter().collect();
    variants.sort_unstable();
    refs.first().map(|first| {
        Finding::new(
            SCANNER_ID,
            Severity::Warning,
            format!(
                "D11: Status value drift on column '{}' — inconsistent casing: {}",
                col,
                variants.join(", ")
            ),
        )
        .with_file(&first.file)
        .with_line(first.line)
        .with_suggestion(
            "Normalize status values across all services to a single casing convention",
        )
    })
}

fn check_cross_service_value_drift(col: &str, refs: &[&StatusLiteralRef]) -> Option<Finding> {
    let mut values_by_service: HashMap<&str, HashSet<&str>> = HashMap::new();
    for r in refs {
        let svc = r.service_name.as_deref().unwrap_or("unknown");
        values_by_service
            .entry(svc)
            .or_default()
            .insert(r.literal_value.as_str());
    }

    if values_by_service.len() < 2 {
        return None;
    }

    let services: Vec<(&str, &HashSet<&str>)> =
        values_by_service.iter().map(|(&k, v)| (k, v)).collect();
    let (first_svc, first_set) = services[0];

    for &(svc, vals) in &services[1..] {
        if first_set != vals {
            return refs.first().map(|first| {
                Finding::new(
                    SCANNER_ID,
                    Severity::Warning,
                    format!(
                        "D11: Service '{}' uses different status values for '{}' than '{}'",
                        svc, col, first_svc
                    ),
                )
                .with_file(&first.file)
                .with_line(first.line)
                .with_suggestion("Align status value enums across all services")
            });
        }
    }

    None
}

fn check_d11_status_value_drift(ctx: &ScanContext) -> Vec<Finding> {
    let all_refs = ctx.index.all_status_literal_refs();
    let by_column = group_refs_by_column(&all_refs);
    let mut findings = Vec::new();

    for (col, refs) in &by_column {
        if let Some(f) = check_casing_drift(col, refs) {
            findings.push(f);
        }
        if let Some(f) = check_cross_service_value_drift(col, refs) {
            findings.push(f);
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

    let d8_count = findings
        .iter()
        .filter(|f| f.message.contains("admin DB pool"))
        .count();
    let d9_count = findings
        .iter()
        .filter(|f| f.message.contains("session identifier without user_id"))
        .count();
    let d10_count = findings
        .iter()
        .filter(|f| f.message.contains("directly accesses table"))
        .count();
    let d11_count = findings
        .iter()
        .filter(|f| f.message.starts_with("D11:"))
        .count();

    let mut detail_parts: Vec<String> = Vec::new();
    if d8_count > 0 {
        detail_parts.push(format!("{} dual-pool", d8_count));
    }
    if d9_count > 0 {
        detail_parts.push(format!("{} redis-enum", d9_count));
    }
    if d10_count > 0 {
        detail_parts.push(format!("{} cross-service", d10_count));
    }
    if d11_count > 0 {
        detail_parts.push(format!("{} status-drift", d11_count));
    }

    let detail_suffix = if detail_parts.is_empty() {
        String::new()
    } else {
        format!(" [{}]", detail_parts.join(", "))
    };

    format!(
        "{} issue(s) found ({} critical, {} warning, {} info). Score: {}%.{}",
        findings.len(),
        critical,
        warning,
        info,
        score,
        detail_suffix,
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
            required_layers: Default::default(),
            linked_repos: Default::default(),
            suppress: None,
            scanner_overrides: Default::default(),
            database_security: Default::default(),
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
        store.data.db_tables.insert(
            "factor_results".into(),
            TableInfo {
                schema_name: None,
                table_name: "factor_results".into(),
                has_rls: false,
                app_role: None,
                ..Default::default()
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

        store.data.db_tables.insert(
            "users".into(),
            TableInfo {
                schema_name: None,
                table_name: "users".into(),
                has_rls: false,
                app_role: None,
                ..Default::default()
            },
        );

        store.data.db_write_refs.insert(
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

        store.data.db_tables.insert(
            "sessions".into(),
            TableInfo {
                schema_name: None,
                table_name: "sessions".into(),
                has_rls: true,
                app_role: Some("app_role".into()),
                ..Default::default()
            },
        );

        store.security.rls_policies.insert(
            "sessions".into(),
            vec![RlsPolicyInfo {
                table_name: "sessions".into(),
                policy_name: "sessions_isolation".into(),
                session_var: Some("app.current_user_id".into()),
                has_force: true,
                role: Some("app_role".into()),
                with_check_expr: None,
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
        assert!(!rls_findings.is_empty(), "Should flag RLS not activated");
        assert_eq!(rls_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_d3_enable_without_force() {
        let config = default_config();
        let store = IndexStore::new();

        store.data.db_tables.insert(
            "audit_logs".into(),
            TableInfo {
                schema_name: None,
                table_name: "audit_logs".into(),
                has_rls: true,
                app_role: None,
                ..Default::default()
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

        store.security.hardcoded_creds.insert(
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

        store.data.db_tables.insert(
            "_prisma_migrations".into(),
            TableInfo {
                schema_name: None,
                table_name: "_prisma_migrations".into(),
                has_rls: false,
                app_role: None,
                ..Default::default()
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

    // -----------------------------------------------------------------------
    // D8: Dual-Pool Detection
    // -----------------------------------------------------------------------

    #[test]
    fn test_d8_admin_pool_in_user_code() {
        let mut config = default_config();
        config.data_isolation.admin_pool_env_vars = vec!["ADMIN_DATABASE_URL".into()];

        let store = IndexStore::new();
        let route_file = PathBuf::from("src/routes/users.ts");

        // File defines an API endpoint -> user-facing
        store.api.endpoints.insert(
            "/users".into(),
            vec![ApiEndpoint {
                method: HttpMethod::Get,
                path: "/users".into(),
                file: route_file.clone(),
                line: 5,
                framework: Framework::Express,
            }],
        );

        // Admin pool ref in that user-facing file
        store.data.db_pool_refs.insert(
            route_file.clone(),
            vec![DbPoolRef {
                pool_name: "adminPool".into(),
                role_hint: None,
                connection_var: Some("ADMIN_DATABASE_URL".into()),
                file: route_file,
                line: 12,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let d8: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("admin DB pool"))
            .collect();
        assert!(!d8.is_empty(), "Should flag admin pool in user-facing code");
        assert_eq!(d8[0].severity, Severity::Critical);
    }

    #[test]
    fn test_d8_admin_pool_in_worker_is_ok() {
        let mut config = default_config();
        config.data_isolation.admin_pool_env_vars = vec!["ADMIN_DATABASE_URL".into()];

        let store = IndexStore::new();
        let worker_file = PathBuf::from("src/worker/cleanup.ts");

        store.data.db_pool_refs.insert(
            worker_file.clone(),
            vec![DbPoolRef {
                pool_name: "adminPool".into(),
                role_hint: None,
                connection_var: Some("ADMIN_DATABASE_URL".into()),
                file: worker_file,
                line: 8,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let d8: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("admin DB pool"))
            .collect();
        assert!(d8.is_empty(), "Admin pool in worker code should not flag");
    }

    // -----------------------------------------------------------------------
    // D9: Redis Key Enumeration Risk
    // -----------------------------------------------------------------------

    #[test]
    fn test_d9_session_key_without_user_prefix() {
        let config = default_config();
        let store = IndexStore::new();

        store.data.redis_key_refs.insert(
            "session:state:{id}".into(),
            vec![RedisKeyRef {
                key_pattern: "session:state:{id}".into(),
                operation: RedisOp::Write,
                has_ttl: true,
                file: PathBuf::from("src/auth.ts"),
                line: 20,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let d9: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("session identifier without user_id"))
            .collect();
        assert!(
            !d9.is_empty(),
            "Should flag session key without user prefix"
        );
        assert_eq!(d9[0].severity, Severity::Warning);
    }

    #[test]
    fn test_d9_user_prefixed_session_key_is_ok() {
        let config = default_config();
        let store = IndexStore::new();

        store.data.redis_key_refs.insert(
            "user:{uid}:session:{sid}".into(),
            vec![RedisKeyRef {
                key_pattern: "user:{uid}:session:{sid}".into(),
                operation: RedisOp::Write,
                has_ttl: true,
                file: PathBuf::from("src/auth.ts"),
                line: 25,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let d9: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("session identifier without user_id"))
            .collect();
        assert!(d9.is_empty(), "User-prefixed session key should not flag");
    }

    // -----------------------------------------------------------------------
    // D10: Cross-Service Data Leak
    // -----------------------------------------------------------------------

    #[test]
    fn test_d10_cross_service_access() {
        use crate::config::schema::ServicePatternConfig;

        let mut config = default_config();
        config.data_isolation.service_patterns = vec![
            ServicePatternConfig {
                name: "billing".into(),
                directory: "services/billing/".into(),
                tables: vec!["invoices".into()],
            },
            ServicePatternConfig {
                name: "users".into(),
                directory: "services/users/".into(),
                tables: vec!["accounts".into()],
            },
        ];

        let store = IndexStore::new();

        // Service "users" queries table "invoices" owned by "billing"
        store.data.sql_query_refs.insert(
            "invoices".into(),
            vec![SqlQueryRef {
                table_name: "invoices".into(),
                operation: SqlQueryOp::Select,
                has_tenant_filter: true,
                file: PathBuf::from("services/users/handlers.ts"),
                line: 42,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let d10: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("directly accesses table"))
            .collect();
        assert!(!d10.is_empty(), "Should flag cross-service table access");
        assert_eq!(d10[0].severity, Severity::Warning);
        assert!(d10[0].message.contains("users"));
        assert!(d10[0].message.contains("billing"));
    }

    #[test]
    fn test_d10_own_table_is_ok() {
        use crate::config::schema::ServicePatternConfig;

        let mut config = default_config();
        config.data_isolation.service_patterns = vec![ServicePatternConfig {
            name: "billing".into(),
            directory: "services/billing/".into(),
            tables: vec!["invoices".into()],
        }];

        let store = IndexStore::new();

        // Service "billing" queries its own table "invoices"
        store.data.sql_query_refs.insert(
            "invoices".into(),
            vec![SqlQueryRef {
                table_name: "invoices".into(),
                operation: SqlQueryOp::Select,
                has_tenant_filter: true,
                file: PathBuf::from("services/billing/queries.ts"),
                line: 10,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let d10: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("directly accesses table"))
            .collect();
        assert!(d10.is_empty(), "Own table access should not flag");
    }

    // -----------------------------------------------------------------------
    // D11: Status Value Drift
    // -----------------------------------------------------------------------

    #[test]
    fn test_d11_casing_drift_detected() {
        let config = default_config();
        let store = IndexStore::new();

        store.data.status_literal_refs.insert(
            "status".into(),
            vec![
                StatusLiteralRef {
                    file: PathBuf::from("services/auth/user.ts"),
                    line: 10,
                    column_name: "status".into(),
                    literal_value: "active".into(),
                    service_name: Some("auth".into()),
                },
                StatusLiteralRef {
                    file: PathBuf::from("services/billing/invoice.ts"),
                    line: 20,
                    column_name: "status".into(),
                    literal_value: "ACTIVE".into(),
                    service_name: Some("billing".into()),
                },
            ],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let d11: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("D11:") && f.message.contains("inconsistent casing"))
            .collect();
        assert!(!d11.is_empty(), "Should flag casing drift");
        assert_eq!(d11[0].severity, Severity::Warning);
    }

    #[test]
    fn test_d11_cross_service_different_values() {
        let config = default_config();
        let store = IndexStore::new();

        store.data.status_literal_refs.insert(
            "status".into(),
            vec![
                StatusLiteralRef {
                    file: PathBuf::from("services/auth/user.ts"),
                    line: 10,
                    column_name: "status".into(),
                    literal_value: "active".into(),
                    service_name: Some("auth".into()),
                },
                StatusLiteralRef {
                    file: PathBuf::from("services/billing/invoice.ts"),
                    line: 20,
                    column_name: "status".into(),
                    literal_value: "enabled".into(),
                    service_name: Some("billing".into()),
                },
            ],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let d11: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("D11:") && f.message.contains("different status values"))
            .collect();
        assert!(!d11.is_empty(), "Should flag cross-service value drift");
        assert_eq!(d11[0].severity, Severity::Warning);
    }

    #[test]
    fn test_d11_consistent_values_no_finding() {
        let config = default_config();
        let store = IndexStore::new();

        store.data.status_literal_refs.insert(
            "status".into(),
            vec![
                StatusLiteralRef {
                    file: PathBuf::from("services/auth/user.ts"),
                    line: 10,
                    column_name: "status".into(),
                    literal_value: "active".into(),
                    service_name: Some("auth".into()),
                },
                StatusLiteralRef {
                    file: PathBuf::from("services/billing/invoice.ts"),
                    line: 20,
                    column_name: "status".into(),
                    literal_value: "active".into(),
                    service_name: Some("billing".into()),
                },
            ],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = DataIsolationAudit.scan(&ctx);
        let d11: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.starts_with("D11:"))
            .collect();
        assert!(d11.is_empty(), "Consistent values should not flag");
    }
}
