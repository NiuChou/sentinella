use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use regex::Regex;

use crate::indexer::types::{SoftDeleteColumn, SqlQueryOp, SqlQueryRef};
use crate::scanners::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S14";
const SCANNER_NAME: &str = "SoftDeleteLifecycle";
const SCANNER_DESC: &str =
    "Detects incomplete soft-delete lifecycle: missing deleted-state handling, missing reactivation paths";

pub struct SoftDeleteLifecycle;

impl Scanner for SoftDeleteLifecycle {
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
        let soft_delete_cols = ctx.index.all_soft_delete_columns();
        let sql_query_refs = ctx.index.all_sql_query_refs();

        if soft_delete_cols.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No soft-delete columns found — nothing to check.".to_string(),
            };
        }

        let tables_by_name = group_soft_delete_by_table(&soft_delete_cols);
        let queries_by_table = group_queries_by_table(&sql_query_refs);

        let filter_findings = check_deleted_state_filtering(&tables_by_name, &queries_by_table);
        let reactivation_findings = check_reactivation_path(&tables_by_name, &queries_by_table);
        let deadlock_findings =
            check_deterministic_id_deadlock(ctx, &tables_by_name, &queries_by_table);
        let data_leak_findings =
            check_reactivation_data_leak(ctx, &tables_by_name, &queries_by_table);

        let mut findings = Vec::new();
        findings.extend(filter_findings);
        findings.extend(reactivation_findings);
        findings.extend(deadlock_findings);
        findings.extend(data_leak_findings);

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
// Helpers: grouping
// ---------------------------------------------------------------------------

fn group_soft_delete_by_table(
    cols: &[SoftDeleteColumn],
) -> HashMap<String, Vec<&SoftDeleteColumn>> {
    let mut map: HashMap<String, Vec<&SoftDeleteColumn>> = HashMap::new();
    for col in cols {
        map.entry(col.table_name.clone()).or_default().push(col);
    }
    map
}

fn group_queries_by_table(refs: &[SqlQueryRef]) -> HashMap<String, Vec<&SqlQueryRef>> {
    let mut map: HashMap<String, Vec<&SqlQueryRef>> = HashMap::new();
    for r in refs {
        map.entry(r.table_name.clone()).or_default().push(r);
    }
    map
}

// ---------------------------------------------------------------------------
// Dimension 1: Deleted-state filtering
// ---------------------------------------------------------------------------

fn check_deleted_state_filtering(
    tables: &HashMap<String, Vec<&SoftDeleteColumn>>,
    queries: &HashMap<String, Vec<&SqlQueryRef>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (table_name, sd_cols) in tables {
        let selects = select_queries_for_table(table_name, queries);

        if selects.is_empty() {
            continue;
        }

        let has_filtered_select = selects.iter().any(|q| q.has_tenant_filter);

        if has_filtered_select {
            continue;
        }

        let first_select = &selects[0];
        let col_hint = format_column_hint(sd_cols);

        findings.push(
            Finding::new(
                SCANNER_ID,
                Severity::Warning,
                format!(
                    "Table '{}' has soft-delete column ({}) but SELECT queries do not filter deleted rows",
                    table_name, col_hint,
                ),
            )
            .with_file(&first_select.file)
            .with_line(first_select.line)
            .with_suggestion(format!(
                "Add WHERE clause filtering deleted state (e.g. WHERE {} IS NULL or WHERE status != 'deleted') to SELECT queries on '{}'.",
                sd_cols[0].column_name, table_name,
            )),
        );
    }

    findings
}

fn select_queries_for_table<'a>(
    table: &str,
    queries: &'a HashMap<String, Vec<&'a SqlQueryRef>>,
) -> Vec<&'a SqlQueryRef> {
    queries
        .get(table)
        .map(|refs| {
            refs.iter()
                .filter(|r| r.operation == SqlQueryOp::Select)
                .copied()
                .collect()
        })
        .unwrap_or_default()
}

fn format_column_hint(cols: &[&SoftDeleteColumn]) -> String {
    cols.iter()
        .map(|c| format!("{}: {:?}", c.column_name, c.column_type))
        .collect::<Vec<_>>()
        .join(", ")
}

// ---------------------------------------------------------------------------
// Dimension 2: Reactivation path
// ---------------------------------------------------------------------------

fn check_reactivation_path(
    tables: &HashMap<String, Vec<&SoftDeleteColumn>>,
    queries: &HashMap<String, Vec<&SqlQueryRef>>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (table_name, sd_cols) in tables {
        let table_queries = match queries.get(table_name) {
            Some(q) => q,
            None => continue,
        };

        let has_delete = table_queries
            .iter()
            .any(|r| r.operation == SqlQueryOp::Delete);

        let has_update = table_queries
            .iter()
            .any(|r| r.operation == SqlQueryOp::Update);

        if has_delete && !has_update {
            let first_delete = table_queries
                .iter()
                .find(|r| r.operation == SqlQueryOp::Delete)
                .unwrap();

            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Warning,
                    format!(
                        "Table '{}' has soft-delete ({}) and DELETE operations but no UPDATE (reactivation) path",
                        table_name, sd_cols[0].column_name,
                    ),
                )
                .with_file(&first_delete.file)
                .with_line(first_delete.line)
                .with_suggestion(format!(
                    "Add an UPDATE endpoint/operation for '{}' to support reactivation of soft-deleted rows.",
                    table_name,
                )),
            );
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Dimension 3: Deterministic ID deadlock
// ---------------------------------------------------------------------------

/// Pattern: deterministic UUID generation (v3/v5) in the same file as
/// soft-delete operations without a reactivation path creates an
/// unrecoverable state — the same ID cannot be re-inserted after soft-delete.
fn check_deterministic_id_deadlock(
    ctx: &ScanContext,
    tables: &HashMap<String, Vec<&SoftDeleteColumn>>,
    queries: &HashMap<String, Vec<&SqlQueryRef>>,
) -> Vec<Finding> {
    let uuid_pattern = build_uuid_regex();
    let uuid_files = find_uuid_files(ctx, &uuid_pattern);

    if uuid_files.is_empty() {
        return Vec::new();
    }

    let tables_without_reactivation = tables_missing_reactivation(tables, queries);
    build_deadlock_findings(&tables_without_reactivation, queries, &uuid_files)
}

fn build_uuid_regex() -> Regex {
    Regex::new(r"(?i)uuid[\._]?(v?[35]|new_v[35]|uuid[35])").unwrap()
}

fn find_uuid_files(ctx: &ScanContext, pattern: &Regex) -> HashSet<PathBuf> {
    let mut result = HashSet::new();

    for entry in ctx.index.files.iter() {
        let file_info = entry.value();
        let path_str = file_info.path.to_string_lossy();

        if pattern.is_match(&path_str) {
            result.insert(file_info.path.clone());
            continue;
        }

        // Also check if the file content can be inferred from imports
        if let Some(imports) = ctx.index.imports.get(&file_info.path) {
            let has_uuid_import = imports.value().iter().any(|imp| {
                let module_lower = imp.target_module.to_lowercase();
                module_lower.contains("uuid")
                    && imp.symbols.iter().any(|s| {
                        let sl = s.to_lowercase();
                        sl.contains("v5")
                            || sl.contains("v3")
                            || sl.contains("uuid5")
                            || sl.contains("uuid3")
                    })
            });
            if has_uuid_import {
                result.insert(file_info.path.clone());
            }
        }
    }

    result
}

fn tables_missing_reactivation<'a>(
    tables: &'a HashMap<String, Vec<&'a SoftDeleteColumn>>,
    queries: &HashMap<String, Vec<&SqlQueryRef>>,
) -> HashSet<&'a str> {
    let mut result = HashSet::new();

    for table_name in tables.keys() {
        let has_update = queries
            .get(table_name.as_str())
            .map(|refs| refs.iter().any(|r| r.operation == SqlQueryOp::Update))
            .unwrap_or(false);

        if !has_update {
            result.insert(table_name.as_str());
        }
    }

    result
}

fn build_deadlock_findings(
    tables_no_reactivation: &HashSet<&str>,
    queries: &HashMap<String, Vec<&SqlQueryRef>>,
    uuid_files: &HashSet<PathBuf>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    for table_name in tables_no_reactivation {
        let table_queries = match queries.get(*table_name) {
            Some(q) => q,
            None => continue,
        };

        let insert_in_uuid_file = table_queries
            .iter()
            .find(|r| r.operation == SqlQueryOp::Insert && uuid_files.contains(&r.file));

        if let Some(insert_ref) = insert_in_uuid_file {
            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Critical,
                    format!(
                        "Table '{}': deterministic UUID generation + soft-delete + no reactivation = ID deadlock risk",
                        table_name,
                    ),
                )
                .with_file(&insert_ref.file)
                .with_line(insert_ref.line)
                .with_suggestion(format!(
                    "Add a reactivation (UPDATE) path for '{}', or use random UUIDs (v4) instead of deterministic (v3/v5).",
                    table_name,
                )),
            );
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Dimension 4: Reactivation data leak (Clean Slate missing)
// ---------------------------------------------------------------------------

const PII_FIELD_PATTERN: &str =
    r"(?i)(nickname|avatar|role|email|phone|profile|display_name|bio|image)";
const REACTIVATION_KEYWORD_PATTERN: &str =
    r"(?i)(reactivat|restore|recover|undelete|un_delete|re.?activate)";

/// Detects reactivation UPDATE queries that change status without resetting
/// PII fields, which can leak a previous account holder's data to a new user.
fn check_reactivation_data_leak(
    ctx: &ScanContext,
    tables: &HashMap<String, Vec<&SoftDeleteColumn>>,
    queries: &HashMap<String, Vec<&SqlQueryRef>>,
) -> Vec<Finding> {
    let pii_re = Regex::new(PII_FIELD_PATTERN).unwrap();
    let reactivation_re = Regex::new(REACTIVATION_KEYWORD_PATTERN).unwrap();
    let uuid_re = build_uuid_regex();
    let uuid_files = find_uuid_files(ctx, &uuid_re);

    let mut findings = Vec::new();

    for table_name in tables.keys() {
        let updates = match queries.get(table_name) {
            Some(refs) => refs.iter().filter(|r| r.operation == SqlQueryOp::Update),
            None => continue,
        };

        for update_ref in updates {
            let file_path = &update_ref.file;
            let path_str = file_path.to_string_lossy();

            if !reactivation_re.is_match(&path_str) {
                continue;
            }

            let has_pii_reset = pii_re.is_match(&path_str);
            if has_pii_reset {
                continue;
            }

            let is_deterministic = uuid_files.contains(file_path);
            let severity = if is_deterministic {
                Severity::Critical
            } else {
                Severity::Warning
            };

            findings.push(
                Finding::new(
                    SCANNER_ID,
                    severity,
                    format!(
                        "Reactivation of table '{}' may leak previous user's PII — no field reset detected",
                        table_name,
                    ),
                )
                .with_file(file_path)
                .with_line(update_ref.line)
                .with_suggestion(
                    "Reset PII fields (nickname, avatar, role) when reactivating a deleted account".to_string(),
                ),
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
            Severity::Warning => 8.0,
            Severity::Info => 2.0,
        };
        deductions += penalty;
    }

    let score = (100.0 - deductions).max(0.0);
    score.round() as u8
}

fn build_summary(findings: &[Finding], score: u8) -> String {
    if findings.is_empty() {
        return "No soft-delete lifecycle issues found.".to_string();
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

    let filter_count = findings
        .iter()
        .filter(|f| f.message.contains("do not filter deleted"))
        .count();
    let reactivation_count = findings
        .iter()
        .filter(|f| f.message.contains("no UPDATE (reactivation)"))
        .count();
    let deadlock_count = findings
        .iter()
        .filter(|f| f.message.contains("ID deadlock"))
        .count();
    let data_leak_count = findings
        .iter()
        .filter(|f| f.message.contains("may leak previous user"))
        .count();

    let mut detail_parts: Vec<String> = Vec::new();
    if filter_count > 0 {
        detail_parts.push(format!("{} unfiltered-select", filter_count));
    }
    if reactivation_count > 0 {
        detail_parts.push(format!("{} missing-reactivation", reactivation_count));
    }
    if deadlock_count > 0 {
        detail_parts.push(format!("{} id-deadlock", deadlock_count));
    }
    if data_leak_count > 0 {
        detail_parts.push(format!("{} reactivation-data-leak", data_leak_count));
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
    use std::path::Path;

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
        }
    }

    fn make_soft_delete_col(table: &str, col: &str, col_type: SoftDeleteType) -> SoftDeleteColumn {
        SoftDeleteColumn {
            table_name: table.to_string(),
            column_name: col.to_string(),
            column_type: col_type,
            file: PathBuf::from("migrations/001.sql"),
            line: 1,
        }
    }

    fn make_query_ref(table: &str, op: SqlQueryOp, file: &str, has_filter: bool) -> SqlQueryRef {
        SqlQueryRef {
            table_name: table.to_string(),
            operation: op,
            has_tenant_filter: has_filter,
            file: PathBuf::from(file),
            line: 10,
        }
    }

    #[test]
    fn test_no_soft_delete_gives_perfect_score() {
        let config = default_config();
        let store = IndexStore::new();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = SoftDeleteLifecycle.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_unfiltered_select_is_warning() {
        let config = default_config();
        let store = IndexStore::new();

        store
            .soft_delete_columns
            .entry("users".into())
            .or_default()
            .push(make_soft_delete_col(
                "users",
                "deleted_at",
                SoftDeleteType::Timestamp,
            ));
        store
            .sql_query_refs
            .entry("users".into())
            .or_default()
            .push(make_query_ref(
                "users",
                SqlQueryOp::Select,
                "src/users.ts",
                false,
            ));

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = SoftDeleteLifecycle.scan(&ctx);

        let warnings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert!(!warnings.is_empty());
        assert!(warnings[0].message.contains("do not filter deleted"));
    }

    #[test]
    fn test_filtered_select_no_finding() {
        let config = default_config();
        let store = IndexStore::new();

        store
            .soft_delete_columns
            .entry("users".into())
            .or_default()
            .push(make_soft_delete_col(
                "users",
                "deleted_at",
                SoftDeleteType::Timestamp,
            ));
        store
            .sql_query_refs
            .entry("users".into())
            .or_default()
            .push(make_query_ref(
                "users",
                SqlQueryOp::Select,
                "src/users.ts",
                true,
            ));

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = SoftDeleteLifecycle.scan(&ctx);
        assert!(result
            .findings
            .iter()
            .all(|f| !f.message.contains("do not filter deleted")),);
    }

    #[test]
    fn test_missing_reactivation_is_warning() {
        let config = default_config();
        let store = IndexStore::new();

        store
            .soft_delete_columns
            .entry("orders".into())
            .or_default()
            .push(make_soft_delete_col(
                "orders",
                "status",
                SoftDeleteType::Status,
            ));
        // Only delete, no update
        store
            .sql_query_refs
            .entry("orders".into())
            .or_default()
            .push(make_query_ref(
                "orders",
                SqlQueryOp::Delete,
                "src/orders.ts",
                false,
            ));

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = SoftDeleteLifecycle.scan(&ctx);

        let warnings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("no UPDATE (reactivation)"))
            .collect();
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn test_has_reactivation_no_finding() {
        let config = default_config();
        let store = IndexStore::new();

        store
            .soft_delete_columns
            .entry("orders".into())
            .or_default()
            .push(make_soft_delete_col(
                "orders",
                "status",
                SoftDeleteType::Status,
            ));
        store
            .sql_query_refs
            .entry("orders".into())
            .or_default()
            .push(make_query_ref(
                "orders",
                SqlQueryOp::Delete,
                "src/orders.ts",
                false,
            ));
        store
            .sql_query_refs
            .entry("orders".into())
            .or_default()
            .push(make_query_ref(
                "orders",
                SqlQueryOp::Update,
                "src/orders.ts",
                false,
            ));

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = SoftDeleteLifecycle.scan(&ctx);

        assert!(result
            .findings
            .iter()
            .all(|f| !f.message.contains("no UPDATE (reactivation)")),);
    }

    #[test]
    fn test_scoring_formula() {
        // 1 critical (15) + 2 warnings (8*2=16) = 31 deductions => score 69
        let findings = vec![
            Finding::new(SCANNER_ID, Severity::Critical, "critical issue"),
            Finding::new(SCANNER_ID, Severity::Warning, "warning 1"),
            Finding::new(SCANNER_ID, Severity::Warning, "warning 2"),
        ];
        assert_eq!(compute_score(&findings), 69);
    }

    #[test]
    fn test_scoring_floor_at_zero() {
        let findings: Vec<Finding> = (0..10)
            .map(|i| Finding::new(SCANNER_ID, Severity::Critical, format!("crit {}", i)))
            .collect();
        assert_eq!(compute_score(&findings), 0);
    }

    #[test]
    fn test_empty_findings_perfect_score() {
        assert_eq!(compute_score(&[]), 100);
    }

    #[test]
    fn test_summary_format() {
        let findings = vec![
            Finding::new(SCANNER_ID, Severity::Warning, "do not filter deleted rows"),
            Finding::new(
                SCANNER_ID,
                Severity::Warning,
                "no UPDATE (reactivation) path",
            ),
        ];
        let summary = build_summary(&findings, 84);
        assert!(summary.contains("2 issue(s)"));
        assert!(summary.contains("0 critical"));
        assert!(summary.contains("2 warning"));
        assert!(summary.contains("Score: 84%"));
        assert!(summary.contains("unfiltered-select"));
        assert!(summary.contains("missing-reactivation"));
    }

    // -----------------------------------------------------------------------
    // Dimension 4: Reactivation data leak tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_reactivation_no_pii_reset_is_warning() {
        let config = default_config();
        let store = IndexStore::new();

        store
            .soft_delete_columns
            .entry("users".into())
            .or_default()
            .push(make_soft_delete_col(
                "users",
                "status",
                SoftDeleteType::Status,
            ));
        // UPDATE in a file whose path contains "reactivate" but no PII field names
        store
            .sql_query_refs
            .entry("users".into())
            .or_default()
            .push(make_query_ref(
                "users",
                SqlQueryOp::Update,
                "src/reactivate_user.ts",
                false,
            ));

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = SoftDeleteLifecycle.scan(&ctx);

        let leaks: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("may leak previous user"))
            .collect();
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].severity, Severity::Warning);
    }

    #[test]
    fn test_reactivation_with_pii_reset_no_finding() {
        let config = default_config();
        let store = IndexStore::new();

        store
            .soft_delete_columns
            .entry("users".into())
            .or_default()
            .push(make_soft_delete_col(
                "users",
                "status",
                SoftDeleteType::Status,
            ));
        // File path contains both reactivation keyword AND a PII field name
        store
            .sql_query_refs
            .entry("users".into())
            .or_default()
            .push(make_query_ref(
                "users",
                SqlQueryOp::Update,
                "src/reactivate_user_reset_nickname.ts",
                false,
            ));

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = SoftDeleteLifecycle.scan(&ctx);

        assert!(result
            .findings
            .iter()
            .all(|f| !f.message.contains("may leak previous user")),);
    }

    #[test]
    fn test_reactivation_deterministic_id_escalates_to_critical() {
        let config = default_config();
        let store = IndexStore::new();

        let uuid_file = PathBuf::from("src/reactivate_user.ts");

        store
            .soft_delete_columns
            .entry("users".into())
            .or_default()
            .push(make_soft_delete_col(
                "users",
                "status",
                SoftDeleteType::Status,
            ));
        store
            .sql_query_refs
            .entry("users".into())
            .or_default()
            .push(make_query_ref(
                "users",
                SqlQueryOp::Update,
                "src/reactivate_user.ts",
                false,
            ));

        // Register the file in the index so find_uuid_files can discover it
        store.files.insert(
            uuid_file.clone(),
            FileInfo {
                path: uuid_file.clone(),
                language: Language::TypeScript,
                lines: 50,
                hash: 0,
            },
        );
        // Add a UUID v5 import so the file is flagged as deterministic-ID
        store.imports.insert(
            uuid_file.clone(),
            vec![ImportEdge {
                source_file: uuid_file,
                target_module: "uuid".to_string(),
                symbols: vec!["v5".to_string()],
                is_type_only: false,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };
        let result = SoftDeleteLifecycle.scan(&ctx);

        let leaks: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("may leak previous user"))
            .collect();
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].severity, Severity::Critical);
    }

    #[test]
    fn test_summary_includes_data_leak_count() {
        let findings = vec![Finding::new(
            SCANNER_ID,
            Severity::Warning,
            "Reactivation of table 'users' may leak previous user's PII — no field reset detected",
        )];
        let summary = build_summary(&findings, 92);
        assert!(summary.contains("reactivation-data-leak"));
    }
}
