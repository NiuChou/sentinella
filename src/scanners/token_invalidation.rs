use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::indexer::types::{DbWriteOp, HttpMethod, SqlQueryOp};
use crate::scanners::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S18";
const SCANNER_NAME: &str = "TokenInvalidation";
const SCANNER_DESC: &str =
    "Detects user state changes (deletion, suspension) without token/session invalidation";

pub struct TokenInvalidation;

/// A file containing a user state change operation.
#[derive(Debug)]
struct StateChangeTarget {
    file: PathBuf,
    line: usize,
    description: String,
    has_api_endpoint: bool,
}

/// Default keywords in API paths that indicate user state change endpoints.
const DEFAULT_STATE_CHANGE_PATH_KEYWORDS: &[&str] = &[
    "delete",
    "deactivate",
    "suspend",
    "ban",
    "disable",
    "revoke",
    "block",
];

/// Collect all files that have session invalidation refs.
fn files_with_invalidation(ctx: &ScanContext) -> HashSet<PathBuf> {
    ctx.index
        .all_session_invalidation_refs()
        .into_iter()
        .map(|r| r.file)
        .collect()
}

/// Collect tables with soft-delete columns.
fn soft_delete_tables(ctx: &ScanContext) -> HashSet<String> {
    ctx.index
        .all_soft_delete_columns()
        .into_iter()
        .map(|c| c.table_name)
        .collect()
}

/// Check if a file contains a state-change API endpoint (DELETE method or
/// path containing state change keywords).
fn file_has_state_change_endpoint(ctx: &ScanContext, file: &PathBuf, keywords: &[&str]) -> bool {
    let endpoints = ctx.index.all_api_endpoints();
    endpoints.iter().any(|ep| {
        ep.file == *file
            && (ep.method == HttpMethod::Delete
                || keywords
                    .iter()
                    .any(|kw| ep.path.to_lowercase().contains(kw)))
    })
}

/// Collect state change targets from SQL UPDATE/DELETE queries.
fn collect_sql_state_changes(ctx: &ScanContext, keywords: &[&str]) -> Vec<StateChangeTarget> {
    let sd_tables = soft_delete_tables(ctx);

    ctx.index
        .all_sql_query_refs()
        .into_iter()
        .filter(|r| {
            r.operation == SqlQueryOp::Delete
                || (r.operation == SqlQueryOp::Update && sd_tables.contains(&r.table_name))
        })
        .map(|r| {
            let has_api = file_has_state_change_endpoint(ctx, &r.file, keywords);
            StateChangeTarget {
                description: format!("SQL {} on '{}'", r.operation_label(), r.table_name),
                file: r.file,
                line: r.line,
                has_api_endpoint: has_api,
            }
        })
        .collect()
}

/// Collect state change targets from DB write refs (ORM-level deletes).
fn collect_db_write_state_changes(
    ctx: &ScanContext,
    seen: &HashSet<PathBuf>,
    keywords: &[&str],
) -> Vec<StateChangeTarget> {
    let sd_tables = soft_delete_tables(ctx);

    ctx.index
        .all_db_write_refs()
        .into_iter()
        .filter(|r| {
            !seen.contains(&r.file)
                && (r.operation == DbWriteOp::Delete
                    || (r.operation == DbWriteOp::Update && sd_tables.contains(&r.table_name)))
        })
        .map(|r| {
            let has_api = file_has_state_change_endpoint(ctx, &r.file, keywords);
            StateChangeTarget {
                description: format!("DB {} on '{}'", r.operation_label(), r.table_name),
                file: r.file,
                line: r.line,
                has_api_endpoint: has_api,
            }
        })
        .collect()
}

/// Deduplicate targets by file, keeping the first occurrence per file.
fn deduplicate_by_file(targets: Vec<StateChangeTarget>) -> Vec<StateChangeTarget> {
    let mut seen = HashMap::new();
    for target in targets {
        seen.entry(target.file.clone()).or_insert(target);
    }
    seen.into_values().collect()
}

/// Compute score from invalidation ratio.
fn compute_score(invalidated: usize, total: usize) -> u8 {
    if total == 0 {
        return 100;
    }
    ((invalidated as f64 / total as f64) * 100.0).round() as u8
}

impl Scanner for TokenInvalidation {
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
        // Read trigger fields from config override or fall back to defaults
        let config_triggers: Vec<String> = ctx
            .config
            .scanner_overrides
            .s18
            .as_ref()
            .map(|c| c.trigger_fields.clone())
            .unwrap_or_default();
        let state_kw: Vec<&str> = if config_triggers.is_empty() {
            DEFAULT_STATE_CHANGE_PATH_KEYWORDS.to_vec()
        } else {
            config_triggers.iter().map(|s| s.as_str()).collect()
        };

        let invalidation_files = files_with_invalidation(ctx);
        let mut findings: Vec<Finding> = Vec::new();

        // Phase 1: SQL-level state changes
        let sql_targets = collect_sql_state_changes(ctx, &state_kw);
        let sql_files: HashSet<PathBuf> = sql_targets.iter().map(|t| t.file.clone()).collect();

        // Phase 2: ORM-level state changes (avoid duplicates)
        let db_targets = collect_db_write_state_changes(ctx, &sql_files, &state_kw);

        // Merge and deduplicate
        let all_targets: Vec<StateChangeTarget> =
            sql_targets.into_iter().chain(db_targets).collect();
        let targets = deduplicate_by_file(all_targets);

        let total = targets.len();
        let mut invalidated_count: usize = 0;

        for target in &targets {
            if invalidation_files.contains(&target.file) {
                invalidated_count += 1;
                continue;
            }

            let severity = if target.has_api_endpoint {
                Severity::Critical
            } else {
                Severity::Warning
            };

            findings.push(
                Finding::new(
                    SCANNER_ID,
                    severity,
                    format!(
                        "User state change without token/session invalidation: {}",
                        target.description
                    ),
                )
                .with_file(&target.file)
                .with_line(target.line)
                .with_suggestion(
                    "Add JWT blacklisting or session destruction after user state changes",
                ),
            );
        }

        let score = compute_score(invalidated_count, total);

        let summary = if total == 0 {
            "No user state change operations found to check.".to_string()
        } else {
            format!(
                "{}/{} state change operations have token/session invalidation (score: {})",
                invalidated_count, total, score
            )
        };

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

/// Helper trait for operation label formatting.
trait OperationLabel {
    fn operation_label(&self) -> &str;
}

impl OperationLabel for crate::indexer::types::SqlQueryRef {
    fn operation_label(&self) -> &str {
        match self.operation {
            SqlQueryOp::Select => "SELECT",
            SqlQueryOp::Insert => "INSERT",
            SqlQueryOp::Update => "UPDATE",
            SqlQueryOp::Delete => "DELETE",
        }
    }
}

impl OperationLabel for crate::indexer::types::DbWriteRef {
    fn operation_label(&self) -> &str {
        match self.operation {
            DbWriteOp::Insert => "INSERT",
            DbWriteOp::Update => "UPDATE",
            DbWriteOp::Upsert => "UPSERT",
            DbWriteOp::Delete => "DELETE",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{
        ApiEndpoint, DbWriteRef, Framework, SessionInvalidationRef, SessionInvalidationType,
        SoftDeleteColumn, SoftDeleteType, SqlQueryRef,
    };
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
            linked_repos: Vec::new(),
            scanner_overrides: Default::default(),
        }
    }

    #[test]
    fn test_no_state_changes_gives_perfect_score() {
        let config = default_config();
        let store = IndexStore::new();

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = TokenInvalidation.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_delete_query_without_invalidation_is_warning() {
        let config = default_config();
        let store = IndexStore::new();

        store.sql_query_refs.insert(
            "users".into(),
            vec![SqlQueryRef {
                table_name: "users".to_string(),
                operation: SqlQueryOp::Delete,
                has_tenant_filter: false,
                file: PathBuf::from("services/user.ts"),
                line: 42,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = TokenInvalidation.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("state change"));
    }

    #[test]
    fn test_delete_endpoint_without_invalidation_is_critical() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/users.ts");

        store.sql_query_refs.insert(
            "users".into(),
            vec![SqlQueryRef {
                table_name: "users".to_string(),
                operation: SqlQueryOp::Delete,
                has_tenant_filter: false,
                file: file.clone(),
                line: 42,
            }],
        );

        store.api_endpoints.insert(
            "/users/:id".into(),
            vec![ApiEndpoint {
                method: HttpMethod::Delete,
                path: "/users/:id".to_string(),
                file: file.clone(),
                line: 10,
                framework: Framework::Express,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = TokenInvalidation.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_state_change_with_invalidation_passes() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/users.ts");

        store.sql_query_refs.insert(
            "users".into(),
            vec![SqlQueryRef {
                table_name: "users".to_string(),
                operation: SqlQueryOp::Delete,
                has_tenant_filter: false,
                file: file.clone(),
                line: 42,
            }],
        );

        store.session_invalidation_refs.insert(
            file.clone(),
            vec![SessionInvalidationRef {
                file: file.clone(),
                line: 43,
                invalidation_type: SessionInvalidationType::JwtBlacklist,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = TokenInvalidation.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_soft_delete_update_without_invalidation_detected() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("services/archive.ts");

        store.soft_delete_columns.insert(
            "users".to_string(),
            vec![SoftDeleteColumn {
                table_name: "users".to_string(),
                column_name: "deleted_at".to_string(),
                column_type: SoftDeleteType::Timestamp,
                file: PathBuf::from("migrations/001.sql"),
                line: 5,
            }],
        );

        store.db_write_refs.insert(
            "users".into(),
            vec![DbWriteRef {
                table_name: "users".to_string(),
                operation: DbWriteOp::Update,
                file: file.clone(),
                line: 22,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = TokenInvalidation.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("state change"));
    }

    #[test]
    fn test_mixed_protected_and_unprotected() {
        let config = default_config();
        let store = IndexStore::new();

        let protected_file = PathBuf::from("routes/users.ts");
        let unprotected_file = PathBuf::from("routes/accounts.ts");

        store.sql_query_refs.insert(
            "users".into(),
            vec![SqlQueryRef {
                table_name: "users".to_string(),
                operation: SqlQueryOp::Delete,
                has_tenant_filter: false,
                file: protected_file.clone(),
                line: 42,
            }],
        );

        store
            .sql_query_refs
            .entry("accounts".into())
            .or_default()
            .push(SqlQueryRef {
                table_name: "accounts".to_string(),
                operation: SqlQueryOp::Delete,
                has_tenant_filter: false,
                file: unprotected_file.clone(),
                line: 30,
            });

        store.session_invalidation_refs.insert(
            protected_file.clone(),
            vec![SessionInvalidationRef {
                file: protected_file.clone(),
                line: 43,
                invalidation_type: SessionInvalidationType::SessionDestroy,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = TokenInvalidation.scan(&ctx);
        assert_eq!(result.score, 50);
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn test_suspend_endpoint_path_is_critical() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/admin.ts");

        store.db_write_refs.insert(
            "users".into(),
            vec![DbWriteRef {
                table_name: "users".to_string(),
                operation: DbWriteOp::Update,
                file: file.clone(),
                line: 15,
            }],
        );

        store.soft_delete_columns.insert(
            "users".to_string(),
            vec![SoftDeleteColumn {
                table_name: "users".to_string(),
                column_name: "status".to_string(),
                column_type: SoftDeleteType::Status,
                file: PathBuf::from("migrations/001.sql"),
                line: 3,
            }],
        );

        store.api_endpoints.insert(
            "/admin/users/:id/suspend".into(),
            vec![ApiEndpoint {
                method: HttpMethod::Post,
                path: "/admin/users/:id/suspend".to_string(),
                file: file.clone(),
                line: 10,
                framework: Framework::Express,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = TokenInvalidation.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_summary_no_state_changes() {
        let config = default_config();
        let store = IndexStore::new();

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = TokenInvalidation.scan(&ctx);
        assert_eq!(
            result.summary,
            "No user state change operations found to check."
        );
    }
}
