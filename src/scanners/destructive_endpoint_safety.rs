use std::collections::HashSet;
use std::path::PathBuf;

use crate::indexer::types::{DbWriteOp, HttpMethod};
use crate::scanners::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S13";
const SCANNER_NAME: &str = "DestructiveEndpointSafety";
const SCANNER_DESC: &str =
    "Detects DELETE endpoints and destructive operations lacking secondary verification (OTP/2FA)";

pub struct DestructiveEndpointSafety;

/// Tracks a destructive endpoint or file-level destructive operation.
#[derive(Debug)]
struct DestructiveTarget {
    file: PathBuf,
    line: usize,
    description: String,
}

/// Collect files that have secondary auth refs.
fn files_with_secondary_auth(ctx: &ScanContext) -> HashSet<PathBuf> {
    ctx.index
        .all_secondary_auth_refs()
        .into_iter()
        .map(|r| r.file)
        .collect()
}

/// Identify soft-delete patterns: Update operations whose table has a
/// `deleted_at`-style soft-delete column.
fn files_with_soft_deletes(ctx: &ScanContext) -> Vec<DestructiveTarget> {
    let soft_delete_tables: HashSet<String> = ctx
        .index
        .all_soft_delete_columns()
        .into_iter()
        .map(|c| c.table_name)
        .collect();

    ctx.index
        .all_db_write_refs()
        .into_iter()
        .filter(|r| r.operation == DbWriteOp::Update && soft_delete_tables.contains(&r.table_name))
        .map(|r| DestructiveTarget {
            file: r.file,
            line: r.line,
            description: format!("Soft-delete update on table '{}'", r.table_name),
        })
        .collect()
}

/// Compute score from protection ratio.
fn compute_score(protected: usize, total: usize) -> u8 {
    if total == 0 {
        return 100;
    }
    ((protected as f64 / total as f64) * 100.0).round() as u8
}

impl Scanner for DestructiveEndpointSafety {
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
        let auth_files = files_with_secondary_auth(ctx);
        let mut findings: Vec<Finding> = Vec::new();

        // Phase 1: DELETE endpoints
        let all_endpoints = ctx.index.all_api_endpoints();
        let delete_endpoints: Vec<_> = all_endpoints
            .into_iter()
            .filter(|ep| ep.method == HttpMethod::Delete)
            .collect();

        let mut destructive_targets: Vec<DestructiveTarget> = delete_endpoints
            .into_iter()
            .map(|ep| DestructiveTarget {
                file: ep.file,
                line: ep.line,
                description: format!("DELETE {}", ep.path),
            })
            .collect();

        // Phase 2: DB delete operations in files NOT already covered by a DELETE endpoint
        let endpoint_files: HashSet<PathBuf> =
            destructive_targets.iter().map(|t| t.file.clone()).collect();

        let db_delete_refs: Vec<_> = ctx
            .index
            .all_db_write_refs()
            .into_iter()
            .filter(|r| r.operation == DbWriteOp::Delete && !endpoint_files.contains(&r.file))
            .collect();

        for r in db_delete_refs {
            destructive_targets.push(DestructiveTarget {
                description: format!("DB DELETE on table '{}'", r.table_name),
                file: r.file,
                line: r.line,
            });
        }

        // Phase 3: Soft-delete operations in files not already tracked
        let covered_files: HashSet<PathBuf> =
            destructive_targets.iter().map(|t| t.file.clone()).collect();

        let soft_delete_targets = files_with_soft_deletes(ctx);
        for target in soft_delete_targets {
            if !covered_files.contains(&target.file) {
                destructive_targets.push(target);
            }
        }

        // Evaluate each target
        let total = destructive_targets.len();
        let mut protected_count: usize = 0;

        for target in &destructive_targets {
            if auth_files.contains(&target.file) {
                protected_count += 1;
                continue;
            }

            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Critical,
                    format!(
                        "DELETE endpoint lacks secondary verification (OTP/2FA): {}",
                        target.description
                    ),
                )
                .with_file(&target.file)
                .with_line(target.line)
                .with_suggestion(
                    "Add OTP or 2FA verification before executing destructive operations",
                ),
            );
        }

        let score = compute_score(protected_count, total);

        let summary = if total == 0 {
            "No destructive endpoints found to check.".to_string()
        } else {
            format!(
                "{}/{} destructive endpoints have secondary verification (score: {})",
                protected_count, total, score
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{
        ApiEndpoint, DbWriteRef, Framework, SecondaryAuthRef, SecondaryAuthType, SoftDeleteColumn,
        SoftDeleteType,
    };
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
            linked_repos: Vec::new(),
            scanner_overrides: Default::default(),
        }
    }

    fn make_delete_endpoint(path: &str, file: &str, line: usize) -> ApiEndpoint {
        ApiEndpoint {
            method: HttpMethod::Delete,
            path: path.to_string(),
            file: PathBuf::from(file),
            line,
            framework: Framework::Express,
        }
    }

    fn make_secondary_auth(file: &str, line: usize) -> SecondaryAuthRef {
        SecondaryAuthRef {
            file: PathBuf::from(file),
            line,
            auth_type: SecondaryAuthType::Otp,
            near_endpoint: None,
        }
    }

    #[test]
    fn test_no_destructive_endpoints_gives_perfect_score() {
        let config = default_config();
        let store = IndexStore::new();

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DestructiveEndpointSafety.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_unprotected_delete_is_critical() {
        let config = default_config();
        let store = IndexStore::new();

        store.api_endpoints.insert(
            "/users/:id".into(),
            vec![make_delete_endpoint("/users/:id", "routes/users.ts", 20)],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DestructiveEndpointSafety.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].message.contains("DELETE"));
    }

    #[test]
    fn test_protected_delete_passes() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/users.ts");

        store.api_endpoints.insert(
            "/users/:id".into(),
            vec![make_delete_endpoint("/users/:id", "routes/users.ts", 20)],
        );

        store
            .secondary_auth_refs
            .insert(file, vec![make_secondary_auth("routes/users.ts", 18)]);

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DestructiveEndpointSafety.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_mixed_protected_and_unprotected() {
        let config = default_config();
        let store = IndexStore::new();

        store.api_endpoints.insert(
            "/users/:id".into(),
            vec![make_delete_endpoint("/users/:id", "routes/users.ts", 20)],
        );
        store.api_endpoints.insert(
            "/posts/:id".into(),
            vec![make_delete_endpoint("/posts/:id", "routes/posts.ts", 15)],
        );

        store.secondary_auth_refs.insert(
            PathBuf::from("routes/users.ts"),
            vec![make_secondary_auth("routes/users.ts", 18)],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DestructiveEndpointSafety.scan(&ctx);
        assert_eq!(result.score, 50);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("DELETE /posts/:id"));
    }

    #[test]
    fn test_db_delete_without_endpoint_is_detected() {
        let config = default_config();
        let store = IndexStore::new();

        let file = "services/cleanup.ts";

        store.db_write_refs.insert(
            "sessions".into(),
            vec![DbWriteRef {
                table_name: "sessions".to_string(),
                operation: DbWriteOp::Delete,
                file: PathBuf::from(file),
                line: 30,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DestructiveEndpointSafety.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("DB DELETE"));
    }

    #[test]
    fn test_soft_delete_without_protection_is_detected() {
        let config = default_config();
        let store = IndexStore::new();

        let file = "services/archive.ts";

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
                file: PathBuf::from(file),
                line: 22,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DestructiveEndpointSafety.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("Soft-delete"));
    }

    #[test]
    fn test_get_endpoint_is_not_flagged() {
        let config = default_config();
        let store = IndexStore::new();

        store.api_endpoints.insert(
            "/users".into(),
            vec![ApiEndpoint {
                method: HttpMethod::Get,
                path: "/users".to_string(),
                file: PathBuf::from("routes/users.ts"),
                line: 5,
                framework: Framework::Express,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DestructiveEndpointSafety.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_summary_format_with_findings() {
        let config = default_config();
        let store = IndexStore::new();

        store.api_endpoints.insert(
            "/users/:id".into(),
            vec![make_delete_endpoint("/users/:id", "routes/users.ts", 20)],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DestructiveEndpointSafety.scan(&ctx);
        assert!(result.summary.contains("0/1"));
        assert!(result.summary.contains("score: 0"));
    }

    #[test]
    fn test_summary_format_no_destructive() {
        let config = default_config();
        let store = IndexStore::new();

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DestructiveEndpointSafety.scan(&ctx);
        assert_eq!(result.summary, "No destructive endpoints found to check.");
    }
}
