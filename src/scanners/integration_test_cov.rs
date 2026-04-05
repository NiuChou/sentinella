use crate::scanners::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S8";
const SCANNER_NAME: &str = "IntegrationTestCoverage";
const SCANNER_DESC: &str =
    "Checks that database tables have integration tests with read/write/assert coverage and RLS alignment.";

pub struct IntegrationTestCoverage;

fn table_matches_exclude(table_name: &str, exclude_patterns: &[String]) -> bool {
    exclude_patterns
        .iter()
        .any(|pattern| table_name == pattern || table_name.contains(pattern.as_str()))
}

struct TableTestResult {
    has_test: bool,
    has_write: bool,
    has_read: bool,
    has_assert: bool,
}

impl TableTestResult {
    fn completeness_weight(&self) -> f64 {
        if !self.has_test {
            return 0.0;
        }

        let mut weight = 0.25_f64; // base weight for having any test
        if self.has_write {
            weight += 0.25;
        }
        if self.has_read {
            weight += 0.25;
        }
        if self.has_assert {
            weight += 0.25;
        }

        weight
    }
}

impl Scanner for IntegrationTestCoverage {
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
        let test_config = &ctx.config.integration_tests;

        if !test_config.enabled {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "Integration test scanning is disabled.".to_string(),
            };
        }

        let store = ctx.index;

        // Collect non-excluded tables
        let tables: Vec<_> = store
            .db_tables
            .iter()
            .filter(|entry| {
                !table_matches_exclude(&entry.value().table_name, &test_config.exclude_tables)
            })
            .map(|entry| {
                let info = entry.value().clone();
                (entry.key().clone(), info)
            })
            .collect();

        if tables.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No database tables found to check.".to_string(),
            };
        }

        // Collect all test files once
        let test_files: Vec<_> = store
            .test_files
            .iter()
            .map(|entry| entry.value().clone())
            .collect();

        let mut findings: Vec<Finding> = Vec::new();
        let mut table_results: Vec<TableTestResult> = Vec::new();

        for (_key, table_info) in &tables {
            let table_name = &table_info.table_name;

            // Find test files covering this table
            let covering_tests: Vec<_> = test_files
                .iter()
                .filter(|tf| tf.tables_tested.iter().any(|t| t == table_name))
                .collect();

            let has_test = !covering_tests.is_empty();
            let has_write = covering_tests.iter().any(|tf| tf.has_write);
            let has_read = covering_tests.iter().any(|tf| tf.has_read);
            let has_assert = covering_tests.iter().any(|tf| tf.has_assert);
            let has_rls = table_info.has_rls;

            // RLS alignment check: if the table has RLS and there is a test,
            // verify the test exercises the RLS path (via middleware protection)
            // rather than just using raw WHERE clauses.
            let rls_tested = if has_rls && has_test {
                covering_tests
                    .iter()
                    .any(|tf| store.has_middleware_protection(&tf.path, 0))
            } else {
                true // no RLS or no test => skip this check
            };

            if !has_test {
                findings.push(
                    Finding::new(
                        SCANNER_ID,
                        Severity::Warning,
                        format!("Table '{}' has no integration test coverage", table_name),
                    )
                    .with_suggestion(format!(
                        "Add an integration test that exercises reads, writes, and assertions for '{}'.",
                        table_name
                    )),
                );
            } else {
                if !has_write {
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Info,
                            format!(
                                "Table '{}' integration test has no write operations",
                                table_name
                            ),
                        )
                        .with_suggestion(format!(
                            "Add INSERT/UPDATE/DELETE operations to the test for '{}'.",
                            table_name
                        )),
                    );
                }

                if !has_read {
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Info,
                            format!(
                                "Table '{}' integration test has no read operations",
                                table_name
                            ),
                        )
                        .with_suggestion(format!(
                            "Add SELECT/query operations to the test for '{}'.",
                            table_name
                        )),
                    );
                }

                if !has_assert {
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Warning,
                            format!(
                                "Table '{}' integration test has no assertions",
                                table_name
                            ),
                        )
                        .with_suggestion(format!(
                            "Add assertions to verify the behavior of operations on '{}'.",
                            table_name
                        )),
                    );
                }

                if has_rls && !rls_tested {
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Critical,
                            format!(
                                "Table '{}' has RLS enabled but integration test does not verify the RLS path",
                                table_name
                            ),
                        )
                        .with_suggestion(format!(
                            "Test '{}' through the authenticated API path so RLS policies are exercised, not just raw SQL with WHERE.",
                            table_name
                        )),
                    );
                }
            }

            table_results.push(TableTestResult {
                has_test,
                has_write,
                has_read,
                has_assert,
            });
        }

        // Score: weighted by test completeness per table
        let total_tables = table_results.len() as f64;
        let weighted_sum: f64 = table_results.iter().map(|r| r.completeness_weight()).sum();
        let score = ((weighted_sum / total_tables) * 100.0).round() as u8;

        let covered = table_results.iter().filter(|r| r.has_test).count();
        let summary = format!(
            "{}/{} tables have integration tests. Weighted score: {}%.",
            covered,
            table_results.len(),
            score
        );

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
    use crate::indexer::types::{TableInfo, TestFileInfo};
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
        config.integration_tests.enabled = false;
        let store = IndexStore::new();

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = IntegrationTestCoverage.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_no_tables_gives_perfect_score() {
        let config = default_config();
        let store = IndexStore::new();

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = IntegrationTestCoverage.scan(&ctx);
        assert_eq!(result.score, 100);
    }

    #[test]
    fn test_untested_table_is_warning() {
        let config = default_config();
        let store = IndexStore::new();

        store.db_tables.insert(
            "users".into(),
            TableInfo {
                schema_name: Some("public".into()),
                table_name: "users".into(),
                has_rls: false,
                app_role: None,
            },
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = IntegrationTestCoverage.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_fully_covered_table() {
        let config = default_config();
        let store = IndexStore::new();

        store.db_tables.insert(
            "users".into(),
            TableInfo {
                schema_name: Some("public".into()),
                table_name: "users".into(),
                has_rls: false,
                app_role: None,
            },
        );

        store.test_files.insert(
            PathBuf::from("tests/integration/users.test.ts"),
            TestFileInfo {
                path: PathBuf::from("tests/integration/users.test.ts"),
                tables_tested: vec!["users".into()],
                has_write: true,
                has_read: true,
                has_assert: true,
            },
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = IntegrationTestCoverage.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_rls_table_without_rls_test_is_critical() {
        let config = default_config();
        let store = IndexStore::new();

        store.db_tables.insert(
            "orders".into(),
            TableInfo {
                schema_name: Some("public".into()),
                table_name: "orders".into(),
                has_rls: true,
                app_role: Some("app_user".into()),
            },
        );

        store.test_files.insert(
            PathBuf::from("tests/integration/orders.test.ts"),
            TestFileInfo {
                path: PathBuf::from("tests/integration/orders.test.ts"),
                tables_tested: vec!["orders".into()],
                has_write: true,
                has_read: true,
                has_assert: true,
            },
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = IntegrationTestCoverage.scan(&ctx);
        let critical_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .collect();
        assert_eq!(critical_findings.len(), 1);
        assert!(critical_findings[0].message.contains("RLS"));
    }

    #[test]
    fn test_excluded_tables_are_skipped() {
        let mut config = default_config();
        config.integration_tests.exclude_tables = vec!["_prisma_migrations".into()];
        let store = IndexStore::new();

        store.db_tables.insert(
            "_prisma_migrations".into(),
            TableInfo {
                schema_name: Some("public".into()),
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

        let result = IntegrationTestCoverage.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_partial_coverage_weighted_score() {
        let config = default_config();
        let store = IndexStore::new();

        store.db_tables.insert(
            "users".into(),
            TableInfo {
                schema_name: Some("public".into()),
                table_name: "users".into(),
                has_rls: false,
                app_role: None,
            },
        );

        // Test file with only reads, no writes or asserts
        store.test_files.insert(
            PathBuf::from("tests/integration/users.test.ts"),
            TestFileInfo {
                path: PathBuf::from("tests/integration/users.test.ts"),
                tables_tested: vec!["users".into()],
                has_write: false,
                has_read: true,
                has_assert: false,
            },
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = IntegrationTestCoverage.scan(&ctx);
        // 0.25 (base) + 0.25 (read) = 0.50 => 50%
        assert_eq!(result.score, 50);
    }

    #[test]
    fn test_multiple_tables_mixed_coverage() {
        let config = default_config();
        let store = IndexStore::new();

        store.db_tables.insert(
            "users".into(),
            TableInfo {
                schema_name: Some("public".into()),
                table_name: "users".into(),
                has_rls: false,
                app_role: None,
            },
        );
        store.db_tables.insert(
            "posts".into(),
            TableInfo {
                schema_name: Some("public".into()),
                table_name: "posts".into(),
                has_rls: false,
                app_role: None,
            },
        );

        // Only users has a test (full coverage)
        store.test_files.insert(
            PathBuf::from("tests/integration/users.test.ts"),
            TestFileInfo {
                path: PathBuf::from("tests/integration/users.test.ts"),
                tables_tested: vec!["users".into()],
                has_write: true,
                has_read: true,
                has_assert: true,
            },
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = IntegrationTestCoverage.scan(&ctx);
        // users: 1.0, posts: 0.0 => average 0.5 => 50%
        assert_eq!(result.score, 50);
    }
}
