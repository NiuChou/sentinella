use std::path::PathBuf;

use crate::indexer::types::{Language, TableInfo};
use crate::scanners::types::{
    Confidence, Finding, ScanContext, ScanResult, Scanner, Severity,
};

const SCANNER_ID: &str = "S33";
const SCANNER_NAME: &str = "AppendOnlyLifecycle";
const SCANNER_DESC: &str =
    "Detects high-volume append-only tables that lack an archive, partition, or cleanup strategy";
const PENALTY_PER_FINDING: f64 = 8.0;

pub struct AppendOnlyLifecycle;

impl Scanner for AppendOnlyLifecycle {
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
        let cfg = &ctx.config.database_security.append_only_lifecycle;

        if !cfg.enabled || cfg.high_volume_tables.is_empty() {
            return empty_result();
        }

        let all_tables = ctx.index.all_db_tables();
        let sql_contents = collect_sql_file_contents(ctx);
        let findings = evaluate_tables(&cfg.high_volume_tables, &cfg.lifecycle_markers, &all_tables, &sql_contents);
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
// Helpers
// ---------------------------------------------------------------------------

fn empty_result() -> ScanResult {
    ScanResult {
        scanner: SCANNER_ID.to_string(),
        findings: Vec::new(),
        score: 100,
        summary: "No high-volume tables configured — nothing to check.".to_string(),
    }
}

/// Collect the contents of all SQL files from the index, reading each once.
fn collect_sql_file_contents(ctx: &ScanContext) -> Vec<(PathBuf, String)> {
    ctx.index
        .files
        .iter()
        .filter(|entry| entry.value().language == Language::Sql)
        .filter_map(|entry| {
            let path = entry.value().path.clone();
            let abs_path = if path.is_absolute() {
                path.clone()
            } else {
                ctx.root_dir.join(&path)
            };
            std::fs::read_to_string(&abs_path)
                .ok()
                .map(|content| (path, content))
        })
        .collect()
}

/// Evaluate each high-volume table and produce findings for those missing a lifecycle strategy.
fn evaluate_tables(
    high_volume_tables: &[String],
    lifecycle_markers: &[String],
    all_tables: &[TableInfo],
    sql_contents: &[(PathBuf, String)],
) -> Vec<Finding> {
    high_volume_tables
        .iter()
        .filter(|table_name| !has_lifecycle_strategy(table_name, all_tables, lifecycle_markers, sql_contents))
        .map(|table_name| build_finding(table_name))
        .collect()
}

/// Check whether the table satisfies at least one lifecycle strategy.
fn has_lifecycle_strategy(
    table_name: &str,
    all_tables: &[TableInfo],
    lifecycle_markers: &[String],
    sql_contents: &[(PathBuf, String)],
) -> bool {
    has_partition(table_name, all_tables) || has_marker_in_sql(table_name, lifecycle_markers, sql_contents)
}

/// Check if the table's `TableInfo` has partitioning enabled.
fn has_partition(table_name: &str, all_tables: &[TableInfo]) -> bool {
    all_tables
        .iter()
        .any(|t| t.table_name == table_name && t.has_partition)
}

/// Check if any SQL file mentions both the table name and at least one lifecycle marker.
fn has_marker_in_sql(
    table_name: &str,
    lifecycle_markers: &[String],
    sql_contents: &[(PathBuf, String)],
) -> bool {
    let table_lower = table_name.to_lowercase();
    sql_contents.iter().any(|(_path, content)| {
        let content_lower = content.to_lowercase();
        content_lower.contains(&table_lower)
            && lifecycle_markers
                .iter()
                .any(|marker| content_lower.contains(&marker.to_lowercase()))
    })
}

fn build_finding(table_name: &str) -> Finding {
    Finding::new(
        SCANNER_ID,
        Severity::Warning,
        format!(
            "High-volume table '{}' has no archive, partition, or cleanup strategy",
            table_name,
        ),
    )
    .with_suggestion(format!(
        "Add a lifecycle strategy for '{}': partitioning (PARTITION BY), \
         an archive table (archive_{}), or pg_partman configuration.",
        table_name, table_name,
    ))
    .with_confidence(Confidence::Likely)
}

// ---------------------------------------------------------------------------
// Scoring & Summary
// ---------------------------------------------------------------------------

fn compute_score(findings: &[Finding]) -> u8 {
    let deductions = findings.len() as f64 * PENALTY_PER_FINDING;
    let score = (100.0 - deductions).max(0.0);
    (score.round() as u8).min(100)
}

fn build_summary(findings: &[Finding], score: u8) -> String {
    if findings.is_empty() {
        return "All high-volume tables have a lifecycle strategy.".to_string();
    }

    let table_names: Vec<&str> = findings
        .iter()
        .filter_map(|f| extract_table_name_from_message(&f.message))
        .collect();

    format!(
        "{} table(s) missing lifecycle strategy ({}). Score: {}%.",
        findings.len(),
        table_names.join(", "),
        score,
    )
}

/// Extract the table name from the finding message pattern "High-volume table 'X' has no ...".
fn extract_table_name_from_message(msg: &str) -> Option<&str> {
    let start = msg.find('\'')?;
    let end = msg[start + 1..].find('\'')?;
    Some(&msg[start + 1..start + 1 + end])
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
    use std::sync::Arc;

    fn default_config() -> Config {
        serde_yaml::from_str("version: '1.0'\nproject: test\n").unwrap()
    }

    fn make_ctx<'a>(
        config: &'a Config,
        store: &'a Arc<IndexStore>,
        root: &'a Path,
    ) -> ScanContext<'a> {
        ScanContext {
            config,
            index: store,
            root_dir: root,
        }
    }

    #[test]
    fn test_empty_high_volume_tables_gives_perfect_score() {
        let config = default_config();
        let store = Arc::new(IndexStore::new());
        let ctx = make_ctx(&config, &store, Path::new("/tmp"));
        let result = AppendOnlyLifecycle.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_table_with_partition_is_satisfied() {
        let mut config = default_config();
        config
            .database_security
            .append_only_lifecycle
            .high_volume_tables = vec!["events".into()];

        let store = Arc::new(IndexStore::new());
        store.db_tables.insert(
            "events".into(),
            TableInfo {
                table_name: "events".into(),
                has_partition: true,
                ..Default::default()
            },
        );

        let ctx = make_ctx(&config, &store, Path::new("/tmp"));
        let result = AppendOnlyLifecycle.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_table_without_strategy_produces_finding() {
        let mut config = default_config();
        config
            .database_security
            .append_only_lifecycle
            .high_volume_tables = vec!["audit_logs".into()];

        let store = Arc::new(IndexStore::new());
        store.db_tables.insert(
            "audit_logs".into(),
            TableInfo {
                table_name: "audit_logs".into(),
                has_partition: false,
                ..Default::default()
            },
        );

        let ctx = make_ctx(&config, &store, Path::new("/tmp"));
        let result = AppendOnlyLifecycle.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("audit_logs"));
        assert_eq!(result.score, 92);
    }

    #[test]
    fn test_multiple_tables_missing_strategy() {
        let mut config = default_config();
        config
            .database_security
            .append_only_lifecycle
            .high_volume_tables = vec![
            "events".into(),
            "audit_logs".into(),
            "notifications".into(),
        ];

        let store = Arc::new(IndexStore::new());
        for name in &["events", "audit_logs", "notifications"] {
            store.db_tables.insert(
                (*name).into(),
                TableInfo {
                    table_name: (*name).into(),
                    has_partition: false,
                    ..Default::default()
                },
            );
        }

        let ctx = make_ctx(&config, &store, Path::new("/tmp"));
        let result = AppendOnlyLifecycle.scan(&ctx);
        assert_eq!(result.findings.len(), 3);
        // 100 - 3*8 = 76
        assert_eq!(result.score, 76);
    }

    #[test]
    fn test_scoring_floors_at_zero() {
        let findings: Vec<Finding> = (0..20)
            .map(|i| build_finding(&format!("table_{}", i)))
            .collect();
        assert_eq!(compute_score(&findings), 0);
    }

    #[test]
    fn test_disabled_scanner_gives_perfect_score() {
        let mut config = default_config();
        config.database_security.append_only_lifecycle.enabled = false;
        config
            .database_security
            .append_only_lifecycle
            .high_volume_tables = vec!["events".into()];

        let store = Arc::new(IndexStore::new());
        let ctx = make_ctx(&config, &store, Path::new("/tmp"));
        let result = AppendOnlyLifecycle.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_extract_table_name_from_message() {
        let msg = "High-volume table 'events' has no archive, partition, or cleanup strategy";
        assert_eq!(extract_table_name_from_message(msg), Some("events"));
    }

    #[test]
    fn test_summary_with_findings() {
        let findings = vec![
            build_finding("events"),
            build_finding("audit_logs"),
        ];
        let summary = build_summary(&findings, 84);
        assert!(summary.contains("2 table(s)"));
        assert!(summary.contains("events"));
        assert!(summary.contains("audit_logs"));
        assert!(summary.contains("84%"));
    }

    #[test]
    fn test_summary_no_findings() {
        let summary = build_summary(&[], 100);
        assert!(summary.contains("All high-volume tables have a lifecycle strategy"));
    }
}
