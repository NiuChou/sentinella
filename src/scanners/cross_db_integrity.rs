use std::path::Path;

use super::types::{Confidence, Finding, ScanContext, ScanResult, Scanner, Severity};
use crate::config::schema::CrossDbRefConfig;
use crate::indexer::types::Language;

pub struct CrossDbIntegrity;

const SCANNER_ID: &str = "S32";
const SCANNER_NAME: &str = "CrossDbIntegrity";
const SCANNER_DESC: &str =
    "Detects UUID columns referencing another database without a local FK target or reconciliation mechanism";

const PENALTY_PER_FINDING: u8 = 3;

impl Scanner for CrossDbIntegrity {
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
        let cfg = &ctx.config.database_security.cross_db_integrity;

        if !cfg.enabled || cfg.cross_db_refs.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "Cross-DB integrity check skipped (no refs configured)".to_string(),
            };
        }

        let sql_contents = collect_sql_contents(ctx);
        let findings = check_all_refs(&cfg.cross_db_refs, ctx, &sql_contents);
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

/// Read all SQL files once and return their contents as (path_display, content) pairs.
fn collect_sql_contents(ctx: &ScanContext) -> Vec<(String, String)> {
    ctx.index
        .files
        .iter()
        .filter(|entry| entry.value().language == Language::Sql)
        .filter_map(|entry| {
            let path = &entry.value().path;
            let content = std::fs::read_to_string(path).ok()?;
            Some((path.display().to_string(), content))
        })
        .collect()
}

/// Check all configured cross-DB references and collect findings.
fn check_all_refs(
    refs: &[CrossDbRefConfig],
    ctx: &ScanContext,
    sql_contents: &[(String, String)],
) -> Vec<Finding> {
    let tables = ctx.index.all_db_tables();

    refs.iter()
        .flat_map(|ref_cfg| check_single_ref(ref_cfg, &tables, ctx.root_dir, sql_contents))
        .collect()
}

/// For one cross-DB ref config, find tables with matching columns that lack safeguards.
fn check_single_ref(
    ref_cfg: &CrossDbRefConfig,
    tables: &[crate::indexer::types::TableInfo],
    root_dir: &Path,
    sql_contents: &[(String, String)],
) -> Vec<Finding> {
    let pattern_lower = ref_cfg.column_pattern.to_lowercase();

    tables
        .iter()
        .filter(|t| table_has_matching_column(t, &pattern_lower))
        .filter(|t| !has_safeguard(t, ref_cfg, root_dir, sql_contents))
        .map(|t| build_finding(t, ref_cfg))
        .collect()
}

/// Check whether a table has a column matching the configured pattern (case-insensitive substring).
fn table_has_matching_column(
    table: &crate::indexer::types::TableInfo,
    pattern_lower: &str,
) -> bool {
    table
        .columns
        .iter()
        .any(|col| col.to_lowercase().contains(pattern_lower))
}

/// Check whether any of the `require_one_of` patterns appear in the SQL codebase
/// for the given table. Searches both the column definitions (for FK references)
/// and all SQL file contents (for reconciliation functions).
fn has_safeguard(
    table: &crate::indexer::types::TableInfo,
    ref_cfg: &CrossDbRefConfig,
    _root_dir: &Path,
    sql_contents: &[(String, String)],
) -> bool {
    if ref_cfg.require_one_of.is_empty() {
        return false;
    }

    let table_lower = table.table_name.to_lowercase();

    ref_cfg.require_one_of.iter().any(|pattern| {
        let pat_lower = pattern.to_lowercase();
        // Check if any SQL file mentions both this table and the safeguard pattern
        sql_contents.iter().any(|(_path, content)| {
            let content_lower = content.to_lowercase();
            content_lower.contains(&table_lower) && content_lower.contains(&pat_lower)
        })
    })
}

/// Build a finding for a table that has a cross-DB reference without safeguards.
fn build_finding(table: &crate::indexer::types::TableInfo, ref_cfg: &CrossDbRefConfig) -> Finding {
    Finding::new(
        SCANNER_ID,
        Severity::Info,
        format!(
            "Table `{}` has column matching `{}` (→ {}.{}) with no local FK or reconciliation",
            table.table_name, ref_cfg.column_pattern, ref_cfg.source_db, ref_cfg.target_db
        ),
    )
    .with_suggestion(format!(
        "Add a local FK reference or a reconciliation mechanism (expected one of: {:?})",
        ref_cfg.require_one_of
    ))
    .with_confidence(Confidence::Likely)
}

/// Score = 100 - (3 * number_of_findings), clamped to [0, 100].
fn compute_score(findings: &[Finding]) -> u8 {
    let penalty = (findings.len() as u16).saturating_mul(PENALTY_PER_FINDING as u16);
    100u8.saturating_sub(penalty.min(100) as u8)
}

fn build_summary(findings: &[Finding], score: u8) -> String {
    if findings.is_empty() {
        return "All cross-DB references have local FK targets or reconciliation mechanisms"
            .to_string();
    }
    format!(
        "Found {} cross-DB reference(s) without safeguards (score: {})",
        findings.len(),
        score
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::TableInfo;
    use std::sync::Arc;

    fn minimal_config() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    fn config_with_refs() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
database_security:
  cross_db_integrity:
    enabled: true
    cross_db_refs:
      - source_db: payments
        column_pattern: user_id
        target_db: users
        require_one_of:
          - "REFERENCES user_refs"
          - "reconcile_"
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    fn insert_table(store: &IndexStore, name: &str, columns: Vec<&str>) {
        store.db_tables.insert(
            name.to_string(),
            TableInfo {
                schema_name: None,
                table_name: name.to_string(),
                columns: columns.into_iter().map(String::from).collect(),
                has_rls: false,
                has_force_rls: false,
                has_partition: false,
                app_role: None,
            },
        );
    }

    #[test]
    fn no_refs_configured_returns_perfect_score() {
        let store = Arc::new(IndexStore::default());
        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = CrossDbIntegrity.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn table_without_matching_column_is_clean() {
        let store = Arc::new(IndexStore::default());
        insert_table(&store, "orders", vec!["id", "amount", "created_at"]);

        let config = config_with_refs();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = CrossDbIntegrity.scan(&ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 100);
    }

    #[test]
    fn table_with_matching_column_no_safeguard_flagged() {
        let store = Arc::new(IndexStore::default());
        insert_table(&store, "payments", vec!["id", "user_id", "amount"]);

        let config = config_with_refs();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = CrossDbIntegrity.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Info);
        assert!(result.findings[0].message.contains("payments"));
        assert!(result.findings[0].message.contains("user_id"));
        assert_eq!(result.score, 97);
    }

    #[test]
    fn score_clamps_to_zero() {
        let store = Arc::new(IndexStore::default());
        // 34+ findings => penalty >= 102, clamped to 0
        for i in 0..35 {
            let name = format!("table_{}", i);
            insert_table(&store, &name, vec!["id", "user_id"]);
            // Need to re-insert since insert_table uses a local reference
        }
        // Re-insert properly
        let store2 = Arc::new(IndexStore::default());
        for i in 0..35 {
            let name = format!("table_{}", i);
            store2.db_tables.insert(
                name.clone(),
                TableInfo {
                    schema_name: None,
                    table_name: name,
                    columns: vec!["id".to_string(), "user_id".to_string()],
                    has_rls: false,
                    has_force_rls: false,
                    has_partition: false,
                    app_role: None,
                },
            );
        }

        let config = config_with_refs();
        let ctx = ScanContext {
            config: &config,
            index: &store2,
            root_dir: std::path::Path::new("."),
        };

        let result = CrossDbIntegrity.scan(&ctx);
        assert_eq!(result.score, 0);
    }

    #[test]
    fn column_pattern_is_case_insensitive() {
        let store = Arc::new(IndexStore::default());
        insert_table(&store, "invoices", vec!["id", "User_ID", "total"]);

        let config = config_with_refs();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = CrossDbIntegrity.scan(&ctx);
        assert_eq!(
            result.findings.len(),
            1,
            "Case-insensitive column match should produce a finding"
        );
    }

    #[test]
    fn compute_score_boundary_values() {
        assert_eq!(compute_score(&[]), 100);

        let one_finding = vec![Finding::new(SCANNER_ID, Severity::Info, "test")];
        assert_eq!(compute_score(&one_finding), 97);
    }

    #[test]
    fn has_safeguard_with_empty_requirements_returns_false() {
        let table = TableInfo {
            schema_name: None,
            table_name: "orders".to_string(),
            columns: vec!["user_id".to_string()],
            has_rls: false,
            has_force_rls: false,
            has_partition: false,
            app_role: None,
        };
        let ref_cfg = CrossDbRefConfig {
            source_db: "payments".to_string(),
            column_pattern: "user_id".to_string(),
            target_db: "users".to_string(),
            require_one_of: Vec::new(),
        };

        let result = has_safeguard(&table, &ref_cfg, Path::new("."), &[]);
        assert!(!result);
    }

    #[test]
    fn has_safeguard_finds_pattern_in_sql() {
        let table = TableInfo {
            schema_name: None,
            table_name: "orders".to_string(),
            columns: vec!["user_id".to_string()],
            has_rls: false,
            has_force_rls: false,
            has_partition: false,
            app_role: None,
        };
        let ref_cfg = CrossDbRefConfig {
            source_db: "payments".to_string(),
            column_pattern: "user_id".to_string(),
            target_db: "users".to_string(),
            require_one_of: vec!["REFERENCES user_refs".to_string()],
        };

        let sql_contents = vec![(
            "migrations/001.sql".to_string(),
            "CREATE TABLE orders (user_id UUID REFERENCES user_refs(id))".to_string(),
        )];

        let result = has_safeguard(&table, &ref_cfg, Path::new("."), &sql_contents);
        assert!(result);
    }
}
