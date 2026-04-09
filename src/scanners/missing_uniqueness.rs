use std::collections::HashSet;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

pub struct MissingUniqueness;

const SCANNER_ID: &str = "S24";
const SCANNER_NAME: &str = "MissingUniqueness";
const SCANNER_DESC: &str =
    "Detects columns used in WHERE equality lookups that lack a UNIQUE constraint";

/// Columns commonly used in WHERE clauses that do not require uniqueness.
const COMMON_COLUMNS: &[&str] = &[
    "id",
    "created_at",
    "updated_at",
    "deleted_at",
    "status",
    "is_active",
    "type",
    "name",
    "email",
];

impl Scanner for MissingUniqueness {
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
        let findings = find_missing_uniqueness(ctx);
        let score = compute_score(&findings, ctx);
        let summary = build_summary(&findings, score);

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

fn find_missing_uniqueness(ctx: &ScanContext) -> Vec<Finding> {
    let unique_refs = ctx.index.all_unique_constraint_refs();
    let lookup_refs = ctx.index.all_column_lookup_refs();

    if lookup_refs.is_empty() {
        return Vec::new();
    }

    let unique_set: HashSet<(String, String)> = unique_refs
        .iter()
        .map(|r| (r.table_name.to_lowercase(), r.column_name.to_lowercase()))
        .collect();

    let mut findings = Vec::new();

    for lookup in &lookup_refs {
        let col_lower = lookup.column_name.to_lowercase();

        if is_common_column(&col_lower) {
            continue;
        }

        let key = (lookup.table_name.to_lowercase(), col_lower);

        if !unique_set.contains(&key) {
            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Warning,
                    format!(
                        "Column `{}`.`{}` is used in a WHERE equality lookup but has no UNIQUE constraint — may cause ambiguous matching",
                        lookup.table_name, lookup.column_name
                    ),
                )
                .with_file(&lookup.file)
                .with_line(lookup.line)
                .with_suggestion(format!(
                    "Add a UNIQUE constraint or index on `{}`.`{}`",
                    lookup.table_name, lookup.column_name
                )),
            );
        }
    }

    findings
}

fn is_common_column(column: &str) -> bool {
    COMMON_COLUMNS.contains(&column)
}

fn compute_score(findings: &[Finding], ctx: &ScanContext) -> u8 {
    let lookups = ctx.index.all_column_lookup_refs();

    // Only count non-common-column lookups (same filter as find_missing_uniqueness)
    let relevant: Vec<_> = lookups
        .iter()
        .filter(|l| !is_common_column(&l.column_name.to_lowercase()))
        .collect();

    if relevant.is_empty() {
        return 100;
    }

    let total = relevant.len();
    let unconstrained = findings.len();
    let constrained = total.saturating_sub(unconstrained);

    let raw = (constrained as f64 / total as f64 * 100.0).round() as u8;
    raw.min(100)
}

fn build_summary(findings: &[Finding], score: u8) -> String {
    if findings.is_empty() {
        return "All WHERE equality lookup columns have UNIQUE constraints".to_string();
    }
    format!(
        "Found {} column(s) used in WHERE equality lookups without UNIQUE constraints (score: {})",
        findings.len(),
        score
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{ColumnLookupRef, UniqueConstraintRef};
    use std::path::PathBuf;

    fn minimal_config() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    fn make_lookup(table: &str, column: &str, file: &str, line: usize) -> ColumnLookupRef {
        ColumnLookupRef {
            table_name: table.to_string(),
            column_name: column.to_string(),
            file: PathBuf::from(file),
            line,
        }
    }

    fn make_unique(table: &str, column: &str, file: &str, line: usize) -> UniqueConstraintRef {
        UniqueConstraintRef {
            table_name: table.to_string(),
            column_name: column.to_string(),
            file: PathBuf::from(file),
            line,
        }
    }

    #[test]
    fn no_lookups_perfect_score() {
        let store = IndexStore::new();
        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = MissingUniqueness.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
        assert_eq!(
            result.summary,
            "All WHERE equality lookup columns have UNIQUE constraints"
        );
    }

    #[test]
    fn lookup_without_unique() {
        let store = IndexStore::new();
        store.data.column_lookup_refs.insert(
            "users.wecom_userid".to_string(),
            vec![make_lookup("users", "wecom_userid", "src/repo/user.ts", 42)],
        );

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = MissingUniqueness.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("wecom_userid"));
        assert!(result.findings[0].message.contains("no UNIQUE constraint"));
        assert_eq!(result.score, 0);
    }

    #[test]
    fn lookup_with_unique_constraint() {
        let store = IndexStore::new();
        store.data.column_lookup_refs.insert(
            "users.github_id".to_string(),
            vec![make_lookup("users", "github_id", "src/repo/user.ts", 30)],
        );
        store.data.unique_constraint_refs.insert(
            "users.github_id".to_string(),
            vec![make_unique(
                "users",
                "github_id",
                "migrations/001_users.sql",
                5,
            )],
        );

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = MissingUniqueness.scan(&ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 100);
    }

    #[test]
    fn common_columns_excluded() {
        let store = IndexStore::new();

        // Add lookups for common columns that should be skipped
        for col in &["id", "created_at", "status", "email", "type", "name"] {
            store.data.column_lookup_refs.insert(
                format!("users.{}", col),
                vec![make_lookup("users", col, "src/repo/user.ts", 10)],
            );
        }

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = MissingUniqueness.scan(&ctx);
        assert!(
            result.findings.is_empty(),
            "Common columns should not produce findings"
        );
    }

    #[test]
    fn mixed_constrained_and_unconstrained() {
        let store = IndexStore::new();

        // Constrained lookup
        store.data.column_lookup_refs.insert(
            "users.github_id".to_string(),
            vec![make_lookup("users", "github_id", "src/repo/user.ts", 30)],
        );
        store.data.unique_constraint_refs.insert(
            "users.github_id".to_string(),
            vec![make_unique(
                "users",
                "github_id",
                "migrations/001_users.sql",
                5,
            )],
        );

        // Unconstrained lookup
        store.data.column_lookup_refs.insert(
            "users.oauth_id".to_string(),
            vec![make_lookup("users", "oauth_id", "src/repo/oauth.ts", 15)],
        );

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = MissingUniqueness.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("oauth_id"));
        // 1 constrained out of 2 total = 50%
        assert_eq!(result.score, 50);
    }

    #[test]
    fn case_insensitive_matching() {
        let store = IndexStore::new();
        store.data.column_lookup_refs.insert(
            "Users.WecomUserID".to_string(),
            vec![make_lookup("Users", "WecomUserID", "src/repo/user.ts", 42)],
        );
        store.data.unique_constraint_refs.insert(
            "users.wecomuserid".to_string(),
            vec![make_unique(
                "users",
                "wecomuserid",
                "migrations/001_users.sql",
                5,
            )],
        );

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = MissingUniqueness.scan(&ctx);
        assert!(
            result.findings.is_empty(),
            "Case-insensitive match should recognize the UNIQUE constraint"
        );
    }
}
