use crate::scanners::types::{Confidence, Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S31";
const SCANNER_NAME: &str = "PolicyStrength";
const SCANNER_DESC: &str =
    "Flags RLS policies with overly permissive WITH CHECK expressions (e.g., WITH CHECK(true))";

const PENALTY_PER_FINDING: u8 = 10;

pub struct PolicyStrength;

/// Returns `true` when the WITH CHECK expression is the literal `true`,
/// which lets any user insert/update any row and defeats tenant isolation.
fn is_weak_with_check(expr: &str) -> bool {
    expr.trim().eq_ignore_ascii_case("true")
}

/// Returns `true` when the table appears in the exception list.
fn is_table_excepted(table: &str, except_tables: &[String]) -> bool {
    except_tables.iter().any(|t| t.eq_ignore_ascii_case(table))
}

/// Returns `true` when the policy name contains any of the configured
/// comment markers (e.g., "open-insert" inside "orders_open_insert_policy").
fn is_marker_excepted(policy_name: &str, markers: &[String]) -> bool {
    let normalized_name = policy_name.to_lowercase().replace('-', "_");
    markers.iter().any(|m| {
        let normalized_marker = m.to_lowercase().replace('-', "_");
        normalized_name.contains(&normalized_marker)
    })
}

fn build_finding(table: &str, policy: &str) -> Finding {
    Finding::new(
        SCANNER_ID,
        Severity::Warning,
        format!(
            "Policy \"{}\" on table \"{}\" uses WITH CHECK(true) \u{2014} any role can write any row",
            policy, table,
        ),
    )
    .with_suggestion(
        "Replace WITH CHECK(true) with a tenant-scoped predicate, \
         e.g., WITH CHECK(tenant_id = current_setting('app.tenant_id')::uuid)",
    )
    .with_confidence(Confidence::Confirmed)
}

fn compute_score(finding_count: usize) -> u8 {
    let penalty = (finding_count as u16).saturating_mul(PENALTY_PER_FINDING as u16);
    100u8.saturating_sub(penalty.min(100) as u8)
}

fn build_summary(finding_count: usize, total_policies: usize, score: u8) -> String {
    if total_policies == 0 {
        return "No RLS policies found to analyze.".to_string();
    }
    if finding_count == 0 {
        return format!(
            "All {} RLS policies have scoped WITH CHECK expressions. Score: {}%.",
            total_policies, score,
        );
    }
    format!(
        "{}/{} RLS policies use WITH CHECK(true). Score: {}%.",
        finding_count, total_policies, score,
    )
}

impl Scanner for PolicyStrength {
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
        let cfg = &ctx.config.database_security.policy_strength;

        if !cfg.enabled {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "PolicyStrength scanner disabled.".to_string(),
            };
        }

        let policies = ctx.index.all_rls_policies();

        let findings: Vec<Finding> = policies
            .iter()
            .filter(|p| !is_table_excepted(&p.table_name, &cfg.except_tables))
            .filter(|p| !is_marker_excepted(&p.policy_name, &cfg.except_comment_markers))
            .filter(|p| p.with_check_expr.as_deref().is_some_and(is_weak_with_check))
            .map(|p| build_finding(&p.table_name, &p.policy_name))
            .collect();

        let score = compute_score(findings.len());
        let summary = build_summary(findings.len(), policies.len(), score);

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
    use crate::indexer::types::RlsPolicyInfo;
    use std::path::Path;
    use std::sync::Arc;

    fn default_config() -> Config {
        serde_yaml::from_str("version: '1.0'\nproject: test\n").unwrap()
    }

    fn make_policy(table: &str, name: &str, with_check: Option<&str>) -> RlsPolicyInfo {
        RlsPolicyInfo {
            table_name: table.into(),
            policy_name: name.into(),
            session_var: None,
            has_force: false,
            role: None,
            with_check_expr: with_check.map(String::from),
        }
    }

    fn insert_policies(store: &IndexStore, policies: Vec<RlsPolicyInfo>) {
        for p in policies {
            store
                .security
                .rls_policies
                .entry(p.table_name.clone())
                .or_default()
                .push(p);
        }
    }

    #[test]
    fn no_policies_gives_perfect_score() {
        let config = default_config();
        let store = Arc::new(IndexStore::new());
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PolicyStrength.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn with_check_true_is_flagged() {
        let config = default_config();
        let store = Arc::new(IndexStore::new());
        insert_policies(
            &store,
            vec![make_policy("orders", "orders_insert", Some("true"))],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PolicyStrength.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert_eq!(result.score, 90);
    }

    #[test]
    fn with_check_true_case_insensitive() {
        let config = default_config();
        let store = Arc::new(IndexStore::new());
        insert_policies(
            &store,
            vec![
                make_policy("t1", "p1", Some("TRUE")),
                make_policy("t2", "p2", Some("  True  ")),
            ],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PolicyStrength.scan(&ctx);
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.score, 80);
    }

    #[test]
    fn scoped_expression_not_flagged() {
        let config = default_config();
        let store = Arc::new(IndexStore::new());
        insert_policies(
            &store,
            vec![make_policy(
                "orders",
                "orders_insert",
                Some("tenant_id = current_setting('app.tenant_id')::uuid"),
            )],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PolicyStrength.scan(&ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 100);
    }

    #[test]
    fn no_with_check_not_flagged() {
        let config = default_config();
        let store = Arc::new(IndexStore::new());
        insert_policies(&store, vec![make_policy("orders", "orders_select", None)]);

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PolicyStrength.scan(&ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 100);
    }

    #[test]
    fn excepted_table_is_skipped() {
        let mut config = default_config();
        config
            .database_security
            .policy_strength
            .except_tables
            .push("audit_log".into());

        let store = Arc::new(IndexStore::new());
        insert_policies(
            &store,
            vec![make_policy("audit_log", "audit_insert", Some("true"))],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PolicyStrength.scan(&ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 100);
    }

    #[test]
    fn excepted_comment_marker_is_skipped() {
        let mut config = default_config();
        config
            .database_security
            .policy_strength
            .except_comment_markers
            .push("open-insert".into());

        let store = Arc::new(IndexStore::new());
        insert_policies(
            &store,
            vec![make_policy(
                "events",
                "events_open_insert_policy",
                Some("true"),
            )],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PolicyStrength.scan(&ctx);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn disabled_scanner_returns_perfect_score() {
        let mut config = default_config();
        config.database_security.policy_strength.enabled = false;

        let store = Arc::new(IndexStore::new());
        insert_policies(&store, vec![make_policy("orders", "p1", Some("true"))]);

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PolicyStrength.scan(&ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 100);
    }

    #[test]
    fn score_clamps_at_zero() {
        let config = default_config();
        let store = Arc::new(IndexStore::new());

        let policies: Vec<RlsPolicyInfo> = (0..15)
            .map(|i| make_policy(&format!("t{}", i), &format!("p{}", i), Some("true")))
            .collect();
        insert_policies(&store, policies);

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PolicyStrength.scan(&ctx);
        assert_eq!(result.findings.len(), 15);
        assert_eq!(result.score, 0);
    }

    #[test]
    fn mixed_policies_scores_correctly() {
        let config = default_config();
        let store = Arc::new(IndexStore::new());
        insert_policies(
            &store,
            vec![
                make_policy("orders", "orders_insert", Some("true")),
                make_policy(
                    "users",
                    "users_insert",
                    Some("user_id = current_setting('app.uid')::uuid"),
                ),
                make_policy("items", "items_select", None),
            ],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PolicyStrength.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.score, 90);
    }

    #[test]
    fn is_weak_with_check_unit() {
        assert!(is_weak_with_check("true"));
        assert!(is_weak_with_check("TRUE"));
        assert!(is_weak_with_check("  True  "));
        assert!(!is_weak_with_check("false"));
        assert!(!is_weak_with_check("tenant_id = 1"));
        assert!(!is_weak_with_check(""));
    }

    #[test]
    fn finding_has_suggestion_and_confidence() {
        let config = default_config();
        let store = Arc::new(IndexStore::new());
        insert_policies(&store, vec![make_policy("orders", "p1", Some("true"))]);

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PolicyStrength.scan(&ctx);
        let finding = &result.findings[0];
        assert!(finding.suggestion.is_some());
        assert_eq!(finding.confidence, Confidence::Confirmed);
    }
}
