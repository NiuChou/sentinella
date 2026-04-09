use regex::{Regex, RegexBuilder};

use crate::config::schema::{PermissionBoundaryConfig, RestrictedTableConfig};
use crate::indexer::types::GrantDetail;
use crate::scanners::types::{Confidence, Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S30";
const SCANNER_NAME: &str = "PermissionBoundary";
const SCANNER_DESC: &str =
    "Detects restricted-table access violations and dangerous blanket grants";

const DEDUCTION_CRITICAL: u8 = 20;
const DEDUCTION_WARNING: u8 = 5;

pub struct PermissionBoundary;

// ── Restricted-table checks ─────────────────────────────────────────

/// Check whether a grant violates a restricted-table rule.
///
/// A violation occurs when a denied role holds any privilege not in the
/// `allow` list for that table.
fn check_restricted_table(grant: &GrantDetail, rule: &RestrictedTableConfig) -> Option<Finding> {
    let role_denied = rule
        .deny_roles
        .iter()
        .any(|dr| dr.eq_ignore_ascii_case(&grant.role));

    if !role_denied {
        return None;
    }

    let disallowed: Vec<&String> = grant
        .privileges
        .iter()
        .filter(|priv_name| !rule.allow.iter().any(|a| a.eq_ignore_ascii_case(priv_name)))
        .collect();

    if disallowed.is_empty() {
        return None;
    }

    let priv_list: Vec<&str> = disallowed.iter().map(|s| s.as_str()).collect();
    let reason_suffix = rule
        .reason
        .as_deref()
        .map(|r| format!(" Reason: {r}"))
        .unwrap_or_default();

    let message = format!(
        "Role '{}' has disallowed privileges [{}] on restricted table '{}'{reason_suffix}",
        grant.role,
        priv_list.join(", "),
        rule.table,
    );

    Some(
        Finding::new(SCANNER_ID, Severity::Critical, message)
            .with_suggestion(format!(
                "REVOKE {} ON {} FROM {}",
                priv_list.join(", "),
                rule.table,
                grant.role,
            ))
            .with_confidence(Confidence::Confirmed),
    )
}

/// Evaluate all grants against every restricted-table rule.
fn find_restricted_table_violations(
    grants: &[GrantDetail],
    rules: &[RestrictedTableConfig],
) -> Vec<Finding> {
    rules
        .iter()
        .flat_map(|rule| {
            grants
                .iter()
                .filter(|g| g.table_name.eq_ignore_ascii_case(&rule.table))
                .filter_map(|g| check_restricted_table(g, rule))
        })
        .collect()
}

// ── Blanket-grant checks ────────────────────────────────────────────

/// Flag any grant where `is_blanket == true`.
fn find_blanket_grant_findings(grants: &[GrantDetail]) -> Vec<Finding> {
    grants
        .iter()
        .filter(|g| g.is_blanket)
        .map(|g| {
            let message = format!(
                "Blanket GRANT detected: role '{}' has [{}] on '{}'",
                g.role,
                g.privileges.join(", "),
                g.table_name,
            );
            Finding::new(SCANNER_ID, Severity::Critical, message)
                .with_suggestion("Replace blanket grants with explicit per-table grants")
                .with_confidence(Confidence::Confirmed)
        })
        .collect()
}

// ── Flag-pattern checks ─────────────────────────────────────────────

/// Compile user-supplied regex patterns, skipping invalid ones.
fn compile_patterns(raw: &[String]) -> Vec<Regex> {
    raw.iter()
        .filter_map(|pat| {
            match RegexBuilder::new(pat)
                .size_limit(1 << 20) // 1 MB — defence against ReDoS
                .build()
            {
                Ok(re) => Some(re),
                Err(e) => {
                    eprintln!("[{SCANNER_ID}] invalid flag_pattern '{pat}': {e}");
                    None
                }
            }
        })
        .collect()
}

/// Test each grant against user-configured regex patterns.
fn find_pattern_matches(grants: &[GrantDetail], patterns: &[Regex]) -> Vec<Finding> {
    if patterns.is_empty() {
        return Vec::new();
    }

    grants
        .iter()
        .flat_map(|g| {
            let grant_text = format!(
                "GRANT {} ON {} TO {}",
                g.privileges.join(", "),
                g.table_name,
                g.role,
            );
            patterns
                .iter()
                .filter(move |re| re.is_match(&grant_text))
                .map(move |re| {
                    let message = format!(
                        "Grant matches flag pattern '{}': role '{}' on '{}'",
                        re.as_str(),
                        g.role,
                        g.table_name,
                    );
                    Finding::new(SCANNER_ID, Severity::Warning, message)
                        .with_suggestion("Review this grant against your security policy")
                        .with_confidence(Confidence::Likely)
                })
        })
        .collect()
}

// ── Scoring ─────────────────────────────────────────────────────────

fn compute_score(findings: &[Finding]) -> u8 {
    let deduction: u16 = findings.iter().fold(0u16, |acc, f| {
        let d = match f.severity {
            Severity::Critical => DEDUCTION_CRITICAL as u16,
            Severity::Warning => DEDUCTION_WARNING as u16,
            Severity::Info => 0,
        };
        acc.saturating_add(d)
    });

    100u8.saturating_sub(deduction.min(100) as u8)
}

fn build_summary(findings: &[Finding], score: u8) -> String {
    if findings.is_empty() {
        return "No permission boundary violations detected.".to_string();
    }

    let critical = findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let warning = findings
        .iter()
        .filter(|f| f.severity == Severity::Warning)
        .count();

    format!(
        "{} permission boundary issue(s) found ({} critical, {} warning). Score: {score}%.",
        findings.len(),
        critical,
        warning,
    )
}

// ── Scanner implementation ──────────────────────────────────────────

fn is_enabled(cfg: &PermissionBoundaryConfig) -> bool {
    cfg.enabled
}

impl Scanner for PermissionBoundary {
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
        let cfg = &ctx.config.database_security.permission_boundaries;

        if !is_enabled(cfg) {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "Permission boundary scanner disabled.".to_string(),
            };
        }

        let grants = ctx.index.all_grant_details();

        if grants.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No grant details found to analyze.".to_string(),
            };
        }

        let restricted_findings = find_restricted_table_violations(&grants, &cfg.restricted_tables);
        let blanket_findings = find_blanket_grant_findings(&grants);
        let patterns = compile_patterns(&cfg.flag_patterns);
        let pattern_findings = find_pattern_matches(&grants, &patterns);

        let findings: Vec<Finding> = restricted_findings
            .into_iter()
            .chain(blanket_findings)
            .chain(pattern_findings)
            .collect();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::indexer::store::IndexStore;
    use std::path::Path;

    fn default_config() -> Config {
        serde_yaml::from_str("version: '1.0'\nproject: test\n").unwrap()
    }

    fn make_grant(table: &str, role: &str, privileges: &[&str], blanket: bool) -> GrantDetail {
        GrantDetail {
            table_name: table.to_string(),
            privileges: privileges.iter().map(|s| s.to_string()).collect(),
            role: role.to_string(),
            is_blanket: blanket,
        }
    }

    #[test]
    fn no_grants_gives_perfect_score() {
        let config = default_config();
        let store = IndexStore::new();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PermissionBoundary.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn disabled_scanner_returns_100() {
        let mut config = default_config();
        config.database_security.permission_boundaries.enabled = false;

        let store = IndexStore::new();
        store.security.grant_details.insert(
            "users".to_string(),
            vec![make_grant("users", "anon", &["ALL"], true)],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PermissionBoundary.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn restricted_table_violation_is_critical() {
        let mut config = default_config();
        config
            .database_security
            .permission_boundaries
            .restricted_tables
            .push(RestrictedTableConfig {
                table: "users".to_string(),
                deny_roles: vec!["anon".to_string()],
                allow: vec!["SELECT".to_string()],
                reason: Some("PII table".to_string()),
            });

        let store = IndexStore::new();
        store.security.grant_details.insert(
            "users".to_string(),
            vec![make_grant("users", "anon", &["SELECT", "INSERT"], false)],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PermissionBoundary.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].message.contains("INSERT"));
        assert!(result.findings[0].message.contains("PII table"));
        assert_eq!(result.score, 80);
    }

    #[test]
    fn allowed_privileges_pass_cleanly() {
        let mut config = default_config();
        config
            .database_security
            .permission_boundaries
            .restricted_tables
            .push(RestrictedTableConfig {
                table: "users".to_string(),
                deny_roles: vec!["anon".to_string()],
                allow: vec!["SELECT".to_string()],
                reason: None,
            });

        let store = IndexStore::new();
        store.security.grant_details.insert(
            "users".to_string(),
            vec![make_grant("users", "anon", &["SELECT"], false)],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PermissionBoundary.scan(&ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 100);
    }

    #[test]
    fn non_denied_role_passes() {
        let mut config = default_config();
        config
            .database_security
            .permission_boundaries
            .restricted_tables
            .push(RestrictedTableConfig {
                table: "users".to_string(),
                deny_roles: vec!["anon".to_string()],
                allow: vec![],
                reason: None,
            });

        let store = IndexStore::new();
        store.security.grant_details.insert(
            "users".to_string(),
            vec![make_grant("users", "admin", &["ALL"], false)],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PermissionBoundary.scan(&ctx);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn blanket_grant_is_critical() {
        let config = default_config();
        let store = IndexStore::new();
        store.security.grant_details.insert(
            "ALL TABLES IN SCHEMA public".to_string(),
            vec![make_grant(
                "ALL TABLES IN SCHEMA public",
                "app_user",
                &["ALL"],
                true,
            )],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PermissionBoundary.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].message.contains("Blanket"));
        assert_eq!(result.score, 80);
    }

    #[test]
    fn flag_pattern_match_is_warning() {
        let mut config = default_config();
        config.database_security.permission_boundaries.flag_patterns = vec!["anon".to_string()];

        let store = IndexStore::new();
        store.security.grant_details.insert(
            "posts".to_string(),
            vec![make_grant("posts", "anon", &["SELECT"], false)],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PermissionBoundary.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert_eq!(result.score, 95);
    }

    #[test]
    fn invalid_pattern_is_skipped() {
        let mut config = default_config();
        config.database_security.permission_boundaries.flag_patterns = vec!["[invalid".to_string()];

        let store = IndexStore::new();
        store.security.grant_details.insert(
            "posts".to_string(),
            vec![make_grant("posts", "anon", &["SELECT"], false)],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PermissionBoundary.scan(&ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 100);
    }

    #[test]
    fn score_clamps_to_zero() {
        let config = default_config();
        let store = IndexStore::new();

        // 6 blanket grants => 6 * 20 = 120, clamped to 0
        for i in 0..6 {
            let table = format!("table_{i}");
            store.security.grant_details.insert(
                table.clone(),
                vec![make_grant(&table, "bad_role", &["ALL"], true)],
            );
        }

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PermissionBoundary.scan(&ctx);
        assert_eq!(result.score, 0);
    }

    #[test]
    fn combined_findings_deduct_correctly() {
        let mut config = default_config();
        config
            .database_security
            .permission_boundaries
            .restricted_tables
            .push(RestrictedTableConfig {
                table: "secrets".to_string(),
                deny_roles: vec!["anon".to_string()],
                allow: vec![],
                reason: None,
            });
        config.database_security.permission_boundaries.flag_patterns = vec!["anon".to_string()];

        let store = IndexStore::new();
        // Restricted table violation (Critical, -20)
        store.security.grant_details.insert(
            "secrets".to_string(),
            vec![make_grant("secrets", "anon", &["SELECT"], false)],
        );
        // Blanket grant (Critical, -20)
        store.security.grant_details.insert(
            "ALL TABLES IN SCHEMA public".to_string(),
            vec![make_grant(
                "ALL TABLES IN SCHEMA public",
                "app",
                &["ALL"],
                true,
            )],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PermissionBoundary.scan(&ctx);
        // 1 restricted (Critical -20) + 1 blanket (Critical -20) + pattern matches on both grants
        // The "secrets" grant matches "anon" pattern (Warning -5)
        // The blanket grant role is "app", doesn't match "anon"
        // Total: -20 + -20 + -5 = -45 => score 55
        assert_eq!(result.score, 55);
    }

    #[test]
    fn case_insensitive_role_matching() {
        let mut config = default_config();
        config
            .database_security
            .permission_boundaries
            .restricted_tables
            .push(RestrictedTableConfig {
                table: "users".to_string(),
                deny_roles: vec!["ANON".to_string()],
                allow: vec![],
                reason: None,
            });

        let store = IndexStore::new();
        store.security.grant_details.insert(
            "users".to_string(),
            vec![make_grant("users", "anon", &["SELECT"], false)],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = PermissionBoundary.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
    }
}
