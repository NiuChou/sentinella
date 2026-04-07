use regex::Regex;

use super::schema::{EvidenceRule, RuleLifecycle, RulePack};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssueLevel {
    Error,
    Warning,
}

impl std::fmt::Display for IssueLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssueLevel::Error => write!(f, "ERROR"),
            IssueLevel::Warning => write!(f, "WARNING"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidationIssue {
    pub rule_name: Option<String>,
    pub field: String,
    pub message: String,
    pub level: IssueLevel,
}

// ---------------------------------------------------------------------------
// Supported rule kinds
// ---------------------------------------------------------------------------

const SUPPORTED_KINDS: &[&str] = &[
    "protection",
    "data_source",
    "authentication",
    "authorization",
    "validation",
    "logging",
    "rate_limiting",
    "encryption",
    "",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Validate a rule pack and return all discovered issues.
pub fn validate_rule_pack(pack: &RulePack) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    validate_pack_metadata(pack, &mut issues);
    validate_evidence_rules(&pack.protection_evidence, "protection_evidence", &mut issues);
    validate_evidence_rules(
        &pack.data_source_evidence,
        "data_source_evidence",
        &mut issues,
    );
    issues
}

/// Format a human-readable validation report.
pub fn format_validation_report(issues: &[ValidationIssue]) -> String {
    if issues.is_empty() {
        return String::from("  No issues found.\n");
    }

    issues
        .iter()
        .map(|issue| {
            let rule_ctx = issue
                .rule_name
                .as_ref()
                .map(|n| format!(" (rule: {n})"))
                .unwrap_or_default();
            format!(
                "  [{}] {}{}: {}",
                issue.level, issue.field, rule_ctx, issue.message,
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// Pack-level checks
// ---------------------------------------------------------------------------

fn validate_pack_metadata(pack: &RulePack, issues: &mut Vec<ValidationIssue>) {
    if pack.name.trim().is_empty() {
        issues.push(ValidationIssue {
            rule_name: None,
            field: "name".into(),
            message: "pack name must not be empty".into(),
            level: IssueLevel::Error,
        });
    }
    if pack.version.trim().is_empty() {
        issues.push(ValidationIssue {
            rule_name: None,
            field: "version".into(),
            message: "pack version must not be empty".into(),
            level: IssueLevel::Error,
        });
    }
    if pack.languages.is_empty() {
        issues.push(ValidationIssue {
            rule_name: None,
            field: "languages".into(),
            message: "pack must declare at least one language".into(),
            level: IssueLevel::Warning,
        });
    }
}

// ---------------------------------------------------------------------------
// Rule-level checks
// ---------------------------------------------------------------------------

fn validate_evidence_rules(
    rules: &[EvidenceRule],
    section: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    for rule in rules {
        validate_single_rule(rule, section, issues);
    }
}

fn validate_single_rule(rule: &EvidenceRule, section: &str, issues: &mut Vec<ValidationIssue>) {
    validate_rule_pattern(rule, section, issues);
    validate_rule_kind(rule, section, issues);
    validate_rule_confidence(rule, section, issues);
    validate_rule_deprecation(rule, section, issues);
}

fn validate_rule_pattern(rule: &EvidenceRule, section: &str, issues: &mut Vec<ValidationIssue>) {
    if Regex::new(&rule.pattern).is_err() {
        issues.push(ValidationIssue {
            rule_name: Some(rule.name.clone()),
            field: format!("{section}.pattern"),
            message: format!("invalid regex pattern: {}", rule.pattern),
            level: IssueLevel::Error,
        });
    }
}

fn validate_rule_kind(rule: &EvidenceRule, section: &str, issues: &mut Vec<ValidationIssue>) {
    if !SUPPORTED_KINDS.contains(&rule.kind.as_str()) {
        issues.push(ValidationIssue {
            rule_name: Some(rule.name.clone()),
            field: format!("{section}.kind"),
            message: format!("unsupported kind: '{}'", rule.kind),
            level: IssueLevel::Warning,
        });
    }
}

fn validate_rule_confidence(
    rule: &EvidenceRule,
    section: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    if !(0.0..=1.0).contains(&rule.confidence) {
        issues.push(ValidationIssue {
            rule_name: Some(rule.name.clone()),
            field: format!("{section}.confidence"),
            message: format!(
                "confidence must be between 0.0 and 1.0, got {}",
                rule.confidence
            ),
            level: IssueLevel::Error,
        });
    }
}

fn validate_rule_deprecation(
    rule: &EvidenceRule,
    section: &str,
    issues: &mut Vec<ValidationIssue>,
) {
    if rule.lifecycle == RuleLifecycle::Deprecated && rule.deprecated_reason.is_none() {
        issues.push(ValidationIssue {
            rule_name: Some(rule.name.clone()),
            field: format!("{section}.deprecated_reason"),
            message: "deprecated rules should have a deprecated_reason".into(),
            level: IssueLevel::Warning,
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_pack::schema::EvidenceRule;

    fn minimal_valid_pack() -> RulePack {
        RulePack {
            name: "test-pack".into(),
            version: "1.0".into(),
            description: None,
            languages: vec!["rust".into()],
            protection_evidence: vec![],
            data_source_evidence: vec![],
            source: None,
        }
    }

    fn rule_with(name: &str, pattern: &str, kind: &str, confidence: f64) -> EvidenceRule {
        EvidenceRule {
            name: name.into(),
            pattern: pattern.into(),
            kind: kind.into(),
            confidence,
            lifecycle: RuleLifecycle::Active,
            deprecated_reason: None,
            description: None,
        }
    }

    #[test]
    fn valid_pack_has_no_issues() {
        let pack = minimal_valid_pack();
        let issues = validate_rule_pack(&pack);
        assert!(issues.is_empty(), "expected no issues: {issues:?}");
    }

    #[test]
    fn empty_name_is_error() {
        let pack = RulePack {
            name: "  ".into(),
            ..minimal_valid_pack()
        };
        let issues = validate_rule_pack(&pack);
        assert!(issues.iter().any(|i| i.field == "name" && i.level == IssueLevel::Error));
    }

    #[test]
    fn empty_version_is_error() {
        let pack = RulePack {
            version: "".into(),
            ..minimal_valid_pack()
        };
        let issues = validate_rule_pack(&pack);
        assert!(issues.iter().any(|i| i.field == "version" && i.level == IssueLevel::Error));
    }

    #[test]
    fn empty_languages_is_warning() {
        let pack = RulePack {
            languages: vec![],
            ..minimal_valid_pack()
        };
        let issues = validate_rule_pack(&pack);
        assert!(issues
            .iter()
            .any(|i| i.field == "languages" && i.level == IssueLevel::Warning));
    }

    #[test]
    fn invalid_regex_pattern_is_error() {
        let pack = RulePack {
            protection_evidence: vec![rule_with("bad", "[invalid(", "protection", 0.5)],
            ..minimal_valid_pack()
        };
        let issues = validate_rule_pack(&pack);
        assert!(issues
            .iter()
            .any(|i| i.field.contains("pattern") && i.level == IssueLevel::Error));
    }

    #[test]
    fn confidence_out_of_range_is_error() {
        let pack = RulePack {
            data_source_evidence: vec![rule_with("high", "ok", "data_source", 1.5)],
            ..minimal_valid_pack()
        };
        let issues = validate_rule_pack(&pack);
        assert!(issues
            .iter()
            .any(|i| i.field.contains("confidence") && i.level == IssueLevel::Error));
    }

    #[test]
    fn unsupported_kind_is_warning() {
        let pack = RulePack {
            protection_evidence: vec![rule_with("odd", "ok", "unknown_kind", 0.5)],
            ..minimal_valid_pack()
        };
        let issues = validate_rule_pack(&pack);
        assert!(issues
            .iter()
            .any(|i| i.field.contains("kind") && i.level == IssueLevel::Warning));
    }

    #[test]
    fn deprecated_without_reason_is_warning() {
        let mut rule = rule_with("old", "pattern", "protection", 0.5);
        rule.lifecycle = RuleLifecycle::Deprecated;
        rule.deprecated_reason = None;

        let pack = RulePack {
            protection_evidence: vec![rule],
            ..minimal_valid_pack()
        };
        let issues = validate_rule_pack(&pack);
        assert!(issues
            .iter()
            .any(|i| i.field.contains("deprecated_reason") && i.level == IssueLevel::Warning));
    }

    #[test]
    fn format_report_renders_issues() {
        let issues = vec![ValidationIssue {
            rule_name: Some("test_rule".into()),
            field: "pattern".into(),
            message: "bad regex".into(),
            level: IssueLevel::Error,
        }];
        let report = format_validation_report(&issues);
        assert!(report.contains("ERROR"));
        assert!(report.contains("test_rule"));
        assert!(report.contains("bad regex"));
    }

    #[test]
    fn format_report_empty_issues() {
        let report = format_validation_report(&[]);
        assert!(report.contains("No issues"));
    }
}
