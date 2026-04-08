use regex::Regex;

use super::schema::{DataSourceRule, ProtectionEvidenceRule, RuleLifecycle, RulePack};

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
// Public API
// ---------------------------------------------------------------------------

/// Validate a rule pack and return all discovered issues.
pub fn validate_rule_pack(pack: &RulePack) -> Vec<ValidationIssue> {
    let mut issues = Vec::new();
    validate_pack_metadata(pack, &mut issues);
    validate_protection_evidence_rules(&pack.protection_evidence, &mut issues);
    validate_data_source_rules(&pack.data_source_evidence, &mut issues);
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
// ProtectionEvidenceRule checks
// ---------------------------------------------------------------------------

fn validate_protection_evidence_rules(
    rules: &[ProtectionEvidenceRule],
    issues: &mut Vec<ValidationIssue>,
) {
    for rule in rules {
        // Validate regex pattern if present
        if let Some(ref pattern) = rule.pattern {
            if Regex::new(pattern).is_err() {
                issues.push(ValidationIssue {
                    rule_name: Some(rule.name.clone()),
                    field: "protection_evidence.pattern".into(),
                    message: format!("invalid regex pattern: {}", pattern),
                    level: IssueLevel::Error,
                });
            }
        }

        // Validate confidence range
        let confidence = rule.provides.confidence;
        if !(0.0..=1.0).contains(&confidence) {
            issues.push(ValidationIssue {
                rule_name: Some(rule.name.clone()),
                field: "protection_evidence.confidence".into(),
                message: format!(
                    "confidence must be between 0.0 and 1.0, got {}",
                    confidence
                ),
                level: IssueLevel::Error,
            });
        }

        // Validate deprecation reason
        if rule.lifecycle == RuleLifecycle::Deprecated && rule.deprecated_reason.is_none() {
            issues.push(ValidationIssue {
                rule_name: Some(rule.name.clone()),
                field: "protection_evidence.deprecated_reason".into(),
                message: "deprecated rules should have a deprecated_reason".into(),
                level: IssueLevel::Warning,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// DataSourceRule checks
// ---------------------------------------------------------------------------

fn validate_data_source_rules(rules: &[DataSourceRule], issues: &mut Vec<ValidationIssue>) {
    for rule in rules {
        // Validate regex pattern if present
        if let Some(ref pattern) = rule.pattern {
            if Regex::new(pattern).is_err() {
                issues.push(ValidationIssue {
                    rule_name: Some(rule.name.clone()),
                    field: "data_source_evidence.pattern".into(),
                    message: format!("invalid regex pattern: {}", pattern),
                    level: IssueLevel::Error,
                });
            }
        }

        // Validate confidence range
        let confidence = rule.provides.confidence;
        if !(0.0..=1.0).contains(&confidence) {
            issues.push(ValidationIssue {
                rule_name: Some(rule.name.clone()),
                field: "data_source_evidence.confidence".into(),
                message: format!(
                    "confidence must be between 0.0 and 1.0, got {}",
                    confidence
                ),
                level: IssueLevel::Error,
            });
        }

        // Validate deprecation reason
        if rule.lifecycle == RuleLifecycle::Deprecated && rule.deprecated_reason.is_none() {
            issues.push(ValidationIssue {
                rule_name: Some(rule.name.clone()),
                field: "data_source_evidence.deprecated_reason".into(),
                message: "deprecated rules should have a deprecated_reason".into(),
                level: IssueLevel::Warning,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{EvidenceKind, EvidenceScope};
    use crate::rule_pack::schema::{ProvidesConfig, ProtectionEvidenceRule, RuleType};

    fn minimal_valid_pack() -> RulePack {
        RulePack {
            kind: "rule-pack".into(),
            name: "test-pack".into(),
            version: "1.0".into(),
            languages: vec!["rust".into()],
            detect: Default::default(),
            routes: vec![],
            protection_evidence: vec![],
            data_source_evidence: vec![],
            error_handling: Default::default(),
            sensitive_logging: Default::default(),
            description: None,
            source: None,
        }
    }

    fn make_protection_rule(
        name: &str,
        pattern: Option<&str>,
        confidence: f64,
    ) -> ProtectionEvidenceRule {
        ProtectionEvidenceRule {
            name: name.into(),
            description: None,
            scope: Some(EvidenceScope::Function),
            rule_type: RuleType::Regex,
            query: None,
            pattern: pattern.map(String::from),
            match_condition: None,
            provides: ProvidesConfig {
                kind: EvidenceKind::Auth,
                confidence,
                scope_extends_to: None,
            },
            lifecycle: RuleLifecycle::Stable,
            since_version: None,
            deprecated_reason: None,
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
        assert!(issues
            .iter()
            .any(|i| i.field == "name" && i.level == IssueLevel::Error));
    }

    #[test]
    fn empty_version_is_error() {
        let pack = RulePack {
            version: "".into(),
            ..minimal_valid_pack()
        };
        let issues = validate_rule_pack(&pack);
        assert!(issues
            .iter()
            .any(|i| i.field == "version" && i.level == IssueLevel::Error));
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
            protection_evidence: vec![make_protection_rule("bad", Some("[invalid("), 0.5)],
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
            protection_evidence: vec![make_protection_rule("high", Some("ok"), 1.5)],
            ..minimal_valid_pack()
        };
        let issues = validate_rule_pack(&pack);
        assert!(issues
            .iter()
            .any(|i| i.field.contains("confidence") && i.level == IssueLevel::Error));
    }

    #[test]
    fn deprecated_without_reason_is_warning() {
        let mut rule = make_protection_rule("old", Some("pattern"), 0.5);
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
