use std::collections::HashMap;

use crate::rule_pack::schema::{RuleLifecycle, RulePack};

// ---------------------------------------------------------------------------
// LifecyclePolicy
// ---------------------------------------------------------------------------

/// Controls which rule lifecycle states are included when filtering.
///
/// Stable rules are always included. Experimental and deprecated rules are
/// opt-in via their respective flags.
#[derive(Debug, Clone)]
pub struct LifecyclePolicy {
    pub include_experimental: bool,
    pub include_deprecated: bool,
}

impl Default for LifecyclePolicy {
    fn default() -> Self {
        Self {
            include_experimental: false,
            include_deprecated: false,
        }
    }
}

// ---------------------------------------------------------------------------
// LifecycleSummary
// ---------------------------------------------------------------------------

/// Per-pack breakdown of rule counts by lifecycle state.
#[derive(Debug, Clone)]
pub struct LifecycleSummary {
    pub packs: Vec<PackLifecycleCounts>,
}

/// Lifecycle counts for a single rule pack.
#[derive(Debug, Clone)]
pub struct PackLifecycleCounts {
    pub pack_name: String,
    pub stable: usize,
    pub experimental: usize,
    pub deprecated: usize,
}

// ---------------------------------------------------------------------------
// Filtering
// ---------------------------------------------------------------------------

/// Returns a new `RulePack` containing only rules whose lifecycle matches
/// the given policy. Stable rules are always included.
pub fn filter_rules_by_lifecycle(pack: &RulePack, policy: &LifecyclePolicy) -> RulePack {
    let protection_evidence = pack
        .protection_evidence
        .iter()
        .filter(|r| should_include_lifecycle(r.lifecycle, policy))
        .cloned()
        .collect();

    let data_source_evidence = pack
        .data_source_evidence
        .iter()
        .filter(|r| should_include_lifecycle(r.lifecycle, policy))
        .cloned()
        .collect();

    RulePack {
        kind: pack.kind.clone(),
        name: pack.name.clone(),
        version: pack.version.clone(),
        languages: pack.languages.clone(),
        detect: pack.detect.clone(),
        routes: pack.routes.clone(),
        protection_evidence,
        data_source_evidence,
        error_handling: pack.error_handling.clone(),
        sensitive_logging: pack.sensitive_logging.clone(),
        description: pack.description.clone(),
        source: pack.source,
    }
}

fn should_include_lifecycle(lifecycle: RuleLifecycle, policy: &LifecyclePolicy) -> bool {
    match lifecycle {
        RuleLifecycle::Stable => true,
        RuleLifecycle::Experimental => policy.include_experimental,
        RuleLifecycle::Deprecated => policy.include_deprecated,
    }
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/// Aggregate lifecycle counts across all supplied rule packs.
pub fn summarize_lifecycle(packs: &[RulePack]) -> LifecycleSummary {
    let packs = packs
        .iter()
        .map(|pack| {
            let mut counts: HashMap<RuleLifecycle, usize> = HashMap::new();

            for rule in &pack.protection_evidence {
                *counts.entry(rule.lifecycle).or_default() += 1;
            }
            for rule in &pack.data_source_evidence {
                *counts.entry(rule.lifecycle).or_default() += 1;
            }

            PackLifecycleCounts {
                pack_name: pack.name.clone(),
                stable: *counts.get(&RuleLifecycle::Stable).unwrap_or(&0),
                experimental: *counts.get(&RuleLifecycle::Experimental).unwrap_or(&0),
                deprecated: *counts.get(&RuleLifecycle::Deprecated).unwrap_or(&0),
            }
        })
        .collect();

    LifecycleSummary { packs }
}

/// Format a lifecycle summary as a human-readable string.
pub fn format_lifecycle_summary(summary: &LifecycleSummary) -> String {
    let mut lines = Vec::new();
    lines.push("Rule Lifecycle Summary".to_string());
    lines.push("======================".to_string());

    for pack in &summary.packs {
        let total = pack.stable + pack.experimental + pack.deprecated;
        lines.push(format!(
            "{}: {} total ({} stable, {} experimental, {} deprecated)",
            pack.pack_name, total, pack.stable, pack.experimental, pack.deprecated,
        ));
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceKind;
    use crate::rule_pack::schema::{
        DataSourceRule, ProtectionEvidenceRule, ProvidesConfig, RuleType,
    };

    fn make_protection_rule(name: &str, lifecycle: RuleLifecycle) -> ProtectionEvidenceRule {
        ProtectionEvidenceRule {
            name: name.to_string(),
            description: None,
            scope: None,
            rule_type: RuleType::Regex,
            query: None,
            pattern: Some("test".to_string()),
            match_condition: None,
            provides: ProvidesConfig {
                kind: EvidenceKind::Auth,
                confidence: 0.9,
                scope_extends_to: None,
            },
            lifecycle,
            since_version: None,
            deprecated_reason: None,
        }
    }

    fn make_data_source_rule(name: &str, lifecycle: RuleLifecycle) -> DataSourceRule {
        DataSourceRule {
            name: name.to_string(),
            rule_type: RuleType::Regex,
            query: None,
            pattern: Some("test".to_string()),
            provides: ProvidesConfig {
                kind: EvidenceKind::RealData,
                confidence: 0.8,
                scope_extends_to: None,
            },
            lifecycle,
            since_version: None,
            deprecated_reason: None,
        }
    }

    fn make_test_pack() -> RulePack {
        RulePack {
            kind: "rule-pack".to_string(),
            name: "test-pack".to_string(),
            version: "1.0.0".to_string(),
            languages: vec!["typescript".to_string()],
            detect: Default::default(),
            routes: vec![],
            protection_evidence: vec![
                make_protection_rule("stable-auth", RuleLifecycle::Stable),
                make_protection_rule("experimental-auth", RuleLifecycle::Experimental),
                make_protection_rule("deprecated-auth", RuleLifecycle::Deprecated),
            ],
            data_source_evidence: vec![
                make_data_source_rule("stable-ds", RuleLifecycle::Stable),
                make_data_source_rule("experimental-ds", RuleLifecycle::Experimental),
            ],
            error_handling: Default::default(),
            sensitive_logging: Default::default(),
            description: None,
            source: None,
        }
    }

    #[test]
    fn default_policy_includes_only_stable() {
        let pack = make_test_pack();
        let policy = LifecyclePolicy::default();

        let filtered = filter_rules_by_lifecycle(&pack, &policy);

        assert_eq!(filtered.protection_evidence.len(), 1);
        assert_eq!(filtered.protection_evidence[0].name, "stable-auth");
        assert_eq!(filtered.data_source_evidence.len(), 1);
        assert_eq!(filtered.data_source_evidence[0].name, "stable-ds");
    }

    #[test]
    fn experimental_policy_includes_stable_and_experimental() {
        let pack = make_test_pack();
        let policy = LifecyclePolicy {
            include_experimental: true,
            include_deprecated: false,
        };

        let filtered = filter_rules_by_lifecycle(&pack, &policy);

        assert_eq!(filtered.protection_evidence.len(), 2);
        assert_eq!(filtered.data_source_evidence.len(), 2);
    }

    #[test]
    fn deprecated_policy_includes_stable_and_deprecated() {
        let pack = make_test_pack();
        let policy = LifecyclePolicy {
            include_experimental: false,
            include_deprecated: true,
        };

        let filtered = filter_rules_by_lifecycle(&pack, &policy);

        assert_eq!(filtered.protection_evidence.len(), 2);
        let names: Vec<&str> = filtered
            .protection_evidence
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert!(names.contains(&"stable-auth"));
        assert!(names.contains(&"deprecated-auth"));
    }

    #[test]
    fn all_policy_includes_everything() {
        let pack = make_test_pack();
        let policy = LifecyclePolicy {
            include_experimental: true,
            include_deprecated: true,
        };

        let filtered = filter_rules_by_lifecycle(&pack, &policy);

        assert_eq!(filtered.protection_evidence.len(), 3);
        assert_eq!(filtered.data_source_evidence.len(), 2);
    }

    #[test]
    fn filter_preserves_pack_metadata() {
        let pack = make_test_pack();
        let policy = LifecyclePolicy::default();

        let filtered = filter_rules_by_lifecycle(&pack, &policy);

        assert_eq!(filtered.name, "test-pack");
        assert_eq!(filtered.version, "1.0.0");
        assert_eq!(filtered.languages, vec!["typescript"]);
    }

    #[test]
    fn summarize_lifecycle_counts_correctly() {
        let pack = make_test_pack();
        let summary = summarize_lifecycle(&[pack]);

        assert_eq!(summary.packs.len(), 1);
        let counts = &summary.packs[0];
        assert_eq!(counts.pack_name, "test-pack");
        assert_eq!(counts.stable, 2);
        assert_eq!(counts.experimental, 2);
        assert_eq!(counts.deprecated, 1);
    }

    #[test]
    fn format_lifecycle_summary_contains_pack_name() {
        let pack = make_test_pack();
        let summary = summarize_lifecycle(&[pack]);
        let output = format_lifecycle_summary(&summary);

        assert!(output.contains("test-pack"));
        assert!(output.contains("2 stable"));
        assert!(output.contains("2 experimental"));
        assert!(output.contains("1 deprecated"));
    }

    #[test]
    fn default_lifecycle_is_stable() {
        assert_eq!(RuleLifecycle::default(), RuleLifecycle::Stable);
    }
}
