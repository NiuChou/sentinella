//! YAML schema for framework-specific rule packs.
//!
//! Rule packs declare detection patterns, protection evidence, data-source
//! evidence, error-handling overrides, and sensitive-logging safe patterns
//! for a particular framework (NestJS, Express, Django, etc.).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Top-level rule pack
// ---------------------------------------------------------------------------

/// A complete rule pack loaded from a YAML file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    /// Human-readable name, e.g. "NestJS Rule Pack".
    pub name: String,

    /// Semver string for the rule pack itself.
    pub version: String,

    /// Free-form description.
    #[serde(default)]
    pub description: String,

    /// How Sentinella decides whether this pack applies to a project.
    pub detect: DetectBlock,

    /// Rules that contribute **protection** evidence (auth, rate-limit, etc.).
    #[serde(default)]
    pub protection_evidence: Vec<EvidenceRule>,

    /// Rules that contribute **data-source** evidence (real data vs stub).
    #[serde(default)]
    pub data_source_evidence: Vec<EvidenceRule>,

    /// Overrides for the error-handling scanner.
    #[serde(default)]
    pub error_handling: ErrorHandlingBlock,

    /// Overrides for the sensitive-logging scanner.
    #[serde(default)]
    pub sensitive_logging: SensitiveLoggingBlock,
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Criteria used to auto-detect whether a rule pack applies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectBlock {
    /// If **any** of these packages appear in `package.json` (or the
    /// language-equivalent manifest), the pack is considered applicable.
    #[serde(default)]
    pub package_json_dependencies: Vec<String>,

    /// Glob patterns for files whose presence indicates applicability.
    #[serde(default)]
    pub file_patterns: Vec<String>,
}

// ---------------------------------------------------------------------------
// Evidence rules
// ---------------------------------------------------------------------------

/// A single regex-based (or future tree-sitter-based) evidence rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRule {
    /// Unique identifier within the pack, e.g. `nestjs-class-guard`.
    pub id: String,

    /// Human-readable label shown in reports.
    #[serde(default)]
    pub description: String,

    /// The type of matching engine.
    #[serde(rename = "type")]
    pub rule_type: RuleType,

    /// The pattern string (regex or tree-sitter query, depending on `rule_type`).
    pub pattern: String,

    /// What kind of evidence this rule produces.
    pub kind: EvidenceKind,

    /// Confidence score in the range `0.0..=1.0`.
    pub confidence: f64,

    /// How far the evidence radiates from the match location.
    #[serde(default = "default_scope")]
    pub scope: EvidenceScope,
}

fn default_scope() -> EvidenceScope {
    EvidenceScope::Function
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

/// Matching engine used by a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleType {
    Regex,
    TreeSitter,
}

/// The category of evidence a rule produces.
///
/// Serialized as **kebab-case** to match the rest of Sentinella's YAML
/// conventions (e.g. `auth-exempt`, `rate-limit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    Auth,
    AuthExempt,
    RateLimit,
    Audit,
    Csrf,
    TwoFactor,
    SoftDelete,
    RealData,
    ErrorHandled,
    SafeIgnore,
}

/// How far from the match location the evidence applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceScope {
    Function,
    Class,
    File,
    Block,
    Module,
}

// ---------------------------------------------------------------------------
// Error-handling overrides
// ---------------------------------------------------------------------------

/// Patterns the error-handling scanner should treat as intentional / safe.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorHandlingBlock {
    #[serde(default)]
    pub safe_ignore_patterns: Vec<SafePattern>,
}

/// A pattern that should be silently ignored by a scanner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafePattern {
    /// Regex pattern to match against source lines.
    pub pattern: String,

    /// Why this pattern is safe (shown in verbose output).
    #[serde(default)]
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Sensitive-logging overrides
// ---------------------------------------------------------------------------

/// Overrides for the sensitive-logging scanner.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SensitiveLoggingBlock {
    /// Strings that look sensitive but are actually safe in this framework
    /// context (e.g. `"token expired"` is a message, not a token value).
    #[serde(default)]
    pub safe_patterns: Vec<String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the built-in NestJS pack deserializes without errors.
    #[test]
    fn parse_nestjs_yaml() {
        let yaml = include_str!("../../rules/builtin/nestjs.yaml");
        let pack: RulePack = serde_yaml::from_str(yaml).expect("nestjs.yaml should parse");
        assert_eq!(pack.name, "NestJS");
        assert!(!pack.protection_evidence.is_empty());
        assert!(!pack.data_source_evidence.is_empty());
    }

    /// Verify the built-in Express pack deserializes without errors.
    #[test]
    fn parse_express_yaml() {
        let yaml = include_str!("../../rules/builtin/express.yaml");
        let pack: RulePack = serde_yaml::from_str(yaml).expect("express.yaml should parse");
        assert_eq!(pack.name, "Express");
        assert!(!pack.protection_evidence.is_empty());
        assert!(!pack.data_source_evidence.is_empty());
    }

    #[test]
    fn evidence_kind_serde_roundtrip() {
        let kinds = vec![
            (EvidenceKind::Auth, "\"auth\""),
            (EvidenceKind::AuthExempt, "\"auth-exempt\""),
            (EvidenceKind::RateLimit, "\"rate-limit\""),
            (EvidenceKind::RealData, "\"real-data\""),
            (EvidenceKind::SafeIgnore, "\"safe-ignore\""),
        ];
        for (kind, expected_json) in kinds {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, expected_json, "serialization of {:?}", kind);
            let back: EvidenceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn rule_type_serde() {
        let rt: RuleType = serde_yaml::from_str("regex").unwrap();
        assert_eq!(rt, RuleType::Regex);
        let rt: RuleType = serde_yaml::from_str("tree-sitter").unwrap();
        assert_eq!(rt, RuleType::TreeSitter);
    }

    #[test]
    fn scope_defaults_to_function() {
        let yaml = r#"
id: test-rule
type: regex
pattern: "foo"
kind: auth
confidence: 0.9
"#;
        let rule: EvidenceRule = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(rule.scope, EvidenceScope::Function);
    }
}
