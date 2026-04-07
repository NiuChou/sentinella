use crate::evidence::{EvidenceKind, EvidenceScope};
use serde::{Deserialize, Serialize};

/// A complete rule pack file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    pub kind: String,
    pub name: String,
    pub version: String,
    pub languages: Vec<String>,

    #[serde(default)]
    pub detect: DetectConfig,

    #[serde(default)]
    pub routes: Vec<RouteRule>,

    #[serde(default)]
    pub protection_evidence: Vec<ProtectionEvidenceRule>,

    #[serde(default)]
    pub data_source_evidence: Vec<DataSourceRule>,

    #[serde(default)]
    pub error_handling: ErrorHandlingConfig,

    #[serde(default)]
    pub sensitive_logging: SensitiveLoggingConfig,
}

/// How to auto-detect if this rule pack applies
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectConfig {
    #[serde(default)]
    pub package_json: Option<PackageJsonDetect>,
    #[serde(default)]
    pub requirements_txt: Option<Vec<String>>,
    #[serde(default)]
    pub pyproject_toml: Option<PyprojectDetect>,
    #[serde(default)]
    pub go_mod: Option<Vec<String>>,
    #[serde(default)]
    pub cargo_toml: Option<Vec<String>>,
    #[serde(default)]
    pub file_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageJsonDetect {
    #[serde(default)]
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyprojectDetect {
    #[serde(default)]
    pub dependencies: Vec<String>,
}

/// A route extraction rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub extract: Option<ExtractConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleType {
    TreeSitter,
    Regex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractConfig {
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
}

/// A protection evidence rule (auth, rate-limit, audit, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionEvidenceRule {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub scope: Option<EvidenceScope>,
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub match_condition: Option<MatchCondition>,
    pub provides: ProvidesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchCondition {
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub auth_func_keywords: Vec<String>,
    #[serde(default)]
    pub auth_class_keywords: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvidesConfig {
    pub kind: EvidenceKind,
    pub confidence: f64,
    #[serde(default)]
    pub scope_extends_to: Option<String>,
}

/// Data source evidence rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSourceRule {
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: RuleType,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    pub provides: ProvidesConfig,
}

/// Error handling configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ErrorHandlingConfig {
    #[serde(default)]
    pub safe_ignore_patterns: Vec<SafePattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafePattern {
    pub pattern: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Sensitive logging configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SensitiveLoggingConfig {
    #[serde(default)]
    pub safe_patterns: Vec<String>,
    #[serde(default)]
    pub mask_functions: Vec<String>,
}
