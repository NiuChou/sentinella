use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// RulePack YAML schema
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    #[serde(default)]
    pub description: String,
    pub kind: RuleKind,
    pub pattern: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(default)]
    pub suggestion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// Pattern that should NOT appear in code
    Antipattern,
    /// Pattern that MUST appear in code
    Required,
    /// Informational match (no pass/fail)
    Informational,
}

fn default_severity() -> String {
    "warning".to_string()
}

// ---------------------------------------------------------------------------
// Valid kind values (for validation without depending on serde)
// ---------------------------------------------------------------------------

pub const VALID_KINDS: &[&str] = &["antipattern", "required", "informational"];
