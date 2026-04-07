use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PackSource — origin of a loaded rule pack
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackSource {
    Builtin,
    Community,
    User,
    Project,
}

impl std::fmt::Display for PackSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PackSource::Builtin => write!(f, "builtin"),
            PackSource::Community => write!(f, "community"),
            PackSource::User => write!(f, "user"),
            PackSource::Project => write!(f, "project"),
        }
    }
}

// ---------------------------------------------------------------------------
// RuleLifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuleLifecycle {
    Active,
    Deprecated,
    Experimental,
}

impl Default for RuleLifecycle {
    fn default() -> Self {
        Self::Active
    }
}

// ---------------------------------------------------------------------------
// EvidenceRule — a single pattern-matching rule inside a pack
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRule {
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    #[serde(default)]
    pub lifecycle: RuleLifecycle,
    #[serde(default)]
    pub deprecated_reason: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

fn default_confidence() -> f64 {
    0.5
}

// ---------------------------------------------------------------------------
// RulePack — top-level rule pack definition
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulePack {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub protection_evidence: Vec<EvidenceRule>,
    #[serde(default)]
    pub data_source_evidence: Vec<EvidenceRule>,

    /// Runtime-only field set by the loader; never serialized from YAML.
    #[serde(skip)]
    pub source: Option<PackSource>,
}

// ---------------------------------------------------------------------------
// LoadedPack — convenience wrapper returned by the loader
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LoadedPack {
    pub pack: RulePack,
    pub source: PackSource,
}
