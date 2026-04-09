use std::fmt;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::config::Config;
use crate::indexer::store::IndexStore;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Suspect, // < 0.5 -- low confidence, likely false positive
    #[default]
    Likely, // 0.5-0.8 -- medium confidence, needs review
    Confirmed, // >= 0.8 -- high confidence, AST-precise match
}

impl Confidence {
    /// Create `Confidence` from a float score (0.0 - 1.0).
    pub fn from_score(score: f64) -> Self {
        if score >= 0.8 {
            Confidence::Confirmed
        } else if score >= 0.5 {
            Confidence::Likely
        } else {
            Confidence::Suspect
        }
    }

    /// Convert to a representative float.
    pub fn as_score(&self) -> f64 {
        match self {
            Confidence::Confirmed => 0.95,
            Confidence::Likely => 0.65,
            Confidence::Suspect => 0.25,
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Confidence::Confirmed => write!(f, "Confirmed"),
            Confidence::Likely => write!(f, "Likely"),
            Confidence::Suspect => write!(f, "Suspect"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Finding {
    pub scanner: String,
    pub severity: Severity,
    #[serde(default)]
    pub confidence: Confidence,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

impl Finding {
    pub fn new(scanner: &str, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            scanner: scanner.to_string(),
            severity,
            confidence: Confidence::default(),
            message: message.into(),
            file: None,
            line: None,
            suggestion: None,
        }
    }

    pub fn with_confidence(self, confidence: Confidence) -> Self {
        Self { confidence, ..self }
    }

    pub fn with_file(self, file: impl Into<PathBuf>) -> Self {
        Self {
            file: Some(file.into()),
            ..self
        }
    }

    pub fn with_line(self, line: usize) -> Self {
        Self {
            line: Some(line),
            ..self
        }
    }

    pub fn with_suggestion(self, suggestion: impl Into<String>) -> Self {
        Self {
            suggestion: Some(suggestion.into()),
            ..self
        }
    }

    /// Generate a deterministic ID for tracking findings across runs.
    ///
    /// Uses FNV-1a (deterministic across Rust versions) over
    /// `"{scanner}:{rel_file}:{normalized_message}"`.  Line numbers are
    /// excluded because code moves between edits while finding identity stays.
    pub fn stable_id(&self, root: &std::path::Path) -> String {
        let rel_file = self
            .file
            .as_ref()
            .map(|f| {
                f.strip_prefix(root)
                    .unwrap_or(f)
                    .to_string_lossy()
                    .into_owned()
            })
            .unwrap_or_default();
        let key = format!("{}:{}:{}", self.scanner, rel_file, self.normalize_message());
        let hash = fnv1a_hash(&key);
        format!("{}-{:08x}", self.scanner, hash)
    }

    fn normalize_message(&self) -> String {
        static RE_METHOD: OnceLock<regex::Regex> = OnceLock::new();
        static RE_LINE: OnceLock<regex::Regex> = OnceLock::new();

        let re_method = RE_METHOD.get_or_init(|| {
            regex::Regex::new(r"(GET|POST|PUT|PATCH|DELETE)\s+\S+").expect("valid regex")
        });
        let normalized = re_method.replace_all(&self.message, "METHOD PATH");

        let re_line = RE_LINE.get_or_init(|| regex::Regex::new(r"line \d+").expect("valid regex"));
        re_line.replace_all(&normalized, "line N").into_owned()
    }
}

/// FNV-1a 32-bit hash — deterministic and stable across Rust versions.
pub fn fnv1a_hash(input: &str) -> u32 {
    let mut hash: u32 = 2_166_136_261;
    for byte in input.bytes() {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub scanner: String,
    pub findings: Vec<Finding>,
    pub score: u8,
    pub summary: String,
}

pub struct ScanContext<'a> {
    pub config: &'a Config,
    pub index: &'a Arc<IndexStore>,
    pub root_dir: &'a std::path::Path,
}

pub trait Scanner: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn scan(&self, ctx: &ScanContext) -> ScanResult;
}
