use std::fmt;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Arc;

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
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Suspect,   // < 0.5 -- low confidence, likely false positive
    Likely,    // 0.5-0.8 -- medium confidence, needs review
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
    #[serde(default = "default_confidence")]
    pub confidence: Confidence,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggestion: Option<String>,
}

fn default_confidence() -> Confidence {
    Confidence::Likely
}

impl Finding {
    pub fn new(scanner: &str, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            scanner: scanner.to_string(),
            severity,
            confidence: Confidence::Likely,
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
    /// The ID is based on scanner name, relative file path, and a normalized
    /// message pattern. Line numbers are excluded because code moves between
    /// edits while the finding identity remains the same.
    pub fn stable_id(&self, root: &std::path::Path) -> String {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.scanner.hash(&mut hasher);
        if let Some(ref file) = self.file {
            let rel = file.strip_prefix(root).unwrap_or(file);
            rel.to_string_lossy().hash(&mut hasher);
        }
        self.normalize_message().hash(&mut hasher);
        let hash = hasher.finish();
        format!("{}-{:08x}", self.scanner, hash as u32)
    }

    fn normalize_message(&self) -> String {
        let re_method =
            regex::Regex::new(r"(GET|POST|PUT|PATCH|DELETE)\s+\S+").expect("valid regex");
        let normalized = re_method.replace_all(&self.message, "METHOD PATH");
        let re_line = regex::Regex::new(r"line \d+").expect("valid regex");
        let normalized = re_line.replace_all(&normalized, "line N");
        normalized.into_owned()
    }
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
