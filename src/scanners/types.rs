use std::fmt;
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
    Suspect,   // low confidence, likely false positive
    Likely,    // medium confidence, needs review
    Confirmed, // high confidence, AST-precise match
}

impl Default for Confidence {
    fn default() -> Self {
        Self::Likely
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
