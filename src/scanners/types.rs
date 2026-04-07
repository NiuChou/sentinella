use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::Config;
use crate::indexer::store::IndexStore;

// ---------------------------------------------------------------------------
// Confidence (Bayesian-calibrated)
// ---------------------------------------------------------------------------

/// Confidence level for a finding, derived from Bayesian calibration.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    /// Map a 0.0..=1.0 score to a discrete confidence level.
    pub fn from_score(score: f64) -> Self {
        if score >= 0.7 {
            Self::High
        } else if score >= 0.4 {
            Self::Medium
        } else {
            Self::Low
        }
    }

    /// Return a representative numeric score for the confidence level.
    pub fn as_score(&self) -> f64 {
        match self {
            Self::High => 0.85,
            Self::Medium => 0.55,
            Self::Low => 0.25,
        }
    }
}

impl Default for Confidence {
    fn default() -> Self {
        Self::High
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::High => write!(f, "high"),
            Self::Medium => write!(f, "medium"),
            Self::Low => write!(f, "low"),
        }
    }
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

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

    pub fn with_confidence(self, confidence: Confidence) -> Self {
        Self { confidence, ..self }
    }

    /// Compute a stable identifier for deduplication across scans.
    /// Format: "{scanner}:{relative_file}:{line_or_0}:{message_prefix}"
    pub fn stable_id(&self, root: &Path) -> String {
        let file_part = self
            .file
            .as_ref()
            .and_then(|f| f.strip_prefix(root).ok())
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let line_part = self.line.unwrap_or(0);
        let msg_prefix: String = self.message.chars().take(60).collect();
        format!(
            "{}:{}:{}:{}",
            self.scanner, file_part, line_part, msg_prefix
        )
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
