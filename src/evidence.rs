use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

/// The kind of evidence detected (auth, rate-limiting, etc.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    Auth,
    RateLimit,
    AuditLog,
    InputValidation,
    Encryption,
    Csrf,
    Cors,
    RealDataSource,
    ErrorHandling,
    Logging,
}

/// The scope at which evidence applies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceScope {
    Function,
    Class,
    File,
    Block,
    Module,
}

impl Default for EvidenceScope {
    fn default() -> Self {
        Self::Function
    }
}

/// A single piece of evidence found in source code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    pub confidence: f64,
    pub source: String,
    pub file: PathBuf,
    pub line_start: usize,
    pub line_end: usize,
    pub scope: EvidenceScope,
}

/// Thread-safe store for collecting evidence across scanners
#[derive(Debug, Default)]
pub struct EvidenceStore {
    entries: Mutex<Vec<Evidence>>,
}

impl EvidenceStore {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn add(&self, evidence: Evidence) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.push(evidence);
        }
    }

    /// Return a snapshot of all collected evidence (immutable copy)
    pub fn snapshot(&self) -> Vec<Evidence> {
        self.entries
            .lock()
            .map(|entries| entries.clone())
            .unwrap_or_default()
    }

    /// Query evidence covering a specific file and line range
    pub fn query_evidence(
        &self,
        file: &std::path::Path,
        line: usize,
        kind: EvidenceKind,
    ) -> Vec<Evidence> {
        self.snapshot()
            .into_iter()
            .filter(|e| {
                e.kind == kind && e.file == file && e.line_start <= line && e.line_end >= line
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
