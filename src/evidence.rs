use dashmap::DashMap;
use std::path::{Path, PathBuf};

use crate::indexer::types::MiddlewareScope;

// ---------------------------------------------------------------------------
// EvidenceKind
// ---------------------------------------------------------------------------

/// Describes *what* type of protection or annotation a piece of evidence
/// represents. Each variant maps to a broad category that multiple scanners
/// can query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceKind {
    /// Authentication protection (middleware, guard, decorator, DI).
    Auth,
    /// Explicitly declared as not needing auth (`@Public`, `auth_exceptions`).
    AuthExempt,
    /// Rate limiting protection.
    RateLimit,
    /// Audit logging.
    Audit,
    /// CSRF protection.
    Csrf,
    /// 2FA verification.
    TwoFactor,
    /// Soft delete (vs hard delete).
    SoftDelete,
    /// Real data source (API call, DB query, service injection).
    RealData,
    /// Error has been handled.
    ErrorHandled,
    /// Can be safely ignored.
    SafeIgnore,
}

// ---------------------------------------------------------------------------
// EvidenceScope
// ---------------------------------------------------------------------------

/// How broadly the evidence applies in the source tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceScope {
    /// Single function / method.
    Function,
    /// All methods in a class.
    Class,
    /// Entire file.
    File,
    /// Code block (e.g. router group).
    Block,
    /// Module level.
    Module,
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// A single piece of evidence that something is protected / annotated.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Evidence {
    pub kind: EvidenceKind,
    /// Confidence score in the range `0.0..=1.0`.
    pub confidence: f64,
    /// Rule name or source identifier (e.g. `"nestjs-class-guard"`).
    pub source: String,
    pub file: PathBuf,
    pub line_start: usize,
    pub line_end: usize,
    pub scope: EvidenceScope,
}

// ---------------------------------------------------------------------------
// EvidenceResult
// ---------------------------------------------------------------------------

/// High-level protection verdict returned by [`EvidenceStore::has_protection`].
#[derive(Debug, Clone, PartialEq)]
pub enum EvidenceResult {
    /// confidence >= 0.8
    Protected(f64),
    /// 0.5 <= confidence < 0.8
    Likely(f64),
    /// confidence < 0.5
    Suspect(f64),
    /// Explicitly exempted (`AuthExempt` found).
    Exempt,
    /// No evidence found at all.
    NoEvidence,
}

// ---------------------------------------------------------------------------
// EvidenceStore
// ---------------------------------------------------------------------------

/// Thread-safe store for all evidence entries, keyed by file path.
pub struct EvidenceStore {
    entries: DashMap<PathBuf, Vec<Evidence>>,
}

impl EvidenceStore {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Add a single evidence entry.
    pub fn add(&self, evidence: Evidence) {
        self.entries
            .entry(evidence.file.clone())
            .or_default()
            .push(evidence);
    }

    /// Add many evidence entries at once (e.g. migration from
    /// `MiddlewareScope`).
    pub fn add_batch(&self, evidences: Vec<Evidence>) {
        for evidence in evidences {
            self.add(evidence);
        }
    }

    /// Query evidence for a specific file + line + kind.
    ///
    /// Returns all entries where `line` falls within `[line_start, line_end]`.
    pub fn query(&self, file: &Path, line: usize, kind: EvidenceKind) -> Vec<Evidence> {
        self.entries
            .get(file)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| e.kind == kind && line >= e.line_start && line <= e.line_end)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Query *all* evidence for a file + line regardless of kind.
    pub fn query_all(&self, file: &Path, line: usize) -> Vec<Evidence> {
        self.entries
            .get(file)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|e| line >= e.line_start && line <= e.line_end)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// High-level check: does this endpoint have protection of a given kind?
    pub fn has_protection(&self, file: &Path, line: usize, kind: EvidenceKind) -> EvidenceResult {
        if kind == EvidenceKind::Auth {
            let exemptions = self.query(file, line, EvidenceKind::AuthExempt);
            if !exemptions.is_empty() {
                return EvidenceResult::Exempt;
            }
        }

        let evidences = self.query(file, line, kind);

        let max_confidence = evidences
            .iter()
            .map(|e| e.confidence)
            .fold(f64::NEG_INFINITY, f64::max);

        match max_confidence {
            c if c >= 0.8 => EvidenceResult::Protected(c),
            c if c >= 0.5 => EvidenceResult::Likely(c),
            c if c > f64::NEG_INFINITY => EvidenceResult::Suspect(c),
            _ => EvidenceResult::NoEvidence,
        }
    }

    /// Total count of all evidence entries (for diagnostics).
    pub fn len(&self) -> usize {
        self.entries.iter().map(|entry| entry.value().len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for EvidenceStore {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Migration helpers: MiddlewareScope -> Evidence
// ---------------------------------------------------------------------------

/// Convert a legacy [`MiddlewareScope`] into an [`Evidence`] entry.
pub fn from_middleware_scope(scope: &MiddlewareScope) -> Evidence {
    let name_lower = scope.middleware_name.to_lowercase();

    let (kind, confidence) = if contains_auth_keyword(&name_lower) {
        (EvidenceKind::Auth, 0.85)
    } else if name_lower.contains("rate")
        || name_lower.contains("throttle")
        || name_lower.contains("limit")
    {
        (EvidenceKind::RateLimit, 0.80)
    } else if name_lower.contains("csrf") || name_lower.contains("csurf") {
        (EvidenceKind::Csrf, 0.85)
    } else if name_lower.contains("audit") || name_lower.contains("log") {
        (EvidenceKind::Audit, 0.75)
    } else {
        (EvidenceKind::Auth, 0.40)
    };

    Evidence {
        kind,
        confidence,
        source: format!("middleware:{}", scope.middleware_name),
        file: scope.file.clone(),
        line_start: scope.line_start,
        line_end: scope.line_end,
        scope: EvidenceScope::Block,
    }
}

fn contains_auth_keyword(name: &str) -> bool {
    const AUTH_KEYWORDS: &[&str] = &[
        "auth", "guard", "verify", "jwt", "session", "protect", "passport", "login",
    ];
    AUTH_KEYWORDS.iter().any(|kw| name.contains(kw))
}
