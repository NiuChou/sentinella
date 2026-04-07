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
    ///
    /// This replaces the old `endpoint_has_auth_scope()` pattern.
    pub fn has_protection(&self, file: &Path, line: usize, kind: EvidenceKind) -> EvidenceResult {
        // Check for explicit exemption first (only relevant for Auth queries).
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
///
/// This allows gradual migration: parsers can still populate
/// `middleware_scopes`, and we convert them to `Evidence` before scanners run.
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
        // Unknown middleware — low confidence auth guess.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_evidence(kind: EvidenceKind, confidence: f64, start: usize, end: usize) -> Evidence {
        Evidence {
            kind,
            confidence,
            source: "test".to_string(),
            file: PathBuf::from("app/routes.ts"),
            line_start: start,
            line_end: end,
            scope: EvidenceScope::Block,
        }
    }

    #[test]
    fn add_and_query_basic() {
        let store = EvidenceStore::new();
        store.add(make_evidence(EvidenceKind::Auth, 0.9, 10, 50));

        let results = store.query(Path::new("app/routes.ts"), 25, EvidenceKind::Auth);
        assert_eq!(results.len(), 1);
        assert!((results[0].confidence - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn query_outside_range_returns_empty() {
        let store = EvidenceStore::new();
        store.add(make_evidence(EvidenceKind::Auth, 0.9, 10, 50));

        let results = store.query(Path::new("app/routes.ts"), 5, EvidenceKind::Auth);
        assert!(results.is_empty());
    }

    #[test]
    fn query_wrong_kind_returns_empty() {
        let store = EvidenceStore::new();
        store.add(make_evidence(EvidenceKind::Auth, 0.9, 10, 50));

        let results = store.query(Path::new("app/routes.ts"), 25, EvidenceKind::RateLimit);
        assert!(results.is_empty());
    }

    #[test]
    fn query_all_returns_every_kind() {
        let store = EvidenceStore::new();
        store.add(make_evidence(EvidenceKind::Auth, 0.9, 10, 50));
        store.add(make_evidence(EvidenceKind::RateLimit, 0.8, 10, 50));

        let results = store.query_all(Path::new("app/routes.ts"), 25);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn has_protection_protected() {
        let store = EvidenceStore::new();
        store.add(make_evidence(EvidenceKind::Auth, 0.9, 10, 50));

        let result = store.has_protection(Path::new("app/routes.ts"), 25, EvidenceKind::Auth);
        assert!(matches!(result, EvidenceResult::Protected(c) if c >= 0.8));
    }

    #[test]
    fn has_protection_likely() {
        let store = EvidenceStore::new();
        store.add(make_evidence(EvidenceKind::Auth, 0.6, 10, 50));

        let result = store.has_protection(Path::new("app/routes.ts"), 25, EvidenceKind::Auth);
        assert!(matches!(result, EvidenceResult::Likely(c) if (0.5..0.8).contains(&c)));
    }

    #[test]
    fn has_protection_suspect() {
        let store = EvidenceStore::new();
        store.add(make_evidence(EvidenceKind::Auth, 0.3, 10, 50));

        let result = store.has_protection(Path::new("app/routes.ts"), 25, EvidenceKind::Auth);
        assert!(matches!(result, EvidenceResult::Suspect(_)));
    }

    #[test]
    fn has_protection_exempt() {
        let store = EvidenceStore::new();
        store.add(make_evidence(EvidenceKind::AuthExempt, 1.0, 10, 50));

        let result = store.has_protection(Path::new("app/routes.ts"), 25, EvidenceKind::Auth);
        assert_eq!(result, EvidenceResult::Exempt);
    }

    #[test]
    fn has_protection_no_evidence() {
        let store = EvidenceStore::new();

        let result = store.has_protection(Path::new("app/routes.ts"), 25, EvidenceKind::Auth);
        assert_eq!(result, EvidenceResult::NoEvidence);
    }

    #[test]
    fn len_and_is_empty() {
        let store = EvidenceStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        store.add(make_evidence(EvidenceKind::Auth, 0.9, 1, 10));
        store.add(make_evidence(EvidenceKind::Csrf, 0.8, 1, 10));
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
    }

    #[test]
    fn add_batch_inserts_all() {
        let store = EvidenceStore::new();
        let batch = vec![
            make_evidence(EvidenceKind::Auth, 0.9, 1, 10),
            make_evidence(EvidenceKind::RateLimit, 0.8, 1, 10),
            make_evidence(EvidenceKind::Csrf, 0.85, 1, 10),
        ];
        store.add_batch(batch);
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn from_middleware_scope_auth() {
        let scope = MiddlewareScope {
            router_var: "app".to_string(),
            middleware_name: "authGuard".to_string(),
            file: PathBuf::from("src/main.ts"),
            line_start: 1,
            line_end: 100,
        };
        let ev = from_middleware_scope(&scope);
        assert_eq!(ev.kind, EvidenceKind::Auth);
        assert!((ev.confidence - 0.85).abs() < f64::EPSILON);
        assert_eq!(ev.source, "middleware:authGuard");
    }

    #[test]
    fn from_middleware_scope_rate_limit() {
        let scope = MiddlewareScope {
            router_var: "app".to_string(),
            middleware_name: "rateLimit".to_string(),
            file: PathBuf::from("src/main.ts"),
            line_start: 1,
            line_end: 100,
        };
        let ev = from_middleware_scope(&scope);
        assert_eq!(ev.kind, EvidenceKind::RateLimit);
        assert!((ev.confidence - 0.80).abs() < f64::EPSILON);
    }

    #[test]
    fn from_middleware_scope_csrf() {
        let scope = MiddlewareScope {
            router_var: "app".to_string(),
            middleware_name: "csurf".to_string(),
            file: PathBuf::from("src/main.ts"),
            line_start: 1,
            line_end: 100,
        };
        let ev = from_middleware_scope(&scope);
        assert_eq!(ev.kind, EvidenceKind::Csrf);
    }

    #[test]
    fn from_middleware_scope_audit() {
        let scope = MiddlewareScope {
            router_var: "app".to_string(),
            middleware_name: "auditLogger".to_string(),
            file: PathBuf::from("src/main.ts"),
            line_start: 1,
            line_end: 100,
        };
        let ev = from_middleware_scope(&scope);
        assert_eq!(ev.kind, EvidenceKind::Audit);
    }

    #[test]
    fn from_middleware_scope_unknown_falls_back_to_low_confidence_auth() {
        let scope = MiddlewareScope {
            router_var: "app".to_string(),
            middleware_name: "cors".to_string(),
            file: PathBuf::from("src/main.ts"),
            line_start: 1,
            line_end: 100,
        };
        let ev = from_middleware_scope(&scope);
        assert_eq!(ev.kind, EvidenceKind::Auth);
        assert!((ev.confidence - 0.40).abs() < f64::EPSILON);
    }
}
