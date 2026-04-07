use crate::evidence::{EvidenceKind, EvidenceResult};
use crate::indexer::types::HttpMethod;
use crate::scanners::types::{Confidence, Finding, ScanContext, ScanResult, Scanner, Severity};
use std::path::Path;

const SCANNER_ID: &str = "S7";
const SCANNER_NAME: &str = "SecurityCompleteness";
const SCANNER_DESC: &str =
    "Checks that API endpoints are protected by auth middleware (auth, guard, verify, jwt, session, protect).";

// TODO(P1): move to rule pack YAML
// Kept for the migration layer in evidence.rs and for test assertions.
#[allow(dead_code)]
const AUTH_KEYWORDS: &[&str] = &["auth", "guard", "verify", "jwt", "session", "protect"];

pub struct SecurityCompleteness;

// TODO(P1): move to rule pack YAML
// Kept for the migration layer in evidence.rs and for test assertions.
#[cfg(test)]
fn is_auth_middleware(name: &str) -> bool {
    let lower = name.to_lowercase();
    AUTH_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

fn is_mutating(method: HttpMethod) -> bool {
    matches!(
        method,
        HttpMethod::Post | HttpMethod::Put | HttpMethod::Delete | HttpMethod::Patch
    )
}

/// Compute score from endpoint protection ratio.
fn compute_score(protected: usize, total_endpoints: usize) -> u8 {
    if total_endpoints == 0 {
        return 100;
    }
    ((protected as f64 / total_endpoints as f64) * 100.0).round() as u8
}

fn build_summary(
    findings: &[Finding],
    total_endpoints: usize,
    protected_count: usize,
    score: u8,
) -> String {
    if total_endpoints == 0 {
        return "No API endpoints found to check.".to_string();
    }

    let unprotected = total_endpoints - protected_count;
    if unprotected > 0 {
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical && f.message.contains("auth middleware"))
            .count();
        format!(
            "{}/{} endpoints unprotected ({} critical). Score: {}%.",
            unprotected, total_endpoints, critical_count, score
        )
    } else {
        format!("All endpoints protected. Score: {}%.", score)
    }
}

/// Query the evidence store for auth protection at a given file/line.
///
/// Replaces the old `endpoint_has_auth_scope()` which read directly from
/// `middleware_scopes`.
fn endpoint_protection(ctx: &ScanContext, file: &Path, line: usize) -> EvidenceResult {
    ctx.index
        .evidence_store
        .has_protection(file, line, EvidenceKind::Auth)
}

impl Scanner for SecurityCompleteness {
    fn id(&self) -> &str {
        SCANNER_ID
    }

    fn name(&self) -> &str {
        SCANNER_NAME
    }

    fn description(&self) -> &str {
        SCANNER_DESC
    }

    fn scan(&self, ctx: &ScanContext) -> ScanResult {
        let all_endpoints = ctx.index.all_api_endpoints();
        let mut findings: Vec<Finding> = Vec::new();

        let total_endpoints = all_endpoints.len();
        let mut protected_count: usize = 0;

        for ep in &all_endpoints {
            match endpoint_protection(ctx, &ep.file, ep.line) {
                EvidenceResult::Protected(_) | EvidenceResult::Exempt => {
                    protected_count += 1;
                }
                EvidenceResult::Likely(conf) => {
                    // Probably protected but not certain — Info level
                    protected_count += 1;
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Info,
                            format!(
                                "{} {} likely has auth middleware but confidence is moderate",
                                ep.method, ep.path
                            ),
                        )
                        .with_confidence(Confidence::from_score(conf))
                        .with_file(&ep.file)
                        .with_line(ep.line)
                        .with_suggestion(
                            "Verify this endpoint is explicitly wrapped with auth middleware."
                                .to_string(),
                        ),
                    );
                }
                EvidenceResult::Suspect(conf) => {
                    // Low confidence — Warning instead of Critical
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Warning,
                            format!(
                                "{} {} has low-confidence auth protection",
                                ep.method, ep.path
                            ),
                        )
                        .with_confidence(Confidence::from_score(conf))
                        .with_file(&ep.file)
                        .with_line(ep.line)
                        .with_suggestion(format!(
                            "Wrap this {} endpoint with an auth middleware (e.g. requireAuth, verifyJwt).",
                            ep.method
                        )),
                    );
                }
                EvidenceResult::NoEvidence => {
                    // No protection evidence — severity depends on mutation risk
                    let severity = if is_mutating(ep.method) {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    };

                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            severity,
                            format!(
                                "{} {} has no auth middleware protection",
                                ep.method, ep.path
                            ),
                        )
                        .with_confidence(Confidence::Likely)
                        .with_file(&ep.file)
                        .with_line(ep.line)
                        .with_suggestion(format!(
                            "Wrap this {} endpoint with an auth middleware (e.g. requireAuth, verifyJwt).",
                            ep.method
                        )),
                    );
                }
            }
        }

        let score = compute_score(protected_count, total_endpoints);
        let summary = build_summary(&findings, total_endpoints, protected_count, score);

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::evidence::{Evidence, EvidenceKind, EvidenceScope};
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{ApiEndpoint, Framework, MiddlewareScope};
    use std::path::{Path, PathBuf};

    fn default_config() -> Config {
        Config {
            version: "1.0".into(),
            project: "test".into(),
            r#type: Default::default(),
            layers: Default::default(),
            modules: Default::default(),
            flows: Default::default(),
            deploy: Default::default(),
            integration_tests: Default::default(),
            events: Default::default(),
            env: Default::default(),
            output: Default::default(),
            dispatch: Default::default(),
            data_isolation: Default::default(),
            required_layers: Default::default(),
            linked_repos: Vec::new(),
            suppress: None,
        }
    }

    fn make_endpoint(method: HttpMethod, path: &str, file: &str, line: usize) -> ApiEndpoint {
        ApiEndpoint {
            method,
            path: path.to_string(),
            file: PathBuf::from(file),
            line,
            framework: Framework::Express,
        }
    }

    /// Add auth evidence to the evidence store (replaces direct middleware_scopes insertion).
    fn add_auth_evidence(store: &IndexStore, file: &Path, line_start: usize, line_end: usize) {
        store.evidence_store.add(Evidence {
            kind: EvidenceKind::Auth,
            confidence: 0.95,
            source: "test".to_string(),
            file: file.to_path_buf(),
            line_start,
            line_end,
            scope: EvidenceScope::Block,
        });
    }

    #[test]
    fn test_no_endpoints_gives_perfect_score() {
        let config = default_config();
        let store = IndexStore::new();

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = SecurityCompleteness.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_unprotected_post_is_critical() {
        let config = default_config();
        let store = IndexStore::new();

        store.api_endpoints.insert(
            "/users".into(),
            vec![make_endpoint(
                HttpMethod::Post,
                "/users",
                "routes/users.ts",
                10,
            )],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = SecurityCompleteness.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_unprotected_get_is_warning() {
        let config = default_config();
        let store = IndexStore::new();

        store.api_endpoints.insert(
            "/health".into(),
            vec![make_endpoint(
                HttpMethod::Get,
                "/health",
                "routes/health.ts",
                5,
            )],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = SecurityCompleteness.scan(&ctx);
        assert_eq!(result.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_protected_endpoint_passes() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/users.ts");

        store.api_endpoints.insert(
            "/users".into(),
            vec![make_endpoint(
                HttpMethod::Post,
                "/users",
                "routes/users.ts",
                10,
            )],
        );

        // Populate evidence store (primary path for S7)
        add_auth_evidence(&store, &file, 5, 20);

        // Keep legacy middleware_scopes for backward compat
        store.middleware_scopes.insert(
            file.clone(),
            vec![MiddlewareScope {
                router_var: "router".into(),
                middleware_name: "requireAuth".into(),
                file: file.clone(),
                line_start: 5,
                line_end: 20,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = SecurityCompleteness.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_endpoint_outside_auth_scope_is_unprotected() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/users.ts");

        store.api_endpoints.insert(
            "/users".into(),
            vec![make_endpoint(
                HttpMethod::Delete,
                "/users",
                "routes/users.ts",
                30,
            )],
        );

        // Evidence only covers lines 5-20, endpoint is at line 30
        add_auth_evidence(&store, &file, 5, 20);

        // Keep legacy middleware_scopes for backward compat
        store.middleware_scopes.insert(
            file.clone(),
            vec![MiddlewareScope {
                router_var: "router".into(),
                middleware_name: "requireAuth".into(),
                file: file.clone(),
                line_start: 5,
                line_end: 20,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = SecurityCompleteness.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings[0].severity, Severity::Critical);
    }

    #[test]
    fn test_non_auth_middleware_does_not_protect() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/api.ts");

        store.api_endpoints.insert(
            "/data".into(),
            vec![make_endpoint(HttpMethod::Put, "/data", "routes/api.ts", 10)],
        );

        // Add low-confidence evidence (unknown middleware falls back to Auth at 0.40)
        store.evidence_store.add(Evidence {
            kind: EvidenceKind::Auth,
            confidence: 0.40,
            source: "middleware:rateLimiter".to_string(),
            file: file.to_path_buf(),
            line_start: 1,
            line_end: 50,
            scope: EvidenceScope::Block,
        });

        // Keep legacy middleware_scopes for backward compat
        store.middleware_scopes.insert(
            file.clone(),
            vec![MiddlewareScope {
                router_var: "router".into(),
                middleware_name: "rateLimiter".into(),
                file: file.clone(),
                line_start: 1,
                line_end: 50,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = SecurityCompleteness.scan(&ctx);
        // Low confidence (0.40 < 0.5) => Suspect => Warning
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_auth_keyword_matching() {
        assert!(is_auth_middleware("requireAuth"));
        assert!(is_auth_middleware("jwtVerify"));
        assert!(is_auth_middleware("sessionMiddleware"));
        assert!(is_auth_middleware("protectRoute"));
        assert!(is_auth_middleware("authGuard"));
        assert!(!is_auth_middleware("rateLimiter"));
        assert!(!is_auth_middleware("cors"));
        assert!(!is_auth_middleware("logger"));
    }

    #[test]
    fn test_mixed_protected_and_unprotected() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/mixed.ts");

        store.api_endpoints.insert(
            "/protected".into(),
            vec![make_endpoint(
                HttpMethod::Get,
                "/protected",
                "routes/mixed.ts",
                10,
            )],
        );
        store.api_endpoints.insert(
            "/open".into(),
            vec![make_endpoint(
                HttpMethod::Get,
                "/open",
                "routes/mixed.ts",
                30,
            )],
        );

        // Evidence covers lines 5-15 only (protects /protected at line 10)
        add_auth_evidence(&store, &file, 5, 15);

        // Keep legacy middleware_scopes for backward compat
        store.middleware_scopes.insert(
            file.clone(),
            vec![MiddlewareScope {
                router_var: "router".into(),
                middleware_name: "verifyToken".into(),
                file: file.clone(),
                line_start: 5,
                line_end: 15,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = SecurityCompleteness.scan(&ctx);
        assert_eq!(result.score, 50);
        assert_eq!(result.findings.len(), 1);
    }

    #[test]
    fn test_exempt_endpoint_is_protected() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/public.ts");

        store.api_endpoints.insert(
            "/health".into(),
            vec![make_endpoint(
                HttpMethod::Get,
                "/health",
                "routes/public.ts",
                10,
            )],
        );

        // Mark as explicitly exempt
        store.evidence_store.add(Evidence {
            kind: EvidenceKind::AuthExempt,
            confidence: 1.0,
            source: "test".to_string(),
            file: file.to_path_buf(),
            line_start: 1,
            line_end: 50,
            scope: EvidenceScope::File,
        });

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = SecurityCompleteness.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_likely_evidence_produces_info_finding() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/maybe.ts");

        store.api_endpoints.insert(
            "/maybe".into(),
            vec![make_endpoint(
                HttpMethod::Get,
                "/maybe",
                "routes/maybe.ts",
                10,
            )],
        );

        // Moderate confidence (0.6) => Likely => Info
        store.evidence_store.add(Evidence {
            kind: EvidenceKind::Auth,
            confidence: 0.6,
            source: "test".to_string(),
            file: file.to_path_buf(),
            line_start: 1,
            line_end: 50,
            scope: EvidenceScope::Block,
        });

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = SecurityCompleteness.scan(&ctx);
        // Likely counts as protected for score purposes
        assert_eq!(result.score, 100);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_confidence_is_set_on_no_evidence_findings() {
        let config = default_config();
        let store = IndexStore::new();

        store.api_endpoints.insert(
            "/users".into(),
            vec![make_endpoint(
                HttpMethod::Post,
                "/users",
                "routes/users.ts",
                10,
            )],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = SecurityCompleteness.scan(&ctx);
        assert_eq!(result.findings[0].confidence, Confidence::Likely);
    }
}
