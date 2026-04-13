use std::collections::HashMap;
use std::path::PathBuf;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

pub struct RateLimitingCoverage;

const SCANNER_ID: &str = "S22";
const SCANNER_NAME: &str = "RateLimitingCoverage";
const SCANNER_DESC: &str =
    "Checks whether authentication and sensitive endpoints have rate limiting protection, \
     validates Retry-After header inclusion, and detects refresh endpoint rate-limit deadlocks";

/// Default keywords that identify auth-related endpoints.
const DEFAULT_AUTH_KEYWORDS: &[&str] = &[
    "login",
    "auth",
    "verify",
    "reset-password",
    "otp",
    "register",
    "sms",
    "token",
    "refresh",
    "callback",
];

/// Keywords that identify refresh/token endpoints that should be excluded from
/// aggressive rate limiting to avoid deadlock (user locked out of re-auth).
/// These must co-occur with an auth keyword to avoid matching non-auth refreshes
/// like `/api/refresh-cache` or `/api/data/refresh`.
const REFRESH_KEYWORDS: &[&str] = &["refresh", "token/refresh", "auth/refresh"];

/// Auth-context keywords that confirm a "refresh" endpoint is auth-related.
const AUTH_CONTEXT_KEYWORDS: &[&str] = &["auth", "token", "login", "session", "oauth"];

/// Returns true if the endpoint path contains any of the given keywords.
fn is_auth_endpoint_with_keywords(path: &str, keywords: &[&str]) -> bool {
    let lower = path.to_lowercase();
    keywords.iter().any(|kw| lower.contains(kw))
}

/// Returns true if the endpoint path is an **auth-related** refresh endpoint.
/// Requires both a refresh keyword AND an auth-context keyword to avoid
/// false positives on non-auth refresh endpoints like `/api/refresh-cache`.
fn is_refresh_endpoint(path: &str) -> bool {
    let lower = path.to_lowercase();
    let has_refresh = REFRESH_KEYWORDS.iter().any(|kw| lower.contains(kw));
    if !has_refresh {
        return false;
    }
    // Must also have auth context — "token/refresh" and "auth/refresh" already
    // contain auth keywords, but standalone "/refresh" needs a second signal.
    AUTH_CONTEXT_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Compute score from the ratio of protected auth endpoints to total auth endpoints.
/// Returns 100 when there are no auth endpoints (not applicable).
fn compute_score(protected: usize, total: usize) -> u8 {
    if total == 0 {
        return 100;
    }
    ((protected as f64 / total as f64) * 100.0).round() as u8
}

/// Returns true if the endpoint path contains any auth keyword (default set).
#[cfg(test)]
fn is_auth_endpoint(path: &str) -> bool {
    is_auth_endpoint_with_keywords(path, DEFAULT_AUTH_KEYWORDS)
}

fn build_summary(findings: &[Finding], _protected: usize, total: usize, score: u8) -> String {
    if total == 0 {
        return "No authentication endpoints detected — rate limiting check not applicable"
            .to_string();
    }
    if findings.is_empty() {
        return format!(
            "All {} auth endpoints have rate limiting protection (score: {})",
            total, score
        );
    }

    let missing_rl = findings
        .iter()
        .filter(|f| f.message.contains("no rate limiting"))
        .count();
    let missing_retry = findings
        .iter()
        .filter(|f| f.message.contains("Retry-After"))
        .count();
    let deadlock = findings
        .iter()
        .filter(|f| f.message.contains("deadlock"))
        .count();

    let mut parts = Vec::new();
    if missing_rl > 0 {
        parts.push(format!("{} unprotected", missing_rl));
    }
    if missing_retry > 0 {
        parts.push(format!("{} missing Retry-After", missing_retry));
    }
    if deadlock > 0 {
        parts.push(format!("{} refresh deadlock risk", deadlock));
    }

    format!(
        "{}/{} auth endpoints with issues: {} (score: {})",
        findings.len(),
        total,
        parts.join(", "),
        score
    )
}

impl Scanner for RateLimitingCoverage {
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
        // Read rate-limit auth keywords from config override or fall back to defaults
        let config_keywords: Vec<String> = ctx
            .config
            .scanner_overrides
            .s22
            .as_ref()
            .map(|c| c.rate_limit_keywords.clone())
            .unwrap_or_default();
        let auth_kw: Vec<&str> = if config_keywords.is_empty() {
            DEFAULT_AUTH_KEYWORDS.to_vec()
        } else {
            config_keywords.iter().map(|s| s.as_str()).collect()
        };

        let all_endpoints = ctx.index.all_api_endpoints();

        let auth_endpoints: Vec<_> = all_endpoints
            .iter()
            .filter(|ep| is_auth_endpoint_with_keywords(&ep.path, &auth_kw))
            .collect();

        let total_auth = auth_endpoints.len();

        if total_auth == 0 {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: build_summary(&[], 0, 0, 100),
            };
        }

        // Group rate limit refs by file with their line numbers and metadata
        const PROXIMITY_LINES: usize = 30;

        let all_rate_limit_refs = ctx.index.all_rate_limit_refs();

        let rate_limit_by_file: HashMap<PathBuf, Vec<&crate::indexer::types::RateLimitRef>> = {
            let mut map: HashMap<PathBuf, Vec<&crate::indexer::types::RateLimitRef>> =
                HashMap::new();
            for r in &all_rate_limit_refs {
                map.entry(r.file.clone()).or_default().push(r);
            }
            map
        };

        let mut findings = Vec::new();

        for ep in &auth_endpoints {
            let matching_rl = rate_limit_by_file
                .get(&ep.file)
                .and_then(|refs| {
                    refs.iter().find(|rl| {
                        rl.line <= ep.line && ep.line - rl.line <= PROXIMITY_LINES
                    })
                });

            match matching_rl {
                None => {
                    // No rate limiting at all
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Critical,
                            format!(
                                "Auth endpoint {} {} has no rate limiting protection",
                                ep.method, ep.path
                            ),
                        )
                        .with_file(&ep.file)
                        .with_line(ep.line)
                        .with_suggestion(
                            "Add rate limiting (decorator, middleware, or library) to protect \
                             this authentication endpoint from brute-force attacks",
                        ),
                    );
                }
                Some(rl) => {
                    // Check 1: Rate limiting exists but missing Retry-After header
                    if !rl.has_retry_after {
                        findings.push(
                            Finding::new(
                                SCANNER_ID,
                                Severity::Warning,
                                format!(
                                    "Rate limiter for {} {} does not return Retry-After header",
                                    ep.method, ep.path
                                ),
                            )
                            .with_file(&ep.file)
                            .with_line(rl.line)
                            .with_suggestion(
                                "Configure the rate limiter to include a Retry-After header \
                                 so clients can implement proper backoff instead of hammering",
                            ),
                        );
                    }

                    // Check 2: Refresh endpoint under aggressive rate limiting = deadlock risk
                    if is_refresh_endpoint(&ep.path) {
                        findings.push(
                            Finding::new(
                                SCANNER_ID,
                                Severity::Critical,
                                format!(
                                    "Refresh endpoint {} {} is rate-limited — deadlock risk: \
                                     expired tokens + rate limit = user locked out",
                                    ep.method, ep.path
                                ),
                            )
                            .with_file(&ep.file)
                            .with_line(ep.line)
                            .with_suggestion(
                                "Exclude refresh/token-renewal endpoints from global rate limiting \
                                 or use a much higher limit. Rate-limiting refresh causes users \
                                 with expired tokens to be permanently locked out",
                            ),
                        );
                    }
                }
            }
        }

        // Score: only count the "no rate limiting" findings as truly unprotected
        let unprotected = findings
            .iter()
            .filter(|f| f.message.contains("no rate limiting"))
            .count();
        let protected = total_auth - unprotected;
        let score = compute_score(protected, total_auth);
        let summary = build_summary(&findings, protected, total_auth, score);

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
    use crate::config::schema::Config;
    use crate::indexer::store::{normalize_api_path, IndexStore};
    use crate::indexer::types::{ApiEndpoint, Framework, HttpMethod, RateLimitRef, RateLimitType};
    use std::path::PathBuf;

    fn minimal_config() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
"#;
        serde_yaml::from_str(yaml).unwrap()
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

    fn insert_endpoint(store: &IndexStore, ep: &ApiEndpoint) {
        let key = normalize_api_path(&ep.path);
        store.api.endpoints.entry(key).or_default().push(ep.clone());
    }

    fn insert_rate_limit(
        store: &IndexStore,
        file: &str,
        line: usize,
        limit_type: RateLimitType,
        has_retry_after: bool,
    ) {
        let path = PathBuf::from(file);
        store
            .security
            .rate_limit_refs
            .entry(path.clone())
            .or_default()
            .push(RateLimitRef {
                file: path,
                line,
                endpoint_hint: None,
                limit_type,
                has_retry_after,
            });
    }

    #[test]
    fn no_auth_endpoints_perfect_score() {
        let store = IndexStore::new();
        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = RateLimitingCoverage.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
        assert!(result.summary.contains("not applicable"));
    }

    #[test]
    fn auth_endpoint_without_rate_limit() {
        let store = IndexStore::new();
        let ep = make_endpoint(HttpMethod::Post, "/api/login", "src/auth/login.ts", 10);
        insert_endpoint(&store, &ep);

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = RateLimitingCoverage.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].message.contains("login"));
    }

    #[test]
    fn auth_endpoint_with_rate_limit() {
        let store = IndexStore::new();
        let ep = make_endpoint(HttpMethod::Post, "/api/login", "src/auth/login.ts", 10);
        insert_endpoint(&store, &ep);
        insert_rate_limit(&store, "src/auth/login.ts", 5, RateLimitType::Decorator, true);

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = RateLimitingCoverage.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn mixed_coverage() {
        let store = IndexStore::new();

        let ep1 = make_endpoint(HttpMethod::Post, "/api/login", "src/auth/login.ts", 10);
        insert_endpoint(&store, &ep1);
        insert_rate_limit(
            &store,
            "src/auth/login.ts",
            5,
            RateLimitType::Middleware,
            true,
        );

        let ep2 = make_endpoint(
            HttpMethod::Post,
            "/api/register",
            "src/auth/register.ts",
            20,
        );
        insert_endpoint(&store, &ep2);

        let ep3 = make_endpoint(
            HttpMethod::Post,
            "/api/reset-password",
            "src/auth/reset.ts",
            15,
        );
        insert_endpoint(&store, &ep3);

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = RateLimitingCoverage.scan(&ctx);
        assert_eq!(result.score, 33);
        assert_eq!(result.findings.len(), 2);
        assert!(result
            .findings
            .iter()
            .all(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn non_auth_endpoints_ignored() {
        let store = IndexStore::new();

        let ep1 = make_endpoint(HttpMethod::Get, "/api/users", "src/users/list.ts", 5);
        insert_endpoint(&store, &ep1);

        let ep2 = make_endpoint(HttpMethod::Get, "/api/products", "src/products/list.ts", 8);
        insert_endpoint(&store, &ep2);

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = RateLimitingCoverage.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
        assert!(result.summary.contains("not applicable"));
    }

    #[test]
    fn all_auth_keywords_detected() {
        assert!(is_auth_endpoint("/api/login"));
        assert!(is_auth_endpoint("/api/auth/me"));
        assert!(is_auth_endpoint("/api/verify-email"));
        assert!(is_auth_endpoint("/api/reset-password"));
        assert!(is_auth_endpoint("/api/otp/send"));
        assert!(is_auth_endpoint("/api/register"));
        assert!(is_auth_endpoint("/api/sms/verify"));
        assert!(is_auth_endpoint("/api/token/refresh"));
        assert!(is_auth_endpoint("/api/refresh"));
        assert!(is_auth_endpoint("/api/callback/google"));
        assert!(!is_auth_endpoint("/api/users"));
        assert!(!is_auth_endpoint("/api/products/list"));
    }

    #[test]
    fn score_computation() {
        assert_eq!(compute_score(0, 0), 100);
        assert_eq!(compute_score(3, 3), 100);
        assert_eq!(compute_score(0, 3), 0);
        assert_eq!(compute_score(1, 3), 33);
        assert_eq!(compute_score(2, 3), 67);
        assert_eq!(compute_score(1, 2), 50);
    }

    #[test]
    fn rate_limit_type_variants_all_protect() {
        for limit_type in [
            RateLimitType::Decorator,
            RateLimitType::Middleware,
            RateLimitType::Library,
        ] {
            let store = IndexStore::new();
            let ep = make_endpoint(HttpMethod::Post, "/api/login", "src/auth/login.ts", 10);
            insert_endpoint(&store, &ep);
            insert_rate_limit(&store, "src/auth/login.ts", 5, limit_type, true);

            let config = minimal_config();
            let ctx = ScanContext {
                config: &config,
                index: &store,
                root_dir: std::path::Path::new("."),
            };

            let result = RateLimitingCoverage.scan(&ctx);
            assert_eq!(result.score, 100, "Failed for {:?}", limit_type);
            assert!(result.findings.is_empty());
        }
    }

    // --- New tests for Retry-After and refresh deadlock ---

    #[test]
    fn rate_limit_without_retry_after_header() {
        let store = IndexStore::new();
        let ep = make_endpoint(HttpMethod::Post, "/api/login", "src/auth/login.ts", 10);
        insert_endpoint(&store, &ep);
        // has_retry_after = false
        insert_rate_limit(
            &store,
            "src/auth/login.ts",
            5,
            RateLimitType::Middleware,
            false,
        );

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = RateLimitingCoverage.scan(&ctx);
        // Has rate limiting → protected (score 100), but missing Retry-After → Warning
        assert_eq!(result.score, 100);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("Retry-After"));
    }

    #[test]
    fn refresh_endpoint_rate_limited_deadlock() {
        let store = IndexStore::new();
        let ep = make_endpoint(
            HttpMethod::Post,
            "/api/auth/refresh",
            "src/auth/refresh.ts",
            10,
        );
        insert_endpoint(&store, &ep);
        insert_rate_limit(
            &store,
            "src/auth/refresh.ts",
            5,
            RateLimitType::Middleware,
            true,
        );

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = RateLimitingCoverage.scan(&ctx);
        // Rate-limited refresh endpoint = deadlock risk
        assert_eq!(result.score, 100); // "protected" but with deadlock finding
        let deadlock_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("deadlock"))
            .collect();
        assert_eq!(deadlock_findings.len(), 1);
        assert_eq!(deadlock_findings[0].severity, Severity::Critical);
    }

    #[test]
    fn refresh_endpoint_not_rate_limited_is_fine() {
        let store = IndexStore::new();
        // Refresh endpoint without rate limiting — that's actually correct
        let ep = make_endpoint(
            HttpMethod::Post,
            "/api/auth/refresh",
            "src/auth/refresh.ts",
            10,
        );
        insert_endpoint(&store, &ep);
        // No rate limit inserted for this file

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = RateLimitingCoverage.scan(&ctx);
        // Missing rate limit = Critical, but no deadlock finding
        // (The "no rate limiting" finding is expected since it's still an auth keyword match)
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("no rate limiting"));
        // No deadlock finding
        assert!(!result
            .findings
            .iter()
            .any(|f| f.message.contains("deadlock")));
    }

    #[test]
    fn is_refresh_endpoint_detection() {
        // Auth-related refreshes — should match
        assert!(is_refresh_endpoint("/api/auth/refresh"));
        assert!(is_refresh_endpoint("/api/token/refresh"));
        assert!(is_refresh_endpoint("/api/oauth/refresh"));
        // Non-auth paths — should NOT match
        assert!(!is_refresh_endpoint("/api/login"));
        assert!(!is_refresh_endpoint("/api/register"));
        // Non-auth "refresh" — should NOT match (no auth context keyword)
        assert!(!is_refresh_endpoint("/api/refresh-cache"));
        assert!(!is_refresh_endpoint("/api/data/refresh"));
    }
}
