use std::collections::HashMap;
use std::path::PathBuf;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

pub struct RateLimitingCoverage;

const SCANNER_ID: &str = "S22";
const SCANNER_NAME: &str = "RateLimitingCoverage";
const SCANNER_DESC: &str =
    "Checks whether authentication and sensitive endpoints have rate limiting protection";

/// Keywords that identify auth-related endpoints.
const AUTH_KEYWORDS: &[&str] = &[
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

/// Returns true if the endpoint path contains any auth-related keyword.
fn is_auth_endpoint(path: &str) -> bool {
    let lower = path.to_lowercase();
    AUTH_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Compute score from the ratio of protected auth endpoints to total auth endpoints.
/// Returns 100 when there are no auth endpoints (not applicable).
fn compute_score(protected: usize, total: usize) -> u8 {
    if total == 0 {
        return 100;
    }
    ((protected as f64 / total as f64) * 100.0).round() as u8
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
    format!(
        "{}/{} auth endpoints lack rate limiting ({} unprotected, score: {})",
        findings.len(),
        total,
        findings.len(),
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
        let all_endpoints = ctx.index.all_api_endpoints();

        let auth_endpoints: Vec<_> = all_endpoints
            .iter()
            .filter(|ep| is_auth_endpoint(&ep.path))
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

        // Group rate limit refs by file with their line numbers so we can check
        // proximity rather than mere file-level co-occurrence.
        const PROXIMITY_LINES: usize = 30;

        let rate_limit_by_file: HashMap<PathBuf, Vec<usize>> = {
            let mut map: HashMap<PathBuf, Vec<usize>> = HashMap::new();
            for r in ctx.index.all_rate_limit_refs() {
                map.entry(r.file).or_default().push(r.line);
            }
            map
        };

        let mut findings = Vec::new();

        for ep in &auth_endpoints {
            let is_protected = rate_limit_by_file
                .get(&ep.file)
                .map(|lines| {
                    lines.iter().any(|&rl_line| {
                        // Rate limit should appear before or at the endpoint definition
                        // (decorators/middleware are usually above the handler).
                        rl_line <= ep.line && ep.line - rl_line <= PROXIMITY_LINES
                    })
                })
                .unwrap_or(false);

            if !is_protected {
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
        }

        let protected = total_auth - findings.len();
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
        store.api_endpoints.entry(key).or_default().push(ep.clone());
    }

    fn insert_rate_limit(store: &IndexStore, file: &str, line: usize, limit_type: RateLimitType) {
        let path = PathBuf::from(file);
        store
            .rate_limit_refs
            .entry(path.clone())
            .or_default()
            .push(RateLimitRef {
                file: path,
                line,
                endpoint_hint: None,
                limit_type,
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
        insert_rate_limit(&store, "src/auth/login.ts", 5, RateLimitType::Decorator);

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

        // Auth endpoint WITH rate limiting
        let ep1 = make_endpoint(HttpMethod::Post, "/api/login", "src/auth/login.ts", 10);
        insert_endpoint(&store, &ep1);
        insert_rate_limit(&store, "src/auth/login.ts", 5, RateLimitType::Middleware);

        // Auth endpoint WITHOUT rate limiting
        let ep2 = make_endpoint(
            HttpMethod::Post,
            "/api/register",
            "src/auth/register.ts",
            20,
        );
        insert_endpoint(&store, &ep2);

        // Auth endpoint WITHOUT rate limiting
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
        // 1 protected out of 3 = 33%
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

        // Non-auth endpoints (no rate limiting needed for this scanner)
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
            insert_rate_limit(&store, "src/auth/login.ts", 5, limit_type);

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
}
