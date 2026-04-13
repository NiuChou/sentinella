use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};
use crate::indexer::types::InsecureStorageType;

pub struct InsecureTokenStorage;

const SCANNER_ID: &str = "S21";
const SCANNER_NAME: &str = "InsecureTokenStorage";
const SCANNER_DESC: &str =
    "Detects tokens stored in localStorage/sessionStorage/plain cookies instead of httpOnly \
     cookies, and flags hardcoded cookie TTL values";

/// Keywords in storage key names that indicate auth/token data.
const TOKEN_KEYWORDS: &[&str] = &[
    "token",
    "jwt",
    "access_token",
    "refresh_token",
    "auth",
    "bearer",
    "session",
    "id_token",
    "api_key",
    "apikey",
];

/// Check whether a storage key name refers to an authentication token.
fn is_token_key(key_name: &str) -> bool {
    let lower = key_name.to_lowercase();
    TOKEN_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Map a storage reference to its severity based on storage type and key name.
fn classify_severity(storage_type: InsecureStorageType, key_name: &str) -> Severity {
    match storage_type {
        InsecureStorageType::LocalStorage if is_token_key(key_name) => Severity::Critical,
        InsecureStorageType::LocalStorage => Severity::Warning,
        InsecureStorageType::SessionStorage => Severity::Warning,
        InsecureStorageType::PlainCookie => Severity::Warning,
    }
}

/// Build a human-readable label for the storage type.
fn storage_label(storage_type: InsecureStorageType) -> &'static str {
    match storage_type {
        InsecureStorageType::LocalStorage => "localStorage",
        InsecureStorageType::SessionStorage => "sessionStorage",
        InsecureStorageType::PlainCookie => "plain cookie (non-httpOnly)",
    }
}

/// Build a finding from a single insecure storage reference.
fn to_storage_finding(r: &crate::indexer::types::InsecureStorageRef) -> Finding {
    let severity = classify_severity(r.storage_type, &r.key_name);
    let label = storage_label(r.storage_type);

    let message = format!(
        "Auth token '{}' stored in {} — vulnerable to XSS theft",
        r.key_name, label
    );

    let suggestion = match r.storage_type {
        InsecureStorageType::LocalStorage | InsecureStorageType::SessionStorage => {
            "Use httpOnly secure cookies for token storage instead of browser storage APIs"
        }
        InsecureStorageType::PlainCookie => {
            "Set the httpOnly and Secure flags on cookies that carry auth tokens"
        }
    };

    Finding::new(SCANNER_ID, severity, message)
        .with_file(r.file.clone())
        .with_line(r.line)
        .with_suggestion(suggestion)
}

/// Build a finding from a cookie setting with hardcoded TTL.
fn to_cookie_ttl_finding(r: &crate::indexer::types::CookieSettingRef) -> Option<Finding> {
    if r.is_hardcoded_ttl {
        Some(
            Finding::new(
                SCANNER_ID,
                Severity::Warning,
                format!(
                    "Cookie '{}' uses hardcoded TTL — TTL should be parameterized \
                     to avoid cookie/JWT expiry clock drift",
                    r.cookie_name
                ),
            )
            .with_file(r.file.clone())
            .with_line(r.line)
            .with_suggestion(
                "Remove default TTL from SetTokenCookies() and require explicit TTL \
                 parameter. Hardcoded TTL causes cookie expiry and JWT expiry clocks \
                 to diverge, producing subtle auth failures",
            ),
        )
    } else if !r.has_explicit_ttl {
        Some(
            Finding::new(
                SCANNER_ID,
                Severity::Critical,
                format!(
                    "Cookie '{}' set without explicit TTL — defaults to session cookie \
                     or framework default, which may not match JWT lifetime",
                    r.cookie_name
                ),
            )
            .with_file(r.file.clone())
            .with_line(r.line)
            .with_suggestion(
                "Always pass an explicit Max-Age or Expires value when setting auth cookies. \
                 Missing TTL means the cookie lifetime is controlled by browser defaults, \
                 not your application",
            ),
        )
    } else {
        None
    }
}

/// Compute the scanner score: 100 - (critical * 15 + warning * 5), min 0.
fn compute_score(critical_count: usize, warning_count: usize) -> u8 {
    let penalty = critical_count * 15 + warning_count * 5;
    let raw = 100_usize.saturating_sub(penalty);
    raw.min(100) as u8
}

impl Scanner for InsecureTokenStorage {
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
        let storage_refs = ctx.index.all_insecure_storage_refs();
        let cookie_refs = ctx.index.all_cookie_setting_refs();

        // Cookie TTL check only makes sense when the project has JWT/token infrastructure.
        // Without JWT, cookie TTL mismatches are irrelevant. Check for evidence of JWT:
        // token refresh endpoints, or insecure storage refs with token keys.
        let has_jwt_infra = !ctx.index.all_token_refresh_refs().is_empty()
            || storage_refs.iter().any(|r| is_token_key(&r.key_name));

        let mut findings: Vec<Finding> = storage_refs.iter().map(to_storage_finding).collect();

        // Add cookie TTL findings — only when project has JWT infrastructure,
        // otherwise cookie TTL mismatch is irrelevant noise
        if has_jwt_infra {
            let cookie_ttl_findings: Vec<Finding> =
                cookie_refs.iter().filter_map(to_cookie_ttl_finding).collect();
            findings.extend(cookie_ttl_findings);
        }

        if findings.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No insecure token storage detected".to_string(),
            };
        }

        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let warning_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count();

        let score = compute_score(critical_count, warning_count);

        let summary = format!(
            "Found {} insecure token storage issues: {} critical, {} warnings (score: {})",
            findings.len(),
            critical_count,
            warning_count,
            score
        );

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
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{
        CookieSettingRef, InsecureStorageRef, InsecureStorageType, TokenRefreshRef,
    };
    use std::path::PathBuf;

    fn minimal_config() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    /// Insert a token refresh ref so that `has_jwt_infra` evaluates to true.
    fn seed_jwt_infra(store: &IndexStore) {
        let file = PathBuf::from("src/auth/refresh.ts");
        store.security.token_refresh_refs.insert(
            file.clone(),
            vec![TokenRefreshRef {
                file,
                line: 1,
                has_old_token_revocation: true,
            }],
        );
    }

    #[test]
    fn detects_localstorage_token() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/auth.ts");

        store.security.insecure_storage_refs.insert(
            file.clone(),
            vec![InsecureStorageRef {
                file: file.clone(),
                line: 12,
                storage_type: InsecureStorageType::LocalStorage,
                key_name: "access_token".to_string(),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = InsecureTokenStorage.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].message.contains("localStorage"));
        assert!(result.findings[0].message.contains("access_token"));
    }

    #[test]
    fn detects_plain_cookie() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/session.ts");

        store.security.insecure_storage_refs.insert(
            file.clone(),
            vec![InsecureStorageRef {
                file: file.clone(),
                line: 8,
                storage_type: InsecureStorageType::PlainCookie,
                key_name: "jwt".to_string(),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = InsecureTokenStorage.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("plain cookie"));
        assert!(result.findings[0]
            .suggestion
            .as_ref()
            .unwrap()
            .contains("httpOnly"));
    }

    #[test]
    fn perfect_score_when_clean() {
        let config = minimal_config();
        let store = IndexStore::new();

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = InsecureTokenStorage.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
        assert_eq!(result.summary, "No insecure token storage detected");
    }

    #[test]
    fn score_calculation() {
        assert_eq!(compute_score(0, 0), 100);
        assert_eq!(compute_score(1, 0), 85);
        assert_eq!(compute_score(0, 1), 95);
        assert_eq!(compute_score(2, 3), 55);
        assert_eq!(compute_score(7, 0), 0);
        assert_eq!(compute_score(3, 5), 30);
    }

    #[test]
    fn localstorage_non_token_key_is_warning() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/prefs.ts");

        store.security.insecure_storage_refs.insert(
            file.clone(),
            vec![InsecureStorageRef {
                file: file.clone(),
                line: 5,
                storage_type: InsecureStorageType::LocalStorage,
                key_name: "theme_preference".to_string(),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = InsecureTokenStorage.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn session_storage_token_is_warning() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/login.ts");

        store.security.insecure_storage_refs.insert(
            file.clone(),
            vec![InsecureStorageRef {
                file: file.clone(),
                line: 20,
                storage_type: InsecureStorageType::SessionStorage,
                key_name: "jwt_token".to_string(),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = InsecureTokenStorage.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn mixed_findings_score_and_summary() {
        let config = minimal_config();
        let store = IndexStore::new();

        let file_a = PathBuf::from("src/auth.ts");
        let file_b = PathBuf::from("src/session.ts");

        store.security.insecure_storage_refs.insert(
            file_a.clone(),
            vec![InsecureStorageRef {
                file: file_a.clone(),
                line: 10,
                storage_type: InsecureStorageType::LocalStorage,
                key_name: "token".to_string(),
            }],
        );

        store.security.insecure_storage_refs.insert(
            file_b.clone(),
            vec![InsecureStorageRef {
                file: file_b.clone(),
                line: 15,
                storage_type: InsecureStorageType::PlainCookie,
                key_name: "refresh_token".to_string(),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = InsecureTokenStorage.scan(&ctx);
        assert_eq!(result.findings.len(), 2);
        assert_eq!(result.score, 80);
        assert!(result.summary.contains("1 critical"));
        assert!(result.summary.contains("1 warnings"));
    }

    // --- New tests for cookie TTL hardcoding ---

    #[test]
    fn detects_hardcoded_cookie_ttl() {
        let config = minimal_config();
        let store = IndexStore::new();
        seed_jwt_infra(&store); // Cookie TTL check requires JWT infra
        let file = PathBuf::from("src/auth/cookies.go");

        store.security.cookie_setting_refs.insert(
            file.clone(),
            vec![CookieSettingRef {
                file: file.clone(),
                line: 42,
                cookie_name: "access_token".to_string(),
                has_explicit_ttl: true,
                is_hardcoded_ttl: true,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = InsecureTokenStorage.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("hardcoded TTL"));
        assert!(result.findings[0].message.contains("access_token"));
    }

    #[test]
    fn detects_missing_cookie_ttl() {
        let config = minimal_config();
        let store = IndexStore::new();
        seed_jwt_infra(&store);
        let file = PathBuf::from("src/auth/cookies.go");

        store.security.cookie_setting_refs.insert(
            file.clone(),
            vec![CookieSettingRef {
                file: file.clone(),
                line: 30,
                cookie_name: "refresh_token".to_string(),
                has_explicit_ttl: false,
                is_hardcoded_ttl: false,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = InsecureTokenStorage.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].message.contains("without explicit TTL"));
    }

    #[test]
    fn cookie_ttl_skipped_without_jwt_infra() {
        let config = minimal_config();
        let store = IndexStore::new();
        // NO seed_jwt_infra — cookie TTL check should be skipped
        let file = PathBuf::from("src/auth/cookies.go");

        store.security.cookie_setting_refs.insert(
            file.clone(),
            vec![CookieSettingRef {
                file: file.clone(),
                line: 42,
                cookie_name: "access_token".to_string(),
                has_explicit_ttl: true,
                is_hardcoded_ttl: true,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = InsecureTokenStorage.scan(&ctx);
        // No findings because no JWT infra detected
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 100);
    }

    #[test]
    fn parameterized_cookie_ttl_is_clean() {
        let config = minimal_config();
        let store = IndexStore::new();
        seed_jwt_infra(&store);
        let file = PathBuf::from("src/auth/cookies.go");

        store.security.cookie_setting_refs.insert(
            file.clone(),
            vec![CookieSettingRef {
                file: file.clone(),
                line: 42,
                cookie_name: "access_token".to_string(),
                has_explicit_ttl: true,
                is_hardcoded_ttl: false,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = InsecureTokenStorage.scan(&ctx);
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 100);
    }

    #[test]
    fn mixed_storage_and_cookie_findings() {
        let config = minimal_config();
        let store = IndexStore::new();
        seed_jwt_infra(&store); // has_jwt_infra = true via token_refresh_refs

        let file_a = PathBuf::from("src/auth.ts");
        store.security.insecure_storage_refs.insert(
            file_a.clone(),
            vec![InsecureStorageRef {
                file: file_a.clone(),
                line: 10,
                storage_type: InsecureStorageType::LocalStorage,
                key_name: "token".to_string(),
            }],
        );

        let file_b = PathBuf::from("src/auth/cookies.go");
        store.security.cookie_setting_refs.insert(
            file_b.clone(),
            vec![CookieSettingRef {
                file: file_b.clone(),
                line: 42,
                cookie_name: "access_token".to_string(),
                has_explicit_ttl: true,
                is_hardcoded_ttl: true,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = InsecureTokenStorage.scan(&ctx);
        assert_eq!(result.findings.len(), 2);
        // 1 critical (localStorage token) + 1 warning (hardcoded TTL)
        // score = 100 - 15 - 5 = 80
        assert_eq!(result.score, 80);
    }
}
