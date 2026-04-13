use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};
use crate::indexer::types::ErrorHandlingType;

pub struct SilentErrorSwallowing;

const SCANNER_ID: &str = "S17";
const SCANNER_NAME: &str = "SilentErrorSwallowing";
const SCANNER_DESC: &str =
    "Detects silently swallowed errors: empty catch blocks, ignored error returns, \
     unchecked responses, and missing 429 status handling in HTTP clients";

impl Scanner for SilentErrorSwallowing {
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
        let all_refs = ctx.index.all_error_handling_refs();

        // Check if RawFetchBypass is opted-in via config
        let raw_fetch_enabled = ctx
            .config
            .scanner_overrides
            .s17
            .as_ref()
            .and_then(|c| c.auth_client_pattern.as_ref())
            .is_some();

        // Filter: skip RawFetchBypass if not opted-in
        let filtered_refs: Vec<_> = all_refs
            .iter()
            .filter(|r| {
                if r.error_type == ErrorHandlingType::RawFetchBypass && !raw_fetch_enabled {
                    return false;
                }
                true
            })
            .collect();

        if filtered_refs.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No silent error handling issues found".to_string(),
            };
        }

        let findings: Vec<Finding> = filtered_refs.iter().map(|r| to_finding(r)).collect();

        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let warning_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count();
        let info_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .count();
        let total = findings.len();

        let score = compute_score(critical_count, warning_count, info_count);

        let summary = format!(
            "Found {} silent error handling issues: {} critical, {} swallowed errors, \
             {} unchecked responses (score: {})",
            total, critical_count, warning_count, info_count, score
        );

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

fn to_finding(r: &crate::indexer::types::ErrorHandlingRef) -> Finding {
    let (severity, message, suggestion) = match r.error_type {
        ErrorHandlingType::EmptyCatch
        | ErrorHandlingType::EmptyExcept
        | ErrorHandlingType::EmptyErrorBranch => (
            Severity::Warning,
            format!("Empty catch block silently swallows error — {}", r.context),
            "Log the error or propagate it to callers",
        ),
        ErrorHandlingType::IgnoredError => (
            Severity::Warning,
            format!("Error return value explicitly ignored — {}", r.context),
            "Check the error return value and handle failures",
        ),
        ErrorHandlingType::UncheckedResponse => (
            Severity::Info,
            format!(
                "External call response not checked for errors — {}",
                r.context
            ),
            "Verify the response status before using the result",
        ),
        // Downgraded from Critical → Info: only auth-path fetches should be Critical,
        // but the parser emits this for ALL fetch calls in files without 429 handling.
        // At Info level it's informational noise, not a blocker.
        ErrorHandlingType::Missing429Handler => (
            Severity::Info,
            format!(
                "HTTP client does not handle 429 (Too Many Requests) — {}",
                r.context
            ),
            "Add explicit handling for HTTP 429 responses with exponential backoff \
             using the Retry-After header if this endpoint may be rate-limited",
        ),
        // Downgraded from Warning → Info: many catch blocks intentionally don't
        // rethrow (ErrorBoundary, graceful degradation, top-level middleware).
        // Only informational unless near an API call.
        ErrorHandlingType::CatchNoRethrow => (
            Severity::Info,
            format!(
                "Catch block handles error but does not re-throw — upstream callers \
                 assume success — {}",
                r.context
            ),
            "Re-throw the error after logging, or return an error value so callers \
             know the operation failed",
        ),
        ErrorHandlingType::EmptyCatch401 => (
            Severity::Critical,
            format!(
                "Empty catch swallows 401 auth error — user stays in broken \
                 unauthenticated state — {}",
                r.context
            ),
            "Handle 401 by redirecting to login or triggering token refresh. \
             An empty catch around auth calls means expired tokens are never \
             detected and users see cryptic failures",
        ),
        // Opt-in only (gated by auth_client_pattern config).
        // Downgraded from Warning → Info: raw fetch is normal in most projects.
        ErrorHandlingType::RawFetchBypass => (
            Severity::Info,
            format!(
                "Raw fetch/axios call bypasses shared auth client — 401/429 \
                 handling not applied — {}",
                r.context
            ),
            "Use the shared auth client wrapper instead of raw fetch(). \
             Independent API clients duplicate error handling and miss \
             unified 401/429 retry logic",
        ),
    };

    Finding::new(SCANNER_ID, severity, message)
        .with_file(r.file.clone())
        .with_line(r.line)
        .with_suggestion(suggestion)
}

fn compute_score(critical_count: usize, warning_count: usize, info_count: usize) -> u8 {
    let penalty = critical_count * 10 + warning_count * 3 + info_count;
    let raw = 100_usize.saturating_sub(penalty);
    raw.min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{ErrorHandlingRef, ErrorHandlingType};
    use std::path::PathBuf;
    use std::sync::Arc;

    fn minimal_config() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    fn config_with_auth_client() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
scanner_overrides:
  s17:
    auth_client_pattern: "authFetch|apiClient"
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    fn store_with_errors() -> Arc<IndexStore> {
        let store = IndexStore::new();
        let file = PathBuf::from("src/api.ts");

        store.code_quality.error_handling_refs.insert(
            file.clone(),
            vec![
                ErrorHandlingRef {
                    file: file.clone(),
                    line: 10,
                    error_type: ErrorHandlingType::EmptyCatch,
                    context: "catch (e) {}".to_string(),
                },
                ErrorHandlingRef {
                    file: file.clone(),
                    line: 25,
                    error_type: ErrorHandlingType::IgnoredError,
                    context: "_ = doSomething()".to_string(),
                },
                ErrorHandlingRef {
                    file: file.clone(),
                    line: 40,
                    error_type: ErrorHandlingType::UncheckedResponse,
                    context: "fetch('/api/data')".to_string(),
                },
            ],
        );

        store
    }

    #[test]
    fn detects_all_error_types() {
        let config = minimal_config();
        let store = store_with_errors();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = SilentErrorSwallowing.scan(&ctx);
        assert_eq!(result.findings.len(), 3);

        let warnings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        let infos: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Info)
            .collect();
        assert_eq!(warnings.len(), 2);
        assert_eq!(infos.len(), 1);
    }

    #[test]
    fn score_penalizes_warnings_and_infos() {
        assert_eq!(compute_score(0, 0, 0), 100);
        assert_eq!(compute_score(0, 2, 1), 93);
        assert_eq!(compute_score(0, 10, 5), 65);
        assert_eq!(compute_score(0, 34, 0), 0);
        assert_eq!(compute_score(1, 0, 0), 90);
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

        let result = SilentErrorSwallowing.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn summary_format() {
        let config = minimal_config();
        let store = store_with_errors();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = SilentErrorSwallowing.scan(&ctx);
        // 2 warnings * 3 + 1 info * 1 = 7 penalty => score 93
        assert_eq!(result.score, 93);
        assert!(result.summary.contains("3 silent error handling issues"));
    }

    // --- Missing429Handler: now Info severity ---

    #[test]
    fn detects_missing_429_handler_as_info() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/api-client.ts");

        store.code_quality.error_handling_refs.insert(
            file.clone(),
            vec![ErrorHandlingRef {
                file: file.clone(),
                line: 15,
                error_type: ErrorHandlingType::Missing429Handler,
                context: "fetch('/api/models')".to_string(),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = SilentErrorSwallowing.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        // Downgraded to Info
        assert_eq!(result.findings[0].severity, Severity::Info);
        assert!(result.findings[0].message.contains("429"));
    }

    #[test]
    fn mixed_errors_with_429() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/fetcher.ts");

        store.code_quality.error_handling_refs.insert(
            file.clone(),
            vec![
                ErrorHandlingRef {
                    file: file.clone(),
                    line: 10,
                    error_type: ErrorHandlingType::EmptyCatch,
                    context: "catch (e) {}".to_string(),
                },
                ErrorHandlingRef {
                    file: file.clone(),
                    line: 30,
                    error_type: ErrorHandlingType::Missing429Handler,
                    context: "axios.get('/api/data')".to_string(),
                },
            ],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = SilentErrorSwallowing.scan(&ctx);
        assert_eq!(result.findings.len(), 2);
        // 0 critical, 1 warning (empty catch), 1 info (429)
        // score = 100 - 3 - 1 = 96
        assert_eq!(result.score, 96);
    }

    // --- CatchNoRethrow: now Info ---

    #[test]
    fn detects_catch_no_rethrow_as_info() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/api-client.ts");

        store.code_quality.error_handling_refs.insert(
            file.clone(),
            vec![ErrorHandlingRef {
                file: file.clone(),
                line: 20,
                error_type: ErrorHandlingType::CatchNoRethrow,
                context: "catch(e) { console.error(e) }".to_string(),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = SilentErrorSwallowing.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Info);
        assert!(result.findings[0].message.contains("does not re-throw"));
    }

    // --- EmptyCatch401: remains Critical ---

    #[test]
    fn detects_empty_catch_401() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/auth/refresh.ts");

        store.code_quality.error_handling_refs.insert(
            file.clone(),
            vec![ErrorHandlingRef {
                file: file.clone(),
                line: 35,
                error_type: ErrorHandlingType::EmptyCatch401,
                context: "catch(e) {} // around 401 check".to_string(),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = SilentErrorSwallowing.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].message.contains("401"));
    }

    // --- RawFetchBypass: opt-in only ---

    #[test]
    fn raw_fetch_bypass_suppressed_without_config() {
        let config = minimal_config(); // no auth_client_pattern
        let store = IndexStore::new();
        let file = PathBuf::from("src/pages/dashboard.tsx");

        store.code_quality.error_handling_refs.insert(
            file.clone(),
            vec![ErrorHandlingRef {
                file: file.clone(),
                line: 42,
                error_type: ErrorHandlingType::RawFetchBypass,
                context: "fetch('/api/me')".to_string(),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = SilentErrorSwallowing.scan(&ctx);
        // Should be filtered out — no findings
        assert!(result.findings.is_empty());
        assert_eq!(result.score, 100);
    }

    #[test]
    fn raw_fetch_bypass_reported_with_config() {
        let config = config_with_auth_client();
        let store = IndexStore::new();
        let file = PathBuf::from("src/pages/dashboard.tsx");

        store.code_quality.error_handling_refs.insert(
            file.clone(),
            vec![ErrorHandlingRef {
                file: file.clone(),
                line: 42,
                error_type: ErrorHandlingType::RawFetchBypass,
                context: "fetch('/api/me')".to_string(),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = SilentErrorSwallowing.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Info);
        assert!(result.findings[0].message.contains("Raw fetch"));
    }

    // --- Mixed all new types ---

    #[test]
    fn mixed_all_new_types() {
        let config = config_with_auth_client();
        let store = IndexStore::new();
        let file = PathBuf::from("src/api.ts");

        store.code_quality.error_handling_refs.insert(
            file.clone(),
            vec![
                ErrorHandlingRef {
                    file: file.clone(),
                    line: 10,
                    error_type: ErrorHandlingType::CatchNoRethrow,
                    context: "catch(e) { log(e) }".to_string(),
                },
                ErrorHandlingRef {
                    file: file.clone(),
                    line: 20,
                    error_type: ErrorHandlingType::EmptyCatch401,
                    context: "catch(e) {} // 401".to_string(),
                },
                ErrorHandlingRef {
                    file: file.clone(),
                    line: 30,
                    error_type: ErrorHandlingType::RawFetchBypass,
                    context: "fetch('/api/data')".to_string(),
                },
            ],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = SilentErrorSwallowing.scan(&ctx);
        assert_eq!(result.findings.len(), 3);
        // 1 critical (EmptyCatch401) + 0 warnings + 2 info (CatchNoRethrow + RawFetchBypass)
        // score = 100 - 10 - 1 - 1 = 88
        assert_eq!(result.score, 88);
    }
}
