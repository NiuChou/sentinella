use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};
use crate::indexer::types::ErrorHandlingType;

pub struct SilentErrorSwallowing;

const SCANNER_ID: &str = "S17";
const SCANNER_NAME: &str = "SilentErrorSwallowing";
const SCANNER_DESC: &str =
    "Detects silently swallowed errors: empty catch blocks, ignored error returns, unchecked responses";

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

        if all_refs.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No silent error handling issues found".to_string(),
            };
        }

        let findings: Vec<Finding> = all_refs.iter().map(|r| to_finding(r)).collect();

        let warning_count = findings.iter().filter(|f| f.severity == Severity::Warning).count();
        let info_count = findings.iter().filter(|f| f.severity == Severity::Info).count();
        let total = findings.len();

        let score = compute_score(warning_count, info_count);

        let summary = format!(
            "Found {} silent error handling issues: {} swallowed errors, {} unchecked responses (score: {})",
            total, warning_count, info_count, score
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
        ErrorHandlingType::EmptyCatch | ErrorHandlingType::EmptyExcept | ErrorHandlingType::EmptyErrorBranch => (
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
            format!("External call response not checked for errors — {}", r.context),
            "Verify the response status before using the result",
        ),
    };

    Finding::new(SCANNER_ID, severity, message)
        .with_file(r.file.clone())
        .with_line(r.line)
        .with_suggestion(suggestion)
}

fn compute_score(warning_count: usize, info_count: usize) -> u8 {
    let penalty = warning_count * 3 + info_count;
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

    fn store_with_errors() -> Arc<IndexStore> {
        let store = IndexStore::new();
        let file = PathBuf::from("src/api.ts");

        store.error_handling_refs.insert(
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

        let warnings: Vec<_> = result.findings.iter().filter(|f| f.severity == Severity::Warning).collect();
        let infos: Vec<_> = result.findings.iter().filter(|f| f.severity == Severity::Info).collect();
        assert_eq!(warnings.len(), 2);
        assert_eq!(infos.len(), 1);
    }

    #[test]
    fn score_penalizes_warnings_and_infos() {
        assert_eq!(compute_score(0, 0), 100);
        assert_eq!(compute_score(2, 1), 93); // 100 - 6 - 1
        assert_eq!(compute_score(10, 5), 65); // 100 - 30 - 5
        assert_eq!(compute_score(34, 0), 0);  // capped at 0
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
        assert!(result.summary.contains("2 swallowed errors"));
        assert!(result.summary.contains("1 unchecked responses"));
    }
}
