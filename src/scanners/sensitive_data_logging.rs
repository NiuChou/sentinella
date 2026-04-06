use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};
use crate::indexer::types::{SensitiveLogRef, SensitiveLogType};

pub struct SensitiveDataLogging;

const SCANNER_ID: &str = "S20";
const SCANNER_NAME: &str = "SensitiveDataLogging";
const SCANNER_DESC: &str =
    "Detects sensitive data being logged: passwords, tokens, secrets, OTP codes, API keys in log statements";

impl Scanner for SensitiveDataLogging {
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
        let all_refs = ctx.index.all_sensitive_log_refs();

        if all_refs.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No sensitive data logging detected".to_string(),
            };
        }

        let findings: Vec<Finding> = all_refs.iter().map(|r| to_finding(r)).collect();

        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let warning_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .count();
        let total = findings.len();

        let score = compute_score(critical_count, warning_count);

        let summary = format!(
            "Found {} sensitive data logging issues: {} critical, {} warnings (score: {})",
            total, critical_count, warning_count, score
        );

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

fn to_finding(r: &SensitiveLogRef) -> Finding {
    let (severity, message, suggestion) = match r.log_type {
        SensitiveLogType::Password => (
            Severity::Critical,
            format!("Password logged in plaintext — {}", r.matched_text),
            "Never log passwords; remove the log statement or redact the value",
        ),
        SensitiveLogType::Token => (
            Severity::Critical,
            format!("Authentication token logged — {}", r.matched_text),
            "Remove token from log output; log a token prefix or hash instead",
        ),
        SensitiveLogType::Secret => (
            Severity::Critical,
            format!("Secret value logged — {}", r.matched_text),
            "Remove secret from log output; use a masked placeholder",
        ),
        SensitiveLogType::CreditCard => (
            Severity::Critical,
            format!("Credit card data logged — {}", r.matched_text),
            "Never log credit card numbers; this violates PCI-DSS compliance",
        ),
        SensitiveLogType::OtpCode => (
            Severity::Warning,
            format!("OTP code logged — {}", r.matched_text),
            "Remove OTP from logs; logging OTP codes weakens second-factor security",
        ),
        SensitiveLogType::ApiKey => (
            Severity::Warning,
            format!("API key logged — {}", r.matched_text),
            "Remove API key from logs; log a masked version or key ID instead",
        ),
    };

    Finding::new(SCANNER_ID, severity, message)
        .with_file(r.file.clone())
        .with_line(r.line)
        .with_suggestion(suggestion)
}

fn compute_score(critical_count: usize, warning_count: usize) -> u8 {
    let penalty = critical_count * 10 + warning_count * 5;
    let raw = 100_usize.saturating_sub(penalty);
    raw.min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{SensitiveLogRef, SensitiveLogType};
    use std::path::PathBuf;

    fn minimal_config() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    fn make_ref(
        file: &str,
        line: usize,
        log_type: SensitiveLogType,
        matched_text: &str,
    ) -> SensitiveLogRef {
        SensitiveLogRef {
            file: PathBuf::from(file),
            line,
            log_type,
            matched_text: matched_text.to_string(),
        }
    }

    #[test]
    fn detects_password_logging() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/auth.ts");

        store.sensitive_log_refs.insert(
            file.clone(),
            vec![make_ref(
                "src/auth.ts",
                15,
                SensitiveLogType::Password,
                "console.log(password)",
            )],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = SensitiveDataLogging.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].message.contains("Password"));
    }

    #[test]
    fn detects_token_logging() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/api.ts");

        store.sensitive_log_refs.insert(
            file.clone(),
            vec![make_ref(
                "src/api.ts",
                42,
                SensitiveLogType::Token,
                "logger.info(jwt_token)",
            )],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = SensitiveDataLogging.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].message.contains("token"));
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

        let result = SensitiveDataLogging.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
        assert_eq!(result.summary, "No sensitive data logging detected");
    }

    #[test]
    fn score_penalizes_by_severity() {
        // Critical: 10 points each, Warning: 5 points each
        assert_eq!(compute_score(0, 0), 100);
        assert_eq!(compute_score(1, 0), 90); // 100 - 10
        assert_eq!(compute_score(0, 1), 95); // 100 - 5
        assert_eq!(compute_score(2, 2), 70); // 100 - 20 - 10
        assert_eq!(compute_score(5, 5), 25); // 100 - 50 - 25
        assert_eq!(compute_score(10, 0), 0); // capped at 0
        assert_eq!(compute_score(15, 5), 0); // capped at 0
    }
}
