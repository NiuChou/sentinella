use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};
use crate::indexer::types::TestBypassType;

pub struct TestBypassDetection;

const SCANNER_ID: &str = "S25";
const SCANNER_NAME: &str = "TestBypassDetection";
const SCANNER_DESC: &str =
    "Detects test account bypasses in auth paths: hardcoded phones, emails, master passwords, debug flags, env-check bugs";

impl Scanner for TestBypassDetection {
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
        let all_refs = ctx.index.all_test_bypass_refs();

        if all_refs.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No test/trial account bypasses found in auth paths".to_string(),
            };
        }

        let findings: Vec<Finding> = all_refs.iter().map(to_finding).collect();

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
            "Found {} test bypass issues: {} critical, {} warnings (score: {})",
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

fn to_finding(r: &crate::indexer::types::TestBypassRef) -> Finding {
    let (severity, message, suggestion) = match r.bypass_type {
        TestBypassType::MasterPassword => (
            Severity::Critical,
            format!(
                "Master/backdoor password allows direct auth bypass — \"{}\"",
                r.matched_value
            ),
            "Remove hardcoded master passwords; use feature flags with proper access control",
        ),
        TestBypassType::DebugFlag => (
            Severity::Critical,
            format!(
                "Debug flag bypasses authentication via header/query — \"{}\"",
                r.matched_value
            ),
            "Remove debug auth bypasses; use a dedicated staging environment instead",
        ),
        TestBypassType::HardcodedPhone => (
            Severity::Warning,
            format!(
                "Hardcoded phone number skips OTP verification — \"{}\"",
                r.matched_value
            ),
            "Remove hardcoded test phone numbers from production auth paths",
        ),
        TestBypassType::HardcodedEmail => (
            Severity::Warning,
            format!(
                "Hardcoded email bypasses normal auth flow — \"{}\"",
                r.matched_value
            ),
            "Remove hardcoded test emails; use feature flags gated by environment",
        ),
        TestBypassType::EnvCheckBug => (
            Severity::Warning,
            format!(
                "Environment check may leak test bypass into production — \"{}\"",
                r.matched_value
            ),
            "Ensure env checks use strict equality and default to production behavior",
        ),
        TestBypassType::TestAccountList => (
            Severity::Warning,
            format!(
                "Hardcoded test account list found in auth path — \"{}\"",
                r.matched_value
            ),
            "Move test accounts to a config or feature-flag system, not source code",
        ),
    };

    Finding::new(SCANNER_ID, severity, message)
        .with_file(r.file.clone())
        .with_line(r.line)
        .with_suggestion(suggestion)
}

fn compute_score(critical_count: usize, warning_count: usize) -> u8 {
    let penalty = critical_count * 15 + warning_count * 8;
    let raw = 100_usize.saturating_sub(penalty);
    raw.min(100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{TestBypassRef, TestBypassType};
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

    fn make_ref(bypass_type: TestBypassType, matched_value: &str, line: usize) -> TestBypassRef {
        TestBypassRef {
            file: PathBuf::from("src/auth/login.ts"),
            line,
            bypass_type,
            matched_value: matched_value.to_string(),
        }
    }

    fn store_with_bypass(bypass: TestBypassRef) -> Arc<IndexStore> {
        let store = IndexStore::new();
        let file = bypass.file.clone();
        store.security.test_bypass_refs.insert(file, vec![bypass]);
        store
    }

    #[test]
    fn no_bypasses_perfect_score() {
        let config = minimal_config();
        let store = IndexStore::new();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = TestBypassDetection.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
        assert!(result.summary.contains("No test/trial account bypasses"));
    }

    #[test]
    fn detects_hardcoded_phone() {
        let config = minimal_config();
        let store = store_with_bypass(make_ref(TestBypassType::HardcodedPhone, "+1555000000", 12));
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = TestBypassDetection.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("+1555000000"));
        assert!(result.findings[0].message.contains("Hardcoded phone"));
    }

    #[test]
    fn detects_master_password() {
        let config = minimal_config();
        let store = store_with_bypass(make_ref(
            TestBypassType::MasterPassword,
            "superSecret123!",
            30,
        ));
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = TestBypassDetection.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0]
            .message
            .contains("Master/backdoor password"));
        assert!(result.findings[0].message.contains("superSecret123!"));
    }

    #[test]
    fn detects_debug_flag() {
        let config = minimal_config();
        let store = store_with_bypass(make_ref(TestBypassType::DebugFlag, "X-Debug-Auth: true", 5));
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = TestBypassDetection.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].message.contains("Debug flag"));
    }

    #[test]
    fn detects_env_check_bug() {
        let config = minimal_config();
        let store = store_with_bypass(make_ref(
            TestBypassType::EnvCheckBug,
            "if env != 'production'",
            18,
        ));
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = TestBypassDetection.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("Environment check"));
    }

    #[test]
    fn score_calculation() {
        // No issues: perfect
        assert_eq!(compute_score(0, 0), 100);

        // 1 critical (15) => 85
        assert_eq!(compute_score(1, 0), 85);

        // 1 warning (8) => 92
        assert_eq!(compute_score(0, 1), 92);

        // 2 critical (30) + 3 warnings (24) = 54 penalty => 46
        assert_eq!(compute_score(2, 3), 46);

        // Saturates at 0
        assert_eq!(compute_score(5, 5), 0); // 75 + 40 = 115 > 100
        assert_eq!(compute_score(7, 0), 0); // 105 > 100
    }

    #[test]
    fn detects_hardcoded_email() {
        let config = minimal_config();
        let store = store_with_bypass(make_ref(
            TestBypassType::HardcodedEmail,
            "test@example.com",
            22,
        ));
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = TestBypassDetection.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("Hardcoded email"));
    }

    #[test]
    fn detects_test_account_list() {
        let config = minimal_config();
        let store = store_with_bypass(make_ref(
            TestBypassType::TestAccountList,
            "TEST_USERS = [...]",
            45,
        ));
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = TestBypassDetection.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("test account list"));
    }

    #[test]
    fn mixed_severities_summary() {
        let store = IndexStore::new();
        let file = PathBuf::from("src/auth/login.ts");
        store.security.test_bypass_refs.insert(
            file.clone(),
            vec![
                make_ref(TestBypassType::MasterPassword, "backdoor", 10),
                make_ref(TestBypassType::DebugFlag, "x-skip-auth", 20),
                make_ref(TestBypassType::HardcodedPhone, "+1000", 30),
            ],
        );

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = TestBypassDetection.scan(&ctx);
        assert_eq!(result.findings.len(), 3);
        // 2 critical * 15 + 1 warning * 8 = 38 penalty => 62
        assert_eq!(result.score, 62);
        assert!(result.summary.contains("2 critical"));
        assert!(result.summary.contains("1 warnings"));
    }
}
