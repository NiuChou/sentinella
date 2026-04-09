use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use regex::Regex;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};
use crate::indexer::types::RedisOp;

pub struct OtpReplayProtection;

const SCANNER_ID: &str = "S19";
const SCANNER_NAME: &str = "OtpReplayProtection";
const SCANNER_DESC: &str =
    "Detects OTP/verification code usage without single-use consumption (replay vulnerability)";

impl Scanner for OtpReplayProtection {
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
        let mut findings = Vec::new();

        check_redis_otp_without_delete(ctx, &mut findings);
        check_otp_files_without_redis_delete(ctx, &mut findings);

        let warning_count = count_by_severity(&findings, Severity::Warning);
        let info_count = count_by_severity(&findings, Severity::Info);
        let score = compute_score(warning_count, info_count);

        let summary = build_summary(&findings, score);

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

/// Detect Redis keys with OTP-like patterns that are read but never deleted.
fn check_redis_otp_without_delete(ctx: &ScanContext, findings: &mut Vec<Finding>) {
    let redis_refs = ctx.index.all_redis_key_refs();
    if redis_refs.is_empty() {
        return;
    }

    let otp_refs: Vec<_> = redis_refs
        .iter()
        .filter(|r| is_otp_key_pattern(&r.key_pattern))
        .collect();

    let by_file = group_redis_ops_by_file(&otp_refs);

    for (file, ops) in &by_file {
        let has_read = ops.contains(&RedisOp::Read);
        let has_delete = ops.contains(&RedisOp::Delete);

        if has_read && !has_delete {
            let line = otp_refs
                .iter()
                .find(|r| &r.file == file && r.operation == RedisOp::Read)
                .map(|r| r.line)
                .unwrap_or(0);

            findings.push(make_warning(file, line));
        }
    }
}

/// Scan source files for OTP verification patterns without corresponding delete/consume.
fn check_otp_files_without_redis_delete(ctx: &ScanContext, findings: &mut Vec<Finding>) {
    let redis_refs = ctx.index.all_redis_key_refs();
    let redis_delete_files: HashSet<PathBuf> = redis_refs
        .iter()
        .filter(|r| r.operation == RedisOp::Delete)
        .map(|r| r.file.clone())
        .collect();

    let already_warned: HashSet<PathBuf> = findings.iter().filter_map(|f| f.file.clone()).collect();

    let otp_verify_re = build_otp_verify_regex();
    let otp_consume_re = build_otp_consume_regex();

    for entry in ctx.index.files.iter() {
        let file_path = entry.key();
        if already_warned.contains(file_path) || redis_delete_files.contains(file_path) {
            continue;
        }

        let abs_path = ctx.root_dir.join(file_path);
        let content = match fs::read_to_string(&abs_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        if let Some(line) =
            find_otp_verify_without_consume(&content, &otp_verify_re, &otp_consume_re)
        {
            findings.push(make_info(file_path, line));
        }
    }
}

/// Check if file content has OTP verification but no consumption pattern.
/// Returns the line number of the first verify match, or None if safe.
fn find_otp_verify_without_consume(
    content: &str,
    verify_re: &Regex,
    consume_re: &Regex,
) -> Option<usize> {
    let verify_match = verify_re.find(content)?;
    if consume_re.is_match(content) {
        return None;
    }
    let line = content[..verify_match.start()].lines().count() + 1;
    Some(line)
}

/// Returns true if the Redis key pattern looks OTP-related.
fn is_otp_key_pattern(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("otp")
        || lower.contains("verification_code")
        || lower.contains("verify_code")
        || lower.contains("2fa")
        || lower.contains("totp")
        || lower.contains("one_time")
        || lower.contains("onetime")
        || lower.contains("mfa_code")
}

/// Group Redis operations by file path.
fn group_redis_ops_by_file(
    refs: &[&crate::indexer::types::RedisKeyRef],
) -> HashMap<PathBuf, Vec<RedisOp>> {
    let mut map: HashMap<PathBuf, Vec<RedisOp>> = HashMap::new();
    for r in refs {
        map.entry(r.file.clone()).or_default().push(r.operation);
    }
    map
}

fn build_otp_verify_regex() -> Regex {
    Regex::new(r"(?i)(verify[_\s]*(otp|code|token)|check[_\s]*(otp|code|token)|validate[_\s]*(otp|code|token)|otp[_\s]*verify|otp[_\s]*check|verify_2fa|check_2fa|verify_totp)")
        .expect("valid regex")
}

fn build_otp_consume_regex() -> Regex {
    Regex::new(r"(?i)(delete|del|remove|consume|invalidate|expire|revoke|destroy)[_\s]*(otp|code|token|key)|(otp|code|token)[_\s]*(delete|del|remove|consume|invalidate|revoke|destroy)")
        .expect("valid regex")
}

fn make_warning(file: &PathBuf, line: usize) -> Finding {
    Finding::new(
        SCANNER_ID,
        Severity::Warning,
        "OTP verification without consumption — code may be replayable",
    )
    .with_file(file)
    .with_line(line)
    .with_suggestion(
        "Delete OTP from Redis after successful verification to prevent replay attacks",
    )
}

fn make_info(file: &PathBuf, line: usize) -> Finding {
    Finding::new(
        SCANNER_ID,
        Severity::Info,
        "OTP verification found but no Redis consumption detected — verify single-use enforcement",
    )
    .with_file(file)
    .with_line(line)
    .with_suggestion(
        "Ensure OTP codes are invalidated after use, whether via Redis DEL, database update, or other mechanism",
    )
}

fn count_by_severity(findings: &[Finding], severity: Severity) -> usize {
    findings.iter().filter(|f| f.severity == severity).count()
}

fn compute_score(warning_count: usize, info_count: usize) -> u8 {
    let penalty = warning_count * 10 + info_count * 3;
    let raw = 100_usize.saturating_sub(penalty);
    raw.min(100) as u8
}

fn build_summary(findings: &[Finding], score: u8) -> String {
    if findings.is_empty() {
        return "No OTP replay vulnerabilities detected".to_string();
    }
    let warning_count = count_by_severity(findings, Severity::Warning);
    let info_count = count_by_severity(findings, Severity::Info);
    format!(
        "Found {} OTP replay issues: {} warnings, {} informational (score: {})",
        findings.len(),
        warning_count,
        info_count,
        score
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{RedisKeyRef, RedisOp};
    use std::path::PathBuf;

    fn minimal_config() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    fn make_redis_ref(file: &str, line: usize, op: RedisOp, key: &str) -> RedisKeyRef {
        RedisKeyRef {
            key_pattern: key.to_string(),
            operation: op,
            has_ttl: true,
            file: PathBuf::from(file),
            line,
        }
    }

    #[test]
    fn warns_on_otp_redis_read_without_delete() {
        let store = IndexStore::new();
        store.redis_key_refs.insert(
            "otp:user:*".to_string(),
            vec![make_redis_ref(
                "src/auth/verify_otp.ts",
                10,
                RedisOp::Read,
                "otp:user:*",
            )],
        );

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = OtpReplayProtection.scan(&ctx);
        let warnings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].message.contains("replayable"));
    }

    #[test]
    fn safe_when_otp_redis_read_and_delete_present() {
        let store = IndexStore::new();
        store.redis_key_refs.insert(
            "otp:user:*".to_string(),
            vec![
                make_redis_ref("src/auth/verify_otp.ts", 10, RedisOp::Read, "otp:user:*"),
                make_redis_ref("src/auth/verify_otp.ts", 15, RedisOp::Delete, "otp:user:*"),
            ],
        );

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = OtpReplayProtection.scan(&ctx);
        let warnings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert!(warnings.is_empty());
    }

    #[test]
    fn ignores_non_otp_redis_keys() {
        let store = IndexStore::new();
        store.redis_key_refs.insert(
            "session:user:*".to_string(),
            vec![make_redis_ref(
                "src/auth/session.ts",
                5,
                RedisOp::Read,
                "session:user:*",
            )],
        );

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = OtpReplayProtection.scan(&ctx);
        // No OTP keys, so no warnings from redis check
        let warnings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert!(warnings.is_empty());
    }

    #[test]
    fn score_computation() {
        assert_eq!(compute_score(0, 0), 100);
        assert_eq!(compute_score(1, 0), 90);
        assert_eq!(compute_score(0, 1), 97);
        assert_eq!(compute_score(2, 3), 71); // 100 - 20 - 9
        assert_eq!(compute_score(10, 0), 0);
        assert_eq!(compute_score(10, 10), 0); // capped at 0
    }

    #[test]
    fn perfect_score_when_clean() {
        let store = IndexStore::new();
        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = OtpReplayProtection.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
        assert_eq!(result.summary, "No OTP replay vulnerabilities detected");
    }

    #[test]
    fn is_otp_key_pattern_matches_correctly() {
        assert!(is_otp_key_pattern("otp:user:123"));
        assert!(is_otp_key_pattern("verification_code:abc"));
        assert!(is_otp_key_pattern("2fa:session:xyz"));
        assert!(is_otp_key_pattern("totp:secret"));
        assert!(is_otp_key_pattern("mfa_code:user"));
        assert!(!is_otp_key_pattern("session:user:123"));
        assert!(!is_otp_key_pattern("cache:data"));
    }

    #[test]
    fn find_otp_verify_without_consume_detects_vulnerability() {
        let verify_re = build_otp_verify_regex();
        let consume_re = build_otp_consume_regex();

        let vulnerable = "function verifyOtp(code) {\n  const stored = redis.get(key);\n  return stored === code;\n}";
        assert!(find_otp_verify_without_consume(vulnerable, &verify_re, &consume_re).is_some());

        let safe = "function verifyOtp(code) {\n  const stored = redis.get(key);\n  deleteOtp(key);\n  return stored === code;\n}";
        assert!(find_otp_verify_without_consume(safe, &verify_re, &consume_re).is_none());
    }

    #[test]
    fn multiple_files_mixed_findings() {
        let store = IndexStore::new();

        // File 1: OTP read without delete (warning)
        store.redis_key_refs.insert(
            "otp:verify:*".to_string(),
            vec![make_redis_ref(
                "src/auth/verify.ts",
                10,
                RedisOp::Read,
                "otp:verify:*",
            )],
        );

        // File 2: 2FA read with delete (safe)
        store.redis_key_refs.insert(
            "2fa:session:*".to_string(),
            vec![
                make_redis_ref("src/auth/two_factor.ts", 20, RedisOp::Read, "2fa:session:*"),
                make_redis_ref(
                    "src/auth/two_factor.ts",
                    25,
                    RedisOp::Delete,
                    "2fa:session:*",
                ),
            ],
        );

        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = OtpReplayProtection.scan(&ctx);
        let warnings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Warning)
            .collect();
        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0].file.as_ref().unwrap(),
            &PathBuf::from("src/auth/verify.ts")
        );
    }
}
