use std::collections::HashMap;

use crate::indexer::types::FunctionSignature;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S15";
const SCANNER_NAME: &str = "CrossServiceDuplication";
const SCANNER_DESC: &str = "Detects duplicated business logic across services in monorepo/polyrepo";

/// Known shared/common directory prefixes that indicate a shared package exists.
const SHARED_DIR_PREFIXES: &[&str] = &["shared/", "common/", "pkg/", "lib/"];

/// Path prefixes used to infer service name from file path.
const SERVICE_PATH_PREFIXES: &[&str] = &["apps/", "services/", "packages/"];

pub struct CrossServiceDuplication;

impl Scanner for CrossServiceDuplication {
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
        let signatures = ctx.index.all_function_signatures();

        if signatures.is_empty() {
            return empty_result();
        }

        let grouped = group_by_service(signatures);
        let shared_functions = collect_shared_functions(ctx);
        let findings = detect_duplicates(&grouped, &shared_functions);

        let (high, warn, info) = count_by_severity(&findings);
        let score = compute_score(high, warn, info);
        let summary = format_summary(high, warn, info, &findings);

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

/// Group function signatures by their resolved service name.
/// Functions with no determinable service are excluded.
fn group_by_service(signatures: Vec<FunctionSignature>) -> HashMap<String, Vec<FunctionSignature>> {
    let mut by_service: HashMap<String, Vec<FunctionSignature>> = HashMap::new();

    for sig in signatures {
        let service = resolve_service_name(&sig);
        if service != "unknown" {
            by_service.entry(service).or_default().push(sig);
        }
    }

    by_service
}

/// Resolve the service name for a function signature.
/// Prefers the explicit `service_name` field, falls back to path inference.
fn resolve_service_name(sig: &FunctionSignature) -> String {
    if let Some(ref name) = sig.service_name {
        if !name.is_empty() {
            return name.clone();
        }
    }

    infer_service_from_path(sig)
}

/// Infer service name from file path segments like `apps/xxx/`, `services/xxx/`.
fn infer_service_from_path(sig: &FunctionSignature) -> String {
    let path_str = sig.file.to_string_lossy();
    let normalized = path_str.replace('\\', "/");

    for prefix in SERVICE_PATH_PREFIXES {
        if let Some(rest) = find_segment_after_prefix(&normalized, prefix) {
            if !rest.is_empty() {
                return rest;
            }
        }
    }

    "unknown".to_string()
}

/// Extract the first path segment after a known prefix.
fn find_segment_after_prefix(path: &str, prefix: &str) -> Option<String> {
    let idx = path.find(prefix)?;
    let after = &path[idx + prefix.len()..];
    let segment = after.split('/').next()?;

    if segment.is_empty() {
        None
    } else {
        Some(segment.to_string())
    }
}

/// Collect function names that exist in shared/common/pkg directories.
fn collect_shared_functions(ctx: &ScanContext) -> HashMap<String, bool> {
    let mut shared = HashMap::new();

    for entry in ctx.index.code_quality.function_signatures.iter() {
        let path_str = entry.key().to_string_lossy();
        let normalized = path_str.replace('\\', "/").to_lowercase();

        if is_shared_path(&normalized) {
            for sig in entry.value().iter() {
                shared.insert(sig.name.clone(), true);
            }
        }
    }

    shared
}

/// Check if a file path belongs to a shared/common directory.
fn is_shared_path(normalized_path: &str) -> bool {
    SHARED_DIR_PREFIXES
        .iter()
        .any(|prefix| normalized_path.contains(prefix))
}

/// A function seen across multiple services, keyed by function name.
struct CrossServiceMatch {
    name: String,
    services: Vec<String>,
    first: FunctionSignature,
    is_exact: bool,
}

/// Detect exact and near duplicates across services.
fn detect_duplicates(
    by_service: &HashMap<String, Vec<FunctionSignature>>,
    shared_functions: &HashMap<String, bool>,
) -> Vec<Finding> {
    let cross_matches = find_cross_service_matches(by_service);
    let mut findings = Vec::new();

    for m in &cross_matches {
        let in_shared = shared_functions.contains_key(&m.name);
        let finding = build_finding(m, in_shared);
        findings.push(finding);
    }

    findings
}

/// Build a finding from a cross-service match.
fn build_finding(m: &CrossServiceMatch, in_shared: bool) -> Finding {
    if in_shared {
        return Finding::new(
            SCANNER_ID,
            Severity::Critical,
            format!(
                "Function '{}' is duplicated across services [{}] but already exists in shared package",
                m.name,
                m.services.join(", ")
            ),
        )
        .with_file(&m.first.file)
        .with_line(m.first.line)
        .with_suggestion("Use the existing shared package instead of duplicating");
    }

    if m.is_exact {
        Finding::new(
            SCANNER_ID,
            Severity::Warning,
            format!(
                "Function '{}' is duplicated across services: {}",
                m.name,
                m.services.join(", ")
            ),
        )
        .with_file(&m.first.file)
        .with_line(m.first.line)
        .with_suggestion("Consider extracting to a shared package")
    } else {
        Finding::new(
            SCANNER_ID,
            Severity::Info,
            format!(
                "Function '{}' has similar signatures across services: {}",
                m.name,
                m.services.join(", ")
            ),
        )
        .with_file(&m.first.file)
        .with_line(m.first.line)
        .with_suggestion("Review for potential consolidation into a shared package")
    }
}

/// Identify functions that appear in multiple services.
fn find_cross_service_matches(
    by_service: &HashMap<String, Vec<FunctionSignature>>,
) -> Vec<CrossServiceMatch> {
    let by_name = index_by_function_name(by_service);
    let mut matches = Vec::new();

    for (name, occurrences) in &by_name {
        let unique_services = unique_service_names(occurrences);
        if unique_services.len() < 2 {
            continue;
        }

        let is_exact = check_exact_duplicate(occurrences);
        let first = occurrences[0].1.clone();

        matches.push(CrossServiceMatch {
            name: name.clone(),
            services: unique_services,
            first,
            is_exact,
        });
    }

    matches.sort_by(|a, b| a.name.cmp(&b.name));
    matches
}

/// Index all function signatures by their name, paired with service info.
fn index_by_function_name(
    by_service: &HashMap<String, Vec<FunctionSignature>>,
) -> HashMap<String, Vec<(&str, &FunctionSignature)>> {
    let mut by_name: HashMap<String, Vec<(&str, &FunctionSignature)>> = HashMap::new();

    for (service, sigs) in by_service {
        for sig in sigs {
            by_name
                .entry(sig.name.clone())
                .or_default()
                .push((service.as_str(), sig));
        }
    }

    by_name
}

/// Extract unique service names from occurrences, sorted.
fn unique_service_names(occurrences: &[(&str, &FunctionSignature)]) -> Vec<String> {
    let mut services: Vec<String> = occurrences.iter().map(|(svc, _)| svc.to_string()).collect();
    services.sort();
    services.dedup();
    services
}

/// Check if all occurrences share the same body hash (exact duplicate).
fn check_exact_duplicate(occurrences: &[(&str, &FunctionSignature)]) -> bool {
    if occurrences.len() < 2 {
        return false;
    }

    let first_hash = occurrences[0].1.body_hash;
    let first_params = occurrences[0].1.params.len();

    occurrences
        .iter()
        .skip(1)
        .all(|(_, sig)| sig.body_hash == first_hash && sig.params.len() == first_params)
}

/// Count findings by severity category.
fn count_by_severity(findings: &[Finding]) -> (u32, u32, u32) {
    let mut high = 0u32;
    let mut warn = 0u32;
    let mut info = 0u32;

    for f in findings {
        match f.severity {
            Severity::Critical => high += 1,
            Severity::Warning => warn += 1,
            Severity::Info => info += 1,
        }
    }

    (high, warn, info)
}

/// Compute the duplication score.
fn compute_score(high: u32, warn: u32, info: u32) -> u8 {
    let penalty = high * 10 + warn * 5 + info * 2;
    100u8.saturating_sub(penalty.min(100) as u8)
}

fn format_summary(high: u32, warn: u32, info: u32, findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No cross-service duplication detected".to_string();
    }

    format!(
        "{} cross-service duplication(s) found: {} critical, {} warning, {} info",
        findings.len(),
        high,
        warn,
        info
    )
}

fn empty_result() -> ScanResult {
    ScanResult {
        scanner: SCANNER_ID.to_string(),
        findings: vec![],
        score: 100,
        summary: "No function signatures indexed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_sig(
        name: &str,
        file: &str,
        service: Option<&str>,
        body_hash: u64,
        params: &[&str],
    ) -> FunctionSignature {
        FunctionSignature {
            file: PathBuf::from(file),
            line: 10,
            name: name.to_string(),
            params: params.iter().map(|s| s.to_string()).collect(),
            body_hash,
            service_name: service.map(|s| s.to_string()),
        }
    }

    #[test]
    fn test_resolve_service_from_explicit_name() {
        let sig = make_sig("foo", "src/main.rs", Some("billing"), 0, &[]);
        assert_eq!(resolve_service_name(&sig), "billing");
    }

    #[test]
    fn test_resolve_service_from_path() {
        let sig = make_sig("foo", "apps/billing/src/utils.ts", None, 0, &[]);
        assert_eq!(resolve_service_name(&sig), "billing");
    }

    #[test]
    fn test_resolve_service_unknown() {
        let sig = make_sig("foo", "src/utils.ts", None, 0, &[]);
        assert_eq!(resolve_service_name(&sig), "unknown");
    }

    #[test]
    fn test_infer_services_path() {
        let sig = make_sig("foo", "services/auth/handler.ts", None, 0, &[]);
        assert_eq!(resolve_service_name(&sig), "auth");
    }

    #[test]
    fn test_exact_duplicate_detection() {
        let sigs = vec![
            make_sig("validate", "apps/auth/v.ts", Some("auth"), 12345, &["x"]),
            make_sig(
                "validate",
                "apps/billing/v.ts",
                Some("billing"),
                12345,
                &["x"],
            ),
        ];

        let grouped = group_by_service(sigs);
        let shared = HashMap::new();
        let findings = detect_duplicates(&grouped, &shared);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warning);
        assert!(findings[0].message.contains("duplicated"));
    }

    #[test]
    fn test_near_duplicate_detection() {
        let sigs = vec![
            make_sig("format", "apps/auth/f.ts", Some("auth"), 111, &["a"]),
            make_sig("format", "apps/billing/f.ts", Some("billing"), 999, &["a"]),
        ];

        let grouped = group_by_service(sigs);
        let shared = HashMap::new();
        let findings = detect_duplicates(&grouped, &shared);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("similar"));
    }

    #[test]
    fn test_shared_upgrade_to_critical() {
        let sigs = vec![
            make_sig("hash", "apps/auth/h.ts", Some("auth"), 42, &["x"]),
            make_sig("hash", "apps/billing/h.ts", Some("billing"), 42, &["x"]),
        ];

        let grouped = group_by_service(sigs);
        let mut shared = HashMap::new();
        shared.insert("hash".to_string(), true);
        let findings = detect_duplicates(&grouped, &shared);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert!(findings[0].message.contains("shared package"));
    }

    #[test]
    fn test_same_service_no_finding() {
        let sigs = vec![
            make_sig("foo", "apps/auth/a.ts", Some("auth"), 42, &["x"]),
            make_sig("foo", "apps/auth/b.ts", Some("auth"), 42, &["x"]),
        ];

        let grouped = group_by_service(sigs);
        let shared = HashMap::new();
        let findings = detect_duplicates(&grouped, &shared);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_score_computation() {
        assert_eq!(compute_score(0, 0, 0), 100);
        assert_eq!(compute_score(1, 0, 0), 90);
        assert_eq!(compute_score(0, 2, 0), 90);
        assert_eq!(compute_score(0, 0, 5), 90);
        assert_eq!(compute_score(10, 0, 0), 0);
        assert_eq!(compute_score(5, 5, 5), 15);
    }

    #[test]
    fn test_is_shared_path() {
        assert!(is_shared_path("packages/shared/utils.ts"));
        assert!(is_shared_path("libs/common/hash.ts"));
        assert!(is_shared_path("src/pkg/utils.go"));
        assert!(!is_shared_path("apps/billing/utils.ts"));
    }

    #[test]
    fn test_unknown_service_excluded() {
        let sigs = vec![
            make_sig("foo", "src/utils.ts", None, 42, &["x"]),
            make_sig("foo", "lib/utils.ts", None, 42, &["x"]),
        ];

        let grouped = group_by_service(sigs);
        assert!(grouped.is_empty());
    }

    #[test]
    fn test_empty_result_on_no_signatures() {
        let result = empty_result();
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }
}
