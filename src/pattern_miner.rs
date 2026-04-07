//! P5 — Pattern mining engine.
//!
//! Clusters dismissed (FalsePositive) findings from [`ProjectState`] to suggest
//! suppression rules and rule-pack exceptions. This module is pure computation:
//! it reads state immutably and returns new suggestion structs.

use std::collections::HashMap;

use crate::state::{FindingStatus, ProjectState};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestedSuppression {
    pub scanner: String,
    pub file_pattern: String,
    pub reason: String,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuggestedRuleException {
    pub scanner: String,
    pub pattern: String,
    pub description: String,
}

#[derive(Debug, Clone, Default)]
pub struct MinerResult {
    pub suppressions: Vec<SuggestedSuppression>,
    pub exceptions: Vec<SuggestedRuleException>,
}

// ---------------------------------------------------------------------------
// Cluster key types
// ---------------------------------------------------------------------------

/// An intermediate grouping of dismissed findings by (scanner, file_pattern).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClusterKey {
    scanner: String,
    file_pattern: String,
}

/// Per-cluster aggregated data used for suggestion generation.
#[derive(Debug, Clone)]
struct ClusterData {
    count: usize,
    messages: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Mine dismissed findings for recurring patterns that suggest suppression rules.
///
/// Only findings with status `FalsePositive` are considered. Clusters are formed
/// by `(scanner, file_pattern)`. A cluster must reach `min_cluster_size` to
/// produce a suggestion.
///
/// Returns a new `MinerResult` — the input state is never mutated.
pub fn mine_patterns(state: &ProjectState, min_cluster_size: usize) -> MinerResult {
    let clusters = build_clusters(state);
    let suppressions = build_suppressions(&clusters, min_cluster_size);
    let exceptions = build_exceptions(&clusters, min_cluster_size);

    MinerResult {
        suppressions,
        exceptions,
    }
}

/// Render suggestions as a human-readable string for CLI display.
pub fn format_suggestions(result: &MinerResult) -> String {
    if result.suppressions.is_empty() && result.exceptions.is_empty() {
        return "No recurring false-positive patterns found.".to_string();
    }

    let mut lines: Vec<String> = Vec::new();

    if !result.suppressions.is_empty() {
        lines.push("Suggested suppressions:".to_string());
        lines.push(String::new());
        for (i, s) in result.suppressions.iter().enumerate() {
            lines.push(format!(
                "  {}. [{}] {} ({} dismissed)",
                i + 1,
                s.scanner,
                s.file_pattern,
                s.count,
            ));
            lines.push(format!("     Reason: {}", s.reason));
        }
    }

    if !result.exceptions.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("Suggested rule exceptions:".to_string());
        lines.push(String::new());
        for (i, e) in result.exceptions.iter().enumerate() {
            lines.push(format!(
                "  {}. [{}] pattern: \"{}\"",
                i + 1,
                e.scanner,
                e.pattern,
            ));
            lines.push(format!("     {}", e.description));
        }
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Internal helpers (each < 50 lines)
// ---------------------------------------------------------------------------

/// Build clusters from all FalsePositive findings in the state.
fn build_clusters(state: &ProjectState) -> HashMap<ClusterKey, ClusterData> {
    let mut clusters: HashMap<ClusterKey, ClusterData> = HashMap::new();

    for record in state.findings.values() {
        if record.status != FindingStatus::FalsePositive {
            continue;
        }

        let file_pattern = extract_file_pattern(record.file.as_deref());
        let key = ClusterKey {
            scanner: record.scanner.clone(),
            file_pattern,
        };

        let data = clusters.entry(key).or_insert_with(|| ClusterData {
            count: 0,
            messages: Vec::new(),
        });
        data.count += 1;
        data.messages.push(record.message_pattern.clone());
    }

    clusters
}

/// Extract a glob-style file pattern from an optional file path.
///
/// Examples:
///   `Some("src/tests/user.test.ts")` -> `"*.test.ts"`
///   `Some("migrations/001.sql")`     -> `"migrations/*.sql"`
///   `Some("src/main.rs")`            -> `"*.rs"`
///   `None`                           -> `"*"`
fn extract_file_pattern(file: Option<&std::path::Path>) -> String {
    let path = match file {
        Some(p) => p,
        None => return "*".to_string(),
    };

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // Check for multi-extension patterns like .test.ts, .spec.js
    if let Some(pattern) = extract_multi_extension(&file_name) {
        return pattern;
    }

    // Check for well-known directory prefixes
    if let Some(prefix) = extract_directory_prefix(path) {
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default();
        if ext.is_empty() {
            return format!("{prefix}/*");
        }
        return format!("{prefix}/*.{ext}");
    }

    // Fall back to extension-only pattern
    match path.extension() {
        Some(ext) => format!("*.{}", ext.to_string_lossy()),
        None => "*".to_string(),
    }
}

/// Detect multi-extension patterns like `.test.ts` or `.spec.js`.
fn extract_multi_extension(file_name: &str) -> Option<String> {
    let suffixes = [
        ".test.ts",
        ".test.tsx",
        ".test.js",
        ".test.jsx",
        ".spec.ts",
        ".spec.tsx",
        ".spec.js",
        ".spec.jsx",
        ".stories.tsx",
        ".stories.ts",
        ".d.ts",
        ".module.css",
        ".module.scss",
    ];

    for suffix in &suffixes {
        if file_name.ends_with(suffix) {
            return Some(format!("*{suffix}"));
        }
    }
    None
}

/// Check for well-known directory prefixes like `migrations/`, `test/`, etc.
fn extract_directory_prefix(path: &std::path::Path) -> Option<String> {
    let known_dirs = [
        "migrations",
        "seeds",
        "fixtures",
        "mocks",
        "__mocks__",
        "__tests__",
        "test",
        "tests",
        "e2e",
        "cypress",
        "storybook",
        "stories",
    ];

    for component in path.components() {
        let segment = component.as_os_str().to_string_lossy();
        for dir in &known_dirs {
            if segment.eq_ignore_ascii_case(dir) {
                return Some(dir.to_string());
            }
        }
    }
    None
}

/// Build suppression suggestions from clusters that meet the threshold.
fn build_suppressions(
    clusters: &HashMap<ClusterKey, ClusterData>,
    min_cluster_size: usize,
) -> Vec<SuggestedSuppression> {
    let mut suggestions: Vec<SuggestedSuppression> = clusters
        .iter()
        .filter(|(_, data)| data.count >= min_cluster_size)
        .map(|(key, data)| {
            let reason = build_reason(&key.scanner, &key.file_pattern, &data.messages);
            SuggestedSuppression {
                scanner: key.scanner.clone(),
                file_pattern: key.file_pattern.clone(),
                reason,
                count: data.count,
            }
        })
        .collect();

    // Sort by count descending for deterministic, useful output
    suggestions.sort_by(|a, b| b.count.cmp(&a.count).then(a.scanner.cmp(&b.scanner)));
    suggestions
}

/// Build rule exception suggestions from message-keyword clusters.
fn build_exceptions(
    clusters: &HashMap<ClusterKey, ClusterData>,
    min_cluster_size: usize,
) -> Vec<SuggestedRuleException> {
    let mut exceptions: Vec<SuggestedRuleException> = Vec::new();

    for (key, data) in clusters {
        if data.count < min_cluster_size {
            continue;
        }

        if let Some(shared) = find_shared_keyword(&data.messages) {
            exceptions.push(SuggestedRuleException {
                scanner: key.scanner.clone(),
                pattern: shared.clone(),
                description: format!(
                    "{} FPs in {} share keyword \"{}\"; consider adding a rule exception",
                    data.count, key.file_pattern, shared,
                ),
            });
        }
    }

    exceptions.sort_by(|a, b| a.scanner.cmp(&b.scanner).then(a.pattern.cmp(&b.pattern)));
    exceptions
}

/// Build a human-readable reason string from the cluster data.
fn build_reason(scanner: &str, file_pattern: &str, messages: &[String]) -> String {
    let prefix = find_shared_prefix(messages);
    if prefix.is_empty() {
        format!(
            "Scanner {} consistently flags {} files as false positives",
            scanner, file_pattern,
        )
    } else {
        format!(
            "Scanner {} on {} — common pattern: \"{}...\"",
            scanner, file_pattern, prefix,
        )
    }
}

/// Find the longest shared prefix across all messages (word-boundary aware).
fn find_shared_prefix(messages: &[String]) -> String {
    if messages.is_empty() {
        return String::new();
    }

    let first = &messages[0];
    let mut prefix_len = first.len();

    for msg in &messages[1..] {
        prefix_len = first
            .chars()
            .zip(msg.chars())
            .take(prefix_len)
            .take_while(|(a, b)| a == b)
            .count();
    }

    // Trim to last word boundary
    let candidate = &first[..first.char_indices().nth(prefix_len).map_or(first.len(), |(i, _)| i)];
    let trimmed = candidate.trim_end();

    // Only keep if it's at least 8 chars (meaningful)
    if trimmed.len() < 8 {
        return String::new();
    }

    trimmed.to_string()
}

/// Find the most common non-trivial keyword across messages.
fn find_shared_keyword(messages: &[String]) -> Option<String> {
    if messages.len() < 2 {
        return None;
    }

    let stop_words: std::collections::HashSet<&str> = [
        "the", "a", "an", "is", "in", "on", "at", "to", "for", "of", "and", "or", "not", "no",
        "has", "have", "with", "without", "this", "that", "but", "from",
    ]
    .into_iter()
    .collect();

    let mut word_counts: HashMap<String, usize> = HashMap::new();

    for msg in messages {
        // Deduplicate words within a single message
        let unique_words: std::collections::HashSet<String> = msg
            .split_whitespace()
            .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()).to_lowercase())
            .filter(|w| w.len() > 3 && !stop_words.contains(w.as_str()))
            .collect();

        for word in unique_words {
            *word_counts.entry(word).or_insert(0) += 1;
        }
    }

    // Find keyword that appears in all messages; prefer longest on ties
    let threshold = messages.len();
    word_counts
        .into_iter()
        .filter(|(_, count)| *count >= threshold)
        .max_by(|(word_a, count_a), (word_b, count_b)| {
            count_a
                .cmp(count_b)
                .then(word_a.len().cmp(&word_b.len()))
        })
        .map(|(word, _)| word)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{FindingRecord, FindingStatus, ProjectState};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn make_fp_record(scanner: &str, file: Option<&str>, message: &str) -> FindingRecord {
        FindingRecord {
            status: FindingStatus::FalsePositive,
            scanner: scanner.to_string(),
            file: file.map(PathBuf::from),
            message_pattern: message.to_string(),
            first_seen: "2026-01-01".to_string(),
            labeled_at: Some("2026-02-01".to_string()),
            labeled_by: Some("user".to_string()),
            reason: Some("not relevant".to_string()),
            fixed_at: None,
            tags: Vec::new(),
        }
    }

    fn make_state(records: Vec<(&str, FindingRecord)>) -> ProjectState {
        let findings: HashMap<String, FindingRecord> = records
            .into_iter()
            .map(|(id, r)| (id.to_string(), r))
            .collect();
        ProjectState {
            version: 1,
            last_scan: Some("2026-04-07".to_string()),
            findings,
        }
    }

    #[test]
    fn empty_state_returns_no_suggestions() {
        let state = ProjectState::default();
        let result = mine_patterns(&state, 3);
        assert!(result.suppressions.is_empty());
        assert!(result.exceptions.is_empty());
    }

    #[test]
    fn ignores_non_false_positive_findings() {
        let state = make_state(vec![
            (
                "id1",
                FindingRecord {
                    status: FindingStatus::Open,
                    scanner: "S7".to_string(),
                    file: Some(PathBuf::from("src/user.test.ts")),
                    message_pattern: "missing error handling".to_string(),
                    first_seen: "2026-01-01".to_string(),
                    labeled_at: None,
                    labeled_by: None,
                    reason: None,
                    fixed_at: None,
                    tags: Vec::new(),
                },
            ),
            (
                "id2",
                FindingRecord {
                    status: FindingStatus::Confirmed,
                    scanner: "S7".to_string(),
                    file: Some(PathBuf::from("src/user2.test.ts")),
                    message_pattern: "missing error handling".to_string(),
                    first_seen: "2026-01-01".to_string(),
                    labeled_at: None,
                    labeled_by: None,
                    reason: None,
                    fixed_at: None,
                    tags: Vec::new(),
                },
            ),
        ]);

        let result = mine_patterns(&state, 1);
        assert!(result.suppressions.is_empty());
    }

    #[test]
    fn clusters_by_scanner_and_file_pattern() {
        let state = make_state(vec![
            (
                "id1",
                make_fp_record("S7", Some("src/user.test.ts"), "missing handler"),
            ),
            (
                "id2",
                make_fp_record("S7", Some("src/order.test.ts"), "missing handler"),
            ),
            (
                "id3",
                make_fp_record("S7", Some("src/cart.test.ts"), "missing handler"),
            ),
        ]);

        let result = mine_patterns(&state, 3);
        assert_eq!(result.suppressions.len(), 1);
        assert_eq!(result.suppressions[0].scanner, "S7");
        assert_eq!(result.suppressions[0].file_pattern, "*.test.ts");
        assert_eq!(result.suppressions[0].count, 3);
    }

    #[test]
    fn below_threshold_produces_no_suggestions() {
        let state = make_state(vec![
            (
                "id1",
                make_fp_record("S7", Some("src/user.test.ts"), "missing handler"),
            ),
            (
                "id2",
                make_fp_record("S7", Some("src/order.test.ts"), "missing handler"),
            ),
        ]);

        let result = mine_patterns(&state, 3);
        assert!(result.suppressions.is_empty());
    }

    #[test]
    fn migration_files_get_directory_pattern() {
        let state = make_state(vec![
            (
                "id1",
                make_fp_record("S12", Some("migrations/001_init.sql"), "missing index"),
            ),
            (
                "id2",
                make_fp_record("S12", Some("migrations/002_users.sql"), "missing index"),
            ),
            (
                "id3",
                make_fp_record("S12", Some("migrations/003_orders.sql"), "missing index"),
            ),
        ]);

        let result = mine_patterns(&state, 3);
        assert_eq!(result.suppressions.len(), 1);
        assert_eq!(result.suppressions[0].file_pattern, "migrations/*.sql");
    }

    #[test]
    fn shared_prefix_builds_descriptive_reason() {
        let state = make_state(vec![
            (
                "id1",
                make_fp_record(
                    "S7",
                    Some("src/a.test.ts"),
                    "missing error handling in endpoint /api/users",
                ),
            ),
            (
                "id2",
                make_fp_record(
                    "S7",
                    Some("src/b.test.ts"),
                    "missing error handling in endpoint /api/orders",
                ),
            ),
            (
                "id3",
                make_fp_record(
                    "S7",
                    Some("src/c.test.ts"),
                    "missing error handling in endpoint /api/cart",
                ),
            ),
        ]);

        let result = mine_patterns(&state, 3);
        assert_eq!(result.suppressions.len(), 1);
        assert!(result.suppressions[0]
            .reason
            .contains("missing error handling in endpoint"));
    }

    #[test]
    fn shared_keyword_generates_exception() {
        let state = make_state(vec![
            (
                "id1",
                make_fp_record(
                    "S11",
                    Some("src/a.ts"),
                    "rate limiter not found for authentication route",
                ),
            ),
            (
                "id2",
                make_fp_record(
                    "S11",
                    Some("src/b.ts"),
                    "rate limiter missing on authentication handler",
                ),
            ),
            (
                "id3",
                make_fp_record(
                    "S11",
                    Some("src/c.ts"),
                    "no rate limiter for authentication middleware",
                ),
            ),
        ]);

        let result = mine_patterns(&state, 3);
        assert!(!result.exceptions.is_empty());

        let auth_exception = result
            .exceptions
            .iter()
            .find(|e| e.pattern == "authentication");
        assert!(
            auth_exception.is_some(),
            "Expected an exception for 'authentication' keyword"
        );
    }

    #[test]
    fn format_suggestions_empty() {
        let result = MinerResult::default();
        let output = format_suggestions(&result);
        assert_eq!(output, "No recurring false-positive patterns found.");
    }

    #[test]
    fn format_suggestions_renders_both_types() {
        let result = MinerResult {
            suppressions: vec![SuggestedSuppression {
                scanner: "S7".to_string(),
                file_pattern: "*.test.ts".to_string(),
                reason: "Test files consistently flagged".to_string(),
                count: 5,
            }],
            exceptions: vec![SuggestedRuleException {
                scanner: "S11".to_string(),
                pattern: "authentication".to_string(),
                description: "5 FPs share keyword".to_string(),
            }],
        };

        let output = format_suggestions(&result);
        assert!(output.contains("Suggested suppressions:"));
        assert!(output.contains("[S7] *.test.ts (5 dismissed)"));
        assert!(output.contains("Suggested rule exceptions:"));
        assert!(output.contains("[S11] pattern: \"authentication\""));
    }

    #[test]
    fn extract_file_pattern_none_returns_star() {
        assert_eq!(extract_file_pattern(None), "*");
    }

    #[test]
    fn extract_file_pattern_spec_js() {
        let path = std::path::Path::new("src/components/Button.spec.js");
        assert_eq!(extract_file_pattern(Some(path)), "*.spec.js");
    }

    #[test]
    fn extract_file_pattern_plain_extension() {
        let path = std::path::Path::new("src/main.rs");
        assert_eq!(extract_file_pattern(Some(path)), "*.rs");
    }
}
