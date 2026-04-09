// ---------------------------------------------------------------------------
// suppress.rs — Three-layer finding suppression system
//
// Layer 1: Inline comments (sentinella-ignore / sentinella-ignore-next-line / sentinella-ignore-file)
// Layer 2: Config-based suppression (disabled_scanners, exclude_paths, auth_exceptions)
// Layer 3: Interactive dismiss (.sentinella/ignore.yaml)
// ---------------------------------------------------------------------------

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::scanners::types::ScanResult;

// ---------------------------------------------------------------------------
// Layer 1 — Inline suppression comments
// ---------------------------------------------------------------------------

/// Aggregated set of inline suppression directives parsed from source files.
#[derive(Debug, Clone, Default)]
pub struct SuppressionSet {
    /// file -> line -> set of suppressed scanner IDs
    line_suppressions: HashMap<PathBuf, HashMap<usize, HashSet<String>>>,
    /// file -> set of scanner IDs suppressed for the entire file
    file_suppressions: HashMap<PathBuf, HashSet<String>>,
}

impl SuppressionSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a suppression set from all indexed source files.
    pub fn from_index(store: &crate::indexer::store::IndexStore) -> Self {
        let mut set = Self::new();
        for entry in store.files.iter() {
            let path = entry.key();
            if let Ok(source) = std::fs::read_to_string(path) {
                set.parse_file(path, &source);
            }
        }
        set
    }

    /// Parse suppression comments from a single source file.
    ///
    /// Supported forms:
    ///   // sentinella-ignore-next-line S7
    ///   // sentinella-ignore S12          (current line)
    ///   # sentinella-ignore-next-line S7  (Python / shell)
    ///   /* sentinella-ignore-file S1 */   (whole file)
    ///   <!-- sentinella-ignore S5 -->     (HTML)
    pub fn parse_file(&mut self, path: &Path, source: &str) {
        let canonical = path.to_path_buf();

        for (line_idx, line) in source.lines().enumerate() {
            let line_number = line_idx + 1; // 1-based

            if let Some(directive) = extract_directive(line) {
                match directive.kind {
                    DirectiveKind::NextLine => {
                        let target_line = line_number + 1;
                        self.line_suppressions
                            .entry(canonical.clone())
                            .or_default()
                            .entry(target_line)
                            .or_default()
                            .insert(directive.scanner_id);
                    }
                    DirectiveKind::CurrentLine => {
                        self.line_suppressions
                            .entry(canonical.clone())
                            .or_default()
                            .entry(line_number)
                            .or_default()
                            .insert(directive.scanner_id);
                    }
                    DirectiveKind::File => {
                        self.file_suppressions
                            .entry(canonical.clone())
                            .or_default()
                            .insert(directive.scanner_id);
                    }
                }
            }
        }
    }

    /// Returns `true` when the given scanner finding at `file:line` is suppressed.
    pub fn is_suppressed(&self, file: &Path, line: usize, scanner_id: &str) -> bool {
        // Check file-level suppression
        if let Some(ids) = self.file_suppressions.get(file) {
            if ids.contains(scanner_id) {
                return true;
            }
        }
        // Check line-level suppression
        if let Some(lines) = self.line_suppressions.get(file) {
            if let Some(ids) = lines.get(&line) {
                if ids.contains(scanner_id) {
                    return true;
                }
            }
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Directive parser internals
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum DirectiveKind {
    NextLine,
    CurrentLine,
    File,
}

#[derive(Debug, Clone)]
struct Directive {
    kind: DirectiveKind,
    scanner_id: String,
}

/// Extract a sentinella suppression directive from a single line of source.
fn extract_directive(line: &str) -> Option<Directive> {
    // Strip common comment delimiters to get the inner text.
    let inner = strip_comment_delimiters(line)?;
    let trimmed = inner.trim();

    if let Some(rest) = trimmed.strip_prefix("sentinella-ignore-next-line") {
        let scanner_id = rest.trim().to_string();
        if scanner_id.is_empty() {
            return None;
        }
        Some(Directive {
            kind: DirectiveKind::NextLine,
            scanner_id,
        })
    } else if let Some(rest) = trimmed.strip_prefix("sentinella-ignore-file") {
        let scanner_id = rest.trim().to_string();
        if scanner_id.is_empty() {
            return None;
        }
        Some(Directive {
            kind: DirectiveKind::File,
            scanner_id,
        })
    } else if let Some(rest) = trimmed.strip_prefix("sentinella-ignore") {
        let scanner_id = rest.trim().to_string();
        if scanner_id.is_empty() {
            return None;
        }
        Some(Directive {
            kind: DirectiveKind::CurrentLine,
            scanner_id,
        })
    } else {
        None
    }
}

/// Strip comment delimiters from various languages and return the inner text.
///
/// Handles: `//`, `#`, `/* ... */`, `<!-- ... -->`
fn strip_comment_delimiters(line: &str) -> Option<String> {
    let trimmed = line.trim();

    // `// ...`
    if let Some(rest) = trimmed.strip_prefix("//") {
        return Some(rest.to_string());
    }
    // `# ...` (Python / shell)
    if let Some(rest) = trimmed.strip_prefix('#') {
        return Some(rest.to_string());
    }
    // `/* ... */`
    if let Some(rest) = trimmed.strip_prefix("/*") {
        let inner = rest.strip_suffix("*/").unwrap_or(rest);
        return Some(inner.to_string());
    }
    // `<!-- ... -->`
    if let Some(rest) = trimmed.strip_prefix("<!--") {
        let inner = rest.strip_suffix("-->").unwrap_or(rest);
        return Some(inner.to_string());
    }

    // Inline trailing comments: `code // sentinella-...` or `code # sentinella-...`
    if let Some(pos) = trimmed.find("// sentinella-") {
        return Some(trimmed[pos + 2..].to_string());
    }
    if let Some(pos) = trimmed.find("# sentinella-") {
        return Some(trimmed[pos + 1..].to_string());
    }

    None
}

// ---------------------------------------------------------------------------
// Layer 2 — Config-based suppression
// ---------------------------------------------------------------------------

/// Suppression section of `.sentinella.yaml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuppressConfig {
    /// Completely disable these scanners (e.g. ["S7", "S12"])
    #[serde(default)]
    pub disabled_scanners: Vec<String>,

    /// Path-glob exclusions (global and per-scanner)
    #[serde(default)]
    pub exclude_paths: ExcludePaths,

    /// Specific auth exceptions for scanners that flag unprotected routes
    #[serde(default)]
    pub auth_exceptions: Vec<AuthException>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExcludePaths {
    /// Globs that suppress findings across all scanners
    #[serde(default)]
    pub global: Vec<String>,

    /// Scanner-specific path globs: `{ "S1": ["tests/**"] }`
    #[serde(flatten)]
    pub per_scanner: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthException {
    pub path: String,
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Layer 3 — Dismiss command + ignore file
// ---------------------------------------------------------------------------

/// A single dismissal record persisted in `.sentinella/ignore.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DismissRecord {
    pub scanner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub by: Option<String>,
    pub at: String,
}

/// Contents of `.sentinella/ignore.yaml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DismissFile {
    #[serde(default)]
    pub dismissed: Vec<DismissRecord>,
}

/// Load the dismiss file from `<root>/.sentinella/ignore.yaml`.
pub fn load_dismissals(root: &Path) -> anyhow::Result<DismissFile> {
    let path = root.join(".sentinella").join("ignore.yaml");
    if !path.exists() {
        return Ok(DismissFile::default());
    }
    let contents = std::fs::read_to_string(&path)?;
    let file: DismissFile = serde_yaml::from_str(&contents)?;
    Ok(file)
}

/// Save the dismiss file to `<root>/.sentinella/ignore.yaml`.
pub fn save_dismissals(root: &Path, file: &DismissFile) -> anyhow::Result<()> {
    let dir = root.join(".sentinella");
    std::fs::create_dir_all(&dir)?;
    let contents = serde_yaml::to_string(file)?;
    let path = dir.join("ignore.yaml");
    let tmp_path = path.with_extension("yaml.tmp");
    std::fs::write(&tmp_path, contents)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Check if a finding's stable_id is dismissed.
pub fn is_dismissed(dismissals: &DismissFile, stable_id: &str) -> bool {
    dismissals
        .dismissed
        .iter()
        .any(|record| record.pattern.as_ref().is_some_and(|p| p == stable_id))
}

/// Return today's date as an ISO-8601 string (YYYY-MM-DD) without external deps.
pub fn today_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    crate::state::chrono_free_date(secs)
}

// ---------------------------------------------------------------------------
// Combined filter — apply all suppression layers
// ---------------------------------------------------------------------------

/// Filter scan results through all three suppression layers.
///
/// Returns a new `Vec<ScanResult>` with suppressed findings removed and
/// scores recalculated.  The input is not mutated.
pub fn apply_suppressions(
    results: &[ScanResult],
    suppressions: &SuppressionSet,
    config_suppress: &SuppressConfig,
    dismissals: &DismissFile,
    root: &Path,
) -> Vec<ScanResult> {
    results
        .iter()
        .map(|result| filter_single_result(result, suppressions, config_suppress, dismissals, root))
        .collect()
}

fn filter_single_result(
    result: &ScanResult,
    suppressions: &SuppressionSet,
    config_suppress: &SuppressConfig,
    dismissals: &DismissFile,
    root: &Path,
) -> ScanResult {
    // Layer 2: entirely disabled scanner
    if config_suppress.disabled_scanners.contains(&result.scanner) {
        return ScanResult {
            scanner: result.scanner.clone(),
            findings: vec![],
            score: 100,
            summary: format!("{} (disabled)", result.summary),
        };
    }

    let filtered_findings: Vec<_> = result
        .findings
        .iter()
        .filter(|f| !is_finding_suppressed(f, suppressions, config_suppress, dismissals, root))
        .cloned()
        .collect();

    let score = recalculate_score(result.score, result.findings.len(), filtered_findings.len());

    ScanResult {
        scanner: result.scanner.clone(),
        findings: filtered_findings,
        score,
        summary: result.summary.clone(),
    }
}

fn is_finding_suppressed(
    f: &crate::scanners::types::Finding,
    suppressions: &SuppressionSet,
    config_suppress: &SuppressConfig,
    dismissals: &DismissFile,
    root: &Path,
) -> bool {
    // Layer 1: inline suppression
    if let (Some(file), Some(line)) = (&f.file, f.line) {
        if suppressions.is_suppressed(file, line, &f.scanner) {
            return true;
        }
    }

    // Layer 2: config exclude_paths
    if let Some(file) = &f.file {
        let file_str = make_relative(file, root);
        // Global excludes
        if config_suppress
            .exclude_paths
            .global
            .iter()
            .any(|pat| glob_match(pat, &file_str))
        {
            return true;
        }
        // Per-scanner excludes
        if let Some(patterns) = config_suppress.exclude_paths.per_scanner.get(&f.scanner) {
            if patterns.iter().any(|pat| glob_match(pat, &file_str)) {
                return true;
            }
        }
    }

    // Layer 3: dismissals
    let stable_id = compute_stable_id(&f.scanner, f.file.as_deref(), &f.message);
    is_dismissed(dismissals, &stable_id)
}

/// Derive a relative path string for glob matching.
fn make_relative(file: &Path, root: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .to_string()
}

/// Compute a stable finding identifier from scanner + file + message.
///
/// Uses FNV-1a over `"{scanner}:{file}:{normalized_message}"` — identical
/// algorithm to `Finding::stable_id`.  The `file` path should already be
/// relative to the project root.
pub fn compute_stable_id(scanner: &str, file: Option<&Path>, message: &str) -> String {
    let file_str = file.map_or_else(String::new, |p| p.to_string_lossy().to_string());
    let normalized = normalize_message_str(message);
    let key = format!("{scanner}:{file_str}:{normalized}");
    let hash = crate::scanners::types::fnv1a_hash(&key);
    format!("{scanner}-{hash:08x}")
}

/// Normalize a message string for stable ID generation.
///
/// Replaces volatile tokens (HTTP method+path, line numbers) so that
/// minor code movement doesn't invalidate a stored ID.
fn normalize_message_str(message: &str) -> String {
    use std::sync::OnceLock;
    static RE_METHOD: OnceLock<regex::Regex> = OnceLock::new();
    static RE_LINE: OnceLock<regex::Regex> = OnceLock::new();

    let re_method = RE_METHOD.get_or_init(|| {
        regex::Regex::new(r"(GET|POST|PUT|PATCH|DELETE)\s+\S+").expect("valid regex")
    });
    let normalized = re_method.replace_all(message, "METHOD PATH");

    let re_line = RE_LINE.get_or_init(|| regex::Regex::new(r"line \d+").expect("valid regex"));
    re_line.replace_all(&normalized, "line N").into_owned()
}

fn recalculate_score(base_score: u8, original_count: usize, filtered_count: usize) -> u8 {
    if original_count == 0 {
        return 100;
    }
    let suppressed = original_count - filtered_count;
    let bonus = (suppressed * 100) / original_count.max(1);
    ((base_score as usize) + bonus).min(100) as u8
}

/// Simple glob matching supporting `**` (any path) and `*` (single segment).
fn glob_match(pattern: &str, path: &str) -> bool {
    globset::GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .ok()
        .and_then(|g| {
            let mut builder = globset::GlobSetBuilder::new();
            builder.add(g);
            builder.build().ok()
        })
        .map(|gs| gs.is_match(path))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::types::{Finding, Severity};

    // -- Directive parsing ---------------------------------------------------

    #[test]
    fn parse_double_slash_ignore_next_line() {
        let d = extract_directive("  // sentinella-ignore-next-line S7").unwrap();
        assert_eq!(d.kind, DirectiveKind::NextLine);
        assert_eq!(d.scanner_id, "S7");
    }

    #[test]
    fn parse_hash_ignore_next_line() {
        let d = extract_directive("# sentinella-ignore-next-line S7").unwrap();
        assert_eq!(d.kind, DirectiveKind::NextLine);
        assert_eq!(d.scanner_id, "S7");
    }

    #[test]
    fn parse_block_comment_ignore_file() {
        let d = extract_directive("/* sentinella-ignore-file S1 */").unwrap();
        assert_eq!(d.kind, DirectiveKind::File);
        assert_eq!(d.scanner_id, "S1");
    }

    #[test]
    fn parse_html_comment_ignore() {
        let d = extract_directive("<!-- sentinella-ignore S5 -->").unwrap();
        assert_eq!(d.kind, DirectiveKind::CurrentLine);
        assert_eq!(d.scanner_id, "S5");
    }

    #[test]
    fn parse_no_scanner_id_returns_none() {
        assert!(extract_directive("// sentinella-ignore").is_none());
    }

    #[test]
    fn parse_unrelated_comment_returns_none() {
        assert!(extract_directive("// TODO: fix this").is_none());
    }

    // -- SuppressionSet ------------------------------------------------------

    #[test]
    fn suppression_set_next_line() {
        let mut set = SuppressionSet::new();
        let source = "// sentinella-ignore-next-line S7\nlet x = 1;\n";
        let path = PathBuf::from("test.rs");
        set.parse_file(&path, source);

        assert!(!set.is_suppressed(&path, 1, "S7")); // comment line itself
        assert!(set.is_suppressed(&path, 2, "S7")); // next line
        assert!(!set.is_suppressed(&path, 2, "S1")); // different scanner
    }

    #[test]
    fn suppression_set_current_line() {
        let mut set = SuppressionSet::new();
        let source = "let x = 1; // sentinella-ignore S12\n";
        let path = PathBuf::from("test.rs");
        set.parse_file(&path, source);

        assert!(set.is_suppressed(&path, 1, "S12"));
    }

    #[test]
    fn suppression_set_file_level() {
        let mut set = SuppressionSet::new();
        let source = "/* sentinella-ignore-file S1 */\nfn main() {}\n";
        let path = PathBuf::from("test.rs");
        set.parse_file(&path, source);

        assert!(set.is_suppressed(&path, 1, "S1"));
        assert!(set.is_suppressed(&path, 2, "S1"));
        assert!(set.is_suppressed(&path, 999, "S1"));
    }

    // -- Dismiss file --------------------------------------------------------

    #[test]
    fn is_dismissed_matches_pattern() {
        let file = DismissFile {
            dismissed: vec![DismissRecord {
                scanner: "S7".into(),
                file: None,
                pattern: Some("S7-a3f2b1c0".into()),
                reason: "false positive".into(),
                by: Some("dev".into()),
                at: "2025-01-01".into(),
            }],
        };
        assert!(is_dismissed(&file, "S7-a3f2b1c0"));
        assert!(!is_dismissed(&file, "S7-deadbeef"));
    }

    #[test]
    fn is_dismissed_empty_file() {
        let file = DismissFile::default();
        assert!(!is_dismissed(&file, "S7-a3f2b1c0"));
    }

    // -- Glob matching -------------------------------------------------------

    #[test]
    fn glob_match_double_star() {
        assert!(glob_match("tests/**", "tests/unit/foo.rs"));
        assert!(!glob_match("tests/**", "src/main.rs"));
    }

    #[test]
    fn glob_match_single_star() {
        assert!(glob_match("*.rs", "main.rs"));
        assert!(!glob_match("*.rs", "src/main.rs"));
    }

    #[test]
    fn glob_match_combined() {
        assert!(glob_match("src/**/*.test.ts", "src/utils/foo.test.ts"));
        assert!(!glob_match("src/**/*.test.ts", "src/utils/foo.ts"));
    }

    // -- Stable ID -----------------------------------------------------------

    #[test]
    fn stable_id_deterministic() {
        let id1 = compute_stable_id("S7", Some(Path::new("src/main.rs")), "bad thing");
        let id2 = compute_stable_id("S7", Some(Path::new("src/main.rs")), "bad thing");
        assert_eq!(id1, id2);
        assert!(id1.starts_with("S7-"));
    }

    #[test]
    fn stable_id_differs_by_message() {
        let id1 = compute_stable_id("S7", Some(Path::new("a.rs")), "msg1");
        let id2 = compute_stable_id("S7", Some(Path::new("a.rs")), "msg2");
        assert_ne!(id1, id2);
    }

    // -- apply_suppressions --------------------------------------------------

    #[test]
    fn apply_suppressions_disables_scanner() {
        let results = vec![ScanResult {
            scanner: "S7".into(),
            findings: vec![Finding::new("S7", Severity::Warning, "oops")],
            score: 50,
            summary: "test".into(),
        }];

        let config = SuppressConfig {
            disabled_scanners: vec!["S7".into()],
            ..Default::default()
        };

        let filtered = apply_suppressions(
            &results,
            &SuppressionSet::new(),
            &config,
            &DismissFile::default(),
            Path::new("/project"),
        );

        assert_eq!(filtered[0].findings.len(), 0);
        assert_eq!(filtered[0].score, 100);
        assert!(filtered[0].summary.contains("(disabled)"));
    }

    #[test]
    fn apply_suppressions_global_exclude() {
        let results = vec![ScanResult {
            scanner: "S1".into(),
            findings: vec![Finding::new("S1", Severity::Warning, "stub")
                .with_file("/project/tests/foo.rs")
                .with_line(10)],
            score: 50,
            summary: "test".into(),
        }];

        let config = SuppressConfig {
            exclude_paths: ExcludePaths {
                global: vec!["tests/**".into()],
                per_scanner: HashMap::new(),
            },
            ..Default::default()
        };

        let filtered = apply_suppressions(
            &results,
            &SuppressionSet::new(),
            &config,
            &DismissFile::default(),
            Path::new("/project"),
        );

        assert_eq!(filtered[0].findings.len(), 0);
    }

    // -- today_iso -----------------------------------------------------------

    #[test]
    fn today_iso_format() {
        let date = today_iso();
        // Should match YYYY-MM-DD
        assert_eq!(date.len(), 10);
        assert_eq!(&date[4..5], "-");
        assert_eq!(&date[7..8], "-");
    }
}
