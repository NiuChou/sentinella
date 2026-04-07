//! Bayesian confidence calibration for scanner findings.
//!
//! Each (scanner, file_extension) bucket maintains a Beta distribution
//! (alpha, beta). User feedback shifts the posterior, adjusting future
//! confidence scores toward empirical precision.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::scanners::types::{Confidence, ScanResult};
use crate::state::{FindingStatus, ProjectState};

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationStore {
    pub version: u32,
    pub buckets: HashMap<String, BucketEntry>,
    #[serde(default)]
    pub global_priors: HashMap<String, BucketEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketEntry {
    pub alpha: f64,
    pub beta: f64,
    #[serde(default)]
    pub last_update: Option<String>,
}

impl BucketEntry {
    pub fn new(alpha: f64, beta: f64) -> Self {
        Self {
            alpha,
            beta,
            last_update: None,
        }
    }

    /// Posterior mean = alpha / (alpha + beta).
    pub fn confidence(&self) -> f64 {
        let total = self.alpha + self.beta;
        if total == 0.0 {
            0.5
        } else {
            self.alpha / total
        }
    }

    /// Record a true positive (confirmed finding).
    pub fn record_confirmed(&mut self) {
        self.alpha += 1.0;
    }

    /// Record a false positive.
    pub fn record_false_positive(&mut self) {
        self.beta += 1.0;
    }

    /// Record a fix (the finding was a real issue).
    pub fn record_fixed(&mut self) {
        self.alpha += 1.0;
    }

    /// Total feedback samples.
    pub fn samples(&self) -> f64 {
        self.alpha + self.beta
    }
}

// ---------------------------------------------------------------------------
// Bucket key
// ---------------------------------------------------------------------------

/// Compute the calibration bucket key for a finding.
/// Format: "S7:*.controller.ts" or "S12:*.sql"
pub fn bucket_key(scanner_id: &str, file: Option<&Path>) -> String {
    let ext_pattern = file
        .and_then(|f| f.extension())
        .map(|ext| format!("*.{}", ext.to_string_lossy()))
        .unwrap_or_else(|| "*".to_string());
    format!("{scanner_id}:{ext_pattern}")
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

pub fn calibration_file_path(root: &Path) -> PathBuf {
    root.join(".sentinella").join("calibration.json")
}

pub fn load_calibration(root: &Path) -> anyhow::Result<CalibrationStore> {
    let path = calibration_file_path(root);
    if !path.exists() {
        return Ok(CalibrationStore {
            version: 1,
            buckets: HashMap::new(),
            global_priors: builtin_priors(),
        });
    }
    let content = std::fs::read_to_string(&path)?;
    let store: CalibrationStore = serde_json::from_str(&content)?;
    Ok(store)
}

pub fn save_calibration(root: &Path, store: &CalibrationStore) -> anyhow::Result<()> {
    let path = calibration_file_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(store)?;
    std::fs::write(&path, content)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Built-in priors (derived from 3 audit datasets)
// ---------------------------------------------------------------------------

fn builtin_priors() -> HashMap<String, BucketEntry> {
    let mut priors = HashMap::new();
    // S7 on .ts controller files: ~97% FP
    priors.insert("S7:*.ts".into(), BucketEntry::new(1.0, 20.0));
    // S12 on .sql files: ~95% FP
    priors.insert("S12:*.sql".into(), BucketEntry::new(1.0, 10.0));
    // S1 on .tsx files: ~95% FP (hook chains not traced)
    priors.insert("S1:*.tsx".into(), BucketEntry::new(1.0, 15.0));
    // S17 on .go files: ~80% FP (_ = err pattern)
    priors.insert("S17:*.go".into(), BucketEntry::new(2.0, 8.0));
    // S13 on general files: moderate FP
    priors.insert("S13:*".into(), BucketEntry::new(1.0, 5.0));
    priors
}

// ---------------------------------------------------------------------------
// Apply calibration (immutable: returns new vec)
// ---------------------------------------------------------------------------

/// Minimum samples before calibration overrides rule-based confidence.
const MIN_SAMPLES_FOR_CALIBRATION: f64 = 5.0;

/// Adjust finding confidence based on calibration data.
/// Returns a new vector; the original results are not mutated.
pub fn apply_calibration(results: &[ScanResult], store: &CalibrationStore) -> Vec<ScanResult> {
    results
        .iter()
        .map(|result| {
            let adjusted_findings = result
                .findings
                .iter()
                .map(|f| {
                    let key = bucket_key(&f.scanner, f.file.as_deref());

                    let entry = lookup_entry(store, &key, &f.scanner);

                    let mut new_finding = f.clone();

                    if let Some(entry) = entry {
                        if entry.samples() >= MIN_SAMPLES_FOR_CALIBRATION {
                            let calibrated = entry.confidence();
                            let rule_score = f.confidence.as_score();
                            let final_score = rule_score.min(calibrated);
                            new_finding.confidence = Confidence::from_score(final_score);
                        }
                    }

                    new_finding
                })
                .collect();

            ScanResult {
                scanner: result.scanner.clone(),
                findings: adjusted_findings,
                score: result.score,
                summary: result.summary.clone(),
            }
        })
        .collect()
}

/// Look up a calibration entry: exact bucket -> global prior -> scanner wildcard.
fn lookup_entry<'a>(
    store: &'a CalibrationStore,
    key: &str,
    scanner_id: &str,
) -> Option<&'a BucketEntry> {
    store
        .buckets
        .get(key)
        .or_else(|| store.global_priors.get(key))
        .or_else(|| {
            let wildcard = format!("{scanner_id}:*");
            store
                .buckets
                .get(&wildcard)
                .or_else(|| store.global_priors.get(&wildcard))
        })
}

// ---------------------------------------------------------------------------
// Update from user feedback
// ---------------------------------------------------------------------------

/// Update calibration buckets from state changes.
/// Mutates the store in place (caller owns the data).
pub fn update_from_state(store: &mut CalibrationStore, state: &ProjectState) {
    for record in state.findings.values() {
        let key = bucket_key(&record.scanner, record.file.as_deref());

        let entry = store
            .buckets
            .entry(key)
            .or_insert_with(|| BucketEntry::new(1.0, 1.0));

        match record.status {
            FindingStatus::Confirmed => entry.record_confirmed(),
            FindingStatus::FalsePositive => entry.record_false_positive(),
            FindingStatus::Fixed => entry.record_fixed(),
            FindingStatus::Open | FindingStatus::Accepted => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Triage handler
// ---------------------------------------------------------------------------

/// Run an interactive triage session over the given scan results.
///
/// Presents findings sorted by uncertainty (closest to 0.5 first),
/// prompts the user for a label, and persists updates to state + calibration.
pub fn handle_triage(
    root: &Path,
    results: &[ScanResult],
    batch: usize,
    scanner_filter: Option<&str>,
) -> anyhow::Result<()> {
    use std::io::Write;

    let mut state = crate::state::load_state(root)?;
    let mut calibration = load_calibration(root)?;

    // Collect findings, optionally filtered by scanner
    let mut all_findings: Vec<_> = results
        .iter()
        .flat_map(|r| r.findings.iter())
        .filter(|f| scanner_filter.map_or(true, |s| f.scanner == s))
        .collect();

    // Sort by uncertainty: closest to 0.5 confidence = most uncertain first
    all_findings.sort_by(|a, b| {
        let ua = (a.confidence.as_score() - 0.5).abs();
        let ub = (b.confidence.as_score() - 0.5).abs();
        ua.partial_cmp(&ub).unwrap_or(std::cmp::Ordering::Equal)
    });

    println!("Triage session: label up to {batch} findings\n");

    let stdin = std::io::stdin();
    let mut labeled = 0u32;

    for finding in all_findings.into_iter().take(batch) {
        let stable_id = finding.stable_id(root);

        // Skip already-labeled findings
        if let Some(record) = state.findings.get(&stable_id) {
            if record.status != FindingStatus::Open {
                continue;
            }
        }

        print_finding(finding);

        print!("  > ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        stdin.read_line(&mut input)?;
        let choice = input.trim().to_lowercase();

        let status = match choice.as_str() {
            "c" | "confirmed" => Some(FindingStatus::Confirmed),
            "f" | "false" | "fp" => Some(FindingStatus::FalsePositive),
            "a" | "accept" => Some(FindingStatus::Accepted),
            _ => None, // skip
        };

        if let Some(status) = status {
            let today = crate::state::today_iso();
            let user = std::env::var("USER").ok();

            // Upsert finding record
            let record =
                state
                    .findings
                    .entry(stable_id)
                    .or_insert_with(|| crate::state::FindingRecord {
                        status: FindingStatus::Open,
                        scanner: finding.scanner.clone(),
                        file: finding.file.clone(),
                        message_pattern: finding.message.clone(),
                        first_seen: today.clone(),
                        labeled_at: None,
                        labeled_by: None,
                        reason: None,
                        fixed_at: None,
                        tags: vec![],
                    });
            record.status = status;
            record.labeled_at = Some(today);
            record.labeled_by = user;

            // Update calibration bucket
            let key = bucket_key(&finding.scanner, finding.file.as_deref());
            let entry = calibration
                .buckets
                .entry(key)
                .or_insert_with(|| BucketEntry::new(1.0, 1.0));
            match status {
                FindingStatus::Confirmed => entry.record_confirmed(),
                FindingStatus::FalsePositive => entry.record_false_positive(),
                _ => {}
            }

            labeled += 1;
        }
    }

    // Persist
    crate::state::save_state(root, &state)?;
    save_calibration(root, &calibration)?;

    println!("\nLabeled {labeled} findings. Calibration updated.");
    Ok(())
}

/// Pretty-print a single finding for triage review.
fn print_finding(finding: &crate::scanners::types::Finding) {
    println!("-------------------------------------------");
    println!(
        "[{}] {} ({})",
        finding.scanner, finding.confidence, finding.severity
    );
    if let Some(ref file) = finding.file {
        if let Some(line) = finding.line {
            println!("  File: {}:{}", file.display(), line);
        } else {
            println!("  File: {}", file.display());
        }
    }
    println!("  {}", finding.message);
    if let Some(ref suggestion) = finding.suggestion {
        println!("  Suggestion: {suggestion}");
    }
    println!();
    println!("  [C]onfirmed  [F]alse positive  [A]ccept risk  [S]kip");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::types::{Finding, Severity};

    #[test]
    fn test_bucket_entry_confidence() {
        let entry = BucketEntry::new(3.0, 7.0);
        assert!((entry.confidence() - 0.3).abs() < f64::EPSILON);
    }

    #[test]
    fn test_bucket_entry_zero() {
        let entry = BucketEntry::new(0.0, 0.0);
        assert!((entry.confidence() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_bucket_key_with_extension() {
        let key = bucket_key("S7", Some(Path::new("src/controllers/user.controller.ts")));
        assert_eq!(key, "S7:*.ts");
    }

    #[test]
    fn test_bucket_key_no_file() {
        let key = bucket_key("S12", None);
        assert_eq!(key, "S12:*");
    }

    #[test]
    fn test_calibration_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = CalibrationStore {
            version: 1,
            buckets: HashMap::new(),
            global_priors: HashMap::new(),
        };
        store
            .buckets
            .insert("S7:*.ts".into(), BucketEntry::new(2.0, 18.0));

        save_calibration(dir.path(), &store).unwrap();
        let loaded = load_calibration(dir.path()).unwrap();
        assert_eq!(loaded.buckets.len(), 1);
        assert!((loaded.buckets["S7:*.ts"].confidence() - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_apply_calibration_reduces_confidence() {
        let mut store = CalibrationStore {
            version: 1,
            buckets: HashMap::new(),
            global_priors: HashMap::new(),
        };
        // Very low precision bucket: alpha=1, beta=20 -> ~4.8% confidence
        store
            .buckets
            .insert("S7:*.ts".into(), BucketEntry::new(1.0, 20.0));

        let results = vec![ScanResult {
            scanner: "S7".to_string(),
            findings: vec![Finding::new("S7", Severity::Warning, "suspicious pattern")
                .with_file("src/user.controller.ts")],
            score: 70,
            summary: "test".to_string(),
        }];

        let adjusted = apply_calibration(&results, &store);
        assert_eq!(adjusted[0].findings[0].confidence, Confidence::Suspect);
    }

    #[test]
    fn test_apply_calibration_skips_insufficient_samples() {
        let mut store = CalibrationStore {
            version: 1,
            buckets: HashMap::new(),
            global_priors: HashMap::new(),
        };
        // Only 3 samples: should not override
        store
            .buckets
            .insert("S7:*.ts".into(), BucketEntry::new(1.0, 2.0));

        let results = vec![ScanResult {
            scanner: "S7".to_string(),
            findings: vec![Finding::new("S7", Severity::Warning, "suspicious pattern")
                .with_file("src/user.controller.ts")],
            score: 70,
            summary: "test".to_string(),
        }];

        let adjusted = apply_calibration(&results, &store);
        // Confidence should remain Likely (default) — insufficient samples
        assert_eq!(adjusted[0].findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn test_builtin_priors_loaded_on_fresh_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = load_calibration(dir.path()).unwrap();
        assert!(!store.global_priors.is_empty());
        assert!(store.global_priors.contains_key("S7:*.ts"));
    }

    #[test]
    fn test_update_from_state() {
        let mut store = CalibrationStore {
            version: 1,
            buckets: HashMap::new(),
            global_priors: HashMap::new(),
        };
        let mut state = ProjectState {
            version: 1,
            findings: HashMap::new(),
            last_scan: None,
        };
        state.findings.insert(
            "test:key".into(),
            crate::state::FindingRecord {
                status: FindingStatus::FalsePositive,
                scanner: "S7".to_string(),
                file: Some(PathBuf::from("src/user.ts")),
                message_pattern: "test".to_string(),
                first_seen: "2024-01-01".to_string(),
                labeled_at: None,
                labeled_by: None,
                reason: None,
                fixed_at: None,
                tags: vec![],
            },
        );

        update_from_state(&mut store, &state);
        let entry = &store.buckets["S7:*.ts"];
        // Default 1+1, plus one FP -> beta should be 2
        assert!((entry.beta - 2.0).abs() < f64::EPSILON);
    }
}
