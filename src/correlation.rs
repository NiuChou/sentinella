//! Cross-Scanner Correlation Engine (P7)
//!
//! Groups findings from multiple scanners that flag the same file/area,
//! boosting confidence when scanners corroborate each other.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::scanners::types::{Confidence, Finding, ScanResult};

/// A cluster of findings from multiple scanners in the same file region.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CorrelationGroup {
    pub file: PathBuf,
    pub line_range: (usize, usize),
    /// Scanner IDs that flagged this area.
    pub scanners: Vec<String>,
    /// References to original findings as (scanner_id, finding_index).
    pub findings: Vec<(String, usize)>,
    /// 1.0 = single scanner, higher = more corroboration.
    pub corroboration_score: f64,
}

/// Maximum line distance for two findings to be clustered together.
const PROXIMITY_THRESHOLD: usize = 10;

// -------------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------------

/// Group findings by file path, then cluster within ±PROXIMITY_THRESHOLD lines.
pub fn correlate_findings(results: &[ScanResult]) -> Vec<CorrelationGroup> {
    let indexed = collect_file_findings(results);
    let mut groups: Vec<CorrelationGroup> = Vec::new();

    for (file, entries) in &indexed {
        let clusters = cluster_by_proximity(entries);
        for cluster in clusters {
            groups.push(build_group(file.clone(), &cluster));
        }
    }

    groups.sort_by(|a, b| {
        b.corroboration_score
            .partial_cmp(&a.corroboration_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    groups
}

/// Boost confidence for findings corroborated by 2+ scanners.
/// Returns new `Vec<ScanResult>` — never mutates input.
pub fn apply_correlation(results: &[ScanResult], groups: &[CorrelationGroup]) -> Vec<ScanResult> {
    let boost_map = build_boost_map(groups);

    results
        .iter()
        .map(|sr| {
            let new_findings: Vec<Finding> = sr
                .findings
                .iter()
                .enumerate()
                .map(|(idx, f)| {
                    let key = (sr.scanner.clone(), idx);
                    match boost_map.get(&key) {
                        Some(&boost) if boost >= 2.0 => boost_finding(f, boost),
                        _ => f.clone(),
                    }
                })
                .collect();
            ScanResult {
                scanner: sr.scanner.clone(),
                findings: new_findings,
                score: sr.score,
                summary: sr.summary.clone(),
            }
        })
        .collect()
}

/// Produce a human-readable summary of correlated hotspots.
pub fn format_correlation_summary(groups: &[CorrelationGroup]) -> String {
    let multi: Vec<&CorrelationGroup> = groups.iter().filter(|g| g.scanners.len() >= 2).collect();

    if multi.is_empty() {
        return "No cross-scanner correlations found.".to_string();
    }

    let mut lines = vec![format!(
        "Cross-scanner correlations: {} hotspot(s)\n",
        multi.len()
    )];

    for g in &multi {
        lines.push(format!(
            "  {} (lines {}-{}): {} scanner(s) [{}]  score={:.1}",
            g.file.display(),
            g.line_range.0,
            g.line_range.1,
            g.scanners.len(),
            g.scanners.join(", "),
            g.corroboration_score,
        ));
    }

    lines.join("\n")
}

// -------------------------------------------------------------------------
// Internal helpers (each < 50 lines)
// -------------------------------------------------------------------------

/// An intermediate record tying a finding back to its scanner + index.
#[derive(Debug, Clone)]
struct FileFinding {
    scanner_id: String,
    finding_index: usize,
    line: usize,
}

/// Collect all findings that have both a file and a line into a per-file map.
fn collect_file_findings(results: &[ScanResult]) -> HashMap<PathBuf, Vec<FileFinding>> {
    let mut map: HashMap<PathBuf, Vec<FileFinding>> = HashMap::new();

    for sr in results {
        for (idx, f) in sr.findings.iter().enumerate() {
            if let (Some(file), Some(line)) = (&f.file, f.line) {
                map.entry(file.clone()).or_default().push(FileFinding {
                    scanner_id: sr.scanner.clone(),
                    finding_index: idx,
                    line,
                });
            }
        }
    }

    map
}

/// Cluster findings within ±PROXIMITY_THRESHOLD lines using greedy merge.
fn cluster_by_proximity(entries: &[FileFinding]) -> Vec<Vec<&FileFinding>> {
    let mut sorted: Vec<&FileFinding> = entries.iter().collect();
    sorted.sort_by_key(|e| e.line);

    let mut clusters: Vec<Vec<&FileFinding>> = Vec::new();
    for entry in sorted {
        let merged = clusters.iter_mut().find(|c| {
            c.iter()
                .any(|e| line_distance(e.line, entry.line) <= PROXIMITY_THRESHOLD)
        });
        match merged {
            Some(cluster) => cluster.push(entry),
            None => clusters.push(vec![entry]),
        }
    }

    clusters
}

fn line_distance(a: usize, b: usize) -> usize {
    a.abs_diff(b)
}

/// Build a `CorrelationGroup` from a cluster of file-findings.
fn build_group(file: PathBuf, cluster: &[&FileFinding]) -> CorrelationGroup {
    let min_line = cluster.iter().map(|e| e.line).min().unwrap_or(0);
    let max_line = cluster.iter().map(|e| e.line).max().unwrap_or(0);

    let findings: Vec<(String, usize)> = cluster
        .iter()
        .map(|e| (e.scanner_id.clone(), e.finding_index))
        .collect();

    let mut scanners: Vec<String> = cluster.iter().map(|e| e.scanner_id.clone()).collect();
    scanners.sort();
    scanners.dedup();

    let corroboration_score = scanners.len() as f64;

    CorrelationGroup {
        file,
        line_range: (min_line, max_line),
        scanners,
        findings,
        corroboration_score,
    }
}

/// Build a lookup from (scanner_id, finding_index) -> corroboration_score
/// for groups with 2+ distinct scanners.
fn build_boost_map(groups: &[CorrelationGroup]) -> HashMap<(String, usize), f64> {
    let mut map: HashMap<(String, usize), f64> = HashMap::new();

    for g in groups {
        if g.scanners.len() < 2 {
            continue;
        }
        for (scanner_id, idx) in &g.findings {
            let key = (scanner_id.clone(), *idx);
            let existing = map.get(&key).copied().unwrap_or(0.0);
            if g.corroboration_score > existing {
                map.insert(key, g.corroboration_score);
            }
        }
    }

    map
}

/// Return a new finding with boosted confidence.
fn boost_finding(finding: &Finding, corroboration: f64) -> Finding {
    let boosted = match finding.confidence {
        Confidence::Suspect if corroboration >= 3.0 => Confidence::Confirmed,
        Confidence::Suspect => Confidence::Likely,
        Confidence::Likely => Confidence::Confirmed,
        Confidence::Confirmed => Confidence::Confirmed,
    };
    Finding {
        confidence: boosted,
        ..finding.clone()
    }
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::types::Severity;

    fn make_finding(scanner: &str, file: &str, line: usize, conf: Confidence) -> Finding {
        Finding::new(
            scanner,
            Severity::Warning,
            format!("issue at {file}:{line}"),
        )
        .with_confidence(conf)
        .with_file(PathBuf::from(file))
        .with_line(line)
    }

    fn make_result(scanner: &str, findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            scanner: scanner.to_string(),
            findings,
            score: 80,
            summary: format!("{scanner} result"),
        }
    }

    #[test]
    fn single_scanner_no_boost() {
        let results = vec![make_result(
            "S1",
            vec![make_finding("S1", "src/main.rs", 10, Confidence::Suspect)],
        )];
        let groups = correlate_findings(&results);
        let applied = apply_correlation(&results, &groups);

        assert_eq!(applied[0].findings[0].confidence, Confidence::Suspect);
    }

    #[test]
    fn two_scanners_same_line_boost() {
        let results = vec![
            make_result(
                "S1",
                vec![make_finding("S1", "src/auth.rs", 50, Confidence::Suspect)],
            ),
            make_result(
                "S2",
                vec![make_finding("S2", "src/auth.rs", 52, Confidence::Suspect)],
            ),
        ];
        let groups = correlate_findings(&results);
        let applied = apply_correlation(&results, &groups);

        assert_eq!(applied[0].findings[0].confidence, Confidence::Likely);
        assert_eq!(applied[1].findings[0].confidence, Confidence::Likely);
    }

    #[test]
    fn two_scanners_far_apart_no_grouping() {
        let results = vec![
            make_result(
                "S1",
                vec![make_finding("S1", "src/auth.rs", 10, Confidence::Suspect)],
            ),
            make_result(
                "S2",
                vec![make_finding("S2", "src/auth.rs", 100, Confidence::Suspect)],
            ),
        ];
        let groups = correlate_findings(&results);
        let applied = apply_correlation(&results, &groups);

        // No boost — lines too far apart
        assert_eq!(applied[0].findings[0].confidence, Confidence::Suspect);
        assert_eq!(applied[1].findings[0].confidence, Confidence::Suspect);
    }

    #[test]
    fn three_scanners_max_boost_to_confirmed() {
        let results = vec![
            make_result(
                "S1",
                vec![make_finding("S1", "src/db.rs", 20, Confidence::Suspect)],
            ),
            make_result(
                "S2",
                vec![make_finding("S2", "src/db.rs", 22, Confidence::Suspect)],
            ),
            make_result(
                "S3",
                vec![make_finding("S3", "src/db.rs", 25, Confidence::Suspect)],
            ),
        ];
        let groups = correlate_findings(&results);
        let applied = apply_correlation(&results, &groups);

        // 3 scanners on Suspect -> Confirmed
        assert_eq!(applied[0].findings[0].confidence, Confidence::Confirmed);
        assert_eq!(applied[1].findings[0].confidence, Confidence::Confirmed);
        assert_eq!(applied[2].findings[0].confidence, Confidence::Confirmed);
    }

    #[test]
    fn empty_results() {
        let results: Vec<ScanResult> = vec![];
        let groups = correlate_findings(&results);
        let applied = apply_correlation(&results, &groups);

        assert!(groups.is_empty());
        assert!(applied.is_empty());
    }

    #[test]
    fn different_files_no_correlation() {
        let results = vec![
            make_result(
                "S1",
                vec![make_finding("S1", "src/a.rs", 10, Confidence::Suspect)],
            ),
            make_result(
                "S2",
                vec![make_finding("S2", "src/b.rs", 10, Confidence::Suspect)],
            ),
        ];
        let groups = correlate_findings(&results);
        let applied = apply_correlation(&results, &groups);

        assert_eq!(applied[0].findings[0].confidence, Confidence::Suspect);
        assert_eq!(applied[1].findings[0].confidence, Confidence::Suspect);
    }

    #[test]
    fn likely_boosted_to_confirmed() {
        let results = vec![
            make_result(
                "S1",
                vec![make_finding("S1", "src/api.rs", 30, Confidence::Likely)],
            ),
            make_result(
                "S2",
                vec![make_finding("S2", "src/api.rs", 32, Confidence::Likely)],
            ),
        ];
        let groups = correlate_findings(&results);
        let applied = apply_correlation(&results, &groups);

        assert_eq!(applied[0].findings[0].confidence, Confidence::Confirmed);
        assert_eq!(applied[1].findings[0].confidence, Confidence::Confirmed);
    }

    #[test]
    fn confirmed_stays_confirmed() {
        let results = vec![
            make_result(
                "S1",
                vec![make_finding("S1", "src/x.rs", 5, Confidence::Confirmed)],
            ),
            make_result(
                "S2",
                vec![make_finding("S2", "src/x.rs", 7, Confidence::Confirmed)],
            ),
        ];
        let groups = correlate_findings(&results);
        let applied = apply_correlation(&results, &groups);

        assert_eq!(applied[0].findings[0].confidence, Confidence::Confirmed);
    }

    #[test]
    fn format_summary_no_correlations() {
        let groups: Vec<CorrelationGroup> = vec![];
        let summary = format_correlation_summary(&groups);
        assert!(summary.contains("No cross-scanner correlations"));
    }

    #[test]
    fn format_summary_with_hotspot() {
        let groups = vec![CorrelationGroup {
            file: PathBuf::from("src/auth.rs"),
            line_range: (50, 55),
            scanners: vec!["S1".to_string(), "S2".to_string()],
            findings: vec![("S1".to_string(), 0), ("S2".to_string(), 0)],
            corroboration_score: 2.0,
        }];
        let summary = format_correlation_summary(&groups);
        assert!(summary.contains("1 hotspot"));
        assert!(summary.contains("src/auth.rs"));
        assert!(summary.contains("S1, S2"));
    }

    #[test]
    fn findings_without_file_or_line_ignored() {
        let mut f = Finding::new("S1", Severity::Warning, "no location");
        f.confidence = Confidence::Suspect;
        let results = vec![make_result("S1", vec![f])];
        let groups = correlate_findings(&results);

        assert!(groups.is_empty());
    }
}
