use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// FindingStatus — lifecycle of a finding across runs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    Open,
    Confirmed,
    FalsePositive,
    Accepted,
    Fixed,
}

impl Default for FindingStatus {
    fn default() -> Self {
        FindingStatus::Open
    }
}

// ---------------------------------------------------------------------------
// FindingRecord — persisted data for a single finding
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRecord {
    pub status: FindingStatus,
    pub scanner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    pub message_pattern: String,
    pub first_seen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labeled_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labeled_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fixed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// ProjectState — root state container
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectState {
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_scan: Option<String>,
    pub findings: HashMap<String, FindingRecord>,
}

impl Default for ProjectState {
    fn default() -> Self {
        Self {
            version: 1,
            last_scan: None,
            findings: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// File path helpers
// ---------------------------------------------------------------------------

/// Default state file location: `{project_root}/.sentinella/state.json`
pub fn state_file_path(root: &Path) -> PathBuf {
    root.join(".sentinella").join("state.json")
}

// ---------------------------------------------------------------------------
// Load / Save (immutable — always returns new values)
// ---------------------------------------------------------------------------

/// Load state from disk. Returns default state if file doesn't exist.
pub fn load_state(root: &Path) -> anyhow::Result<ProjectState> {
    let path = state_file_path(root);
    if !path.exists() {
        return Ok(ProjectState::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let state: ProjectState = serde_json::from_str(&content)?;
    Ok(state)
}

/// Save state to disk. Creates `.sentinella/` directory if needed.
pub fn save_state(root: &Path, state: &ProjectState) -> anyhow::Result<()> {
    let path = state_file_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, content)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Date helpers (no chrono dependency)
// ---------------------------------------------------------------------------

/// Get today's date as an ISO-8601 string (`YYYY-MM-DD`).
fn today_iso() -> String {
    let epoch_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    chrono_free_date(epoch_secs)
}

/// Convert a unix timestamp to `YYYY-MM-DD` without the chrono crate.
///
/// Algorithm from <http://howardhinnant.github.io/date_algorithms.html>.
fn chrono_free_date(epoch_secs: u64) -> String {
    let mut days = (epoch_secs / 86400) as i64;

    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = (days - era * 146_097) as u32; // day-of-era  [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // year-of-era
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day-of-year
    let mp = (5 * doy + 2) / 153; // month-proxy
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02}", y, m, d)
}

// ---------------------------------------------------------------------------
// Stable ID helper (temporary until Finding gets the method)
// ---------------------------------------------------------------------------

/// Compute a deterministic stable ID for a finding.
///
/// Format: `{scanner}-{hash:08x}` where hash is derived from scanner,
/// relative file path, and message.
fn compute_stable_id(finding: &crate::scanners::types::Finding, root: &Path) -> String {
    use std::hash::{Hash, Hasher};

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    finding.scanner.hash(&mut hasher);
    if let Some(ref file) = finding.file {
        let rel = file.strip_prefix(root).unwrap_or(file);
        rel.to_string_lossy().hash(&mut hasher);
    }
    finding.message.hash(&mut hasher);
    let hash = hasher.finish();
    format!("{}-{:08x}", finding.scanner, hash as u32)
}

// ---------------------------------------------------------------------------
// State synchronisation
// ---------------------------------------------------------------------------

/// Sync current scan findings against persisted state (immutable).
///
/// Returns a **new** `ProjectState` with updated lifecycle transitions:
/// - New findings get status `Open`.
/// - Previously `Fixed` findings that reappear become `Open` again.
/// - Previously seen findings that are no longer detected:
///   - `Confirmed` → `Fixed`
///   - `Open` → removed (code changed, never confirmed)
///   - `FalsePositive` / `Accepted` → kept as-is
pub fn sync_findings(
    state: &ProjectState,
    current_finding_ids: &[String],
    _root: &Path,
) -> ProjectState {
    let today = today_iso();
    let current_set: HashSet<&str> = current_finding_ids.iter().map(|s| s.as_str()).collect();

    let mut new_findings: HashMap<String, FindingRecord> = HashMap::new();

    // --- Process existing findings -------------------------------------------
    for (id, record) in &state.findings {
        if current_set.contains(id.as_str()) {
            // Still detected
            match record.status {
                FindingStatus::Fixed => {
                    // Reappeared after being fixed → reopen
                    let reopened = FindingRecord {
                        status: FindingStatus::Open,
                        fixed_at: None,
                        ..record.clone()
                    };
                    new_findings.insert(id.clone(), reopened);
                }
                _ => {
                    new_findings.insert(id.clone(), record.clone());
                }
            }
        } else {
            // No longer detected
            match record.status {
                FindingStatus::Confirmed => {
                    let fixed = FindingRecord {
                        status: FindingStatus::Fixed,
                        fixed_at: Some(today.clone()),
                        ..record.clone()
                    };
                    new_findings.insert(id.clone(), fixed);
                }
                FindingStatus::FalsePositive | FindingStatus::Accepted => {
                    new_findings.insert(id.clone(), record.clone());
                }
                FindingStatus::Open | FindingStatus::Fixed => {
                    // Open findings that disappear → drop (code changed)
                    // Already-fixed findings that stay gone → drop
                }
            }
        }
    }

    // --- Add truly new findings ---------------------------------------------
    for id in current_finding_ids {
        if !new_findings.contains_key(id) && !state.findings.contains_key(id) {
            let scanner = id.split('-').next().unwrap_or("unknown").to_string();
            new_findings.insert(
                id.clone(),
                FindingRecord {
                    status: FindingStatus::Open,
                    scanner,
                    file: None,
                    message_pattern: String::new(),
                    first_seen: today.clone(),
                    labeled_at: None,
                    labeled_by: None,
                    reason: None,
                    fixed_at: None,
                    tags: Vec::new(),
                },
            );
        }
    }

    ProjectState {
        version: state.version,
        last_scan: Some(today),
        findings: new_findings,
    }
}

/// Create a `FindingRecord` from a `Finding`, returning `(stable_id, record)`.
pub fn record_from_finding(
    finding: &crate::scanners::types::Finding,
    root: &Path,
) -> (String, FindingRecord) {
    let stable_id = compute_stable_id(finding, root);
    let record = FindingRecord {
        status: FindingStatus::Open,
        scanner: finding.scanner.clone(),
        file: finding.file.clone(),
        message_pattern: finding.message.clone(),
        first_seen: today_iso(),
        labeled_at: None,
        labeled_by: None,
        reason: None,
        fixed_at: None,
        tags: Vec::new(),
    };
    (stable_id, record)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_project_state_is_v1_empty() {
        let state = ProjectState::default();
        assert_eq!(state.version, 1);
        assert!(state.last_scan.is_none());
        assert!(state.findings.is_empty());
    }

    #[test]
    fn chrono_free_date_known_epoch() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(chrono_free_date(1_704_067_200), "2024-01-01");
    }

    #[test]
    fn chrono_free_date_unix_epoch() {
        assert_eq!(chrono_free_date(0), "1970-01-01");
    }

    #[test]
    fn sync_adds_new_findings() {
        let state = ProjectState::default();
        let ids = vec!["s01-aabbccdd".to_string()];
        let result = sync_findings(&state, &ids, Path::new("/tmp"));

        assert_eq!(result.findings.len(), 1);
        assert_eq!(
            result.findings["s01-aabbccdd"].status,
            FindingStatus::Open
        );
        assert!(result.last_scan.is_some());
    }

    #[test]
    fn sync_marks_confirmed_as_fixed_when_gone() {
        let mut state = ProjectState::default();
        state.findings.insert(
            "s01-11111111".to_string(),
            FindingRecord {
                status: FindingStatus::Confirmed,
                scanner: "s01".to_string(),
                file: None,
                message_pattern: "test".to_string(),
                first_seen: "2026-01-01".to_string(),
                labeled_at: None,
                labeled_by: None,
                reason: None,
                fixed_at: None,
                tags: Vec::new(),
            },
        );

        // Finding no longer present in current scan
        let result = sync_findings(&state, &[], Path::new("/tmp"));

        assert_eq!(
            result.findings["s01-11111111"].status,
            FindingStatus::Fixed
        );
        assert!(result.findings["s01-11111111"].fixed_at.is_some());
    }

    #[test]
    fn sync_drops_open_findings_that_disappear() {
        let mut state = ProjectState::default();
        state.findings.insert(
            "s01-22222222".to_string(),
            FindingRecord {
                status: FindingStatus::Open,
                scanner: "s01".to_string(),
                file: None,
                message_pattern: "gone".to_string(),
                first_seen: "2026-01-01".to_string(),
                labeled_at: None,
                labeled_by: None,
                reason: None,
                fixed_at: None,
                tags: Vec::new(),
            },
        );

        let result = sync_findings(&state, &[], Path::new("/tmp"));
        assert!(result.findings.is_empty());
    }

    #[test]
    fn sync_keeps_false_positive_even_when_gone() {
        let mut state = ProjectState::default();
        state.findings.insert(
            "s01-33333333".to_string(),
            FindingRecord {
                status: FindingStatus::FalsePositive,
                scanner: "s01".to_string(),
                file: None,
                message_pattern: "fp".to_string(),
                first_seen: "2026-01-01".to_string(),
                labeled_at: Some("2026-02-01".to_string()),
                labeled_by: Some("user".to_string()),
                reason: Some("not relevant".to_string()),
                fixed_at: None,
                tags: Vec::new(),
            },
        );

        let result = sync_findings(&state, &[], Path::new("/tmp"));
        assert_eq!(
            result.findings["s01-33333333"].status,
            FindingStatus::FalsePositive
        );
    }

    #[test]
    fn sync_reopens_fixed_findings_that_reappear() {
        let mut state = ProjectState::default();
        state.findings.insert(
            "s01-44444444".to_string(),
            FindingRecord {
                status: FindingStatus::Fixed,
                scanner: "s01".to_string(),
                file: None,
                message_pattern: "was fixed".to_string(),
                first_seen: "2026-01-01".to_string(),
                labeled_at: None,
                labeled_by: None,
                reason: None,
                fixed_at: Some("2026-03-01".to_string()),
                tags: Vec::new(),
            },
        );

        let ids = vec!["s01-44444444".to_string()];
        let result = sync_findings(&state, &ids, Path::new("/tmp"));

        assert_eq!(
            result.findings["s01-44444444"].status,
            FindingStatus::Open
        );
        assert!(result.findings["s01-44444444"].fixed_at.is_none());
    }

    #[test]
    fn round_trip_json_serialization() {
        let mut state = ProjectState::default();
        state.last_scan = Some("2026-04-07".to_string());
        state.findings.insert(
            "s01-deadbeef".to_string(),
            FindingRecord {
                status: FindingStatus::Accepted,
                scanner: "s01".to_string(),
                file: Some(PathBuf::from("src/main.rs")),
                message_pattern: "test message".to_string(),
                first_seen: "2026-04-01".to_string(),
                labeled_at: Some("2026-04-05".to_string()),
                labeled_by: Some("kd".to_string()),
                reason: Some("risk accepted".to_string()),
                fixed_at: None,
                tags: vec!["low-priority".to_string()],
            },
        );

        let json = serde_json::to_string_pretty(&state).unwrap();
        let restored: ProjectState = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.version, 1);
        assert_eq!(restored.last_scan, Some("2026-04-07".to_string()));
        assert_eq!(
            restored.findings["s01-deadbeef"].status,
            FindingStatus::Accepted
        );
        assert_eq!(
            restored.findings["s01-deadbeef"].reason,
            Some("risk accepted".to_string())
        );
    }

    #[test]
    fn load_returns_default_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let state = load_state(dir.path()).unwrap();
        assert_eq!(state.version, 1);
        assert!(state.findings.is_empty());
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = ProjectState::default();
        state.last_scan = Some("2026-04-07".to_string());
        state.findings.insert(
            "s01-cafe0000".to_string(),
            FindingRecord {
                status: FindingStatus::Open,
                scanner: "s01".to_string(),
                file: None,
                message_pattern: "round trip".to_string(),
                first_seen: "2026-04-07".to_string(),
                labeled_at: None,
                labeled_by: None,
                reason: None,
                fixed_at: None,
                tags: Vec::new(),
            },
        );

        save_state(dir.path(), &state).unwrap();
        let loaded = load_state(dir.path()).unwrap();

        assert_eq!(loaded.version, state.version);
        assert_eq!(loaded.last_scan, state.last_scan);
        assert!(loaded.findings.contains_key("s01-cafe0000"));
    }

    #[test]
    fn compute_stable_id_deterministic() {
        let finding = crate::scanners::types::Finding::new(
            "s01",
            crate::scanners::types::Severity::Warning,
            "test message",
        )
        .with_file("/project/src/main.rs");

        let root = Path::new("/project");
        let id1 = compute_stable_id(&finding, root);
        let id2 = compute_stable_id(&finding, root);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("s01-"));
    }

    #[test]
    fn record_from_finding_populates_fields() {
        let finding = crate::scanners::types::Finding::new(
            "s05",
            crate::scanners::types::Severity::Critical,
            "hardcoded secret",
        )
        .with_file("/project/config.rs");

        let root = Path::new("/project");
        let (id, record) = record_from_finding(&finding, root);

        assert!(id.starts_with("s05-"));
        assert_eq!(record.status, FindingStatus::Open);
        assert_eq!(record.scanner, "s05");
        assert_eq!(record.message_pattern, "hardcoded secret");
        assert_eq!(record.file, Some(PathBuf::from("/project/config.rs")));
        assert!(record.labeled_at.is_none());
    }
}
