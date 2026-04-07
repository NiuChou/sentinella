//! Persistent project state: tracks finding statuses across scans.
//!
//! State is stored in `.sentinella/state.json` alongside calibration data.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Finding status & record
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
        Self::Open
    }
}

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
    #[serde(default)]
    pub tags: Vec<String>,
}

// ---------------------------------------------------------------------------
// Project state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectState {
    pub version: u32,
    pub findings: HashMap<String, FindingRecord>,
}

impl Default for ProjectState {
    fn default() -> Self {
        Self {
            version: 1,
            findings: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// File path helpers
// ---------------------------------------------------------------------------

pub fn state_file_path(root: &Path) -> PathBuf {
    root.join(".sentinella").join("state.json")
}

// ---------------------------------------------------------------------------
// Load / Save (immutable API: returns new values, never mutates in place)
// ---------------------------------------------------------------------------

pub fn load_state(root: &Path) -> anyhow::Result<ProjectState> {
    let path = state_file_path(root);
    if !path.exists() {
        return Ok(ProjectState::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let state: ProjectState = serde_json::from_str(&content)?;
    Ok(state)
}

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
// Date helper (no chrono dependency)
// ---------------------------------------------------------------------------

/// Convert Unix epoch seconds to an ISO-8601 date string (UTC, date only).
/// Avoids pulling in the `chrono` crate for a single use-case.
pub fn chrono_free_date(epoch_secs: u64) -> String {
    // Days since Unix epoch
    let days = epoch_secs / 86400;
    // Compute year/month/day from days using a civil calendar algorithm
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Civil calendar conversion (algorithm from Howard Hinnant).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Return today's date as an ISO-8601 string.
pub fn today_iso() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    chrono_free_date(secs)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrono_free_date_epoch() {
        assert_eq!(chrono_free_date(0), "1970-01-01");
    }

    #[test]
    fn test_chrono_free_date_known() {
        // 2024-01-15 = 1705276800 epoch seconds
        assert_eq!(chrono_free_date(1_705_276_800), "2024-01-15");
    }

    #[test]
    fn test_default_state() {
        let state = ProjectState::default();
        assert_eq!(state.version, 1);
        assert!(state.findings.is_empty());
    }

    #[test]
    fn test_state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = ProjectState::default();
        state.findings.insert(
            "test:key".to_string(),
            FindingRecord {
                status: FindingStatus::Confirmed,
                scanner: "S1".to_string(),
                file: Some(PathBuf::from("src/main.rs")),
                message_pattern: "test finding".to_string(),
                first_seen: "2024-01-01".to_string(),
                labeled_at: None,
                labeled_by: None,
                reason: None,
                fixed_at: None,
                tags: vec![],
            },
        );
        save_state(dir.path(), &state).unwrap();
        let loaded = load_state(dir.path()).unwrap();
        assert_eq!(loaded.findings.len(), 1);
        assert_eq!(loaded.findings["test:key"].status, FindingStatus::Confirmed);
    }
}
