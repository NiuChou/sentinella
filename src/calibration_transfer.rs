//! Cross-project calibration import/export.
//!
//! Enables teams to share Bayesian calibration data between projects,
//! so false-positive-rate knowledge transfers without re-triaging.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::calibration::{BucketEntry, CalibrationStore};

// ---------------------------------------------------------------------------
// Exported data model
// ---------------------------------------------------------------------------

/// Portable representation of a project's calibration data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedCalibration {
    pub version: u32,
    pub exported_from: String,
    pub exported_at: String,
    pub buckets: HashMap<String, ExportedBucket>,
}

/// A single bucket's calibration snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedBucket {
    pub alpha: f64,
    pub beta: f64,
    pub total_samples: u64,
    pub false_positive_rate: f64,
}

// ---------------------------------------------------------------------------
// Minimum samples threshold for export
// ---------------------------------------------------------------------------

const MIN_EXPORT_SAMPLES: f64 = 5.0;

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Export all buckets that have sufficient feedback samples.
///
/// Buckets with fewer than 5 total samples are excluded because
/// their posteriors are still dominated by the prior.
pub fn export_calibration(store: &CalibrationStore, project_name: &str) -> ExportedCalibration {
    let buckets = store
        .buckets
        .iter()
        .filter(|(_, entry)| entry.samples() >= MIN_EXPORT_SAMPLES)
        .map(|(key, entry)| {
            let exported = ExportedBucket {
                alpha: entry.alpha,
                beta: entry.beta,
                total_samples: entry.samples() as u64,
                false_positive_rate: compute_fp_rate(entry),
            };
            (key.clone(), exported)
        })
        .collect();

    ExportedCalibration {
        version: 1,
        exported_from: project_name.to_string(),
        exported_at: crate::state::today_iso(),
        buckets,
    }
}

/// FP rate = beta / (alpha + beta). Returns 0.0 when no samples exist.
fn compute_fp_rate(entry: &BucketEntry) -> f64 {
    let total = entry.alpha + entry.beta;
    if total == 0.0 {
        0.0
    } else {
        entry.beta / total
    }
}

// ---------------------------------------------------------------------------
// Import (immutable merge)
// ---------------------------------------------------------------------------

/// Merge imported calibration into an existing store, returning a new store.
///
/// `weight` (0.0–1.0) controls how much the imported data influences the
/// result. Imported alpha/beta values are scaled by `weight` before being
/// added to the existing counters.
pub fn import_calibration(
    existing: &CalibrationStore,
    imported: &ExportedCalibration,
    weight: f64,
) -> CalibrationStore {
    let clamped_weight = weight.clamp(0.0, 1.0);

    let mut merged_buckets = existing.buckets.clone();

    for (key, imp_bucket) in &imported.buckets {
        let entry = merged_buckets.entry(key.clone()).or_insert_with(|| {
            // New bucket: start from a neutral prior
            BucketEntry::new(1.0, 1.0)
        });

        let updated = BucketEntry::new(
            entry.alpha + imp_bucket.alpha * clamped_weight,
            entry.beta + imp_bucket.beta * clamped_weight,
        );

        merged_buckets.insert(key.clone(), updated);
    }

    CalibrationStore {
        version: existing.version,
        buckets: merged_buckets,
        global_priors: existing.global_priors.clone(),
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Write an exported calibration to a JSON file.
pub fn save_export(path: &Path, export: &ExportedCalibration) -> Result<(), String> {
    let content =
        serde_json::to_string_pretty(export).map_err(|e| format!("serialize error: {e}"))?;
    std::fs::write(path, content).map_err(|e| format!("write error: {e}"))
}

/// Read an exported calibration from a JSON file.
pub fn load_export(path: &Path) -> Result<ExportedCalibration, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("parse error: {e}"))
}

// ---------------------------------------------------------------------------
// Display helpers
// ---------------------------------------------------------------------------

/// Format calibration store stats for terminal display.
pub fn format_calibration_stats(store: &CalibrationStore) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "Calibration store v{} — {} bucket(s)",
        store.version,
        store.buckets.len()
    ));

    let mut sorted_keys: Vec<_> = store.buckets.keys().collect();
    sorted_keys.sort();

    for key in sorted_keys {
        let entry = &store.buckets[key];
        let fp_rate = compute_fp_rate(entry);
        lines.push(format!(
            "  {key:30}  alpha={:6.1}  beta={:6.1}  samples={:4}  FP={:.1}%",
            entry.alpha,
            entry.beta,
            entry.samples() as u64,
            fp_rate * 100.0,
        ));
    }

    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_store() -> CalibrationStore {
        let mut buckets = HashMap::new();
        // Enough samples to export
        buckets.insert("S7:*.ts".into(), BucketEntry::new(2.0, 18.0));
        buckets.insert("S12:*.sql".into(), BucketEntry::new(5.0, 10.0));
        // Too few samples — should be filtered on export
        buckets.insert("S1:*.tsx".into(), BucketEntry::new(1.0, 2.0));

        CalibrationStore {
            version: 1,
            buckets,
            global_priors: HashMap::new(),
        }
    }

    #[test]
    fn export_filters_low_sample_buckets() {
        let store = sample_store();
        let exported = export_calibration(&store, "test-project");

        assert_eq!(exported.buckets.len(), 2);
        assert!(exported.buckets.contains_key("S7:*.ts"));
        assert!(exported.buckets.contains_key("S12:*.sql"));
        assert!(!exported.buckets.contains_key("S1:*.tsx"));
    }

    #[test]
    fn export_fp_rate_computation() {
        let store = sample_store();
        let exported = export_calibration(&store, "test-project");

        let s7 = &exported.buckets["S7:*.ts"];
        // beta / (alpha + beta) = 18 / 20 = 0.9
        assert!((s7.false_positive_rate - 0.9).abs() < f64::EPSILON);
        assert_eq!(s7.total_samples, 20);
    }

    #[test]
    fn import_weight_full_merge() {
        let existing = CalibrationStore {
            version: 1,
            buckets: {
                let mut m = HashMap::new();
                m.insert("S7:*.ts".into(), BucketEntry::new(2.0, 8.0));
                m
            },
            global_priors: HashMap::new(),
        };

        let imported = ExportedCalibration {
            version: 1,
            exported_from: "other".into(),
            exported_at: "2025-01-01".into(),
            buckets: {
                let mut m = HashMap::new();
                m.insert(
                    "S7:*.ts".into(),
                    ExportedBucket {
                        alpha: 4.0,
                        beta: 16.0,
                        total_samples: 20,
                        false_positive_rate: 0.8,
                    },
                );
                m
            },
        };

        let merged = import_calibration(&existing, &imported, 1.0);
        let entry = &merged.buckets["S7:*.ts"];
        assert!((entry.alpha - 6.0).abs() < f64::EPSILON);
        assert!((entry.beta - 24.0).abs() < f64::EPSILON);
    }

    #[test]
    fn import_weight_half_merge() {
        let existing = CalibrationStore {
            version: 1,
            buckets: {
                let mut m = HashMap::new();
                m.insert("S7:*.ts".into(), BucketEntry::new(2.0, 8.0));
                m
            },
            global_priors: HashMap::new(),
        };

        let imported = ExportedCalibration {
            version: 1,
            exported_from: "other".into(),
            exported_at: "2025-01-01".into(),
            buckets: {
                let mut m = HashMap::new();
                m.insert(
                    "S7:*.ts".into(),
                    ExportedBucket {
                        alpha: 4.0,
                        beta: 16.0,
                        total_samples: 20,
                        false_positive_rate: 0.8,
                    },
                );
                m
            },
        };

        let merged = import_calibration(&existing, &imported, 0.5);
        let entry = &merged.buckets["S7:*.ts"];
        // 2.0 + 4.0 * 0.5 = 4.0
        assert!((entry.alpha - 4.0).abs() < f64::EPSILON);
        // 8.0 + 16.0 * 0.5 = 16.0
        assert!((entry.beta - 16.0).abs() < f64::EPSILON);
    }

    #[test]
    fn import_adds_new_buckets() {
        let existing = CalibrationStore {
            version: 1,
            buckets: HashMap::new(),
            global_priors: HashMap::new(),
        };

        let imported = ExportedCalibration {
            version: 1,
            exported_from: "other".into(),
            exported_at: "2025-01-01".into(),
            buckets: {
                let mut m = HashMap::new();
                m.insert(
                    "S12:*.sql".into(),
                    ExportedBucket {
                        alpha: 3.0,
                        beta: 12.0,
                        total_samples: 15,
                        false_positive_rate: 0.8,
                    },
                );
                m
            },
        };

        let merged = import_calibration(&existing, &imported, 1.0);
        assert!(merged.buckets.contains_key("S12:*.sql"));
        let entry = &merged.buckets["S12:*.sql"];
        // 1.0 (neutral prior) + 3.0 * 1.0 = 4.0
        assert!((entry.alpha - 4.0).abs() < f64::EPSILON);
        // 1.0 (neutral prior) + 12.0 * 1.0 = 13.0
        assert!((entry.beta - 13.0).abs() < f64::EPSILON);
    }

    #[test]
    fn roundtrip_export_import_preserves_data() {
        let store = sample_store();
        let exported = export_calibration(&store, "roundtrip-test");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("calibration_export.json");

        save_export(&path, &exported).unwrap();
        let loaded = load_export(&path).unwrap();

        assert_eq!(loaded.version, exported.version);
        assert_eq!(loaded.exported_from, "roundtrip-test");
        assert_eq!(loaded.buckets.len(), exported.buckets.len());

        for (key, original) in &exported.buckets {
            let reloaded = &loaded.buckets[key];
            assert!((original.alpha - reloaded.alpha).abs() < f64::EPSILON);
            assert!((original.beta - reloaded.beta).abs() < f64::EPSILON);
            assert_eq!(original.total_samples, reloaded.total_samples);
        }
    }

    #[test]
    fn empty_store_export() {
        let store = CalibrationStore {
            version: 1,
            buckets: HashMap::new(),
            global_priors: HashMap::new(),
        };
        let exported = export_calibration(&store, "empty");
        assert!(exported.buckets.is_empty());
    }

    #[test]
    fn export_metadata_populated() {
        let store = sample_store();
        let exported = export_calibration(&store, "my-project");

        assert_eq!(exported.version, 1);
        assert_eq!(exported.exported_from, "my-project");
        assert!(!exported.exported_at.is_empty());
    }

    #[test]
    fn import_weight_clamped() {
        let existing = CalibrationStore {
            version: 1,
            buckets: {
                let mut m = HashMap::new();
                m.insert("S7:*.ts".into(), BucketEntry::new(2.0, 8.0));
                m
            },
            global_priors: HashMap::new(),
        };

        let imported = ExportedCalibration {
            version: 1,
            exported_from: "other".into(),
            exported_at: "2025-01-01".into(),
            buckets: {
                let mut m = HashMap::new();
                m.insert(
                    "S7:*.ts".into(),
                    ExportedBucket {
                        alpha: 10.0,
                        beta: 10.0,
                        total_samples: 20,
                        false_positive_rate: 0.5,
                    },
                );
                m
            },
        };

        // Weight > 1.0 should be clamped to 1.0
        let merged = import_calibration(&existing, &imported, 5.0);
        let entry = &merged.buckets["S7:*.ts"];
        assert!((entry.alpha - 12.0).abs() < f64::EPSILON);
        assert!((entry.beta - 18.0).abs() < f64::EPSILON);
    }
}
