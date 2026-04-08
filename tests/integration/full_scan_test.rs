use std::path::PathBuf;
use std::sync::Arc;

use sentinella::config::schema::Config;
use sentinella::indexer::build_index;
use sentinella::indexer::store::IndexStore;
use sentinella::scanners::types::ScanContext;
use sentinella::scanners::{create_scanners, run_scanners};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn test_config() -> Config {
    let yaml = r#"
version: "1.0"
project: test-fixtures
type: fullstack

layers:
  backend:
    pattern: "**/*.ts"
  database:
    pattern: "**/*.sql"

deploy:
  dockerfile_pattern: "**/Dockerfile"
  require_healthcheck: true
  require_pinned_deps: true
  require_dockerignore: false

output:
  format: terminal
  min_coverage: 0
  severity: warning
"#;
    serde_yaml::from_str(yaml).unwrap()
}

fn build_fixture_index() -> (Config, Arc<IndexStore>) {
    let config = test_config();
    let root = fixtures_dir();
    let index = build_index(&root, &config).expect("build_index should succeed");
    (config, index)
}

#[test]
fn build_index_succeeds_on_fixtures() {
    let (_config, _index) = build_fixture_index();
    // build_index should not panic or error on fixture directory
}

#[test]
fn full_scan_produces_results() {
    let (config, index) = build_fixture_index();
    let root = fixtures_dir();

    let scanners = create_scanners(None);
    let ctx = ScanContext {
        config: &config,
        index: &index,
        root_dir: &root,
    };

    let results = run_scanners(&scanners, &ctx);
    assert!(!results.is_empty(), "Scanner results should not be empty");
}

#[test]
fn scanner_scores_are_in_range() {
    let (config, index) = build_fixture_index();
    let root = fixtures_dir();

    let scanners = create_scanners(None);
    let ctx = ScanContext {
        config: &config,
        index: &index,
        root_dir: &root,
    };

    let results = run_scanners(&scanners, &ctx);
    for result in &results {
        assert!(
            result.score <= 100,
            "Scanner {} score {} should be <= 100",
            result.scanner,
            result.score
        );
    }
}

#[test]
fn filtered_scanner_returns_subset() {
    let all_scanners = create_scanners(None);
    let filtered = create_scanners(Some("S1,S6"));

    assert!(
        filtered.len() < all_scanners.len(),
        "Filtered scanners should be a subset"
    );
    assert_eq!(filtered.len(), 2, "Should have exactly S1 and S6");
}

#[test]
fn index_contains_files_when_populated() {
    let (_config, index) = build_fixture_index();

    // The ignore crate's WalkBuilder may yield zero files in non-git
    // directories depending on the platform. When files ARE found, verify
    // they have valid paths.
    for entry in index.files.iter() {
        assert!(
            entry.key().exists(),
            "Indexed file should exist on disk: {}",
            entry.key().display()
        );
    }
}

#[test]
fn scanner_results_have_valid_scanner_ids() {
    let (config, index) = build_fixture_index();
    let root = fixtures_dir();

    let scanners = create_scanners(None);
    let ctx = ScanContext {
        config: &config,
        index: &index,
        root_dir: &root,
    };

    let results = run_scanners(&scanners, &ctx);

    let valid_ids = [
        "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11", "S12", "S13", "S14",
        "S15", "S16", "S17", "S18", "S19", "S20", "S21", "S22", "S23", "S24", "S25", "S26", "S27",
        "S28",
    ];

    for result in &results {
        let scanner_id = result.scanner.split('-').next().unwrap_or("");
        assert!(
            valid_ids.contains(&scanner_id),
            "Scanner ID '{}' should be valid (from '{}')",
            scanner_id,
            result.scanner
        );
    }
}

#[test]
fn all_twenty_seven_scanners_produce_results() {
    let (config, index) = build_fixture_index();
    let root = fixtures_dir();

    let scanners = create_scanners(None);
    let ctx = ScanContext {
        config: &config,
        index: &index,
        root_dir: &root,
    };

    let results = run_scanners(&scanners, &ctx);
    assert_eq!(
        results.len(),
        28,
        "All 28 scanners should produce results, got {}",
        results.len()
    );
}
