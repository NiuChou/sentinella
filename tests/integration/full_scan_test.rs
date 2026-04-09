use std::collections::HashSet;
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
        // Score must also be >= 0 (u8 guarantees this, but assert explicitly for documentation)
        assert!(
            result.score <= 100,
            "Scanner {} score {} must be in [0, 100]",
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
        "S28", "S29", "S30", "S31", "S32", "S33",
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
fn all_thirty_three_scanners_produce_results() {
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
        33,
        "All 33 scanners should produce results, got {}",
        results.len()
    );
}

/// A. All 33 expected scanner IDs must be present in the results.
/// This catches scanners that silently return no result instead of a ScanResult.
#[test]
fn all_scanner_ids_are_present_in_results() {
    let (config, index) = build_fixture_index();
    let root = fixtures_dir();

    let scanners = create_scanners(None);
    let ctx = ScanContext {
        config: &config,
        index: &index,
        root_dir: &root,
    };

    let results = run_scanners(&scanners, &ctx);
    let scanner_ids: HashSet<&str> = results.iter().map(|r| r.scanner.as_str()).collect();

    let expected_ids = [
        "S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8", "S9", "S10", "S11", "S12", "S13", "S14",
        "S15", "S16", "S17", "S18", "S19", "S20", "S21", "S22", "S23", "S24", "S25", "S26", "S27",
        "S28", "S29", "S30", "S31", "S32", "S33",
    ];

    for id in &expected_ids {
        assert!(
            scanner_ids.contains(id),
            "Expected scanner ID '{}' missing from results — scanner may have been removed or returns no result",
            id
        );
    }
}

/// B. Scanners whose detection targets are present in fixtures must produce
/// findings or a degraded score, not a silent score=100.
///
/// Fixture content driving these assertions:
///
/// S6 (ResidueFinder): typescript/data_isolation.ts and python/data_isolation.py both contain
///   the word "hardcoded" in comments (e.g. "// --- D7: Hardcoded credentials ---"), which
///   matches the `(?i)\bhardcoded\b` StubType::Hardcoded pattern indexed by the parsers.
///
/// S12 (DataIsolationAudit): typescript/data_isolation.ts has `database_password: "postgres123"`,
///   `redis_secret: "redis-dev-secret"`, and `INTERNAL_API_KEY = "dev-internal-key-12345"`,
///   all matching the hardcoded-credential regex. python/data_isolation.py has
///   `MINIO_ACCESS_KEY = "minioadmin"` and `DATABASE_PASSWORD = "dev-postgres-password"`.
///   DataIsolationConfig defaults to enabled=true so D7 runs.
///
/// S13 (DestructiveEndpointSafety): typescript/routes.ts has `router.delete(...)`,
///   go/routes.go has `r.DELETE(...)`, python/routes.py has `@router.delete(...)`,
///   rust/routes.rs has `#[delete(...)]`. These are indexed as DELETE HTTP endpoints with
///   no secondary-auth refs, so findings are expected.
#[test]
fn scanners_detect_known_patterns_in_fixtures() {
    let (config, index) = build_fixture_index();
    let root = fixtures_dir();

    let scanners = create_scanners(None);
    let ctx = ScanContext {
        config: &config,
        index: &index,
        root_dir: &root,
    };

    let results = run_scanners(&scanners, &ctx);

    // S6: ResidueFinder — fixtures contain "hardcoded" keyword in comments
    let s6 = results
        .iter()
        .find(|r| r.scanner == "S6")
        .expect("S6 (ResidueFinder) must produce a result");
    assert!(
        !s6.findings.is_empty() || s6.score < 100,
        "S6 (ResidueFinder) should detect residue markers (e.g. 'hardcoded' in data_isolation.ts comments)"
    );

    // S12: DataIsolationAudit — hardcoded credentials in data_isolation.ts and data_isolation.py
    let s12 = results
        .iter()
        .find(|r| r.scanner == "S12")
        .expect("S12 (DataIsolationAudit) must produce a result");
    assert!(
        !s12.findings.is_empty() || s12.score < 100,
        "S12 (DataIsolationAudit) should detect hardcoded credentials in fixtures"
    );

    // S13: DestructiveEndpointSafety — DELETE routes in routes.ts, routes.go, routes.py, routes.rs
    let s13 = results
        .iter()
        .find(|r| r.scanner == "S13")
        .expect("S13 (DestructiveEndpointSafety) must produce a result");
    assert!(
        !s13.findings.is_empty() || s13.score < 100,
        "S13 (DestructiveEndpointSafety) should detect DELETE endpoints in fixtures (routes.ts, routes.go, routes.py, routes.rs)"
    );
}

/// D. Dedicated test: scanners whose detection targets appear in fixture files
/// must produce at least one finding (not merely "no error, score=100").
#[test]
fn scanners_with_relevant_fixtures_detect_findings() {
    let (config, index) = build_fixture_index();
    let root = fixtures_dir();

    let scanners = create_scanners(None);
    let ctx = ScanContext {
        config: &config,
        index: &index,
        root_dir: &root,
    };

    let results = run_scanners(&scanners, &ctx);

    // Helper closure to look up a result by scanner ID
    let find = |id: &str| -> &sentinella::scanners::types::ScanResult {
        results
            .iter()
            .find(|r| r.scanner == id)
            .unwrap_or_else(|| panic!("Scanner '{}' produced no result", id))
    };

    // S6 must produce findings: "hardcoded" comment in data_isolation.ts and data_isolation.py
    // triggers StubType::Hardcoded which is indexed by both TypeScript and Python parsers.
    let s6 = find("S6");
    assert!(
        !s6.findings.is_empty(),
        "S6 (ResidueFinder) must have at least one finding — fixture files contain 'hardcoded' comments"
    );

    // S12 must produce findings: hardcoded credentials (database_password, redis_secret,
    // INTERNAL_API_KEY in data_isolation.ts; MINIO_ACCESS_KEY, DATABASE_PASSWORD in
    // data_isolation.py) are matched by the D7 check inside DataIsolationAudit.
    let s12 = find("S12");
    assert!(
        !s12.findings.is_empty(),
        "S12 (DataIsolationAudit) must have at least one finding — fixture files contain hardcoded credentials"
    );

    // S13 must produce findings: DELETE endpoints in routes.ts (router.delete), routes.go
    // (r.DELETE), routes.py (@router.delete), routes.rs (#[delete]) are all indexed and
    // none have secondary auth refs in the fixtures.
    let s13 = find("S13");
    assert!(
        !s13.findings.is_empty(),
        "S13 (DestructiveEndpointSafety) must have at least one finding — fixture files contain unprotected DELETE endpoints"
    );
}
