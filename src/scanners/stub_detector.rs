use std::collections::HashSet;
use std::path::PathBuf;

use crate::indexer::types::StubType;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

pub struct StubDetector;

impl Scanner for StubDetector {
    fn id(&self) -> &str {
        "S1"
    }

    fn name(&self) -> &str {
        "Stub Detector"
    }

    fn description(&self) -> &str {
        "Detects stub/shell frontend pages and hooks that lack real data connections"
    }

    fn scan(&self, ctx: &ScanContext) -> ScanResult {
        let mut findings = Vec::new();

        // Collect files from layers that match hooks/pages patterns
        let target_files = collect_target_files(ctx);

        if target_files.is_empty() {
            return ScanResult {
                scanner: self.id().to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No hook/page files found to check".to_string(),
            };
        }

        let mut stub_count: usize = 0;
        let total = target_files.len();

        for file in &target_files {
            let has_api_calls = file_has_api_calls(ctx, file);
            let has_stubs = file_has_stub_indicators(ctx, file);

            if !has_api_calls && has_stubs {
                // Stub file: no real data, but has stub markers
                stub_count += 1;
                findings.push(
                    Finding::new(
                        self.id(),
                        Severity::Critical,
                        format!(
                            "Stub detected: {} has stub indicators but no API calls",
                            file.display()
                        ),
                    )
                    .with_file(file.clone())
                    .with_suggestion(
                        "Replace stub/placeholder data with real API integration".to_string(),
                    ),
                );
            } else if !has_api_calls && !has_stubs {
                // Unknown: no API calls and no stub markers
                findings.push(
                    Finding::new(
                        self.id(),
                        Severity::Warning,
                        format!(
                            "Unknown data source: {} has neither API calls nor stub indicators",
                            file.display()
                        ),
                    )
                    .with_file(file.clone())
                    .with_suggestion("Verify this file connects to a real data source".to_string()),
                );
            }
        }

        let score = if total > 0 {
            (((total - stub_count) as f64 / total as f64) * 100.0) as u8
        } else {
            100
        };

        let summary = format!(
            "Checked {} files: {} stubs detected, {} unknown",
            total,
            stub_count,
            findings
                .iter()
                .filter(|f| f.severity == Severity::Warning)
                .count()
        );

        ScanResult {
            scanner: self.id().to_string(),
            findings,
            score,
            summary,
        }
    }
}

/// Collect files from the index that match hook/page layer patterns.
fn collect_target_files(ctx: &ScanContext) -> Vec<PathBuf> {
    let mut targets = HashSet::new();

    // Gather patterns from layers config
    let patterns: Vec<&str> = ctx
        .config
        .layers
        .values()
        .map(|layer| layer.pattern.as_str())
        .collect();

    // Also include module hooks/pages
    for module in &ctx.config.modules {
        if let Some(ref hooks) = module.hooks {
            targets.insert(PathBuf::from(hooks));
        }
        if let Some(ref page) = module.page {
            targets.insert(PathBuf::from(page));
        }
    }

    // Match index files against layer patterns
    for entry in ctx.index.files.iter() {
        let path = entry.key();
        let path_str = path.to_string_lossy();
        for pattern in &patterns {
            if path_matches_glob(&path_str, pattern) {
                targets.insert(path.clone());
            }
        }
    }

    let mut result: Vec<PathBuf> = targets.into_iter().collect();
    result.sort();
    result
}

/// Simple glob matching: supports `**` (any path segment) and `*` (any name chars).
fn path_matches_glob(path: &str, pattern: &str) -> bool {
    if pattern.contains("**") {
        let parts: Vec<&str> = pattern.split("**").collect();
        if parts.len() == 2 {
            let prefix = parts[0].trim_end_matches('/');
            let suffix = parts[1].trim_start_matches('/');
            let prefix_ok = prefix.is_empty() || path.contains(prefix);
            let suffix_ok = suffix.is_empty()
                || path.ends_with(suffix)
                || suffix.starts_with('*') && has_matching_extension(path, suffix);
            return prefix_ok && suffix_ok;
        }
    }
    path.contains(pattern.trim_start_matches('*').trim_end_matches('*'))
}

fn has_matching_extension(path: &str, suffix_pattern: &str) -> bool {
    // Handle patterns like "*.tsx" or "*.ts"
    if let Some(ext) = suffix_pattern.strip_prefix("*.") {
        return path.ends_with(&format!(".{}", ext));
    }
    if let Some(ext) = suffix_pattern.strip_prefix('.') {
        return path.ends_with(&format!(".{}", ext));
    }
    path.ends_with(suffix_pattern)
}

/// Check whether the index has any API calls originating from this file.
fn file_has_api_calls(ctx: &ScanContext, file: &PathBuf) -> bool {
    for entry in ctx.index.api_calls.iter() {
        for call in entry.value() {
            if call.file == *file {
                return true;
            }
        }
    }
    false
}

/// Check whether the index has stub indicators for this file.
fn file_has_stub_indicators(ctx: &ScanContext, file: &PathBuf) -> bool {
    ctx.index
        .stub_indicators
        .get(file.as_path())
        .map(|indicators| {
            indicators.value().iter().any(|s| {
                matches!(
                    s.indicator_type,
                    StubType::StubData
                        | StubType::MockData
                        | StubType::Placeholder
                        | StubType::Fake
                        | StubType::Dummy
                        | StubType::Todo
                        | StubType::Fixme
                        | StubType::Hack
                        | StubType::Hardcoded
                )
            })
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{StubIndicator, StubType};
    use std::sync::Arc;

    fn minimal_config() -> Config {
        let yaml = r#"
version: "1.0"
project: test
type: fullstack
layers:
  frontend:
    pattern: "src/**/*.ts"
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    fn store_with_stubs() -> Arc<IndexStore> {
        let store = IndexStore::new();
        let file = PathBuf::from("src/hooks/useData.ts");

        store.stub_indicators.insert(
            file.clone(),
            vec![StubIndicator {
                file: file.clone(),
                line: 10,
                indicator_type: StubType::MockData,
                matched_text: "mockData".to_string(),
            }],
        );

        store.files.insert(
            file.clone(),
            crate::indexer::types::FileInfo {
                path: file,
                language: crate::indexer::types::Language::TypeScript,
                lines: 50,
                hash: 0,
            },
        );

        store
    }

    #[test]
    fn detects_stub_files() {
        let config = minimal_config();
        let store = store_with_stubs();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = StubDetector.scan(&ctx);
        assert!(result.score < 100, "Score should be < 100 when stubs exist");
    }

    #[test]
    fn perfect_score_when_no_files() {
        let config = minimal_config();
        let store = IndexStore::new();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = StubDetector.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn path_matches_glob_double_star() {
        assert!(path_matches_glob("src/hooks/useData.ts", "src/**/*.ts"));
    }

    #[test]
    fn path_matches_glob_no_match() {
        assert!(!path_matches_glob("lib/main.py", "src/**/*.ts"));
    }
}
