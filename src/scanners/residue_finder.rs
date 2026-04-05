use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::indexer::types::StubType;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

pub struct ResidueFinder;

impl Scanner for ResidueFinder {
    fn id(&self) -> &str {
        "S6"
    }

    fn name(&self) -> &str {
        "Residue Finder"
    }

    fn description(&self) -> &str {
        "Detects TODO, mock, stub, and placeholder residue across the codebase"
    }

    fn scan(&self, ctx: &ScanContext) -> ScanResult {
        let mut findings = Vec::new();

        // Collect all stub indicators from the store
        let all_indicators = ctx.index.all_stub_indicators();

        if all_indicators.is_empty() {
            return ScanResult {
                scanner: self.id().to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No residue found".to_string(),
            };
        }

        // Group indicators by StubType
        let mut by_type: HashMap<StubType, Vec<(PathBuf, usize, String)>> = HashMap::new();
        let mut files_with_residues: HashSet<PathBuf> = HashSet::new();

        for indicator in &all_indicators {
            files_with_residues.insert(indicator.file.clone());
            by_type
                .entry(indicator.indicator_type)
                .or_default()
                .push((
                    indicator.file.clone(),
                    indicator.line,
                    indicator.matched_text.clone(),
                ));
        }

        // Generate findings per type, grouped
        for (stub_type, occurrences) in &by_type {
            let severity = severity_for_stub_type(*stub_type);

            for (file, line, matched_text) in occurrences {
                findings.push(
                    Finding::new(
                        self.id(),
                        severity,
                        format!("{} residue: \"{}\"", stub_type, matched_text),
                    )
                    .with_file(file.clone())
                    .with_line(*line)
                    .with_suggestion(suggestion_for_stub_type(*stub_type)),
                );
            }
        }

        // Sort findings by severity (critical first), then by file path
        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.file.cmp(&b.file))
                .then_with(|| a.line.cmp(&b.line))
        });

        // Score: (total_files - files_with_residues) / total_files * 100
        let total_files = ctx.index.files.len();
        let residue_count = files_with_residues.len();

        let score = if total_files > 0 {
            (((total_files - residue_count) as f64 / total_files as f64) * 100.0) as u8
        } else {
            100
        };

        let summary = format!(
            "Found {} residue markers in {} files ({} total files indexed)",
            all_indicators.len(),
            residue_count,
            total_files
        );

        ScanResult {
            scanner: self.id().to_string(),
            findings,
            score,
            summary,
        }
    }
}

fn severity_for_stub_type(stub_type: StubType) -> Severity {
    match stub_type {
        StubType::MockData | StubType::StubData => Severity::Critical,
        StubType::Todo | StubType::Fixme => Severity::Warning,
        StubType::Hack
        | StubType::Placeholder
        | StubType::Hardcoded
        | StubType::Fake
        | StubType::Dummy => Severity::Info,
    }
}

fn suggestion_for_stub_type(stub_type: StubType) -> String {
    match stub_type {
        StubType::MockData => "Replace mock data with real API integration".to_string(),
        StubType::StubData => "Replace stub data with actual implementation".to_string(),
        StubType::Todo => "Resolve TODO before shipping".to_string(),
        StubType::Fixme => "Fix the noted issue before shipping".to_string(),
        StubType::Hack => "Refactor hack into a proper implementation".to_string(),
        StubType::Placeholder => "Replace placeholder with real content".to_string(),
        StubType::Hardcoded => "Move hardcoded value to configuration".to_string(),
        StubType::Fake => "Replace fake implementation with real one".to_string(),
        StubType::Dummy => "Replace dummy data with real data source".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{FileInfo, Language, StubIndicator, StubType};
    use std::sync::Arc;

    fn minimal_config() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    fn store_with_residues() -> Arc<IndexStore> {
        let store = IndexStore::new();

        let file_a = PathBuf::from("src/api.ts");
        let file_b = PathBuf::from("src/db.ts");

        store.files.insert(
            file_a.clone(),
            FileInfo {
                path: file_a.clone(),
                language: Language::TypeScript,
                lines: 100,
                hash: 1,
            },
        );
        store.files.insert(
            file_b.clone(),
            FileInfo {
                path: file_b.clone(),
                language: Language::TypeScript,
                lines: 50,
                hash: 2,
            },
        );

        store.stub_indicators.insert(
            file_a.clone(),
            vec![
                StubIndicator {
                    file: file_a.clone(),
                    line: 5,
                    indicator_type: StubType::Todo,
                    matched_text: "TODO".to_string(),
                },
                StubIndicator {
                    file: file_a.clone(),
                    line: 20,
                    indicator_type: StubType::MockData,
                    matched_text: "mockData".to_string(),
                },
            ],
        );

        store.stub_indicators.insert(
            file_b.clone(),
            vec![StubIndicator {
                file: file_b.clone(),
                line: 10,
                indicator_type: StubType::Fixme,
                matched_text: "FIXME".to_string(),
            }],
        );

        store
    }

    #[test]
    fn groups_findings_by_type() {
        let config = minimal_config();
        let store = store_with_residues();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = ResidueFinder.scan(&ctx);
        assert_eq!(result.findings.len(), 3, "Should have 3 findings total");
    }

    #[test]
    fn score_reflects_residue_ratio() {
        let config = minimal_config();
        let store = store_with_residues();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = ResidueFinder.scan(&ctx);
        // 2 files total, 2 with residues => score = 0
        assert_eq!(result.score, 0, "All files have residues, score should be 0");
    }

    #[test]
    fn perfect_score_when_clean() {
        let config = minimal_config();
        let store = IndexStore::new();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = ResidueFinder.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn findings_sorted_by_severity() {
        let config = minimal_config();
        let store = store_with_residues();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: std::path::Path::new("."),
        };

        let result = ResidueFinder.scan(&ctx);
        for window in result.findings.windows(2) {
            assert!(
                window[0].severity >= window[1].severity,
                "Findings should be sorted by severity descending"
            );
        }
    }

    #[test]
    fn severity_mapping_is_correct() {
        assert_eq!(severity_for_stub_type(StubType::MockData), Severity::Critical);
        assert_eq!(severity_for_stub_type(StubType::Todo), Severity::Warning);
        assert_eq!(severity_for_stub_type(StubType::Hack), Severity::Info);
    }
}
