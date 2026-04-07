use std::collections::{HashMap, HashSet};

use crate::indexer::types::RoleCheckType;
use crate::scanners::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S16";
const SCANNER_NAME: &str = "RoleHardcoding";
const SCANNER_DESC: &str =
    "Detects single-value role checks in middleware/guards that should use role sets";

/// Prefixes stripped to derive a base role name.
const ROLE_PREFIXES: &[&str] = &[
    "super_",
    "platform_",
    "readonly_",
    "support_",
    "read_only_",
    "senior_",
    "junior_",
    "lead_",
    "assistant_",
    "chief_",
];

pub struct RoleHardcoding;

/// Extract the base role name by stripping known prefixes.
///
/// For example: `super_admin` -> `admin`, `platform_admin` -> `admin`,
/// `editor` -> `editor` (no prefix matched).
fn extract_base_role(role: &str) -> String {
    let lower = role.to_lowercase();
    for prefix in ROLE_PREFIXES {
        if let Some(base) = lower.strip_prefix(prefix) {
            if !base.is_empty() {
                return base.to_string();
            }
        }
    }
    lower
}

/// Build a mapping from base role name to the set of all role values that
/// share that base. For example: `admin` -> {`admin`, `super_admin`, `platform_admin`}.
fn build_role_variants(all_role_values: &[String]) -> HashMap<String, HashSet<String>> {
    let mut map: HashMap<String, HashSet<String>> = HashMap::new();
    for role in all_role_values {
        let base = extract_base_role(role);
        map.entry(base).or_default().insert(role.clone());
    }
    map
}

fn is_middleware_file(path: &std::path::Path) -> bool {
    let path_str = path.to_string_lossy().to_lowercase();
    path_str.contains("middleware")
        || path_str.contains("guard")
        || path_str.contains("polic")
        || path_str.contains("permission")
        || path_str.contains("authorize")
}

fn compute_score(correct_checks: usize, total_checks: usize) -> u8 {
    if total_checks == 0 {
        return 100;
    }
    ((correct_checks as f64 / total_checks as f64) * 100.0).round() as u8
}

fn build_summary(
    findings: &[Finding],
    total_checks: usize,
    correct_checks: usize,
    score: u8,
) -> String {
    if total_checks == 0 {
        return "No role checks found to analyze.".to_string();
    }

    let problematic = total_checks - correct_checks;
    if problematic > 0 {
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        format!(
            "{}/{} role checks use single-value comparison where role sets exist ({} critical). Score: {}%.",
            problematic, total_checks, critical_count, score
        )
    } else {
        format!(
            "All {} role checks use appropriate patterns. Score: {}%.",
            total_checks, score
        )
    }
}

impl Scanner for RoleHardcoding {
    fn id(&self) -> &str {
        SCANNER_ID
    }

    fn name(&self) -> &str {
        SCANNER_NAME
    }

    fn description(&self) -> &str {
        SCANNER_DESC
    }

    fn scan(&self, ctx: &ScanContext) -> ScanResult {
        let all_checks = ctx.index.all_role_check_refs();

        if all_checks.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No role checks found to analyze.".to_string(),
            };
        }

        // Collect every role value across all checks
        let all_role_values: Vec<String> =
            all_checks.iter().map(|c| c.role_value.clone()).collect();
        let role_variants = build_role_variants(&all_role_values);

        let mut findings: Vec<Finding> = Vec::new();
        let total_checks = all_checks.len();
        let mut correct_checks: usize = 0;

        for check in &all_checks {
            match check.check_type {
                RoleCheckType::SetCheck | RoleCheckType::ArrayIncludes => {
                    // These patterns are correct
                    correct_checks += 1;
                }
                RoleCheckType::SingleValue => {
                    let base = extract_base_role(&check.role_value);
                    let variants = role_variants.get(&base);

                    let variant_count = variants.map(|v| v.len()).unwrap_or(1);

                    if variant_count >= 2 {
                        // Multiple role variants exist for this base role
                        let variant_names: Vec<String> = variants
                            .map(|v| {
                                let mut sorted: Vec<String> = v.iter().cloned().collect();
                                sorted.sort();
                                sorted
                            })
                            .unwrap_or_default();

                        let severity = if check.is_middleware || is_middleware_file(&check.file) {
                            Severity::Critical
                        } else {
                            Severity::Warning
                        };

                        findings.push(
                            Finding::new(
                                SCANNER_ID,
                                severity,
                                format!(
                                    "Single-value role check 'role == \"{}\"' but {} role variants exist: {}",
                                    check.role_value,
                                    variant_count,
                                    variant_names.join(", ")
                                ),
                            )
                            .with_file(&check.file)
                            .with_line(check.line)
                            .with_suggestion(
                                "Use a role set check instead of single-value comparison",
                            ),
                        );
                    } else {
                        // Single-value check but only one variant exists - acceptable
                        correct_checks += 1;
                    }
                }
            }
        }

        let score = compute_score(correct_checks, total_checks);
        let summary = build_summary(&findings, total_checks, correct_checks, score);

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::RoleCheckRef;
    use std::path::{Path, PathBuf};

    fn default_config() -> Config {
        Config {
            version: "1.0".into(),
            project: "test".into(),
            r#type: Default::default(),
            layers: Default::default(),
            modules: Default::default(),
            flows: Default::default(),
            deploy: Default::default(),
            integration_tests: Default::default(),
            events: Default::default(),
            env: Default::default(),
            output: Default::default(),
            dispatch: Default::default(),
            data_isolation: Default::default(),
            required_layers: Default::default(),
            linked_repos: Default::default(),
            suppress: None,
        }
    }

    #[test]
    fn test_no_role_checks_gives_perfect_score() {
        let config = default_config();
        let store = IndexStore::new();

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = RoleHardcoding.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_single_value_with_variants_is_warning() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("src/services/user.ts");
        store.role_check_refs.insert(
            file.clone(),
            vec![
                RoleCheckRef {
                    file: file.clone(),
                    line: 10,
                    check_type: RoleCheckType::SingleValue,
                    role_value: "admin".to_string(),
                    is_middleware: false,
                },
                RoleCheckRef {
                    file: file.clone(),
                    line: 20,
                    check_type: RoleCheckType::SingleValue,
                    role_value: "super_admin".to_string(),
                    is_middleware: false,
                },
            ],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = RoleHardcoding.scan(&ctx);
        assert_eq!(result.findings.len(), 2);
        assert!(result
            .findings
            .iter()
            .all(|f| f.severity == Severity::Warning));
        assert_eq!(result.score, 0);
    }

    #[test]
    fn test_middleware_single_value_is_critical() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("src/middleware/auth.ts");
        store.role_check_refs.insert(
            file.clone(),
            vec![
                RoleCheckRef {
                    file: file.clone(),
                    line: 5,
                    check_type: RoleCheckType::SingleValue,
                    role_value: "admin".to_string(),
                    is_middleware: true,
                },
                RoleCheckRef {
                    file: PathBuf::from("src/services/other.ts"),
                    line: 15,
                    check_type: RoleCheckType::SingleValue,
                    role_value: "super_admin".to_string(),
                    is_middleware: false,
                },
            ],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = RoleHardcoding.scan(&ctx);
        assert_eq!(result.findings.len(), 2);

        let middleware_finding = result.findings.iter().find(|f| f.line == Some(5)).unwrap();
        assert_eq!(middleware_finding.severity, Severity::Critical);

        let service_finding = result.findings.iter().find(|f| f.line == Some(15)).unwrap();
        assert_eq!(service_finding.severity, Severity::Warning);
    }

    #[test]
    fn test_set_check_is_correct() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("src/middleware/auth.ts");
        store.role_check_refs.insert(
            file.clone(),
            vec![RoleCheckRef {
                file: file.clone(),
                line: 5,
                check_type: RoleCheckType::SetCheck,
                role_value: "admin".to_string(),
                is_middleware: true,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = RoleHardcoding.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_array_includes_is_correct() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("src/guards/role.ts");
        store.role_check_refs.insert(
            file.clone(),
            vec![RoleCheckRef {
                file: file.clone(),
                line: 8,
                check_type: RoleCheckType::ArrayIncludes,
                role_value: "editor".to_string(),
                is_middleware: false,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = RoleHardcoding.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_single_value_without_variants_is_ok() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("src/services/user.ts");
        store.role_check_refs.insert(
            file.clone(),
            vec![RoleCheckRef {
                file: file.clone(),
                line: 10,
                check_type: RoleCheckType::SingleValue,
                role_value: "editor".to_string(),
                is_middleware: false,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = RoleHardcoding.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_mixed_correct_and_incorrect() {
        let config = default_config();
        let store = IndexStore::new();

        let file_a = PathBuf::from("src/services/a.ts");
        let file_b = PathBuf::from("src/services/b.ts");
        store.role_check_refs.insert(
            file_a.clone(),
            vec![
                RoleCheckRef {
                    file: file_a.clone(),
                    line: 10,
                    check_type: RoleCheckType::SetCheck,
                    role_value: "admin".to_string(),
                    is_middleware: false,
                },
                RoleCheckRef {
                    file: file_a.clone(),
                    line: 20,
                    check_type: RoleCheckType::SingleValue,
                    role_value: "admin".to_string(),
                    is_middleware: false,
                },
            ],
        );
        store.role_check_refs.insert(
            file_b.clone(),
            vec![RoleCheckRef {
                file: file_b.clone(),
                line: 5,
                check_type: RoleCheckType::SingleValue,
                role_value: "super_admin".to_string(),
                is_middleware: false,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = RoleHardcoding.scan(&ctx);
        // 3 total checks: 1 SetCheck (correct) + 2 SingleValue with variants (incorrect)
        // score = (1/3) * 100 = 33
        assert_eq!(result.score, 33);
        assert_eq!(result.findings.len(), 2);
    }

    #[test]
    fn test_middleware_file_path_detection() {
        assert!(is_middleware_file(Path::new("src/middleware/auth.ts")));
        assert!(is_middleware_file(Path::new("src/guards/role.guard.ts")));
        assert!(is_middleware_file(Path::new("app/policies/admin.py")));
        assert!(is_middleware_file(Path::new("src/permissions/check.ts")));
        assert!(is_middleware_file(Path::new("lib/authorize/role.rb")));
        assert!(!is_middleware_file(Path::new("src/services/user.ts")));
        assert!(!is_middleware_file(Path::new("src/controllers/api.ts")));
    }

    #[test]
    fn test_extract_base_role() {
        assert_eq!(extract_base_role("super_admin"), "admin");
        assert_eq!(extract_base_role("platform_admin"), "admin");
        assert_eq!(extract_base_role("readonly_editor"), "editor");
        assert_eq!(extract_base_role("admin"), "admin");
        assert_eq!(extract_base_role("editor"), "editor");
        assert_eq!(extract_base_role("SUPER_ADMIN"), "admin");
    }

    #[test]
    fn test_middleware_flag_on_check_ref_upgrades_severity() {
        let config = default_config();
        let store = IndexStore::new();

        // Place in a non-middleware file path but set is_middleware = true
        let file = PathBuf::from("src/services/user.ts");
        store.role_check_refs.insert(
            file.clone(),
            vec![
                RoleCheckRef {
                    file: file.clone(),
                    line: 10,
                    check_type: RoleCheckType::SingleValue,
                    role_value: "admin".to_string(),
                    is_middleware: true,
                },
                RoleCheckRef {
                    file: file.clone(),
                    line: 20,
                    check_type: RoleCheckType::SingleValue,
                    role_value: "platform_admin".to_string(),
                    is_middleware: false,
                },
            ],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = RoleHardcoding.scan(&ctx);
        let critical = result.findings.iter().find(|f| f.line == Some(10)).unwrap();
        assert_eq!(critical.severity, Severity::Critical);
    }

    #[test]
    fn test_finding_has_suggestion() {
        let config = default_config();
        let store = IndexStore::new();

        let file = PathBuf::from("src/services/user.ts");
        store.role_check_refs.insert(
            file.clone(),
            vec![
                RoleCheckRef {
                    file: file.clone(),
                    line: 10,
                    check_type: RoleCheckType::SingleValue,
                    role_value: "admin".to_string(),
                    is_middleware: false,
                },
                RoleCheckRef {
                    file: file.clone(),
                    line: 20,
                    check_type: RoleCheckType::SingleValue,
                    role_value: "super_admin".to_string(),
                    is_middleware: false,
                },
            ],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = RoleHardcoding.scan(&ctx);
        for finding in &result.findings {
            assert!(finding.suggestion.is_some());
            assert!(finding.suggestion.as_ref().unwrap().contains("role set"));
        }
    }
}
