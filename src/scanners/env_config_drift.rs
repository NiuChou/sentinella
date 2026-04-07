use std::collections::HashSet;
use std::path::Path;

use crate::config::schema::EXCLUDED_VAR_PREFIXES;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S11";
const UNSAFE_DEFAULTS: &[&str] = &["localhost", "127.0.0.1"];

pub struct EnvConfigDrift;

impl Scanner for EnvConfigDrift {
    fn id(&self) -> &str {
        SCANNER_ID
    }

    fn name(&self) -> &str {
        "Env Config Drift"
    }

    fn description(&self) -> &str {
        "Detects drift between environment variable references in code and deploy configurations"
    }

    fn scan(&self, ctx: &ScanContext) -> ScanResult {
        let mut findings = Vec::new();

        let exclude_paths = &ctx.config.env.exclude_paths;
        let exclude_vars = &ctx.config.env.exclude_vars;

        let ref_vars = collect_filtered_var_names(&ctx.index.env_refs, exclude_paths, exclude_vars);
        let config_vars = collect_var_names(&ctx.index.env_configs);

        if ref_vars.is_empty() && config_vars.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No environment variable references or configurations found".to_string(),
            };
        }

        // Missing: referenced in code but not configured
        for var in &ref_vars {
            if !config_vars.contains(var) {
                let entries = ctx.index.env_refs.get(var);
                if let Some(entries) = entries {
                    for entry in entries.value() {
                        if is_excluded_path(&entry.file, exclude_paths) {
                            continue;
                        }
                        findings.push(
                            Finding::new(
                                SCANNER_ID,
                                Severity::Critical,
                                format!(
                                    "Missing env config: '{}' is referenced in code but not configured in any deploy target",
                                    var
                                ),
                            )
                            .with_file(entry.file.clone())
                            .with_line(entry.line)
                            .with_suggestion(format!(
                                "Add '{}' to your .env, docker-compose, or k8s config",
                                var
                            )),
                        );
                    }
                }
            }
        }

        // Orphan: configured but never referenced
        for var in &config_vars {
            if !ref_vars.contains(var) {
                let entries = ctx.index.env_configs.get(var);
                if let Some(entries) = entries {
                    for entry in entries.value() {
                        findings.push(
                            Finding::new(
                                SCANNER_ID,
                                Severity::Info,
                                format!(
                                    "Orphan env config: '{}' is configured but never referenced in code",
                                    var
                                ),
                            )
                            .with_file(entry.source_file.clone())
                            .with_suggestion(format!(
                                "Remove '{}' from deploy config if no longer needed",
                                var
                            )),
                        );
                    }
                }
            }
        }

        // Unsafe defaults: env refs with defaults containing localhost or 127.0.0.1
        check_unsafe_defaults(ctx, &mut findings, exclude_paths, exclude_vars);

        let all_vars: HashSet<&String> = ref_vars.union(&config_vars).collect();
        let aligned_count = ref_vars.iter().filter(|v| config_vars.contains(*v)).count();
        let total = all_vars.len();

        let score = if total > 0 {
            ((aligned_count as f64 / total as f64) * 100.0) as u8
        } else {
            100
        };

        let missing = ref_vars
            .iter()
            .filter(|v| !config_vars.contains(*v))
            .count();
        let orphaned = config_vars
            .iter()
            .filter(|v| !ref_vars.contains(*v))
            .count();
        let unsafe_count = findings
            .iter()
            .filter(|f| f.message.contains("Unsafe default"))
            .count();

        let summary = format!(
            "{} vars total, {} aligned, {} missing, {} orphaned, {} unsafe defaults",
            total, aligned_count, missing, orphaned, unsafe_count,
        );

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

/// Collect all unique variable names from a DashMap.
fn collect_var_names<V>(map: &dashmap::DashMap<String, Vec<V>>) -> HashSet<String> {
    map.iter().map(|entry| entry.key().clone()).collect()
}

/// Collect variable names from env_refs, excluding vars that match excluded
/// paths or excluded variable names/prefixes.
fn collect_filtered_var_names(
    map: &dashmap::DashMap<String, Vec<crate::indexer::types::EnvRef>>,
    exclude_paths: &[String],
    exclude_vars: &[String],
) -> HashSet<String> {
    map.iter()
        .filter(|entry| {
            let var_name = entry.key();
            if is_excluded_var(var_name, exclude_vars) {
                return false;
            }
            // Keep the var if at least one ref is in a non-excluded path
            entry
                .value()
                .iter()
                .any(|r| !is_excluded_path(&r.file, exclude_paths))
        })
        .map(|entry| entry.key().clone())
        .collect()
}

/// Check whether a file path falls inside any excluded directory.
fn is_excluded_path(file: &Path, exclude_paths: &[String]) -> bool {
    let path_str = file.to_string_lossy();
    exclude_paths
        .iter()
        .any(|excl| path_str.contains(excl.as_str()))
}

/// Check whether a variable name should be excluded by exact match or prefix.
fn is_excluded_var(var_name: &str, exclude_vars: &[String]) -> bool {
    if exclude_vars.iter().any(|ev| ev == var_name) {
        return true;
    }
    EXCLUDED_VAR_PREFIXES
        .iter()
        .any(|prefix| var_name.starts_with(prefix))
}

const CONNECTION_KEYWORDS: &[&str] = &["url", "host", "endpoint", "addr", "port"];

/// Check if a variable name suggests a connection/network configuration.
fn is_connection_var(var_name: &str) -> bool {
    let lower = var_name.to_lowercase();
    CONNECTION_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Check if a default value contains any of the known unsafe defaults.
fn contains_unsafe_default(value: &str) -> bool {
    let lower = value.to_lowercase();
    UNSAFE_DEFAULTS.iter().any(|ud| lower.contains(ud))
}

/// Check for env refs that have defaults containing unsafe values like localhost.
///
/// When `default_value` is available, checks it directly against UNSAFE_DEFAULTS.
/// Otherwise, flags connection-related variables that have any default set.
fn check_unsafe_defaults(
    ctx: &ScanContext,
    findings: &mut Vec<Finding>,
    exclude_paths: &[String],
    exclude_vars: &[String],
) {
    for entry in ctx.index.env_refs.iter() {
        for env_ref in entry.value() {
            if !env_ref.has_default {
                continue;
            }
            if is_excluded_path(&env_ref.file, exclude_paths) {
                continue;
            }
            if is_excluded_var(&env_ref.var_name, exclude_vars) {
                continue;
            }

            // If we have the actual default value, check it directly
            if let Some(ref default_val) = env_ref.default_value {
                if contains_unsafe_default(default_val) {
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Warning,
                            format!(
                                "Unsafe default: '{}' defaults to '{}' which contains a local-only address",
                                env_ref.var_name, default_val
                            ),
                        )
                        .with_file(env_ref.file.clone())
                        .with_line(env_ref.line)
                        .with_suggestion(format!(
                            "Remove the default value for '{}' or use an environment-specific endpoint",
                            env_ref.var_name
                        )),
                    );
                }
                continue;
            }

            // Fallback: no default_value captured, flag connection vars with any default
            if is_connection_var(&env_ref.var_name) {
                findings.push(
                    Finding::new(
                        SCANNER_ID,
                        Severity::Warning,
                        format!(
                            "Unsafe default: '{}' has a default value for a connection variable - \
                             verify it does not contain localhost or 127.0.0.1",
                            env_ref.var_name
                        ),
                    )
                    .with_file(env_ref.file.clone())
                    .with_line(env_ref.line)
                    .with_suggestion(format!(
                        "Remove the default value for '{}' or ensure it points to a valid environment-specific endpoint",
                        env_ref.var_name
                    )),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collect_var_names_empty() {
        let map: dashmap::DashMap<String, Vec<crate::indexer::types::EnvRef>> =
            dashmap::DashMap::new();
        let names = collect_var_names(&map);
        assert!(names.is_empty());
    }

    #[test]
    fn test_collect_var_names_populated() {
        let map: dashmap::DashMap<String, Vec<crate::indexer::types::EnvRef>> =
            dashmap::DashMap::new();
        map.insert(
            "DATABASE_URL".to_string(),
            vec![crate::indexer::types::EnvRef {
                var_name: "DATABASE_URL".to_string(),
                file: std::path::PathBuf::from("src/db.rs"),
                line: 5,
                has_default: false,
                default_value: None,
            }],
        );
        map.insert(
            "API_KEY".to_string(),
            vec![crate::indexer::types::EnvRef {
                var_name: "API_KEY".to_string(),
                file: std::path::PathBuf::from("src/api.rs"),
                line: 12,
                has_default: false,
                default_value: None,
            }],
        );
        let names = collect_var_names(&map);
        assert_eq!(names.len(), 2);
        assert!(names.contains("DATABASE_URL"));
        assert!(names.contains("API_KEY"));
    }

    #[test]
    fn test_unsafe_defaults_constant() {
        assert!(UNSAFE_DEFAULTS.contains(&"localhost"));
        assert!(UNSAFE_DEFAULTS.contains(&"127.0.0.1"));
    }

    #[test]
    fn test_contains_unsafe_default_localhost() {
        assert!(contains_unsafe_default("http://localhost:3000"));
        assert!(contains_unsafe_default("127.0.0.1:5432"));
        assert!(!contains_unsafe_default("https://api.example.com"));
    }

    #[test]
    fn test_is_connection_var() {
        assert!(is_connection_var("DATABASE_URL"));
        assert!(is_connection_var("REDIS_HOST"));
        assert!(is_connection_var("API_ENDPOINT"));
        assert!(is_connection_var("BIND_ADDR"));
        assert!(is_connection_var("SERVER_PORT"));
        assert!(!is_connection_var("LOG_LEVEL"));
        assert!(!is_connection_var("APP_NAME"));
    }

    #[test]
    fn test_node_modules_path_excluded() {
        let exclude_paths = vec!["node_modules/".to_string()];
        let path = std::path::PathBuf::from("node_modules/@prisma/client/index.js");
        assert!(is_excluded_path(&path, &exclude_paths));

        let src_path = std::path::PathBuf::from("src/config.ts");
        assert!(!is_excluded_path(&src_path, &exclude_paths));
    }

    #[test]
    fn test_system_env_var_excluded() {
        let exclude_vars = vec![
            "NODE_ENV".to_string(),
            "HOME".to_string(),
            "PATH".to_string(),
        ];
        assert!(is_excluded_var("NODE_ENV", &exclude_vars));
        assert!(is_excluded_var("HOME", &exclude_vars));
        assert!(!is_excluded_var("DATABASE_URL", &exclude_vars));
    }

    #[test]
    fn test_platform_prefix_excluded() {
        let exclude_vars: Vec<String> = Vec::new();
        // Even with no exact matches, GITHUB_ prefix should be excluded
        assert!(is_excluded_var("GITHUB_TOKEN", &exclude_vars));
        assert!(is_excluded_var("VERCEL_URL", &exclude_vars));
        assert!(is_excluded_var("NETLIFY_BUILD_ID", &exclude_vars));
        assert!(!is_excluded_var("MY_CUSTOM_VAR", &exclude_vars));
    }

    #[test]
    fn test_filtered_var_names_skips_node_modules() {
        let map: dashmap::DashMap<String, Vec<crate::indexer::types::EnvRef>> =
            dashmap::DashMap::new();
        // Ref only in node_modules — should be excluded
        map.insert(
            "PRISMA_ENGINE".to_string(),
            vec![crate::indexer::types::EnvRef {
                var_name: "PRISMA_ENGINE".to_string(),
                file: std::path::PathBuf::from("node_modules/.prisma/client/index.js"),
                line: 1,
                has_default: false,
                default_value: None,
            }],
        );
        // Ref in src — should be kept
        map.insert(
            "DATABASE_URL".to_string(),
            vec![crate::indexer::types::EnvRef {
                var_name: "DATABASE_URL".to_string(),
                file: std::path::PathBuf::from("src/db.ts"),
                line: 5,
                has_default: false,
                default_value: None,
            }],
        );

        let exclude_paths = vec!["node_modules/".to_string()];
        let exclude_vars: Vec<String> = Vec::new();
        let filtered = collect_filtered_var_names(&map, &exclude_paths, &exclude_vars);
        assert!(!filtered.contains("PRISMA_ENGINE"));
        assert!(filtered.contains("DATABASE_URL"));
    }

    #[test]
    fn test_unsafe_default_with_known_value() {
        use crate::config::Config;
        use crate::indexer::store::IndexStore;
        use std::path::Path;

        let config = Config {
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
            linked_repos: Vec::new(),
            suppress: None,
        };
        let store = IndexStore::new();

        store.env_refs.insert(
            "DATABASE_URL".to_string(),
            vec![crate::indexer::types::EnvRef {
                var_name: "DATABASE_URL".to_string(),
                file: std::path::PathBuf::from("src/db.ts"),
                line: 5,
                has_default: true,
                default_value: Some("http://localhost:5432".to_string()),
            }],
        );
        store.env_configs.insert(
            "DATABASE_URL".to_string(),
            vec![crate::indexer::types::EnvConfig {
                var_name: "DATABASE_URL".to_string(),
                source_file: std::path::PathBuf::from(".env"),
                source_type: crate::indexer::types::EnvSourceType::DotEnv,
            }],
        );

        let ctx = crate::scanners::types::ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = EnvConfigDrift.scan(&ctx);
        let unsafe_findings: Vec<_> = result
            .findings
            .iter()
            .filter(|f| f.message.contains("Unsafe default"))
            .collect();
        assert_eq!(unsafe_findings.len(), 1);
        assert!(unsafe_findings[0].message.contains("localhost"));
    }
}
