use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;

use super::{count_lines, hash_source, LanguageParser};
use crate::indexer::store::IndexStore;
use crate::indexer::types::{EnvConfig, EnvSourceType, FileInfo, Language};

pub struct YamlConfigParser;

impl LanguageParser for YamlConfigParser {
    fn extensions(&self) -> &[&str] {
        &["yaml", "yml"]
    }

    fn parse_file(&self, path: &Path, source: &[u8], store: &IndexStore) -> Result<()> {
        let file_info = FileInfo {
            path: path.to_path_buf(),
            language: Language::Yaml,
            lines: count_lines(source),
            hash: hash_source(source),
        };
        store.files.insert(path.to_path_buf(), file_info);

        let source_str = std::str::from_utf8(source)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in YAML file: {e}"))?;

        let docs: Vec<serde_yaml::Value> = match parse_yaml_docs(source_str) {
            Ok(docs) => docs,
            Err(e) => {
                eprintln!("Warning: failed to parse YAML {}: {e}", path.display());
                return Ok(());
            }
        };

        for doc in &docs {
            let kind = doc.get("kind").and_then(|v| v.as_str()).unwrap_or("");

            match kind {
                "ConfigMap" => parse_k8s_configmap(path, doc, store),
                "Secret" => parse_k8s_secret(path, doc, store),
                _ => {}
            }

            // Docker Compose detection: top-level "services" key without "kind"
            if kind.is_empty() {
                if let Some(services) = doc.get("services") {
                    parse_docker_compose_services(path, services, store);
                }
            }
        }

        Ok(())
    }
}

/// Parse potentially multi-document YAML. Falls back to single-doc parse.
fn parse_yaml_docs(source: &str) -> Result<Vec<serde_yaml::Value>> {
    // serde_yaml does not natively support multi-doc streaming in recent versions,
    // so we split on the `---` separator and parse each document individually.
    let mut docs = Vec::new();

    for segment in source.split("\n---") {
        let trimmed = segment.trim();
        if trimmed.is_empty() || trimmed == "---" {
            continue;
        }
        match serde_yaml::from_str::<serde_yaml::Value>(trimmed) {
            Ok(val) => docs.push(val),
            Err(_) => continue,
        }
    }

    if docs.is_empty() {
        // Try a single-document parse as fallback
        let val: serde_yaml::Value = serde_yaml::from_str(source)?;
        docs.push(val);
    }

    Ok(docs)
}

/// Extract env vars from a K8s ConfigMap's `data` section.
fn parse_k8s_configmap(path: &Path, doc: &serde_yaml::Value, store: &IndexStore) {
    if let Some(data) = doc.get("data").and_then(|d| d.as_mapping()) {
        for (key, _) in data {
            if let Some(var_name) = key.as_str() {
                let config = EnvConfig {
                    var_name: var_name.to_string(),
                    source_file: path.to_path_buf(),
                    source_type: EnvSourceType::K8sConfigMap,
                };
                store
                    .infra
                    .env_configs
                    .entry(var_name.to_string())
                    .or_default()
                    .push(config);
            }
        }
    }
}

/// Extract env vars from a K8s Secret's `data` or `stringData` section.
fn parse_k8s_secret(path: &Path, doc: &serde_yaml::Value, store: &IndexStore) {
    for section_key in &["data", "stringData"] {
        if let Some(data) = doc.get(*section_key).and_then(|d| d.as_mapping()) {
            for (key, _) in data {
                if let Some(var_name) = key.as_str() {
                    let config = EnvConfig {
                        var_name: var_name.to_string(),
                        source_file: path.to_path_buf(),
                        source_type: EnvSourceType::K8sSecret,
                    };
                    store
                        .infra
                        .env_configs
                        .entry(var_name.to_string())
                        .or_default()
                        .push(config);
                }
            }
        }
    }
}

fn env_file_kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)"#).unwrap())
}

/// Parse a referenced env file (relative to the YAML file) and register its vars.
fn parse_referenced_env_file(yaml_path: &Path, env_path_str: &str, store: &IndexStore) {
    let yaml_dir = match yaml_path.parent() {
        Some(d) => d,
        None => return,
    };
    let env_path = yaml_dir.join(env_path_str);
    let source = match std::fs::read_to_string(&env_path) {
        Ok(s) => s,
        Err(_) => return, // file doesn't exist or is unreadable — skip silently
    };

    let kv_re = env_file_kv_re();
    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(cap) = kv_re.captures(trimmed) {
            if let Some(key) = cap.get(1) {
                let var_name = key.as_str().to_string();
                let config = EnvConfig {
                    var_name: var_name.clone(),
                    source_file: env_path.clone(),
                    source_type: EnvSourceType::DotEnv,
                };
                store
                    .infra
                    .env_configs
                    .entry(var_name)
                    .or_default()
                    .push(config);
            }
        }
    }
}

/// Extract env file paths from a service's `env_file` directive.
fn collect_env_file_paths(value: &serde_yaml::Value) -> Vec<String> {
    match value {
        serde_yaml::Value::String(s) => vec![s.clone()],
        serde_yaml::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|item| item.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Extract env vars from docker-compose services' `environment` and `env_file` sections.
fn parse_docker_compose_services(path: &Path, services: &serde_yaml::Value, store: &IndexStore) {
    let services_map = match services.as_mapping() {
        Some(m) => m,
        None => return,
    };

    for (_service_name, service_def) in services_map {
        // Handle env_file directives: parse referenced .env files
        if let Some(env_file_val) = service_def.get("env_file") {
            for env_path_str in collect_env_file_paths(env_file_val) {
                parse_referenced_env_file(path, &env_path_str, store);
            }
        }

        let env_section = match service_def.get("environment") {
            Some(e) => e,
            None => continue,
        };

        // Environment can be a mapping { KEY: value } or a list [ "KEY=value" ]
        if let Some(mapping) = env_section.as_mapping() {
            for (key, _) in mapping {
                if let Some(var_name) = key.as_str() {
                    let config = EnvConfig {
                        var_name: var_name.to_string(),
                        source_file: path.to_path_buf(),
                        source_type: EnvSourceType::DockerCompose,
                    };
                    store
                        .infra
                        .env_configs
                        .entry(var_name.to_string())
                        .or_default()
                        .push(config);
                }
            }
        } else if let Some(list) = env_section.as_sequence() {
            for item in list {
                if let Some(entry_str) = item.as_str() {
                    // "KEY=value" or just "KEY"
                    let var_name = entry_str
                        .split('=')
                        .next()
                        .unwrap_or(entry_str)
                        .trim()
                        .to_string();

                    if !var_name.is_empty() {
                        let config = EnvConfig {
                            var_name: var_name.clone(),
                            source_file: path.to_path_buf(),
                            source_type: EnvSourceType::DockerCompose,
                        };
                        store
                            .infra
                            .env_configs
                            .entry(var_name)
                            .or_default()
                            .push(config);
                    }
                }
            }
        }
    }
}
