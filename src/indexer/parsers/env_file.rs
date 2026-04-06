use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;

use super::{count_lines, hash_source, LanguageParser};
use crate::indexer::store::IndexStore;
use crate::indexer::types::{EnvConfig, EnvSourceType, FileInfo, Language};

pub struct EnvFileParser;

impl LanguageParser for EnvFileParser {
    fn extensions(&self) -> &[&str] {
        // Matched by filename prefix in the walker: .env, .env.example, .env.local, etc.
        &[".env"]
    }

    fn parse_file(&self, path: &Path, source: &[u8], store: &IndexStore) -> Result<()> {
        let file_info = FileInfo {
            path: path.to_path_buf(),
            language: Language::Env,
            lines: count_lines(source),
            hash: hash_source(source),
        };
        store.files.insert(path.to_path_buf(), file_info);

        let source_str = std::str::from_utf8(source)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in env file: {e}"))?;

        parse_env_vars(path, source_str, store);

        Ok(())
    }
}

fn env_kv_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Match optional `export` prefix, then KEY=VALUE.
        Regex::new(r#"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)"#).unwrap()
    })
}

fn parse_env_vars(path: &Path, source: &str, store: &IndexStore) {
    let kv_re = env_kv_re();

    for line in source.lines() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(cap) = kv_re.captures(trimmed) {
            if let Some(key) = cap.get(1) {
                let var_name = key.as_str().to_string();

                let config = EnvConfig {
                    var_name: var_name.clone(),
                    source_file: path.to_path_buf(),
                    source_type: EnvSourceType::DotEnv,
                };

                store.env_configs.entry(var_name).or_default().push(config);
            }
        }
    }
}
