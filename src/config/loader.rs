use std::path::{Path, PathBuf};

use miette::{Context, IntoDiagnostic, Result};

use super::schema::Config;

/// Ordered list of config file names to search for.
const CONFIG_FILE_NAMES: &[&str] = &[
    ".sentinella.yaml",
    ".sentinella.yml",
    "sentinella.yaml",
    "sentinella.yml",
];

/// Search for the first matching config file in `base_dir`.
pub fn find_config_file(base_dir: &Path) -> Option<PathBuf> {
    CONFIG_FILE_NAMES
        .iter()
        .map(|name| base_dir.join(name))
        .find(|path| path.is_file())
}

/// Load and parse a Sentinella config from an explicit path.
pub fn load_config(path: &Path) -> Result<Config> {
    let contents = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read config file: {}", path.display()))?;

    let config: Config = serde_yaml::from_str(&contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to parse config file: {}", path.display()))?;

    Ok(config)
}

/// Load a config from an explicit path, or auto-discover in `base_dir`.
///
/// When `explicit_path` is `Some`, it is used directly. Otherwise we search
/// `base_dir` for the first matching candidate file name.
pub fn load_config_auto(explicit_path: Option<&Path>, base_dir: &Path) -> Result<Config> {
    match explicit_path {
        Some(path) => load_config(path),
        None => load_config_from_dir(base_dir),
    }
}

/// Locate and load a config file from `base_dir`, trying each candidate name.
pub fn load_config_from_dir(base_dir: &Path) -> Result<Config> {
    let path = find_config_file(base_dir).ok_or_else(|| {
        miette::miette!(
            help = "Create one with `sentinella init`",
            "no config file found in {}.\nSearched for: {}",
            base_dir.display(),
            CONFIG_FILE_NAMES.join(", "),
        )
    })?;

    load_config(&path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_config_file_discovers_sentinella_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".sentinella.yaml");
        std::fs::write(&config_path, "version: '1.0'\nproject: test\n").unwrap();

        let found = find_config_file(dir.path());
        assert_eq!(found, Some(config_path));
    }

    #[test]
    fn find_config_file_discovers_sentinella_yml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".sentinella.yml");
        std::fs::write(&config_path, "version: '1.0'\nproject: test\n").unwrap();

        let found = find_config_file(dir.path());
        assert_eq!(found, Some(config_path));
    }

    #[test]
    fn find_config_file_returns_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let found = find_config_file(dir.path());
        assert_eq!(found, None);
    }

    #[test]
    fn find_config_file_prefers_dot_yaml_over_yml() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".sentinella.yaml"),
            "version: '1.0'\nproject: first\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join(".sentinella.yml"),
            "version: '1.0'\nproject: second\n",
        )
        .unwrap();

        let found = find_config_file(dir.path()).unwrap();
        assert!(
            found.to_string_lossy().ends_with(".sentinella.yaml"),
            "Should prefer .yaml over .yml"
        );
    }

    #[test]
    fn load_config_parses_valid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".sentinella.yaml");
        let content = r#"
version: "1.0"
project: my-app
type: fullstack
layers:
  backend:
    pattern: "src/**/*.rs"
output:
  format: terminal
  min_coverage: 80
  severity: warning
"#;
        std::fs::write(&config_path, content).unwrap();

        let config = load_config(&config_path).unwrap();
        assert_eq!(config.project, "my-app");
        assert!(config.layers.contains_key("backend"));
    }

    #[test]
    fn load_config_fails_on_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".sentinella.yaml");
        std::fs::write(&config_path, "not: [valid: yaml: {{").unwrap();

        let result = load_config(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn load_config_fails_on_missing_file() {
        let missing = PathBuf::from("/tmp/nonexistent_sentinella_test.yaml");
        let result = load_config(&missing);
        assert!(result.is_err());
    }

    #[test]
    fn load_config_auto_uses_explicit_path() {
        let dir = tempfile::tempdir().unwrap();
        let explicit = dir.path().join("custom.yaml");
        std::fs::write(&explicit, "version: '1.0'\nproject: custom\n").unwrap();

        let config = load_config_auto(Some(explicit.as_path()), dir.path()).unwrap();
        assert_eq!(config.project, "custom");
    }

    #[test]
    fn load_config_auto_discovers_in_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".sentinella.yaml"),
            "version: '1.0'\nproject: discovered\n",
        )
        .unwrap();

        let config = load_config_auto(None, dir.path()).unwrap();
        assert_eq!(config.project, "discovered");
    }
}
