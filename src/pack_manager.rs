use std::fmt;
use std::path::{Path, PathBuf};

use crate::rule_pack::schema::RulePack;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackSource {
    Builtin,
    User,
    Project,
    Community,
}

impl fmt::Display for PackSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackSource::Builtin => write!(f, "builtin"),
            PackSource::User => write!(f, "user"),
            PackSource::Project => write!(f, "project"),
            PackSource::Community => write!(f, "community"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackInfo {
    pub name: String,
    pub version: String,
    pub source: PackSource,
    pub languages: Vec<String>,
    pub rule_count: usize,
    pub lifecycle_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationSeverity {
    Error,
    Warning,
}

impl fmt::Display for ValidationSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationSeverity::Error => write!(f, "ERROR"),
            ValidationSeverity::Warning => write!(f, "WARNING"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
    pub severity: ValidationSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallScope {
    User,
    Project,
}

// ---------------------------------------------------------------------------
// list_packs — scan user and project directories
// ---------------------------------------------------------------------------

pub fn list_packs(root_dir: &Path) -> Vec<PackInfo> {
    let mut packs = Vec::new();

    let user_dir = user_rules_dir();
    collect_packs_from_dir(&user_dir, PackSource::User, &mut packs);

    let project_dir = root_dir.join(".sentinella").join("rules");
    collect_packs_from_dir(&project_dir, PackSource::Project, &mut packs);

    packs
}

fn user_rules_dir() -> PathBuf {
    dirs_home().join(".sentinella").join("rules")
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn collect_packs_from_dir(dir: &Path, source: PackSource, packs: &mut Vec<PackInfo>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if is_yaml_file(&path) {
            if let Some(info) = load_pack_info(&path, source.clone()) {
                packs.push(info);
            }
        }
    }
}

fn is_yaml_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml" | "yml")
    )
}

fn load_pack_info(path: &Path, source: PackSource) -> Option<PackInfo> {
    let content = std::fs::read_to_string(path).ok()?;
    let pack: RulePack = serde_yaml::from_str(&content).ok()?;
    let rule_count = pack.protection_evidence.len() + pack.data_source_evidence.len();
    let summary = format!(
        "{} protection, {} data-source",
        pack.protection_evidence.len(),
        pack.data_source_evidence.len()
    );
    Some(PackInfo {
        name: pack.name,
        version: pack.version,
        source,
        languages: pack.languages,
        rule_count,
        lifecycle_summary: summary,
    })
}

// ---------------------------------------------------------------------------
// validate_pack — structural + regex validation
// ---------------------------------------------------------------------------

pub fn validate_pack(path: &Path) -> Vec<ValidationError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            return vec![ValidationError {
                field: "file".to_string(),
                message: format!("cannot read file: {e}"),
                severity: ValidationSeverity::Error,
            }];
        }
    };

    validate_pack_content(&content)
}

pub fn validate_pack_content(content: &str) -> Vec<ValidationError> {
    let pack: RulePack = match serde_yaml::from_str(content) {
        Ok(p) => p,
        Err(e) => {
            return vec![ValidationError {
                field: "yaml".to_string(),
                message: format!("invalid YAML: {e}"),
                severity: ValidationSeverity::Error,
            }];
        }
    };

    let mut errors = Vec::new();
    validate_pack_metadata(&pack, &mut errors);
    validate_pack_rules(&pack, &mut errors);
    errors
}

fn validate_pack_metadata(pack: &RulePack, errors: &mut Vec<ValidationError>) {
    if pack.name.trim().is_empty() {
        errors.push(ValidationError {
            field: "name".to_string(),
            message: "pack name must not be empty".to_string(),
            severity: ValidationSeverity::Error,
        });
    }
    if pack.version.trim().is_empty() {
        errors.push(ValidationError {
            field: "version".to_string(),
            message: "pack version must not be empty".to_string(),
            severity: ValidationSeverity::Error,
        });
    }
    if pack.protection_evidence.is_empty() && pack.data_source_evidence.is_empty() {
        errors.push(ValidationError {
            field: "rules".to_string(),
            message: "pack must contain at least one rule".to_string(),
            severity: ValidationSeverity::Error,
        });
    }
}

fn validate_pack_rules(pack: &RulePack, errors: &mut Vec<ValidationError>) {
    for (i, rule) in pack.protection_evidence.iter().enumerate() {
        let prefix = format!("protection_evidence[{}]", i);
        if let Some(ref pat) = rule.pattern {
            validate_regex(pat, &prefix, errors);
        }
    }
    for (i, rule) in pack.data_source_evidence.iter().enumerate() {
        let prefix = format!("data_source_evidence[{}]", i);
        if let Some(ref pat) = rule.pattern {
            validate_regex(pat, &prefix, errors);
        }
    }
}

fn validate_regex(pattern: &str, prefix: &str, errors: &mut Vec<ValidationError>) {
    if pattern.trim().is_empty() {
        errors.push(ValidationError {
            field: format!("{prefix}.pattern"),
            message: "pattern must not be empty".to_string(),
            severity: ValidationSeverity::Error,
        });
    } else if regex::Regex::new(pattern).is_err() {
        errors.push(ValidationError {
            field: format!("{prefix}.pattern"),
            message: format!("invalid regex: {pattern}"),
            severity: ValidationSeverity::Error,
        });
    }
}

// ---------------------------------------------------------------------------
// install_pack — validate then copy to target scope
// ---------------------------------------------------------------------------

pub fn install_pack(
    source_path: &Path,
    target_dir: &Path,
    scope: InstallScope,
) -> Result<String, String> {
    let errors = validate_pack(source_path);
    let has_error = errors
        .iter()
        .any(|e| e.severity == ValidationSeverity::Error);
    if has_error {
        let msgs: Vec<String> = errors
            .iter()
            .filter(|e| e.severity == ValidationSeverity::Error)
            .map(|e| format!("[{}] {}: {}", e.severity, e.field, e.message))
            .collect();
        return Err(format!("validation failed:\n{}", msgs.join("\n")));
    }

    let dest_dir = resolve_install_dir(target_dir, &scope);
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("cannot create directory {}: {e}", dest_dir.display()))?;

    let file_name = source_path
        .file_name()
        .ok_or_else(|| "source path has no file name".to_string())?;

    let dest_file = dest_dir.join(file_name);
    if dest_file.exists() {
        return Err(format!(
            "pack already exists at {}; remove it first to reinstall",
            dest_file.display()
        ));
    }

    std::fs::copy(source_path, &dest_file).map_err(|e| format!("failed to copy: {e}"))?;

    Ok(format!("installed to {}", dest_file.display()))
}

fn resolve_install_dir(target_dir: &Path, scope: &InstallScope) -> PathBuf {
    match scope {
        InstallScope::User => user_rules_dir(),
        InstallScope::Project => target_dir.join(".sentinella").join("rules"),
    }
}

// ---------------------------------------------------------------------------
// format_pack_list — tabular output
// ---------------------------------------------------------------------------

pub fn format_pack_list(packs: &[PackInfo]) -> String {
    if packs.is_empty() {
        return "No rule packs found.".to_string();
    }

    let header = format!(
        "{:<25} {:<10} {:<10} {:<20} {:<6} {}",
        "NAME", "VERSION", "SOURCE", "LANGUAGES", "RULES", "SUMMARY"
    );
    let separator = "-".repeat(header.len());

    let rows: Vec<String> = packs
        .iter()
        .map(|p| {
            format!(
                "{:<25} {:<10} {:<10} {:<20} {:<6} {}",
                truncate(&p.name, 24),
                truncate(&p.version, 9),
                p.source,
                truncate(&p.languages.join(", "), 19),
                p.rule_count,
                &p.lifecycle_summary,
            )
        })
        .collect();

    format!("{header}\n{separator}\n{}", rows.join("\n"))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn valid_pack_yaml() -> &'static str {
        r#"
kind: rule-pack
name: test-pack
version: "1.0"
languages: [rust, python]
protection_evidence:
  - name: test-auth
    type: regex
    pattern: '@UseGuards\(AuthGuard\)'
    provides:
      kind: auth
      confidence: 0.9
data_source_evidence:
  - name: test-db
    type: regex
    pattern: 'Repository'
    provides:
      kind: real-data
      confidence: 0.8
"#
    }

    fn write_temp_yaml(content: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn validate_valid_pack_has_no_errors() {
        let errors = validate_pack_content(valid_pack_yaml());
        let hard_errors: Vec<_> = errors
            .iter()
            .filter(|e| e.severity == ValidationSeverity::Error)
            .collect();
        assert!(
            hard_errors.is_empty(),
            "expected no errors: {hard_errors:?}"
        );
    }

    #[test]
    fn validate_empty_name_reports_error() {
        let yaml = r#"
kind: rule-pack
name: ""
version: "1.0"
languages: [rust]
protection_evidence:
  - name: r1
    type: regex
    pattern: "foo"
    provides:
      kind: auth
      confidence: 0.9
"#;
        let errors = validate_pack_content(yaml);
        assert!(errors.iter().any(|e| e.field == "name"));
    }

    #[test]
    fn validate_empty_version_reports_error() {
        let yaml = r#"
kind: rule-pack
name: my-pack
version: ""
languages: [rust]
protection_evidence:
  - name: r1
    type: regex
    pattern: "foo"
    provides:
      kind: auth
      confidence: 0.9
"#;
        let errors = validate_pack_content(yaml);
        assert!(errors.iter().any(|e| e.field == "version"));
    }

    #[test]
    fn validate_no_rules_reports_error() {
        let yaml = r#"
kind: rule-pack
name: my-pack
version: "1.0"
languages: [rust]
"#;
        let errors = validate_pack_content(yaml);
        assert!(errors.iter().any(|e| e.field == "rules"));
    }

    #[test]
    fn validate_invalid_regex_reports_error() {
        let yaml = r#"
kind: rule-pack
name: my-pack
version: "1.0"
languages: [rust]
protection_evidence:
  - name: r1
    type: regex
    pattern: "[invalid("
    provides:
      kind: auth
      confidence: 0.9
"#;
        let errors = validate_pack_content(yaml);
        assert!(errors
            .iter()
            .any(|e| e.field.contains("pattern") && e.severity == ValidationSeverity::Error));
    }

    #[test]
    fn validate_invalid_yaml_reports_error() {
        let errors = validate_pack_content("not: [valid: yaml: {{{");
        assert!(!errors.is_empty());
        assert!(errors[0].field == "yaml");
    }

    #[test]
    fn format_pack_list_empty() {
        let result = format_pack_list(&[]);
        assert_eq!(result, "No rule packs found.");
    }

    #[test]
    fn format_pack_list_has_header_and_rows() {
        let packs = vec![PackInfo {
            name: "my-pack".to_string(),
            version: "1.0".to_string(),
            source: PackSource::User,
            languages: vec!["rust".to_string()],
            rule_count: 3,
            lifecycle_summary: "2 protection, 1 data-source".to_string(),
        }];
        let output = format_pack_list(&packs);
        assert!(output.contains("NAME"));
        assert!(output.contains("my-pack"));
        assert!(output.contains("user"));
    }

    #[test]
    fn install_pack_rejects_invalid_pack() {
        let yaml = r#"
kind: rule-pack
name: ""
version: ""
"#;
        let f = write_temp_yaml(yaml);
        let tmp_dir = tempfile::tempdir().unwrap();
        let result = install_pack(f.path(), tmp_dir.path(), InstallScope::Project);
        assert!(result.is_err());
    }

    #[test]
    fn install_pack_succeeds_for_valid_pack() {
        let f = write_temp_yaml(valid_pack_yaml());
        let tmp_dir = tempfile::tempdir().unwrap();
        let result = install_pack(f.path(), tmp_dir.path(), InstallScope::Project);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn install_pack_rejects_duplicate() {
        let f = write_temp_yaml(valid_pack_yaml());
        let tmp_dir = tempfile::tempdir().unwrap();
        let _ = install_pack(f.path(), tmp_dir.path(), InstallScope::Project);
        let result = install_pack(f.path(), tmp_dir.path(), InstallScope::Project);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[test]
    fn list_packs_returns_empty_for_nonexistent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let packs = list_packs(tmp.path());
        assert!(packs.is_empty());
    }
}
