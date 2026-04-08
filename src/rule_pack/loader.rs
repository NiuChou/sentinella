use super::schema::{LoadedPack, PackSource, RulePack};
use super::validator::{format_validation_report, validate_rule_pack, IssueLevel};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const RULE_PACK_EXTENSIONS: &[&str] = &["yaml", "yml"];
const PROJECT_RULES_DIR: &str = ".sentinella/rules";
const USER_RULES_DIR: &str = ".sentinella/rules";
const COMMUNITY_SUBDIR: &str = "community";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load all rule packs using 4-tier priority:
/// project > user > community > builtin.
///
/// Packs loaded earlier (higher priority) shadow packs with the same name
/// from lower-priority sources.
pub fn load_all_packs(project_root: &Path, verbose: bool) -> Result<Vec<LoadedPack>> {
    let project_dir = project_root.join(PROJECT_RULES_DIR);
    let user_dir = home_dir().map(|h| h.join(USER_RULES_DIR));
    let community_dir = user_dir.as_ref().map(|d| d.join(COMMUNITY_SUBDIR));

    let project_packs = load_packs_from_dir(&project_dir, PackSource::Project);
    let user_packs = load_packs_from_dir_opt(user_dir.as_deref(), PackSource::User);
    let community_packs = load_packs_from_dir_opt(community_dir.as_deref(), PackSource::Community);
    let builtin_packs = load_builtin_loaded_packs();

    let all_packs = merge_packs_by_priority(vec![
        project_packs,
        user_packs,
        community_packs,
        builtin_packs,
    ]);

    let validated = validate_loaded_packs(all_packs, verbose);
    Ok(validated)
}

/// Load a single rule pack from a YAML file (legacy API).
pub fn load_rule_pack(path: &Path) -> Result<RulePack> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read rule pack: {}", path.display()))?;
    let pack: RulePack = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse rule pack: {}", path.display()))?;

    if pack.kind != "rule-pack" {
        anyhow::bail!(
            "Invalid rule pack kind: {} (expected 'rule-pack')",
            pack.kind
        );
    }

    Ok(pack)
}

/// Load a single rule pack from a YAML file, returning a LoadedPack.
pub fn load_pack_file(path: &Path, source: PackSource) -> Result<LoadedPack> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read rule pack: {}", path.display()))?;
    let pack: RulePack = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse rule pack: {}", path.display()))?;

    let loaded = LoadedPack {
        pack: RulePack {
            source: Some(source),
            ..pack
        },
        source,
    };
    Ok(loaded)
}

/// Load all rule packs from a directory (non-recursive, legacy API)
pub fn load_rule_packs_from_dir(dir: &Path) -> Result<Vec<RulePack>> {
    let mut packs = Vec::new();
    if !dir.exists() {
        return Ok(packs);
    }

    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read rule pack directory: {}", dir.display()))?;

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if is_yaml_file(&path) {
            match load_rule_pack(&path) {
                Ok(pack) => packs.push(pack),
                Err(e) => {
                    eprintln!("[WARN] Failed to load rule pack {}: {}", path.display(), e)
                }
            }
        }
    }

    Ok(packs)
}

/// Resolve all rule packs in priority order (legacy API):
/// 1. Project-level (.sentinella/rules/)
/// 2. Global user-level (~/.sentinella/rules/)
/// 3. Built-in (embedded in binary)
pub fn resolve_rule_packs(project_root: &Path) -> Result<Vec<RulePack>> {
    let mut all_packs = Vec::new();

    // 1. Project-level (highest priority)
    let project_rules = project_root.join(".sentinella").join("rules");
    if project_rules.exists() {
        let packs = load_rule_packs_from_dir(&project_rules)?;
        all_packs.extend(packs);
    }

    // 2. User-level global
    if let Some(home) = home_dir() {
        let global_rules = home.join(".sentinella").join("rules");
        if global_rules.exists() {
            let packs = load_rule_packs_from_dir(&global_rules)?;
            for pack in packs {
                if !all_packs.iter().any(|p: &RulePack| p.name == pack.name) {
                    all_packs.push(pack);
                }
            }
        }
    }

    // 3. Built-in rule packs (embedded in binary)
    let builtins = load_builtin_rule_packs();
    for pack in builtins {
        if !all_packs.iter().any(|p: &RulePack| p.name == pack.name) {
            all_packs.push(pack);
        }
    }

    Ok(all_packs)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Get home directory path
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("USERPROFILE").ok().map(PathBuf::from))
}

fn is_yaml_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| RULE_PACK_EXTENSIONS.contains(&ext))
        .unwrap_or(false)
}

fn load_packs_from_dir_opt(dir: Option<&Path>, source: PackSource) -> Vec<LoadedPack> {
    match dir {
        Some(d) => load_packs_from_dir(d, source),
        None => Vec::new(),
    }
}

fn load_packs_from_dir(dir: &Path, source: PackSource) -> Vec<LoadedPack> {
    if !dir.is_dir() {
        return Vec::new();
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    entries
        .flatten()
        .filter(|e| is_yaml_file(&e.path()))
        .filter_map(|e| load_pack_file(&e.path(), source).ok())
        .collect()
}

/// Load built-in rule packs embedded in the binary
fn load_builtin_rule_packs() -> Vec<RulePack> {
    let mut packs = Vec::new();

    let builtin_yamls: &[(&str, &str)] = &[
        ("nestjs", include_str!("../../rules/builtin/nestjs.yaml")),
        ("express", include_str!("../../rules/builtin/express.yaml")),
        ("fastapi", include_str!("../../rules/builtin/fastapi.yaml")),
        ("gin", include_str!("../../rules/builtin/gin.yaml")),
        ("django", include_str!("../../rules/builtin/django.yaml")),
        ("flask", include_str!("../../rules/builtin/flask.yaml")),
        (
            "spring-boot",
            include_str!("../../rules/builtin/spring-boot.yaml"),
        ),
        ("rails", include_str!("../../rules/builtin/rails.yaml")),
        ("laravel", include_str!("../../rules/builtin/laravel.yaml")),
        ("echo", include_str!("../../rules/builtin/echo.yaml")),
        ("chi", include_str!("../../rules/builtin/chi.yaml")),
        ("actix", include_str!("../../rules/builtin/actix.yaml")),
        ("axum", include_str!("../../rules/builtin/axum.yaml")),
    ];

    for (name, yaml) in builtin_yamls {
        match serde_yaml::from_str::<RulePack>(yaml) {
            Ok(pack) => packs.push(pack),
            Err(e) => {
                eprintln!(
                    "[WARN] Failed to parse built-in rule pack '{}': {}",
                    name, e
                )
            }
        }
    }

    packs
}

/// Load built-in rule packs as LoadedPack wrappers
fn load_builtin_loaded_packs() -> Vec<LoadedPack> {
    load_builtin_rule_packs()
        .into_iter()
        .map(|pack| LoadedPack {
            pack: RulePack {
                source: Some(PackSource::Builtin),
                ..pack
            },
            source: PackSource::Builtin,
        })
        .collect()
}

/// Merge packs from multiple tiers. Earlier tiers have higher priority.
/// If two packs share the same name, only the higher-priority one is kept.
fn merge_packs_by_priority(tiers: Vec<Vec<LoadedPack>>) -> Vec<LoadedPack> {
    let mut seen_names: Vec<String> = Vec::new();
    let mut result: Vec<LoadedPack> = Vec::new();

    for tier in tiers {
        for pack in tier {
            let name = pack.pack.name.to_lowercase();
            if !seen_names.contains(&name) {
                seen_names.push(name);
                result.push(pack);
            }
        }
    }
    result
}

/// Validate each pack, printing issues to stderr. Error-level issues are
/// reported but do not prevent loading (fault-tolerant).
fn validate_loaded_packs(packs: Vec<LoadedPack>, verbose: bool) -> Vec<LoadedPack> {
    packs
        .into_iter()
        .map(|lp| {
            let issues = validate_rule_pack(&lp.pack);
            let has_errors = issues.iter().any(|i| i.level == IssueLevel::Error);
            let has_warnings = issues.iter().any(|i| i.level == IssueLevel::Warning);

            if has_errors {
                let report = format_validation_report(&issues);
                eprintln!(
                    "[warn] rule pack '{}' ({}) has validation errors:\n{}",
                    lp.pack.name, lp.source, report,
                );
            } else if has_warnings && verbose {
                let report = format_validation_report(&issues);
                eprintln!(
                    "[info] rule pack '{}' ({}) warnings:\n{}",
                    lp.pack.name, lp.source, report,
                );
            }
            lp
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_load_builtin_packs() {
        let packs = load_builtin_rule_packs();
        assert!(!packs.is_empty(), "Should load at least one built-in pack");
        for pack in &packs {
            assert_eq!(pack.kind, "rule-pack");
        }
    }

    #[test]
    fn test_load_single_rule_pack() {
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("test.yaml");

        let yaml_content = r#"
kind: rule-pack
name: test-pack
version: "0.1"
languages: [typescript]
routes: []
protection_evidence: []
data_source_evidence: []
"#;
        let mut file = std::fs::File::create(&yaml_path).unwrap();
        file.write_all(yaml_content.as_bytes()).unwrap();

        let pack = load_rule_pack(&yaml_path).unwrap();
        assert_eq!(pack.name, "test-pack");
        assert_eq!(pack.languages, vec!["typescript"]);
    }

    #[test]
    fn test_load_invalid_kind_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let yaml_path = dir.path().join("bad.yaml");

        let yaml_content = r#"
kind: not-a-rule-pack
name: bad
version: "0.1"
languages: []
"#;
        let mut file = std::fs::File::create(&yaml_path).unwrap();
        file.write_all(yaml_content.as_bytes()).unwrap();

        let result = load_rule_pack(&yaml_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let packs = load_rule_packs_from_dir(dir.path()).unwrap();
        assert!(packs.is_empty());
    }

    #[test]
    fn test_load_from_nonexistent_dir() {
        let packs = load_rule_packs_from_dir(Path::new("/nonexistent/path")).unwrap();
        assert!(packs.is_empty());
    }

    #[test]
    fn load_pack_file_parses_valid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yaml");
        fs::write(
            &path,
            r#"
kind: rule-pack
name: test-pack
version: "1.0"
languages: [rust]
protection_evidence: []
data_source_evidence: []
"#,
        )
        .unwrap();

        let loaded = load_pack_file(&path, PackSource::User).unwrap();
        assert_eq!(loaded.pack.name, "test-pack");
        assert_eq!(loaded.source, PackSource::User);
        assert_eq!(loaded.pack.source, Some(PackSource::User));
    }

    #[test]
    fn load_pack_file_fails_on_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.yaml");
        fs::write(&path, "not: [valid: {{").unwrap();

        assert!(load_pack_file(&path, PackSource::User).is_err());
    }

    #[test]
    fn load_packs_from_dir_finds_yaml_files() {
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
kind: rule-pack
name: alpha
version: "1.0"
languages: [rust]
"#;
        let yaml2 = r#"
kind: rule-pack
name: beta
version: "1.0"
languages: [rust]
"#;
        fs::write(dir.path().join("a.yaml"), yaml).unwrap();
        fs::write(dir.path().join("b.yml"), yaml2).unwrap();
        fs::write(dir.path().join("c.txt"), "ignored").unwrap();

        let packs = load_packs_from_dir(dir.path(), PackSource::Community);
        assert_eq!(packs.len(), 2);
        assert!(packs.iter().all(|p| p.source == PackSource::Community));
    }

    #[test]
    fn load_packs_from_dir_returns_empty_for_missing_dir() {
        let packs = load_packs_from_dir(Path::new("/nonexistent_dir_xyz"), PackSource::Builtin);
        assert!(packs.is_empty());
    }

    #[test]
    fn merge_packs_higher_priority_wins() {
        let mk = |name: &str, src: PackSource| {
            let pack = RulePack {
                kind: "rule-pack".into(),
                name: name.into(),
                version: "1.0".into(),
                languages: vec![],
                detect: Default::default(),
                routes: vec![],
                protection_evidence: vec![],
                data_source_evidence: vec![],
                error_handling: Default::default(),
                sensitive_logging: Default::default(),
                description: None,
                source: Some(src),
            };
            LoadedPack { pack, source: src }
        };

        let tier1 = vec![mk("shared", PackSource::Project)];
        let tier2 = vec![mk("shared", PackSource::User), mk("extra", PackSource::User)];

        let merged = merge_packs_by_priority(vec![tier1, tier2]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].source, PackSource::Project);
        assert_eq!(merged[1].pack.name, "extra");
    }

    #[test]
    fn load_all_packs_returns_builtins_for_empty_project() {
        let dir = tempfile::tempdir().unwrap();
        let packs = load_all_packs(dir.path(), false).unwrap();
        // Should at least contain built-in packs
        assert!(!packs.is_empty());
    }

    #[test]
    fn is_yaml_file_checks_extensions() {
        assert!(is_yaml_file(Path::new("rules.yaml")));
        assert!(is_yaml_file(Path::new("rules.yml")));
        assert!(!is_yaml_file(Path::new("rules.json")));
        assert!(!is_yaml_file(Path::new("rules")));
    }
}
