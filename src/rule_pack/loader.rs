use std::path::{Path, PathBuf};

use miette::{Context, IntoDiagnostic, Result};

use super::schema::{LoadedPack, PackSource, RulePack};
use super::validator::{format_validation_report, validate_rule_pack, IssueLevel};

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
    let user_dir = resolve_user_rules_dir();
    let community_dir = user_dir.as_ref().map(|d| d.join(COMMUNITY_SUBDIR));

    let project_packs = load_packs_from_dir(&project_dir, PackSource::Project);
    let user_packs = load_packs_from_dir_opt(user_dir.as_deref(), PackSource::User);
    let community_packs = load_packs_from_dir_opt(community_dir.as_deref(), PackSource::Community);

    let all_packs = merge_packs_by_priority(vec![
        project_packs,
        user_packs,
        community_packs,
        // builtin packs would go here when we embed them via include_str!
    ]);

    let validated = validate_loaded_packs(all_packs, verbose);
    Ok(validated)
}

/// Load a single rule pack from a YAML file.
pub fn load_pack_file(path: &Path, source: PackSource) -> Result<LoadedPack> {
    let contents = std::fs::read_to_string(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read rule pack: {}", path.display()))?;

    let pack: RulePack = serde_yaml::from_str(&contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to parse rule pack: {}", path.display()))?;

    let loaded = LoadedPack {
        pack: RulePack {
            source: Some(source),
            ..pack
        },
        source,
    };
    Ok(loaded)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn resolve_user_rules_dir() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(USER_RULES_DIR))
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

fn is_yaml_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| RULE_PACK_EXTENSIONS.contains(&ext))
        .unwrap_or(false)
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

    fn sample_pack_yaml(name: &str) -> String {
        format!(
            r#"
name: {name}
version: "1.0"
languages: [rust]
protection_evidence:
  - name: auth_check
    pattern: "fn authenticate"
    kind: protection
    confidence: 0.9
"#
        )
    }

    #[test]
    fn load_pack_file_parses_valid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.yaml");
        fs::write(&path, sample_pack_yaml("test-pack")).unwrap();

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
        fs::write(dir.path().join("a.yaml"), sample_pack_yaml("alpha")).unwrap();
        fs::write(dir.path().join("b.yml"), sample_pack_yaml("beta")).unwrap();
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
        let mk = |name: &str, src: PackSource| LoadedPack {
            pack: RulePack {
                name: name.into(),
                version: "1.0".into(),
                description: None,
                languages: vec![],
                protection_evidence: vec![],
                data_source_evidence: vec![],
                source: Some(src),
            },
            source: src,
        };

        let tier1 = vec![mk("shared", PackSource::Project)];
        let tier2 = vec![mk("shared", PackSource::User), mk("extra", PackSource::User)];

        let merged = merge_packs_by_priority(vec![tier1, tier2]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].source, PackSource::Project);
        assert_eq!(merged[1].pack.name, "extra");
    }

    #[test]
    fn load_all_packs_returns_empty_for_empty_project() {
        let dir = tempfile::tempdir().unwrap();
        let packs = load_all_packs(dir.path(), false).unwrap();
        // No rule pack dirs exist, so we get an empty list
        assert!(packs.is_empty());
    }

    #[test]
    fn is_yaml_file_checks_extensions() {
        assert!(is_yaml_file(Path::new("rules.yaml")));
        assert!(is_yaml_file(Path::new("rules.yml")));
        assert!(!is_yaml_file(Path::new("rules.json")));
        assert!(!is_yaml_file(Path::new("rules")));
    }
}
