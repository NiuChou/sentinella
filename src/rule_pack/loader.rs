use super::schema::RulePack;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Load all rule packs from a directory (non-recursive)
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
        if path
            .extension()
            .map_or(false, |ext| ext == "yaml" || ext == "yml")
        {
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

/// Load a single rule pack from a YAML file
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

/// Resolve all rule packs in priority order:
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

/// Load built-in rule packs embedded in the binary
fn load_builtin_rule_packs() -> Vec<RulePack> {
    let mut packs = Vec::new();

    let builtin_yamls: &[(&str, &str)] = &[
        ("nestjs", include_str!("../../rules/builtin/nestjs.yaml")),
        ("express", include_str!("../../rules/builtin/express.yaml")),
        ("fastapi", include_str!("../../rules/builtin/fastapi.yaml")),
        ("gin", include_str!("../../rules/builtin/gin.yaml")),
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

/// Get home directory path
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME")
        .ok()
        .map(PathBuf::from)
        .or_else(|| std::env::var("USERPROFILE").ok().map(PathBuf::from))
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
