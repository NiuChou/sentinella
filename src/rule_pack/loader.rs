//! Loads built-in and user-supplied rule packs from YAML.

use super::schema::RulePack;

/// Built-in NestJS rule pack (compiled into the binary).
const NESTJS_YAML: &str = include_str!("../../rules/builtin/nestjs.yaml");

/// Built-in Express rule pack (compiled into the binary).
const EXPRESS_YAML: &str = include_str!("../../rules/builtin/express.yaml");

/// Returns all built-in rule packs shipped with the Sentinella binary.
pub fn builtin_packs() -> Vec<RulePack> {
    [NESTJS_YAML, EXPRESS_YAML]
        .iter()
        .map(|yaml| serde_yaml::from_str(yaml).expect("built-in rule pack YAML is invalid"))
        .collect()
}

/// Parse a rule pack from a user-supplied YAML string.
///
/// # Errors
///
/// Returns a [`serde_yaml::Error`] if the YAML is malformed or does not
/// conform to the [`RulePack`] schema.
pub fn parse_rule_pack(yaml: &str) -> Result<RulePack, serde_yaml::Error> {
    serde_yaml::from_str(yaml)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_packs_load_successfully() {
        let packs = builtin_packs();
        assert_eq!(packs.len(), 2);

        let names: Vec<&str> = packs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"NestJS"));
        assert!(names.contains(&"Express"));
    }

    #[test]
    fn parse_rule_pack_rejects_garbage() {
        let result = parse_rule_pack("not: [valid: rule_pack");
        assert!(result.is_err());
    }
}
