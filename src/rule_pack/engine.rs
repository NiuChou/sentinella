use super::schema::{DataSourceRule, ProtectionEvidenceRule, RulePack, RuleType};
use crate::evidence::{Evidence, EvidenceScope, EvidenceStore};
use regex::Regex;
use std::path::Path;

/// Execute all regex-based protection and data-source evidence rules
/// from loaded rule packs against a source file.
pub fn execute_protection_rules(
    packs: &[RulePack],
    file_path: &Path,
    source: &str,
    evidence_store: &EvidenceStore,
) {
    let file_ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");

    for pack in packs {
        if !pack_applies_to_extension(&pack.languages, file_ext) {
            continue;
        }

        for rule in &pack.protection_evidence {
            execute_protection_rule(rule, &pack.name, file_path, source, evidence_store);
        }

        for rule in &pack.data_source_evidence {
            execute_data_source_rule(rule, &pack.name, file_path, source, evidence_store);
        }
    }
}

fn execute_protection_rule(
    rule: &ProtectionEvidenceRule,
    pack_name: &str,
    file_path: &Path,
    source: &str,
    evidence_store: &EvidenceStore,
) {
    if rule.rule_type != RuleType::Regex {
        return; // Tree-sitter rules handled by existing parsers
    }

    let pattern = match rule.pattern {
        Some(ref p) => p,
        None => return,
    };

    let re = match Regex::new(pattern) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[WARN] Invalid regex in rule '{}': {}", rule.name, e);
            return;
        }
    };

    let total_lines = source.lines().count();

    for (line_idx, line) in source.lines().enumerate() {
        if !re.is_match(line) {
            continue;
        }
        if !check_match_condition(line, &rule.match_condition) {
            continue;
        }

        let scope = rule.scope.unwrap_or(EvidenceScope::Function);
        let (line_start, line_end) = compute_scope_range(line_idx + 1, scope, total_lines);

        evidence_store.add(Evidence {
            kind: rule.provides.kind,
            confidence: rule.provides.confidence,
            source: format!("{}:{}", pack_name, rule.name),
            file: file_path.to_path_buf(),
            line_start,
            line_end,
            scope,
        });
    }
}

fn execute_data_source_rule(
    rule: &DataSourceRule,
    pack_name: &str,
    file_path: &Path,
    source: &str,
    evidence_store: &EvidenceStore,
) {
    if rule.rule_type != RuleType::Regex {
        return;
    }

    let pattern = match rule.pattern {
        Some(ref p) => p,
        None => return,
    };

    let re = match Regex::new(pattern) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "[WARN] Invalid regex in data source rule '{}': {}",
                rule.name, e
            );
            return;
        }
    };

    for (line_idx, line) in source.lines().enumerate() {
        if re.is_match(line) {
            evidence_store.add(Evidence {
                kind: rule.provides.kind,
                confidence: rule.provides.confidence,
                source: format!("{}:{}", pack_name, rule.name),
                file: file_path.to_path_buf(),
                line_start: line_idx + 1,
                line_end: line_idx + 1,
                scope: EvidenceScope::Function,
            });
        }
    }
}

/// Check if a rule pack applies to a file extension
fn pack_applies_to_extension(languages: &[String], ext: &str) -> bool {
    let ext_to_lang: &[(&str, &str)] = &[
        ("ts", "typescript"),
        ("tsx", "typescript"),
        ("js", "javascript"),
        ("jsx", "javascript"),
        ("py", "python"),
        ("go", "go"),
        ("rs", "rust"),
        ("rb", "ruby"),
        ("java", "java"),
        ("kt", "kotlin"),
        ("php", "php"),
    ];

    for (file_ext, lang) in ext_to_lang {
        if *file_ext == ext && languages.iter().any(|l| l == lang) {
            return true;
        }
    }
    false
}

/// Check optional match conditions (keyword matching)
fn check_match_condition(line: &str, condition: &Option<super::schema::MatchCondition>) -> bool {
    let cond = match condition {
        None => return true,
        Some(c) => c,
    };

    let line_lower = line.to_lowercase();

    if !cond.keywords.is_empty() {
        return cond
            .keywords
            .iter()
            .any(|kw| line_lower.contains(&kw.to_lowercase()));
    }

    if !cond.auth_func_keywords.is_empty() {
        return cond
            .auth_func_keywords
            .iter()
            .any(|kw| line_lower.contains(&kw.to_lowercase()));
    }

    if !cond.auth_class_keywords.is_empty() {
        return cond
            .auth_class_keywords
            .iter()
            .any(|kw| line_lower.contains(&kw.to_lowercase()));
    }

    true
}

/// Compute scope range based on EvidenceScope.
/// For regex-based rules, we approximate scope by line count.
fn compute_scope_range(
    match_line: usize,
    scope: EvidenceScope,
    total_lines: usize,
) -> (usize, usize) {
    match scope {
        EvidenceScope::Function => {
            let start = match_line.saturating_sub(5).max(1);
            let end = (match_line + 30).min(total_lines);
            (start, end)
        }
        EvidenceScope::Class => {
            let start = match_line.saturating_sub(5).max(1);
            let end = (match_line + 200).min(total_lines);
            (start, end)
        }
        EvidenceScope::File | EvidenceScope::Module => (1, total_lines),
        EvidenceScope::Block => {
            let start = match_line.saturating_sub(2).max(1);
            let end = (match_line + 50).min(total_lines);
            (start, end)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceKind;
    use crate::rule_pack::schema::{ProvidesConfig, RuleType};

    fn make_test_pack(pattern: &str, kind: EvidenceKind) -> RulePack {
        RulePack {
            kind: "rule-pack".into(),
            name: "test".into(),
            version: "0.1".into(),
            languages: vec!["typescript".into()],
            detect: Default::default(),
            routes: vec![],
            protection_evidence: vec![ProtectionEvidenceRule {
                name: "test-rule".into(),
                description: None,
                scope: Some(EvidenceScope::Function),
                rule_type: RuleType::Regex,
                query: None,
                pattern: Some(pattern.into()),
                match_condition: None,
                provides: ProvidesConfig {
                    kind,
                    confidence: 0.8,
                    scope_extends_to: None,
                },
            }],
            data_source_evidence: vec![],
            error_handling: Default::default(),
            sensitive_logging: Default::default(),
        }
    }

    #[test]
    fn test_regex_rule_matches() {
        let store = EvidenceStore::new();
        let pack = make_test_pack(r"@UseGuards\(AuthGuard\)", EvidenceKind::Auth);
        let source = r#"
import { Controller } from '@nestjs/common';
@UseGuards(AuthGuard)
export class MyController {}
"#;
        execute_protection_rules(&[pack], Path::new("src/app.controller.ts"), source, &store);
        let evidence = store.snapshot();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].kind, EvidenceKind::Auth);
    }

    #[test]
    fn test_no_match_wrong_extension() {
        let store = EvidenceStore::new();
        let pack = make_test_pack(r"@UseGuards", EvidenceKind::Auth);
        let source = "@UseGuards(AuthGuard)";
        execute_protection_rules(&[pack], Path::new("src/app.py"), source, &store);
        assert!(store.is_empty(), "Should not match .py for typescript pack");
    }

    #[test]
    fn test_match_condition_keywords() {
        let cond = Some(super::super::schema::MatchCondition {
            keywords: vec!["auth".into(), "jwt".into()],
            auth_func_keywords: vec![],
            auth_class_keywords: vec![],
        });
        assert!(check_match_condition("UseGuards(AuthGuard)", &cond));
        assert!(!check_match_condition("UseGuards(LoggingGuard)", &cond));
    }

    #[test]
    fn test_pack_applies_to_extension() {
        let langs = vec!["typescript".to_string()];
        assert!(pack_applies_to_extension(&langs, "ts"));
        assert!(pack_applies_to_extension(&langs, "tsx"));
        assert!(!pack_applies_to_extension(&langs, "py"));
        assert!(!pack_applies_to_extension(&langs, "go"));
    }

    #[test]
    fn test_compute_scope_range_function() {
        let (start, end) = compute_scope_range(10, EvidenceScope::Function, 100);
        assert_eq!(start, 5);
        assert_eq!(end, 40);
    }

    #[test]
    fn test_compute_scope_range_file() {
        let (start, end) = compute_scope_range(10, EvidenceScope::File, 100);
        assert_eq!(start, 1);
        assert_eq!(end, 100);
    }

    #[test]
    fn test_compute_scope_range_edge_start() {
        let (start, end) = compute_scope_range(1, EvidenceScope::Function, 100);
        assert_eq!(start, 1);
        assert_eq!(end, 31);
    }
}
