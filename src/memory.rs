// src/memory.rs — Declarative project context that adjusts scanner behavior.
//
// Users describe project characteristics in `.sentinella/memories.yaml`.
// The system parses these into structured effects and uses them to adjust
// finding severity (the codebase's confidence proxy).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::scanners::types::{Finding, ScanResult, Severity};

// ---------------------------------------------------------------------------
// YAML schema types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryFile {
    #[serde(default)]
    pub project: Vec<String>,
    #[serde(default)]
    pub scanners: HashMap<String, Vec<String>>,
    #[serde(default)]
    pub patterns: Vec<PatternMemory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMemory {
    #[serde(rename = "match")]
    pub match_pattern: String,
    pub memory: String,
}

// ---------------------------------------------------------------------------
// Parsed memory effects
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct MemoryEffect {
    pub scope: MemoryScope,
    pub effect: MemoryEffectType,
}

#[derive(Debug, Clone)]
pub enum MemoryScope {
    Project,
    Scanner(String),
    Pattern(String),
}

#[derive(Debug, Clone)]
pub enum MemoryEffectType {
    /// Declares protection exists — downgrade severity for related findings
    ProtectionDeclared {
        scanners: Vec<String>,
        downgrade_to: Severity,
    },
    /// Declares scanner not applicable — suppress findings entirely
    NotApplicable { scanner: String },
    /// Declares a code pattern is safe — downgrade to Info
    SafePattern,
}

// ---------------------------------------------------------------------------
// Memory parser: natural-language memories -> structured effects
// ---------------------------------------------------------------------------

pub fn parse_memory_effects(memories: &MemoryFile) -> Vec<MemoryEffect> {
    let mut effects = Vec::new();

    parse_project_memories(&memories.project, &mut effects);
    parse_scanner_memories(&memories.scanners, &mut effects);
    parse_pattern_memories(&memories.patterns, &mut effects);

    effects
}

fn parse_project_memories(texts: &[String], effects: &mut Vec<MemoryEffect>) {
    for text in texts {
        let lower = text.to_lowercase();

        // Auth-related
        if contains_any(
            &lower,
            &["auth", "\u{8ba4}\u{8bc1}", "guard", "gateway", "jwt"],
        ) {
            effects.push(MemoryEffect {
                scope: MemoryScope::Project,
                effect: MemoryEffectType::ProtectionDeclared {
                    scanners: vec!["S7".into()],
                    downgrade_to: Severity::Info,
                },
            });
        }

        // Soft delete
        if contains_any(
            &lower,
            &[
                "\u{8f6f}\u{5220}\u{9664}",
                "soft delete",
                "soft-delete",
                "deleted_at",
            ],
        ) {
            effects.push(MemoryEffect {
                scope: MemoryScope::Project,
                effect: MemoryEffectType::ProtectionDeclared {
                    scanners: vec!["S13".into(), "S14".into()],
                    downgrade_to: Severity::Info,
                },
            });
        }

        // Rate limiting
        if contains_any(
            &lower,
            &["\u{9650}\u{6d41}", "rate limit", "rate-limit", "throttle"],
        ) {
            effects.push(MemoryEffect {
                scope: MemoryScope::Project,
                effect: MemoryEffectType::ProtectionDeclared {
                    scanners: vec!["S22".into()],
                    downgrade_to: Severity::Info,
                },
            });
        }

        // Audit / log sanitisation
        if contains_any(
            &lower,
            &[
                "\u{5ba1}\u{8ba1}",
                "audit",
                "\u{65e5}\u{5fd7}\u{8131}\u{654f}",
                "log sanitiz",
            ],
        ) {
            effects.push(MemoryEffect {
                scope: MemoryScope::Project,
                effect: MemoryEffectType::ProtectionDeclared {
                    scanners: vec!["S20".into(), "S23".into()],
                    downgrade_to: Severity::Info,
                },
            });
        }

        // RLS / data isolation
        if contains_any(
            &lower,
            &[
                "rls",
                "row level",
                "\u{79df}\u{6237}\u{9694}\u{79bb}",
                "tenant",
                "multi-tenant",
            ],
        ) {
            effects.push(MemoryEffect {
                scope: MemoryScope::Project,
                effect: MemoryEffectType::ProtectionDeclared {
                    scanners: vec!["S12".into()],
                    downgrade_to: Severity::Info,
                },
            });
        }
    }
}

fn parse_scanner_memories(
    scanners: &HashMap<String, Vec<String>>,
    effects: &mut Vec<MemoryEffect>,
) {
    for (scanner_id, texts) in scanners {
        for text in texts {
            let lower = text.to_lowercase();

            if contains_any(
                &lower,
                &[
                    "\u{516c}\u{5f00}",
                    "public",
                    "\u{4e0d}\u{9700}\u{8981}",
                    "exempt",
                    "\u{8c41}\u{514d}",
                ],
            ) {
                effects.push(MemoryEffect {
                    scope: MemoryScope::Scanner(scanner_id.clone()),
                    effect: MemoryEffectType::ProtectionDeclared {
                        scanners: vec![scanner_id.clone()],
                        downgrade_to: Severity::Info,
                    },
                });
            }

            if contains_any(
                &lower,
                &[
                    "\u{4e0d}\u{9002}\u{7528}",
                    "not applicable",
                    "\u{5ffd}\u{7565}",
                    "skip",
                    "\u{7cfb}\u{7edf}\u{8868}",
                ],
            ) {
                effects.push(MemoryEffect {
                    scope: MemoryScope::Scanner(scanner_id.clone()),
                    effect: MemoryEffectType::NotApplicable {
                        scanner: scanner_id.clone(),
                    },
                });
            }

            if contains_any(
                &lower,
                &[
                    "hook",
                    "\u{95f4}\u{63a5}\u{8c03}\u{7528}",
                    "indirect",
                    "wrapper",
                ],
            ) {
                effects.push(MemoryEffect {
                    scope: MemoryScope::Scanner(scanner_id.clone()),
                    effect: MemoryEffectType::SafePattern,
                });
            }
        }
    }
}

fn parse_pattern_memories(patterns: &[PatternMemory], effects: &mut Vec<MemoryEffect>) {
    for pm in patterns {
        let lower = pm.memory.to_lowercase();
        let affected_scanners = infer_scanners_from_text(&lower);

        if !affected_scanners.is_empty() {
            effects.push(MemoryEffect {
                scope: MemoryScope::Pattern(pm.match_pattern.clone()),
                effect: MemoryEffectType::ProtectionDeclared {
                    scanners: affected_scanners,
                    downgrade_to: Severity::Info,
                },
            });
        }
    }
}

fn contains_any(text: &str, keywords: &[&str]) -> bool {
    keywords.iter().any(|kw| text.contains(kw))
}

fn infer_scanners_from_text(text: &str) -> Vec<String> {
    let mut scanners = Vec::new();
    if contains_any(text, &["auth", "guard", "\u{8ba4}\u{8bc1}", "jwt"]) {
        scanners.push("S7".into());
    }
    if contains_any(
        text,
        &[
            "\u{7c7b}\u{578b}\u{5b9a}\u{4e49}",
            "type definition",
            "contract",
            "sdk",
        ],
    ) {
        scanners.push("S8".into());
        scanners.push("S26".into());
    }
    scanners
}

// ---------------------------------------------------------------------------
// Apply memories to scan results (immutable — returns new Vec)
// ---------------------------------------------------------------------------

/// Adjust finding severity based on memory effects.
/// Returns new results with adjusted severity; does not mutate inputs.
pub fn apply_memories(results: &[ScanResult], effects: &[MemoryEffect]) -> Vec<ScanResult> {
    results
        .iter()
        .map(|r| apply_to_result(r, effects))
        .collect()
}

fn apply_to_result(result: &ScanResult, effects: &[MemoryEffect]) -> ScanResult {
    let adjusted_findings: Vec<Finding> = result
        .findings
        .iter()
        .filter_map(|f| apply_effects_to_finding(f, &result.scanner, effects))
        .collect();

    ScanResult {
        scanner: result.scanner.clone(),
        findings: adjusted_findings,
        score: result.score,
        summary: result.summary.clone(),
    }
}

fn apply_effects_to_finding(
    finding: &Finding,
    result_scanner: &str,
    effects: &[MemoryEffect],
) -> Option<Finding> {
    let mut severity = finding.severity;
    let mut suppressed = false;

    for effect in effects {
        if !effect_applies(effect, result_scanner, finding) {
            continue;
        }

        match &effect.effect {
            MemoryEffectType::ProtectionDeclared {
                scanners,
                downgrade_to,
            } => {
                if scanners.contains(&result_scanner.to_string())
                    || scanners.contains(&finding.scanner)
                {
                    severity = lower_severity(severity, *downgrade_to);
                }
            }
            MemoryEffectType::NotApplicable { scanner } => {
                if scanner == result_scanner || scanner == &finding.scanner {
                    suppressed = true;
                }
            }
            MemoryEffectType::SafePattern => {
                severity = lower_severity(severity, Severity::Info);
            }
        }
    }

    if suppressed {
        return None;
    }

    Some(Finding {
        scanner: finding.scanner.clone(),
        severity,
        confidence: finding.confidence,
        message: finding.message.clone(),
        file: finding.file.clone(),
        line: finding.line,
        suggestion: finding.suggestion.clone(),
    })
}

/// Downgrade severity but never escalate.
fn lower_severity(current: Severity, target: Severity) -> Severity {
    if target < current {
        target
    } else {
        current
    }
}

fn effect_applies(effect: &MemoryEffect, scanner_id: &str, finding: &Finding) -> bool {
    match &effect.scope {
        MemoryScope::Project => true,
        MemoryScope::Scanner(id) => id == scanner_id || id == &finding.scanner,
        MemoryScope::Pattern(glob_pattern) => match &finding.file {
            Some(file) => glob_match(glob_pattern, &file.to_string_lossy()),
            None => false,
        },
    }
}

/// Simple glob matching using the `globset` crate already in Cargo.toml.
fn glob_match(pattern: &str, path: &str) -> bool {
    globset::Glob::new(pattern)
        .ok()
        .and_then(|g| g.compile_matcher().is_match(path).then_some(true))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Load / Save
// ---------------------------------------------------------------------------

pub fn memory_file_path(root: &Path) -> PathBuf {
    root.join(".sentinella").join("memories.yaml")
}

pub fn load_memories(root: &Path) -> anyhow::Result<MemoryFile> {
    let path = memory_file_path(root);
    if !path.exists() {
        return Ok(MemoryFile::default());
    }
    let content = std::fs::read_to_string(&path)?;
    let memories: MemoryFile = serde_yaml::from_str(&content)?;
    Ok(memories)
}

pub fn save_memories(root: &Path, memories: &MemoryFile) -> anyhow::Result<()> {
    let path = memory_file_path(root);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_yaml::to_string(memories)?;
    let tmp_path = path.with_extension("yaml.tmp");
    std::fs::write(&tmp_path, &content)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI helpers
// ---------------------------------------------------------------------------

/// Add a memory entry and return the updated (new) MemoryFile.
pub fn add_memory(current: &MemoryFile, text: String, scanner: Option<String>) -> MemoryFile {
    match scanner {
        Some(scanner_id) => {
            let mut scanners = current.scanners.clone();
            scanners.entry(scanner_id).or_default().push(text);
            MemoryFile {
                project: current.project.clone(),
                scanners,
                patterns: current.patterns.clone(),
            }
        }
        None => {
            let mut project = current.project.clone();
            project.push(text);
            MemoryFile {
                project,
                scanners: current.scanners.clone(),
                patterns: current.patterns.clone(),
            }
        }
    }
}

/// Format memories for display.
pub fn format_memories(memories: &MemoryFile) -> String {
    let mut lines = Vec::new();

    if !memories.project.is_empty() {
        lines.push("Project memories:".to_string());
        for (i, m) in memories.project.iter().enumerate() {
            lines.push(format!("  {}. {}", i + 1, m));
        }
    }

    if !memories.scanners.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("Scanner memories:".to_string());
        let mut sorted_keys: Vec<_> = memories.scanners.keys().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            let texts = &memories.scanners[key];
            lines.push(format!("  [{}]", key));
            for (i, m) in texts.iter().enumerate() {
                lines.push(format!("    {}. {}", i + 1, m));
            }
        }
    }

    if !memories.patterns.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push("Pattern memories:".to_string());
        for pm in &memories.patterns {
            lines.push(format!("  {} -> {}", pm.match_pattern, pm.memory));
        }
    }

    if lines.is_empty() {
        "No memories configured.".to_string()
    } else {
        lines.join("\n")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_memory_file() -> MemoryFile {
        MemoryFile {
            project: vec![
                "\u{8ba4}\u{8bc1}\u{7edf}\u{4e00}\u{5728} API Gateway \u{5c42}\u{5904}\u{7406}"
                    .into(),
                "\u{6240}\u{6709} DELETE \u{64cd}\u{4f5c}\u{90fd}\u{662f}\u{8f6f}\u{5220}\u{9664}"
                    .into(),
            ],
            scanners: {
                let mut m = HashMap::new();
                m.insert(
                    "S7".into(),
                    vec!["\u{4ee5}\u{4e0b}\u{7aef}\u{70b9}\u{8bbe}\u{8ba1}\u{4e0a}\u{662f}\u{516c}\u{5f00}\u{7684}: /health".into()],
                );
                m.insert(
                    "S1".into(),
                    vec!["\u{524d}\u{7aef}\u{9875}\u{9762}\u{901a}\u{8fc7}\u{81ea}\u{5b9a}\u{4e49} hook \u{95f4}\u{63a5}\u{8c03}\u{7528} API".into()],
                );
                m
            },
            patterns: vec![PatternMemory {
                match_pattern: "**/*.controller.ts".into(),
                memory: "\u{6240}\u{6709} controller \u{6709}\u{7c7b}\u{7ea7} guard".into(),
            }],
        }
    }

    #[test]
    fn test_parse_project_auth_memory() {
        let mem = sample_memory_file();
        let effects = parse_memory_effects(&mem);

        let auth_effects: Vec<_> = effects
            .iter()
            .filter(|e| matches!(&e.scope, MemoryScope::Project))
            .filter(|e| match &e.effect {
                MemoryEffectType::ProtectionDeclared { scanners, .. } => {
                    scanners.contains(&"S7".into())
                }
                _ => false,
            })
            .collect();

        assert!(!auth_effects.is_empty(), "Should detect auth protection");
    }

    #[test]
    fn test_parse_soft_delete_memory() {
        let mem = sample_memory_file();
        let effects = parse_memory_effects(&mem);

        let soft_del: Vec<_> = effects
            .iter()
            .filter(|e| match &e.effect {
                MemoryEffectType::ProtectionDeclared { scanners, .. } => {
                    scanners.contains(&"S13".into())
                }
                _ => false,
            })
            .collect();

        assert!(!soft_del.is_empty(), "Should detect soft-delete protection");
    }

    #[test]
    fn test_parse_scanner_public_endpoint() {
        let mem = sample_memory_file();
        let effects = parse_memory_effects(&mem);

        let public_effects: Vec<_> = effects
            .iter()
            .filter(|e| matches!(&e.scope, MemoryScope::Scanner(id) if id == "S7"))
            .collect();

        assert!(
            !public_effects.is_empty(),
            "Should detect public endpoint declaration"
        );
    }

    #[test]
    fn test_parse_hook_safe_pattern() {
        let mem = sample_memory_file();
        let effects = parse_memory_effects(&mem);

        let safe: Vec<_> = effects
            .iter()
            .filter(|e| matches!(&e.effect, MemoryEffectType::SafePattern))
            .collect();

        assert!(!safe.is_empty(), "Should detect safe hook pattern");
    }

    #[test]
    fn test_parse_pattern_memory() {
        let mem = sample_memory_file();
        let effects = parse_memory_effects(&mem);

        let pat: Vec<_> = effects
            .iter()
            .filter(|e| matches!(&e.scope, MemoryScope::Pattern(_)))
            .collect();

        assert!(!pat.is_empty(), "Should parse pattern-level memories");
    }

    #[test]
    fn test_apply_memories_downgrades_severity() {
        let results = vec![ScanResult {
            scanner: "S7".into(),
            findings: vec![Finding::new("S7", Severity::Critical, "Missing auth")],
            score: 40,
            summary: "Auth gaps".into(),
        }];

        let effects = vec![MemoryEffect {
            scope: MemoryScope::Project,
            effect: MemoryEffectType::ProtectionDeclared {
                scanners: vec!["S7".into()],
                downgrade_to: Severity::Info,
            },
        }];

        let adjusted = apply_memories(&results, &effects);
        assert_eq!(adjusted[0].findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_apply_memories_suppresses_not_applicable() {
        let results = vec![ScanResult {
            scanner: "S12".into(),
            findings: vec![Finding::new("S12", Severity::Warning, "Missing RLS")],
            score: 60,
            summary: "Data isolation".into(),
        }];

        let effects = vec![MemoryEffect {
            scope: MemoryScope::Scanner("S12".into()),
            effect: MemoryEffectType::NotApplicable {
                scanner: "S12".into(),
            },
        }];

        let adjusted = apply_memories(&results, &effects);
        assert!(
            adjusted[0].findings.is_empty(),
            "NotApplicable should suppress findings"
        );
    }

    #[test]
    fn test_apply_memories_safe_pattern() {
        let results = vec![ScanResult {
            scanner: "S1".into(),
            findings: vec![Finding::new("S1", Severity::Warning, "Unused endpoint")],
            score: 70,
            summary: "API coverage".into(),
        }];

        let effects = vec![MemoryEffect {
            scope: MemoryScope::Scanner("S1".into()),
            effect: MemoryEffectType::SafePattern,
        }];

        let adjusted = apply_memories(&results, &effects);
        assert_eq!(adjusted[0].findings[0].severity, Severity::Info);
    }

    #[test]
    fn test_lower_severity_never_escalates() {
        assert_eq!(
            lower_severity(Severity::Info, Severity::Critical),
            Severity::Info
        );
        assert_eq!(
            lower_severity(Severity::Warning, Severity::Info),
            Severity::Info
        );
        assert_eq!(
            lower_severity(Severity::Critical, Severity::Warning),
            Severity::Warning
        );
    }

    #[test]
    fn test_glob_match_basic() {
        assert!(glob_match("**/*.ts", "src/controllers/auth.ts"));
        assert!(!glob_match("**/*.ts", "src/controllers/auth.rs"));
        assert!(glob_match("**/contracts/**", "packages/contracts/types.ts"));
    }

    #[test]
    fn test_empty_memory_file_no_effects() {
        let mem = MemoryFile::default();
        let effects = parse_memory_effects(&mem);
        assert!(effects.is_empty());
    }

    #[test]
    fn test_add_memory_project_level() {
        let mem = MemoryFile::default();
        let updated = add_memory(&mem, "test memory".into(), None);
        assert_eq!(updated.project.len(), 1);
        assert_eq!(updated.project[0], "test memory");
        // Original unchanged (immutability)
        assert!(mem.project.is_empty());
    }

    #[test]
    fn test_add_memory_scanner_level() {
        let mem = MemoryFile::default();
        let updated = add_memory(&mem, "scanner note".into(), Some("S7".into()));
        assert_eq!(updated.scanners["S7"], vec!["scanner note"]);
        assert!(mem.scanners.is_empty());
    }

    #[test]
    fn test_format_memories_empty() {
        let mem = MemoryFile::default();
        assert_eq!(format_memories(&mem), "No memories configured.");
    }

    #[test]
    fn test_load_nonexistent_returns_default() {
        let tmp = tempfile::tempdir().unwrap();
        let mem = load_memories(tmp.path()).unwrap();
        assert!(mem.project.is_empty());
        assert!(mem.scanners.is_empty());
        assert!(mem.patterns.is_empty());
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let mem = MemoryFile {
            project: vec!["test memory".into()],
            scanners: HashMap::new(),
            patterns: vec![],
        };
        save_memories(tmp.path(), &mem).unwrap();
        let loaded = load_memories(tmp.path()).unwrap();
        assert_eq!(loaded.project, vec!["test memory"]);
    }
}
