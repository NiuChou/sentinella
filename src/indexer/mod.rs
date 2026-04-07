pub mod parsers;
pub mod queries;
pub mod store;
pub mod types;

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use ignore::WalkBuilder;
use rayon::prelude::*;

use self::store::IndexStore;
use crate::config::schema::Config;

/// Maximum file size to index (1 MB). Files exceeding this limit are
/// assumed to be generated artifacts and are silently skipped.
const MAX_FILE_SIZE_BYTES: u64 = 1_024 * 1_024;

pub fn build_index(root: &Path, config: &Config) -> Result<Arc<IndexStore>> {
    build_index_multi(&[root], config)
}

pub fn build_index_multi(roots: &[&Path], _config: &Config) -> Result<Arc<IndexStore>> {
    let store = IndexStore::new();
    let parsers = parsers::all_parsers();

    let entries = collect_entries(roots);
    parse_source_files(&entries, &parsers, &store);
    parse_test_files(&entries, &store);

    // Migrate middleware_scopes to evidence_store
    for entry in store.middleware_scopes.iter() {
        for scope in entry.value().iter() {
            let evidence = crate::evidence::from_middleware_scope(scope);
            store.evidence_store.add(evidence);
        }
    }

    // Load and execute rule packs against indexed source files
    execute_rule_packs(roots, &store);

    Ok(store)
}

/// Load rule packs, detect tech stack, and execute regex rules against
/// all indexed source files. Evidence is written to `store.evidence_store`.
fn execute_rule_packs(roots: &[&Path], store: &IndexStore) {
    for root in roots {
        let rule_packs = match crate::rule_pack::loader::resolve_rule_packs(root) {
            Ok(packs) => packs,
            Err(e) => {
                eprintln!(
                    "[WARN] Failed to load rule packs for {}: {e}",
                    root.display()
                );
                continue;
            }
        };

        let detected_stack = crate::rule_pack::detect::detect_tech_stack(root);

        let active_packs: Vec<_> = rule_packs
            .into_iter()
            .filter(|pack| {
                detected_stack.iter().any(|entry| entry.name == pack.name) || pack.name == "custom"
                // always load custom packs
            })
            .collect();

        if detected_stack.is_empty() {
            eprintln!(
                "[WARN] No tech stack detected for {}. \
                 Run `sentinella init --detect` to configure rule packs.",
                root.display()
            );
        } else {
            eprintln!(
                "[INFO] Detected tech stack: {}",
                detected_stack
                    .iter()
                    .map(|e| e.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            eprintln!(
                "[INFO] Active rule packs: {}",
                active_packs
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        run_rule_packs_against_files(&active_packs, store);
    }
}

/// Execute regex rules from active packs against each source file in the store.
fn run_rule_packs_against_files(
    active_packs: &[crate::rule_pack::schema::RulePack],
    store: &IndexStore,
) {
    if active_packs.is_empty() {
        return;
    }

    for entry in store.files.iter() {
        let file_path = entry.key();
        if let Ok(source) = std::fs::read_to_string(file_path) {
            crate::rule_pack::engine::execute_protection_rules(
                active_packs,
                file_path,
                &source,
                &store.evidence_store,
            );
        }
    }
}

fn collect_entries(roots: &[&Path]) -> Vec<ignore::DirEntry> {
    roots
        .iter()
        .flat_map(|root| {
            WalkBuilder::new(root)
                .hidden(true)
                .git_ignore(true)
                .follow_links(false)
                .build()
                .filter_map(|result| match result {
                    Ok(entry) => Some(entry),
                    Err(err) => {
                        eprintln!("Warning: directory walk error: {err}");
                        None
                    }
                })
                .filter(|entry| entry.file_type().map_or(false, |ft| ft.is_file()))
        })
        .collect()
}

fn parse_source_files(
    entries: &[ignore::DirEntry],
    parsers: &[Box<dyn parsers::LanguageParser>],
    store: &IndexStore,
) {
    entries.par_iter().for_each(|entry| {
        let path = entry.path();

        if let Ok(meta) = path.metadata() {
            if meta.len() > MAX_FILE_SIZE_BYTES {
                return;
            }
        }

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        let matching_parser = parsers.iter().find(|parser| {
            parser.extensions().iter().any(|&pattern| {
                ext == pattern
                    || file_name == pattern
                    || (file_name.starts_with(pattern)
                        && file_name.as_bytes().get(pattern.len()) == Some(&b'.'))
            })
        });

        let parser = match matching_parser {
            Some(p) => p,
            None => return,
        };

        let source = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("Warning: failed to read {}: {err}", path.display());
                return;
            }
        };

        if is_likely_binary(&source) {
            return;
        }

        if let Err(err) = parser.parse_file(path, &source, store) {
            eprintln!("Warning: failed to parse {}: {err}", path.display());
        }
    });
}

fn parse_test_files(entries: &[ignore::DirEntry], store: &IndexStore) {
    entries.par_iter().for_each(|entry| {
        let path = entry.path();

        if !parsers::test_file::is_test_file(path) {
            return;
        }

        let source = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => return,
        };

        if is_likely_binary(&source) {
            return;
        }

        if let Err(err) = parsers::test_file::parse_test_file(path, &source, store) {
            eprintln!(
                "Warning: failed to parse test file {}: {err}",
                path.display()
            );
        }
    });
}

/// Heuristic binary detection: if the first 8 KB contain a NUL byte the
/// file is almost certainly not source code.
fn is_likely_binary(bytes: &[u8]) -> bool {
    let check_len = bytes.len().min(8192);
    bytes[..check_len].contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_detection_identifies_nul_bytes() {
        assert!(is_likely_binary(b"hello\x00world"));
        assert!(!is_likely_binary(b"hello world"));
    }

    #[test]
    fn binary_detection_handles_empty_input() {
        assert!(!is_likely_binary(b""));
    }

    /// Helper that replicates the matching logic used in `build_index` so we
    /// can unit-test it in isolation without needing real files on disk.
    fn matches_pattern(file_name: &str, ext: &str, pattern: &str) -> bool {
        ext == pattern
            || file_name == pattern
            || (file_name.starts_with(pattern)
                && file_name.as_bytes().get(pattern.len()) == Some(&b'.'))
    }

    #[test]
    fn test_extension_matching_logic() {
        // 1. "routes.py" matches pattern "py" via extension
        assert!(matches_pattern("routes.py", "py", "py"));

        // 2. "Dockerfile" matches pattern "Dockerfile" via exact file_name
        assert!(matches_pattern("Dockerfile", "", "Dockerfile"));

        // 3. "Dockerfile.dev" matches pattern "Dockerfile" via starts_with
        assert!(matches_pattern("Dockerfile.dev", "dev", "Dockerfile"));

        // 4. "app.ts" matches pattern "ts" via extension
        assert!(matches_pattern("app.ts", "ts", "ts"));

        // 5. "pyproject.toml" must NOT match pattern "py" — ext is "toml"
        assert!(!matches_pattern("pyproject.toml", "toml", "py"));
    }
}
