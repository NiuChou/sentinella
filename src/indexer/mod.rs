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

    Ok(store)
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
