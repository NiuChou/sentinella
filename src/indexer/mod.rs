pub mod types;
pub mod store;
pub mod parsers;
pub mod queries;

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use ignore::WalkBuilder;
use rayon::prelude::*;

use crate::config::schema::Config;
use self::store::IndexStore;

/// Maximum file size to index (1 MB). Files exceeding this limit are
/// assumed to be generated artifacts and are silently skipped.
const MAX_FILE_SIZE_BYTES: u64 = 1_024 * 1_024;

/// Build the complete index by walking the project tree and parsing every
/// recognised file in parallel.
///
/// The walker respects `.gitignore` rules and does not follow symlinks.
/// Binary files and files larger than [`MAX_FILE_SIZE_BYTES`] are skipped.
pub fn build_index(root: &Path, _config: &Config) -> Result<Arc<IndexStore>> {
    let store = IndexStore::new();
    let parsers = parsers::all_parsers();

    // Collect walkable file entries.  The `ignore` crate automatically
    // respects `.gitignore`, `.ignore`, and hidden-file rules.
    let entries: Vec<_> = WalkBuilder::new(root)
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
        .collect();

    // Parse every file in parallel via rayon.
    entries.par_iter().for_each(|entry| {
        let path = entry.path();

        // Skip files that exceed the size threshold.
        if let Ok(meta) = path.metadata() {
            if meta.len() > MAX_FILE_SIZE_BYTES {
                return;
            }
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Find the first parser whose extension list matches this file.
        let matching_parser = parsers.iter().find(|parser| {
            parser.extensions().iter().any(|&pattern| {
                if pattern.contains('/') || !pattern.contains('.') {
                    // Pattern is a filename prefix (e.g. "Dockerfile", ".env")
                    file_name == pattern || file_name.starts_with(pattern)
                } else {
                    ext == pattern
                }
            })
        });

        let parser = match matching_parser {
            Some(p) => p,
            None => return,
        };

        // Read the file, skipping unreadable or binary content.
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

        if let Err(err) = parser.parse_file(path, &source, &store) {
            eprintln!("Warning: failed to parse {}: {err}", path.display());
        }
    });

    // Second pass: detect test files and populate test_files store.
    // This runs independently of language parsers so that test files
    // parsed by (e.g.) TypeScriptParser also get a TestFileInfo entry.
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

        if let Err(err) = parsers::test_file::parse_test_file(path, &source, &store) {
            eprintln!("Warning: failed to parse test file {}: {err}", path.display());
        }
    });

    Ok(store)
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
}
