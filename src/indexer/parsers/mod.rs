use std::path::Path;

use anyhow::Result;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Parser, Query, QueryCursor, Tree};

use crate::indexer::store::IndexStore;

pub mod typescript;
pub mod python;
pub mod go_lang;
pub mod sql;
pub mod dockerfile;
pub mod yaml_config;
pub mod rust_lang;
pub mod env_file;
pub mod test_file;

/// Trait for language-specific parsers
pub trait LanguageParser: Send + Sync {
    /// File extensions this parser handles
    fn extensions(&self) -> &[&str];

    /// Parse a file and populate the index store
    fn parse_file(
        &self,
        path: &Path,
        source: &[u8],
        store: &IndexStore,
    ) -> Result<()>;
}

/// Create a tree-sitter parser for the given language
pub fn create_parser(language: &Language) -> Result<Parser> {
    let mut parser = Parser::new();
    parser.set_language(language)?;
    Ok(parser)
}

/// Parse source code into a tree-sitter Tree
pub fn parse_source(parser: &mut Parser, source: &[u8]) -> Result<Tree> {
    parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse source"))
}

/// Run a tree-sitter query against a parsed tree, calling the callback for each match.
/// Each tuple in the captures list: (capture_name, captured_text, line_number)
pub fn run_query<F>(
    query_source: &str,
    language: &Language,
    source: &[u8],
    tree: &Tree,
    mut callback: F,
) where
    F: FnMut(&tree_sitter::QueryMatch, &[(String, String, usize)]),
{
    let query = Query::new(language, query_source)
        .unwrap_or_else(|e| panic!("Invalid tree-sitter query: {e}"));
    let mut cursor = QueryCursor::new();
    let capture_names: Vec<String> = query
        .capture_names()
        .iter()
        .map(|s| s.to_string())
        .collect();

    let mut matches = cursor.matches(&query, tree.root_node(), source);
    while let Some(m) = matches.next() {
        let captures: Vec<(String, String, usize)> = m
            .captures
            .iter()
            .map(|c| {
                let name = capture_names[c.index as usize].clone();
                let text = c.node.utf8_text(source).unwrap_or("").to_string();
                let line = c.node.start_position().row + 1;
                (name, text, line)
            })
            .collect();
        callback(m, &captures);
    }
}

/// Helper: find a capture by name from a captures list
pub fn find_capture<'a>(
    captures: &'a [(String, String, usize)],
    name: &str,
) -> Option<&'a (String, String, usize)> {
    captures.iter().find(|(n, _, _)| n == name)
}

/// Compute a simple FNV-1a hash of source bytes for FileInfo dedup.
pub fn hash_source(source: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in source {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Count lines in a byte slice.
pub fn count_lines(source: &[u8]) -> usize {
    if source.is_empty() {
        return 0;
    }
    let newlines = source.iter().filter(|&&b| b == b'\n').count();
    if source.last() == Some(&b'\n') {
        newlines
    } else {
        newlines + 1
    }
}

/// Return all registered parsers.
pub fn all_parsers() -> Vec<Box<dyn LanguageParser>> {
    vec![
        Box::new(typescript::TypeScriptParser),
        Box::new(python::PythonParser),
        Box::new(go_lang::GoParser),
        Box::new(sql::SqlParser),
        Box::new(dockerfile::DockerfileParser),
        Box::new(yaml_config::YamlConfigParser),
        Box::new(rust_lang::RustParser),
        Box::new(env_file::EnvFileParser),
    ]
}
