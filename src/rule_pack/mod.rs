//! Framework-specific rule packs for Sentinella.
//!
//! Rule packs are YAML files that declare regex (or tree-sitter) patterns for
//! detecting frameworks, gathering protection/data-source evidence, and
//! providing scanner overrides. Built-in packs for NestJS and Express are
//! compiled into the binary; users can supply additional packs via config.

pub mod loader;
pub mod schema;
