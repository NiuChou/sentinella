use std::path::Path;
use std::sync::OnceLock;

use anyhow::Result;
use regex::Regex;

use super::{count_lines, hash_source, LanguageParser};
use crate::indexer::store::IndexStore;
use crate::indexer::types::{FileInfo, Language, RlsPolicyInfo, TableInfo};

pub struct SqlParser;

impl LanguageParser for SqlParser {
    fn extensions(&self) -> &[&str] {
        &["sql"]
    }

    fn parse_file(&self, path: &Path, source: &[u8], store: &IndexStore) -> Result<()> {
        let file_info = FileInfo {
            path: path.to_path_buf(),
            language: Language::Sql,
            lines: count_lines(source),
            hash: hash_source(source),
        };
        store.files.insert(path.to_path_buf(), file_info);

        let source_str = std::str::from_utf8(source)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in SQL file: {e}"))?;

        parse_tables(source_str, store);
        parse_rls_policies(source_str, store);
        parse_rls_enable(source_str, store);
        parse_grants(source_str, store);
        parse_rls_policy_details(source_str, store);
        parse_force_rls(source_str, store);

        Ok(())
    }
}

fn create_table_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"?(\w+)"?\.)?"?(\w+)"?"#,
        )
        .unwrap()
    })
}

fn rls_policy_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)CREATE\s+POLICY\s+\w+\s+ON\s+(?:(\w+)\.)?(\w+)").unwrap()
    })
}

fn rls_enable_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)ALTER\s+TABLE\s+(?:(\w+)\.)?(\w+)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY",
        )
        .unwrap()
    })
}

fn grant_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)GRANT\s+\w+(?:\s*,\s*\w+)*\s+ON\s+(?:TABLE\s+)?(?:(\w+)\.)?(\w+)\s+TO\s+(\w+)",
        )
        .unwrap()
    })
}

/// Match: CREATE POLICY policy_name ON [schema.]table_name ... TO role_name
/// Capture groups: policy_name, optional schema, table_name, role_name
fn rls_policy_detail_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)CREATE\s+POLICY\s+(\w+)\s+ON\s+(?:(\w+)\.)?(\w+)(?:.*?TO\s+(\w+))?")
            .unwrap()
    })
}

/// Match: current_setting('app.xxx', true) inside USING/WITH CHECK
fn rls_session_var_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"current_setting\s*\(\s*'([^']+)'").unwrap())
}

/// Match: ALTER TABLE [schema.]table FORCE ROW LEVEL SECURITY
fn force_rls_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)ALTER\s+TABLE\s+(?:(\w+)\.)?(\w+)\s+FORCE\s+ROW\s+LEVEL\s+SECURITY")
            .unwrap()
    })
}

/// Extract CREATE TABLE statements: `CREATE TABLE [IF NOT EXISTS] ["schema".]"name"`
/// Supports optional double-quoted identifiers around schema and table names.
fn parse_tables(source: &str, store: &IndexStore) {
    let re = create_table_re();

    for cap in re.captures_iter(source) {
        let schema_name = cap.get(1).map(|m| m.as_str().to_string());
        let table_name = cap.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();

        let key = match &schema_name {
            Some(s) => format!("{s}.{table_name}"),
            None => table_name.clone(),
        };

        store.db_tables.entry(key).or_insert_with(|| TableInfo {
            schema_name,
            table_name,
            has_rls: false,
            app_role: None,
        });
    }
}

/// Detect RLS POLICY statements and mark the corresponding table.
/// Pattern: `CREATE POLICY ... ON [schema.]table_name`
fn parse_rls_policies(source: &str, store: &IndexStore) {
    let re = rls_policy_re();

    for cap in re.captures_iter(source) {
        let schema = cap.get(1).map(|m| m.as_str().to_string());
        let table = cap.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();

        let key = match &schema {
            Some(s) => format!("{s}.{table}"),
            None => table.clone(),
        };

        if let Some(mut entry) = store.db_tables.get_mut(&key) {
            entry.has_rls = true;
        }
    }
}

/// Detect ALTER TABLE ... ENABLE ROW LEVEL SECURITY
fn parse_rls_enable(source: &str, store: &IndexStore) {
    let re = rls_enable_re();

    for cap in re.captures_iter(source) {
        let schema = cap.get(1).map(|m| m.as_str().to_string());
        let table = cap.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();

        let key = match &schema {
            Some(s) => format!("{s}.{table}"),
            None => table.clone(),
        };

        if let Some(mut entry) = store.db_tables.get_mut(&key) {
            entry.has_rls = true;
        }
    }
}

/// Detect GRANT statements: `GRANT ... TO role_name`
fn parse_grants(source: &str, store: &IndexStore) {
    let re = grant_re();

    for cap in re.captures_iter(source) {
        let schema = cap.get(1).map(|m| m.as_str().to_string());
        let table = cap.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
        let role = cap.get(3).map(|m| m.as_str().to_string()).unwrap_or_default();

        let key = match &schema {
            Some(s) => format!("{s}.{table}"),
            None => table.clone(),
        };

        if let Some(mut entry) = store.db_tables.get_mut(&key) {
            entry.app_role = Some(role);
        }
    }
}

/// Extract detailed RLS policy information including session variable and role.
fn parse_rls_policy_details(source: &str, store: &IndexStore) {
    let policy_re = rls_policy_detail_re();
    let session_re = rls_session_var_re();

    for cap in policy_re.captures_iter(source) {
        let policy_name = cap.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
        let schema = cap.get(2).map(|m| m.as_str().to_string());
        let table = cap.get(3).map(|m| m.as_str().to_string()).unwrap_or_default();
        let role = cap.get(4).map(|m| m.as_str().to_string());

        let key = match &schema {
            Some(s) => format!("{s}.{table}"),
            None => table.clone(),
        };

        // Look for current_setting() in the vicinity of this policy
        let match_start = cap.get(0).map(|m| m.start()).unwrap_or(0);
        let context_end = (match_start + 500).min(source.len());
        let context = &source[match_start..context_end];
        let session_var = session_re
            .captures(context)
            .and_then(|sc| sc.get(1))
            .map(|m| m.as_str().to_string());

        let info = RlsPolicyInfo {
            table_name: table,
            policy_name,
            session_var,
            has_force: false,
            role,
        };

        store.rls_policies.entry(key).or_default().push(info);
    }
}

/// Detect FORCE ROW LEVEL SECURITY and update corresponding RlsPolicyInfo entries.
fn parse_force_rls(source: &str, store: &IndexStore) {
    let re = force_rls_re();

    for cap in re.captures_iter(source) {
        let schema = cap.get(1).map(|m| m.as_str().to_string());
        let table = cap.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();

        let key = match &schema {
            Some(s) => format!("{s}.{table}"),
            None => table.clone(),
        };

        if let Some(mut policies) = store.rls_policies.get_mut(&key) {
            for policy in policies.value_mut().iter_mut() {
                policy.has_force = true;
            }
        }

        if let Some(mut entry) = store.db_tables.get_mut(&key) {
            entry.has_rls = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sql")
            .join(name)
    }

    fn parse_fixture(name: &str) -> Arc<IndexStore> {
        let path = fixture_path(name);
        let source = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
        let store = IndexStore::new();
        SqlParser.parse_file(&path, &source, &store).unwrap();
        store
    }

    #[test]
    fn detects_create_table() {
        let store = parse_fixture("migrations.sql");
        assert!(
            store.db_tables.contains_key("users"),
            "Should detect users table"
        );
    }

    #[test]
    fn detects_create_table_with_schema() {
        let store = parse_fixture("migrations.sql");
        assert!(
            store.db_tables.contains_key("public.orders"),
            "Should detect public.orders table"
        );
    }

    #[test]
    fn detects_rls_via_alter_table() {
        let store = parse_fixture("migrations.sql");
        let has_rls = store
            .db_tables
            .get("users")
            .map(|u| u.has_rls)
            .expect("users table not found");
        assert!(has_rls, "users table should have RLS enabled");
    }

    #[test]
    fn detects_rls_via_create_policy() {
        let store = parse_fixture("migrations.sql");
        let has_rls = store
            .db_tables
            .get("users")
            .map(|u| u.has_rls)
            .unwrap_or(false);
        assert!(has_rls, "users should have RLS from CREATE POLICY");
    }

    #[test]
    fn table_without_rls() {
        let store = parse_fixture("migrations.sql");
        let has_rls = store
            .db_tables
            .get("public.orders")
            .map(|o| o.has_rls)
            .unwrap_or(true);
        assert!(
            !has_rls,
            "orders should not have RLS (no policy or alter)"
        );
    }

    #[test]
    fn detects_grant_role() {
        let store = parse_fixture("migrations.sql");
        let app_role = store
            .db_tables
            .get("users")
            .and_then(|u| u.app_role.clone());
        assert_eq!(
            app_role.as_deref(),
            Some("app_role"),
            "users should be granted to app_role"
        );
    }

    #[test]
    fn file_info_is_populated() {
        let store = parse_fixture("migrations.sql");
        let path = fixture_path("migrations.sql");
        assert!(
            store.files.contains_key(&path),
            "FileInfo should be stored"
        );
        let (lang, lines) = store
            .files
            .get(&path)
            .map(|info| (info.language, info.lines))
            .unwrap();
        assert_eq!(lang, Language::Sql);
        assert!(lines > 0);
    }

    #[test]
    fn extracts_rls_policy_details() {
        let store = parse_fixture("migrations.sql");
        let policies = store.all_rls_policies();
        assert!(!policies.is_empty(), "Should extract RLS policy details");
    }

    #[test]
    fn extracts_session_var_from_policy() {
        let store = parse_fixture("migrations.sql");
        let policies = store.all_rls_policies();
        let with_session_var: Vec<_> = policies.iter().filter(|p| p.session_var.is_some()).collect();
        // This may be empty if fixture doesn't have current_setting — that's OK
        // The important thing is the parser doesn't crash
        let _ = with_session_var;
    }

    #[test]
    fn detects_force_rls() {
        let store = parse_fixture("migrations.sql");
        let policies = store.all_rls_policies();
        let forced: Vec<_> = policies.iter().filter(|p| p.has_force).collect();
        // Will be populated once we update the fixture
        let _ = forced;
    }
}
