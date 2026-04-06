use std::path::Path;

use anyhow::Result;
use regex::Regex;

use crate::indexer::store::IndexStore;
use crate::indexer::types::TestFileInfo;

/// Detect whether a file path corresponds to a test file based on naming
/// conventions and directory structure.
pub fn is_test_file(path: &Path) -> bool {
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // TypeScript / JavaScript test patterns
    if file_name.ends_with(".test.ts")
        || file_name.ends_with(".spec.ts")
        || file_name.ends_with(".test.tsx")
        || file_name.ends_with(".spec.tsx")
        || file_name.ends_with(".test.js")
        || file_name.ends_with(".spec.js")
        || file_name.ends_with(".test.jsx")
        || file_name.ends_with(".spec.jsx")
    {
        return true;
    }

    // Python test patterns
    if file_name.ends_with(".py")
        && (file_name.starts_with("test_") || file_name.ends_with("_test.py"))
    {
        return true;
    }

    // Go test pattern
    if file_name.ends_with("_test.go") {
        return true;
    }

    // Directory-based detection: files under tests/, __tests__/, or test/
    let path_str = path.to_string_lossy();
    let has_test_dir = path_str.contains("/tests/")
        || path_str.contains("/__tests__/")
        || path_str.contains("/test/")
        || path_str.starts_with("tests/")
        || path_str.starts_with("__tests__/")
        || path_str.starts_with("test/");

    if has_test_dir {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        matches!(ext, "ts" | "tsx" | "js" | "jsx" | "py" | "go")
    } else {
        false
    }
}

/// Parse a test file and insert a `TestFileInfo` entry into the store.
pub fn parse_test_file(path: &Path, source: &[u8], store: &IndexStore) -> Result<()> {
    let content = std::str::from_utf8(source).unwrap_or("");

    let tables_tested = extract_tables_tested(content);
    let has_write = detect_write_patterns(content);
    let has_read = detect_read_patterns(content);
    let has_assert = detect_assert_patterns(content);

    let info = TestFileInfo {
        path: path.to_path_buf(),
        tables_tested,
        has_write,
        has_read,
        has_assert,
    };

    store.test_files.insert(path.to_path_buf(), info);
    Ok(())
}

/// Extract table names from SQL-like strings in the source content.
fn extract_tables_tested(content: &str) -> Vec<String> {
    let patterns = [
        r#"(?i)\bINSERT\s+INTO\s+[`"']?(\w+)[`"']?"#,
        r#"(?i)\bFROM\s+[`"']?(\w+)[`"']?"#,
        r#"(?i)\bUPDATE\s+[`"']?(\w+)[`"']?\s+SET\b"#,
        r#"(?i)\bDELETE\s+FROM\s+[`"']?(\w+)[`"']?"#,
    ];

    let mut tables: Vec<String> = Vec::new();

    for pattern in &patterns {
        let re = Regex::new(pattern).expect("valid regex");
        for caps in re.captures_iter(content) {
            if let Some(table_match) = caps.get(1) {
                let table_name = table_match.as_str().to_lowercase();
                // Skip SQL keywords that might be falsely captured
                if !is_sql_keyword(&table_name) && !tables.contains(&table_name) {
                    tables.push(table_name);
                }
            }
        }
    }

    tables
}

/// Returns true if the content contains write operation patterns.
fn detect_write_patterns(content: &str) -> bool {
    let re = Regex::new(r"(?i)\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|\.post\(|\.put\(|\.patch\(|POST|PUT|PATCH)\b")
        .expect("valid regex");
    re.is_match(content)
}

/// Returns true if the content contains read operation patterns.
fn detect_read_patterns(content: &str) -> bool {
    let re = Regex::new(
        r#"(?i)\b(SELECT\s|\.get\(|\.find\(|\.query\(|\.findOne\(|\.findMany\(|GET\s+["'/])"#,
    )
    .expect("valid regex");
    re.is_match(content)
}

/// Returns true if the content contains assertion patterns.
fn detect_assert_patterns(content: &str) -> bool {
    let re = Regex::new(r"(?i)\b(assert|expect|should|assert_eq|assert_ne|assertEqual|assertNotEqual|assert_equal|assert_not_equal|assert_raises|assert_called|\.to_be|\.to_equal|\.toBe|\.toEqual|\.toHaveBeenCalled)\b")
        .expect("valid regex");
    re.is_match(content)
}

/// Check if a string is a common SQL keyword (not a table name).
fn is_sql_keyword(name: &str) -> bool {
    matches!(
        name,
        "select"
            | "from"
            | "where"
            | "and"
            | "or"
            | "not"
            | "insert"
            | "into"
            | "update"
            | "delete"
            | "set"
            | "values"
            | "null"
            | "true"
            | "false"
            | "join"
            | "inner"
            | "outer"
            | "left"
            | "right"
            | "on"
            | "group"
            | "order"
            | "by"
            | "having"
            | "limit"
            | "offset"
            | "as"
            | "in"
            | "exists"
            | "between"
            | "like"
            | "is"
            | "case"
            | "when"
            | "then"
            | "else"
            | "end"
            | "distinct"
            | "count"
            | "sum"
            | "avg"
            | "min"
            | "max"
            | "create"
            | "alter"
            | "drop"
            | "table"
            | "index"
            | "view"
            | "schema"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    // ---------------------------------------------------------------
    // is_test_file detection
    // ---------------------------------------------------------------

    #[test]
    fn detects_typescript_test_files() {
        assert!(is_test_file(Path::new("src/users.test.ts")));
        assert!(is_test_file(Path::new("src/users.spec.ts")));
        assert!(is_test_file(Path::new("src/App.test.tsx")));
        assert!(is_test_file(Path::new("src/App.spec.tsx")));
    }

    #[test]
    fn detects_python_test_files() {
        assert!(is_test_file(Path::new("tests/test_users.py")));
        assert!(is_test_file(Path::new("src/users_test.py")));
    }

    #[test]
    fn detects_go_test_files() {
        assert!(is_test_file(Path::new("pkg/handler_test.go")));
    }

    #[test]
    fn detects_files_in_test_directories() {
        assert!(is_test_file(Path::new("__tests__/helper.ts")));
        assert!(is_test_file(Path::new("tests/integration/setup.py")));
        assert!(is_test_file(Path::new("test/api.go")));
    }

    #[test]
    fn rejects_non_test_files() {
        assert!(!is_test_file(Path::new("src/users.ts")));
        assert!(!is_test_file(Path::new("src/main.py")));
        assert!(!is_test_file(Path::new("pkg/handler.go")));
    }

    // ---------------------------------------------------------------
    // Table extraction
    // ---------------------------------------------------------------

    #[test]
    fn extracts_tables_from_sql_strings() {
        let content = r#"
            const q = "INSERT INTO users (name) VALUES ($1)";
            const q2 = "SELECT * FROM orders WHERE id = $1";
            const q3 = "UPDATE products SET price = 10";
            const q4 = "DELETE FROM sessions WHERE expired = true";
        "#;
        let tables = extract_tables_tested(content);
        assert!(tables.contains(&"users".to_string()));
        assert!(tables.contains(&"orders".to_string()));
        assert!(tables.contains(&"products".to_string()));
        assert!(tables.contains(&"sessions".to_string()));
    }

    #[test]
    fn skips_sql_keywords_as_tables() {
        let content = r#"SELECT * FROM select"#;
        let tables = extract_tables_tested(content);
        assert!(!tables.contains(&"select".to_string()));
    }

    #[test]
    fn deduplicates_table_names() {
        let content = r#"
            INSERT INTO users (name) VALUES ($1);
            SELECT * FROM users WHERE active = true;
        "#;
        let tables = extract_tables_tested(content);
        assert_eq!(tables.iter().filter(|t| *t == "users").count(), 1);
    }

    // ---------------------------------------------------------------
    // Write / Read / Assert detection
    // ---------------------------------------------------------------

    #[test]
    fn detects_write_patterns() {
        assert!(detect_write_patterns("INSERT INTO users VALUES (1)"));
        assert!(detect_write_patterns("await api.post('/users')"));
        assert!(detect_write_patterns("fetch(url, { method: 'PUT' })"));
        assert!(!detect_write_patterns("SELECT * FROM users"));
    }

    #[test]
    fn detects_read_patterns() {
        assert!(detect_read_patterns("SELECT * FROM users"));
        assert!(detect_read_patterns("await api.get('/users')"));
        assert!(detect_read_patterns("db.find({ active: true })"));
        assert!(!detect_read_patterns("INSERT INTO users VALUES (1)"));
    }

    #[test]
    fn detects_assert_patterns() {
        assert!(detect_assert_patterns("expect(result).toBe(200)"));
        assert!(detect_assert_patterns("assert_eq!(a, b)"));
        assert!(detect_assert_patterns("self.assertEqual(a, b)"));
        assert!(!detect_assert_patterns("const x = 42;"));
    }

    // ---------------------------------------------------------------
    // Full parse integration
    // ---------------------------------------------------------------

    #[test]
    fn parse_test_file_populates_store() {
        let store = IndexStore::default();
        let path = PathBuf::from("tests/test_orders.py");
        let source = br#"
import pytest

def test_create_order():
    db.execute("INSERT INTO orders (user_id) VALUES (1)")
    result = db.execute("SELECT * FROM orders WHERE user_id = 1")
    assert len(result) == 1
"#;
        parse_test_file(&path, source, &store).unwrap();

        let info = store.test_files.get(&path).expect("test file entry");
        assert!(info.tables_tested.contains(&"orders".to_string()));
        assert!(info.has_write);
        assert!(info.has_read);
        assert!(info.has_assert);
    }
}
