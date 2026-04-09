use std::collections::HashSet;
use std::path::PathBuf;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};
use crate::indexer::types::{DbWriteOp, DbWriteRef};

pub struct RaceConditionSafety;

const SCANNER_ID: &str = "S27";
const SCANNER_NAME: &str = "RaceConditionSafety";
const SCANNER_DESC: &str = "Detects database write operations in auth paths without concurrency protection (transactions, locks, ON CONFLICT)";

/// Keywords in API endpoint paths that indicate auth-related routes.
const AUTH_PATH_KEYWORDS: &[&str] = &["login", "register", "auth", "verify", "user", "account"];

/// Keywords in file path segments that indicate auth-related source files.
const AUTH_FILE_KEYWORDS: &[&str] = &[
    "login", "register", "auth", "verify", "user", "account", "signup", "signin", "session",
];

/// Returns true if the given path string contains any auth-related keyword.
fn is_auth_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    AUTH_PATH_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Returns true if the file path contains auth-related segments.
fn is_auth_file(file: &std::path::Path) -> bool {
    let lower = file.to_string_lossy().to_lowercase();
    AUTH_FILE_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Collect files that contain auth-related API endpoints.
fn collect_auth_endpoint_files(ctx: &ScanContext) -> HashSet<PathBuf> {
    ctx.index
        .all_api_endpoints()
        .into_iter()
        .filter(|ep| is_auth_path(&ep.path))
        .map(|ep| ep.file)
        .collect()
}

/// Collect files that have concurrency safety protection.
fn collect_protected_files(ctx: &ScanContext) -> HashSet<PathBuf> {
    ctx.index
        .all_concurrency_safety_refs()
        .into_iter()
        .map(|r| r.file)
        .collect()
}

/// Filter DB write refs to only Insert and Upsert operations.
fn collect_insert_upsert_writes(ctx: &ScanContext) -> Vec<DbWriteRef> {
    ctx.index
        .all_db_write_refs()
        .into_iter()
        .filter(|r| r.operation == DbWriteOp::Insert || r.operation == DbWriteOp::Upsert)
        .collect()
}

/// Compute score from the ratio of protected to total auth write files.
fn compute_score(protected: usize, total: usize) -> u8 {
    if total == 0 {
        return 100;
    }
    ((protected as f64 / total as f64) * 100.0).round() as u8
}

fn build_summary(findings: &[Finding], _protected: usize, total: usize, score: u8) -> String {
    if total == 0 {
        return "No auth-path database write operations found -- nothing to check.".to_string();
    }
    if findings.is_empty() {
        return format!(
            "All {} auth write files have concurrency protection (score: {})",
            total, score
        );
    }
    format!(
        "{}/{} auth write files lack concurrency protection ({} unprotected, score: {})",
        findings.len(),
        total,
        findings.len(),
        score
    )
}

impl Scanner for RaceConditionSafety {
    fn id(&self) -> &str {
        SCANNER_ID
    }

    fn name(&self) -> &str {
        SCANNER_NAME
    }

    fn description(&self) -> &str {
        SCANNER_DESC
    }

    fn scan(&self, ctx: &ScanContext) -> ScanResult {
        let insert_writes = collect_insert_upsert_writes(ctx);

        if insert_writes.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No auth-path database write operations found -- nothing to check."
                    .to_string(),
            };
        }

        let auth_endpoint_files = collect_auth_endpoint_files(ctx);
        let protected_files = collect_protected_files(ctx);

        // Find files that have insert/upsert writes AND are auth-related
        // (either the file hosts an auth endpoint, or the file path itself is auth-related).
        let auth_write_files: HashSet<PathBuf> = insert_writes
            .iter()
            .filter(|w| auth_endpoint_files.contains(&w.file) || is_auth_file(&w.file))
            .map(|w| w.file.clone())
            .collect();

        if auth_write_files.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No auth-path database write operations found -- nothing to check."
                    .to_string(),
            };
        }

        let total = auth_write_files.len();
        let mut findings: Vec<Finding> = Vec::new();
        let mut protected_count: usize = 0;

        // For each unprotected auth write file, find the first insert/upsert ref
        // to use for the finding location.
        let mut sorted_files: Vec<PathBuf> = auth_write_files.into_iter().collect();
        sorted_files.sort();

        for file in &sorted_files {
            if protected_files.contains(file) {
                protected_count += 1;
                continue;
            }

            let representative_write = insert_writes
                .iter()
                .find(|w| &w.file == file)
                .expect("file must have at least one write ref");

            let op_label = match representative_write.operation {
                DbWriteOp::Insert => "INSERT",
                DbWriteOp::Upsert => "UPSERT",
                _ => "WRITE",
            };

            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Warning,
                    format!(
                        "Auth-path file has {} on '{}' without concurrency protection (transaction, lock, or ON CONFLICT)",
                        op_label, representative_write.table_name,
                    ),
                )
                .with_file(file)
                .with_line(representative_write.line)
                .with_suggestion(
                    "Wrap the write operation in a transaction, use a database lock, or add an ON CONFLICT clause to prevent race conditions",
                ),
            );
        }

        let score = compute_score(protected_count, total);
        let summary = build_summary(&findings, protected_count, total, score);

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{
        ApiEndpoint, ConcurrencySafetyRef, ConcurrencySafetyType, DbWriteRef, Framework, HttpMethod,
    };
    use std::path::Path;

    fn minimal_config() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    fn make_db_write(table: &str, op: DbWriteOp, file: &str, line: usize) -> DbWriteRef {
        DbWriteRef {
            table_name: table.to_string(),
            operation: op,
            file: PathBuf::from(file),
            line,
        }
    }

    fn make_auth_endpoint(path: &str, file: &str, line: usize) -> ApiEndpoint {
        ApiEndpoint {
            method: HttpMethod::Post,
            path: path.to_string(),
            file: PathBuf::from(file),
            line,
            framework: Framework::Express,
        }
    }

    fn make_concurrency_ref(file: &str, line: usize) -> ConcurrencySafetyRef {
        ConcurrencySafetyRef {
            file: PathBuf::from(file),
            line,
            safety_type: ConcurrencySafetyType::Transaction,
        }
    }

    fn insert_db_write(store: &IndexStore, write: DbWriteRef) {
        store
            .data
            .db_write_refs
            .entry(write.table_name.clone())
            .or_default()
            .push(write);
    }

    fn insert_endpoint(store: &IndexStore, ep: ApiEndpoint) {
        store
            .api
            .endpoints
            .entry(ep.path.clone())
            .or_default()
            .push(ep);
    }

    fn insert_concurrency_ref(store: &IndexStore, r: ConcurrencySafetyRef) {
        store
            .code_quality
            .concurrency_safety_refs
            .entry(r.file.clone())
            .or_default()
            .push(r);
    }

    // -----------------------------------------------------------------------
    // Test: no auth writes at all => perfect score
    // -----------------------------------------------------------------------
    #[test]
    fn no_auth_writes_perfect_score() {
        let store = IndexStore::new();
        let config = minimal_config();
        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("."),
        };

        let result = RaceConditionSafety.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test: auth file with INSERT but no concurrency protection => warning
    // -----------------------------------------------------------------------
    #[test]
    fn auth_write_without_protection() {
        let store = IndexStore::new();
        let config = minimal_config();

        // Insert in a file whose path is auth-related
        insert_db_write(
            &store,
            make_db_write("users", DbWriteOp::Insert, "src/auth/register.ts", 25),
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("."),
        };

        let result = RaceConditionSafety.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("INSERT"));
        assert!(result.findings[0]
            .message
            .contains("concurrency protection"));
    }

    // -----------------------------------------------------------------------
    // Test: auth file with INSERT + transaction protection => no findings
    // -----------------------------------------------------------------------
    #[test]
    fn auth_write_with_transaction() {
        let store = IndexStore::new();
        let config = minimal_config();

        let file = "src/auth/register.ts";

        insert_db_write(&store, make_db_write("users", DbWriteOp::Insert, file, 25));
        insert_concurrency_ref(&store, make_concurrency_ref(file, 20));

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("."),
        };

        let result = RaceConditionSafety.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test: non-auth file with INSERT but no protection => ignored
    // -----------------------------------------------------------------------
    #[test]
    fn non_auth_writes_ignored() {
        let store = IndexStore::new();
        let config = minimal_config();

        // Insert in a file that is NOT auth-related
        insert_db_write(
            &store,
            make_db_write("products", DbWriteOp::Insert, "src/catalog/products.ts", 30),
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("."),
        };

        let result = RaceConditionSafety.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test: score calculation with mixed protected/unprotected
    // -----------------------------------------------------------------------
    #[test]
    fn score_calculation() {
        let store = IndexStore::new();
        let config = minimal_config();

        // Two auth write files: one protected, one not
        let protected_file = "src/auth/login.ts";
        let unprotected_file = "src/auth/register.ts";

        insert_db_write(
            &store,
            make_db_write("sessions", DbWriteOp::Insert, protected_file, 10),
        );
        insert_db_write(
            &store,
            make_db_write("users", DbWriteOp::Insert, unprotected_file, 20),
        );
        insert_concurrency_ref(&store, make_concurrency_ref(protected_file, 8));

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("."),
        };

        let result = RaceConditionSafety.scan(&ctx);
        assert_eq!(result.score, 50);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("users"));
    }

    // -----------------------------------------------------------------------
    // Test: auth endpoint file (not auth path name) is detected
    // -----------------------------------------------------------------------
    #[test]
    fn auth_endpoint_file_detected() {
        let store = IndexStore::new();
        let config = minimal_config();

        // File does NOT have an auth-keyword path, but hosts an auth endpoint
        let file = "src/routes/handler.ts";
        insert_db_write(&store, make_db_write("tokens", DbWriteOp::Upsert, file, 42));
        insert_endpoint(&store, make_auth_endpoint("/api/auth/verify", file, 10));

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("."),
        };

        let result = RaceConditionSafety.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("UPSERT"));
    }

    // -----------------------------------------------------------------------
    // Test: UPDATE and DELETE operations are not flagged
    // -----------------------------------------------------------------------
    #[test]
    fn update_and_delete_not_flagged() {
        let store = IndexStore::new();
        let config = minimal_config();

        insert_db_write(
            &store,
            make_db_write("users", DbWriteOp::Update, "src/auth/profile.ts", 15),
        );
        insert_db_write(
            &store,
            make_db_write("sessions", DbWriteOp::Delete, "src/auth/logout.ts", 20),
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("."),
        };

        let result = RaceConditionSafety.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    // -----------------------------------------------------------------------
    // Test: ON CONFLICT safety type protects the file
    // -----------------------------------------------------------------------
    #[test]
    fn on_conflict_protection_accepted() {
        let store = IndexStore::new();
        let config = minimal_config();

        let file = "src/auth/register.ts";
        insert_db_write(&store, make_db_write("users", DbWriteOp::Insert, file, 25));
        store
            .code_quality
            .concurrency_safety_refs
            .entry(PathBuf::from(file))
            .or_default()
            .push(ConcurrencySafetyRef {
                file: PathBuf::from(file),
                line: 24,
                safety_type: ConcurrencySafetyType::OnConflict,
            });

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("."),
        };

        let result = RaceConditionSafety.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }
}
