use std::collections::HashSet;
use std::path::PathBuf;

use crate::indexer::types::HttpMethod;
use crate::scanners::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S23";
const SCANNER_NAME: &str = "AuditLogCompleteness";
const SCANNER_DESC: &str =
    "Checks whether state-changing operations have corresponding audit log calls";

pub struct AuditLogCompleteness;

/// Path segments that indicate authentication-related endpoints.
const AUTH_PATH_KEYWORDS: &[&str] = &["login", "logout", "register", "signup", "signin", "signout"];

/// Collect files containing auth endpoints (login, logout, register).
fn collect_auth_endpoint_files(ctx: &ScanContext) -> HashSet<PathBuf> {
    ctx.index
        .all_api_endpoints()
        .into_iter()
        .filter(|ep| {
            let lower = ep.path.to_lowercase();
            AUTH_PATH_KEYWORDS.iter().any(|kw| lower.contains(kw))
        })
        .map(|ep| ep.file)
        .collect()
}

/// Collect files containing mutating (PUT, PATCH, DELETE) endpoints.
fn collect_mutating_endpoint_files(ctx: &ScanContext) -> HashSet<PathBuf> {
    ctx.index
        .all_api_endpoints()
        .into_iter()
        .filter(|ep| {
            matches!(
                ep.method,
                HttpMethod::Put | HttpMethod::Patch | HttpMethod::Delete
            )
        })
        .map(|ep| ep.file)
        .collect()
}

/// Collect files with session invalidation references (user lifecycle changes).
fn collect_session_invalidation_files(ctx: &ScanContext) -> HashSet<PathBuf> {
    ctx.index
        .all_session_invalidation_refs()
        .into_iter()
        .map(|r| r.file)
        .collect()
}

/// Collect files with role check references (role/permission changes).
fn collect_role_check_files(ctx: &ScanContext) -> HashSet<PathBuf> {
    ctx.index
        .all_role_check_refs()
        .into_iter()
        .map(|r| r.file)
        .collect()
}

/// Collect all files that contain audit log calls.
fn collect_audit_log_files(ctx: &ScanContext) -> HashSet<PathBuf> {
    ctx.index
        .all_audit_log_refs()
        .into_iter()
        .map(|r| r.file)
        .collect()
}

/// Merge all state-changing file sets into a single deduplicated set.
fn collect_all_state_changing_files(ctx: &ScanContext) -> HashSet<PathBuf> {
    let mut files = collect_auth_endpoint_files(ctx);
    files.extend(collect_mutating_endpoint_files(ctx));
    files.extend(collect_session_invalidation_files(ctx));
    files.extend(collect_role_check_files(ctx));
    files
}

/// Compute score as the percentage of state-changing files that have audit logs.
fn compute_score(audited: usize, total: usize) -> u8 {
    if total == 0 {
        return 100;
    }
    ((audited as f64 / total as f64) * 100.0).round() as u8
}

impl Scanner for AuditLogCompleteness {
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
        let state_changing_files = collect_all_state_changing_files(ctx);
        let audit_log_files = collect_audit_log_files(ctx);
        let mut findings: Vec<Finding> = Vec::new();

        let total = state_changing_files.len();
        let mut audited_count: usize = 0;

        for file in &state_changing_files {
            if audit_log_files.contains(file) {
                audited_count += 1;
                continue;
            }

            findings.push(
                Finding::new(
                    SCANNER_ID,
                    Severity::Warning,
                    format!(
                        "State-changing file has no audit log call: {}",
                        file.display()
                    ),
                )
                .with_file(file)
                .with_suggestion("Add an audit log call to record this state-changing operation"),
            );
        }

        let score = compute_score(audited_count, total);

        let summary = if total == 0 {
            "No state-changing operations found to audit.".to_string()
        } else {
            format!(
                "{}/{} state-changing files have audit log calls (score: {})",
                audited_count, total, score
            )
        };

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::{
        ApiEndpoint, AuditLogRef, Framework, HttpMethod, RoleCheckRef, RoleCheckType,
        SessionInvalidationRef, SessionInvalidationType,
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

    #[test]
    fn no_state_changes_perfect_score() {
        let config = minimal_config();
        let store = IndexStore::new();

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = AuditLogCompleteness.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
        assert_eq!(
            result.summary,
            "No state-changing operations found to audit."
        );
    }

    #[test]
    fn state_change_without_audit() {
        let config = minimal_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/auth.ts");

        store.api_endpoints.insert(
            "/auth/login".into(),
            vec![ApiEndpoint {
                method: HttpMethod::Post,
                path: "/auth/login".to_string(),
                file: file.clone(),
                line: 10,
                framework: Framework::Express,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = AuditLogCompleteness.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
        assert!(result.findings[0].message.contains("no audit log call"));
    }

    #[test]
    fn state_change_with_audit() {
        let config = minimal_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/auth.ts");

        store.api_endpoints.insert(
            "/auth/login".into(),
            vec![ApiEndpoint {
                method: HttpMethod::Post,
                path: "/auth/login".to_string(),
                file: file.clone(),
                line: 10,
                framework: Framework::Express,
            }],
        );

        store.audit_log_refs.insert(
            file.clone(),
            vec![AuditLogRef {
                file: file.clone(),
                line: 15,
                event_name: Some("user.login".to_string()),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = AuditLogCompleteness.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn score_calculation() {
        let config = minimal_config();
        let store = IndexStore::new();

        let auth_file = PathBuf::from("routes/auth.ts");
        let delete_file = PathBuf::from("routes/users.ts");
        let session_file = PathBuf::from("services/session.ts");
        let role_file = PathBuf::from("middleware/rbac.ts");

        // Auth endpoint (has audit)
        store.api_endpoints.insert(
            "/auth/login".into(),
            vec![ApiEndpoint {
                method: HttpMethod::Post,
                path: "/auth/login".to_string(),
                file: auth_file.clone(),
                line: 10,
                framework: Framework::Express,
            }],
        );
        store.audit_log_refs.insert(
            auth_file.clone(),
            vec![AuditLogRef {
                file: auth_file.clone(),
                line: 15,
                event_name: Some("user.login".to_string()),
            }],
        );

        // DELETE endpoint (no audit)
        store
            .api_endpoints
            .entry("/users/:id".into())
            .or_default()
            .push(ApiEndpoint {
                method: HttpMethod::Delete,
                path: "/users/:id".to_string(),
                file: delete_file.clone(),
                line: 20,
                framework: Framework::Express,
            });

        // Session invalidation file (no audit)
        store.session_invalidation_refs.insert(
            session_file.clone(),
            vec![SessionInvalidationRef {
                file: session_file.clone(),
                line: 30,
                invalidation_type: SessionInvalidationType::SessionDestroy,
            }],
        );

        // Role check file (has audit)
        store.role_check_refs.insert(
            role_file.clone(),
            vec![RoleCheckRef {
                file: role_file.clone(),
                line: 5,
                check_type: RoleCheckType::SingleValue,
                role_value: "admin".to_string(),
                is_middleware: true,
            }],
        );
        store.audit_log_refs.insert(
            role_file.clone(),
            vec![AuditLogRef {
                file: role_file.clone(),
                line: 8,
                event_name: Some("role.check".to_string()),
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = AuditLogCompleteness.scan(&ctx);
        // 4 state-changing files, 2 have audit => 50%
        assert_eq!(result.score, 50);
        assert_eq!(result.findings.len(), 2);
    }

    #[test]
    fn destructive_endpoint_without_audit() {
        let config = minimal_config();
        let store = IndexStore::new();

        let file = PathBuf::from("routes/resources.ts");

        store.api_endpoints.insert(
            "/resources/:id".into(),
            vec![ApiEndpoint {
                method: HttpMethod::Delete,
                path: "/resources/:id".to_string(),
                file: file.clone(),
                line: 25,
                framework: Framework::Express,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = AuditLogCompleteness.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert!(result.findings[0].message.contains("resources.ts"));
    }

    #[test]
    fn put_and_patch_endpoints_without_audit() {
        let config = minimal_config();
        let store = IndexStore::new();

        let put_file = PathBuf::from("routes/settings.ts");
        let patch_file = PathBuf::from("routes/profile.ts");

        store.api_endpoints.insert(
            "/settings".into(),
            vec![ApiEndpoint {
                method: HttpMethod::Put,
                path: "/settings".to_string(),
                file: put_file.clone(),
                line: 10,
                framework: Framework::Express,
            }],
        );

        store
            .api_endpoints
            .entry("/profile".into())
            .or_default()
            .push(ApiEndpoint {
                method: HttpMethod::Patch,
                path: "/profile".to_string(),
                file: patch_file.clone(),
                line: 15,
                framework: Framework::Express,
            });

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = AuditLogCompleteness.scan(&ctx);
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 2);

        let messages: Vec<&str> = result.findings.iter().map(|f| f.message.as_str()).collect();
        assert!(messages.iter().any(|m| m.contains("settings.ts")));
        assert!(messages.iter().any(|m| m.contains("profile.ts")));
    }

    #[test]
    fn deduplicated_file_counted_once() {
        let config = minimal_config();
        let store = IndexStore::new();

        // Same file is both an auth endpoint and has session invalidation
        let file = PathBuf::from("routes/auth.ts");

        store.api_endpoints.insert(
            "/auth/logout".into(),
            vec![ApiEndpoint {
                method: HttpMethod::Post,
                path: "/auth/logout".to_string(),
                file: file.clone(),
                line: 10,
                framework: Framework::Express,
            }],
        );

        store.session_invalidation_refs.insert(
            file.clone(),
            vec![SessionInvalidationRef {
                file: file.clone(),
                line: 15,
                invalidation_type: SessionInvalidationType::CookieClear,
            }],
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = AuditLogCompleteness.scan(&ctx);
        // File appears in two categories but should only count once
        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
    }
}
