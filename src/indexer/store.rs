use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::types::*;

#[derive(Default)]
pub struct IndexStore {
    pub files: DashMap<PathBuf, FileInfo>,
    pub api_endpoints: DashMap<String, Vec<ApiEndpoint>>,
    pub api_calls: DashMap<String, Vec<ApiCall>>,
    pub imports: DashMap<PathBuf, Vec<ImportEdge>>,
    pub env_refs: DashMap<String, Vec<EnvRef>>,
    pub env_configs: DashMap<String, Vec<EnvConfig>>,
    pub event_producers: DashMap<String, Vec<EventProducer>>,
    pub event_consumers: DashMap<String, Vec<EventConsumer>>,
    pub db_tables: DashMap<String, TableInfo>,
    pub test_files: DashMap<PathBuf, TestFileInfo>,
    pub stub_indicators: DashMap<PathBuf, Vec<StubIndicator>>,
    pub dockerfile_checks: DashMap<String, DockerfileCheck>,
    pub middleware_scopes: DashMap<PathBuf, Vec<MiddlewareScope>>,
    pub db_write_refs: DashMap<String, Vec<DbWriteRef>>,
    pub redis_key_refs: DashMap<String, Vec<RedisKeyRef>>,
    pub rls_context_refs: DashMap<PathBuf, Vec<RlsContextRef>>,
    pub rls_policies: DashMap<String, Vec<RlsPolicyInfo>>,
    pub hardcoded_creds: DashMap<PathBuf, Vec<HardcodedCredential>>,
    pub sql_query_refs: DashMap<String, Vec<SqlQueryRef>>,
}

impl IndexStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn all_api_endpoints(&self) -> Vec<ApiEndpoint> {
        self.api_endpoints
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_api_calls(&self) -> Vec<ApiCall> {
        self.api_calls
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_imports(&self) -> Vec<ImportEdge> {
        self.imports
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_env_refs(&self) -> Vec<EnvRef> {
        self.env_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_env_configs(&self) -> Vec<EnvConfig> {
        self.env_configs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_event_producers(&self) -> Vec<EventProducer> {
        self.event_producers
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_event_consumers(&self) -> Vec<EventConsumer> {
        self.event_consumers
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_db_tables(&self) -> Vec<TableInfo> {
        self.db_tables
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_test_files(&self) -> Vec<TestFileInfo> {
        self.test_files
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_dockerfile_checks(&self) -> Vec<DockerfileCheck> {
        self.dockerfile_checks
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_stub_indicators(&self) -> Vec<StubIndicator> {
        self.stub_indicators
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn endpoints_for_path(&self, normalized: &str) -> Vec<ApiEndpoint> {
        self.api_endpoints
            .get(normalized)
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }

    pub fn calls_for_url(&self, normalized: &str) -> Vec<ApiCall> {
        self.api_calls
            .get(normalized)
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }

    pub fn imports_for_file(&self, path: &Path) -> Vec<ImportEdge> {
        self.imports
            .get(path)
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }

    pub fn stubs_for_file(&self, path: &Path) -> Vec<StubIndicator> {
        self.stub_indicators
            .get(path)
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }

    pub fn all_db_write_refs(&self) -> Vec<DbWriteRef> {
        self.db_write_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_redis_key_refs(&self) -> Vec<RedisKeyRef> {
        self.redis_key_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_rls_context_refs(&self) -> Vec<RlsContextRef> {
        self.rls_context_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_rls_policies(&self) -> Vec<RlsPolicyInfo> {
        self.rls_policies
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_hardcoded_creds(&self) -> Vec<HardcodedCredential> {
        self.hardcoded_creds
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_sql_query_refs(&self) -> Vec<SqlQueryRef> {
        self.sql_query_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn has_middleware_protection(&self, file: &Path, line: usize) -> bool {
        self.middleware_scopes
            .get(file)
            .map(|scopes| {
                scopes
                    .value()
                    .iter()
                    .any(|scope| line >= scope.line_start && line <= scope.line_end)
            })
            .unwrap_or(false)
    }
}

/// Normalize an API path for consistent matching.
///
/// - Replace `:param_name` with `:param`
/// - Replace `{param_name}` with `:param`
/// - Remove trailing slashes
/// - Lowercase
pub fn normalize_api_path(path: &str) -> String {
    let lowered = path.to_lowercase();
    let trimmed = lowered.trim_end_matches('/');

    let mut result = String::with_capacity(trimmed.len());
    let mut chars = trimmed.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == ':' {
            // Consume the parameter name, replace with :param
            result.push_str(":param");
            while let Some(&next) = chars.peek() {
                if next == '/' {
                    break;
                }
                chars.next();
            }
        } else if ch == '{' {
            // Consume until closing brace, replace with :param
            result.push_str(":param");
            while let Some(inner) = chars.next() {
                if inner == '}' {
                    break;
                }
            }
        } else {
            result.push(ch);
        }
    }

    if result.is_empty() {
        "/".to_string()
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_colon_params() {
        assert_eq!(
            normalize_api_path("/users/:userId/posts/:postId"),
            "/users/:param/posts/:param"
        );
    }

    #[test]
    fn test_normalize_brace_params() {
        assert_eq!(
            normalize_api_path("/users/{userId}/posts/{postId}"),
            "/users/:param/posts/:param"
        );
    }

    #[test]
    fn test_normalize_trailing_slash() {
        assert_eq!(normalize_api_path("/api/v1/users/"), "/api/v1/users");
    }

    #[test]
    fn test_normalize_lowercase() {
        assert_eq!(normalize_api_path("/API/V1/Users"), "/api/v1/users");
    }

    #[test]
    fn test_normalize_mixed() {
        assert_eq!(
            normalize_api_path("/API/{orgId}/Users/:name/"),
            "/api/:param/users/:param"
        );
    }

    #[test]
    fn test_normalize_empty_path() {
        assert_eq!(normalize_api_path("/"), "/");
    }
}
