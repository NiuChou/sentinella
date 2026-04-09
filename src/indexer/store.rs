use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::types::*;

/// API routing and endpoint data
#[derive(Default)]
pub struct ApiStore {
    pub endpoints: DashMap<String, Vec<ApiEndpoint>>,
    pub calls: DashMap<String, Vec<ApiCall>>,
}

impl ApiStore {
    pub fn all_endpoints(&self) -> Vec<ApiEndpoint> {
        self.endpoints
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_calls(&self) -> Vec<ApiCall> {
        self.calls
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn endpoints_for_path(&self, normalized: &str) -> Vec<ApiEndpoint> {
        self.endpoints
            .get(normalized)
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }

    pub fn calls_for_url(&self, normalized: &str) -> Vec<ApiCall> {
        self.calls
            .get(normalized)
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }
}

/// Security-related indexed data (auth, tokens, credentials, RLS, etc.)
#[derive(Default)]
pub struct SecurityStore {
    pub middleware_scopes: DashMap<PathBuf, Vec<MiddlewareScope>>,
    pub hardcoded_creds: DashMap<PathBuf, Vec<HardcodedCredential>>,
    pub rls_context_refs: DashMap<PathBuf, Vec<RlsContextRef>>,
    pub rls_policies: DashMap<String, Vec<RlsPolicyInfo>>,
    pub secondary_auth_refs: DashMap<PathBuf, Vec<SecondaryAuthRef>>,
    pub role_check_refs: DashMap<PathBuf, Vec<RoleCheckRef>>,
    pub session_invalidation_refs: DashMap<PathBuf, Vec<SessionInvalidationRef>>,
    pub sensitive_log_refs: DashMap<PathBuf, Vec<SensitiveLogRef>>,
    pub insecure_storage_refs: DashMap<PathBuf, Vec<InsecureStorageRef>>,
    pub rate_limit_refs: DashMap<PathBuf, Vec<RateLimitRef>>,
    pub audit_log_refs: DashMap<PathBuf, Vec<AuditLogRef>>,
    pub test_bypass_refs: DashMap<PathBuf, Vec<TestBypassRef>>,
    pub token_refresh_refs: DashMap<PathBuf, Vec<TokenRefreshRef>>,
    pub grant_details: DashMap<String, Vec<GrantDetail>>,
}

impl SecurityStore {
    pub fn all_hardcoded_creds(&self) -> Vec<HardcodedCredential> {
        self.hardcoded_creds
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

    pub fn all_secondary_auth_refs(&self) -> Vec<SecondaryAuthRef> {
        self.secondary_auth_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_role_check_refs(&self) -> Vec<RoleCheckRef> {
        self.role_check_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_session_invalidation_refs(&self) -> Vec<SessionInvalidationRef> {
        self.session_invalidation_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_sensitive_log_refs(&self) -> Vec<SensitiveLogRef> {
        self.sensitive_log_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_insecure_storage_refs(&self) -> Vec<InsecureStorageRef> {
        self.insecure_storage_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_rate_limit_refs(&self) -> Vec<RateLimitRef> {
        self.rate_limit_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_audit_log_refs(&self) -> Vec<AuditLogRef> {
        self.audit_log_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_test_bypass_refs(&self) -> Vec<TestBypassRef> {
        self.test_bypass_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_token_refresh_refs(&self) -> Vec<TokenRefreshRef> {
        self.token_refresh_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_grant_details(&self) -> Vec<GrantDetail> {
        self.grant_details
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }
}

/// Infrastructure and deployment data (env vars, Docker, config)
#[derive(Default)]
pub struct InfraStore {
    pub env_refs: DashMap<String, Vec<EnvRef>>,
    pub env_configs: DashMap<String, Vec<EnvConfig>>,
    pub dockerfile_checks: DashMap<String, DockerfileCheck>,
}

impl InfraStore {
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

    pub fn all_dockerfile_checks(&self) -> Vec<DockerfileCheck> {
        self.dockerfile_checks
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
}

/// Code quality and testing data (error handling, test patterns, stubs)
#[derive(Default)]
pub struct CodeQualityStore {
    pub stub_indicators: DashMap<PathBuf, Vec<StubIndicator>>,
    pub test_files: DashMap<PathBuf, TestFileInfo>,
    pub error_handling_refs: DashMap<PathBuf, Vec<ErrorHandlingRef>>,
    pub function_signatures: DashMap<PathBuf, Vec<FunctionSignature>>,
    pub concurrency_safety_refs: DashMap<PathBuf, Vec<ConcurrencySafetyRef>>,
}

impl CodeQualityStore {
    pub fn all_stub_indicators(&self) -> Vec<StubIndicator> {
        self.stub_indicators
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_test_files(&self) -> Vec<TestFileInfo> {
        self.test_files
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_error_handling_refs(&self) -> Vec<ErrorHandlingRef> {
        self.error_handling_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_function_signatures(&self) -> Vec<FunctionSignature> {
        self.function_signatures
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_concurrency_safety_refs(&self) -> Vec<ConcurrencySafetyRef> {
        self.concurrency_safety_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn stubs_for_file(&self, path: &Path) -> Vec<StubIndicator> {
        self.stub_indicators
            .get(path)
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }
}

/// Database and data layer (SQL, migrations, pools, Redis)
#[derive(Default)]
pub struct DataStore {
    pub db_tables: DashMap<String, TableInfo>,
    pub db_write_refs: DashMap<String, Vec<DbWriteRef>>,
    pub sql_query_refs: DashMap<String, Vec<SqlQueryRef>>,
    pub db_pool_refs: DashMap<PathBuf, Vec<DbPoolRef>>,
    pub service_boundaries: DashMap<String, ServiceBoundary>,
    pub table_ownership: DashMap<String, String>,
    pub soft_delete_columns: DashMap<String, Vec<SoftDeleteColumn>>,
    pub redis_key_refs: DashMap<String, Vec<RedisKeyRef>>,
    pub unique_constraint_refs: DashMap<String, Vec<UniqueConstraintRef>>,
    pub column_lookup_refs: DashMap<String, Vec<ColumnLookupRef>>,
    pub status_literal_refs: DashMap<String, Vec<StatusLiteralRef>>,
}

impl DataStore {
    pub fn all_db_tables(&self) -> Vec<TableInfo> {
        self.db_tables
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_db_write_refs(&self) -> Vec<DbWriteRef> {
        self.db_write_refs
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

    pub fn all_db_pool_refs(&self) -> Vec<(PathBuf, Vec<DbPoolRef>)> {
        self.db_pool_refs
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    pub fn all_service_boundaries(&self) -> Vec<(String, ServiceBoundary)> {
        self.service_boundaries
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    pub fn all_soft_delete_columns(&self) -> Vec<SoftDeleteColumn> {
        self.soft_delete_columns
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

    pub fn all_unique_constraint_refs(&self) -> Vec<UniqueConstraintRef> {
        self.unique_constraint_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_column_lookup_refs(&self) -> Vec<ColumnLookupRef> {
        self.column_lookup_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_status_literal_refs(&self) -> Vec<StatusLiteralRef> {
        self.status_literal_refs
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }
}

/// Event and messaging (Kafka, event schemas)
#[derive(Default)]
pub struct EventStore {
    pub producers: DashMap<String, Vec<EventProducer>>,
    pub consumers: DashMap<String, Vec<EventConsumer>>,
}

impl EventStore {
    pub fn all_producers(&self) -> Vec<EventProducer> {
        self.producers
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn all_consumers(&self) -> Vec<EventConsumer> {
        self.consumers
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }
}

#[derive(Default)]
pub struct IndexStore {
    // Cross-cutting fields at top level
    pub files: DashMap<PathBuf, FileInfo>,
    pub imports: DashMap<PathBuf, Vec<ImportEdge>>,

    // Domain sub-stores
    pub api: ApiStore,
    pub security: SecurityStore,
    pub infra: InfraStore,
    pub code_quality: CodeQualityStore,
    pub data: DataStore,
    pub events: EventStore,

    pub evidence_store: crate::evidence::EvidenceStore,
}

impl IndexStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    // -- API ------------------------------------------------------------------

    pub fn all_api_endpoints(&self) -> Vec<ApiEndpoint> {
        self.api.all_endpoints()
    }

    pub fn all_api_calls(&self) -> Vec<ApiCall> {
        self.api.all_calls()
    }

    pub fn endpoints_for_path(&self, normalized: &str) -> Vec<ApiEndpoint> {
        self.api.endpoints_for_path(normalized)
    }

    pub fn calls_for_url(&self, normalized: &str) -> Vec<ApiCall> {
        self.api.calls_for_url(normalized)
    }

    // -- Files / Imports ------------------------------------------------------

    pub fn all_imports(&self) -> Vec<ImportEdge> {
        self.imports
            .iter()
            .flat_map(|entry| entry.value().clone())
            .collect()
    }

    pub fn imports_for_file(&self, path: &Path) -> Vec<ImportEdge> {
        self.imports
            .get(path)
            .map(|entry| entry.value().clone())
            .unwrap_or_default()
    }

    // -- Infra ----------------------------------------------------------------

    pub fn all_env_refs(&self) -> Vec<EnvRef> {
        self.infra.all_env_refs()
    }

    pub fn all_env_configs(&self) -> Vec<EnvConfig> {
        self.infra.all_env_configs()
    }

    pub fn all_dockerfile_checks(&self) -> Vec<DockerfileCheck> {
        self.infra.all_dockerfile_checks()
    }

    // -- Events ---------------------------------------------------------------

    pub fn all_event_producers(&self) -> Vec<EventProducer> {
        self.events.all_producers()
    }

    pub fn all_event_consumers(&self) -> Vec<EventConsumer> {
        self.events.all_consumers()
    }

    // -- Data -----------------------------------------------------------------

    pub fn all_db_tables(&self) -> Vec<TableInfo> {
        self.data.all_db_tables()
    }

    pub fn all_db_write_refs(&self) -> Vec<DbWriteRef> {
        self.data.all_db_write_refs()
    }

    pub fn all_redis_key_refs(&self) -> Vec<RedisKeyRef> {
        self.data.all_redis_key_refs()
    }

    pub fn all_rls_context_refs(&self) -> Vec<RlsContextRef> {
        self.security.all_rls_context_refs()
    }

    pub fn all_rls_policies(&self) -> Vec<RlsPolicyInfo> {
        self.security.all_rls_policies()
    }

    pub fn all_hardcoded_creds(&self) -> Vec<HardcodedCredential> {
        self.security.all_hardcoded_creds()
    }

    pub fn all_sql_query_refs(&self) -> Vec<SqlQueryRef> {
        self.data.all_sql_query_refs()
    }

    pub fn all_db_pool_refs(&self) -> Vec<(PathBuf, Vec<DbPoolRef>)> {
        self.data.all_db_pool_refs()
    }

    pub fn all_service_boundaries(&self) -> Vec<(String, ServiceBoundary)> {
        self.data.all_service_boundaries()
    }

    pub fn all_secondary_auth_refs(&self) -> Vec<SecondaryAuthRef> {
        self.security.all_secondary_auth_refs()
    }

    pub fn all_soft_delete_columns(&self) -> Vec<SoftDeleteColumn> {
        self.data.all_soft_delete_columns()
    }

    pub fn all_error_handling_refs(&self) -> Vec<ErrorHandlingRef> {
        self.code_quality.all_error_handling_refs()
    }

    pub fn all_role_check_refs(&self) -> Vec<RoleCheckRef> {
        self.security.all_role_check_refs()
    }

    pub fn all_function_signatures(&self) -> Vec<FunctionSignature> {
        self.code_quality.all_function_signatures()
    }

    pub fn all_status_literal_refs(&self) -> Vec<StatusLiteralRef> {
        self.data.all_status_literal_refs()
    }

    pub fn all_session_invalidation_refs(&self) -> Vec<SessionInvalidationRef> {
        self.security.all_session_invalidation_refs()
    }

    pub fn all_sensitive_log_refs(&self) -> Vec<SensitiveLogRef> {
        self.security.all_sensitive_log_refs()
    }

    pub fn all_insecure_storage_refs(&self) -> Vec<InsecureStorageRef> {
        self.security.all_insecure_storage_refs()
    }

    pub fn all_rate_limit_refs(&self) -> Vec<RateLimitRef> {
        self.security.all_rate_limit_refs()
    }

    pub fn all_audit_log_refs(&self) -> Vec<AuditLogRef> {
        self.security.all_audit_log_refs()
    }

    pub fn all_unique_constraint_refs(&self) -> Vec<UniqueConstraintRef> {
        self.data.all_unique_constraint_refs()
    }

    pub fn all_column_lookup_refs(&self) -> Vec<ColumnLookupRef> {
        self.data.all_column_lookup_refs()
    }

    pub fn all_test_bypass_refs(&self) -> Vec<TestBypassRef> {
        self.security.all_test_bypass_refs()
    }

    pub fn all_token_refresh_refs(&self) -> Vec<TokenRefreshRef> {
        self.security.all_token_refresh_refs()
    }

    pub fn all_concurrency_safety_refs(&self) -> Vec<ConcurrencySafetyRef> {
        self.code_quality.all_concurrency_safety_refs()
    }

    pub fn all_grant_details(&self) -> Vec<GrantDetail> {
        self.security.all_grant_details()
    }

    pub fn all_test_files(&self) -> Vec<TestFileInfo> {
        self.code_quality.all_test_files()
    }

    pub fn all_stub_indicators(&self) -> Vec<StubIndicator> {
        self.code_quality.all_stub_indicators()
    }

    pub fn stubs_for_file(&self, path: &Path) -> Vec<StubIndicator> {
        self.code_quality.stubs_for_file(path)
    }

    /// Deprecated: use `evidence_store.has_protection(file, line, EvidenceKind::Auth)` instead.
    pub fn has_middleware_protection(&self, file: &Path, line: usize) -> bool {
        self.security
            .middleware_scopes
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
/// - Strip query strings (`?key=val`)
/// - Replace `:param_name` with `:param`
/// - Replace `{param_name}`, `${param_name}`, `[param_name]` with `:param`
/// - Remove trailing slashes
/// - Lowercase
pub fn normalize_api_path(path: &str) -> String {
    // Strip query string before normalizing
    let path_only = path.split('?').next().unwrap_or(path);
    let lowered = path_only.to_lowercase();
    let trimmed = lowered.trim_end_matches('/');

    normalize_param_segments(trimmed)
}

/// Core parameter normalization shared by all path-matching functions.
/// Replaces `:name`, `{name}`, `${name}`, and `[name]` with `:param`.
fn normalize_param_segments(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            // Consume `${param_name}`, replace with :param
            chars.next(); // consume '{'
            result.push_str(":param");
            for inner in chars.by_ref() {
                if inner == '}' {
                    break;
                }
            }
        } else if ch == ':' {
            // Consume `:param_name`, replace with :param
            result.push_str(":param");
            while let Some(&next) = chars.peek() {
                if next == '/' {
                    break;
                }
                chars.next();
            }
        } else if ch == '{' {
            // Consume `{param_name}`, replace with :param
            result.push_str(":param");
            for inner in chars.by_ref() {
                if inner == '}' {
                    break;
                }
            }
        } else if ch == '[' {
            // Consume `[param_name]`, replace with :param
            result.push_str(":param");
            for inner in chars.by_ref() {
                if inner == ']' {
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

/// Generate plural/singular variants of a normalized path.
///
/// For each non-parameter segment, produces a variant where that segment
/// has its trailing 's' toggled (added or removed). Returns the original
/// path plus all single-segment variants.
pub fn plural_variants(normalized: &str) -> Vec<String> {
    let segments: Vec<&str> = normalized.split('/').collect();
    let mut variants = vec![normalized.to_string()];

    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() || *seg == ":param" {
            continue;
        }

        let toggled = if seg.ends_with('s') {
            seg.trim_end_matches('s').to_string()
        } else {
            format!("{}s", seg)
        };

        let mut new_segments = segments.clone();
        new_segments[i] = &toggled;
        let variant = new_segments.join("/");
        if variant != normalized {
            variants.push(variant);
        }
    }

    variants
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

    #[test]
    fn test_normalize_dollar_brace_params() {
        assert_eq!(
            normalize_api_path("/api/users/${userId}/posts/${postId}"),
            "/api/users/:param/posts/:param"
        );
    }

    #[test]
    fn test_normalize_bracket_params() {
        assert_eq!(
            normalize_api_path("/api/users/[userId]/posts/[postId]"),
            "/api/users/:param/posts/:param"
        );
    }

    #[test]
    fn test_normalize_strips_query_string() {
        assert_eq!(
            normalize_api_path("/api/users/:id?include=posts&limit=10"),
            "/api/users/:param"
        );
    }

    #[test]
    fn test_normalize_mixed_param_formats() {
        // All param formats produce the same normalized output
        let colon = normalize_api_path("/api/users/:id");
        let brace = normalize_api_path("/api/users/{id}");
        let dollar = normalize_api_path("/api/users/${id}");
        let bracket = normalize_api_path("/api/users/[id]");
        assert_eq!(colon, brace);
        assert_eq!(brace, dollar);
        assert_eq!(dollar, bracket);
    }

    #[test]
    fn test_plural_variants_basic() {
        let variants = plural_variants("/api/session/:param/answer");
        assert!(variants.contains(&"/api/session/:param/answer".to_string()));
        assert!(variants.contains(&"/api/sessions/:param/answer".to_string()));
        assert!(variants.contains(&"/api/session/:param/answers".to_string()));
    }

    #[test]
    fn test_plural_variants_already_plural() {
        let variants = plural_variants("/api/users/:param");
        assert!(variants.contains(&"/api/users/:param".to_string()));
        assert!(variants.contains(&"/api/user/:param".to_string()));
    }
}
