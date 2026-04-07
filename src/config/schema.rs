use serde::Deserialize;
use std::collections::HashMap;

use super::architecture::LinkedRepo;
use crate::suppress::SuppressConfig;

// ---------------------------------------------------------------------------
// ScannerOverrides — per-scanner config tuning
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ScannerOverrides {
    #[serde(default)]
    pub s1: Option<S1Config>,
    #[serde(default)]
    pub s7: Option<S7Config>,
    #[serde(default)]
    pub s11: Option<S11Config>,
    #[serde(default)]
    pub s13: Option<S13Config>,
    #[serde(default)]
    pub s17: Option<S17Config>,
    #[serde(default)]
    pub s18: Option<S18Config>,
    #[serde(default)]
    pub s20: Option<S20Config>,
    #[serde(default)]
    pub s22: Option<S22Config>,
    #[serde(default)]
    pub s23: Option<S23Config>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S1Config {
    #[serde(default)]
    pub stub_indicators: Vec<String>,
    #[serde(default)]
    pub real_data_indicators: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S7Config {
    #[serde(default)]
    pub auth_keywords: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S11Config {
    #[serde(default)]
    pub build_time_prefixes: Vec<String>,
    #[serde(default)]
    pub exclude_var_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S13Config {
    #[serde(default)]
    pub require_2fa_paths: Vec<String>,
    #[serde(default)]
    pub skip_internal_paths: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S17Config {
    #[serde(default)]
    pub safe_ignore_patterns: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S18Config {
    #[serde(default)]
    pub trigger_fields: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S20Config {
    #[serde(default)]
    pub safe_patterns: Vec<String>,
    #[serde(default)]
    pub sensitive_keywords: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S22Config {
    #[serde(default)]
    pub rate_limit_keywords: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct S23Config {
    #[serde(default)]
    pub audit_keywords: Vec<String>,
}

fn default_version() -> String {
    "1.0".into()
}

fn default_required_layers() -> Vec<String> {
    vec![
        "backend".into(),
        "bff".into(),
        "hooks".into(),
        "page".into(),
    ]
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: String,
    pub project: String,
    #[serde(default)]
    pub r#type: ProjectType,
    #[serde(default)]
    pub layers: HashMap<String, LayerConfig>,
    #[serde(default)]
    pub modules: Vec<ModuleConfig>,
    #[serde(default)]
    pub flows: Vec<FlowConfig>,
    #[serde(default)]
    pub deploy: DeployConfig,
    #[serde(default)]
    pub integration_tests: IntegrationTestConfig,
    #[serde(default)]
    pub events: EventConfig,
    #[serde(default)]
    pub env: EnvConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub dispatch: DispatchConfig,
    #[serde(default)]
    pub data_isolation: DataIsolationConfig,
    /// Layers required for S2 cross-layer tracing. Defaults to ["backend", "bff", "hooks", "page"]
    #[serde(default = "default_required_layers")]
    pub required_layers: Vec<String>,
    #[serde(default)]
    pub linked_repos: Vec<LinkedRepo>,
    /// Optional suppression configuration for silencing known false positives
    #[serde(default)]
    pub suppress: Option<SuppressConfig>,
    #[serde(default)]
    pub scanner_overrides: ScannerOverrides,
}

// ---------------------------------------------------------------------------
// ProjectType
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectType {
    Fullstack,
    BackendOnly,
    Monorepo,
}

impl Default for ProjectType {
    fn default() -> Self {
        Self::Fullstack
    }
}

// ---------------------------------------------------------------------------
// LayerConfig
// ---------------------------------------------------------------------------

fn default_stub_indicators() -> Vec<String> {
    vec![
        "TODO".into(),
        "FIXME".into(),
        "STUB".into(),
        "PLACEHOLDER".into(),
        "not implemented".into(),
    ]
}

fn default_real_data_indicators() -> Vec<String> {
    vec![
        "fetch(".into(),
        "axios.".into(),
        "useQuery".into(),
        "useSWR".into(),
        "prisma.".into(),
    ]
}

#[derive(Debug, Clone, Deserialize)]
pub struct LayerConfig {
    pub pattern: String,
    #[serde(default)]
    pub api_pattern: Option<String>,
    #[serde(default = "default_stub_indicators")]
    pub stub_indicators: Vec<String>,
    #[serde(default = "default_real_data_indicators")]
    pub real_data_indicators: Vec<String>,
}

// ---------------------------------------------------------------------------
// ModuleConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct ModuleConfig {
    pub name: String,
    #[serde(default)]
    pub backend: Option<String>,
    #[serde(default)]
    pub bff: Option<String>,
    #[serde(default)]
    pub hooks: Option<String>,
    #[serde(default)]
    pub page: Option<String>,
}

// ---------------------------------------------------------------------------
// FlowConfig / FlowStepConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct FlowConfig {
    pub name: String,
    #[serde(default)]
    pub steps: Vec<FlowStepConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FlowStepConfig {
    pub action: String,
    pub api: String,
    #[serde(default)]
    pub page: Option<String>,
}

// ---------------------------------------------------------------------------
// DeployConfig
// ---------------------------------------------------------------------------

fn default_dockerfile_pattern() -> String {
    "**/Dockerfile".into()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeployConfig {
    #[serde(default = "default_dockerfile_pattern")]
    pub dockerfile_pattern: String,
    #[serde(default = "default_true")]
    pub require_healthcheck: bool,
    #[serde(default = "default_true")]
    pub require_pinned_deps: bool,
    #[serde(default = "default_true")]
    pub require_dockerignore: bool,
}

impl Default for DeployConfig {
    fn default() -> Self {
        Self {
            dockerfile_pattern: default_dockerfile_pattern(),
            require_healthcheck: true,
            require_pinned_deps: true,
            require_dockerignore: true,
        }
    }
}

// ---------------------------------------------------------------------------
// IntegrationTestConfig
// ---------------------------------------------------------------------------

fn default_migrations_pattern() -> String {
    "db/migrations/**/*.sql".into()
}

fn default_tests_pattern() -> String {
    "tests/integration/**/*.test.ts".into()
}

fn default_exclude_tables() -> Vec<String> {
    vec!["_prisma_migrations".into()]
}

fn default_min_coverage() -> u8 {
    80
}

#[derive(Debug, Clone, Deserialize)]
pub struct IntegrationTestConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_migrations_pattern")]
    pub migrations_pattern: String,
    #[serde(default = "default_tests_pattern")]
    pub tests_pattern: String,
    #[serde(default = "default_exclude_tables")]
    pub exclude_tables: Vec<String>,
    #[serde(default = "default_true")]
    pub require_rls_alignment: bool,
    #[serde(default = "default_min_coverage")]
    pub min_coverage: u8,
}

impl Default for IntegrationTestConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            migrations_pattern: default_migrations_pattern(),
            tests_pattern: default_tests_pattern(),
            exclude_tables: default_exclude_tables(),
            require_rls_alignment: true,
            min_coverage: default_min_coverage(),
        }
    }
}

// ---------------------------------------------------------------------------
// EventConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Default)]
pub struct EventConfig {
    #[serde(default)]
    pub producer_patterns: Vec<String>,
    #[serde(default)]
    pub consumer_patterns: Vec<String>,
}

// ---------------------------------------------------------------------------
// EnvConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct EnvConfig {
    #[serde(default)]
    pub code_patterns: Vec<String>,
    #[serde(default)]
    pub deploy_patterns: Vec<String>,
    #[serde(default)]
    pub env_example: Option<String>,
    #[serde(default = "default_exclude_paths")]
    pub exclude_paths: Vec<String>,
    #[serde(default = "default_exclude_vars")]
    pub exclude_vars: Vec<String>,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            code_patterns: Vec::new(),
            deploy_patterns: Vec::new(),
            env_example: None,
            exclude_paths: default_exclude_paths(),
            exclude_vars: default_exclude_vars(),
        }
    }
}

fn default_exclude_paths() -> Vec<String> {
    vec![
        "node_modules/".into(),
        "vendor/".into(),
        ".next/".into(),
        "dist/".into(),
        "build/".into(),
        "target/".into(),
        ".git/".into(),
        "__pycache__/".into(),
        ".venv/".into(),
        "venv/".into(),
    ]
}

fn default_exclude_vars() -> Vec<String> {
    vec![
        "NODE_ENV".into(),
        "HOME".into(),
        "PATH".into(),
        "USER".into(),
        "SHELL".into(),
        "LANG".into(),
        "CI".into(),
    ]
}

/// Well-known env var prefixes provided by CI/CD and hosting platforms.
/// Variables matching these prefixes are excluded by default.
pub const EXCLUDED_VAR_PREFIXES: &[&str] = &["GITHUB_", "VERCEL_", "NETLIFY_"];

// ---------------------------------------------------------------------------
// DataIsolationConfig
// ---------------------------------------------------------------------------

fn default_tenant_column() -> String {
    "user_id".into()
}

fn default_rls_session_var() -> String {
    "app.current_user_id".into()
}

fn default_credential_keys() -> Vec<String> {
    vec![
        "password".into(),
        "secret".into(),
        "api_key".into(),
        "access_key".into(),
        "token".into(),
    ]
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ServicePatternConfig {
    pub name: String,
    pub directory: String,
    #[serde(default)]
    pub tables: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DataIsolationConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_tenant_column")]
    pub tenant_column: String,
    #[serde(default)]
    pub tenant_column_aliases: Vec<String>,
    #[serde(default = "default_rls_session_var")]
    pub rls_session_var: String,
    #[serde(default)]
    pub exclude_tables: Vec<String>,
    #[serde(default)]
    pub exclude_redis_patterns: Vec<String>,
    #[serde(default)]
    pub admin_roles: Vec<String>,
    #[serde(default = "default_credential_keys")]
    pub credential_keys: Vec<String>,
    /// D8: Env var names for restricted (user-facing) DB connections
    #[serde(default)]
    pub restricted_pool_env_vars: Vec<String>,
    /// D8: Env var names for admin DB connections
    #[serde(default)]
    pub admin_pool_env_vars: Vec<String>,
    /// D10: Service directory patterns for monorepo boundary detection
    #[serde(default)]
    pub service_patterns: Vec<ServicePatternConfig>,
}

impl Default for DataIsolationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tenant_column: default_tenant_column(),
            tenant_column_aliases: Vec::new(),
            rls_session_var: default_rls_session_var(),
            exclude_tables: Vec::new(),
            exclude_redis_patterns: Vec::new(),
            admin_roles: Vec::new(),
            credential_keys: default_credential_keys(),
            restricted_pool_env_vars: Vec::new(),
            admin_pool_env_vars: Vec::new(),
            service_patterns: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// OutputConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum OutputFormat {
    Terminal,
    Json,
    Markdown,
    Notion,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Terminal
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SeverityLevel {
    Warning,
    Error,
}

impl Default for SeverityLevel {
    fn default() -> Self {
        Self::Warning
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutputConfig {
    #[serde(default)]
    pub format: OutputFormat,
    #[serde(default = "default_min_coverage")]
    pub min_coverage: u8,
    #[serde(default)]
    pub severity: SeverityLevel,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::default(),
            min_coverage: default_min_coverage(),
            severity: SeverityLevel::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// DispatchConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DispatchTarget {
    Stdout,
    Notion,
    Github,
}

impl Default for DispatchTarget {
    fn default() -> Self {
        Self::Stdout
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DispatchConfig {
    #[serde(default)]
    pub target: DispatchTarget,
    #[serde(default)]
    pub notion_database_id: Option<String>,
    #[serde(default)]
    pub github_repo: Option<String>,
    #[serde(default)]
    pub auto_assign: bool,
}

impl Default for DispatchConfig {
    fn default() -> Self {
        Self {
            target: DispatchTarget::default(),
            notion_database_id: None,
            github_repo: None,
            auto_assign: false,
        }
    }
}
