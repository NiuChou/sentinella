use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
            HttpMethod::Patch => write!(f, "PATCH"),
            HttpMethod::Delete => write!(f, "DELETE"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framework {
    Express,
    NestJS,
    FastAPI,
    Gin,
    Echo,
    Actix,
    Axum,
    Rocket,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    TypeScript,
    Python,
    Go,
    Sql,
    Dockerfile,
    Rust,
    Yaml,
    Env,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub language: Language,
    pub lines: usize,
    pub hash: u64,
}

#[derive(Debug, Clone)]
pub struct ApiEndpoint {
    pub method: HttpMethod,
    pub path: String,
    pub file: PathBuf,
    pub line: usize,
    pub framework: Framework,
}

#[derive(Debug, Clone)]
pub struct ApiCall {
    pub method: HttpMethod,
    pub url: String,
    pub file: PathBuf,
    pub line: usize,
    pub is_template: bool,
}

#[derive(Debug, Clone)]
pub struct ImportEdge {
    pub source_file: PathBuf,
    pub target_module: String,
    pub symbols: Vec<String>,
    pub is_type_only: bool,
}

#[derive(Debug, Clone)]
pub struct EnvRef {
    pub var_name: String,
    pub file: PathBuf,
    pub line: usize,
    pub has_default: bool,
    pub default_value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EnvConfig {
    pub var_name: String,
    pub source_file: PathBuf,
    pub source_type: EnvSourceType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvSourceType {
    DotEnv,
    K8sConfigMap,
    K8sSecret,
    DockerCompose,
}

#[derive(Debug, Clone)]
pub struct EventProducer {
    pub topic: String,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct EventConsumer {
    pub topic: String,
    pub group: String,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone)]
pub struct TableInfo {
    pub schema_name: Option<String>,
    pub table_name: String,
    pub has_rls: bool,
    pub app_role: Option<String>,
}

#[derive(Debug, Clone)]
pub struct TestFileInfo {
    pub path: PathBuf,
    pub tables_tested: Vec<String>,
    pub has_write: bool,
    pub has_read: bool,
    pub has_assert: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StubType {
    Todo,
    Fixme,
    Hack,
    MockData,
    StubData,
    Placeholder,
    Hardcoded,
    Fake,
    Dummy,
}

impl fmt::Display for StubType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StubType::Todo => write!(f, "TODO"),
            StubType::Fixme => write!(f, "FIXME"),
            StubType::Hack => write!(f, "HACK"),
            StubType::MockData => write!(f, "MOCK_DATA"),
            StubType::StubData => write!(f, "STUB_DATA"),
            StubType::Placeholder => write!(f, "PLACEHOLDER"),
            StubType::Hardcoded => write!(f, "HARDCODED"),
            StubType::Fake => write!(f, "FAKE"),
            StubType::Dummy => write!(f, "DUMMY"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct StubIndicator {
    pub file: PathBuf,
    pub line: usize,
    pub indicator_type: StubType,
    pub matched_text: String,
}

#[derive(Debug, Clone)]
pub struct DockerfileCheck {
    pub service: String,
    pub has_healthcheck: bool,
    pub base_pinned: bool,
    pub has_user: bool,
    /// Whether a `.dockerignore` file exists alongside this Dockerfile.
    /// Note: this field extends the core spec to surface missing ignore files.
    pub has_dockerignore: bool,
}

#[derive(Debug, Clone)]
pub struct MiddlewareScope {
    pub router_var: String,
    pub middleware_name: String,
    pub file: PathBuf,
    pub line_start: usize,
    pub line_end: usize,
}

/// A reference to a database write operation found in application code.
#[derive(Debug, Clone)]
pub struct DbWriteRef {
    pub table_name: String,
    pub operation: DbWriteOp,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbWriteOp {
    Insert,
    Update,
    Upsert,
    Delete,
}

/// A Redis key pattern found in application code.
#[derive(Debug, Clone)]
pub struct RedisKeyRef {
    pub key_pattern: String,
    pub operation: RedisOp,
    pub has_ttl: bool,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisOp {
    Read,
    Write,
    Delete,
}

/// An RLS session variable setting found in application code.
#[derive(Debug, Clone)]
pub struct RlsContextRef {
    pub session_var: String,
    pub file: PathBuf,
    pub line: usize,
}

/// A hardcoded credential found in application code or config.
#[derive(Debug, Clone)]
pub struct HardcodedCredential {
    pub key_name: String,
    pub value_hint: String,
    pub file: PathBuf,
    pub line: usize,
}

/// RLS policy detail extracted from SQL migrations.
#[derive(Debug, Clone)]
pub struct RlsPolicyInfo {
    pub table_name: String,
    pub policy_name: String,
    pub session_var: Option<String>,
    pub has_force: bool,
    pub role: Option<String>,
}

/// SQL query with table reference found in application code.
#[derive(Debug, Clone)]
pub struct SqlQueryRef {
    pub table_name: String,
    pub operation: SqlQueryOp,
    pub has_tenant_filter: bool,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlQueryOp {
    Select,
    Insert,
    Update,
    Delete,
}

/// D8: A DB connection/pool reference found in application code.
#[derive(Debug, Clone)]
pub struct DbPoolRef {
    pub pool_name: String,
    pub role_hint: Option<String>,
    pub connection_var: Option<String>,
    pub file: PathBuf,
    pub line: usize,
}

/// D8: Classification of code context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceContext {
    UserFacing,
    Worker,
    Unknown,
}

/// D10: A service boundary in a monorepo.
#[derive(Debug, Clone)]
pub struct ServiceBoundary {
    pub service_name: String,
    pub root_dir: PathBuf,
    pub owned_tables: Vec<String>,
}

/// S13: Secondary authentication reference (OTP/2FA/password re-entry).
#[derive(Debug, Clone)]
pub struct SecondaryAuthRef {
    pub file: PathBuf,
    pub line: usize,
    pub auth_type: SecondaryAuthType,
    pub near_endpoint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecondaryAuthType {
    Otp,
    TwoFactor,
    PasswordConfirm,
    CsrfToken,
}

/// S14: Soft-delete column information.
#[derive(Debug, Clone)]
pub struct SoftDeleteColumn {
    pub table_name: String,
    pub column_name: String,
    pub column_type: SoftDeleteType,
    pub file: PathBuf,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoftDeleteType {
    Timestamp,
    Status,
    Boolean,
}

/// S15: Function signature for cross-service duplication detection.
#[derive(Debug, Clone)]
pub struct FunctionSignature {
    pub file: PathBuf,
    pub line: usize,
    pub name: String,
    pub params: Vec<String>,
    pub body_hash: u64,
    pub service_name: Option<String>,
}

/// S16: Role check reference.
#[derive(Debug, Clone)]
pub struct RoleCheckRef {
    pub file: PathBuf,
    pub line: usize,
    pub check_type: RoleCheckType,
    pub role_value: String,
    pub is_middleware: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleCheckType {
    SingleValue,
    SetCheck,
    ArrayIncludes,
}

/// S17: Error handling reference.
#[derive(Debug, Clone)]
pub struct ErrorHandlingRef {
    pub file: PathBuf,
    pub line: usize,
    pub error_type: ErrorHandlingType,
    pub context: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorHandlingType {
    EmptyCatch,
    EmptyExcept,
    IgnoredError,
    UncheckedResponse,
    EmptyErrorBranch,
}

/// D11: Status literal reference in SQL queries.
#[derive(Debug, Clone)]
pub struct StatusLiteralRef {
    pub file: PathBuf,
    pub line: usize,
    pub column_name: String,
    pub literal_value: String,
    pub service_name: Option<String>,
}

/// S18: Session/Token invalidation reference.
#[derive(Debug, Clone)]
pub struct SessionInvalidationRef {
    pub file: PathBuf,
    pub line: usize,
    pub invalidation_type: SessionInvalidationType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionInvalidationType {
    RedisSessionDelete,
    JwtBlacklist,
    CookieClear,
    SessionDestroy,
}
