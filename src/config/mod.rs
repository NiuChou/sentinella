pub mod architecture;
pub mod loader;
pub mod schema;

pub use crate::suppress::SuppressConfig;
pub use loader::{load_config_auto, load_config_from_dir};
pub use schema::{
    AppendOnlyLifecycleConfig, Config, CrossDbIntegrityConfig, DatabaseSecurityConfig,
    DeployConfig, DispatchConfig, DispatchTarget, EnvConfig, EventConfig, FlowConfig,
    FlowStepConfig, IntegrationTestConfig, LayerConfig, ModuleConfig, OutputConfig, OutputFormat,
    PermissionBoundaryConfig, PolicyStrengthConfig, ProjectType, RlsCoverageConfig, S11Config,
    S17Config, S1Config, S20Config, S22Config, S23Config, S7Config, ScannerOverrides,
    SeverityLevel,
};
