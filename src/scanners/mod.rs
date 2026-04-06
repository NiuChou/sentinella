pub mod api_contract_drift;
pub mod audit_log_completeness;
pub mod cross_layer_tracer;
pub mod cross_service_duplication;
pub mod data_isolation;
pub mod deploy_readiness;
pub mod destructive_endpoint_safety;
pub mod env_config_drift;
pub mod event_schema_drift;
pub mod flow_analyzer;
pub mod insecure_token_storage;
pub mod integration_test_cov;
pub mod missing_uniqueness;
pub mod otp_replay_protection;
pub mod plan_drift;
pub mod race_condition_safety;
pub mod rate_limiting_coverage;
pub mod refresh_token_rotation;
pub mod residue_finder;
pub mod role_hardcoding;
pub mod security_completeness;
pub mod sensitive_data_logging;
pub mod silent_error_swallowing;
pub mod soft_delete_lifecycle;
pub mod stub_detector;
pub mod test_bypass_detection;
pub mod token_invalidation;
pub mod types;

use rayon::prelude::*;

use self::types::Scanner;

/// Create all scanners. Optionally filter by IDs (e.g. "S1,S9").
pub fn create_scanners(filter: Option<&str>) -> Vec<Box<dyn Scanner>> {
    let all: Vec<Box<dyn Scanner>> = vec![
        Box::new(stub_detector::StubDetector),                   // S1
        Box::new(cross_layer_tracer::CrossLayerTracer),          // S2
        Box::new(flow_analyzer::FlowAnalyzer),                   // S3
        Box::new(deploy_readiness::DeployReadiness),             // S4
        Box::new(plan_drift::PlanDrift),                         // S5
        Box::new(residue_finder::ResidueFinder),                 // S6
        Box::new(security_completeness::SecurityCompleteness),   // S7
        Box::new(integration_test_cov::IntegrationTestCoverage), // S8
        Box::new(api_contract_drift::ApiContractDrift),          // S9
        Box::new(event_schema_drift::EventSchemaDrift),          // S10
        Box::new(env_config_drift::EnvConfigDrift),              // S11
        Box::new(data_isolation::DataIsolationAudit),            // S12
        Box::new(destructive_endpoint_safety::DestructiveEndpointSafety), // S13
        Box::new(soft_delete_lifecycle::SoftDeleteLifecycle),    // S14
        Box::new(cross_service_duplication::CrossServiceDuplication), // S15
        Box::new(role_hardcoding::RoleHardcoding),               // S16
        Box::new(silent_error_swallowing::SilentErrorSwallowing), // S17
        Box::new(token_invalidation::TokenInvalidation),         // S18
        Box::new(otp_replay_protection::OtpReplayProtection),    // S19
        Box::new(sensitive_data_logging::SensitiveDataLogging),  // S20
        Box::new(insecure_token_storage::InsecureTokenStorage),  // S21
        Box::new(rate_limiting_coverage::RateLimitingCoverage),  // S22
        Box::new(audit_log_completeness::AuditLogCompleteness),  // S23
        Box::new(missing_uniqueness::MissingUniqueness),         // S24
        Box::new(test_bypass_detection::TestBypassDetection),    // S25
        Box::new(refresh_token_rotation::RefreshTokenRotation),  // S26
        Box::new(race_condition_safety::RaceConditionSafety),    // S27
    ];

    match filter {
        Some(ids) => {
            let wanted: Vec<&str> = ids.split(',').map(|s| s.trim()).collect();
            all.into_iter()
                .filter(|s| wanted.contains(&s.id()))
                .collect()
        }
        None => all,
    }
}

/// 5-layer execution order with intra-layer parallelism:
///   Layer 1 (Base):         S1 + S6 + S17 + S20 + S25
///   Layer 2 (Core):         S2 + S9
///   Layer 3 (Completeness): S3 + S4 + S7 + S13 + S16 + S8 + S12(D11) + S14 + S18 + S19 + S21 + S22 + S26 + S27
///   Layer 4 (Drift):        S10 + S11 + S15 + S23 + S24
///   Layer 5 (Project):      S5 (optional)
const EXECUTION_LAYERS: &[&[&str]] = &[
    &["S1", "S6", "S17", "S20", "S25"],
    &["S2", "S9"],
    &[
        "S3", "S4", "S7", "S13", "S16", "S8", "S12", "S14", "S18", "S19", "S21", "S22", "S26",
        "S27",
    ],
    &["S10", "S11", "S15", "S23", "S24"],
    &["S5"],
];

/// Run scanners in 5-layer sequential order with intra-layer parallelism.
pub fn run_scanners(
    scanners: &[Box<dyn Scanner>],
    ctx: &types::ScanContext,
) -> Vec<types::ScanResult> {
    let mut results: Vec<types::ScanResult> = Vec::new();

    for layer_ids in EXECUTION_LAYERS {
        let layer_scanners: Vec<&Box<dyn Scanner>> = scanners
            .iter()
            .filter(|s| layer_ids.contains(&s.id()))
            .collect();

        let layer_results: Vec<types::ScanResult> =
            layer_scanners.par_iter().map(|s| s.scan(ctx)).collect();

        results.extend(layer_results);
    }

    results
}
