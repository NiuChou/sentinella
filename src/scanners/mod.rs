pub mod types;
pub mod stub_detector;
pub mod residue_finder;
pub mod cross_layer_tracer;
pub mod api_contract_drift;
pub mod flow_analyzer;
pub mod deploy_readiness;
pub mod plan_drift;
pub mod security_completeness;
pub mod integration_test_cov;
pub mod event_schema_drift;
pub mod env_config_drift;
pub mod data_isolation;
pub mod destructive_endpoint_safety;
pub mod soft_delete_lifecycle;
pub mod cross_service_duplication;
pub mod role_hardcoding;
pub mod silent_error_swallowing;
pub mod token_invalidation;
pub mod otp_replay_protection;

use rayon::prelude::*;

use self::types::Scanner;

/// Create all scanners. Optionally filter by IDs (e.g. "S1,S9").
pub fn create_scanners(filter: Option<&str>) -> Vec<Box<dyn Scanner>> {
    let all: Vec<Box<dyn Scanner>> = vec![
        Box::new(stub_detector::StubDetector),                  // S1
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
        Box::new(soft_delete_lifecycle::SoftDeleteLifecycle),            // S14
        Box::new(cross_service_duplication::CrossServiceDuplication),    // S15
        Box::new(role_hardcoding::RoleHardcoding),                      // S16
        Box::new(silent_error_swallowing::SilentErrorSwallowing),       // S17
        Box::new(token_invalidation::TokenInvalidation),                // S18
        Box::new(otp_replay_protection::OtpReplayProtection),          // S19
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
///   Layer 1 (Base):         S1 + S6 + S17
///   Layer 2 (Core):         S2 + S9
///   Layer 3 (Completeness): S3 + S4 + S7 + S13 + S16 + S8 + S12(D11) + S14 + S18 + S19
///   Layer 4 (Drift):        S10 + S11 + S15
///   Layer 5 (Project):      S5 (optional)
const EXECUTION_LAYERS: &[&[&str]] = &[
    &["S1", "S6", "S17"],
    &["S2", "S9"],
    &["S3", "S4", "S7", "S13", "S16", "S8", "S12", "S14", "S18", "S19"],
    &["S10", "S11", "S15"],
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

        let layer_results: Vec<types::ScanResult> = layer_scanners
            .par_iter()
            .map(|s| s.scan(ctx))
            .collect();

        results.extend(layer_results);
    }

    results
}
