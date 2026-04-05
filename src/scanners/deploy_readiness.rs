use crate::scanners::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S4";
const SCANNER_NAME: &str = "DeployReadiness";
const SCANNER_DESC: &str = "Checks deployment readiness of Dockerfiles: healthchecks, pinned bases, non-root USER, and .dockerignore presence.";

pub struct DeployReadiness;

impl Scanner for DeployReadiness {
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
        let deploy = &ctx.config.deploy;
        let store = ctx.index;

        let mut findings: Vec<Finding> = Vec::new();
        let mut total_checks: u32 = 0;
        let mut checks_passed: u32 = 0;

        for entry in store.dockerfile_checks.iter() {
            let check = entry.value();
            let service = &check.service;

            // Healthcheck
            if deploy.require_healthcheck {
                total_checks += 1;
                if check.has_healthcheck {
                    checks_passed += 1;
                } else {
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Critical,
                            format!(
                                "Service '{}' Dockerfile has no HEALTHCHECK instruction",
                                service
                            ),
                        )
                        .with_suggestion(
                            "Add a HEALTHCHECK instruction so the orchestrator can detect unhealthy containers.",
                        ),
                    );
                }
            }

            // Pinned base image
            if deploy.require_pinned_deps {
                total_checks += 1;
                if check.base_pinned {
                    checks_passed += 1;
                } else {
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Warning,
                            format!(
                                "Service '{}' Dockerfile uses an unpinned base image (e.g. :latest)",
                                service
                            ),
                        )
                        .with_suggestion(
                            "Pin the base image to a specific digest or version tag for reproducible builds.",
                        ),
                    );
                }
            }

            // Non-root USER (always checked)
            total_checks += 1;
            if check.has_user {
                checks_passed += 1;
            } else {
                findings.push(
                    Finding::new(
                        SCANNER_ID,
                        Severity::Warning,
                        format!(
                            "Service '{}' Dockerfile does not set a non-root USER",
                            service
                        ),
                    )
                    .with_suggestion(
                        "Add a USER instruction to run the container as a non-root user.",
                    ),
                );
            }

            // .dockerignore
            if deploy.require_dockerignore {
                total_checks += 1;
                if check.has_dockerignore {
                    checks_passed += 1;
                } else {
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Warning,
                            format!("Service '{}' has no .dockerignore file", service),
                        )
                        .with_suggestion(
                            "Add a .dockerignore to exclude unnecessary files and reduce image size.",
                        ),
                    );
                }
            }
        }

        let score = if total_checks == 0 {
            100
        } else {
            ((checks_passed as f64 / total_checks as f64) * 100.0).round() as u8
        };

        let summary = if findings.is_empty() {
            "All Dockerfile checks passed.".to_string()
        } else {
            format!(
                "{} issue(s) found across {} service(s). Score: {}%.",
                findings.len(),
                store.dockerfile_checks.len(),
                score
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
    use crate::config::schema::DeployConfig;
    use crate::config::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::DockerfileCheck;
    use std::path::Path;

    fn make_config(
        require_healthcheck: bool,
        require_pinned_deps: bool,
        require_dockerignore: bool,
    ) -> Config {
        Config {
            version: "1.0".into(),
            project: "test".into(),
            r#type: Default::default(),
            layers: Default::default(),
            modules: Default::default(),
            flows: Default::default(),
            deploy: DeployConfig {
                dockerfile_pattern: "**/Dockerfile".into(),
                require_healthcheck,
                require_pinned_deps,
                require_dockerignore,
            },
            integration_tests: Default::default(),
            events: Default::default(),
            env: Default::default(),
            output: Default::default(),
            dispatch: Default::default(),
            data_isolation: Default::default(),
        }
    }

    #[test]
    fn test_all_checks_pass() {
        let config = make_config(true, true, true);
        let store = IndexStore::new();
        store.dockerfile_checks.insert(
            "web".into(),
            DockerfileCheck {
                service: "web".into(),
                has_healthcheck: true,
                base_pinned: true,
                has_user: true,
                has_dockerignore: true,
            },
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DeployReadiness.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_missing_healthcheck_is_critical() {
        let config = make_config(true, false, false);
        let store = IndexStore::new();
        store.dockerfile_checks.insert(
            "api".into(),
            DockerfileCheck {
                service: "api".into(),
                has_healthcheck: false,
                base_pinned: true,
                has_user: true,
                has_dockerignore: true,
            },
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DeployReadiness.scan(&ctx);
        assert!(result.score < 100);
        let critical_count = result
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        assert_eq!(critical_count, 1);
    }

    #[test]
    fn test_empty_store_gives_perfect_score() {
        let config = make_config(true, true, true);
        let store = IndexStore::new();

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DeployReadiness.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_missing_user_is_warning() {
        let config = make_config(false, false, false);
        let store = IndexStore::new();
        store.dockerfile_checks.insert(
            "worker".into(),
            DockerfileCheck {
                service: "worker".into(),
                has_healthcheck: true,
                base_pinned: true,
                has_user: false,
                has_dockerignore: true,
            },
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DeployReadiness.scan(&ctx);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Warning);
    }

    #[test]
    fn test_multiple_services_accumulate_findings() {
        let config = make_config(true, true, true);
        let store = IndexStore::new();

        store.dockerfile_checks.insert(
            "api".into(),
            DockerfileCheck {
                service: "api".into(),
                has_healthcheck: false,
                base_pinned: false,
                has_user: false,
                has_dockerignore: false,
            },
        );
        store.dockerfile_checks.insert(
            "web".into(),
            DockerfileCheck {
                service: "web".into(),
                has_healthcheck: true,
                base_pinned: true,
                has_user: true,
                has_dockerignore: true,
            },
        );

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: Path::new("/tmp"),
        };

        let result = DeployReadiness.scan(&ctx);
        // api has 4 failures, web has 0 => 4 out of 8 passed => 50%
        assert_eq!(result.score, 50);
        assert_eq!(result.findings.len(), 4);
    }
}
