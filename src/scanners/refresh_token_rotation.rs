use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

pub struct RefreshTokenRotation;

const SCANNER_ID: &str = "S26";
const SCANNER_NAME: &str = "RefreshTokenRotation";
const SCANNER_DESC: &str =
    "Detects refresh token endpoints that issue new tokens without revoking old ones (missing token rotation)";

impl Scanner for RefreshTokenRotation {
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
        let all_refs = ctx.index.all_token_refresh_refs();

        if all_refs.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No refresh token endpoints detected".to_string(),
            };
        }

        let findings: Vec<Finding> = all_refs
            .iter()
            .filter(|r| !r.has_old_token_revocation)
            .map(to_finding)
            .collect();

        let total = all_refs.len();
        let rotated = total - findings.len();
        let score = compute_score(rotated, total);

        let summary = format!(
            "Found {} refresh token endpoint(s): {} with proper rotation, {} missing revocation (score: {})",
            total, rotated, findings.len(), score
        );

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

fn to_finding(r: &crate::indexer::types::TokenRefreshRef) -> Finding {
    Finding::new(
        SCANNER_ID,
        Severity::Critical,
        format!(
            "Refresh token endpoint issues new token without revoking the old one at {}:{}",
            r.file.display(),
            r.line
        ),
    )
    .with_file(r.file.clone())
    .with_line(r.line)
    .with_suggestion("Revoke or blacklist the old refresh token before issuing a new one to prevent token reuse attacks")
}

fn compute_score(rotated: usize, total: usize) -> u8 {
    if total == 0 {
        return 100;
    }
    ((rotated as f64 / total as f64) * 100.0).round() as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::Config;
    use crate::indexer::store::IndexStore;
    use crate::indexer::types::TokenRefreshRef;
    use std::path::PathBuf;

    fn minimal_config() -> Config {
        let yaml = r#"
version: "1.0"
project: test
layers: {}
"#;
        serde_yaml::from_str(yaml).unwrap()
    }

    fn make_ctx<'a>(config: &'a Config, store: &'a std::sync::Arc<IndexStore>) -> ScanContext<'a> {
        ScanContext {
            config,
            index: store,
            root_dir: std::path::Path::new("."),
        }
    }

    #[test]
    fn no_refresh_endpoints_perfect_score() {
        let config = minimal_config();
        let store = IndexStore::new();
        let ctx = make_ctx(&config, &store);

        let result = RefreshTokenRotation.scan(&ctx);
        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
        assert!(result
            .summary
            .contains("No refresh token endpoints detected"));
    }

    #[test]
    fn refresh_without_revocation() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/auth/refresh.ts");

        store.security.token_refresh_refs.insert(
            file.clone(),
            vec![TokenRefreshRef {
                file: file.clone(),
                line: 42,
                has_old_token_revocation: false,
            }],
        );

        let ctx = make_ctx(&config, &store);
        let result = RefreshTokenRotation.scan(&ctx);

        assert_eq!(result.score, 0);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].severity, Severity::Critical);
        assert!(result.findings[0].message.contains("without revoking"));
    }

    #[test]
    fn refresh_with_revocation() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file = PathBuf::from("src/auth/refresh.ts");

        store.security.token_refresh_refs.insert(
            file.clone(),
            vec![TokenRefreshRef {
                file: file.clone(),
                line: 42,
                has_old_token_revocation: true,
            }],
        );

        let ctx = make_ctx(&config, &store);
        let result = RefreshTokenRotation.scan(&ctx);

        assert_eq!(result.score, 100);
        assert!(result.findings.is_empty());
        assert!(result.summary.contains("1 with proper rotation"));
        assert!(result.summary.contains("0 missing revocation"));
    }

    #[test]
    fn mixed_endpoints() {
        let config = minimal_config();
        let store = IndexStore::new();
        let file_a = PathBuf::from("src/auth/refresh.ts");
        let file_b = PathBuf::from("src/auth/oauth.ts");

        store.security.token_refresh_refs.insert(
            file_a.clone(),
            vec![
                TokenRefreshRef {
                    file: file_a.clone(),
                    line: 10,
                    has_old_token_revocation: true,
                },
                TokenRefreshRef {
                    file: file_a.clone(),
                    line: 50,
                    has_old_token_revocation: false,
                },
            ],
        );
        store.security.token_refresh_refs.insert(
            file_b.clone(),
            vec![TokenRefreshRef {
                file: file_b.clone(),
                line: 20,
                has_old_token_revocation: false,
            }],
        );

        let ctx = make_ctx(&config, &store);
        let result = RefreshTokenRotation.scan(&ctx);

        assert_eq!(result.findings.len(), 2);
        assert!(result
            .findings
            .iter()
            .all(|f| f.severity == Severity::Critical));
        assert!(result.summary.contains("3 refresh token endpoint(s)"));
        assert!(result.summary.contains("1 with proper rotation"));
        assert!(result.summary.contains("2 missing revocation"));
    }

    #[test]
    fn score_calculation() {
        assert_eq!(compute_score(0, 0), 100);
        assert_eq!(compute_score(0, 1), 0);
        assert_eq!(compute_score(1, 1), 100);
        assert_eq!(compute_score(1, 2), 50);
        assert_eq!(compute_score(2, 3), 67);
        assert_eq!(compute_score(3, 4), 75);
        assert_eq!(compute_score(1, 3), 33);
    }
}
