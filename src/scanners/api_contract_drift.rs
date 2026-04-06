use std::collections::HashSet;

use crate::indexer::store::{normalize_api_path, plural_variants};
use crate::indexer::types::{ApiCall, ApiEndpoint, HttpMethod};

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S9";
const SCANNER_NAME: &str = "API Contract Drift";
const SCANNER_DESC: &str = "Detect frontend/backend API contract mismatches";

pub struct ApiContractDrift;

impl Scanner for ApiContractDrift {
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
        let endpoints = ctx.index.all_api_endpoints();
        let calls = ctx.index.all_api_calls();

        let endpoint_index = build_endpoint_index(&endpoints);
        let call_index = build_call_index(&calls);

        let mut findings = Vec::new();
        let mut broken_count: u32 = 0;
        let total_calls = calls.len() as u32;

        // Check each API call against known endpoints
        for call in &calls {
            let normalized_url = normalize_api_path(&call.url);
            match find_matching_endpoint(&normalized_url, call.method, &endpoint_index) {
                EndpointMatch::Exact => {}
                EndpointMatch::PathMatchMethodMismatch(expected_methods) => {
                    broken_count += 1;
                    let methods_str: Vec<String> =
                        expected_methods.iter().map(|m| m.to_string()).collect();
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Critical,
                            format!(
                                "METHOD MISMATCH: {} {} - backend expects [{}]",
                                call.method,
                                call.url,
                                methods_str.join(", ")
                            ),
                        )
                        .with_file(&call.file)
                        .with_line(call.line)
                        .with_suggestion(format!(
                            "Change the HTTP method to one of: {}",
                            methods_str.join(", ")
                        )),
                    );
                }
                EndpointMatch::NoMatch => {
                    broken_count += 1;
                    findings.push(
                        Finding::new(
                            SCANNER_ID,
                            Severity::Critical,
                            format!(
                                "BROKEN CALL: {} {} - no matching backend endpoint",
                                call.method, call.url
                            ),
                        )
                        .with_file(&call.file)
                        .with_line(call.line)
                        .with_suggestion(
                            "Verify the API endpoint exists or remove the dead call".to_string(),
                        ),
                    );
                }
            }
        }

        // Check for unused endpoints (no matching call)
        for endpoint in &endpoints {
            let normalized_path = normalize_api_path(&endpoint.path);
            if !call_index.contains(&(normalized_path, endpoint.method)) {
                findings.push(
                    Finding::new(
                        SCANNER_ID,
                        Severity::Warning,
                        format!(
                            "UNUSED API: {} {} - no frontend call found",
                            endpoint.method, endpoint.path
                        ),
                    )
                    .with_file(&endpoint.file)
                    .with_line(endpoint.line)
                    .with_suggestion(
                        "Remove the unused endpoint or add a frontend consumer".to_string(),
                    ),
                );
            }
        }

        let unused_count = findings
            .iter()
            .filter(|f| f.message.starts_with("UNUSED API"))
            .count();

        let score = if total_calls == 0 {
            100
        } else {
            let healthy = total_calls.saturating_sub(broken_count);
            ((healthy as f64 / total_calls as f64) * 100.0).round() as u8
        };

        let summary = format!(
            "{} API calls checked: {} broken, {} unused endpoints",
            total_calls, broken_count, unused_count
        );

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

enum EndpointMatch {
    Exact,
    PathMatchMethodMismatch(Vec<HttpMethod>),
    NoMatch,
}

struct EndpointEntry {
    normalized_path: String,
    method: HttpMethod,
}

fn build_endpoint_index(endpoints: &[ApiEndpoint]) -> Vec<EndpointEntry> {
    endpoints
        .iter()
        .map(|ep| EndpointEntry {
            normalized_path: normalize_api_path(&ep.path),
            method: ep.method,
        })
        .collect()
}

fn build_call_index(calls: &[ApiCall]) -> HashSet<(String, HttpMethod)> {
    let mut index = HashSet::new();
    for c in calls {
        let normalized = normalize_api_path(&c.url);
        // Insert the normalized form and all plural/singular variants
        for variant in plural_variants(&normalized) {
            index.insert((variant, c.method));
        }
    }
    index
}

fn find_matching_endpoint(
    normalized_url: &str,
    method: HttpMethod,
    endpoints: &[EndpointEntry],
) -> EndpointMatch {
    // 1. Exact normalized path match (current behavior)
    let path_matches: Vec<&EndpointEntry> = endpoints
        .iter()
        .filter(|ep| ep.normalized_path == normalized_url)
        .collect();

    if !path_matches.is_empty() {
        let has_exact = path_matches.iter().any(|ep| ep.method == method);
        if has_exact {
            return EndpointMatch::Exact;
        }
        let available_methods: Vec<HttpMethod> = path_matches.iter().map(|ep| ep.method).collect();
        return EndpointMatch::PathMatchMethodMismatch(available_methods);
    }

    // 2. Plural/singular variant fallback
    let url_variants = plural_variants(normalized_url);
    for variant in &url_variants {
        let variant_matches: Vec<&EndpointEntry> = endpoints
            .iter()
            .filter(|ep| ep.normalized_path == *variant)
            .collect();

        if !variant_matches.is_empty() {
            let has_method = variant_matches.iter().any(|ep| ep.method == method);
            if has_method {
                return EndpointMatch::Exact;
            }
            let available_methods: Vec<HttpMethod> =
                variant_matches.iter().map(|ep| ep.method).collect();
            return EndpointMatch::PathMatchMethodMismatch(available_methods);
        }
    }

    EndpointMatch::NoMatch
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_exact_match() {
        let endpoints = vec![EndpointEntry {
            normalized_path: "/api/users".to_string(),
            method: HttpMethod::Get,
        }];
        let result = find_matching_endpoint("/api/users", HttpMethod::Get, &endpoints);
        assert!(matches!(result, EndpointMatch::Exact));
    }

    #[test]
    fn test_find_method_mismatch() {
        let endpoints = vec![EndpointEntry {
            normalized_path: "/api/users".to_string(),
            method: HttpMethod::Post,
        }];
        let result = find_matching_endpoint("/api/users", HttpMethod::Get, &endpoints);
        assert!(matches!(result, EndpointMatch::PathMatchMethodMismatch(_)));
    }

    #[test]
    fn test_find_no_match() {
        let endpoints = vec![EndpointEntry {
            normalized_path: "/api/users".to_string(),
            method: HttpMethod::Get,
        }];
        let result = find_matching_endpoint("/api/orders", HttpMethod::Get, &endpoints);
        assert!(matches!(result, EndpointMatch::NoMatch));
    }

    #[test]
    fn test_normalize_route_params() {
        // All parameter formats produce the same normalized output
        let colon = normalize_api_path("/api/users/:id");
        let dollar = normalize_api_path("/api/users/${userId}");
        let brace = normalize_api_path("/api/users/{id}");
        let bracket = normalize_api_path("/api/users/[id]");
        assert_eq!(colon, "/api/users/:param");
        assert_eq!(dollar, "/api/users/:param");
        assert_eq!(brace, "/api/users/:param");
        assert_eq!(bracket, "/api/users/:param");
    }

    #[test]
    fn test_find_match_with_different_param_formats() {
        // Backend uses Express-style :id
        let endpoints = vec![EndpointEntry {
            normalized_path: normalize_api_path("/api/users/:id"),
            method: HttpMethod::Get,
        }];
        // Frontend uses ${userId} — after normalization should match
        let frontend_url = normalize_api_path("/api/users/${userId}");
        let result = find_matching_endpoint(&frontend_url, HttpMethod::Get, &endpoints);
        assert!(
            matches!(result, EndpointMatch::Exact),
            "Expected /api/users/${{userId}} to match /api/users/:id"
        );
    }

    #[test]
    fn test_find_match_with_query_string() {
        let endpoints = vec![EndpointEntry {
            normalized_path: normalize_api_path("/api/users/:id"),
            method: HttpMethod::Get,
        }];
        // Frontend call includes query string
        let frontend_url = normalize_api_path("/api/users/${userId}?include=posts");
        let result = find_matching_endpoint(&frontend_url, HttpMethod::Get, &endpoints);
        assert!(
            matches!(result, EndpointMatch::Exact),
            "Expected query string to be stripped before matching"
        );
    }

    #[test]
    fn test_find_match_with_plural_variant() {
        // Backend has singular: /api/session/:id
        let endpoints = vec![EndpointEntry {
            normalized_path: normalize_api_path("/api/session/:id"),
            method: HttpMethod::Get,
        }];
        // Frontend uses plural: /api/sessions/:id
        let frontend_url = normalize_api_path("/api/sessions/:id");
        let result = find_matching_endpoint(&frontend_url, HttpMethod::Get, &endpoints);
        assert!(
            matches!(result, EndpointMatch::Exact),
            "Expected /api/sessions/:id to match /api/session/:id via plural variant"
        );
    }
}
