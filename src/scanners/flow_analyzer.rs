use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;

use crate::config::FlowConfig;
use crate::indexer::store::{normalize_api_path, plural_variants};
use crate::indexer::types::HttpMethod;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S3";
const SCANNER_NAME: &str = "Flow Analyzer";
const SCANNER_DESC: &str = "Analyze business flow closure across backend and frontend";

pub struct FlowAnalyzer;

impl Scanner for FlowAnalyzer {
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
        let flows = &ctx.config.flows;

        if flows.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: vec![],
                score: 100,
                summary: "No flows configured".to_string(),
            };
        }

        let mut findings = Vec::new();
        let mut total_steps: u32 = 0;
        let mut closed_steps: u32 = 0;

        for (flow_idx, flow) in flows.iter().enumerate() {
            let flow_result = analyze_flow(flow, flow_idx, ctx);
            total_steps += flow_result.total;
            closed_steps += flow_result.closed;
            findings.extend(flow_result.findings);
        }

        let score = if total_steps == 0 {
            100
        } else {
            ((closed_steps as f64 / total_steps as f64) * 100.0).round() as u8
        };

        let summary = format!(
            "{}/{} flow steps closed across {} flow(s)",
            closed_steps,
            total_steps,
            flows.len()
        );

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

struct FlowResult {
    total: u32,
    closed: u32,
    findings: Vec<Finding>,
}

fn analyze_flow(flow: &FlowConfig, flow_idx: usize, ctx: &ScanContext) -> FlowResult {
    let is_primary_flow = flow_idx == 0;
    let mut findings = Vec::new();
    let mut total: u32 = 0;
    let mut closed: u32 = 0;

    for step in &flow.steps {
        total += 1;
        let parsed = match parse_api_spec(&step.api) {
            Some(p) => p,
            None => {
                findings.push(Finding::new(
                    SCANNER_ID,
                    Severity::Warning,
                    format!(
                        "Flow '{}', step '{}': invalid API spec '{}'",
                        flow.name, step.action, step.api
                    ),
                ));
                continue;
            }
        };

        let has_endpoint = check_endpoint_exists(ctx, &parsed);
        let has_call = check_call_exists(ctx, &parsed);
        let has_page = check_page_exists(ctx, &step.page);
        let has_import_path = if has_endpoint && has_call {
            check_import_connectivity(ctx, &parsed)
        } else {
            // Skip import check if endpoint or call is missing
            true
        };

        let step_closed = has_endpoint && has_call && has_page && has_import_path;
        if step_closed {
            closed += 1;
            continue;
        }

        let severity = if is_primary_flow {
            Severity::Critical
        } else {
            Severity::Warning
        };

        let mut reasons = Vec::new();
        if !has_endpoint {
            reasons.push("no backend endpoint");
        }
        if !has_call {
            reasons.push("no frontend call");
        }
        if !has_page {
            reasons.push("page not found");
        }
        if !has_import_path {
            reasons.push("call file not reachable from any page via imports");
        }

        findings.push(
            Finding::new(
                SCANNER_ID,
                severity,
                format!(
                    "Flow '{}', step '{}' ({} {}): {}",
                    flow.name,
                    step.action,
                    parsed.method,
                    parsed.path,
                    reasons.join(", ")
                ),
            )
            .with_suggestion(format!(
                "Implement the missing pieces for step '{}' in flow '{}'",
                step.action, flow.name
            )),
        );
    }

    FlowResult {
        total,
        closed,
        findings,
    }
}

struct ParsedApiSpec {
    method: HttpMethod,
    path: String,
}

fn parse_api_spec(api: &str) -> Option<ParsedApiSpec> {
    let parts: Vec<&str> = api.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return None;
    }

    let method = match parts[0].to_uppercase().as_str() {
        "GET" => HttpMethod::Get,
        "POST" => HttpMethod::Post,
        "PUT" => HttpMethod::Put,
        "PATCH" => HttpMethod::Patch,
        "DELETE" => HttpMethod::Delete,
        _ => return None,
    };

    let path = parts[1].trim().to_string();
    if path.is_empty() {
        return None;
    }

    Some(ParsedApiSpec { method, path })
}

fn check_endpoint_exists(ctx: &ScanContext, spec: &ParsedApiSpec) -> bool {
    let normalized = normalize_api_path(&spec.path);

    // 1. Exact match (current behavior)
    let endpoints = ctx.index.endpoints_for_path(&normalized);
    if endpoints.iter().any(|ep| ep.method == spec.method) {
        return true;
    }

    // 2. Plural/singular variant match
    for variant in plural_variants(&normalized) {
        let eps = ctx.index.endpoints_for_path(&variant);
        if eps.iter().any(|ep| ep.method == spec.method) {
            return true;
        }
    }

    // 3. Prefix match — flow path is a prefix of a backend route
    let all_endpoints = ctx.index.all_api_endpoints();
    all_endpoints.iter().any(|ep| {
        ep.method == spec.method && {
            let ep_normalized = normalize_api_path(&ep.path);
            ep_normalized.starts_with(&normalized)
        }
    })
}

fn check_call_exists(ctx: &ScanContext, spec: &ParsedApiSpec) -> bool {
    let normalized = normalize_api_path(&spec.path);

    // 1. Exact match (current behavior)
    let calls = ctx.index.calls_for_url(&normalized);
    if calls.iter().any(|c| c.method == spec.method) {
        return true;
    }

    // 2. Plural/singular variant match
    for variant in plural_variants(&normalized) {
        let cs = ctx.index.calls_for_url(&variant);
        if cs.iter().any(|c| c.method == spec.method) {
            return true;
        }
    }

    // 3. Prefix match — flow path is a prefix of a frontend call URL
    let all_calls = ctx.index.all_api_calls();
    all_calls.iter().any(|c| {
        c.method == spec.method && {
            let c_normalized = normalize_api_path(&c.url);
            c_normalized.starts_with(&normalized)
        }
    })
}

/// Check if any file making the API call is reachable from a page file
/// via the import graph. Uses BFS from each page file through imports.
fn check_import_connectivity(ctx: &ScanContext, spec: &ParsedApiSpec) -> bool {
    let normalized = normalize_api_path(&spec.path);

    // Collect call files from exact match + plural variants
    let mut call_files: HashSet<PathBuf> = HashSet::new();
    for variant in plural_variants(&normalized) {
        let calls = ctx.index.calls_for_url(&variant);
        for c in calls.iter().filter(|c| c.method == spec.method) {
            call_files.insert(c.file.clone());
        }
    }

    // Also check prefix matches
    for c in ctx.index.all_api_calls() {
        if c.method == spec.method {
            let c_norm = normalize_api_path(&c.url);
            if c_norm.starts_with(&normalized) {
                call_files.insert(c.file.clone());
            }
        }
    }

    if call_files.is_empty() {
        return false;
    }

    let page_files = collect_page_files(ctx);
    if page_files.is_empty() {
        // No page files to check against; skip this check gracefully
        return true;
    }

    // BFS from each page file to see if we can reach any call file
    for page_file in &page_files {
        if bfs_reaches_any(ctx, page_file, &call_files) {
            return true;
        }
    }

    false
}

/// Collect all files that look like page files (page.tsx, page.ts, etc.)
fn collect_page_files(ctx: &ScanContext) -> Vec<PathBuf> {
    ctx.index
        .files
        .iter()
        .filter_map(|entry| {
            let path = entry.key();
            let file_name = path.file_name()?.to_str()?;
            let lower = file_name.to_lowercase();
            if lower == "page.tsx"
                || lower == "page.ts"
                || lower == "page.jsx"
                || lower == "page.js"
            {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect()
}

/// BFS through the import graph from `start` to see if any file in `targets` is reachable.
fn bfs_reaches_any(ctx: &ScanContext, start: &PathBuf, targets: &HashSet<PathBuf>) -> bool {
    let mut visited: HashSet<PathBuf> = HashSet::new();
    let mut queue: VecDeque<PathBuf> = VecDeque::new();

    queue.push_back(start.clone());
    visited.insert(start.clone());

    while let Some(current) = queue.pop_front() {
        if targets.contains(&current) {
            return true;
        }

        let imports = ctx.index.imports_for_file(&current);
        for edge in imports {
            // Resolve the target_module to a file path via fuzzy matching
            let resolved = resolve_import_target(ctx, &edge.target_module);
            for resolved_path in resolved {
                if visited.insert(resolved_path.clone()) {
                    queue.push_back(resolved_path);
                }
            }
        }
    }

    false
}

/// Resolve an import target module string to actual file paths in the store.
/// Uses prefix/suffix matching since import paths may be relative or aliased.
fn resolve_import_target(ctx: &ScanContext, target_module: &str) -> Vec<PathBuf> {
    let target_lower = target_module.to_lowercase();
    ctx.index
        .files
        .iter()
        .filter_map(|entry| {
            let path = entry.key();
            let path_str = path.to_string_lossy().to_lowercase();
            if path_str.contains(&target_lower) {
                Some(path.clone())
            } else {
                None
            }
        })
        .collect()
}

fn check_page_exists(ctx: &ScanContext, page: &Option<String>) -> bool {
    let pattern = match page {
        Some(p) => p,
        None => return true, // No page requirement means the check passes
    };

    let pattern_lower = pattern.to_lowercase();
    ctx.index.files.iter().any(|entry| {
        let path_str = entry.key().to_string_lossy().to_lowercase();
        path_str.contains(&pattern_lower)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_api_spec_post() {
        let result = parse_api_spec("POST /api/orders").unwrap();
        assert_eq!(result.method, HttpMethod::Post);
        assert_eq!(result.path, "/api/orders");
    }

    #[test]
    fn test_parse_api_spec_get_with_param() {
        let result = parse_api_spec("GET /api/users/:id").unwrap();
        assert_eq!(result.method, HttpMethod::Get);
        assert_eq!(result.path, "/api/users/:id");
    }

    #[test]
    fn test_parse_api_spec_invalid_method() {
        assert!(parse_api_spec("FOOBAR /api/test").is_none());
    }

    #[test]
    fn test_parse_api_spec_missing_path() {
        assert!(parse_api_spec("GET").is_none());
    }

    #[test]
    fn test_parse_api_spec_empty() {
        assert!(parse_api_spec("").is_none());
    }

    #[test]
    fn test_normalize_api_path_params() {
        // All parameter formats produce the same normalized output
        let colon = normalize_api_path("/api/users/:id");
        let dollar_brace = normalize_api_path("/api/users/${id}");
        let brace = normalize_api_path("/api/users/{id}");
        assert_eq!(colon, "/api/users/:param");
        assert_eq!(dollar_brace, "/api/users/:param");
        assert_eq!(brace, "/api/users/:param");
    }

    #[test]
    fn test_flow_step_fuzzy_match() {
        // /api/sessions/:id should match /api/session/:sessionId
        // after normalization + plural variants
        let flow_path = normalize_api_path("/api/sessions/:id");
        let backend_path = normalize_api_path("/api/session/:sessionId");

        // Direct normalized comparison may differ due to plural
        // but plural_variants of one should contain the other
        let flow_variants = plural_variants(&flow_path);
        let backend_variants = plural_variants(&backend_path);

        let matched = flow_variants.iter().any(|fv| backend_variants.contains(fv));
        assert!(
            matched,
            "Expected /api/sessions/:id to fuzzy-match /api/session/:sessionId. \
             Flow variants: {:?}, Backend variants: {:?}",
            flow_variants, backend_variants
        );
    }
}
