use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S5";

pub struct PlanDrift;

impl Scanner for PlanDrift {
    fn id(&self) -> &str {
        SCANNER_ID
    }

    fn name(&self) -> &str {
        "Plan Drift"
    }

    fn description(&self) -> &str {
        "Detects deviation between the project plan (Notion) and the actual codebase"
    }

    fn scan(&self, ctx: &ScanContext) -> ScanResult {
        let notion_db_id = match &ctx.config.dispatch.notion_database_id {
            Some(id) if !id.is_empty() => id.clone(),
            _ => {
                return ScanResult {
                    scanner: SCANNER_ID.to_string(),
                    findings: Vec::new(),
                    score: 100,
                    summary: "Skipped: no notion_database_id configured in dispatch settings"
                        .to_string(),
                };
            }
        };

        let plan_items = fetch_plan_items(&notion_db_id);

        if plan_items.is_empty() {
            return build_empty_result(&notion_db_id);
        }

        evaluate_plan_items(ctx, &plan_items)
    }
}

/// A plan item fetched from the project management tool.
#[derive(Debug, Clone)]
struct PlanItem {
    name: String,
    expected_route: Option<String>,
    priority: String,
}

/// Build a result when no plan items are returned.
fn build_empty_result(notion_db_id: &str) -> ScanResult {
    ScanResult {
        scanner: SCANNER_ID.to_string(),
        findings: vec![Finding::new(
            SCANNER_ID,
            Severity::Info,
            format!("Notion database '{}' returned no plan items", notion_db_id),
        )
        .with_suggestion(
            "Ensure the Notion database contains plan items with feature names and routes",
        )],
        score: 100,
        summary: format!(
            "Plan drift check configured (db: {}) but no plan items found",
            truncate_id(notion_db_id)
        ),
    }
}

/// Evaluate plan items against the codebase and produce a scan result.
fn evaluate_plan_items(ctx: &ScanContext, plan_items: &[PlanItem]) -> ScanResult {
    let mut implemented_count: usize = 0;
    let mut findings = Vec::new();

    for item in plan_items {
        let found = search_codebase_for_plan_item(ctx, item);
        if found {
            implemented_count += 1;
        } else {
            let severity = priority_to_severity(&item.priority);
            findings.push(
                Finding::new(
                    SCANNER_ID,
                    severity,
                    format!(
                        "Plan item not implemented: '{}' [{}]",
                        item.name, item.priority
                    ),
                )
                .with_suggestion(format!(
                    "Implement feature '{}' or update the plan to reflect current scope",
                    item.name
                )),
            );
        }
    }

    let total = plan_items.len();
    let score = if total > 0 {
        ((implemented_count as f64 / total as f64) * 100.0) as u8
    } else {
        100
    };

    let summary = format!(
        "{} plan items, {} implemented, {} missing",
        total,
        implemented_count,
        total - implemented_count,
    );

    ScanResult {
        scanner: SCANNER_ID.to_string(),
        findings,
        score,
        summary,
    }
}

/// Map plan item priority to scan severity.
/// P0 = Critical, P1 = Warning, anything else = Info.
fn priority_to_severity(priority: &str) -> Severity {
    match priority {
        "P0" => Severity::Critical,
        "P1" => Severity::Warning,
        _ => Severity::Info,
    }
}

/// Fetch plan items from Notion by querying a database.
///
/// Reads `NOTION_API_KEY` from the environment. If it is not set,
/// returns an empty vector with a warning printed to stderr (graceful degradation).
fn fetch_plan_items(db_id: &str) -> Vec<PlanItem> {
    let api_key = match std::env::var("NOTION_API_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            eprintln!(
                "  [WARN] NOTION_API_KEY not set; skipping plan drift Notion fetch for db {}",
                truncate_id(db_id)
            );
            return Vec::new();
        }
    };

    match query_notion_database(db_id, &api_key) {
        Ok(items) => items,
        Err(err) => {
            eprintln!("  [WARN] Failed to fetch Notion plan items: {err}");
            Vec::new()
        }
    }
}

/// Execute the Notion database query and parse the response.
///
/// ureq v3 treats 4xx/5xx as errors, so a successful `send_json` guarantees 2xx.
fn query_notion_database(db_id: &str, api_key: &str) -> anyhow::Result<Vec<PlanItem>> {
    let url = format!("https://api.notion.com/v1/databases/{db_id}/query");

    let mut response = ureq::post(&url)
        .header("Authorization", &format!("Bearer {api_key}"))
        .header("Notion-Version", "2022-06-28")
        .header("Content-Type", "application/json")
        .send_json(serde_json::json!({}))
        .map_err(|e| match e {
            ureq::Error::StatusCode(code) => {
                anyhow::anyhow!("Notion database query returned HTTP {code}")
            }
            other => anyhow::anyhow!("Notion database query failed: {other}"),
        })?;

    let body_str = response
        .body_mut()
        .read_to_string()
        .map_err(|e| anyhow::anyhow!("Failed to read Notion response body: {e}"))?;

    let json: serde_json::Value = serde_json::from_str(&body_str)
        .map_err(|e| anyhow::anyhow!("Failed to parse Notion response JSON: {e}"))?;

    parse_notion_results(&json)
}

/// Parse the Notion query response into plan items.
fn parse_notion_results(json: &serde_json::Value) -> anyhow::Result<Vec<PlanItem>> {
    let results = json["results"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Notion response missing 'results' array"))?;

    let items: Vec<PlanItem> = results.iter().filter_map(parse_single_page).collect();

    Ok(items)
}

/// Parse a single Notion page object into a PlanItem.
fn parse_single_page(page: &serde_json::Value) -> Option<PlanItem> {
    let properties = page.get("properties")?;

    let title = extract_title(properties)?;
    let priority = extract_select(properties, "Priority").unwrap_or_else(|| "P2".to_string());
    let route = extract_rich_text(properties, "Route");
    Some(PlanItem {
        name: title,
        expected_route: route,
        priority,
    })
}

/// Extract the title text from a Notion page's "Name" or "Title" property.
fn extract_title(properties: &serde_json::Value) -> Option<String> {
    let title_prop = properties.get("Name").or_else(|| properties.get("Title"))?;

    let title_arr = title_prop.get("title")?.as_array()?;
    let text = title_arr.first()?.get("text")?.get("content")?.as_str()?;

    if text.is_empty() {
        return None;
    }

    Some(text.to_string())
}

/// Extract a select property value by property name.
fn extract_select(properties: &serde_json::Value, prop_name: &str) -> Option<String> {
    properties
        .get(prop_name)?
        .get("select")?
        .get("name")?
        .as_str()
        .map(String::from)
}

/// Extract a rich_text property value by property name.
fn extract_rich_text(properties: &serde_json::Value, prop_name: &str) -> Option<String> {
    let arr = properties.get(prop_name)?.get("rich_text")?.as_array()?;
    let text = arr.first()?.get("text")?.get("content")?.as_str()?;

    if text.is_empty() {
        return None;
    }

    Some(text.to_string())
}

/// Search the code index for evidence that a plan item has been implemented.
///
/// Checks:
/// 1. File names containing the feature name (snake_case or kebab-case)
/// 2. API endpoints matching the expected route
/// 3. Import symbols matching the feature name
fn search_codebase_for_plan_item(ctx: &ScanContext, item: &PlanItem) -> bool {
    let feature_snake = to_snake_case(&item.name);
    let feature_kebab = feature_snake.replace('_', "-");

    if has_matching_file(ctx, &feature_snake, &feature_kebab) {
        return true;
    }

    if has_matching_endpoint(ctx, &item.expected_route) {
        return true;
    }

    has_matching_import(ctx, &feature_snake, &feature_kebab)
}

/// Check if any indexed file names contain the feature identifiers.
fn has_matching_file(ctx: &ScanContext, snake: &str, kebab: &str) -> bool {
    ctx.index.files.iter().any(|entry| {
        let path_str = entry.key().to_string_lossy().to_lowercase();
        path_str.contains(snake) || path_str.contains(kebab)
    })
}

/// Check if any indexed API endpoints match the expected route.
fn has_matching_endpoint(ctx: &ScanContext, route: &Option<String>) -> bool {
    let route = match route {
        Some(r) => r.to_lowercase(),
        None => return false,
    };

    ctx.index.api.endpoints.iter().any(|entry| {
        entry
            .value()
            .iter()
            .any(|ep| ep.path.to_lowercase().contains(&route))
    })
}

/// Check if any indexed imports reference the feature identifiers.
fn has_matching_import(ctx: &ScanContext, snake: &str, kebab: &str) -> bool {
    ctx.index.imports.iter().any(|entry| {
        entry.value().iter().any(|edge| {
            let target_lower = edge.target_module.to_lowercase();
            target_lower.contains(snake) || target_lower.contains(kebab)
        })
    })
}

/// Convert a human-readable name to snake_case.
fn to_snake_case(name: &str) -> String {
    name.to_lowercase()
        .replace(|c: char| !c.is_alphanumeric(), "_")
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

/// Truncate a Notion database ID for display in summaries.
fn truncate_id(id: &str) -> String {
    if id.len() > 12 {
        format!("{}...", &id[..12])
    } else {
        id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("Asset Upload"), "asset_upload");
        assert_eq!(to_snake_case("User-Profile Page"), "user_profile_page");
        assert_eq!(to_snake_case("PLM Integration"), "plm_integration");
    }

    #[test]
    fn test_truncate_id_short() {
        assert_eq!(truncate_id("abc123"), "abc123");
    }

    #[test]
    fn test_truncate_id_long() {
        let long_id = "abcdef123456789012345";
        assert_eq!(truncate_id(long_id), "abcdef123456...");
    }

    #[test]
    fn test_fetch_plan_items_returns_empty_without_api_key() {
        // Without NOTION_API_KEY set, should return empty vec gracefully
        std::env::remove_var("NOTION_API_KEY");
        let items = fetch_plan_items("fake-db-id");
        assert!(items.is_empty());
    }

    #[test]
    fn test_priority_to_severity() {
        assert_eq!(priority_to_severity("P0"), Severity::Critical);
        assert_eq!(priority_to_severity("P1"), Severity::Warning);
        assert_eq!(priority_to_severity("P2"), Severity::Info);
        assert_eq!(priority_to_severity("unknown"), Severity::Info);
    }

    #[test]
    fn test_parse_notion_results_empty() {
        let json = serde_json::json!({ "results": [] });
        let items = parse_notion_results(&json).unwrap();
        assert!(items.is_empty());
    }

    #[test]
    fn test_parse_notion_results_with_page() {
        let json = serde_json::json!({
            "results": [{
                "properties": {
                    "Name": {
                        "title": [{ "text": { "content": "Auth Flow" } }]
                    },
                    "Priority": {
                        "select": { "name": "P0" }
                    }
                }
            }]
        });
        let items = parse_notion_results(&json).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].name, "Auth Flow");
        assert_eq!(items[0].priority, "P0");
    }

    #[test]
    fn test_parse_single_page_missing_title() {
        let page = serde_json::json!({
            "properties": {
                "Priority": { "select": { "name": "P1" } }
            }
        });
        assert!(parse_single_page(&page).is_none());
    }

    #[test]
    fn test_extract_select_missing() {
        let props = serde_json::json!({});
        assert!(extract_select(&props, "Priority").is_none());
    }

    #[test]
    fn test_extract_rich_text() {
        let props = serde_json::json!({
            "Route": {
                "rich_text": [{ "text": { "content": "/api/auth" } }]
            }
        });
        assert_eq!(extract_rich_text(&props, "Route"), Some("/api/auth".into()));
    }
}
