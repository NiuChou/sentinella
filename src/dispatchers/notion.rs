use anyhow::{Context, Result};

use crate::reporters::task_decomposer::Task;

/// Dispatch tasks to a Notion database.
///
/// When `dry_run` is `true`, tasks are printed to stdout without making any
/// API calls. The real implementation requires `NOTION_API_KEY` in the
/// environment.
pub fn dispatch(tasks: &[Task], database_id: &str, dry_run: bool) -> Result<()> {
    if tasks.is_empty() {
        println!("  No tasks to dispatch to Notion.");
        return Ok(());
    }

    if dry_run {
        println!(
            "  [DRY RUN] Would create {} Notion pages in database {}",
            tasks.len(),
            database_id
        );
        for task in tasks {
            println!("    - [{}] {}", task.priority_str(), task.title);
        }
        return Ok(());
    }

    let api_key = std::env::var("NOTION_API_KEY").context(
        "NOTION_API_KEY environment variable is not set. \
         Set it to your Notion integration token to enable dispatch.",
    )?;

    let created = create_task_pages(tasks, database_id, &api_key)?;
    println!("  Created {} Notion pages in database {}", created, database_id);
    Ok(())
}

/// Create Notion pages for each task, returning the count of successfully created pages.
fn create_task_pages(tasks: &[Task], database_id: &str, api_key: &str) -> Result<usize> {
    let mut created: usize = 0;

    for task in tasks {
        create_single_page(task, database_id, api_key)
            .with_context(|| format!("Failed to create Notion page for task: {}", task.title))?;
        created += 1;
    }

    Ok(created)
}

/// Create a single Notion page representing one task.
///
/// ureq v3 treats 4xx/5xx responses as `Error::StatusCode`, so a successful
/// `send_json` call guarantees a 2xx response.
fn create_single_page(task: &Task, database_id: &str, api_key: &str) -> Result<()> {
    let body = build_page_body(task, database_id);

    ureq::post("https://api.notion.com/v1/pages")
        .header("Authorization", &format!("Bearer {api_key}"))
        .header("Notion-Version", "2022-06-28")
        .header("Content-Type", "application/json")
        .send_json(&body)
        .map_err(|e| map_ureq_error("Notion", e))?;

    Ok(())
}

/// Convert a ureq error into an anyhow error with a clear message.
fn map_ureq_error(service: &str, err: ureq::Error) -> anyhow::Error {
    match err {
        ureq::Error::StatusCode(code) => {
            anyhow::anyhow!("{service} API returned HTTP {code}")
        }
        other => anyhow::anyhow!("{service} API request failed: {other}"),
    }
}

/// Build the JSON body for a Notion page creation request.
fn build_page_body(task: &Task, database_id: &str) -> serde_json::Value {
    serde_json::json!({
        "parent": { "database_id": database_id },
        "properties": {
            "Name": {
                "title": [{ "text": { "content": &task.title } }]
            },
            "Status": {
                "select": { "name": "Todo" }
            },
            "Priority": {
                "select": { "name": task.priority_str() }
            },
            "Scanner": {
                "rich_text": [{ "text": { "content": &task.source_finding } }]
            },
            "Effort": {
                "select": { "name": task.effort_str() }
            },
            "Type": {
                "select": { "name": task.task_type.to_string() }
            },
            "Description": {
                "rich_text": [{ "text": { "content": &task.description } }]
            }
        }
    })
}
