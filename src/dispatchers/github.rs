use anyhow::{Context, Result};

use crate::reporters::task_decomposer::Task;

/// Dispatch tasks as GitHub issues.
///
/// When `dry_run` is `true`, tasks are printed to stdout without making any
/// API calls. The real implementation requires `GITHUB_TOKEN` in the
/// environment.
pub fn dispatch(tasks: &[Task], repo: &str, dry_run: bool) -> Result<()> {
    if tasks.is_empty() {
        println!("  No tasks to dispatch to GitHub.");
        return Ok(());
    }

    if dry_run {
        println!(
            "  [DRY RUN] Would create {} GitHub issues in {}",
            tasks.len(),
            repo
        );
        for task in tasks {
            println!("    - [{}] {}", task.priority_str(), task.title);
        }
        return Ok(());
    }

    let token = std::env::var("GITHUB_TOKEN").context(
        "GITHUB_TOKEN environment variable is not set. \
         Set it to a GitHub personal access token to enable dispatch.",
    )?;

    let repo_slug = resolve_repo(repo)?;
    let (owner, name) = parse_repo(&repo_slug)?;

    let created = create_issues(tasks, owner, name, &token)?;
    println!("  Created {} GitHub issues in {}/{}", created, owner, name);
    Ok(())
}

/// Resolve the repository slug from the config value or the GITHUB_REPOSITORY env var.
fn resolve_repo(repo: &str) -> Result<String> {
    if !repo.is_empty() {
        return Ok(repo.to_string());
    }

    std::env::var("GITHUB_REPOSITORY").context(
        "No repository configured. Set github_repo in config or \
         GITHUB_REPOSITORY environment variable (format: owner/repo).",
    )
}

/// Create GitHub issues for each task, returning the count of successfully created issues.
fn create_issues(tasks: &[Task], owner: &str, name: &str, token: &str) -> Result<usize> {
    let mut created: usize = 0;

    for task in tasks {
        create_single_issue(task, owner, name, token)
            .with_context(|| format!("Failed to create GitHub issue for task: {}", task.title))?;
        created += 1;
    }

    Ok(created)
}

/// Create a single GitHub issue representing one task.
///
/// ureq v3 treats 4xx/5xx responses as `Error::StatusCode`, so a successful
/// `send_json` call guarantees a 2xx response.
fn create_single_issue(task: &Task, owner: &str, name: &str, token: &str) -> Result<()> {
    let url = format!("https://api.github.com/repos/{owner}/{name}/issues");
    let body = build_issue_body(task);

    ureq::post(&url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "sentinella")
        .send_json(&body)
        .map_err(|e| map_ureq_error("GitHub", e))?;

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

/// Build the JSON body for a GitHub issue creation request.
fn build_issue_body(task: &Task) -> serde_json::Value {
    let labels = vec![
        format!("priority:{}", task.priority_str()),
        format!("type:{}", task.task_type),
        format!("effort:{}", task.effort_str()),
    ];

    let body_text = format!(
        "## Finding\n\n{}\n\n## Details\n\n{}\n\n---\n\n\
         **Priority:** {} | **Effort:** {} | **Type:** {}",
        task.source_finding,
        task.description,
        task.priority_str(),
        task.effort_str(),
        task.task_type,
    );

    serde_json::json!({
        "title": &task.title,
        "body": body_text,
        "labels": labels,
    })
}

/// Parse an "owner/repo" string into its two components.
fn parse_repo(repo: &str) -> Result<(&str, &str)> {
    let parts: Vec<&str> = repo.splitn(2, '/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        anyhow::bail!(
            "Invalid repo format: '{}'. Expected 'owner/repo'.",
            repo
        );
    }
    Ok((parts[0], parts[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_repo_valid() {
        let (owner, name) = parse_repo("acme/widgets").unwrap();
        assert_eq!(owner, "acme");
        assert_eq!(name, "widgets");
    }

    #[test]
    fn parse_repo_invalid() {
        assert!(parse_repo("no-slash").is_err());
    }

    #[test]
    fn parse_repo_empty_parts() {
        assert!(parse_repo("/repo").is_err());
        assert!(parse_repo("owner/").is_err());
    }

    #[test]
    fn resolve_repo_uses_config_value() {
        let result = resolve_repo("acme/widgets").unwrap();
        assert_eq!(result, "acme/widgets");
    }

    #[test]
    fn build_issue_body_has_required_fields() {
        use crate::reporters::task_decomposer::{Effort, Priority, TaskType};

        let task = Task {
            title: "Test task".into(),
            description: "A test description".into(),
            task_type: TaskType::FixApi,
            priority: Priority::P0,
            estimated_effort: Effort::Medium,
            source_finding: "Some finding".into(),
        };

        let body = build_issue_body(&task);
        assert_eq!(body["title"], "Test task");
        assert!(body["body"].as_str().unwrap().contains("Some finding"));
        let labels = body["labels"].as_array().unwrap();
        assert!(labels.iter().any(|l| l == "priority:P0"));
        assert!(labels.iter().any(|l| l == "type:fix-api"));
        assert!(labels.iter().any(|l| l == "effort:M"));
    }
}
