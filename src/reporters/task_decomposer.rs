use crate::scanners::types::{ScanResult, Severity};

/// An actionable task derived from scan findings.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Task {
    pub title: String,
    pub description: String,
    pub task_type: TaskType,
    pub priority: Priority,
    pub estimated_effort: Effort,
    pub source_finding: String,
}

impl Task {
    /// Human-readable priority label.
    pub fn priority_str(&self) -> &'static str {
        match self.priority {
            Priority::P0 => "P0",
            Priority::P1 => "P1",
            Priority::P2 => "P2",
        }
    }

    /// Human-readable effort label.
    pub fn effort_str(&self) -> &'static str {
        match self.estimated_effort {
            Effort::Small => "S",
            Effort::Medium => "M",
            Effort::Large => "L",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    CreateBff,
    CreateHook,
    CreatePage,
    FixFlow,
    FixApi,
    AddTest,
    AddConfig,
    AddDeploy,
    FixGhostTable,
    FixRLS,
    FixCredential,
    FixCacheOnly,
    FixIsolation,
}

impl std::fmt::Display for TaskType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskType::CreateBff => write!(f, "create-bff"),
            TaskType::CreateHook => write!(f, "create-hook"),
            TaskType::CreatePage => write!(f, "create-page"),
            TaskType::FixFlow => write!(f, "fix-flow"),
            TaskType::FixApi => write!(f, "fix-api"),
            TaskType::AddTest => write!(f, "add-test"),
            TaskType::AddConfig => write!(f, "add-config"),
            TaskType::AddDeploy => write!(f, "add-deploy"),
            TaskType::FixGhostTable => write!(f, "fix-ghost-table"),
            TaskType::FixRLS => write!(f, "fix-rls"),
            TaskType::FixCredential => write!(f, "fix-credential"),
            TaskType::FixCacheOnly => write!(f, "fix-cache-only"),
            TaskType::FixIsolation => write!(f, "fix-isolation"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
pub enum Priority {
    P0,
    P1,
    P2,
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Priority::P0 => write!(f, "P0"),
            Priority::P1 => write!(f, "P1"),
            Priority::P2 => write!(f, "P2"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Effort {
    Small,
    Medium,
    Large,
}

/// Decompose scan results into actionable tasks.
///
/// Only `Critical` and `Warning` findings produce tasks; `Info` findings are
/// treated as informational and skipped.
pub fn decompose(results: &[ScanResult]) -> Vec<Task> {
    let mut tasks: Vec<Task> = Vec::new();

    for result in results {
        let scanner_id = extract_scanner_id(&result.scanner);

        for finding in &result.findings {
            if finding.severity == Severity::Info {
                continue;
            }

            let priority = severity_to_priority(finding.severity);
            let task_types = if scanner_id == "S12" {
                vec![classify_s12_finding(&finding.message)]
            } else {
                scanner_to_task_types(scanner_id)
            };

            for task_type in task_types {
                let effort = estimate_effort(task_type, finding.severity);

                let title = build_title(task_type, &finding.message);
                let description =
                    build_description(task_type, &finding.message, finding.suggestion.as_deref());

                tasks.push(Task {
                    title,
                    description,
                    task_type,
                    priority,
                    estimated_effort: effort,
                    source_finding: finding.message.clone(),
                });
            }
        }
    }

    // Sort by priority (P0 first).
    tasks.sort_by_key(|t| t.priority);
    tasks
}

// ---------------------------------------------------------------------------
// Mapping helpers
// ---------------------------------------------------------------------------

/// Extract a short scanner id like "S1" from names like "S1-stub-detector".
fn extract_scanner_id(scanner: &str) -> &str {
    scanner.split('-').next().unwrap_or(scanner)
}

/// Classify an S12 data-isolation finding into a specific task type based on
/// the finding message content.
fn classify_s12_finding(message: &str) -> TaskType {
    if message.contains("ghost table") || message.contains("never written") {
        TaskType::FixGhostTable
    } else if message.contains("RLS") || message.contains("SET LOCAL") || message.contains("FORCE")
    {
        TaskType::FixRLS
    } else if message.contains("Hardcoded credential") {
        TaskType::FixCredential
    } else if message.contains("Redis") || message.contains("cache") {
        TaskType::FixCacheOnly
    } else {
        TaskType::FixIsolation
    }
}

fn scanner_to_task_types(id: &str) -> Vec<TaskType> {
    match id {
        "S1" => vec![TaskType::CreateHook, TaskType::CreatePage],
        "S2" => vec![
            TaskType::CreateBff,
            TaskType::CreateHook,
            TaskType::CreatePage,
        ],
        "S3" => vec![TaskType::FixFlow],
        "S4" => vec![TaskType::AddDeploy],
        "S5" => vec![TaskType::FixFlow, TaskType::AddConfig],
        "S6" => vec![TaskType::CreateHook, TaskType::CreatePage],
        "S7" => vec![TaskType::AddConfig],
        "S8" => vec![TaskType::AddTest],
        "S9" => vec![TaskType::FixApi],
        _ => vec![TaskType::AddConfig],
    }
}

fn severity_to_priority(severity: Severity) -> Priority {
    match severity {
        Severity::Critical => Priority::P0,
        Severity::Warning => Priority::P1,
        Severity::Info => Priority::P2,
    }
}

fn estimate_effort(task_type: TaskType, severity: Severity) -> Effort {
    match (task_type, severity) {
        (TaskType::CreateBff, _) => Effort::Large,
        (TaskType::CreatePage, Severity::Critical) => Effort::Large,
        (TaskType::CreatePage, _) => Effort::Medium,
        (TaskType::CreateHook, _) => Effort::Medium,
        (TaskType::FixFlow, Severity::Critical) => Effort::Large,
        (TaskType::FixFlow, _) => Effort::Medium,
        (TaskType::FixApi, _) => Effort::Medium,
        (TaskType::AddTest, _) => Effort::Small,
        (TaskType::AddConfig, _) => Effort::Small,
        (TaskType::AddDeploy, _) => Effort::Medium,
        (TaskType::FixGhostTable, _) => Effort::Medium,
        (TaskType::FixRLS, Severity::Critical) => Effort::Large,
        (TaskType::FixRLS, _) => Effort::Medium,
        (TaskType::FixCredential, _) => Effort::Small,
        (TaskType::FixCacheOnly, _) => Effort::Medium,
        (TaskType::FixIsolation, Severity::Critical) => Effort::Large,
        (TaskType::FixIsolation, _) => Effort::Medium,
    }
}

fn build_title(task_type: TaskType, message: &str) -> String {
    let prefix = match task_type {
        TaskType::CreateBff => "Create BFF endpoint",
        TaskType::CreateHook => "Create hook",
        TaskType::CreatePage => "Create page",
        TaskType::FixFlow => "Fix flow",
        TaskType::FixApi => "Fix API contract",
        TaskType::AddTest => "Add test coverage",
        TaskType::AddConfig => "Add configuration",
        TaskType::AddDeploy => "Add deploy config",
        TaskType::FixGhostTable => "Remove ghost table",
        TaskType::FixRLS => "Fix RLS policy",
        TaskType::FixCredential => "Fix hardcoded credential",
        TaskType::FixCacheOnly => "Fix cache isolation",
        TaskType::FixIsolation => "Fix data isolation",
    };

    // Truncate the finding message for a concise title.
    let short_msg = if message.len() > 60 {
        format!("{}...", &message[..57])
    } else {
        message.to_string()
    };

    format!("{prefix}: {short_msg}")
}

fn build_description(task_type: TaskType, message: &str, suggestion: Option<&str>) -> String {
    let mut desc = format!("**Finding:** {message}\n\n**Action:** ");

    let action = match task_type {
        TaskType::CreateBff => {
            "Implement a Backend-for-Frontend endpoint to bridge the gap \
             between the frontend expectation and the current API."
        }
        TaskType::CreateHook => {
            "Create a custom hook that encapsulates the required logic \
             and exposes a clean interface to consuming components."
        }
        TaskType::CreatePage => {
            "Create the missing page or view component to complete \
             the user-facing flow."
        }
        TaskType::FixFlow => {
            "Trace the user flow end-to-end and fix the broken or \
             incomplete transition between steps."
        }
        TaskType::FixApi => {
            "Align the API contract between producer and consumer. \
             Ensure request/response shapes match the specification."
        }
        TaskType::AddTest => "Add unit and/or integration tests to cover the identified gap.",
        TaskType::AddConfig => {
            "Add or update configuration (e.g. auth middleware, env vars) \
             to satisfy the requirement."
        }
        TaskType::AddDeploy => {
            "Add deployment configuration (Dockerfile, CI pipeline, \
             infrastructure-as-code) to enable production readiness."
        }
        TaskType::FixGhostTable => {
            "Remove or connect the ghost table that is defined in migrations \
             but never referenced in application code."
        }
        TaskType::FixRLS => {
            "Enable or fix Row-Level Security policies so every query is \
             scoped to the current tenant."
        }
        TaskType::FixCredential => {
            "Replace the hardcoded credential with an environment variable \
             or secret manager reference."
        }
        TaskType::FixCacheOnly => {
            "Add tenant-scoped key prefixes to shared cache entries to \
             prevent cross-tenant data leakage."
        }
        TaskType::FixIsolation => {
            "Review and fix the data isolation boundary to ensure tenant \
             data cannot leak across contexts."
        }
    };

    desc.push_str(action);

    if let Some(hint) = suggestion {
        desc.push_str(&format!("\n\n**Hint:** {hint}"));
    }

    desc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::types::{Finding, ScanResult, Severity};

    #[test]
    fn info_findings_are_skipped() {
        let results = vec![ScanResult {
            scanner: "S1-stub-detector".into(),
            findings: vec![Finding::new(
                "S1-stub-detector",
                Severity::Info,
                "minor note",
            )],
            score: 90,
            summary: String::new(),
        }];
        let tasks = decompose(&results);
        assert!(tasks.is_empty());
    }

    #[test]
    fn critical_finding_produces_p0_tasks() {
        let results = vec![ScanResult {
            scanner: "S3-flow".into(),
            findings: vec![Finding::new("S3-flow", Severity::Critical, "broken flow")],
            score: 30,
            summary: String::new(),
        }];
        let tasks = decompose(&results);
        assert!(!tasks.is_empty());
        assert!(tasks.iter().all(|t| t.priority == Priority::P0));
    }

    #[test]
    fn s2_scanner_creates_three_task_types() {
        let results = vec![ScanResult {
            scanner: "S2-layer-gap".into(),
            findings: vec![Finding::new("S2", Severity::Warning, "missing layer")],
            score: 50,
            summary: String::new(),
        }];
        let tasks = decompose(&results);
        assert_eq!(tasks.len(), 3);
    }
}
