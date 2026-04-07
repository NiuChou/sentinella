use owo_colors::OwoColorize;

use crate::scanners::types::{Confidence, Finding, ScanResult, Severity};

/// Output format for gap reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Terminal,
    Json,
    Markdown,
    Notion,
}

/// Render a gap report in the requested format.
///
/// Findings are filtered by confidence level before rendering:
/// - Default (no flags): show Confirmed + Likely only
/// - `show_suspect = true`: show all including Suspect
/// - `min_confidence = Some(Confirmed)`: show only Confirmed
/// - `min_confidence = Some(Suspect)`: same as show_suspect
pub fn render_gap_report(
    results: &[ScanResult],
    format: ReportFormat,
    min_confidence: Option<Confidence>,
    show_suspect: bool,
) -> String {
    let threshold = if show_suspect {
        Confidence::Suspect
    } else {
        min_confidence.unwrap_or(Confidence::Likely)
    };

    let filtered_results = filter_results_by_confidence(results, threshold);

    let total_all: usize = results.iter().map(|r| r.findings.len()).sum();
    let total_filtered: usize = filtered_results.iter().map(|r| r.findings.len()).sum();

    let mut output = match format {
        ReportFormat::Terminal => render_terminal(&filtered_results),
        ReportFormat::Json => render_json(&filtered_results),
        ReportFormat::Markdown => render_markdown(&filtered_results),
        ReportFormat::Notion => render_notion(&filtered_results),
    };

    if total_filtered < total_all {
        let summary = format_filter_summary(threshold, total_filtered, total_all);
        output.push_str(&summary);
    }

    output
}

/// Build filtered copies of scan results, keeping only findings at or above the threshold.
fn filter_results_by_confidence(results: &[ScanResult], threshold: Confidence) -> Vec<ScanResult> {
    results
        .iter()
        .map(|r| {
            let filtered_findings: Vec<Finding> = r
                .findings
                .iter()
                .filter(|f| f.confidence >= threshold)
                .cloned()
                .collect();
            ScanResult {
                scanner: r.scanner.clone(),
                findings: filtered_findings,
                score: r.score,
                summary: r.summary.clone(),
            }
        })
        .collect()
}

/// Format a summary line showing how many findings were filtered out.
fn format_filter_summary(threshold: Confidence, shown: usize, total: usize) -> String {
    let level_label = match threshold {
        Confidence::Confirmed => "Confirmed",
        Confidence::Likely => "Confirmed + Likely",
        Confidence::Suspect => "all",
    };
    format!(
        "\n  Showing {shown} findings ({level_label}). Use --show-suspect to see all {total}.\n"
    )
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

fn render_terminal(results: &[ScanResult]) -> String {
    let mut buf = String::new();
    let all_findings = collect_sorted_findings(results);

    if all_findings.is_empty() {
        buf.push_str(&"  No gaps found.\n".green().to_string());
        return buf;
    }

    let sections: &[(Severity, &str)] = &[
        (Severity::Critical, "CRITICAL"),
        (Severity::Warning, "WARNING"),
        (Severity::Info, "INFO"),
    ];

    for (sev, label) in sections {
        let group: Vec<&Finding> = all_findings
            .iter()
            .filter(|f| f.severity == *sev)
            .copied()
            .collect();

        if group.is_empty() {
            continue;
        }

        let header = format!("\n  [{label}] ({} issues)\n", group.len());
        match sev {
            Severity::Critical => buf.push_str(&header.red().bold().to_string()),
            Severity::Warning => buf.push_str(&header.yellow().bold().to_string()),
            Severity::Info => buf.push_str(&header.cyan().to_string()),
        }

        for finding in &group {
            let location = format_location(finding);
            let confidence_tag = format_confidence_tag(finding.confidence);
            buf.push_str(&format!(
                "    {} {}{}\n",
                location, confidence_tag, finding.message
            ));

            if let Some(suggestion) = &finding.suggestion {
                buf.push_str(&format!("      {} {suggestion}\n", "hint:".dimmed()));
            }
        }
    }

    buf
}

fn format_location(finding: &Finding) -> String {
    match (&finding.file, finding.line) {
        (Some(file), Some(line)) => format!("{}:{line}:", file.display()),
        (Some(file), None) => format!("{}:", file.display()),
        _ => format!("[{}]", finding.scanner),
    }
}

fn format_confidence_tag(confidence: Confidence) -> String {
    match confidence {
        Confidence::Confirmed => String::new(),
        Confidence::Likely => "(Likely) ".to_string(),
        Confidence::Suspect => "(Suspect) ".to_string(),
    }
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn render_json(results: &[ScanResult]) -> String {
    serde_json::to_string_pretty(results).unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

fn render_markdown(results: &[ScanResult]) -> String {
    let mut md = String::from("# Sentinella Gap Report\n\n");

    // Summary table
    md.push_str("## Summary\n\n");
    md.push_str("| Scanner | Score | Findings |\n");
    md.push_str("|---------|------:|---------:|\n");
    for result in results {
        md.push_str(&format!(
            "| {} | {}/100 | {} |\n",
            result.scanner,
            result.score,
            result.findings.len()
        ));
    }
    md.push('\n');

    // Findings by severity
    let all_findings = collect_sorted_findings(results);

    let sections: &[(Severity, &str)] = &[
        (Severity::Critical, "Critical"),
        (Severity::Warning, "Warning"),
        (Severity::Info, "Info"),
    ];

    for (sev, label) in sections {
        let group: Vec<&Finding> = all_findings
            .iter()
            .filter(|f| f.severity == *sev)
            .copied()
            .collect();

        if group.is_empty() {
            continue;
        }

        md.push_str(&format!("## {label}\n\n"));
        md.push_str("| Scanner | Confidence | Location | Message | Suggestion |\n");
        md.push_str("|---------|------------|----------|---------|------------|\n");

        for finding in &group {
            let location = match (&finding.file, finding.line) {
                (Some(file), Some(line)) => format!("`{}:{line}`", file.display()),
                (Some(file), None) => format!("`{}`", file.display()),
                _ => String::from("-"),
            };
            let suggestion = finding.suggestion.as_deref().unwrap_or("-");
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                finding.scanner, finding.confidence, location, finding.message, suggestion
            ));
        }
        md.push('\n');
    }

    md
}

// ---------------------------------------------------------------------------
// Notion
// ---------------------------------------------------------------------------

fn render_notion(results: &[ScanResult]) -> String {
    let mut md = String::from("# Sentinella Gap Report\n\n");

    // Summary table
    md.push_str("## Summary\n\n");
    md.push_str("| Scanner | Score | Findings |\n");
    md.push_str("|---------|------:|---------:|\n");
    for result in results {
        md.push_str(&format!(
            "| {} | {}/100 | {} |\n",
            result.scanner,
            result.score,
            result.findings.len()
        ));
    }
    md.push('\n');

    // Findings by severity with Notion callout blocks
    let all_findings = collect_sorted_findings(results);

    let sections: &[(Severity, &str, &str)] = &[
        (Severity::Critical, "Critical", "🔴"),
        (Severity::Warning, "Warning", "🟡"),
        (Severity::Info, "Info", "🔵"),
    ];

    for (sev, label, icon) in sections {
        let group: Vec<&Finding> = all_findings
            .iter()
            .filter(|f| f.severity == *sev)
            .copied()
            .collect();

        if group.is_empty() {
            continue;
        }

        md.push_str(&format!("## {label}\n\n"));
        md.push_str(&notion_callout_open(icon, label, group.len()));

        for finding in &group {
            md.push_str(&notion_finding_line(finding));
        }

        md.push_str(&notion_callout_close());
    }

    md
}

fn notion_callout_open(icon: &str, label: &str, count: usize) -> String {
    format!("> {icon} **{label}** ({count} issues)\n>\n")
}

fn notion_finding_line(finding: &Finding) -> String {
    let location = match (&finding.file, finding.line) {
        (Some(file), Some(line)) => format!("`{}:{line}`", file.display()),
        (Some(file), None) => format!("`{}`", file.display()),
        _ => format!("`[{}]`", finding.scanner),
    };

    let confidence_tag = match finding.confidence {
        Confidence::Confirmed => "",
        Confidence::Likely => " `Likely`",
        Confidence::Suspect => " `Suspect`",
    };

    let mut line = format!("> - {location}{confidence_tag} {}\n", finding.message);

    if let Some(suggestion) = &finding.suggestion {
        line.push_str(&format!(">   *Hint: {suggestion}*\n"));
    }

    line
}

fn notion_callout_close() -> String {
    String::from("\n")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn collect_sorted_findings(results: &[ScanResult]) -> Vec<&Finding> {
    let mut findings: Vec<&Finding> = results.iter().flat_map(|r| &r.findings).collect();
    // Sort by severity descending (Critical > Warning > Info).
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::types::{Finding, ScanResult, Severity};

    fn sample_results() -> Vec<ScanResult> {
        vec![ScanResult {
            scanner: "S1-stub-detector".into(),
            findings: vec![
                Finding::new("S1-stub-detector", Severity::Critical, "TODO found"),
                Finding::new("S1-stub-detector", Severity::Info, "Minor note"),
            ],
            score: 60,
            summary: "Some stubs remain".into(),
        }]
    }

    #[test]
    fn json_round_trips() {
        let results = sample_results();
        let json = render_gap_report(&results, ReportFormat::Json, None, false);
        let parsed: Vec<ScanResult> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 1);
    }

    #[test]
    fn markdown_contains_header() {
        let results = sample_results();
        let md = render_gap_report(&results, ReportFormat::Markdown, None, false);
        assert!(md.starts_with("# Sentinella Gap Report"));
    }

    #[test]
    fn notion_contains_callout_blocks() {
        let results = sample_results();
        let notion = render_gap_report(&results, ReportFormat::Notion, None, false);
        assert!(notion.starts_with("# Sentinella Gap Report"));
        // Critical findings produce a red callout
        assert!(notion.contains("> \u{1f534} **Critical**"));
        // Info findings produce a blue callout
        assert!(notion.contains("> \u{1f535} **Info**"));
    }

    #[test]
    fn notion_includes_suggestions_as_hints() {
        let results = vec![ScanResult {
            scanner: "S1".into(),
            findings: vec![
                Finding::new("S1", Severity::Warning, "needs fix").with_suggestion("try this")
            ],
            score: 50,
            summary: String::new(),
        }];
        let notion = render_gap_report(&results, ReportFormat::Notion, None, false);
        assert!(notion.contains("*Hint: try this*"));
    }

    #[test]
    fn snapshot_json_output() {
        let results = vec![
            ScanResult {
                scanner: "S1-stub-detector".into(),
                findings: vec![Finding::new(
                    "S1",
                    Severity::Critical,
                    "Stub detected in useData.ts",
                )
                .with_file(std::path::PathBuf::from("src/hooks/useData.ts"))
                .with_line(10)
                .with_suggestion("Replace with real API call")],
                score: 75,
                summary: "1 stub detected".into(),
            },
            ScanResult {
                scanner: "S6-residue-finder".into(),
                findings: vec![Finding::new("S6", Severity::Warning, "TODO residue found")
                    .with_file(std::path::PathBuf::from("src/api.ts"))
                    .with_line(42)],
                score: 90,
                summary: "1 residue marker".into(),
            },
        ];

        let json = render_gap_report(&results, ReportFormat::Json, None, false);
        insta::assert_snapshot!("gap_report_json", json);
    }

    #[test]
    fn snapshot_json_empty() {
        let results: Vec<ScanResult> = vec![ScanResult {
            scanner: "S1".into(),
            findings: vec![],
            score: 100,
            summary: "Clean".into(),
        }];

        let json = render_gap_report(&results, ReportFormat::Json, None, false);
        insta::assert_snapshot!("gap_report_json_empty", json);
    }
}
