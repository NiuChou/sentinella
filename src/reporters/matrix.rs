use comfy_table::{
    presets::UTF8_FULL_CONDENSED, Attribute, Cell, CellAlignment, Color, ContentArrangement,
    Table,
};
use owo_colors::OwoColorize;

use crate::config::schema::{Config, FlowConfig, ModuleConfig};
use crate::scanners::types::ScanResult;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Render the completeness matrix to the terminal.
///
/// When modules are configured, the primary table is module x layer.
/// A secondary "Scanner Scores" table always follows.
pub fn render_matrix(results: &[ScanResult], config: &Config) {
    let date = chrono_free_date();

    println!();
    println!(
        "{}",
        format!("  Sentinella  {}  {date}", config.project).bold()
    );
    println!();

    if !config.modules.is_empty() {
        render_module_layer_table(&config.modules, &config.flows);
        println!();
    }

    render_scanner_scores_table(results);

    print_overall_score(results);
    println!();
}

/// Compute the weighted average score across all scan results.
///
/// Each scanner contributes equally. Returns 0 when `results` is empty.
pub fn overall_score(results: &[ScanResult]) -> u8 {
    if results.is_empty() {
        return 0;
    }

    let sum: u32 = results.iter().map(|r| u32::from(r.score)).sum();
    let avg = sum / results.len() as u32;
    avg.min(100) as u8
}

// ---------------------------------------------------------------------------
// Module x Layer table
// ---------------------------------------------------------------------------

/// Coverage status for a single layer within a module.
struct LayerStatus {
    covered: bool,
    detail: String,
}

/// Assessed coverage for one module across all layers.
struct ModuleCoverage {
    name: String,
    backend: LayerStatus,
    bff: LayerStatus,
    hook: LayerStatus,
    page: LayerStatus,
    flow: LayerStatus,
    score_pct: u8,
}

fn assess_module(module: &ModuleConfig, flows: &[FlowConfig]) -> ModuleCoverage {
    let backend = match &module.backend {
        Some(pattern) => LayerStatus {
            covered: true,
            detail: format!("pattern:{pattern}"),
        },
        None => LayerStatus {
            covered: false,
            detail: String::new(),
        },
    };

    let bff = match &module.bff {
        Some(_) => LayerStatus {
            covered: true,
            detail: "yes".into(),
        },
        None => LayerStatus {
            covered: false,
            detail: String::new(),
        },
    };

    let hook = match &module.hooks {
        Some(_) => LayerStatus {
            covered: true,
            detail: "yes".into(),
        },
        None => LayerStatus {
            covered: false,
            detail: String::new(),
        },
    };

    let page = match &module.page {
        Some(_) => LayerStatus {
            covered: true,
            detail: "yes".into(),
        },
        None => LayerStatus {
            covered: false,
            detail: String::new(),
        },
    };

    let has_flow = has_module_flow(&module.name, flows);
    let flow = LayerStatus {
        covered: has_flow,
        detail: if has_flow { "yes".into() } else { String::new() },
    };

    let score_pct = compute_module_score(&backend, &bff, &hook, &page, &flow);

    ModuleCoverage {
        name: module.name.clone(),
        backend,
        bff,
        hook,
        page,
        flow,
        score_pct,
    }
}

fn has_module_flow(module_name: &str, flows: &[FlowConfig]) -> bool {
    let lower = module_name.to_lowercase();
    flows
        .iter()
        .any(|f| f.name.to_lowercase().contains(&lower) && !f.steps.is_empty())
}

fn compute_module_score(
    backend: &LayerStatus,
    bff: &LayerStatus,
    hook: &LayerStatus,
    page: &LayerStatus,
    flow: &LayerStatus,
) -> u8 {
    let layers = [
        backend.covered,
        bff.covered,
        hook.covered,
        page.covered,
        flow.covered,
    ];
    let covered = layers.iter().filter(|&&c| c).count() as u8;
    let total = layers.len() as u8;
    ((u16::from(covered) * 100) / u16::from(total)) as u8
}

fn render_module_layer_table(modules: &[ModuleConfig], flows: &[FlowConfig]) {
    let coverages: Vec<ModuleCoverage> = modules
        .iter()
        .map(|m| assess_module(m, flows))
        .collect();

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(module_table_header());

    for cov in &coverages {
        table.add_row(module_table_row(cov));
    }

    println!("{table}");
}

fn module_table_header() -> Vec<Cell> {
    let labels = ["Module", "Backend", "BFF", "Hook", "Page", "Flow", "Score"];
    labels
        .iter()
        .map(|l| {
            Cell::new(l)
                .add_attribute(Attribute::Bold)
                .fg(Color::White)
        })
        .collect()
}

fn module_table_row(cov: &ModuleCoverage) -> Vec<Cell> {
    vec![
        Cell::new(&cov.name),
        layer_cell(&cov.backend),
        layer_cell(&cov.bff),
        layer_cell(&cov.hook),
        layer_cell(&cov.page),
        layer_cell(&cov.flow),
        score_cell(cov.score_pct),
    ]
}

fn layer_cell(status: &LayerStatus) -> Cell {
    if status.covered {
        Cell::new("  \u{2705}  ")
            .fg(Color::Green)
            .set_alignment(CellAlignment::Center)
    } else {
        Cell::new("  \u{274c}  ")
            .fg(Color::Red)
            .set_alignment(CellAlignment::Center)
    }
}

fn score_cell(pct: u8) -> Cell {
    let color = score_color(pct);
    Cell::new(format!("{pct}%"))
        .fg(color)
        .set_alignment(CellAlignment::Center)
}

// ---------------------------------------------------------------------------
// Scanner Scores table (original behavior)
// ---------------------------------------------------------------------------

fn render_scanner_scores_table(results: &[ScanResult]) {
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(scanner_table_header());

    for result in results {
        table.add_row(scanner_table_row(result));
    }

    println!("  Scanner Scores");
    println!("{table}");
}

fn scanner_table_header() -> Vec<Cell> {
    vec![
        Cell::new("Scanner")
            .add_attribute(Attribute::Bold)
            .fg(Color::White),
        Cell::new("Score")
            .add_attribute(Attribute::Bold)
            .fg(Color::White)
            .set_alignment(CellAlignment::Center),
        Cell::new("Findings")
            .add_attribute(Attribute::Bold)
            .fg(Color::White)
            .set_alignment(CellAlignment::Center),
        Cell::new("Status")
            .add_attribute(Attribute::Bold)
            .fg(Color::White),
    ]
}

fn scanner_table_row(result: &ScanResult) -> Vec<Cell> {
    let color = score_color(result.score);
    vec![
        Cell::new(&result.scanner),
        Cell::new(format!("{}/100", result.score))
            .fg(color)
            .set_alignment(CellAlignment::Center),
        Cell::new(result.findings.len().to_string()).set_alignment(CellAlignment::Center),
        Cell::new(status_label(result.score)).fg(color),
    ]
}

// ---------------------------------------------------------------------------
// Overall score display
// ---------------------------------------------------------------------------

fn print_overall_score(results: &[ScanResult]) {
    let total = overall_score(results);
    let total_color = score_color(total);
    let total_label = format!("  Overall Score: {total}/100");

    match total_color {
        Color::Green => println!("{}", total_label.green().bold()),
        Color::Yellow => println!("{}", total_label.yellow().bold()),
        _ => println!("{}", total_label.red().bold()),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn score_color(score: u8) -> Color {
    if score >= 80 {
        Color::Green
    } else if score >= 50 {
        Color::Yellow
    } else {
        Color::Red
    }
}

fn status_label(score: u8) -> &'static str {
    if score >= 80 {
        "PASS"
    } else if score >= 50 {
        "WARN"
    } else {
        "FAIL"
    }
}

/// Simple date string without pulling in the `chrono` crate.
fn chrono_free_date() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let days = secs / 86_400;
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    days += 719_468;
    let era = days / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanners::types::ScanResult;

    #[test]
    fn overall_score_empty() {
        assert_eq!(overall_score(&[]), 0);
    }

    #[test]
    fn overall_score_averages() {
        let results = vec![
            ScanResult {
                scanner: "a".into(),
                findings: vec![],
                score: 80,
                summary: String::new(),
            },
            ScanResult {
                scanner: "b".into(),
                findings: vec![],
                score: 60,
                summary: String::new(),
            },
        ];
        assert_eq!(overall_score(&results), 70);
    }

    #[test]
    fn compute_module_score_all_covered() {
        let yes = LayerStatus { covered: true, detail: String::new() };
        assert_eq!(compute_module_score(&yes, &yes, &yes, &yes, &yes), 100);
    }

    #[test]
    fn compute_module_score_none_covered() {
        let no = LayerStatus { covered: false, detail: String::new() };
        assert_eq!(compute_module_score(&no, &no, &no, &no, &no), 0);
    }

    #[test]
    fn compute_module_score_partial() {
        let yes = LayerStatus { covered: true, detail: String::new() };
        let no = LayerStatus { covered: false, detail: String::new() };
        // 1 out of 5 = 20%
        assert_eq!(compute_module_score(&yes, &no, &no, &no, &no), 20);
    }

    #[test]
    fn has_module_flow_matches() {
        let flows = vec![FlowConfig {
            name: "CRM create lead".into(),
            steps: vec![crate::config::schema::FlowStepConfig {
                action: "create".into(),
                api: "/api/leads".into(),
                page: None,
            }],
        }];
        assert!(has_module_flow("CRM", &flows));
        assert!(!has_module_flow("Inbox", &flows));
    }

    #[test]
    fn has_module_flow_empty_steps_not_covered() {
        let flows = vec![FlowConfig {
            name: "CRM create lead".into(),
            steps: vec![],
        }];
        assert!(!has_module_flow("CRM", &flows));
    }

    #[test]
    fn assess_module_full_coverage() {
        let module = ModuleConfig {
            name: "Inbox".into(),
            backend: Some("services/inbox/**".into()),
            bff: Some("bff/inbox/**".into()),
            hooks: Some("hooks/useInbox*".into()),
            page: Some("pages/inbox/**".into()),
        };
        let flows = vec![FlowConfig {
            name: "Inbox send message".into(),
            steps: vec![crate::config::schema::FlowStepConfig {
                action: "send".into(),
                api: "/api/messages".into(),
                page: Some("/inbox".into()),
            }],
        }];
        let cov = assess_module(&module, &flows);
        assert_eq!(cov.score_pct, 100);
        assert!(cov.backend.covered);
        assert!(cov.bff.covered);
        assert!(cov.hook.covered);
        assert!(cov.page.covered);
        assert!(cov.flow.covered);
    }

    #[test]
    fn assess_module_backend_only() {
        let module = ModuleConfig {
            name: "CRM".into(),
            backend: Some("services/crm/**".into()),
            bff: None,
            hooks: None,
            page: None,
        };
        let cov = assess_module(&module, &[]);
        assert_eq!(cov.score_pct, 20);
        assert!(cov.backend.covered);
        assert!(!cov.bff.covered);
    }

    #[test]
    fn snapshot_scanner_results_yaml() {
        let results = vec![
            ScanResult {
                scanner: "S1-stub-detector".into(),
                findings: vec![],
                score: 100,
                summary: "No stubs found".into(),
            },
            ScanResult {
                scanner: "S6-residue-finder".into(),
                findings: vec![crate::scanners::types::Finding::new(
                    "S6",
                    crate::scanners::types::Severity::Warning,
                    "TODO residue in api.ts",
                )],
                score: 85,
                summary: "1 residue marker".into(),
            },
        ];

        insta::assert_yaml_snapshot!("matrix_scanner_results", results);
    }

    #[test]
    fn snapshot_overall_score_calculation() {
        let results = vec![
            ScanResult {
                scanner: "S1".into(),
                findings: vec![],
                score: 100,
                summary: String::new(),
            },
            ScanResult {
                scanner: "S2".into(),
                findings: vec![],
                score: 80,
                summary: String::new(),
            },
            ScanResult {
                scanner: "S3".into(),
                findings: vec![],
                score: 60,
                summary: String::new(),
            },
        ];

        let score = overall_score(&results);
        insta::assert_yaml_snapshot!("matrix_overall_score", score);
    }
}
