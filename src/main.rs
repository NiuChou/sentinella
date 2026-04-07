use std::path::PathBuf;
use std::process;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use miette::{Context, IntoDiagnostic, Result};
use owo_colors::OwoColorize;

use sentinella::config;
use sentinella::config::architecture::{detect_architecture, Architecture};
use sentinella::indexer::build_index_multi;
use sentinella::reporters::gap::{self, ReportFormat};
use sentinella::reporters::matrix;
use sentinella::reporters::task_decomposer;
use sentinella::scanners::types::ScanContext;
use sentinella::scanners::{create_scanners, run_scanners};
use sentinella::suppress;

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "sentinella", version, about = "System completeness audit tool")]
struct Cli {
    /// Path to a config file (overrides auto-discovery)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run completeness scanners against the project
    Check {
        /// Project root directory (defaults to current directory)
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,

        /// Run only specific scanners (e.g. S1,S9)
        #[arg(short, long)]
        scanner: Option<String>,

        /// Output format
        #[arg(short, long, value_enum, default_value_t = CliOutputFormat::Terminal)]
        format: CliOutputFormat,

        /// Minimum coverage percentage to pass
        #[arg(long)]
        min_coverage: Option<u8>,
    },

    /// Generate a starter config file
    Init {
        /// Project type template to generate
        #[arg(short, long, value_enum, default_value_t = CliProjectType::Fullstack)]
        r#type: CliProjectType,
    },

    /// Generate and dispatch task breakdowns
    Dispatch {
        /// Project root directory (defaults to current directory)
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,

        /// Dispatch target
        #[arg(short, long, value_enum, default_value_t = CliDispatchTarget::Stdout)]
        target: CliDispatchTarget,

        /// Show what would be dispatched without sending
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },

    /// Dismiss a finding as a false positive
    Dismiss {
        /// Finding stable ID (e.g., S7-a3f2b1c0)
        finding_id: String,

        /// Reason for dismissal
        #[arg(long)]
        reason: String,

        /// Project root directory (defaults to current directory)
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
}

// ---------------------------------------------------------------------------
// CLI value enums (mirror config schema enums for clap)
// ---------------------------------------------------------------------------

#[derive(Clone, ValueEnum)]
enum CliOutputFormat {
    Terminal,
    Json,
    Markdown,
    Notion,
}

#[derive(Clone, ValueEnum)]
enum CliProjectType {
    Fullstack,
    BackendOnly,
    Monorepo,
}

#[derive(Clone, ValueEnum)]
enum CliDispatchTarget {
    Stdout,
    Notion,
    Github,
}

// ---------------------------------------------------------------------------
// Template contents
// ---------------------------------------------------------------------------

fn template_for(project_type: &CliProjectType) -> &'static str {
    match project_type {
        CliProjectType::Fullstack => include_str!("../templates/fullstack.yaml"),
        CliProjectType::BackendOnly => include_str!("../templates/backend_only.yaml"),
        CliProjectType::Monorepo => include_str!("../templates/monorepo.yaml"),
    }
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

fn print_banner() {
    let bold = "sentinella".bold();
    let name = bold.cyan();
    let tag = "system completeness audit".dimmed();
    eprintln!("{name}  {tag}");
    eprintln!();
}

// ---------------------------------------------------------------------------
// Format conversion
// ---------------------------------------------------------------------------

fn to_report_format(cli_fmt: &CliOutputFormat) -> ReportFormat {
    match cli_fmt {
        CliOutputFormat::Terminal => ReportFormat::Terminal,
        CliOutputFormat::Json => ReportFormat::Json,
        CliOutputFormat::Markdown => ReportFormat::Markdown,
        CliOutputFormat::Notion => ReportFormat::Notion,
    }
}

// ---------------------------------------------------------------------------
// Subcommand handlers
// ---------------------------------------------------------------------------

fn handle_init(project_type: CliProjectType) -> Result<()> {
    let dest = PathBuf::from(".sentinella.yaml");
    if dest.exists() {
        return Err(miette::miette!(
            help = "Remove or rename the existing file first",
            ".sentinella.yaml already exists"
        ));
    }

    let content = template_for(&project_type);
    std::fs::write(&dest, content)
        .into_diagnostic()
        .wrap_err("failed to write config file")?;

    eprintln!("{} wrote {}", "done:".green().bold(), dest.display().cyan());
    Ok(())
}

fn handle_check(
    config_path: Option<PathBuf>,
    dir: PathBuf,
    scanner_filter: Option<String>,
    format: CliOutputFormat,
    min_coverage: Option<u8>,
) -> Result<()> {
    let cfg = load_project_config(config_path.as_deref(), &dir)?;

    let arch = detect_architecture(&dir, &cfg.linked_repos);
    eprintln!(
        "{} detected architecture: {}",
        "info:".blue().bold(),
        format!("{arch}").cyan(),
    );

    let index = build_project_index_for_arch(&dir, &cfg, &arch)?;
    let raw_results = run_project_scanners(&cfg, &index, &dir, scanner_filter.as_deref())?;

    // Apply all suppression layers
    let suppressions = suppress::SuppressionSet::from_index(&index);
    let config_suppress = cfg.suppress.clone().unwrap_or_default();
    let dismissals = suppress::load_dismissals(&dir).unwrap_or_default();
    let results = suppress::apply_suppressions(
        &raw_results,
        &suppressions,
        &config_suppress,
        &dismissals,
        &dir,
    );

    render_check_output(&results, &cfg, &format);

    exit_on_coverage_failure(&results, min_coverage);
    Ok(())
}

fn handle_dispatch(
    config_path: Option<PathBuf>,
    dir: PathBuf,
    target: CliDispatchTarget,
    dry_run: bool,
) -> Result<()> {
    let cfg = load_project_config(config_path.as_deref(), &dir)?;

    let arch = detect_architecture(&dir, &cfg.linked_repos);
    eprintln!(
        "{} detected architecture: {}",
        "info:".blue().bold(),
        format!("{arch}").cyan(),
    );

    let index = build_project_index_for_arch(&dir, &cfg, &arch)?;
    let results = run_project_scanners(&cfg, &index, &dir, None)?;

    let tasks = task_decomposer::decompose(&results);

    dispatch_tasks(&tasks, &target, dry_run);
    Ok(())
}

// ---------------------------------------------------------------------------
// Pipeline helpers (each < 50 lines, no mutation)
// ---------------------------------------------------------------------------

fn load_project_config(
    explicit_path: Option<&std::path::Path>,
    dir: &std::path::Path,
) -> Result<config::Config> {
    let cfg = config::load_config_auto(explicit_path, dir)?;
    eprintln!(
        "{} loaded config for project {}",
        "info:".blue().bold(),
        cfg.project.cyan().bold(),
    );
    Ok(cfg)
}

fn build_project_index_for_arch(
    dir: &std::path::Path,
    cfg: &config::Config,
    arch: &Architecture,
) -> Result<Arc<sentinella::indexer::store::IndexStore>> {
    eprintln!("{} building file index...", "info:".blue().bold());

    let roots = collect_roots_for_arch(dir, arch);
    let root_refs: Vec<&std::path::Path> = roots.iter().map(|p| p.as_path()).collect();

    let index = build_index_multi(&root_refs, cfg)
        .map_err(|e| miette::miette!("failed to build file index: {e}"))?;

    eprintln!(
        "{} file index ready ({} root(s))",
        "info:".blue().bold(),
        roots.len(),
    );
    Ok(index)
}

fn collect_roots_for_arch(dir: &std::path::Path, arch: &Architecture) -> Vec<PathBuf> {
    match arch {
        Architecture::SingleRepo => vec![dir.to_path_buf()],
        Architecture::Monorepo { services } => {
            services.iter().map(|s| s.root_dir.clone()).collect()
        }
        Architecture::Polyrepo { linked_repos } => {
            let mut roots = vec![dir.to_path_buf()];
            roots.extend(linked_repos.iter().map(|r| r.path.clone()));
            roots
        }
    }
}

fn run_project_scanners(
    cfg: &config::Config,
    index: &Arc<sentinella::indexer::store::IndexStore>,
    dir: &std::path::Path,
    scanner_filter: Option<&str>,
) -> Result<Vec<sentinella::scanners::types::ScanResult>> {
    let scanners = create_scanners(scanner_filter);
    eprintln!(
        "{} running {} scanner(s)...",
        "info:".blue().bold(),
        scanners.len()
    );

    let ctx = ScanContext {
        config: cfg,
        index,
        root_dir: dir,
    };

    let results = run_scanners(&scanners, &ctx);
    eprintln!(
        "{} scanning complete ({} results)",
        "info:".blue().bold(),
        results.len()
    );
    Ok(results)
}

fn render_check_output(
    results: &[sentinella::scanners::types::ScanResult],
    cfg: &config::Config,
    format: &CliOutputFormat,
) {
    matrix::render_matrix(results, cfg);

    let report_format = to_report_format(format);
    let gap_output = gap::render_gap_report(results, report_format);
    print!("{gap_output}");
}

fn exit_on_coverage_failure(
    results: &[sentinella::scanners::types::ScanResult],
    min_coverage: Option<u8>,
) {
    let threshold = match min_coverage {
        Some(t) => t,
        None => return,
    };

    let score = matrix::overall_score(results);
    if score < threshold {
        eprintln!(
            "{} overall score {}/100 is below minimum {}/100",
            "fail:".red().bold(),
            score,
            threshold,
        );
        process::exit(1);
    }
}

fn dispatch_tasks(tasks: &[task_decomposer::Task], target: &CliDispatchTarget, dry_run: bool) {
    match target {
        CliDispatchTarget::Stdout => {
            sentinella::dispatchers::stdout::dispatch(tasks, dry_run);
        }
        CliDispatchTarget::Notion => {
            eprintln!(
                "{} Notion dispatch not yet implemented, falling back to stdout",
                "warn:".yellow().bold()
            );
            sentinella::dispatchers::stdout::dispatch(tasks, dry_run);
        }
        CliDispatchTarget::Github => {
            eprintln!(
                "{} GitHub dispatch not yet implemented, falling back to stdout",
                "warn:".yellow().bold()
            );
            sentinella::dispatchers::stdout::dispatch(tasks, dry_run);
        }
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let cli = Cli::parse();
    print_banner();

    match cli.command {
        Command::Init { r#type } => handle_init(r#type),
        Command::Check {
            dir,
            scanner,
            format,
            min_coverage,
        } => handle_check(cli.config, dir, scanner, format, min_coverage),
        Command::Dispatch {
            dir,
            target,
            dry_run,
        } => handle_dispatch(cli.config, dir, target, dry_run),
        Command::Dismiss {
            finding_id,
            reason,
            dir,
        } => handle_dismiss(dir, finding_id, reason),
    }
}

fn handle_dismiss(dir: PathBuf, finding_id: String, reason: String) -> Result<()> {
    let mut dismissals = suppress::load_dismissals(&dir)
        .map_err(|e| miette::miette!("failed to load dismiss file: {e}"))?;

    let scanner = finding_id.split('-').next().unwrap_or("").to_string();

    let record = suppress::DismissRecord {
        scanner,
        file: None,
        pattern: Some(finding_id.clone()),
        reason,
        by: std::env::var("USER").ok(),
        at: suppress::today_iso(),
    };

    // Produce a new vec rather than mutating in place
    let mut new_dismissed = dismissals.dismissed.clone();
    new_dismissed.push(record);
    dismissals = suppress::DismissFile {
        dismissed: new_dismissed,
    };

    suppress::save_dismissals(&dir, &dismissals)
        .map_err(|e| miette::miette!("failed to save dismiss file: {e}"))?;

    eprintln!("{} dismissed {}", "done:".green().bold(), finding_id.cyan(),);
    Ok(())
}
