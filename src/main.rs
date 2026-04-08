use std::path::{Path, PathBuf};
use std::process;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use miette::{Context, IntoDiagnostic, Result};
use owo_colors::OwoColorize;

use sentinella::config;
use sentinella::config::architecture::{detect_architecture, Architecture};
use sentinella::indexer::build_index_multi;
use sentinella::pack_manager;
use sentinella::reporters::gap::{self, ReportFormat};
use sentinella::reporters::matrix;
use sentinella::reporters::task_decomposer;
use sentinella::scanners::types::{Confidence, ScanContext};
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

        /// Minimum confidence level to display (suspect, likely, confirmed)
        #[arg(long, value_enum)]
        min_confidence: Option<CliConfidence>,

        /// Show all findings including low-confidence suspects
        #[arg(long)]
        show_suspect: bool,

        /// Show verbose output (tech stack, rule packs, evidence counts)
        #[arg(short, long)]
        verbose: bool,

        /// Include experimental rules in the scan
        #[arg(long, default_value_t = false)]
        experimental: bool,

        /// Include deprecated rules in the scan
        #[arg(long, default_value_t = false)]
        include_deprecated: bool,

        /// Disable cross-scanner correlation
        #[arg(long)]
        no_correlation: bool,
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

    /// Manage project context memories
    Memory {
        #[command(subcommand)]
        action: MemoryAction,
    },

    /// Export, import, or inspect Bayesian calibration data
    Calibrate {
        #[command(subcommand)]
        action: CalibrateAction,
    },

    /// Interactive triage: label findings as confirmed or false positive
    Triage {
        /// Project root directory (defaults to current directory)
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,

        /// Number of findings to triage per session
        #[arg(long, default_value = "20")]
        batch: usize,

        /// Only triage findings from this scanner
        #[arg(long)]
        scanner: Option<String>,
    },

    /// Mine dismissed findings for recurring patterns and suggest suppression rules
    Learn {
        /// Project root directory (defaults to current directory)
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,

        /// Minimum cluster size to generate a suggestion
        #[arg(long, default_value = "3")]
        min_cluster: usize,
    },

    /// Manage rule packs (list, validate, install)
    Pack {
        #[command(subcommand)]
        action: PackAction,
    },
}

#[derive(Debug, Subcommand)]
enum MemoryAction {
    /// Add a project-level or scanner-scoped memory
    Add {
        /// Memory text
        text: String,
        /// Scanner ID to scope to (e.g. S7)
        #[arg(long)]
        scanner: Option<String>,
        /// Project root directory
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
    /// List all memories
    List {
        /// Project root directory
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum CalibrateAction {
    /// Export calibration data to a JSON file for sharing
    Export {
        /// Project root directory
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
        /// Project name label for the export
        #[arg(short, long)]
        name: Option<String>,
    },
    /// Import calibration data from another project
    Import {
        /// Project root directory
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
        /// Input file path (exported JSON)
        #[arg(short, long)]
        input: PathBuf,
        /// Merge weight 0.0-1.0 (default 0.5)
        #[arg(short, long)]
        weight: Option<f64>,
    },
    /// Display current calibration statistics
    Show {
        /// Project root directory
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum PackAction {
    /// List all available rule packs
    List {
        /// Project root directory (defaults to current directory)
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,
    },

    /// Validate a rule pack YAML file
    Validate {
        /// Path to the rule pack YAML file
        path: PathBuf,
    },

    /// Install a rule pack
    Install {
        /// Path to the rule pack YAML file
        source: PathBuf,

        /// Project root directory (defaults to current directory)
        #[arg(short, long, default_value = ".")]
        dir: PathBuf,

        /// Install globally (~/.sentinella/rules/) instead of project-local
        #[arg(long)]
        global: bool,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliConfidence {
    Suspect,
    Likely,
    Confirmed,
}

// ---------------------------------------------------------------------------
// Confidence conversion
// ---------------------------------------------------------------------------

fn to_confidence(cli: &CliConfidence) -> Confidence {
    match cli {
        CliConfidence::Suspect => Confidence::Suspect,
        CliConfidence::Likely => Confidence::Likely,
        CliConfidence::Confirmed => Confidence::Confirmed,
    }
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
    min_confidence: Option<CliConfidence>,
    show_suspect: bool,
    verbose: bool,
    experimental: bool,
    include_deprecated: bool,
    no_correlation: bool,
) -> Result<()> {
    let cfg = load_project_config(config_path.as_deref(), &dir)?;

    let lifecycle_policy = sentinella::rule_lifecycle::LifecyclePolicy {
        include_experimental: experimental,
        include_deprecated,
    };

    if experimental {
        eprintln!("{} including experimental rules", "info:".blue().bold(),);
    }
    if include_deprecated {
        eprintln!("{} including deprecated rules", "info:".blue().bold(),);
    }

    let arch = detect_architecture(&dir, &cfg.linked_repos);
    eprintln!(
        "{} detected architecture: {}",
        "info:".blue().bold(),
        format!("{arch}").cyan(),
    );

    let index = build_project_index_for_arch(&dir, &arch, &lifecycle_policy)?;

    if verbose {
        print_rule_pack_summary(&dir);
    }

    let raw_results = run_project_scanners(&cfg, &index, &dir, scanner_filter.as_deref())?;

    // Apply all suppression layers
    let suppressions = suppress::SuppressionSet::from_index(&index);
    let config_suppress = cfg.suppress.clone().unwrap_or_default();
    let dismissals = suppress::load_dismissals(&dir).unwrap_or_default();
    let suppressed = suppress::apply_suppressions(
        &raw_results,
        &suppressions,
        &config_suppress,
        &dismissals,
        &dir,
    );

    // Apply context memories to adjust severity/confidence
    let memories = sentinella::memory::load_memories(&dir).unwrap_or_default();
    let memory_effects = sentinella::memory::parse_memory_effects(&memories);
    let after_memory = sentinella::memory::apply_memories(&suppressed, &memory_effects);

    // Apply Bayesian calibration to adjust confidence scores
    let calibration_store = sentinella::calibration::load_calibration(&dir)
        .map_err(|e| miette::miette!("failed to load calibration: {e}"))?;
    let calibrated = sentinella::calibration::apply_calibration(&after_memory, &calibration_store);

    // Apply cross-scanner correlation unless disabled
    let results = if no_correlation {
        calibrated
    } else {
        let groups = sentinella::correlation::correlate_findings(&calibrated);
        let correlated = sentinella::correlation::apply_correlation(&calibrated, &groups);
        print_correlation_summary(&groups, &format);
        correlated
    };

    let confidence_threshold = min_confidence.as_ref().map(to_confidence);
    render_check_output(&results, &cfg, &format, confidence_threshold, show_suspect);

    print_evidence_summary(&index, &format);

    // Sync finding state: track Open/Confirmed/Fixed lifecycle
    sync_and_save_state(&dir, &results);

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

    let default_policy = sentinella::rule_lifecycle::LifecyclePolicy::default();
    let index = build_project_index_for_arch(&dir, &arch, &default_policy)?;
    let results = run_project_scanners(&cfg, &index, &dir, None)?;

    let tasks = task_decomposer::decompose(&results);

    dispatch_tasks(&tasks, &target, dry_run);
    Ok(())
}

fn handle_triage_cmd(
    config_path: Option<PathBuf>,
    dir: PathBuf,
    batch: usize,
    scanner_filter: Option<String>,
) -> Result<()> {
    let cfg = load_project_config(config_path.as_deref(), &dir)?;

    let arch = detect_architecture(&dir, &cfg.linked_repos);
    let default_policy = sentinella::rule_lifecycle::LifecyclePolicy::default();
    let index = build_project_index_for_arch(&dir, &arch, &default_policy)?;
    let results = run_project_scanners(&cfg, &index, &dir, scanner_filter.as_deref())?;

    let calibration_store = sentinella::calibration::load_calibration(&dir)
        .map_err(|e| miette::miette!("failed to load calibration: {e}"))?;
    let calibrated = sentinella::calibration::apply_calibration(&results, &calibration_store);

    sentinella::calibration::handle_triage(&dir, &calibrated, batch, scanner_filter.as_deref())
        .map_err(|e| miette::miette!("triage failed: {e}"))?;

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
    arch: &Architecture,
    lifecycle_policy: &sentinella::rule_lifecycle::LifecyclePolicy,
) -> Result<Arc<sentinella::indexer::store::IndexStore>> {
    eprintln!("{} building file index...", "info:".blue().bold());

    let roots = collect_roots_for_arch(dir, arch);
    let root_refs: Vec<&std::path::Path> = roots.iter().map(|p| p.as_path()).collect();

    let index = build_index_multi(&root_refs, lifecycle_policy)
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
    min_confidence: Option<Confidence>,
    show_suspect: bool,
) {
    matrix::render_matrix(results, cfg);

    let report_format = to_report_format(format);
    let gap_output = gap::render_gap_report(results, report_format, min_confidence, show_suspect);
    print!("{gap_output}");
}

fn print_rule_pack_summary(dir: &std::path::Path) {
    let detected_stack = sentinella::rule_pack::detect::detect_tech_stack(dir);
    if detected_stack.is_empty() {
        eprintln!("{} no tech stack detected", "verbose:".dimmed(),);
    } else {
        eprintln!(
            "{} detected tech stack: {}",
            "verbose:".dimmed(),
            detected_stack
                .iter()
                .map(|e| format!("{} ({:.0}%)", e.name, e.confidence * 100.0))
                .collect::<Vec<_>>()
                .join(", "),
        );
    }

    match sentinella::rule_pack::loader::resolve_rule_packs(dir) {
        Ok(packs) => {
            let active_packs: Vec<_> = packs
                .iter()
                .filter(|pack| {
                    detected_stack.iter().any(|entry| entry.name == pack.name)
                        || pack.name == "custom"
                })
                .collect();
            eprintln!(
                "{} loaded {} rule pack(s), {} active: {}",
                "verbose:".dimmed(),
                packs.len(),
                active_packs.len(),
                active_packs
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        }
        Err(e) => {
            eprintln!("{} failed to load rule packs: {e}", "warn:".yellow().bold(),);
        }
    }
}

fn print_evidence_summary(
    index: &Arc<sentinella::indexer::store::IndexStore>,
    format: &CliOutputFormat,
) {
    if !matches!(format, CliOutputFormat::Terminal) {
        return;
    }

    let evidence_count = index.evidence_store.len();
    if evidence_count > 0 {
        eprintln!(
            "{} evidence: {} entries from rule packs and middleware migration",
            "info:".blue().bold(),
            evidence_count,
        );
    }
}

fn sync_and_save_state(dir: &std::path::Path, results: &[sentinella::scanners::types::ScanResult]) {
    let current_ids: Vec<String> = results
        .iter()
        .flat_map(|r| r.findings.iter().map(|f| f.stable_id(dir)))
        .collect();

    let existing_state = sentinella::state::load_state(dir).unwrap_or_default();
    let new_state = sentinella::state::sync_findings(&existing_state, &current_ids, dir);

    if let Err(e) = sentinella::state::save_state(dir, &new_state) {
        eprintln!("{} failed to save state: {e}", "warn:".yellow().bold(),);
    }
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

fn handle_memory(action: MemoryAction) -> Result<()> {
    match action {
        MemoryAction::Add { text, scanner, dir } => {
            let current = sentinella::memory::load_memories(&dir)
                .map_err(|e| miette::miette!("failed to load memories: {e}"))?;
            let updated = sentinella::memory::add_memory(&current, text.clone(), scanner.clone());
            sentinella::memory::save_memories(&dir, &updated)
                .map_err(|e| miette::miette!("failed to save memories: {e}"))?;

            let scope_label = scanner.as_deref().unwrap_or("project");
            eprintln!(
                "{} added memory to scope [{}]: {}",
                "done:".green().bold(),
                scope_label.cyan(),
                text,
            );
            Ok(())
        }
        MemoryAction::List { dir } => {
            let memories = sentinella::memory::load_memories(&dir)
                .map_err(|e| miette::miette!("failed to load memories: {e}"))?;
            println!("{}", sentinella::memory::format_memories(&memories));
            Ok(())
        }
    }
}

fn print_correlation_summary(
    groups: &[sentinella::correlation::CorrelationGroup],
    format: &CliOutputFormat,
) {
    if !matches!(format, CliOutputFormat::Terminal) {
        return;
    }
    let summary = sentinella::correlation::format_correlation_summary(groups);
    if !summary.is_empty() {
        eprintln!("{} {}", "correlation:".blue().bold(), summary);
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
// Pack subcommand handlers
// ---------------------------------------------------------------------------

fn handle_pack(action: PackAction) -> Result<()> {
    match action {
        PackAction::List { dir } => handle_pack_list(&dir),
        PackAction::Validate { path } => handle_pack_validate(&path),
        PackAction::Install {
            source,
            dir,
            global,
        } => handle_pack_install(&source, &dir, global),
    }
}

fn handle_pack_list(dir: &Path) -> Result<()> {
    let packs = pack_manager::list_packs(dir);
    let output = pack_manager::format_pack_list(&packs);
    println!("{output}");
    Ok(())
}

fn handle_pack_validate(path: &Path) -> Result<()> {
    let errors = pack_manager::validate_pack(path);
    if errors.is_empty() {
        eprintln!("{} pack is valid", "ok:".green().bold());
        return Ok(());
    }
    for e in &errors {
        let tag = match e.severity {
            pack_manager::ValidationSeverity::Error => "error:".red().bold().to_string(),
            pack_manager::ValidationSeverity::Warning => "warn:".yellow().bold().to_string(),
        };
        eprintln!("{tag} [{}] {}", e.field, e.message);
    }
    let has_error = errors
        .iter()
        .any(|e| e.severity == pack_manager::ValidationSeverity::Error);
    if has_error {
        process::exit(1);
    }
    Ok(())
}

fn handle_pack_install(source: &Path, dir: &Path, global: bool) -> Result<()> {
    let scope = if global {
        pack_manager::InstallScope::User
    } else {
        pack_manager::InstallScope::Project
    };
    match pack_manager::install_pack(source, dir, scope) {
        Ok(msg) => {
            eprintln!("{} {msg}", "done:".green().bold());
            Ok(())
        }
        Err(msg) => Err(miette::miette!("{msg}")),
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
            min_confidence,
            show_suspect,
            verbose,
            experimental,
            include_deprecated,
            no_correlation,
        } => handle_check(
            cli.config,
            dir,
            scanner,
            format,
            min_coverage,
            min_confidence,
            show_suspect,
            verbose,
            experimental,
            include_deprecated,
            no_correlation,
        ),
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
        Command::Memory { action } => handle_memory(action),
        Command::Calibrate { action } => handle_calibrate(action),
        Command::Triage {
            dir,
            batch,
            scanner,
        } => handle_triage_cmd(cli.config, dir, batch, scanner),
        Command::Learn { dir, min_cluster } => handle_learn(dir, min_cluster),
        Command::Pack { action } => handle_pack(action),
    }
}

fn handle_calibrate(action: CalibrateAction) -> Result<()> {
    match action {
        CalibrateAction::Export { dir, output, name } => handle_calibrate_export(dir, output, name),
        CalibrateAction::Import { dir, input, weight } => {
            handle_calibrate_import(dir, input, weight)
        }
        CalibrateAction::Show { dir } => handle_calibrate_show(dir),
    }
}

fn handle_calibrate_export(dir: PathBuf, output: PathBuf, name: Option<String>) -> Result<()> {
    let store = sentinella::calibration::load_calibration(&dir)
        .map_err(|e| miette::miette!("failed to load calibration: {e}"))?;

    let project_name = name.unwrap_or_else(|| {
        dir.canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            .unwrap_or_else(|| "unknown".to_string())
    });

    let exported = sentinella::calibration_transfer::export_calibration(&store, &project_name);

    sentinella::calibration_transfer::save_export(&output, &exported)
        .map_err(|e| miette::miette!("failed to save export: {e}"))?;

    eprintln!(
        "{} exported {} bucket(s) to {}",
        "done:".green().bold(),
        exported.buckets.len(),
        output.display().cyan(),
    );
    Ok(())
}

fn handle_calibrate_import(dir: PathBuf, input: PathBuf, weight: Option<f64>) -> Result<()> {
    let existing = sentinella::calibration::load_calibration(&dir)
        .map_err(|e| miette::miette!("failed to load calibration: {e}"))?;

    let imported = sentinella::calibration_transfer::load_export(&input)
        .map_err(|e| miette::miette!("failed to load export file: {e}"))?;

    let merge_weight = weight.unwrap_or(0.5);
    let merged =
        sentinella::calibration_transfer::import_calibration(&existing, &imported, merge_weight);

    sentinella::calibration::save_calibration(&dir, &merged)
        .map_err(|e| miette::miette!("failed to save calibration: {e}"))?;

    eprintln!(
        "{} imported {} bucket(s) from {} (weight={:.2})",
        "done:".green().bold(),
        imported.buckets.len(),
        imported.exported_from.cyan(),
        merge_weight,
    );
    Ok(())
}

fn handle_calibrate_show(dir: PathBuf) -> Result<()> {
    let store = sentinella::calibration::load_calibration(&dir)
        .map_err(|e| miette::miette!("failed to load calibration: {e}"))?;

    println!(
        "{}",
        sentinella::calibration_transfer::format_calibration_stats(&store)
    );
    Ok(())
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

    dismissals.dismissed.push(record);

    suppress::save_dismissals(&dir, &dismissals)
        .map_err(|e| miette::miette!("failed to save dismiss file: {e}"))?;

    eprintln!("{} dismissed {}", "done:".green().bold(), finding_id.cyan(),);
    Ok(())
}

fn handle_learn(dir: PathBuf, min_cluster: usize) -> Result<()> {
    let state = sentinella::state::load_state(&dir)
        .map_err(|e| miette::miette!("failed to load state: {e}"))?;

    let fp_count = state
        .findings
        .values()
        .filter(|r| r.status == sentinella::state::FindingStatus::FalsePositive)
        .count();

    eprintln!(
        "{} analyzing {} false-positive findings (min cluster: {})",
        "info:".blue().bold(),
        fp_count,
        min_cluster,
    );

    let result = sentinella::pattern_miner::mine_patterns(&state, min_cluster);
    let output = sentinella::pattern_miner::format_suggestions(&result);
    println!("{output}");

    Ok(())
}
