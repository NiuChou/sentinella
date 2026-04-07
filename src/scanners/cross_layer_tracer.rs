use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::config::ModuleConfig;
use crate::indexer::types::ImportEdge;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S2";
const SCANNER_NAME: &str = "Cross-Layer Tracer";
const SCANNER_DESC: &str =
    "Trace cross-layer coverage across configured layers (default: backend, bff, hooks, page)";

const DEFAULT_LAYERS: [&str; 4] = ["backend", "bff", "hooks", "page"];

pub struct CrossLayerTracer;

impl Scanner for CrossLayerTracer {
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
        let required_layers = resolve_required_layers(ctx);
        let layer_count_required = required_layers.len();
        let modules = resolve_modules(ctx);

        if modules.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: vec![],
                score: 100,
                summary: "No modules found to trace".to_string(),
            };
        }

        let all_imports = ctx.index.all_imports();
        let import_targets = build_import_target_set(&all_imports);
        let explicitly_configured = !ctx.config.modules.is_empty();

        let mut findings = Vec::new();
        let mut fully_connected: u32 = 0;
        let total = modules.len() as u32;
        let mut module_layer_map: Vec<(String, HashSet<String>)> = Vec::new();

        for module in &modules {
            let layers_present = detect_present_layers(
                module,
                ctx,
                &import_targets,
                &required_layers,
                explicitly_configured,
            );
            let present_count = layers_present.len();

            module_layer_map.push((module.name.clone(), layers_present.clone()));

            if present_count == layer_count_required {
                fully_connected += 1;
            } else {
                let missing: Vec<&str> = required_layers
                    .iter()
                    .filter(|l| !layers_present.contains(l.as_str()))
                    .map(|l| l.as_str())
                    .collect();

                let severity = if present_count <= layer_count_required / 2 {
                    Severity::Critical
                } else {
                    Severity::Warning
                };

                let finding = Finding::new(
                    SCANNER_ID,
                    severity,
                    format!(
                        "Module '{}' has {}/{} layers. Missing: {}",
                        module.name,
                        present_count,
                        layer_count_required,
                        missing.join(", ")
                    ),
                )
                .with_suggestion(format!(
                    "Add the missing layer(s) ({}) for module '{}'",
                    missing.join(", "),
                    module.name
                ));

                findings.push(finding);
            }
        }

        let score = if total == 0 {
            100
        } else {
            ((fully_connected as f64 / total as f64) * 100.0).round() as u8
        };

        let matrix = build_layer_matrix(&module_layer_map, &required_layers);
        let summary = format!(
            "{}/{} modules fully connected across all layers\n\n{}",
            fully_connected, total, matrix
        );

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary,
        }
    }
}

/// Resolve which layers are required. Falls back to default 4 layers when
/// the config field is empty.
fn resolve_required_layers(ctx: &ScanContext) -> Vec<String> {
    let configured = &ctx.config.required_layers;
    if configured.is_empty() {
        DEFAULT_LAYERS.iter().map(|s| (*s).to_string()).collect()
    } else {
        configured.clone()
    }
}

#[derive(Debug)]
struct ModuleInfo {
    name: String,
    backend: Option<String>,
    bff: Option<String>,
    hooks: Option<String>,
    page: Option<String>,
}

impl ModuleInfo {
    /// Retrieve the configured pattern for a given layer name.
    fn layer_pattern(&self, layer: &str) -> Option<&str> {
        match layer {
            "backend" => self.backend.as_deref(),
            "bff" => self.bff.as_deref(),
            "hooks" => self.hooks.as_deref(),
            "page" => self.page.as_deref(),
            _ => None,
        }
    }
}

fn resolve_modules(ctx: &ScanContext) -> Vec<ModuleInfo> {
    if !ctx.config.modules.is_empty() {
        return ctx.config.modules.iter().map(module_from_config).collect();
    }

    auto_discover_modules(ctx)
}

fn module_from_config(mc: &ModuleConfig) -> ModuleInfo {
    ModuleInfo {
        name: mc.name.clone(),
        backend: mc.backend.clone(),
        bff: mc.bff.clone(),
        hooks: mc.hooks.clone(),
        page: mc.page.clone(),
    }
}

fn auto_discover_modules(ctx: &ScanContext) -> Vec<ModuleInfo> {
    let mut module_layers: HashMap<String, HashMap<&str, PathBuf>> = HashMap::new();

    for entry in ctx.index.files.iter() {
        let path = entry.key();
        let file_name = match path.file_name().and_then(|f| f.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };

        if let Some((module_name, layer)) = extract_module_from_filename(&file_name, path) {
            module_layers
                .entry(module_name)
                .or_default()
                .insert(layer, path.clone());
        }
    }

    module_layers
        .into_iter()
        .map(|(name, layers)| ModuleInfo {
            name,
            backend: layers
                .get("backend")
                .map(|p| p.to_string_lossy().to_string()),
            bff: layers.get("bff").map(|p| p.to_string_lossy().to_string()),
            hooks: layers.get("hooks").map(|p| p.to_string_lossy().to_string()),
            page: layers.get("page").map(|p| p.to_string_lossy().to_string()),
        })
        .collect()
}

fn extract_module_from_filename<'a>(
    file_name: &str,
    path: &std::path::Path,
) -> Option<(String, &'a str)> {
    let lower = file_name.to_lowercase();

    // Pattern: crm.controller.ts / crm.service.ts -> backend layer
    if lower.ends_with(".controller.ts")
        || lower.ends_with(".controller.js")
        || lower.ends_with(".service.ts")
        || lower.ends_with(".service.js")
    {
        let module_name = lower.split('.').next()?;
        return Some((module_name.to_string(), "backend"));
    }

    // Pattern: crm.mapper.ts / crm.router.ts -> bff layer
    if lower.ends_with(".mapper.ts")
        || lower.ends_with(".mapper.js")
        || lower.ends_with(".router.ts")
        || lower.ends_with(".router.js")
    {
        let module_name = lower.split('.').next()?;
        return Some((module_name.to_string(), "bff"));
    }

    // Pattern: use-crm.ts -> hooks layer
    if lower.starts_with("use-") && (lower.ends_with(".ts") || lower.ends_with(".tsx")) {
        let without_prefix = lower.strip_prefix("use-")?;
        let module_name = without_prefix.split('.').next()?;
        return Some((module_name.to_string(), "hooks"));
    }

    // Pattern: crm/page.tsx -> page layer
    if lower == "page.tsx" || lower == "page.ts" || lower == "page.jsx" || lower == "page.js" {
        let parent_name = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|f| f.to_str())?;
        return Some((parent_name.to_lowercase(), "page"));
    }

    None
}

/// Build a text table showing which layers each module has.
///
/// Columns are dynamically generated from the required layers list.
fn build_layer_matrix(
    module_layers: &[(String, HashSet<String>)],
    required_layers: &[String],
) -> String {
    if module_layers.is_empty() {
        return String::from("(no modules)");
    }

    let max_name_len = module_layers
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(6)
        .max(6); // minimum "Module" header width

    // Build dynamic header
    let layer_headers: Vec<String> = required_layers.iter().map(|l| format!(" {} ", l)).collect();
    let header = format!(
        "{:<width$} |{}",
        "Module",
        layer_headers.join("|"),
        width = max_name_len
    );

    // Build dynamic separator
    let layer_seps: Vec<String> = required_layers
        .iter()
        .map(|l| "-".repeat(l.len() + 2))
        .collect();
    let separator = format!(
        "{:-<width$}-|{}",
        "",
        layer_seps.join("|"),
        width = max_name_len
    );

    let mut rows = Vec::with_capacity(module_layers.len());
    for (name, layers) in module_layers {
        let layer_cells: Vec<String> = required_layers
            .iter()
            .map(|l| {
                let pad = l.len() + 2;
                let marker = if layers.contains(l) { "x" } else { " " };
                format!("{:^width$}", marker, width = pad)
            })
            .collect();
        let row = format!(
            "{:<width$} |{}",
            name,
            layer_cells.join("|"),
            width = max_name_len
        );
        rows.push(row);
    }

    format!("{}\n{}\n{}", header, separator, rows.join("\n"))
}

fn build_import_target_set(imports: &[ImportEdge]) -> HashSet<String> {
    imports
        .iter()
        .map(|edge| edge.target_module.to_lowercase())
        .collect()
}

fn detect_present_layers(
    module: &ModuleInfo,
    ctx: &ScanContext,
    import_targets: &HashSet<String>,
    required_layers: &[String],
    explicitly_configured: bool,
) -> HashSet<String> {
    let mut present = HashSet::new();

    for layer_name in required_layers {
        if let Some(pat) = module.layer_pattern(layer_name) {
            if explicitly_configured {
                // Explicitly configured modules: skip import connectivity check.
                // Cross-language projects (e.g. Python backend + TS frontend) communicate
                // via HTTP, not imports, so import graph connectivity is meaningless.
                if file_exists_in_store(ctx, pat) {
                    present.insert(layer_name.to_string());
                }
            } else if file_exists_in_store(ctx, pat)
                && has_import_connectivity(pat, ctx, import_targets)
            {
                present.insert(layer_name.to_string());
            }
        }
    }

    present
}

fn file_exists_in_store(ctx: &ScanContext, pattern: &str) -> bool {
    let pattern_lower = pattern.to_lowercase();

    // Primary: check the index store
    let in_store = ctx.index.files.iter().any(|entry| {
        let path_str = entry.key().to_string_lossy().to_lowercase();
        path_str.contains(&pattern_lower)
    });

    if in_store {
        return true;
    }

    // Fallback: check filesystem directly.
    // This handles languages without parsers (e.g., Rust, Elixir)
    // whose files are never indexed into the store.
    let root = ctx.root_dir;
    let candidates = [
        root.join(pattern),
        root.join(format!("apps/{pattern}")),
        root.join(format!("packages/{pattern}")),
        root.join(format!("services/{pattern}")),
    ];

    candidates.iter().any(|path| path.exists())
}

fn has_import_connectivity(
    pattern: &str,
    ctx: &ScanContext,
    import_targets: &HashSet<String>,
) -> bool {
    let pattern_lower = pattern.to_lowercase();

    // Check if any file imports this module pattern
    let is_imported = import_targets
        .iter()
        .any(|target| target.contains(&pattern_lower));

    if is_imported {
        return true;
    }

    // Check if the file matching this pattern imports anything
    for entry in ctx.index.imports.iter() {
        let source_str = entry.key().to_string_lossy().to_lowercase();
        if source_str.contains(&pattern_lower) && !entry.value().is_empty() {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_controller() {
        let path = std::path::Path::new("src/crm.controller.ts");
        let result = extract_module_from_filename("crm.controller.ts", path);
        assert_eq!(result, Some(("crm".to_string(), "backend")));
    }

    #[test]
    fn test_extract_hook() {
        let path = std::path::Path::new("src/use-crm.ts");
        let result = extract_module_from_filename("use-crm.ts", path);
        assert_eq!(result, Some(("crm".to_string(), "hooks")));
    }

    #[test]
    fn test_extract_page() {
        let path = std::path::Path::new("src/crm/page.tsx");
        let result = extract_module_from_filename("page.tsx", path);
        assert_eq!(result, Some(("crm".to_string(), "page")));
    }

    #[test]
    fn test_extract_mapper() {
        let path = std::path::Path::new("src/crm.mapper.ts");
        let result = extract_module_from_filename("crm.mapper.ts", path);
        assert_eq!(result, Some(("crm".to_string(), "bff")));
    }

    #[test]
    fn test_extract_unrecognized() {
        let path = std::path::Path::new("src/utils.ts");
        let result = extract_module_from_filename("utils.ts", path);
        assert_eq!(result, None);
    }

    #[test]
    fn test_file_exists_fallback() {
        use crate::indexer::store::IndexStore;
        use crate::indexer::types::{FileInfo, Language};

        let store = IndexStore::new();
        let config = test_config();

        // Use a temp directory so we control what exists on disk
        let tmp = std::env::temp_dir().join("sentinella_test_fallback");
        let nested = tmp.join("apps").join("hive-engine").join("src");
        std::fs::create_dir_all(&nested).expect("create temp dirs");

        let ctx = ScanContext {
            config: &config,
            index: &store,
            root_dir: tmp.as_path(),
        };

        // Pattern not in store, but exists on filesystem via apps/ prefix
        assert!(
            file_exists_in_store(&ctx, "hive-engine/src"),
            "should find via filesystem fallback with apps/ prefix"
        );

        // Pattern that does not exist anywhere
        assert!(
            !file_exists_in_store(&ctx, "nonexistent-service/lib"),
            "should return false when pattern is nowhere"
        );

        // Store hit takes priority: insert a fake file into the index
        store.files.insert(
            PathBuf::from("some/path/billing/api"),
            FileInfo {
                path: PathBuf::from("some/path/billing/api"),
                language: Language::Unknown,
                lines: 0,
                hash: 0,
            },
        );
        assert!(
            file_exists_in_store(&ctx, "billing/api"),
            "should find via index store (primary path)"
        );

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_resolve_required_layers_uses_default_when_empty() {
        let layers = resolve_required_layers_from_config(&[]);
        assert_eq!(layers, vec!["backend", "bff", "hooks", "page"]);
    }

    #[test]
    fn test_resolve_required_layers_uses_configured() {
        let configured = vec![
            "backend".to_string(),
            "hooks".to_string(),
            "page".to_string(),
        ];
        let layers = resolve_required_layers_from_config(&configured);
        assert_eq!(layers, vec!["backend", "hooks", "page"]);
    }

    #[test]
    fn test_build_layer_matrix_dynamic_layers() {
        let required = vec!["backend".to_string(), "page".to_string()];
        let mut layers = HashSet::new();
        layers.insert("backend".to_string());
        let module_layers = vec![("crm".to_string(), layers)];
        let matrix = build_layer_matrix(&module_layers, &required);
        assert!(matrix.contains("backend"));
        assert!(matrix.contains("page"));
        assert!(!matrix.contains("bff"));
    }

    /// Test helper that mirrors `resolve_required_layers` without needing a ScanContext.
    fn resolve_required_layers_from_config(configured: &[String]) -> Vec<String> {
        if configured.is_empty() {
            DEFAULT_LAYERS.iter().map(|s| (*s).to_string()).collect()
        } else {
            configured.to_vec()
        }
    }

    fn test_config() -> crate::config::Config {
        crate::config::Config {
            version: "1.0".into(),
            project: "test".into(),
            r#type: Default::default(),
            layers: Default::default(),
            modules: Default::default(),
            flows: Default::default(),
            deploy: Default::default(),
            integration_tests: Default::default(),
            events: Default::default(),
            env: Default::default(),
            output: Default::default(),
            dispatch: Default::default(),
            data_isolation: Default::default(),
            required_layers: vec![
                "backend".into(),
                "bff".into(),
                "hooks".into(),
                "page".into(),
            ],
            linked_repos: Vec::new(),
            suppress: None,
        }
    }
}
