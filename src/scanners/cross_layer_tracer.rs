use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::config::ModuleConfig;
use crate::indexer::types::ImportEdge;

use super::types::{Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S2";
const SCANNER_NAME: &str = "Cross-Layer Tracer";
const SCANNER_DESC: &str =
    "Trace cross-layer coverage across backend, BFF, hooks, and page layers";

const LAYER_NAMES: [&str; 4] = ["backend", "bff", "hooks", "page"];

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

        let mut findings = Vec::new();
        let mut fully_connected: u32 = 0;
        let total = modules.len() as u32;
        let mut module_layer_map: Vec<(String, HashSet<String>)> = Vec::new();

        for module in &modules {
            let layers_present = detect_present_layers(module, ctx, &import_targets);
            let layer_count = layers_present.len();

            module_layer_map.push((module.name.clone(), layers_present.clone()));

            if layer_count == 4 {
                fully_connected += 1;
            } else {
                let missing: Vec<&str> = LAYER_NAMES
                    .iter()
                    .filter(|l| !layers_present.contains(**l))
                    .copied()
                    .collect();

                let severity = if layer_count <= 2 {
                    Severity::Critical
                } else {
                    Severity::Warning
                };

                let finding = Finding::new(
                    SCANNER_ID,
                    severity,
                    format!(
                        "Module '{}' has {}/4 layers. Missing: {}",
                        module.name,
                        layer_count,
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

        let matrix = build_layer_matrix(&module_layer_map);
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

#[derive(Debug)]
struct ModuleInfo {
    name: String,
    backend: Option<String>,
    bff: Option<String>,
    hooks: Option<String>,
    page: Option<String>,
}

fn resolve_modules(ctx: &ScanContext) -> Vec<ModuleInfo> {
    if !ctx.config.modules.is_empty() {
        return ctx
            .config
            .modules
            .iter()
            .map(module_from_config)
            .collect();
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
            hooks: layers
                .get("hooks")
                .map(|p| p.to_string_lossy().to_string()),
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
/// Example output:
/// ```text
/// Module     | backend | bff | hooks | page
/// -----------|---------|-----|-------|-----
/// crm        |    x    |  x  |   x   |  x
/// billing    |    x    |     |   x   |
/// ```
fn build_layer_matrix(module_layers: &[(String, HashSet<String>)]) -> String {
    if module_layers.is_empty() {
        return String::from("(no modules)");
    }

    let max_name_len = module_layers
        .iter()
        .map(|(name, _)| name.len())
        .max()
        .unwrap_or(6)
        .max(6); // minimum "Module" header width

    let header = format!(
        "{:<width$} | backend | bff | hooks | page",
        "Module",
        width = max_name_len
    );
    let separator = format!(
        "{:-<width$}-|---------|-----|-------|-----",
        "",
        width = max_name_len
    );

    let mut rows = Vec::with_capacity(module_layers.len());
    for (name, layers) in module_layers {
        let row = format!(
            "{:<width$} |    {}    |  {}  |   {}   |  {}",
            name,
            if layers.contains("backend") { "x" } else { " " },
            if layers.contains("bff") { "x" } else { " " },
            if layers.contains("hooks") { "x" } else { " " },
            if layers.contains("page") { "x" } else { " " },
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
) -> HashSet<String> {
    let mut present = HashSet::new();

    let layer_patterns: [(&str, &Option<String>); 4] = [
        ("backend", &module.backend),
        ("bff", &module.bff),
        ("hooks", &module.hooks),
        ("page", &module.page),
    ];

    for (layer_name, pattern) in &layer_patterns {
        if let Some(pat) = pattern {
            if file_exists_in_store(ctx, pat) && has_import_connectivity(pat, ctx, import_targets) {
                present.insert(layer_name.to_string());
            }
        }
    }

    present
}

fn file_exists_in_store(ctx: &ScanContext, pattern: &str) -> bool {
    let pattern_lower = pattern.to_lowercase();
    ctx.index.files.iter().any(|entry| {
        let path_str = entry.key().to_string_lossy().to_lowercase();
        path_str.contains(&pattern_lower)
    })
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
}
