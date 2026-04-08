use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::types::{Confidence, Finding, ScanContext, ScanResult, Scanner, Severity};

const SCANNER_ID: &str = "S28";

// ===========================================================================
// Public scanner
// ===========================================================================

pub struct DocFactDrift;

impl Scanner for DocFactDrift {
    fn id(&self) -> &str {
        SCANNER_ID
    }

    fn name(&self) -> &str {
        "Doc Fact Drift"
    }

    fn description(&self) -> &str {
        "Detects drift between facts extracted from config/manifest files and claims in README"
    }

    fn scan(&self, ctx: &ScanContext) -> ScanResult {
        let root = ctx.root_dir;

        let facts = extract_all_facts(root);
        if facts.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No config sources found for fact extraction".to_string(),
            };
        }

        let doc_files = discover_doc_files(root);
        if doc_files.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "No README/doc files found to check".to_string(),
            };
        }

        let mut all_claims = Vec::new();
        for doc_path in &doc_files {
            if let Ok(content) = std::fs::read_to_string(doc_path) {
                let claims = parse_doc_claims(&content, doc_path);
                all_claims.extend(claims);
            }
        }

        if all_claims.is_empty() {
            return ScanResult {
                scanner: SCANNER_ID.to_string(),
                findings: Vec::new(),
                score: 100,
                summary: "README contains no verifiable claims".to_string(),
            };
        }

        let drifts = detect_drifts(&facts, &all_claims);

        let findings: Vec<Finding> = drifts
            .iter()
            .map(|d| {
                Finding::new(SCANNER_ID, d.severity, d.message.clone())
                    .with_file(d.doc_file.clone())
                    .with_line(d.doc_line)
                    .with_confidence(d.confidence)
                    .with_suggestion(d.suggestion.clone())
            })
            .collect();

        let total_claims = all_claims.len();
        let drift_count = findings.len();
        let score = if total_claims == 0 {
            100
        } else {
            let ratio = 1.0 - (drift_count as f64 / total_claims as f64);
            (ratio.clamp(0.0, 1.0) * 100.0) as u8
        };

        ScanResult {
            scanner: SCANNER_ID.to_string(),
            findings,
            score,
            summary: format!(
                "{drift_count} drift(s) found across {total_claims} verifiable claim(s)"
            ),
        }
    }
}

// ===========================================================================
// Fact — a verifiable datum extracted from a config/manifest source
// ===========================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct Fact {
    pub category: FactCategory,
    pub key: String,
    pub value: String,
    pub source_file: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FactCategory {
    Port,
    Dependency,
    GoModule,
    PythonVersion,
    NodeVersion,
    ServiceName,
    DockerBaseImage,
    EnvVar,
    K8sReplica,
    K8sImage,
    K8sResourceLimit,
    RustEdition,
    License,
    Version,
}

impl FactCategory {
    fn label(self) -> &'static str {
        match self {
            Self::Port => "port",
            Self::Dependency => "dependency",
            Self::GoModule => "Go module",
            Self::PythonVersion => "Python version",
            Self::NodeVersion => "Node version",
            Self::ServiceName => "service name",
            Self::DockerBaseImage => "Docker base image",
            Self::EnvVar => "environment variable",
            Self::K8sReplica => "K8s replicas",
            Self::K8sImage => "K8s image",
            Self::K8sResourceLimit => "K8s resource limit",
            Self::RustEdition => "Rust edition",
            Self::License => "license",
            Self::Version => "version",
        }
    }
}

// ===========================================================================
// DocClaim — a verifiable statement found in documentation
// ===========================================================================

#[derive(Debug, Clone)]
pub struct DocClaim {
    pub category: FactCategory,
    pub key: String,
    pub claimed_value: String,
    pub file: PathBuf,
    pub line: usize,
    pub raw_text: String,
}

// ===========================================================================
// Drift — a mismatch between a fact and a claim
// ===========================================================================

#[derive(Debug, Clone)]
pub struct Drift {
    pub message: String,
    pub suggestion: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub doc_file: PathBuf,
    pub doc_line: usize,
}

// ===========================================================================
// 1. FactExtractor — pluggable multi-source fact extraction
// ===========================================================================

pub fn extract_all_facts(root: &Path) -> Vec<Fact> {
    let extractors: Vec<(&str, fn(&Path) -> Vec<Fact>)> = vec![
        ("Cargo.toml", extract_cargo_toml),
        ("go.mod", extract_go_mod),
        ("go.work", extract_go_work),
        ("package.json", extract_package_json),
        ("pyproject.toml", extract_pyproject_toml),
        ("requirements.txt", extract_requirements_txt),
        ("Dockerfile", extract_dockerfile),
        ("docker-compose.yml", extract_docker_compose),
        ("docker-compose.yaml", extract_docker_compose),
    ];

    let mut facts = Vec::new();

    for (filename, extractor) in &extractors {
        let path = root.join(filename);
        if path.exists() {
            facts.extend(extractor(&path));
        }
    }

    // Glob-based extractors (K8s manifests, config files)
    facts.extend(extract_k8s_manifests(root));
    facts.extend(extract_config_yamls(root));

    facts
}

// ---------------------------------------------------------------------------
// Cargo.toml
// ---------------------------------------------------------------------------

fn extract_cargo_toml(path: &Path) -> Vec<Fact> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut facts = Vec::new();
    let file = path.to_path_buf();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("version") && trimmed.contains('=') {
            if let Some(val) = extract_toml_string_value(trimmed) {
                facts.push(Fact {
                    category: FactCategory::Version,
                    key: "version".into(),
                    value: val,
                    source_file: file.clone(),
                });
            }
        }
        if trimmed.starts_with("edition") && trimmed.contains('=') {
            if let Some(val) = extract_toml_string_value(trimmed) {
                facts.push(Fact {
                    category: FactCategory::RustEdition,
                    key: "rust-edition".into(),
                    value: val,
                    source_file: file.clone(),
                });
            }
        }
        if trimmed.starts_with("license") && trimmed.contains('=') {
            if let Some(val) = extract_toml_string_value(trimmed) {
                facts.push(Fact {
                    category: FactCategory::License,
                    key: "license".into(),
                    value: val,
                    source_file: file.clone(),
                });
            }
        }
    }

    // dependencies section
    let dep_re = regex::Regex::new(r#"^(\w[\w-]*)\s*=\s*"([^"]+)""#).unwrap();
    let dep_table_re =
        regex::Regex::new(r#"^(\w[\w-]*)\s*=\s*\{.*version\s*=\s*"([^"]+)".*\}"#).unwrap();
    let mut in_deps = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("[dependencies") || trimmed.starts_with("[dev-dependencies") {
            in_deps = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_deps = false;
            continue;
        }
        if in_deps {
            if let Some(caps) = dep_re.captures(trimmed) {
                facts.push(Fact {
                    category: FactCategory::Dependency,
                    key: caps[1].to_string(),
                    value: caps[2].to_string(),
                    source_file: file.clone(),
                });
            } else if let Some(caps) = dep_table_re.captures(trimmed) {
                facts.push(Fact {
                    category: FactCategory::Dependency,
                    key: caps[1].to_string(),
                    value: caps[2].to_string(),
                    source_file: file.clone(),
                });
            }
        }
    }

    facts
}

// ---------------------------------------------------------------------------
// go.mod
// ---------------------------------------------------------------------------

fn extract_go_mod(path: &Path) -> Vec<Fact> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut facts = Vec::new();
    let file = path.to_path_buf();

    // module path
    if let Some(line) = content.lines().find(|l| l.starts_with("module ")) {
        let module_name = line.trim_start_matches("module ").trim();
        facts.push(Fact {
            category: FactCategory::GoModule,
            key: "module".into(),
            value: module_name.into(),
            source_file: file.clone(),
        });
    }

    // go version
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("go ") && !trimmed.contains("module") {
            let ver = trimmed.trim_start_matches("go ").trim();
            facts.push(Fact {
                category: FactCategory::Version,
                key: "go".into(),
                value: ver.into(),
                source_file: file.clone(),
            });
        }
    }

    // require block dependencies
    let require_re = regex::Regex::new(r"^\s+(\S+)\s+(v\S+)").unwrap();
    let mut in_require = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "require (" {
            in_require = true;
            continue;
        }
        if trimmed == ")" {
            in_require = false;
            continue;
        }
        if in_require {
            if let Some(caps) = require_re.captures(line) {
                facts.push(Fact {
                    category: FactCategory::Dependency,
                    key: caps[1].to_string(),
                    value: caps[2].to_string(),
                    source_file: file.clone(),
                });
            }
        }
    }

    facts
}

// ---------------------------------------------------------------------------
// go.work
// ---------------------------------------------------------------------------

fn extract_go_work(path: &Path) -> Vec<Fact> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut facts = Vec::new();
    let file = path.to_path_buf();

    let mut modules = Vec::new();
    let mut in_use = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "use (" {
            in_use = true;
            continue;
        }
        if trimmed == ")" {
            in_use = false;
            continue;
        }
        if in_use && !trimmed.is_empty() {
            modules.push(trimmed.trim_start_matches("./").to_string());
        }
    }

    facts.push(Fact {
        category: FactCategory::GoModule,
        key: "workspace-module-count".into(),
        value: modules.len().to_string(),
        source_file: file.clone(),
    });

    for m in &modules {
        facts.push(Fact {
            category: FactCategory::GoModule,
            key: format!("workspace-module:{m}"),
            value: m.clone(),
            source_file: file.clone(),
        });
    }

    facts
}

// ---------------------------------------------------------------------------
// package.json
// ---------------------------------------------------------------------------

fn extract_package_json(path: &Path) -> Vec<Fact> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut facts = Vec::new();
    let file = path.to_path_buf();

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    if let Some(ver) = json.get("version").and_then(|v| v.as_str()) {
        facts.push(Fact {
            category: FactCategory::Version,
            key: "version".into(),
            value: ver.into(),
            source_file: file.clone(),
        });
    }

    if let Some(license) = json.get("license").and_then(|v| v.as_str()) {
        facts.push(Fact {
            category: FactCategory::License,
            key: "license".into(),
            value: license.into(),
            source_file: file.clone(),
        });
    }

    if let Some(engines) = json.get("engines").and_then(|v| v.as_object()) {
        if let Some(node) = engines.get("node").and_then(|v| v.as_str()) {
            facts.push(Fact {
                category: FactCategory::NodeVersion,
                key: "node".into(),
                value: node.into(),
                source_file: file.clone(),
            });
        }
    }

    // Collect key dependencies
    for section in ["dependencies", "devDependencies"] {
        if let Some(deps) = json.get(section).and_then(|v| v.as_object()) {
            for (name, ver) in deps {
                if let Some(v) = ver.as_str() {
                    facts.push(Fact {
                        category: FactCategory::Dependency,
                        key: name.clone(),
                        value: v.into(),
                        source_file: file.clone(),
                    });
                }
            }
        }
    }

    facts
}

// ---------------------------------------------------------------------------
// pyproject.toml
// ---------------------------------------------------------------------------

fn extract_pyproject_toml(path: &Path) -> Vec<Fact> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut facts = Vec::new();
    let file = path.to_path_buf();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("requires-python") {
            if let Some(val) = extract_toml_string_value(trimmed) {
                facts.push(Fact {
                    category: FactCategory::PythonVersion,
                    key: "python".into(),
                    value: val,
                    source_file: file.clone(),
                });
            }
        }
        if trimmed.starts_with("version") && trimmed.contains('=') {
            if let Some(val) = extract_toml_string_value(trimmed) {
                facts.push(Fact {
                    category: FactCategory::Version,
                    key: "version".into(),
                    value: val,
                    source_file: file.clone(),
                });
            }
        }
        if trimmed.starts_with("license") && trimmed.contains('=') {
            if let Some(val) = extract_toml_string_value(trimmed) {
                facts.push(Fact {
                    category: FactCategory::License,
                    key: "license".into(),
                    value: val,
                    source_file: file.clone(),
                });
            }
        }
    }

    facts
}

// ---------------------------------------------------------------------------
// requirements.txt
// ---------------------------------------------------------------------------

fn extract_requirements_txt(path: &Path) -> Vec<Fact> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut facts = Vec::new();
    let file = path.to_path_buf();

    let re = regex::Regex::new(r"^([A-Za-z0-9_-]+)\s*([=<>!~]+.+)?$").unwrap();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
            continue;
        }
        if let Some(caps) = re.captures(trimmed) {
            let name = caps[1].to_string();
            let ver = caps
                .get(2)
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
            facts.push(Fact {
                category: FactCategory::Dependency,
                key: name,
                value: ver,
                source_file: file.clone(),
            });
        }
    }

    facts
}

// ---------------------------------------------------------------------------
// Dockerfile
// ---------------------------------------------------------------------------

fn extract_dockerfile(path: &Path) -> Vec<Fact> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut facts = Vec::new();
    let file = path.to_path_buf();

    for line in content.lines() {
        let trimmed = line.trim();
        let upper = trimmed.to_uppercase();
        if upper.starts_with("FROM ") {
            let image = trimmed[5..].trim().split_whitespace().next().unwrap_or("");
            facts.push(Fact {
                category: FactCategory::DockerBaseImage,
                key: "base-image".into(),
                value: image.to_string(),
                source_file: file.clone(),
            });
        }
        if upper.starts_with("EXPOSE ") {
            for port in trimmed[7..].split_whitespace() {
                let port_num = port.split('/').next().unwrap_or(port);
                facts.push(Fact {
                    category: FactCategory::Port,
                    key: format!("docker-port:{port_num}"),
                    value: port_num.to_string(),
                    source_file: file.clone(),
                });
            }
        }
    }

    facts
}

// ---------------------------------------------------------------------------
// docker-compose.yml
// ---------------------------------------------------------------------------

fn extract_docker_compose(path: &Path) -> Vec<Fact> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut facts = Vec::new();
    let file = path.to_path_buf();

    // Lightweight line-based parsing (avoids full YAML dep for a scanner)
    let port_re = regex::Regex::new(r#"^\s*-\s*"?(\d+):(\d+)"?"#).unwrap();
    let image_re = regex::Regex::new(r"^\s*image:\s*(.+)$").unwrap();
    let svc_re = regex::Regex::new(r"^  (\w[\w_-]*):\s*$").unwrap();
    let mut current_service = String::new();

    for line in content.lines() {
        if let Some(caps) = svc_re.captures(line) {
            current_service = caps[1].to_string();
        }
        if let Some(caps) = port_re.captures(line) {
            let host_port = &caps[1];
            facts.push(Fact {
                category: FactCategory::Port,
                key: format!("compose-port:{current_service}"),
                value: host_port.to_string(),
                source_file: file.clone(),
            });
        }
        if let Some(caps) = image_re.captures(line) {
            let image = caps[1].trim().trim_matches('"').trim_matches('\'');
            facts.push(Fact {
                category: FactCategory::DockerBaseImage,
                key: format!("compose-image:{current_service}"),
                value: image.to_string(),
                source_file: file.clone(),
            });
        }
    }

    facts
}

// ---------------------------------------------------------------------------
// K8s manifests (deployment, service, etc.)
// ---------------------------------------------------------------------------

fn extract_k8s_manifests(root: &Path) -> Vec<Fact> {
    let mut facts = Vec::new();
    let k8s_dirs = ["k8s", "kubernetes", "deploy", "manifests", "helm", ".k8s"];

    for dir_name in &k8s_dirs {
        let dir = root.join(dir_name);
        if !dir.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if is_yaml_file(&path) {
                    facts.extend(extract_k8s_yaml(&path));
                }
            }
        }
    }

    facts
}

fn extract_k8s_yaml(path: &Path) -> Vec<Fact> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut facts = Vec::new();
    let file = path.to_path_buf();

    let replica_re = regex::Regex::new(r"^\s*replicas:\s*(\d+)").unwrap();
    let image_re = regex::Regex::new(r"^\s*-?\s*image:\s*(.+)$").unwrap();
    let port_re = regex::Regex::new(r"^\s*-?\s*(?:containerPort|port|targetPort):\s*(\d+)").unwrap();
    let cpu_re = regex::Regex::new(r#"^\s*cpu:\s*"?(\S+)"?"#).unwrap();
    let mem_re = regex::Regex::new(r#"^\s*memory:\s*"?(\S+)"?"#).unwrap();

    for line in content.lines() {
        if let Some(caps) = replica_re.captures(line) {
            facts.push(Fact {
                category: FactCategory::K8sReplica,
                key: "replicas".into(),
                value: caps[1].to_string(),
                source_file: file.clone(),
            });
        }
        if let Some(caps) = image_re.captures(line) {
            let image = caps[1].trim().trim_matches('"').trim_matches('\'');
            if image.contains('/') || image.contains(':') {
                facts.push(Fact {
                    category: FactCategory::K8sImage,
                    key: "k8s-image".into(),
                    value: image.to_string(),
                    source_file: file.clone(),
                });
            }
        }
        if let Some(caps) = port_re.captures(line) {
            facts.push(Fact {
                category: FactCategory::Port,
                key: format!("k8s-port:{}", &caps[1]),
                value: caps[1].to_string(),
                source_file: file.clone(),
            });
        }
        if let Some(caps) = cpu_re.captures(line) {
            facts.push(Fact {
                category: FactCategory::K8sResourceLimit,
                key: "cpu".into(),
                value: caps[1].to_string(),
                source_file: file.clone(),
            });
        }
        if let Some(caps) = mem_re.captures(line) {
            facts.push(Fact {
                category: FactCategory::K8sResourceLimit,
                key: "memory".into(),
                value: caps[1].to_string(),
                source_file: file.clone(),
            });
        }
    }

    facts
}

// ---------------------------------------------------------------------------
// Generic config.yaml / config.yml (port, service name, env vars)
// ---------------------------------------------------------------------------

fn extract_config_yamls(root: &Path) -> Vec<Fact> {
    let mut facts = Vec::new();
    let config_names = [
        "config.yaml",
        "config.yml",
        "app.yaml",
        "app.yml",
        "application.yml",
        "application.yaml",
    ];

    for name in &config_names {
        let path = root.join(name);
        if path.exists() {
            facts.extend(extract_generic_config(&path));
        }
    }

    facts
}

fn extract_generic_config(path: &Path) -> Vec<Fact> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut facts = Vec::new();
    let file = path.to_path_buf();

    let port_re = regex::Regex::new(r"(?i)^\s*port:\s*(\d+)").unwrap();
    let svc_re = regex::Regex::new(r"(?i)^\s*(?:name|service[_-]?name):\s*(\S+)").unwrap();

    for line in content.lines() {
        if let Some(caps) = port_re.captures(line) {
            facts.push(Fact {
                category: FactCategory::Port,
                key: "config-port".into(),
                value: caps[1].to_string(),
                source_file: file.clone(),
            });
        }
        if let Some(caps) = svc_re.captures(line) {
            let val = caps[1].trim().trim_matches('"').trim_matches('\'');
            facts.push(Fact {
                category: FactCategory::ServiceName,
                key: "service-name".into(),
                value: val.to_string(),
                source_file: file.clone(),
            });
        }
    }

    facts
}

// ===========================================================================
// 2. DocClaimParser — extract verifiable claims from README/docs
// ===========================================================================

fn discover_doc_files(root: &Path) -> Vec<PathBuf> {
    let candidates = [
        "README.md",
        "README.rst",
        "README.txt",
        "README",
        "docs/README.md",
        "doc/README.md",
        "ARCHITECTURE.md",
        "CONTRIBUTING.md",
    ];
    candidates
        .iter()
        .map(|c| root.join(c))
        .filter(|p| p.is_file())
        .collect()
}

pub fn parse_doc_claims(content: &str, file: &Path) -> Vec<DocClaim> {
    let mut claims = Vec::new();

    let port_re = regex::Regex::new(r"(?i)\bport\s+(\d{2,5})\b").unwrap();
    let port_colon_re = regex::Regex::new(r"(?i)\bport[:\s]+`?(\d{2,5})`?").unwrap();
    let localhost_re = regex::Regex::new(r"localhost:(\d{2,5})").unwrap();
    let version_re =
        regex::Regex::new(r"(?i)\bv(?:ersion)?\s*[:\s]?\s*`?(\d+\.\d+(?:\.\d+)?)`?").unwrap();
    let go_ver_re = regex::Regex::new(r"(?i)\bgo\s+(\d+\.\d+(?:\.\d+)?)\b").unwrap();
    let python_ver_re = regex::Regex::new(r"(?i)\bpython\s+(\d+\.\d+(?:\.\d+)?)\b").unwrap();
    let node_ver_re = regex::Regex::new(r"(?i)\bnode(?:\.?js)?\s+(\d+(?:\.\d+)*)\b").unwrap();
    let rust_edition_re = regex::Regex::new(r"(?i)\bedition\s+`?(\d{4})`?").unwrap();
    let license_re =
        regex::Regex::new(r"(?i)\blicen[sc]e[d]?\s+(?:under\s+(?:the\s+)?)?`?(MIT|Apache[- ]2\.0|GPL[- ]?\d*|BSD[- ]?\d*|ISC|MPL[- ]?\d*|AGPL[- ]?\d*|LGPL[- ]?\d*)`?")
            .unwrap();
    let dep_re =
        regex::Regex::new(r"(?i)\b(?:requires?|depends?\s+on|built\s+(?:with|on))\s+[`*]*(\w[\w-]*)[`*]*(?:\s+([v\d][\d.]+))?")
            .unwrap();
    let module_count_re = regex::Regex::new(r"(?i)(\d+)\s+(?:modules?|services?|packages?)").unwrap();
    let replicas_re = regex::Regex::new(r"(?i)(\d+)\s+replicas?").unwrap();

    for (line_idx, line) in content.lines().enumerate() {
        let line_num = line_idx + 1;

        // Port claims
        for caps in port_re.captures_iter(line) {
            claims.push(DocClaim {
                category: FactCategory::Port,
                key: "port".into(),
                claimed_value: caps[1].to_string(),
                file: file.to_path_buf(),
                line: line_num,
                raw_text: line.to_string(),
            });
        }
        for caps in port_colon_re.captures_iter(line) {
            if !claims.iter().any(|c| {
                c.line == line_num
                    && c.category == FactCategory::Port
                    && c.claimed_value == caps[1]
            }) {
                claims.push(DocClaim {
                    category: FactCategory::Port,
                    key: "port".into(),
                    claimed_value: caps[1].to_string(),
                    file: file.to_path_buf(),
                    line: line_num,
                    raw_text: line.to_string(),
                });
            }
        }
        for caps in localhost_re.captures_iter(line) {
            if !claims.iter().any(|c| {
                c.line == line_num
                    && c.category == FactCategory::Port
                    && c.claimed_value == caps[1]
            }) {
                claims.push(DocClaim {
                    category: FactCategory::Port,
                    key: "port".into(),
                    claimed_value: caps[1].to_string(),
                    file: file.to_path_buf(),
                    line: line_num,
                    raw_text: line.to_string(),
                });
            }
        }

        // Version claims
        for caps in version_re.captures_iter(line) {
            claims.push(DocClaim {
                category: FactCategory::Version,
                key: "version".into(),
                claimed_value: caps[1].to_string(),
                file: file.to_path_buf(),
                line: line_num,
                raw_text: line.to_string(),
            });
        }

        // Go version
        for caps in go_ver_re.captures_iter(line) {
            claims.push(DocClaim {
                category: FactCategory::Version,
                key: "go".into(),
                claimed_value: caps[1].to_string(),
                file: file.to_path_buf(),
                line: line_num,
                raw_text: line.to_string(),
            });
        }

        // Python version
        for caps in python_ver_re.captures_iter(line) {
            claims.push(DocClaim {
                category: FactCategory::PythonVersion,
                key: "python".into(),
                claimed_value: caps[1].to_string(),
                file: file.to_path_buf(),
                line: line_num,
                raw_text: line.to_string(),
            });
        }

        // Node version
        for caps in node_ver_re.captures_iter(line) {
            claims.push(DocClaim {
                category: FactCategory::NodeVersion,
                key: "node".into(),
                claimed_value: caps[1].to_string(),
                file: file.to_path_buf(),
                line: line_num,
                raw_text: line.to_string(),
            });
        }

        // Rust edition
        for caps in rust_edition_re.captures_iter(line) {
            claims.push(DocClaim {
                category: FactCategory::RustEdition,
                key: "rust-edition".into(),
                claimed_value: caps[1].to_string(),
                file: file.to_path_buf(),
                line: line_num,
                raw_text: line.to_string(),
            });
        }

        // License
        for caps in license_re.captures_iter(line) {
            claims.push(DocClaim {
                category: FactCategory::License,
                key: "license".into(),
                claimed_value: caps[1].to_string(),
                file: file.to_path_buf(),
                line: line_num,
                raw_text: line.to_string(),
            });
        }

        // Dependency mentions
        for caps in dep_re.captures_iter(line) {
            let name = caps[1].to_string();
            let ver = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
            claims.push(DocClaim {
                category: FactCategory::Dependency,
                key: name,
                claimed_value: ver,
                file: file.to_path_buf(),
                line: line_num,
                raw_text: line.to_string(),
            });
        }

        // Module/service count
        for caps in module_count_re.captures_iter(line) {
            claims.push(DocClaim {
                category: FactCategory::GoModule,
                key: "workspace-module-count".into(),
                claimed_value: caps[1].to_string(),
                file: file.to_path_buf(),
                line: line_num,
                raw_text: line.to_string(),
            });
        }

        // Replica count
        for caps in replicas_re.captures_iter(line) {
            claims.push(DocClaim {
                category: FactCategory::K8sReplica,
                key: "replicas".into(),
                claimed_value: caps[1].to_string(),
                file: file.to_path_buf(),
                line: line_num,
                raw_text: line.to_string(),
            });
        }
    }

    claims
}

// ===========================================================================
// 3. DriftDetector — compare facts against claims
// ===========================================================================

pub fn detect_drifts(facts: &[Fact], claims: &[DocClaim]) -> Vec<Drift> {
    let mut drifts = Vec::new();

    // Build lookup: (category, key) -> Vec<Fact>
    let mut fact_map: HashMap<(FactCategory, String), Vec<&Fact>> = HashMap::new();
    for fact in facts {
        fact_map
            .entry((fact.category, fact.key.clone()))
            .or_default()
            .push(fact);
    }

    // Also build a set of all fact values per category for loose matching
    let mut category_values: HashMap<FactCategory, Vec<&str>> = HashMap::new();
    for fact in facts {
        category_values
            .entry(fact.category)
            .or_default()
            .push(&fact.value);
    }

    for claim in claims {
        // Skip claims with no specific value to verify
        if claim.claimed_value.is_empty() && claim.category != FactCategory::Dependency {
            continue;
        }

        // Strategy 1: exact key match
        if let Some(matched_facts) = fact_map.get(&(claim.category, claim.key.clone())) {
            for fact in matched_facts {
                if let Some(drift) = compare_fact_claim(fact, claim) {
                    drifts.push(drift);
                }
            }
            continue;
        }

        // Strategy 2: category-wide match for ports (any port fact vs port claim)
        if claim.category == FactCategory::Port {
            let all_port_facts: Vec<&&Fact> = fact_map
                .iter()
                .filter(|((cat, _), _)| *cat == FactCategory::Port)
                .flat_map(|(_, v)| v)
                .collect();

            if !all_port_facts.is_empty() {
                let any_match = all_port_facts
                    .iter()
                    .any(|f| f.value == claim.claimed_value);
                if !any_match {
                    drifts.push(Drift {
                        message: format!(
                            "README claims port {} but config sources define ports: {}",
                            claim.claimed_value,
                            all_port_facts
                                .iter()
                                .map(|f| f.value.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        suggestion: format!(
                            "Update README to match actual port(s) from {}",
                            all_port_facts[0].source_file.display()
                        ),
                        severity: Severity::Warning,
                        confidence: Confidence::Likely,
                        doc_file: claim.file.clone(),
                        doc_line: claim.line,
                    });
                }
            }
            continue;
        }

        // Strategy 3: dependency name match (version drift)
        if claim.category == FactCategory::Dependency && !claim.claimed_value.is_empty() {
            // Look for any fact with this dependency name as key
            let dep_facts: Vec<&&Fact> = fact_map
                .iter()
                .filter(|((cat, key), _)| {
                    *cat == FactCategory::Dependency && key == &claim.key
                })
                .flat_map(|(_, v)| v)
                .collect();

            for fact in &dep_facts {
                if let Some(drift) = compare_fact_claim(fact, claim) {
                    drifts.push(drift);
                }
            }
        }
    }

    drifts
}

fn compare_fact_claim(fact: &Fact, claim: &DocClaim) -> Option<Drift> {
    if claim.claimed_value.is_empty() {
        return None;
    }

    let fact_val = normalize_value(&fact.value);
    let claim_val = normalize_value(&claim.claimed_value);

    if fact_val == claim_val {
        return None;
    }

    // For versions, strip leading 'v' for comparison
    let fact_ver = fact_val.trim_start_matches('v');
    let claim_ver = claim_val.trim_start_matches('v');
    if fact_ver == claim_ver {
        return None;
    }

    // Prefix match: claim "1.21" matches fact "1.21.5"
    if fact_ver.starts_with(claim_ver) || claim_ver.starts_with(fact_ver) {
        return None;
    }

    let category_label = fact.category.label();
    Some(Drift {
        message: format!(
            "README says {category_label} is `{claim_val}` but {} has `{fact_val}`",
            fact.source_file.display()
        ),
        suggestion: format!(
            "Update README {category_label} from `{claim_val}` to `{fact_val}`"
        ),
        severity: Severity::Warning,
        confidence: Confidence::Confirmed,
        doc_file: claim.file.clone(),
        doc_line: claim.line,
    })
}

fn normalize_value(s: &str) -> String {
    s.trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_matches('`')
        .to_string()
}

// ===========================================================================
// Helpers
// ===========================================================================

fn extract_toml_string_value(line: &str) -> Option<String> {
    let after_eq = line.split_once('=')?.1.trim();
    let val = after_eq.trim_matches('"').trim_matches('\'');
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

fn is_yaml_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml" | "yml")
    )
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // -----------------------------------------------------------------------
    // FactExtractor tests
    // -----------------------------------------------------------------------

    #[test]
    fn extract_cargo_toml_extracts_version_and_edition() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Cargo.toml");
        std::fs::write(
            &path,
            r#"
[package]
name = "my-app"
version = "0.3.0"
edition = "2021"
license = "MIT"

[dependencies]
serde = "1.0"
tokio = { version = "1.35", features = ["full"] }
"#,
        )
        .unwrap();

        let facts = extract_cargo_toml(&path);
        assert!(facts.iter().any(|f| f.category == FactCategory::Version && f.value == "0.3.0"));
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::RustEdition && f.value == "2021")
        );
        assert!(facts.iter().any(|f| f.category == FactCategory::License && f.value == "MIT"));
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::Dependency
                    && f.key == "serde"
                    && f.value == "1.0")
        );
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::Dependency
                    && f.key == "tokio"
                    && f.value == "1.35")
        );
    }

    #[test]
    fn extract_go_mod_extracts_module_and_deps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("go.mod");
        std::fs::write(
            &path,
            r#"module github.com/example/myapp

go 1.22

require (
	github.com/gin-gonic/gin v1.9.1
	google.golang.org/grpc v1.60.0
)
"#,
        )
        .unwrap();

        let facts = extract_go_mod(&path);
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::GoModule
                    && f.value == "github.com/example/myapp")
        );
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::Version
                    && f.key == "go"
                    && f.value == "1.22")
        );
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::Dependency
                    && f.key == "github.com/gin-gonic/gin"
                    && f.value == "v1.9.1")
        );
    }

    #[test]
    fn extract_go_work_counts_modules() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("go.work");
        std::fs::write(
            &path,
            r#"go 1.22

use (
    ./api
    ./worker
    ./shared
)
"#,
        )
        .unwrap();

        let facts = extract_go_work(&path);
        let count_fact = facts
            .iter()
            .find(|f| f.key == "workspace-module-count")
            .unwrap();
        assert_eq!(count_fact.value, "3");
        assert!(
            facts
                .iter()
                .any(|f| f.key == "workspace-module:api" && f.value == "api")
        );
    }

    #[test]
    fn extract_package_json_extracts_version_and_deps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package.json");
        std::fs::write(
            &path,
            r#"{
  "version": "2.1.0",
  "license": "Apache-2.0",
  "engines": { "node": ">=18" },
  "dependencies": { "express": "^4.18.0" }
}"#,
        )
        .unwrap();

        let facts = extract_package_json(&path);
        assert!(facts.iter().any(|f| f.category == FactCategory::Version && f.value == "2.1.0"));
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::License && f.value == "Apache-2.0")
        );
        assert!(facts.iter().any(|f| f.category == FactCategory::NodeVersion && f.value == ">=18"));
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::Dependency && f.key == "express")
        );
    }

    #[test]
    fn extract_dockerfile_extracts_base_image_and_port() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Dockerfile");
        std::fs::write(
            &path,
            "FROM node:20-alpine AS builder\nEXPOSE 3000 8080\n",
        )
        .unwrap();

        let facts = extract_dockerfile(&path);
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::DockerBaseImage
                    && f.value == "node:20-alpine")
        );
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::Port && f.value == "3000")
        );
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::Port && f.value == "8080")
        );
    }

    // -----------------------------------------------------------------------
    // DocClaimParser tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_claims_extracts_port_and_version() {
        let readme = r#"
# My App

The server runs on port 3000.
Visit http://localhost:8080 to see the dashboard.

## Requirements
- Go 1.21
- Node.js 18
- Python 3.11

Version: 2.1.0

Licensed under the MIT license.
"#;
        let claims = parse_doc_claims(readme, Path::new("README.md"));

        assert!(claims.iter().any(|c| c.category == FactCategory::Port && c.claimed_value == "3000"));
        assert!(claims.iter().any(|c| c.category == FactCategory::Port && c.claimed_value == "8080"));
        assert!(
            claims
                .iter()
                .any(|c| c.category == FactCategory::Version
                    && c.key == "go"
                    && c.claimed_value == "1.21")
        );
        assert!(
            claims
                .iter()
                .any(|c| c.category == FactCategory::NodeVersion && c.claimed_value == "18")
        );
        assert!(
            claims
                .iter()
                .any(|c| c.category == FactCategory::PythonVersion && c.claimed_value == "3.11")
        );
        assert!(
            claims
                .iter()
                .any(|c| c.category == FactCategory::License && c.claimed_value == "MIT")
        );
    }

    #[test]
    fn parse_claims_extracts_dependency_mention() {
        let readme = "Built with `express` v4.18\nRequires gin v1.9\n";
        let claims = parse_doc_claims(readme, Path::new("README.md"));
        assert!(claims.iter().any(|c| c.category == FactCategory::Dependency && c.key == "express"));
        assert!(claims.iter().any(|c| c.category == FactCategory::Dependency && c.key == "gin"));
    }

    #[test]
    fn parse_claims_extracts_module_count() {
        let readme = "The workspace contains 5 modules.\n";
        let claims = parse_doc_claims(readme, Path::new("README.md"));
        assert!(
            claims
                .iter()
                .any(|c| c.key == "workspace-module-count" && c.claimed_value == "5")
        );
    }

    #[test]
    fn parse_claims_extracts_replica_count() {
        let readme = "Production runs 3 replicas behind a load balancer.\n";
        let claims = parse_doc_claims(readme, Path::new("README.md"));
        assert!(
            claims
                .iter()
                .any(|c| c.category == FactCategory::K8sReplica && c.claimed_value == "3")
        );
    }

    // -----------------------------------------------------------------------
    // DriftDetector tests
    // -----------------------------------------------------------------------

    #[test]
    fn detect_port_drift() {
        let facts = vec![Fact {
            category: FactCategory::Port,
            key: "docker-port:3000".into(),
            value: "3000".into(),
            source_file: PathBuf::from("Dockerfile"),
        }];
        let claims = vec![DocClaim {
            category: FactCategory::Port,
            key: "port".into(),
            claimed_value: "8080".into(),
            file: PathBuf::from("README.md"),
            line: 5,
            raw_text: "runs on port 8080".into(),
        }];

        let drifts = detect_drifts(&facts, &claims);
        assert_eq!(drifts.len(), 1);
        assert!(drifts[0].message.contains("8080"));
        assert!(drifts[0].message.contains("3000"));
    }

    #[test]
    fn no_drift_when_port_matches() {
        let facts = vec![Fact {
            category: FactCategory::Port,
            key: "docker-port:3000".into(),
            value: "3000".into(),
            source_file: PathBuf::from("Dockerfile"),
        }];
        let claims = vec![DocClaim {
            category: FactCategory::Port,
            key: "port".into(),
            claimed_value: "3000".into(),
            file: PathBuf::from("README.md"),
            line: 5,
            raw_text: "runs on port 3000".into(),
        }];

        let drifts = detect_drifts(&facts, &claims);
        assert!(drifts.is_empty());
    }

    #[test]
    fn detect_version_drift() {
        let facts = vec![Fact {
            category: FactCategory::Version,
            key: "go".into(),
            value: "1.22".into(),
            source_file: PathBuf::from("go.mod"),
        }];
        let claims = vec![DocClaim {
            category: FactCategory::Version,
            key: "go".into(),
            claimed_value: "1.19".into(),
            file: PathBuf::from("README.md"),
            line: 10,
            raw_text: "Go 1.19".into(),
        }];

        let drifts = detect_drifts(&facts, &claims);
        assert_eq!(drifts.len(), 1);
        assert!(drifts[0].message.contains("1.19"));
        assert!(drifts[0].message.contains("1.22"));
    }

    #[test]
    fn no_drift_version_prefix_match() {
        let facts = vec![Fact {
            category: FactCategory::Version,
            key: "go".into(),
            value: "1.22.5".into(),
            source_file: PathBuf::from("go.mod"),
        }];
        let claims = vec![DocClaim {
            category: FactCategory::Version,
            key: "go".into(),
            claimed_value: "1.22".into(),
            file: PathBuf::from("README.md"),
            line: 10,
            raw_text: "Go 1.22".into(),
        }];

        let drifts = detect_drifts(&facts, &claims);
        assert!(drifts.is_empty(), "prefix match should not be drift");
    }

    #[test]
    fn detect_module_count_drift() {
        let facts = vec![Fact {
            category: FactCategory::GoModule,
            key: "workspace-module-count".into(),
            value: "3".into(),
            source_file: PathBuf::from("go.work"),
        }];
        let claims = vec![DocClaim {
            category: FactCategory::GoModule,
            key: "workspace-module-count".into(),
            claimed_value: "5".into(),
            file: PathBuf::from("README.md"),
            line: 8,
            raw_text: "5 modules".into(),
        }];

        let drifts = detect_drifts(&facts, &claims);
        assert_eq!(drifts.len(), 1);
        assert!(drifts[0].message.contains("5"));
        assert!(drifts[0].message.contains("3"));
    }

    #[test]
    fn detect_license_drift() {
        let facts = vec![Fact {
            category: FactCategory::License,
            key: "license".into(),
            value: "Apache-2.0".into(),
            source_file: PathBuf::from("Cargo.toml"),
        }];
        let claims = vec![DocClaim {
            category: FactCategory::License,
            key: "license".into(),
            claimed_value: "MIT".into(),
            file: PathBuf::from("README.md"),
            line: 20,
            raw_text: "Licensed under MIT".into(),
        }];

        let drifts = detect_drifts(&facts, &claims);
        assert_eq!(drifts.len(), 1);
    }

    // -----------------------------------------------------------------------
    // Integration: full pipeline
    // -----------------------------------------------------------------------

    #[test]
    fn full_pipeline_detects_port_drift() {
        let dir = tempfile::tempdir().unwrap();

        // Create Dockerfile with port 3000
        std::fs::write(dir.path().join("Dockerfile"), "FROM node:20\nEXPOSE 3000\n").unwrap();

        // Create README claiming port 8080
        std::fs::write(
            dir.path().join("README.md"),
            "# App\nThe server runs on port 8080.\n",
        )
        .unwrap();

        let facts = extract_all_facts(dir.path());
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::Port && f.value == "3000")
        );

        let docs = discover_doc_files(dir.path());
        assert!(!docs.is_empty());

        let content = std::fs::read_to_string(&docs[0]).unwrap();
        let claims = parse_doc_claims(&content, &docs[0]);
        assert!(
            claims
                .iter()
                .any(|c| c.category == FactCategory::Port && c.claimed_value == "8080")
        );

        let drifts = detect_drifts(&facts, &claims);
        assert_eq!(drifts.len(), 1);
    }

    #[test]
    fn full_pipeline_no_drift_when_consistent() {
        let dir = tempfile::tempdir().unwrap();

        std::fs::write(dir.path().join("Dockerfile"), "FROM node:20\nEXPOSE 3000\n").unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            "# App\nVisit http://localhost:3000\n",
        )
        .unwrap();

        let facts = extract_all_facts(dir.path());
        let docs = discover_doc_files(dir.path());
        let content = std::fs::read_to_string(&docs[0]).unwrap();
        let claims = parse_doc_claims(&content, &docs[0]);
        let drifts = detect_drifts(&facts, &claims);
        assert!(drifts.is_empty());
    }

    #[test]
    fn full_pipeline_go_version_drift() {
        let dir = tempfile::tempdir().unwrap();

        std::fs::write(
            dir.path().join("go.mod"),
            "module example.com/app\n\ngo 1.22\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("README.md"),
            "# App\nRequires Go 1.19 or later.\n",
        )
        .unwrap();

        let facts = extract_all_facts(dir.path());
        let docs = discover_doc_files(dir.path());
        let content = std::fs::read_to_string(&docs[0]).unwrap();
        let claims = parse_doc_claims(&content, &docs[0]);
        let drifts = detect_drifts(&facts, &claims);
        assert_eq!(drifts.len(), 1);
    }

    #[test]
    fn extract_all_facts_returns_empty_for_bare_dir() {
        let dir = tempfile::tempdir().unwrap();
        let facts = extract_all_facts(dir.path());
        assert!(facts.is_empty());
    }

    #[test]
    fn docker_compose_extracts_ports_and_images() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker-compose.yml");
        std::fs::write(
            &path,
            r#"version: "3"
services:
  web:
    image: nginx:1.25
    ports:
      - "80:80"
  api:
    image: myapp:latest
    ports:
      - "3000:3000"
"#,
        )
        .unwrap();

        let facts = extract_docker_compose(&path);
        assert!(facts.iter().any(|f| f.category == FactCategory::Port && f.value == "80"));
        assert!(facts.iter().any(|f| f.category == FactCategory::Port && f.value == "3000"));
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::DockerBaseImage && f.value == "nginx:1.25")
        );
    }

    #[test]
    fn k8s_manifest_extracts_replicas_and_image() {
        let dir = tempfile::tempdir().unwrap();
        let k8s_dir = dir.path().join("k8s");
        std::fs::create_dir(&k8s_dir).unwrap();
        std::fs::write(
            k8s_dir.join("deployment.yaml"),
            r#"apiVersion: apps/v1
kind: Deployment
spec:
  replicas: 3
  template:
    spec:
      containers:
      - image: myapp/api:v2.1.0
        ports:
        - containerPort: 8080
"#,
        )
        .unwrap();

        let facts = extract_k8s_manifests(dir.path());
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::K8sReplica && f.value == "3")
        );
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::K8sImage
                    && f.value == "myapp/api:v2.1.0")
        );
        assert!(
            facts
                .iter()
                .any(|f| f.category == FactCategory::Port && f.value == "8080")
        );
    }
}
