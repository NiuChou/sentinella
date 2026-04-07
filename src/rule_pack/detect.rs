use std::path::Path;

/// Detected technology stack entry
#[derive(Debug, Clone)]
pub struct TechStackEntry {
    pub name: String,
    pub confidence: f64,
    pub source: String,
}

/// Detect the project's tech stack by examining manifest files.
/// Returns a list of rule pack names that should be loaded.
pub fn detect_tech_stack(root: &Path) -> Vec<TechStackEntry> {
    let mut stack = Vec::new();

    detect_node(root, &mut stack);
    detect_python(root, &mut stack);
    detect_go(root, &mut stack);
    detect_rust(root, &mut stack);

    stack
}

fn detect_node(root: &Path, stack: &mut Vec<TechStackEntry>) {
    let candidates = [
        root.join("package.json"),
        root.join("backend/package.json"),
        root.join("server/package.json"),
        root.join("api/package.json"),
    ];

    for pkg_path in &candidates {
        if let Ok(content) = std::fs::read_to_string(pkg_path) {
            let source = pkg_path
                .strip_prefix(root)
                .unwrap_or(pkg_path)
                .to_string_lossy()
                .to_string();

            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                let deps = collect_deps(&json);
                check_node_deps(&deps, &source, stack);
            }
        }
    }
}

fn check_node_deps(deps: &[String], source: &str, stack: &mut Vec<TechStackEntry>) {
    let matchers: &[(&[&str], &str, f64)] = &[
        (&["@nestjs/core", "@nestjs/common"], "nestjs", 0.95),
        (&["express"], "express", 0.90),
        (&["next"], "nextjs", 0.95),
        (&["fastify"], "fastify", 0.90),
        (&["@hono/hono", "hono"], "hono", 0.90),
        (&["nuxt", "nuxt3"], "nuxt", 0.90),
    ];

    for (dep_names, pack_name, confidence) in matchers {
        if dep_names.iter().any(|d| deps.iter().any(|dep| dep == d)) {
            stack.push(TechStackEntry {
                name: (*pack_name).into(),
                confidence: *confidence,
                source: source.to_string(),
            });
        }
    }
}

fn detect_python(root: &Path, stack: &mut Vec<TechStackEntry>) {
    let req_files = [
        root.join("requirements.txt"),
        root.join("backend/requirements.txt"),
    ];

    for req_path in &req_files {
        if let Ok(content) = std::fs::read_to_string(req_path) {
            let source = req_path
                .strip_prefix(root)
                .unwrap_or(req_path)
                .to_string_lossy()
                .to_string();
            let lower = content.to_lowercase();

            check_python_deps(&lower, &source, stack);
        }
    }

    let pyproject = root.join("pyproject.toml");
    if let Ok(content) = std::fs::read_to_string(&pyproject) {
        let lower = content.to_lowercase();
        check_python_deps(&lower, "pyproject.toml", stack);
    }
}

fn check_python_deps(lower_content: &str, source: &str, stack: &mut Vec<TechStackEntry>) {
    let matchers: &[(&str, &str, f64)] = &[
        ("fastapi", "fastapi", 0.95),
        ("django", "django", 0.95),
        ("flask", "flask", 0.90),
    ];

    for (keyword, pack_name, confidence) in matchers {
        if lower_content.contains(keyword) {
            stack.push(TechStackEntry {
                name: (*pack_name).into(),
                confidence: *confidence,
                source: source.to_string(),
            });
        }
    }
}

fn detect_go(root: &Path, stack: &mut Vec<TechStackEntry>) {
    let gomod_files = [root.join("go.mod"), root.join("backend/go.mod")];

    let matchers: &[(&str, &str, f64)] = &[
        ("gin-gonic/gin", "gin", 0.95),
        ("labstack/echo", "echo", 0.95),
        ("go-chi/chi", "chi", 0.90),
        ("gofiber/fiber", "fiber", 0.90),
    ];

    for gomod_path in &gomod_files {
        if let Ok(content) = std::fs::read_to_string(gomod_path) {
            let source = gomod_path
                .strip_prefix(root)
                .unwrap_or(gomod_path)
                .to_string_lossy()
                .to_string();

            for (keyword, pack_name, confidence) in matchers {
                if content.contains(keyword) {
                    stack.push(TechStackEntry {
                        name: (*pack_name).into(),
                        confidence: *confidence,
                        source: source.clone(),
                    });
                }
            }
        }
    }
}

fn detect_rust(root: &Path, stack: &mut Vec<TechStackEntry>) {
    let cargo_path = root.join("Cargo.toml");
    if let Ok(content) = std::fs::read_to_string(&cargo_path) {
        let matchers: &[(&str, &str, f64)] = &[
            ("actix-web", "actix", 0.95),
            ("axum", "axum", 0.95),
            ("rocket", "rocket", 0.90),
        ];

        for (keyword, pack_name, confidence) in matchers {
            if content.contains(keyword) {
                stack.push(TechStackEntry {
                    name: (*pack_name).into(),
                    confidence: *confidence,
                    source: "Cargo.toml".to_string(),
                });
            }
        }
    }
}

/// Collect all dependency names from package.json
fn collect_deps(json: &serde_json::Value) -> Vec<String> {
    let mut deps = Vec::new();
    for key in &["dependencies", "devDependencies", "peerDependencies"] {
        if let Some(obj) = json.get(key).and_then(|v| v.as_object()) {
            deps.extend(obj.keys().cloned());
        }
    }
    deps
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_detect_node_nestjs() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("package.json");
        let mut f = std::fs::File::create(&pkg).unwrap();
        f.write_all(br#"{"dependencies": {"@nestjs/core": "^10.0.0", "express": "^4.0.0"}}"#)
            .unwrap();

        let stack = detect_tech_stack(dir.path());
        let names: Vec<&str> = stack.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"nestjs"));
        assert!(names.contains(&"express"));
    }

    #[test]
    fn test_detect_python_fastapi() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        let mut f = std::fs::File::create(&req).unwrap();
        f.write_all(b"fastapi==0.100.0\nuvicorn\n").unwrap();

        let stack = detect_tech_stack(dir.path());
        let names: Vec<&str> = stack.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"fastapi"));
    }

    #[test]
    fn test_detect_go_gin() {
        let dir = tempfile::tempdir().unwrap();
        let gomod = dir.path().join("go.mod");
        let mut f = std::fs::File::create(&gomod).unwrap();
        f.write_all(b"module myapp\nrequire github.com/gin-gonic/gin v1.9.0\n")
            .unwrap();

        let stack = detect_tech_stack(dir.path());
        let names: Vec<&str> = stack.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"gin"));
    }

    #[test]
    fn test_detect_empty_project() {
        let dir = tempfile::tempdir().unwrap();
        let stack = detect_tech_stack(dir.path());
        assert!(stack.is_empty());
    }

    #[test]
    fn test_collect_deps() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{"dependencies": {"express": "4"}, "devDependencies": {"jest": "29"}}"#,
        )
        .unwrap();
        let deps = collect_deps(&json);
        assert!(deps.contains(&"express".to_string()));
        assert!(deps.contains(&"jest".to_string()));
    }
}
