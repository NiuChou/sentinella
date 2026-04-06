use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Architecture {
    SingleRepo,
    Monorepo { services: Vec<DetectedService> },
    Polyrepo { linked_repos: Vec<LinkedRepo> },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectedService {
    pub name: String,
    pub root_dir: PathBuf,
    pub language: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LinkedRepo {
    pub name: String,
    pub path: PathBuf,
    #[serde(default)]
    pub service_name: Option<String>,
}

const SERVICE_MARKERS: &[(&str, Option<&str>)] = &[
    ("package.json", Some("typescript")),
    ("go.mod", Some("go")),
    ("Cargo.toml", Some("rust")),
    ("pyproject.toml", Some("python")),
    ("setup.py", Some("python")),
    ("pom.xml", Some("java")),
    ("build.gradle", Some("java")),
];

const IGNORED_DIRS: &[&str] = &["node_modules", "target", "dist", "build", "vendor"];

pub fn detect_architecture(root: &Path, linked_repos_config: &[LinkedRepo]) -> Architecture {
    if !linked_repos_config.is_empty() {
        return Architecture::Polyrepo {
            linked_repos: linked_repos_config.to_vec(),
        };
    }

    let services = detect_monorepo_services(root);

    if services.len() >= 2 {
        Architecture::Monorepo { services }
    } else {
        Architecture::SingleRepo
    }
}

fn detect_monorepo_services(root: &Path) -> Vec<DetectedService> {
    let entries = match std::fs::read_dir(root) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };

    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_dir() {
                return None;
            }

            let dir_name = path.file_name()?.to_str()?;
            if dir_name.starts_with('.') || IGNORED_DIRS.contains(&dir_name) {
                return None;
            }

            detect_service_in_dir(&path, dir_name)
        })
        .collect()
}

fn detect_service_in_dir(path: &Path, dir_name: &str) -> Option<DetectedService> {
    for &(marker, language) in SERVICE_MARKERS {
        if path.join(marker).exists() {
            return Some(DetectedService {
                name: dir_name.to_string(),
                root_dir: path.to_path_buf(),
                language: language.map(String::from),
            });
        }
    }
    None
}

impl std::fmt::Display for Architecture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Architecture::SingleRepo => write!(f, "SingleRepo"),
            Architecture::Monorepo { services } => {
                let names: Vec<&str> = services.iter().map(|s| s.name.as_str()).collect();
                write!(f, "Monorepo ({})", names.join(", "))
            }
            Architecture::Polyrepo { linked_repos } => {
                let names: Vec<&str> = linked_repos.iter().map(|r| r.name.as_str()).collect();
                write!(f, "Polyrepo ({})", names.join(", "))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn empty_linked_repos_and_no_subdirs_returns_single_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let arch = detect_architecture(tmp.path(), &[]);
        assert_eq!(arch, Architecture::SingleRepo);
    }

    #[test]
    fn linked_repos_config_returns_polyrepo() {
        let tmp = tempfile::tempdir().unwrap();
        let repos = vec![LinkedRepo {
            name: "auth-service".into(),
            path: PathBuf::from("/repos/auth"),
            service_name: None,
        }];
        let arch = detect_architecture(tmp.path(), &repos);
        assert!(matches!(arch, Architecture::Polyrepo { .. }));
    }

    #[test]
    fn multiple_service_dirs_returns_monorepo() {
        let tmp = tempfile::tempdir().unwrap();

        let svc_a = tmp.path().join("service-a");
        fs::create_dir(&svc_a).unwrap();
        fs::write(svc_a.join("package.json"), "{}").unwrap();

        let svc_b = tmp.path().join("service-b");
        fs::create_dir(&svc_b).unwrap();
        fs::write(svc_b.join("go.mod"), "module b").unwrap();

        let arch = detect_architecture(tmp.path(), &[]);
        match arch {
            Architecture::Monorepo { services } => {
                assert_eq!(services.len(), 2);
                let names: Vec<&str> = services.iter().map(|s| s.name.as_str()).collect();
                assert!(names.contains(&"service-a"));
                assert!(names.contains(&"service-b"));
            }
            other => panic!("expected Monorepo, got {:?}", other),
        }
    }

    #[test]
    fn single_service_dir_returns_single_repo() {
        let tmp = tempfile::tempdir().unwrap();

        let svc = tmp.path().join("service-a");
        fs::create_dir(&svc).unwrap();
        fs::write(svc.join("Cargo.toml"), "[package]").unwrap();

        let arch = detect_architecture(tmp.path(), &[]);
        assert_eq!(arch, Architecture::SingleRepo);
    }

    #[test]
    fn hidden_and_ignored_dirs_are_skipped() {
        let tmp = tempfile::tempdir().unwrap();

        let hidden = tmp.path().join(".hidden");
        fs::create_dir(&hidden).unwrap();
        fs::write(hidden.join("package.json"), "{}").unwrap();

        let nm = tmp.path().join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("package.json"), "{}").unwrap();

        let svc = tmp.path().join("real-service");
        fs::create_dir(&svc).unwrap();
        fs::write(svc.join("package.json"), "{}").unwrap();

        let arch = detect_architecture(tmp.path(), &[]);
        assert_eq!(arch, Architecture::SingleRepo);
    }

    #[test]
    fn display_formats_correctly() {
        let single = Architecture::SingleRepo;
        assert_eq!(format!("{single}"), "SingleRepo");

        let mono = Architecture::Monorepo {
            services: vec![DetectedService {
                name: "api".into(),
                root_dir: PathBuf::from("/api"),
                language: Some("rust".into()),
            }],
        };
        assert_eq!(format!("{mono}"), "Monorepo (api)");
    }
}
