use std::path::Path;

use anyhow::Result;
use regex::Regex;

use super::{count_lines, hash_source, LanguageParser};
use crate::indexer::store::IndexStore;
use crate::indexer::types::{DockerfileCheck, FileInfo, Language};

pub struct DockerfileParser;

impl LanguageParser for DockerfileParser {
    fn extensions(&self) -> &[&str] {
        // Matched by filename prefix in the walker (see indexer/mod.rs)
        &["Dockerfile"]
    }

    fn parse_file(&self, path: &Path, source: &[u8], store: &IndexStore) -> Result<()> {
        let file_info = FileInfo {
            path: path.to_path_buf(),
            language: Language::Dockerfile,
            lines: count_lines(source),
            hash: hash_source(source),
        };
        store.files.insert(path.to_path_buf(), file_info);

        let source_str = std::str::from_utf8(source)
            .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in Dockerfile: {e}"))?;

        let service_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Dockerfile")
            .to_string();

        let base_pinned = check_base_pinned(source_str);
        let has_healthcheck = check_healthcheck(source_str);
        let has_user = check_non_root_user(source_str);
        let has_dockerignore = check_dockerignore(path);

        let check = DockerfileCheck {
            service: service_name.clone(),
            has_healthcheck,
            base_pinned,
            has_user,
            has_dockerignore,
        };

        store.infra.dockerfile_checks.insert(service_name, check);

        Ok(())
    }
}

/// Check whether the FROM image is pinned with @sha256: or a specific version tag
/// (not :latest and not just a bare image name).
fn check_base_pinned(source: &str) -> bool {
    let from_re = Regex::new(r"(?i)^FROM\s+(\S+)").unwrap();

    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(cap) = from_re.captures(trimmed) {
            if let Some(image) = cap.get(1) {
                let image_str = image.as_str();
                // Pinned by digest
                if image_str.contains("@sha256:") {
                    continue;
                }
                // Has a tag that is not :latest
                if let Some(tag_pos) = image_str.rfind(':') {
                    let tag = &image_str[tag_pos + 1..];
                    if tag == "latest" {
                        return false;
                    }
                    // Specific version tag — considered pinned
                    continue;
                }
                // No tag at all — unpinned (defaults to :latest)
                return false;
            }
        }
    }

    true
}

/// Check for HEALTHCHECK instruction.
fn check_healthcheck(source: &str) -> bool {
    let re = Regex::new(r"(?i)^HEALTHCHECK\s").unwrap();
    source.lines().any(|line| re.is_match(line.trim()))
}

/// Check for USER instruction with a non-root user.
fn check_non_root_user(source: &str) -> bool {
    let re = Regex::new(r"(?i)^USER\s+(\S+)").unwrap();

    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(cap) = re.captures(trimmed) {
            if let Some(user) = cap.get(1) {
                let user_str = user.as_str();
                if user_str != "root" && user_str != "0" {
                    return true;
                }
            }
        }
    }

    false
}

/// Check whether a .dockerignore file exists alongside the Dockerfile.
fn check_dockerignore(dockerfile_path: &Path) -> bool {
    let parent = match dockerfile_path.parent() {
        Some(p) => p,
        None => return false,
    };
    parent.join(".dockerignore").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/docker")
            .join(name)
    }

    fn parse_fixture(name: &str) -> Arc<IndexStore> {
        let path = fixture_path(name);
        let source = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", path.display()));
        let store = IndexStore::new();
        DockerfileParser.parse_file(&path, &source, &store).unwrap();
        store
    }

    #[test]
    fn detects_healthcheck() {
        let store = parse_fixture("Dockerfile");
        let check = store.infra.dockerfile_checks.iter().next();
        assert!(check.is_some(), "Should have a dockerfile check entry");
        let entry = check.unwrap();
        assert!(
            entry.has_healthcheck,
            "Should detect HEALTHCHECK instruction"
        );
    }

    #[test]
    fn detects_non_root_user() {
        let store = parse_fixture("Dockerfile");
        let check = store.infra.dockerfile_checks.iter().next().unwrap();
        assert!(check.has_user, "Should detect non-root USER instruction");
    }

    #[test]
    fn detects_pinned_base_image() {
        let store = parse_fixture("Dockerfile");
        let check = store.infra.dockerfile_checks.iter().next().unwrap();
        assert!(
            check.base_pinned,
            "node:20-alpine should be considered pinned"
        );
    }

    #[test]
    fn check_base_pinned_with_latest_tag() {
        assert!(!check_base_pinned("FROM node:latest\nRUN echo hi"));
    }

    #[test]
    fn check_base_pinned_with_no_tag() {
        assert!(!check_base_pinned("FROM node\nRUN echo hi"));
    }

    #[test]
    fn check_base_pinned_with_sha256() {
        let src = "FROM node@sha256:abc123\nRUN echo hi";
        assert!(check_base_pinned(src));
    }

    #[test]
    fn check_healthcheck_present() {
        assert!(check_healthcheck("HEALTHCHECK CMD curl http://localhost"));
    }

    #[test]
    fn check_healthcheck_absent() {
        assert!(!check_healthcheck("FROM node:20\nRUN echo hi"));
    }

    #[test]
    fn check_non_root_user_present() {
        assert!(check_non_root_user("USER node"));
    }

    #[test]
    fn check_non_root_user_root_is_false() {
        assert!(!check_non_root_user("USER root"));
    }

    #[test]
    fn check_non_root_user_absent() {
        assert!(!check_non_root_user("FROM node:20\nRUN echo hi"));
    }

    #[test]
    fn file_info_is_populated() {
        let store = parse_fixture("Dockerfile");
        let path = fixture_path("Dockerfile");
        assert!(store.files.contains_key(&path), "FileInfo should exist");
        let (lang, lines) = store
            .files
            .get(&path)
            .map(|info| (info.language, info.lines))
            .unwrap();
        assert_eq!(lang, Language::Dockerfile);
        assert!(lines > 0);
    }
}
