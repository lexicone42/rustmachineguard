use crate::platform::PlatformInfo;
use crate::scanners::{read_bounded, Scanner};
use std::path::{Path, PathBuf};

/// Resolves installed npm packages (name + version) so the catalog's 31 npm rows can
/// actually match.
///
/// `node_packages.rs` enumerates package MANAGERS (the npm/yarn/pnpm/bun binaries), not
/// packages. Until this existed the only way to reach an npm catalog row was an MCP
/// server whose launch command named the package — so the typosquat rows (`claud-code`,
/// `cloude-code`, `opencraw`) were unreachable by construction: nobody launches a
/// typosquat as an MCP server, they install it by mistyping `npm i -g`.
///
/// This is the npm counterpart of [`crate::scanners::python_packages`], and it makes the
/// same guarantee: identities only (name, version, location). Package CODE is never read,
/// so there is no path from a dependency's contents into the report.
pub struct NpmPackagesScanner;

/// Cap the per-root scan. A node_modules directory routinely holds thousands of entries,
/// and a pathological tree must not hang the scan.
const MAX_PACKAGES_PER_ROOT: usize = 5_000;

/// One installed npm package.
#[derive(Debug, Clone, PartialEq)]
pub struct NpmPackage {
    pub name: String,
    pub version: String,
    pub location: String,
}

impl Scanner for NpmPackagesScanner {
    type Output = Vec<NpmPackage>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<NpmPackage> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for root in node_modules_roots(platform) {
            if !seen.insert(root.clone()) {
                continue;
            }
            scan_root(&root, &mut out);
        }
        // The same package appears in many trees; keep one per (name, version).
        let mut uniq = std::collections::HashSet::new();
        out.retain(|p| uniq.insert((p.name.clone(), p.version.clone())));
        out
    }
}

/// Where npm packages live. Deliberately bounded: the global roots of each package
/// manager, plus `node_modules` in the agent's registered project roots — which is where
/// an agent actually installs things. We do not sweep the whole filesystem.
fn node_modules_roots(platform: &dyn PlatformInfo) -> Vec<PathBuf> {
    let home = platform.home_dir();
    let mut roots = Vec::new();

    // System / global installs.
    for base in [
        "/usr/lib/node_modules",
        "/usr/local/lib/node_modules",
        "/opt/homebrew/lib/node_modules",
    ] {
        roots.push(PathBuf::from(base));
    }
    // Per-user global prefixes, one per package manager.
    for rel in [
        ".npm-global/lib/node_modules",
        ".local/lib/node_modules",
        ".bun/install/global/node_modules",
        ".config/yarn/global/node_modules",
        ".local/share/pnpm/global/5/node_modules",
    ] {
        roots.push(home.join(rel));
    }
    // nvm keeps one global root per installed Node version.
    if let Ok(entries) = std::fs::read_dir(home.join(".nvm/versions/node")) {
        for e in entries.flatten() {
            roots.push(e.path().join("lib/node_modules"));
        }
    }
    // Project-local installs in registered project roots and the cwd.
    let mut projects = project_dirs(&home.join(".claude.json")).unwrap_or_default();
    if let Ok(cwd) = std::env::current_dir() {
        projects.push(cwd);
    }
    for proj in projects {
        roots.push(proj.join("node_modules"));
    }
    roots.retain(|p| p.is_dir());
    roots
}

fn project_dirs(claude_json: &Path) -> Option<Vec<PathBuf>> {
    let content = read_bounded(claude_json)?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    Some(
        parsed
            .get("projects")?
            .as_object()?
            .keys()
            .map(PathBuf::from)
            .filter(|p| p.is_dir())
            .collect(),
    )
}

fn scan_root(root: &Path, out: &mut Vec<NpmPackage>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut budget = MAX_PACKAGES_PER_ROOT;
    for entry in entries.flatten() {
        if budget == 0 {
            return;
        }
        let p = entry.path();
        let Some(dir_name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // `.bin`, `.package-lock.json` and friends are not packages.
        if dir_name.starts_with('.') {
            continue;
        }
        // A scope directory holds packages one level down: @scope/name.
        if dir_name.starts_with('@') {
            let Ok(scoped) = std::fs::read_dir(&p) else {
                continue;
            };
            for s in scoped.flatten() {
                if budget == 0 {
                    return;
                }
                budget -= 1;
                push_package(&s.path(), out);
            }
            continue;
        }
        budget -= 1;
        push_package(&p, out);
    }
}

fn push_package(dir: &Path, out: &mut Vec<NpmPackage>) {
    if let Some((name, version)) = parse_package_json_name_version(&dir.join("package.json")) {
        out.push(NpmPackage {
            name,
            version,
            location: dir.to_string_lossy().to_string(),
        });
    }
}

/// Read `name` and `version` from a package.json.
///
/// Only those two fields are taken. A package.json also carries `description`,
/// `scripts` and `readme`, which are attacker-controlled free text; pulling them into
/// the report would hand a malicious package a channel into the operator's console.
pub fn parse_package_json_name_version(path: &Path) -> Option<(String, String)> {
    let content = read_bounded(path)?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    let name = parsed.get("name")?.as_str()?.trim();
    let version = parsed.get("version")?.as_str()?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}
