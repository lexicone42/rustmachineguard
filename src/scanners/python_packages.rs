use crate::platform::PlatformInfo;
use crate::scanners::{read_bounded, Scanner};
use std::path::{Path, PathBuf};

/// Resolves installed Python distributions (name + version) so the catalog's pypi rows
/// can actually match.
///
/// Until now the only path that reached a pypi row was an MCP server whose launch
/// command pinned a version — so a compromised package merely *installed* on the machine
/// was invisible. This walks the standard install locations and reads the authoritative
/// metadata rather than guessing from directory names.
///
/// Returns identities only (name, version, location). It never reads package CODE, so
/// there is no path from a package's contents into the report.
pub struct PythonPackagesScanner;

/// Cap the per-root scan; a site-packages directory has hundreds of entries, and a
/// pathological tree must not hang the scan.
const MAX_DISTS_PER_ROOT: usize = 5_000;

/// One installed Python distribution.
#[derive(Debug, Clone, PartialEq)]
pub struct PythonPackage {
    pub name: String,
    pub version: String,
    pub location: String,
}

impl Scanner for PythonPackagesScanner {
    type Output = Vec<PythonPackage>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<PythonPackage> {
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for root in site_package_roots(platform) {
            if !seen.insert(root.clone()) {
                continue;
            }
            scan_root(&root, &mut out);
        }
        // The same distribution can appear in several roots; keep one per (name, version).
        let mut uniq = std::collections::HashSet::new();
        out.retain(|p| uniq.insert((p.name.clone(), p.version.clone())));
        out
    }
}

/// Where Python distributions live. Deliberately bounded: system and user site-packages,
/// plus virtualenvs sitting in the agent's registered project roots — which is where an
/// agent actually installs things. We do not sweep the whole filesystem.
fn site_package_roots(platform: &dyn PlatformInfo) -> Vec<PathBuf> {
    let home = platform.home_dir();
    let mut roots = Vec::new();

    // System interpreters.
    for base in ["/usr/lib", "/usr/local/lib", "/opt/homebrew/lib"] {
        let Ok(entries) = std::fs::read_dir(base) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let is_python_dir = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("python3"));
            if is_python_dir {
                roots.push(p.join("site-packages"));
                roots.push(p.join("dist-packages"));
            }
        }
    }
    // User site-packages.
    if let Ok(entries) = std::fs::read_dir(home.join(".local/lib")) {
        for e in entries.flatten() {
            roots.push(e.path().join("site-packages"));
        }
    }
    // Virtualenvs in registered project roots and the cwd.
    let mut projects = project_dirs(&home.join(".claude.json")).unwrap_or_default();
    if let Ok(cwd) = std::env::current_dir() {
        projects.push(cwd);
    }
    for proj in projects {
        for venv in [".venv", "venv", "env", ".env"] {
            let lib = proj.join(venv).join("lib");
            let Ok(entries) = std::fs::read_dir(&lib) else {
                continue;
            };
            for e in entries.flatten() {
                roots.push(e.path().join("site-packages"));
            }
        }
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

fn scan_root(root: &Path, out: &mut Vec<PythonPackage>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    let mut budget = MAX_DISTS_PER_ROOT;
    for entry in entries.flatten() {
        if budget == 0 {
            return;
        }
        let p = entry.path();
        let Some(dir_name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Modern wheels use *.dist-info/METADATA; older installs use *.egg-info/PKG-INFO.
        let meta = if dir_name.ends_with(".dist-info") {
            p.join("METADATA")
        } else if dir_name.ends_with(".egg-info") {
            p.join("PKG-INFO")
        } else {
            continue;
        };
        budget -= 1;
        // The directory name (`Name-Version.dist-info`) is the installed identity: the
        // installer wrote it, and it survives a padded or lying METADATA. METADATA is
        // the fallback (bare egg-info dirs carry no version). Names are PEP 503
        // normalised on both sides of the catalog match, so `mcp_runcommand_server`,
        // `Mcp.Runcommand.Server` and `mcp-runcommand-server` are one project.
        let from_dir = dir_name
            .rsplit_once('.')
            .and_then(|(stem, _)| stem.rsplit_once('-'))
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .filter(|(_, v)| v.chars().next().is_some_and(|c| c.is_ascii_digit()));
        let ident = from_dir.or_else(|| parse_metadata_name_version(&meta));
        if let Some((name, version)) = ident
            && crate::scanners::npm_packages::is_valid_npm_name(&name)
            && crate::scanners::npm_packages::is_valid_version(&version)
        {
            out.push(PythonPackage {
                name: crate::scanners::exposure::pep503_normalize(&name),
                version,
                location: crate::scanners::sanitize_display(&p.to_string_lossy(), 512),
            });
        }
    }
}

/// Read `Name:` and `Version:` from a METADATA / PKG-INFO file.
///
/// Parses only the RFC-822 header block and stops at the blank line that precedes the
/// long description — so a package's README, which can be large and can contain
/// anything, is never pulled into the report.
pub fn parse_metadata_name_version(path: &Path) -> Option<(String, String)> {
    // A bounded head, never a size refusal: a METADATA padded past 1 MiB used to make
    // the distribution vanish from the inventory. The headers are at the top.
    let head = crate::scanners::read_head_bytes(path, 64 * 1024)?;
    let content = String::from_utf8_lossy(&head).into_owned();
    let mut name = None;
    let mut version = None;
    for line in content.lines() {
        if line.trim().is_empty() {
            break; // end of headers; the long description follows
        }
        if let Some(v) = line.strip_prefix("Name:") {
            name = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("Version:") {
            version = Some(v.trim().to_string());
        }
        if name.is_some() && version.is_some() {
            break;
        }
    }
    match (name, version) {
        (Some(n), Some(v)) if !n.is_empty() && !v.is_empty() => Some((n, v)),
        _ => None,
    }
}
