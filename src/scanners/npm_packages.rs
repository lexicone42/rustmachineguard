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
            let mut budget = MAX_PACKAGES_PER_ROOT;
            scan_root(&root, &mut out, &mut budget);
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
    roots.retain(|p| crate::scanners::probe_dir(&p));
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
            .filter(|p| crate::scanners::probe_dir(&p))
            .collect(),
    )
}

/// Bytes of package.json / METADATA to read for an identity. Not `read_bounded`: that
/// refuses files over 1 MiB, so padding package.json with a 1 MiB description made a
/// typosquat disappear from the inventory -- a deterministic evasion. The identity
/// fields sit at the top of these files; a bounded head is enough.
const IDENTITY_HEAD_BYTES: usize = 64 * 1024;

fn scan_root(root: &Path, out: &mut Vec<NpmPackage>, budget: &mut usize) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            return;
        }
        let p = entry.path();
        let Some(dir_name) = p.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // pnpm keeps every package -- including all transitive ones -- under the virtual
        // store node_modules/.pnpm/<pkg>@<ver>/node_modules/. The top level holds only
        // direct dependencies as symlinks, so without this a pnpm project's transitive
        // dependencies (where an injected malicious dep lives) were never enumerated.
        if dir_name == ".pnpm" {
            if let Ok(store) = std::fs::read_dir(&p) {
                for s in store.flatten() {
                    let nm = s.path().join("node_modules");
                    if crate::scanners::probe_dir(&nm) {
                        scan_root(&nm, out, budget);
                    }
                }
            }
            continue;
        }
        // Inside the pnpm store every dependency edge is a symlink back into the store.
        // Each target is enumerated as its own store entry, so following the symlink
        // would double-count it AND charge budget per edge -- which exhausted the
        // budget at ~1,300 packages and silently truncated the inventory.
        if entry.file_type().is_ok_and(|k| k.is_symlink()) && root.to_string_lossy().contains("/.pnpm/") {
            continue;
        }
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
                if *budget == 0 {
                    return;
                }
                *budget -= 1;
                let sp = s.path();
                let Some(leaf) = sp.file_name().and_then(|n| n.to_str()) else {
                    continue;
                };
                push_package(&sp, &format!("{dir_name}/{leaf}"), out, budget);
            }
            continue;
        }
        *budget -= 1;
        push_package(&p, dir_name, out, budget);
    }
}

fn push_package(dir: &Path, installed_name: &str, out: &mut Vec<NpmPackage>, budget: &mut usize) {
    // The DIRECTORY name is the installed identity: npm resolves `require("x")` by
    // directory, and that is what a typosquat is installed as. Taking the name from
    // package.json let an attacker garble or pad the file and vanish from the catalog
    // check; now only the version comes from the file, and it is validated.
    if !is_valid_npm_name(installed_name) {
        return;
    }
    let parsed = parse_package_json_name_version(&dir.join("package.json"));
    let version = parsed
        .as_ref()
        .map(|(_, v)| v.clone())
        .filter(|v| is_valid_version(v))
        .unwrap_or_else(|| "unknown".to_string());
    // The location is printed in the terminal; a store-entry directory name is
    // attacker-controlled, so it is sanitized like any other free text.
    let location = crate::scanners::sanitize_display(&dir.to_string_lossy(), 512);
    out.push(NpmPackage {
        name: installed_name.to_string(),
        version: version.clone(),
        location: location.clone(),
    });
    // npm aliases: `npm i harmless@npm:claud-code` installs claud-code's tarball under
    // node_modules/harmless. The directory says one thing and package.json another;
    // both are identities the catalog must see, or an alias hides a known-bad package.
    if let Some((declared, _)) = parsed
        && declared != installed_name
        && is_valid_npm_name(&declared)
    {
        out.push(NpmPackage {
            name: declared,
            version,
            location,
        });
    }
    // npm/yarn nest a dependency under its parent when versions conflict:
    // node_modules/<parent>/node_modules/<child>. Same budget.
    let nested = dir.join("node_modules");
    if crate::scanners::probe_dir(&nested) {
        scan_root(&nested, out, budget);
    }
}

/// npm's package-name grammar, tightened: lowercase or legacy mixed case, digits,
/// `._-`, an optional `@scope/`, at most 214 bytes, no path tricks.
pub fn is_valid_npm_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 || name.contains("..") {
        return false;
    }
    let body = match name.strip_prefix('@') {
        Some(rest) => {
            let Some((scope, leaf)) = rest.split_once('/') else {
                return false;
            };
            if scope.is_empty() || leaf.is_empty() || leaf.contains('/') {
                return false;
            }
            rest
        }
        None => {
            if name.contains('/') {
                return false;
            }
            name
        }
    };
    body.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
}

/// A version string a catalog can compare: semver / PEP 440 characters only, bounded.
/// Anything else -- newlines, ANSI escapes, prose -- is attacker text and is dropped.
pub fn is_valid_version(v: &str) -> bool {
    !v.is_empty() && v.len() <= 64 && v.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-' | '!'))
}

/// Read `name` and `version` from a package.json.
///
/// Reads only a bounded HEAD of the file and never refuses on size (see
/// IDENTITY_HEAD_BYTES). Falls back to a field scan when the head is not complete JSON.
/// Only those two fields are taken. A package.json also carries `description`,
/// `scripts` and `readme`, which are attacker-controlled free text; pulling them into
/// the report would hand a malicious package a channel into the operator's console.
pub fn parse_package_json_name_version(path: &Path) -> Option<(String, String)> {
    let head = crate::scanners::read_head_bytes(path, IDENTITY_HEAD_BYTES)?;
    let head = String::from_utf8_lossy(&head);
    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&head) {
        let name = parsed.get("name")?.as_str()?.trim();
        let version = parsed.get("version")?.as_str()?.trim();
        if name.is_empty() || version.is_empty() {
            return None;
        }
        return Some((name.to_string(), version.to_string()));
    }
    // Truncated (the file was larger than the head): take the two top-level string
    // fields by scanning. Good enough for an identity; a garbled file yields None and
    // the caller falls back to the directory name.
    let name = json_string_field(&head, "name")?;
    let version = json_string_field(&head, "version")?;
    Some((name, version))
}

/// Find `"key": "value"` in (possibly truncated) JSON text and return the value.
fn json_string_field(text: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let mut from = 0;
    while let Some(i) = text[from..].find(&needle) {
        let after = &text[from + i + needle.len()..];
        let after = after.trim_start();
        if let Some(rest) = after.strip_prefix(':') {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('"') {
                let mut val = String::new();
                let mut chars = rest.chars();
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => {
                            if let Some(n) = chars.next() {
                                val.push(n);
                            }
                        }
                        '"' => return Some(val).filter(|v| !v.is_empty()),
                        _ => val.push(c),
                    }
                }
                return None;
            }
        }
        from += i + needle.len();
    }
    None
}
