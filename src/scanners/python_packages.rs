use crate::models::PackageRootKind;
use crate::platform::PlatformInfo;
use crate::scanners::{Scanner, read_bounded};
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
    /// The kind of root it was found in.
    pub root_kind: PackageRootKind,
    /// The uv tool / pipx venv / agent venv name (sanitized), when the root has one.
    pub root_name: Option<String>,
}

/// One site-packages directory to read, and what kind of install it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PythonRoot {
    pub path: PathBuf,
    pub kind: PackageRootKind,
    pub name: Option<String>,
}

impl Scanner for PythonPackagesScanner {
    type Output = Vec<PythonPackage>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<PythonPackage> {
        let mut out = Vec::new();
        for root in python_roots(platform) {
            scan_root(&root, &mut out);
        }
        // The same distribution can appear in several roots. System roots (several
        // interpreters sharing a dist) and project venvs collapse to one row per
        // (name, version) as before; a uv tool, pipx venv or agent venv is its own
        // install with its own upgrade command, so each keeps its row.
        let mut uniq = std::collections::HashSet::new();
        out.retain(|p| uniq.insert((p.name.clone(), p.version.clone(), p.root_kind, p.root_name.clone())));
        out
    }
}

/// Directories listed while enumerating the per-user environment roots (uv tools, pipx
/// venvs, uv pythons, agent-private venvs), written at [`BASE_WALK_BUDGET`] and scaled
/// with `--walk-budget` ([`walk_cap`]): 6,250 at the default. A home with more than that
/// many is reported as truncated rather than walked without end.
///
/// [`BASE_WALK_BUDGET`]: crate::scanners::telemetry::BASE_WALK_BUDGET
/// [`walk_cap`]: crate::scanners::telemetry::walk_cap
const BASE_ENV_ROOT_DIRS: usize = 1_000;

/// How deep under an agent directory (`~/.claude`, ...) a virtualenv is looked for:
/// `~/.claude/security/agent-sdk-venv` is depth 2.
const AGENT_VENV_DEPTH: usize = 3;

/// The agent directories whose private virtualenvs are inventoried. An agent that
/// bootstraps its own Python tooling (an SDK venv, a plugin's MCP server) installs it
/// here, outside every project and outside `uv tool` / pipx.
const AGENT_DIRS: &[&str] = &[".claude", ".codex", ".gemini", ".cursor", ".vibe", ".serena"];

/// Where Python distributions live, as the scanner and the persistence scanner's
/// `.pth` / `sitecustomize` check both read them. Deliberately bounded: system and user
/// site-packages, virtualenvs in the agent's registered project roots, and the per-user
/// environments that tool installers create (uv tools, pipx, uv-managed interpreters,
/// agent-private venvs). We do not sweep the whole filesystem.
///
/// Each root is listed once, by its real path (a venv's `lib64 -> lib` link is one
/// root), in a fixed order: the order of the kinds below, then by directory name.
pub(crate) fn python_roots(platform: &dyn PlatformInfo) -> Vec<PythonRoot> {
    let home = platform.home_dir();
    let mut roots = Vec::new();
    let push = |roots: &mut Vec<PythonRoot>, path: PathBuf, kind: PackageRootKind, name: Option<&str>| {
        roots.push(PythonRoot {
            path,
            kind,
            name: name.map(|n| crate::scanners::sanitize_display(n, 128)),
        });
    };

    // System interpreters.
    for base in ["/usr/lib", "/usr/local/lib", "/opt/homebrew/lib"] {
        for p in sorted_dirs(Path::new(base)) {
            let is_python_dir = p
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("python3"));
            if is_python_dir {
                push(&mut roots, p.join("site-packages"), PackageRootKind::System, None);
                push(&mut roots, p.join("dist-packages"), PackageRootKind::System, None);
            }
        }
    }
    // User site-packages.
    for p in sorted_dirs(&home.join(".local/lib")) {
        push(&mut roots, p.join("site-packages"), PackageRootKind::User, None);
    }
    // Virtualenvs in registered project roots and (primary pass) the cwd.
    let projects = platform
        .pass_scope()
        .with_cwd(project_dirs(&home.join(".claude.json")).unwrap_or_default());
    for proj in projects {
        for venv in [".venv", "venv", "env", ".env"] {
            for p in sorted_dirs(&proj.join(venv).join("lib")) {
                push(&mut roots, p.join("site-packages"), PackageRootKind::Project, None);
            }
        }
    }

    let mut budget =
        crate::scanners::telemetry::walk_cap(BASE_ENV_ROOT_DIRS, crate::scanners::telemetry::walk_budget());
    let env = EnvDirs::for_pass(platform);

    // uv tool environments, one venv per `uv tool install`: `$UV_TOOL_DIR`, else
    // `$XDG_DATA_HOME/uv/tools`, else `~/.local/share/uv/tools`
    // (https://docs.astral.sh/uv/concepts/tools/,
    // https://docs.astral.sh/uv/reference/environment/#uv_tool_dir). The default is read
    // as well as an override: tools installed before the variable was set stay there.
    let mut uv_tool_dirs: Vec<PathBuf> = env.uv_tool_dir.iter().cloned().collect();
    uv_tool_dirs.extend(env.xdg_data_home.iter().map(|d| d.join("uv/tools")));
    uv_tool_dirs.push(home.join(".local/share/uv/tools"));
    if cfg!(target_os = "macos") {
        uv_tool_dirs.push(home.join("Library/Application Support/uv/tools"));
    }
    for dir in uv_tool_dirs {
        for venv in bounded_dirs(&dir, &mut budget) {
            let name = dir_name(&venv);
            for sp in venv_site_packages(&venv, &mut budget) {
                push(&mut roots, sp, PackageRootKind::UvTool, name.as_deref());
            }
        }
    }

    // pipx venvs: `$PIPX_HOME/venvs/<name>`, else `~/.local/share/pipx/venvs/<name>`
    // (pipx >= 1.3), the legacy `~/.local/pipx/venvs/<name>`, and on macOS
    // `~/Library/Application Support/pipx/venvs/<name>`
    // (https://pipx.pypa.io/stable/installation/).
    let mut pipx_homes: Vec<PathBuf> = env.pipx_home.iter().cloned().collect();
    pipx_homes.push(home.join(".local/share/pipx"));
    pipx_homes.push(home.join(".local/pipx"));
    if cfg!(target_os = "macos") {
        pipx_homes.push(home.join("Library/Application Support/pipx"));
    }
    for ph in pipx_homes {
        for venv in bounded_dirs(&ph.join("venvs"), &mut budget) {
            let name = dir_name(&venv);
            for sp in venv_site_packages(&venv, &mut budget) {
                push(&mut roots, sp, PackageRootKind::Pipx, name.as_deref());
            }
        }
    }

    // Agent-private virtualenvs: a directory holding `pyvenv.cfg` (the PEP 405 marker,
    // https://peps.python.org/pep-0405/) within AGENT_VENV_DEPTH of an agent directory.
    for agent in AGENT_DIRS {
        for venv in find_venvs(&home.join(agent), &mut budget) {
            let name = dir_name(&venv);
            for sp in venv_site_packages(&venv, &mut budget) {
                push(&mut roots, sp, PackageRootKind::AgentVenv, name.as_deref());
            }
        }
    }

    // uv-managed interpreters (`uv python install`): `$UV_PYTHON_INSTALL_DIR`, else
    // `$XDG_DATA_HOME/uv/python`, else `~/.local/share/uv/python`
    // (https://docs.astral.sh/uv/reference/environment/#uv_python_install_dir). A
    // package installed into one with `--system` / `--break-system-packages` lands in
    // its base site-packages.
    let mut uv_python_dirs: Vec<PathBuf> = env.uv_python_dir.iter().cloned().collect();
    uv_python_dirs.extend(env.xdg_data_home.iter().map(|d| d.join("uv/python")));
    uv_python_dirs.push(home.join(".local/share/uv/python"));
    for dir in uv_python_dirs {
        for interp in bounded_dirs(&dir, &mut budget) {
            for sp in venv_site_packages(&interp, &mut budget) {
                push(&mut roots, sp, PackageRootKind::UvPython, None);
            }
        }
    }

    // One row per real directory, first kind wins. Not found: dropped.
    let mut seen = std::collections::HashSet::new();
    roots.retain(|r| {
        crate::scanners::probe_dir(&r.path)
            && seen.insert(std::fs::canonicalize(&r.path).unwrap_or_else(|_| r.path.clone()))
    });
    roots
}

/// The environment overrides that name this user's install roots. They describe the
/// user running rmguard, so they apply only to the pass whose home is that user's
/// `$HOME`; a `--search-dirs` home gets its defaults only.
struct EnvDirs {
    uv_tool_dir: Option<PathBuf>,
    uv_python_dir: Option<PathBuf>,
    xdg_data_home: Option<PathBuf>,
    pipx_home: Option<PathBuf>,
}

impl EnvDirs {
    fn for_pass(platform: &dyn PlatformInfo) -> Self {
        let own_home = std::env::var_os("HOME").is_some_and(|h| Path::new(&h) == platform.home_dir());
        // Absolute paths only: a relative override would resolve against the cwd.
        let var = |k: &str| {
            std::env::var_os(k)
                .map(PathBuf::from)
                .filter(|p| own_home && p.is_absolute())
        };
        Self {
            uv_tool_dir: var("UV_TOOL_DIR"),
            uv_python_dir: var("UV_PYTHON_INSTALL_DIR"),
            xdg_data_home: var("XDG_DATA_HOME"),
            pipx_home: var("PIPX_HOME"),
        }
    }
}

fn dir_name(p: &Path) -> Option<String> {
    p.file_name().and_then(|n| n.to_str()).map(str::to_string)
}

/// The subdirectories of `dir`, sorted by name. Unbounded: used for the fixed system
/// and project roots, whose listings were never capped.
fn sorted_dirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = crate::scanners::probe_read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    v.sort();
    v
}

/// Spend one unit of `budget`, or, when it is spent, mark the scanner truncated and
/// return false. Every directory the environment-root enumeration lists or descends
/// into is charged here, depth first in name order, so which roots survive a tripped
/// cap does not depend on the order the filesystem lists entries in.
fn charge(budget: &mut usize) -> bool {
    if *budget == 0 {
        crate::scanners::telemetry::mark_truncated();
        return false;
    }
    *budget -= 1;
    true
}

/// The real (non-symlink) subdirectories of `dir`, sorted by name. Charges one unit
/// for listing `dir`; listing nothing when the budget is spent.
fn bounded_dirs(dir: &Path, budget: &mut usize) -> Vec<PathBuf> {
    if !crate::scanners::probe_dir(dir) || !charge(budget) {
        return Vec::new();
    }
    let Ok(entries) = crate::scanners::probe_read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    v.sort();
    v
}

/// `<venv>/lib/python*/site-packages` and `<venv>/lib64/python*/site-packages` (the
/// lib64 spelling is what a multilib Linux interpreter, Gentoo's or Fedora's, writes;
/// a venv usually links `lib64 -> lib`, and the caller drops the duplicate). Charges
/// one unit per `lib` directory listed.
fn venv_site_packages(venv: &Path, budget: &mut usize) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for lib in ["lib", "lib64"] {
        let lib = venv.join(lib);
        // `lib64` is often a symlink to `lib`: listed by its path, not by file type.
        if !lib.is_dir() || !charge(budget) {
            continue;
        }
        let Ok(entries) = crate::scanners::probe_read_dir(&lib) else {
            continue;
        };
        let mut v: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("python"))
            })
            .collect();
        v.sort();
        out.extend(v.into_iter().map(|p| p.join("site-packages")));
    }
    out
}

/// Virtualenvs (directories holding a `pyvenv.cfg` regular file) at depth 1 to
/// AGENT_VENV_DEPTH under `base`, depth first in name order. Symlinked directories are
/// not followed (an agent directory can hold a link into a credential store, and the
/// walk must never be steered out of it), a found venv is not descended into, and every
/// directory listed is charged to `budget`.
fn find_venvs(base: &Path, budget: &mut usize) -> Vec<PathBuf> {
    fn walk(dir: &Path, depth: usize, budget: &mut usize, found: &mut Vec<PathBuf>) {
        for child in bounded_dirs(dir, budget) {
            if is_venv(&child) {
                found.push(child);
            } else if depth < AGENT_VENV_DEPTH {
                walk(&child, depth + 1, budget, found);
            }
        }
    }
    let mut found = Vec::new();
    walk(base, 1, budget, &mut found);
    found
}

/// `dir/pyvenv.cfg` is a regular file (not a link). Only its type is checked: the file
/// is never opened. Not counted in the diagnostics' missing paths: this asks every
/// directory of the walk (about 1,500 under a busy `~/.claude`), and an absent marker
/// is the normal answer, not a path that was expected and missing.
fn is_venv(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join("pyvenv.cfg")).is_ok_and(|m| m.is_file())
}

pub(crate) fn project_dirs(claude_json: &Path) -> Option<Vec<PathBuf>> {
    let content = read_bounded(claude_json)?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    Some(
        parsed
            .get("projects")?
            .as_object()?
            .keys()
            .map(PathBuf::from)
            .filter(|p| crate::scanners::probe_dir(p))
            .collect(),
    )
}

fn scan_root(root: &PythonRoot, out: &mut Vec<PythonPackage>) {
    let Ok(entries) = crate::scanners::probe_read_dir(&root.path) else {
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
                root_kind: root.kind,
                root_name: root.name.clone(),
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
