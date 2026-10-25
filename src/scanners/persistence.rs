use crate::models::PersistenceArtifact;
use crate::platform::PlatformInfo;
use crate::scanners::{Scanner, is_git_tracked, read_head_bytes, sanitize_display};
use std::path::{Path, PathBuf};

/// Finds the on-disk artifacts the 2026 agent-targeting worms and agent CVEs leave or
/// rely on, none of which any other scanner looks at:
///
/// - **Python startup hooks**: a `.pth` file in site-packages whose line begins with
///   `import` runs on every interpreter start, and a `sitecustomize.py` /
///   `usercustomize.py` at the site-packages root does the same. litellm 1.107.0
///   (`cook.pth` + `cook.py` + `sitecustomize.py`) and the openaii/langgrap wave used
///   exactly this: the implant survives `pip uninstall` and runs in every MCP server
///   launched with that interpreter, whether or not the package is ever imported.
/// - **Planted binaries**: a regular executable named like a tool an agent spawns by
///   bare name (`git`, `npx`, `node`, `python`, ...) sitting in a project root. On
///   Windows the working directory is searched first (Claude Desktop CVE-2026-88066,
///   Cursor CVE-2026-63093, Kiro); on POSIX it fires when PATH contains `.`, and a
///   git-tracked one ships with every clone of the repo.
/// - **Escaping committed symlinks**: a git-tracked symlink whose target resolves
///   outside the repository, so an approved in-project write lands in `~/.ssh`, a
///   shell rc or an agent config (the GhostApproval shape, Claude Code CVE-2026-103435).
/// - **Loader staging**: a JavaScript loader placed directly inside a project's
///   `.vscode/` or `.claude/` directory — the ChainDrop/tensorlake worm's `setup.mjs`
///   that the hook/task persistence pair re-launches.
/// - **Known worm persistence paths**: the hostage-token monitor (tensorlake), the
///   EtherDuck launchd/systemd units, the Deadbugz hidden MCP script, the Apex
///   `~/.apex/agent/mcp.json`, and the litellm loader lock.
///
/// Identity and shape only: a `.pth` contributes its first line (which is code, not a
/// secret, and is what makes it a hook), everything else contributes a path, a name or
/// a symlink target. Package code is never read, and every attacker-chosen string is
/// passed through `sanitize_display` before it reaches the report.
pub struct PersistenceScanner;

/// Per-root caps so a pathological site-packages or repository cannot hang the scan.
const MAX_ENTRIES_PER_ROOT: usize = 5_000;
const MAX_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_SYMLINKS_PER_REPO: usize = 500;
const GIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// `.pth` files that legitimately carry `import` lines. Everything else that imports
/// at interpreter start is reported (Medium when a distribution's RECORD claims the
/// file, High when nothing does).
const KNOWN_IMPORT_PTH: &[&str] = &[
    "distutils-precedence.pth", // setuptools
    "_virtualenv.pth",          // virtualenv
    "easy-install.pth",         // setuptools legacy
    "pytest-cov.pth",           // pytest-cov subprocess coverage
    "coverage.pth",             // coverage subprocess hook (opt-in)
];

/// Startup-hook file names published as indicators of the litellm 1.107.0 implant.
const IOC_STARTUP_NAMES: &[&str] = &["cook.pth", "cook.py"];

/// Tool names agents and IDEs spawn by bare name. A regular file with one of these
/// names in a project root shadows the real tool wherever the working directory is on
/// the search path.
const SHADOWABLE_TOOLS: &[&str] = &[
    "git",
    "npx",
    "npm",
    "node",
    "python",
    "python3",
    "pwsh",
    "powershell",
    "bash",
    "sh",
    "rg",
    "gh",
    "hatch",
    "uv",
    "which",
    "code",
    "cargo",
    "pip",
    "pip3",
];
const WINDOWS_EXEC_EXTS: &[&str] = &["exe", "cmd", "bat", "ps1", "com"];

/// Where an escaping symlink becomes a credential or persistence write, not just a
/// path confusion.
const SENSITIVE_TARGET_DIRS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".config",
    ".claude",
    ".codex",
    ".gemini",
    ".cursor",
    ".kube",
    ".docker",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
];
const SENSITIVE_TARGET_FILES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".claude.json",
    "authorized_keys",
];

/// Known persistence artifacts of agent-targeting campaigns, relative to HOME.
/// `(path, campaign)`.
const HOME_IOC_PATHS: &[(&str, &str)] = &[
    (
        ".config/gh-token-monitor",
        "tensorlake hostage-token monitor (Shai-Hulud/ChainDrop, 2026-10)",
    ),
    (
        ".local/bin/gh-token-monitor.sh",
        "tensorlake hostage-token monitor (Shai-Hulud/ChainDrop, 2026-10)",
    ),
    (
        ".config/systemd/user/gh-token-monitor.service",
        "tensorlake hostage-token monitor (Shai-Hulud/ChainDrop, 2026-10)",
    ),
    (
        "Library/LaunchAgents/com.user.gh-token-monitor.plist",
        "tensorlake hostage-token monitor (Shai-Hulud/ChainDrop, 2026-10)",
    ),
    (".solidity", "EtherDuck Open VSX Solidity extensions (2026-09)"),
    (
        "Library/LaunchAgents/com.solidity.langsupport.runner.plist",
        "EtherDuck Open VSX Solidity extensions (2026-09)",
    ),
    (
        ".config/systemd/user/solidity-langsupport-runner.service",
        "EtherDuck Open VSX Solidity extensions (2026-09)",
    ),
    (
        ".config/.cache/.sys/.deadbug-mcp.py",
        "Deadbugz MCP metadata-poisoning campaign (2026-08)",
    ),
    (
        ".apex/agent/mcp.json",
        "Apex Accelerator backdoored coding agent, REF8801 (2026-10)",
    ),
];
/// Absolute paths (not under HOME) the same campaigns leave behind.
const ABS_IOC_PATHS: &[(&str, &str)] = &[(
    "/tmp/remote_code_loader.lock",
    "litellm 1.107.0 remote-code loader (2026-10)",
)];
/// Known persistence artifacts relative to a project root.
const PROJECT_IOC_PATHS: &[(&str, &str)] = &[(
    ".github/workflows/runtime-update.yml",
    "MemTensor sckit worm GitHub Actions dropper (2026-09)",
)];

impl Scanner for PersistenceScanner {
    type Output = Vec<PersistenceArtifact>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<PersistenceArtifact> {
        let home = platform.home_dir();
        let mut out = Vec::new();

        // Python startup hooks in every site-packages root the package scanner knows
        // (system, user, project venvs, uv tools, pipx, agent venvs, uv pythons), each
        // listed once by its real path.
        for root in crate::scanners::python_packages::python_roots(platform) {
            scan_site_packages(&root.path, &mut out);
        }

        // Project-rooted shapes.
        let projects = platform
            .pass_scope()
            .with_cwd(crate::scanners::python_packages::project_dirs(&home.join(".claude.json")).unwrap_or_default());
        let mut seen_projects = std::collections::HashSet::new();
        let path_searches_cwd = path_searches_cwd(std::env::var_os("PATH").as_deref());
        for proj in projects {
            if !seen_projects.insert(proj.clone()) {
                continue;
            }
            scan_planted_binaries(&proj, path_searches_cwd, &mut out);
            scan_loader_staging(&proj, &mut out);
            scan_committed_symlinks(&proj, &home, &mut out);
            for (rel, campaign) in PROJECT_IOC_PATHS {
                let p = proj.join(rel);
                if crate::scanners::probe_exists(&p) {
                    out.push(ioc(&p, &proj, campaign, is_git_tracked(&p)));
                }
            }
        }

        // Known campaign artifacts under HOME and in /tmp.
        for (rel, campaign) in HOME_IOC_PATHS {
            let p = home.join(rel);
            if crate::scanners::probe_exists(&p) {
                out.push(ioc(&p, &home, campaign, false));
            }
        }
        for (abs, campaign) in ABS_IOC_PATHS {
            let p = PathBuf::from(abs);
            if crate::scanners::probe_exists(&p) {
                out.push(ioc(&p, Path::new("/"), campaign, false));
            }
        }

        // Agent launch surface and leftovers under the agent's own directories.
        scan_url_handlers(&home, &mut out);
        let claude = platform.claude_config_dir();
        scan_agent_bin(&claude.join("bin"), &home, &mut out);
        scan_dangling_plugin_records(&claude, &mut out);

        let mut seen = std::collections::HashSet::new();
        out.retain(|a| seen.insert((a.kind.clone(), a.path.clone())));
        out
    }
}

/// Program basenames of coding agents a URL scheme handler can launch.
const AGENT_PROGRAMS: &[&str] = &["claude", "codex", "cursor", "windsurf", "gemini", "vibe"];
/// Entries looked at per applications directory, and bytes read per `.desktop` file.
const MAX_DESKTOP_FILES: usize = 2_000;
const MAX_DESKTOP_BYTES: usize = 64 * 1024;

/// The `x-scheme-handler/<scheme>` types and the Exec program basename of a `.desktop`
/// file's `[Desktop Entry]` group (freedesktop Desktop Entry Specification).
pub fn desktop_scheme_handler(text: &str) -> (Vec<String>, Option<String>) {
    let mut in_entry = false;
    let (mut schemes, mut program) = (Vec::new(), None);
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry {
            continue;
        }
        if let Some(v) = line.strip_prefix("MimeType=") {
            schemes.extend(
                v.split(';')
                    .filter_map(|m| m.trim().strip_prefix("x-scheme-handler/"))
                    .filter(|s| !s.is_empty())
                    .map(|s| sanitize_display(s, 64)),
            );
        } else if let Some(v) = line.strip_prefix("Exec=") {
            let v = v.trim_start();
            let first = match v.strip_prefix('"') {
                Some(rest) => rest.split('"').next().unwrap_or(""),
                None => v.split_whitespace().next().unwrap_or(""),
            };
            let base = first.rsplit('/').next().unwrap_or(first);
            if !base.is_empty() {
                program = Some(sanitize_display(base, 64));
            }
        }
    }
    (schemes, program)
}

/// `x-scheme-handler/<scheme>=<desktop>` defaults from the user's `mimeapps.list` files.
fn default_scheme_handlers(home: &Path) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    for p in [
        home.join(".config").join("mimeapps.list"),
        home.join(".local/share/applications").join("mimeapps.list"),
    ] {
        let Some(text) = crate::scanners::read_bounded(&p) else {
            continue;
        };
        for line in text.lines() {
            if let Some((k, v)) = line.trim().split_once('=')
                && let Some(scheme) = k.strip_prefix("x-scheme-handler/")
            {
                let desktop = v.split(';').next().unwrap_or("").trim();
                out.entry(scheme.to_string()).or_insert_with(|| desktop.to_string());
            }
        }
    }
    out
}

/// Linux URL scheme handlers that launch a coding agent: a `.desktop` file in the user's
/// or the system's applications directory declaring `x-scheme-handler/claude-cli`, or
/// any `x-scheme-handler/*` whose Exec program is a known agent ([`AGENT_PROGRAMS`]).
/// Records the scheme and the program basename only. macOS registers handlers in the
/// LaunchServices database (a binary plist) and app bundles' Info.plist: not parsed.
fn scan_url_handlers(home: &Path, out: &mut Vec<PersistenceArtifact>) {
    let defaults = default_scheme_handlers(home);
    for dir in [
        home.join(".local/share/applications"),
        crate::scanners::system_path("/usr/share/applications"),
        crate::scanners::system_path("/usr/local/share/applications"),
    ] {
        let Ok(entries) = crate::scanners::probe_read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten().take(MAX_DESKTOP_FILES) {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("desktop") {
                continue;
            }
            let Some(bytes) = crate::scanners::read_head_bytes_nofollow(&path, MAX_DESKTOP_BYTES) else {
                continue;
            };
            let (schemes, program) = desktop_scheme_handler(&String::from_utf8_lossy(&bytes));
            let agent_program = program.as_deref().is_some_and(|p| AGENT_PROGRAMS.contains(&p));
            let file_name = entry.file_name().to_string_lossy().into_owned();
            for scheme in schemes.iter().filter(|s| *s == "claude-cli" || agent_program) {
                let is_default = defaults.get(scheme.as_str()).is_some_and(|d| *d == file_name);
                out.push(PersistenceArtifact {
                    kind: "url-handler".into(),
                    path: show(&path),
                    scope: show(&dir),
                    detail: format!(
                        "{scheme}:// opens {}{}",
                        program.as_deref().unwrap_or("an unnamed program"),
                        if is_default {
                            " (the default handler in mimeapps.list)"
                        } else {
                            ""
                        }
                    ),
                    sensitive_target: agent_program,
                    ..Default::default()
                });
            }
        }
    }
}

/// Entries looked at in the agent's bin directory, and the hashing bound.
const MAX_BIN_ENTRIES: usize = 200;
const MAX_HASH_BYTES: usize = 64 * 1024 * 1024;

/// Executables in `~/.claude/bin/`: Claude Code keeps plugins under plugins/cache, so a
/// file here was put by a plugin's script or by hand, is outside any plugin cache, and
/// survives the plugin's uninstall. Identity only: mode, owner, mtime, a 4-byte magic
/// read and a SHA-256.
fn scan_agent_bin(dir: &Path, home: &Path, out: &mut Vec<PersistenceArtifact>) {
    let Ok(entries) = crate::scanners::probe_read_dir(dir) else {
        return;
    };
    let mut files: Vec<PathBuf> = entries.flatten().take(MAX_BIN_ENTRIES).map(|e| e.path()).collect();
    files.sort();
    for path in files {
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_file() || !is_executable(&meta) {
            continue;
        }
        let info = agent_bin_info(&path, &meta);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        out.push(PersistenceArtifact {
            kind: "agent-bin".into(),
            path: show(&path),
            scope: show(home),
            detail: format!("{} ({}, {})", sanitize_display(&name, 128), info.format, info.mode),
            bin: Some(info),
            ..Default::default()
        });
    }
}

/// The identity of one regular file (`meta` from `symlink_metadata`): format from its first
/// four bytes, mode, owner, mtime, size and a SHA-256 (files up to the hashing bound), both
/// read without following a link. Shared by `~/.claude/bin` and the scripts settings
/// commands run (`scanners::settings_scripts`).
pub(crate) fn agent_bin_info(path: &Path, meta: &std::fs::Metadata) -> crate::models::AgentBinInfo {
    let magic = crate::scanners::read_head_bytes_nofollow(path, 4).unwrap_or_default();
    let format = match magic.as_slice() {
        [0x7f, b'E', b'L', b'F', ..] => "elf",
        [0xcf, 0xfa, 0xed, 0xfe, ..] | [0xfe, 0xed, 0xfa, 0xcf, ..] | [0xca, 0xfe, 0xba, 0xbe, ..] => "mach-o",
        [b'#', b'!', ..] => "script",
        _ => "other",
    };
    let sha256 = if meta.len() as usize <= MAX_HASH_BYTES {
        crate::scanners::read_head_bytes_nofollow(path, MAX_HASH_BYTES).map(|b| {
            use sha2::Digest;
            sha2::Sha256::digest(&b)
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect::<String>()
        })
    } else {
        None
    };
    let (mode, owned_by_user, world_writable) = owner_and_mode(meta);
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    crate::models::AgentBinInfo {
        format: format.into(),
        mode,
        mtime,
        size: meta.len(),
        sha256,
        owned_by_user,
        world_writable,
    }
}

#[cfg(unix)]
fn owner_and_mode(meta: &std::fs::Metadata) -> (String, bool, bool) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let m = meta.permissions().mode() & 0o7777;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    (format!("{m:04o}"), meta.uid() == me, m & 0o022 != 0)
}
#[cfg(not(unix))]
fn owner_and_mode(_meta: &std::fs::Metadata) -> (String, bool, bool) {
    (String::new(), true, false)
}

/// `installed_plugins.json` entries whose `installPath` does not exist. `sensitive_target`
/// marks a plugin `enabledPlugins` turns on in user settings (key and boolean only).
fn scan_dangling_plugin_records(claude: &Path, out: &mut Vec<PersistenceArtifact>) {
    let record = claude.join("plugins").join("installed_plugins.json");
    let Some(json) =
        crate::scanners::read_bounded(&record).and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
    else {
        return;
    };
    let enabled: std::collections::HashSet<String> = crate::scanners::read_bounded(&claude.join("settings.json"))
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|s| {
            s.get("enabledPlugins").and_then(|v| v.as_object()).map(|m| {
                m.iter()
                    .filter(|(_, v)| v.as_bool() == Some(true))
                    .map(|(k, _)| k.clone())
                    .collect()
            })
        })
        .unwrap_or_default();
    for ((plugin, market), entries) in crate::scanners::marketplaces::installed_entries(&json) {
        let key = format!("{plugin}@{market}");
        for e in entries {
            let Some(install) = e.get("installPath").and_then(|v| v.as_str()).filter(|s| !s.is_empty()) else {
                continue;
            };
            let install = Path::new(install);
            if crate::scanners::probe_exists(install) {
                continue;
            }
            let on = enabled.contains(&key);
            out.push(PersistenceArtifact {
                kind: "dangling-plugin-record".into(),
                path: show(install),
                scope: show(&record),
                detail: format!(
                    "{}; {}",
                    sanitize_display(&key, 200),
                    if on { "enabled in user settings" } else { "not enabled" }
                ),
                sensitive_target: on,
                ..Default::default()
            });
        }
    }
}

fn show(p: &Path) -> String {
    sanitize_display(&p.to_string_lossy(), 512)
}

fn ioc(path: &Path, scope: &Path, campaign: &str, git_tracked: bool) -> PersistenceArtifact {
    PersistenceArtifact {
        kind: "worm-ioc".into(),
        path: sanitize_display(&path.to_string_lossy(), 512),
        scope: sanitize_display(&scope.to_string_lossy(), 512),
        detail: campaign.to_string(),
        git_tracked,
        claimed: false,
        sensitive_target: false,
        bin: None,
    }
}

// ── Python startup hooks ──────────────────────────────────────────────────────

/// Walk one site-packages root for `.pth` import lines and `sitecustomize.py` /
/// `usercustomize.py`. RECORD files are read only if a hook candidate exists in the
/// root, so a clean machine pays nothing beyond the directory listing.
fn scan_site_packages(root: &Path, out: &mut Vec<PersistenceArtifact>) {
    let Ok(entries) = crate::scanners::probe_read_dir(root) else {
        return;
    };
    let mut candidates: Vec<(PathBuf, String, String)> = Vec::new(); // (path, kind, detail)
    let mut dist_infos: Vec<PathBuf> = Vec::new();
    let mut budget = MAX_ENTRIES_PER_ROOT;
    for entry in entries.flatten() {
        if budget == 0 {
            break;
        }
        budget -= 1;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
            continue;
        };
        let name = name.as_str();
        if name.ends_with(".dist-info") || name.ends_with(".egg-info") {
            dist_infos.push(path);
            continue;
        }
        let lower = name.to_ascii_lowercase();
        if lower == "sitecustomize.py" || lower == "usercustomize.py" {
            if crate::scanners::probe_file(&path) {
                candidates.push((
                    path,
                    "python-startup-hook".into(),
                    format!("{name}: runs on every interpreter start"),
                ));
            }
            continue;
        }
        if lower.ends_with(".pth") && crate::scanners::probe_file(&path) {
            if KNOWN_IMPORT_PTH.contains(&lower.as_str())
                || lower.starts_with("__editable__")
                || lower.ends_with("-nspkg.pth")
            {
                continue;
            }
            if let Some(line) = pth_import_line(&path) {
                candidates.push((path, "python-startup-hook".into(), format!("{name}: {line}")));
            }
        }
    }
    if candidates.is_empty() {
        return;
    }

    // Which root-level files do installed distributions claim? A hook nothing claims
    // was dropped by something other than an installer.
    let (claimed_names, all_records_readable) = claimed_root_files(&dist_infos);
    for (path, kind, detail) in candidates {
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        let lower = name.to_ascii_lowercase();
        let claimed = claimed_names.contains(&lower) || !all_records_readable;
        let is_ioc = IOC_STARTUP_NAMES.contains(&lower.as_str());
        out.push(PersistenceArtifact {
            kind,
            path: sanitize_display(&path.to_string_lossy(), 512),
            scope: sanitize_display(&root.to_string_lossy(), 512),
            detail: if is_ioc {
                format!(
                    "{} — file name published as an indicator of the litellm 1.107.0 implant",
                    sanitize_display(&detail, 300)
                )
            } else {
                sanitize_display(&detail, 300)
            },
            git_tracked: false,
            claimed,
            sensitive_target: is_ioc,
            bin: None,
        });
    }
}

/// The first executable line of a `.pth` file, or None if it only lists paths. The
/// site module executes any line that begins with `import` (space or tab); everything
/// else is a sys.path entry. Only the head is read.
pub fn pth_import_line(path: &Path) -> Option<String> {
    let head = read_head_bytes(path, 16 * 1024)?;
    let text = String::from_utf8_lossy(&head);
    pth_import_line_from(&text)
}

pub fn pth_import_line_from(text: &str) -> Option<String> {
    text.lines()
        .map(|l| l.trim_start_matches('\u{feff}'))
        .find(|l| l.starts_with("import ") || l.starts_with("import\t"))
        .map(|l| l.trim().chars().take(200).collect())
}

/// Root-level file names (lowercased) listed in every readable RECORD / installed-files
/// manifest, plus whether every manifest was readable. An unreadable manifest means we
/// cannot assert "unclaimed", so callers treat that as claimed (conservative).
fn claimed_root_files(dist_infos: &[PathBuf]) -> (std::collections::HashSet<String>, bool) {
    let mut names = std::collections::HashSet::new();
    let mut all_readable = true;
    for di in dist_infos {
        let record = if di.extension().is_some_and(|e| e == "dist-info") {
            di.join("RECORD")
        } else {
            di.join("installed-files.txt")
        };
        if !crate::scanners::probe_file(&record) {
            // A dist-info without RECORD (or a bare egg-info) claims nothing we can
            // verify; that is normal for egg-info and must not poison the verdict.
            continue;
        }
        let Some(bytes) = read_head_bytes(&record, MAX_RECORD_BYTES) else {
            all_readable = false;
            continue;
        };
        if bytes.len() >= MAX_RECORD_BYTES {
            all_readable = false; // truncated: the claimed set is incomplete
        }
        for line in String::from_utf8_lossy(&bytes).lines() {
            // RECORD: `path,hash,size`; installed-files.txt: `../path` relative to the
            // egg-info dir. Keep only names with no directory component.
            let p = line.split(',').next().unwrap_or("").trim();
            let p = p.strip_prefix("../").unwrap_or(p);
            if p.is_empty() || p.contains('/') || p.contains('\\') {
                continue;
            }
            names.insert(p.to_ascii_lowercase());
        }
    }
    (names, all_readable)
}

// ── Planted binaries ──────────────────────────────────────────────────────────

/// True if PATH would search the working directory: an empty entry or `.`.
pub fn path_searches_cwd(path: Option<&std::ffi::OsStr>) -> bool {
    let Some(path) = path else { return false };
    std::env::split_paths(path).any(|p| p.as_os_str().is_empty() || p == Path::new("."))
}

/// Does this file name shadow a tool an agent spawns? `git`, `git.exe`, `git.cmd`,
/// `npx.ps1`... The bare POSIX name only counts when the file is executable; a Windows
/// extension counts on any host, because the repo is what carries it.
pub fn shadowed_tool(file_name: &str, executable: bool) -> Option<&'static str> {
    let lower = file_name.to_ascii_lowercase();
    if let Some((stem, ext)) = lower.rsplit_once('.')
        && WINDOWS_EXEC_EXTS.contains(&ext)
    {
        return SHADOWABLE_TOOLS.iter().copied().find(|t| *t == stem);
    }
    if executable {
        return SHADOWABLE_TOOLS.iter().copied().find(|t| *t == lower);
    }
    None
}

fn scan_planted_binaries(proj: &Path, path_searches_cwd: bool, out: &mut Vec<PersistenceArtifact>) {
    // The root and the directories an IDE or agent treats as its own.
    let dirs = [
        proj.to_path_buf(),
        proj.join(".vscode"),
        proj.join(".claude"),
        proj.join(".cursor"),
    ];
    for dir in dirs {
        let Ok(entries) = crate::scanners::probe_read_dir(&dir) else {
            continue;
        };
        let mut budget = MAX_ENTRIES_PER_ROOT;
        for entry in entries.flatten() {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let path = entry.path();
            // A symlink named `git` is the same trap; metadata() follows it so an
            // executable target still counts, but a directory never does.
            let Ok(meta) = std::fs::metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let executable = is_executable(&meta);
            let Some(tool) = shadowed_tool(name, executable) else {
                continue;
            };
            let git_tracked = is_git_tracked(&path);
            let mut detail = format!("shadows `{tool}`");
            if path_searches_cwd {
                detail.push_str("; PATH searches the working directory on this host");
            }
            out.push(PersistenceArtifact {
                kind: "planted-binary".into(),
                path: sanitize_display(&path.to_string_lossy(), 512),
                scope: sanitize_display(&proj.to_string_lossy(), 512),
                detail,
                git_tracked,
                claimed: false,
                sensitive_target: path_searches_cwd,
                bin: None,
            });
        }
    }
}

#[cfg(unix)]
fn is_executable(meta: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}
#[cfg(not(unix))]
fn is_executable(_meta: &std::fs::Metadata) -> bool {
    true
}

// ── Loader staging in agent directories ───────────────────────────────────────

/// A JavaScript file directly inside `.vscode/` or `.claude/` of a project. Both
/// directories hold configuration (JSON, Markdown, subdirectories of scripts); a bare
/// `.mjs` at the top level is the worm's loader, re-launched by the `tasks.json` /
/// `settings.json` persistence pair. Shell scripts are deliberately not included: a
/// `.claude/statusline.sh` is ordinary.
fn scan_loader_staging(proj: &Path, out: &mut Vec<PersistenceArtifact>) {
    for agent_dir in [".vscode", ".claude", ".cursor", ".codex", ".gemini"] {
        let dir = proj.join(agent_dir);
        let Ok(entries) = crate::scanners::probe_read_dir(&dir) else {
            continue;
        };
        let mut budget = MAX_ENTRIES_PER_ROOT;
        for entry in entries.flatten() {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let path = entry.path();
            if !crate::scanners::probe_file(&path) {
                continue;
            }
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let lower = name.to_ascii_lowercase();
            if !(lower.ends_with(".mjs") || lower.ends_with(".cjs") || lower.ends_with(".js")) {
                continue;
            }
            let known_loader = matches!(
                lower.as_str(),
                "setup.mjs" | "setup.js" | "setup.cjs" | "math_symbol.js"
            );
            out.push(PersistenceArtifact {
                kind: "loader-script".into(),
                path: sanitize_display(&path.to_string_lossy(), 512),
                scope: sanitize_display(&proj.to_string_lossy(), 512),
                detail: if known_loader {
                    format!("{agent_dir}/{name} — the ChainDrop/tensorlake loader name")
                } else {
                    format!("JavaScript staged directly in {agent_dir}/")
                },
                git_tracked: is_git_tracked(&path),
                claimed: false,
                sensitive_target: known_loader,
                bin: None,
            });
        }
    }
}

// ── Committed symlinks that escape the repository ─────────────────────────────

/// `git ls-files -s` lists every tracked entry with its mode; mode 120000 is a symlink.
/// The link target is what git stores, so a clone reproduces it byte for byte. We
/// resolve the target lexically against the link's directory and ask whether it stays
/// inside the repository; an absolute target or one that climbs out is the trap.
fn scan_committed_symlinks(proj: &Path, home: &Path, out: &mut Vec<PersistenceArtifact>) {
    if !crate::scanners::probe_dir(&proj.join(".git")) {
        return;
    }
    let mut cmd = crate::scanners::hardened_git();
    cmd.args(["ls-files", "-s", "-z"]).current_dir(proj);
    let Some(output) = crate::scanners::output_with_timeout(&mut cmd, GIT_TIMEOUT) else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut budget = MAX_SYMLINKS_PER_REPO;
    for rec in text.split('\0') {
        // `<mode> <object> <stage>\t<path>`
        let Some((meta, rel)) = rec.split_once('\t') else {
            continue;
        };
        if !meta.starts_with("120000 ") {
            continue;
        }
        if budget == 0 {
            break;
        }
        budget -= 1;
        let link = proj.join(rel);
        let Ok(target) = std::fs::read_link(&link) else {
            continue;
        };
        let Some(verdict) = symlink_escapes(proj, &link, &target, home) else {
            continue;
        };
        out.push(PersistenceArtifact {
            kind: "escaping-symlink".into(),
            path: sanitize_display(&link.to_string_lossy(), 512),
            scope: sanitize_display(&proj.to_string_lossy(), 512),
            detail: format!("-> {}", sanitize_display(&target.to_string_lossy(), 300)),
            git_tracked: true,
            claimed: false,
            sensitive_target: verdict,
            bin: None,
        });
    }
}

/// None if the target stays inside the repo; Some(sensitive) if it escapes, where
/// `sensitive` says the resolved target is a credential, shell-rc or agent-config path.
pub fn symlink_escapes(repo: &Path, link: &Path, target: &Path, home: &Path) -> Option<bool> {
    let base = link.parent().unwrap_or(repo);
    let resolved = lexical_join(base, target);
    let repo_norm = lexical_join(repo, Path::new(""));
    if resolved.starts_with(&repo_norm) {
        return None;
    }
    Some(is_sensitive_target(&resolved, home))
}

/// Join and normalise `.`/`..` lexically (no filesystem access, so a dangling or
/// looping link is still classified).
pub(crate) fn lexical_join(base: &Path, target: &Path) -> PathBuf {
    let start: PathBuf = if target.is_absolute() {
        PathBuf::new()
    } else {
        base.to_path_buf()
    };
    let mut parts: Vec<std::ffi::OsString> = Vec::new();
    let mut absolute = false;
    for comp in start.components().chain(target.components()) {
        use std::path::Component;
        match comp {
            Component::RootDir => {
                absolute = true;
                parts.clear();
            }
            Component::CurDir | Component::Prefix(_) => {}
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(s) => parts.push(s.to_os_string()),
        }
    }
    let mut out = if absolute { PathBuf::from("/") } else { PathBuf::new() };
    for p in parts {
        out.push(p);
    }
    out
}

fn is_sensitive_target(resolved: &Path, home: &Path) -> bool {
    if resolved.starts_with("/etc") {
        return true;
    }
    let Ok(rel) = resolved.strip_prefix(home) else {
        return false;
    };
    let mut comps = rel.components();
    let first = comps.next().and_then(|c| c.as_os_str().to_str()).unwrap_or("");
    if SENSITIVE_TARGET_DIRS.contains(&first) || SENSITIVE_TARGET_FILES.contains(&first) {
        return true;
    }
    resolved
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| SENSITIVE_TARGET_FILES.contains(&n))
}

/// HOME-relative paths (directories or files) whose content must never be read through a
/// link: keys, credential stores, keyrings, browser profiles and agent homes. Narrower
/// than SENSITIVE_TARGET_DIRS where that matters for reading: `~/.config` as a whole is
/// the XDG location of ordinary dotfiles, so only its known credential subpaths are here.
const SENSITIVE_READ_PATHS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".password-store",
    ".pki",
    ".oci",
    ".terraform.d",
    ".gem/credentials",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".vault-token",
    ".netrc",
    ".pgpass",
    ".my.cnf",
    ".git-credentials",
    ".npmrc",
    ".pypirc",
    ".yarnrc.yml",
    ".local/share/keyrings",
    ".local/share/fish",
    ".mozilla",
    ".thunderbird",
    ".config/gcloud",
    ".config/gh",
    ".config/hub",
    ".config/op",
    ".config/sops",
    ".config/rclone",
    ".config/containers",
    ".config/git/credentials",
    ".config/google-chrome",
    ".config/chromium",
    ".config/BraveSoftware",
    ".config/doctl",
    ".config/Bitwarden CLI",
    ".config/fish/config.fish",
    ".config/github-copilot",
    ".config/claude",
    "Library/Keychains",
    "Library/Cookies",
    "Library/Application Support/Google/Chrome",
    ".claude",
    ".claude.json",
    ".codex",
    ".gemini",
    ".cursor",
    ".kiro",
    ".cache/huggingface",
    ".huggingface",
    ".config/glab-cli",
    ".s3cfg",
    ".authinfo",
    ".authinfo.gpg",
    ".boto",
    ".databrickscfg",
    ".config/configstore",
    ".copilot",
    ".codeium",
    ".config/devin",
    ".config/opencode",
];
/// File names that are sensitive wherever they sit, inside HOME or not, inside a
/// repository or a plugin or not: shell rc and history files, credential dotfiles,
/// authorized_keys. `.env`/`.env.*`, SSH private keys and key/certificate extensions are
/// matched in [`is_sensitive_read_name`].
const SENSITIVE_READ_NAMES: &[&str] = &[
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".profile",
    ".bash_history",
    ".zsh_history",
    ".python_history",
    ".psql_history",
    ".mysql_history",
    ".node_repl_history",
    ".sqlite_history",
    ".lesshst",
    ".viminfo",
    "authorized_keys",
    ".netrc",
    "_netrc",
    ".pgpass",
    ".git-credentials",
    ".vault-token",
    ".s3cfg",
    ".authinfo",
    ".authinfo.gpg",
    ".boto",
    ".databrickscfg",
    ".npmrc",
    ".pypirc",
    ".htpasswd",
    ".my.cnf",
    "credentials",
    "credentials.json",
    "credentials.toml",
];
/// Extensions of key, certificate and keystore files.
const SENSITIVE_READ_EXTS: &[&str] = &[
    "pem", "key", "p12", "pfx", "keystore", "jks", "ppk", "kdbx", "gpg", "asc",
];
/// True when the FILE NAME alone marks a path as unreadable through a link, wherever it
/// sits: a `.env`/`.env.*`, a shell rc or history file, a credential dotfile, an SSH
/// private key (`id_rsa`, `id_ed25519`, ... but not `*.pub`), or a key/certificate/
/// keystore extension. Unlike the HOME and system-tree rules this applies inside a
/// repository, a plugin and the skill areas too: a project outside HOME linking SKILL.md
/// to its own `.env.production` is refused like one under HOME.
pub(crate) fn is_sensitive_read_name(resolved: &Path) -> bool {
    let Some(n) = resolved.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if SENSITIVE_READ_NAMES.contains(&n) || n == ".env" || n.starts_with(".env.") {
        return true;
    }
    if n.starts_with("id_") && !n.ends_with(".pub") && !n.contains('.') {
        return true;
    }
    resolved
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SENSITIVE_READ_EXTS.iter().any(|x| e.eq_ignore_ascii_case(x)))
}

/// Agent credential and state files kept inside an agent home, as (agent directory,
/// file name): the OpenAI key and OAuth tokens of Codex (`auth.json`,
/// learn.chatgpt.com/docs/auth), Gemini CLI's OAuth credentials and account list,
/// Claude Code's Linux credential store, and Copilot CLI's config (its OAuth token).
const AGENT_CREDENTIAL_FILES: &[(&str, &str)] = &[
    (".codex", "auth.json"),
    (".gemini", "oauth_creds.json"),
    (".gemini", "google_accounts.json"),
    (".claude", ".credentials.json"),
    (".copilot", "config.json"),
];

/// Whether `p` is an agent's credential or state file ([`AGENT_CREDENTIAL_FILES`], or
/// anything under `.copilot/mcp-oauth-config/`), judged lexically on its last
/// components. With `agent_home` (the directory the file was found in, lexical or
/// canonical, for a relocated home such as `CODEX_HOME`), a credential file name directly
/// inside it counts too. Never opened through a link, even inside the agent's own home.
pub(crate) fn is_agent_credential_path(p: &Path, agent_home: Option<&Path>) -> bool {
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let parent = p.parent();
    let parent_name = parent
        .and_then(|d| d.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");
    if AGENT_CREDENTIAL_FILES
        .iter()
        .any(|(d, f)| *d == parent_name && *f == name)
    {
        return true;
    }
    let comps: Vec<&std::ffi::OsStr> = p.components().map(|c| c.as_os_str()).collect();
    if comps
        .windows(2)
        .any(|w| w[0] == ".copilot" && w[1] == "mcp-oauth-config")
    {
        return true;
    }
    // `config.json` is left to the `.copilot` pair: Devin CLI's own hook file is a
    // `config.json` directly in its home.
    agent_home.is_some_and(|h| {
        parent == Some(h) && name != "config.json" && AGENT_CREDENTIAL_FILES.iter().any(|(_, f)| *f == name)
    })
}

/// Trees outside HOME that hold system configuration, process state or other users' data.
pub(crate) const SENSITIVE_SYSTEM_ROOTS: &[&str] = &[
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/root",
    "/var",
    "/private",
    "/run",
    "/boot",
    "/Library/Keychains",
];

/// True when a resolved path must not be READ through a link: a credential, key,
/// keyring, shell-rc/history, `.env` or agent-settings path under HOME, another user's
/// home, or a system tree (/etc, /proc, /sys, /root, /var, ...). Paths under HOME are
/// judged only by the HOME rules, so a HOME that itself lives under /var (macOS temp
/// homes) is not refused wholesale.
pub(crate) fn is_sensitive_read_target(resolved: &Path, home: &Path) -> bool {
    if is_sensitive_read_name(resolved) {
        return true;
    }
    if let Ok(rel) = resolved.strip_prefix(home) {
        return SENSITIVE_READ_PATHS.iter().any(|p| rel.starts_with(p));
    }
    if SENSITIVE_SYSTEM_ROOTS.iter().any(|r| resolved.starts_with(r)) {
        return true;
    }
    // Another user's home directory.
    ["/home", "/Users"].iter().any(|b| resolved.starts_with(b))
}

/// HOME-relative agent homes in SENSITIVE_READ_PATHS: agent configuration rather than a
/// credential store (their credential files are judged by name).
const AGENT_CONFIG_READ_PATHS: &[&str] = &[
    ".claude",
    ".claude.json",
    ".codex",
    ".gemini",
    ".cursor",
    ".kiro",
    ".config/claude",
    ".copilot",
    ".codeium",
    ".config/devin",
    ".config/opencode",
];

/// Why [`is_sensitive_read_target`] refuses `resolved`, for wording and grading:
/// `"credential"` (a credential, key, `.env` or shell-rc/history name, or a credential
/// store under HOME), `"agent-config"` (an agent home such as `~/.claude`),
/// `"other-home"` (another user's home) or `"system"` (/etc, /var, /run, ...). None when
/// it is not refused.
pub(crate) fn sensitive_read_kind(resolved: &Path, home: &Path) -> Option<&'static str> {
    if is_sensitive_read_name(resolved) {
        return Some("credential");
    }
    if let Ok(rel) = resolved.strip_prefix(home) {
        if AGENT_CONFIG_READ_PATHS.iter().any(|p| rel.starts_with(p)) {
            return Some("agent-config");
        }
        return SENSITIVE_READ_PATHS
            .iter()
            .any(|p| rel.starts_with(p))
            .then_some("credential");
    }
    sensitive_read_kind_outside_home(resolved)
}

/// [`sensitive_read_kind`] for a path judged under no home: a credential name, a system
/// tree (`"system"`) or another user's home (`"other-home"`).
pub(crate) fn sensitive_read_kind_outside_home(resolved: &Path) -> Option<&'static str> {
    if is_sensitive_read_name(resolved) {
        return Some("credential");
    }
    if SENSITIVE_SYSTEM_ROOTS.iter().any(|r| resolved.starts_with(r)) {
        return Some("system");
    }
    ["/home", "/Users"]
        .iter()
        .any(|b| resolved.starts_with(b))
        .then_some("other-home")
}

/// The most specific of several [`sensitive_read_kind`] verdicts: credential, then
/// agent-config, other-home, system.
pub(crate) fn worst_read_kind(kinds: impl IntoIterator<Item = Option<&'static str>>) -> Option<&'static str> {
    let rank = |k: &str| match k {
        "credential" => 3,
        "agent-config" => 2,
        "other-home" => 1,
        _ => 0,
    };
    kinds.into_iter().flatten().max_by_key(|k| rank(k))
}

#[cfg(test)]
mod tests {

    /// The `[Desktop Entry]` group's scheme handlers and Exec program basename; other
    /// groups (desktop actions) are ignored.
    #[test]
    fn desktop_scheme_handler_reads_schemes_and_program() {
        let (schemes, prog) = desktop_scheme_handler(
            "[Desktop Entry]\nExec=\"~/.local/bin/claude\" --handle-uri %u\nMimeType=x-scheme-handler/claude-cli;text/plain;\n[Desktop Action new]\nExec=evil\nMimeType=x-scheme-handler/evil;\n",
        );
        assert_eq!(schemes, ["claude-cli"]);
        assert_eq!(prog.as_deref(), Some("claude"));
        let (schemes, prog) =
            desktop_scheme_handler("[Desktop Entry]\nExec=/opt/codex/bin/codex %U\nMimeType=x-scheme-handler/codex\n");
        assert_eq!(schemes, ["codex"]);
        assert_eq!(prog.as_deref(), Some("codex"));
        assert_eq!(
            desktop_scheme_handler("Exec=claude\nMimeType=x-scheme-handler/claude-cli;")
                .0
                .len(),
            0
        );
    }

    use super::*;

    #[test]
    fn sensitive_read_targets() {
        let home = Path::new("/home/u");
        for p in [
            "/home/u/.ssh/id_ed25519",
            "/home/u/.netrc",
            "/home/u/.pgpass",
            "/home/u/.vault-token",
            "/home/u/.password-store/x.gpg",
            "/home/u/.local/share/keyrings/login.keyring",
            "/home/u/.config/gcloud/credentials.db",
            "/home/u/.config/gh/hosts.yml",
            "/home/u/.zsh_history",
            "/home/u/proj/.env",
            "/home/u/.claude/settings.json",
            "/proc/self/environ",
            "/sys/kernel/x",
            "/root/.bashrc",
            "/home/other/notes.md",
            "/etc/shadow",
            "/var/lib/x",
            // File-name rules apply outside HOME too (a project under /datar or /srv).
            "/srv/proj/.env.production",
            "/datar/w/app/.env",
            "/opt/x/id_ed25519",
            "/srv/p/certs/tls.key",
            "/home/u/.cache/huggingface/token",
            "/home/u/.config/glab-cli/config.yml",
            "/home/u/.s3cfg",
            "/home/u/.authinfo",
            "/home/u/.boto",
            "/home/u/.databrickscfg",
            "/home/u/.config/configstore/x.json",
        ] {
            assert!(is_sensitive_read_target(Path::new(p), home), "{p}");
        }
        for p in [
            "/home/u/.config/dotfiles/skills/x/SKILL.md",
            "/home/u/dotfiles/SKILL.md",
            "/home/u/Documents/notes.md",
            "/nix/store/abc-skill/SKILL.md",
            "/tmp/x",
            "/srv/proj/docs/env.md",
            "/home/u/.ssh-notes.md",
            "/opt/x/id_ed25519.pub",
        ] {
            assert!(!is_sensitive_read_target(Path::new(p), home), "{p}");
        }
        // The kind agrees with the verdict and names it honestly.
        for p in [
            "/home/u/.ssh/id_ed25519",
            "/home/u/.config/gh/hosts.yml",
            "/srv/proj/.env.production",
            "/home/u/.zshrc",
        ] {
            assert_eq!(sensitive_read_kind(Path::new(p), home), Some("credential"), "{p}");
        }
        assert_eq!(
            sensitive_read_kind(Path::new("/home/u/.claude/skills-archive/x/SKILL.md"), home),
            Some("agent-config")
        );
        // Agent credential and state files (review of 4e3f8c3), by their agent directory
        // or, for a relocated home, directly inside it.
        for p in [
            "/home/u/.codex/auth.json",
            "/home/u/.gemini/oauth_creds.json",
            "/home/u/.gemini/google_accounts.json",
            "/home/u/.claude/.credentials.json",
            "/home/u/.copilot/config.json",
            "/home/u/.copilot/mcp-oauth-config/x.json",
        ] {
            assert!(is_agent_credential_path(Path::new(p), None), "{p}");
        }
        assert!(is_agent_credential_path(
            Path::new("/srv/codex-home/auth.json"),
            Some(Path::new("/srv/codex-home"))
        ));
        for p in [
            "/home/u/.codex/hooks.json",
            "/home/u/.gemini/settings.json",
            "/home/u/.copilot/settings.json",
            "/home/u/proj/auth.json",
        ] {
            assert!(!is_agent_credential_path(Path::new(p), None), "{p}");
        }
        assert!(!is_agent_credential_path(
            Path::new("/home/u/.config/devin/config.json"),
            Some(Path::new("/home/u/.config/devin"))
        ));
        assert_eq!(
            sensitive_read_kind(Path::new("/var/tmp/x/SKILL.md"), home),
            Some("system")
        );
        assert_eq!(
            sensitive_read_kind(Path::new("/home/other/notes.md"), home),
            Some("other-home")
        );
        assert_eq!(sensitive_read_kind(Path::new("/home/u/dotfiles/SKILL.md"), home), None);
        assert_eq!(
            worst_read_kind([Some("system"), None, Some("credential")]),
            Some("credential")
        );
        // A home under /var is judged by the HOME rules only.
        let mac = Path::new("/private/var/folders/x/T/h");
        assert!(!is_sensitive_read_target(&mac.join("dotfiles/a.md"), mac));
        assert!(is_sensitive_read_target(&mac.join(".ssh/id_rsa"), mac));
    }

    #[test]
    fn pth_import_detection_ignores_path_lines() {
        assert_eq!(pth_import_line_from("/usr/lib/python3/dist-packages\n"), None);
        assert_eq!(
            pth_import_line_from("\u{feff}import cook\n").as_deref(),
            Some("import cook")
        );
        assert_eq!(
            pth_import_line_from("# comment\nimport\tsys; sys.x = 1\n").as_deref(),
            Some("import\tsys; sys.x = 1")
        );
        assert_eq!(
            pth_import_line_from("importantpath/\n"),
            None,
            "a path that starts with 'import' is not an import"
        );
    }

    #[test]
    fn shadowed_tool_names() {
        assert_eq!(shadowed_tool("git", true), Some("git"));
        assert_eq!(
            shadowed_tool("git", false),
            None,
            "a non-executable 'git' file is not a trap"
        );
        assert_eq!(
            shadowed_tool("git.exe", false),
            Some("git"),
            "a Windows binary counts on any host"
        );
        assert_eq!(shadowed_tool("NPX.CMD", false), Some("npx"));
        assert_eq!(shadowed_tool("gitignore", true), None);
        assert_eq!(shadowed_tool("git.py", true), None);
        assert_eq!(shadowed_tool("README", true), None);
    }

    #[test]
    fn path_cwd_detection() {
        use std::ffi::OsStr;
        assert!(!path_searches_cwd(Some(OsStr::new("/usr/bin:/bin"))));
        assert!(path_searches_cwd(Some(OsStr::new("/usr/bin::/bin"))));
        assert!(path_searches_cwd(Some(OsStr::new(".:/usr/bin"))));
        assert!(path_searches_cwd(Some(OsStr::new("/usr/bin:"))));
        assert!(!path_searches_cwd(None));
    }

    #[test]
    fn symlink_escape_classification() {
        let repo = Path::new("/home/u/proj");
        let home = Path::new("/home/u");
        let link = repo.join("config/settings.json");
        assert_eq!(symlink_escapes(repo, &link, Path::new("../other.json"), home), None);
        assert_eq!(symlink_escapes(repo, &link, Path::new("./sub/../x"), home), None);
        assert_eq!(
            symlink_escapes(repo, &link, Path::new("../../.ssh/authorized_keys"), home),
            Some(true)
        );
        assert_eq!(
            symlink_escapes(repo, &link, Path::new("/home/u/.zshrc"), home),
            Some(true)
        );
        assert_eq!(
            symlink_escapes(repo, &link, Path::new("/home/u/.claude/settings.json"), home),
            Some(true)
        );
        assert_eq!(symlink_escapes(repo, &link, Path::new("/etc/hosts"), home), Some(true));
        assert_eq!(
            symlink_escapes(repo, &link, Path::new("/home/u/Documents/notes.md"), home),
            Some(false)
        );
        assert_eq!(
            symlink_escapes(repo, &link, Path::new("../../proj-sibling/x"), home),
            Some(false)
        );
        // Climbing out and back in is still inside.
        assert_eq!(symlink_escapes(repo, &link, Path::new("../../proj/README"), home), None);
        // A prefix-sharing sibling is outside.
        assert_eq!(
            symlink_escapes(repo, &link, Path::new("../../proj2/README"), home),
            Some(false)
        );
        // The committed-symlink grading keeps its own (narrower) sensitive list: a shared
        // data path under /var, /run or another user's home escapes the repository (High)
        // but is not a credential or agent-config path (Critical). The skills read-refusal
        // list (is_sensitive_read_target) is broader and is not used here.
        for p in [
            "/var/tmp/shared/x",
            "/run/user/1000/x",
            "/home/other/shared/x",
            "/Users/Shared/x",
        ] {
            assert_eq!(symlink_escapes(repo, &link, Path::new(p), home), Some(false), "{p}");
        }
    }
}
