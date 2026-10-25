//! What Playwright MCP leaves behind (github.com/microsoft/playwright-mcp, README fetched
//! 2026-10-24).
//!
//! - **Persistent browser profiles.** "You can run Playwright MCP with persistent profile
//!   like a regular browser (default)". The README puts the profile at
//!   `~/.cache/ms-playwright/mcp-{channel}-{workspace-hash}` on Linux and
//!   `~/Library/Caches/ms-playwright/mcp-{channel}-{workspace-hash}` on macOS.
//!   `--isolated` keeps it "in memory, do not save it to disk", and `--user-data-dir`
//!   moves it.
//!
//!   @playwright/mcp 0.0.83 (playwright-core 1.64 `coreBundle.js`) writes under
//!   `ms-playwright-mcp/` instead, so both directories are looked at. Each profile
//!   holds the browser's cookie and saved-login stores. These are recorded by
//!   existence, mode, size and modification time only, and never opened.
//!   Reachability follows the transcript-store rule: o+r on the file, o+x on every
//!   directory from the profile root down, and no untraversable ancestor
//!   ([`crate::scanners::transcripts::untraversable_ancestor`]).
//! - **Output directories.** `--output-dir` is the "path to the directory for
//!   automatically named output files". The README gives no default. The 0.0.83 code
//!   uses `<cwd>/.playwright-mcp` (page snapshots, console logs, screenshots), the
//!   directory found inside projects. Files are counted, never read. Tracked state
//!   comes from the scan's once-per-repository `git ls-files` listing, and the ignore
//!   state from one hardened `git check-ignore` per directory.
//!
//! Floors:
//! - a profile moved with `--user-data-dir` or `XDG_CACHE_HOME`, and an output
//!   directory moved with `--output-dir`, are not found;
//! - Firefox and WebKit profiles are matched by the same file names, not by their own
//!   layouts.

use crate::models::{AgentBrowserProfiles, AgentOutputDir};
use crate::platform::PlatformInfo;
use crate::scanners::sanitize_display;
use std::path::{Path, PathBuf};

/// What the `playwright` job stores.
pub enum PlaywrightOut {
    Profiles(AgentBrowserProfiles),
    OutputDir(AgentOutputDir),
}

/// Profile parents, relative to HOME.
const PROFILE_PARENTS: &[&str] = &[
    ".cache/ms-playwright-mcp",
    ".cache/ms-playwright",
    "Library/Caches/ms-playwright-mcp",
    "Library/Caches/ms-playwright",
];
/// Cookie and saved-login stores inside one profile directory (Chromium `Default/`,
/// Chromium's newer `Default/Network/Cookies`, Firefox's root files). Never opened.
const LOGIN_FILES: &[&str] = &[
    "Default/Cookies",
    "Default/Network/Cookies",
    "Default/Login Data",
    "Default/Login Data For Account",
    "cookies.sqlite",
    "logins.json",
];
/// Profiles looked at per parent.
const MAX_PROFILES: usize = 500;
/// Files counted per output directory, at the base walk budget; levels below it.
const BASE_OUTPUT_FILES: usize = 5_000;
const OUTPUT_DEPTH: usize = 3;

/// The `playwright` job for one home.
pub fn scan_home(platform: &dyn PlatformInfo) -> Vec<PlaywrightOut> {
    let home = platform.home_dir();
    let mut out: Vec<PlaywrightOut> = browser_profiles(&home)
        .into_iter()
        .map(PlaywrightOut::Profiles)
        .collect();
    let registered = crate::scanners::python_packages::project_dirs(&home.join(".claude.json")).unwrap_or_default();
    let scope = platform.pass_scope();
    let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let own_home = real(&home);
    let mut seen = std::collections::HashSet::new();
    // Every project of this pass; this pass's own home too when it is one (Claude Code run
    // in `~` writes `~/.playwright-mcp`), as the MCP scanner reads `~/.mcp.json`.
    for proj in scope.with_cwd(registered) {
        if real(&proj) != own_home && scope.is_scan_home_or_ancestor(&proj) {
            continue;
        }
        if !seen.insert(real(&proj)) {
            continue;
        }
        if let Some(d) = output_dir(&proj.join(".playwright-mcp")) {
            out.push(PlaywrightOut::OutputDir(d));
        }
    }
    out
}

#[cfg(unix)]
fn other_bits(meta: &std::fs::Metadata) -> (bool, bool) {
    use std::os::unix::fs::PermissionsExt;
    let m = meta.permissions().mode();
    (m & 0o004 != 0, m & 0o001 != 0)
}
#[cfg(not(unix))]
fn other_bits(_meta: &std::fs::Metadata) -> (bool, bool) {
    (false, false)
}

/// One row per profile parent of `home` that holds at least one `mcp-*` profile.
pub fn browser_profiles(home: &Path) -> Vec<AgentBrowserProfiles> {
    let mut out = Vec::new();
    for rel in PROFILE_PARENTS {
        let parent = home.join(rel);
        let Ok(meta) = std::fs::symlink_metadata(&parent) else {
            crate::scanners::telemetry::note_probe(&parent, false);
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        crate::scanners::telemetry::note_probe(&parent, true);
        let Ok(rd) = crate::scanners::probe_read_dir(&parent) else {
            continue;
        };
        let mut profiles: Vec<PathBuf> = rd
            .flatten()
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter(|e| e.file_name().to_str().is_some_and(|n| n.starts_with("mcp-")))
            .map(|e| e.path())
            .collect();
        profiles.sort();
        if profiles.len() > MAX_PROFILES {
            profiles.truncate(MAX_PROFILES);
            crate::scanners::telemetry::mark_truncated();
        }
        if profiles.is_empty() {
            continue;
        }
        let parent_x = other_bits(&meta).1;
        let mut row = AgentBrowserProfiles {
            framework: "playwright-mcp".into(),
            path: sanitize_display(&parent.to_string_lossy(), 512),
            profile_count: profiles.len(),
            mode: crate::scanners::file_perms(&parent).map(|(m, _, _)| m),
            unreachable_via: crate::scanners::transcripts::untraversable_ancestor(&parent),
            ..Default::default()
        };
        for p in &profiles {
            let mut any = false;
            for f in LOGIN_FILES {
                let file = p.join(f);
                let Ok(fm) = std::fs::symlink_metadata(&file) else {
                    continue;
                };
                if !fm.is_file() {
                    continue;
                }
                any = true;
                row.login_files += 1;
                let mtime = fm
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64);
                if let Some(t) = mtime {
                    row.newest_login_mtime = Some(row.newest_login_mtime.map_or(t, |n| n.max(t)));
                }
                if parent_x && other_bits(&fm).0 && dirs_traversable(&parent, &file) {
                    row.readable_login_files += 1;
                }
            }
            if any {
                row.login_profiles += 1;
            }
        }
        out.push(row);
    }
    out
}

/// Every directory strictly between `root` and `file` has o+x (mode bits, no link followed).
fn dirs_traversable(root: &Path, file: &Path) -> bool {
    let Some(mut d) = file.parent() else {
        return false;
    };
    while d != root {
        match std::fs::symlink_metadata(d) {
            Ok(m) if m.is_dir() && other_bits(&m).1 => {}
            _ => return false,
        }
        match d.parent() {
            Some(p) => d = p,
            None => return false,
        }
    }
    true
}

/// The output directory at `dir` (a real directory, not a link), with its files counted.
pub fn output_dir(dir: &Path) -> Option<AgentOutputDir> {
    let present = std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir());
    crate::scanners::telemetry::note_probe(dir, present);
    if !present {
        return None;
    }
    let cap = crate::scanners::telemetry::walk_cap(BASE_OUTPUT_FILES, crate::scanners::telemetry::walk_budget());
    let mut files = Vec::new();
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    'walk: while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = crate::scanners::probe_read_dir(&d) else {
            continue;
        };
        let mut entries: Vec<(PathBuf, std::fs::FileType)> = rd
            .flatten()
            .filter_map(|e| Some((e.path(), e.file_type().ok()?)))
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (p, t) in entries {
            if t.is_dir() {
                if depth < OUTPUT_DEPTH {
                    stack.push((p, depth + 1));
                }
            } else if t.is_file() {
                if files.len() >= cap {
                    crate::scanners::telemetry::mark_truncated();
                    break 'walk;
                }
                files.push(p);
            }
        }
    }
    files.sort();
    let in_repo = crate::scanners::git_work_tree_of(dir).is_some();
    let mut tracked = 0usize;
    let mut first_untracked: Option<&PathBuf> = None;
    for f in &files {
        if in_repo && crate::scanners::git_tracked_state(f) == Some(true) {
            tracked += 1;
        } else if first_untracked.is_none() {
            first_untracked = Some(f);
        }
    }
    let ignored = match first_untracked {
        Some(f) if in_repo => crate::scanners::git_check_ignored(f),
        _ => None,
    };
    Some(AgentOutputDir {
        framework: "playwright-mcp".into(),
        path: sanitize_display(&dir.to_string_lossy(), 512),
        file_count: files.len(),
        tracked_files: tracked,
        in_repo,
        ignored,
    })
}
