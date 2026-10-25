//! What is running now, as opposed to what is installed. There are two signals.
//!
//! - **Plugin versions in use.** Claude Code keeps every plugin version it fetched under
//!   `~/.claude/plugins/cache/<marketplace>/<plugin>/<version>/`. A version that a live
//!   session has loaded holds `.in_use/<pid>` entries. This is an OBSERVED signal and
//!   is not documented. The plugin docs (code.claude.com/docs/en/plugins/loading.md,
//!   fetched 2026-10-24) describe only the `.orphaned_at` marker on superseded
//!   versions, which are removed "in a background cleanup 14 days later". On the
//!   machine this was written on, a 21-day-old session still ran an old playwright and
//!   an old security-guidance plugin, while every other scanner grades the installed
//!   versions only. Only the entry NAMES are read: a pid counts when `/proc/<pid>`
//!   exists and is owned by the scanning user. `kill(pid, 0)` is not used. Off Linux
//!   there is no `/proc` and nothing is reported (a documented floor).
//! - **npx caches running.** A process counts when one of its command-line arguments
//!   STARTS with a path inside `~/.npm/_npx/<hash>/` (`node ~/.npm/_npx/<hash>/node_modules/.bin/x`).
//!   The command line is needed: the processes this was built for (playwright-mcp run by
//!   `npx`, three on the machine it was written on, 2026-10-24) have `exe` = the system
//!   `node`, a `cwd` in the project, and no open descriptor or mapping under the cache
//!   (node reads the scripts and closes them), so `exe`, `cwd`, `fd/*` and `maps` find
//!   none of them. argv can carry secrets (`--token X`), so the reader is narrow: for
//!   each `/proc/<pid>` owned by the scanning user (`stat(2)` of the directory), at most
//!   16 KiB of `cmdline` is read into one buffer, each NUL-separated element is
//!   compared by byte prefix against the cache root, the `<hash>` directory name (hex,
//!   at most 64 characters) is the only text kept, and the buffer is zeroed before the
//!   next process. No argv text is stored, logged, traced or printed (a test plants a
//!   canary argument and checks every output format and the trace). `environ`, `comm`,
//!   `exe`, `cwd` and `fd` are not opened. Linux only. A cache moved by
//!   `npm_config_cache` is not followed. Debug builds read a fixture tree under
//!   `RMGUARD_TEST_PROC_ROOT` (the listener scanner's knob); release builds read `/proc`.

use crate::models::{NpxCacheRunning, PluginVersionInUse};
use crate::platform::PlatformInfo;
use crate::scanners::sanitize_display;
use std::path::{Path, PathBuf};

/// What the `liveness` job stores.
pub enum LivenessOut {
    InUse(PluginVersionInUse),
    Npx(NpxCacheRunning),
}

/// Cache version directories looked at, at the base walk budget.
const BASE_VERSION_DIRS: usize = 2_000;
/// `.in_use` entries read per version.
const MAX_IN_USE_ENTRIES: usize = 256;
/// Processes whose command line is read, at the base walk budget.
const BASE_PROCESSES: usize = 8_192;
/// Bytes of one command line read.
const MAX_CMDLINE_BYTES: u64 = 16 * 1024;

/// The `liveness` job for one home.
pub fn scan_home(platform: &dyn PlatformInfo) -> Vec<LivenessOut> {
    let home = platform.home_dir();
    let owner = crate::scanners::home_owner_uid(&home);
    let mut out: Vec<LivenessOut> = plugin_versions_in_use(&home, &|pid, marked| pid_is_live(pid, owner, marked))
        .into_iter()
        .map(LivenessOut::InUse)
        .collect();
    out.extend(npx_caches_running(&home, owner).into_iter().map(LivenessOut::Npx));
    out
}

/// The `/proc` this scanner reads: `/proc`, or in a debug build a fixture tree named by
/// `RMGUARD_TEST_PROC_ROOT`. Unlike [`crate::scanners::listeners::proc_root`] it is not
/// re-rooted under `RMGUARD_TEST_SYSTEM_ROOT`: the liveness tests run real processes.
fn proc_root() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(root) = std::env::var_os("RMGUARD_TEST_PROC_ROOT").filter(|r| !r.is_empty()) {
        return PathBuf::from(root);
    }
    PathBuf::from("/proc")
}

/// Seconds of slack between a process's start (whole seconds from `/proc/stat` btime and
/// clock ticks) and the mtime of the `.in_use` marker it wrote.
const START_TOLERANCE_SECS: u64 = 2;

/// A process of `owner` (the scanned home's owner, not the scanner's uid) with this pid
/// exists (Linux `/proc`), and it was already running when its `.in_use` marker was
/// written (`marked`, the marker's mtime): a pid the kernel handed to a later process
/// after the session exited is not that session. When the start time cannot be read the
/// pid counts, as before. Always false elsewhere.
pub fn pid_is_live(pid: u32, owner: u32, marked: Option<std::time::SystemTime>) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let root = proc_root();
        if !std::fs::metadata(root.join(pid.to_string())).is_ok_and(|m| m.uid() == owner) {
            return false;
        }
        let (Some(marked), Some(start)) = (marked, process_start_epoch(&root, pid)) else {
            return true;
        };
        let marked = marked.duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        start <= marked.saturating_add(START_TOLERANCE_SECS)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, owner, marked);
        false
    }
}

/// A process's start time in seconds since the epoch: `/proc/stat` `btime` plus field 22
/// (`starttime`, clock ticks after boot) of `/proc/<pid>/stat`, parsed as the listener
/// scanner parses them ([`crate::scanners::listeners::parse_stat`], counting fields from
/// the LAST `)` so a command name holding `)` or spaces cannot shift them).
#[cfg(target_os = "linux")]
pub fn process_start_epoch(root: &Path, pid: u32) -> Option<u64> {
    use crate::scanners::listeners::{clock_ticks, parse_btime, parse_stat};
    let head = |p: PathBuf, n: u64| -> Option<String> {
        use std::io::Read;
        let mut buf = Vec::new();
        std::fs::File::open(p).ok()?.take(n).read_to_end(&mut buf).ok()?;
        Some(String::from_utf8_lossy(&buf).into_owned())
    };
    let stat = parse_stat(&head(root.join(pid.to_string()).join("stat"), 4096)?)?;
    let btime = u64::try_from(parse_btime(&head(root.join("stat"), 64 * 1024)?)?).ok()?;
    Some(btime + stat.starttime / clock_ticks())
}

/// Directories directly under `dir`, sorted, that are real directories (not links).
fn subdirs(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(rd) = crate::scanners::probe_read_dir(dir) else {
        return Vec::new();
    };
    let mut v: Vec<(String, PathBuf)> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| Some((e.file_name().into_string().ok()?, e.path())))
        .collect();
    v.sort();
    v
}

/// Every cache version of `home` with a live `.in_use` entry, sorted by (plugin, version).
/// `live` answers whether a pid is a running session (injected for tests).
/// `live(pid, marker_mtime)` answers whether a pid is a running session that wrote its
/// marker (injected for tests).
pub fn plugin_versions_in_use(
    home: &Path,
    live: &dyn Fn(u32, Option<std::time::SystemTime>) -> bool,
) -> Vec<PluginVersionInUse> {
    let cache = home.join(".claude").join("plugins").join("cache");
    if !std::fs::symlink_metadata(&cache).is_ok_and(|m| m.is_dir()) {
        crate::scanners::telemetry::note_probe(&cache, false);
        return Vec::new();
    }
    let ctx = crate::scanners::skills::PluginContext::load(home);
    let cap = crate::scanners::telemetry::walk_cap(BASE_VERSION_DIRS, crate::scanners::telemetry::walk_budget());
    let mut seen_dirs = 0usize;
    let mut out = Vec::new();
    'markets: for (market, mdir) in subdirs(&cache) {
        for (plugin, pdir) in subdirs(&mdir) {
            for (version, vdir) in subdirs(&pdir) {
                if seen_dirs >= cap {
                    crate::scanners::telemetry::mark_truncated();
                    break 'markets;
                }
                seen_dirs += 1;
                let pids = live_entries(&vdir.join(".in_use"), live);
                if pids.is_empty() {
                    continue;
                }
                let installed: Vec<&PathBuf> = ctx
                    .install_paths()
                    .iter()
                    .filter(|(_, p, m)| *p == plugin && *m == market)
                    .map(|(ip, _, _)| ip)
                    .collect();
                let is_installed = installed.iter().any(|ip| **ip == vdir);
                let installed_version = if is_installed {
                    None
                } else {
                    installed
                        .first()
                        .and_then(|ip| ip.file_name())
                        .map(|n| sanitize_display(&n.to_string_lossy(), 128))
                };
                let label = sanitize_display(&format!("{plugin}@{market}"), 256);
                let mut row = PluginVersionInUse {
                    plugin: label.clone(),
                    version: sanitize_display(&version, 128),
                    path: sanitize_display(&vdir.to_string_lossy(), 512),
                    in_use_by_sessions: pids.len(),
                    pids,
                    installed_version,
                    stale_version: !is_installed,
                    ..Default::default()
                };
                if row.stale_version {
                    stale_inventory(home, &cache, &vdir, &label, &mut row);
                }
                out.push(row);
            }
        }
    }
    out
}

/// The live pids among a `.in_use` directory's entry names (decimal names only), sorted.
fn live_entries(dir: &Path, live: &dyn Fn(u32, Option<std::time::SystemTime>) -> bool) -> Vec<u32> {
    if !std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()) {
        return Vec::new();
    }
    let Ok(rd) = crate::scanners::probe_read_dir(dir) else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = rd
        .flatten()
        .take(MAX_IN_USE_ENTRIES)
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.is_empty() && n.len() <= 10 && n.bytes().all(|b| b.is_ascii_digit()))
        .filter_map(|n| n.parse().ok())
        .collect();
    pids.sort_unstable();
    pids.dedup();
    pids.into_iter()
        .filter(|p| {
            let marked = std::fs::symlink_metadata(dir.join(p.to_string()))
                .ok()
                .and_then(|m| m.modified().ok());
            *p > 0 && live(*p, marked)
        })
        .collect()
}

/// A stale version's hooks and MCP servers, read with the installed-version containment
/// rules (real path inside the real cache, files inside the version directory).
fn stale_inventory(home: &Path, cache: &Path, vdir: &Path, label: &str, row: &mut PluginVersionInUse) {
    let (Ok(real_cache), Ok(real_root)) = (std::fs::canonicalize(cache), std::fs::canonicalize(vdir)) else {
        return;
    };
    if !real_root.starts_with(&real_cache) || real_root == real_cache {
        return;
    }
    row.hooks = crate::scanners::hook_discovery::plugin_version_hooks(home, vdir);
    row.mcp_servers = crate::scanners::mcp::plugin_root_configs(vdir, &real_root, label, true)
        .into_iter()
        .flat_map(|c| c.servers)
        .collect();
}

/// npx caches of `home` that a running process of this user executes from, sorted.
/// `owner` is the scanned home's owner: only its processes count.
pub fn npx_caches_running(home: &Path, owner: u32) -> Vec<NpxCacheRunning> {
    let root = home.join(".npm").join("_npx");
    if !std::fs::symlink_metadata(&root).is_ok_and(|m| m.is_dir()) {
        crate::scanners::telemetry::note_probe(&root, false);
        return Vec::new();
    }
    let mut roots = vec![root.clone()];
    if let Ok(real) = std::fs::canonicalize(&root)
        && real != root
    {
        roots.push(real);
    }
    let counts = running_under(&roots, &|f| process_cmdlines(owner, f));
    counts
        .into_iter()
        .map(|(hash, pids)| NpxCacheRunning {
            path: sanitize_display(&root.join(&hash).to_string_lossy(), 512),
            pids,
        })
        .collect()
}

/// Calls its argument once per process command line (NUL-separated bytes).
pub type CmdlineSource<'a> = &'a dyn Fn(&mut dyn FnMut(&[u8]));

/// For each `<root>/<hash>/...` argument of the command lines `each` yields, the number of
/// processes per `<hash>` (a process counted once per hash). `each` calls its argument
/// with every process's NUL-separated command line; nothing of it is kept.
pub fn running_under(roots: &[PathBuf], each: CmdlineSource<'_>) -> std::collections::BTreeMap<String, usize> {
    let prefixes: Vec<Vec<u8>> = roots
        .iter()
        .map(|r| {
            let mut p = r.to_string_lossy().into_owned().into_bytes();
            p.push(b'/');
            p
        })
        .collect();
    let mut counts = std::collections::BTreeMap::new();
    each(&mut |cmdline: &[u8]| {
        let mut hashes = std::collections::BTreeSet::new();
        for arg in cmdline.split(|b| *b == 0) {
            for p in &prefixes {
                if let Some(rest) = arg.strip_prefix(p.as_slice()) {
                    let hash: Vec<u8> = rest.iter().take_while(|b| **b != b'/').copied().collect();
                    if !hash.is_empty() && hash.len() <= 64 && hash.iter().all(|b| b.is_ascii_hexdigit()) {
                        hashes.insert(String::from_utf8_lossy(&hash).into_owned());
                    }
                }
            }
        }
        for h in hashes {
            *counts.entry(h).or_insert(0) += 1;
        }
    });
    counts
}

/// Call `f` with the command line of every process of this user (Linux `/proc`), at most
/// the scaled [`BASE_PROCESSES`], each read to [`MAX_CMDLINE_BYTES`]. Nothing elsewhere.
/// The one buffer is zeroed after each call, so no argv outlives its comparison.
fn process_cmdlines(owner: u32, f: &mut dyn FnMut(&[u8])) {
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        use std::os::unix::fs::MetadataExt;
        let root = proc_root();
        let Ok(rd) = std::fs::read_dir(&root) else {
            return;
        };
        let me = owner;
        let cap = crate::scanners::telemetry::walk_cap(BASE_PROCESSES, crate::scanners::telemetry::walk_budget());
        let mut pids: Vec<u32> = rd
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok()?.parse().ok())
            .collect();
        pids.sort_unstable();
        if pids.len() > cap {
            pids.truncate(cap);
            crate::scanners::telemetry::mark_truncated();
        }
        let mut buf = Vec::new();
        for pid in pids {
            let dir = root.join(pid.to_string());
            if !std::fs::metadata(&dir).is_ok_and(|m| m.uid() == me) {
                continue;
            }
            let Ok(file) = std::fs::File::open(dir.join("cmdline")) else {
                continue;
            };
            if file.take(MAX_CMDLINE_BYTES).read_to_end(&mut buf).is_ok() && !buf.is_empty() {
                f(&buf);
            }
            buf.fill(0);
            buf.clear();
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (owner, f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn running_under_counts_processes_per_cache() {
        let roots = vec![PathBuf::from("/h/.npm/_npx")];
        let lines: Vec<&[u8]> = vec![
            b"node\0/h/.npm/_npx/9833c18b2d85bc59/node_modules/.bin/playwright-mcp\0",
            b"node\0/h/.npm/_npx/9833c18b2d85bc59/node_modules/.bin/playwright-mcp\0--x\0/h/.npm/_npx/9833c18b2d85bc59/y\0",
            // A shell whose script text mentions the cache is not running from it.
            b"/bin/bash\0-c\0cd /h/.npm/_npx/eea2bd7412d4593b/ && ls\0",
            b"node\0/h/.npm/_npx/not-hex/x\0",
        ];
        let each = |f: &mut dyn FnMut(&[u8])| {
            for l in &lines {
                f(l);
            }
        };
        let c = running_under(&roots, &each);
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("9833c18b2d85bc59"), Some(&2));
    }
}
