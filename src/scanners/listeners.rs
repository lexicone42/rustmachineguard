//! Network listeners that hand out a shell or a terminal into the agent's environment.
//!
//! A web terminal (ttyd, gotty, a home-made PTY bridge) started from a project and bound
//! to every interface gives whoever gets past its login a shell as this user: the same
//! files, keys and tmux server the coding agents run in. This scanner inventories the
//! user's listening TCP sockets so the grading ([`crate::analysis_surfaces`]) can say
//! which of them do that, and whether their credentials sit in a world-readable file.
//!
//! Linux only, and nothing is spawned (`ss`, `netstat` and `lsof` are not needed):
//!
//! 1. `/proc/net/tcp` and `/proc/net/tcp6`: rows in LISTEN state (`st == 0A`) whose
//!    socket uid is the scanning user's, with their local address, port and inode.
//! 2. `/proc/<pid>/fd/*` link targets (`socket:[<inode>]`) of the user's OWN processes
//!    (the `/proc/<pid>` owner is compared to the effective uid before anything under it
//!    is opened; another user's process is never looked into), at most [`BASE_PIDS`]
//!    processes (scaled by `--walk-budget`) and [`MAX_FDS`] descriptors each.
//! 3. For a listener's process: `comm`, the `exe` and `cwd` links, `stat` (start time,
//!    for the age; parent pid) and its children (`/proc/<pid>/task/*/children`, or, on
//!    a kernel built without `CONFIG_PROC_CHILDREN`, the parent pid of each of the
//!    user's processes). `/proc/<pid>/cmdline` and `/proc/<pid>/environ` are never
//!    opened: the program is known by its `comm` and `exe` only.
//!
//! macOS has no `/proc`: the scanner is reported as skipped with [`FLOOR_REASON`] (a
//! documented floor; `lsof` is not spawned). Debug builds honour `RMGUARD_TEST_PROC_ROOT`
//! (a fixture `/proc` tree), and otherwise re-root `/proc` under `RMGUARD_TEST_SYSTEM_ROOT`
//! like every machine-wide path ([`crate::scanners::system_path`]); release builds always
//! read `/proc`.

use crate::models::{BindClass, NetworkListener, ServesShell};
use crate::platform::PlatformInfo;
use crate::scanners::sanitize_display;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

/// Why the scanner does not run off Linux (the diagnostics row is `skipped`, and this is
/// its warning).
pub const FLOOR_REASON: &str =
    "no /proc on this platform: listening sockets are not inventoried (documented floor; lsof is not spawned)";

/// The user's own processes whose descriptors are listed, at the base walk budget.
pub const BASE_PIDS: usize = 4096;
/// `/proc` entries looked at to find them (every user's pids are directory names).
const MAX_PROC_ENTRIES: usize = 65_536;
/// Descriptors listed per process.
pub const MAX_FDS: usize = 1024;
/// Threads whose `children` file is read per process.
const MAX_TASKS: usize = 1024;
/// Bytes of `/proc/net/tcp{,6}` read (about 100,000 sockets).
const MAX_NET_BYTES: u64 = 16 * 1024 * 1024;
/// Bytes of a small `/proc` file (`comm`, `stat`, `children`).
const MAX_SMALL_BYTES: u64 = 64 * 1024;

/// Web-terminal programs: each serves a shell or a terminal session over HTTP/WebSocket.
/// Matched against `comm` (15 bytes) and the `exe` basename.
/// - ttyd: <https://github.com/tsl0922/ttyd> ("Share your terminal over the web")
/// - gotty: <https://github.com/yudai/gotty> (and the maintained fork
///   <https://github.com/sorenisanerd/gotty>): "turns CLI tools into web applications"
/// - wetty: <https://github.com/butlerx/wetty> ("Terminal in browser over http/https");
///   an npm package, so a global install usually runs as `node` and is not seen by name
/// - shellinabox: <https://github.com/shellinabox/shellinabox>, daemon `shellinaboxd`
/// - webssh: <https://github.com/huashengdun/webssh>, entry point `wssh` (a Python
///   program: under `python3 -m webssh` it is not seen by name)
/// - sshwifty: <https://github.com/nirui/sshwifty> (web SSH and Telnet client)
/// - terminal-bridge: the PTY bridge this scanner was written against (a project-local
///   Rust server that runs `tmux new -A -s <name>` behind token/passkey auth); no
///   public upstream
/// - generic names a self-written PTY or web-terminal bridge is given (`pty-bridge`,
///   `pty-server`, `web-terminal`, `webterm`, `term-server`): a name that says what it
///   does, matched whole
pub const KNOWN_BRIDGES: &[&str] = &[
    "ttyd",
    "gotty",
    "wetty",
    "shellinaboxd",
    "shellinabox",
    "wssh",
    "webssh",
    "sshwifty",
    "terminal-bridge",
    "pty-bridge",
    "pty-server",
    "web-terminal",
    "webterm",
    "term-server",
];

/// Child process names that are a shell.
const SHELLS: &[&str] = &["bash", "zsh", "sh", "fish", "dash"];

/// Development servers that commonly bind every interface on purpose (`vite --host`,
/// `next dev -H 0.0.0.0`, `python -m http.server`): a listener of one of these, in a
/// project, that hands out no shell is inventory, not a finding. Closed and small:
/// `comm` exact matches, plus `python3.<minor>` and Next.js's `next-server (v..)` title.
pub const DEV_SERVERS: &[&str] = &["node", "bun", "deno", "python", "python3", "vite", "next-server"];

/// `program` (a `comm`) is a [`DEV_SERVERS`] entry.
pub fn is_dev_server(program: &str) -> bool {
    DEV_SERVERS.contains(&program)
        || program
            .strip_prefix("python3.")
            .is_some_and(|m| !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()))
        || program.starts_with("next-server ")
}

/// The listener's program is a development server, by `comm` or by the `exe` basename
/// (a program that renames its main thread, as Node does to `MainThread`, keeps its exe).
pub fn is_dev_server_listener(l: &NetworkListener) -> bool {
    let exe = l
        .exe
        .as_deref()
        .map(|e| e.trim_end_matches(" (deleted)"))
        .and_then(|e| e.rsplit('/').next());
    [l.program.as_deref(), exe].into_iter().flatten().any(is_dev_server)
}

/// The `/proc` this scan reads: see the module docs.
pub fn proc_root() -> PathBuf {
    #[cfg(debug_assertions)]
    if let Some(root) = std::env::var_os("RMGUARD_TEST_PROC_ROOT").filter(|r| !r.is_empty()) {
        return PathBuf::from(root);
    }
    crate::scanners::system_path("/proc")
}

/// The `listeners` job (Linux; global, run once per scan with the primary pass's projects).
pub fn scan(platform: &dyn PlatformInfo) -> Vec<NetworkListener> {
    let home = platform.home_dir();
    let scope = platform.pass_scope();
    let projects = scope.excluding_scan_homes(scope.with_cwd(registered_projects(&home.join(".claude.json"))));
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    scan_root(&proc_root(), me, &projects, chrono::Utc::now().timestamp())
}

/// `~/.claude.json` `projects` keys that are directories.
fn registered_projects(claude_json: &Path) -> Vec<PathBuf> {
    let Some(content) = crate::scanners::read_bounded(claude_json) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) else {
        return Vec::new();
    };
    v.get("projects")
        .and_then(|p| p.as_object())
        .map(|o| {
            o.keys()
                .map(PathBuf::from)
                .filter(|p| p.is_absolute() && crate::scanners::probe_dir(p))
                .collect()
        })
        .unwrap_or_default()
}

// ── /proc/net/tcp ─────────────────────────────────────────────────────────────────────

/// One LISTEN row of `/proc/net/tcp{,6}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawListener {
    pub addr: IpAddr,
    pub port: u16,
    /// The socket owner's uid.
    pub uid: u32,
    pub inode: u64,
}

/// The LISTEN rows (`st == 0A`) of one `/proc/net/tcp` (`v6 == false`) or `tcp6` file.
/// The kernel prints each 32-bit address word with `%08X` in host byte order; `little`
/// says how to undo that (the host's own order in production; fixtures are little-endian).
/// The port is printed in host order already. Malformed rows are skipped.
pub fn parse_proc_net_tcp(text: &str, v6: bool, little: bool) -> Vec<RawListener> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // sl local rem st tx:rx tr:when retrnsmt uid timeout inode ...
        if f.len() < 10 || f[0] == "sl" || f[3] != "0A" {
            continue;
        }
        let Some((addr, port)) = f[1].split_once(':') else {
            continue;
        };
        let (Some(addr), Ok(port)) = (decode_addr(addr, v6, little), u16::from_str_radix(port, 16)) else {
            continue;
        };
        let (Ok(uid), Ok(inode)) = (f[7].parse::<u32>(), f[9].parse::<u64>()) else {
            continue;
        };
        out.push(RawListener { addr, port, uid, inode });
    }
    out
}

/// A `/proc/net/tcp{,6}` hex address: 8 hex digits (IPv4) or 32 (IPv6, four words).
pub fn decode_addr(hex: &str, v6: bool, little: bool) -> Option<IpAddr> {
    let word = |s: &str| -> Option<[u8; 4]> {
        let w = u32::from_str_radix(s, 16).ok()?;
        Some(if little { w.to_le_bytes() } else { w.to_be_bytes() })
    };
    if !hex.is_ascii() {
        return None;
    }
    if !v6 {
        if hex.len() != 8 {
            return None;
        }
        return Some(IpAddr::V4(Ipv4Addr::from(word(hex)?)));
    }
    if hex.len() != 32 {
        return None;
    }
    let mut b = [0u8; 16];
    for i in 0..4 {
        b[i * 4..i * 4 + 4].copy_from_slice(&word(&hex[i * 8..i * 8 + 8])?);
    }
    Some(IpAddr::V6(Ipv6Addr::from(b)))
}

/// The bind class of a local address.
pub fn bind_class(addr: IpAddr) -> BindClass {
    match addr {
        IpAddr::V4(a) if a.is_loopback() => BindClass::Loopback,
        IpAddr::V4(a) if a.is_unspecified() => BindClass::AllInterfaces,
        IpAddr::V4(_) => BindClass::SpecificAddress,
        IpAddr::V6(a) => match a.to_ipv4_mapped() {
            Some(v4) => bind_class(IpAddr::V4(v4)),
            None if a.is_loopback() => BindClass::Loopback,
            None if a.is_unspecified() => BindClass::Ipv6Any,
            None => BindClass::SpecificAddress,
        },
    }
}

// ── /proc/<pid> ───────────────────────────────────────────────────────────────────────

/// A small `/proc` file, bounded, counted as a read.
fn read_small(path: &Path, max: u64) -> Option<String> {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => {
            crate::scanners::telemetry::note_read(path, "missing");
            return None;
        }
    };
    crate::scanners::telemetry::note_read(path, "ok");
    let mut buf = Vec::new();
    file.take(max).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Fields of `/proc/<pid>/stat` this scanner uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidStat {
    pub ppid: u32,
    /// Clock ticks after boot.
    pub starttime: u64,
}

/// Parse `/proc/<pid>/stat`. The second field is `(comm)`, which may itself hold spaces
/// and parentheses, so fields are counted from the LAST `)`.
pub fn parse_stat(s: &str) -> Option<PidStat> {
    let rest = &s[s.rfind(')')? + 1..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After ")": state(3) ppid(4) ... starttime(22).
    Some(PidStat {
        ppid: f.get(1)?.parse().ok()?,
        starttime: f.get(19)?.parse().ok()?,
    })
}

/// `btime` (boot time, Unix seconds) from `/proc/stat`.
pub fn parse_btime(s: &str) -> Option<i64> {
    s.lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
}

/// The pids under `root` whose directory the user `me` owns, sorted, capped.
fn own_pids(root: &Path, me: u32) -> Vec<u32> {
    use std::os::unix::fs::MetadataExt;
    let Ok(rd) = crate::scanners::probe_read_dir(root) else {
        return Vec::new();
    };
    let mut seen = 0usize;
    let mut pids: Vec<u32> = rd
        .flatten()
        .take_while(|_| {
            seen += 1;
            seen <= MAX_PROC_ENTRIES
        })
        .filter_map(|e| {
            let n = e.file_name().into_string().ok()?;
            if n.is_empty() || n.len() > 10 || !n.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            n.parse().ok()
        })
        .collect();
    if seen > MAX_PROC_ENTRIES {
        crate::scanners::telemetry::mark_truncated();
    }
    pids.sort_unstable();
    let cap = crate::scanners::telemetry::walk_cap(BASE_PIDS, crate::scanners::telemetry::walk_budget());
    let mut own = Vec::new();
    for pid in pids {
        // The owner check is a stat of the directory itself: nothing under another
        // user's /proc/<pid> is opened or listed.
        if !std::fs::symlink_metadata(root.join(pid.to_string())).is_ok_and(|m| m.is_dir() && m.uid() == me) {
            continue;
        }
        if own.len() >= cap {
            crate::scanners::telemetry::mark_truncated();
            break;
        }
        own.push(pid);
    }
    own
}

/// What one process's descriptors show: the socket inodes it holds, and whether it
/// holds a PTY master.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FdInfo {
    pub sockets: Vec<u64>,
    pub ptmx: bool,
}

/// The descriptor links of `<root>/<pid>/fd`, at most [`MAX_FDS`]. Only the link TEXT is
/// read (readlink); no descriptor is opened.
pub fn fd_info(root: &Path, pid: u32) -> FdInfo {
    let mut info = FdInfo::default();
    let Ok(rd) = std::fs::read_dir(root.join(pid.to_string()).join("fd")) else {
        return info;
    };
    for (n, e) in rd.flatten().enumerate() {
        if n >= MAX_FDS {
            crate::scanners::telemetry::mark_truncated();
            break;
        }
        let Ok(t) = std::fs::read_link(e.path()) else {
            continue;
        };
        let t = t.to_string_lossy();
        if let Some(inode) = t.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
            if let Ok(i) = inode.parse() {
                info.sockets.push(i);
            }
        } else if t == "/dev/ptmx" || t == "/dev/pts/ptmx" {
            info.ptmx = true;
        }
    }
    info
}

/// `<root>/<pid>/comm`, trimmed (None when unreadable or empty).
fn comm(root: &Path, pid: u32) -> Option<String> {
    let c = read_small(&root.join(pid.to_string()).join("comm"), 256)?;
    let c = c.trim_end_matches('\n').to_string();
    (!c.is_empty()).then_some(c)
}

/// The children of `pid` from `task/*/children`; None when no such file exists (a kernel
/// without `CONFIG_PROC_CHILDREN`), so the caller falls back to parent pids.
pub fn children_from_tasks(root: &Path, pid: u32) -> Option<Vec<u32>> {
    let rd = std::fs::read_dir(root.join(pid.to_string()).join("task")).ok()?;
    let mut any = false;
    let mut kids = BTreeSet::new();
    for e in rd.flatten().take(MAX_TASKS) {
        let Ok(text) = std::fs::read_to_string(e.path().join("children")) else {
            continue;
        };
        any = true;
        kids.extend(text.split_whitespace().filter_map(|p| p.parse::<u32>().ok()));
    }
    any.then(|| kids.into_iter().collect())
}

/// The shell signal of a listener's process: its children's names (tmux/screen, then a
/// shell), whether it holds a PTY master, and whether it is a known bridge by name.
/// `children` lists `pid`'s children; `owner_ok` says a child is the user's own.
pub fn serves_shell(
    root: &Path,
    program: Option<&str>,
    exe: Option<&str>,
    ptmx: bool,
    children: &[u32],
    owner_ok: &dyn Fn(u32) -> bool,
) -> (ServesShell, Option<String>) {
    let names: Vec<String> = children
        .iter()
        .take(256)
        .filter(|c| owner_ok(**c))
        .filter_map(|c| comm(root, *c))
        .collect();
    let base = |n: &str| n.rsplit('/').next().unwrap_or(n).to_string();
    if let Some(n) = names.iter().find(|n| {
        let b = n.split([':', ' ']).next().unwrap_or("");
        matches!(b, "tmux" | "screen" | "SCREEN")
    }) {
        return (
            ServesShell::TmuxChild,
            Some(format!("child '{}'", sanitize_display(n, 64))),
        );
    }
    if ptmx {
        return (ServesShell::PtyChild, Some("holds /dev/ptmx (a PTY master)".into()));
    }
    // A known bridge by name outranks a shell child: a bridge with a shell under it is a
    // bridge (High), a server that merely has a shell child is a weaker signal (Medium).
    let exe_base = exe.map(|e| base(e.trim_end_matches(" (deleted)")));
    for n in [program.map(str::to_string), exe_base].into_iter().flatten() {
        if KNOWN_BRIDGES.contains(&n.as_str()) {
            return (
                ServesShell::KnownBridgeName,
                Some(format!("program {}", sanitize_display(&n, 64))),
            );
        }
    }
    if let Some(n) = names
        .iter()
        .find(|n| SHELLS.contains(&base(n.trim_start_matches('-')).as_str()))
    {
        return (
            ServesShell::ShellChild,
            Some(format!("child '{}'", sanitize_display(n, 64))),
        );
    }
    (ServesShell::None, None)
}

/// The most specific project `cwd` is in, compared as given and canonically.
pub fn project_of(cwd: &Path, projects: &[PathBuf]) -> Option<PathBuf> {
    let mut best: Option<(usize, &PathBuf)> = None;
    for p in projects {
        let real = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
        let len = [p, &real]
            .iter()
            .filter(|q| cwd.starts_with(q))
            .map(|q| q.components().count())
            .max();
        if let Some(len) = len
            && best.is_none_or(|(l, _)| len > l)
        {
            best = Some((len, p));
        }
    }
    best.map(|(_, p)| p.clone())
}

/// Every LISTEN socket of user `me` under `root` (a `/proc` tree), mapped to the user's
/// own processes and graded for shell signals. `projects` are the scan's project
/// directories; `now` is Unix seconds. Sorted by (port, address).
pub fn scan_root(root: &Path, me: u32, projects: &[PathBuf], now: i64) -> Vec<NetworkListener> {
    let little = cfg!(target_endian = "little");
    let mut raw: Vec<RawListener> = Vec::new();
    for (file, v6) in [("tcp", false), ("tcp6", true)] {
        if let Some(text) = read_small(&root.join("net").join(file), MAX_NET_BYTES) {
            raw.extend(
                parse_proc_net_tcp(&text, v6, little)
                    .into_iter()
                    .filter(|r| r.uid == me),
            );
        }
    }
    if raw.is_empty() {
        return Vec::new();
    }
    let wanted: BTreeSet<u64> = raw.iter().map(|r| r.inode).collect();

    // inode -> lowest pid holding it; pids holding a PTY master.
    let pids = own_pids(root, me);
    let mut holder: BTreeMap<u64, u32> = BTreeMap::new();
    let mut ptmx: BTreeSet<u32> = BTreeSet::new();
    for &pid in &pids {
        let info = fd_info(root, pid);
        if info.ptmx {
            ptmx.insert(pid);
        }
        for i in info.sockets {
            if wanted.contains(&i) {
                holder.entry(i).or_insert(pid);
            }
        }
    }

    let btime = read_small(&root.join("stat"), MAX_NET_BYTES)
        .as_deref()
        .and_then(parse_btime);
    let clk = clock_ticks();
    let own: BTreeSet<u32> = pids.iter().copied().collect();
    // Parent pids of the user's processes, read once and only when a kernel has no
    // `children` files.
    let mut by_parent: Option<BTreeMap<u32, Vec<u32>>> = None;
    let mut cache: BTreeMap<u32, ProcInfo> = BTreeMap::new();

    let mut out = Vec::new();
    for r in &raw {
        let pid = holder.get(&r.inode).copied();
        let mut row = NetworkListener {
            bind: bind_class(r.addr),
            address: r.addr.to_string(),
            port: r.port,
            pid,
            ..Default::default()
        };
        if let Some(pid) = pid {
            let info = cache.entry(pid).or_insert_with(|| {
                let dir = root.join(pid.to_string());
                let program = comm(root, pid);
                let exe = std::fs::read_link(dir.join("exe")).ok();
                let cwd = std::fs::read_link(dir.join("cwd")).ok();
                let stat = read_small(&dir.join("stat"), MAX_SMALL_BYTES)
                    .as_deref()
                    .and_then(parse_stat);
                let kids = children_from_tasks(root, pid).unwrap_or_else(|| {
                    by_parent
                        .get_or_insert_with(|| parent_map(root, &pids))
                        .get(&pid)
                        .cloned()
                        .unwrap_or_default()
                });
                let exe_s = exe.as_ref().map(|e| e.to_string_lossy().into_owned());
                let (shell, signal) = serves_shell(
                    root,
                    program.as_deref(),
                    exe_s.as_deref(),
                    ptmx.contains(&pid),
                    &kids,
                    &|c| own.contains(&c),
                );
                let age_days = match (stat, btime) {
                    (Some(s), Some(b)) => {
                        let started = b + (s.starttime / clk) as i64;
                        (now >= started).then(|| ((now - started) / 86_400) as u64)
                    }
                    _ => None,
                };
                ProcInfo {
                    program: program.map(|p| sanitize_display(&p, 64)),
                    exe: exe_s.map(|e| sanitize_display(&e, 512)),
                    project: cwd
                        .as_deref()
                        .and_then(|c| project_of(c, projects))
                        .map(|p| sanitize_display(&p.to_string_lossy(), 512)),
                    cwd: cwd.map(|c| sanitize_display(&c.to_string_lossy(), 512)),
                    age_days,
                    shell,
                    signal,
                }
            });
            row.program = info.program.clone();
            row.exe = info.exe.clone();
            row.cwd = info.cwd.clone();
            row.age_days = info.age_days;
            row.project = info.project.clone();
            row.serves_shell = info.shell;
            row.shell_signal = info.signal.clone();
        }
        out.push(row);
    }
    out.sort_by(|a, b| (a.port, &a.address, a.pid).cmp(&(b.port, &b.address, b.pid)));
    out
}

/// What is recorded of one listener process.
struct ProcInfo {
    program: Option<String>,
    exe: Option<String>,
    cwd: Option<String>,
    project: Option<String>,
    age_days: Option<u64>,
    shell: ServesShell,
    signal: Option<String>,
}

/// parent pid -> children, from the `stat` of each of the user's processes `pids`.
fn parent_map(root: &Path, pids: &[u32]) -> BTreeMap<u32, Vec<u32>> {
    let mut m: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
    for &pid in pids {
        let path = root.join(pid.to_string()).join("stat");
        // Not counted as reads: one per process would drown the row's real inputs.
        let Ok(s) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(st) = parse_stat(&s) {
            m.entry(st.ppid).or_default().push(pid);
        }
    }
    m
}

/// `sysconf(_SC_CLK_TCK)`, 100 when unknown.
pub(crate) fn clock_ticks() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 { t as u64 } else { 100 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_rows_decode_address_port_and_listen_state() {
        let t = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:15CC 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 8657 1 0000000000000000 100 0 0 10 0\n\
   3: 00000000:20FB 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4072362 1 0000000000000000 100 0 0 10 0\n\
   4: 0501A8C0:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 77 1 0000000000000000 100 0 0 10 0\n\
   5: 0100007F:A643 0100007F:D2E4 01 00000000:00000000 00:00000000 00000000  1000        0 99 1 0000000000000000 100 0 0 10 0\n";
        let r = parse_proc_net_tcp(t, false, true);
        assert_eq!(
            r.len(),
            3,
            "the ESTABLISHED (01) row and the header are not listeners: {r:?}"
        );
        assert_eq!(r[0].addr.to_string(), "127.0.0.1");
        assert_eq!(r[0].port, 5580);
        assert_eq!((r[0].uid, r[0].inode), (1000, 8657));
        assert_eq!(r[1].addr.to_string(), "0.0.0.0");
        assert_eq!(r[1].port, 8443);
        assert_eq!(r[2].addr.to_string(), "192.168.1.5");
        assert_eq!(r[2].port, 8080);
        assert_eq!(r[2].uid, 0);
        assert_eq!(bind_class(r[0].addr), BindClass::Loopback);
        assert_eq!(bind_class(r[1].addr), BindClass::AllInterfaces);
        assert_eq!(bind_class(r[2].addr), BindClass::SpecificAddress);
    }

    #[test]
    fn ipv6_rows_decode_words_in_host_order() {
        let t = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000000000000:D605 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 8632 1\n\
   1: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 8508 1\n\
   2: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 11 1\n\
   3: 0000000000000000FFFF000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12 1\n\
   4: 000080FE00000000FF6AE96D9A7EB3FE:1F92 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 13 1\n";
        let r = parse_proc_net_tcp(t, true, true);
        assert_eq!(r.len(), 5);
        let shown: Vec<(String, u16, BindClass)> = r
            .iter()
            .map(|x| (x.addr.to_string(), x.port, bind_class(x.addr)))
            .collect();
        assert_eq!(shown[0], ("::".into(), 54789, BindClass::Ipv6Any));
        assert_eq!(shown[1], ("::1".into(), 22, BindClass::Loopback));
        assert_eq!(shown[2], ("::ffff:127.0.0.1".into(), 8080, BindClass::Loopback));
        assert_eq!(shown[3], ("::ffff:0.0.0.0".into(), 8081, BindClass::AllInterfaces));
        assert_eq!(shown[4].0, "fe80::6de9:6aff:feb3:7e9a");
        assert_eq!(shown[4].2, BindClass::SpecificAddress);
    }

    #[test]
    fn malformed_rows_are_skipped() {
        let t = "0: ZZ:0016 x 0A a b c 1000 0 5\n0: 0100007F 0 0A a b c 1000 0 5\n0: 0100007F:0016 0 0A a b c x 0 5\n";
        assert!(parse_proc_net_tcp(t, false, true).is_empty());
        assert_eq!(decode_addr("0100007F", true, true), None);
        assert_eq!(
            decode_addr("7F000001", false, false),
            Some("127.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn stat_fields_count_from_the_last_paren() {
        let s = "4242 (a) b) (c) S 77 4242 4242 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 123456 1 1 18446744073709551615";
        assert_eq!(
            parse_stat(s),
            Some(PidStat {
                ppid: 77,
                starttime: 123456
            })
        );
        assert_eq!(
            parse_btime("cpu 1 2\nbtime 1700000000\nprocesses 5\n"),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn dev_server_allowlist_is_closed() {
        for p in ["node", "python3", "python3.12", "next-server (v15", "vite", "bun"] {
            assert!(is_dev_server(p), "{p}");
        }
        for p in ["pty-bridge", "python3.x", "nodejs-bridge", "devhub", "ttyd"] {
            assert!(!is_dev_server(p), "{p}");
        }
    }

    #[test]
    fn project_of_picks_the_most_specific_project() {
        let ps = vec![
            PathBuf::from("/w/app"),
            PathBuf::from("/w/app/server"),
            PathBuf::from("/w/other"),
        ];
        assert_eq!(
            project_of(Path::new("/w/app/server/src"), &ps),
            Some(PathBuf::from("/w/app/server"))
        );
        assert_eq!(project_of(Path::new("/w/app/web"), &ps), Some(PathBuf::from("/w/app")));
        assert_eq!(project_of(Path::new("/w/application"), &ps), None);
    }
}
