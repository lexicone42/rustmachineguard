//! Network listeners that hand out a shell (`scanners::listeners`, graded in
//! `analysis_surfaces::listener_findings`).
//!
//! The scanner reads a `/proc` tree; these tests build one (`RMGUARD_TEST_PROC_ROOT`, a
//! debug-build knob, for the binary; `scan_root` directly for the library): `net/tcp`,
//! `net/tcp6`, `stat` (btime), and per pid `comm`, `stat`, the `exe` and `cwd` links,
//! `fd/*` links and optionally `task/<tid>/children`. Every pid directory also holds a
//! `cmdline` and an `environ` with canary text, which must never reach any output.
//!
//! `RMGUARD_TEST_BIN` runs another binary in place of the one under test. Pointed at a
//! debug build of main before this change (f8aa2a1/b44ed97), the end-to-end tests fail:
//! the report has no `network_listeners` rows and no "Network listener" finding (the
//! `listeners` --skip label is only a warning there). The library tests do not compile
//! there (no `scanners::listeners`).
#![cfg(unix)]

#[cfg(target_os = "linux")]
use rustmachineguard::analysis::{Finding, Severity, collect_findings};
#[cfg(target_os = "linux")]
use rustmachineguard::models::ScanReport;
use rustmachineguard::models::{BindClass, ServesShell};
use rustmachineguard::scanners::listeners::{fd_info, scan_root};
#[cfg(target_os = "linux")]
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
const ALL_LABELS: &[&str] = &[
    "ai",
    "frameworks",
    "ide",
    "extensions",
    "mcp",
    "node",
    "shell",
    "ssh",
    "cloud",
    "containers",
    "notebooks",
    "browser",
    "packages",
    "rules",
    "skills",
    "settings",
    "aicreds",
    "envfiles",
    "transcripts",
    "marketplaces",
    "vscodetasks",
    "gitconfig",
    "pypkgs",
    "npmpkgs",
    "jbplugins",
    "persistence",
    "lsp",
    "liveness",
    "playwright",
    "vibe",
    "statusline",
    "listeners",
];

const CMDLINE_CANARY: &str = "CMDLINECANARY --token=ArgvSecretCanary";
const ENVIRON_CANARY: &str = "BRIDGE_TOKEN=EnvironSecretCanary";
#[cfg(target_os = "linux")]
const ENV_VALUES: &[&str] = &["hunter2ValueCanary", "FullTokValueCanary", "ViewTokValueCanary"];

/// A fresh temp directory (mode 0755), canonicalized.
fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rmg-listen-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
    fs::canonicalize(&d).unwrap()
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn my_uid(p: &Path) -> u32 {
    fs::metadata(p).unwrap().uid()
}

fn clk_tck() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let t = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if t > 0 { t as u64 } else { 100 }
}

/// A fixture `/proc` tree.
struct Proc {
    root: PathBuf,
    tcp: Vec<String>,
    tcp6: Vec<String>,
    now: i64,
    btime: i64,
}

/// One process of the fixture.
struct Pid<'a> {
    pid: u32,
    comm: &'a str,
    exe: &'a str,
    cwd: &'a Path,
    ppid: u32,
    age_days: u64,
    fds: &'a [&'a str],
    /// `task/<pid>/children` content; None writes no task directory (a kernel without
    /// CONFIG_PROC_CHILDREN: the scanner falls back to parent pids).
    children: Option<&'a [u32]>,
}

impl Proc {
    fn new(root: PathBuf) -> Self {
        let now = chrono::Utc::now().timestamp();
        Proc {
            root,
            tcp: Vec::new(),
            tcp6: Vec::new(),
            now,
            btime: now - 60 * 86_400,
        }
    }

    /// A LISTEN row: `addr` in /proc's little-endian hex.
    fn listen(&mut self, v6: bool, addr: &str, port: u16, uid: u32, inode: u64) {
        let rem = if v6 { "0".repeat(32) } else { "0".repeat(8) };
        let i = self.tcp.len() + self.tcp6.len();
        let row = format!(
            "{i:4}: {addr}:{port:04X} {rem}:0000 0A 00000000:00000000 00:00000000 00000000 {uid:5}        0 {inode} 1 0000000000000000 100 0 0 10 0"
        );
        if v6 { &mut self.tcp6 } else { &mut self.tcp }.push(row);
    }

    fn pid(&self, p: Pid<'_>) {
        let dir = self.root.join(p.pid.to_string());
        fs::create_dir_all(dir.join("fd")).unwrap();
        write(&dir.join("comm"), &format!("{}\n", p.comm));
        let start = (60 - p.age_days) * 86_400 * clk_tck() + clk_tck() / 2;
        write(
            &dir.join("stat"),
            &format!(
                "{} ({}) S {} {} {} 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 {start} 1 1 18446744073709551615\n",
                p.pid, p.comm, p.ppid, p.pid, p.pid
            ),
        );
        write(&dir.join("cmdline"), &format!("{}\0", CMDLINE_CANARY));
        write(&dir.join("environ"), &format!("{}\0", ENVIRON_CANARY));
        symlink(p.exe, dir.join("exe")).unwrap();
        symlink(p.cwd, dir.join("cwd")).unwrap();
        for (n, t) in p.fds.iter().enumerate() {
            symlink(t, dir.join("fd").join(n.to_string())).unwrap();
        }
        if let Some(kids) = p.children {
            let list: Vec<String> = kids.iter().map(u32::to_string).collect();
            write(
                &dir.join("task").join(p.pid.to_string()).join("children"),
                &format!("{} ", list.join(" ")),
            );
        }
    }

    fn finish(&self) {
        let head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
        write(&self.root.join("net/tcp"), &format!("{head}{}\n", self.tcp.join("\n")));
        write(
            &self.root.join("net/tcp6"),
            &format!("{head}{}\n", self.tcp6.join("\n")),
        );
        write(
            &self.root.join("stat"),
            &format!("cpu  1 2 3 4\nbtime {}\nprocesses 9\n", self.btime),
        );
    }
}

const ANY4: &str = "00000000";
const LO4: &str = "0100007F";
const ANY6: &str = "00000000000000000000000000000000";

// ── Library: /proc tree -> rows ──────────────────────────────────────────────────────────

/// The inode in `/proc/net/tcp` is found among a process's `fd` links (`socket:[N]`), and
/// the lowest holder is the row's pid; the shell signals are read from `children`, the
/// PTY master and the program name, in that order.
#[test]
fn inodes_map_to_pids_and_shell_signals_are_classified() {
    let base = temp_dir("lib");
    let proc_root = base.join("proc");
    let proj = base.join("proj");
    fs::create_dir_all(&proj).unwrap();
    fs::create_dir_all(&proc_root).unwrap();
    let me = my_uid(&base);
    let mut p = Proc::new(proc_root.clone());
    p.listen(false, ANY4, 7681, me, 1001); // tmux child (task children file)
    p.listen(false, ANY4, 7682, me, 1002); // holds /dev/ptmx
    p.listen(true, ANY6, 7683, me, 1003); // shell child via the ppid fallback
    p.listen(false, ANY4, 7684, me, 1004); // ttyd by name
    p.listen(false, LO4, 7685, me, 1005); // nothing; loopback
    p.listen(false, ANY4, 7686, me + 1, 1006); // another user's socket: not listed
    p.listen(false, ANY4, 7687, me, 1007); // no process holds it
    p.finish();
    let pid = |pid, comm, fds, children, ppid| Pid {
        pid,
        comm,
        exe: "/usr/bin/whatever",
        cwd: &proj,
        ppid,
        age_days: 12,
        fds,
        children,
    };
    p.pid(pid(100, "bridge-a", &["socket:[1001]", "/dev/pts/3"], Some(&[101]), 1));
    p.pid(pid(101, "tmux: client", &["/dev/pts/4"], Some(&[]), 100));
    p.pid(pid(200, "bridge-b", &["socket:[1002]", "/dev/ptmx"], Some(&[]), 1));
    // pid 300 has no task directory: its children come from the ppid of every process.
    p.pid(pid(300, "bridge-c", &["socket:[1003]"], None, 1));
    p.pid(pid(301, "-bash", &[], None, 300));
    p.pid(pid(400, "ttyd", &["socket:[1004]"], Some(&[]), 1));
    // Two holders of one socket (a forked worker): the lowest pid is the row's.
    p.pid(pid(501, "worker", &["socket:[1005]"], Some(&[]), 500));
    p.pid(pid(500, "devd", &["socket:[1005]", "/dev/pts/9"], Some(&[501]), 1));

    assert_eq!(fd_info(&proc_root, 200).sockets, vec![1002]);
    assert!(fd_info(&proc_root, 200).ptmx);
    assert!(!fd_info(&proc_root, 100).ptmx, "a /dev/pts/N slave is not a PTY master");

    let rows = scan_root(&proc_root, me, std::slice::from_ref(&proj), p.now);
    let by_port = |port: u16| rows.iter().find(|r| r.port == port);
    assert_eq!(rows.len(), 6, "{rows:#?}");
    assert!(by_port(7686).is_none(), "another user's socket is not listed");

    let a = by_port(7681).unwrap();
    assert_eq!(a.pid, Some(100));
    assert_eq!(a.program.as_deref(), Some("bridge-a"));
    assert_eq!(a.bind, BindClass::AllInterfaces);
    assert_eq!(a.serves_shell, ServesShell::TmuxChild);
    assert_eq!(a.shell_signal.as_deref(), Some("child 'tmux: client'"));
    assert_eq!(a.age_days, Some(12));
    assert_eq!(a.project.as_deref(), Some(proj.to_str().unwrap()));
    assert_eq!(a.cwd.as_deref(), Some(proj.to_str().unwrap()));
    assert_eq!(a.exe.as_deref(), Some("/usr/bin/whatever"));

    assert_eq!(by_port(7682).unwrap().serves_shell, ServesShell::PtyChild);
    let c = by_port(7683).unwrap();
    assert_eq!((c.bind, c.address.as_str()), (BindClass::Ipv6Any, "::"));
    assert_eq!(c.serves_shell, ServesShell::ShellChild, "{c:#?}");
    assert_eq!(by_port(7684).unwrap().serves_shell, ServesShell::KnownBridgeName);
    let e = by_port(7685).unwrap();
    assert_eq!(
        (e.pid, e.bind, e.serves_shell),
        (Some(500), BindClass::Loopback, ServesShell::None)
    );
    let g = by_port(7687).unwrap();
    assert_eq!((g.pid, g.program.as_deref()), (None, None));

    // Scanning as another uid: no socket is that user's and no pid directory either, so
    // nothing of ours is listed or looked into.
    assert!(
        scan_root(&proc_root, me + 1, std::slice::from_ref(&proj), p.now)
            .iter()
            .all(|r| r.pid.is_none())
    );
    fs::remove_dir_all(&base).unwrap();
}

// ── End to end ───────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod e2e {
    use super::*;

    fn run(home: &Path, proc_root: &Path, format: &str) -> String {
        let keep = ["envfiles", "listeners"];
        let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
        let out = Command::new(bin())
            .args(["--skip", &skip.join(","), "--format", format])
            .env("HOME", home)
            .env("PATH", "/usr/bin:/bin")
            .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
            .env("RMGUARD_TEST_PROC_ROOT", proc_root)
            .env("NO_COLOR", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("RMGUARD_TRACE")
            .current_dir(home)
            .output()
            .expect("run rmguard");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    fn dump(findings: &[Finding]) -> String {
        findings
            .iter()
            .map(|f| {
                format!(
                    "[{}] {} | {} | {}\n",
                    f.severity.label(),
                    f.category,
                    f.title,
                    f.location
                )
            })
            .collect()
    }

    /// The machine this was written for: a PTY bridge in a project, on 0.0.0.0:8443 and
    /// :8080 for 30 days, its login tokens in a world-readable `.env` beside it. Critical,
    /// naming the keys and never a value, the command line or the environment. Controls: a
    /// loopback listener in the project, a shell bridge outside every project, a dev server
    /// on all interfaces in the project (inventory only), and a non-dev program on all
    /// interfaces in the project (Low).
    #[test]
    fn a_lan_pty_bridge_with_a_world_readable_env_is_critical_and_leaks_nothing() {
        let home = temp_dir("e2e");
        let proc_root = home.join("fixture-proc");
        let proj = home.join("work/minon");
        let server = proj.join("server");
        let web = home.join("work/web");
        let elsewhere = home.join("srv/bridge");
        for d in [&server, &web, &elsewhere, &proc_root] {
            fs::create_dir_all(d).unwrap();
        }
        write(
            &home.join(".claude.json"),
            &serde_json::json!({"projects": {
                proj.to_str().unwrap(): {},
                server.to_str().unwrap(): {},
                web.to_str().unwrap(): {},
            }})
            .to_string(),
        );
        let env = server.join(".env");
        write(
            &env,
            &format!(
                "FULL_PASS={}\nFULL_TOKEN={}\nVIEW_TOKEN={}\nPORT=8443\n",
                ENV_VALUES[0], ENV_VALUES[1], ENV_VALUES[2]
            ),
        );
        fs::set_permissions(&env, fs::Permissions::from_mode(0o644)).unwrap();

        let me = my_uid(&home);
        let mut p = Proc::new(proc_root.clone());
        p.listen(false, ANY4, 8443, me, 4072362);
        p.listen(false, ANY4, 8080, me, 4077698);
        p.listen(false, LO4, 8094, me, 5001); // loopback, in a project
        p.listen(false, ANY4, 7681, me, 5002); // ttyd outside every project
        p.listen(true, ANY6, 5173, me, 5003); // vite (node) on ::, in a project
        p.listen(false, ANY4, 8091, me, 5004); // a non-dev program on 0.0.0.0, in a project
        p.finish();
        let exe = server.join("target/release/terminal-bridge");
        p.pid(Pid {
            pid: 2875651,
            comm: "terminal-bridge",
            exe: exe.to_str().unwrap(),
            cwd: &server,
            ppid: 1,
            age_days: 30,
            fds: &[
                "/dev/null",
                "socket:[4077698]",
                "socket:[4072362]",
                "anon_inode:[eventpoll]",
            ],
            children: Some(&[]),
        });
        p.pid(Pid {
            pid: 4700,
            comm: "birdnet-local",
            exe: "/opt/birdnet/birdnet-local",
            cwd: &proj,
            ppid: 1,
            age_days: 3,
            fds: &["socket:[5001]"],
            children: Some(&[]),
        });
        p.pid(Pid {
            pid: 4800,
            comm: "ttyd",
            exe: "/usr/bin/ttyd",
            cwd: &elsewhere,
            ppid: 1,
            age_days: 3,
            fds: &["socket:[5002]"],
            children: Some(&[4801]),
        });
        p.pid(Pid {
            pid: 4801,
            comm: "bash",
            exe: "/bin/bash",
            cwd: &elsewhere,
            ppid: 4800,
            age_days: 3,
            fds: &[],
            children: Some(&[]),
        });
        p.pid(Pid {
            pid: 4900,
            comm: "MainThread",
            exe: "/usr/bin/node",
            cwd: &web,
            ppid: 1,
            age_days: 1,
            fds: &["socket:[5003]"],
            children: Some(&[]),
        });
        p.pid(Pid {
            pid: 5000,
            comm: "hearth",
            exe: "/opt/hearth/hearth",
            cwd: &web,
            ppid: 1,
            age_days: 2,
            fds: &["socket:[5004]"],
            children: Some(&[]),
        });

        let text = run(&home, &proc_root, "json");
        let v: Value = serde_json::from_str(&text).unwrap();
        let report: ScanReport = serde_json::from_str(&text).unwrap();
        let rows = v["network_listeners"].as_array().expect("network_listeners rows");
        assert_eq!(rows.len(), 6, "{rows:#?}");
        let bridge: Vec<&Value> = rows.iter().filter(|r| r["pid"] == 2875651).collect();
        assert_eq!(bridge.len(), 2);
        for r in &bridge {
            assert_eq!(r["bind"], "all-interfaces");
            assert_eq!(r["program"], "terminal-bridge");
            assert_eq!(r["serves_shell"], "known-bridge-name");
            assert_eq!(r["age_days"], 30);
            assert_eq!(r["project"], server.to_str().unwrap(), "the most specific project");
            assert_eq!(r["readable_secret_files"], 1);
        }
        let ttyd = rows.iter().find(|r| r["port"] == 7681).unwrap();
        assert_eq!(ttyd["serves_shell"], "shell-child");
        assert!(ttyd.get("project").is_none());

        let findings = collect_findings(&report);
        let ours: Vec<&Finding> = findings.iter().filter(|f| f.category == "Network listener").collect();
        assert_eq!(ours.len(), 2, "{}", dump(&findings));
        let crit = ours
            .iter()
            .find(|f| f.severity == Severity::Critical)
            .expect("Critical");
        assert_eq!(
            crit.title,
            format!(
                "a network listener in project {} hands out a shell/PTY (program terminal-bridge, ports 8080, 8443, bound to all interfaces, running 30 days) and its directory holds a world-readable env file with secret-named keys (names only: FULL_PASS, FULL_TOKEN, VIEW_TOKEN)",
                server.display()
            )
        );
        assert_eq!(crit.location, server.to_str().unwrap());
        let low = ours
            .iter()
            .find(|f| f.severity == Severity::Low)
            .expect("Low for hearth");
        assert!(
            low.title
                .starts_with("project process listening on all interfaces: hearth on port 8091")
        );
        // Controls: the loopback listener, ttyd outside every project and the node dev server
        // produce no finding.
        for f in &ours {
            for not in ["8094", "7681", "5173", "ttyd", "MainThread"] {
                assert!(!f.title.contains(not), "{not}: {}", dump(&findings));
            }
        }

        // Nothing of the env values, the command line or the environment, in any output.
        let mut outputs = vec![text];
        for fmt in ["terminal", "html", "sbom", "blueprint", "compliance"] {
            outputs.push(run(&home, &proc_root, fmt));
        }
        let terminal = &outputs[1];
        assert!(terminal.contains("Network Listeners (6)"), "{terminal}");
        assert!(terminal.contains("0.0.0.0:8443 all-interfaces — terminal-bridge (pid 2875651), 30 days [serves shell: known-bridge-name] [1 world-readable .env with secret-named keys]"), "{terminal}");
        for out in &outputs {
            for canary in ENV_VALUES.iter().copied().chain([
                "CMDLINECANARY",
                "ArgvSecretCanary",
                "EnvironSecretCanary",
                "BRIDGE_TOKEN",
            ]) {
                assert!(!out.contains(canary), "{canary} leaked");
            }
        }
        fs::remove_dir_all(&home).unwrap();
    }

    /// The same bridge with its `.env` mode 0600: High, not Critical, and the title says
    /// nothing about an env file. Without `listeners` in --skip, `--skip listeners` removes
    /// the rows and the finding.
    #[test]
    fn a_private_env_keeps_it_high_and_skip_removes_it() {
        let home = temp_dir("e2e-high");
        let proc_root = home.join("fixture-proc");
        let server = home.join("work/server");
        fs::create_dir_all(&server).unwrap();
        fs::create_dir_all(&proc_root).unwrap();
        write(
            &home.join(".claude.json"),
            &serde_json::json!({"projects": {server.to_str().unwrap(): {}}}).to_string(),
        );
        let env = server.join(".env");
        write(&env, &format!("FULL_TOKEN={}\n", ENV_VALUES[1]));
        fs::set_permissions(&env, fs::Permissions::from_mode(0o600)).unwrap();
        let me = my_uid(&home);
        let mut p = Proc::new(proc_root.clone());
        p.listen(false, "0501A8C0", 8443, me, 77);
        p.finish();
        p.pid(Pid {
            pid: 900,
            comm: "my-term",
            exe: "/opt/x/my-term",
            cwd: &server,
            ppid: 1,
            age_days: 1,
            fds: &["socket:[77]", "/dev/ptmx"],
            children: Some(&[]),
        });
        let text = run(&home, &proc_root, "json");
        let report: ScanReport = serde_json::from_str(&text).unwrap();
        let findings = collect_findings(&report);
        let ours: Vec<&Finding> = findings.iter().filter(|f| f.category == "Network listener").collect();
        assert_eq!(ours.len(), 1, "{}", dump(&findings));
        assert_eq!(ours[0].severity, Severity::High);
        assert_eq!(
            ours[0].title,
            format!(
                "a network listener in project {} hands out a shell/PTY (program my-term, port 8443, bound to address 192.168.1.5, running 1 day)",
                server.display()
            )
        );

        let keep = ["envfiles"];
        let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
        let out = Command::new(bin())
            .args(["--skip", &skip.join(","), "--format", "json"])
            .env("HOME", &home)
            .env("PATH", "/usr/bin:/bin")
            .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
            .env("RMGUARD_TEST_PROC_ROOT", &proc_root)
            .current_dir(&home)
            .output()
            .unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(v.get("network_listeners").is_none());
        let row = v["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["scanner"] == "listeners")
            .expect("a listeners diagnostics row");
        assert_eq!(row["skipped"], true);
        fs::remove_dir_all(&home).unwrap();
    }

    /// Without `RMGUARD_TEST_PROC_ROOT`, a debug build under `RMGUARD_TEST_SYSTEM_ROOT` reads
    /// `<sysroot>/proc`, so the other end-to-end suites never see the host's listeners.
    #[test]
    fn the_system_root_knob_hides_the_hosts_proc() {
        let home = temp_dir("sysroot");
        let keep = ["listeners"];
        let skip: Vec<&str> = ALL_LABELS.iter().copied().filter(|l| !keep.contains(l)).collect();
        let out = Command::new(bin())
            .args(["--skip", &skip.join(","), "--format", "json"])
            .env("HOME", &home)
            .env("RMGUARD_TEST_SYSTEM_ROOT", home.join("sysroot"))
            .env_remove("RMGUARD_TEST_PROC_ROOT")
            .current_dir(&home)
            .output()
            .unwrap();
        let v: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert!(v.get("network_listeners").is_none(), "{v}");
        let row = v["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["scanner"] == "listeners")
            .expect("a listeners diagnostics row");
        assert_eq!(row["skipped"], false);
        assert!(row["files_missing"].as_u64().unwrap() > 0, "it looked: {row}");
        fs::remove_dir_all(&home).unwrap();
    }
}

fn bin() -> String {
    std::env::var("RMGUARD_TEST_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_rmguard").to_string())
}

/// The test knobs are compiled into debug builds only: a release binary does not carry
/// their names, so no environment variable can point a real scan at a fake `/proc` or
/// system root. Checked on the binary under test (both directions, so the check itself
/// is seen to work); `cargo test --release --test listeners test_knobs` checks the release
/// side (the other end-to-end tests here need the knobs, so they are debug-only).
#[test]
fn test_knobs_are_absent_from_release_builds() {
    let bytes = fs::read(bin()).expect("read the binary");
    for knob in ["RMGUARD_TEST_PROC_ROOT", "RMGUARD_TEST_SYSTEM_ROOT"] {
        let found = bytes.windows(knob.len()).any(|w| w == knob.as_bytes());
        // The /proc knob is only compiled on Linux (the listener scanner is skipped
        // elsewhere), so its presence is asserted there alone; absence from a release
        // build is asserted on every platform.
        let compiled_in = knob != "RMGUARD_TEST_PROC_ROOT" || cfg!(target_os = "linux");
        if cfg!(debug_assertions) && compiled_in {
            assert!(
                found,
                "{knob} missing from a debug build: is the check still finding it?"
            );
        } else if !cfg!(debug_assertions) {
            assert!(!found, "{knob} is in a release build");
        }
    }
}
