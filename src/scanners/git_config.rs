use crate::models::GitAutorunConfig;
use crate::platform::PlatformInfo;
use crate::scanners::{read_bounded, Scanner};
use crate::otel::{Attr, Key};
use std::path::{Path, PathBuf};

/// Detects git configuration that makes an ordinary git command execute an attacker's
/// code — the class behind CVE-2026-45033 (Copilot CLI, nested bare repository).
///
/// # Why this is value-gated, not key-gated
///
/// Nearly every exec-capable git key has a common legitimate use: `core.fsmonitor=true`
/// selects git's own built-in daemon, `core.hooksPath` is set by husky on every
/// `npm install`, `filter.*` is git-lfs, `credential.helper` is the OS keychain,
/// `core.pager` is delta. Flagging the KEY reports git's own features as RCE and trains
/// users to ignore the tool. So we flag only when the VALUE is attack-shaped, and only
/// in a scope an untrusted repository can actually control.
///
/// Protected scope (`~/.gitconfig`, `/etc/gitconfig`) is never reported: git itself
/// treats that as user-controlled, and on an ordinary machine it is ~100% noise.
pub struct GitConfigScanner;

/// Keys whose value git executes as a command. Examined only in untrusted scope.
const EXEC_KEYS: &[&str] = &[
    "core.fsmonitor",
    "core.hookspath",
    "core.sshcommand",
    "core.gitproxy",
    "diff.external",
    "credential.helper",
];

/// Key suffixes for the `<section>.<name>.<key>` forms git executes.
const EXEC_KEY_SUFFIXES: &[&str] = &[
    ".textconv",
    ".clean",
    ".smudge",
    ".process",
    ".driver",
    ".command",
];

impl Scanner for GitConfigScanner {
    type Output = Vec<GitAutorunConfig>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<GitAutorunConfig> {
        let home = platform.home_dir();
        let mut dirs = extract_project_dirs(&home.join(".claude.json")).unwrap_or_default();
        if let Ok(cwd) = std::env::current_dir() {
            dirs.push(cwd);
        }
        let mut seen = std::collections::HashSet::new();
        dirs.retain(|d| seen.insert(d.clone()));
        // Two passes, each under its own span, so the trace separates git config reads
        // from the directory walk. Findings are kept per project and joined in the old
        // order (each project's repo-local findings, then its nested ones): the report
        // is the same as the single interleaved pass produced.
        let mut local: Vec<Vec<GitAutorunConfig>> = Vec::with_capacity(dirs.len());
        {
            let mut span = crate::otel::span("gitconfig.repos", Vec::new);
            for dir in &dirs {
                let mut o = Vec::new();
                scan_repo_local(dir, &mut o);
                local.push(o);
            }
            span.set(|| vec![Attr::int(Key::Repos, dirs.len() as i64)]);
        }
        // HOME, or an ancestor of it, registered as a project (or the cwd when rmguard
        // runs from HOME) is not walked for nested git dirs: the skills scanner's rule
        // (HOME is never a project). Its walk was every directory under HOME up to the
        // budget, in no meaningful order, and ran out of budget on any real HOME. Its
        // repo-local config (a dotfiles repo at ~/.git) is still checked above.
        let walkable = crate::scanners::skills::project_dirs_excluding_home(dirs.clone(), &home);
        let nested = {
            let mut span = crate::otel::span("gitconfig.nested_walk", Vec::new);
            let jobs = crate::scanners::telemetry::helper_jobs();
            let (nested, stats) = walk_projects(&dirs, &walkable, jobs);
            span.set(|| {
                vec![
                    Attr::int(Key::WalkEntries, stats.entries as i64),
                    Attr::int(Key::WalkDirs, stats.dirs as i64),
                    Attr::int(Key::WalkPruned, stats.pruned as i64),
                    Attr::int(Key::Repos, stats.repos as i64),
                    Attr::bool(Key::WalkBudgetExhausted, stats.budget_exhausted),
                ]
            });
            nested
        };
        local.into_iter().zip(nested).flat_map(|(l, n)| l.into_iter().chain(n)).collect()
    }
}

/// The nested walk of every project in `dirs` that is in `walkable`, on up to `jobs`
/// threads ([`par_map`](crate::scanners::telemetry::par_map)), one project per task, each
/// with its own directory budget and its own [`WalkStats`]. Findings come back per
/// project in `dirs` order and the stats are summed in that order, so neither depends on
/// which project finished first; `jobs` 1 is the sequential loop.
fn walk_projects(dirs: &[PathBuf], walkable: &[PathBuf], jobs: usize) -> (Vec<Vec<GitAutorunConfig>>, WalkStats) {
    let per_project = crate::scanners::telemetry::par_map(dirs.iter().collect(), jobs, |dir: &PathBuf| {
        let (mut o, mut stats) = (Vec::new(), WalkStats::default());
        if walkable.contains(dir) {
            scan_nested_repos(dir, &mut o, &mut stats);
        }
        (o, stats)
    });
    let mut total = WalkStats::default();
    let nested = per_project
        .into_iter()
        .map(|(o, s)| {
            total.add(&s);
            o
        })
        .collect();
    (nested, total)
}

/// Counts for the `gitconfig.nested_walk` span, summed over every project walked.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct WalkStats {
    /// Directory entries seen.
    entries: u64,
    /// Directories listed.
    dirs: u64,
    /// Nested git directories found (git's own HEAD + objects/ + refs/ test).
    repos: u64,
    /// Directories not descended into as generated content: skipped by name
    /// (`node_modules`, ...) or listed and found to hold a `CACHEDIR.TAG` or
    /// `pyvenv.cfg`.
    pruned: u64,
    /// A project's walk stopped at its directory budget.
    budget_exhausted: bool,
}

impl WalkStats {
    /// Fold one project's counts into the total.
    fn add(&mut self, o: &WalkStats) {
        self.entries += o.entries;
        self.dirs += o.dirs;
        self.repos += o.repos;
        self.pruned += o.pruned;
        self.budget_exhausted |= o.budget_exhausted;
    }
}

fn extract_project_dirs(claude_json: &Path) -> Option<Vec<PathBuf>> {
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

/// Ask git itself for the effective repo-local config.
///
/// Three flags here are load-bearing, each verified by experiment rather than assumed:
/// * `--includes` — WITHOUT it, `--local` does NOT resolve `include.path`, so a config
///   that hides `core.fsmonitor` in an included file is invisible. Omitting this makes
///   the whole scanner trivially bypassable.
/// * `--no-pager` — `git config --list` attached to a TTY EXECUTES the repo's
///   `core.pager` value. Reading a hostile config must not run it.
/// * `--git-dir=` rather than `-C` — `-C` performs repo discovery, so a project nested
///   inside a larger repo would return the OUTER repo's config under `--local`.
fn run_git_config(top_args: &[String], config_args: &[String]) -> Option<String> {
    // Ordering matters: `--git-dir` is a top-level git option and must precede
    // `config`, whereas `--local` / `--file` are `git config` options and must follow
    // it. Passing them in the wrong position makes git error out and the scanner
    // silently report nothing.
    let mut cmd = crate::scanners::git_command();
    cmd.arg("--no-pager")
        .args(top_args)
        .arg("config")
        .args(config_args)
        .args(["--list", "--show-origin", "--includes", "-z"]);
    // Attacker-authored: `[include] path = /dev/tty` or a FIFO blocks git forever.
    let out = crate::scanners::output_with_timeout(&mut cmd, std::time::Duration::from_secs(5))?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

/// Parse git's `-z` output: records are `origin\0key\nvalue\0`, or `origin\0key\0` for a
/// valueless key. Split on that, never on `=` — values legitimately contain `=`.
fn parse_z(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut it = text.split('\0');
    while let (Some(origin), Some(kv)) = (it.next(), it.next()) {
        if origin.is_empty() {
            continue;
        }
        let (key, value) = match kv.split_once('\n') {
            Some((k, v)) => (k, v),
            None => (kv, ""),
        };
        out.push((
            origin.trim_start_matches("file:").to_string(),
            key.to_ascii_lowercase(),
            value.to_string(),
        ));
    }
    out
}

fn scan_repo_local(dir: &Path, out: &mut Vec<GitAutorunConfig>) {
    let git_dir = dir.join(".git");
    if !crate::scanners::probe_exists(&git_dir) {
        // A project that IS a bare gitdir: an agent launched inside a payload directory
        // (`cd vendor/evil && claude`) registers that directory as a project, and git
        // treats the cwd as the repo -- CVE-2026-45033's own shape, and the one place
        // git is guaranteed to look. Neither path checked it before.
        let cfg = dir.join("config");
        if is_bare_gitdir(dir)
            && config_needs_git(&cfg)
            && let Some(text) = run_git_config(&[], &[format!("--file={}", cfg.display())])
        {
            collect(&text, dir, "bare-root", true, out);
        }
        return;
    }
    if !config_needs_git(&git_dir.join("config")) {
        return;
    }
    let gd = git_dir.to_string_lossy().to_string();
    let Some(text) = run_git_config(&[format!("--git-dir={gd}")], &["--local".to_string()]) else {
        return;
    };
    collect(&text, dir, "repo-local", false, out);
}

/// Decide, from the file itself, whether `git config --list` needs to run on it.
///
/// Spawning git is the faithful way to resolve `include`/`includeIf` and git's own key
/// normalisation, but it costs a process per config -- 774 execs and 2.5s on one
/// developer machine with 32 registered projects, almost all for files holding nothing
/// but `[core]` and `[remote "origin"]`. So read the file first (bounded, and counted
/// in the scan diagnostics) and spawn only when it mentions an exec-capable key, the
/// `ext` transport, or an include that could pull one in from elsewhere.
///
/// Anything we cannot read -- a worktree's `.git` FILE, a permissions problem -- is
/// handed to git anyway: the conservative direction is to spawn.
fn config_needs_git(cfg: &Path) -> bool {
    const NEEDLES: &[&str] = &[
        "fsmonitor", "hookspath", "sshcommand", "gitproxy", "external", "credential",
        "textconv", "clean", "smudge", "process", "driver", "command", "include", "ext",
    ];
    let Some(text) = crate::scanners::read_bounded(cfg) else {
        return true;
    };
    let lower = text.to_ascii_lowercase();
    NEEDLES.iter().any(|n| lower.contains(n))
}

/// Walk for git directories BURIED inside the project — the CVE-2026-45033 shape. A
/// directory shipped inside a repo can itself be a git dir (HEAD/config/objects/refs are
/// all legal tracked filenames), and git auto-discovers it from the cwd. Its config is
/// attacker-authored in a way the project's own `.git/config` is not.
fn scan_nested_repos(root: &Path, out: &mut Vec<GitAutorunConfig>, stats: &mut WalkStats) {
    const MAX_DIRS: usize = 4_000;
    /// Trees skipped BY NAME: dependency and tooling dirs that are where nearly all of
    /// a project's directories live, and that no sane repo ships as tracked content.
    /// Deliberately NOT here: `env`, `venv`, `target`, `build`, `dist` -- those are
    /// plausible names for tracked directories, and an attacker chooses the layout, so
    /// skipping them by name would be a deterministic way to hide a gitdir. Those are
    /// recognised by marker instead (see GENERATED_MARKERS).
    const PRUNE_BY_NAME: &[&str] = &[
        "node_modules", ".tox", ".mypy_cache", ".pytest_cache", "__pycache__", ".cache",
        ".npm", ".cargo", "site-packages", "dist-packages",
    ];
    /// A directory whose listing contains one of these was produced by a tool, not
    /// committed: `pyvenv.cfg` marks a virtualenv (written at a venv's top by Python's
    /// `venv`, https://docs.python.org/3/library/venv.html), `CACHEDIR.TAG` marks cargo's
    /// target/ and most caches (the Cache Directory Tagging Specification,
    /// https://bford.info/cachedir/, which cargo, pip, uv and others follow). Only the
    /// name in the listing is checked; neither file is opened. The gitdir check runs BEFORE this skip, so planting a marker in
    /// the payload directory itself does not hide it; planting one in an ancestor does,
    /// which is the same adversarial floor as exhausting the directory budget.
    const GENERATED_MARKERS: &[&str] = &["pyvenv.cfg", "CACHEDIR.TAG"];
    let own_git = root.join(".git");
    let mut budget = MAX_DIRS;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        // Budget is spent per directory LISTED, never per file: charging it per entry
        // let a few thousand junk files exhaust the walk before it reached a buried git
        // dir -- an attacker-controllable way to hide from the CVE-2026-45033 check.
        if budget == 0 {
            stats.budget_exhausted = true;
            crate::scanners::telemetry::mark_truncated();
            return;
        }
        budget -= 1;
        let Ok(entries) = crate::scanners::probe_read_dir(&dir) else {
            continue;
        };
        stats.dirs += 1;
        // One listing answers both questions -- "is this a git dir?" and "what do I
        // descend into?" -- using the entry type the listing already carries. The
        // previous version stat'ed every entry and then stat'ed config and HEAD again
        // per directory: three extra syscalls a dir, over ~130k dirs on one machine.
        let (mut has_config, mut has_head, mut has_objects, mut has_refs, mut generated) =
            (false, false, false, false, false);
        let mut children = Vec::new();
        for entry in entries.flatten() {
            stats.entries += 1;
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            // A symlink reports itself here, not its target. Resolve it for the FILE
            // checks -- `config -> ../real-config` is how a payload hid from the first
            // version of this walk -- but never descend through a symlinked directory.
            // git's is_git_directory uses stat(), which follows symlinks, so a symlinked
            // objects/ or refs/ satisfies it -- and therefore must satisfy us. Resolve the
            // target type for the CRITERION; the descent decision below is separate and
            // never follows a symlinked directory.
            let (is_file, is_dir) = if kind.is_symlink() {
                match std::fs::metadata(entry.path()) {
                    Ok(m) => (m.is_file(), m.is_dir()),
                    Err(_) => (false, false),
                }
            } else {
                (kind.is_file(), kind.is_dir())
            };
            // A symlink named HEAD counts here whatever its target: git never opens the
            // target, it reads the link text, and head_is_valid() decides below.
            if name == "HEAD" && (is_file || kind.is_symlink()) {
                has_head = true;
            } else if is_file {
                if name == "config" {
                    has_config = true;
                } else if GENERATED_MARKERS.iter().any(|m| name == *m) {
                    generated = true;
                }
            } else if is_dir {
                if name == "objects" {
                    has_objects = true;
                } else if name == "refs" {
                    has_refs = true;
                }
                // A symlinked directory is never descended through (above), and is not
                // counted as pruned.
                if !kind.is_symlink() {
                    if PRUNE_BY_NAME.iter().any(|p| name == *p) {
                        stats.pruned += 1;
                    } else {
                        children.push((name, entry.path()));
                    }
                }
            }
        }
        // git's own test (setup.c is_git_directory): HEAD plus objects/ and refs/
        // directories. That is what makes git treat a cwd as a bare repo and read its
        // config -- the CVE-2026-45033 shape. Two plain files named config and HEAD are
        // NOT a git dir, and the first version of this walk treated them as one and
        // stopped descending: an attacker could hide a whole subtree, or the whole
        // project, behind two empty files.
        // git also validates HEAD's CONTENT (validate_headref): a symref or an object
        // id. A junk HEAD is not a git dir to git, so reporting it would be a false
        // positive from a scanner whose whole design is to not cry wolf.
        let is_git_dir =
            has_head && has_objects && has_refs && dir != root && head_is_valid(&dir.join("HEAD"));
        if dir == own_git {
            continue; // the project's own .git is handled by scan_repo_local
        }
        if is_git_dir {
            stats.repos += 1;
        }
        if is_git_dir && has_config {
            let cfg = dir.join("config");
            if config_needs_git(&cfg)
                && let Some(text) = run_git_config(&[], &[format!("--file={}", cfg.display())])
            {
                collect(&text, &dir, "nested-repo", true, out);
            }
        }
        if generated && !is_git_dir {
            stats.pruned += 1;
            continue; // a virtualenv or build cache: nothing in it was shipped by the repo
        }
        // Keep descending through a nested git dir too -- a decoy with a boring config
        // must not hide a real payload underneath it -- but not into its object store,
        // which fans out 256 ways and is not somewhere an agent cds into.
        for (name, path) in children {
            if is_git_dir && name == "objects" {
                continue;
            }
            stack.push(path);
        }
    }
}

fn collect(text: &str, location: &Path, scope: &str, nested: bool, out: &mut Vec<GitAutorunConfig>) {
    for (origin, key, value) in parse_z(text) {
        let is_exec_key = EXEC_KEYS.contains(&key.as_str())
            || EXEC_KEY_SUFFIXES.iter().any(|s| key.ends_with(s));
        // protocol.ext.allow re-enables the `ext::` transport, which runs an arbitrary
        // command as the git transport. git's default is `never` precisely because of
        // that, and there is no mainstream legitimate reason for a repo to flip it.
        let is_ext_allow = key == "protocol.ext.allow" && value.eq_ignore_ascii_case("always");
        if !is_exec_key && !is_ext_allow {
            continue;
        }
        let shape = if is_ext_allow {
            Some("re-enables the ext:: transport, which runs an arbitrary command".to_string())
        } else {
            attack_shape(&value)
        };
        let Some(reason) = shape else { continue };
        // Key, value, origin and path are attacker-authored (a quoted subsection name may
        // hold ESC) and are printed on the Critical line: sanitize them all.
        out.push(GitAutorunConfig {
            path: crate::scanners::sanitize_display(&location.to_string_lossy(), 512),
            origin: crate::scanners::sanitize_display(&origin, 512),
            key: crate::scanners::sanitize_display(&key, 128),
            // A credential.helper can embed a live password; the command SHAPE is the
            // finding, the credential is not.
            value: crate::scanners::sanitize_display(&crate::scanners::redact_secrets_in_text(&value), 512),
            scope: scope.to_string(),
            nested,
            reason,
        });
    }
}

/// Decide whether an exec-key VALUE is attack-shaped. This is where the false-positive
/// budget is spent, so it is deliberately narrow: a value is only reported when it
/// chains shell commands, matches a known-dangerous pattern, or runs a script from
/// inside the repository itself.
///
/// Returns None for the ordinary values a developer machine is full of: `true`, `auto`,
/// a bare program name (`delta`, `git-lfs`), or a program with plain flags.
pub fn attack_shape(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }
    // git's own built-in fsmonitor / boolean forms.
    if matches!(v.to_ascii_lowercase().as_str(), "true" | "false" | "auto" | "1" | "0") {
        return None;
    }
    // Shell command chaining or substitution: the value is not one program with
    // arguments, it is a script. Legitimate helpers do not need this.
    let normalized = crate::scanners::normalize_for_matching(v);
    for (tok, why) in [
        (";", "chains a second shell command"),
        ("&&", "chains a second shell command"),
        ("||", "chains a second shell command"),
        ("|", "pipes into another command"),
        ("$(", "uses command substitution"),
        ("`", "uses command substitution"),
        ("\n", "contains a newline, i.e. multiple commands"),
    ] {
        if normalized.contains(tok) {
            return Some(format!("value {why}"));
        }
    }
    // Known-dangerous content (curl|bash, base64 -d, …) — reuses the shared,
    // evasion-normalized matcher.
    if let Some(found) = crate::scanners::rules_files::check_dangerous_patterns(v).first() {
        return Some(format!("value matches a dangerous pattern: {}", found.pattern));
    }
    // A script path inside the repository: the config points at content the repo ships,
    // which is the smuggled-payload shape. `git-lfs`, `delta`, `/usr/bin/…` are not.
    let first = v.trim_start_matches('!').split_whitespace().next().unwrap_or("");
    if first.starts_with("./") || first.starts_with("../") || first.contains("/../") {
        return Some("value runs a script from inside the repository".to_string());
    }
    None
}

/// Test hook for the nested-repo walk, which is otherwise reachable only through a full
/// platform scan.
pub fn scan_nested_repos_for_test(root: &Path, out: &mut Vec<GitAutorunConfig>) {
    scan_nested_repos(root, out, &mut WalkStats::default());
}

/// [`scan_nested_repos_for_test`] that also returns the walk's (directories listed,
/// directories pruned) counts.
pub fn nested_walk_counts_for_test(root: &Path, out: &mut Vec<GitAutorunConfig>) -> (u64, u64) {
    let mut stats = WalkStats::default();
    scan_nested_repos(root, out, &mut stats);
    (stats.dirs, stats.pruned)
}

#[cfg(test)]
mod needs_git_tests {
    use super::config_needs_git;

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("rmg-cfg-{}-{name}", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn boring_config_does_not_spawn_git() {
        let p = tmp("boring", "[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.com/x.git\n");
        assert!(!config_needs_git(&p));
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn exec_keys_includes_and_ext_transport_spawn_git() {
        for (n, body) in [
            ("fsm", "[core]\n\tfsmonitor = ./x\n"),
            ("hooks", "[core]\n\thooksPath = .hooks\n"),
            ("filter", "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n"),
            ("inc", "[include]\n\tpath = ../other\n"),
            ("incif", "[includeIf \"gitdir:~/w/\"]\n\tpath = x\n"),
            ("ext", "[protocol \"ext\"]\n\tallow = always\n"),
            ("cred", "[credential]\n\thelper = !f() { :; }; f\n"),
        ] {
            let p = tmp(n, body);
            assert!(config_needs_git(&p), "{n}: {body:?}");
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn unreadable_config_is_left_to_git() {
        // A worktree's `.git` is a FILE, so `.git/config` does not exist; git resolves
        // the real gitdir itself, and we must not skip it.
        assert!(config_needs_git(std::path::Path::new("/nonexistent/.git/config")));
    }
}

/// Mirror git's validate_headref. A symlink HEAD is lstat()ed and readlink()ed: the
/// link text must start with "refs/", and the target is never opened (a dangling link
/// is fine). A regular HEAD is `ref: refs/...` or an object id: git parses the FIRST 40
/// (or 64) hex characters and ignores whatever follows, so `<40 hex> junk` and 41 hex
/// characters are valid -- requiring the whole line to be hex let those hide a gitdir.
fn head_is_valid(head: &Path) -> bool {
    if let Ok(m) = std::fs::symlink_metadata(head)
        && m.file_type().is_symlink()
    {
        return std::fs::read_link(head)
            .ok()
            .is_some_and(|t| t.to_string_lossy().starts_with("refs/"));
    }
    let Some(bytes) = crate::scanners::read_head_bytes(head, 256) else {
        return false;
    };
    let text = String::from_utf8_lossy(&bytes);
    if let Some(target) = text.strip_prefix("ref:") {
        return target.trim_start().starts_with("refs/");
    }
    text.chars().take_while(|c| c.is_ascii_hexdigit()).count() >= 40
}

/// git's is_git_directory for a directory that is itself the repo: valid HEAD plus
/// objects/ and refs/ (symlinks followed, as stat() does).
fn is_bare_gitdir(dir: &Path) -> bool {
    head_is_valid(&dir.join("HEAD"))
        && crate::scanners::probe_dir(&dir.join("objects"))
        && crate::scanners::probe_dir(&dir.join("refs"))
}

#[cfg(test)]
mod walk_projects_tests {
    use super::{walk_projects, WalkStats};
    use std::path::{Path, PathBuf};

    /// A buried bare git dir at `<project>/<rel>` whose `core.fsmonitor` runs a script
    /// named after `tag`, so each finding says which project and repo it came from.
    fn plant(project: &Path, rel: &str, tag: &str) {
        let g = project.join(rel);
        std::fs::create_dir_all(g.join("objects")).unwrap();
        std::fs::create_dir_all(g.join("refs")).unwrap();
        std::fs::write(g.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::write(g.join("config"), format!("[core]\n\tfsmonitor = \"./{tag}.sh\"\n")).unwrap();
    }

    fn base(tag: &str) -> PathBuf {
        let b = std::env::temp_dir().join(format!("rmg-gc-walk-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&b);
        b
    }

    fn findings(nested: &[Vec<crate::models::GitAutorunConfig>]) -> Vec<Vec<String>> {
        nested.iter().map(|o| o.iter().map(|c| serde_json::to_string(c).unwrap()).collect()).collect()
    }

    /// Three projects (one registered but not walkable) walked at `jobs` 1 and `jobs` 4:
    /// the same findings, per project, in project order, and the same summed counts.
    #[test]
    fn projects_walked_concurrently_keep_order_and_counts() {
        let b = base("order");
        let dirs: Vec<PathBuf> = (0..4).map(|i| b.join(format!("proj{i}"))).collect();
        for (i, d) in dirs.iter().enumerate() {
            for j in 0..30 {
                std::fs::create_dir_all(d.join(format!("src/m{j}"))).unwrap();
            }
            std::fs::create_dir_all(d.join("node_modules/dep")).unwrap();
            plant(d, "vendor/a", &format!("p{i}-a"));
            plant(d, &format!("src/m{}/b", i * 3), &format!("p{i}-b"));
        }
        // proj2 is registered but not walked (HOME-as-project): no findings, no counts.
        let walkable: Vec<PathBuf> = dirs.iter().filter(|d| !d.ends_with("proj2")).cloned().collect();
        let (n1, s1) = walk_projects(&dirs, &walkable, 1);
        let (n4, s4) = walk_projects(&dirs, &walkable, 4);
        let _ = std::fs::remove_dir_all(&b);
        let (f1, f4) = (findings(&n1), findings(&n4));
        assert_eq!(f1, f4, "findings differ between jobs 1 and jobs 4");
        assert_eq!(s1, s4, "walk counts differ between jobs 1 and jobs 4");
        assert_eq!(f1.len(), 4);
        for (i, per) in f1.iter().enumerate() {
            if i == 2 {
                assert!(per.is_empty(), "unwalkable project produced {per:?}");
                continue;
            }
            assert_eq!(per.len(), 2, "project {i}: {per:?}");
            assert!(per.iter().all(|f| f.contains(&format!("proj{i}")) && f.contains(&format!("p{i}-"))), "project {i}: {per:?}");
        }
        assert_eq!(s1.repos, 6);
        assert_eq!(s1.pruned, 3);
        assert!(!s1.budget_exhausted);
    }

    /// One project past its 4,000-directory budget and one well inside it, at `jobs` 4:
    /// the scanner row is `truncated` (set on whichever thread walked the big project),
    /// the big project stopped at exactly its own budget, and the small project's walk is
    /// complete, its buried repos all found, as at `jobs` 1.
    #[test]
    fn one_project_over_budget_leaves_the_others_complete() {
        let b = base("budget");
        let big = b.join("big");
        for i in 0..70 {
            for j in 0..60 {
                std::fs::create_dir_all(big.join(format!("d{i}/e{j}"))).unwrap();
            }
        }
        let small = b.join("small");
        for j in 0..20 {
            std::fs::create_dir_all(small.join(format!("lib/x{j}"))).unwrap();
        }
        plant(&small, "lib/x3/pay", "small-1");
        plant(&small, "lib/x17/deep/pay", "small-2");
        let dirs = vec![big.clone(), small.clone()];
        let mut seen: Vec<(Vec<Vec<String>>, WalkStats, bool)> = Vec::new();
        for jobs in [1, 4] {
            let (out, pending) = crate::scanners::telemetry::run("gitconfig", None, || {
                let (n, s) = walk_projects(&dirs, &dirs, jobs);
                vec![(n, s)]
            });
            let stat = pending.finalize();
            let (n, s) = out.into_iter().next().unwrap();
            seen.push((findings(&n), s, stat.truncated));
        }
        // The small project alone, for its complete count.
        let (_, alone) = walk_projects(std::slice::from_ref(&small), std::slice::from_ref(&small), 1);
        let _ = std::fs::remove_dir_all(&b);
        let (f4, s4, truncated4) = &seen[1];
        assert_eq!(seen[0].0, *f4, "findings differ between jobs 1 and jobs 4");
        assert_eq!(seen[0].1, *s4, "counts differ between jobs 1 and jobs 4");
        assert!(seen[0].2 && *truncated4, "truncated: jobs 1 {}, jobs 4 {truncated4}", seen[0].2);
        assert!(s4.budget_exhausted);
        assert_eq!(s4.dirs, 4_000 + alone.dirs, "the big project's own budget, the small one complete");
        assert_eq!(f4[0].len(), 0);
        assert_eq!(f4[1].len(), 2, "small project findings: {:?}", f4[1]);
        assert!(f4[1][0].contains("small-") && f4[1][1].contains("small-"));
    }
}
