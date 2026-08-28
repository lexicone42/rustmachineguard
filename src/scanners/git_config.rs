use crate::models::GitAutorunConfig;
use crate::platform::PlatformInfo;
use crate::scanners::{read_bounded, Scanner};
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
        let mut out = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for dir in dirs {
            if !seen.insert(dir.clone()) {
                continue;
            }
            scan_repo_local(&dir, &mut out);
            scan_nested_repos(&dir, &mut out);
        }
        out
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
            .filter(|p| p.is_dir())
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
    let out = std::process::Command::new("git")
        .arg("--no-pager")
        .args(top_args)
        .arg("config")
        .args(config_args)
        .args(["--list", "--show-origin", "--includes", "-z"])
        .output()
        .ok()?;
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
    if !git_dir.exists() {
        return;
    }
    let gd = git_dir.to_string_lossy().to_string();
    let Some(text) = run_git_config(&[format!("--git-dir={gd}")], &["--local".to_string()]) else {
        return;
    };
    collect(&text, dir, "repo-local", false, out);
}

/// Walk for git directories BURIED inside the project — the CVE-2026-45033 shape. A
/// directory shipped inside a repo can itself be a git dir (HEAD/config/objects/refs are
/// all legal tracked filenames), and git auto-discovers it from the cwd. Its config is
/// attacker-authored in a way the project's own `.git/config` is not.
fn scan_nested_repos(root: &Path, out: &mut Vec<GitAutorunConfig>) {
    const MAX_DIRS: usize = 4_000;
    let mut budget = MAX_DIRS;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if budget == 0 {
                return;
            }
            let p = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            // Spend budget only on directories. Charging it per plain FILE let a repo
            // with a few thousand junk files exhaust the walk before reaching the buried
            // git dir -- a deterministic, attacker-controllable way to hide from the
            // CVE-2026-45033 check.
            budget -= 1;
            // A git dir has a config file plus HEAD; that pair is the cheap signal.
            let cfg = p.join("config");
            if cfg.is_file() && p.join("HEAD").is_file() {
                // The project's own .git is handled by scan_repo_local.
                if p != root.join(".git")
                    && let Some(text) =
                        run_git_config(&[], &[format!("--file={}", cfg.display())])
                {
                    collect(&text, &p, "nested-repo", true, out);
                }
                continue; // don't descend into a git dir's internals
            }
            stack.push(p);
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
        out.push(GitAutorunConfig {
            path: location.to_string_lossy().to_string(),
            origin,
            key,
            // A credential.helper can embed a live password; the command SHAPE is the
            // finding, the credential is not.
            value: crate::scanners::redact_secrets_in_text(&value),
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
    scan_nested_repos(root, out);
}
