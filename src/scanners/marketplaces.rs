use crate::models::{AgentMarketplace, PluginPinIssue};
use crate::platform::PlatformInfo;
use crate::scanners::{read_bounded, redact_secrets_in_text, sanitize_display, Scanner};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

/// Inventories Claude Code plugin marketplaces — remote git sources whose plugins and
/// skills run as agent code (the EAA-009 remote hot-load surface). Records provenance
/// (source, official-vs-third-party) and whether each auto-updates. Reads config JSON
/// and plain git files only; never fetches, clones, or executes a marketplace.
pub struct MarketplacesScanner;

// Plugin4Shell (Air Security: Or Nevo Michrowski, Dor Granat, Niv Hoffman; CVE-2026-86063).
// Plain-file reads only: never spawn git in a marketplace clone.
//
// A plugin "pinned" to a commit was checked out by NAME, and git resolves a name to a
// branch or tag before it tries it as an object ID, so a branch called
// `af59ee3a1051a29dda4a2e7a2af221aa457ae08b` in the upstream repository silently replaced
// the reviewed commit. git itself never creates a ref named like an object ID, so one on
// disk is either the attack or a pin that floats with a branch.
//
// Floors, stated so nobody mistakes silence for coverage:
// - marketplaces not listed in known_marketplaces.json are skipped;
// - a `.git` that is a FILE (`gitdir:` indirection, a worktree) is skipped;
// - only installed plugins' manifest pins are checked.

impl Scanner for MarketplacesScanner {
    type Output = Vec<AgentMarketplace>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<AgentMarketplace> {
        let dir = platform.claude_config_dir().join("plugins");
        let known_path = dir.join("known_marketplaces.json");
        let Some(content) = read_bounded(&known_path) else {
            return Vec::new();
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) else {
            return Vec::new();
        };
        let installed_path = dir.join("installed_plugins.json");
        let installed_json = read_bounded(&installed_path)
            .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok());
        let counts = installed_json.as_ref().map(plugin_counts).unwrap_or_default();
        let mut mps = parse_marketplaces(&json, &counts);
        let installed = installed_json.as_ref().map(installed_entries).unwrap_or_default();
        attach_pin_issues(&dir, &json, &installed, &mut mps);
        mps
    }
}

/// `installed_plugins.json` as `(plugin, marketplace) -> entries`.
pub fn installed_entries(json: &serde_json::Value) -> BTreeMap<(String, String), Vec<serde_json::Value>> {
    let mut out: BTreeMap<(String, String), Vec<serde_json::Value>> = BTreeMap::new();
    let Some(plugins) = json.get("plugins").and_then(|v| v.as_object()) else {
        return out;
    };
    for (key, entries) in plugins {
        let Some((plugin, market)) = key.rsplit_once('@') else { continue };
        let list = out.entry((plugin.to_string(), market.to_string())).or_default();
        match entries {
            serde_json::Value::Array(a) => list.extend(a.iter().cloned()),
            serde_json::Value::Object(_) => list.push(entries.clone()),
            _ => {}
        }
    }
    out
}

fn show_path(p: &Path) -> String {
    sanitize_display(&p.to_string_lossy(), 512)
}

/// A `sha` / `gitCommitSha` / ref value as it may be shown: a hex value by its first 12
/// characters, a plausible ref name (`[A-Za-z0-9._/-]`, 64 characters or fewer) as it is
/// (token shapes still redacted), anything else as `<unparseable>`. None of these fields
/// is a secret, but a credential pasted into the wrong field must not be echoed, and
/// free text (ESC, spaces) is no ref name.
fn show_value(v: &str) -> String {
    let t = v.trim();
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return hex12(t);
    }
    let ref_name = t.len() <= 64 && t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'));
    if ref_name {
        sanitize_display(&redact_secrets_in_text(t), 64)
    } else {
        "<unparseable>".to_string()
    }
}

fn hex12(s: &str) -> String {
    let s = sanitize_display(s, 64);
    if s.chars().count() > 12 {
        format!("{}…", s.chars().take(12).collect::<String>())
    } else {
        s
    }
}

/// True when `path` lexically lies under `prefix` (no filesystem access).
fn lexically_under(path: &Path, prefix: &Path) -> bool {
    let p = crate::scanners::persistence::lexical_join(Path::new("/"), path);
    let q = crate::scanners::persistence::lexical_join(Path::new("/"), prefix);
    p.starts_with(&q) && p != q
}

/// The canonical path of `file` when it is a regular file, not itself a symlink, whose
/// real location lies inside the real location of `root`.
fn contained_real_path(file: &Path, root: &Path) -> Option<PathBuf> {
    if !std::fs::symlink_metadata(file).is_ok_and(|m| m.is_file()) {
        return None;
    }
    let real = std::fs::canonicalize(file).ok()?;
    let real_root = std::fs::canonicalize(root).ok()?;
    real.starts_with(&real_root).then_some(real)
}

/// A real `.git` DIRECTORY (not a symlink, not a `gitdir:` file).
fn git_dir_of(work: &Path) -> Option<PathBuf> {
    let g = work.join(".git");
    match std::fs::symlink_metadata(&g) {
        Ok(m) if m.is_dir() => Some(g),
        Ok(_) => None,
        Err(_) => {
            crate::scanners::telemetry::note_probe(&g, false);
            None
        }
    }
}

fn attach_pin_issues(
    plugins_dir: &Path,
    known: &serde_json::Value,
    installed: &BTreeMap<(String, String), Vec<serde_json::Value>>,
    mps: &mut [AgentMarketplace],
) {
    let Some(obj) = known.as_object() else { return };
    let market_root = plugins_dir.join("marketplaces");
    let cache_root = plugins_dir.join("cache");
    let known_path = plugins_dir.join("known_marketplaces.json");
    let installed_path = plugins_dir.join("installed_plugins.json");
    let mut by_market: HashMap<String, Vec<PluginPinIssue>> = HashMap::new();

    for (name, entry) in obj {
        let mut issues = Vec::new();
        // The clone directory: the default location, or installLocation only when it
        // stays inside it (a manifest must not point the scanner at an arbitrary tree).
        let default = market_root.join(name);
        let clone = entry
            .get("installLocation")
            .and_then(|v| v.as_str())
            .map(PathBuf::from)
            .filter(|p| lexically_under(p, &market_root))
            .unwrap_or(default);
        if lexically_under(&clone, &market_root) {
            if let Some(git) = git_dir_of(&clone) {
                issues.extend(git_pin_issues(&git));
            }
            // marketplace.json plugin pins, for plugins installed from this marketplace.
            // The clone's own file: repository content, so it is read only when it is a
            // regular file (not a symlink) whose real path stays inside the clone (a
            // symlinked `.claude-plugin` directory cannot redirect it either).
            let manifest = clone.join(".claude-plugin").join("marketplace.json");
            if crate::scanners::probe_file(&manifest)
                && let Some(real) = contained_real_path(&manifest, &clone)
                && let Some(text) = crate::scanners::read_bounded_nofollow(&manifest, Some(&real))
                && let Ok(mj) = serde_json::from_str::<serde_json::Value>(&text)
                && let Some(list) = mj.get("plugins").and_then(|v| v.as_array())
            {
                for p in list {
                    let Some(pname) = p.get("name").and_then(|v| v.as_str()) else { continue };
                    if !installed.contains_key(&(pname.to_string(), name.clone())) {
                        continue;
                    }
                    let Some(src) = p.get("source").filter(|s| s.is_object()) else { continue };
                    issues.extend(source_pin_issues(src, &manifest, Some(pname)));
                }
            }
        }
        // The marketplace's own source pin in known_marketplaces.json.
        if let Some(src) = entry.get("source").filter(|s| s.is_object()) {
            issues.extend(source_pin_issues(src, &known_path, None));
        }
        by_market.entry(name.clone()).or_default().extend(issues);
    }

    for ((plugin, market), entries) in installed {
        if !obj.contains_key(market) {
            continue; // floor: unlisted marketplaces are skipped
        }
        let mut issues = Vec::new();
        for e in entries {
            if let Some(sha) = e.get("gitCommitSha").and_then(|v| v.as_str())
                && let Some(problem) = sha_problem(sha)
            {
                issues.push(PluginPinIssue {
                    kind: format!("installed-sha-{problem}"),
                    path: show_path(&installed_path),
                    plugin: Some(sanitize_display(plugin, 128)),
                    detail: format!("gitCommitSha = {}", show_value(sha)),
                    mismatch: false,
                });
            }
            // A plugin cache that is itself a git clone gets the same ref checks.
            if let Some(ip) = e.get("installPath").and_then(|v| v.as_str()) {
                let ip = PathBuf::from(ip);
                if lexically_under(&ip, &cache_root)
                    && let Some(git) = git_dir_of(&ip)
                {
                    for mut i in git_pin_issues(&git) {
                        i.plugin = Some(sanitize_display(plugin, 128));
                        issues.push(i);
                    }
                }
            }
        }
        by_market.entry(market.clone()).or_default().extend(issues);
    }

    for m in mps.iter_mut() {
        // parse_marketplaces sanitizes names; match on the same transformation.
        let key = by_market
            .keys()
            .find(|k| sanitize_display(k, 128) == m.name)
            .cloned();
        if let Some(k) = key
            && let Some(mut issues) = by_market.remove(&k)
        {
            issues.sort_by(|a, b| {
                (&a.kind, &a.path, &a.plugin, &a.detail).cmp(&(&b.kind, &b.path, &b.plugin, &b.detail))
            });
            issues.dedup_by(|a, b| a.kind == b.kind && a.path == b.path && a.plugin == b.plugin && a.detail == b.detail);
            m.pin_issues = issues;
        }
    }
}

/// The two manifest rules, for a marketplace.json plugin `source` object or a
/// known_marketplaces.json `source`: a `sha` that is not a commit ID, or a commit ID
/// given as `ref` with no `sha` (the shape a same-named branch wins).
fn source_pin_issues(src: &serde_json::Value, path: &Path, plugin: Option<&str>) -> Vec<PluginPinIssue> {
    let mut out = Vec::new();
    let sha = src.get("sha").and_then(|v| v.as_str());
    let r#ref = src.get("ref").and_then(|v| v.as_str());
    if let Some(s) = sha
        && let Some(problem) = sha_problem(s)
    {
        out.push(PluginPinIssue {
            kind: format!("manifest-sha-{problem}"),
            path: show_path(path),
            plugin: plugin.map(|p| sanitize_display(p, 128)),
            detail: format!("sha = {}", show_value(s)),
            mismatch: false,
        });
    }
    if sha.is_none()
        && let Some(r) = r#ref
        && is_full_hex(r)
    {
        out.push(PluginPinIssue {
            kind: "manifest-ref-is-sha".into(),
            path: show_path(path),
            plugin: plugin.map(|p| sanitize_display(p, 128)),
            detail: format!("ref = {} with no sha", hex12(r)),
            mismatch: false,
        });
    }
    out
}

/// Why a `sha` / `gitCommitSha` value is not a full commit ID, or None when it is one:
/// "empty" (no pin recorded), "abbreviated" (a hex prefix: still a commit, but resolved
/// by name, so a branch of that name wins) or "not-commit" (a branch or tag name).
pub fn sha_problem(s: &str) -> Option<&'static str> {
    let t = s.trim();
    if is_full_hex(t) {
        None
    } else if t.is_empty() {
        Some("empty")
    } else if t.len() >= 4 && t.len() < 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some("abbreviated")
    } else {
        Some("not-commit")
    }
}

/// True for a full git object name: 40 (SHA-1) or 64 (SHA-256) ASCII hex digits.
pub fn is_full_hex(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// If `refname` puts a full-hex name in one of git's DWIM positions, return it:
/// `<H>`, `refs/<H>`, `refs/tags/<H>`, `refs/heads/<H>`, `refs/remotes/<r>/<H>`. The
/// last matters because checkout's remote-tracking guess turns `origin/<H>` into a local
/// branch when the pinned object is absent. Nested names (`refs/heads/feature/<H>`) are
/// not resolved from a bare `<H>` and do not qualify.
pub fn dwim_hex_name(refname: &str) -> Option<&str> {
    let parts: Vec<&str> = refname.split('/').collect();
    let h = *parts.last()?;
    if !is_full_hex(h) {
        return None;
    }
    let ok = match parts.as_slice() {
        [_] => true,
        ["refs", _] => true,
        ["refs", "heads" | "tags", _] => true,
        ["refs", "remotes", r, _] => !r.is_empty(),
        _ => false,
    };
    ok.then_some(h)
}

/// Parse `packed-refs` into `(oid, refname)`, skipping the `#` header and `^` peeled lines.
pub fn parse_packed_refs(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.starts_with('^'))
        .filter_map(|l| {
            let (oid, name) = l.trim_end().split_once(' ')?;
            Some((oid.to_string(), name.trim().to_string()))
        })
        .filter(|(o, n)| !o.is_empty() && !n.is_empty())
        .collect()
}

/// HEAD content: the branch name after `ref: refs/heads/`, if HEAD is symbolic.
pub fn parse_head(text: &str) -> Option<String> {
    let line = text.lines().next()?.trim();
    let rest = line.strip_prefix("ref:")?.trim();
    let name = rest.strip_prefix("refs/heads/")?;
    (!name.is_empty()).then(|| name.to_string())
}

/// FETCH_HEAD lines `<oid>\t[not-for-merge]\t<desc>`. The name is extracted for
/// `branch '<n>'`, `tag '<n>'` and `remote-tracking branch '<r>/<n>'` (remote prefix
/// removed); a description that is only a URL (a fetch by object ID) has no name.
pub fn parse_fetch_head(text: &str) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.splitn(3, '\t');
        let Some(oid) = parts.next().map(str::trim).filter(|o| !o.is_empty()) else { continue };
        let _flag = parts.next();
        let desc = parts.next().unwrap_or("").trim_start();
        let quoted = |prefix: &str| -> Option<String> {
            let rest = desc.strip_prefix(prefix)?;
            let end = rest.find('\'')?;
            Some(rest[..end].to_string())
        };
        let name = quoted("branch '")
            .or_else(|| quoted("tag '"))
            .or_else(|| {
                quoted("remote-tracking branch '")
                    .map(|n| n.split_once('/').map(|(_, b)| b.to_string()).unwrap_or(n))
            });
        out.push((oid.to_string(), name));
    }
    out
}

/// Every ref in `git_dir` whose name puts a full-hex string in a DWIM position, with the
/// object it points at (None if symbolic or unreadable) and the file it came from. Loose
/// refs override packed ones. Plain-file reads; symlinks are never followed.
pub fn sha_shaped_refs(git_dir: &Path) -> Vec<(String, Option<String>)> {
    sha_shaped_refs_with_source(git_dir).into_iter().map(|(n, (o, _))| (n, o)).collect()
}

const MAX_REF_ENTRIES: usize = 10_000;

fn ref_oid(path: &Path) -> Option<String> {
    let bytes = crate::scanners::read_head_bytes_nofollow(path, 256)?;
    let text = String::from_utf8(bytes).ok()?;
    let tok = text.split_whitespace().next()?;
    is_full_hex(tok).then(|| tok.to_ascii_lowercase())
}

fn sha_shaped_refs_with_source(git_dir: &Path) -> BTreeMap<String, (Option<String>, PathBuf)> {
    let mut out: BTreeMap<String, (Option<String>, PathBuf)> = BTreeMap::new();
    let packed = git_dir.join("packed-refs");
    if let Some(bytes) = crate::scanners::read_head_bytes_nofollow(&packed, 4 * 1024 * 1024) {
        let text = String::from_utf8_lossy(&bytes);
        for (oid, name) in parse_packed_refs(&text) {
            if dwim_hex_name(&name).is_some() {
                let oid = is_full_hex(&oid).then(|| oid.to_ascii_lowercase());
                out.insert(name, (oid, packed.clone()));
            }
        }
    }
    let mut budget = MAX_REF_ENTRIES;
    // `<git_dir>/<H>`: a top-level ref file named like a commit.
    if let Ok(entries) = std::fs::read_dir(git_dir) {
        for e in entries.flatten() {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let Some(n) = e.file_name().to_str().map(String::from) else { continue };
            if !is_full_hex(&n) {
                continue;
            }
            let p = e.path();
            if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file()) {
                out.insert(n, (ref_oid(&p), p));
            }
        }
    }
    // The walk root is checked like every entry below it: a `.git/refs` that is a link
    // (to a directory outside the clone) is not walked.
    let refs = git_dir.join("refs");
    let mut stack: Vec<PathBuf> = Vec::new();
    if std::fs::symlink_metadata(&refs).is_ok_and(|m| m.is_dir()) {
        stack.push(refs);
    }
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            if budget == 0 {
                return out;
            }
            budget -= 1;
            let p = e.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
            if meta.is_dir() {
                stack.push(p);
                continue;
            }
            if !meta.is_file() {
                continue; // symlinks, FIFOs, devices: never followed or opened
            }
            let Ok(rel) = p.strip_prefix(git_dir) else { continue };
            let name = rel
                .components()
                .filter_map(|c| c.as_os_str().to_str())
                .collect::<Vec<_>>()
                .join("/");
            if dwim_hex_name(&name).is_some() {
                out.insert(name, (ref_oid(&p), p));
            }
        }
    }
    out
}

/// The ref-level Plugin4Shell checks for one git directory (plugin left None).
pub fn git_pin_issues(git_dir: &Path) -> Vec<PluginPinIssue> {
    let mut out = Vec::new();
    let refs = sha_shaped_refs_with_source(git_dir);
    let differs = |oid: &Option<String>, name: &str| -> bool {
        oid.as_deref().is_none_or(|o| !o.eq_ignore_ascii_case(name))
    };

    let head = git_dir.join("HEAD");
    // HEAD, packed-refs and FETCH_HEAD are read like the loose refs: never through a
    // symlink (a link to ~/.ssh/id_ed25519 would otherwise be opened and parsed).
    if let Some(text) = crate::scanners::read_head_bytes_nofollow(&head, 256).and_then(|b| String::from_utf8(b).ok())
        && let Some(branch) = parse_head(&text)
        && is_full_hex(&branch)
    {
        let refname = format!("refs/heads/{branch}");
        let oid = refs.get(&refname).and_then(|(o, _)| o.clone());
        out.push(PluginPinIssue {
            kind: "head-on-sha-branch".into(),
            path: show_path(&head),
            plugin: None,
            detail: format!(
                "HEAD -> refs/heads/{} -> {}",
                hex12(&branch),
                oid.as_deref().map(hex12).unwrap_or_else(|| "unresolved".into())
            ),
            mismatch: differs(&oid, &branch),
        });
    }

    for (name, (oid, src)) in &refs {
        let Some(h) = dwim_hex_name(name) else { continue };
        // Remote name, if any, is attacker-chosen text: sanitized and capped.
        let prefix = name.strip_suffix(h).unwrap_or("");
        out.push(PluginPinIssue {
            kind: "sha-shaped-ref".into(),
            path: show_path(src),
            plugin: None,
            detail: format!(
                "{}{} -> {}",
                sanitize_display(prefix, 64),
                hex12(h),
                oid.as_deref().map(hex12).unwrap_or_else(|| "unresolved".into())
            ),
            mismatch: differs(oid, h),
        });
    }

    let fetch = git_dir.join("FETCH_HEAD");
    if let Some(bytes) = crate::scanners::read_head_bytes_nofollow(&fetch, 1024 * 1024) {
        let text = String::from_utf8_lossy(&bytes);
        for (oid, name) in parse_fetch_head(&text) {
            let Some(name) = name.filter(|n| is_full_hex(n)) else { continue };
            out.push(PluginPinIssue {
                kind: "fetch-head-sha-branch".into(),
                path: show_path(&fetch),
                plugin: None,
                detail: format!("FETCH_HEAD '{}' -> {}", hex12(&name), hex12(&oid)),
                mismatch: !oid.eq_ignore_ascii_case(&name),
            });
        }
    }
    out
}

/// Count installed plugins per marketplace from `installed_plugins.json`. Plugin keys
/// are namespaced `plugin@marketplace`, so the count per marketplace is the number of
/// keys ending in `@<name>`.
pub fn plugin_counts(json: &serde_json::Value) -> HashMap<String, usize> {
    let mut counts = HashMap::new();
    if let Some(plugins) = json.get("plugins").and_then(|v| v.as_object()) {
        for key in plugins.keys() {
            if let Some((_, market)) = key.rsplit_once('@') {
                *counts.entry(market.to_string()).or_insert(0) += 1;
            }
        }
    }
    counts
}

/// Parse the `known_marketplaces.json` object into structured marketplace records.
pub fn parse_marketplaces(
    json: &serde_json::Value,
    counts: &HashMap<String, usize>,
) -> Vec<AgentMarketplace> {
    let Some(obj) = json.as_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (name, entry) in obj {
        let source = entry.get("source");
        let source_type = source
            .and_then(|s| s.get("source"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        // A github source carries `repo: owner/name`; a git source carries `url`.
        let source_ref = source
            .and_then(|s| s.get("repo").or_else(|| s.get("url")).or_else(|| s.get("path")))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let auto_update = entry
            .get("autoUpdate")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let official = is_official(&source_type, &source_ref);
        let installed_plugin_count = counts.get(name).copied().unwrap_or(0);
        out.push(AgentMarketplace {
            name: crate::scanners::sanitize_display(name, 128),
            source_type,
            // A git URL with `oauth2:<token>@` is the standard way to hand git a token.
            source_ref: crate::scanners::sanitize_display(&crate::scanners::redact_secrets_in_text(&source_ref), 512),
            auto_update,
            official,
            installed_plugin_count,
            pin_issues: Vec::new(),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// True if a marketplace is published by Anthropic (an official source).
pub(crate) fn is_official(source_type: &str, source_ref: &str) -> bool {
    let r = source_ref.to_ascii_lowercase();
    match source_type {
        "github" => r.starts_with("anthropics/"),
        "git" => anthropic_github_url(&r),
        _ => false,
    }
}

/// A git URL whose HOST is github.com and whose path is under `/anthropics/`:
/// `https://github.com/anthropics/x.git`, `ssh://git@github.com/anthropics/x`,
/// `git@github.com:anthropics/x.git`. A substring test would also accept
/// `https://evil.example/github.com/anthropics/x.git`.
fn anthropic_github_url(url: &str) -> bool {
    let url = url.trim();
    if let Some(i) = url.find("://") {
        let (_, host_port) = crate::scanners::split_url_authority(url);
        let host = host_port.split(':').next().unwrap_or(host_port);
        let after = &url[i + 3..];
        // The path starts where the authority ends (`/`), never at a `?`, `#` or `\`.
        let path = match after.find(['/', '?', '#', '\\']) {
            Some(j) if after[j..].starts_with('/') => &after[j..],
            _ => "",
        };
        return host == "github.com" && path.starts_with("/anthropics/");
    }
    // scp-like `[user@]host:path`.
    let Some((authority, path)) = url.split_once(':') else { return false };
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    !authority.contains('/') && host == "github.com" && path.starts_with("anthropics/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_github_and_git_sources() {
        let j = json!({
            "official-mp": {"source": {"source": "github", "repo": "anthropics/claude-plugins-official"}},
            "vendor-mp": {"source": {"source": "github", "repo": "trailofbits/skills"}, "autoUpdate": true},
            "raw-git": {"source": {"source": "git", "url": "https://github.com/someone/x.git"}}
        });
        let counts = HashMap::new();
        let mps = parse_marketplaces(&j, &counts);
        assert_eq!(mps.len(), 3);
        let official = mps.iter().find(|m| m.name == "official-mp").unwrap();
        assert!(official.official);
        assert!(!official.auto_update);
        let vendor = mps.iter().find(|m| m.name == "vendor-mp").unwrap();
        assert!(!vendor.official);
        assert!(vendor.auto_update);
        assert_eq!(vendor.source_ref, "trailofbits/skills");
        let raw = mps.iter().find(|m| m.name == "raw-git").unwrap();
        assert!(!raw.official);
        assert_eq!(raw.source_type, "git");
    }

    #[test]
    fn official_anthropic_git_url_is_recognized() {
        assert!(is_official("git", "https://github.com/anthropics/claude-code.git"));
        assert!(is_official("github", "anthropics/claude-plugins-official"));
        assert!(!is_official("github", "evil/anthropics-lookalike"));
        assert!(!is_official("git", "https://gitlab.com/x/y.git"));
        assert!(is_official("git", "git@github.com:anthropics/claude-code.git"));
        assert!(is_official("git", "ssh://git@github.com/anthropics/claude-code"));
        // The host decides, not a substring of the URL.
        for evil in [
            "https://evil.example/github.com/anthropics/x.git",
            "https://github.com.evil.example/anthropics/x.git",
            "https://github.com@evil.example/anthropics/x.git",
            "https://evil.example/?github.com/anthropics/",
            "https://github.com/anthropics-lookalike/x.git",
            "evil.example:github.com/anthropics/x",
            "https://github.com?/anthropics/x",
        ] {
            assert!(!is_official("git", evil), "{evil}");
        }
    }

    #[test]
    fn counts_plugins_per_marketplace() {
        let installed = json!({
            "version": 2,
            "plugins": {
                "a@official-mp": [{}],
                "b@official-mp": [{}],
                "c@vendor-mp": [{}]
            }
        });
        let counts = plugin_counts(&installed);
        assert_eq!(counts.get("official-mp"), Some(&2));
        assert_eq!(counts.get("vendor-mp"), Some(&1));
    }

    const H40: &str = "af59ee3a1051a29dda4a2e7a2af221aa457ae08b";

    #[test]
    fn full_hex_is_40_or_64_hex_chars() {
        assert!(is_full_hex(H40));
        assert!(is_full_hex(&H40.to_ascii_uppercase()));
        assert!(is_full_hex(&"ab".repeat(32)));
        assert!(!is_full_hex(&H40[..39]), "39 chars");
        assert!(!is_full_hex(&format!("{H40}a")), "41 chars");
        assert!(!is_full_hex("main"));
        assert!(!is_full_hex(&format!("{}g", &H40[..39])));
    }

    #[test]
    fn dwim_positions_only() {
        for ok in [H40.to_string(), format!("refs/{H40}"), format!("refs/heads/{H40}"),
                   format!("refs/tags/{H40}"), format!("refs/remotes/origin/{H40}")] {
            assert_eq!(dwim_hex_name(&ok), Some(H40), "{ok}");
        }
        for no in [format!("refs/heads/feature/{H40}"), "refs/heads/main".to_string(),
                   format!("refs/heads/{}", &H40[..39]), format!("refs/notes/x/{H40}")] {
            assert_eq!(dwim_hex_name(&no), None, "{no}");
        }
    }

    #[test]
    fn fetch_head_table() {
        let text = format!(
            "{H40}\t\tbranch 'main' of https://github.com/x/y\n\
             {H40}\tnot-for-merge\ttag '{H40}' of https://github.com/x/y\n\
             {H40}\t\tremote-tracking branch 'origin/{H40}' of https://github.com/x/y\n\
             {H40}\t\thttps://github.com/lexicone42/exo-self\n\
             {H40}\t\tbranch '{H40}\n\
             garbage-without-tabs\n\n"
        );
        let got = parse_fetch_head(&text);
        assert_eq!(got[0].1.as_deref(), Some("main"));
        assert_eq!(got[1].1.as_deref(), Some(H40), "tag, not-for-merge");
        assert_eq!(got[2].1.as_deref(), Some(H40), "remote prefix removed");
        assert_eq!(got[3].1, None, "fetch by object ID records only the URL");
        assert_eq!(got[4].1, None, "unterminated quote is not a name");
        assert_eq!(got[5].1, None, "malformed line");
        assert_eq!(got.len(), 6);
    }

    #[test]
    fn packed_refs_skip_header_and_peeled() {
        let text = format!("# pack-refs with: peeled fully-peeled sorted \n{H40} refs/remotes/origin/main\n^{H40}\n{H40} refs/tags/v1\n");
        let got = parse_packed_refs(&text);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].1, "refs/remotes/origin/main");
        assert_eq!(got[1].1, "refs/tags/v1");
    }

    #[test]
    fn head_parse() {
        assert_eq!(parse_head("ref: refs/heads/main\n").as_deref(), Some("main"));
        assert_eq!(parse_head(&format!("ref: refs/heads/{H40}")).as_deref(), Some(H40));
        assert_eq!(parse_head(H40), None, "detached HEAD is a commit, not a branch");
        assert_eq!(parse_head("ref: refs/tags/x"), None);
    }

    #[cfg(unix)]
    #[test]
    fn ref_walk_does_not_follow_a_symlinked_refs_dir() {
        let base = std::env::temp_dir().join(format!("rmg-mkt-refwalk-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let elsewhere = base.join("elsewhere/heads");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::write(elsewhere.join(H40), format!("{H40}\n")).unwrap();
        let git = base.join("clone/.git");
        std::fs::create_dir_all(git.join("refs")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, git.join("refs/heads")).unwrap();
        let got = sha_shaped_refs(&git);
        // A real loose ref is seen.
        std::fs::create_dir_all(git.join("refs/tags")).unwrap();
        std::fs::write(git.join("refs/tags").join(H40), format!("{H40}\n")).unwrap();
        let got2 = sha_shaped_refs(&git);
        let _ = std::fs::remove_dir_all(&base);
        assert!(got.is_empty(), "followed a symlinked refs/heads: {got:?}");
        assert_eq!(got2, vec![(format!("refs/tags/{H40}"), Some(H40.to_string()))]);
    }

    #[test]
    fn ref_walk_does_not_follow_a_symlinked_refs_root() {
        let base = std::env::temp_dir().join(format!("rmg-mkt-refroot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let elsewhere = base.join("elsewhere");
        std::fs::create_dir_all(elsewhere.join("heads")).unwrap();
        std::fs::write(elsewhere.join("heads").join(H40), format!("{H40}\n")).unwrap();
        let git = base.join("clone/.git");
        std::fs::create_dir_all(&git).unwrap();
        std::os::unix::fs::symlink(&elsewhere, git.join("refs")).unwrap();
        let got = sha_shaped_refs(&git);
        let _ = std::fs::remove_dir_all(&base);
        assert!(got.is_empty(), "followed a symlinked .git/refs: {got:?}");
    }

    #[test]
    fn empty_or_malformed_is_empty() {
        assert!(parse_marketplaces(&json!("nope"), &HashMap::new()).is_empty());
        assert!(plugin_counts(&json!({})).is_empty());
    }
}
