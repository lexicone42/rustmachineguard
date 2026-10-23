//! Where each agent keeps its hook files, read for the `settings` scanner (not a scanner
//! label of its own). Every file is opened through [`read_hook_file`] /
//! [`read_settings_in`], so a link out of a repository or plugin is inventoried by its
//! target and never followed into a credential path, and every read and miss is counted
//! by the scanner's diagnostics. Each file with hooks becomes one [`AgentSettings`]
//! entry; parsing is in [`crate::scanners::hook_sources`].
//!
//! Formats and paths are from the vendors' docs, fetched 2026-10-23 (README "Agent
//! Settings" and docs/THREAT-CATALOG.md "Detection techniques" carry the URLs and the
//! floors: what is documented but not read).

use crate::models::{AgentHook, AgentSettings, SkillProvenance};
use crate::platform::PlatformInfo;
use crate::scanners::agent_settings::{is_repository_scope, linked_settings, read_hook_file, SettingsRead};
use crate::scanners::hook_sources::{
    self as hs, claude_plugin_vars, extract_hook_map, extract_kiro_hooks, Dialect, HookCtx, RegistersRule,
};
use crate::scanners::persistence::lexical_join;
use crate::scanners::{probe_dir, probe_file, probe_read_dir, sanitize_display, system_path};
use std::path::{Path, PathBuf};

/// Hook files read per directory listing (`.github/hooks/*.json`, `policy.d`, ...).
const MAX_HOOK_FILES: usize = 200;
/// Directory entries visited while looking for Codex plugin roots.
const MAX_CODEX_PLUGIN_ENTRIES: usize = 5_000;

/// A project for the hook walk: the directory as registered and the root its files are
/// contained in (the enclosing git work tree).
struct Project {
    dir: PathBuf,
    root: PathBuf,
}

/// One hook file to read: where it is and how it is graded.
struct Src<'a> {
    source: &'a str,
    framework: &'static str,
    /// Repository scopes: the containment root (see `read_settings_in`).
    project_dir: Option<&'a Path>,
    /// Other scopes: the directory a link may stay inside (see `read_hook_file`).
    containment: Option<&'a Path>,
    provenance: Option<SkillProvenance>,
}

impl Src<'_> {
    fn read(&self, path: &Path) -> SettingsRead {
        read_hook_file(path, self.source, self.project_dir, self.containment)
    }
}

fn exists_nofollow(p: &Path) -> bool {
    let present = std::fs::symlink_metadata(p).is_ok();
    crate::scanners::telemetry::note_probe(p, present);
    present
}

/// Read and parse a JSON (or, by extension, TOML) hook file. A link that is not followed
/// is pushed as its own inventory entry and gives None.
fn load(path: &Path, src: &Src, out: &mut Vec<AgentSettings>) -> Option<serde_json::Value> {
    if !exists_nofollow(path) {
        return None;
    }
    match src.read(path) {
        SettingsRead::Content(c) => {
            if path.extension().is_some_and(|e| e == "toml") {
                crate::scanners::mcp::toml_to_json(&c)
            } else {
                serde_json::from_str(&c).ok()
            }
        }
        SettingsRead::Link(l) => {
            let mut e = linked_settings(path, src.source, src.framework, l);
            e.git_tracked = is_repository_scope(src.source) && e.git_tracked;
            e.provenance = src.provenance.clone();
            out.push(e);
            None
        }
        SettingsRead::Unreadable => None,
    }
}

/// Push one entry for a hook file that has hooks.
fn push(path: &Path, src: &Src, hooks: Vec<AgentHook>, out: &mut Vec<AgentSettings>) {
    if hooks.is_empty() {
        return;
    }
    out.push(AgentSettings {
        path: sanitize_display(&path.to_string_lossy(), 512),
        source: src.source.to_string(),
        framework: src.framework.to_string(),
        git_tracked: is_repository_scope(src.source) && crate::scanners::is_git_tracked(path),
        hooks,
        world_writable: crate::scanners::is_world_or_group_writable(path),
        provenance: src.provenance.clone(),
        ..Default::default()
    });
}

/// The event map of a hook file: its `hooks` object, or the file itself when it has none
/// (plugin hook files and manifest objects come both ways).
fn hook_map(v: &serde_json::Value) -> &serde_json::Value {
    match v.get("hooks") {
        Some(h) if h.is_object() => h,
        _ => v,
    }
}

/// `*.json` (or `exts`) files in a directory, sorted, at most [`MAX_HOOK_FILES`].
fn files_in(dir: &Path, exts: &[&str]) -> Vec<PathBuf> {
    if !probe_dir(dir) {
        return Vec::new();
    }
    let Ok(rd) = probe_read_dir(dir) else { return Vec::new() };
    let mut v: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            !name.starts_with('.')
                && p.extension().and_then(|e| e.to_str()).is_some_and(|e| exts.iter().any(|x| e.eq_ignore_ascii_case(x)))
                && exists_nofollow(p) && std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file() || m.file_type().is_symlink())
        })
        .collect();
    v.sort();
    v.truncate(MAX_HOOK_FILES);
    v
}

/// [`files_in`] for a directory a repository ships (`.github/hooks`, `.kiro/hooks`,
/// `.opencode/plugins`): when the directory's real path leaves the project (it, or an
/// agent directory above it, is a symlink out), it is inventoried once by its link text
/// and not listed, so a repository cannot make the scan list the names in any directory
/// the user can read.
fn project_files_in(dir: &Path, src: &Src, exts: &[&str], out: &mut Vec<AgentSettings>) -> Vec<PathBuf> {
    if let Some(root) = src.project_dir
        && exists_nofollow(dir)
        && let Ok(real) = std::fs::canonicalize(dir)
    {
        let real_root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        if !real.starts_with(&real_root) {
            let _ = load(dir, src, out);
            return Vec::new();
        }
    }
    files_in(dir, exts)
}

/// Subdirectories of `dir`, sorted, at most [`MAX_HOOK_FILES`].
fn dirs_in(dir: &Path) -> Vec<PathBuf> {
    if !probe_dir(dir) {
        return Vec::new();
    }
    let Ok(rd) = probe_read_dir(dir) else { return Vec::new() };
    let mut v: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| !p.file_name().and_then(|n| n.to_str()).unwrap_or(".").starts_with('.') && probe_dir(p))
        .collect();
    v.sort();
    v.truncate(MAX_HOOK_FILES);
    v
}

fn dir_name(p: &Path) -> String {
    sanitize_display(&p.file_name().map(|n| n.to_string_lossy()).unwrap_or_default(), 128)
}

fn prov(marketplace: &str, plugin: String, third_party: bool) -> Option<SkillProvenance> {
    Some(SkillProvenance {
        marketplace: Some(marketplace.to_string()),
        plugin: Some(plugin),
        third_party,
        active: true,
        ..Default::default()
    })
}

/// A path named in a manifest (`./hooks/extra.json`): must start with `./` and stay
/// lexically inside `root`.
fn manifest_path(root: &Path, s: &str) -> Option<PathBuf> {
    if !s.starts_with("./") {
        return None;
    }
    let p = lexical_join(root, Path::new(s));
    (p.starts_with(root) && p != root).then_some(p)
}

/// Every new hook surface. `project_dirs` are the registered projects plus the cwd.
pub(crate) fn scan(
    platform: &dyn PlatformInfo,
    home: &Path,
    project_dirs: &[PathBuf],
    claude_json: Option<&serde_json::Value>,
    out: &mut Vec<AgentSettings>,
) {
    // HOME (or an ancestor) registered as a project is the user's own configuration, read
    // below with the user ladder; it is not walked again as repository content.
    let real_home = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    let mut projects: Vec<Project> = Vec::new();
    for d in project_dirs {
        let real = std::fs::canonicalize(d).unwrap_or_else(|_| d.clone());
        if home.starts_with(d) || real_home.starts_with(&real) {
            continue;
        }
        if projects.iter().any(|p| std::fs::canonicalize(&p.dir).unwrap_or_else(|_| p.dir.clone()) == real) {
            continue;
        }
        let root = crate::scanners::skills::project_containment_root(d, home);
        projects.push(Project { dir: d.clone(), root });
    }

    claude(home, &projects, out);
    cursor(home, out);
    codex(platform, &projects, out);
    copilot(home, &projects, out);
    gemini(home, &projects, out);
    devin(home, &projects, claude_json, out);
    opencode(home, &projects, out);
    kiro(home, &projects, out);
}

// ── Claude Code ─────────────────────────────────────────────────────────────────

fn claude(home: &Path, projects: &[Project], out: &mut Vec<AgentSettings>) {
    let ctx = crate::scanners::skills::PluginContext::load(home);
    // Installed plugin versions only: marketplace clones and orphaned cache versions
    // never load, so they are never visited.
    let mut ips: Vec<(PathBuf, String, String)> = ctx.install_paths().to_vec();
    ips.sort();
    ips.dedup_by(|a, b| a.0 == b.0);
    for (ip, _, _) in &ips {
        if !probe_dir(ip) {
            continue;
        }
        let src = Src {
            source: "plugin",
            framework: "claude-code",
            project_dir: None,
            containment: Some(ip),
            provenance: ctx.provenance(&ip.join("hooks").join("hooks.json")),
        };
        claude_plugin_dir(ip, &src, out);
    }

    // Plugins kept in a skills directory (`<d>/.claude-plugin/plugin.json`): the user's
    // own (no trust gate) and a repository's (trust-gated, primary working dir).
    let user_skills = home.join(".claude").join("skills");
    for d in dirs_in(&user_skills) {
        if !exists_nofollow(&d.join(".claude-plugin").join("plugin.json")) {
            continue;
        }
        let src = Src {
            source: "user-global",
            framework: "claude-code",
            project_dir: None,
            containment: Some(&d),
            provenance: prov("skills-dir", dir_name(&d), false),
        };
        claude_plugin_dir(&d, &src, out);
    }
    for p in projects {
        for d in dirs_in(&p.dir.join(".claude").join("skills")) {
            if !exists_nofollow(&d.join(".claude-plugin").join("plugin.json")) {
                continue;
            }
            let src = Src {
                source: "project",
                framework: "claude-code",
                project_dir: Some(&p.root),
                containment: None,
                provenance: prov("skills-dir", dir_name(&d), false),
            };
            claude_plugin_dir(&d, &src, out);
        }
    }
}

/// One Claude Code plugin root: `hooks/hooks.json` (event map and `modules`), the
/// manifest's `hooks` (a `./path.json`, an inline event map, or an array of either) and
/// the root `settings.json` `subagentStatusLine`, merged into one entry.
fn claude_plugin_dir(root: &Path, src: &Src, out: &mut Vec<AgentSettings>) {
    let hooks_json = root.join("hooks").join("hooks.json");
    let manifest = root.join(".claude-plugin").join("plugin.json");
    let settings = root.join("settings.json");
    let mut ctx = HookCtx::new(&hooks_json, Dialect::Claude);
    ctx.own_dir = Some(".claude");
    ctx.root = Some(root);
    ctx.root_label = if src.source == "project" { "project" } else { "plugin" };
    ctx.vars = claude_plugin_vars(root);

    let mut hooks = Vec::new();
    let mut entry: Option<PathBuf> = None;
    if let Some(j) = load(&hooks_json, src, out) {
        hooks.extend(j.get("hooks").map(|m| extract_hook_map(m, &ctx)).unwrap_or_default());
        hooks.extend(claude_modules(&j, &hooks_json, root, src));
        entry = Some(hooks_json.clone());
    }
    if let Some(m) = load(&manifest, src, out) {
        let declared = match m.get("hooks") {
            Some(serde_json::Value::Array(a)) => a.iter().take(MAX_HOOK_FILES).collect(),
            Some(v) => vec![v],
            None => Vec::new(),
        };
        let before = hooks.len();
        for d in declared {
            match d {
                // A named file carries the top-level "hooks" wrapper.
                serde_json::Value::String(s) => {
                    if let Some(p) = manifest_path(root, s)
                        && let Some(j) = load(&p, src, out)
                        && let Some(map) = j.get("hooks")
                    {
                        hooks.extend(extract_hook_map(map, &ctx));
                    }
                }
                // An inline manifest object is the bare event map.
                v @ serde_json::Value::Object(_) => hooks.extend(extract_hook_map(v, &ctx)),
                _ => {}
            }
        }
        if hooks.len() > before && entry.is_none() {
            entry = Some(manifest.clone());
        }
    }
    if let Some(j) = load(&settings, src, out) {
        let before = hooks.len();
        hooks.extend(hs::settings_commands_with(&j, &ctx, &["subagentStatusLine"]));
        if hooks.len() > before && entry.is_none() {
            entry = Some(settings.clone());
        }
    }
    hooks.truncate(hs::MAX_HOOKS_PER_FILE);
    if let Some(path) = entry {
        push(&path, src, hooks, out);
    }
}

/// hooks.json `modules`: `./register.ts` paths relative to the hooks directory, inside
/// the plugin root. The source is read (never run) for its `on("event")` calls and for
/// critical dangerous patterns.
fn claude_modules(j: &serde_json::Value, hooks_json: &Path, root: &Path, src: &Src) -> Vec<AgentHook> {
    let Some(list) = j.get("modules").and_then(|m| m.as_array()) else { return Vec::new() };
    let hooks_dir = hooks_json.parent().unwrap_or(root);
    let mut out = Vec::new();
    for m in list.iter().take(50).filter_map(|m| m.as_str()) {
        let p = lexical_join(hooks_dir, Path::new(m));
        // Claude Code rejects component paths that escape the plugin root.
        if !p.starts_with(root) || p == root {
            continue;
        }
        if !p.extension().and_then(|e| e.to_str()).is_some_and(|e| hs::MODULE_EXTS.contains(&e)) {
            continue;
        }
        let read = if exists_nofollow(&p) { Some(src.read(&p)) } else { None };
        let mut h = match &read {
            Some(SettingsRead::Content(c)) => hs::module_hook(m, Some(c), RegistersRule::ClaudeMod),
            _ => hs::module_hook(m, None, RegistersRule::ClaudeMod),
        };
        if let Some(SettingsRead::Link(l)) = &read {
            h.risks.push(format!("the module is a symlink leaving its plugin ({}) — not read", l.target));
        }
        out.push(h);
    }
    out
}

// ── Cursor ──────────────────────────────────────────────────────────────────────

fn cursor(home: &Path, out: &mut Vec<AgentSettings>) {
    // Enterprise hooks (cursor.com/docs/hooks: Linux/WSL /etc/cursor, macOS
    // /Library/Application Support/Cursor). Team hooks are cloud-distributed: a floor.
    let ent = system_path(if cfg!(target_os = "macos") {
        "/Library/Application Support/Cursor/hooks.json"
    } else {
        "/etc/cursor/hooks.json"
    });
    let ent_dir = ent.parent().map(Path::to_path_buf).unwrap_or_default();
    let src = Src { source: "managed", framework: "cursor", project_dir: None, containment: Some(&ent_dir), provenance: None };
    if let Some(j) = load(&ent, &src, out) {
        let ctx = HookCtx::new(&ent, Dialect::Cursor);
        let hooks = j.get("hooks").map(|m| extract_hook_map(m, &ctx)).unwrap_or_default();
        push(&ent, &src, hooks, out);
    }

    // Local plugins: ~/.cursor/plugins/local/<p>/.cursor-plugin/plugin.json. A linked
    // entry that resolves outside the folder is skipped (Cursor skips it too).
    let local = home.join(".cursor").join("plugins").join("local");
    let real_local = std::fs::canonicalize(&local).unwrap_or_else(|_| local.clone());
    for d in dirs_in(&local) {
        let canon = std::fs::canonicalize(&d).unwrap_or_else(|_| d.clone());
        if !canon.starts_with(&real_local) {
            continue;
        }
        let manifest = d.join(".cursor-plugin").join("plugin.json");
        if !probe_file(&manifest) {
            continue;
        }
        let src = Src {
            source: "user-global",
            framework: "cursor",
            project_dir: None,
            containment: Some(&d),
            provenance: prov("local", dir_name(&d), false),
        };
        let default = d.join("hooks").join("hooks.json");
        let mut ctx = HookCtx::new(&default, Dialect::Cursor);
        ctx.root = Some(&d);
        ctx.root_label = "plugin";
        ctx.vars = vec![("${CURSOR_PLUGIN_ROOT}", d.clone())];
        let mut path = default.clone();
        let mut hooks = Vec::new();
        let declared = load(&manifest, &src, out).and_then(|m| m.get("hooks").cloned());
        match declared {
            Some(serde_json::Value::String(s)) => {
                let rel = if s.starts_with("./") { s.clone() } else { format!("./{s}") };
                if let Some(p) = manifest_path(&d, &rel)
                    && let Some(j) = load(&p, &src, out)
                {
                    hooks = extract_hook_map(hook_map(&j), &ctx);
                    path = p;
                }
            }
            Some(v @ serde_json::Value::Object(_)) => {
                hooks = extract_hook_map(hook_map(&v), &ctx);
                path = manifest.clone();
            }
            _ => {
                if let Some(j) = load(&default, &src, out) {
                    hooks = extract_hook_map(hook_map(&j), &ctx);
                }
            }
        }
        push(&path, &src, hooks, out);
    }
}

// ── Codex ───────────────────────────────────────────────────────────────────────

/// Reads one Codex hooks.json / config.toml / requirements.toml; returns its
/// `[features].hooks` switch when it sets one.
fn codex_file(path: &Path, src: &Src, root: Option<(&Path, &'static str)>, vars: &[(&'static str, PathBuf)], out: &mut Vec<AgentSettings>) -> Option<bool> {
    let j = load(path, src, out)?;
    let switch = j.get("features").and_then(|f| f.get("hooks")).and_then(|v| v.as_bool());
    let mut ctx = HookCtx::new(path, Dialect::Codex);
    ctx.own_dir = Some(".codex");
    if let Some((r, l)) = root {
        ctx.root = Some(r);
        ctx.root_label = l;
    }
    ctx.vars = vars.to_vec();
    let hooks = j.get("hooks").map(|m| extract_hook_map(m, &ctx)).unwrap_or_default();
    push(path, src, hooks, out);
    switch
}

/// Mark the non-managed hooks of `framework` in `out[start..]` disabled (a global
/// switch turned them off): inventoried and counted inactive, not graded.
fn disable_non_managed(out: &mut [AgentSettings], start: usize, framework: &str) {
    for e in out[start..].iter_mut().filter(|e| e.framework == framework && e.source != "managed") {
        e.hooks.iter_mut().for_each(|h| h.disabled = true);
    }
}

fn codex(platform: &dyn PlatformInfo, projects: &[Project], out: &mut Vec<AgentSettings>) {
    let start = out.len();
    let ch = platform.codex_config_dir();
    let user = Src { source: "user-global", framework: "codex", project_dir: None, containment: Some(&ch), provenance: None };
    codex_file(&ch.join("hooks.json"), &user, None, &[], out);
    let user_switch = codex_file(&ch.join("config.toml"), &user, None, &[], out);
    let mut project_on = false;
    for p in projects {
        let src = Src { source: "project", framework: "codex", project_dir: Some(&p.root), containment: None, provenance: None };
        codex_file(&p.dir.join(".codex").join("hooks.json"), &src, None, &[], out);
        project_on |= codex_file(&p.dir.join(".codex").join("config.toml"), &src, None, &[], out) == Some(true);
    }
    // The system config layer and managed requirements (`managed_dir` and other
    // non-array values under [hooks] are skipped by the parser).
    let etc = system_path("/etc/codex");
    let managed = Src { source: "managed", framework: "codex", project_dir: None, containment: Some(&etc), provenance: None };
    let sys_switch = codex_file(&etc.join("config.toml"), &managed, None, &[], out);
    let required = codex_file(&etc.join("requirements.toml"), &managed, None, &[], out);
    // "Hooks are enabled by default. To turn them off in config.toml, set: [features]
    // hooks = false"; "Admins can force hooks off the same way in requirements.toml"
    // (learn.chatgpt.com/docs/hooks.md, fetched 2026-10-23). requirements.toml decides
    // when it sets the switch; otherwise the user or system config turns hooks off unless
    // a project config turns them back on (read conservatively: any project that does
    // keeps every hook graded).
    let off = match required {
        Some(v) => !v,
        None => (user_switch == Some(false) || sys_switch == Some(false)) && !project_on,
    };

    // Plugins: a directory holding `.codex-plugin/plugin.json`, at most four levels down.
    let plugins_dir = ch.join("plugins");
    let roots = codex_plugin_roots(&plugins_dir);
    let identities = codex_plugin_identities(&plugins_dir, &roots);
    for (root, (marketplace, plugin, active)) in roots.iter().zip(identities) {
        let root = root.clone();
        let mut provenance = prov(&marketplace, plugin, true);
        if let Some(p) = provenance.as_mut() {
            p.active = active;
        }
        let src = Src { source: "plugin", framework: "codex", project_dir: None, containment: Some(&root), provenance };
        let vars = vec![
            ("${PLUGIN_ROOT}", root.clone()),
            ("$PLUGIN_ROOT", root.clone()),
            ("${CLAUDE_PLUGIN_ROOT}", root.clone()),
            ("$CLAUDE_PLUGIN_ROOT", root.clone()),
        ];
        let manifest = root.join(".codex-plugin").join("plugin.json");
        let default = root.join("hooks").join("hooks.json");
        let mut ctx = HookCtx::new(&default, Dialect::Codex);
        ctx.own_dir = Some(".codex");
        ctx.root = Some(&root);
        ctx.root_label = "plugin";
        ctx.vars = vars.clone();
        let declared = load(&manifest, &src, out).and_then(|m| m.get("hooks").cloned());
        // The manifest's `hooks` REPLACES the default hooks/hooks.json.
        match declared {
            Some(d) => {
                let items: Vec<serde_json::Value> = match d {
                    serde_json::Value::Array(a) => a.into_iter().take(MAX_HOOK_FILES).collect(),
                    v => vec![v],
                };
                let mut hooks = Vec::new();
                for item in items {
                    match item {
                        serde_json::Value::String(s) => {
                            if let Some(p) = manifest_path(&root, &s)
                                && let Some(j) = load(&p, &src, out)
                            {
                                hooks.extend(extract_hook_map(hook_map(&j), &ctx));
                            }
                        }
                        v @ serde_json::Value::Object(_) => hooks.extend(extract_hook_map(hook_map(&v), &ctx)),
                        _ => {}
                    }
                }
                hooks.truncate(hs::MAX_HOOKS_PER_FILE);
                push(&manifest, &src, hooks, out);
            }
            None => {
                if let Some(j) = load(&default, &src, out) {
                    let hooks = extract_hook_map(hook_map(&j), &ctx);
                    push(&default, &src, hooks, out);
                }
            }
        }
    }
    if off {
        disable_non_managed(out, start, "codex");
    }
}

/// (marketplace, plugin, active) for each Codex plugin root. The documented cache is
/// `~/.codex/plugins/cache/$MARKETPLACE_NAME/$PLUGIN_NAME/$VERSION/`, `$VERSION` being
/// `local` for local plugins (developers.openai.com/plugins/build/plugins.md, fetched
/// 2026-10-23): the identity is the (marketplace, plugin) pair, never the version
/// directory, so two `local` plugins stay two plugins. One version per plugin is graded
/// (`local` when present, else the highest version, compared numerically per dot-separated
/// part); the other cached versions are inventoried as inactive. A root outside that
/// layout is its own plugin of the `codex` marketplace, named by its directory.
fn codex_plugin_identities(plugins_dir: &Path, roots: &[PathBuf]) -> Vec<(String, String, bool)> {
    let cache = plugins_dir.join("cache");
    let ids: Vec<(String, String, Option<String>)> = roots
        .iter()
        .map(|r| {
            let comps: Vec<String> = r
                .strip_prefix(&cache)
                .map(|rel| rel.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect())
                .unwrap_or_default();
            match comps.as_slice() {
                [m, p, v] => (sanitize_display(m, 128), sanitize_display(p, 128), Some(v.clone())),
                _ => ("codex".to_string(), dir_name(r), None),
            }
        })
        .collect();
    let rank = |v: &str| -> (bool, Vec<(u64, String)>) {
        let parts = v.split(['.', '-', '+']).map(|x| (x.parse::<u64>().unwrap_or(0), x.to_string())).collect();
        (v == "local", parts)
    };
    ids.iter()
        .enumerate()
        .map(|(i, (m, p, v))| {
            let active = match v {
                None => true,
                Some(v) => !ids.iter().enumerate().any(|(j, (m2, p2, v2))| {
                    j != i && m2 == m && p2 == p && v2.as_ref().is_some_and(|v2| (rank(v2), v2) > (rank(v), v))
                }),
            };
            (m.clone(), p.clone(), active)
        })
        .collect()
}

fn codex_plugin_roots(dir: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if !probe_dir(dir) {
        return roots;
    }
    let mut budget = MAX_CODEX_PLUGIN_ENTRIES;
    let mut stack = vec![(dir.to_path_buf(), 0usize)];
    while let Some((d, depth)) = stack.pop() {
        if d != dir && std::fs::symlink_metadata(d.join(".codex-plugin").join("plugin.json")).is_ok() {
            roots.push(d);
            continue;
        }
        if depth >= 4 {
            continue;
        }
        let Ok(rd) = probe_read_dir(&d) else { continue };
        for e in rd.flatten() {
            if budget == 0 {
                break;
            }
            budget -= 1;
            let p = e.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == ".git" || name == "node_modules" {
                continue;
            }
            // Symlinked directories are not descended.
            if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_dir()) {
                stack.push((p, depth + 1));
            }
        }
    }
    roots.sort();
    roots
}

// ── GitHub Copilot CLI ──────────────────────────────────────────────────────────

/// A Copilot CLI hook file. Hook configuration files must say `version: 1` ("Hook
/// configuration files use JSON format with version `1`", docs.github.com/en/copilot/
/// reference/hooks-configuration, fetched 2026-10-23); a settings file (`settings.json`,
/// `settings.local.json`) carries `hooks` as one key among others and has no version.
/// A file-level `disableAllHooks: true` marks the file's hooks disabled. Returns whether
/// the file set `disableAllHooks: true`.
fn copilot_file(path: &Path, src: &Src, root: Option<(&Path, &'static str)>, out: &mut Vec<AgentSettings>) -> bool {
    let Some(j) = load(path, src, out) else { return false };
    let settings = matches!(path.file_name().and_then(|n| n.to_str()), Some("settings.json" | "settings.local.json"));
    let off = j.get("disableAllHooks").and_then(|v| v.as_bool()) == Some(true);
    if !settings && j.get("version").and_then(|v| v.as_u64()) != Some(1) {
        return false;
    }
    let mut ctx = HookCtx::new(path, Dialect::Copilot);
    if let Some((r, l)) = root {
        ctx.root = Some(r);
        ctx.root_label = l;
    }
    let mut hooks = j.get("hooks").map(|m| extract_hook_map(m, &ctx)).unwrap_or_default();
    if off {
        for h in &mut hooks {
            h.disabled = true;
        }
    }
    push(path, src, hooks, out);
    off
}

fn copilot(home: &Path, projects: &[Project], out: &mut Vec<AgentSettings>) {
    let ch = home.join(".copilot");
    let user = Src { source: "user-global", framework: "copilot-cli", project_dir: None, containment: Some(&ch), provenance: None };
    for f in files_in(&ch.join("hooks"), &["json"]) {
        copilot_file(&f, &user, None, out);
    }
    copilot_file(&ch.join("settings.json"), &user, None, out);
    for p in projects {
        let src = Src { source: "project", framework: "copilot-cli", project_dir: Some(&p.root), containment: None, provenance: None };
        let root = Some((p.dir.as_path(), "project"));
        let start = out.len();
        for f in project_files_in(&p.dir.join(".github").join("hooks"), &src, &["json"], out) {
            copilot_file(&f, &src, root, out);
        }
        let cp = p.dir.join(".github").join("copilot");
        let mut off = copilot_file(&cp.join("settings.json"), &src, root, out);
        let local = Src { source: "local", ..src };
        off |= copilot_file(&cp.join("settings.local.json"), &local, root, out);
        // A repository settings `disableAllHooks: true` skips every hook in that
        // repository's sessions except policy hooks: its own hook files are inventoried
        // as disabled. (User and plugin hooks are skipped there too, but only in that
        // repository, so they stay graded.)
        if off {
            for e in &mut out[start..] {
                e.hooks.iter_mut().for_each(|h| h.disabled = true);
            }
        }
    }
    // Machine policy (Linux and macOS): applied in name order, cannot be disabled.
    let pol = system_path("/etc/github-copilot/policy.d");
    let managed = Src { source: "managed", framework: "copilot-cli", project_dir: None, containment: Some(&pol), provenance: None };
    for f in files_in(&pol, &["json"]) {
        copilot_file(&f, &managed, None, out);
    }
    // Installed plugins: installed-plugins/<marketplace>/<plugin>/ (`_direct` for direct
    // installs). The default marketplaces are GitHub's (copilot-plugins, awesome-copilot),
    // but the directory layout is not documented, so no name is trusted as first-party:
    // graded like a third-party plugin and titled "provenance not verified".
    for m in dirs_in(&ch.join("installed-plugins")) {
        for pdir in dirs_in(&m) {
            let src = Src {
                source: "plugin",
                framework: "copilot-cli",
                project_dir: None,
                containment: Some(&pdir),
                provenance: Some(SkillProvenance {
                    marketplace: Some(dir_name(&m)),
                    plugin: Some(dir_name(&pdir)),
                    third_party: true,
                    active: true,
                    ..Default::default()
                }),
            };
            let top = pdir.join("hooks.json");
            let file = if exists_nofollow(&top) { top } else { pdir.join("hooks").join("hooks.json") };
            copilot_file(&file, &src, Some((pdir.as_path(), "plugin")), out);
        }
    }
}

// ── Gemini CLI ──────────────────────────────────────────────────────────────────

/// Reads one Gemini CLI settings file; returns its `hooksConfig.enabled` when set.
fn gemini_file(path: &Path, src: &Src, vars: Vec<(&'static str, PathBuf)>, out: &mut Vec<AgentSettings>) -> Option<bool> {
    let j = load(path, src, out)?;
    let switch = j.get("hooksConfig").and_then(|c| c.get("enabled")).and_then(|v| v.as_bool());
    let mut ctx = HookCtx::new(path, Dialect::Gemini);
    ctx.own_dir = Some(".gemini");
    ctx.vars = vars;
    // Only `hooks`: Gemini hooks are command-only and never reference mcpServers.
    let hooks = j.get("hooks").map(|m| extract_hook_map(m, &ctx)).unwrap_or_default();
    push(path, src, hooks, out);
    switch
}

fn gemini(home: &Path, projects: &[Project], out: &mut Vec<AgentSettings>) {
    let start = out.len();
    let gh = home.join(".gemini");
    let user = Src { source: "user-global", framework: "gemini-cli", project_dir: None, containment: Some(&gh), provenance: None };
    let user_switch = gemini_file(&gh.join("settings.json"), &user, Vec::new(), out);
    let mut project_on = false;
    for p in projects {
        let src = Src { source: "project", framework: "gemini-cli", project_dir: Some(&p.root), containment: None, provenance: None };
        let vars = vec![("${GEMINI_PROJECT_DIR}", p.dir.clone()), ("$GEMINI_PROJECT_DIR", p.dir.clone())];
        project_on |= gemini_file(&p.dir.join(".gemini").join("settings.json"), &src, vars, out) == Some(true);
    }
    let sys = system_path(if cfg!(target_os = "macos") { "/Library/Application Support/GeminiCli" } else { "/etc/gemini-cli" });
    let managed = Src { source: "managed", framework: "gemini-cli", project_dir: None, containment: Some(&sys), provenance: None };
    let sys_switch = gemini_file(&sys.join("settings.json"), &managed, Vec::new(), out);
    let defaults_switch = gemini_file(&sys.join("system-defaults.json"), &managed, Vec::new(), out);
    // "hooksConfig.enabled ... When disabled, no hooks will be executed"
    // (geminicli.com/docs/reference/configuration, fetched 2026-10-23). The system
    // settings file overrides every other layer; below it the user file, then the system
    // defaults, turn hooks off unless a project file turns them back on (read
    // conservatively: any project that does keeps every hook graded).
    let off = match sys_switch {
        Some(v) => !v,
        None => user_switch.or(defaults_switch) == Some(false) && !project_on,
    };
    // Extensions: hooks live in hooks/hooks.json, never in the manifest.
    for e in dirs_in(&gh.join("extensions")) {
        if !probe_file(&e.join("gemini-extension.json")) {
            continue;
        }
        let src = Src {
            source: "plugin",
            framework: "gemini-cli",
            project_dir: None,
            containment: Some(&e),
            provenance: prov("gemini-extensions", dir_name(&e), true),
        };
        let file = e.join("hooks").join("hooks.json");
        let Some(j) = load(&file, &src, out) else { continue };
        let mut ctx = HookCtx::new(&file, Dialect::Gemini);
        ctx.own_dir = Some(".gemini");
        ctx.root = Some(&e);
        ctx.root_label = "plugin";
        ctx.vars = vec![("${extensionPath}", e.clone())];
        let hooks = extract_hook_map(hook_map(&j), &ctx);
        push(&file, &src, hooks, out);
    }
    if off {
        disable_non_managed(out, start, "gemini-cli");
    }
}

// ── Devin Desktop (Windsurf) and Devin CLI ──────────────────────────────────────

/// A Devin Desktop hooks.json (`{"hooks": {event: [{command}]}}`); returns its hook count.
fn devin_desktop_file(path: &Path, src: &Src, own: Option<&'static str>, out: &mut Vec<AgentSettings>) -> usize {
    let Some(j) = load(path, src, out) else { return 0 };
    let mut ctx = HookCtx::new(path, Dialect::DevinDesktop);
    ctx.own_dir = own;
    let hooks = j.get("hooks").map(|m| extract_hook_map(m, &ctx)).unwrap_or_default();
    let n = hooks.len();
    push(path, src, hooks, out);
    n
}

fn devin_cli_file(path: &Path, src: &Src, whole: bool, own: Option<&'static str>, out: &mut Vec<AgentSettings>) {
    let Some(j) = load(path, src, out) else { return };
    let mut ctx = HookCtx::new(path, Dialect::DevinCli);
    ctx.own_dir = own;
    let map = if whole { Some(&j) } else { j.get("hooks") };
    let hooks = map.map(|m| extract_hook_map(m, &ctx)).unwrap_or_default();
    push(path, src, hooks, out);
}

fn devin(home: &Path, projects: &[Project], claude_json: Option<&serde_json::Value>, out: &mut Vec<AgentSettings>) {
    let codeium = home.join(".codeium");
    let user = Src { source: "user-global", framework: "devin-desktop", project_dir: None, containment: Some(&codeium), provenance: None };
    devin_desktop_file(&codeium.join("windsurf").join("hooks.json"), &user, Some(".codeium"), out);
    devin_desktop_file(&codeium.join("hooks.json"), &user, Some(".codeium"), out);
    let (cur, legacy) = if cfg!(target_os = "macos") {
        ("/Library/Application Support/Devin/hooks.json", "/Library/Application Support/Windsurf/hooks.json")
    } else {
        ("/etc/devin/hooks.json", "/etc/windsurf/hooks.json")
    };
    let cur = system_path(cur);
    // The legacy Windsurf system file is read only when the Devin one does not exist.
    let sys = if exists_nofollow(&cur) { cur } else { system_path(legacy) };
    let sys_dir = sys.parent().map(Path::to_path_buf).unwrap_or_default();
    let managed = Src { source: "managed", framework: "devin-desktop", project_dir: None, containment: Some(&sys_dir), provenance: None };
    devin_desktop_file(&sys, &managed, None, out);
    for p in projects {
        let src = Src { source: "project", framework: "devin-desktop", project_dir: Some(&p.root), containment: None, provenance: None };
        // Legacy .windsurf/hooks.json only when .devin/hooks.json is absent or empty.
        if devin_desktop_file(&p.dir.join(".devin").join("hooks.json"), &src, None, out) == 0 {
            devin_desktop_file(&p.dir.join(".windsurf").join("hooks.json"), &src, None, out);
        }
    }

    // Devin CLI.
    for p in projects {
        let src = Src { source: "project", framework: "devin-cli", project_dir: Some(&p.root), containment: None, provenance: None };
        let d = p.dir.join(".devin");
        devin_cli_file(&d.join("hooks.v1.json"), &src, true, None, out);
        devin_cli_file(&d.join("config.json"), &src, false, None, out);
        let local = Src { source: "local", ..src };
        devin_cli_file(&d.join("config.local.json"), &local, false, None, out);
    }
    let cfg = home.join(".config").join("devin");
    let user = Src { source: "user-global", framework: "devin-cli", project_dir: None, containment: Some(&cfg), provenance: None };
    devin_cli_file(&cfg.join("config.json"), &user, false, Some(".devin"), out);
    // Devin CLI reads `hooks` from ~/.claude.json in Claude Code format (Claude Code does
    // not). The file is already read for its projects; no other key is used.
    if let Some(map) = claude_json.and_then(|j| j.get("hooks")) {
        let path = home.join(".claude.json");
        let mut ctx = HookCtx::new(&path, Dialect::DevinCli);
        ctx.own_dir = Some(".claude");
        let hooks = extract_hook_map(map, &ctx);
        let src = Src { source: "user-global", framework: "devin-cli", project_dir: None, containment: None, provenance: None };
        push(&path, &src, hooks, out);
    }
}

// ── OpenCode ────────────────────────────────────────────────────────────────────

fn opencode_modules(dir: &Path, src: &Src, out: &mut Vec<AgentSettings>) {
    for f in project_files_in(dir, src, hs::MODULE_EXTS, out) {
        let shown = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        match src.read(&f) {
            SettingsRead::Content(c) => {
                push(&f, src, vec![hs::module_hook(&shown, Some(&c), RegistersRule::OpenCode)], out);
            }
            SettingsRead::Link(l) => {
                let mut e = linked_settings(&f, src.source, src.framework, l);
                e.git_tracked = is_repository_scope(src.source) && e.git_tracked;
                out.push(e);
            }
            SettingsRead::Unreadable => {}
        }
    }
}

fn opencode_config(path: &Path, src: &Src, out: &mut Vec<AgentSettings>) {
    let Some(j) = load(path, src, out) else { return };
    let Some(list) = j.get("plugin").and_then(|p| p.as_array()) else { return };
    let hooks: Vec<AgentHook> = list
        .iter()
        .take(MAX_HOOK_FILES)
        .filter_map(|v| v.as_str())
        .map(|spec| {
            let shown = sanitize_display(&crate::scanners::redact_secrets_in_text(spec), 200);
            hs::module_hook(&shown, None, RegistersRule::OpenCode)
        })
        .collect();
    push(path, src, hooks, out);
}

fn opencode(home: &Path, projects: &[Project], out: &mut Vec<AgentSettings>) {
    let cfg = home.join(".config").join("opencode");
    let user = Src { source: "user-global", framework: "opencode", project_dir: None, containment: Some(&cfg), provenance: None };
    opencode_config(&cfg.join("opencode.json"), &user, out);
    let plugins = cfg.join("plugins");
    let user_mod = Src { containment: Some(&plugins), ..user };
    opencode_modules(&plugins, &user_mod, out);
    for p in projects {
        let src = Src { source: "project", framework: "opencode", project_dir: Some(&p.root), containment: None, provenance: None };
        opencode_config(&p.dir.join("opencode.json"), &src, out);
        opencode_modules(&p.dir.join(".opencode").join("plugins"), &src, out);
    }
}

// ── Kiro ────────────────────────────────────────────────────────────────────────

fn kiro(home: &Path, projects: &[Project], out: &mut Vec<AgentSettings>) {
    let kh = home.join(".kiro");
    let user = Src { source: "user-global", framework: "kiro", project_dir: None, containment: Some(&kh), provenance: None };
    for f in files_in(&kh.join("hooks"), &["json"]) {
        kiro_file(&f, &user, out);
    }
    for p in projects {
        let src = Src { source: "project", framework: "kiro", project_dir: Some(&p.root), containment: None, provenance: None };
        for f in project_files_in(&p.dir.join(".kiro").join("hooks"), &src, &["json"], out) {
            kiro_file(&f, &src, out);
        }
    }
}

fn kiro_file(path: &Path, src: &Src, out: &mut Vec<AgentSettings>) {
    let Some(j) = load(path, src, out) else { return };
    let ctx = HookCtx::new(path, Dialect::Claude);
    push(path, src, extract_kiro_hooks(&j, &ctx), out);
}
