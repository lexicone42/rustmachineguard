use crate::models::{AgentSkill, SkillDynamicCommand, SkillProvenance, SkillSymlink};
use crate::platform::PlatformInfo;
use crate::scanners::{read_bounded, redact_secrets_in_text, sanitize_display, Scanner};
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

    /// Provenance of a path under `~/.claude/plugins` or `~/.claude/skills/synced`.
    fn provenance(&self, path: &Path) -> Option<SkillProvenance> {
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
        let third_party = self.marketplaces.get(&market).is_some_and(|official| !official);
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
        let ctx = PluginContext::load(&home);
        let mut results = Vec::new();

        // Claude Code custom commands: ~/.claude/commands/
        let global_commands = home.join(".claude").join("commands");
        scan_skill_dir(&global_commands, "claude-code", "global", None, &ctx, &mut results);

        // Claude Code project commands from known projects
        let claude_json = home.join(".claude.json");
        if let Some(project_dirs) = extract_project_dirs(&claude_json) {
            for dir in project_dirs {
                let project_commands = dir.join(".claude").join("commands");
                scan_skill_dir(&project_commands, "claude-code", "project", Some(&dir), &ctx, &mut results);
            }
        }

        // Current directory project commands
        if let Ok(cwd) = std::env::current_dir() {
            let cwd_commands = cwd.join(".claude").join("commands");
            scan_skill_dir(&cwd_commands, "claude-code", "project", Some(&cwd), &ctx, &mut results);
        }

        // Claude Code hooks: ~/.claude/hooks/ and project-level .claude/hooks/
        let global_hooks = home.join(".claude").join("hooks");
        scan_skill_dir(&global_hooks, "claude-code-hook", "global", None, &ctx, &mut results);

        // Codex hooks from ~/.codex/
        let codex_dir = home.join(".codex");
        if crate::scanners::probe_dir(&codex_dir) {
            scan_skill_dir(&codex_dir, "codex", "global", None, &ctx, &mut results);
        }

        // Skill BUNDLES (SKILL.md + sibling scripts), which the flat walk above cannot
        // see. `plugins/` covers the marketplace -> plugin -> skill chain: marketplaces
        // are already inventoried as a remote hot-load surface, but the skills they
        // actually install were never walked.
        scan_skill_bundles(&home.join(".claude").join("skills"), "claude-code", "global", None, &ctx, &mut results);
        scan_skill_bundles(&home.join(".claude").join("plugins"), "claude-code-plugin", "global", None, &ctx, &mut results);
        if let Some(project_dirs) = extract_project_dirs(&home.join(".claude.json")) {
            for dir in project_dirs {
                scan_skill_bundles(&dir.join(".claude").join("skills"), "claude-code", "project", Some(&dir), &ctx, &mut results);
            }
        }
        if let Ok(cwd) = std::env::current_dir() {
            scan_skill_bundles(&cwd.join(".claude").join("skills"), "claude-code", "project", Some(&cwd), &ctx, &mut results);
        }

        // Dedupe by path. Global entries are pushed first, so a home directory that is
        // also a registered project keeps scope "global".
        let mut seen = std::collections::HashSet::new();
        results.retain(|r| seen.insert(r.path.clone()));

        results
    }
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

/// What reading one skill file produced.
struct SkillRead {
    content: Option<String>,
    symlink: Option<SkillSymlink>,
}

/// The canonical form of `p`, or its lexical normalisation when it does not resolve.
fn canon_or_lexical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| crate::scanners::persistence::lexical_join(Path::new("/"), p))
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
/// - a real path that is a credential, key, shell-rc/history, agent-settings or
///   system/other-user path is never read (`sensitive_target`, High);
/// - inside the skill's own directory (for a project: the repository), or inside the
///   user's own skill areas (`~/.claude/{skills,commands,plugins,agents,hooks}`): read;
/// - links in content the scanner inspects (`repo_root`: a plugin's install or clone
///   root, a project repository) are read only when they stay inside it;
/// - the user's own links (`repo_root` None) may also point at their own non-sensitive
///   files under HOME (a dotfiles checkout, XDG `~/.config/...`): read, reported Low;
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
    home: &Path,
) -> Option<SkillRead> {
    use crate::scanners::persistence::{is_sensitive_read_target, lexical_join};
    let real_home = canon_or_lexical(home);
    let areas: Vec<PathBuf> = SKILL_LINK_OK_DIRS
        .iter()
        .flat_map(|d| {
            let l = home.join(".claude").join(d);
            [canon_or_lexical(&l), l]
        })
        .collect();
    let in_skill_area = |p: &Path| areas.iter().any(|a| p.starts_with(a));
    let read = |r: &Path| crate::scanners::read_bounded_nofollow(r, Some(r));

    if !is_link {
        // The walk never descends a symlinked directory, so a regular file can only be
        // redirected by the walk root itself. The user's own roots (a dotfiles-managed
        // ~/.claude/commands) are theirs to link; a repository's are checked.
        let Some(repo) = repo_root else {
            return Some(SkillRead { content: read_bounded(path), symlink: None });
        };
        let real = std::fs::canonicalize(path).ok()?;
        if real.starts_with(canon_or_lexical(repo)) {
            return Some(SkillRead { content: read(&real), symlink: None });
        }
        let sensitive = !in_skill_area(&real) && is_sensitive_read_target(&real, &real_home);
        return Some(SkillRead {
            content: None,
            symlink: Some(SkillSymlink {
                target: sanitize_display(&real.to_string_lossy(), 300),
                escapes: true,
                sensitive_target: sensitive,
                followed: false,
                through_directory: true,
                ..Default::default()
            }),
        });
    }

    let target = std::fs::read_link(path).ok()?;
    let shown = sanitize_display(&target.to_string_lossy(), 300);
    let lexical = lexical_join(path.parent().unwrap_or(containment), &target);
    let real = std::fs::canonicalize(path).ok();
    let sensitive = (!in_skill_area(&lexical) && is_sensitive_read_target(&lexical, home))
        || real.as_ref().is_some_and(|r| !in_skill_area(r) && is_sensitive_read_target(r, &real_home));
    if sensitive {
        return Some(SkillRead {
            content: None,
            symlink: Some(SkillSymlink {
                target: shown,
                escapes: true,
                sensitive_target: true,
                followed: false,
                ..Default::default()
            }),
        });
    }
    // Dangling, looping, or not a regular file (a link to a directory): not a skill file.
    let real = real?;
    if !std::fs::symlink_metadata(&real).is_ok_and(|m| m.is_file()) {
        return None;
    }
    if real.starts_with(canon_or_lexical(containment)) {
        return Some(SkillRead {
            content: read(&real),
            symlink: Some(SkillSymlink { target: shown, followed: true, ..Default::default() }),
        });
    }
    let store = real.starts_with("/nix/store");
    let in_repo = repo_root.is_some_and(|r| real.starts_with(canon_or_lexical(r)));
    let users_own = repo_root.is_none() && real.starts_with(&real_home) && owned_by_current_user(&real);
    let followed = in_skill_area(&real) || in_repo || users_own || store;
    Some(SkillRead {
        content: if followed { read(&real) } else { None },
        symlink: Some(SkillSymlink {
            target: shown,
            escapes: true,
            sensitive_target: false,
            followed,
            store,
            through_directory: false,
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
            let patterns: Vec<String> = crate::scanners::rules_files::check_dangerous_patterns(&raw)
                .into_iter()
                .map(|f| f.pattern)
                .collect();
            dynamic_commands.push(SkillDynamicCommand {
                command: sanitize_display(&redact_secrets_in_text(&raw), 300),
                dangerous: !patterns.is_empty(),
                patterns,
                block,
            });
        }
        if let Some(fm) = frontmatter(text) {
            unrestricted_bash = grants_unrestricted_shell(&parse_allowed_tools(fm));
        }
    }
    let mut provenance = ctx.provenance(path);
    if scope == "project"
        && (unrestricted_bash || !dynamic_commands.is_empty())
        && let Some(root) = project_root
        && crate::scanners::probe_exists(&root.join(".git"))
    {
        let git = if crate::scanners::is_git_tracked(path) { "tracked" } else { "untracked" };
        provenance.get_or_insert_with(SkillProvenance::default).git = Some(git.into());
    }
    // An all-default provenance (a skill outside the plugin tree) says nothing.
    if provenance.as_ref().is_some_and(|p| {
        p.marketplace.is_none() && p.plugin.is_none() && p.git.is_none() && !p.synced
    }) {
        provenance = None;
    }
    let sha256 = match (&content, &read.symlink) {
        (_, Some(l)) if !l.followed => "symlink-not-followed".to_string(),
        (Some(c), _) => sha256_hex(c),
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
    }
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
/// (see `read_skill_file`); symlinked DIRECTORIES are never descended.
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
    let mut budget = MAX_BUNDLE_FILES;
    let mut entries_left = MAX_BUNDLE_ENTRIES;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = crate::scanners::probe_read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if budget == 0 || entries_left == 0 {
                return;
            }
            entries_left -= 1;
            let path = entry.path();
            // symlink_metadata: never follow a link out of the tree we were pointed at.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
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
                skill_dir_of(&path, root)
                    .or_else(|| plugin_root.clone())
                    .unwrap_or_else(|| root.to_path_buf())
            };
            let repo_root = project_root.filter(|_| scope == "project").map(Path::to_path_buf).or(plugin_root);
            let Some(read) = read_skill_file(&path, is_link, &containment, repo_root.as_deref(), &ctx.home) else {
                continue;
            };
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

fn scan_skill_dir(
    dir: &Path,
    framework: &str,
    scope: &str,
    project_root: Option<&Path>,
    ctx: &PluginContext,
    results: &mut Vec<AgentSkill>,
) {
    let Ok(entries) = crate::scanners::probe_read_dir(dir) else {
        return;
    };
    // `commands/` holds custom slash commands, which support dynamic context too.
    let is_commands_dir = dir.file_name().is_some_and(|n| n == "commands");

    for entry in entries.flatten() {
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

        // A project's commands may link anywhere inside the repository (monorepos share
        // prompt files between .claude/commands and other agents' rule directories).
        let project = project_root.filter(|_| scope == "project");
        let containment = project.unwrap_or(dir);
        let Some(read) = read_skill_file(&path, is_link, containment, project, &ctx.home) else {
            continue;
        };

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        results.push(build_skill(
            &path,
            name,
            ext.to_string(),
            is_commands_dir && ext == "md",
            read,
            framework,
            scope,
            project_root,
            ctx,
        ));
    }
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

/// Claude Code dynamic context injection: inline `` !`cmd` `` placeholders (at line
/// start or after whitespace) and ```` ```! ```` fenced blocks, which Claude Code runs
/// in the user's shell when the skill or command loads. Returns `(raw command, block)`,
/// at most 50.
///
/// Ordinary fenced blocks are skipped (documentation teaching the syntax shows it inside
/// ```` ```markdown ```` fences), as are inline code spans: a backtick run of length n
/// opens a span closed only by a run of exactly n, so `` `` !`cmd` `` `` is not a
/// command. `KEY=!`cmd`` and `fuzz_target!`` are not matches either: the `!` has to
/// follow whitespace or start the line.
pub fn extract_dynamic_commands(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let body = body_after_frontmatter(text);
    // (fence char, run length, is a ! block, collected body lines)
    let mut fence: Option<(char, usize, bool, Vec<String>)> = None;
    for line in body.lines() {
        if out.len() >= MAX_DYNAMIC_COMMANDS {
            break;
        }
        let t = line.trim_start();
        let run_char = t.chars().next().filter(|c| *c == '`' || *c == '~');
        let run_len = run_char.map(|c| t.chars().take_while(|x| *x == c).count()).unwrap_or(0);
        if let Some((fc, flen, is_bang, lines)) = fence.as_mut() {
            if run_char == Some(*fc) && run_len >= *flen && t[run_len..].trim().is_empty() {
                if *is_bang {
                    let joined = lines.iter().map(|l| l.trim()).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("; ");
                    if !joined.is_empty() {
                        out.push((joined, true));
                    }
                }
                fence = None;
            } else if *is_bang {
                lines.push(line.to_string());
            }
            continue;
        }
        if run_len >= 3 {
            let info = t[run_len..].trim_start();
            // A backtick fence's info string may not contain a backtick (CommonMark).
            if !(run_char == Some('`') && info.contains('`')) {
                fence = Some((run_char.unwrap_or('`'), run_len, info.starts_with('!'), Vec::new()));
                continue;
            }
        }
        inline_commands(line, &mut out);
    }
    // An unterminated ```! block still runs up to the end of the file.
    if let Some((_, _, true, lines)) = fence {
        let joined = lines.iter().map(|l| l.trim()).filter(|l| !l.is_empty()).collect::<Vec<_>>().join("; ");
        if !joined.is_empty() && out.len() < MAX_DYNAMIC_COMMANDS {
            out.push((joined, true));
        }
    }
    out.truncate(MAX_DYNAMIC_COMMANDS);
    out
}

fn inline_commands(line: &str, out: &mut Vec<(String, bool)>) {
    let chars: Vec<char> = line.chars().collect();
    let n = chars.len();
    let mut i = 0;
    while i < n {
        if out.len() >= MAX_DYNAMIC_COMMANDS {
            return;
        }
        let c = chars[i];
        if c == '!'
            && (i == 0 || chars[i - 1].is_whitespace())
            && i + 1 < n
            && chars[i + 1] == '`'
            && (i + 2 >= n || chars[i + 2] != '`')
        {
            if let Some(end) = (i + 2..n).find(|&j| chars[j] == '`') {
                let cmd: String = chars[i + 2..end].iter().collect();
                if !cmd.trim().is_empty() {
                    out.push((cmd, false));
                }
                i = end + 1;
                continue;
            }
            i += 1;
            continue;
        }
        if c == '`' {
            let run = chars[i..].iter().take_while(|x| **x == '`').count();
            // Find a closing run of exactly `run` backticks.
            let mut j = i + run;
            let mut closed = None;
            while j < n {
                if chars[j] == '`' {
                    let r = chars[j..].iter().take_while(|x| **x == '`').count();
                    if r == run {
                        closed = Some(j + r);
                        break;
                    }
                    j += r;
                } else {
                    j += 1;
                }
            }
            // An unmatched run is literal text.
            i = closed.unwrap_or(i + run);
            continue;
        }
        i += 1;
    }
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
