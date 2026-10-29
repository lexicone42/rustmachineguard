use crate::models::{RulesFile, RulesFileFinding};
use crate::platform::PlatformInfo;
use crate::scanners::{Scanner, read_bounded, read_bounded_nofollow};
use std::path::{Path, PathBuf};

pub struct RulesFilesScanner;

const RULES_FILE_NAMES: &[&str] = &[
    ".cursorrules",
    ".cursorignore",
    "copilot-instructions.md",
    ".github/copilot-instructions.md",
    "CLAUDE.md",
    "CLAUDE.local.md",
    ".claude/CLAUDE.md",
    "AGENTS.md",
    // Gemini CLI's workspace context file (github.com/google-gemini/gemini-cli
    // docs/cli/gemini-md.md, fetched 2026-10-24).
    "GEMINI.md",
    ".windsurfrules",
    ".clinerules",
    ".aiderignore",
    // Agent long-term memory / persona files: malicious postinstall scripts append
    // operating instructions here, which the agent then loads into its context every
    // session (the EAA-004 instruction/memory-poisoning surface). Tamper detection
    // (hash + git_tracked) makes cross-session mutation visible via --diff.
    // NB: do not cite CVE-2026-21852 here — that is Claude Code's ANTHROPIC_BASE_URL
    // pre-trust key exfil (<2.0.65), which is the "Gateway routing" detection in
    // agent_settings.rs, not a memory-file issue.
    "MEMORY.md",
    "SOUL.md",
];

/// Directories of agent memory, walked rather than probed by name: (path under the
/// project or home, kind, framework). `.serena/memories` used to be a
/// [`RULES_FILE_NAMES`] row, so the file probe said "missing" for the directory and no
/// memory in it was ever read.
///
/// - Serena: "Project-specific memories: Stored in the `.serena/memories/` directory
///   within your project folder"; global ones in `~/.serena/memories/global/`; Markdown,
///   topics as subdirectories (oraios.github.io/serena/02-usage/045_memories.html,
///   github.com/oraios/serena, fetched 2026-10-24). The agent "receives the list of
///   available memories" and reads them when it judges them relevant.
/// - Claude Code subagent memory (`memory:` frontmatter): `user` scope
///   `~/.claude/agent-memory/<name>/`, `project` scope `.claude/agent-memory/<name>/`,
///   `local` scope `.claude/agent-memory-local/<name>/`; the first 200 lines or 25KB of its
///   `MEMORY.md` go into the subagent's system prompt
///   (code.claude.com/docs/en/sub-agents, fetched 2026-10-24).
const RULES_DIR_NAMES: &[(&str, &str, &str)] = &[
    (".serena/memories", "memory", "serena"),
    (".claude/agent-memory", "agent-memory", "claude-code"),
    (".claude/agent-memory-local", "agent-memory", "claude-code"),
];

/// Files read per memory directory, at the base walk budget (scaled by `--walk-budget`).
const BASE_MEMORY_DIR_FILES: usize = 200;
/// Subdirectory levels below a memory directory that are listed (Serena topics
/// `modules/frontend`, global `global/modules/x`).
const MEMORY_DIR_DEPTH: usize = 2;
/// `~/.claude/projects/<encoded>` directories looked at, at the base walk budget.
const BASE_AUTO_MEMORY_PROJECTS: usize = 500;

/// Dangerous patterns in rules files.
/// Inspired by SkillFortify (arXiv:2603.00195) phase-2 pattern catalog.
const DANGEROUS_PATTERNS: &[(&str, &str, &str)] = &[
    ("base64 decode to shell", "base64 -d", "critical"),
    ("base64 decode to shell", "base64 --decode", "critical"),
    ("dynamic code evaluation", "eval(", "high"),
    ("dynamic code evaluation", "exec(", "high"),
    ("shell command execution", "subprocess", "high"),
    ("shell command execution", "os.system", "high"),
    ("shell command execution", "child_process", "high"),
    ("netcat listener", "nc -l", "critical"),
    ("netcat listener", "ncat -l", "critical"),
    ("environment variable exfiltration", "printenv", "medium"),
    ("disable security controls", "--no-verify", "high"),
    ("disable security controls", "ssl_verify", "medium"),
    ("disable security controls", "strict-ssl=false", "high"),
    ("credential access", "_authToken", "high"),
    ("credential access", "GITHUB_TOKEN", "medium"),
    ("credential access", "API_KEY", "medium"),
    ("data exfiltration pattern", "| curl", "critical"),
    ("data exfiltration pattern", "| wget", "critical"),
];

impl Scanner for RulesFilesScanner {
    type Output = Vec<RulesFile>;

    /// Families in their own spans, each reading files into [`Pending`] rows; the rows are
    /// then joined in the old order (per root: named files, Serena memories, agent memory,
    /// Serena prompt; then the home; then nested files per walked project; then auto
    /// memory), deduplicated by shown path, analysed (`rules.analysis`) and looked up in
    /// git (`rules.git_tracked`). The report is the one the interleaved single pass gave.
    fn scan(&self, platform: &dyn PlatformInfo) -> Self::Output {
        use crate::otel::{Attr, Key};
        let home = platform.home_dir();

        // Every project of this pass: registered in ~/.claude.json, recovered from
        // ~/.claude/projects/ names, and (primary pass) the working directory; never a
        // scan home (read below as the home) or an ancestor of one.
        let scope = platform.pass_scope();
        let registered = extract_project_dirs(&home.join(".claude.json")).unwrap_or_default();
        let all = scope.with_cwd(registered);
        let projects = scope.excluding_scan_homes(all.clone());
        // The projects' own files, then the home itself (its memory directories are user
        // scope).
        let roots: Vec<(&Path, bool)> = projects
            .iter()
            .map(|d| (d.as_path(), false))
            .chain([(home.as_path(), true)])
            .collect();

        let named: Vec<Vec<Pending>> = family("rules.project_files", roots.len(), || {
            roots.iter().map(|(d, _)| named_rules_files(d)).collect()
        });
        let serena: Vec<(Vec<Pending>, Vec<Pending>)> = family("rules.serena", roots.len(), || {
            roots
                .iter()
                .map(|&(d, user)| {
                    let mut memories = Vec::new();
                    memory_dir_rows(d, user, &RULES_DIR_NAMES[0], &mut memories);
                    (memories, serena_initial_prompt(d, user).into_iter().collect())
                })
                .collect()
        });
        let agent: Vec<Vec<Pending>> = family("rules.agent_memory", roots.len(), || {
            roots
                .iter()
                .map(|&(d, user)| {
                    let mut rows = Vec::new();
                    for row in &RULES_DIR_NAMES[1..] {
                        memory_dir_rows(d, user, row, &mut rows);
                    }
                    rows
                })
                .collect()
        });
        let mut pending: Vec<Pending> = Vec::new();
        for ((n, (s, prompt)), a) in named.into_iter().zip(serena).zip(agent) {
            pending.extend(n.into_iter().chain(s).chain(a).chain(prompt));
        }

        // Instruction files in subdirectories, which Claude Code loads when it works there.
        // The home is walked too when Claude Code is run there (it is a registered or
        // recovered project, or the working directory), its own dot-directories excepted.
        {
            let mut span = crate::otel::span("rules.nested_walk", Vec::new);
            let (rows, stats) = nested_walks(
                &home,
                &all,
                &projects,
                crate::scanners::telemetry::helper_jobs(),
                scope.walk_index(),
            );
            pending.extend(rows);
            span.set(|| {
                vec![
                    Attr::int(Key::WalkProjects, stats.projects as i64),
                    Attr::int(Key::WalkProjectsExhausted, stats.projects_exhausted as i64),
                    Attr::int(Key::WalkSkipped, stats.skipped as i64),
                    Attr::ints(Key::WalkTopDirs, stats.top_dirs.clone()),
                    Attr::int(Key::WalkDirs, stats.dirs as i64),
                    Attr::int(Key::WalkEntries, stats.entries as i64),
                    Attr::int(Key::WalkPruned, stats.pruned as i64),
                    Attr::int(Key::WalkDirsCut, stats.dirs_cut as i64),
                    Attr::bool(Key::WalkBudgetExhausted, stats.projects_exhausted > 0),
                    Attr::int(Key::WalkCacheHits, stats.cache_hits as i64),
                    Attr::int(Key::WalkCacheMisses, stats.cache_misses as i64),
                ]
            });
        }

        // Claude Code auto memory of every project this home has run Claude Code in.
        {
            let mut span = crate::otel::span("rules.auto_memory", Vec::new);
            let (rows, projects_seen) = auto_memory_rows(&platform.claude_config_dir());
            span.set(|| {
                vec![
                    Attr::int(Key::WalkProjects, projects_seen as i64),
                    Attr::int(Key::WalkFiles, rows.len() as i64),
                ]
            });
            pending.extend(rows);
        }

        // Dedupe by shown path (the first row of a path is kept, as before).
        let mut seen = std::collections::HashSet::new();
        pending.retain(|r| seen.insert(r.shown_path.clone()));

        let analysed = {
            let mut span = crate::otel::span("rules.analysis", Vec::new);
            let bytes: usize = pending.iter().map(|p| p.content.len()).sum();
            let files = pending.len();
            let jobs = crate::scanners::telemetry::helper_jobs();
            let out = crate::scanners::telemetry::par_map(pending, jobs, Pending::analyse);
            span.set(|| {
                vec![
                    Attr::int(Key::ContentFiles, files as i64),
                    Attr::int(Key::ContentBytes, bytes as i64),
                ]
            });
            out
        };

        // Each repository is listed once (`git ls-files`, cached per scan). In row order on
        // this thread: which repositories get the scan's git budget when stalled listings
        // spend it stays the row order.
        let mut span = crate::otel::span("rules.git_tracked", Vec::new);
        let lookups = analysed.len();
        let results: Vec<RulesFile> = analysed
            .into_iter()
            .map(|(mut row, path)| {
                row.git_tracked = is_git_tracked(&path);
                row
            })
            .collect();
        span.set(|| vec![Attr::int(Key::GitLookups, lookups as i64)]);
        results
    }
}

/// Run one family of the scan under its own span (`name`, a fixed label) with the number
/// of roots it looks at and the rows it read.
fn family<T: FamilyRows>(name: &'static str, roots: usize, f: impl FnOnce() -> Vec<T>) -> Vec<T> {
    use crate::otel::{Attr, Key};
    let mut span = crate::otel::span(name, Vec::new);
    let out = f();
    let files: usize = out.iter().map(FamilyRows::rows).sum();
    span.set(|| {
        vec![
            Attr::int(Key::WalkProjects, roots as i64),
            Attr::int(Key::WalkFiles, files as i64),
        ]
    });
    out
}

/// The rows one root of a family read (for the family span's file count).
trait FamilyRows {
    fn rows(&self) -> usize;
}
impl FamilyRows for Vec<Pending> {
    fn rows(&self) -> usize {
        self.len()
    }
}
impl FamilyRows for (Vec<Pending>, Vec<Pending>) {
    fn rows(&self) -> usize {
        self.0.len() + self.1.len()
    }
}

/// How a read file is checked ([`Pending::analyse`]).
enum Check {
    /// An instruction file: the rules-file pattern checks.
    Rules,
    /// A walked memory file ([`push_prompt_file`]'s grading).
    Memory { serena: bool, user: bool },
    /// Serena's `initial_prompt`: every pattern check plus injection phrases.
    SerenaPrompt { user: bool },
}

/// One file read by a family, waiting for content analysis and its git lookup.
struct Pending {
    /// The file opened (the git-tracked lookup's path).
    path: PathBuf,
    /// The row's `path`, already shown sanitized (the dedupe key).
    shown_path: String,
    file_name: String,
    /// The text analysed and hashed (for the Serena prompt, the prompt alone).
    content: String,
    check: Check,
    kind: Option<&'static str>,
    framework: Option<&'static str>,
    scope: Option<&'static str>,
}

impl Pending {
    fn new(path: PathBuf, file_name: String, content: String, check: Check) -> Pending {
        Pending {
            // Shown sanitized: a project directory name is attacker-chosen, and an encoded
            // synced-skill name carries account UUIDs (mask_identifiers).
            shown_path: crate::scanners::sanitize_display(&path.to_string_lossy(), 512),
            path,
            file_name,
            content,
            check,
            kind: None,
            framework: None,
            scope: None,
        }
    }

    /// Hash and check the content: the row without its git-tracked state, and the path
    /// to look that up for.
    fn analyse(self) -> (RulesFile, PathBuf) {
        let content = &self.content;
        let findings = match self.check {
            Check::Rules => check_dangerous_patterns(content),
            Check::Memory { serena, user } => {
                let mut f: Vec<RulesFileFinding> = if serena || !user {
                    check_dangerous_patterns(content)
                        .into_iter()
                        .filter(memory_relevant)
                        .collect()
                } else {
                    hidden_unicode_findings(content)
                };
                f.extend(injection_findings(content, user));
                f
            }
            Check::SerenaPrompt { user } => {
                let mut f = check_dangerous_patterns(content);
                f.extend(injection_findings(content, user));
                f
            }
        };
        let row = RulesFile {
            path: self.shown_path,
            file_name: self.file_name,
            sha256: sha256_hex(content),
            git_tracked: false,
            size_bytes: content.len(),
            findings,
            kind: self.kind.map(Into::into),
            framework: self.framework.map(Into::into),
            scope: self.scope.map(Into::into),
        };
        (row, self.path)
    }
}

/// The [`RULES_FILE_NAMES`] files of one root.
fn named_rules_files(dir: &Path) -> Vec<Pending> {
    let mut out = Vec::new();
    for name in RULES_FILE_NAMES {
        let path = dir.join(name);
        if crate::scanners::probe_file(&path)
            && let Some(content) = read_bounded(&path)
        {
            out.push(Pending::new(path, name.to_string(), content, Check::Rules));
        }
    }
    out
}

/// The files of one [`RULES_DIR_NAMES`] row under `dir`.
fn memory_dir_rows(dir: &Path, user: bool, row: &(&str, &'static str, &'static str), out: &mut Vec<Pending>) {
    let (rel, kind, framework) = *row;
    let scope = if user {
        "user"
    } else if rel.ends_with("-local") {
        "local"
    } else {
        "project"
    };
    for (path, shown, real) in walk_memory_dir(dir, Path::new(rel)) {
        let name = format!("{rel}/{shown}");
        push_prompt_file(&path, &real, &name, kind, framework, scope, out);
    }
}

/// Counts for the `rules.nested_walk` span, summed over every project walked.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
struct NestedStats {
    /// Directories listed.
    dirs: u64,
    /// Directory entries read.
    entries: u64,
    /// Subdirectories not entered: `.git`, a dependency or tool tree by name, a home
    /// dot-directory, another project of the pass, or a directory found to hold a valid
    /// generated-content marker.
    pruned: u64,
    /// Directories whose listing stopped at the per-directory entry cap.
    dirs_cut: u64,
    /// The project's walk stopped at its directory or entry budget.
    budget_exhausted: bool,
    /// Listings taken from the pass's shared index (read by the gitconfig walk first),
    /// and read by this walk (perf 6d). They sum to `dirs`. Which walk reached a
    /// directory first depends on thread timing; nothing else does.
    cache_hits: u64,
    cache_misses: u64,
    /// Set on the total only: projects walked, how many stopped at a budget, projects of
    /// the pass not walked (a scan home or an ancestor of one, or the same directory as
    /// one already walked), and the largest per-project directory counts.
    projects: u64,
    projects_exhausted: u64,
    skipped: u64,
    top_dirs: Vec<i64>,
}

/// The nested walk of every project of the pass (and the home when it is one), one
/// project per task on up to `jobs` threads, rows and counts joined in project order.
fn nested_walks(
    home: &Path,
    all: &[PathBuf],
    projects: &[PathBuf],
    jobs: usize,
    index: &std::sync::Arc<crate::scanners::walk_index::WalkIndex>,
) -> (Vec<Pending>, NestedStats) {
    use crate::scanners::walk_index::{Consumer, RootRule};
    let real = |p: &Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    let own_home = real(home);
    let home_is_project = all.iter().any(|d| real(d) == own_home);
    let roots: std::collections::HashSet<PathBuf> = projects.iter().cloned().collect();
    let mut walked = std::collections::HashSet::new();
    let mut walks: Vec<(PathBuf, bool)> = projects
        .iter()
        .filter(|d| walked.insert(real(d)))
        .map(|d| (d.clone(), false))
        .collect();
    if home_is_project && walked.insert(own_home) {
        walks.push((home.to_path_buf(), true));
    }
    let skipped = all.len().saturating_sub(walks.len()) as u64;
    // What this walk may list, for the index to drop what it will never ask for: at most
    // NESTED_DEPTH levels down, never under `.git`, a name pruned by name, a name that is
    // not UTF-8, or (the home) a dot-directory.
    index.register(
        Consumer::Rules,
        walks
            .iter()
            .map(|(d, skip_dot)| {
                let rule = RootRule {
                    max_depth: Some(NESTED_DEPTH),
                    skip_git: true,
                    skip_dot: *skip_dot,
                    utf8_only: true,
                };
                (d.clone(), rule)
            })
            .collect::<Vec<_>>(),
    );
    let mut total = NestedStats {
        skipped,
        ..Default::default()
    };
    let mut rows = Vec::new();
    let mut dir_counts = Vec::new();
    for (r, s) in crate::scanners::telemetry::par_map(walks, jobs, |(dir, skip_dot)| {
        let mut rows = Vec::new();
        let mut stats = NestedStats::default();
        scan_nested_rules(&dir, skip_dot, &roots, jobs, index, &mut rows, &mut stats);
        (rows, stats)
    }) {
        rows.extend(r);
        total.dirs += s.dirs;
        total.entries += s.entries;
        total.pruned += s.pruned;
        total.dirs_cut += s.dirs_cut;
        total.cache_hits += s.cache_hits;
        total.cache_misses += s.cache_misses;
        if s.dirs > 0 {
            total.projects += 1;
            total.projects_exhausted += u64::from(s.budget_exhausted);
            dir_counts.push(s.dirs as i64);
        }
    }
    index.done(Consumer::Rules);
    dir_counts.sort_unstable_by(|a, b| b.cmp(a));
    dir_counts.truncate(TOP_DIRS);
    total.top_dirs = dir_counts;
    (rows, total)
}

/// Perf 6d test hook: [`nested_walks`] on a given index. Returns the rows (shown path,
/// name, content), the summed counts without the cache counts, and (hits, misses).
#[cfg(test)]
pub(crate) fn walk_for_index_test(
    home: &Path,
    all: &[PathBuf],
    projects: &[PathBuf],
    jobs: usize,
    index: &std::sync::Arc<crate::scanners::walk_index::WalkIndex>,
) -> (Vec<String>, String, (u64, u64)) {
    let (rows, mut s) = nested_walks(home, all, projects, jobs, index);
    let cache = (s.cache_hits, s.cache_misses);
    assert_eq!(cache.0 + cache.1, s.dirs, "every listing is a hit or a miss");
    (s.cache_hits, s.cache_misses) = (0, 0);
    let rows = rows
        .iter()
        .map(|r| format!("{} | {} | {}", r.shown_path, r.file_name, r.content))
        .collect();
    (rows, format!("{s:?}"), cache)
}

/// Per-project directory counts kept on the `rules.nested_walk` span.
const TOP_DIRS: usize = 5;

/// Instruction files read from a project's SUBDIRECTORIES. Claude Code: "Claude also
/// discovers `CLAUDE.md` and `CLAUDE.local.md` files in subdirectories under your current
/// working directory. Instead of loading them at launch, Claude Code loads each one once
/// Claude reads, writes, or edits another file in that subdirectory", and reads "a
/// subdirectory's `AGENTS.md`, when Claude opens a file there with the Read tool and that
/// subdirectory has none of the three `CLAUDE.md` files of its own"
/// (code.claude.com/docs/en/memory.md, fetched 2026-10-24). Gemini CLI: "When a tool
/// accesses a file or directory, the CLI automatically scans for `GEMINI.md` files in that
/// directory and its ancestors up to a trusted root" (github.com/google-gemini/gemini-cli
/// `docs/cli/gemini-md.md`, fetched 2026-10-24). A project's own `GEMINI.md` ("workspace
/// directories and their parent directories", same page) is a [`RULES_FILE_NAMES`] row.
const NESTED_RULES_NAMES: &[&str] = &["CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "GEMINI.md"];
/// Subdirectory levels below a project walked for [`NESTED_RULES_NAMES`].
const NESTED_DEPTH: usize = 4;
/// Directories listed per project, at the base walk budget (scaled by `--walk-budget`).
const BASE_NESTED_DIRS: usize = 2_000;
/// Directory entries read per project, at the base walk budget, and per directory: a
/// directory of 350,000 image tiles cost half a second to list in full (the walk is marked
/// truncated past either).
const BASE_NESTED_ENTRIES: usize = 200_000;
const MAX_NESTED_DIR_ENTRIES: usize = 20_000;

/// Read the [`NESTED_RULES_NAMES`] files of `root`'s subdirectories (not of `root` itself,
/// read by [`named_rules_files`]), breadth-first so shallow directories come first,
/// at most [`NESTED_DEPTH`] levels down, at most the scaled [`BASE_NESTED_DIRS`]
/// directories and [`BASE_NESTED_ENTRIES`] entries listed, and [`MAX_NESTED_DIR_ENTRIES`]
/// entries of one directory (the scanner is marked truncated past any of them). Pruned as the gitconfig
/// project walk prunes: `.git`, the dependency and tool trees of
/// [`crate::scanners::git_config::PRUNE_BY_NAME`], a directory holding a valid
/// `CACHEDIR.TAG` or `pyvenv.cfg` (cargo's `target/`, a virtualenv), every symlinked
/// directory, and another project of this pass (`others`, walked as its own root). With
/// `skip_dot_dirs` (the home), dot-directories are not entered either: they are the user's
/// own tool state, each read by its own scanner. Each file is a regular file opened without
/// following a link; the row has the same hash, tracked state and pattern checks as the
/// project's own instruction files, with scope "project".
fn scan_nested_rules(
    root: &Path,
    skip_dot_dirs: bool,
    others: &std::collections::HashSet<PathBuf>,
    jobs: usize,
    index: &std::sync::Arc<crate::scanners::walk_index::WalkIndex>,
    results: &mut Vec<Pending>,
    stats: &mut NestedStats,
) {
    use crate::scanners::prefetch::with_prefetch;
    use crate::scanners::walk_index::{Consumer, WalkCtx};
    use std::collections::VecDeque;
    let ctx = std::sync::Arc::new(WalkCtx::new(index, Consumer::Rules, root));
    let cap = crate::scanners::telemetry::walk_cap(BASE_NESTED_DIRS, crate::scanners::telemetry::walk_budget());
    let entry_cap =
        crate::scanners::telemetry::walk_cap(BASE_NESTED_ENTRIES, crate::scanners::telemetry::walk_budget());
    // Listings are read ahead on helpers ([`crate::scanners::prefetch`]), in this walk's
    // own breadth-first order; every decision below is still made here, in that order.
    let list = {
        let ctx = std::sync::Arc::clone(&ctx);
        move |dir: &Path, cancel: &std::sync::atomic::AtomicBool| list_nested_dir(dir, cancel, &ctx)
    };
    with_prefetch(jobs, NESTED_READ_AHEAD * jobs, list, |pf| {
        let mut listed = 0usize;
        let mut entries_seen = 0usize;
        let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::from([(root.to_path_buf(), 0)]);
        while let Some((dir, depth)) = queue.pop_front() {
            if listed >= cap || entries_seen >= entry_cap {
                stats.budget_exhausted = true;
                crate::scanners::telemetry::mark_truncated();
                return;
            }
            listed += 1;
            let listing = match pf.get(&dir) {
                Ok(l) => l,
                Err(e) => {
                    crate::scanners::note_read_dir_error(&dir, &e);
                    continue;
                }
            };
            stats.dirs += 1;
            if listing.cached {
                stats.cache_hits += 1;
            } else {
                stats.cache_misses += 1;
            }
            entries_seen += listing.entries;
            stats.entries += listing.entries as u64;
            if listing.cut {
                stats.dirs_cut += 1;
                crate::scanners::telemetry::mark_truncated();
            }
            if depth > 0
                && listing
                    .markers
                    .iter()
                    .any(|n| crate::scanners::git_config::is_generated_marker(&dir.join(n)))
            {
                stats.pruned += 1;
                continue;
            }
            if depth < NESTED_DEPTH {
                for name in listing.subdirs {
                    let child = dir.join(&name);
                    let pruned = name == ".git"
                        || crate::scanners::git_config::PRUNE_BY_NAME.contains(&name.as_str())
                        || (skip_dot_dirs && name.starts_with('.'))
                        || others.contains(&child);
                    if pruned {
                        stats.pruned += 1;
                    } else {
                        pf.hint(&child);
                        queue.push_back((child, depth + 1));
                    }
                }
            }
            // The walk root's own files are the project's, read by named_rules_files.
            let found = if depth > 0 { listing.found } else { Vec::new() };
            for name in found {
                let path = dir.join(&name);
                let Some(content) = read_bounded_nofollow(&path, None) else {
                    continue;
                };
                let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
                let mut row = Pending::new(
                    path,
                    crate::scanners::sanitize_display(&rel, 512),
                    content,
                    Check::Rules,
                );
                row.scope = Some("project");
                results.push(row);
            }
        }
    });
    ctx.finish();
}

/// Listings read ahead of the nested walk per helper thread (bounded: a walk that stops
/// at its budget drops what it read ahead).
const NESTED_READ_AHEAD: usize = 32;

/// What [`scan_nested_rules`] keeps of one directory listing.
struct NestedListing {
    /// Subdirectories (not symlinks), sorted.
    subdirs: Vec<String>,
    /// [`NESTED_RULES_NAMES`] regular files, sorted.
    found: Vec<String>,
    /// `CACHEDIR.TAG` / `pyvenv.cfg` regular files (checked by the walk).
    markers: Vec<String>,
    /// Entries read: at most [`MAX_NESTED_DIR_ENTRIES`].
    entries: usize,
    /// The listing stopped at [`MAX_NESTED_DIR_ENTRIES`].
    cut: bool,
    /// Taken from the shared index rather than read by this walk.
    cached: bool,
}

/// List one directory for [`scan_nested_rules`]: only subdirectories and the looked-for
/// names are kept, so a directory of 350,000 image tiles is read through once, not
/// collected and sorted, and at most [`MAX_NESTED_DIR_ENTRIES`] of its entries are read.
/// The listing comes from the pass's shared index when the gitconfig walk read it first
/// ([`crate::scanners::walk_index`]), else from the file system. Runs on a prefetch
/// helper: notes nothing (the walk does, when it takes the listing).
fn list_nested_dir(
    dir: &Path,
    cancel: &std::sync::atomic::AtomicBool,
    ctx: &crate::scanners::walk_index::WalkCtx,
) -> std::io::Result<NestedListing> {
    use crate::scanners::walk_index::{Got, Kind};
    let mut l = NestedListing {
        subdirs: Vec::new(),
        found: Vec::new(),
        markers: Vec::new(),
        entries: 0,
        cut: false,
        cached: false,
    };
    // Cancelled part-way: the walk returned and drops this listing unread.
    let Some((listing, got)) = ctx.get(dir, cancel)? else {
        return Ok(l);
    };
    l.cached = got == Got::Hit;
    let (entries, cut, kept) = listing.capped(MAX_NESTED_DIR_ENTRIES);
    l.entries = entries;
    l.cut = cut;
    // A symlink is neither (its own type, not its target's, as the listing reports it).
    for k in kept {
        let Some(name) = k.name.to_str() else {
            continue;
        };
        match k.kind {
            Kind::Dir => l.subdirs.push(name.to_owned()),
            Kind::File if name == "CACHEDIR.TAG" || name == "pyvenv.cfg" => l.markers.push(name.to_owned()),
            Kind::File if NESTED_RULES_NAMES.contains(&name) => l.found.push(name.to_owned()),
            _ => {}
        }
    }
    l.subdirs.sort();
    l.found.sort();
    Ok(l)
}

/// Serena's project prompt: "the project prompt, i.e. `initial_prompt` in `project.yml`,
/// which is provided to the LLM upon project activation"
/// (oraios.github.io/serena/02-usage/050_configuration.html, fetched 2026-10-24). Only
/// that key is looked at; a row is added when it is non-empty, hashed on the prompt text,
/// so `--diff` shows it appearing or changing.
fn serena_initial_prompt(dir: &Path, user: bool) -> Option<Pending> {
    let path = dir.join(".serena").join("project.yml");
    // `.serena` itself must not be a link (the file is opened without following one).
    if !std::fs::symlink_metadata(dir.join(".serena")).is_ok_and(|m| m.is_dir()) || !crate::scanners::probe_file(&path)
    {
        return None;
    }
    let content = read_bounded_nofollow(&path, None)?;
    let doc = crate::scanners::yaml::to_json(&content)?;
    let prompt = doc.get("initial_prompt").and_then(|v| v.as_str())?;
    if prompt.trim().is_empty() {
        return None;
    }
    let mut row = Pending::new(
        path,
        ".serena/project.yml#initial_prompt".to_string(),
        prompt.to_string(),
        Check::SerenaPrompt { user },
    );
    row.kind = Some("prompt-config");
    row.framework = Some("serena");
    row.scope = Some(if user { "user" } else { "project" });
    Some(row)
}

/// Claude Code auto memory: "Each project gets its own memory directory at
/// `~/.claude/projects/<project>/memory/` ... The first 200 lines of `MEMORY.md`, or the
/// first 25KB, whichever comes first, are loaded at the start of every conversation";
/// topic files are read on demand (code.claude.com/docs/en/memory, fetched 2026-10-24).
/// Every `<project>` directory is looked at, not only those of projects rmguard can name:
/// the memory is loaded whenever Claude Code runs there again, whether or not that
/// project's path can be recovered from its lossy directory name. Returns the rows and
/// how many `<project>` directories were looked at.
fn auto_memory_rows(claude_dir: &Path) -> (Vec<Pending>, usize) {
    let mut results = Vec::new();
    let projects = claude_dir.join("projects");
    if !crate::scanners::probe_dir(&projects) {
        return (results, 0);
    }
    let Ok(rd) = crate::scanners::probe_read_dir(&projects) else {
        return (results, 0);
    };
    let mut names: Vec<String> = rd.flatten().filter_map(|e| e.file_name().into_string().ok()).collect();
    names.sort();
    let cap =
        crate::scanners::telemetry::walk_cap(BASE_AUTO_MEMORY_PROJECTS, crate::scanners::telemetry::walk_budget());
    if names.len() > cap {
        names.truncate(cap);
        crate::scanners::telemetry::mark_truncated();
    }
    let looked = names.len();
    for name in names {
        // Quietly skip a session directory with no memory: most have none, and a
        // missing `memory/` under each is not a looked-for file worth a count.
        if !std::fs::symlink_metadata(projects.join(&name).join("memory")).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        for (path, shown, real) in walk_memory_dir(&projects, &Path::new(&name).join("memory")) {
            let label = format!("projects/{name}/memory/{shown}");
            push_prompt_file(&path, &real, &label, "auto-memory", "claude-code", "user", &mut results);
        }
    }
    (results, looked)
}

/// Read one walked memory file (no-follow, bounded) into a row: hashed and git-tracked
/// like a rules file. Every one gets the invisible-Unicode check and the prompt-injection
/// phrases, graded by scope ([`injection_findings`]). A Serena memory, and any
/// project-scope memory (it may arrive in a clone), also gets the rules-file pattern
/// checks, but only their [`memory_relevant`] rows: a memory is the agent's notes ABOUT
/// the code, so "subprocess", `Eval(EvalArgs)` or "base64 ... http" in it is the project
/// being described (on one machine all 6 such hits in 81 Serena memories were), while a
/// fetch piped to a shell or a credential file handed to a sender is an attack wherever
/// it is written. (The checks run later, in [`Pending::analyse`].)
fn push_prompt_file(
    path: &Path,
    real: &Path,
    name: &str,
    kind: &'static str,
    framework: &'static str,
    scope: &'static str,
    results: &mut Vec<Pending>,
) {
    // `real`: the file must still be exactly where the walk found it (no directory of
    // the chain swapped for a link since).
    let Some(content) = read_bounded_nofollow(path, Some(real)) else {
        return;
    };
    let check = Check::Memory {
        serena: framework == "serena",
        user: scope == "user",
    };
    let mut row = Pending::new(
        path.to_path_buf(),
        crate::scanners::sanitize_display(name, 512),
        content,
        check,
    );
    row.kind = Some(kind);
    row.framework = Some(framework);
    row.scope = Some(scope);
    results.push(row);
}

/// The [`check_dangerous_patterns`] rows kept for a memory file: the Critical ones (a
/// fetch piped to a shell, a credential file sent, base64 decoded to a shell, a netcat
/// listener, output piped to a sender), anything visible only after de-obfuscation (hidden
/// on purpose), and invisible Unicode.
fn memory_relevant(f: &RulesFileFinding) -> bool {
    f.severity == "critical" || f.pattern.contains("(obfuscated") || f.pattern.starts_with("invisible Unicode")
}

/// The `.md` / `.mdc` / `.txt` files of a memory directory, depth-first in name order,
/// at most [`MEMORY_DIR_DEPTH`] subdirectory levels down and at most the scaled
/// [`BASE_MEMORY_DIR_FILES`] files (the scanner is marked truncated past that). The
/// directory is `base/rel`; no component of `rel` may be a symlink (a repository's
/// `.serena -> ~/somewhere` is not walked), and no symlink below it is followed, to a file
/// or a directory. `base` (the project, the home, `~/.claude/projects`) is taken as given.
/// Returns each file with its path relative to the directory and its real path (for
/// [`read_bounded_nofollow`]'s `expect`).
fn walk_memory_dir(base: &Path, rel: &Path) -> Vec<(PathBuf, String, PathBuf)> {
    let root = base.join(rel);
    let mut out = Vec::new();
    let mut at = base.to_path_buf();
    for c in rel.components() {
        at.push(c);
        if !std::fs::symlink_metadata(&at).is_ok_and(|m| m.is_dir()) {
            // Absent is the common case: one traced probe of the directory, counted as
            // missing (a link, or a file, is traced and not counted).
            crate::scanners::probe_dir(&root);
            return out;
        }
    }
    let Ok(real_root) = std::fs::canonicalize(&root) else {
        return out;
    };
    crate::scanners::telemetry::note_probe(&root, true);
    let cap = crate::scanners::telemetry::walk_cap(BASE_MEMORY_DIR_FILES, crate::scanners::telemetry::walk_budget());
    let mut files = Vec::new();
    if walk_memory_level(&root, "", 0, cap, &mut files) {
        crate::scanners::telemetry::mark_truncated();
    }
    for (path, shown) in files {
        let real = real_root.join(&shown);
        out.push((path, shown, real));
    }
    out
}

/// One level of [`walk_memory_dir`]; true when the cap stopped it.
fn walk_memory_level(dir: &Path, prefix: &str, depth: usize, cap: usize, out: &mut Vec<(PathBuf, String)>) -> bool {
    let Ok(rd) = crate::scanners::probe_read_dir(dir) else {
        return false;
    };
    let mut entries: Vec<(String, std::fs::FileType)> = rd
        .flatten()
        .filter_map(|e| Some((e.file_name().into_string().ok()?, e.file_type().ok()?)))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    for (name, ft) in entries {
        let rel = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if ft.is_dir() {
            if depth < MEMORY_DIR_DEPTH && walk_memory_level(&dir.join(&name), &rel, depth + 1, cap, out) {
                return true;
            }
        } else if ft.is_file() && is_prompt_text_name(&name) {
            if out.len() >= cap {
                return true;
            }
            out.push((dir.join(&name), rel));
        }
    }
    false
}

fn is_prompt_text_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [".md", ".mdc", ".txt"].iter().any(|e| lower.ends_with(e))
}

/// Prompt-injection phrases ([`crate::scanners::scan_context_prompt_text`]) in text the
/// agent reads, graded as a prompt hook whose text enters the agent's conversation is
/// (analysis `hook_severity`): in a repository a concealment or override phrase is High
/// and a phrase ordinary instructions also use (`WEAK_CONTEXT_PHRASES`, and the soft
/// concealment phrases unless aimed at the user) Medium; in the user's own files the first
/// is Low and the second is not reported.
pub(crate) fn injection_findings(content: &str, user: bool) -> Vec<RulesFileFinding> {
    let mut out = Vec::new();
    for p in crate::scanners::scan_context_prompt_text(content) {
        let soft = crate::scanners::SOFT_CONCEALMENT_PHRASES.contains(&p);
        let aimed = soft && crate::scanners::concealment_aimed_at_user(content, p);
        let weak = crate::scanners::WEAK_CONTEXT_PHRASES.contains(&p) || (soft && !aimed);
        let severity = match (user, weak) {
            (true, true) => continue,
            (true, false) => "low",
            (false, true) => "medium",
            (false, false) => "high",
        };
        let suffix = if aimed {
            crate::scanners::AIMED_AT_USER_SUFFIX
        } else {
            ""
        };
        out.push(RulesFileFinding {
            severity: severity.to_string(),
            pattern: format!("prompt-injection phrase \"{p}\"{suffix}"),
        });
    }
    out
}

fn extract_project_dirs(claude_json: &std::path::Path) -> Option<Vec<PathBuf>> {
    let content = read_bounded(claude_json)?;
    let parsed: serde_json::Value = serde_json::from_str(&content).ok()?;
    let projects = parsed.get("projects")?.as_object()?;
    let dirs: Vec<PathBuf> = projects
        .keys()
        .map(PathBuf::from)
        .filter(|p| crate::scanners::probe_dir(p))
        .collect();
    if dirs.is_empty() { None } else { Some(dirs) }
}

fn sha256_hex(content: &str) -> String {
    super::sha256_hex(content)
}

fn is_git_tracked(path: &std::path::Path) -> bool {
    super::is_git_tracked(path)
}

/// Whether `hay` (lowercased) contains the pattern `needle` (lowercased) where the
/// pattern means what it names (review of b9cda85: the substring gate made
/// `--no-verify-ssl-warnings`, `~/.claude/hooks/no_subprocess_guard.py`,
/// `python3 -m subprocess_tools.lint` and `rsync -lav` Critical):
/// - a flag (`--no-verify`) only as a whole flag token: not inside a longer word or flag
///   (`--no-verify-ssl-warnings`, `x--no-verify`); `=`, quotes, `*` and spaces end it;
/// - a program with a flag (`nc -l`, `ncat -l`) only as its own word (not `rsync -l`);
/// - a code name (`subprocess`, `child_process`, `os.system`) only as a code token: not
///   inside an identifier (`subprocess_tools`, `no_subprocess_guard`), not a path
///   component or file name (`hooks/subprocess.py`);
/// - a call (`eval(`, `exec(`) only after a non-identifier character (not `retrieval(`).
///
/// Every other row is a substring, as before (`API_KEY` is meant to match
/// `OPENAI_API_KEY`, `| curl` any sender). Linear in `hay`.
pub(crate) fn contains_pattern(hay: &str, needle: &str) -> bool {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let word = |c: char| ident(c) || c == '-';
    enum Rule {
        Flag,
        ProgramFlag,
        Code,
        Call,
        Substring,
    }
    let rule = match needle {
        "--no-verify" => Rule::Flag,
        "nc -l" | "ncat -l" => Rule::ProgramFlag,
        "subprocess" | "child_process" | "os.system" => Rule::Code,
        "eval(" | "exec(" => Rule::Call,
        _ => Rule::Substring,
    };
    if matches!(rule, Rule::Substring) {
        return hay.contains(needle);
    }
    let mut from = 0;
    while let Some(off) = hay[from..].find(needle) {
        let at = from + off;
        let end = at + needle.len();
        from = at + needle.chars().next().map_or(1, char::len_utf8);
        let before = hay[..at].chars().next_back();
        let after = hay[end..].chars().next();
        let ok = match rule {
            Rule::Flag => !before.is_some_and(word) && !after.is_some_and(word),
            Rule::ProgramFlag => !before.is_some_and(|c| word(c) || c == '.' || c == '/'),
            Rule::Code => {
                let in_path = before == Some('/') || before == Some('\\');
                let file_name = after == Some('.') && {
                    let ext: String = hay[end + 1..]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric())
                        .collect();
                    matches!(
                        ext.as_str(),
                        "py" | "sh" | "js" | "ts" | "mjs" | "cjs" | "rb" | "pl" | "md" | "json" | "txt"
                    )
                };
                !before.is_some_and(ident) && !after.is_some_and(ident) && !in_path && !file_name
            }
            Rule::Call => !before.is_some_and(ident),
            Rule::Substring => true,
        };
        if ok {
            return true;
        }
    }
    false
}

pub fn check_dangerous_patterns(content: &str) -> Vec<crate::models::RulesFileFinding> {
    let lower = content.to_lowercase();
    // The same text with homoglyphs folded, shell quoting collapsed and invisible
    // characters dropped — i.e. what a shell would actually execute.
    let normalized = crate::scanners::normalize_for_matching(content);
    let mut findings = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for (description, pattern, severity) in DANGEROUS_PATTERNS {
        let needle = pattern.to_lowercase();
        let raw_hit = contains_pattern(&lower, &needle);
        let folded_hit = contains_pattern(&normalized, &needle);
        if !raw_hit && !folded_hit {
            continue;
        }
        if !seen.insert(*description) {
            continue;
        }
        if raw_hit {
            findings.push(crate::models::RulesFileFinding {
                severity: severity.to_string(),
                pattern: description.to_string(),
            });
        } else {
            // Visible only after de-obfuscation. Text that matches ONLY once
            // homoglyphs/quoting/invisible characters are folded away was obfuscated
            // deliberately — that intent is a stronger signal than the pattern alone,
            // so it is never reported below "high".
            let escalated = if *severity == "medium" || *severity == "low" {
                "high"
            } else {
                severity
            };
            findings.push(crate::models::RulesFileFinding {
                severity: escalated.to_string(),
                pattern: format!("{description} (obfuscated — only visible after de-obfuscation)"),
            });
        }
    }

    // curl/wget PIPED TO A SHELL. This used to be a bare substring match on "curl "
    // labelled "piped to shell" at critical, so any prose mentioning curl produced a
    // critical finding claiming a pipe that was not there. Match the actual shape
    // instead: a fetch and a pipe into a shell on the SAME line.
    let has_fetch_pipe = |text: &str| {
        text.lines().any(|line| {
            (line.contains("curl") || line.contains("wget"))
                && ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh", "| dash", "|dash"]
                    .iter()
                    .any(|p| line.contains(p))
        })
    };
    if has_fetch_pipe(&normalized) && seen.insert("curl|wget piped to shell") {
        // Same obfuscation rule as above: visible only after folding means deliberate.
        let obfuscated = !has_fetch_pipe(&lower);
        findings.push(crate::models::RulesFileFinding {
            severity: "critical".to_string(),
            pattern: if obfuscated {
                "curl|wget piped to shell (obfuscated — only visible after de-obfuscation)".to_string()
            } else {
                "curl|wget piped to shell".to_string()
            },
        });
    }

    // A credential FILE handed to a network sender by substitution, `@` upload, redirection,
    // --post-file, or a URL query (see skills::sends_credential_file). Shared by hooks,
    // helpers, skill dynamic commands, VS Code tasks and rules files.
    let sends_cred = |text: &str| crate::scanners::skills::sends_credential_file(text);
    if (sends_cred(&lower) || sends_cred(&normalized)) && seen.insert("credential file sent by a network client") {
        let obfuscated = !sends_cred(&lower);
        findings.push(crate::models::RulesFileFinding {
            severity: "critical".to_string(),
            pattern: if obfuscated {
                "data exfiltration pattern (a credential file sent by a network client) (obfuscated — only visible after de-obfuscation)".to_string()
            } else {
                "data exfiltration pattern (a credential file sent by a network client)".to_string()
            },
        });
    }

    // Cross-channel detection: encoding + network access (SkillFortify information flow check)
    let has_encoding = lower.contains("base64") || lower.contains("encode");
    let has_network =
        lower.contains("curl") || lower.contains("wget") || lower.contains("fetch") || lower.contains("http");
    if has_encoding && has_network && seen.insert("cross-channel: encoding + network") {
        findings.push(crate::models::RulesFileFinding {
            severity: "high".to_string(),
            pattern: "cross-channel: encoding + network access (potential exfiltration)".to_string(),
        });
    }

    // Invisible / smuggled Unicode. An instruction file that renders perfectly clean can
    // carry a hidden payload: the TrapDoor campaign wrote zero-width and directional-mark
    // sequences into CLAUDE.md and .cursorrules. Visible-text pattern matching is
    // structurally blind to this, so it is detected as a character class instead.
    //
    // Severity is graded by how smuggling-specific the class is, to avoid crying wolf on
    // legitimately multilingual files: tag blocks and variation-selector sequences have no
    // legitimate use in an instruction file, whereas bidi marks are normal in RTL text and
    // soft hyphens are ordinary typography.
    findings.extend(hidden_unicode_findings(content));

    findings
}

/// The invisible-Unicode findings of [`check_dangerous_patterns`] alone, one per class.
pub(crate) fn hidden_unicode_findings(content: &str) -> Vec<RulesFileFinding> {
    let mut seen = std::collections::HashSet::new();
    let mut findings = Vec::new();
    for cat in crate::scanners::scan_suspicious_unicode(content) {
        if seen.insert(cat) {
            findings.push(RulesFileFinding {
                severity: invisible_unicode_severity(cat).to_string(),
                pattern: format!("invisible Unicode ({cat}) — text that renders clean but carries hidden characters"),
            });
        }
    }
    findings
}

/// How suspicious an invisible-Unicode class is when found in an instruction file.
/// Graded, not uniform: some classes are pure smuggling vectors, others have ordinary
/// uses in multilingual or typeset text.
fn invisible_unicode_severity(category: &str) -> &'static str {
    match category {
        // No legitimate use in an agent instruction file — these exist to hide data.
        "tag-block" | "variation-selector-smuggler" => "critical",
        // Rare but not unheard of (emoji ZWJ sequences, some Indic scripts).
        "zero-width" => "high",
        // Normal in right-to-left text, so advisory rather than damning.
        "bidi-control" => "medium",
        // Ordinary typography; worth surfacing only because it can split keywords.
        "soft-hyphen" => "low",
        _ => "medium",
    }
}
