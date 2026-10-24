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

    fn scan(&self, platform: &dyn PlatformInfo) -> Self::Output {
        let home = platform.home_dir();
        let mut results = Vec::new();

        // Every project of this pass: registered in ~/.claude.json, recovered from
        // ~/.claude/projects/ names, and (primary pass) the working directory; never a
        // scan home (read below as the home) or an ancestor of one.
        let scope = platform.pass_scope();
        let registered = extract_project_dirs(&home.join(".claude.json")).unwrap_or_default();
        for dir in scope.excluding_scan_homes(scope.with_cwd(registered)) {
            scan_directory_for_rules(&dir, false, &mut results);
        }

        // The home directory itself (its memory directories are user scope).
        scan_directory_for_rules(&home, true, &mut results);

        // Claude Code auto memory of every project this home has run Claude Code in.
        scan_auto_memory(&platform.claude_config_dir(), &mut results);

        // Dedupe by path
        let mut seen = std::collections::HashSet::new();
        results.retain(|r| seen.insert(r.path.clone()));

        results
    }
}

fn scan_directory_for_rules(dir: &Path, user: bool, results: &mut Vec<RulesFile>) {
    for name in RULES_FILE_NAMES {
        let path = dir.join(name);
        if crate::scanners::probe_file(&path)
            && let Some(content) = read_bounded(&path)
        {
            let hash = sha256_hex(&content);
            let git_tracked = is_git_tracked(&path);
            let findings = check_dangerous_patterns(&content);

            results.push(RulesFile {
                path: path.to_string_lossy().to_string(),
                file_name: name.to_string(),
                sha256: hash,
                git_tracked,
                size_bytes: content.len(),
                findings,
                ..Default::default()
            });
        }
    }
    let scope = if user { "user" } else { "project" };
    for (rel, kind, framework) in RULES_DIR_NAMES {
        let scope = if rel.ends_with("-local") && !user {
            "local"
        } else {
            scope
        };
        for (path, shown, real) in walk_memory_dir(dir, Path::new(rel)) {
            let name = format!("{rel}/{shown}");
            push_prompt_file(&path, &real, &name, kind, framework, scope, results);
        }
    }
    scan_serena_initial_prompt(dir, user, results);
}

/// Serena's project prompt: "the project prompt, i.e. `initial_prompt` in `project.yml`,
/// which is provided to the LLM upon project activation"
/// (oraios.github.io/serena/02-usage/050_configuration.html, fetched 2026-10-24). Only
/// that key is looked at; a row is added when it is non-empty, hashed on the prompt text,
/// so `--diff` shows it appearing or changing.
fn scan_serena_initial_prompt(dir: &Path, user: bool, results: &mut Vec<RulesFile>) {
    let path = dir.join(".serena").join("project.yml");
    // `.serena` itself must not be a link (the file is opened without following one).
    if !std::fs::symlink_metadata(dir.join(".serena")).is_ok_and(|m| m.is_dir()) || !crate::scanners::probe_file(&path)
    {
        return;
    }
    let Some(content) = read_bounded_nofollow(&path, None) else {
        return;
    };
    let Ok(doc) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(&content) else {
        return;
    };
    let Some(prompt) = doc.get("initial_prompt").and_then(|v| v.as_str()) else {
        return;
    };
    if prompt.trim().is_empty() {
        return;
    }
    let mut findings = check_dangerous_patterns(prompt);
    findings.extend(injection_findings(prompt, user));
    results.push(RulesFile {
        path: path.to_string_lossy().to_string(),
        file_name: ".serena/project.yml#initial_prompt".to_string(),
        sha256: sha256_hex(prompt),
        git_tracked: is_git_tracked(&path),
        size_bytes: prompt.len(),
        findings,
        kind: Some("prompt-config".into()),
        framework: Some("serena".into()),
        scope: Some(if user { "user" } else { "project" }.into()),
    });
}

/// Claude Code auto memory: "Each project gets its own memory directory at
/// `~/.claude/projects/<project>/memory/` ... The first 200 lines of `MEMORY.md`, or the
/// first 25KB, whichever comes first, are loaded at the start of every conversation";
/// topic files are read on demand (code.claude.com/docs/en/memory, fetched 2026-10-24).
/// Every `<project>` directory is looked at, not only those of projects rmguard can name:
/// the memory is loaded whenever Claude Code runs there again, whether or not that
/// project's path can be recovered from its lossy directory name.
fn scan_auto_memory(claude_dir: &Path, results: &mut Vec<RulesFile>) {
    let projects = claude_dir.join("projects");
    if !crate::scanners::probe_dir(&projects) {
        return;
    }
    let Ok(rd) = crate::scanners::probe_read_dir(&projects) else {
        return;
    };
    let mut names: Vec<String> = rd.flatten().filter_map(|e| e.file_name().into_string().ok()).collect();
    names.sort();
    let cap =
        crate::scanners::telemetry::walk_cap(BASE_AUTO_MEMORY_PROJECTS, crate::scanners::telemetry::walk_budget());
    if names.len() > cap {
        names.truncate(cap);
        crate::scanners::telemetry::mark_truncated();
    }
    for name in names {
        // Quietly skip a session directory with no memory: most have none, and a
        // missing `memory/` under each is not a looked-for file worth a count.
        if !std::fs::symlink_metadata(projects.join(&name).join("memory")).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        for (path, shown, real) in walk_memory_dir(&projects, &Path::new(&name).join("memory")) {
            let label = format!("projects/{name}/memory/{shown}");
            push_prompt_file(&path, &real, &label, "auto-memory", "claude-code", "user", results);
        }
    }
}

/// Read one walked memory file (no-follow, bounded) into a row: hashed and git-tracked
/// like a rules file. Every one gets the invisible-Unicode check and the prompt-injection
/// phrases, graded by scope ([`injection_findings`]). A Serena memory, and any
/// project-scope memory (it may arrive in a clone), also gets the rules-file pattern
/// checks, but only their [`memory_relevant`] rows: a memory is the agent's notes ABOUT
/// the code, so "subprocess", `Eval(EvalArgs)` or "base64 ... http" in it is the project
/// being described (on one machine all 6 such hits in 81 Serena memories were), while a
/// fetch piped to a shell or a credential file handed to a sender is an attack wherever
/// it is written.
fn push_prompt_file(
    path: &Path,
    real: &Path,
    name: &str,
    kind: &str,
    framework: &str,
    scope: &str,
    results: &mut Vec<RulesFile>,
) {
    // `real`: the file must still be exactly where the walk found it (no directory of
    // the chain swapped for a link since).
    let Some(content) = read_bounded_nofollow(path, Some(real)) else {
        return;
    };
    let user = scope == "user";
    let mut findings: Vec<RulesFileFinding> = if framework == "serena" || !user {
        check_dangerous_patterns(&content)
            .into_iter()
            .filter(memory_relevant)
            .collect()
    } else {
        hidden_unicode_findings(&content)
    };
    findings.extend(injection_findings(&content, user));
    results.push(RulesFile {
        path: path.to_string_lossy().to_string(),
        file_name: crate::scanners::sanitize_display(name, 512),
        sha256: sha256_hex(&content),
        git_tracked: is_git_tracked(path),
        size_bytes: content.len(),
        findings,
        kind: Some(kind.into()),
        framework: Some(framework.into()),
        scope: Some(scope.into()),
    });
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
