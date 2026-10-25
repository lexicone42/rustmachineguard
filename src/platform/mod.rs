#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use crate::models::DeviceInfo;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

/// What one home pass scans beyond its home's own files: the working directory, which is
/// a project of the PRIMARY pass only (an extra `--search-dirs` pass scans the projects
/// registered in that home and never the cwd), and every home this scan visits, none of
/// which (nor any ancestor of one) any pass walks as a project. Without this, rmguard run
/// from HOME with one `--search-dirs` entry walked all of HOME as a project of the extra
/// pass, and reported the cwd's nested repos, skills and settings a second time.
#[derive(Clone, Debug)]
pub struct PassScope {
    cwd_project: Option<PathBuf>,
    /// Each home as given, with its canonical path (lexical when it does not resolve).
    scan_homes: Vec<(PathBuf, PathBuf)>,
    /// Projects recovered from this pass's `~/.claude/projects/<encoded>` directory names
    /// ([`recover_projects`]), computed once on first use and shared by every scanner
    /// of the pass (a fresh cell whenever the homes change).
    recovered: Arc<OnceLock<Recovered>>,
}

/// The result of [`recover_projects`].
#[derive(Debug, Default)]
pub struct Recovered {
    /// Existing directories, sorted, none registered, the cwd, a scan home or an
    /// ancestor of one.
    pub dirs: Vec<PathBuf>,
    /// More encoded names than the cap: some were not looked at.
    pub truncated: bool,
    /// Encoded names that decode to more than one existing directory: none of them is
    /// kept (the encoding cannot say which one Claude Code ran in).
    pub ambiguous: Vec<String>,
}

impl PassScope {
    /// The primary pass for `home`: the current working directory is a project.
    pub fn primary(home: &Path) -> Self {
        Self {
            cwd_project: std::env::current_dir().ok(),
            scan_homes: vec![home_entry(home)],
            recovered: Arc::default(),
        }
    }

    /// An extra (`--search-dirs`) pass for `home`, in a scan that also visits `others`
    /// (the primary home and the other extra homes): no working directory.
    pub fn search_dir(home: &Path, others: &[PathBuf]) -> Self {
        Self {
            cwd_project: None,
            scan_homes: vec![home_entry(home)],
            recovered: Arc::default(),
        }
        .with_scan_homes(others)
    }

    /// `homes` added to the homes this scan visits (the primary pass learns the
    /// `--search-dirs` entries this way).
    pub fn with_scan_homes(mut self, homes: &[PathBuf]) -> Self {
        for h in homes {
            if !self.scan_homes.iter().any(|(given, _)| given == h) {
                self.scan_homes.push(home_entry(h));
            }
        }
        // Recovery excludes every scan home: recompute with the new set.
        self.recovered = Arc::default();
        self
    }

    /// The working directory when this is the primary pass, else None.
    pub fn cwd_project(&self) -> Option<&Path> {
        self.cwd_project.as_deref()
    }

    /// Every home this scan visits, as given.
    pub fn scan_homes(&self) -> impl Iterator<Item = &Path> {
        self.scan_homes.iter().map(|(given, _)| given.as_path())
    }

    /// `registered` (a home's registered projects), plus the projects recovered from
    /// the home's `~/.claude/projects/` directory names ([`Self::recovered`]), plus the
    /// working directory when this is the primary pass. Every scanner's project list is
    /// built here, so a project Claude Code has a session store for but no `.claude.json`
    /// entry (an older registry, one pruned or never written) is still scanned. A
    /// scanner whose list was built from a truncated recovery is marked truncated.
    pub fn with_cwd(&self, mut registered: Vec<PathBuf>) -> Vec<PathBuf> {
        let rec = self.recovered();
        if rec.truncated {
            crate::scanners::telemetry::mark_truncated();
        }
        for d in &rec.dirs {
            if !registered.contains(d) {
                registered.push(d.clone());
            }
        }
        if let Some(cwd) = &self.cwd_project {
            registered.push(cwd.clone());
        }
        registered
    }

    /// The projects recovered from this pass's `<home>/.claude/projects/` directory names
    /// (computed on first use; see [`recover_projects`]).
    pub fn recovered(&self) -> &Recovered {
        self.recovered.get_or_init(|| {
            let home = &self.scan_homes[0].0;
            let rec = recover_projects(home, self);
            if crate::scanners::telemetry::trace_enabled() {
                for n in &rec.ambiguous {
                    eprintln!(
                        "trace: ambiguous encoded project name, skipped: {}",
                        crate::scanners::sanitize_display(n, 512)
                    );
                }
                for d in &rec.dirs {
                    eprintln!(
                        "trace: project {} <- source claude-projects-dir (not in ~/.claude.json)",
                        crate::scanners::sanitize_display(&d.display().to_string(), 512)
                    );
                }
            }
            rec
        })
    }

    /// Whether `dir` is one of this scan's homes or an ancestor of one, compared both as
    /// given and canonically (a symlinked HOME is caught too). Such a directory is never
    /// walked as a project: its agent directories are a home's own configuration.
    pub fn is_scan_home_or_ancestor(&self, dir: &Path) -> bool {
        let real = canon_or_lexical(dir);
        self.scan_homes
            .iter()
            .any(|(given, real_home)| given.starts_with(dir) || real_home.starts_with(&real))
    }

    /// `dirs` without another scan home or an ancestor of one, keeping `own_home` itself
    /// when it is listed (the working directory or a registered project: an agent run in
    /// `~` reads `~/.env`, `~/.vscode/tasks.json`, `~/.mcp.json`). The rule the MCP
    /// scanner's project list follows, for the scanners that check fixed files per project.
    pub fn excluding_other_scan_homes(&self, dirs: Vec<PathBuf>, own_home: &Path) -> Vec<PathBuf> {
        let own = canon_or_lexical(own_home);
        dirs.into_iter()
            .filter(|d| canon_or_lexical(d) == own || !self.is_scan_home_or_ancestor(d))
            .collect()
    }

    /// `dirs` without any scan home or ancestor of one ([`Self::is_scan_home_or_ancestor`]).
    pub fn excluding_scan_homes(&self, dirs: Vec<PathBuf>) -> Vec<PathBuf> {
        dirs.into_iter().filter(|d| !self.is_scan_home_or_ancestor(d)).collect()
    }
}

// ── Projects recovered from ~/.claude/projects/<encoded> ──────────────────────────────

/// Encoded names looked at per pass at the base walk budget (scaled by `--walk-budget`).
const BASE_ENCODED_NAMES: usize = 2_000;
/// Directory listings one encoded name may cost while decoding.
const DECODE_ATTEMPTS_PER_NAME: usize = 64;
/// Entries read from one directory listing while decoding.
const DECODE_ENTRIES_PER_DIR: usize = 10_000;

/// Claude Code's name for a project's directory under `~/.claude/projects/`: the absolute
/// path with every character that is not an ASCII letter or digit replaced by `-`
/// (`/datar/x_y/.claude` -> `-datar-x-y--claude`). Not documented as a rule
/// (code.claude.com/docs/en/memory says only "the `<project>` path is derived from the
/// git repository"); read off the directory names Claude Code writes. A character
/// outside the BMP becomes two dashes (one per UTF-16 unit, as JavaScript's replace sees
/// it).
pub fn encode_project_path(path: &Path) -> String {
    encode_with(&path.to_string_lossy(), |c| c.is_ascii_alphanumeric())
}

/// The older spelling seen beside the current one for the same project (both
/// `-datar-claude_code_x` and `-datar-claude-code-x` exist on one machine): only `/` and
/// `.` replaced, `_` and other characters kept.
pub fn encode_project_path_legacy(path: &Path) -> String {
    encode_with(&path.to_string_lossy(), |c| c != '/' && c != '.')
}

fn encode_with(s: &str, keep: impl Fn(char) -> bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if keep(c) {
            out.push(c);
        } else {
            for _ in 0..c.len_utf16() {
                out.push('-');
            }
        }
    }
    out
}

/// One directory entry while decoding: its path and both encodings of its name.
type DecodeEntry = (PathBuf, String, String);

/// Recover project directories from `<home>/.claude/projects/` names, which Claude Code
/// writes for every directory it runs in whether or not `~/.claude.json` still lists it.
/// The encoding is lossy (`/`, `.`, `_` and `-` all become `-`), so a name is decoded
/// against the filesystem, best effort:
///
/// 1. Anchors: the registered projects and their parents, every scan home, and the
///    working directory and its ancestors. A name that IS an anchor's encoding names it;
///    a name that extends one (`<anchor>-rest`) is decoded from that anchor (the
///    longest such).
/// 2. Otherwise (and below an anchor) the rest is decoded one directory at a time: list
///    the directory and descend into each child directory whose encoded name is the
///    next part of the rest, followed by `-` (the next `/`) or the end. This is the
///    "which of `-`, `.`, `_` was this dash" search done against what exists, and each
///    name may cost at most [`DECODE_ATTEMPTS_PER_NAME`] listings.
///
/// Kept: existing directories that are not registered, not the working directory, and
/// not a scan home or an ancestor of one. Nothing is opened but directory listings and
/// `~/.claude.json`'s `projects` keys; nothing is traced or counted against a scanner
/// (whichever scanner asks first must not get the cost, or diagnostics would depend on
/// thread timing).
pub fn recover_projects(home: &Path, scope: &PassScope) -> Recovered {
    let mut rec = Recovered::default();
    let Ok(rd) = std::fs::read_dir(home.join(".claude").join("projects")) else {
        return rec;
    };
    let mut names: Vec<String> = rd
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with('-'))
        .collect();
    names.sort();
    let cap = crate::scanners::telemetry::walk_cap(BASE_ENCODED_NAMES, crate::scanners::telemetry::walk_budget());
    if names.len() > cap {
        names.truncate(cap);
        rec.truncated = true;
    }

    let registered = registry_projects(home);
    let owner = crate::scanners::home_owner_uid(home);
    let mut anchors: Vec<PathBuf> = Vec::new();
    let mut add = |p: &Path| {
        if p.is_absolute() && !anchors.iter().any(|a| a == p) {
            anchors.push(p.to_path_buf());
        }
    };
    for r in &registered {
        add(r);
        if let Some(parent) = r.parent() {
            add(parent);
        }
    }
    for h in scope.scan_homes() {
        add(h);
    }
    if let Some(cwd) = scope.cwd_project() {
        for a in cwd.ancestors() {
            add(a);
        }
    }
    // (encoding, anchor), longest encoding first so the most specific anchor wins.
    let mut encoded: Vec<(String, &PathBuf)> = Vec::new();
    for a in &anchors {
        if a.parent().is_none() {
            continue; // "/" is the root search below.
        }
        let (now, old) = (encode_project_path(a), encode_project_path_legacy(a));
        if now == old {
            encoded.push((now, a));
        } else {
            encoded.push((now, a));
            encoded.push((old, a));
        }
    }
    encoded.sort_by(|x, y| y.0.len().cmp(&x.0.len()).then_with(|| x.0.cmp(&y.0)));

    let mut listings: std::collections::HashMap<PathBuf, Vec<DecodeEntry>> = std::collections::HashMap::new();
    let mut found: Vec<PathBuf> = Vec::new();
    for name in &names {
        let mut hits: Vec<PathBuf> = Vec::new();
        if let Some((_, a)) = encoded.iter().find(|(e, _)| e == name) {
            hits.push((*a).clone());
        } else {
            // Every anchor the name extends, most specific first, then the root: the first
            // that decodes wins (an anchor `/a/foo` is a false prefix of `/a/foo-bar/x`).
            let starts: Vec<(PathBuf, &str)> = encoded
                .iter()
                .filter(|(e, _)| {
                    name.len() > e.len() + 1 && name.starts_with(e.as_str()) && name.as_bytes()[e.len()] == b'-'
                })
                .map(|(e, a)| ((*a).clone(), &name[e.len() + 1..]))
                .chain(std::iter::once((PathBuf::from("/"), &name[1..])))
                .collect();
            let mut attempts = 0;
            for (base, rest) in starts {
                decode_under(&base, rest, &mut listings, &mut attempts, &mut hits);
                if !hits.is_empty() || attempts >= DECODE_ATTEMPTS_PER_NAME {
                    break;
                }
            }
        }
        // A lossy name that two existing directories both encode to (`shared/a-b` and
        // `shared/a/b`) names neither for certain: keep none rather than scan a
        // directory someone else may have made to match.
        if hits.len() > 1 {
            rec.ambiguous.push(name.clone());
            continue;
        }
        for h in hits {
            if registered.contains(&h)
                || under_shared_sticky_dir(&h, owner)
                || scope.cwd_project() == Some(h.as_path())
                || scope.is_scan_home_or_ancestor(&h)
                || !h.is_dir()
                || found.contains(&h)
            {
                continue;
            }
            found.push(h);
        }
    }
    found.sort();
    rec.dirs = found;
    rec
}

/// Depth-first decode of `rest` (an encoded relative path) under `dir`; see
/// [`recover_projects`].
fn decode_under(
    dir: &Path,
    rest: &str,
    listings: &mut std::collections::HashMap<PathBuf, Vec<DecodeEntry>>,
    attempts: &mut usize,
    hits: &mut Vec<PathBuf>,
) {
    if rest.is_empty() || *attempts >= DECODE_ATTEMPTS_PER_NAME {
        return;
    }
    *attempts += 1;
    let entries = listings
        .entry(dir.to_path_buf())
        .or_insert_with(|| list_child_dirs(dir));
    // Children whose encoded name is a prefix of `rest` at a `/` boundary.
    let mut next: Vec<(PathBuf, usize)> = Vec::new();
    for (path, now, old) in entries.iter() {
        for enc in [now, old] {
            if rest == enc.as_str() {
                if !hits.contains(path) {
                    hits.push(path.clone());
                }
            } else if rest.len() > enc.len() + 1
                && rest.starts_with(enc.as_str())
                && rest.as_bytes()[enc.len()] == b'-'
                && !next.iter().any(|(p, l)| p == path && *l == enc.len())
            {
                next.push((path.clone(), enc.len()));
            }
        }
    }
    for (path, len) in next {
        decode_under(&path, &rest[len + 1..], listings, attempts, hits);
    }
}

/// A directory below a sticky, world-writable one (`/tmp`, `/var/tmp`, any `o+wt`
/// directory) that is not wholly the scanned user's: anyone can create a name there, so
/// a decoded name landing in it counts only when the candidate and every directory
/// between it and the sticky one are owned by the owner of the scanned home
/// ([`crate::scanners::home_owner_uid`]). A directory another account made to match a
/// lossy name is skipped.
#[cfg(unix)]
fn under_shared_sticky_dir(p: &Path, owner: u32) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mut below: Vec<&Path> = Vec::new();
    for a in p.ancestors() {
        let Ok(m) = std::fs::symlink_metadata(a) else {
            return false;
        };
        if !below.is_empty() && m.is_dir() && m.permissions().mode() & 0o1002 == 0o1002 {
            return below
                .iter()
                .any(|d| std::fs::symlink_metadata(d).map_or(true, |m| m.uid() != owner));
        }
        below.push(a);
    }
    false
}
#[cfg(not(unix))]
fn under_shared_sticky_dir(_p: &Path, _owner: u32) -> bool {
    false
}

/// `dir`'s child directories with both encodings of each name, sorted by name, at most
/// [`DECODE_ENTRIES_PER_DIR`]. A symbolic link is never followed while decoding: a link
/// planted under a decoded prefix would otherwise make any name decode to its target.
fn list_child_dirs(dir: &Path) -> Vec<DecodeEntry> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<DecodeEntry> = rd
        .flatten()
        .take(DECODE_ENTRIES_PER_DIR)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| {
            let name = PathBuf::from(e.file_name());
            (e.path(), encode_project_path(&name), encode_project_path_legacy(&name))
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// `<home>/.claude.json`'s `projects` keys, read without telemetry (see
/// [`recover_projects`]), bounded like every config read.
fn registry_projects(home: &Path) -> Vec<PathBuf> {
    use std::io::Read;
    let path = home.join(".claude.json");
    let Ok(meta) = std::fs::metadata(&path) else {
        return Vec::new();
    };
    if !meta.is_file() || meta.len() > crate::scanners::MAX_CONFIG_SIZE {
        return Vec::new();
    }
    let mut buf = String::new();
    if std::fs::File::open(&path)
        .and_then(|f| f.take(crate::scanners::MAX_CONFIG_SIZE).read_to_string(&mut buf))
        .is_err()
    {
        return Vec::new();
    }
    serde_json::from_str::<serde_json::Value>(&buf)
        .ok()
        .and_then(|v| {
            v.get("projects")?
                .as_object()
                .map(|o| o.keys().map(PathBuf::from).collect())
        })
        .unwrap_or_default()
}

fn canon_or_lexical(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| crate::scanners::persistence::lexical_join(Path::new("/"), p))
}

fn home_entry(home: &Path) -> (PathBuf, PathBuf) {
    (home.to_path_buf(), canon_or_lexical(home))
}

/// `(nodename, release)` from `uname(2)`: the hostname and kernel version with no
/// process spawned, so no `hostname` or `uname` on PATH is ever run (it used to be, by
/// name). `nodename` is what `hostname` and `gethostname(2)` print.
#[cfg(unix)]
pub(crate) fn uname() -> Option<(String, String)> {
    let mut u = std::mem::MaybeUninit::<libc::utsname>::zeroed();
    // SAFETY: uname writes into the struct it is given; an all-zero utsname is valid.
    if unsafe { libc::uname(u.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: uname succeeded, so the struct is initialised (and was zeroed before).
    let u = unsafe { u.assume_init() };
    let field = |f: &[libc::c_char]| {
        let bytes: Vec<u8> = f.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
        String::from_utf8_lossy(&bytes).trim().to_string()
    };
    Some((field(&u.nodename), field(&u.release)))
}

/// IDE identifiers used across the platform layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ide {
    VsCode,
    Cursor,
    Windsurf,
    Zed,
    Antigravity,
}

impl Ide {
    pub const ALL: &[Ide] = &[Ide::VsCode, Ide::Cursor, Ide::Windsurf, Ide::Zed, Ide::Antigravity];

    pub fn name(self) -> &'static str {
        match self {
            Ide::VsCode => "Visual Studio Code",
            Ide::Cursor => "Cursor",
            Ide::Windsurf => "Windsurf",
            Ide::Zed => "Zed",
            Ide::Antigravity => "Antigravity",
        }
    }

    pub fn vendor(self) -> &'static str {
        match self {
            Ide::VsCode => "Microsoft",
            Ide::Cursor => "Anysphere",
            Ide::Windsurf => "Codeium",
            Ide::Zed => "Zed Industries",
            Ide::Antigravity => "Antigravity",
        }
    }
}

/// Platform-specific path and device info resolution.
#[allow(dead_code)]
///
/// `Send + Sync`: a phase's scanners run side by side on worker threads (`--jobs`) and
/// share one platform value.
pub trait PlatformInfo: Send + Sync {
    fn device_info(&self) -> DeviceInfo;
    fn home_dir(&self) -> PathBuf;
    /// This pass's working-directory project and the scan's homes: see [`PassScope`].
    fn pass_scope(&self) -> &PassScope;

    // IDE install locations
    fn ide_install_path(&self, ide: Ide) -> Option<PathBuf>;
    fn ide_extension_dir(&self, ide: Ide) -> Option<PathBuf>;

    // MCP config paths for each vendor
    fn mcp_config_paths(&self) -> Vec<(String, PathBuf, String)>;

    // AI desktop app paths
    fn ai_desktop_app_paths(&self) -> Vec<(String, String, PathBuf)>;

    // AI CLI config directories
    fn claude_config_dir(&self) -> PathBuf;
    /// Claude Code managed (organization) settings directory: `managed-settings.json`
    /// and `managed-settings.d/`. A system path, the same for every home.
    fn managed_settings_dir(&self) -> PathBuf;
    fn gemini_config_dir(&self) -> PathBuf;
    fn aws_q_config_dir(&self) -> PathBuf;
    fn codex_config_dir(&self) -> PathBuf;
    fn kiro_config_dir(&self) -> PathBuf;
    fn aish_config_dir(&self) -> PathBuf;
    fn opencode_config_dir(&self) -> PathBuf;
    fn github_copilot_config_dir(&self) -> PathBuf;
    fn aider_config_dir(&self) -> PathBuf;
    fn open_interpreter_config_dir(&self) -> PathBuf;

    /// Claude Desktop application path (for Cowork feature detection)
    fn claude_desktop_app(&self) -> Option<PathBuf>;

    // Shell config files
    fn shell_config_paths(&self) -> Vec<(String, PathBuf)>;

    // SSH directory
    fn ssh_dir(&self) -> PathBuf;

    // Cloud credential paths
    fn aws_credentials_path(&self) -> PathBuf;
    fn gcloud_config_dir(&self) -> PathBuf;
    fn azure_config_dir(&self) -> PathBuf;
}

/// Get the platform implementation for the current OS.
pub fn current_platform() -> Box<dyn PlatformInfo> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsPlatform::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxPlatform::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        compile_error!("Only macOS and Linux are supported");
    }
}

/// Get the platform implementation rooted at a specific home directory, as an extra
/// (`--search-dirs`) pass visiting no other home: the working directory is not a project.
pub fn platform_for_home(home: PathBuf) -> Box<dyn PlatformInfo> {
    let scope = PassScope::search_dir(&home, &[]);
    platform_with_scope(home, scope)
}

/// The primary pass of a scan that also visits `search_dirs`: the user's HOME, with the
/// working directory as a project, and every `--search-dirs` home kept out of its project
/// walks.
pub fn primary_platform(search_dirs: &[PathBuf]) -> Box<dyn PlatformInfo> {
    let plat = current_platform();
    let home = plat.home_dir();
    let scope = plat.pass_scope().clone().with_scan_homes(search_dirs);
    platform_with_scope(home, scope)
}

/// The extra pass for `home` (a `--search-dirs` entry) of the scan whose primary pass is
/// `primary`: no working directory, and every home of the scan kept out of its project
/// walks.
pub fn search_dir_platform(home: PathBuf, primary: &dyn PlatformInfo) -> Box<dyn PlatformInfo> {
    let others: Vec<PathBuf> = primary.pass_scope().scan_homes().map(Path::to_path_buf).collect();
    let scope = PassScope::search_dir(&home, &others);
    platform_with_scope(home, scope)
}

fn platform_with_scope(home: PathBuf, scope: PassScope) -> Box<dyn PlatformInfo> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOsPlatform::with_scope(home, scope))
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxPlatform::with_scope(home, scope))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (home, scope);
        compile_error!("Only macOS and Linux are supported");
    }
}
