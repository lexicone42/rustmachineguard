#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use crate::models::DeviceInfo;
use std::path::{Path, PathBuf};

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
}

impl PassScope {
    /// The primary pass for `home`: the current working directory is a project.
    pub fn primary(home: &Path) -> Self {
        Self {
            cwd_project: std::env::current_dir().ok(),
            scan_homes: vec![home_entry(home)],
        }
    }

    /// An extra (`--search-dirs`) pass for `home`, in a scan that also visits `others`
    /// (the primary home and the other extra homes): no working directory.
    pub fn search_dir(home: &Path, others: &[PathBuf]) -> Self {
        Self {
            cwd_project: None,
            scan_homes: vec![home_entry(home)],
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

    /// `registered` (a home's registered projects) plus the working directory when this
    /// is the primary pass. Every scanner's project list is built here.
    pub fn with_cwd(&self, mut registered: Vec<PathBuf>) -> Vec<PathBuf> {
        if let Some(cwd) = &self.cwd_project {
            registered.push(cwd.clone());
        }
        registered
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

    /// `dirs` without any scan home or ancestor of one ([`Self::is_scan_home_or_ancestor`]).
    pub fn excluding_scan_homes(&self, dirs: Vec<PathBuf>) -> Vec<PathBuf> {
        dirs.into_iter().filter(|d| !self.is_scan_home_or_ancestor(d)).collect()
    }
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
