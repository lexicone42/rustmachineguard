use crate::models::AgentTranscriptStore;
use crate::otel::{Attr, Key};
use crate::platform::PlatformInfo;
use crate::scanners::{Scanner, file_perms};
use std::path::Path;

/// Inventories agent transcript / conversation-state stores — the EAA-005 collection
/// surface. These hold the full conversation history (code, prompts, and any secrets
/// discussed), so a world-readable store is a real exposure. Records existence, file
/// count, size, and permissions ONLY — it never reads transcript content.
pub struct TranscriptsScanner;

/// Cap the recursive walk so a pathological tree can't hang the scan: files counted per
/// store at `--walk-budget` [`BASE_WALK_BUDGET`](crate::scanners::telemetry::BASE_WALK_BUDGET),
/// scaled to the scan's budget ([`max_walk_files`]): 125,000 at the default.
const BASE_WALK_FILES: usize = 20_000;

/// Files one store's count may take at the scan's `--walk-budget`.
fn max_walk_files() -> usize {
    crate::scanners::telemetry::walk_cap(BASE_WALK_FILES, crate::scanners::telemetry::walk_budget())
}

impl Scanner for TranscriptsScanner {
    type Output = Vec<AgentTranscriptStore>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<AgentTranscriptStore> {
        let claude = platform.claude_config_dir();
        let codex = platform.codex_config_dir();
        let gemini = platform.gemini_config_dir();
        let home = platform.home_dir();

        // (framework, path, kind): a closed list. Every directory directly under
        // ~/.claude that holds session-derived state is one store; plugins/ (code, not
        // state) is not. ~/.claude.json and its backup are the account state files.
        let mut stores: Vec<(&str, std::path::PathBuf, &str)> = vec![
            ("claude-code", claude.join("projects"), "conversation transcripts"),
            ("claude-code", claude.join("history.jsonl"), "command history"),
            ("claude-code", claude.join("todos"), "todo state"),
        ];
        for (dir, kind) in CLAUDE_STATE_DIRS {
            stores.push(("claude-code", claude.join(dir), kind));
        }
        stores.extend([
            ("claude-code", home.join(".claude.json"), ACCOUNT_STATE),
            ("claude-code", home.join(".claude.json.backup"), ACCOUNT_STATE_BACKUP),
            ("codex", codex.join("sessions"), "sessions"),
            ("codex", codex.join("history.jsonl"), "command history"),
            ("gemini-cli", gemini.join("tmp"), "session state"),
        ]);

        let mut out = Vec::new();
        for (framework, path, kind) in stores {
            // Closed values only: the framework and kind are the literals above; the
            // path is never exported.
            let mut span = crate::otel::span("transcripts.store", || {
                vec![
                    Attr::str(Key::TranscriptsFramework, framework),
                    Attr::str(Key::TranscriptsKind, kind),
                ]
            });
            let mut walk = Walk::default();
            if let Some(store) = inspect_store(framework, &path, kind, &mut walk) {
                out.push(store);
            }
            span.set(|| {
                vec![
                    Attr::int(Key::WalkEntries, walk.entries as i64),
                    Attr::int(Key::WalkFiles, walk.files as i64),
                    Attr::int(Key::WalkBytes, walk.bytes as i64),
                ]
            });
        }
        out
    }
}

/// `~/.claude/<dir>` stores beyond projects, history and todos, with their kind. Closed.
const CLAUDE_STATE_DIRS: &[(&str, &str)] = &[
    ("shell-snapshots", "shell snapshots"),
    ("session-env", "session environment"),
    ("tasks", "task lists"),
    ("plans", "plan files"),
    ("backups", "settings backups"),
    ("telemetry", "telemetry queue"),
    ("security", "security plugin state"),
    ("exo-self", "exo-self plugin state"),
    ("statsig", "feature-flag cache"),
    ("paste-cache", "paste cache"),
    ("usage-data", "usage data"),
    ("agent-memory", "agent memory"),
    ("file-history", "file edit history"),
];

/// `kind` of `~/.claude.json` and of `~/.claude.json.backup`.
pub const ACCOUNT_STATE: &str = "account state file";
pub const ACCOUNT_STATE_BACKUP: &str = "account state backup";

/// What a store readable by other users exposes, and whether it holds session content
/// (High) rather than metadata (Medium). Fixed words per kind.
pub fn store_exposure(kind: &str) -> (&'static str, bool) {
    match kind {
        "conversation transcripts" | "command history" | "sessions" | "session state" => {
            ("conversation history exposed", true)
        }
        "todo state" | "task lists" | "plan files" => ("session work items exposed", true),
        "shell snapshots" => ("may contain exported environment variables", true),
        "session environment" => ("may contain environment variables set for sessions", true),
        "settings backups" => ("copies of ~/.claude.json with account id and project paths", true),
        "paste cache" => ("pasted content exposed", true),
        "agent memory" | "exo-self plugin state" => ("agent memory and journal text exposed", true),
        "file edit history" => ("copies of files the agent edited exposed", true),
        ACCOUNT_STATE | ACCOUNT_STATE_BACKUP => ("account identifier and project list", true),
        "security plugin state" => ("plugin logs and state exposed", false),
        "telemetry queue" => ("queued telemetry events exposed", false),
        "feature-flag cache" => ("feature-flag evaluations exposed", false),
        _ => ("usage metadata exposed", false),
    }
}

/// The nearest ancestor of `path` other users cannot traverse (no o+x), as
/// `"/home/u is 0700"`. Mode bits only.
#[cfg(unix)]
pub fn untraversable_ancestor(path: &Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    path.ancestors().skip(1).find_map(|a| {
        let mode = std::fs::metadata(a).ok()?.permissions().mode() & 0o777;
        (mode & 0o001 == 0).then(|| format!("{} is {mode:04o}", a.display()))
    })
}
#[cfg(not(unix))]
pub fn untraversable_ancestor(_path: &Path) -> Option<String> {
    None
}

#[cfg(unix)]
fn other_bits(meta: &std::fs::Metadata) -> (bool, bool) {
    use std::os::unix::fs::PermissionsExt;
    let m = meta.permissions().mode();
    (m & 0o004 != 0, m & 0o001 != 0)
}
#[cfg(not(unix))]
fn other_bits(_meta: &std::fs::Metadata) -> (bool, bool) {
    (false, false)
}

/// What inspecting one store walked: directory entries seen, regular files counted and
/// their summed size (the numbers the report carries; nothing is opened).
#[derive(Default)]
struct Walk {
    entries: u64,
    files: u64,
    bytes: u64,
}

fn inspect_store(framework: &str, path: &Path, kind: &str, walk: &mut Walk) -> Option<AgentTranscriptStore> {
    if !crate::scanners::probe_exists(path) {
        return None;
    }
    let meta = std::fs::symlink_metadata(path).ok()?;
    let (file_count, total_size_bytes, readable) = if meta.is_dir() {
        let (c, b, r) = walk_counts_readable(path, &mut walk.entries, other_bits(&meta).1);
        (c, b, r)
    } else if meta.is_file() {
        (1, meta.len(), usize::from(other_bits(&meta).0))
    } else {
        return None; // symlink / device / socket — skip
    };
    walk.files = file_count as u64;
    walk.bytes = total_size_bytes;
    if file_count == 0 {
        return None; // empty dir — nothing collected here
    }
    let perms = file_perms(path);
    let world_readable = perms.as_ref().map(|(_, w, _)| *w).unwrap_or(false);
    Some(AgentTranscriptStore {
        framework: framework.to_string(),
        path: path.display().to_string(),
        kind: kind.to_string(),
        file_count,
        total_size_bytes,
        world_readable,
        readable_files: Some(readable),
        group_readable: perms.as_ref().map(|(_, _, g)| *g).unwrap_or(false),
        mode: perms.map(|(m, _, _)| m),
        unreachable_via: untraversable_ancestor(path),
    })
}

/// Count regular files and total bytes under `dir`, bounded to [`max_walk_files`].
/// `entries` is incremented once per directory entry visited.
#[cfg(test)]
fn walk_counts(dir: &Path, entries_seen: &mut u64) -> (usize, u64) {
    let (c, b, _) = walk_counts_readable(dir, entries_seen, true);
    (c, b)
}

/// [`walk_counts`] plus the files other users can read: o+r on the file, and o+x on
/// every directory from `dir` (`root_traversable`) down to it. Mode bits only.
fn walk_counts_readable(dir: &Path, entries_seen: &mut u64, root_traversable: bool) -> (usize, u64, usize) {
    let mut count = 0usize;
    let mut bytes = 0u64;
    let mut readable = 0usize;
    let max_files = max_walk_files();
    let mut stack = vec![(dir.to_path_buf(), root_traversable)];
    while let Some((d, reachable)) = stack.pop() {
        let Ok(entries) = crate::scanners::probe_read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            if count >= max_files {
                return (count, bytes, readable);
            }
            *entries_seen += 1;
            // symlink_metadata so we don't follow symlinks out of the tree.
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            let ft = meta.file_type();
            let (o_read, o_exec) = other_bits(&meta);
            if ft.is_dir() {
                stack.push((entry.path(), reachable && o_exec));
            } else if ft.is_file() {
                count += 1;
                bytes += meta.len();
                if reachable && o_read {
                    readable += 1;
                }
            }
        }
    }
    (count, bytes, readable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A throwaway directory under the system temp dir, removed on drop. Named by the
    /// caller so parallel tests don't collide.
    struct TmpDir(std::path::PathBuf);
    impl TmpDir {
        fn new(name: &str) -> Self {
            let p = std::env::temp_dir().join(format!("rmguard-transcripts-{name}"));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            TmpDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// The file cap scales with `--walk-budget`: 20,000 at the old 4,000-directory
    /// budget, 125,000 at the default.
    #[test]
    fn walk_file_cap_scales_with_the_walk_budget() {
        use crate::scanners::telemetry::{BASE_WALK_BUDGET, DEFAULT_WALK_BUDGET, walk_cap};
        assert_eq!(walk_cap(BASE_WALK_FILES, BASE_WALK_BUDGET), 20_000);
        assert_eq!(max_walk_files(), 125_000);
        assert_eq!(walk_cap(BASE_WALK_FILES, DEFAULT_WALK_BUDGET), 125_000);
        assert_eq!(walk_cap(BASE_WALK_FILES, 1), 5, "rounded down, never 0");
        assert_eq!(walk_cap(1, 1), 1, "at least 1");
        assert_eq!(walk_cap(BASE_WALK_FILES, usize::MAX), usize::MAX, "saturates");
    }

    #[test]
    fn walk_counts_sums_files_and_bytes_recursively() {
        let d = TmpDir::new("walk-recursive");
        fs::write(d.path().join("a.jsonl"), b"hello").unwrap(); // 5 bytes
        let sub = d.path().join("proj");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("b.jsonl"), b"world!").unwrap(); // 6 bytes
        fs::write(sub.join("c.jsonl"), b"xyz").unwrap(); // 3 bytes
        let mut seen = 0;
        let (count, bytes) = walk_counts(d.path(), &mut seen);
        assert_eq!(seen, 4, "three files and one directory");
        assert_eq!(count, 3);
        assert_eq!(bytes, 14);
    }

    #[test]
    fn inspect_store_reports_a_populated_dir() {
        let d = TmpDir::new("inspect-dir");
        fs::write(d.path().join("t.jsonl"), b"abcd").unwrap();
        let store = inspect_store(
            "claude-code",
            d.path(),
            "conversation transcripts",
            &mut Walk::default(),
        )
        .expect("populated dir should yield a store");
        assert_eq!(store.framework, "claude-code");
        assert_eq!(store.kind, "conversation transcripts");
        assert_eq!(store.file_count, 1);
        assert_eq!(store.total_size_bytes, 4);
    }

    #[test]
    fn inspect_store_skips_empty_and_missing() {
        let d = TmpDir::new("inspect-empty");
        // Empty directory: nothing collected here.
        assert!(inspect_store("codex", d.path(), "sessions", &mut Walk::default()).is_none());
        // Missing path.
        let missing = d.path().join("does-not-exist");
        assert!(inspect_store("codex", &missing, "sessions", &mut Walk::default()).is_none());
    }

    #[test]
    fn inspect_store_reports_a_single_file() {
        let d = TmpDir::new("inspect-file");
        let f = d.path().join("history.jsonl");
        fs::write(&f, b"one\ntwo\n").unwrap(); // 8 bytes
        let store = inspect_store("codex", &f, "command history", &mut Walk::default())
            .expect("a non-empty file should yield a store");
        assert_eq!(store.file_count, 1);
        assert_eq!(store.total_size_bytes, 8);
    }

    #[cfg(unix)]
    #[test]
    fn inspect_store_flags_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let d = TmpDir::new("inspect-worldreadable");
        fs::write(d.path().join("t.jsonl"), b"secret transcript").unwrap();
        // Make the store dir world-readable.
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let store = inspect_store(
            "claude-code",
            d.path(),
            "conversation transcripts",
            &mut Walk::default(),
        )
        .unwrap();
        assert!(store.world_readable);

        // And private (0700) is not flagged.
        let d2 = TmpDir::new("inspect-private");
        fs::write(d2.path().join("t.jsonl"), b"secret transcript").unwrap();
        fs::set_permissions(d2.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store2 = inspect_store(
            "claude-code",
            d2.path(),
            "conversation transcripts",
            &mut Walk::default(),
        )
        .unwrap();
        assert!(!store2.world_readable);
    }

    /// Readable means o+r on the file and o+x on every directory down to it; a 0700
    /// ancestor makes the store unreachable whatever its own mode.
    #[cfg(unix)]
    #[test]
    fn readable_files_follow_file_and_directory_modes() {
        use std::os::unix::fs::PermissionsExt;
        let set = |p: &Path, m: u32| fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
        let d = TmpDir::new("readable-modes");
        let store = d.path().join("home/.claude/session-env");
        fs::create_dir_all(store.join("open")).unwrap();
        fs::create_dir_all(store.join("closed")).unwrap();
        for (rel, mode) in [
            ("a.sh", 0o644),
            ("b.sh", 0o600),
            ("open/c.sh", 0o644),
            ("closed/d.sh", 0o644),
        ] {
            fs::write(store.join(rel), b"x").unwrap();
            set(&store.join(rel), mode);
        }
        set(&store.join("closed"), 0o700);
        for p in [
            d.path().to_path_buf(),
            d.path().join("home"),
            d.path().join("home/.claude"),
            store.clone(),
        ] {
            set(&p, 0o755);
        }
        let s = inspect_store("claude-code", &store, "session environment", &mut Walk::default()).unwrap();
        assert_eq!(s.file_count, 4);
        assert_eq!(s.readable_files, Some(2), "a.sh and open/c.sh");
        assert_eq!(s.mode.as_deref(), Some("0755"));
        assert!(s.unreachable_via.is_none());
        set(&d.path().join("home"), 0o700);
        let s = inspect_store("claude-code", &store, "session environment", &mut Walk::default()).unwrap();
        let via = s.unreachable_via.unwrap();
        assert!(via.ends_with("/home is 0700"), "{via}");
        set(&d.path().join("home"), 0o755);
        set(&store.join("closed"), 0o755);
    }
}
