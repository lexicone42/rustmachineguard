use crate::models::AgentTranscriptStore;
use crate::platform::PlatformInfo;
use crate::scanners::{file_perms, Scanner};
use std::path::Path;

/// Inventories agent transcript / conversation-state stores — the EAA-005 collection
/// surface. These hold the full conversation history (code, prompts, and any secrets
/// discussed), so a world-readable store is a real exposure. Records existence, file
/// count, size, and permissions ONLY — it never reads transcript content.
pub struct TranscriptsScanner;

/// Cap the recursive walk so a pathological tree can't hang the scan.
const MAX_WALK_FILES: usize = 20_000;

impl Scanner for TranscriptsScanner {
    type Output = Vec<AgentTranscriptStore>;

    fn scan(&self, platform: &dyn PlatformInfo) -> Vec<AgentTranscriptStore> {
        let claude = platform.claude_config_dir();
        let codex = platform.codex_config_dir();
        let gemini = platform.gemini_config_dir();

        // (framework, path, kind)
        let stores: Vec<(&str, std::path::PathBuf, &str)> = vec![
            ("claude-code", claude.join("projects"), "conversation transcripts"),
            ("claude-code", claude.join("history.jsonl"), "command history"),
            ("claude-code", claude.join("todos"), "todo state"),
            ("codex", codex.join("sessions"), "sessions"),
            ("codex", codex.join("history.jsonl"), "command history"),
            ("gemini-cli", gemini.join("tmp"), "session state"),
        ];

        let mut out = Vec::new();
        for (framework, path, kind) in stores {
            if let Some(store) = inspect_store(framework, &path, kind) {
                out.push(store);
            }
        }
        out
    }
}

fn inspect_store(framework: &str, path: &Path, kind: &str) -> Option<AgentTranscriptStore> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let (file_count, total_size_bytes) = if meta.is_dir() {
        walk_counts(path)
    } else if meta.is_file() {
        (1, meta.len())
    } else {
        return None; // symlink / device / socket — skip
    };
    if file_count == 0 {
        return None; // empty dir — nothing collected here
    }
    let world_readable = file_perms(path).map(|(_, w, _)| w).unwrap_or(false);
    Some(AgentTranscriptStore {
        framework: framework.to_string(),
        path: path.display().to_string(),
        kind: kind.to_string(),
        file_count,
        total_size_bytes,
        world_readable,
    })
}

/// Count regular files and total bytes under `dir`, bounded to MAX_WALK_FILES.
fn walk_counts(dir: &Path) -> (usize, u64) {
    let mut count = 0usize;
    let mut bytes = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            if count >= MAX_WALK_FILES {
                return (count, bytes);
            }
            // symlink_metadata so we don't follow symlinks out of the tree.
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            let ft = meta.file_type();
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file() {
                count += 1;
                bytes += meta.len();
            }
        }
    }
    (count, bytes)
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

    #[test]
    fn walk_counts_sums_files_and_bytes_recursively() {
        let d = TmpDir::new("walk-recursive");
        fs::write(d.path().join("a.jsonl"), b"hello").unwrap(); // 5 bytes
        let sub = d.path().join("proj");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("b.jsonl"), b"world!").unwrap(); // 6 bytes
        fs::write(sub.join("c.jsonl"), b"xyz").unwrap(); // 3 bytes
        let (count, bytes) = walk_counts(d.path());
        assert_eq!(count, 3);
        assert_eq!(bytes, 14);
    }

    #[test]
    fn inspect_store_reports_a_populated_dir() {
        let d = TmpDir::new("inspect-dir");
        fs::write(d.path().join("t.jsonl"), b"abcd").unwrap();
        let store = inspect_store("claude-code", d.path(), "conversation transcripts")
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
        assert!(inspect_store("codex", d.path(), "sessions").is_none());
        // Missing path.
        let missing = d.path().join("does-not-exist");
        assert!(inspect_store("codex", &missing, "sessions").is_none());
    }

    #[test]
    fn inspect_store_reports_a_single_file() {
        let d = TmpDir::new("inspect-file");
        let f = d.path().join("history.jsonl");
        fs::write(&f, b"one\ntwo\n").unwrap(); // 8 bytes
        let store = inspect_store("codex", &f, "command history")
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
        let store = inspect_store("claude-code", d.path(), "conversation transcripts").unwrap();
        assert!(store.world_readable);

        // And private (0700) is not flagged.
        let d2 = TmpDir::new("inspect-private");
        fs::write(d2.path().join("t.jsonl"), b"secret transcript").unwrap();
        fs::set_permissions(d2.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store2 = inspect_store("claude-code", d2.path(), "conversation transcripts").unwrap();
        assert!(!store2.world_readable);
    }
}
