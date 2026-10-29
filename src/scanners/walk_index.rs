//! One pass's shared index of directory listings (perf 6d): the gitconfig nested-repo walk
//! and the rules nested-instruction-file walk list mostly the same project trees (on one
//! machine 14,465 shared directories and 1.46M of the rules walk's 1.52M entries, most of
//! them in 60 flat image-tile directories cut at 20,000 entries each). Whichever walk
//! reaches a directory first lists it and leaves the listing here; the other takes it
//! instead of listing the directory again.
//!
//! What it does NOT change: each walk keeps its own breadth-first order, budgets, caps,
//! prune and descent rules, and charges its budget for a directory whether its listing
//! came from here or from the file system; a [`Listing`] holds exactly what one read of
//! the directory returned, so each consumer derives from it what its own read would have
//! kept. Read errors are never stored (each consumer reads, and notes, its own), nor is a
//! listing cut short by a cancelled walk.
//!
//! Keys are the directory paths AS THE WALKS SPELL THEM (lexical), not canonical paths:
//! both walks build every path as `root.join(name)` from directory entries that are real
//! directories (neither descends through a symlink), so two walks asking for the same
//! spelling ask the kernel for the same directory, and a cached listing is the one a fresh
//! `read_dir` of that spelling would return at that moment. Canonicalising would cost a
//! `realpath` (an `lstat` per component) per directory, more than the listing saved, and
//! would add symlink resolution to walks whose rule is never to follow one. The cost of
//! lexical keys: a project reached through two spellings (a symlinked project root) is
//! listed once per spelling, as before.
//!
//! Memory: a listing keeps only what a consumer looks at (the name and type of every
//! subdirectory, and of the few file names someone checks, [`KEPT_NAMES`]), not one entry
//! per tile. A listing is dropped as soon as every other consumer has taken it or will
//! not (it is not under any of that consumer's roots, below its depth limit, under a name
//! it prunes, or that consumer finished the root), and nothing is stored past
//! [`MAX_CACHED_BYTES`] (listings are then read fresh, as without the index).

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

/// Entries one listing reads: the largest per-directory cap of any consumer (both are
/// 20,000 today). A consumer with a smaller cap sees only the entries its own read would
/// have ([`Listing::capped`]).
pub(crate) const MAX_ENTRIES: usize = 20_000;

/// Non-directory names some consumer looks at: the gitconfig walk's git-dir test (`HEAD`,
/// `config`, and `objects`/`refs`, which may be symlinks to directories), both walks'
/// generated-tree markers, and the rules walk's instruction files. Every other file is
/// only counted.
pub(crate) const KEPT_NAMES: &[&str] = &[
    "HEAD",
    "config",
    "objects",
    "refs",
    "CACHEDIR.TAG",
    "pyvenv.cfg",
    "CLAUDE.md",
    "CLAUDE.local.md",
    "AGENTS.md",
    "GEMINI.md",
];

/// Bytes of listings held at once (names plus bookkeeping). Past it a listing is handed
/// to the walk that read it and not kept.
pub(crate) const MAX_CACHED_BYTES: usize = 8 << 20;

/// An entry's type as the listing reports it (`lstat`: a symlink is a symlink).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Dir,
    File,
    Symlink,
}

/// One entry a consumer may look at.
#[derive(Debug)]
pub(crate) struct Kept<'a> {
    pub(crate) kind: Kind,
    pub(crate) name: &'a OsStr,
}

/// A kept entry as stored: its position in the listing (0-based, for a consumer with a
/// smaller cap), type, and where its name ends in [`Listing::names`].
#[derive(Debug)]
struct Packed {
    pos: u32,
    end: u32,
    kind: Kind,
}

/// One directory read: entries counted, and the ones a consumer may look at in listing
/// order. Names are packed in one buffer (two allocations a listing, sized exactly).
#[derive(Debug)]
pub(crate) struct Listing {
    /// Entries read: at most [`MAX_ENTRIES`].
    entries: usize,
    /// There was an entry past [`MAX_ENTRIES`].
    cut: bool,
    /// Every directory, and every regular file or symlink named in [`KEPT_NAMES`].
    kept: Box<[Packed]>,
    names: Box<[u8]>,
}

impl Listing {
    /// The listing as a read of at most `cap` (<= [`MAX_ENTRIES`]) entries saw it:
    /// entries read, whether it stopped at `cap` with more left, and the kept entries
    /// among the first `cap`.
    pub(crate) fn capped(&self, cap: usize) -> (usize, bool, impl Iterator<Item = Kept<'_>>) {
        use std::os::unix::ffi::OsStrExt;
        debug_assert!(cap <= MAX_ENTRIES);
        let cut = self.entries > cap || self.cut;
        let mut start = 0usize;
        let kept = self
            .kept
            .iter()
            .take_while(move |k| (k.pos as usize) < cap)
            .map(move |k| {
                let name = OsStr::from_bytes(&self.names[start..k.end as usize]);
                start = k.end as usize;
                Kept { kind: k.kind, name }
            });
        (self.entries.min(cap), cut, kept)
    }

    /// What holding it costs, roughly: the listing, its two buffers, its key and the
    /// map's slot.
    fn bytes(&self, key: &Path) -> usize {
        std::mem::size_of::<Self>()
            + 96
            + key.as_os_str().len()
            + self.names.len()
            + self.kept.len() * std::mem::size_of::<Packed>()
    }
}

/// Read `dir` once. `Ok(None)`: `cancel` was set part-way (the walk that asked returned).
fn read(dir: &Path, cancel: &AtomicBool) -> std::io::Result<Option<Listing>> {
    use std::os::unix::ffi::OsStrExt;
    let rd = std::fs::read_dir(dir)?;
    let (mut entries, mut cut) = (0usize, false);
    let mut kept = Vec::new();
    let mut names = Vec::new();
    for (n, e) in rd.flatten().enumerate() {
        if n == MAX_ENTRIES {
            cut = true;
            break;
        }
        // A walk that stopped no longer wants this listing: give up early.
        if n % 1024 == 1023 && cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        entries += 1;
        let Ok(ft) = e.file_type() else {
            continue;
        };
        let kind = if ft.is_dir() {
            Kind::Dir
        } else if ft.is_file() {
            Kind::File
        } else if ft.is_symlink() {
            Kind::Symlink
        } else {
            continue;
        };
        let name = e.file_name();
        if kind == Kind::Dir || KEPT_NAMES.iter().any(|k| name == *k) {
            names.extend_from_slice(name.as_bytes());
            kept.push(Packed {
                pos: n as u32,
                end: names.len() as u32,
                kind,
            });
        }
    }
    Ok(Some(Listing {
        entries,
        cut,
        kept: kept.into_boxed_slice(),
        names: names.into_boxed_slice(),
    }))
}

/// The walks sharing the index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Consumer {
    GitConfig = 0,
    Rules = 1,
}

const CONSUMERS: usize = 2;

impl Consumer {
    fn bit(self) -> u8 {
        1 << self as u8
    }
}

/// Which directories under one of a consumer's roots it may list: none below
/// `max_depth` levels, none under a name it prunes. Used only to drop listings early:
/// a directory it says yes to may still never be asked for (budget, a marker), and is
/// dropped when the consumer finishes the root.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RootRule {
    pub(crate) max_depth: Option<usize>,
    /// `.git` is pruned.
    pub(crate) skip_git: bool,
    /// Every dot-directory is pruned (the rules walk of a home).
    pub(crate) skip_dot: bool,
    /// Names that are not UTF-8 are pruned (the rules walk).
    pub(crate) utf8_only: bool,
}

impl RootRule {
    fn wants(&self, rel: &Path) -> bool {
        rel.components().enumerate().all(|(i, c)| match c {
            Component::Normal(name) => self.max_depth.is_none_or(|m| i < m) && self.name_ok(name),
            _ => false,
        })
    }

    fn name_ok(&self, name: &OsStr) -> bool {
        if crate::scanners::git_config::PRUNE_BY_NAME.iter().any(|p| name == *p) {
            return false;
        }
        if self.skip_git && name == ".git" {
            return false;
        }
        match name.to_str() {
            None => !self.utf8_only,
            Some(s) => !(self.skip_dot && s.starts_with('.')),
        }
    }
}

#[derive(Debug)]
enum Registration {
    /// Not registered yet (its scanner has not reached its walk, or does not run): any
    /// directory may be wanted.
    Unknown,
    Walking {
        roots: HashMap<PathBuf, RootRule>,
        finished: HashSet<PathBuf>,
    },
    /// Its walks are over: it wants nothing.
    Done,
}

impl Registration {
    /// Whether this consumer may still ask for `dir`: under its nearest root (another
    /// root inside a root is walked on its own and pruned from the outer walk), allowed
    /// there, and that root not finished.
    fn wants(&self, dir: &Path) -> bool {
        match self {
            Registration::Unknown => true,
            Registration::Done => false,
            Registration::Walking { roots, finished } => dir
                .ancestors()
                .find_map(|a| roots.get_key_value(a))
                .is_some_and(|(root, rule)| {
                    !finished.contains(root) && rule.wants(dir.strip_prefix(root).unwrap_or(dir))
                }),
        }
    }
}

#[derive(Debug)]
enum Slot {
    /// Being read by one consumer; others asking wait for it.
    Filling,
    Ready {
        listing: Arc<Listing>,
        /// Consumers that may still ask for it.
        pending: u8,
        bytes: usize,
    },
}

#[derive(Debug)]
struct State {
    slots: HashMap<PathBuf, Slot>,
    regs: [Registration; CONSUMERS],
    bytes: usize,
    peak_bytes: usize,
}

/// See the module documentation. One per home pass ([`crate::platform::PassScope`]).
#[derive(Debug)]
pub struct WalkIndex {
    state: Mutex<State>,
    cv: Condvar,
    /// False: every listing is read fresh and nothing is kept (tests compare against it).
    enabled: bool,
    hits: AtomicU64,
}

/// Where a consumer's listing came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Got {
    /// Left by the other walk.
    Hit,
    /// Read now.
    Miss,
}

impl Default for WalkIndex {
    fn default() -> Self {
        Self::with(true)
    }
}

impl WalkIndex {
    fn with(enabled: bool) -> Self {
        WalkIndex {
            state: Mutex::new(State {
                slots: HashMap::new(),
                regs: [Registration::Unknown, Registration::Unknown],
                bytes: 0,
                peak_bytes: 0,
            }),
            cv: Condvar::new(),
            enabled,
            hits: AtomicU64::new(0),
        }
    }

    /// An index that keeps nothing: every walk reads every listing itself, as before 6d.
    pub fn disabled() -> Self {
        Self::with(false)
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `consumer` is about to walk `roots`: listings it will never ask for are dropped
    /// (the ones kept while it was [`Registration::Unknown`]).
    pub(crate) fn register(&self, consumer: Consumer, roots: impl IntoIterator<Item = (PathBuf, RootRule)>) {
        let mut st = self.lock();
        st.regs[consumer as usize] = Registration::Walking {
            roots: roots.into_iter().collect(),
            finished: HashSet::new(),
        };
        let State { slots, regs, bytes, .. } = &mut *st;
        let reg = &regs[consumer as usize];
        slots.retain(|dir, slot| keep_after(slot, consumer, bytes, !reg.wants(dir)));
    }

    /// `consumer` finished its walk of `root`: it asks for nothing under it any more.
    pub(crate) fn finish_root(&self, consumer: Consumer, root: &Path) {
        let mut st = self.lock();
        let State { slots, regs, bytes, .. } = &mut *st;
        let reg = &mut regs[consumer as usize];
        let Registration::Walking { roots, finished } = reg else {
            return;
        };
        finished.insert(root.to_path_buf());
        let nearest = |dir: &Path| dir.ancestors().find(|a| roots.contains_key(*a)).map(Path::to_path_buf);
        slots.retain(|dir, slot| {
            let mine = dir.starts_with(root) && nearest(dir).as_deref() == Some(root);
            keep_after(slot, consumer, bytes, mine)
        });
    }

    /// `consumer`'s walks are over: it asks for nothing more.
    pub(crate) fn done(&self, consumer: Consumer) {
        let mut st = self.lock();
        st.regs[consumer as usize] = Registration::Done;
        let State { slots, bytes, .. } = &mut *st;
        slots.retain(|_, slot| keep_after(slot, consumer, bytes, true));
        slots.shrink_to_fit();
    }

    /// `dir`'s listing for `consumer`: left by another consumer, being read by one (wait
    /// for it), or read now and left for the consumers that may still ask. `Ok(None)`:
    /// the read was cancelled.
    pub(crate) fn get(
        &self,
        consumer: Consumer,
        dir: &Path,
        cancel: &AtomicBool,
    ) -> std::io::Result<Option<(Arc<Listing>, Got)>> {
        if !self.enabled {
            return Ok(read(dir, cancel)?.map(|l| (Arc::new(l), Got::Miss)));
        }
        let mut st = self.lock();
        loop {
            match st.slots.get_mut(dir) {
                Some(Slot::Filling) => st = self.cv.wait(st).unwrap_or_else(|e| e.into_inner()),
                Some(Slot::Ready { listing, pending, .. }) => {
                    let listing = Arc::clone(listing);
                    *pending &= !consumer.bit();
                    if *pending == 0
                        && let Some(Slot::Ready { bytes, .. }) = st.slots.remove(dir)
                    {
                        st.bytes -= bytes;
                    }
                    self.hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(Some((listing, Got::Hit)));
                }
                None => break,
            }
        }
        st.slots.insert(dir.to_path_buf(), Slot::Filling);
        drop(st);
        // Clears the Filling slot however the read ends (an error, a cancel, a panic),
        // so a consumer waiting for it reads the directory itself.
        let mut fill = Fill {
            index: self,
            dir,
            done: false,
        };
        let listing = match read(dir, cancel) {
            Ok(Some(l)) => Arc::new(l),
            other => return other.map(|o| o.map(|l| (Arc::new(l), Got::Miss))),
        };
        let mut st = self.lock();
        st.slots.remove(dir);
        let pending = (0..CONSUMERS)
            .filter(|&c| c != consumer as usize && st.regs[c].wants(dir))
            .fold(0u8, |m, c| m | 1 << c);
        let bytes = listing.bytes(dir);
        if pending != 0 && st.bytes + bytes <= MAX_CACHED_BYTES {
            st.bytes += bytes;
            st.peak_bytes = st.peak_bytes.max(st.bytes);
            st.slots.insert(
                dir.to_path_buf(),
                Slot::Ready {
                    listing: Arc::clone(&listing),
                    pending,
                    bytes,
                },
            );
        }
        fill.done = true;
        drop(st);
        self.cv.notify_all();
        Ok(Some((listing, Got::Miss)))
    }

    /// (listings held, bytes held, most bytes held at once).
    #[cfg(test)]
    pub(crate) fn usage(&self) -> (usize, usize, usize) {
        let st = self.lock();
        (st.slots.len(), st.bytes, st.peak_bytes)
    }

    /// Listings any consumer took from the index instead of reading them.
    #[cfg(test)]
    pub(crate) fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }
}

/// Retain-closure body: for a ready listing `consumer` will not ask for (`wont_ask`),
/// clear its pending bit, and drop the listing when no consumer is pending.
fn keep_after(slot: &mut Slot, consumer: Consumer, held: &mut usize, wont_ask: bool) -> bool {
    if !wont_ask {
        return true;
    }
    match slot {
        Slot::Filling => true,
        Slot::Ready { pending, bytes, .. } => {
            *pending &= !consumer.bit();
            if *pending == 0 {
                *held -= *bytes;
                false
            } else {
                true
            }
        }
    }
}

/// Removes a `Filling` slot that its read did not complete.
struct Fill<'a> {
    index: &'a WalkIndex,
    dir: &'a Path,
    done: bool,
}

impl Drop for Fill<'_> {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let mut st = self.index.lock();
        if matches!(st.slots.get(self.dir), Some(Slot::Filling)) {
            st.slots.remove(self.dir);
        }
        drop(st);
        self.index.cv.notify_all();
    }
}

/// One walk's view of the index: its consumer, and the root it walks (finished when the
/// walk is dropped).
pub(crate) struct WalkCtx {
    index: Arc<WalkIndex>,
    consumer: Consumer,
    root: PathBuf,
}

impl WalkCtx {
    pub(crate) fn new(index: &Arc<WalkIndex>, consumer: Consumer, root: &Path) -> Self {
        WalkCtx {
            index: Arc::clone(index),
            consumer,
            root: root.to_path_buf(),
        }
    }

    pub(crate) fn get(&self, dir: &Path, cancel: &AtomicBool) -> std::io::Result<Option<(Arc<Listing>, Got)>> {
        self.index.get(self.consumer, dir, cancel)
    }

    /// The walk of this root is over (call once, when it returns).
    pub(crate) fn finish(&self) {
        self.index.finish_root(self.consumer, &self.root);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rmg-walkindex-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rule() -> RootRule {
        RootRule {
            max_depth: None,
            skip_git: false,
            skip_dot: false,
            utf8_only: false,
        }
    }

    #[test]
    fn a_listing_is_shared_once_then_dropped() {
        let d = tmp("share");
        for n in ["a", "b", "CLAUDE.md", "tile1.png", "config"] {
            if n.contains('.') || n == "config" {
                std::fs::write(d.join(n), "x").unwrap();
            } else {
                std::fs::create_dir(d.join(n)).unwrap();
            }
        }
        let ix = Arc::new(WalkIndex::default());
        ix.register(Consumer::GitConfig, [(d.clone(), rule())]);
        ix.register(Consumer::Rules, [(d.clone(), rule())]);
        let no = AtomicBool::new(false);
        let (l1, g1) = ix.get(Consumer::GitConfig, &d, &no).unwrap().unwrap();
        assert_eq!(g1, Got::Miss);
        assert_eq!(ix.usage().0, 1, "kept for the rules walk");
        let (l2, g2) = ix.get(Consumer::Rules, &d, &no).unwrap().unwrap();
        assert_eq!(g2, Got::Hit);
        assert!(Arc::ptr_eq(&l1, &l2));
        assert_eq!(ix.usage().0, 0, "both took it: dropped");
        assert_eq!(ix.usage().1, 0);
        // Five entries counted, the tile not kept.
        let (entries, cut, kept) = l1.capped(MAX_ENTRIES);
        let mut names: Vec<_> = kept.map(|k| k.name.to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!((entries, cut), (5, false));
        assert_eq!(names, ["CLAUDE.md", "a", "b", "config"]);
        // A consumer with a smaller cap sees its own cut.
        let (e2, cut2, _) = l1.capped(3);
        assert_eq!((e2, cut2), (3, true));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn nothing_is_kept_for_a_consumer_that_will_not_ask() {
        let d = tmp("nokeep");
        let deep = d.join("a/b/c/d/e");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::create_dir_all(d.join("node_modules/x")).unwrap();
        let ix = Arc::new(WalkIndex::default());
        let rules = RootRule {
            max_depth: Some(4),
            skip_git: true,
            skip_dot: false,
            utf8_only: true,
        };
        ix.register(Consumer::Rules, [(d.clone(), rules)]);
        ix.register(Consumer::GitConfig, [(d.clone(), rule())]);
        let no = AtomicBool::new(false);
        // Depth 5 is below the rules walk's depth limit; node_modules is pruned by name.
        ix.get(Consumer::GitConfig, &deep, &no).unwrap().unwrap();
        ix.get(Consumer::GitConfig, &d.join("node_modules/x"), &no)
            .unwrap()
            .unwrap();
        assert_eq!(ix.usage().0, 0);
        // Depth 4 is wanted until the rules walk finishes the root.
        ix.get(Consumer::GitConfig, &d.join("a/b/c/d"), &no).unwrap().unwrap();
        assert_eq!(ix.usage().0, 1);
        ix.finish_root(Consumer::Rules, &d);
        assert_eq!(ix.usage(), (0, 0, ix.usage().2));
        // An unregistered consumer may want anything, until it registers elsewhere.
        let ix = Arc::new(WalkIndex::default());
        ix.get(Consumer::GitConfig, &d.join("a"), &no).unwrap().unwrap();
        assert_eq!(ix.usage().0, 1);
        ix.register(Consumer::Rules, [(d.join("elsewhere"), rule())]);
        assert_eq!(ix.usage().0, 0);
        // Done wants nothing.
        let ix = Arc::new(WalkIndex::default());
        ix.done(Consumer::Rules);
        ix.get(Consumer::GitConfig, &d.join("a"), &no).unwrap().unwrap();
        assert_eq!(ix.usage().0, 0);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn errors_are_not_kept_and_a_panicking_fill_frees_its_slot() {
        let d = tmp("err");
        let ix = Arc::new(WalkIndex::default());
        let no = AtomicBool::new(false);
        assert!(ix.get(Consumer::GitConfig, &d.join("missing"), &no).is_err());
        assert!(ix.get(Consumer::Rules, &d.join("missing"), &no).is_err());
        assert_eq!(ix.usage().0, 0);
        // A cancelled read is not kept either.
        let yes = AtomicBool::new(true);
        let big = d.join("big");
        std::fs::create_dir(&big).unwrap();
        for i in 0..1100 {
            std::fs::write(big.join(i.to_string()), "").unwrap();
        }
        assert!(ix.get(Consumer::GitConfig, &big, &yes).unwrap().is_none());
        assert_eq!(ix.usage().0, 0);
        // A Filling slot left by an unwinding read is cleared by its guard.
        {
            ix.lock().slots.insert(big.clone(), Slot::Filling);
            let _f = Fill {
                index: &ix,
                dir: &big,
                done: false,
            };
        }
        let (l, g) = ix.get(Consumer::Rules, &big, &no).unwrap().unwrap();
        assert_eq!((l.capped(MAX_ENTRIES).0, g), (1100, Got::Miss));
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_byte_cap_bounds_what_is_kept() {
        let d = tmp("cap");
        // Each listing of 2,000 subdirectories with 200-byte names is ~0.45 MB: the 8 MiB
        // cap holds at most 18 of 30.
        let name = "n".repeat(196);
        let mut dirs = Vec::new();
        for i in 0..30 {
            let p = d.join(i.to_string());
            std::fs::create_dir(&p).unwrap();
            for j in 0..2000 {
                std::fs::create_dir(p.join(format!("{name}{j:04}"))).unwrap();
            }
            dirs.push(p);
        }
        let ix = Arc::new(WalkIndex::default());
        let no = AtomicBool::new(false);
        for p in &dirs {
            ix.get(Consumer::GitConfig, p, &no).unwrap().unwrap();
        }
        let (held, bytes, peak) = ix.usage();
        assert!(bytes <= MAX_CACHED_BYTES && peak <= MAX_CACHED_BYTES, "{bytes} {peak}");
        assert!(held < 30 && held > 0, "{held}");
        // Past the cap the other walk reads fresh, and sees the same listing.
        for p in &dirs {
            let (l, _) = ix.get(Consumer::Rules, p, &no).unwrap().unwrap();
            assert_eq!(l.capped(MAX_ENTRIES).0, 2000);
        }
        assert_eq!(ix.hits() as usize, held);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The D4 stress: both nested walks over one fixture with shared trees, symlinks (a
    /// symlinked directory, a symlinked `config` and `objects`, a project reached through
    /// a symlinked spelling), a directory cut at 20,000 entries, an inner project, a
    /// generated tree, a home walked by the rules walk only, and one project past the
    /// gitconfig budget. At `jobs` 1, 2, 4 and 8, run side by side on one shared index
    /// (three times each) and one after the other in both orders, each walk's rows,
    /// findings and counts are those of the same walk run alone with no index at `jobs`
    /// 1, and the index ends empty.
    #[test]
    fn both_walks_on_a_shared_index_match_each_walk_alone() {
        use crate::scanners::{git_config, rules_files};
        let b = tmp("stress");
        let home = b.join("home");
        let p1 = home.join("work/p1");
        let p2 = b.join("p2");
        let p3 = p2.join("inner");
        let plink = b.join("plink");
        let w = |p: &Path, body: &str| {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        };
        let git_dir = |g: &Path, tag: &str| {
            std::fs::create_dir_all(g.join("objects/ab")).unwrap();
            std::fs::create_dir_all(g.join("refs/heads")).unwrap();
            w(&g.join("HEAD"), "ref: refs/heads/main\n");
            w(&g.join("config"), &format!("[core]\n\tfsmonitor = \"./{tag}.sh\"\n"));
        };
        // p1: shared modules, instruction files at depths 2 to 6, pruned and generated
        // trees, git dirs (one buried, one behind a symlinked config, one with a
        // symlinked objects/), a symlinked directory, and a cut tile directory.
        for i in 0..40 {
            std::fs::create_dir_all(p1.join(format!("src/m{i:02}/lib"))).unwrap();
        }
        w(&p1.join("src/m03/CLAUDE.md"), "m03 notes\n");
        w(&p1.join("src/m07/lib/AGENTS.md"), "m07 agents\n");
        w(&p1.join("a/b/c/d/e/f/CLAUDE.md"), "too deep for rules\n");
        w(&p1.join("a/b/c/GEMINI.md"), "depth 3\n");
        w(&p1.join("node_modules/x/CLAUDE.md"), "pruned\n");
        w(
            &p1.join("target/CACHEDIR.TAG"),
            "Signature: 8a477f597d28d172789f06886806bc55\n",
        );
        w(&p1.join("target/debug/CLAUDE.md"), "generated\n");
        git_dir(&p1.join(".git"), "own");
        git_dir(&p1.join("vendor/g"), "p1-g");
        std::fs::create_dir_all(p1.join("vendor/g2/objects")).unwrap();
        std::fs::create_dir_all(p1.join("vendor/g2/refs")).unwrap();
        w(&p1.join("vendor/g2/HEAD"), "ref: refs/heads/main\n");
        w(&p1.join("vendor/real-config"), "[core]\n\tfsmonitor = \"./p1-g2.sh\"\n");
        std::os::unix::fs::symlink("../real-config", p1.join("vendor/g2/config")).unwrap();
        std::fs::create_dir_all(p1.join("vendor/g3/refs")).unwrap();
        w(&p1.join("vendor/g3/HEAD"), "ref: refs/heads/main\n");
        w(&p1.join("vendor/g3/config"), "[core]\n\tfsmonitor = \"./p1-g3.sh\"\n");
        std::os::unix::fs::symlink("../g/objects", p1.join("vendor/g3/objects")).unwrap();
        std::os::unix::fs::symlink("src", p1.join("linkdir")).unwrap();
        let tiles = p1.join("tiles");
        std::fs::create_dir_all(tiles.join("sub")).unwrap();
        for i in 0..20_050 {
            std::fs::write(tiles.join(format!("t{i:05}.png")), "").unwrap();
        }
        // p2: past the gitconfig budget below (600 directories), holding an inner project.
        for i in 0..600 {
            std::fs::create_dir_all(p2.join(format!("d/{i:03}"))).unwrap();
        }
        w(&p2.join("d/005/CLAUDE.md"), "p2 notes\n");
        git_dir(&p2.join("d/590/g"), "p2-deep");
        git_dir(&p3.join("x/g"), "p3-g");
        w(&p3.join("x/CLAUDE.md"), "p3 notes\n");
        std::os::unix::fs::symlink(&p2, &plink).unwrap();
        // The home: walked by the rules walk (its dot-directories skipped), never by the
        // gitconfig walk.
        w(&home.join("notes/CLAUDE.md"), "home notes\n");
        w(&home.join(".cache/CLAUDE.md"), "dot dir\n");

        let projects = vec![p1.clone(), p2.clone(), p3.clone(), plink.clone()];
        let mut all = projects.clone();
        all.push(home.clone());
        let budget = 400;
        let gc = |jobs, ix: &Arc<WalkIndex>| git_config::walk_for_index_test(&projects, &projects, jobs, budget, ix);
        let ru = |jobs, ix: &Arc<WalkIndex>| rules_files::walk_for_index_test(&home, &all, &projects, jobs, ix);
        let off = || Arc::new(WalkIndex::disabled());
        let (gc_alone, ru_alone) = (gc(1, &off()), ru(1, &off()));
        // The fixture does what it is for.
        assert!(gc_alone.1.contains("budget_exhausted: true"), "{}", gc_alone.1);
        assert!(gc_alone.1.contains("dirs_cut: 1,"), "{}", gc_alone.1);
        assert!(ru_alone.1.contains("dirs_cut: 1,"), "{}", ru_alone.1);
        assert!(ru_alone.0.iter().any(|r| r.contains("home notes")));
        assert!(
            !ru_alone
                .0
                .iter()
                .any(|r| r.contains("too deep") || r.contains("dot dir"))
        );
        assert_eq!(ru_alone.2, (0, ru_alone.2.1));
        let same =
            |what: &str, jobs, g: &(Vec<Vec<String>>, String, (u64, u64)), r: &(Vec<String>, String, (u64, u64))| {
                assert_eq!((&g.0, &g.1), (&gc_alone.0, &gc_alone.1), "gitconfig {what} jobs {jobs}");
                assert_eq!((&r.0, &r.1), (&ru_alone.0, &ru_alone.1), "rules {what} jobs {jobs}");
            };
        for jobs in [1usize, 2, 4, 8] {
            same("alone", jobs, &gc(jobs, &off()), &ru(jobs, &off()));
            for round in 0..3 {
                let ix = Arc::new(WalkIndex::default());
                let (g, r) = std::thread::scope(|s| {
                    let g = s.spawn(|| gc(jobs, &ix));
                    let r = s.spawn(|| ru(jobs, &ix));
                    (g.join().unwrap(), r.join().unwrap())
                });
                same("side by side", jobs, &g, &r);
                assert!(g.2.0 + r.2.0 > 0, "round {round} jobs {jobs}: nothing shared");
                assert_eq!(ix.usage().1, 0, "jobs {jobs}: listings left behind");
            }
            for gc_first in [true, false] {
                let ix = Arc::new(WalkIndex::default());
                let (g, r) = if gc_first {
                    let g = gc(jobs, &ix);
                    (g, ru(jobs, &ix))
                } else {
                    let r = ru(jobs, &ix);
                    (gc(jobs, &ix), r)
                };
                same(if gc_first { "gitconfig first" } else { "rules first" }, jobs, &g, &r);
                // The second walk finds what the first one read and it lists too.
                let second = if gc_first { r.2.0 } else { g.2.0 };
                assert!(second > 0, "jobs {jobs} gitconfig first {gc_first}");
                assert_eq!(ix.usage().1, 0);
            }
        }
        let _ = std::fs::remove_dir_all(&b);
    }
}
