//! Directory listings read ahead of a walk on helper threads, consumed in the walk's own
//! order.
//!
//! A breadth-first walk (the rules scanner's nested-instruction-file walk, the gitconfig
//! scanner's nested-repository walk) decides what to list next, and when to stop, one
//! directory at a time, from what it has listed so far: its budget and its results depend
//! on that order. [`with_prefetch`] keeps the walk exactly as it is and only moves the
//! listing itself, the system calls, onto helpers: the walk [`hint`](Prefetch::hint)s each
//! directory it has queued, helpers list hinted directories ahead of it, oldest hint first
//! (the order a breadth-first walk consumes its queue), and [`get`](Prefetch::get) hands
//! the walk a directory's listing, read ahead or read there and then. Every decision is
//! still the walk's, in its order, on its thread, so results, budgets and truncation are
//! the same at any `jobs`.
//!
//! The helpers are ONE pool per `jobs` value (perf 6d), shared by every walk running at
//! once, of both scanners and any future one: at most `jobs - 1` helper threads in all,
//! where each walk used to start its own `jobs - 1` (with six projects of each scanner
//! walking at once, the scan peaked at 84 threads at `--jobs` 6; 32 with the pool). A helper takes the next hinted directory
//! of the walks in turn (round robin, one listing at a time), so a walk that hints much
//! does not starve the others. Helpers start when a walk first needs them and exit when no
//! walk is registered; `jobs` 1 starts none, and every listing is read by the walk itself.
//!
//! The listing function runs on a helper: it must not touch the scanner's telemetry
//! (counts, the `truncated` flag), open spans, or spend any budget. The walk notes what a
//! listing found when it consumes it. A listing read ahead and never consumed (the walk
//! stopped at its budget) is dropped; the listing function is passed a cancel flag, set
//! when the walk returns, and should check it now and then so a long listing stops early.
//! At most `max_ahead` listings of one walk are read ahead and unconsumed at once. A
//! listing that panics on a helper is listed again by the walk itself.

use std::cell::{Cell, OnceCell};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

/// Directories a walk lists itself before it asks the pool for helpers: a small project's
/// walk is done before helpers would pay for themselves.
const SPAWN_AFTER: usize = 16;

enum Slot<L> {
    /// Hinted, not taken by a helper yet.
    Hinted,
    /// Being listed by a helper.
    Running,
    /// Listed, waiting for the walk.
    Done(L),
    /// The helper's listing panicked: the walk lists it itself.
    Failed,
}

struct State<L> {
    wanted: VecDeque<PathBuf>,
    slots: HashMap<PathBuf, Slot<L>>,
    /// Running or Done (read ahead and not consumed).
    ahead: usize,
}

/// One walk's read-ahead state, owned jointly by the walk and the pool's helpers.
struct Source<L, F> {
    state: Mutex<State<L>>,
    cv: Condvar,
    cancel: AtomicBool,
    list: F,
    max_ahead: usize,
}

impl<L, F> Source<L, F> {
    fn lock(&self) -> MutexGuard<'_, State<L>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// What a pool helper can do with a registered walk, whatever its listing type.
trait Work: Send + Sync {
    /// The oldest hinted directory not yet taken, marked running, unless the walk has
    /// `max_ahead` listings ahead already or has returned.
    fn take(&self) -> Option<PathBuf>;
    /// List `dir` (taken by [`Work::take`]) and leave the listing for the walk.
    fn run(&self, dir: PathBuf);
}

impl<L, F> Work for Source<L, F>
where
    L: Send,
    F: Fn(&Path, &AtomicBool) -> L + Send + Sync,
{
    fn take(&self) -> Option<PathBuf> {
        if self.cancel.load(Ordering::Relaxed) {
            return None;
        }
        let mut st = self.lock();
        if st.ahead >= self.max_ahead {
            return None;
        }
        while let Some(d) = st.wanted.pop_front() {
            // Taken by the walk itself already, or listed: skip it.
            if let Some(slot) = st.slots.get_mut(&d)
                && matches!(slot, Slot::Hinted)
            {
                *slot = Slot::Running;
                st.ahead += 1;
                return Some(d);
            }
        }
        None
    }

    fn run(&self, dir: PathBuf) {
        let listed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.list)(&dir, &self.cancel)));
        let mut st = self.lock();
        match listed {
            Ok(l) => {
                st.slots.insert(dir, Slot::Done(l));
            }
            Err(_) => {
                st.ahead -= 1;
                st.slots.insert(dir, Slot::Failed);
            }
        }
        drop(st);
        self.cv.notify_all();
    }
}

/// The helpers shared by every walk run with the same `jobs`.
struct Pool {
    helpers: usize,
    state: Mutex<PoolState>,
    cv: Condvar,
}

struct PoolState {
    /// The walks that asked for helpers and have not returned, in turn order.
    walks: VecDeque<Arc<dyn Work>>,
    /// Helper threads alive.
    threads: usize,
}

/// The pool of `helpers` threads (one per distinct value: the scan has one `--jobs`; unit
/// tests use several).
fn pool(helpers: usize) -> &'static Pool {
    static POOLS: Mutex<Vec<&'static Pool>> = Mutex::new(Vec::new());
    let mut pools = POOLS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = pools.iter().find(|p| p.helpers == helpers) {
        return p;
    }
    let p: &'static Pool = Box::leak(Box::new(Pool {
        helpers,
        state: Mutex::new(PoolState {
            walks: VecDeque::new(),
            threads: 0,
        }),
        cv: Condvar::new(),
    }));
    pools.push(p);
    p
}

impl Pool {
    fn lock(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Hand `walk` to the helpers, starting threads up to the pool's size.
    fn add(&'static self, walk: Arc<dyn Work>) {
        let mut st = self.lock();
        st.walks.push_back(walk);
        while st.threads < self.helpers {
            let spawned = std::thread::Builder::new()
                .name("rmguard-prefetch".into())
                .stack_size(2 << 20)
                .spawn(move || self.helper());
            if spawned.is_err() {
                // The walk lists whatever no helper takes: fewer helpers is not an error.
                break;
            }
            st.threads += 1;
        }
        drop(st);
        self.cv.notify_all();
    }

    /// `walk` has returned: helpers stop taking its directories (one already being
    /// listed finishes, cancelled, and is dropped with the walk's state).
    fn remove(&self, walk: &Arc<dyn Work>) {
        let mut st = self.lock();
        st.walks.retain(|w| !Arc::ptr_eq(w, walk));
        drop(st);
        self.cv.notify_all();
    }

    /// Something a helper waits for changed (a hint, a consumed listing). Taken under
    /// the pool's lock, so a helper between "nothing to take" and waiting cannot miss it.
    fn wake(&self) {
        drop(self.lock());
        self.cv.notify_all();
    }

    fn helper(&self) {
        let mut st = self.lock();
        loop {
            if st.walks.is_empty() {
                st.threads -= 1;
                return;
            }
            let mut found = None;
            for _ in 0..st.walks.len() {
                let w = st.walks.pop_front().expect("non-empty");
                st.walks.push_back(Arc::clone(&w));
                if let Some(d) = w.take() {
                    found = Some((w, d));
                    break;
                }
            }
            match found {
                Some((w, d)) => {
                    drop(st);
                    w.run(d);
                    drop(w);
                    st = self.lock();
                }
                None => st = self.cv.wait(st).unwrap_or_else(|e| e.into_inner()),
            }
        }
    }
}

/// The handle a walk uses inside [`with_prefetch`].
pub(crate) struct Prefetch<L, F> {
    source: Arc<Source<L, F>>,
    pool: Option<&'static Pool>,
    /// Directories the walk asked for so far (helpers are asked for at [`SPAWN_AFTER`]).
    asked: Cell<usize>,
    /// This walk as the pool holds it, once handed over.
    registered: OnceCell<Arc<dyn Work>>,
}

/// Run `walk` with a [`Prefetch`] over `list`, read ahead by the shared pool of `jobs - 1`
/// helper threads (none at `jobs` 1, where every listing is read by the walk itself, as
/// without this module).
pub(crate) fn with_prefetch<L, F, R>(
    jobs: usize,
    max_ahead: usize,
    list: F,
    walk: impl FnOnce(&Prefetch<L, F>) -> R,
) -> R
where
    L: Send + 'static,
    F: Fn(&Path, &AtomicBool) -> L + Send + Sync + 'static,
{
    let helpers = jobs.saturating_sub(1);
    let pf = Prefetch {
        source: Arc::new(Source {
            state: Mutex::new(State {
                wanted: VecDeque::new(),
                slots: HashMap::new(),
                ahead: 0,
            }),
            cv: Condvar::new(),
            cancel: AtomicBool::new(false),
            list,
            max_ahead: max_ahead.max(1),
        }),
        pool: (helpers > 0).then(|| pool(helpers)),
        asked: Cell::new(0),
        registered: OnceCell::new(),
    };
    walk(&pf)
}

impl<L, F> Drop for Prefetch<L, F> {
    /// The walk returned (or unwound): cancel what is being read ahead and leave the pool.
    fn drop(&mut self) {
        self.source.cancel.store(true, Ordering::Relaxed);
        if let (Some(pool), Some(w)) = (self.pool, self.registered.get()) {
            pool.remove(w);
        }
    }
}

impl<L, F> Prefetch<L, F>
where
    L: Send + 'static,
    F: Fn(&Path, &AtomicBool) -> L + Send + Sync + 'static,
{
    /// The walk has queued `dir` and will ask for it (unless it stops first).
    pub(crate) fn hint(&self, dir: &Path) {
        let Some(pool) = self.pool else {
            return;
        };
        let mut st = self.source.lock();
        if st.slots.contains_key(dir) {
            return;
        }
        st.slots.insert(dir.to_path_buf(), Slot::Hinted);
        st.wanted.push_back(dir.to_path_buf());
        drop(st);
        if self.registered.get().is_some() {
            pool.wake();
        }
    }

    /// `dir`'s listing: the one read ahead, or read now on this thread.
    pub(crate) fn get(&self, dir: &Path) -> L {
        let source = &self.source;
        let Some(pool) = self.pool else {
            return (source.list)(dir, &source.cancel);
        };
        let asked = self.asked.get() + 1;
        self.asked.set(asked);
        if asked == SPAWN_AFTER {
            let w: Arc<dyn Work> = Arc::clone(source) as Arc<dyn Work>;
            pool.add(Arc::clone(&w));
            let _ = self.registered.set(w);
        }
        let mut st = source.lock();
        loop {
            match st.slots.remove(dir) {
                None | Some(Slot::Hinted) | Some(Slot::Failed) => {
                    drop(st);
                    return (source.list)(dir, &source.cancel);
                }
                Some(Slot::Done(l)) => {
                    st.ahead -= 1;
                    drop(st);
                    pool.wake();
                    return l;
                }
                Some(Slot::Running) => {
                    st.slots.insert(dir.to_path_buf(), Slot::Running);
                    st = source.cv.wait(st).unwrap_or_else(|e| e.into_inner());
                }
            }
        }
    }
}

/// Helper threads alive in the pool for `jobs` (tests: the pool never exceeds `jobs - 1`).
#[cfg(test)]
pub(crate) fn pool_threads(jobs: usize) -> usize {
    match jobs.saturating_sub(1) {
        0 => 0,
        h => pool(h).lock().threads,
    }
}

#[cfg(test)]
mod tests {
    use super::with_prefetch;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn on_helper() -> bool {
        std::thread::current().name() == Some("rmguard-prefetch")
    }

    /// A synthetic tree: every directory `d` of depth < 4 has children `d/0..d/2`. The
    /// walk visits in its own order and stops at a budget; the visit order and the
    /// listings it consumed are the same at every `jobs`.
    fn walk(jobs: usize, budget: usize) -> (Vec<PathBuf>, usize) {
        let listed = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&listed);
        let list = move |d: &Path, _: &AtomicBool| {
            counter.fetch_add(1, Ordering::Relaxed);
            let depth = d.components().count();
            if depth >= 5 {
                Vec::new()
            } else {
                (0..3).map(|i| d.join(i.to_string())).collect::<Vec<_>>()
            }
        };
        let visited = with_prefetch(jobs, 8, list, |pf| {
            let mut seen = Vec::new();
            let mut q = std::collections::VecDeque::from([PathBuf::from("r")]);
            while let Some(d) = q.pop_front() {
                if seen.len() >= budget {
                    break;
                }
                let children = pf.get(&d);
                seen.push(d);
                for c in children {
                    pf.hint(&c);
                    q.push_back(c);
                }
            }
            seen
        });
        (visited, listed.load(Ordering::Relaxed))
    }

    #[test]
    fn visit_order_is_the_same_at_any_jobs_and_read_ahead_is_bounded() {
        for budget in [1, 5, 17, 40, 121, 1000] {
            let (one, listed_one) = walk(1, budget);
            assert_eq!(listed_one, one.len(), "jobs 1 lists only what it visits");
            for jobs in [2, 4, 8] {
                let (many, listed) = walk(jobs, budget);
                assert_eq!(one, many, "budget {budget} jobs {jobs}");
                // Read ahead and never consumed: at most max_ahead (8), listed or in
                // flight (one more may finish after the walk returned, cancelled).
                assert!(
                    listed <= many.len() + 8 + 1,
                    "{listed} listed for {} visited",
                    many.len()
                );
            }
        }
    }

    #[test]
    fn a_panicking_listing_is_retried_by_the_walk() {
        let list = |d: &Path, _: &AtomicBool| {
            assert!(!(on_helper() && d.ends_with("boom")), "helper listing panics");
            d.to_path_buf()
        };
        let name = |i: usize| {
            if i == 30 {
                PathBuf::from("boom")
            } else {
                PathBuf::from(i.to_string())
            }
        };
        let got = with_prefetch(4, 8, list, |pf| {
            for i in 0..40 {
                pf.hint(&name(i));
            }
            (0..40).map(|i| pf.get(&name(i))).collect::<Vec<_>>()
        });
        assert_eq!(got, (0..40).map(name).collect::<Vec<_>>());
    }

    /// Perf 6d: many walks at once share ONE pool of `jobs - 1` helpers. Twelve walks
    /// (six per "scanner", as at `--jobs` 6) at jobs 4: never more than three listings run
    /// on helpers at once, the pool never holds more than three threads, and every walk
    /// still visits its tree in its own order. At jobs 1 no helper ever lists anything.
    #[test]
    fn concurrent_walks_share_one_bounded_pool() {
        for jobs in [1usize, 2, 4] {
            let running = Arc::new(AtomicUsize::new(0));
            let peak = Arc::new(AtomicUsize::new(0));
            let helper_listings = Arc::new(AtomicUsize::new(0));
            let pool_peak = Mutex::new(0usize);
            std::thread::scope(|s| {
                for w in 0..12 {
                    let (running, peak, helper_listings, pool_peak) = (
                        Arc::clone(&running),
                        Arc::clone(&peak),
                        Arc::clone(&helper_listings),
                        &pool_peak,
                    );
                    s.spawn(move || {
                        let list = move |d: &Path, _: &AtomicBool| {
                            if on_helper() {
                                helper_listings.fetch_add(1, Ordering::Relaxed);
                                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                                peak.fetch_max(now, Ordering::SeqCst);
                                std::thread::yield_now();
                                running.fetch_sub(1, Ordering::SeqCst);
                            }
                            let depth = d.components().count();
                            if depth >= 6 {
                                Vec::new()
                            } else {
                                (0..3).map(|i| d.join(i.to_string())).collect::<Vec<_>>()
                            }
                        };
                        let root = PathBuf::from(format!("w{w}"));
                        let visited = with_prefetch(jobs, 16, list, |pf| {
                            let mut seen = Vec::new();
                            let mut q = std::collections::VecDeque::from([root.clone()]);
                            while let Some(d) = q.pop_front() {
                                let children = pf.get(&d);
                                seen.push(d);
                                for c in children {
                                    pf.hint(&c);
                                    q.push_back(c);
                                }
                                let t = super::pool_threads(jobs);
                                let mut p = pool_peak.lock().unwrap();
                                *p = (*p).max(t);
                            }
                            seen
                        });
                        // 3^0 + ... + 3^5 directories, breadth-first: the root first, its
                        // three children next, the deepest level last.
                        assert_eq!(visited.len(), 364, "walk {w} jobs {jobs}");
                        assert_eq!(visited[0], root);
                        assert!(visited[1..4].iter().all(|d| d.components().count() == 2));
                        assert!(visited[121..].iter().all(|d| d.components().count() == 6));
                    });
                }
            });
            let helpers = jobs - 1;
            assert!(peak.load(Ordering::SeqCst) <= helpers, "jobs {jobs}: {peak:?} at once");
            assert!(*pool_peak.lock().unwrap() <= helpers, "jobs {jobs}: pool {pool_peak:?}");
            if jobs == 1 {
                assert_eq!(helper_listings.load(Ordering::Relaxed), 0);
            }
        }
    }
}
