//! Directory listings read ahead of a walk on helper threads, consumed in the walk's own
//! order.
//!
//! A breadth-first walk (the rules scanner's nested-instruction-file walk, the gitconfig
//! scanner's nested-repository walk) decides what to list next, and when to stop, one
//! directory at a time, from what it has listed so far: its budget and its results depend on that order. [`with_prefetch`]
//! keeps the walk exactly as it is and only moves the listing itself, the system calls,
//! onto helpers: the walk [`hint`](Prefetch::hint)s each directory it has queued, helpers
//! list hinted directories ahead of it, oldest hint first (the order a breadth-first walk
//! consumes its queue), and [`get`](Prefetch::get) hands the walk a
//! directory's listing, read ahead or read there and then. Every decision is still the
//! walk's, in its order, on its thread, so results, budgets and truncation are the same at
//! any `jobs`.
//!
//! The listing function runs on a helper: it must not touch the scanner's telemetry
//! (counts, the `truncated` flag), open spans, or spend any budget. The walk notes what a
//! listing found when it consumes it. A listing read ahead and never consumed (the walk
//! stopped at its budget) is dropped; the listing function is passed a cancel flag, set
//! when the walk returns, and should check it now and then so a long listing stops early.
//! At most `max_ahead` listings are read ahead and unconsumed at once.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex};

/// Directories a walk lists itself before its helpers start: a small project's walk is
/// done before threads would pay for themselves.
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
    done: bool,
}

struct Shared<L> {
    state: Mutex<State<L>>,
    cv: Condvar,
    cancel: AtomicBool,
}

impl<L> Shared<L> {
    fn lock(&self) -> std::sync::MutexGuard<'_, State<L>> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The handle a walk uses inside [`with_prefetch`].
pub(crate) struct Prefetch<'s, 'e, L, F> {
    shared: &'e Shared<L>,
    list: &'e F,
    max_ahead: usize,
    helpers: usize,
    /// Directories the walk asked for so far (helpers start at [`SPAWN_AFTER`]).
    asked: AtomicUsize,
    started: AtomicBool,
    scope: Option<&'s std::thread::Scope<'s, 'e>>,
}

/// Run `walk` with a [`Prefetch`] over `list` on up to `jobs - 1` helper threads (none at
/// `jobs` 1, where every listing is read by the walk itself, as without this module).
pub(crate) fn with_prefetch<L, F, R>(
    jobs: usize,
    max_ahead: usize,
    list: F,
    walk: impl FnOnce(&Prefetch<'_, '_, L, F>) -> R,
) -> R
where
    L: Send,
    F: Fn(&Path, &AtomicBool) -> L + Sync,
{
    let shared = Shared {
        state: Mutex::new(State {
            wanted: VecDeque::new(),
            slots: HashMap::new(),
            ahead: 0,
            done: false,
        }),
        cv: Condvar::new(),
        cancel: AtomicBool::new(false),
    };
    let helpers = jobs.saturating_sub(1);
    if helpers == 0 {
        let pf = Prefetch {
            shared: &shared,
            list: &list,
            max_ahead,
            helpers: 0,
            asked: AtomicUsize::new(0),
            started: AtomicBool::new(false),
            scope: None,
        };
        return walk(&pf);
    }
    std::thread::scope(|s| {
        let pf = Prefetch {
            shared: &shared,
            list: &list,
            max_ahead: max_ahead.max(1),
            helpers,
            asked: AtomicUsize::new(0),
            started: AtomicBool::new(false),
            scope: Some(s),
        };
        let r = walk(&pf);
        shared.cancel.store(true, Ordering::Relaxed);
        shared.lock().done = true;
        shared.cv.notify_all();
        r
    })
}

impl<'s, 'e, L, F> Prefetch<'s, 'e, L, F>
where
    L: Send + 's,
    F: Fn(&Path, &AtomicBool) -> L + Sync,
{
    /// The walk has queued `dir` and will ask for it (unless it stops first).
    pub(crate) fn hint(&self, dir: &Path) {
        if self.scope.is_none() {
            return;
        }
        let mut st = self.shared.lock();
        if st.slots.contains_key(dir) {
            return;
        }
        st.slots.insert(dir.to_path_buf(), Slot::Hinted);
        st.wanted.push_back(dir.to_path_buf());
        drop(st);
        if self.started.load(Ordering::Relaxed) {
            self.shared.cv.notify_one();
        }
    }

    /// `dir`'s listing: the one read ahead, or read now on this thread.
    pub(crate) fn get(&self, dir: &Path) -> L {
        let Some(scope) = self.scope else {
            return (self.list)(dir, &self.shared.cancel);
        };
        if self.asked.fetch_add(1, Ordering::Relaxed) + 1 == SPAWN_AFTER {
            self.start(scope);
        }
        let mut st = self.shared.lock();
        loop {
            match st.slots.remove(dir) {
                None | Some(Slot::Hinted) | Some(Slot::Failed) => {
                    drop(st);
                    return (self.list)(dir, &self.shared.cancel);
                }
                Some(Slot::Done(l)) => {
                    st.ahead -= 1;
                    drop(st);
                    self.shared.cv.notify_all();
                    return l;
                }
                Some(Slot::Running) => {
                    st.slots.insert(dir.to_path_buf(), Slot::Running);
                    st = self.shared.cv.wait(st).unwrap_or_else(|e| e.into_inner());
                }
            }
        }
    }

    fn start(&self, scope: &'s std::thread::Scope<'s, 'e>) {
        self.started.store(true, Ordering::Relaxed);
        let (shared, list, max_ahead) = (self.shared, self.list, self.max_ahead);
        for _ in 0..self.helpers {
            let spawned = std::thread::Builder::new()
                .name("rmguard-prefetch".into())
                .stack_size(2 << 20)
                .spawn_scoped(scope, move || helper(shared, list, max_ahead));
            if spawned.is_err() {
                // The walk lists whatever no helper takes: fewer helpers is not an error.
                break;
            }
        }
    }
}

fn helper<L, F>(shared: &Shared<L>, list: &F, max_ahead: usize)
where
    F: Fn(&Path, &AtomicBool) -> L,
{
    loop {
        let dir = {
            let mut st = shared.lock();
            loop {
                if st.done {
                    return;
                }
                if st.ahead < max_ahead {
                    match st.wanted.pop_front() {
                        // Taken by the walk itself already, or listed: skip it.
                        Some(d) if !matches!(st.slots.get(&d), Some(Slot::Hinted)) => continue,
                        Some(d) => {
                            st.slots.insert(d.clone(), Slot::Running);
                            st.ahead += 1;
                            break d;
                        }
                        None => {}
                    }
                }
                st = shared.cv.wait(st).unwrap_or_else(|e| e.into_inner());
            }
        };
        let listed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| list(&dir, &shared.cancel)));
        let mut st = shared.lock();
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
        shared.cv.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::with_prefetch;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;

    /// A synthetic tree: every directory `d` of depth < 4 has children `d/0..d/2`. The
    /// walk visits in its own order and stops at a budget; the visit order and the
    /// listings it consumed are the same at every `jobs`.
    fn walk(jobs: usize, budget: usize) -> (Vec<PathBuf>, usize) {
        let listed = Mutex::new(0usize);
        let list = |d: &Path, _: &AtomicBool| {
            *listed.lock().unwrap() += 1;
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
        let n = *listed.lock().unwrap();
        (visited, n)
    }

    #[test]
    fn visit_order_is_the_same_at_any_jobs_and_read_ahead_is_bounded() {
        for budget in [1, 5, 17, 40, 121, 1000] {
            let (one, listed_one) = walk(1, budget);
            assert_eq!(listed_one, one.len(), "jobs 1 lists only what it visits");
            for jobs in [2, 4, 8] {
                let (many, listed) = walk(jobs, budget);
                assert_eq!(one, many, "budget {budget} jobs {jobs}");
                // Read ahead and never consumed: at most max_ahead (8), listed or in flight.
                assert!(listed <= many.len() + 8, "{listed} listed for {} visited", many.len());
            }
        }
    }

    #[test]
    fn a_panicking_listing_is_retried_by_the_walk() {
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let list = |d: &Path, _: &AtomicBool| {
            let on_helper = std::thread::current().name() == Some("rmguard-prefetch");
            calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            assert!(!(on_helper && d.ends_with("boom")), "helper listing panics");
            d.to_path_buf()
        };
        let got = with_prefetch(4, 8, list, |pf| {
            let mut out = Vec::new();
            for i in 0..40 {
                let d = if i == 30 {
                    PathBuf::from("boom")
                } else {
                    PathBuf::from(i.to_string())
                };
                pf.hint(&d);
            }
            for i in 0..40 {
                let d = if i == 30 {
                    PathBuf::from("boom")
                } else {
                    PathBuf::from(i.to_string())
                };
                out.push(pf.get(&d));
            }
            out
        });
        assert_eq!(got.len(), 40);
        assert_eq!(got[30], PathBuf::from("boom"));
    }
}
