//! Scan-owned admission for input snapshots and discovery. Counts retained payload, not RSS.
use std::io::{self, Read};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::{Exhaustion, Limits, Resource};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InputStats {
    pub arena_bytes: u64,
    pub ast_nodes: u64,
    pub text_bytes: u64,
    pub collection_bytes: u64,
    pub results: u64,
    pub source_bytes: u64,
    pub file_entries: u64,
    pub directory_entries: u64,
    pub roots: u64,
}

#[derive(Debug, Default)]
struct State {
    source_bytes: u64,
    file_entries: u64,
    directory_entries: u64,
    roots: u64,
    arena_bytes: u64,
    exhaustion: Option<Exhaustion>,
}

#[derive(Debug)]
pub struct InputBudget {
    identity: u64,
    limits: Limits,
    state: Mutex<State>,
    ast_nodes: AtomicU64,
    text_bytes: AtomicU64,
    collection_bytes: AtomicU64,
    exhausted: AtomicBool,
    /// Findings and rule errors. Independent of `exhausted`: storage refusal keeps
    /// completed resources, whose results must still be recordable.
    results: AtomicU64,
    results_exhausted: AtomicBool,
}

impl Default for InputBudget {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl InputBudget {
    pub fn new(limits: Limits) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let identity = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .expect("input session identity exhausted");
        Self {
            identity,
            limits,
            state: Mutex::new(State::default()),
            ast_nodes: AtomicU64::new(0),
            text_bytes: AtomicU64::new(0),
            collection_bytes: AtomicU64::new(0),
            exhausted: AtomicBool::new(false),
            results: AtomicU64::new(0),
            results_exhausted: AtomicBool::new(false),
        }
    }

    /// Snapshot identity for parsed caches; independent scans cannot reuse stale definitions.
    pub fn identity(&self) -> u64 {
        self.identity
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub fn stats(&self) -> InputStats {
        let state = self.state.lock().unwrap();
        InputStats {
            source_bytes: state.source_bytes,
            file_entries: state.file_entries,
            directory_entries: state.directory_entries,
            roots: state.roots,
            arena_bytes: state.arena_bytes,
            ast_nodes: self.ast_nodes.load(Ordering::Relaxed),
            text_bytes: self.text_bytes.load(Ordering::Relaxed),
            collection_bytes: self.collection_bytes.load(Ordering::Relaxed),
            results: self.results.load(Ordering::Relaxed),
        }
    }

    pub fn exhaustion(&self) -> Option<Exhaustion> {
        if !self.exhausted.load(Ordering::Acquire) {
            return None;
        }
        self.state.lock().unwrap().exhaustion
    }

    /// Reserve construction before entering the arena. Chunk admission is separate,
    /// so already-admitted storage needs no global mutex on each node construction.
    pub fn admit_ast_nodes(&self, amount: u64) -> Result<(), Exhaustion> {
        self.admit_atomic(
            &self.ast_nodes,
            Resource::AstNodes,
            self.limits.ast_nodes(),
            amount,
        )
    }

    /// Reserve evaluator text buffers and copied string payload before materialization.
    pub fn admit_text(&self, amount: u64) -> Result<(), Exhaustion> {
        self.admit_atomic(
            &self.text_bytes,
            Resource::TextBytes,
            self.limits.text_bytes(),
            amount,
        )
    }

    pub fn text_refused(&self) -> Exhaustion {
        let mut state = self.state.lock().unwrap();
        self.refuse(&mut state, Resource::TextBytes, self.limits.text_bytes())
    }

    /// Cumulative builtin collection payload reservations, before construction.
    pub fn admit_collection(&self, amount: u64) -> Result<(), Exhaustion> {
        self.admit_atomic(
            &self.collection_bytes,
            Resource::CollectionBytes,
            self.limits.collection_bytes(),
            amount,
        )
    }

    /// One finding or rule error. Refusal is sticky for results only and reported
    /// separately from storage exhaustion; see [`InputBudget::results_exhaustion`].
    pub fn admit_result(&self) -> Result<(), Exhaustion> {
        let allowance = self.limits.results();
        let refused = Exhaustion {
            resource: Resource::Results,
            allowance,
        };
        if self.results_exhausted.load(Ordering::Acquire) {
            return Err(refused);
        }
        let result = self
            .results
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                assert!(used <= allowance);
                (used < allowance).then_some(used + 1)
            });
        match result {
            Ok(used) => {
                assert!(used < allowance);
                Ok(())
            }
            Err(_) => {
                self.results_exhausted.store(true, Ordering::Release);
                Err(refused)
            }
        }
    }

    pub fn results_exhaustion(&self) -> Option<Exhaustion> {
        self.results_exhausted
            .load(Ordering::Acquire)
            .then_some(Exhaustion {
                resource: Resource::Results,
                allowance: self.limits.results(),
            })
    }

    pub fn collection_refused(&self) -> Exhaustion {
        let mut state = self.state.lock().unwrap();
        self.refuse(
            &mut state,
            Resource::CollectionBytes,
            self.limits.collection_bytes(),
        )
    }

    fn admit_atomic(
        &self,
        counter: &AtomicU64,
        resource: Resource,
        allowance: u64,
        amount: u64,
    ) -> Result<(), Exhaustion> {
        if let Some(error) = self.exhaustion() {
            return Err(error);
        }
        if amount == 0 {
            return Ok(());
        }
        let result = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            assert!(used <= allowance);
            (amount <= allowance - used).then(|| used + amount)
        });
        match result {
            Ok(used) => {
                assert!(used + amount <= allowance);
                Ok(())
            }
            Err(_) => {
                let mut state = self.state.lock().unwrap();
                Err(self.refuse(&mut state, resource, allowance))
            }
        }
    }

    /// Serialize chunk admission across arenas. The operation must enforce the supplied
    /// growth ceiling before allocation and return actual chunk growth, even on failure.
    pub fn arena<T>(
        &self,
        operation: impl FnOnce(u64) -> (Option<T>, u64),
    ) -> Result<T, Exhaustion> {
        let mut state = self.state.lock().unwrap();
        if let Some(error) = state.exhaustion {
            return Err(error);
        }
        let remaining = self.limits.arena_bytes() - state.arena_bytes;
        let (result, growth) = operation(remaining);
        assert!(growth <= remaining);
        state.arena_bytes += growth;
        result
            .ok_or_else(|| self.refuse(&mut state, Resource::ArenaBytes, self.limits.arena_bytes()))
    }

    pub fn arena_refused(&self) -> Exhaustion {
        let mut state = self.state.lock().unwrap();
        self.refuse(&mut state, Resource::ArenaBytes, self.limits.arena_bytes())
    }

    /// The owner retains a text/raw snapshot only after this reservation succeeds.
    pub fn admit(&self, bytes: u64) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        self.check_document(&mut state, bytes)?;
        state.source_bytes += bytes;
        state.file_entries += 1;
        assert!(state.source_bytes <= self.limits.source_bytes());
        assert!(state.file_entries <= self.limits.file_entries());
        Ok(())
    }

    pub fn directory_entry(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let used = state.directory_entries;
        self.check(
            &mut state,
            Resource::DirectoryEntries,
            self.limits.directory_entries(),
            used,
            1,
        )?;
        state.directory_entries += 1;
        Ok(())
    }

    pub fn root(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let used = state.roots;
        self.check(&mut state, Resource::Roots, self.limits.roots(), used, 1)?;
        state.roots += 1;
        Ok(())
    }

    pub fn ensure_roots(&self, count: u64) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        let used = state.roots;
        self.check(
            &mut state,
            Resource::Roots,
            self.limits.roots(),
            used,
            count.saturating_sub(used),
        )?;
        state.roots = used.max(count);
        Ok(())
    }

    pub fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        self.read_from(std::fs::File::open(path)?)
    }

    pub fn entries(&self, dir: &Path) -> io::Result<Vec<(std::path::PathBuf, std::fs::FileType)>> {
        self.directory_entry()?;
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            self.directory_entry()?;
            let entry = entry?;
            entries.push((entry.path(), entry.file_type()?));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }

    /// Serialize admission and the bounded read: concurrent readers cannot overbook storage.
    /// One lookahead byte detects growth, including readers without metadata or a known size.
    pub fn read_from(&self, reader: impl Read) -> io::Result<Vec<u8>> {
        let mut state = self.state.lock().unwrap();
        self.check_document(&mut state, 0)?;
        let remaining = self.limits.source_bytes() - state.source_bytes;
        let cap = self.limits.input_bytes().min(remaining);
        let mut bytes = Vec::new();
        reader.take(cap + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > cap {
            let (resource, allowance) = if cap < self.limits.input_bytes() {
                (Resource::SourceBytes, self.limits.source_bytes())
            } else {
                (Resource::InputBytes, self.limits.input_bytes())
            };
            return Err(self.refuse(&mut state, resource, allowance).into());
        }
        state.source_bytes += bytes.len() as u64;
        state.file_entries += 1;
        assert!(state.source_bytes <= self.limits.source_bytes());
        assert!(state.file_entries <= self.limits.file_entries());
        Ok(bytes)
    }

    fn check_document(&self, state: &mut State, bytes: u64) -> Result<(), Exhaustion> {
        self.check(
            state,
            Resource::InputBytes,
            self.limits.input_bytes(),
            0,
            bytes,
        )?;
        self.check(
            state,
            Resource::FileEntries,
            self.limits.file_entries(),
            state.file_entries,
            1,
        )?;
        self.check(
            state,
            Resource::SourceBytes,
            self.limits.source_bytes(),
            state.source_bytes,
            bytes,
        )
    }

    fn check(
        &self,
        state: &mut State,
        resource: Resource,
        allowance: u64,
        used: u64,
        amount: u64,
    ) -> Result<(), Exhaustion> {
        assert!(used <= allowance);
        if let Some(exhaustion) = state.exhaustion {
            return Err(exhaustion);
        }
        if amount > allowance - used {
            return Err(self.refuse(state, resource, allowance));
        }
        Ok(())
    }

    fn refuse(&self, state: &mut State, resource: Resource, allowance: u64) -> Exhaustion {
        if let Some(error) = state.exhaustion {
            return error;
        }
        let exhaustion = Exhaustion {
            resource,
            allowance,
        };
        state.exhaustion = Some(exhaustion);
        self.exhausted.store(true, Ordering::Release);
        exhaustion
    }
}

pub fn exhaustion(error: &io::Error) -> Option<Exhaustion> {
    error.get_ref()?.downcast_ref::<Exhaustion>().copied()
}
