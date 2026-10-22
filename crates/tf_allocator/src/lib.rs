//! Arena allocator and arena-backed collections, modelled on `oxc_allocator`.
//!
//! All AST nodes for a parse live in one [`Allocator`]. Dropping the
//! allocator frees the whole tree at once; nodes never run destructors, so
//! anything stored in the arena must not own heap memory outside it.

use std::fmt;
use std::ops::{Deref, DerefMut};

use std::sync::Arc;
use tf_limits::input::InputBudget;

pub type AllocResult<T> = Result<T, tf_limits::Exhaustion>;

/// An arena with cumulative admission shared by all parsers in a scan.
#[derive(Default)]
pub struct Allocator {
    bump: bumpalo::Bump,
    budget: Arc<InputBudget>,
}

impl Allocator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_budget(budget: Arc<InputBudget>) -> Self {
        Self {
            bump: bumpalo::Bump::new(),
            budget,
        }
    }

    pub fn budget(&self) -> &InputBudget {
        &self.budget
    }

    /// Existing chunk space is already admitted; only growth needs the scan mutex.
    fn allocate<T>(
        &self,
        nodes: u64,
        fits: bool,
        operation: impl FnOnce() -> Option<T>,
    ) -> AllocResult<T> {
        self.budget.admit_ast_nodes(nodes)?;
        let before = self.bump.allocated_bytes();
        if fits {
            self.bump.set_allocation_limit(Some(before));
            let result = operation();
            assert_eq!(self.bump.allocated_bytes(), before);
            return result.ok_or_else(|| self.budget.arena_refused());
        }
        self.budget.arena(|remaining| {
            let remaining = usize::try_from(remaining).unwrap_or(usize::MAX);
            self.bump
                .set_allocation_limit(Some(before.saturating_add(remaining)));
            let result = operation();
            let after = self.bump.allocated_bytes();
            assert!(after >= before);
            (result, (after - before) as u64)
        })
    }

    #[inline]
    pub fn alloc<T>(&self, value: T) -> AllocResult<&mut T> {
        let fits = std::mem::size_of::<T>()
            .checked_add(std::mem::align_of::<T>() - 1)
            .is_some_and(|required| required <= self.bump.chunk_capacity());
        self.allocate(1, fits, || self.bump.try_alloc(value).ok())
    }

    #[inline]
    pub fn alloc_str<'a>(&'a self, s: &str) -> AllocResult<&'a str> {
        self.allocate(0, s.len() <= self.bump.chunk_capacity(), || {
            self.bump.try_alloc_str(s).ok().map(|s| &*s)
        })
    }

    /// Chunk payload capacity, including unused space and abandoned vector buffers.
    /// Bump metadata and the global allocator's overhead are excluded.
    pub fn allocated_bytes(&self) -> usize {
        self.bump.allocated_bytes()
    }

    pub fn used_bytes(&self) -> usize {
        // SAFETY: no allocation occurs while the iterator is alive; only lengths are read.
        unsafe {
            self.bump
                .iter_allocated_chunks_raw()
                .map(|(_, len)| len)
                .sum()
        }
    }

    /// Reset storage without refunding cumulative scan admission or clearing exhaustion.
    pub fn reset(&mut self) {
        self.bump.reset();
    }
}

/// An arena-owned box: a thin `&'a mut T`, 8 bytes, no destructor.
pub struct Box<'a, T: ?Sized>(&'a mut T);

impl<'a, T> Box<'a, T> {
    #[inline]
    pub fn new_in(value: T, allocator: &'a Allocator) -> AllocResult<Self> {
        allocator.alloc(value).map(Box)
    }
}

impl<T: ?Sized> AsRef<T> for Box<'_, T> {
    #[inline]
    fn as_ref(&self) -> &T {
        self.0
    }
}

impl<T: ?Sized> Deref for Box<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        self.0
    }
}

impl<T: ?Sized> DerefMut for Box<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        self.0
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for Box<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<T: ?Sized + PartialEq> PartialEq for Box<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        *self.0 == *other.0
    }
}

/// An arena-backed growable vector.
pub struct Vec<'a, T> {
    inner: bumpalo::collections::Vec<'a, T>,
    allocator: &'a Allocator,
}

impl<'a, T> Vec<'a, T> {
    #[inline]
    pub fn new_in(allocator: &'a Allocator) -> Self {
        Self {
            inner: bumpalo::collections::Vec::new_in(&allocator.bump),
            allocator,
        }
    }

    pub fn push(&mut self, value: T) -> AllocResult<()> {
        self.allocator
            .allocate(1, self.inner.len() < self.inner.capacity(), || {
                self.inner.try_reserve(1).ok()?;
                assert!(self.inner.len() < self.inner.capacity());
                self.inner.push(value);
                Some(())
            })
    }

    pub fn extend(&mut self, values: impl IntoIterator<Item = T>) -> AllocResult<()> {
        for value in values {
            self.push(value)?;
        }
        Ok(())
    }

    pub fn drain<R: std::ops::RangeBounds<usize>>(
        &mut self,
        range: R,
    ) -> bumpalo::collections::vec::Drain<'_, 'a, T> {
        self.inner.drain(range)
    }

    pub fn pop(&mut self) -> Option<T> {
        self.inner.pop()
    }
    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }
    pub fn remove(&mut self, index: usize) -> T {
        self.inner.remove(index)
    }
    pub fn clear(&mut self) {
        self.inner.clear();
    }
    pub fn retain(&mut self, f: impl FnMut(&T) -> bool) {
        self.inner.retain(f);
    }
}

impl<T> Deref for Vec<'_, T> {
    type Target = [T];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T> DerefMut for Vec<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<'a, T> IntoIterator for &'a Vec<'_, T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Vec<'_, T> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter_mut()
    }
}

impl<T: fmt::Debug> fmt::Debug for Vec<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.inner.iter()).finish()
    }
}

impl<T: PartialEq> PartialEq for Vec<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.inner[..] == other.inner[..]
    }
}

/// An interned-ish string slice living in the arena (or the source text).
/// 16 bytes. Mirrors `oxc_span::Atom`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Atom<'a>(&'a str);

impl<'a> Atom<'a> {
    pub const EMPTY: Atom<'static> = Atom("");

    #[inline]
    pub fn as_str(&self) -> &'a str {
        self.0
    }

    #[inline]
    pub fn from_in(s: &str, allocator: &'a Allocator) -> AllocResult<Self> {
        allocator.alloc_str(s).map(Atom)
    }
}

impl<'a> From<&'a str> for Atom<'a> {
    #[inline]
    fn from(s: &'a str) -> Self {
        Atom(s)
    }
}

impl Deref for Atom<'_> {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        self.0
    }
}

impl fmt::Debug for Atom<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0, f)
    }
}

impl fmt::Display for Atom<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl PartialEq<str> for Atom<'_> {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Atom<'_> {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(std::mem::size_of::<Box<'_, u64>>(), 8);
        assert_eq!(std::mem::size_of::<Atom<'_>>(), 16);
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use tf_limits::{Limits, Resource};

    fn arena(limits: Limits) -> Allocator {
        Allocator::with_budget(Arc::new(InputBudget::new(limits)))
    }

    #[test]
    fn boxed_values_and_vector_entries_share_the_node_allowance() {
        let allocator = arena(Limits::default().with_ast_nodes(3).unwrap());
        assert_eq!(allocator.allocated_bytes(), 0);
        assert_eq!(*Box::new_in(7u64, &allocator).unwrap(), 7);
        let mut values = Vec::new_in(&allocator);
        values.push(1u64).unwrap();
        values.push(2u64).unwrap();
        assert_eq!(allocator.alloc_str("payload").unwrap(), "payload");
        let before = allocator.budget().stats();
        let failure = values.push(3).unwrap_err();
        assert_eq!(failure.resource, Resource::AstNodes);
        assert_eq!(&*values, &[1, 2]);
        assert_eq!(allocator.budget().stats(), before);
        assert_eq!(allocator.alloc_str(""), Err(failure));
        assert_eq!(allocator.alloc(0u8).unwrap_err(), failure);
    }

    #[test]
    fn refusal_does_not_allocate_a_chunk_or_an_error_placeholder() {
        let allocator = arena(Limits::default().with_arena_bytes(1).unwrap());
        let error = allocator.alloc(42u64).unwrap_err();
        assert_eq!(error.resource, Resource::ArenaBytes);
        assert_eq!(allocator.allocated_bytes(), 0);
        assert_eq!(allocator.budget().stats().arena_bytes, 0);
        assert_eq!(allocator.budget().stats().ast_nodes, 1);
    }

    #[test]
    fn chunks_are_admitted_across_concurrent_arenas() {
        let probe = Allocator::new();
        probe.alloc(0u64).unwrap();
        let cap = probe.allocated_bytes() as u64;
        let budget = Arc::new(InputBudget::new(
            Limits::default().with_arena_bytes(cap).unwrap(),
        ));
        let barrier = std::sync::Barrier::new(8);
        let results = std::thread::scope(|scope| {
            let handles: std::vec::Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let allocator = Allocator::with_budget(budget.clone());
                        barrier.wait();
                        let accepted = allocator.alloc(0u64).is_ok();
                        (accepted, allocator.allocated_bytes())
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<std::vec::Vec<_>>()
        });
        assert_eq!(results.iter().filter(|(ok, _)| *ok).count(), 1);
        assert_eq!(
            results.iter().map(|(_, bytes)| *bytes as u64).sum::<u64>(),
            cap
        );
        assert_eq!(budget.stats().arena_bytes, cap);
        assert_eq!(budget.exhaustion().unwrap().resource, Resource::ArenaBytes);
    }

    #[test]
    fn concurrent_construction_in_admitted_space_cannot_overbook_nodes() {
        let budget = Arc::new(InputBudget::new(
            Limits::default().with_ast_nodes(4).unwrap(),
        ));
        let barrier = std::sync::Barrier::new(8);
        let accepted = std::thread::scope(|scope| {
            let handles: std::vec::Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        let allocator = Allocator::with_budget(budget.clone());
                        barrier.wait();
                        allocator.alloc(()).is_ok()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .filter(|ok| *ok)
                .count()
        });
        assert_eq!(accepted, 4);
        assert_eq!(budget.stats().ast_nodes, 4);
        assert_eq!(budget.exhaustion().unwrap().resource, Resource::AstNodes);
    }

    #[test]
    fn admitted_chunk_space_cannot_hide_an_input_refusal() {
        let budget = Arc::new(InputBudget::new(
            Limits::default().with_source_bytes(1).unwrap(),
        ));
        let allocator = Allocator::with_budget(budget.clone());
        allocator.alloc(0u8).unwrap();
        let error = tf_limits::input::exhaustion(&budget.admit(2).unwrap_err()).unwrap();
        assert_eq!(allocator.alloc(0u8).unwrap_err(), error);
        assert_eq!(allocator.alloc_str("").unwrap_err(), error);
        assert_eq!(budget.stats().ast_nodes, 1);
    }

    #[test]
    fn reset_and_zero_sized_values_cannot_bypass_cumulative_admission() {
        let mut allocator = arena(Limits::default().with_ast_nodes(3).unwrap());
        allocator.alloc(()).unwrap();
        allocator.reset();
        let mut values = Vec::new_in(&allocator);
        assert!(values.extend(std::iter::repeat_n((), 100)).is_err());
        assert_eq!(values.len(), 2);
        assert_eq!(allocator.budget().stats().ast_nodes, 3);
        drop(values);
        allocator.reset();
        assert!(allocator.alloc(()).is_err());
    }
}
