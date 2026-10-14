//! Arena allocator and arena-backed collections, modelled on `oxc_allocator`.
//!
//! All AST nodes for a parse live in one [`Allocator`]. Dropping the
//! allocator frees the whole tree at once; nodes never run destructors, so
//! anything stored in the arena must not own heap memory outside it.

use std::fmt;
use std::ops::{Deref, DerefMut};

pub use bumpalo::collections::String as ArenaString;

/// The arena. Wraps `bumpalo::Bump`.
#[derive(Default)]
pub struct Allocator {
    bump: bumpalo::Bump,
}

impl Allocator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(bytes: usize) -> Self {
        Self { bump: bumpalo::Bump::with_capacity(bytes) }
    }

    #[inline]
    pub fn bump(&self) -> &bumpalo::Bump {
        &self.bump
    }

    #[inline]
    pub fn alloc<T>(&self, value: T) -> &mut T {
        self.bump.alloc(value)
    }

    #[inline]
    pub fn alloc_str<'a>(&'a self, s: &str) -> &'a str {
        self.bump.alloc_str(s)
    }

    /// Bytes currently allocated in the arena.
    pub fn allocated_bytes(&self) -> usize {
        self.bump.allocated_bytes()
    }

    pub fn reset(&mut self) {
        self.bump.reset();
    }
}

/// An arena-owned box: a thin `&'a mut T`, 8 bytes, no destructor.
pub struct Box<'a, T: ?Sized>(&'a mut T);

impl<'a, T> Box<'a, T> {
    #[inline]
    pub fn new_in(value: T, allocator: &'a Allocator) -> Self {
        Box(allocator.bump.alloc(value))
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
pub struct Vec<'a, T>(bumpalo::collections::Vec<'a, T>);

impl<'a, T> Vec<'a, T> {
    #[inline]
    pub fn new_in(allocator: &'a Allocator) -> Self {
        Vec(bumpalo::collections::Vec::new_in(&allocator.bump))
    }

    #[inline]
    pub fn with_capacity_in(cap: usize, allocator: &'a Allocator) -> Self {
        Vec(bumpalo::collections::Vec::with_capacity_in(cap, &allocator.bump))
    }

    pub fn from_iter_in<I: IntoIterator<Item = T>>(iter: I, allocator: &'a Allocator) -> Self {
        Vec(bumpalo::collections::Vec::from_iter_in(iter, &allocator.bump))
    }

    /// Freeze into an arena slice.
    pub fn into_bump_slice(self) -> &'a [T] {
        self.0.into_bump_slice()
    }
}

impl<'a, T> Deref for Vec<'a, T> {
    type Target = bumpalo::collections::Vec<'a, T>;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Vec<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<'a, T> IntoIterator for &'a Vec<'_, T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Vec<'_, T> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter_mut()
    }
}

impl<T: fmt::Debug> fmt::Debug for Vec<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

impl<T: PartialEq> PartialEq for Vec<'_, T> {
    fn eq(&self, other: &Self) -> bool {
        self.0[..] == other.0[..]
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
    pub fn from_in(s: &str, allocator: &'a Allocator) -> Self {
        Atom(allocator.alloc_str(s))
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

    #[test]
    fn vec_push() {
        let a = Allocator::new();
        let mut v = Vec::new_in(&a);
        v.push(1);
        v.push(2);
        assert_eq!(&v[..], &[1, 2]);
    }
}
