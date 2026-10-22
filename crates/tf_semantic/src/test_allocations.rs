use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

thread_local! {
    static ALLOCATED: Cell<Option<usize>> = const { Cell::new(None) };
}

struct CountAllocations;

// SAFETY: every pointer and layout is forwarded unchanged to System.
unsafe impl GlobalAlloc for CountAllocations {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _ = ALLOCATED.try_with(|count| {
            count.set(count.get().map(|bytes| bytes.saturating_add(layout.size())));
        });
        // SAFETY: the caller supplies the layout required by GlobalAlloc.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the pointer and original layout go to the allocating system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountAllocations = CountAllocations;

pub(crate) fn measure<T>(run: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATED.with(|count| count.set(Some(0)));
    let result = run();
    let bytes = ALLOCATED.with(|count| count.replace(None).unwrap());
    (result, bytes)
}
