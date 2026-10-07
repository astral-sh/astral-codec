use std::alloc::{GlobalAlloc, Layout, System};

// Use GlobalAlloc's default realloc: always allocate, copy, and free.
// This keeps buffer growth visible without depending on the heap's free space.
#[global_allocator]
static ALLOCATOR: BenchAllocator = BenchAllocator;

struct BenchAllocator;

#[expect(
    unsafe_code,
    reason = "GlobalAlloc requires unsafe delegation to System"
)]
// SAFETY: System handles all allocations. Every Layout and pointer is passed
// through unchanged; the default realloc also uses these alloc/dealloc methods.
unsafe impl GlobalAlloc for BenchAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc callers provide a valid, non-zero-sized layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc callers provide a valid, non-zero-sized layout.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The pointer was allocated by System with this same layout.
        unsafe { System.dealloc(pointer, layout) }
    }
}
