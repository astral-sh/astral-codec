use std::alloc::{GlobalAlloc, Layout, System};

// GlobalAlloc's defaults always move a reallocation and explicitly zero a
// zeroed allocation. Keep both costs visible without relying on free heap space.
#[global_allocator]
static ALLOCATOR: BenchAllocator = BenchAllocator;

struct BenchAllocator;

#[expect(
    unsafe_code,
    reason = "GlobalAlloc requires unsafe delegation to System"
)]
// SAFETY: System handles all allocations. Every Layout and pointer is passed
// through unchanged; realloc and alloc_zeroed also use these methods.
unsafe impl GlobalAlloc for BenchAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc callers provide a valid, non-zero-sized layout.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: The pointer was allocated by System with this same layout.
        unsafe { System.dealloc(pointer, layout) }
    }
}
