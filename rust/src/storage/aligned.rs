//! Page-aligned, reusable buffer for Direct IO.
//!
//! O_DIRECT requires the userspace buffer, file offset, and length to be aligned
//! to the device block size (we use 4096, the page size, which is a safe
//! superset for NVMe). This type owns a heap allocation whose start address is
//! guaranteed 4096-aligned, and is meant to be reused across reads/writes to
//! avoid per-IO allocation on the hot path.

use std::alloc::{alloc, dealloc, Layout};
use std::ops::{Deref, DerefMut};

/// Direct-IO alignment (page size). NVMe logical blocks are 512/4096; 4096 is a
/// safe alignment for both buffer address and IO length.
pub const ALIGN: usize = 4096;

/// Default IO buffer size for streaming copies (1 MiB, a multiple of ALIGN).
pub const DEFAULT_BUF_SIZE: usize = 1024 * 1024;

/// A heap buffer whose backing allocation start is `ALIGN`-aligned.
pub struct AlignedBuf {
    ptr: *mut u8,
    cap: usize,
    layout: Layout,
}

// The raw pointer is exclusively owned; sending across threads is safe.
unsafe impl Send for AlignedBuf {}

impl AlignedBuf {
    /// Allocate an aligned buffer. `size` is rounded up to a multiple of `ALIGN`.
    pub fn new(size: usize) -> Self {
        let cap = size.div_ceil(ALIGN) * ALIGN;
        let cap = cap.max(ALIGN);
        let layout = Layout::from_size_align(cap, ALIGN).expect("valid aligned layout");
        // SAFETY: layout has non-zero size and valid alignment.
        let ptr = unsafe { alloc(layout) };
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        AlignedBuf { ptr, cap, layout }
    }

    /// Capacity in bytes (a multiple of `ALIGN`).
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Whether the backing pointer is `ALIGN`-aligned (always true; sanity aid).
    pub fn is_aligned(&self) -> bool {
        (self.ptr as usize).is_multiple_of(ALIGN)
    }
}

impl Deref for AlignedBuf {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: ptr points to `cap` initialized-or-not bytes we own; callers
        // treat this as a scratch buffer (write-then-read within the same op).
        unsafe { std::slice::from_raw_parts(self.ptr, self.cap) }
    }
}

impl DerefMut for AlignedBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: see Deref; we have exclusive &mut access.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.cap) }
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: ptr/layout pair came from the matching alloc() above.
        unsafe { dealloc(self.ptr, self.layout) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_is_aligned() {
        let b = AlignedBuf::new(1000);
        assert!(b.is_aligned());
        // Rounded up to a multiple of ALIGN.
        assert_eq!(b.capacity() % ALIGN, 0);
        assert!(b.capacity() >= 1000);
    }

    #[test]
    fn zero_rounds_to_one_page() {
        let b = AlignedBuf::new(0);
        assert_eq!(b.capacity(), ALIGN);
    }

    #[test]
    fn read_write_through_deref() {
        let mut b = AlignedBuf::new(ALIGN);
        b[0] = 42;
        b[ALIGN - 1] = 7;
        assert_eq!(b[0], 42);
        assert_eq!(b[ALIGN - 1], 7);
    }
}
