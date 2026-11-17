//! A ceiling on the memory of the `open-db` helper.
//!
//! The helper parses a file that somebody else may have written, with a parser that takes the
//! file at its word. A compressed database unpacks to whatever its contents unpack to, and a
//! megabyte of zeros takes a kilobyte of file. So the helper is not trusted to be careful with
//! memory. The kernel is told how much it may have ([`limit`], which is `RLIMIT_DATA`), before
//! it is given a credential, and an allocation past that fails wherever in the parser it is
//! made.
//!
//! `RLIMIT_DATA` rather than `RLIMIT_AS`: it counts the memory a process can write to (the heap
//! and every private writable mapping, thread stacks among them; since Linux 4.7), which is
//! what can fill RAM. `RLIMIT_AS` also counts address space that is only reserved, and glibc
//! reserves 64 MiB of it for every thread that allocates.
//!
//! A Rust program aborts when an allocation fails. In the helper it should be an answer
//! instead: this database needs more memory than it is given. So the allocator of this binary
//! is the system's with one addition. Once [`limit`] has been called, a refused allocation
//! writes the report it was given to stderr and exits. In the daemon, which sets no limit,
//! nothing differs from the system allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::OnceLock;

/// What a process that ran into its limit writes to stderr before it exits.
static REPORT: OnceLock<&'static [u8]> = OnceLock::new();

/// Lets this process have `bytes` of writable memory and no more, for good: the limit cannot
/// be raised again. A limit it was started under that is lower still stays as it is. From
/// here on an allocation that the kernel refuses ends the process with `report` on stderr and
/// exit status 1.
pub fn limit(bytes: u64, report: &'static [u8]) -> std::io::Result<()> {
    let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    if unsafe { libc::getrlimit(libc::RLIMIT_DATA, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let bytes = bytes.min(limit.rlim_max);
    let limit = libc::rlimit { rlim_cur: bytes, rlim_max: bytes };
    if unsafe { libc::setrlimit(libc::RLIMIT_DATA, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let _ = REPORT.set(report);
    Ok(())
}

/// Makes this process the one the kernel kills first when the machine runs out of memory.
/// The limit keeps the helper from causing that; this is for the case where memory is short
/// anyway, so that it costs an unlock and not a window.
///
/// Call it before `harden::harden_process`: the files under `/proc/self` of a process that is
/// not dumpable belong to root.
pub fn first_to_go() {
    let _ = std::fs::write("/proc/self/oom_score_adj", "1000");
}

/// The system allocator, which in a process under [`limit`] reports a refusal and exits.
pub struct Limited;

fn answer(memory: *mut u8) -> *mut u8 {
    if memory.is_null()
        && let Some(report) = REPORT.get()
    {
        // Nothing here may allocate, lock or unwind. These two calls do none of that.
        unsafe {
            libc::write(2, report.as_ptr().cast(), report.len());
            libc::_exit(1);
        }
    }
    memory
}

unsafe impl GlobalAlloc for Limited {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        answer(unsafe { System.alloc(layout) })
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        answer(unsafe { System.alloc_zeroed(layout) })
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        answer(unsafe { System.realloc(ptr, layout, new_size) })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
