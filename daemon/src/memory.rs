//! A ceiling on the memory of the `open-db` helper.
//!
//! The helper parses a file that somebody else may have written, with a parser that takes the
//! file at its word. A compressed database unpacks to whatever its contents unpack to, and a
//! megabyte of zeros takes a kilobyte of file. So the helper is not trusted to be careful with
//! memory. The first thing it does is have the kernel limit what it may have ([`limit`]), to
//! a number that is in the code and that nothing in a file can move. An allocation past that
//! fails wherever in the parser it is made.
//!
//! The limit is `RLIMIT_DATA`, which since Linux 4.7 counts every private mapping a process
//! can write to: the heap, what `mmap` gives the allocator for large blocks, and the stacks of
//! threads. That is what a parser can fill. It does not count the stack of the main thread,
//! which gets a limit of its own here, nor mappings shared with other processes, of which the
//! helper makes none. `RLIMIT_AS` would count address space that is only reserved as well, and
//! glibc reserves 64 MiB of it for every thread that allocates.
//!
//! A Rust program aborts when an allocation fails. In the helper it should be an answer
//! instead: this database needs more memory than it is given. So the allocator of this binary
//! is the system's with one addition. Once [`limit`] has been called, an allocation that the
//! system's allocator refuses makes the process write the report it was given to stderr and
//! exit. (What is refused elsewhere still ends the process, without the report: a thread that
//! glibc cannot give a stack, for one.) In the daemon, which sets no limit, nothing differs
//! from the system allocator.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::OnceLock;

/// What a process that ran into its limit writes to stderr before it exits.
static REPORT: OnceLock<&'static [u8]> = OnceLock::new();

/// What the stack of the main thread may grow to: the usual 8 MiB, in case the session this
/// was started from has no limit on it.
const STACK_BYTES: u64 = 8 << 20;

/// Lets this process have `bytes` of writable memory and no more, for good: the limit cannot
/// be raised again. A limit it was started under that is lower still, soft or hard, stays as
/// it is. From here on an allocation that the system's allocator refuses ends the process with
/// `report` on stderr and exit status 1.
///
/// Fails, and nothing should be parsed then, if the limit cannot be set or the kernel does not
/// hold to it.
pub fn limit(bytes: u64, report: &'static [u8]) -> std::io::Result<()> {
    // First, so that running into a limit the session set is answered the same way.
    let _ = REPORT.set(report);
    let bytes = lower(libc::RLIMIT_DATA, bytes)?;
    lower(libc::RLIMIT_STACK, STACK_BYTES)?;
    if !refuses_more_than(bytes) {
        return Err(std::io::Error::other("this kernel does not enforce RLIMIT_DATA"));
    }
    Ok(())
}

/// Sets both limits of `resource` to `bytes`, or to what they are if that is less. Returns
/// what it set.
fn lower(resource: libc::__rlimit_resource_t, bytes: u64) -> std::io::Result<u64> {
    let mut now = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    if unsafe { libc::getrlimit(resource, &mut now) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let bytes = bytes.min(now.rlim_cur).min(now.rlim_max);
    let limit = libc::rlimit { rlim_cur: bytes, rlim_max: bytes };
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(bytes)
}

/// Whether the kernel says no to a writable mapping of more than `bytes`. A kernel older than
/// 4.7, or one booted with `ignore_rlimit_data`, takes the limit and then does not hold to it.
fn refuses_more_than(bytes: u64) -> bool {
    let Ok(len) = usize::try_from(bytes.saturating_add(4096)) else { return true };
    // Not touched, so nothing is used even where it is granted.
    let granted = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    if granted == libc::MAP_FAILED {
        return true;
    }
    unsafe { libc::munmap(granted, len) };
    false
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
