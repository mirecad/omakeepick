//! Process hardening for a process that holds decrypted secrets.

/// Disables core dumps and `ptrace`/`/proc/<pid>/mem` access by other processes of the same
/// user. Swap is not prevented (`mlockall` would make Argon2's large allocations fail under the
/// default 8 MiB `RLIMIT_MEMLOCK`); secrets are wiped from memory when the database locks.
pub fn harden_process() {
    unsafe {
        let no_core = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0 {
            eprintln!("omakeepickd: cannot disable core dumps");
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            eprintln!("omakeepickd: cannot mark the process non-dumpable");
        }
    }
}
