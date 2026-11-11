//! Opening a database in a child process that can be killed.
//!
//! Two things in an unlock cannot be interrupted from inside the process that does them. A key
//! derivation runs until it is done: seconds, or as long as the file's header says. A file read
//! returns when the file system answers: a network mount that went away answers never. A thread
//! of the daemon stuck in either one while it holds the master password would keep it in RAM,
//! and so in a hibernation image, past the point where logind stops waiting for the lock.
//!
//! So the daemon does neither. It runs `omakeepickd open-db`, a fresh exec of its own binary,
//! and the two of them keep to an order in which nobody waits on a file with a credential in
//! hand:
//!
//! 1. The daemon sends the paths of the database and the key file. Nothing secret.
//! 2. The child reads both files, checks the database header, and answers with the database
//!    file's stamp. This is the only step that touches the file system.
//! 3. Only then does the daemon send the credentials. Until that moment they are in an async
//!    task of the daemon, which a lock drops and wipes at once, whatever the child is stuck in.
//! 4. The child derives the key, decrypts, and hands the database back together with the
//!    credentials it ended up using (the password plus the key file it read). From step 3 on
//!    it works in memory and on its two pipes only, so `SIGKILL` always ends it promptly.
//!
//! A lock, suspend, `quit` or a timeout kills the child at any step and the daemon waits for
//! it to be reaped, which returns every page it held to the kernel before the sleep inhibitor
//! is released. A child that the kernel will not kill is one stuck in step 2. It has been
//! given nothing, and holds at most what it has read of the two files, which the kernel's
//! page cache holds as well. The daemon stops waiting for such a child after a moment. After
//! step 2 the child has no file open, so neither its work nor its exit can hang. The child
//! dies with the daemon as well (`PR_SET_PDEATHSIG`), and a parser panic on a hostile file
//! takes down the child, not the daemon.
//!
//! The `keepass` crate can only load a database from KDBX bytes, so the child hands the
//! decrypted database back as one: re-encrypted under a random one-time key with a one-round
//! KDF. That key and the credentials travel on the same pipe, ahead of the data; a pipe is
//! kernel memory shared by nothing but these two processes.
//!
//! Taking that hand-over apart is the one piece of work on the database that the daemon does
//! itself, on a thread that a lock cannot stop. So its size is not left to the file either.
//! The child first takes out what the daemon never uses (attachments, the earlier versions of
//! entries, icons), writes the rest uncompressed, and refuses to hand over more than
//! [`MAX_HANDOVER_DATABASE_BYTES`]. An ordinary database is a few hundred kilobytes by then
//! and is taken apart in milliseconds; one at the limit takes about two thirds of a second.

use std::ffi::OsString;
use std::fs::File;
use std::future::Future;
use std::io::{Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};

use keepass::config::{CompressionConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig};
use keepass::{Database, DatabaseKey};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::harden;
use crate::vault::{self, KeyMaterial, Stamp, VaultError};

const SECRET_LEN: usize = 32;

/// What the child reports on stderr when it fails: the error's code and message, so the
/// daemon can rebuild the `VaultError` the in-process open would have returned.
#[derive(Serialize, Deserialize)]
struct WireError {
    code: String,
    message: String,
}

impl From<&VaultError> for WireError {
    fn from(err: &VaultError) -> Self {
        let message = match err {
            // The path, not the fixed display text: the daemon rebuilds the variant from it.
            VaultError::NotFound(path) => path.to_string_lossy().into_owned(),
            VaultError::BadRequest(m)
            | VaultError::Keyfile(m)
            | VaultError::Format(m)
            | VaultError::Io(m) => m.clone(),
            VaultError::BadCredentials => String::new(),
        };
        WireError { code: err.code().to_string(), message }
    }
}

impl WireError {
    fn into_error(self) -> Option<VaultError> {
        Some(match self.code.as_str() {
            "bad_request" => VaultError::BadRequest(self.message),
            "not_found" => VaultError::NotFound(PathBuf::from(self.message)),
            "bad_credentials" => VaultError::BadCredentials,
            "keyfile_error" => VaultError::Keyfile(self.message),
            "format_error" => VaultError::Format(self.message),
            "failed" => VaultError::Io(self.message),
            _ => return None,
        })
    }
}

/// Longest path the child accepts in a request. Linux stops at 4096.
const MAX_PATH_BYTES: usize = 64 << 10;
/// Most the child accepts as credentials: a password and a key file, which `vault` caps at
/// 16 MiB.
const MAX_CREDENTIAL_BYTES: usize = 32 << 20;

/// Most the child hands over as the database, and so the most the daemon ever has to take
/// apart on a thread of its own. What that costs goes by the entries more than by the bytes:
/// about fifteen milliseconds for a thousand of them. Without attachments and histories an
/// ordinary entry is under a kilobyte here, so this is some forty thousand entries and about
/// two thirds of a second.
pub const MAX_HANDOVER_DATABASE_BYTES: usize = 32 << 20;

/// The whole hand-over: `[len32][key material][one-time key][database]`.
const MAX_HANDOVER_BYTES: usize = 4 + MAX_CREDENTIAL_BYTES + SECRET_LEN + MAX_HANDOVER_DATABASE_BYTES;

const TOO_LARGE: &str =
    "The database is too large: more than 32 MiB even without its attachments and entry histories";

/// `[len32][database path][len32][key file path]`: the first thing the daemon writes to the
/// child's stdin. An empty key file path means there is none. No secrets.
fn encode_request(path: &Path, keyfile: Option<&Path>) -> Vec<u8> {
    let path = path.as_os_str().as_bytes();
    let keyfile = keyfile.map_or(&[][..], |k| k.as_os_str().as_bytes());
    let mut out = Vec::with_capacity(8 + path.len() + keyfile.len());
    for part in [path, keyfile] {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// Reads exactly one request and nothing after it: the credentials follow on the same pipe,
/// later.
fn read_request(input: &mut impl Read) -> std::io::Result<(PathBuf, Option<PathBuf>)> {
    let mut part = || -> std::io::Result<PathBuf> {
        let mut len = [0u8; 4];
        input.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        if len > MAX_PATH_BYTES {
            return Err(std::io::Error::other("the path is too long"));
        }
        let mut bytes = vec![0u8; len];
        input.read_exact(&mut bytes)?;
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    };
    let path = part()?;
    let keyfile = part()?;
    Ok((path, (!keyfile.as_os_str().is_empty()).then_some(keyfile)))
}

fn hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Re-encrypts `db` as KDBX 4 under a fresh random key with a one-round KDF, without what the
/// daemon does not use and without compression, so that its size is the work it will be to
/// read. Returns `[len32][key material][one-time key][file bytes]`: what [`Handover::unseal`]
/// takes apart.
fn seal(mut db: Database, key: &KeyMaterial) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    vault::strip(&mut db);
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    getrandom::fill(secret.as_mut()).map_err(|e| VaultError::Io(format!("No randomness: {e}")))?;
    db.config.version = DatabaseVersion::KDB4(1);
    db.config.kdf_config = KdfConfig::Aes { rounds: 1 };
    db.config.outer_cipher_config = OuterCipherConfig::ChaCha20;
    db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    db.config.compression_config = CompressionConfig::None;
    let key = key.to_bytes();
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(&key);
    out.extend_from_slice(secret.as_ref());
    let database_at = out.len();
    db.save(&mut *out, DatabaseKey::new().with_password(&hex(secret.as_ref())))
        .map_err(|e| VaultError::Io(format!("Cannot hand over the database: {e}")))?;
    if out.len() - database_at > MAX_HANDOVER_DATABASE_BYTES {
        return Err(VaultError::Format(TOO_LARGE.into()));
    }
    Ok(out)
}

const INCOMPLETE: &str = "The database helper stopped before handing over the database";

/// What the child handed over: the decrypted database, sealed for the trip, and the
/// credentials that open the real file.
pub struct Handover(Zeroizing<Vec<u8>>);

impl Handover {
    /// Opens what [`seal`] produced. Parsing of a bounded size: milliseconds as a rule, about
    /// two thirds of a second at the limit. Run it on a blocking thread.
    pub fn unseal(self) -> Result<(Database, KeyMaterial), VaultError> {
        let incomplete = || VaultError::Io(INCOMPLETE.into());
        let (len, rest) = self.0.split_at_checked(4).ok_or_else(incomplete)?;
        let len = u32::from_le_bytes(len.try_into().expect("4 bytes")) as usize;
        let (key, rest) = rest.split_at_checked(len).ok_or_else(incomplete)?;
        let key = KeyMaterial::from_bytes(key).ok_or_else(incomplete)?;
        let (secret, data) = rest.split_at_checked(SECRET_LEN).ok_or_else(incomplete)?;
        let db = Database::parse(data, DatabaseKey::new().with_password(&hex(secret)))
            .map_err(|e| VaultError::Io(format!("Cannot take over the database: {e}")))?;
        Ok((db, key))
    }
}

/// Test hook: with the environment variable `name` set to a FIFO, the child blocks there until
/// something writes to it. `OMAKEEPICK_TEST_HOLD_READ` stands in for a file read that hangs,
/// `OMAKEEPICK_TEST_HOLD_KDF` for a long derivation. Debug builds only.
fn test_hold(name: &str) {
    #[cfg(debug_assertions)]
    if let Some(fifo) = std::env::var_os(name) {
        let _ = std::fs::read(fifo);
    }
    #[cfg(not(debug_assertions))]
    let _ = name;
}

/// `omakeepickd open-db`: the child. Speaks the protocol in the module documentation on stdin
/// and stdout; a failure is a JSON [`WireError`] on stderr with exit status 1.
pub fn open_db_main() -> ExitCode {
    // No core dumps, no ptrace by our other processes.
    harden::harden_process();
    unsafe {
        // Die with the daemon, so a derivation never outlives the process that asked for it.
        // Set before stdin is read: if the daemon is already gone, the pipe is closed and
        // nothing ever arrives.
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        // Started as /proc/self/exe, which ps and top would list as "exe".
        libc::prctl(libc::PR_SET_NAME, c"omakeepickd".as_ptr(), 0, 0, 0);
    }
    match serve_request() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let wire = serde_json::to_string(&WireError::from(&err)).unwrap_or_default();
            let _ = writeln!(std::io::stderr(), "{wire}");
            ExitCode::FAILURE
        }
    }
}

fn serve_request() -> Result<(), VaultError> {
    let io = |what: &'static str| move |e: std::io::Error| VaultError::Io(format!("{what}: {e}"));
    // The two pipes themselves, unbuffered: std's stdin and stdout keep what passes through
    // them in buffers of their own, which nothing wipes, and a buffered stdin would read ahead.
    let mut stdin = ManuallyDrop::new(unsafe { File::from_raw_fd(0) });
    let mut stdout = ManuallyDrop::new(unsafe { File::from_raw_fd(1) });
    let (path, keyfile) = read_request(&mut *stdin).map_err(io("Cannot read the request"))?;

    // Everything that touches the file system happens here, and it can take as long as the
    // file system likes. This process has not been given a credential yet. Both files are
    // opened, read and closed in this step, so that nothing is left for later, exit included,
    // that could hang. The key file comes last: it is the one whose contents are a secret.
    test_hold("OMAKEEPICK_TEST_HOLD_READ");
    let (data, stamp) = vault::read_database(&path)?;
    vault::check_header(&data)?;
    let keyfile = keyfile.as_deref().map(vault::read_keyfile).transpose()?;
    stdout.write_all(&stamp.to_bytes()).map_err(io("Cannot answer"))?;

    // The daemon sends the credentials once it has seen the stamp: `[len32][key material]`.
    // From here on this process only computes and uses its pipes, so a SIGKILL ends it at once.
    let mut len = [0u8; 4];
    stdin.read_exact(&mut len).map_err(io("Cannot read the credentials"))?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_CREDENTIAL_BYTES {
        return Err(VaultError::Io("Malformed credentials".into()));
    }
    // Sized up front, so the buffer never grows and leaves copies behind.
    let mut credentials = Zeroizing::new(vec![0u8; len]);
    stdin.read_exact(&mut credentials).map_err(io("Cannot read the credentials"))?;
    let key = KeyMaterial::from_bytes(&credentials)
        .ok_or_else(|| VaultError::Io("Malformed credentials".into()))?;
    drop(credentials);
    let key = match keyfile {
        Some(keyfile) => key.with_keyfile(keyfile),
        None => key,
    };
    if key.is_empty() {
        return Err(VaultError::no_credentials());
    }
    test_hold("OMAKEEPICK_TEST_HOLD_KDF");
    let db = vault::parse_database(&data, &key)?;
    drop(data);
    let sealed = seal(db, &key)?;
    drop(key);
    stdout
        .write_all(&(sealed.len() as u64).to_le_bytes())
        .and_then(|()| stdout.write_all(&sealed))
        .map_err(io("Cannot hand over the database"))
}

/// A running `open-db` child, as the daemon sees it.
pub struct Opener {
    child: Child,
    /// Open until the credentials are sent.
    stdin: Option<ChildStdin>,
    /// Whether the credentials were sent, or were being sent.
    given: bool,
    /// Resolves when the child has read the files.
    ready: Option<oneshot::Receiver<Stamp>>,
    stamp: Option<Stamp>,
    stdout: Option<JoinHandle<std::io::Result<Zeroizing<Vec<u8>>>>>,
    stderr: Option<JoinHandle<Vec<u8>>>,
}

impl Opener {
    /// Starts `exe open-db` and tells it which files to read. It is given no credential here:
    /// that is [`decrypt`](Self::decrypt), after the files are read. The daemon passes
    /// `/proc/self/exe`; tests pass the built binary.
    pub async fn spawn(exe: &Path, path: &Path, keyfile: Option<&Path>) -> Result<Opener, VaultError> {
        let failed = |e: std::io::Error| VaultError::Io(format!("Cannot start the database helper: {e}"));
        let mut child = Command::new(exe)
            .arg0("omakeepickd")
            .arg("open-db")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Backstop: a dropped Opener (a task that ended some other way) still kills it.
            .kill_on_drop(true)
            .spawn()
            .map_err(failed)?;
        let mut stdin = child.stdin.take().expect("piped");
        let mut out = child.stdout.take().expect("piped");
        let err = child.stderr.take().expect("piped");
        let (files_read, ready) = oneshot::channel();
        // Both pipes are drained while waiting, so a large database cannot fill one and stall.
        let stdout = tokio::spawn(async move {
            let mut stamp = [0u8; Stamp::BYTES];
            out.read_exact(&mut stamp).await?;
            let _ = files_read.send(Stamp::from_bytes(&stamp));
            // The hand-over says how long it is, so its buffer never has to grow: growing
            // would leave copies of the credentials behind in freed memory.
            let len = usize::try_from(out.read_u64_le().await?).map_err(std::io::Error::other)?;
            if len > MAX_HANDOVER_BYTES {
                // Not from our helper, which stops at the limit itself.
                return Err(std::io::Error::other("the hand-over is longer than a helper makes it"));
            }
            let mut sealed = Zeroizing::new(Vec::new());
            sealed.try_reserve_exact(len).map_err(std::io::Error::other)?;
            sealed.resize(len, 0);
            out.read_exact(&mut sealed).await?;
            Ok(sealed)
        });
        let stderr = tokio::spawn(async move {
            let mut buf = Vec::new();
            let _ = err.take(64 << 10).read_to_end(&mut buf).await;
            buf
        });
        let mut opener = Opener {
            child,
            stdin: None,
            given: false,
            ready: Some(ready),
            stamp: None,
            stdout: Some(stdout),
            stderr: Some(stderr),
        };
        if let Err(e) = stdin.write_all(&encode_request(path, keyfile)).await {
            opener.kill().await;
            return Err(failed(e));
        }
        opener.stdin = Some(stdin);
        Ok(opener)
    }

    /// Waits until the child has read the database and the key file, and returns the database
    /// file's stamp. This is the wait that can take forever. Whoever waits here must be able
    /// to drop the credentials meanwhile; the child has none.
    pub async fn read(&mut self) -> Result<Stamp, VaultError> {
        if let Some(ready) = self.ready.as_mut() {
            let stamp = ready.await;
            self.ready = None;
            match stamp {
                Ok(stamp) => self.stamp = Some(stamp),
                // It ended without the stamp: it could not read a file, or refused the header.
                Err(_) => return Err(self.failure().await),
            }
        }
        self.stamp.ok_or_else(|| VaultError::Io(INCOMPLETE.into()))
    }

    /// Gives the child the credentials and waits for the database. Never before the files are
    /// read: this waits for [`read`](Self::read) first if the caller has not.
    pub async fn decrypt(&mut self, key: KeyMaterial) -> Result<Handover, VaultError> {
        self.read().await?;
        let Some(mut stdin) = self.stdin.take() else {
            return Err(VaultError::Io(INCOMPLETE.into()));
        };
        let credentials = key.to_bytes();
        drop(key);
        self.given = true;
        // If the child is gone already these fail, and `failure` below says why it went.
        let _ = stdin.write_all(&(credentials.len() as u32).to_le_bytes()).await;
        let _ = stdin.write_all(&credentials).await;
        let _ = stdin.shutdown().await;
        drop((credentials, stdin));
        let sealed = match self.stdout.as_mut() {
            Some(reader) => {
                let sealed = reader.await;
                self.stdout = None;
                match sealed {
                    Ok(Ok(sealed)) => Some(sealed),
                    // The child is still there, but nobody reads what it writes any more (the
                    // hand-over did not fit in memory, say). The caller kills it.
                    Ok(Err(e)) if e.kind() != std::io::ErrorKind::UnexpectedEof => {
                        return Err(VaultError::Io(format!("Cannot take over the database: {e}")));
                    }
                    // It closed its end early: it ended, and `failure` says how.
                    _ => None,
                }
            }
            None => None,
        };
        if let (Ok(status), Some(sealed)) = (self.child.wait().await, sealed)
            && status.success()
        {
            return Ok(Handover(sealed));
        }
        Err(self.failure().await)
    }

    /// Why the child ended without doing its job: what it reported, or else how it ended.
    async fn failure(&mut self) -> VaultError {
        self.stdin = None; // should it still be waiting for something, it now sees EOF
        let status = self.child.wait().await;
        let stderr = match self.stderr.as_mut() {
            Some(reader) => {
                let stderr = reader.await;
                self.stderr = None;
                stderr.unwrap_or_default()
            }
            None => Vec::new(),
        };
        // Its report is the last line; anything a library printed before it is not.
        let reported = stderr
            .split(|b| *b == b'\n')
            .rev()
            .find_map(|line| serde_json::from_slice::<WireError>(line).ok())
            .and_then(WireError::into_error);
        reported.unwrap_or_else(|| match status {
            // Killed, or a parser panic (which aborts) on a file the header check let through.
            Ok(status) if !status.success() => {
                VaultError::Io(format!("The database helper stopped unexpectedly ({status})"))
            }
            Ok(_) => VaultError::Io(INCOMPLETE.into()),
            Err(e) => VaultError::Io(format!("Database helper: {e}")),
        })
    }

    /// Kills the child right now. The returned future resolves once it is reaped, so its
    /// memory is back with the kernel, and once whatever the daemon had read from it is wiped.
    /// That is prompt unless the kernel cannot interrupt a file read the child is stuck in,
    /// which is before it was given the credentials.
    pub fn kill(mut self) -> impl Future<Output = ()> + Send {
        let _ = self.child.start_kill();
        self.stdin = None;
        if let Some(reader) = &self.stdout {
            reader.abort();
        }
        if let Some(reader) = &self.stderr {
            reader.abort();
        }
        async move {
            if let Some(reader) = self.stdout.take() {
                let _ = reader.await;
            }
            if let Some(reader) = self.stderr.take() {
                let _ = reader.await;
            }
            let _ = self.child.wait().await;
        }
    }

    /// Whether the child was given the credentials. If not, all it can hold is what it read
    /// from the two files.
    pub fn was_given_credentials(&self) -> bool {
        self.given
    }

    /// The child's process id, for tests.
    pub fn id(&self) -> Option<u32> {
        self.child.id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let path = PathBuf::from(OsString::from_vec(b"/v\xff/Secrets.kdbx".to_vec()));
        let keyfile = Path::new("/media/usb/key.keyx");
        // The credentials come later on the same pipe: reading the request must leave them be.
        let mut stream = encode_request(&path, Some(keyfile));
        stream.extend_from_slice(b"later");
        let mut input = &stream[..];
        assert_eq!(read_request(&mut input).unwrap(), (path.clone(), Some(keyfile.to_path_buf())));
        assert_eq!(input, b"later");

        let mut input = &encode_request(&path, None)[..];
        assert_eq!(read_request(&mut input).unwrap(), (path, None));
        assert!(read_request(&mut &[9, 0, 0, 0, 1][..]).is_err());
        assert!(read_request(&mut &u32::MAX.to_le_bytes()[..]).is_err());
    }

    #[test]
    fn errors_survive_the_wire() {
        for err in [
            VaultError::BadRequest("x".into()),
            VaultError::NotFound(PathBuf::from("/a/b.kdbx")),
            VaultError::BadCredentials,
            VaultError::Keyfile("k".into()),
            VaultError::Format("f".into()),
            VaultError::Io("i".into()),
        ] {
            let wire: WireError =
                serde_json::from_str(&serde_json::to_string(&WireError::from(&err)).unwrap()).unwrap();
            assert_eq!(wire.into_error(), Some(err));
        }
        assert!(WireError { code: "nope".into(), message: String::new() }.into_error().is_none());
    }

    #[test]
    fn unseal_rejects_incomplete_input() {
        let unseal = |bytes: &[u8]| Handover(Zeroizing::new(bytes.to_vec())).unseal().map(|_| ());
        assert!(matches!(unseal(&[1, 2, 3]), Err(VaultError::Io(_))));
        // A key length that points past the end.
        assert!(matches!(unseal(&[200, 0, 0, 0, 1, 2]), Err(VaultError::Io(_))));
        // Key material, but no one-time key or database after it.
        let key = KeyMaterial::from_password(Zeroizing::new("pw".into())).to_bytes();
        let mut bytes = (key.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&key);
        assert!(matches!(unseal(&bytes), Err(VaultError::Io(_))));
    }
}
