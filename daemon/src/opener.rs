//! Opening a database in a child process that can be killed.
//!
//! A key derivation cannot be interrupted: the Argon2 or AES-KDF loop runs until it is done,
//! holding the master password, the key file and then the decrypted database. Run on a thread
//! of the daemon, an unlock that was still deriving when the machine went to sleep would keep
//! those in RAM, and so in a hibernation image, past the point where logind stops waiting.
//!
//! So the daemon does not derive keys itself. It runs `omakeepickd open-db`, a fresh exec of
//! its own binary, hands it the database path and the credentials on stdin, and reads the
//! result on stdout. A lock, suspend, `quit` or the timeout sends the child `SIGKILL` and waits
//! for it to be reaped, which returns every page it held to the kernel before the sleep
//! inhibitor is released. The child dies with the daemon as well (`PR_SET_PDEATHSIG`), and a
//! parser panic on a hostile file now takes down the child, not the daemon.
//!
//! The `keepass` crate can only load a database from KDBX bytes, so the child hands the
//! decrypted database back as one: re-encrypted under a random one-time key with a one-round
//! KDF, which the daemon opens in milliseconds. The key travels on the same pipe, ahead of the
//! data; a pipe is kernel memory shared by nothing but these two processes.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};

use keepass::config::{CompressionConfig, DatabaseVersion, InnerCipherConfig, KdfConfig, OuterCipherConfig};
use keepass::{Database, DatabaseKey};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::harden;
use crate::vault::{self, KeyMaterial, VaultError};

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

/// `[len32][path][KeyMaterial bytes]`: what the daemon writes to the child's stdin.
fn encode_request(path: &Path, key: &KeyMaterial) -> Zeroizing<Vec<u8>> {
    let path = path.as_os_str().as_bytes();
    let key = key.to_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(4 + path.len() + key.len()));
    out.extend_from_slice(&(path.len() as u32).to_le_bytes());
    out.extend_from_slice(path);
    out.extend_from_slice(&key);
    out
}

fn decode_request(bytes: &[u8]) -> Option<(PathBuf, KeyMaterial)> {
    let len = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    let path = bytes.get(4..4 + len)?;
    let key = KeyMaterial::from_bytes(bytes.get(4 + len..)?)?;
    Some((PathBuf::from(OsString::from_vec(path.to_vec())), key))
}

fn hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Re-encrypts `db` as KDBX 4 under a fresh random key with a one-round KDF. Returns the key
/// followed by the file bytes.
fn seal(mut db: Database) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    getrandom::fill(secret.as_mut()).map_err(|e| VaultError::Io(format!("No randomness: {e}")))?;
    db.config.version = DatabaseVersion::KDB4(1);
    db.config.kdf_config = KdfConfig::Aes { rounds: 1 };
    db.config.outer_cipher_config = OuterCipherConfig::ChaCha20;
    db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
    db.config.compression_config = CompressionConfig::None;
    let mut out = Zeroizing::new(Vec::new());
    out.extend_from_slice(secret.as_ref());
    db.save(&mut *out, DatabaseKey::new().with_password(&hex(secret.as_ref())))
        .map_err(|e| VaultError::Io(format!("Cannot hand over the database: {e}")))?;
    Ok(out)
}

/// Opens what [`seal`] produced.
fn unseal(bytes: &[u8]) -> Result<Database, VaultError> {
    let (secret, data) =
        bytes.split_at_checked(SECRET_LEN).ok_or_else(|| VaultError::Io(INCOMPLETE.into()))?;
    Database::parse(data, DatabaseKey::new().with_password(&hex(secret)))
        .map_err(|e| VaultError::Io(format!("Cannot take over the database: {e}")))
}

const INCOMPLETE: &str = "The database helper stopped before handing over the database";

/// Test hook: with `OMAKEEPICK_TEST_HOLD_KDF` set to a FIFO, the child blocks there before the
/// derivation until something writes to it, standing in for a long derivation. Debug builds only.
fn test_hold() {
    #[cfg(debug_assertions)]
    if let Some(fifo) = std::env::var_os("OMAKEEPICK_TEST_HOLD_KDF") {
        let _ = std::fs::read(fifo);
    }
}

/// `omakeepickd open-db`: the child. Reads the request on stdin, writes the sealed database on
/// stdout, or a JSON [`WireError`] on stderr with exit status 1.
pub fn open_db_main() -> ExitCode {
    // Secrets live here from the first read on: no core dumps, no ptrace by our other processes.
    harden::harden_process();
    unsafe {
        // Die with the daemon, so a derivation never outlives the process that asked for it.
        // Set before stdin is read: if the daemon is already gone, the pipe is closed and the
        // request never arrives.
        libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
        // Started as /proc/self/exe, which ps and top would list as "exe".
        libc::prctl(libc::PR_SET_NAME, c"omakeepickd".as_ptr(), 0, 0, 0);
    }
    let result = (|| {
        let mut request = Zeroizing::new(Vec::new());
        std::io::stdin()
            .lock()
            .read_to_end(&mut request)
            .map_err(|e| VaultError::Io(format!("Cannot read the request: {e}")))?;
        let (path, key) =
            decode_request(&request).ok_or_else(|| VaultError::Io("Malformed request".into()))?;
        drop(request);
        test_hold();
        let data = vault::read_database(&path)?;
        let db = vault::parse_database(&data, &key)?;
        drop((data, key));
        seal(db)
    })();
    match result {
        Ok(sealed) => {
            let mut stdout = std::io::stdout().lock();
            if stdout.write_all(&sealed).and_then(|()| stdout.flush()).is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            let wire = serde_json::to_string(&WireError::from(&err)).unwrap_or_default();
            eprintln!("{wire}");
            ExitCode::FAILURE
        }
    }
}

/// A running `open-db` child.
pub struct Opener {
    child: Child,
    stdout: JoinHandle<std::io::Result<Zeroizing<Vec<u8>>>>,
    stderr: JoinHandle<std::io::Result<Vec<u8>>>,
}

impl Opener {
    /// Starts `exe open-db` for the database at `path` and sends it the credentials. The
    /// daemon passes `/proc/self/exe`; tests pass the built binary.
    pub async fn spawn(exe: &Path, path: &Path, key: &KeyMaterial) -> Result<Opener, VaultError> {
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
        // Drain both pipes while waiting, so a large database cannot fill one and stall.
        let stdout = tokio::spawn(async move {
            let mut buf = Zeroizing::new(Vec::new());
            out.read_to_end(&mut buf).await?;
            Ok(buf)
        });
        let stderr = tokio::spawn(async move {
            let mut buf = Vec::new();
            err.take(64 << 10).read_to_end(&mut buf).await?;
            Ok(buf)
        });
        let request = encode_request(path, key);
        {
            use tokio::io::AsyncWriteExt;
            if let Err(e) = stdin.write_all(&request).await.and(stdin.shutdown().await) {
                let mut opener = Opener { child, stdout, stderr };
                opener.abort().await;
                return Err(failed(e));
            }
        }
        drop(stdin); // EOF: the child has the whole request
        Ok(Opener { child, stdout, stderr })
    }

    /// Waits for the child and opens what it handed over. Parsing runs on a blocking thread.
    pub async fn wait(&mut self) -> Result<Database, VaultError> {
        let status = self.child.wait().await.map_err(|e| VaultError::Io(format!("Database helper: {e}")))?;
        let stdout = (&mut self.stdout).await.map_err(|e| VaultError::Io(e.to_string()))?;
        let stderr = (&mut self.stderr).await.map_err(|e| VaultError::Io(e.to_string()))?;
        if !status.success() {
            let reported = stderr
                .ok()
                .and_then(|bytes| serde_json::from_slice::<WireError>(&bytes).ok())
                .and_then(WireError::into_error);
            return Err(reported.unwrap_or_else(|| {
                // Killed, or a parser panic (which aborts) on a file the header check let through.
                VaultError::Io(format!("The database helper stopped unexpectedly ({status})"))
            }));
        }
        let sealed = stdout.map_err(|e| VaultError::Io(format!("Database helper: {e}")))?;
        tokio::task::spawn_blocking(move || unseal(&sealed))
            .await
            .unwrap_or_else(|e| Err(VaultError::Io(format!("Database helper: {e}"))))
    }

    /// Kills the child and waits until it is reaped, so its memory is gone when this returns.
    pub async fn abort(&mut self) {
        let _ = self.child.kill().await;
        self.stdout.abort();
        self.stderr.abort();
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
        let key = KeyMaterial::new(Zeroizing::new("pw".into()), Some(Zeroizing::new(vec![7, 8]))).unwrap();
        let path = PathBuf::from(OsString::from_vec(b"/v\xff/Secrets.kdbx".to_vec()));
        let (back_path, back_key) = decode_request(&encode_request(&path, &key)).unwrap();
        assert_eq!(back_path, path);
        assert_eq!(back_key.to_bytes(), key.to_bytes());
        assert!(decode_request(&[9, 0, 0, 0, 1]).is_none());
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
    fn unseal_rejects_short_input() {
        assert!(matches!(unseal(&[1, 2, 3]), Err(VaultError::Io(_))));
    }
}
