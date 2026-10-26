//! Native file dialog through `org.freedesktop.portal.FileChooser`.
//!
//! The daemon cannot ask the portal itself. xdg-desktop-portal tells sandboxed callers from host
//! ones by opening `/proc/<caller>/root`, which `PR_SET_DUMPABLE=0` (see `harden`) closes to every
//! other process, so it turns the daemon away with "Unable to open /proc/<pid>/root". The daemon
//! runs `omakeepickd pick-file` instead: a fresh exec of its own binary, which holds no secrets
//! and is dumpable again, asks the portal, and prints the chosen path.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};

use futures_util::StreamExt;
use zbus::{Connection, OwnedObjectPath, OwnedVariant, Proxy, Variant};

const DESTINATION: &str = "org.freedesktop.portal.Desktop";
const DESKTOP_PATH: &str = "/org/freedesktop/portal/desktop";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Database,
    KeyFile,
}

type Filter = (String, Vec<(u32, String)>);

fn glob_filter(name: &str, patterns: &[&str]) -> Filter {
    (name.to_string(), patterns.iter().map(|p| (0, p.to_string())).collect())
}

impl FileKind {
    /// The protocol's (and `pick-file`'s) name for it: `db` or `keyfile`.
    pub fn parse(name: &str) -> Option<FileKind> {
        match name {
            "db" => Some(FileKind::Database),
            "keyfile" => Some(FileKind::KeyFile),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            FileKind::Database => "db",
            FileKind::KeyFile => "keyfile",
        }
    }

    fn title(self) -> &'static str {
        match self {
            FileKind::Database => "Open KeePass database",
            FileKind::KeyFile => "Choose key file",
        }
    }

    fn filters(self) -> Vec<Filter> {
        let all = glob_filter("All files", &["*"]);
        match self {
            FileKind::Database => vec![glob_filter("KeePass databases", &["*.kdbx"]), all],
            FileKind::KeyFile => vec![glob_filter("Key files", &["*.keyx", "*.key"]), all],
        }
    }
}

/// Shows an "open file" dialog from a `pick-file` child process. Returns `Ok(None)` if the user
/// cancelled it.
pub async fn choose_file(kind: FileKind, folder: Option<&Path>) -> Result<Option<PathBuf>, String> {
    // /proc/self/exe rather than a path: the binary may have been replaced since we started.
    let mut command = tokio::process::Command::new("/proc/self/exe");
    command.arg0("omakeepickd").arg("pick-file").arg(kind.name());
    if let Some(dir) = folder {
        command.arg(dir);
    }
    let out = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // A request dropped while the dialog is up (the daemon quitting) takes the dialog along.
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| format!("Cannot start the file dialog: {e}"))?;
    if !out.status.success() {
        let message = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if message.is_empty() {
            format!("The file dialog failed ({})", out.status)
        } else {
            message
        });
    }
    Ok((!out.stdout.is_empty()).then(|| PathBuf::from(OsString::from_vec(out.stdout))))
}

/// `omakeepickd pick-file db|keyfile [folder]`: shows the dialog and writes the chosen path to
/// stdout as raw bytes, or nothing if it was cancelled. A failure exits 1 with the message, and
/// only the message, on stderr: the daemon passes it on as the reply's error text.
pub fn pick_file_main(args: &[OsString]) -> ExitCode {
    // Started as /proc/self/exe, which ps and top would list as "exe".
    unsafe { libc::prctl(libc::PR_SET_NAME, c"omakeepickd".as_ptr(), 0, 0, 0) };
    let Some(kind) = args.first().and_then(|a| a.to_str()).and_then(FileKind::parse) else {
        eprintln!("usage: omakeepickd pick-file db|keyfile [folder]");
        return ExitCode::from(2);
    };
    let folder = args.get(1).map(PathBuf::from);
    let picked = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime.block_on(open_file(kind, folder.as_deref())),
        Err(e) => Err(format!("Cannot start the file dialog: {e}")),
    };
    match picked {
        Ok(path) => {
            let bytes = path.as_deref().map(Path::as_os_str).unwrap_or(OsStr::new("")).as_bytes();
            let mut stdout = std::io::stdout().lock();
            if stdout.write_all(bytes).and_then(|()| stdout.flush()).is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn err(context: &str) -> impl Fn(zbus::Error) -> String + '_ {
    move |e| format!("{context}: {e}")
}

async fn request_proxy<'a>(conn: &Connection, path: &str) -> zbus::Result<Proxy<'a>> {
    Proxy::new(conn, DESTINATION, path.to_string(), "org.freedesktop.portal.Request").await
}

/// Asks the portal for an "open file" dialog, from this process. Returns `Ok(None)` if the user
/// cancelled it.
async fn open_file(kind: FileKind, folder: Option<&Path>) -> Result<Option<PathBuf>, String> {
    let conn = Connection::session().await.map_err(err("Cannot reach the session bus"))?;
    let mut random = [0u8; 4];
    getrandom::fill(&mut random).map_err(|e| e.to_string())?;
    let token = format!("omakeepick_{}", u32::from_le_bytes(random));
    let sender =
        conn.unique_name().ok_or("No D-Bus unique name")?.as_str().trim_start_matches(':').replace('.', "_");
    // Subscribe before calling so a fast response cannot be missed.
    let expected = format!("{DESKTOP_PATH}/request/{sender}/{token}");
    let request = request_proxy(&conn, &expected).await.map_err(err("File dialog"))?;
    let mut responses = request.receive_signal("Response").await.map_err(err("File dialog"))?;

    let filter_list = kind.filters();
    let mut options: HashMap<&str, Variant<'_>> = HashMap::new();
    options.insert("handle_token", Variant::from(token.as_str()));
    options.insert("modal", Variant::from(true));
    options.insert("current_filter", Variant::from(filter_list[0].clone()));
    options.insert("filters", Variant::from(filter_list));
    if let Some(dir) = folder.filter(|d| d.is_dir()) {
        let mut bytes = dir.as_os_str().as_bytes().to_vec();
        bytes.push(0);
        options.insert("current_folder", Variant::from(bytes));
    }
    let chooser = Proxy::new(&conn, DESTINATION, DESKTOP_PATH, "org.freedesktop.portal.FileChooser")
        .await
        .map_err(err("File dialog"))?;
    let handle: OwnedObjectPath = chooser
        .call("OpenFile", &("", kind.title(), options))
        .await
        .map_err(err("Cannot open the file dialog"))?;
    if handle.as_str() != expected {
        // Very old portals ignore handle_token.
        let request = request_proxy(&conn, handle.as_str()).await.map_err(err("File dialog"))?;
        responses = request.receive_signal("Response").await.map_err(err("File dialog"))?;
    }
    let message = responses.next().await.ok_or("The file dialog went away")?;
    let (code, mut results): (u32, HashMap<String, OwnedVariant>) =
        message.body().deserialize().map_err(err("Unexpected file dialog response"))?;
    match code {
        0 => {}
        // 1 is Cancel; 2 "ended some other way", which is what xdg-desktop-portal-gtk says when
        // the dialog is closed with Esc or by the compositor.
        1 | 2 => return Ok(None),
        _ => return Err("The file dialog failed".into()),
    }
    let uris: Vec<String> =
        results.remove("uris").and_then(|v| Vec::<String>::try_from(v).ok()).unwrap_or_default();
    let Some(uri) = uris.first() else { return Ok(None) };
    file_uri_to_path(uri).map(Some).ok_or_else(|| format!("Not a local file: {uri}"))
}

fn file_uri_to_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    // Skip an optional authority ("file://localhost/...").
    let path = &rest[rest.find('/')?..];
    let mut bytes = Vec::with_capacity(path.len());
    let raw = path.as_bytes();
    let mut i = 0;
    while i < raw.len() {
        let escaped = (raw[i] == b'%')
            .then(|| raw.get(i + 1..i + 3))
            .flatten()
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        if let Some(b) = escaped {
            bytes.push(b);
            i += 3;
            continue;
        }
        bytes.push(raw[i]);
        i += 1;
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_file_uris() {
        assert_eq!(
            file_uri_to_path("file:///home/me/My%20Secrets/K%C3%BD.kdbx").unwrap(),
            PathBuf::from("/home/me/My Secrets/Ký.kdbx")
        );
        assert_eq!(file_uri_to_path("file://localhost/tmp/a").unwrap(), PathBuf::from("/tmp/a"));
        assert!(file_uri_to_path("https://example.com/a").is_none());
    }
}
