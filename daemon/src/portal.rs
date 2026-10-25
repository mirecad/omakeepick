//! Native file dialog through `org.freedesktop.portal.FileChooser`.

use std::collections::HashMap;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use futures_util::StreamExt;
use zbus::{Connection, OwnedObjectPath, OwnedVariant, Proxy, Variant};

const DESTINATION: &str = "org.freedesktop.portal.Desktop";
const DESKTOP_PATH: &str = "/org/freedesktop/portal/desktop";

pub enum Filters {
    Database,
    KeyFile,
}

type Filter = (String, Vec<(u32, String)>);

fn glob_filter(name: &str, patterns: &[&str]) -> Filter {
    (name.to_string(), patterns.iter().map(|p| (0, p.to_string())).collect())
}

impl Filters {
    fn list(&self) -> Vec<Filter> {
        let all = glob_filter("All files", &["*"]);
        match self {
            Filters::Database => vec![glob_filter("KeePass databases", &["*.kdbx"]), all],
            Filters::KeyFile => vec![glob_filter("Key files", &["*.keyx", "*.key"]), all],
        }
    }
}

fn err(context: &str) -> impl Fn(zbus::Error) -> String + '_ {
    move |e| format!("{context}: {e}")
}

async fn request_proxy<'a>(conn: &Connection, path: &str) -> zbus::Result<Proxy<'a>> {
    Proxy::new(conn, DESTINATION, path.to_string(), "org.freedesktop.portal.Request").await
}

/// Shows an "open file" dialog. Returns `Ok(None)` if the user cancelled it.
pub async fn open_file(
    title: &str,
    filters: Filters,
    folder: Option<&Path>,
) -> Result<Option<PathBuf>, String> {
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

    let filter_list = filters.list();
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
    let handle: OwnedObjectPath =
        chooser.call("OpenFile", &("", title, options)).await.map_err(err("Cannot open the file dialog"))?;
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
        1 => return Ok(None),
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
