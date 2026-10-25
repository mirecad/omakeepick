//! `omakeepickd attach` (the shell plugin's bridge) and `omakeepickd ctl` (one-shot requests).

use std::fs::OpenOptions;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::{Zeroize, Zeroizing};

use crate::paths;
use crate::protocol::SecretLines;

/// Logs bigger than this are truncated when a new daemon starts.
const MAX_LOG: u64 = 1 << 20;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime")
}

fn spawn_daemon() -> std::io::Result<()> {
    let log = paths::log_path();
    if let Some(dir) = log.parent() {
        paths::ensure_private_dir(dir)?;
    }
    let truncate = std::fs::metadata(&log).is_ok_and(|m| m.len() > MAX_LOG);
    let log = OpenOptions::new()
        .create(true)
        .append(!truncate)
        .write(true)
        .truncate(truncate)
        .mode(0o600)
        .open(log)?;
    // `serve --detach` forks and its first process exits at once, so waiting reaps it.
    Command::new(std::env::current_exe()?)
        .args(["serve", "--detach"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .status()?;
    Ok(())
}

async fn connect(spawn: bool) -> std::io::Result<UnixStream> {
    let socket = paths::socket_path();
    match UnixStream::connect(&socket).await {
        Ok(stream) => return Ok(stream),
        Err(e) if !spawn => return Err(e),
        Err(_) => {}
    }
    spawn_daemon()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStream::connect(&socket).await {
            Ok(stream) => return Ok(stream),
            Err(e) if Instant::now() > deadline => return Err(e),
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

pub fn attach() -> ExitCode {
    let runtime = runtime();
    let connected = runtime.block_on(async {
        let stream = match connect(true).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("omakeepickd attach: cannot reach the daemon: {e}");
                return false;
            }
        };
        let (mut from_daemon, mut to_daemon) = stream.into_split();
        // Requests may carry the master password: wipe the relay buffer after each chunk.
        let upstream = async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = Zeroizing::new(vec![0u8; 16 * 1024]);
            loop {
                let n = match stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let sent = to_daemon.write_all(&buf[..n]).await;
                buf[..n].zeroize();
                if sent.is_err() {
                    break;
                }
            }
        };
        let downstream = async move {
            let mut stdout = tokio::io::stdout();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = match from_daemon.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if stdout.write_all(&buf[..n]).await.is_err() || stdout.flush().await.is_err() {
                    break;
                }
            }
        };
        tokio::select! {
            _ = upstream => {}
            _ = downstream => {}
        }
        true
    });
    // tokio's stdin reader is a blocking thread that a graceful shutdown would wait for, and
    // the input may never come; don't wait for it.
    runtime.shutdown_background();
    if connected { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

const CTL_USAGE: &str = "usage: omakeepickd ctl <command> [json-arguments]
  e.g. omakeepickd ctl status
       omakeepickd ctl lock
       omakeepickd ctl search '{\"query\": \"git\"}'";

/// Exit codes: 0 ok, 1 error reply, 2 usage, 3 daemon not running.
pub fn ctl(args: &[String]) -> ExitCode {
    let Some(cmd) = args.first() else {
        eprintln!("{CTL_USAGE}");
        return ExitCode::from(2);
    };
    let mut request = match args.get(1).map(|a| serde_json::from_str::<Value>(a)) {
        None => Map::new(),
        Some(Ok(Value::Object(map))) => map,
        Some(_) => {
            eprintln!("omakeepickd ctl: arguments must be a JSON object\n{CTL_USAGE}");
            return ExitCode::from(2);
        }
    };
    request.insert("id".into(), json!(1));
    request.insert("cmd".into(), json!(cmd));
    runtime().block_on(async move {
        let Ok(stream) = connect(false).await else {
            eprintln!("omakeepickd ctl: the daemon is not running");
            return ExitCode::from(3);
        };
        let (reader, mut writer) = stream.into_split();
        let mut line = Value::Object(request).to_string();
        line.push('\n');
        if writer.write_all(line.as_bytes()).await.is_err() {
            return ExitCode::FAILURE;
        }
        let mut lines = SecretLines::new(reader);
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(value) = serde_json::from_slice::<Value>(&line) else { continue };
            if value.get("id") == Some(&json!(1)) {
                println!("{value}");
                let ok = value.get("ok").and_then(Value::as_bool).unwrap_or(false);
                return if ok { ExitCode::SUCCESS } else { ExitCode::FAILURE };
            }
        }
        eprintln!("omakeepickd ctl: no reply");
        ExitCode::FAILURE
    })
}
