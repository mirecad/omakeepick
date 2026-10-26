//! Command-line entry point of omakeepickd.

use std::ffi::OsString;
use std::process::ExitCode;

const USAGE: &str = "omakeepickd — KeePass helper for the OmaKeePick shell plugin

usage:
  omakeepickd serve            run the daemon in the foreground
  omakeepickd attach           bridge stdin/stdout to the daemon (starting it if needed)
  omakeepickd ctl <cmd> [json] send one request and print the reply
  omakeepickd pick-file db|keyfile [folder]
                               show the file dialog and print the chosen path
  omakeepickd --version";

fn main() -> ExitCode {
    // `pick-file` takes a folder, which need not be UTF-8; everything else is text.
    let raw: Vec<OsString> = std::env::args_os().skip(1).collect();
    let args: Vec<String> = raw.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    match args.first().map(String::as_str) {
        Some("serve") => omakeepickd::server::run(args.iter().any(|a| a == "--detach")),
        Some("attach") => omakeepickd::client::attach(),
        Some("ctl") => omakeepickd::client::ctl(&args[1..]),
        Some("pick-file") => omakeepickd::portal::pick_file_main(&raw[1..]),
        Some("--version" | "-V") => {
            println!("omakeepickd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
