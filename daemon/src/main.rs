//! Command-line entry point of omakeepickd.

use std::process::ExitCode;

const USAGE: &str = "omakeepickd — KeePass helper for the OmaKeePick shell plugin

usage:
  omakeepickd serve            run the daemon in the foreground
  omakeepickd attach           bridge stdin/stdout to the daemon (starting it if needed)
  omakeepickd ctl <cmd> [json] send one request and print the reply
  omakeepickd --version";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("serve") => omakeepickd::server::run(args.iter().any(|a| a == "--detach")),
        Some("attach") => omakeepickd::client::attach(),
        Some("ctl") => omakeepickd::client::ctl(&args[1..]),
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
