//! `ominull-screen`: the OmniNull remote screen viewer.
//!
//! * `ominull-screen` / `ominull-screen --stdin`: read one JSON handshake line
//!   from stdin and open the window.
//! * `ominull-screen 'ominull-screen://open?hub=..&session=..&code=..'`: a
//!   console link; only hubs in the viewer's config are trusted.
//! * `ominull-screen ctl <action> ...`: headless, same stdin handshake; prints
//!   one JSON object.
//!
//! The session token is only ever read from stdin or redeemed from a link,
//! never taken from arguments or the environment.

use screen_viewer::{ctl, handshake, launch, ui};
use std::io::Write;
use std::process::ExitCode;

const USAGE: &str = "usage:
  ominull-screen [--stdin]            read the session handshake from stdin and open the viewer
  ominull-screen 'ominull-screen://open?hub=...&session=...&code=...'
                                      open a session from the console link
  ominull-screen ctl <action> [...]   headless: read the handshake from stdin, do one thing, print JSON
    info
    shot [--monitor N] -o PATH [--max-edge E]
    click X Y [--button left|right|middle] [--double] [--monitor N] [--max-edge E]
    move X Y [--monitor N] [--max-edge E]
    drag X1 Y1 X2 Y2 [--button B] [--monitor N] [--max-edge E]
    scroll X Y DY [--monitor N] [--max-edge E]
    type [TEXT]                       without TEXT: the \"text\" field of the stdin session line
    key COMBO                         e.g. ctrl+c, alt+f4, ctrl+alt+del
    end
  X/Y are in screenshot space (the same --max-edge as the shot, default 1280).";

fn stdin_connect() -> Result<handshake::Connect, String> {
    handshake::read_line(&mut std::io::stdin().lock())
}

fn launch_start(url: &str) -> ui::Start {
    let link = match launch::parse_url(url) {
        Ok(l) => l,
        Err(e) => return ui::Start::Error(format!("This link could not be opened: {e}.")),
    };
    let cfg = match launch::load_config() {
        Ok(c) => c,
        Err(e) => return ui::Start::Error(format!("This link could not be opened: {e}")),
    };
    match launch::find_hub(&cfg, &link.hub, &link.hub_origin) {
        Ok(entry) => {
            let entry = launch::HubEntry { origin: entry.origin.clone(), ca_pem: entry.ca_pem.clone() };
            ui::Start::Launch(link, entry)
        }
        Err(e) => ui::Start::Error(format!("This link could not be opened: {e}")),
    }
}

fn window(start: ui::Start) -> ExitCode {
    match ui::run(start) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ominull-screen: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        None | Some("--stdin") if args.len() <= 1 => match stdin_connect() {
            Ok(c) => window(ui::Start::Connect(c)),
            Err(e) => {
                eprintln!("ominull-screen: {e}");
                ExitCode::from(2)
            }
        },
        Some("ctl") => {
            let (out, ok) = ctl::main_ctl(&args[1..], stdin_connect);
            let mut so = std::io::stdout().lock();
            let _ = writeln!(so, "{out}");
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Some("--help" | "-h") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("--version" | "-V") => {
            println!("ominull-screen {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        // Desktop launchers may pass the link with a different case scheme or
        // as the only argument; parse_url is strict and says why it refuses.
        Some(u) if args.len() == 1 && u.to_ascii_lowercase().starts_with("ominull-screen:") => window(launch_start(u)),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
