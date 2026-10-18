//! `ominull-screen-helper` — the capture/input helper the Ominull agent launches
//! into the active console session (`REMOTE_SCREEN.md` §6). It speaks the §4 wire
//! protocol over its stdio, framed per §6.5 by the C agent, and never opens a
//! socket of its own: input and control arrive only on the agent pipe (§6.7).
//!
//! Layering: [`session`] owns the protocol state machine (pure, host-tested),
//! [`backend`] is the capture/input seam, and `win` is the Windows DXGI/GDI +
//! SendInput implementation (Win32, `#[cfg(windows)]`). The pure crates build
//! and test on any host; only the real run needs Windows.

mod backend;
mod session;
#[cfg(windows)]
mod win;

#[cfg(windows)]
fn main() {
    std::process::exit(win::run());
}

/// On a non-Windows host the binary still builds (so `cargo test` runs the pure
/// wire/session logic), but it does not run — there is no backend here yet.
#[cfg(not(windows))]
fn main() {
    eprintln!("ominull-screen-helper: no capture backend on this platform (Windows only in v1)");
    std::process::exit(2);
}

/// Parsed command line (§6.5): `--session <id> --mode <control|view>`. The
/// connect token never reaches the helper (the agent holds the WebSocket).
#[derive(Debug, Clone)]
pub struct Args {
    pub session_id: String,
    pub mode: session::Mode,
}

impl Args {
    pub fn parse<I: IntoIterator<Item = String>>(argv: I) -> Option<Args> {
        let mut session_id = None;
        let mut mode = None;
        let mut it = argv.into_iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--session" => session_id = it.next(),
                "--mode" => mode = it.next().and_then(|m| session::Mode::parse(&m)),
                _ => {}
            }
        }
        Some(Args { session_id: session_id?, mode: mode? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_parse_control_and_view() {
        let a = Args::parse(
            ["--session", "s-1", "--mode", "control"].iter().map(|s| s.to_string()),
        )
        .unwrap();
        assert_eq!(a.session_id, "s-1");
        assert_eq!(a.mode, session::Mode::Control);

        let v = Args::parse(["--mode", "view", "--session", "x"].iter().map(|s| s.to_string())).unwrap();
        assert_eq!(v.mode, session::Mode::View);
    }

    #[test]
    fn args_reject_missing_or_bad() {
        assert!(Args::parse(["--session", "s"].iter().map(|s| s.to_string())).is_none());
        assert!(Args::parse(["--session", "s", "--mode", "god"].iter().map(|s| s.to_string())).is_none());
    }
}
