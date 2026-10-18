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
mod diag;
mod session;
mod stall;
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

/// Parsed command line (§6.5/§7): `--mode <control|view>` plus optional
/// `--unattended`, `--ask-first` and `--operator <name>` consent flags. The
/// session id and connect token never reach the helper — the agent holds the
/// WebSocket and launches the helper into the session — so they are not on the
/// command line. `--operator` is display-only, untrusted, and bounded.
#[derive(Debug, Clone)]
pub struct Args {
    pub mode: session::Mode,
    pub unattended: bool,
    pub ask_first: bool,
    pub operator: Option<String>,
}

impl Args {
    pub fn parse<I: IntoIterator<Item = String>>(argv: I) -> Option<Args> {
        let mut mode = None;
        let mut unattended = false;
        let mut ask_first = false;
        let mut operator = None;
        let mut it = argv.into_iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--mode" => mode = it.next().and_then(|m| session::Mode::parse(&m)),
                "--unattended" => unattended = true,
                "--ask-first" => ask_first = true,
                "--operator" => {
                    operator = it.next().map(|o| sanitize_operator(&o)).filter(|o| !o.is_empty())
                }
                _ => {}
            }
        }
        Some(Args { mode: mode?, unattended, ask_first, operator })
    }
}

/// Bound the display-only operator name: printable ASCII, at most 64 chars (§7).
/// The C launcher already sanitizes it, but the helper is defensive about its
/// own argv rather than trusting the caller.
fn sanitize_operator(s: &str) -> String {
    s.chars().filter(|&c| (' '..='~').contains(&c)).take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_parse_control_and_view() {
        let a = Args::parse(
            ["--mode", "control", "--operator", "admin"].iter().map(|s| s.to_string()),
        )
        .unwrap();
        assert_eq!(a.mode, session::Mode::Control);
        assert_eq!(a.operator.as_deref(), Some("admin"));
        assert!(!a.unattended && !a.ask_first);

        let v = Args::parse(
            ["--mode", "view", "--unattended", "--ask-first"].iter().map(|s| s.to_string()),
        )
        .unwrap();
        assert_eq!(v.mode, session::Mode::View);
        assert!(v.unattended && v.ask_first);
        assert_eq!(v.operator, None);
    }

    #[test]
    fn args_reject_missing_or_bad_mode() {
        assert!(Args::parse(["--unattended"].iter().map(|s| s.to_string())).is_none());
        assert!(Args::parse(["--mode", "god"].iter().map(|s| s.to_string())).is_none());
    }

    #[test]
    fn operator_is_bounded_and_printable() {
        let long = "x".repeat(200);
        let a = Args::parse(["--mode", "view", "--operator", &long].iter().map(|s| s.to_string())).unwrap();
        assert_eq!(a.operator.unwrap().chars().count(), 64);
        let a2 = Args::parse(
            ["--mode", "view", "--operator", "ab\u{7}c"].iter().map(|s| s.to_string()),
        )
        .unwrap();
        assert_eq!(a2.operator.as_deref(), Some("abc"));
    }
}
