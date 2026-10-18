//! Windows capture/input backend and the real run loop (`REMOTE_SCREEN.md`
//! §6.1-§6.7). All Win32 lives here, behind the [`crate::backend::ScreenBackend`]
//! trait, so the protocol, framing, and session loop never see it.
//!
//! What this file wires up:
//!   * process hardening at startup: PER_MONITOR_AWARE_V2 DPI, the
//!     SYSTEM32-only DLL search path, and the display keep-awake (§6.3, §6.7);
//!   * the §6.5 run loop: a reader thread turns pipe frames into `InMsg`s on a
//!     channel; the main thread paces capture at the fps cap and drains input;
//!   * [`WindowsBackend`]: DXGI Desktop Duplication (primary, incl. the secure
//!     desktop as LocalSystem) with a GDI BitBlt fallback, JPEG via the pure
//!     `jpeg-encoder`, `SendInput` with virtual-desktop mapping, input-desktop
//!     following, and the always-on banner + consent prompt (own UI thread).
//!     Ctrl+Alt+Del is not issued here: the session emits a service-request
//!     frame (§6.4) the agent service acts on.

mod banner;
mod capture;
mod desktop;
mod inject;

use std::io::{self, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use windows::Win32::System::LibraryLoader::{SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32};
use windows::Win32::System::Power::{
    SetThreadExecutionState, ES_CONTINUOUS, ES_DISPLAY_REQUIRED, EXECUTION_STATE,
};
use windows::Win32::UI::HiDpi::{SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2};

use screen_wire::framing::{read_frame, write_frame, FrameKind};
use screen_wire::proto::{parse_in, OutMsg};

use crate::backend::ScreenBackend;
use crate::session::{Flow, Session};
use crate::Args;

pub use capture::WindowsBackend;

/// Startup hardening (§6.7). DPI awareness and the DLL search lockdown must
/// happen before any capture/input or DLL load.
fn harden_process() {
    unsafe {
        // SYSTEM32 only for implicit/loaded DLLs: defense in depth against DLL
        // search-order hijack for anything the helper or its deps load (§6.7).
        let _ = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
        // Correct coordinates on scaled displays (§6.3).
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
        // Keep the display awake for the life of the session (§6.7).
        SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED);
    }
}

fn keep_awake_end() {
    unsafe {
        SetThreadExecutionState(ES_CONTINUOUS);
    }
}

/// Entry point for the Windows binary. Returns a process exit code.
pub fn run() -> i32 {
    harden_process();

    // Diagnostics go to C:\ProgramData\Ominull\logs\screen-helper.log (§6/§9),
    // not to NUL as the launcher's stderr once did.
    crate::diag::init(r"C:\ProgramData\Ominull\logs");

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match Args::parse(argv) {
        Some(a) => a,
        None => {
            crate::diag::log("fatal: bad arguments (need --mode control|view)");
            eprintln!("usage: ominull-screen-helper --mode <control|view> [--unattended] [--ask-first] [--operator <name>]");
            return 2;
        }
    };
    crate::diag::log(&format!(
        "helper start mode={} unattended={} ask_first={}",
        if args.mode == crate::session::Mode::Control { "control" } else { "view" },
        args.unattended,
        args.ask_first
    ));

    let backend = match WindowsBackend::new(args.mode == crate::session::Mode::Control, args.operator.as_deref()) {
        Ok(b) => {
            crate::diag::log("backend init ok");
            b
        }
        Err(e) => {
            crate::diag::log(&format!("fatal: backend init failed: {e:?}"));
            // Tell the hub (and so the viewer/ctl) the session failed to start,
            // rather than exiting silently and leaving a generic timeout (§9).
            // `bye` is the existing agent->operator end message the hub already
            // relays and the viewer already surfaces (screen/wire proto.rs).
            let stdout = io::stdout();
            let mut out = stdout.lock();
            let _ = write_frame(&mut out, FrameKind::Text, OutMsg::Bye { reason: "backend init failed".into() }.to_json().as_bytes());
            let _ = out.flush();
            return 1;
        }
    };

    // The monitor list the viewer will receive in `hello` (geometry only).
    {
        let mons = backend.monitors();
        let geo: Vec<String> = mons.iter().map(|m| format!("{}:{}x{}@{},{}{}", m.id, m.w, m.h, m.x, m.y, if m.primary { "*" } else { "" })).collect();
        crate::diag::log(&format!("monitor list ({}): {}", mons.len(), geo.join(" ")));
    }

    let code = run_loop(backend, args);
    keep_awake_end();
    code
}

/// The §6.5 relay loop. Generic over the backend so the pacing/draining logic is
/// exercised by the real Windows backend here and by the mock in session tests.
fn run_loop<B: ScreenBackend>(backend: B, args: Args) -> i32 {
    // Reader thread: pipe frames -> InMsg on a channel. Binary frames from the
    // operator side are not expected (all operator messages are JSON text), so
    // they are dropped. Dropping the sender on EOF/error signals the main loop.
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        loop {
            match read_frame(&mut stdin) {
                Ok(Some((FrameKind::Text, bytes))) => {
                    if let Some(msg) = parse_in(&bytes) {
                        if tx.send(msg).is_err() {
                            break;
                        }
                    }
                }
                Ok(Some((FrameKind::Binary, _))) => { /* not expected operator->agent; drop */ }
                Ok(Some((FrameKind::Service, _))) => { /* service frames only flow helper->agent; drop */ }
                Ok(None) => break, // agent closed our stdin: session over
                Err(_) => break,
            }
        }
        // Sender drops here -> main loop sees Disconnected.
    });

    let mut session = Session::new(backend, args.mode);
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // §7 consent gate: with ask_first on, the session does not go active (no
    // capture, no input) until the person at the keyboard allows it; with it off
    // this returns at once (the banner still shows). A decline writes `bye`.
    match session.authorize(&mut out, args.ask_first, args.unattended, args.operator.as_deref()) {
        Ok(true) => {}
        Ok(false) => {
            let _ = out.flush();
            return 0;
        }
        Err(_) => return 1,
    }

    if session.send_hello(&mut out).is_err() {
        return 1;
    }

    let mut next_tick = Instant::now();
    loop {
        let now = Instant::now();
        if now >= next_tick {
            if session.tick(&mut out).is_err() {
                break;
            }
            let interval = Duration::from_millis((1000 / session.fps().max(1)) as u64);
            next_tick = now + interval;
        }
        let wait = next_tick.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(msg) => match session.on_message(msg, &mut out) {
                Ok(Flow::Stop) => break,
                Ok(Flow::Continue) => {}
                Err(_) => break,
            },
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break, // stdin closed
        }
    }

    let _ = session.shutdown(&mut out, "session ended");
    let _ = out.flush();
    0
}

/// Small helper: turn a `windows::core::Result` error into an `io::Error` for
/// uniform logging where that is convenient.
#[allow(dead_code)]
pub(crate) fn win_io_err(e: windows::core::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{e:?}"))
}

#[allow(dead_code)]
fn keep_awake_flags() -> EXECUTION_STATE {
    ES_CONTINUOUS | ES_DISPLAY_REQUIRED
}
