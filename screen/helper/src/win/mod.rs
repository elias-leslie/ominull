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
//!     following, the always-on banner (own UI thread), and a `sas.dll` SendSAS.

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

use screen_wire::framing::{read_frame, FrameKind};
use screen_wire::proto::parse_in;

use crate::backend::ScreenBackend;
use crate::session::{Flow, Session};
use crate::Args;

pub use capture::WindowsBackend;

/// Startup hardening (§6.7). DPI awareness and the DLL search lockdown must
/// happen before any capture/input or DLL load.
fn harden_process() {
    unsafe {
        // SYSTEM32 only for implicit/loaded DLLs (sas.dll is loaded this way).
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

    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match Args::parse(argv) {
        Some(a) => a,
        None => {
            eprintln!("usage: ominull-screen-helper --session <id> --mode <control|view>");
            return 2;
        }
    };

    let backend = match WindowsBackend::new() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("screen backend init failed: {e:?}");
            return 1;
        }
    };

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
                Ok(None) => break, // agent closed our stdin: session over
                Err(_) => break,
            }
        }
        // Sender drops here -> main loop sees Disconnected.
    });

    let mut session = Session::new(backend, args.mode);
    let stdout = io::stdout();
    let mut out = stdout.lock();

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
