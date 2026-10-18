//! The always-on "being viewed remotely" banner (§7). It lives on its own UI
//! thread because a window pins a thread to one desktop and SetThreadDesktop
//! then fails (§6.1); the capture/input thread must stay window-free. On a
//! desktop switch the window is destroyed and recreated on the new desktop (you
//! cannot move a window between desktops). It is topmost, click-through
//! (WS_EX_TRANSPARENT), non-activating, and re-asserts topmost on a timer so the
//! viewer cannot bury it.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicIsize, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateSolidBrush, DrawTextW, EndPaint, FillRect, SetBkMode, SetTextColor,
    DT_CENTER, DT_SINGLELINE, DT_VCENTER, DT_WORDBREAK, PAINTSTRUCT, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, KillTimer,
    PostMessageW, RegisterClassExW, SetForegroundWindow, SetLayeredWindowAttributes, SetTimer,
    SetWindowPos, TranslateMessage, CW_USEDEFAULT, HMENU, HWND_TOPMOST, LWA_ALPHA, MSG,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, WM_APP, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY,
    WM_PAINT, WM_TIMER, WNDCLASSEXW, WS_BORDER, WS_CHILD, WS_EX_LAYERED, WS_EX_NOACTIVATE,
    WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP, WS_TABSTOP, WS_VISIBLE,
};

const BANNER_TEXT: PCWSTR = w!("This screen is being viewed remotely (OmniNull)");
const BANNER_HEIGHT: i32 = 34;
const REASSERT_TIMER: usize = 1;

// --- consent prompt (§7, "ask the person first") ----------------------------
//
// A session has exactly one consent prompt at a time, so the request and its
// result live in process-wide state the (static) window procedure can reach.
// `CONSENT_RESULT`: 0 pending, 1 allowed, 2 denied.
const WM_APP_CONSENT: u32 = WM_APP + 1;
const CONSENT_TIMER: usize = 2;
const CONSENT_TIMEOUT_MS: u32 = 60_000; // 60 s with no answer = denied (§7)
const ID_ALLOW: isize = 101;
const ID_DENY: isize = 102;

static CONSENT_RESULT: AtomicI32 = AtomicI32::new(0);
static CONSENT_CONTROL: AtomicBool = AtomicBool::new(false);
static CONSENT_OPERATOR: Mutex<String> = Mutex::new(String::new());

// The always-on banner's wording reflects the session: control vs view, and who
// (or what, e.g. "an agent (admin key)") is driving. Set once at Banner::start;
// read by the (static) banner window procedure when it paints.
static BANNER_CONTROL: AtomicBool = AtomicBool::new(false);
static BANNER_OPERATOR: Mutex<String> = Mutex::new(String::new());

/// The banner caption for the current session (control/view + operator).
fn banner_caption() -> String {
    let verb = if BANNER_CONTROL.load(Ordering::SeqCst) { "controlled" } else { "viewed" };
    let op = BANNER_OPERATOR.lock().map(|g| g.clone()).unwrap_or_default();
    if op.is_empty() {
        format!("This screen is being {verb} remotely (OmniNull)")
    } else {
        format!("This screen is being {verb} remotely by {op} (OmniNull)")
    }
}

pub struct Banner {
    running: Arc<AtomicBool>,
    hwnd: Arc<AtomicIsize>,
    epoch: Arc<AtomicU32>,
    thread: Option<JoinHandle<()>>,
}

impl Banner {
    /// Spawn the banner UI thread. It shows at once on the current desktop. The
    /// caption reflects the session: `control` sets "controlled" vs "viewed", and
    /// `operator` (a username, or a phrase like "an agent (admin key)") names who
    /// is driving (§7).
    pub fn start(control: bool, operator: Option<&str>) -> Banner {
        BANNER_CONTROL.store(control, Ordering::SeqCst);
        if let Ok(mut g) = BANNER_OPERATOR.lock() {
            *g = operator.unwrap_or("").to_string();
        }
        let running = Arc::new(AtomicBool::new(true));
        let hwnd = Arc::new(AtomicIsize::new(0));
        let epoch = Arc::new(AtomicU32::new(0));
        let (r, h, e) = (running.clone(), hwnd.clone(), epoch.clone());
        let thread = thread::spawn(move || banner_thread(r, h, e));
        Banner { running, hwnd, epoch, thread: Some(thread) }
    }

    /// Tell the banner thread the input desktop changed: it recreates its window
    /// on the new desktop (§6.1, §7).
    pub fn note_desktop_switch(&self) {
        self.epoch.fetch_add(1, Ordering::SeqCst);
    }

    /// Show the local consent prompt on the banner UI thread and block until the
    /// person answers or it times out (§7). Returns true to allow. The prompt is
    /// created on the banner's own thread (the only one that may own windows on
    /// the input desktop, §6.1) by posting it a message. With no banner window
    /// yet, there is nothing to ask on, so this denies (fail safe).
    pub fn request_consent(&self, control: bool, operator: Option<&str>) -> bool {
        CONSENT_CONTROL.store(control, Ordering::SeqCst);
        if let Ok(mut g) = CONSENT_OPERATOR.lock() {
            *g = operator.unwrap_or("").to_string();
        }
        CONSENT_RESULT.store(0, Ordering::SeqCst);
        // The banner window is created on its own thread just after start(), so an
        // ask that lands in that startup gap would otherwise be a spurious deny.
        // Wait (bounded, ~2 s) for the window to exist before giving up (§7).
        let mut h = self.hwnd.load(Ordering::SeqCst);
        for _ in 0..40 {
            if h != 0 {
                break;
            }
            thread::sleep(Duration::from_millis(50));
            h = self.hwnd.load(Ordering::SeqCst);
        }
        if h == 0 {
            return false;
        }
        unsafe {
            let _ = PostMessageW(Some(HWND(h as *mut core::ffi::c_void)), WM_APP_CONSENT, WPARAM(0), LPARAM(0));
        }
        // The window self-denies at 60 s; wait a little longer, then fail safe.
        for _ in 0..((CONSENT_TIMEOUT_MS / 100) + 20) {
            match CONSENT_RESULT.load(Ordering::SeqCst) {
                0 => thread::sleep(Duration::from_millis(100)),
                r => return r == 1,
            }
        }
        false
    }
}

impl Drop for Banner {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        let h = self.hwnd.load(Ordering::SeqCst);
        if h != 0 {
            unsafe {
                let _ = PostMessageW(Some(HWND(h as *mut core::ffi::c_void)), WM_CLOSE, WPARAM(0), LPARAM(0));
            }
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn banner_thread(running: Arc<AtomicBool>, hwnd_slot: Arc<AtomicIsize>, epoch: Arc<AtomicU32>) {
    unsafe {
        let hinstance = match GetModuleHandleW(None) {
            Ok(h) => h,
            Err(_) => return,
        };
        let class_name = w!("OminullScreenBanner");
        let mut wc = WNDCLASSEXW::default();
        wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = hinstance.into();
        wc.lpszClassName = class_name;
        RegisterClassExW(&wc);

        // The consent prompt (§7) lives on this same thread, created on demand.
        let mut cc = WNDCLASSEXW::default();
        cc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
        cc.lpfnWndProc = Some(consent_wndproc);
        cc.hInstance = hinstance.into();
        cc.lpszClassName = w!("OminullScreenConsent");
        RegisterClassExW(&cc);

        let mut last_epoch = epoch.load(Ordering::SeqCst);
        let mut hwnd = create_banner(class_name, hinstance.into(), &hwnd_slot);

        let mut msg = MSG::default();
        while running.load(Ordering::SeqCst) {
            // Pump available messages without blocking forever: GetMessageW
            // blocks, so the reassert timer drives periodic wakeups.
            let got = GetMessageW(&mut msg, None, 0, 0);
            if got.0 <= 0 {
                break;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);

            // Desktop switch: recreate the window on the new input desktop.
            let cur = epoch.load(Ordering::SeqCst);
            if cur != last_epoch {
                last_epoch = cur;
                if let Some(h) = hwnd {
                    let _ = DestroyWindow(h);
                }
                // The capture thread has already SetThreadDesktop'd the new
                // input desktop process-wide for new threads created there; for
                // the banner we simply recreate — if the switch outran us the
                // next epoch bump corrects it.
                hwnd = create_banner(class_name, hinstance.into(), &hwnd_slot);
            }
        }
        if let Some(h) = hwnd {
            let _ = DestroyWindow(h);
        }
        hwnd_slot.store(0, Ordering::SeqCst);
    }
}

unsafe fn create_banner(
    class_name: PCWSTR,
    hinstance: windows::Win32::Foundation::HINSTANCE,
    hwnd_slot: &Arc<AtomicIsize>,
) -> Option<HWND> {
    let hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
        class_name,
        BANNER_TEXT,
        WS_POPUP | WS_VISIBLE,
        CW_USEDEFAULT,
        0,
        800,
        BANNER_HEIGHT,
        None,
        None,
        Some(hinstance),
        None,
    )
    .ok()?;

    // ~88% opaque amber banner.
    let _ = SetLayeredWindowAttributes(hwnd, COLORREF(0), 225, LWA_ALPHA);
    reassert_topmost(hwnd);
    let _ = SetTimer(Some(hwnd), REASSERT_TIMER, 1000, None);
    hwnd_slot.store(hwnd.0 as isize, Ordering::SeqCst);
    Some(hwnd)
}

unsafe fn reassert_topmost(hwnd: HWND) {
    let _ = SetWindowPos(hwnd, Some(HWND_TOPMOST), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                let brush = CreateSolidBrush(COLORREF(0x0033_66CC)); // amber-ish BGR
                FillRect(hdc, &ps.rcPaint, brush);
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, COLORREF(0x00FF_FFFF));
                let mut rc = RECT { left: 0, top: 0, right: 800, bottom: BANNER_HEIGHT };
                let mut text: Vec<u16> = banner_caption().encode_utf16().collect();
                DrawTextW(hdc, &mut text, &mut rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            WM_TIMER => {
                if wparam.0 == REASSERT_TIMER {
                    reassert_topmost(hwnd);
                }
                LRESULT(0)
            }
            WM_APP_CONSENT => {
                // A consent request arrived from the capture/main thread: show it
                // on this (window-owning) thread, on the current input desktop.
                create_consent_window();
                LRESULT(0)
            }
            WM_CLOSE => {
                let _ = KillTimer(Some(hwnd), REASSERT_TIMER);
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => LRESULT(0),
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// Create the consent prompt window on the banner thread and arm its 60 s deny
/// timer (§7). Buttons are added in WM_CREATE; a click or the timeout writes the
/// result and destroys the window.
unsafe fn create_consent_window() {
    let hinstance = match GetModuleHandleW(None) {
        Ok(h) => h,
        Err(_) => {
            CONSENT_RESULT.store(2, Ordering::SeqCst); // cannot show -> deny (fail safe)
            return;
        }
    };
    match CreateWindowExW(
        WS_EX_TOPMOST,
        w!("OminullScreenConsent"),
        w!("Allow remote access?"),
        WS_POPUP | WS_BORDER | WS_VISIBLE,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        480,
        190,
        None,
        None,
        Some(hinstance.into()),
        None,
    ) {
        Ok(h) => {
            let _ = SetWindowPos(h, Some(HWND_TOPMOST), 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            let _ = SetForegroundWindow(h);
            let _ = SetTimer(Some(h), CONSENT_TIMER, CONSENT_TIMEOUT_MS, None);
        }
        Err(_) => CONSENT_RESULT.store(2, Ordering::SeqCst),
    }
}

extern "system" fn consent_wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CREATE => {
                let hinstance = GetModuleHandleW(None).ok().map(|h| h.into());
                let _ = CreateWindowExW(
                    Default::default(), w!("BUTTON"), w!("Allow"),
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP, 250, 118, 100, 34,
                    Some(hwnd), Some(HMENU(ID_ALLOW as *mut core::ffi::c_void)), hinstance, None,
                );
                let _ = CreateWindowExW(
                    Default::default(), w!("BUTTON"), w!("Deny"),
                    WS_CHILD | WS_VISIBLE | WS_TABSTOP, 360, 118, 100, 34,
                    Some(hwnd), Some(HMENU(ID_DENY as *mut core::ffi::c_void)), hinstance, None,
                );
                LRESULT(0)
            }
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                let brush = CreateSolidBrush(COLORREF(0x00F0_F0F0));
                FillRect(hdc, &ps.rcPaint, brush);
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, COLORREF(0x0000_0000));
                let control = CONSENT_CONTROL.load(Ordering::SeqCst);
                let op = CONSENT_OPERATOR.lock().map(|g| g.clone()).unwrap_or_default();
                let who = if op.is_empty() { "A remote operator".to_string() } else { op };
                let what = if control { "see and control" } else { "see" };
                let message = format!("{who} wants to {what} this screen through OmniNull. Allow?");
                let mut text: Vec<u16> = message.encode_utf16().collect();
                let mut rc = RECT { left: 16, top: 18, right: 464, bottom: 108 };
                DrawTextW(hdc, &mut text, &mut rc, DT_CENTER | DT_WORDBREAK);
                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            WM_COMMAND => {
                let id = (wparam.0 & 0xFFFF) as isize;
                if id == ID_ALLOW {
                    CONSENT_RESULT.store(1, Ordering::SeqCst);
                    let _ = DestroyWindow(hwnd);
                } else if id == ID_DENY {
                    CONSENT_RESULT.store(2, Ordering::SeqCst);
                    let _ = DestroyWindow(hwnd);
                }
                LRESULT(0)
            }
            WM_TIMER => {
                if wparam.0 == CONSENT_TIMER {
                    CONSENT_RESULT.store(2, Ordering::SeqCst); // no answer in time = denied (§7)
                    let _ = DestroyWindow(hwnd);
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                let _ = KillTimer(Some(hwnd), CONSENT_TIMER);
                // Destroyed without a decision (e.g. a desktop switch): record a
                // deny so request_consent never hangs.
                let _ = CONSENT_RESULT.compare_exchange(0, 2, Ordering::SeqCst, Ordering::SeqCst);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}
