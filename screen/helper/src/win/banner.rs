//! The always-on "being viewed remotely" banner (§7). It lives on its own UI
//! thread because a window pins a thread to one desktop and SetThreadDesktop
//! then fails (§6.1); the capture/input thread must stay window-free. On a
//! desktop switch the window is destroyed and recreated on the new desktop (you
//! cannot move a window between desktops). It is topmost, click-through
//! (WS_EX_TRANSPARENT), non-activating, and re-asserts topmost on a timer so the
//! viewer cannot bury it.

use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateSolidBrush, DrawTextW, EndPaint, FillRect, SetBkMode, SetTextColor,
    DT_CENTER, DT_SINGLELINE, DT_VCENTER, PAINTSTRUCT, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, KillTimer,
    PostMessageW, RegisterClassExW, SetLayeredWindowAttributes, SetTimer, SetWindowPos,
    TranslateMessage, CW_USEDEFAULT, HWND_TOPMOST, LWA_ALPHA, MSG, SWP_NOACTIVATE, SWP_NOMOVE,
    SWP_NOSIZE, WM_CLOSE, WM_DESTROY, WM_PAINT, WM_TIMER, WNDCLASSEXW, WS_EX_LAYERED,
    WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP, WS_VISIBLE,
};

const BANNER_TEXT: PCWSTR = w!("This screen is being viewed remotely (OmniNull)");
const BANNER_HEIGHT: i32 = 34;
const REASSERT_TIMER: usize = 1;

pub struct Banner {
    running: Arc<AtomicBool>,
    hwnd: Arc<AtomicIsize>,
    epoch: Arc<AtomicU32>,
    thread: Option<JoinHandle<()>>,
}

impl Banner {
    /// Spawn the banner UI thread. It shows at once on the current desktop.
    pub fn start() -> Banner {
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
                let mut text: Vec<u16> =
                    "This screen is being viewed remotely (OmniNull)".encode_utf16().collect();
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
