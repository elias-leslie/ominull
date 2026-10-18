//! Platform keyboard grab, so Win, Alt+Tab, Esc and friends reach the remote
//! while the viewer has focus (REMOTE_SCREEN.md §9.1).
//!
//! * X11: `XGrabKeyboard` on winit's own Display connection, so key events
//!   still arrive through winit.
//! * Wayland: `zwp_keyboard_shortcuts_inhibit_manager_v1` on winit's own
//!   wl_display and wl_surface. The compositor decides: GNOME asks the user
//!   once, KDE and wlroots grant it; a compositor without the protocol (or a
//!   user who says no) leaves its own shortcuts active.
//! * Windows: a `WH_KEYBOARD_LL` hook that, while grabbed and the viewer is
//!   the foreground window, takes every key (scancode + extended flag) and
//!   hands it to the viewer, so the shell never sees Win or Alt+Tab.
//!   Ctrl+Alt+Del can never be taken (the OS owns it): the toolbar button and
//!   Ctrl+Alt+End send it instead.

use winit::window::Window;

/// Whether the grab took, for the toolbar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrabState {
    Off,
    On,
    /// Asked, but the platform did not grant it.
    Refused,
}

pub struct Grab {
    imp: imp::Imp,
    pub state: GrabState,
}

impl Grab {
    pub fn new(window: &Window) -> Grab {
        Grab { imp: imp::Imp::new(window), state: GrabState::Off }
    }

    pub fn grab(&mut self, window: &Window) -> GrabState {
        self.state = if self.imp.grab(window) { GrabState::On } else { GrabState::Refused };
        self.state
    }

    pub fn release(&mut self) {
        if self.state != GrabState::Off {
            self.imp.release();
        }
        self.state = GrabState::Off;
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod imp {
    use raw_window_handle::{HasDisplayHandle, HasWindowHandle, RawDisplayHandle, RawWindowHandle};
    use wayland_client::protocol::{wl_registry, wl_seat::WlSeat, wl_surface::WlSurface};
    use wayland_client::globals::{registry_queue_init, GlobalListContents};
    use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle};
    use wayland_protocols::wp::keyboard_shortcuts_inhibit::zv1::client::zwp_keyboard_shortcuts_inhibit_manager_v1::ZwpKeyboardShortcutsInhibitManagerV1 as InhibitManager;
    use wayland_protocols::wp::keyboard_shortcuts_inhibit::zv1::client::zwp_keyboard_shortcuts_inhibitor_v1::ZwpKeyboardShortcutsInhibitorV1 as Inhibitor;
    use winit::window::Window;

    pub enum Imp {
        X11 { xlib: Option<Box<x11_dl::xlib::Xlib>>, display: *mut x11_dl::xlib::Display, window: u64 },
        Wayland(Option<Box<Wl>>),
        None,
    }

    pub struct Wl {
        conn: Connection,
        queue: EventQueue<WlState>,
        manager: InhibitManager,
        seat: WlSeat,
        surface: WlSurface,
        inhibitor: Option<Inhibitor>,
    }

    pub struct WlState;

    impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for WlState {
        fn event(_: &mut Self, _: &wl_registry::WlRegistry, _: wl_registry::Event, _: &GlobalListContents, _: &Connection, _: &QueueHandle<Self>) {}
    }
    impl Dispatch<WlSeat, ()> for WlState {
        fn event(_: &mut Self, _: &WlSeat, _: <WlSeat as Proxy>::Event, _: &(), _: &Connection, _: &QueueHandle<Self>) {}
    }
    impl Dispatch<InhibitManager, ()> for WlState {
        fn event(_: &mut Self, _: &InhibitManager, _: <InhibitManager as Proxy>::Event, _: &(), _: &Connection, _: &QueueHandle<Self>) {}
    }
    impl Dispatch<Inhibitor, ()> for WlState {
        fn event(_: &mut Self, _: &Inhibitor, _: <Inhibitor as Proxy>::Event, _: &(), _: &Connection, _: &QueueHandle<Self>) {}
    }

    fn wayland(display: *mut std::ffi::c_void, surface: *mut std::ffi::c_void) -> Option<Wl> {
        // SAFETY: winit owns the wl_display and outlives this viewer's use of it;
        // a foreign backend does not close it on drop.
        let backend = unsafe { wayland_backend::client::Backend::from_foreign_display(display.cast()) };
        let conn = Connection::from_backend(backend);
        let (globals, queue) = registry_queue_init::<WlState>(&conn).ok()?;
        let qh = queue.handle();
        let manager: InhibitManager = globals.bind(&qh, 1..=1, ()).ok()?;
        let seat: WlSeat = globals.bind(&qh, 1..=1, ()).ok()?;
        // SAFETY: the pointer is winit's live wl_surface for this window.
        let id = unsafe { wayland_backend::client::ObjectId::from_ptr(WlSurface::interface(), surface.cast()) }.ok()?;
        let surface = WlSurface::from_id(&conn, id).ok()?;
        Some(Wl { conn, queue, manager, seat, surface, inhibitor: None })
    }

    impl Imp {
        pub fn new(window: &Window) -> Imp {
            let (Ok(d), Ok(w)) = (window.display_handle(), window.window_handle()) else { return Imp::None };
            match (d.as_raw(), w.as_raw()) {
                (RawDisplayHandle::Xlib(dh), RawWindowHandle::Xlib(wh)) => match dh.display {
                    Some(p) => Imp::X11 { xlib: x11_dl::xlib::Xlib::open().ok().map(Box::new), display: p.as_ptr().cast(), window: wh.window },
                    None => Imp::None,
                },
                (RawDisplayHandle::Wayland(dh), RawWindowHandle::Wayland(wh)) => Imp::Wayland(wayland(dh.display.as_ptr(), wh.surface.as_ptr()).map(Box::new)),
                _ => Imp::None,
            }
        }

        pub fn grab(&mut self, _window: &Window) -> bool {
            match self {
                Imp::X11 { xlib: Some(x), display, window } => {
                    // SAFETY: winit's live Display and our own window id.
                    unsafe {
                        let r = (x.XGrabKeyboard)(*display, *window, 1, x11_dl::xlib::GrabModeAsync, x11_dl::xlib::GrabModeAsync, x11_dl::xlib::CurrentTime);
                        (x.XFlush)(*display);
                        r == x11_dl::xlib::GrabSuccess
                    }
                }
                Imp::Wayland(Some(wl)) => {
                    if wl.inhibitor.is_none() {
                        let qh = wl.queue.handle();
                        wl.inhibitor = Some(wl.manager.inhibit_shortcuts(&wl.surface, &wl.seat, &qh, ()));
                    }
                    let _ = wl.conn.flush();
                    let _ = wl.queue.dispatch_pending(&mut WlState);
                    true
                }
                _ => false,
            }
        }

        pub fn release(&mut self) {
            match self {
                Imp::X11 { xlib: Some(x), display, .. } => unsafe {
                    (x.XUngrabKeyboard)(*display, x11_dl::xlib::CurrentTime);
                    (x.XFlush)(*display);
                },
                Imp::Wayland(Some(wl)) => {
                    if let Some(i) = wl.inhibitor.take() {
                        i.destroy();
                    }
                    let _ = wl.conn.flush();
                    let _ = wl.queue.dispatch_pending(&mut WlState);
                }
                _ => {}
            }
        }
    }
}

#[cfg(windows)]
pub mod imp {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use std::sync::Mutex;
    use windows_sys::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, GetForegroundWindow, SetWindowsHookExW, UnhookWindowsHookEx, HC_ACTION, KBDLLHOOKSTRUCT, LLKHF_EXTENDED, LLKHF_INJECTED,
        WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN,
    };
    use winit::window::Window;

    static GRABBED: AtomicBool = AtomicBool::new(false);
    static HWND: AtomicIsize = AtomicIsize::new(0);
    /// Where the hook delivers keys: (scancode, extended, down).
    pub type KeySink = Box<dyn Fn(u8, bool, bool) + Send>;
    pub static SINK: Mutex<Option<KeySink>> = Mutex::new(None);

    unsafe extern "system" fn hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        if code == HC_ACTION as i32 && GRABBED.load(Ordering::Relaxed) && GetForegroundWindow() == HWND.load(Ordering::Relaxed) {
            let k = &*(lparam as *const KBDLLHOOKSTRUCT);
            if k.flags & LLKHF_INJECTED == 0 && k.scanCode > 0 && k.scanCode < 0x100 {
                let down = wparam == WM_KEYDOWN as usize || wparam == WM_SYSKEYDOWN as usize;
                if let Ok(s) = SINK.lock() {
                    if let Some(f) = s.as_ref() {
                        f(k.scanCode as u8, k.flags & LLKHF_EXTENDED != 0, down);
                        return 1;
                    }
                }
            }
        }
        CallNextHookEx(0, code, wparam, lparam)
    }

    pub struct Imp {
        hook: isize,
    }

    impl Imp {
        pub fn new(window: &Window) -> Imp {
            if let Ok(h) = window.window_handle() {
                if let RawWindowHandle::Win32(w) = h.as_raw() {
                    HWND.store(w.hwnd.get(), Ordering::Relaxed);
                }
            }
            // SAFETY: a process-wide low-level hook on this (message-pumping) thread.
            let hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook), GetModuleHandleW(std::ptr::null()), 0) };
            Imp { hook }
        }
        pub fn grab(&mut self, _window: &Window) -> bool {
            GRABBED.store(self.hook != 0, Ordering::Relaxed);
            self.hook != 0
        }
        pub fn release(&mut self) {
            GRABBED.store(false, Ordering::Relaxed);
        }
    }

    impl Drop for Imp {
        fn drop(&mut self) {
            GRABBED.store(false, Ordering::Relaxed);
            if self.hook != 0 {
                unsafe { UnhookWindowsHookEx(self.hook) };
            }
        }
    }
}

#[cfg(not(any(windows, all(unix, not(target_os = "macos")))))]
mod imp {
    use winit::window::Window;
    pub struct Imp;
    impl Imp {
        pub fn new(_: &Window) -> Imp {
            Imp
        }
        pub fn grab(&mut self, _: &Window) -> bool {
            false
        }
        pub fn release(&mut self) {}
    }
}

#[cfg(windows)]
pub use imp::SINK as WINDOWS_KEY_SINK;
