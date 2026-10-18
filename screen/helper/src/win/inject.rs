//! `SendInput` injection (§6.3) and the `sas.dll` Ctrl+Alt+Del path (§6.4).
//!
//! Normalized 0..65535 active-monitor coordinates are mapped into the monitor's
//! rect and then to virtual-desktop absolute, so injection is resolution- and
//! DPI-agnostic (the process is PER_MONITOR_AWARE_V2). The injector tracks every
//! held key and mouse button so `release_all` can lift them on pause/detach/end
//! (§4.2), leaving nothing stuck down on the endpoint.

use std::collections::HashSet;
use std::mem::size_of;

use windows::core::{BOOL, PCSTR};
use windows::Win32::Foundation::{FreeLibrary, ERROR_SUCCESS, FALSE};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryExA, LOAD_LIBRARY_SEARCH_SYSTEM32};
use windows::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE, MOUSEINPUT,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

use screen_wire::input::InputEvent;

use crate::backend::{Monitor, SasResult};

#[derive(Default)]
pub struct Injector {
    held_scancodes: HashSet<u16>,
    held_extended: HashSet<u16>,
    left: bool,
    right: bool,
    middle: bool,
}

impl Injector {
    pub fn new() -> Self {
        Injector::default()
    }

    /// Inject one validated event against the active monitor's geometry.
    pub fn inject(&mut self, ev: &InputEvent, active: &Monitor) {
        match ev {
            InputEvent::Mouse { x, y, left, right, middle, .. } => {
                self.mouse_move(*x, *y, active);
                self.mouse_buttons(*left, *right, *middle);
            }
            InputEvent::Wheel { dx, dy, .. } => self.wheel(*dx, *dy),
            InputEvent::Key { scancode, down, extended } => self.key(*scancode, *down, *extended),
            InputEvent::Text { units } => self.text(units),
            InputEvent::Sas => { /* handled via send_sas() */ }
        }
    }

    fn mouse_move(&self, x: u16, y: u16, mon: &Monitor) {
        // Normalized (0..65535) across the active monitor -> desktop pixel ->
        // virtual-desktop absolute 0..65535 (§4.2/§6.3).
        let px = mon.x as i64 + (x as i64 * mon.w as i64) / 65536;
        let py = mon.y as i64 + (y as i64 * mon.h as i64) / 65536;
        let (vx, vy, vw, vh) = virtual_desktop();
        let aw = (vw - 1).max(1) as i64;
        let ah = (vh - 1).max(1) as i64;
        let ax = ((px - vx as i64) * 65535 / aw).clamp(0, 65535) as i32;
        let ay = ((py - vy as i64) * 65535 / ah).clamp(0, 65535) as i32;
        send_mouse(ax, ay, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK);
    }

    fn mouse_buttons(&mut self, left: bool, right: bool, middle: bool) {
        if left != self.left {
            send_mouse(0, 0, 0, if left { MOUSEEVENTF_LEFTDOWN } else { MOUSEEVENTF_LEFTUP });
            self.left = left;
        }
        if right != self.right {
            send_mouse(0, 0, 0, if right { MOUSEEVENTF_RIGHTDOWN } else { MOUSEEVENTF_RIGHTUP });
            self.right = right;
        }
        if middle != self.middle {
            send_mouse(0, 0, 0, if middle { MOUSEEVENTF_MIDDLEDOWN } else { MOUSEEVENTF_MIDDLEUP });
            self.middle = middle;
        }
    }

    fn wheel(&self, dx: i32, dy: i32) {
        // Windows convention, 120/notch (§4.2). Positive dy = up, dx = right.
        if dy != 0 {
            send_mouse(0, 0, dy as u32, MOUSEEVENTF_WHEEL);
        }
        if dx != 0 {
            send_mouse(0, 0, dx as u32, MOUSEEVENTF_HWHEEL);
        }
    }

    fn key(&mut self, scancode: u16, down: bool, extended: bool) {
        let mut flags = KEYEVENTF_SCANCODE;
        if extended {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        if !down {
            flags |= KEYEVENTF_KEYUP;
        }
        send_key(scancode, flags);
        if down {
            if extended {
                self.held_extended.insert(scancode);
            } else {
                self.held_scancodes.insert(scancode);
            }
        } else if extended {
            self.held_extended.remove(&scancode);
        } else {
            self.held_scancodes.remove(&scancode);
        }
    }

    fn text(&self, units: &[u16]) {
        for &u in units {
            send_unicode(u, false);
            send_unicode(u, true);
        }
    }

    /// Lift every held key and mouse button (§4.2).
    pub fn release_all(&mut self) {
        let normal: Vec<u16> = self.held_scancodes.drain().collect();
        for sc in normal {
            send_key(sc, KEYEVENTF_SCANCODE | KEYEVENTF_KEYUP);
        }
        let ext: Vec<u16> = self.held_extended.drain().collect();
        for sc in ext {
            send_key(sc, KEYEVENTF_SCANCODE | KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP);
        }
        if self.left {
            send_mouse(0, 0, 0, MOUSEEVENTF_LEFTUP);
            self.left = false;
        }
        if self.right {
            send_mouse(0, 0, 0, MOUSEEVENTF_RIGHTUP);
            self.right = false;
        }
        if self.middle {
            send_mouse(0, 0, 0, MOUSEEVENTF_MIDDLEUP);
            self.middle = false;
        }
    }
}

fn virtual_desktop() -> (i32, i32, i32, i32) {
    unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    }
}

fn send_mouse(dx: i32, dy: i32, mouse_data: u32, flags: MOUSE_EVENT_FLAGS) {
    let input = INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT { dx, dy, mouseData: mouse_data, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    };
    unsafe {
        SendInput(&[input], size_of::<INPUT>() as i32);
    }
}

fn send_key(scancode: u16, flags: KEYBD_EVENT_FLAGS) {
    let input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT { wVk: VIRTUAL_KEY(0), wScan: scancode, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    };
    unsafe {
        SendInput(&[input], size_of::<INPUT>() as i32);
    }
}

fn send_unicode(unit: u16, up: bool) {
    let mut flags = KEYEVENTF_UNICODE;
    if up {
        flags |= KEYEVENTF_KEYUP;
    }
    let input = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT { wVk: VIRTUAL_KEY(0), wScan: unit, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    };
    unsafe {
        SendInput(&[input], size_of::<INPUT>() as i32);
    }
}

/// Ctrl+Alt+Del (§6.4). `SoftwareSASGeneration` "not configured" means disabled
/// (the default), and we never write it; so we read it, and only call `SendSAS`
/// when services are permitted (bit 0). Otherwise the viewer is told it is off.
/// `sas.dll` is loaded SYSTEM32-only (mingw lacks the import lib).
pub fn send_sas() -> SasResult {
    if !sas_policy_allows_services() {
        return SasResult::Unavailable;
    }
    unsafe {
        let module = match LoadLibraryExA(PCSTR(b"sas.dll\0".as_ptr()), None, LOAD_LIBRARY_SEARCH_SYSTEM32) {
            Ok(m) if !m.is_invalid() => m,
            _ => return SasResult::Unavailable,
        };
        let result = match GetProcAddress(module, PCSTR(b"SendSAS\0".as_ptr())) {
            Some(p) => {
                let send_sas: unsafe extern "system" fn(BOOL) = std::mem::transmute(p);
                send_sas(FALSE);
                SasResult::Sent
            }
            None => SasResult::Unavailable,
        };
        let _ = FreeLibrary(module);
        result
    }
}

fn sas_policy_allows_services() -> bool {
    // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System :
    // SoftwareSASGeneration, bit0 = services allowed. Absent = disabled.
    let subkey: Vec<u16> =
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\0".encode_utf16().collect();
    let value: Vec<u16> = "SoftwareSASGeneration\0".encode_utf16().collect();
    let mut data: u32 = 0;
    let mut size: u32 = size_of::<u32>() as u32;
    unsafe {
        let status = RegGetValueW(
            HKEY_LOCAL_MACHINE,
            pcwstr_of(&subkey),
            pcwstr_of(&value),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut u32 as *mut core::ffi::c_void),
            Some(&mut size),
        );
        status == ERROR_SUCCESS && (data & 0x1) != 0
    }
}

fn pcwstr_of(buf: &[u16]) -> windows::core::PCWSTR {
    windows::core::PCWSTR(buf.as_ptr())
}
