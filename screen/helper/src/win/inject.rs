//! `SendInput` injection (§6.3). Ctrl+Alt+Del (§6.4) is not here: the SAS can
//! only be issued by the agent service, so a `sas` event becomes a
//! service-request frame the agent acts on; the helper never calls SendSAS.
//!
//! Normalized 0..65535 active-monitor coordinates are mapped into the monitor's
//! rect and then to virtual-desktop absolute, so injection is resolution- and
//! DPI-agnostic (the process is PER_MONITOR_AWARE_V2). The injector tracks every
//! held key and mouse button so `release_all` can lift them on pause/detach/end
//! (§4.2), leaving nothing stuck down on the endpoint.

use std::collections::HashSet;
use std::mem::size_of;

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

use crate::backend::Monitor;

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
            // SAS is never injected here; the session turns it into a
            // service-request frame the agent service acts on (§6.4).
            InputEvent::Sas => {}
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

