//! Input-desktop following and desktop-state reporting (§6.1, §4.1).
//!
//! The capture/input thread must own no window (SetThreadDesktop fails once a
//! thread owns one, §6.1), so this runs on that thread and only switches
//! desktops. On a switch it reports the new [`DesktopState`] so the session can
//! send a `desktop` frame and the banner thread can recreate its window.

use std::mem::size_of;

use windows::core::PWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::RemoteDesktop::{
    WTSFreeMemory, WTSGetActiveConsoleSessionId, WTSQuerySessionInformationW, WTSUserName,
    WTS_CURRENT_SERVER_HANDLE,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, SetThreadDesktop,
    DESKTOP_ACCESS_FLAGS, HDESK, UOI_NAME,
};

/// Access mask for the input desktop: enough to SetThreadDesktop and read its
/// name (all DESKTOP_* bits).
const DESKTOP_ACCESS: DESKTOP_ACCESS_FLAGS = DESKTOP_ACCESS_FLAGS(0x01FF);

use crate::backend::DesktopState;

#[derive(Default)]
pub struct DesktopFollower {
    current_name: Option<String>,
    current: Option<HDESK>,
}

impl DesktopFollower {
    pub fn new() -> Self {
        DesktopFollower::default()
    }

    /// Attach this thread to the current input desktop. Returns `Some(state)`
    /// when the desktop changed since the last call (first call always reports),
    /// so the caller re-acquires DXGI and re-asserts the banner.
    pub fn follow(&mut self) -> Option<DesktopState> {
        let hdesk = unsafe {
            // 0x0100 = DESKTOP_READOBJECTS | ... ; GENERIC access is enough to
            // SetThreadDesktop and read the name.
            OpenInputDesktop(Default::default(), false, DESKTOP_ACCESS).ok()?
        };
        let name = desktop_name(hdesk);
        unsafe {
            let _ = SetThreadDesktop(hdesk);
        }
        let changed = self.current_name.as_deref() != Some(name.as_str());
        // Close the previous handle, keep the new one bound to this thread.
        if let Some(prev) = self.current.take() {
            unsafe {
                let _ = CloseDesktop(prev);
            }
        }
        self.current = Some(hdesk);
        if changed {
            self.current_name = Some(name.clone());
            Some(classify(&name))
        } else {
            None
        }
    }

    /// The current desktop state regardless of change (for the first `desktop`
    /// frame after `hello`).
    pub fn state(&mut self) -> DesktopState {
        if let Some(name) = &self.current_name {
            classify(name)
        } else {
            // Not yet followed: read it directly.
            let name = unsafe {
                match OpenInputDesktop(Default::default(), false, DESKTOP_ACCESS) {
                    Ok(h) => {
                        let n = desktop_name(h);
                        let _ = CloseDesktop(h);
                        n
                    }
                    Err(_) => "user".to_string(),
                }
            };
            classify(&name)
        }
    }
}

fn desktop_name(hdesk: HDESK) -> String {
    let mut buf = [0u16; 128];
    let mut needed: u32 = 0;
    let ok = unsafe {
        GetUserObjectInformationW(
            HANDLE(hdesk.0),
            UOI_NAME,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            (buf.len() * size_of::<u16>()) as u32,
            Some(&mut needed),
        )
    };
    if ok.is_err() {
        return String::new();
    }
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Map a desktop name + sign-in state to the wire "user|lock|secure" (§4.1).
fn classify(name: &str) -> DesktopState {
    let signed_in = console_user_signed_in();
    let n = name.to_ascii_lowercase();
    let kind = if n == "default" {
        "user"
    } else if n == "winlogon" {
        if signed_in {
            "lock"
        } else {
            "secure"
        }
    } else {
        // Screen-saver or a custom desktop: treat as the user's for the viewer.
        "user"
    };
    DesktopState { name: kind.to_string(), signed_in }
}

/// Whether a user is signed in on the active console session (WTS username set).
fn console_user_signed_in() -> bool {
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == 0xFFFF_FFFF {
        return false;
    }
    let mut p = PWSTR::null();
    let mut bytes: u32 = 0;
    let got = unsafe {
        WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            session,
            WTSUserName,
            &mut p,
            &mut bytes,
        )
    };
    if got.is_err() || p.is_null() {
        return false;
    }
    let signed_in = unsafe { !p.is_null() && *p.0 != 0 };
    unsafe {
        WTSFreeMemory(p.0 as *mut core::ffi::c_void);
    }
    signed_in
}
