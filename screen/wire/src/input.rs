//! Strict validation of operator input (§4.2, §6.3). The helper runs as SYSTEM
//! and these events arrive from the network, so every bound is checked here
//! before anything reaches input injection; a malformed event is **dropped**,
//! never clamped into a different action (§7, §6.7).

use crate::proto::RawInput;

/// Wheel delta sanity bound (§4.2): 120 per notch; past ±1200 (ten notches in
/// one event) is dropped as implausible.
pub const WHEEL_LIMIT: i32 = 1200;

/// Normalized coordinate space for the active monitor's picture (§4.2).
pub const COORD_MAX: i64 = 65535;

/// A validated, injectable input event. Coordinates stay in the normalized
/// 0..65535 active-monitor space; the backend maps them to virtual-desktop
/// absolute at injection time (§6.3), since only it knows the live monitor rects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputEvent {
    Mouse { x: u16, y: u16, left: bool, right: bool, middle: bool, monitor: u32 },
    Wheel { dx: i32, dy: i32, monitor: u32 },
    Key { scancode: u16, down: bool, extended: bool },
    /// Validated UTF-16 code units (what KEYEVENTF_UNICODE injects).
    Text { units: Vec<u16> },
    Sas,
}

/// Validates one raw `input` event against the live monitor count. Returns the
/// typed event, or `None` if anything is out of contract (caller drops it).
/// `monitor_count` is how many monitors the backend reports; a `monitor` index
/// must be `< monitor_count`.
pub fn validate(raw: &RawInput, monitor_count: u32) -> Option<InputEvent> {
    match raw.ev.as_str() {
        "mouse" => {
            let x = in_coord(raw.x?)?;
            let y = in_coord(raw.y?)?;
            let monitor = valid_monitor(raw.monitor, monitor_count)?;
            let b = raw.buttons.unwrap_or_default();
            Some(InputEvent::Mouse { x, y, left: b.l, right: b.r, middle: b.m, monitor })
        }
        "wheel" => {
            let dx = in_wheel(raw.dx.unwrap_or(0))?;
            let dy = in_wheel(raw.dy.unwrap_or(0))?;
            let monitor = valid_monitor(raw.monitor, monitor_count)?;
            if dx == 0 && dy == 0 {
                return None;
            }
            Some(InputEvent::Wheel { dx, dy, monitor })
        }
        "key" => {
            let code = raw.code?;
            // A scancode is a 16-bit value (set-1 make code incl. the 0xE0xx
            // extended space). Reject anything outside; never mask it.
            if !(0..=0xFFFF).contains(&code) {
                return None;
            }
            Some(InputEvent::Key {
                scancode: code as u16,
                down: raw.down.unwrap_or(true),
                extended: raw.ext.unwrap_or(false),
            })
        }
        "text" => {
            let ch = raw.ch.as_ref()?;
            if ch.is_empty() || ch.len() > 64 {
                return None;
            }
            let units: Vec<u16> = ch.encode_utf16().collect();
            if units.is_empty() || units.len() > 128 {
                return None;
            }
            Some(InputEvent::Text { units })
        }
        "sas" => Some(InputEvent::Sas),
        _ => None,
    }
}

fn in_coord(v: i64) -> Option<u16> {
    (0..=COORD_MAX).contains(&v).then_some(v as u16)
}

fn in_wheel(v: i64) -> Option<i32> {
    (-(WHEEL_LIMIT as i64)..=(WHEEL_LIMIT as i64)).contains(&v).then_some(v as i32)
}

fn valid_monitor(m: Option<i64>, count: u32) -> Option<u32> {
    let m = m.unwrap_or(0);
    (m >= 0 && (m as u64) < count as u64).then_some(m as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{parse_in, InMsg};

    fn raw(json: &str) -> RawInput {
        match parse_in(json.as_bytes()).unwrap() {
            InMsg::Input(r) => r,
            _ => panic!("not an input frame"),
        }
    }

    #[test]
    fn mouse_in_bounds_ok() {
        let r = raw(r#"{"type":"input","ev":"mouse","x":32768,"y":100,"buttons":{"l":true},"monitor":0}"#);
        assert_eq!(
            validate(&r, 2).unwrap(),
            InputEvent::Mouse { x: 32768, y: 100, left: true, right: false, middle: false, monitor: 0 }
        );
    }

    #[test]
    fn mouse_out_of_range_dropped() {
        assert!(validate(&raw(r#"{"type":"input","ev":"mouse","x":70000,"y":0,"monitor":0}"#), 1).is_none());
        assert!(validate(&raw(r#"{"type":"input","ev":"mouse","x":-1,"y":0,"monitor":0}"#), 1).is_none());
    }

    #[test]
    fn mouse_bad_monitor_dropped() {
        assert!(validate(&raw(r#"{"type":"input","ev":"mouse","x":0,"y":0,"monitor":5}"#), 2).is_none());
    }

    #[test]
    fn wheel_range_and_convention() {
        assert_eq!(
            validate(&raw(r#"{"type":"input","ev":"wheel","dx":0,"dy":120,"monitor":0}"#), 1).unwrap(),
            InputEvent::Wheel { dx: 0, dy: 120, monitor: 0 }
        );
        assert!(validate(&raw(r#"{"type":"input","ev":"wheel","dx":0,"dy":5000,"monitor":0}"#), 1).is_none());
        assert!(validate(&raw(r#"{"type":"input","ev":"wheel","dx":0,"dy":0,"monitor":0}"#), 1).is_none());
    }

    #[test]
    fn key_scancode_bounds() {
        assert_eq!(
            validate(&raw(r#"{"type":"input","ev":"key","code":30,"down":true,"ext":false}"#), 1).unwrap(),
            InputEvent::Key { scancode: 30, down: true, extended: false }
        );
        assert!(validate(&raw(r#"{"type":"input","ev":"key","code":70000,"down":true}"#), 1).is_none());
        assert!(validate(&raw(r#"{"type":"input","ev":"key","code":-1,"down":true}"#), 1).is_none());
    }

    #[test]
    fn text_event_to_utf16() {
        match validate(&raw(r#"{"type":"input","ev":"text","ch":"A"}"#), 1).unwrap() {
            InputEvent::Text { units } => assert_eq!(units, vec![0x41]),
            _ => panic!("expected text"),
        }
        assert!(validate(&raw(r#"{"type":"input","ev":"text","ch":""}"#), 1).is_none());
    }

    #[test]
    fn sas_and_unknown() {
        assert_eq!(validate(&raw(r#"{"type":"input","ev":"sas"}"#), 1).unwrap(), InputEvent::Sas);
        assert!(validate(&raw(r#"{"type":"input","ev":"teleport","x":0,"y":0}"#), 1).is_none());
    }
}
