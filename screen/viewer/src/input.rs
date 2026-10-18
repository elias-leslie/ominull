//! Operator input frames (REMOTE_SCREEN.md §4.2) and the held-key/button
//! state, so every path (focus loss, release-grab, view-only, end, ctl exit)
//! can put everything back up.

use crate::keymap::Scan;
use screen_wire::{InMsg, RawButtons, RawInput};

fn raw(ev: &str) -> RawInput {
    RawInput { ev: ev.into(), x: None, y: None, buttons: None, monitor: None, dx: None, dy: None, code: None, down: None, ext: None, ch: None }
}

pub fn mouse(x: u16, y: u16, b: RawButtons, monitor: u32) -> String {
    InMsg::Input(RawInput { x: Some(x as i64), y: Some(y as i64), buttons: Some(b), monitor: Some(monitor as i64), ..raw("mouse") }).to_json()
}

pub fn wheel(dx: i32, dy: i32, monitor: u32) -> String {
    InMsg::Input(RawInput { dx: Some(dx as i64), dy: Some(dy as i64), monitor: Some(monitor as i64), ..raw("wheel") }).to_json()
}

pub fn key(s: Scan, down: bool) -> String {
    InMsg::Input(RawInput { code: Some(s.code as i64), down: Some(down), ext: Some(s.ext), ..raw("key") }).to_json()
}

pub fn text(ch: &str) -> String {
    InMsg::Input(RawInput { ch: Some(ch.into()), ..raw("text") }).to_json()
}

pub fn sas() -> String {
    InMsg::Input(raw("sas")).to_json()
}

pub fn set_monitor(monitor: u32) -> String {
    InMsg::SetMonitor { monitor }.to_json()
}

pub fn quality(fps: u32, jpeg_q: u32) -> String {
    InMsg::Quality { fps: Some(fps), jpeg_q: Some(jpeg_q) }.to_json()
}

/// Splits text into the units sent as `text` events: one per grapheme-ish
/// cluster (a base character plus following combining marks / joiners /
/// variation selectors), capped by the helper's 64-byte limit.
pub fn text_units(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut join_next = false;
    for c in s.chars() {
        let attach = join_next || is_extender(c);
        join_next = c == '\u{200d}';
        match out.last_mut() {
            Some(last) if attach && last.len() + c.len_utf8() <= 64 => last.push(c),
            _ => out.push(c.to_string()),
        }
    }
    out
}

fn is_extender(c: char) -> bool {
    matches!(c as u32,
        0x0300..=0x036f | 0x1ab0..=0x1aff | 0x1dc0..=0x1dff | 0x20d0..=0x20ff | 0xfe20..=0xfe2f // combining marks
        | 0xfe00..=0xfe0f | 0xe0100..=0xe01ef // variation selectors
        | 0x200d // zero-width joiner
        | 0x1f3fb..=0x1f3ff // skin tones
        | 0xe0020..=0xe007f) // tag characters
}

/// Held keys and buttons on the far side.
#[derive(Default, Debug)]
pub struct Held {
    keys: Vec<Scan>,
    pub buttons: RawButtons,
    /// The last pointer position sent, for the button-release frame.
    pub last: Option<(u16, u16, u32)>,
}

impl Held {
    /// Records a key change; returns false for an up of a key never sent down.
    pub fn key(&mut self, s: Scan, down: bool) -> bool {
        if down {
            if !self.keys.contains(&s) {
                self.keys.push(s);
            }
            true
        } else if let Some(i) = self.keys.iter().position(|k| *k == s) {
            self.keys.remove(i);
            true
        } else {
            false
        }
    }

    pub fn any(&self) -> bool {
        !self.keys.is_empty() || self.buttons.l || self.buttons.r || self.buttons.m
    }

    /// Frames that put every held key and button back up, newest key first.
    pub fn release_all(&mut self) -> Vec<String> {
        let mut out: Vec<String> = self.keys.drain(..).rev().map(|k| key(k, false)).collect();
        let b = self.buttons;
        if b.l || b.r || b.m {
            self.buttons = RawButtons::default();
            if let Some((x, y, m)) = self.last {
                out.push(mouse(x, y, RawButtons::default(), m));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keymap::{LALT, LCTRL};

    #[test]
    fn frames_match_the_contract() {
        assert_eq!(mouse(1, 2, RawButtons { l: true, r: false, m: false }, 0), r#"{"type":"input","ev":"mouse","x":1,"y":2,"buttons":{"l":true,"r":false,"m":false},"monitor":0}"#);
        assert_eq!(wheel(0, 120, 1), r#"{"type":"input","ev":"wheel","monitor":1,"dx":0,"dy":120}"#);
        assert_eq!(key(Scan { code: 0x4b, ext: true }, true), r#"{"type":"input","ev":"key","code":75,"down":true,"ext":true}"#);
        assert_eq!(text("é"), r#"{"type":"input","ev":"text","ch":"é"}"#);
        assert_eq!(sas(), r#"{"type":"input","ev":"sas"}"#);
        assert_eq!(set_monitor(2), r#"{"type":"set_monitor","monitor":2}"#);
        assert_eq!(quality(5, 45), r#"{"type":"quality","fps":5,"jpeg_q":45}"#);
    }

    #[test]
    fn release_all_ups_everything_once() {
        let mut h = Held::default();
        assert!(h.key(LCTRL, true));
        assert!(h.key(LALT, true));
        assert!(!h.key(Scan { code: 0x1e, ext: false }, false), "up without down is dropped");
        h.buttons.l = true;
        h.last = Some((10, 20, 0));
        let ups = h.release_all();
        assert_eq!(ups.len(), 3);
        assert!(ups[0].contains(r#""code":56"#) && ups[0].contains(r#""down":false"#), "alt up first");
        assert!(ups[2].contains(r#""l":false"#));
        assert!(!h.any());
        assert!(h.release_all().is_empty());
    }

    #[test]
    fn text_clusters() {
        assert_eq!(text_units("ab"), vec!["a", "b"]);
        assert_eq!(text_units("e\u{301}x"), vec!["e\u{301}", "x"]);
        assert_eq!(text_units("👍🏽!"), vec!["👍🏽", "!"]);
        assert_eq!(text_units("👨\u{200d}👩"), vec!["👨\u{200d}👩"]);
    }
}
