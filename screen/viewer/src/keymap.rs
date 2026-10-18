//! Keys as PC set-1 scancodes with the E0 `ext` flag (REMOTE_SCREEN.md §4.2):
//! winit physical keys for the window, and key names for `ctl key`.

use winit::keyboard::KeyCode;

/// A set-1 make code and whether it is an E0 (extended) key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Scan {
    pub code: u8,
    pub ext: bool,
}

const fn s(code: u8) -> Option<Scan> {
    Some(Scan { code, ext: false })
}
const fn e(code: u8) -> Option<Scan> {
    Some(Scan { code, ext: true })
}

pub const LCTRL: Scan = Scan { code: 0x1d, ext: false };
pub const RCTRL: Scan = Scan { code: 0x1d, ext: true };
pub const LSHIFT: Scan = Scan { code: 0x2a, ext: false };
pub const RSHIFT: Scan = Scan { code: 0x36, ext: false };
pub const LALT: Scan = Scan { code: 0x38, ext: false };
pub const RALT: Scan = Scan { code: 0x38, ext: true };
pub const LWIN: Scan = Scan { code: 0x5b, ext: true };
pub const RWIN: Scan = Scan { code: 0x5c, ext: true };

/// The physical key position -> scancode. Layout-independent, so the
/// endpoint's own layout applies.
pub fn from_keycode(k: KeyCode) -> Option<Scan> {
    use KeyCode::*;
    match k {
        Escape => s(0x01),
        Digit1 => s(0x02),
        Digit2 => s(0x03),
        Digit3 => s(0x04),
        Digit4 => s(0x05),
        Digit5 => s(0x06),
        Digit6 => s(0x07),
        Digit7 => s(0x08),
        Digit8 => s(0x09),
        Digit9 => s(0x0a),
        Digit0 => s(0x0b),
        Minus => s(0x0c),
        Equal => s(0x0d),
        Backspace => s(0x0e),
        Tab => s(0x0f),
        KeyQ => s(0x10),
        KeyW => s(0x11),
        KeyE => s(0x12),
        KeyR => s(0x13),
        KeyT => s(0x14),
        KeyY => s(0x15),
        KeyU => s(0x16),
        KeyI => s(0x17),
        KeyO => s(0x18),
        KeyP => s(0x19),
        BracketLeft => s(0x1a),
        BracketRight => s(0x1b),
        Enter => s(0x1c),
        ControlLeft => s(0x1d),
        KeyA => s(0x1e),
        KeyS => s(0x1f),
        KeyD => s(0x20),
        KeyF => s(0x21),
        KeyG => s(0x22),
        KeyH => s(0x23),
        KeyJ => s(0x24),
        KeyK => s(0x25),
        KeyL => s(0x26),
        Semicolon => s(0x27),
        Quote => s(0x28),
        Backquote => s(0x29),
        ShiftLeft => s(0x2a),
        Backslash => s(0x2b),
        KeyZ => s(0x2c),
        KeyX => s(0x2d),
        KeyC => s(0x2e),
        KeyV => s(0x2f),
        KeyB => s(0x30),
        KeyN => s(0x31),
        KeyM => s(0x32),
        Comma => s(0x33),
        Period => s(0x34),
        Slash => s(0x35),
        ShiftRight => s(0x36),
        NumpadMultiply => s(0x37),
        AltLeft => s(0x38),
        Space => s(0x39),
        CapsLock => s(0x3a),
        F1 => s(0x3b),
        F2 => s(0x3c),
        F3 => s(0x3d),
        F4 => s(0x3e),
        F5 => s(0x3f),
        F6 => s(0x40),
        F7 => s(0x41),
        F8 => s(0x42),
        F9 => s(0x43),
        F10 => s(0x44),
        NumLock => s(0x45),
        ScrollLock => s(0x46),
        Numpad7 => s(0x47),
        Numpad8 => s(0x48),
        Numpad9 => s(0x49),
        NumpadSubtract => s(0x4a),
        Numpad4 => s(0x4b),
        Numpad5 => s(0x4c),
        Numpad6 => s(0x4d),
        NumpadAdd => s(0x4e),
        Numpad1 => s(0x4f),
        Numpad2 => s(0x50),
        Numpad3 => s(0x51),
        Numpad0 => s(0x52),
        NumpadDecimal => s(0x53),
        IntlBackslash => s(0x56),
        F11 => s(0x57),
        F12 => s(0x58),
        F13 => s(0x64),
        F14 => s(0x65),
        F15 => s(0x66),
        F16 => s(0x67),
        F17 => s(0x68),
        F18 => s(0x69),
        F19 => s(0x6a),
        F20 => s(0x6b),
        F21 => s(0x6c),
        F22 => s(0x6d),
        F23 => s(0x6e),
        KanaMode => s(0x70),
        IntlRo => s(0x73),
        F24 => s(0x76),
        Convert => s(0x79),
        NonConvert => s(0x7b),
        IntlYen => s(0x7d),
        NumpadEnter => e(0x1c),
        ControlRight => e(0x1d),
        NumpadDivide => e(0x35),
        PrintScreen => e(0x37),
        AltRight => e(0x38),
        Pause => e(0x46),
        Home => e(0x47),
        ArrowUp => e(0x48),
        PageUp => e(0x49),
        ArrowLeft => e(0x4b),
        ArrowRight => e(0x4d),
        End => e(0x4f),
        ArrowDown => e(0x50),
        PageDown => e(0x51),
        Insert => e(0x52),
        Delete => e(0x53),
        SuperLeft => e(0x5b),
        SuperRight => e(0x5c),
        ContextMenu => e(0x5d),
        AudioVolumeMute => e(0x20),
        AudioVolumeDown => e(0x2e),
        AudioVolumeUp => e(0x30),
        MediaPlayPause => e(0x22),
        MediaStop => e(0x24),
        MediaTrackPrevious => e(0x10),
        MediaTrackNext => e(0x19),
        _ => None,
    }
}

/// `ctl key` names -> scancode.
pub fn from_name(name: &str) -> Option<Scan> {
    let n = name.to_ascii_lowercase();
    let k = match n.as_str() {
        "ctrl" | "control" | "lctrl" => return Some(LCTRL),
        "rctrl" => return Some(RCTRL),
        "shift" | "lshift" => return Some(LSHIFT),
        "rshift" => return Some(RSHIFT),
        "alt" | "lalt" => return Some(LALT),
        "ralt" | "altgr" => return Some(RALT),
        "win" | "super" | "meta" | "cmd" => return Some(LWIN),
        "enter" | "return" => KeyCode::Enter,
        "esc" | "escape" => KeyCode::Escape,
        "tab" => KeyCode::Tab,
        "space" => KeyCode::Space,
        "backspace" | "bksp" => KeyCode::Backspace,
        "del" | "delete" => KeyCode::Delete,
        "ins" | "insert" => KeyCode::Insert,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        "pgup" | "pageup" => KeyCode::PageUp,
        "pgdn" | "pagedown" => KeyCode::PageDown,
        "up" => KeyCode::ArrowUp,
        "down" => KeyCode::ArrowDown,
        "left" => KeyCode::ArrowLeft,
        "right" => KeyCode::ArrowRight,
        "menu" | "apps" => KeyCode::ContextMenu,
        "prtsc" | "printscreen" => KeyCode::PrintScreen,
        "capslock" => KeyCode::CapsLock,
        _ => {
            if let Some(f) = n.strip_prefix('f').and_then(|d| d.parse::<u8>().ok()) {
                const F: [KeyCode; 12] = [
                    KeyCode::F1,
                    KeyCode::F2,
                    KeyCode::F3,
                    KeyCode::F4,
                    KeyCode::F5,
                    KeyCode::F6,
                    KeyCode::F7,
                    KeyCode::F8,
                    KeyCode::F9,
                    KeyCode::F10,
                    KeyCode::F11,
                    KeyCode::F12,
                ];
                return F.get((f as usize).checked_sub(1)?).and_then(|k| from_keycode(*k));
            }
            let mut chars = n.chars();
            let (Some(c), None) = (chars.next(), chars.next()) else { return None };
            return char_key(c).and_then(from_keycode);
        }
    };
    from_keycode(k)
}

fn char_key(c: char) -> Option<KeyCode> {
    use KeyCode::*;
    const LETTERS: [KeyCode; 26] = [
        KeyA, KeyB, KeyC, KeyD, KeyE, KeyF, KeyG, KeyH, KeyI, KeyJ, KeyK, KeyL, KeyM, KeyN, KeyO, KeyP, KeyQ, KeyR, KeyS, KeyT, KeyU,
        KeyV, KeyW, KeyX, KeyY, KeyZ,
    ];
    const DIGITS: [KeyCode; 10] = [Digit0, Digit1, Digit2, Digit3, Digit4, Digit5, Digit6, Digit7, Digit8, Digit9];
    Some(match c {
        'a'..='z' => LETTERS[(c as u8 - b'a') as usize],
        '0'..='9' => DIGITS[(c as u8 - b'0') as usize],
        '-' => Minus,
        '=' => Equal,
        '[' => BracketLeft,
        ']' => BracketRight,
        ';' => Semicolon,
        '\'' => Quote,
        '`' => Backquote,
        '\\' => Backslash,
        ',' => Comma,
        '.' => Period,
        '/' => Slash,
        _ => return None,
    })
}

pub fn is_modifier(s: Scan) -> bool {
    [LCTRL, RCTRL, LSHIFT, RSHIFT, LALT, RALT, LWIN, RWIN].contains(&s)
}

/// A parsed `ctl key` combo.
#[derive(Debug, PartialEq, Eq)]
pub enum Combo {
    /// Ctrl+Alt+Del: the `sas` request, never synthesized keys.
    Sas,
    /// Modifiers down in order, the key down/up, modifiers up in reverse.
    Keys { mods: Vec<Scan>, key: Scan },
}

pub fn parse_combo(spec: &str) -> Result<Combo, String> {
    let parts: Vec<&str> = spec.split('+').map(str::trim).collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(format!("bad key combo {spec:?}"));
    }
    let lower: Vec<String> = parts.iter().map(|p| p.to_ascii_lowercase()).collect();
    let mut set: Vec<&str> = lower.iter().map(|s| match s.as_str() {
        "control" => "ctrl",
        "delete" => "del",
        o => o,
    }).collect();
    set.sort_unstable();
    if set == ["alt", "ctrl", "del"] {
        return Ok(Combo::Sas);
    }
    let mut scans = Vec::new();
    for p in &parts {
        scans.push(from_name(p).ok_or_else(|| format!("unknown key {p:?}"))?);
    }
    let key = scans.pop().expect("non-empty");
    if scans.iter().any(|m| !is_modifier(*m)) {
        return Err(format!("in {spec:?} only the last key may be a non-modifier"));
    }
    Ok(Combo::Keys { mods: scans, key })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keycode_table() {
        assert_eq!(from_keycode(KeyCode::KeyA), s(0x1e));
        assert_eq!(from_keycode(KeyCode::Enter), s(0x1c));
        assert_eq!(from_keycode(KeyCode::NumpadEnter), e(0x1c));
        assert_eq!(from_keycode(KeyCode::ArrowLeft), e(0x4b));
        assert_eq!(from_keycode(KeyCode::Numpad4), s(0x4b), "same make code, no E0");
        assert_eq!(from_keycode(KeyCode::SuperLeft), Some(LWIN));
        assert_eq!(from_keycode(KeyCode::AltRight), Some(RALT));
        assert_eq!(from_keycode(KeyCode::F11), s(0x57));
        assert_eq!(from_keycode(KeyCode::Fn), None);
    }

    #[test]
    fn names() {
        assert_eq!(from_name("Win"), Some(LWIN));
        assert_eq!(from_name("f12"), s(0x58));
        assert_eq!(from_name("f13"), None);
        assert_eq!(from_name("f0"), None);
        assert_eq!(from_name("r"), s(0x13));
        assert_eq!(from_name("7"), s(0x08));
        assert_eq!(from_name("pgdn"), e(0x51));
        assert_eq!(from_name("nope"), None);
    }

    #[test]
    fn combos() {
        assert_eq!(parse_combo("ctrl+alt+del").unwrap(), Combo::Sas);
        assert_eq!(parse_combo("Alt+Ctrl+Delete").unwrap(), Combo::Sas);
        assert_eq!(parse_combo("win+r").unwrap(), Combo::Keys { mods: vec![LWIN], key: s(0x13).unwrap() });
        assert_eq!(parse_combo("enter").unwrap(), Combo::Keys { mods: vec![], key: s(0x1c).unwrap() });
        assert_eq!(parse_combo("ctrl").unwrap(), Combo::Keys { mods: vec![], key: LCTRL });
        assert!(parse_combo("a+b").is_err());
        assert!(parse_combo("ctrl++c").is_err());
        assert!(parse_combo("ctrl+bogus").is_err());
    }
}
