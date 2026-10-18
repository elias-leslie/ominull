//! The picture side of a session: applies agent->operator messages
//! (REMOTE_SCREEN.md §4.1) to a framebuffer and cursor, and answers every
//! `frame_end` with an `ack` (§4.2/§4.3). No window, no socket: the window,
//! `ctl` and the tests all drive it the same way.

use screen_wire::{
    decode_cursor_shape, decode_tile_message, parse_out, InMsg, MonitorInfo, OutMsg, CURSOR_FORMAT_COLOR_BGRA,
    CURSOR_FORMAT_MASKED_COLOR, CURSOR_FORMAT_MONO, MSG_TYPE_CURSOR_SHAPE, MSG_TYPE_TILE,
};
use std::sync::{Arc, Mutex, MutexGuard};
use zune_jpeg::zune_core::bytestream::ZCursor;
use zune_jpeg::zune_core::colorspace::ColorSpace;
use zune_jpeg::zune_core::options::DecoderOptions;
use zune_jpeg::JpegDecoder;

/// The largest monitor side accepted from `hello`/`resized` (8K).
pub const MAX_SIDE: u32 = 8192;
/// The most framebuffer pixels one monitor may need (one `u32` each, so
/// 256 MiB at most). The hub is not trusted to bound this.
pub const MAX_FB_PIXELS: u64 = 8192 * 8192;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum State {
    Connecting,
    Waiting,
    Live,
    Ended(String),
}

/// A decoded cursor image, premultiplied-free ARGB (alpha in the top byte).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub w: u32,
    pub h: u32,
    pub hx: u32,
    pub hy: u32,
    pub argb: Vec<u32>,
}

/// What the window draws and `ctl` reads. Guarded by one mutex.
#[derive(Debug)]
pub struct Picture {
    pub monitors: Vec<MonitorInfo>,
    pub active: Option<u32>,
    /// 0x00RRGGBB, `fb_w * fb_h`, the active monitor's picture.
    pub fb: Vec<u32>,
    pub fb_w: u32,
    pub fb_h: u32,
    pub cursor: Option<Cursor>,
    /// Monitor-relative position and visibility.
    pub cursor_pos: Option<(i32, i32, bool)>,
    /// From the agent's `desktop` message: name ("user", "lock", "secure") and signed-in.
    pub desktop: Option<(String, bool)>,
    pub state: State,
    /// Set by `sas_unavailable`; the window shows it, then clears it.
    pub sas_unavailable: bool,
    /// Keyframes fully received (tiles and their `frame_end`), per active switch.
    pub keyframes_done: u64,
    /// Every whole frame applied.
    pub frames: u64,
    /// Bumped on any visible change.
    pub version: u64,
}

impl Picture {
    fn new() -> Picture {
        Picture {
            monitors: Vec::new(),
            active: None,
            fb: Vec::new(),
            fb_w: 0,
            fb_h: 0,
            cursor: None,
            cursor_pos: None,
            desktop: None,
            state: State::Connecting,
            sas_unavailable: false,
            keyframes_done: 0,
            frames: 0,
            version: 0,
        }
    }

    pub fn monitor(&self, id: u32) -> Option<&MonitorInfo> {
        self.monitors.iter().find(|m| m.id == id)
    }

    pub fn active_monitor(&self) -> Option<&MonitorInfo> {
        self.active.and_then(|a| self.monitor(a))
    }

    /// Switches the picture to monitor `id` (the caller sends `set_monitor`).
    /// The old picture is cleared; the agent replies with a keyframe.
    pub fn set_active(&mut self, id: u32) -> bool {
        let Some(m) = self.monitor(id).cloned() else { return false };
        self.active = Some(id);
        self.fb_w = m.w;
        self.fb_h = m.h;
        self.fb = vec![0; (m.w as usize) * (m.h as usize)];
        self.cursor_pos = None;
        self.keyframes_done = 0;
        if self.state == State::Live {
            self.state = State::Waiting;
        }
        self.version += 1;
        true
    }

    /// The framebuffer with the cursor drawn on top, as RGB bytes.
    pub fn composite_rgb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.fb.len() * 3);
        for &p in &self.fb {
            out.extend_from_slice(&[(p >> 16) as u8, (p >> 8) as u8, p as u8]);
        }
        if let (Some(c), Some((x, y, true))) = (&self.cursor, self.cursor_pos) {
            for cy in 0..c.h {
                for cx in 0..c.w {
                    let px = x - c.hx as i32 + cx as i32;
                    let py = y - c.hy as i32 + cy as i32;
                    if px < 0 || py < 0 || px >= self.fb_w as i32 || py >= self.fb_h as i32 {
                        continue;
                    }
                    let s = c.argb[(cy * c.w + cx) as usize];
                    let a = s >> 24;
                    if a == 0 {
                        continue;
                    }
                    let i = (py as usize * self.fb_w as usize + px as usize) * 3;
                    for (k, shift) in [(0, 16), (1, 8), (2, 0)] {
                        let sv = (s >> shift) & 0xff;
                        let dv = out[i + k] as u32;
                        out[i + k] = ((sv * a + dv * (255 - a)) / 255) as u8;
                    }
                }
            }
        }
        out
    }
}

pub struct Session {
    pic: Arc<Mutex<Picture>>,
    /// A keyframe tile for the active monitor arrived since the last frame_end.
    keyframe_in_frame: bool,
    changed: bool,
    bye: Option<String>,
    /// Set when the far side sent something the viewer refuses; the pump
    /// ends the session with this reason.
    fatal: Option<String>,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Session {
        Session { pic: Arc::new(Mutex::new(Picture::new())), keyframe_in_frame: false, changed: false, bye: None, fatal: None }
    }

    pub fn picture(&self) -> Arc<Mutex<Picture>> {
        self.pic.clone()
    }

    fn lock(&self) -> MutexGuard<'_, Picture> {
        lk(&self.pic)
    }

    /// True once after any change the window should redraw for.
    pub fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    /// The agent's `bye` reason, if it sent one.
    pub fn end_reason(&self) -> Option<String> {
        self.bye.clone()
    }

    /// Why the viewer refuses to go on, once; the pump then ends the session.
    pub fn take_fatal(&mut self) -> Option<String> {
        self.fatal.take()
    }

    pub fn set_ended(&mut self, why: &str) {
        let mut p = lk(&self.pic);
        if !matches!(p.state, State::Ended(_)) {
            p.state = State::Ended(why.to_string());
            p.version += 1;
        }
        self.changed = true;
    }

    /// One JSON text frame. Returns the replies to send (an `ack`).
    pub fn on_text(&mut self, data: &[u8]) -> Vec<String> {
        let Some(msg) = parse_out(data) else { return Vec::new() };
        let mut replies = Vec::new();
        let mut p = lk(&self.pic);
        match msg {
            OutMsg::Hello { monitors, active } | OutMsg::Resized { monitors, active } => {
                if let Some(m) = monitors.iter().find(|m| !monitor_fits(m)) {
                    let why = format!(
                        "the screen reported a {}x{} monitor, larger than this viewer accepts ({MAX_SIDE}x{MAX_SIDE})",
                        m.w, m.h
                    );
                    self.bye = Some(why.clone());
                    self.fatal = Some(why.clone());
                    p.state = State::Ended(why);
                    p.version += 1;
                    drop(p);
                    self.changed = true;
                    return replies;
                }
                let monitors: Vec<MonitorInfo> = monitors.into_iter().filter(|m| m.w > 0 && m.h > 0).collect();
                let keep = p.active.filter(|a| monitors.iter().any(|m| m.id == *a));
                let want = if monitors.iter().any(|m| m.id == active) {
                    active
                } else if let Some(k) = keep {
                    k
                } else {
                    monitors.iter().find(|m| m.primary).or(monitors.first()).map(|m| m.id).unwrap_or(0)
                };
                p.monitors = monitors;
                if p.state == State::Connecting {
                    p.state = State::Waiting;
                }
                if !p.set_active(want) {
                    p.active = None;
                    p.fb.clear();
                    p.fb_w = 0;
                    p.fb_h = 0;
                }
                self.keyframe_in_frame = false;
            }
            OutMsg::Desktop { name, signed_in } => {
                p.desktop = Some((name, signed_in));
                p.version += 1;
            }
            OutMsg::FrameEnd { monitor, frame, .. } => {
                // Every frame_end is acked, applied or not, or the agent stalls.
                replies.push(InMsg::Ack { monitor, frame }.to_json());
                if Some(monitor) == p.active {
                    p.frames += 1;
                    if self.keyframe_in_frame {
                        p.keyframes_done += 1;
                        if p.state == State::Waiting {
                            p.state = State::Live;
                        }
                    }
                    p.version += 1;
                }
                self.keyframe_in_frame = false;
            }
            OutMsg::CursorPos { x, y, visible } => {
                p.cursor_pos = Some((x, y, visible));
                p.version += 1;
            }
            OutMsg::SasUnavailable { .. } => {
                p.sas_unavailable = true;
                p.version += 1;
            }
            OutMsg::Bye { reason } => {
                let why = if reason.trim().is_empty() { "the host ended the session".to_string() } else { reason };
                self.bye = Some(why.clone());
                p.state = State::Ended(why);
                p.version += 1;
            }
            OutMsg::Unknown => return replies,
        }
        drop(p);
        self.changed = true;
        replies
    }

    /// One binary frame: a tile or a cursor shape. No replies.
    pub fn on_binary(&mut self, data: &[u8]) -> Vec<String> {
        match data.first() {
            Some(&MSG_TYPE_TILE) => self.on_tile(data),
            Some(&MSG_TYPE_CURSOR_SHAPE) => {
                if let Some(c) = parse_cursor(data) {
                    let mut p = lk(&self.pic);
                    p.cursor = Some(c);
                    p.version += 1;
                    self.changed = true;
                }
            }
            _ => {}
        }
        Vec::new()
    }

    fn on_tile(&mut self, data: &[u8]) {
        let Some((h, jpeg)) = decode_tile_message(data) else { return };
        if Some(h.monitor as u32) != self.lock().active {
            return;
        }
        let Some((w, ht, rgb)) = decode_jpeg(jpeg) else { return };
        let mut p = lk(&self.pic);
        if Some(h.monitor as u32) != p.active {
            return;
        }
        let (fw, fh) = (p.fb_w as usize, p.fb_h as usize);
        let (x0, y0) = (h.x as usize, h.y as usize);
        // Draw the decoded size, clipped to both the header and the monitor.
        let tw = w.min(if h.w == 0 { w } else { h.w as usize });
        let th = ht.min(if h.h == 0 { ht } else { h.h as usize });
        for row in 0..th {
            let y = y0 + row;
            if y >= fh {
                break;
            }
            for col in 0..tw {
                let x = x0 + col;
                if x >= fw {
                    break;
                }
                let s = (row * w + col) * 3;
                p.fb[y * fw + x] = (rgb[s] as u32) << 16 | (rgb[s + 1] as u32) << 8 | rgb[s + 2] as u32;
            }
        }
        if h.keyframe {
            self.keyframe_in_frame = true;
        }
        p.version += 1;
        self.changed = true;
    }
}

/// A monitor whose framebuffer the viewer is willing to allocate.
pub fn monitor_fits(m: &MonitorInfo) -> bool {
    m.w <= MAX_SIDE && m.h <= MAX_SIDE && (m.w as u64) * (m.h as u64) <= MAX_FB_PIXELS
}

fn lk(pic: &Mutex<Picture>) -> MutexGuard<'_, Picture> {
    pic.lock().unwrap_or_else(|p| p.into_inner())
}

/// JPEG bytes -> (width, height, RGB). Bounded to a 4096x4096 tile.
pub fn decode_jpeg(jpeg: &[u8]) -> Option<(usize, usize, Vec<u8>)> {
    let opts = DecoderOptions::default().jpeg_set_out_colorspace(ColorSpace::RGB).set_max_width(4096).set_max_height(4096);
    let mut d = JpegDecoder::new_with_options(ZCursor::new(jpeg), opts);
    let rgb = d.decode().ok()?;
    let (w, h) = d.dimensions()?;
    (rgb.len() >= w * h * 3).then_some((w, h, rgb))
}

/// A cursor-shape message -> ARGB. The screen cannot be XORed from here, so
/// an inverting pixel is drawn black, which shows on most backgrounds.
pub fn parse_cursor(msg: &[u8]) -> Option<Cursor> {
    let (h, body) = decode_cursor_shape(msg)?;
    let (w, ht) = (h.w as usize, h.h as usize);
    let mut argb = vec![0u32; w * ht];
    let px = |a: u32, r: u32, g: u32, b: u32| a << 24 | r << 16 | g << 8 | b;
    match h.format {
        CURSOR_FORMAT_COLOR_BGRA | CURSOR_FORMAT_MASKED_COLOR => {
            for (i, out) in argb.iter_mut().enumerate() {
                let (b, g, r, a) = (body[i * 4] as u32, body[i * 4 + 1] as u32, body[i * 4 + 2] as u32, body[i * 4 + 3] as u32);
                *out = if h.format == CURSOR_FORMAT_COLOR_BGRA {
                    px(a, r, g, b)
                } else if a == 0 {
                    px(255, r, g, b)
                } else if r | g | b != 0 {
                    px(255, 0, 0, 0)
                } else {
                    0
                };
            }
        }
        CURSOR_FORMAT_MONO => {
            let pitch = w.div_ceil(8);
            for y in 0..ht {
                for x in 0..w {
                    let bit = 0x80u8 >> (x & 7);
                    let and = body[y * pitch + x / 8] & bit != 0;
                    let xor = body[(y + ht) * pitch + x / 8] & bit != 0;
                    argb[y * w + x] = match (and, xor) {
                        (false, false) => px(255, 0, 0, 0),
                        (false, true) => px(255, 255, 255, 255),
                        (true, false) => 0,
                        (true, true) => px(255, 0, 0, 0),
                    };
                }
            }
        }
        _ => return None,
    }
    Some(Cursor { w: w as u32, h: ht as u32, hx: (h.hotspot_x as u32).min(w as u32 - 1), hy: (h.hotspot_y as u32).min(ht as u32 - 1), argb })
}

#[cfg(test)]
mod tests {
    use super::*;
    use screen_wire::{encode_cursor_shape, encode_tile_message};

    fn hello() -> String {
        r#"{"type":"hello","monitors":[{"id":0,"w":64,"h":32,"x":0,"y":0,"primary":true},{"id":1,"w":40,"h":20,"x":64,"y":0,"primary":false}],"active":0}"#.into()
    }

    pub(crate) fn solid_jpeg(w: u16, h: u16, rgb: [u8; 3]) -> Vec<u8> {
        let px: Vec<u8> = (0..(w as usize * h as usize)).flat_map(|_| rgb).collect();
        let mut out = Vec::new();
        jpeg_encoder::Encoder::new(&mut out, 95).encode(&px, w, h, jpeg_encoder::ColorType::Rgb).unwrap();
        out
    }

    #[test]
    fn hello_sizes_picture_and_acks_every_frame_end() {
        let mut s = Session::new();
        assert!(s.on_text(hello().as_bytes()).is_empty());
        {
            let p = s.picture();
            let p = p.lock().unwrap();
            assert_eq!((p.fb_w, p.fb_h, p.active), (64, 32, Some(0)));
            assert_eq!(p.state, State::Waiting);
        }
        // Keyframe: two tiles then frame_end.
        let red = solid_jpeg(32, 32, [250, 0, 0]);
        s.on_binary(&encode_tile_message(0, true, 0, 0, 32, 32, 1, &red));
        s.on_binary(&encode_tile_message(0, true, 32, 0, 32, 32, 1, &red));
        let acks = s.on_text(br#"{"type":"frame_end","monitor":0,"frame":1,"tiles":2}"#);
        assert_eq!(acks, vec![r#"{"type":"ack","monitor":0,"frame":1}"#.to_string()]);
        let p = s.picture();
        let p = p.lock().unwrap();
        assert_eq!(p.state, State::Live);
        assert_eq!(p.keyframes_done, 1);
        let c = p.fb[5 * 64 + 40];
        assert!((c >> 16) > 200 && (c >> 8 & 0xff) < 40, "tile painted red: {c:06x}");
    }

    #[test]
    fn frame_end_for_other_monitor_still_acked() {
        let mut s = Session::new();
        s.on_text(hello().as_bytes());
        let acks = s.on_text(br#"{"type":"frame_end","monitor":1,"frame":9,"tiles":0}"#);
        assert_eq!(acks.len(), 1);
        assert!(acks[0].contains(r#""frame":9"#));
    }

    #[test]
    fn tiles_for_inactive_monitor_and_garbage_ignored() {
        let mut s = Session::new();
        s.on_text(hello().as_bytes());
        s.on_binary(&encode_tile_message(1, true, 0, 0, 8, 8, 1, &solid_jpeg(8, 8, [255, 255, 255])));
        s.on_binary(&encode_tile_message(0, false, 0, 0, 8, 8, 2, b"not a jpeg"));
        s.on_binary(&[1, 2, 3]);
        s.on_text(b"{not json");
        assert!(s.picture().lock().unwrap().fb.iter().all(|&p| p == 0));
    }

    #[test]
    fn tile_clipped_at_monitor_edge() {
        let mut s = Session::new();
        s.on_text(hello().as_bytes());
        // A 32x32 tile at x=48 on a 64-wide monitor: half falls off.
        s.on_binary(&encode_tile_message(0, false, 48, 16, 32, 32, 1, &solid_jpeg(32, 32, [0, 0, 250])));
        let p = s.picture();
        let p = p.lock().unwrap();
        assert!(p.fb[20 * 64 + 63] & 0xff > 200);
        assert_eq!(p.fb[20 * 64 + 47], 0);
    }

    #[test]
    fn oversized_monitor_ends_session_without_allocating() {
        let mut s = Session::new();
        s.on_text(hello().as_bytes());
        let big = r#"{"type":"resized","monitors":[{"id":0,"w":16384,"h":16384,"x":0,"y":0,"primary":true}],"active":0}"#;
        assert!(s.on_text(big.as_bytes()).is_empty());
        let why = s.take_fatal().expect("session must end");
        assert!(why.contains("16384x16384") && why.contains("8192x8192"), "{why}");
        assert_eq!(s.take_fatal(), None, "reported once");
        {
            let p = s.picture();
            let p = p.lock().unwrap();
            assert_eq!(p.state, State::Ended(why.clone()));
            assert_eq!((p.fb_w, p.fb_h, p.fb.len()), (64, 32, 64 * 32), "old picture kept, nothing allocated");
        }
        assert_eq!(s.end_reason(), Some(why));
        // One side too long, even if the other is tiny, is refused as well.
        let mut s = Session::new();
        s.on_text(br#"{"type":"hello","monitors":[{"id":0,"w":8193,"h":1,"x":0,"y":0,"primary":true}],"active":0}"#);
        assert!(s.take_fatal().is_some());
        assert!(s.picture().lock().unwrap().fb.is_empty());
        // The limit itself is accepted.
        let edge = MonitorInfo { id: 0, w: MAX_SIDE, h: MAX_SIDE, x: 0, y: 0, primary: true };
        assert!(monitor_fits(&edge));
        assert!(!monitor_fits(&MonitorInfo { w: MAX_SIDE + 1, ..edge.clone() }));
    }

    #[test]
    fn bye_and_desktop_and_sas() {
        let mut s = Session::new();
        s.on_text(hello().as_bytes());
        s.on_text(br#"{"type":"desktop","name":"lock","signed_in":true}"#);
        s.on_text(br#"{"type":"sas_unavailable","reason":"policy"}"#);
        s.on_text(br#"{"type":"bye","reason":"helper exited"}"#);
        let p = s.picture();
        let p = p.lock().unwrap();
        assert_eq!(p.desktop, Some(("lock".into(), true)));
        assert!(p.sas_unavailable);
        assert_eq!(p.state, State::Ended("helper exited".into()));
    }

    #[test]
    fn cursor_formats() {
        // color: one opaque red pixel, one transparent.
        let c = parse_cursor(&encode_cursor_shape(2, 1, 5, 5, CURSOR_FORMAT_COLOR_BGRA, &[0, 0, 255, 255, 9, 9, 9, 0])).unwrap();
        assert_eq!(c.argb, vec![0xffff0000, 0x00090909]);
        assert_eq!((c.hx, c.hy), (1, 0), "hotspot clamped into the shape");
        // mono 8x1: AND row then XOR row. bits: px0 and=0 xor=0 black, px1 and=0 xor=1 white,
        // px2 and=1 xor=0 transparent, px3 and=1 xor=1 invert->black.
        let c = parse_cursor(&encode_cursor_shape(8, 1, 0, 0, CURSOR_FORMAT_MONO, &[0b0011_1111, 0b0101_0000])).unwrap();
        assert_eq!(&c.argb[..4], &[0xff000000, 0xffffffff, 0, 0xff000000]);
        // masked: alpha 0 -> opaque color; alpha ff with color -> black; alpha ff black -> clear.
        let c = parse_cursor(&encode_cursor_shape(3, 1, 0, 0, CURSOR_FORMAT_MASKED_COLOR, &[0, 255, 0, 0, 1, 1, 1, 255, 0, 0, 0, 255])).unwrap();
        assert_eq!(c.argb, vec![0xff00ff00, 0xff000000, 0]);
    }

    #[test]
    fn composite_draws_cursor_at_hotspot() {
        let mut s = Session::new();
        s.on_text(hello().as_bytes());
        s.on_binary(&encode_cursor_shape(2, 2, 1, 1, CURSOR_FORMAT_COLOR_BGRA, &[255u8; 16]));
        s.on_text(br#"{"type":"cursor_pos","x":10,"y":10,"visible":true}"#);
        let rgb = s.picture().lock().unwrap().composite_rgb();
        let at = |x: usize, y: usize| rgb[(y * 64 + x) * 3];
        assert_eq!((at(9, 9), at(10, 10), at(11, 11)), (255, 255, 0));
    }
}
