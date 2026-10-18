//! §4.1/§4.2 messages. JSON text control/metadata both ways, plus the fixed
//! little-endian binary headers for tiles and cursor shapes. Everything is both
//! encodable and decodable so the helper and the viewer share one code path:
//! the helper encodes agent->operator and decodes operator->agent, the viewer
//! does the reverse, from the same functions.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Binary messages (§4.1).
// ---------------------------------------------------------------------------

pub const MSG_TYPE_TILE: u8 = 1;
pub const MSG_TYPE_CURSOR_SHAPE: u8 = 2;

/// Tile header is 16 bytes, LE (§4.1).
pub const TILE_HEADER_LEN: usize = 16;
/// Cursor-shape header is 10 bytes, LE (§4.1, pinned 2026-10-17).
pub const CURSOR_HEADER_LEN: usize = 10;

/// Tile flags bitfield (§4.1).
pub const TILE_FLAG_KEYFRAME: u8 = 0x01;

/// Cursor pixel formats (§4.1).
pub const CURSOR_FORMAT_COLOR_BGRA: u8 = 0;
pub const CURSOR_FORMAT_MONO: u8 = 1;
pub const CURSOR_FORMAT_MASKED_COLOR: u8 = 2;

/// Max cursor dimension accepted/produced; a larger shape is rejected.
pub const CURSOR_MAX_DIM: u16 = 256;

/// Parsed tile header plus the JPEG byte slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TileHeader {
    pub monitor: u8,
    pub keyframe: bool,
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
    pub seq: u32,
}

/// Builds one tile binary message: 16-byte LE header then JPEG bytes (§4.1).
/// `x`/`y`/`w`/`h` are pre-rotation, monitor-relative desktop pixels.
pub fn encode_tile_message(
    monitor: u8,
    keyframe: bool,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    seq: u32,
    jpeg: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TILE_HEADER_LEN + jpeg.len());
    out.push(MSG_TYPE_TILE);
    out.push(monitor);
    out.push(if keyframe { TILE_FLAG_KEYFRAME } else { 0 });
    out.push(0); // reserved
    out.extend_from_slice(&x.to_le_bytes());
    out.extend_from_slice(&y.to_le_bytes());
    out.extend_from_slice(&w.to_le_bytes());
    out.extend_from_slice(&h.to_le_bytes());
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(jpeg);
    out
}

/// Decodes a tile message, returning the header and the JPEG slice. `None` if
/// it is not a tile or is shorter than the header.
pub fn decode_tile_message(msg: &[u8]) -> Option<(TileHeader, &[u8])> {
    if msg.len() < TILE_HEADER_LEN || msg[0] != MSG_TYPE_TILE {
        return None;
    }
    let hdr = TileHeader {
        monitor: msg[1],
        keyframe: msg[2] & TILE_FLAG_KEYFRAME != 0,
        x: u16::from_le_bytes([msg[4], msg[5]]),
        y: u16::from_le_bytes([msg[6], msg[7]]),
        w: u16::from_le_bytes([msg[8], msg[9]]),
        h: u16::from_le_bytes([msg[10], msg[11]]),
        seq: u32::from_le_bytes([msg[12], msg[13], msg[14], msg[15]]),
    };
    Some((hdr, &msg[TILE_HEADER_LEN..]))
}

/// Parsed cursor-shape header plus the pixel/mask slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorShapeHeader {
    pub w: u16,
    pub h: u16,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    pub format: u8,
}

/// The exact payload length a shape of `(w, h, format)` must carry, or `None`
/// for an unknown format or out-of-bound dimensions. Layout (DXGI-native):
/// * color (0): BGRA, `w*h*4`.
/// * monochrome (1): 1bpp mask, height `2*h` (AND then XOR), pitch `ceil(w/8)`.
/// * masked-color (2): BGRA, `w*h*4` (alpha carries the mask/XOR flag).
pub fn cursor_payload_len(w: u16, h: u16, format: u8) -> Option<usize> {
    if w == 0 || h == 0 || w > CURSOR_MAX_DIM || h > CURSOR_MAX_DIM {
        return None;
    }
    let (w, h) = (w as usize, h as usize);
    match format {
        CURSOR_FORMAT_COLOR_BGRA | CURSOR_FORMAT_MASKED_COLOR => Some(w * h * 4),
        CURSOR_FORMAT_MONO => Some(((w + 7) / 8) * (2 * h)),
        _ => None,
    }
}

/// Builds one cursor-shape binary message (§4.1). The caller passes tight rows
/// (the helper converts DXGI pitch to tight rows first).
pub fn encode_cursor_shape(
    w: u16,
    h: u16,
    hotspot_x: u16,
    hotspot_y: u16,
    format: u8,
    pixels: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CURSOR_HEADER_LEN + pixels.len());
    out.push(MSG_TYPE_CURSOR_SHAPE);
    out.extend_from_slice(&w.to_le_bytes());
    out.extend_from_slice(&h.to_le_bytes());
    out.extend_from_slice(&hotspot_x.to_le_bytes());
    out.extend_from_slice(&hotspot_y.to_le_bytes());
    out.push(format);
    out.extend_from_slice(pixels);
    out
}

/// Decodes a cursor-shape message, validating the format and that the payload
/// length matches `cursor_payload_len`. `None` on any mismatch (the viewer
/// drops it rather than drawing garbage).
pub fn decode_cursor_shape(msg: &[u8]) -> Option<(CursorShapeHeader, &[u8])> {
    if msg.len() < CURSOR_HEADER_LEN || msg[0] != MSG_TYPE_CURSOR_SHAPE {
        return None;
    }
    let hdr = CursorShapeHeader {
        w: u16::from_le_bytes([msg[1], msg[2]]),
        h: u16::from_le_bytes([msg[3], msg[4]]),
        hotspot_x: u16::from_le_bytes([msg[5], msg[6]]),
        hotspot_y: u16::from_le_bytes([msg[7], msg[8]]),
        format: msg[9],
    };
    let want = cursor_payload_len(hdr.w, hdr.h, hdr.format)?;
    let body = &msg[CURSOR_HEADER_LEN..];
    if body.len() != want {
        return None;
    }
    Some((hdr, body))
}

// ---------------------------------------------------------------------------
// JSON messages, agent -> operator (§4.1).
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MonitorInfo {
    pub id: u32,
    pub w: u32,
    pub h: u32,
    pub x: i32,
    pub y: i32,
    pub primary: bool,
}

/// Agent->operator control/metadata. Encodable (helper) and decodable (viewer).
/// Unknown types decode to `Unknown` so an older viewer tolerates a newer agent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutMsg {
    Hello { monitors: Vec<MonitorInfo>, active: u32 },
    /// Which input desktop the capture is now on (§4.1): `name` is
    /// "user" | "lock" | "secure"; `signed_in` from the WTS session state.
    /// Sent right after `hello` and again on every input-desktop switch.
    Desktop { name: String, signed_in: bool },
    FrameEnd { monitor: u32, frame: u64, tiles: u32 },
    CursorPos { x: i32, y: i32, visible: bool },
    Resized { monitors: Vec<MonitorInfo>, active: u32 },
    SasUnavailable { reason: String },
    Bye { reason: String },
    #[serde(other)]
    Unknown,
}

impl OutMsg {
    /// Serializes to a JSON text frame payload.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Parses one agent->operator JSON text frame (viewer side). Malformed -> None.
pub fn parse_out(json: &[u8]) -> Option<OutMsg> {
    serde_json::from_slice::<OutMsg>(json).ok()
}

// ---------------------------------------------------------------------------
// JSON messages, operator/hub -> agent (§4.2, §4.3). Untrusted at the helper:
// `input::validate` checks every numeric bound before anything is injected.
// ---------------------------------------------------------------------------

/// A raw `input` event (shape depends on `ev`). Serializable so the viewer
/// builds one; deserializable so the helper reads it. Validation is separate
/// ([`crate::input::validate`]).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawInput {
    pub ev: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buttons: Option<RawButtons>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dx: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dy: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub down: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ch: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct RawButtons {
    #[serde(default)]
    pub l: bool,
    #[serde(default)]
    pub r: bool,
    #[serde(default)]
    pub m: bool,
}

/// One operator/hub -> agent message. Encodable (viewer) and decodable (helper).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InMsg {
    Input(RawInput),
    Ack {
        #[serde(default)]
        monitor: u32,
        frame: u64,
    },
    SetMonitor {
        monitor: u32,
    },
    Quality {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fps: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        jpeg_q: Option<u32>,
    },
    Pause,
    Resume,
    Close,
    #[serde(other)]
    Unknown,
}

impl InMsg {
    /// Serializes to a JSON text frame payload (viewer side).
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Parses one operator/hub -> agent JSON text frame (helper side). A malformed
/// message is dropped (None) rather than ending the session.
pub fn parse_in(json: &[u8]) -> Option<InMsg> {
    serde_json::from_slice::<InMsg>(json).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tile_header_roundtrip() {
        let jpeg = [0xFFu8, 0xD8, 0xFF, 0xD9];
        let msg = encode_tile_message(2, true, 256, 512, 256, 128, 42, &jpeg);
        assert_eq!(msg.len(), TILE_HEADER_LEN + jpeg.len());
        let (hdr, body) = decode_tile_message(&msg).unwrap();
        assert_eq!(hdr, TileHeader { monitor: 2, keyframe: true, x: 256, y: 512, w: 256, h: 128, seq: 42 });
        assert_eq!(body, &jpeg);
    }

    #[test]
    fn cursor_shape_color_roundtrip() {
        let px = vec![0x7Fu8; 4 * 32 * 24];
        let msg = encode_cursor_shape(32, 24, 1, 2, CURSOR_FORMAT_COLOR_BGRA, &px);
        let (hdr, body) = decode_cursor_shape(&msg).unwrap();
        assert_eq!(hdr, CursorShapeHeader { w: 32, h: 24, hotspot_x: 1, hotspot_y: 2, format: CURSOR_FORMAT_COLOR_BGRA });
        assert_eq!(body, &px[..]);
    }

    #[test]
    fn cursor_shape_mono_length_rule() {
        // 1bpp, w=32 -> pitch 4, height 2*h. h=16 -> 4*32 = 128 bytes.
        let want = cursor_payload_len(32, 16, CURSOR_FORMAT_MONO).unwrap();
        assert_eq!(want, 128);
        let px = vec![0u8; want];
        let msg = encode_cursor_shape(32, 16, 0, 0, CURSOR_FORMAT_MONO, &px);
        assert!(decode_cursor_shape(&msg).is_some());
    }

    #[test]
    fn cursor_shape_bad_length_rejected() {
        let mut msg = encode_cursor_shape(32, 24, 0, 0, CURSOR_FORMAT_COLOR_BGRA, &vec![0u8; 4 * 32 * 24]);
        msg.pop(); // one byte short of the declared dimensions
        assert!(decode_cursor_shape(&msg).is_none());
    }

    #[test]
    fn cursor_shape_oversize_rejected() {
        assert!(cursor_payload_len(257, 16, CURSOR_FORMAT_COLOR_BGRA).is_none());
    }

    #[test]
    fn out_msg_roundtrip() {
        let m = OutMsg::FrameEnd { monitor: 0, frame: 7, tiles: 12 };
        let j = m.to_json();
        assert!(j.contains("\"type\":\"frame_end\""));
        assert_eq!(parse_out(j.as_bytes()).unwrap(), m);
    }

    #[test]
    fn out_msg_unknown_tolerated() {
        assert_eq!(parse_out(b"{\"type\":\"future_thing\"}").unwrap(), OutMsg::Unknown);
    }

    #[test]
    fn in_msg_roundtrip_both_ways() {
        // Viewer encodes an input frame; helper decodes it.
        let built = InMsg::Input(RawInput {
            ev: "mouse".into(),
            x: Some(100),
            y: Some(200),
            buttons: Some(RawButtons { l: true, r: false, m: false }),
            monitor: Some(0),
            dx: None,
            dy: None,
            code: None,
            down: None,
            ext: None,
            ch: None,
        });
        let j = built.to_json();
        assert!(j.contains("\"type\":\"input\""));
        assert!(j.contains("\"ev\":\"mouse\""));
        assert!(!j.contains("\"dx\""), "None fields are not serialized");
        assert!(matches!(parse_in(j.as_bytes()), Some(InMsg::Input(_))));
    }

    #[test]
    fn in_msg_control_frames() {
        assert!(matches!(parse_in(b"{\"type\":\"close\"}"), Some(InMsg::Close)));
        assert!(matches!(parse_in(b"{\"type\":\"pause\"}"), Some(InMsg::Pause)));
        assert!(matches!(parse_in(b"{\"type\":\"future\"}"), Some(InMsg::Unknown)));
        assert!(parse_in(b"{not json").is_none());
    }
}
