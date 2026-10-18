//! # screen-wire
//!
//! The one shared schema for Ominull remote screen control (`REMOTE_SCREEN.md`
//! §4), owned here and used by **both** the Rust capture/input helper and the
//! native viewer — there is no mirror to drift (§4.4). Platform-neutral (no
//! `windows` crate), minimal deps (serde), fully unit-tested.
//!
//! Three layers:
//!
//! * [`framing`] — the §6.5 pipe length-prefix framing between the helper and
//!   the C agent (`u8 kind` + `u32le len` + bytes). The agent relays a text
//!   frame as a WebSocket text message and a binary frame as a binary message.
//! * [`proto`] — the §4.1/§4.2 messages: JSON text control/metadata in both
//!   directions, and the fixed little-endian binary headers for tiles and
//!   cursor shapes. Both directions are encodable and decodable, so a client
//!   (viewer) decodes agent->operator messages and encodes operator->agent ones
//!   from the same code the helper uses.
//! * [`input`] — strict validation of operator input against live monitor
//!   geometry (bounds on monitor index, coordinates, scancode, wheel), turning
//!   an untrusted `input` frame into a typed, injectable event or dropping it.

pub mod framing;
pub mod input;
pub mod proto;

// Convenience re-exports: the names a helper or viewer reaches for most.
pub use framing::{read_frame, write_frame, FrameKind, MAX_PAYLOAD};
pub use input::{validate, InputEvent, COORD_MAX, WHEEL_LIMIT};
pub use proto::{
    decode_cursor_shape, decode_tile_message, encode_cursor_shape, encode_tile_message, parse_in,
    parse_out, CursorShapeHeader, InMsg, MonitorInfo, OutMsg, RawButtons, RawInput, TileHeader,
    CURSOR_FORMAT_COLOR_BGRA, CURSOR_FORMAT_MASKED_COLOR, CURSOR_FORMAT_MONO, CURSOR_HEADER_LEN,
    MSG_TYPE_CURSOR_SHAPE, MSG_TYPE_TILE, TILE_FLAG_KEYFRAME, TILE_HEADER_LEN,
};
