//! §6.5 pipe framing: `u8 kind (0=text, 1=binary)` + `u32le len` + `len` bytes.
//! One frame carries one WebSocket message end to end.

use std::io::{self, Read, Write};

/// Relay message cap, agent->operator (§4.3: MaxMessageSize 1 MiB). A single
/// 256x256 JPEG tile plus its header stays far under this; the cap only bounds
/// how much a corrupt length can make a reader allocate.
pub const MAX_PAYLOAD: u32 = 1024 * 1024;

/// §6.5 frame kind on the helper<->agent pipe. Text carries JSON; Binary a tile
/// or cursor shape (both relay to/from the WebSocket). Service is a helper->agent
/// request the C agent acts on itself and never forwards to the WebSocket — its
/// payload is a 1-byte opcode (e.g. SAS, which only a real service may issue).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    Text,
    Binary,
    Service,
}

/// Service-request opcodes (pipe frame kind `Service`).
pub const SERVICE_OP_SAS: u8 = 1;

impl FrameKind {
    fn to_byte(self) -> u8 {
        match self {
            FrameKind::Text => 0,
            FrameKind::Binary => 1,
            FrameKind::Service => 2,
        }
    }
    fn from_byte(b: u8) -> Option<FrameKind> {
        match b {
            0 => Some(FrameKind::Text),
            1 => Some(FrameKind::Binary),
            2 => Some(FrameKind::Service),
            _ => None,
        }
    }
}

/// Reads one length-prefixed frame. `Ok(None)` is a clean end of stream. A bad
/// kind or an over-cap length is a protocol error, not silently accepted.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<(FrameKind, Vec<u8>)>> {
    let mut hdr = [0u8; 5];
    if !read_exact_or_eof(r, &mut hdr)? {
        return Ok(None);
    }
    let kind = FrameKind::from_byte(hdr[0])
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad frame kind"))?;
    let len = u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
    if len > MAX_PAYLOAD {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame over cap"));
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf)?;
    Ok(Some((kind, buf)))
}

/// Writes one length-prefixed frame.
pub fn write_frame<W: Write>(w: &mut W, kind: FrameKind, payload: &[u8]) -> io::Result<()> {
    if payload.len() as u64 > MAX_PAYLOAD as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "payload over cap"));
    }
    let mut hdr = [0u8; 5];
    hdr[0] = kind.to_byte();
    hdr[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    w.write_all(&hdr)?;
    w.write_all(payload)?;
    w.flush()
}

/// `read_exact` that distinguishes a clean EOF (nothing read -> `Ok(false)`)
/// from a truncated read (some bytes then EOF -> error).
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated header"));
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_text_and_binary() {
        let mut buf = Vec::new();
        write_frame(&mut buf, FrameKind::Text, b"{\"type\":\"close\"}").unwrap();
        write_frame(&mut buf, FrameKind::Binary, &[1, 2, 3, 0, 255]).unwrap();
        let mut c = Cursor::new(buf);
        let (k1, p1) = read_frame(&mut c).unwrap().unwrap();
        assert_eq!(k1, FrameKind::Text);
        assert_eq!(p1, b"{\"type\":\"close\"}");
        let (k2, p2) = read_frame(&mut c).unwrap().unwrap();
        assert_eq!(k2, FrameKind::Binary);
        assert_eq!(p2, vec![1, 2, 3, 0, 255]);
        assert!(read_frame(&mut c).unwrap().is_none());
    }

    #[test]
    fn zero_length() {
        let mut buf = Vec::new();
        write_frame(&mut buf, FrameKind::Binary, &[]).unwrap();
        let mut c = Cursor::new(buf);
        let (k, p) = read_frame(&mut c).unwrap().unwrap();
        assert_eq!(k, FrameKind::Binary);
        assert!(p.is_empty());
    }

    #[test]
    fn service_request_roundtrip() {
        // Kind 2 (service request): a 1-byte opcode payload the agent acts on and
        // never forwards to the WebSocket (§6.4/§6.5).
        let mut buf = Vec::new();
        write_frame(&mut buf, FrameKind::Service, &[SERVICE_OP_SAS]).unwrap();
        let mut c = Cursor::new(buf);
        let (k, p) = read_frame(&mut c).unwrap().unwrap();
        assert_eq!(k, FrameKind::Service);
        assert_eq!(p, vec![SERVICE_OP_SAS]);
    }

    #[test]
    fn rejects_bad_kind_and_over_cap() {
        // Kind 2 is now valid (service); 7 is still out of contract.
        assert!(read_frame(&mut Cursor::new(vec![7u8, 0, 0, 0, 0])).is_err());
        assert_eq!(FrameKind::from_byte(2), Some(FrameKind::Service));
        let mut over = vec![1u8];
        over.extend_from_slice(&(MAX_PAYLOAD + 1).to_le_bytes());
        assert!(read_frame(&mut Cursor::new(over)).is_err());
    }

    #[test]
    fn truncated_header_is_error_not_eof() {
        assert!(read_frame(&mut Cursor::new(vec![0u8, 10, 0])).is_err());
    }
}
