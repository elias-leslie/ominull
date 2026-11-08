//! Base64 readers: the terminal's forgiving one and the strict one every signed
//! value goes through (C: TermB64_Decode, Response_Base64Decode).

fn val(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Skips whitespace and JSON escape backslashes, stops at padding or the first
/// invalid character; a full output cuts it short. Returns the bytes written.
pub fn term_decode(input: &[u8], out: &mut [u8]) -> usize {
    let mut j = 0usize;
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in input {
        if matches!(c, b' ' | b'\r' | b'\n' | b'\t' | b'\\') {
            continue;
        }
        if c == b'=' {
            break;
        }
        let Some(v) = val(c) else { break };
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let Some(slot) = out.get_mut(j) else { return j };
            *slot = (acc >> bits) as u8;
            j += 1;
        }
    }
    j
}

/// Standard base64. Whitespace is skipped; any other character outside the
/// alphabet, data after padding, more than two pad characters, a wrong pad
/// position or output past the buffer returns 0.
pub fn strict_decode(input: &[u8], out: &mut [u8]) -> usize {
    let mut out_len = 0usize;
    let mut chars = 0usize;
    let mut pad = 0usize;
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in input {
        if matches!(c, b' ' | b'\n' | b'\r' | b'\t') {
            continue;
        }
        chars += 1;
        if c == b'=' {
            pad += 1;
            if pad > 2 {
                return 0;
            }
            continue;
        }
        if pad != 0 {
            return 0;
        }
        let Some(v) = val(c) else { return 0 };
        buf = ((buf << 6) | v) & 0xFF_FFFF;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let Some(slot) = out.get_mut(out_len) else { return 0 };
            *slot = ((buf >> bits) & 0xFF) as u8;
            out_len += 1;
        }
    }
    if pad != 0 && chars % 4 != 0 {
        return 0;
    }
    out_len
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_refuses_junk() {
        let mut o = [0u8; 8];
        assert_eq!(strict_decode(b"aGk=", &mut o), 2);
        assert_eq!(&o[..2], b"hi");
        assert_eq!(strict_decode(b"aGk", &mut o), 2); // no padding is accepted, as in C
        assert_eq!(strict_decode(b"aG=k", &mut o), 0);
        assert_eq!(strict_decode(b"aGk===", &mut o), 0);
        assert_eq!(strict_decode(b"a!k=", &mut o), 0);
        assert_eq!(strict_decode(b"aGlhaGlhaGlhaGlh", &mut o), 0);
    }

    #[test]
    fn term_stops_at_padding_or_junk() {
        let mut o = [0u8; 8];
        assert_eq!(term_decode(b"aGk=aGk=", &mut o), 2);
        assert_eq!(term_decode(br"a\/Gk", &mut o), 3);
        let mut short = [0u8; 1];
        assert_eq!(term_decode(b"aGk=", &mut short), 1);
    }
}
