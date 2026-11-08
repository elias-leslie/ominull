//! The strict reader behind offers, grants, script and forensic payloads and
//! terminal frames (C: TermJson in terminal_frame.h). Same acceptance, byte for
//! byte: differential tests compare this against the C reader.

pub const DEFAULT_MAX_DEPTH: i32 = 8;
pub const REPLY_MAX_DEPTH: i32 = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VType {
    Str,
    Scalar,
    Composite,
}

#[derive(Clone, Copy)]
pub struct Member<'a> {
    pub key: &'a [u8],
    pub vtype: VType,
    pub val: &'a [u8],
}

pub enum Step<'a> {
    End,
    Member(Member<'a>),
    Bad,
}

pub struct Reader<'a> {
    pub s: &'a [u8],
    pub i: usize,
    pub first: bool,
    pub max_depth: i32,
}

impl<'a> Reader<'a> {
    pub fn at(s: &'a [u8], i: usize, max_depth: i32) -> Self {
        Reader { s, i, first: true, max_depth }
    }

    pub fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    pub fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.i += 1;
        }
    }

    /// The raw content between the quotes (escapes left in place).
    pub fn string(&mut self) -> Option<&'a [u8]> {
        if self.peek() != Some(b'"') {
            return None;
        }
        self.i += 1;
        let start = self.i;
        while let Some(c) = self.peek() {
            if c == b'\\' {
                self.i += 2;
                continue;
            }
            if c == b'"' {
                let out = self.s.get(start..self.i)?;
                self.i += 1;
                return Some(out);
            }
            if c < 0x20 {
                return None;
            }
            self.i += 1;
        }
        None
    }

    pub fn skip_value(&mut self, depth: i32) -> bool {
        let limit = if self.max_depth > 0 { self.max_depth } else { DEFAULT_MAX_DEPTH };
        if depth > limit {
            return false;
        }
        self.skip_ws();
        let Some(c) = self.peek() else { return false };
        if c == b'"' {
            return self.string().is_some();
        }
        if c == b'{' || c == b'[' {
            let close = if c == b'{' { b'}' } else { b']' };
            self.i += 1;
            self.skip_ws();
            if self.peek() == Some(close) {
                self.i += 1;
                return true;
            }
            while self.i < self.s.len() {
                if c == b'{' {
                    self.skip_ws();
                    if self.string().is_none() {
                        return false;
                    }
                    self.skip_ws();
                    if self.peek() != Some(b':') {
                        return false;
                    }
                    self.i += 1;
                }
                if !self.skip_value(depth + 1) {
                    return false;
                }
                self.skip_ws();
                match self.peek() {
                    None => return false,
                    Some(b',') => self.i += 1,
                    Some(x) if x == close => {
                        self.i += 1;
                        return true;
                    }
                    Some(_) => return false,
                }
            }
            return false;
        }
        let start = self.i;
        while let Some(d) = self.peek() {
            if d.is_ascii_digit() || d.is_ascii_lowercase() || matches!(d, b'-' | b'+' | b'.' | b'E') {
                self.i += 1;
            } else {
                break;
            }
        }
        self.i > start
    }

    /// TermJson_Begin: positioned inside the opening brace.
    pub fn begin(s: &'a [u8]) -> Option<Self> {
        let mut r = Reader::at(s, 0, 0);
        r.skip_ws();
        if r.peek() != Some(b'{') {
            return None;
        }
        r.i += 1;
        Some(r)
    }

    /// The next top-level member; End at the closing brace (only whitespace or
    /// a NUL may follow).
    pub fn next_member(&mut self) -> Step<'a> {
        self.skip_ws();
        let Some(c) = self.peek() else { return Step::Bad };
        if c == b'}' {
            self.i += 1;
            self.skip_ws();
            return match self.peek() {
                None | Some(0) => Step::End,
                Some(_) => Step::Bad,
            };
        }
        if !self.first {
            if c != b',' {
                return Step::Bad;
            }
            self.i += 1;
            self.skip_ws();
        }
        self.first = false;
        let Some(key) = self.string() else { return Step::Bad };
        self.skip_ws();
        if self.peek() != Some(b':') {
            return Step::Bad;
        }
        self.i += 1;
        self.skip_ws();
        let Some(v) = self.peek() else { return Step::Bad };
        if v == b'"' {
            return match self.string() {
                Some(val) => Step::Member(Member { key, vtype: VType::Str, val }),
                None => Step::Bad,
            };
        }
        let start = self.i;
        let vtype = if v == b'{' || v == b'[' { VType::Composite } else { VType::Scalar };
        if !self.skip_value(1) {
            return Step::Bad;
        }
        let Some(val) = self.s.get(start..self.i) else { return Step::Bad };
        self.skip_ws();
        if !matches!(self.peek(), None | Some(b',' | b'}')) {
            return Step::Bad;
        }
        Step::Member(Member { key, vtype, val })
    }
}

/// How a raw member key reads against the names a reader knows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Known {
    /// Index of the exact match.
    At(usize),
    Unknown,
    /// A key another JSON reader could take for a known member: one holding an
    /// escape or a non-ASCII byte, or one equal to a name ignoring ASCII case.
    Twin,
}

pub fn classify(key: &[u8], names: &[&[u8]]) -> Known {
    if key.iter().any(|&b| b == b'\\' || b >= 0x80) {
        return Known::Twin;
    }
    for (m, name) in names.iter().enumerate() {
        if name.len() != key.len() {
            continue;
        }
        if *name == key {
            return Known::At(m);
        }
        if name.eq_ignore_ascii_case(key) {
            return Known::Twin;
        }
    }
    Known::Unknown
}

/// TermJson_CopyString: simple escapes, \u for ASCII only; fails, never truncates.
pub fn copy_string(raw: &[u8], out: &mut [u8]) -> bool {
    let mut o = 0usize;
    let mut i = 0usize;
    while let Some(&b) = raw.get(i) {
        let mut c = b;
        if c == b'\\' {
            i += 1;
            let Some(&e) = raw.get(i) else { return false };
            c = match e {
                b'"' => b'"',
                b'\\' => b'\\',
                b'/' => b'/',
                b'b' => 0x08,
                b'f' => 0x0c,
                b'n' => b'\n',
                b'r' => b'\r',
                b't' => b'\t',
                b'u' => {
                    if i + 4 >= raw.len() {
                        return false;
                    }
                    let Some(v) = hex4(raw, i + 1) else { return false };
                    if v == 0 || v > 0x7f {
                        return false;
                    }
                    i += 4;
                    v as u8
                }
                _ => return false,
            };
        }
        if o + 1 >= out.len() {
            return false;
        }
        let Some(slot) = out.get_mut(o) else { return false };
        *slot = c;
        o += 1;
        i += 1;
    }
    match out.get_mut(o) {
        Some(slot) => {
            *slot = 0;
            true
        }
        None => false,
    }
}

fn hex4(raw: &[u8], at: usize) -> Option<u32> {
    let mut v = 0u32;
    for h in 0..4 {
        let d = hex_val(*raw.get(at + h)?)?;
        v = v * 16 + u32::from(d);
    }
    Some(v)
}

pub fn hex_val(x: u8) -> Option<u8> {
    match x {
        b'0'..=b'9' => Some(x - b'0'),
        b'a'..=b'f' => Some(x - b'a' + 10),
        b'A'..=b'F' => Some(x - b'A' + 10),
        _ => None,
    }
}

/// TermJson_DecodeString: a raw span into UTF-8, every JSON escape, \u pairs past
/// the BMP. Refuses \u0000, a lone surrogate, a raw control byte, an unknown
/// escape and anything that does not fit. Returns the decoded length. With no
/// output it only checks the string.
pub fn decode_string(raw: &[u8], mut out: Option<&mut [u8]>) -> Option<usize> {
    let cap = match &out {
        Some(o) => {
            if o.is_empty() {
                return None;
            }
            o.len()
        }
        None => usize::MAX,
    };
    let mut o = 0usize;
    let mut i = 0usize;
    while let Some(&c) = raw.get(i) {
        if c < 0x20 {
            return None;
        }
        if c != b'\\' {
            if o + 1 >= cap {
                return None;
            }
            put(&mut out, o, &[c]);
            o += 1;
            i += 1;
            continue;
        }
        i += 1;
        let e = *raw.get(i)?;
        let simple = match e {
            b'"' => Some(b'"'),
            b'\\' => Some(b'\\'),
            b'/' => Some(b'/'),
            b'b' => Some(0x08),
            b'f' => Some(0x0c),
            b'n' => Some(b'\n'),
            b'r' => Some(b'\r'),
            b't' => Some(b'\t'),
            b'u' => None,
            _ => return None,
        };
        if let Some(d) = simple {
            if o + 1 >= cap {
                return None;
            }
            put(&mut out, o, &[d]);
            o += 1;
            i += 1;
            continue;
        }
        if i + 4 >= raw.len() {
            return None;
        }
        let mut cp = hex4(raw, i + 1)?;
        i += 4;
        if (0xD800..=0xDBFF).contains(&cp) {
            if i + 6 >= raw.len() || raw.get(i + 1) != Some(&b'\\') || raw.get(i + 2) != Some(&b'u') {
                return None;
            }
            let lo = hex4(raw, i + 3)?;
            if !(0xDC00..=0xDFFF).contains(&lo) {
                return None;
            }
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
            i += 6;
        } else if (0xDC00..=0xDFFF).contains(&cp) {
            return None;
        }
        if cp == 0 {
            return None;
        }
        let mut u = [0u8; 4];
        let n = if cp < 0x80 {
            u[0] = cp as u8;
            1
        } else if cp < 0x800 {
            u[0] = (0xC0 | (cp >> 6)) as u8;
            u[1] = (0x80 | (cp & 0x3F)) as u8;
            2
        } else if cp < 0x10000 {
            u[0] = (0xE0 | (cp >> 12)) as u8;
            u[1] = (0x80 | ((cp >> 6) & 0x3F)) as u8;
            u[2] = (0x80 | (cp & 0x3F)) as u8;
            3
        } else {
            u[0] = (0xF0 | (cp >> 18)) as u8;
            u[1] = (0x80 | ((cp >> 12) & 0x3F)) as u8;
            u[2] = (0x80 | ((cp >> 6) & 0x3F)) as u8;
            u[3] = (0x80 | (cp & 0x3F)) as u8;
            4
        };
        if o + n >= cap {
            return None;
        }
        put(&mut out, o, u.get(..n)?);
        o += n;
        i += 1;
    }
    put(&mut out, o, &[0]);
    Some(o)
}

fn put(out: &mut Option<&mut [u8]>, at: usize, bytes: &[u8]) {
    if let Some(buf) = out {
        if let Some(dst) = buf.get_mut(at..at + bytes.len()) {
            dst.copy_from_slice(bytes);
        }
    }
}

/// TermJson_Int: strtol over a scalar's text, saturating at the platform long.
pub fn int_long(raw: &[u8]) -> Option<core::ffi::c_long> {
    use core::ffi::c_long;
    if raw.is_empty() || raw.len() >= 24 {
        return None;
    }
    let (neg, digits) = match raw.first() {
        Some(b'-') => (true, raw.get(1..)?),
        Some(b'+') => (false, raw.get(1..)?),
        _ => (false, raw),
    };
    if digits.is_empty() {
        return None;
    }
    let mut v: c_long = 0;
    for &d in digits {
        if !d.is_ascii_digit() {
            return None;
        }
        let digit = c_long::from(d - b'0');
        v = if neg {
            v.saturating_mul(10).saturating_sub(digit)
        } else {
            v.saturating_mul(10).saturating_add(digit)
        };
    }
    Some(v)
}

/// C string content of a NUL-terminated field.
pub fn cstr(buf: &[u8]) -> &[u8] {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf.get(..end).unwrap_or(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_charset_and_trailing_rules_match_the_c_reader() {
        // "E" but not "e"-only rules: lowercase, digits, sign, dot, capital E.
        let mut r = Reader::begin(br#"{"a":1E+5,"b":truex,"c":null}"#).unwrap();
        for _ in 0..3 {
            assert!(matches!(r.next_member(), Step::Member(_)));
        }
        assert!(matches!(r.next_member(), Step::End));
        // A capital letter other than E ends the scalar and the member is bad.
        let mut r = Reader::begin(br#"{"a":TRUE}"#).unwrap();
        assert!(matches!(r.next_member(), Step::Bad));
        // Only whitespace or a NUL may follow the closing brace.
        let mut r = Reader::begin(b"{} \0junk").unwrap();
        assert!(matches!(r.next_member(), Step::End));
        let mut r = Reader::begin(b"{} x").unwrap();
        assert!(matches!(r.next_member(), Step::Bad));
    }

    #[test]
    fn a_backslash_at_the_end_never_reads_past_the_input() {
        let mut r = Reader::at(br#""abc\"#, 0, 0);
        assert!(r.string().is_none());
    }

    #[test]
    fn classify_refuses_twins() {
        let names: &[&[u8]] = &[b"source", b"mode"];
        assert_eq!(classify(b"source", names), Known::At(0));
        assert_eq!(classify(b"Source", names), Known::Twin);
        assert_eq!(classify(b"sour\\u0063e", names), Known::Twin);
        assert_eq!(classify("ſource".as_bytes(), names), Known::Twin);
        assert_eq!(classify(b"other", names), Known::Unknown);
    }

    #[test]
    fn decode_string_refuses_what_c_refuses() {
        let mut o = [0u8; 16];
        assert_eq!(decode_string(br"a\u0041\n", Some(&mut o)), Some(3));
        assert_eq!(&o[..3], b"aA\n");
        assert_eq!(decode_string(br"\u0000", Some(&mut o)), None);
        assert_eq!(decode_string(br"\ud800", Some(&mut o)), None);
        assert_eq!(decode_string(br"\udc00", Some(&mut o)), None);
        assert_eq!(decode_string(br"\ud83d\ude00", Some(&mut o)), Some(4));
        assert_eq!(&o[..4], "😀".as_bytes());
        assert_eq!(decode_string(br"\x", None), None);
        let mut small = [0u8; 2];
        assert_eq!(decode_string(b"ab", Some(&mut small)), None);
        assert_eq!(decode_string(b"a", Some(&mut small)), Some(1));
    }

    #[test]
    fn strtol_semantics() {
        assert_eq!(int_long(b"12"), Some(12));
        assert_eq!(int_long(b"-3"), Some(-3));
        assert_eq!(int_long(b"+4"), Some(4));
        assert_eq!(int_long(b"-"), None);
        assert_eq!(int_long(b"1.5"), None);
        assert_eq!(int_long(b"99999999999999999999"), Some(core::ffi::c_long::MAX));
        assert_eq!(int_long(b"-99999999999999999999"), Some(core::ffi::c_long::MIN));
    }
}
