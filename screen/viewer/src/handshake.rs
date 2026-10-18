//! The session the viewer connects to: from one JSON line on stdin
//! (ominullctl, REMOTE_SCREEN.md §8.1) or from a redeemed launch code (§9.2).
//! The operator token never comes from argv or the environment.

use serde::Deserialize;
use std::fmt;
use std::io::BufRead;

/// The longest handshake line accepted (a CA bundle fits easily).
pub const MAX_LINE: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Control,
    View,
}

impl Mode {
    pub fn parse(s: &str) -> Result<Mode, String> {
        match s {
            "control" => Ok(Mode::Control),
            "view" => Ok(Mode::View),
            other => Err(format!("unknown mode {other:?} (want control or view)")),
        }
    }
}

/// A hub origin: `https://host[:port]`, nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HubAddr {
    /// Host as written, without brackets for IPv6, lowercased.
    pub host: String,
    pub port: u16,
}

impl HubAddr {
    /// `host:port` for the socket and the WebSocket URL (IPv6 bracketed).
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Parses a hub origin. Only `https://host[:port]` with an optional trailing
/// `/`: no user info, path, query or fragment.
pub fn parse_origin(url: &str) -> Result<HubAddr, String> {
    let rest = url.strip_prefix("https://").ok_or("the hub address must start with https://")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() {
        return Err("the hub address has no host".into());
    }
    if rest.contains(['/', '?', '#', '@', ' ', '\\']) || rest.chars().any(|c| c.is_control()) {
        return Err("the hub address must be just https://host[:port]".into());
    }
    let (host, port) = if let Some(v6) = rest.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or("bad IPv6 hub address")?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or("bad hub port")?),
        };
        (h.to_string(), port)
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (rest.to_string(), None),
        }
    };
    if host.is_empty() || (host.contains(':') && host.parse::<std::net::Ipv6Addr>().is_err()) {
        return Err("bad hub host".into());
    }
    let port = match port {
        None => 443,
        Some(p) => match p.parse::<u16>() {
            Ok(n) if n > 0 && !p.starts_with('+') => n,
            _ => return Err("bad hub port".into()),
        },
    };
    Ok(HubAddr { host: host.to_ascii_lowercase(), port })
}

/// Session ids are the hub's opaque ids: short and URL-safe, so they go into
/// the WebSocket query without encoding.
pub fn valid_session_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// A token goes into one HTTP header: visible ASCII only, so it can never
/// split the header block.
pub fn valid_token(s: &str) -> bool {
    !s.is_empty() && s.len() <= 4096 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Everything needed to attach. `Debug` leaves the token out.
#[derive(Clone)]
pub struct Connect {
    pub hub: HubAddr,
    pub ca_pem: String,
    pub session_id: String,
    pub token: String,
    pub mode: Mode,
    pub host_label: String,
    /// `ctl type`'s text, when the caller sends it here instead of in argv
    /// (argv is visible in the process list). Never logged.
    pub text: Option<String>,
}

impl fmt::Debug for Connect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connect")
            .field("hub", &self.hub)
            .field("session_id", &self.session_id)
            .field("token", &"<redacted>")
            .field("mode", &self.mode)
            .field("host_label", &self.host_label)
            .field("text", &self.text.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Connect {
    pub fn ws_url(&self) -> String {
        format!("wss://{}/api/v1/screen/ws/operator?session_id={}", self.hub.authority(), self.session_id)
    }
}

#[derive(Deserialize)]
struct Line {
    hub_url: String,
    ca_pem: String,
    session_id: String,
    token: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

/// Parses and checks one handshake line.
pub fn parse_line(line: &str) -> Result<Connect, String> {
    let l: Line = serde_json::from_str(line.trim()).map_err(|e| format!("the session line is not valid: {}", e.classify_name()))?;
    let hub = parse_origin(&l.hub_url)?;
    if !l.ca_pem.contains("-----BEGIN CERTIFICATE-----") {
        return Err("the session line has no hub CA certificate".into());
    }
    if !valid_session_id(&l.session_id) {
        return Err("the session id is not valid".into());
    }
    if !valid_token(&l.token) {
        return Err("the session token is not valid".into());
    }
    // No mode means view: the hub enforces it anyway, and view is the safe guess.
    let mode = Mode::parse(l.mode.as_deref().unwrap_or("view"))?;
    let host_label = clean_label(l.host.as_deref().unwrap_or(""), &hub.host);
    Ok(Connect { hub, ca_pem: l.ca_pem, session_id: l.session_id, token: l.token, mode, host_label, text: l.text })
}

/// Reads exactly one line (bounded) from `r` and parses it.
pub fn read_line<R: BufRead>(r: &mut R) -> Result<Connect, String> {
    let mut buf = Vec::new();
    let mut limited = std::io::Read::take(&mut *r, MAX_LINE as u64 + 1);
    limited.read_until(b'\n', &mut buf).map_err(|e| format!("could not read the session line: {e}"))?;
    if buf.len() > MAX_LINE {
        return Err("the session line is too long".into());
    }
    if buf.iter().all(|b| b.is_ascii_whitespace()) {
        return Err("no session line on stdin".into());
    }
    let s = String::from_utf8(buf).map_err(|_| "the session line is not UTF-8".to_string())?;
    parse_line(&s)
}

/// A host label for the title bar: printable, short, never empty.
pub fn clean_label(label: &str, fallback: &str) -> String {
    let s: String = label.chars().filter(|c| !c.is_control()).take(64).collect();
    let s = s.trim().to_string();
    if s.is_empty() {
        fallback.to_string()
    } else {
        s
    }
}

trait ClassifyName {
    fn classify_name(&self) -> &'static str;
}

impl ClassifyName for serde_json::Error {
    /// Serde's messages can quote input; the line holds the token, so only the
    /// error class is shown.
    fn classify_name(&self) -> &'static str {
        match self.classify() {
            serde_json::error::Category::Io => "read error",
            serde_json::error::Category::Syntax => "not JSON",
            serde_json::error::Category::Data => "missing or wrong fields",
            serde_json::error::Category::Eof => "cut short",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str = "-----BEGIN CERTIFICATE-----\\nMIIB\\n-----END CERTIFICATE-----\\n";

    fn line(extra: &str) -> String {
        format!(r#"{{"hub_url":"https://hub.lan:9443","ca_pem":"{CA}","session_id":"s-1","token":"tok_abc","mode":"control","host":"PC-1"{extra}}}"#)
    }

    #[test]
    fn origin_forms() {
        assert_eq!(parse_origin("https://Hub.LAN").unwrap(), HubAddr { host: "hub.lan".into(), port: 443 });
        assert_eq!(parse_origin("https://hub:9443/").unwrap().port, 9443);
        assert_eq!(parse_origin("https://[::1]:8443").unwrap(), HubAddr { host: "::1".into(), port: 8443 });
        assert_eq!(parse_origin("https://[::1]:8443").unwrap().authority(), "[::1]:8443");
        for bad in ["http://hub", "https://", "https://hub/x", "https://u@hub", "https://hub:0", "https://hub:99999", "https://hub?x", "https://::1", "https://hub:+1"] {
            assert!(parse_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn good_line() {
        let c = read_line(&mut (line("") + "\n").as_bytes()).unwrap();
        assert_eq!(c.hub.authority(), "hub.lan:9443");
        assert_eq!(c.mode, Mode::Control);
        assert_eq!(c.host_label, "PC-1");
        assert_eq!(c.ws_url(), "wss://hub.lan:9443/api/v1/screen/ws/operator?session_id=s-1");
        assert!(!format!("{c:?}").contains("tok_abc"), "Debug must not print the token");
        assert_eq!(c.text, None);
    }

    #[test]
    fn text_rides_the_line_and_stays_out_of_debug() {
        let c = parse_line(&line(r#","text":"hunter2 \u00e9""#)).unwrap();
        assert_eq!(c.text.as_deref(), Some("hunter2 é"));
        assert!(!format!("{c:?}").contains("hunter2"), "Debug must not print the text");
    }

    #[test]
    fn unknown_fields_tolerated_and_view_mode() {
        let l = line(r#","future":1"#).replace(r#""mode":"control""#, r#""mode":"view""#);
        assert_eq!(parse_line(&l).unwrap().mode, Mode::View);
    }

    #[test]
    fn bad_lines() {
        assert!(read_line(&mut "\n".as_bytes()).is_err());
        assert!(parse_line(&line("").replace("control", "admin")).is_err());
        assert!(parse_line(&line("").replace("tok_abc", "tok abc")).is_err(), "space in token");
        assert!(parse_line(&line("").replace("tok_abc", "tok\\r\\nX: y")).is_err(), "header injection");
        assert!(parse_line(&line("").replace("s-1", "s/1")).is_err());
        assert!(parse_line(&line("").replace("https://", "http://")).is_err());
        let err = parse_line(r#"{"hub_url":"https://h","token":"secret-tok"}"#).unwrap_err();
        assert!(!err.contains("secret-tok"));
    }

    #[test]
    fn line_length_cap() {
        let long = "x".repeat(MAX_LINE + 10);
        assert!(read_line(&mut long.as_bytes()).unwrap_err().contains("too long"));
    }
}
