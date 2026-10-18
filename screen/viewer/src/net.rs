//! TLS pinned to the hub CA, the operator WebSocket, the launch-code redeem
//! POST, and the socket pump shared by the window and `ctl`.

use crate::handshake::{Connect, HubAddr};
use crate::session::Session;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::Arc;
use std::time::Duration;
use tungstenite::client::IntoClientRequest;
use tungstenite::http::HeaderValue;
use tungstenite::{Message, WebSocket};

pub type Tls = StreamOwned<ClientConnection, TcpStream>;
pub type Ws = WebSocket<Tls>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// How long one read waits before the pump checks for outgoing messages.
const POLL: Duration = Duration::from_millis(15);
/// Cap on a redeem response body.
const MAX_HTTP_BODY: usize = 64 * 1024;

/// A client config that trusts only the certificates in `ca_pem`.
pub fn tls_config(ca_pem: &str) -> Result<Arc<ClientConfig>, String> {
    let mut roots = RootCertStore::empty();
    let mut n = 0;
    for cert in CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        let cert = cert.map_err(|_| "the hub CA PEM could not be read".to_string())?;
        roots.add(cert).map_err(|e| format!("the hub CA certificate was refused: {e}"))?;
        n += 1;
    }
    if n == 0 {
        return Err("the hub CA PEM holds no certificate".into());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup failed: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// TCP + TLS to the hub. Returns the stream and a handle to the same socket
/// for changing its read timeout later.
pub fn dial(hub: &HubAddr, ca_pem: &str) -> Result<(Tls, TcpStream), String> {
    let cfg = tls_config(ca_pem)?;
    let addrs: Vec<_> = (hub.host.as_str(), hub.port)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve {}: {e}", hub.host))?
        .collect();
    let mut last = format!("could not resolve {}", hub.host);
    let mut tcp = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
            Ok(s) => {
                tcp = Some(s);
                break;
            }
            Err(e) => last = format!("could not reach {}: {e}", hub.authority()),
        }
    }
    let tcp = tcp.ok_or(last)?;
    let _ = tcp.set_nodelay(true);
    tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(|e| e.to_string())?;
    let ctl = tcp.try_clone().map_err(|e| e.to_string())?;
    let name = ServerName::try_from(hub.host.clone()).map_err(|_| "bad hub host name".to_string())?;
    let conn = ClientConnection::new(cfg, name).map_err(|e| format!("TLS setup failed: {e}"))?;
    let mut tls = StreamOwned::new(conn, tcp);
    // Finish the TLS handshake now so a certificate problem reads as one.
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).map_err(|e| tls_error(&e, hub))?;
    }
    Ok((tls, ctl))
}

fn tls_error(e: &std::io::Error, hub: &HubAddr) -> String {
    let s = e.to_string();
    if s.contains("certificate") || s.contains("Certificate") {
        format!("the hub at {} did not present a certificate from the configured CA ({s})", hub.authority())
    } else {
        format!("TLS with {} failed: {s}", hub.authority())
    }
}

/// Opens the operator socket: `X-Screen-Token` header, no cookie, no Origin.
pub fn open_ws(c: &Connect) -> Result<Ws, String> {
    let (tls, ctl) = dial(&c.hub, &c.ca_pem)?;
    let ws = ws_handshake(tls, &c.ws_url(), &c.token)?;
    ctl.set_read_timeout(Some(POLL)).map_err(|e| e.to_string())?;
    ctl.set_write_timeout(None).map_err(|e| e.to_string())?;
    Ok(ws)
}

/// The WebSocket upgrade over any stream (TLS in use, plain TCP in tests).
pub fn ws_handshake<S: Read + Write>(stream: S, url: &str, token: &str) -> Result<WebSocket<S>, String> {
    let mut req = url.into_client_request().map_err(|_| "bad WebSocket address".to_string())?;
    let v = HeaderValue::from_str(token).map_err(|_| "the session token is not valid".to_string())?;
    req.headers_mut().insert("X-Screen-Token", v);
    match tungstenite::client(req, stream) {
        Ok((ws, _)) => Ok(ws),
        Err(tungstenite::HandshakeError::Failure(tungstenite::Error::Http(resp))) => {
            let code = resp.status().as_u16();
            Err(match code {
                401 | 403 => "the hub refused the session token (it may be used up or expired)".into(),
                404 | 410 => "the hub no longer has this session".into(),
                409 => "another viewer is attached to this session".into(),
                _ => format!("the hub refused the screen connection (HTTP {code})"),
            })
        }
        Err(tungstenite::HandshakeError::Failure(e)) => Err(format!("the screen connection failed: {e}")),
        Err(tungstenite::HandshakeError::Interrupted(_)) => Err("the screen connection timed out".into()),
    }
}

/// POSTs JSON to the hub over pinned TLS. Returns status and body.
pub fn post_json(hub: &HubAddr, ca_pem: &str, path: &str, body: &str) -> Result<(u16, String), String> {
    let (mut tls, _ctl) = dial(hub, ca_pem)?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\nUser-Agent: ominull-screen/{}\r\n\r\n{body}",
        hub.authority(),
        body.len(),
        env!("CARGO_PKG_VERSION"),
    );
    tls.write_all(req.as_bytes()).map_err(|e| format!("could not reach the hub: {e}"))?;
    tls.flush().map_err(|e| format!("could not reach the hub: {e}"))?;
    let mut raw = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match tls.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if raw.len() > MAX_HTTP_BODY + 16 * 1024 {
                    return Err("the hub's answer is too large".into());
                }
            }
            // A server that closes without close_notify still sent a whole answer.
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("reading the hub's answer failed: {e}")),
        }
    }
    parse_http_response(&raw)
}

/// Minimal HTTP/1.1 response parse: status line, headers, body by
/// Content-Length, chunked, or to the end.
pub fn parse_http_response(raw: &[u8]) -> Result<(u16, String), String> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("the hub's answer is not HTTP")?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| "the hub's answer is not HTTP")?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    let code: u16 = status
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .filter(|_| status.starts_with("HTTP/1."))
        .ok_or("the hub's answer is not HTTP")?;
    let mut len = None;
    let mut chunked = false;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            let k = k.trim().to_ascii_lowercase();
            if k == "content-length" {
                len = v.trim().parse::<usize>().ok();
            } else if k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }
    let rest = &raw[split + 4..];
    let body = if chunked {
        let mut out = Vec::new();
        let mut p = rest;
        loop {
            let nl = p.windows(2).position(|w| w == b"\r\n").ok_or("bad chunked answer")?;
            let size = std::str::from_utf8(&p[..nl]).ok().and_then(|s| usize::from_str_radix(s.split(';').next()?.trim(), 16).ok()).ok_or("bad chunked answer")?;
            p = &p[nl + 2..];
            if size == 0 {
                break;
            }
            if p.len() < size {
                return Err("bad chunked answer".into());
            }
            out.extend_from_slice(&p[..size]);
            p = p.get(size + 2..).unwrap_or(&[]);
        }
        out
    } else if let Some(n) = len {
        rest.get(..n).ok_or("the hub's answer was cut short")?.to_vec()
    } else {
        rest.to_vec()
    };
    if body.len() > MAX_HTTP_BODY {
        return Err("the hub's answer is too large".into());
    }
    Ok((code, String::from_utf8_lossy(&body).into_owned()))
}

/// What the UI or `ctl` asks the pump to do.
#[derive(Debug)]
pub enum Out {
    /// One JSON text frame.
    Msg(String),
    /// Send `{"type":"close"}` and close: the session ends.
    End,
    /// Close the socket without `{"type":"close"}`: the hub detaches, the
    /// session stays live for the next viewer.
    Detach,
}

/// Why the pump stopped.
#[derive(Debug, PartialEq, Eq)]
pub enum Stop {
    /// We ended or detached on request.
    Local,
    /// The agent said bye or the hub closed the socket.
    Remote(String),
}

/// Runs the socket until it closes or `out` says to stop. Every incoming
/// message goes to `session`; any reply it produces (acks) is sent at once.
/// `changed` is called after each message that changed the picture.
pub fn pump<S: Read + Write>(
    ws: &mut WebSocket<S>,
    session: &mut Session,
    out: &Receiver<Out>,
    changed: &mut dyn FnMut(),
) -> Result<Stop, String> {
    loop {
        loop {
            match out.try_recv() {
                Ok(Out::Msg(m)) => send(ws, m)?,
                Ok(Out::End) => {
                    let _ = send(ws, screen_wire::InMsg::Close.to_json());
                    let _ = ws.close(None);
                    let _ = ws.flush();
                    return Ok(Stop::Local);
                }
                Ok(Out::Detach) | Err(TryRecvError::Disconnected) => {
                    let _ = ws.close(None);
                    let _ = ws.flush();
                    return Ok(Stop::Local);
                }
                Err(TryRecvError::Empty) => break,
            }
        }
        let replies = match ws.read() {
            Ok(Message::Text(t)) => session.on_text(t.as_bytes()),
            Ok(Message::Binary(b)) => session.on_binary(&b),
            Ok(Message::Close(f)) => {
                let why = f.map(|f| f.reason.to_string()).filter(|r| !r.is_empty());
                let why = session.end_reason().or(why).unwrap_or_else(|| "the hub closed the connection".into());
                session.set_ended(&why);
                changed();
                return Ok(Stop::Remote(why));
            }
            Ok(_) => Vec::new(),
            Err(tungstenite::Error::Io(e)) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                let _ = ws.flush();
                continue;
            }
            Err(tungstenite::Error::ConnectionClosed) | Err(tungstenite::Error::AlreadyClosed) => {
                let why = session.end_reason().unwrap_or_else(|| "the connection closed".into());
                session.set_ended(&why);
                changed();
                return Ok(Stop::Remote(why));
            }
            Err(e) => {
                let why = session.end_reason().unwrap_or_else(|| format!("the connection dropped ({e})"));
                session.set_ended(&why);
                changed();
                return Ok(Stop::Remote(why));
            }
        };
        for r in replies {
            send(ws, r)?;
        }
        if session.take_changed() {
            changed();
        }
    }
}

fn send<S: Read + Write>(ws: &mut WebSocket<S>, m: String) -> Result<(), String> {
    let would_block = |e: &tungstenite::Error| matches!(e, tungstenite::Error::Io(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut));
    match ws.send(Message::text(m)) {
        Ok(()) => Ok(()),
        // The frame is queued; the next flush or read finishes writing it.
        Err(e) if would_block(&e) => match ws.flush() {
            Err(e) if !would_block(&e) => Err(format!("sending to the hub failed: {e}")),
            _ => Ok(()),
        },
        Err(e) => Err(format!("sending to the hub failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_parse_length_and_chunked() {
        let (c, b) = parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n{\"a\"}").unwrap();
        assert_eq!((c, b.as_str()), (200, "{\"a\""));
        let (c, b) = parse_http_response(b"HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"x\r\n2\r\n\"}\r\n0\r\n\r\n").unwrap();
        assert_eq!((c, b.as_str()), (201, "{\"x\"}"));
        assert!(parse_http_response(b"garbage").is_err());
        assert!(parse_http_response(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nab").is_err());
    }

    #[test]
    fn ca_without_cert_refused() {
        assert!(tls_config("nothing here").is_err());
    }
}
