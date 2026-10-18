//! Loopback: a fake hub over real TLS (test CA) speaking the agent side of
//! the wire, driven through the same `ctl` entry point the binary uses.

use screen_viewer::{ctl, handshake};
use screen_wire::{encode_cursor_shape, encode_tile_message, CURSOR_FORMAT_COLOR_BGRA};
use serde_json::{json, Value};
use std::net::TcpListener;
use std::sync::mpsc::{channel, Receiver};
use std::sync::Arc;
use tungstenite::handshake::server::{Request, Response};
use tungstenite::Message;

/// Test PKI, generated once per test run: a CA, a server leaf for
/// 127.0.0.1/localhost signed by it, and an unrelated CA.
struct Pki {
    ca: String,
    other_ca: String,
    leaf: String,
    leaf_key: String,
}

fn pki() -> &'static Pki {
    use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    static PKI: std::sync::OnceLock<Pki> = std::sync::OnceLock::new();
    PKI.get_or_init(|| {
        let ca_params = |cn: &str| {
            let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
            p.distinguished_name.push(DnType::CommonName, cn);
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            p
        };
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params("ominull-screen test CA").self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params("ominull-screen test CA"), ca_key);
        let other_key = KeyPair::generate().unwrap();
        let other_ca = ca_params("unrelated test CA").self_signed(&other_key).unwrap();
        let mut leaf_params = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
        leaf_params.distinguished_name.push(DnType::CommonName, "localhost");
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf_key = KeyPair::generate().unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();
        Pki { ca: ca.pem(), other_ca: other_ca.pem(), leaf: leaf.pem(), leaf_key: leaf_key.serialize_pem() }
    })
}
const TOKEN: &str = "tok_Test-123.abc";

#[derive(Debug, Default)]
struct Rec {
    path: String,
    token: Option<String>,
    origin: bool,
    cookie: bool,
    msgs: Vec<Value>,
}

impl Rec {
    fn of(&self, t: &str) -> Vec<&Value> {
        self.msgs.iter().filter(|m| m["type"] == t).collect()
    }
    fn inputs(&self) -> Vec<&Value> {
        self.of("input")
    }
}

fn jpeg(w: u16, h: u16, rgb: [u8; 3]) -> Vec<u8> {
    let px: Vec<u8> = (0..(w as usize * h as usize)).flat_map(|_| rgb).collect();
    let mut out = Vec::new();
    jpeg_encoder::Encoder::new(&mut out, 95).encode(&px, w, h, jpeg_encoder::ColorType::Rgb).unwrap();
    out
}

fn server_config() -> Arc<rustls::ServerConfig> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(pki().leaf.as_bytes()).map(|c| c.unwrap()).collect();
    let key = PrivateKeyDer::from_pem_slice(pki().leaf_key.as_bytes()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    Arc::new(cfg)
}

/// Monitor 0 is 128x64 (red left half, blue right half), monitor 1 is 64x32 green.
fn send_monitor<S: std::io::Read + std::io::Write>(ws: &mut tungstenite::WebSocket<S>, id: u8, frame: u64) {
    if id == 0 {
        let _ = ws.send(Message::binary(encode_tile_message(0, true, 0, 0, 64, 64, 1, &jpeg(64, 64, [230, 20, 20]))));
        let _ = ws.send(Message::binary(encode_tile_message(0, true, 64, 0, 64, 64, 2, &jpeg(64, 64, [20, 20, 230]))));
        let _ = ws.send(Message::text(json!({"type":"frame_end","monitor":0,"frame":frame,"tiles":2}).to_string()));
    } else {
        let _ = ws.send(Message::binary(encode_tile_message(1, true, 0, 0, 64, 32, 3, &jpeg(64, 32, [20, 220, 20]))));
        let _ = ws.send(Message::text(json!({"type":"frame_end","monitor":1,"frame":frame,"tiles":1}).to_string()));
    }
}

/// Serves `n` operator connections, one scripted agent each; returns the port
/// and what each connection received.
fn fake_hub(n: usize) -> (u16, Receiver<Rec>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = channel();
    let cfg = server_config();
    std::thread::spawn(move || {
        for _ in 0..n {
            let Ok((tcp, _)) = listener.accept() else { return };
            let tx = tx.clone();
            let cfg = cfg.clone();
            std::thread::spawn(move || {
                let mut rec = Rec::default();
                let conn = rustls::ServerConnection::new(cfg).unwrap();
                let tls = rustls::StreamOwned::new(conn, tcp);
                #[allow(clippy::result_large_err)]
                let cb = |req: &Request, resp: Response| {
                    rec.path = req.uri().to_string();
                    rec.token = req.headers().get("x-screen-token").and_then(|v| v.to_str().ok()).map(String::from);
                    rec.origin = req.headers().contains_key("origin");
                    rec.cookie = req.headers().contains_key("cookie");
                    Ok(resp)
                };
                let mut ws = match tungstenite::accept_hdr(tls, cb) {
                    Ok(ws) => ws,
                    Err(_) => {
                        let _ = tx.send(rec);
                        return;
                    }
                };
                let hello = json!({"type":"hello","active":0,"monitors":[
                    {"id":0,"w":128,"h":64,"x":0,"y":0,"primary":true},
                    {"id":1,"w":64,"h":32,"x":128,"y":0,"primary":false}]});
                let _ = ws.send(Message::text(hello.to_string()));
                let _ = ws.send(Message::text(r#"{"type":"desktop","name":"Default","signed_in":true}"#));
                // A 4x4 opaque white cursor, hotspot 1,1, at 10,10.
                let white: Vec<u8> = (0..16).flat_map(|_| [255u8, 255, 255, 255]).collect();
                let _ = ws.send(Message::binary(encode_cursor_shape(4, 4, 1, 1, CURSOR_FORMAT_COLOR_BGRA, &white)));
                let _ = ws.send(Message::text(r#"{"type":"cursor_pos","x":10,"y":10,"visible":true}"#));
                send_monitor(&mut ws, 0, 1);
                // Two more frame_ends straight away: each one must be acked.
                let _ = ws.send(Message::text(r#"{"type":"frame_end","monitor":0,"frame":2,"tiles":0}"#));
                let _ = ws.send(Message::text(r#"{"type":"frame_end","monitor":0,"frame":3,"tiles":0}"#));
                let mut frame = 4;
                loop {
                    match ws.read() {
                        Ok(Message::Text(t)) => {
                            let v: Value = serde_json::from_str(t.as_str()).unwrap();
                            if v["type"] == "set_monitor" {
                                send_monitor(&mut ws, v["monitor"].as_u64().unwrap() as u8, frame);
                                frame += 1;
                            }
                            rec.msgs.push(v);
                        }
                        Ok(Message::Close(_)) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                let _ = tx.send(rec);
            });
        }
    });
    (port, rx)
}

fn line(port: u16, ca: &str, mode: &str) -> String {
    json!({"hub_url": format!("https://127.0.0.1:{port}"), "ca_pem": ca, "session_id": "sess-1",
           "token": TOKEN, "mode": mode, "host": "pc-01"})
    .to_string()
}

fn ctl(port: u16, mode: &str, args: &str) -> (Value, bool) {
    let args: Vec<String> = shell_split(args);
    ctl::main_ctl(&args, || handshake::read_line(&mut line(port, &pki().ca, mode).as_bytes()))
}

fn shell_split(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
}

fn scratch(name: &str) -> String {
    let d = std::env::temp_dir().join(format!("ominull-screen-test-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name).to_string_lossy().into_owned()
}

fn png_rgb(path: &str) -> (u32, u32, Vec<u8>) {
    let dec = png::Decoder::new(std::io::BufReader::new(std::fs::File::open(path).unwrap()));
    let mut r = dec.read_info().unwrap();
    let mut buf = vec![0; r.output_buffer_size().unwrap()];
    let info = r.next_frame(&mut buf).unwrap();
    buf.truncate(info.buffer_size());
    (info.width, info.height, buf)
}

fn px(img: &(u32, u32, Vec<u8>), x: u32, y: u32) -> [u8; 3] {
    let i = ((y * img.0 + x) * 3) as usize;
    [img.2[i], img.2[i + 1], img.2[i + 2]]
}

fn near(a: [u8; 3], b: [u8; 3]) -> bool {
    a.iter().zip(b).all(|(x, y)| (*x as i32 - y as i32).abs() < 40)
}

#[test]
fn info_shot_and_acks() {
    let (port, rx) = fake_hub(3);

    let (v, ok) = ctl(port, "control", "info");
    assert!(ok, "{v}");
    assert_eq!(v["monitors"].as_array().unwrap().len(), 2);
    assert_eq!(v["active"], 0);
    assert_eq!(v["desktop"], json!({"name":"Default","signed_in":true}));
    let rec = rx.recv().unwrap();
    assert_eq!(rec.path, "/api/v1/screen/ws/operator?session_id=sess-1");
    assert_eq!(rec.token.as_deref(), Some(TOKEN));
    assert!(!rec.origin && !rec.cookie, "no Origin or Cookie header");
    assert!(rec.inputs().is_empty());
    assert!(rec.of("close").is_empty(), "info detaches, it does not end the session");

    let path = scratch("m0.png");
    let (v, ok) = ctl(port, "control", &format!("shot -o {path} --max-edge 64"));
    assert!(ok, "{v}");
    assert_eq!((v["width"].as_u64(), v["height"].as_u64(), v["scale"].as_f64()), (Some(64), Some(32), Some(0.5)));
    assert_eq!((v["monitor"].as_u64(), v["monitor_width"].as_u64(), v["monitor_height"].as_u64()), (Some(0), Some(128), Some(64)));
    let img = png_rgb(&path);
    assert_eq!((img.0, img.1), (64, 32));
    assert!(near(px(&img, 10, 20), [230, 20, 20]), "{:?}", px(&img, 10, 20));
    assert!(near(px(&img, 50, 20), [20, 20, 230]), "{:?}", px(&img, 50, 20));
    // The cursor (white, 4x4 at 9..13 in monitor pixels) is composited in.
    assert!(px(&img, 5, 5).iter().all(|c| *c > 150), "{:?}", px(&img, 5, 5));
    let rec = rx.recv().unwrap();
    let acks: Vec<u64> = rec.of("ack").iter().map(|a| a["frame"].as_u64().unwrap()).collect();
    assert_eq!(acks, [1, 2, 3], "every frame_end acked once, in order");
    assert!(rec.of("ack").iter().all(|a| a["monitor"] == 0));

    let path = scratch("m1.png");
    let (v, ok) = ctl(port, "control", &format!("shot --monitor 1 -o {path}"));
    assert!(ok, "{v}");
    assert_eq!((v["width"].as_u64(), v["height"].as_u64(), v["scale"].as_f64()), (Some(64), Some(32), Some(1.0)), "never upscales");
    assert!(near(px(&png_rgb(&path), 30, 16), [20, 220, 20]));
    let rec = rx.recv().unwrap();
    assert_eq!(rec.of("set_monitor").len(), 1);
    assert!(rec.of("ack").iter().any(|a| a["monitor"] == 1 && a["frame"] == 4));
}

#[test]
fn input_actions() {
    let (port, rx) = fake_hub(7);

    // Right click at the centre of a 128-wide shot of the 128x64 monitor.
    let (v, ok) = ctl(port, "control", "click 64 32 --button right --max-edge 128");
    assert!(ok, "{v}");
    let rec = rx.recv().unwrap();
    let mice: Vec<&Value> = rec.inputs().into_iter().filter(|m| m["ev"] == "mouse").collect();
    assert!(mice.len() >= 3);
    let x = 33024; // floor(64.5 * 65536 / 128)
    let y = 33280; // floor(32.5 * 65536 / 64)
    assert!(mice.iter().all(|m| m["x"] == x && m["y"] == y && m["monitor"] == 0), "{mice:?}");
    assert_eq!(mice[1]["buttons"], json!({"l":false,"r":true,"m":false}));
    assert_eq!(mice.last().unwrap()["buttons"], json!({"l":false,"r":false,"m":false}));

    let (v, ok) = ctl(port, "control", "key ctrl+c");
    assert!(ok, "{v}");
    let keys: Vec<(u64, bool)> =
        rx.recv().unwrap().inputs().iter().filter(|m| m["ev"] == "key").map(|m| (m["code"].as_u64().unwrap(), m["down"].as_bool().unwrap())).collect();
    assert_eq!(&keys[..4], &[(0x1d, true), (0x2e, true), (0x2e, false), (0x1d, false)]);

    let (v, ok) = ctl(port, "control", "key ctrl+alt+del");
    assert!(ok, "{v}");
    let rec = rx.recv().unwrap();
    assert_eq!(rec.inputs().iter().filter(|m| m["ev"] == "sas").count(), 1);

    let (v, ok) = ctl(port, "control", "scroll 10 10 -2");
    assert!(ok, "{v}");
    let rec = rx.recv().unwrap();
    let wheel: Vec<&Value> = rec.inputs().into_iter().filter(|m| m["ev"] == "wheel").collect();
    assert_eq!(wheel.len(), 1);
    assert_eq!((wheel[0]["dx"].clone(), wheel[0]["dy"].clone()), (json!(0), json!(-240)));

    let (v, ok) = ctl::main_ctl(&["type".into(), "hé!".into()], || handshake::read_line(&mut line(port, &pki().ca, "control").as_bytes()));
    assert!(ok, "{v}");
    let rec = rx.recv().unwrap();
    let text: Vec<&str> = rec.inputs().iter().filter(|m| m["ev"] == "text").map(|m| m["ch"].as_str().unwrap()).collect();
    assert_eq!(text, ["h", "é", "!"]);

    // Out of bounds: refused, nothing sent, nonzero.
    let (v, ok) = ctl(port, "control", "click 200 10 --max-edge 128");
    assert!(!ok);
    assert!(v["error"].as_str().unwrap().contains("outside"), "{v}");
    let rec = rx.recv().unwrap();
    assert!(rec.inputs().iter().all(|m| m["ev"] != "mouse" || m["buttons"] == json!({"l":false,"r":false,"m":false})));

    let (v, ok) = ctl(port, "control", "end");
    assert!(ok, "{v}");
    assert_eq!(rx.recv().unwrap().of("close").len(), 1, "end sends close");
}

#[test]
fn view_mode_refuses_input() {
    let (port, rx) = fake_hub(1);
    let (v, ok) = ctl(port, "view", "click 1 1");
    assert!(!ok);
    assert!(v["error"].as_str().unwrap().contains("view-only"), "{v}");
    assert!(rx.recv().unwrap().inputs().is_empty());
}

#[test]
fn wrong_ca_is_refused() {
    let (port, _rx) = fake_hub(1);
    let (v, ok) = ctl::main_ctl(&["info".into()], || handshake::read_line(&mut line(port, &pki().other_ca, "control").as_bytes()));
    assert!(!ok);
    let e = v["error"].as_str().unwrap();
    assert!(e.contains("certificate"), "{e}");
    assert!(!e.contains(TOKEN));
}

/// Not a test: a fake hub for looking at the window by hand or under Xvfb.
/// `FAKE_HUB_PORT=9555 FAKE_HUB_LOG=/tmp/in.jsonl cargo test --test loopback
/// manual_fake_hub -- --ignored --nocapture` prints the handshake line to feed
/// the viewer on stdin (with this run's generated CA); FAKE_HUB_LINE=PATH
/// also writes it to a file.
#[test]
#[ignore]
fn manual_fake_hub() {
    use std::io::Write;
    let port: u16 = std::env::var("FAKE_HUB_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(9555);
    let log = std::env::var("FAKE_HUB_LOG").ok();
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let cfg = server_config();
    let hello = json!({"hub_url": format!("https://127.0.0.1:{port}"), "ca_pem": pki().ca, "session_id": "demo",
                       "token": "demo-token", "mode": "control", "host": "pc-01"});
    println!("{hello}");
    if let Ok(path) = std::env::var("FAKE_HUB_LINE") {
        std::fs::write(path, format!("{hello}\n")).unwrap();
    }
    for tcp in listener.incoming().flatten() {
        let conn = rustls::ServerConnection::new(cfg.clone()).unwrap();
        let Ok(mut ws) = tungstenite::accept(rustls::StreamOwned::new(conn, tcp)) else { continue };
        let log = log.clone();
        std::thread::spawn(move || {
            let hello = json!({"type":"hello","active":0,"monitors":[
                {"id":0,"w":1280,"h":720,"x":0,"y":0,"primary":true},
                {"id":1,"w":1024,"h":768,"x":1280,"y":0,"primary":false}]});
            let _ = ws.send(Message::text(hello.to_string()));
            let _ = ws.send(Message::text(r#"{"type":"desktop","name":"Default","signed_in":true}"#));
            let arrow: Vec<u8> = (0..16u32 * 16)
                .flat_map(|i| {
                    let (x, y) = (i % 16, i / 16);
                    if x <= y && x + y < 24 { if x == 0 || x == y || x + y == 23 { [0, 0, 0, 255] } else { [255, 255, 255, 255] } } else { [0, 0, 0, 0] }
                })
                .collect();
            let _ = ws.send(Message::binary(encode_cursor_shape(16, 16, 0, 0, CURSOR_FORMAT_COLOR_BGRA, &arrow)));
            let _ = ws.send(Message::text(r#"{"type":"cursor_pos","x":640,"y":360,"visible":true}"#));
            let desktop = |ws: &mut tungstenite::WebSocket<_>, id: u8, w: u16, h: u16, frame: u64| {
                let mut n = 0;
                for ty in (0..h).step_by(128) {
                    for tx in (0..w).step_by(128) {
                        let (tw, th) = (128.min(w - tx), 128.min(h - ty));
                        let base = if id == 0 { [32u8, 72, 120] } else { [60, 40, 90] };
                        let mut c = [base[0].wrapping_add((tx / 16) as u8), base[1].wrapping_add((ty / 12) as u8), base[2]];
                        // A "window" in the middle of monitor 0.
                        if id == 0 && (256..1024).contains(&tx) && (128..640).contains(&ty) {
                            c = if ty == 128 { [50, 54, 62] } else { [235, 236, 240] };
                        }
                        let _ = ws.send(Message::binary(encode_tile_message(id, true, tx, ty, tw, th, n, &jpeg(tw, th, c))));
                        n += 1;
                    }
                }
                let _ = ws.send(Message::text(json!({"type":"frame_end","monitor":id,"frame":frame,"tiles":n}).to_string()));
            };
            desktop(&mut ws, 0, 1280, 720, 1);
            let mut frame = 2;
            loop {
                match ws.read() {
                    Ok(Message::Text(t)) => {
                        if let Some(path) = &log {
                            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                                let _ = writeln!(f, "{}", t.as_str());
                            }
                        }
                        let v: Value = serde_json::from_str(t.as_str()).unwrap_or_default();
                        match v["type"].as_str() {
                            Some("set_monitor") => {
                                let id = v["monitor"].as_u64().unwrap_or(0) as u8;
                                let (w, h) = if id == 0 { (1280, 720) } else { (1024, 768) };
                                desktop(&mut ws, id, w, h, frame);
                                frame += 1;
                            }
                            Some("input") if v["ev"] == "sas" => {
                                let _ = ws.send(Message::text(r#"{"type":"sas_unavailable","reason":"policy"}"#));
                            }
                            Some("input") if v["ev"] == "mouse" => {
                                let (x, y) = (v["x"].as_u64().unwrap_or(0) * 1280 / 65536, v["y"].as_u64().unwrap_or(0) * 720 / 65536);
                                let _ = ws.send(Message::text(json!({"type":"cursor_pos","x":x,"y":y,"visible":true}).to_string()));
                            }
                            Some("close") => {
                                let _ = ws.send(Message::text(r#"{"type":"bye","reason":"the operator ended the session"}"#));
                                let _ = ws.close(None);
                            }
                            _ => {}
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });
    }
}

#[test]
fn launch_code_redeemed_once_over_pinned_tls() {
    use screen_viewer::launch;
    use std::io::{Read, Write};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let cfg = server_config();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), tcp);
        let mut req = Vec::new();
        let mut buf = [0u8; 4096];
        while !String::from_utf8_lossy(&req).contains("}") {
            let n = tls.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            req.extend_from_slice(&buf[..n]);
        }
        let body = r#"{"token":"tok_redeemed-1","mode":"view","host":"pc-02","expires_at":"2026-10-17T00:00:00Z"}"#;
        let _ = write!(tls, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        let _ = tls.flush();
        tls.conn.send_close_notify();
        let _ = tls.flush();
        tx.send(String::from_utf8(req).unwrap()).unwrap();
    });
    let code = "Zx9_k2-abcdefghijklmnop";
    let link = launch::parse_url(&format!("ominull-screen://open?hub=https://127.0.0.1:{port}&session=sess-9&code={code}")).unwrap();
    let entry = launch::HubEntry { origin: format!("https://127.0.0.1:{port}"), ca_pem: pki().ca.clone() };
    let c = launch::redeem(&link, &entry).unwrap();
    assert_eq!((c.token.as_str(), c.session_id.as_str(), c.host_label.as_str()), ("tok_redeemed-1", "sess-9", "pc-02"));
    assert_eq!(c.mode, handshake::Mode::View);
    let req = rx.recv().unwrap();
    assert!(req.starts_with("POST /api/v1/screen/launch/redeem HTTP/1.1\r\n"), "{req}");
    assert!(!req.to_ascii_lowercase().contains("\r\norigin:") && !req.to_ascii_lowercase().contains("\r\ncookie:"));
    let body: Value = serde_json::from_str(&req[req.find("\r\n\r\n").unwrap() + 4..]).unwrap();
    assert_eq!(body, json!({"session_id":"sess-9","code":code}));

    // The same link against a hub whose certificate is not from the configured CA.
    let wrong = launch::HubEntry { origin: entry.origin.clone(), ca_pem: pki().other_ca.clone() };
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port2 = listener.local_addr().unwrap().port();
    let cfg = server_config();
    std::thread::spawn(move || {
        if let Ok((tcp, _)) = listener.accept() {
            let mut tls = rustls::StreamOwned::new(rustls::ServerConnection::new(cfg).unwrap(), tcp);
            let _ = tls.read(&mut [0u8; 64]);
        }
    });
    let link2 = launch::parse_url(&format!("ominull-screen://open?hub=https://127.0.0.1:{port2}&session=sess-9&code={code}")).unwrap();
    let e = launch::redeem(&link2, &wrong).unwrap_err();
    assert!(e.contains("certificate") && !e.contains(code), "{e}");
}
