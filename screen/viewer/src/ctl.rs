//! `ominull-screen ctl <action>`: headless agent control (REMOTE_SCREEN.md
//! §8.2). Reads the stdin handshake, attaches, does one action, puts every
//! key and button back up, and detaches (the session stays live). Prints one
//! JSON object; exit code 0 on success.

use crate::geometry::{downscale_rgb, shot_scale, shot_size, shot_to_wire};
use crate::handshake::{Connect, Mode};
use crate::input::{self, Held};
use crate::keymap::{parse_combo, Combo};
use crate::net::{self, Out};
use crate::session::{Picture, Session, State};
use screen_wire::{MonitorInfo, RawButtons};
use serde_json::{json, Value};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const DEFAULT_MAX_EDGE: u32 = 1280;
const HELLO_WAIT: Duration = Duration::from_secs(15);
const KEYFRAME_WAIT: Duration = Duration::from_secs(20);

#[derive(Debug, PartialEq)]
pub enum Action {
    Info,
    Shot { monitor: Option<u32>, path: String, max_edge: u32 },
    Click { x: f64, y: f64, button: Button, double: bool, monitor: Option<u32>, max_edge: u32 },
    Move { x: f64, y: f64, monitor: Option<u32>, max_edge: u32 },
    Drag { x1: f64, y1: f64, x2: f64, y2: f64, monitor: Option<u32>, max_edge: u32 },
    Scroll { x: f64, y: f64, dy: i32, monitor: Option<u32>, max_edge: u32 },
    /// `None`: the text comes from the stdin session line (`"text"`), which
    /// keeps it out of the process list.
    Type { text: Option<String> },
    Key { combo: Combo },
    End,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
    Middle,
}

impl Button {
    fn pressed(self) -> RawButtons {
        RawButtons { l: self == Button::Left, r: self == Button::Right, m: self == Button::Middle }
    }
}

/// Parses `ctl` arguments (after the word `ctl`).
pub fn parse_args(args: &[String]) -> Result<Action, String> {
    let (name, rest) = args.split_first().ok_or("ctl needs an action: info, shot, click, move, drag, scroll, type, key, end")?;
    let mut pos: Vec<&str> = Vec::new();
    let mut monitor = None;
    let mut max_edge = DEFAULT_MAX_EDGE;
    let mut out = None;
    let mut button = Button::Left;
    let mut double = false;
    let mut i = 0;
    let value = |i: usize, flag: &str| rest.get(i + 1).map(String::as_str).ok_or(format!("{flag} needs a value"));
    while i < rest.len() {
        let a = rest[i].as_str();
        match a {
            "--monitor" => {
                monitor = Some(value(i, a)?.parse::<u32>().map_err(|_| "--monitor takes a monitor id")?);
                i += 1;
            }
            "--max-edge" => {
                let v = value(i, a)?.parse::<u32>().map_err(|_| "--max-edge takes a pixel count")?;
                if !(16..=16384).contains(&v) {
                    return Err("--max-edge must be between 16 and 16384".into());
                }
                max_edge = v;
                i += 1;
            }
            "-o" | "--output" => {
                out = Some(value(i, a)?.to_string());
                i += 1;
            }
            "--button" => {
                button = match value(i, a)? {
                    "left" => Button::Left,
                    "right" => Button::Right,
                    "middle" => Button::Middle,
                    _ => return Err("--button is left, right or middle".into()),
                };
                i += 1;
            }
            "--double" => double = true,
            "--" => {
                pos.extend(rest[i + 1..].iter().map(String::as_str));
                break;
            }
            f if f.starts_with("--") => return Err(format!("unknown option {f}")),
            p => pos.push(p),
        }
        i += 1;
    }
    let num = |s: &str| -> Result<f64, String> {
        let v: f64 = s.parse().map_err(|_| format!("{s:?} is not a number"))?;
        if v.is_finite() {
            Ok(v)
        } else {
            Err(format!("{s:?} is not a number"))
        }
    };
    let want = |n: usize| -> Result<(), String> {
        if pos.len() == n {
            Ok(())
        } else {
            Err(format!("ctl {name} takes {n} argument(s), got {}", pos.len()))
        }
    };
    let action = match name.as_str() {
        "info" => {
            want(0)?;
            Action::Info
        }
        "shot" => {
            want(0)?;
            Action::Shot { monitor, path: out.ok_or("ctl shot needs -o PATH")?, max_edge }
        }
        "click" => {
            want(2)?;
            Action::Click { x: num(pos[0])?, y: num(pos[1])?, button, double, monitor, max_edge }
        }
        "move" => {
            want(2)?;
            Action::Move { x: num(pos[0])?, y: num(pos[1])?, monitor, max_edge }
        }
        "drag" => {
            want(4)?;
            Action::Drag { x1: num(pos[0])?, y1: num(pos[1])?, x2: num(pos[2])?, y2: num(pos[3])?, monitor, max_edge }
        }
        "scroll" => {
            want(3)?;
            let dy: i32 = pos[2].parse().map_err(|_| "DY is a whole number of notches")?;
            if dy == 0 || dy.abs() > 10 {
                return Err("DY must be 1..10 notches, up positive, down negative".into());
            }
            Action::Scroll { x: num(pos[0])?, y: num(pos[1])?, dy, monitor, max_edge }
        }
        "type" => {
            if pos.len() > 1 {
                return Err(format!("ctl type takes at most 1 argument, got {}", pos.len()));
            }
            match pos.first() {
                Some(&"") => return Err("ctl type needs some text".into()),
                t => Action::Type { text: t.map(|t| t.to_string()) },
            }
        }
        "key" => {
            want(1)?;
            Action::Key { combo: parse_combo(pos[0])? }
        }
        "end" => {
            want(0)?;
            Action::End
        }
        other => return Err(format!("unknown ctl action {other:?}")),
    };
    Ok(action)
}

impl Action {
    fn sends_input(&self) -> bool {
        !matches!(self, Action::Info | Action::Shot { .. } | Action::End)
    }
}

/// An attached session: the pump on its own thread, the picture, the sender.
pub struct Attached {
    pub pic: Arc<Mutex<Picture>>,
    pub tx: Sender<Out>,
    pump: JoinHandle<Result<net::Stop, String>>,
}

impl Attached {
    /// Attaches over TLS.
    pub fn open(c: &Connect) -> Result<Attached, String> {
        let ws = net::open_ws(c)?;
        Ok(Self::start(ws))
    }

    /// Runs the pump for an already-open socket (tests use plain TCP).
    pub fn start<S: std::io::Read + std::io::Write + Send + 'static>(mut ws: tungstenite::WebSocket<S>) -> Attached {
        let mut session = Session::new();
        let pic = session.picture();
        let (tx, rx) = channel();
        let pump = thread::spawn(move || net::pump(&mut ws, &mut session, &rx, &mut || {}));
        Attached { pic, tx, pump }
    }

    fn send(&self, m: String) {
        let _ = self.tx.send(Out::Msg(m));
    }

    /// Polls the picture until `f` gives a value, the session ends, or time runs out.
    fn wait<T>(&self, timeout: Duration, what: &str, mut f: impl FnMut(&Picture) -> Option<T>) -> Result<T, String> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let p = self.pic.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(v) = f(&p) {
                    return Ok(v);
                }
                if let State::Ended(why) = &p.state {
                    return Err(format!("the session ended: {why}. Open a new one."));
                }
            }
            if self.pump.is_finished() {
                return Err("the connection closed".into());
            }
            if Instant::now() >= deadline {
                return Err(format!("timed out waiting for {what}"));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn monitors(&self) -> Result<(Vec<MonitorInfo>, Option<u32>), String> {
        self.wait(HELLO_WAIT, "the screen's monitor list", |p| (!p.monitors.is_empty()).then(|| (p.monitors.clone(), p.active)))
    }

    /// Ends the attachment: `end` closes the session, otherwise detach.
    pub fn finish(self, end: bool) -> Result<(), String> {
        let _ = self.tx.send(if end { Out::End } else { Out::Detach });
        match self.pump.join() {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("the connection thread failed".into()),
        }
    }
}

fn pick_monitor(monitors: &[MonitorInfo], want: Option<u32>) -> Result<MonitorInfo, String> {
    match want {
        Some(id) => monitors.iter().find(|m| m.id == id).cloned().ok_or_else(|| {
            let ids: Vec<String> = monitors.iter().map(|m| m.id.to_string()).collect();
            format!("no monitor {id}; this screen has {}", ids.join(", "))
        }),
        None => monitors.iter().find(|m| m.primary).or(monitors.first()).cloned().ok_or("the screen reports no monitors".into()),
    }
}

/// Runs one action on an attached session. Every key and button pressed is
/// released before this returns, on success or failure.
pub fn run(a: &Attached, action: &Action, mode: Mode) -> Result<Value, String> {
    if action.sends_input() && mode == Mode::View {
        return Err("this session is view-only, so it cannot send input".into());
    }
    let mut held = Held::default();
    let r = run_inner(a, action, &mut held);
    for m in held.release_all() {
        a.send(m);
    }
    r
}

fn point(m: &MonitorInfo, x: f64, y: f64, max_edge: u32) -> Result<(u16, u16), String> {
    shot_to_wire(x, y, max_edge, m.w, m.h)
}

fn run_inner(a: &Attached, action: &Action, held: &mut Held) -> Result<Value, String> {
    let pause = || thread::sleep(Duration::from_millis(20));
    match action {
        Action::Info => {
            let (monitors, active) = a.monitors()?;
            // The agent sends `desktop` right after `hello`; give it a moment.
            let desktop = a.wait(Duration::from_millis(1500), "", |p| p.desktop.clone()).ok();
            Ok(json!({
                "monitors": monitors,
                "active": active,
                "desktop": desktop.map(|(name, signed_in)| json!({ "name": name, "signed_in": signed_in })),
            }))
        }
        Action::Shot { monitor, path, max_edge } => {
            let (monitors, active) = a.monitors()?;
            let m = pick_monitor(&monitors, *monitor)?;
            if active != Some(m.id) {
                a.pic.lock().unwrap_or_else(|e| e.into_inner()).set_active(m.id);
                a.send(input::set_monitor(m.id));
            }
            let rgb = a.wait(KEYFRAME_WAIT, "a full picture of the monitor", |p| {
                (p.active == Some(m.id) && p.keyframes_done > 0).then(|| p.composite_rgb())
            })?;
            let scale = shot_scale(*max_edge, m.w, m.h);
            let (w, h) = shot_size(scale, m.w, m.h);
            let img = downscale_rgb(&rgb, m.w, m.h, w, h);
            write_png(path, w, h, &img)?;
            Ok(json!({
                "ok": true, "path": path, "width": w, "height": h, "scale": scale,
                "monitor": m.id, "monitor_width": m.w, "monitor_height": m.h,
            }))
        }
        Action::Click { x, y, button, double, monitor, max_edge } => {
            let m = pick_monitor(&a.monitors()?.0, *monitor)?;
            let (wx, wy) = point(&m, *x, *y, *max_edge)?;
            press_at(a, held, wx, wy, m.id, RawButtons::default());
            pause();
            for n in 0..if *double { 2 } else { 1 } {
                if n > 0 {
                    thread::sleep(Duration::from_millis(60));
                }
                held.buttons = button.pressed();
                press_at(a, held, wx, wy, m.id, button.pressed());
                pause();
                held.buttons = RawButtons::default();
                press_at(a, held, wx, wy, m.id, RawButtons::default());
            }
            Ok(json!({ "ok": true }))
        }
        Action::Move { x, y, monitor, max_edge } => {
            let m = pick_monitor(&a.monitors()?.0, *monitor)?;
            let (wx, wy) = point(&m, *x, *y, *max_edge)?;
            press_at(a, held, wx, wy, m.id, RawButtons::default());
            Ok(json!({ "ok": true }))
        }
        Action::Drag { x1, y1, x2, y2, monitor, max_edge } => {
            let m = pick_monitor(&a.monitors()?.0, *monitor)?;
            let p1 = point(&m, *x1, *y1, *max_edge)?;
            let p2 = point(&m, *x2, *y2, *max_edge)?;
            let left = Button::Left.pressed();
            press_at(a, held, p1.0, p1.1, m.id, RawButtons::default());
            pause();
            held.buttons = left;
            press_at(a, held, p1.0, p1.1, m.id, left);
            const STEPS: i32 = 8;
            for s in 1..=STEPS {
                pause();
                let t = s as f64 / STEPS as f64;
                let x = (p1.0 as f64 + (p2.0 as f64 - p1.0 as f64) * t).round() as u16;
                let y = (p1.1 as f64 + (p2.1 as f64 - p1.1 as f64) * t).round() as u16;
                press_at(a, held, x, y, m.id, left);
            }
            pause();
            held.buttons = RawButtons::default();
            press_at(a, held, p2.0, p2.1, m.id, RawButtons::default());
            Ok(json!({ "ok": true }))
        }
        Action::Scroll { x, y, dy, monitor, max_edge } => {
            let m = pick_monitor(&a.monitors()?.0, *monitor)?;
            let (wx, wy) = point(&m, *x, *y, *max_edge)?;
            press_at(a, held, wx, wy, m.id, RawButtons::default());
            pause();
            a.send(input::wheel(0, dy * 120, m.id));
            Ok(json!({ "ok": true }))
        }
        Action::Type { text } => {
            let text = text.as_deref().ok_or("ctl type has no text")?;
            a.monitors()?;
            let units = input::text_units(text);
            for u in &units {
                a.send(input::text(u));
            }
            Ok(json!({ "ok": true, "sent": units.len() }))
        }
        Action::Key { combo } => {
            a.monitors()?;
            match combo {
                Combo::Sas => a.send(input::sas()),
                Combo::Keys { mods, key } => {
                    for m in mods {
                        held.key(*m, true);
                        a.send(input::key(*m, true));
                    }
                    held.key(*key, true);
                    a.send(input::key(*key, true));
                    pause();
                    held.key(*key, false);
                    a.send(input::key(*key, false));
                    for m in mods.iter().rev() {
                        held.key(*m, false);
                        a.send(input::key(*m, false));
                    }
                }
            }
            Ok(json!({ "ok": true }))
        }
        Action::End => Ok(json!({ "ok": true, "ended": true })),
    }
}

fn press_at(a: &Attached, held: &mut Held, x: u16, y: u16, monitor: u32, b: RawButtons) {
    held.last = Some((x, y, monitor));
    a.send(input::mouse(x, y, b, monitor));
}

fn write_png(path: &str, w: u32, h: u32, rgb: &[u8]) -> Result<(), String> {
    let file = std::fs::File::create(path).map_err(|e| format!("could not write {path}: {e}"))?;
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w, h);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    let mut wr = enc.write_header().map_err(|e| format!("could not write {path}: {e}"))?;
    wr.write_image_data(rgb).map_err(|e| format!("could not write {path}: {e}"))?;
    wr.finish().map_err(|e| format!("could not write {path}: {e}"))
}

/// The whole `ctl` command: parse, attach, act, detach. Returns the JSON to
/// print and whether it succeeded.
pub fn main_ctl(args: &[String], connect: impl FnOnce() -> Result<Connect, String>) -> (Value, bool) {
    let action = match parse_args(args) {
        Ok(a) => a,
        Err(e) => return (json!({ "error": e }), false),
    };
    let mut c = match connect() {
        Ok(c) => c,
        Err(e) => return (json!({ "error": e }), false),
    };
    let action = match with_line_text(action, c.text.take()) {
        Ok(a) => a,
        Err(e) => return (json!({ "error": e }), false),
    };
    let a = match Attached::open(&c) {
        Ok(a) => a,
        Err(e) => return (json!({ "error": e }), false),
    };
    let result = run(&a, &action, c.mode);
    let fin = a.finish(action == Action::End && result.is_ok());
    match (result, fin) {
        (Ok(v), Ok(())) => (v, true),
        (Ok(_), Err(e)) => (json!({ "error": e }), false),
        (Err(e), _) => (json!({ "error": e }), false),
    }
}

/// Fills `ctl type`'s text from the session line when argv had none. The
/// text must come from exactly one place.
fn with_line_text(action: Action, line_text: Option<String>) -> Result<Action, String> {
    match (action, line_text) {
        (Action::Type { text: None }, Some(t)) if !t.is_empty() => Ok(Action::Type { text: Some(t) }),
        (Action::Type { text: None }, _) => Err("ctl type needs some text: as its argument or as \"text\" in the session line on stdin".into()),
        (Action::Type { text: Some(_) }, Some(_)) => Err("ctl type got text both as an argument and in the session line; send it once".into()),
        (a, _) => Ok(a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn parses_actions() {
        assert_eq!(parse_args(&args("info")).unwrap(), Action::Info);
        assert_eq!(
            parse_args(&args("shot --monitor 1 -o /tmp/a.png --max-edge 800")).unwrap(),
            Action::Shot { monitor: Some(1), path: "/tmp/a.png".into(), max_edge: 800 }
        );
        assert_eq!(
            parse_args(&args("click 10 20.5 --button right --double")).unwrap(),
            Action::Click { x: 10.0, y: 20.5, button: Button::Right, double: true, monitor: None, max_edge: 1280 }
        );
        assert!(matches!(parse_args(&args("drag 1 2 3 4 --monitor 0")).unwrap(), Action::Drag { monitor: Some(0), .. }));
        assert!(matches!(parse_args(&args("scroll 1 2 -3")).unwrap(), Action::Scroll { dy: -3, .. }));
        assert_eq!(parse_args(&["type".into(), "héllo world".into()]).unwrap(), Action::Type { text: Some("héllo world".into()) });
        assert_eq!(parse_args(&args("type")).unwrap(), Action::Type { text: None });
        assert_eq!(parse_args(&args("key ctrl+alt+del")).unwrap(), Action::Key { combo: Combo::Sas });
        assert_eq!(parse_args(&args("end")).unwrap(), Action::End);
    }

    #[test]
    fn rejects_bad_args() {
        for bad in ["", "shot", "click 1", "click a b", "click 1 2 --button side", "scroll 1 2 0", "scroll 1 2 50", "move 1 2 --bogus", "key a+b", "fly", "info extra", "click NaN 1", "shot -o x --max-edge 1", "type a b"] {
            assert!(parse_args(&args(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn type_text_from_the_session_line() {
        let line = |t: &str| Some(t.to_string());
        assert_eq!(with_line_text(Action::Type { text: None }, line("pa ss")).unwrap(), Action::Type { text: line("pa ss") });
        assert_eq!(with_line_text(Action::Type { text: line("argv") }, None).unwrap(), Action::Type { text: line("argv") });
        assert!(with_line_text(Action::Type { text: None }, None).is_err());
        assert!(with_line_text(Action::Type { text: None }, line("")).is_err());
        assert!(with_line_text(Action::Type { text: line("a") }, line("b")).is_err());
        assert_eq!(with_line_text(Action::Info, line("ignored")).unwrap(), Action::Info);
    }
}
