//! The viewer window (REMOTE_SCREEN.md §9.1): a toolbar, the remote picture
//! and cursor, and mouse/keyboard capture.

use crate::draw::{self, text_w, Canvas};
use crate::geometry::{place, to_wire, Placement, Scale, Wheel};
use crate::grab::{Grab, GrabState};
use crate::handshake::{Connect, Mode};
use crate::input::{self, Held};
use crate::keymap::{self, Scan, LALT, LCTRL, LSHIFT, RALT, RCTRL, RSHIFT};
use crate::launch::{self, HubEntry, LaunchUrl};
use crate::net::{self, Out, Stop};
use crate::session::{Picture, Session, State};
use screen_wire::RawButtons;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use winit::application::ApplicationHandler;
use winit::dpi::{LogicalSize, PhysicalPosition};
use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{KeyCode, PhysicalKey};
use winit::window::{Fullscreen, Window, WindowId};

/// The hotkey that captures or releases the keyboard, shown on screen.
pub const GRAB_HOTKEY: &str = "Ctrl+Alt+Shift+G";
/// The hotkey for Ctrl+Alt+Del (the local OS keeps the real one).
pub const SAS_HOTKEY: &str = "Ctrl+Alt+End";

const QUALITY: [(&str, u32, u32); 4] = [("Sharp", 10, 80), ("Normal", 10, 60), ("Slow link", 5, 45), ("Very slow link", 2, 30)];
const NOTICE_FOR: Duration = Duration::from_secs(8);

/// How the window gets its session.
pub enum Start {
    /// A handshake already read from stdin.
    Connect(Connect),
    /// A console link: redeem the code first.
    Launch(LaunchUrl, HubEntry),
    /// Nothing to connect to: show why.
    Error(String),
}

#[derive(Debug)]
pub enum UserEvent {
    Redraw,
    /// The launch code was redeemed: the real mode and host label.
    Attached { mode: Mode, host: String },
    NetEnded(Result<Stop, String>),
    #[allow(dead_code)]
    HookKey { code: u8, ext: bool, down: bool },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Act {
    Scale,
    Monitor,
    Quality,
    ViewOnly,
    Sas,
    Fullscreen,
    Grab,
    End,
}

struct Item {
    x: i64,
    w: i64,
    label: String,
    act: Act,
    on: bool,
    enabled: bool,
}

struct App {
    #[cfg_attr(not(windows), allow(dead_code))]
    proxy: EventLoopProxy<UserEvent>,
    window: Option<Rc<Window>>,
    surface: Option<softbuffer::Surface<Rc<Window>, Rc<Window>>>,
    grab: Option<Grab>,
    pic: Arc<Mutex<Picture>>,
    tx: Option<Sender<Out>>,
    /// Set by the net thread when it has asked for a redraw; cleared here.
    redraw_pending: Arc<AtomicBool>,
    mode: Mode,
    host: String,
    attached: bool,
    fatal: Option<String>,
    view_only: bool,
    grab_wanted: bool,
    focused: bool,
    scale: Scale,
    quality: usize,
    fullscreen: bool,
    pointer: Option<(f64, f64)>,
    last_sent: Option<(u16, u16)>,
    held: Held,
    local_down: Vec<Scan>,
    wheel: Wheel,
    notice: Option<(String, Instant)>,
    end_armed: Option<Instant>,
    ending: bool,
    items: Vec<Item>,
    toolbar_h: i64,
    g: i64,
}

pub fn run(start: Start) -> Result<(), String> {
    let event_loop = EventLoop::<UserEvent>::with_user_event().build().map_err(|e| format!("cannot open a window: {e}"))?;
    let proxy = event_loop.create_proxy();
    let session = Session::new();
    let pic = session.picture();
    let mut app = App {
        proxy: proxy.clone(),
        window: None,
        surface: None,
        grab: None,
        pic,
        tx: None,
        redraw_pending: Arc::new(AtomicBool::new(false)),
        mode: Mode::View,
        host: String::new(),
        attached: false,
        fatal: None,
        view_only: true,
        grab_wanted: true,
        focused: false,
        scale: Scale::Fit,
        quality: 1,
        fullscreen: false,
        pointer: None,
        last_sent: None,
        held: Held::default(),
        local_down: Vec::new(),
        wheel: Wheel::default(),
        notice: None,
        end_armed: None,
        ending: false,
        items: Vec::new(),
        toolbar_h: 28,
        g: 1,
    };
    match start {
        Start::Error(e) => app.fatal = Some(e),
        Start::Connect(c) => {
            app.mode = c.mode;
            app.view_only = c.mode == Mode::View;
            app.host = c.host_label.clone();
            app.attached = true;
            app.tx = Some(spawn_net(proxy, session, Ok(c), app.quality, app.redraw_pending.clone()));
        }
        Start::Launch(link, entry) => {
            app.host = link.hub.host.clone();
            app.tx = Some(spawn_net(proxy, session, Err((link, entry)), app.quality, app.redraw_pending.clone()));
        }
    }
    event_loop.run_app(&mut app).map_err(|e| format!("the window failed: {e}"))
}

fn spawn_net(proxy: EventLoopProxy<UserEvent>, mut session: Session, target: Result<Connect, (LaunchUrl, HubEntry)>, quality: usize, pending: Arc<AtomicBool>) -> Sender<Out> {
    let (tx, rx) = channel();
    let (_, fps, q) = QUALITY[quality];
    let _ = tx.send(Out::Msg(input::quality(fps, q)));
    std::thread::spawn(move || {
        let result = (|| {
            let c = match target {
                Ok(c) => c,
                Err((link, entry)) => {
                    let c = launch::redeem(&link, &entry)?;
                    let _ = proxy.send_event(UserEvent::Attached { mode: c.mode, host: c.host_label.clone() });
                    c
                }
            };
            let mut ws = net::open_ws(&c)?;
            let p = proxy.clone();
            let pend = pending.clone();
            net::pump(&mut ws, &mut session, &rx, &mut || {
                if !pend.swap(true, Ordering::AcqRel) {
                    let _ = p.send_event(UserEvent::Redraw);
                }
            })
        })();
        let _ = proxy.send_event(UserEvent::NetEnded(result));
    });
    tx
}

impl App {
    fn window(&self) -> Option<&Rc<Window>> {
        self.window.as_ref()
    }

    fn redraw(&self) {
        if let Some(w) = self.window() {
            w.request_redraw();
        }
    }

    fn notify(&mut self, s: impl Into<String>) {
        self.notice = Some((s.into(), Instant::now()));
        self.redraw();
    }

    fn send(&self, m: String) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Out::Msg(m));
        }
    }

    fn live(&self) -> bool {
        let p = self.pic.lock().unwrap_or_else(|e| e.into_inner());
        matches!(p.state, State::Waiting | State::Live) && p.active.is_some()
    }

    fn can_input(&self) -> bool {
        self.attached && !self.view_only && !self.ending && self.focused && self.live()
    }

    /// Every held key and button back up on the remote.
    fn release_all(&mut self) {
        for m in self.held.release_all() {
            self.send(m);
        }
    }

    fn set_grab(&mut self, on: bool) {
        let Some(w) = self.window.clone() else { return };
        let Some(g) = self.grab.as_mut() else { return };
        if on {
            if g.state != GrabState::On {
                g.grab(&w);
            }
        } else {
            g.release();
        }
    }

    /// Grab whenever it is wanted and allowed; release otherwise.
    fn sync_grab(&mut self) {
        let want = self.grab_wanted && self.can_input();
        let have = self.grab.as_ref().map(|g| g.state == GrabState::On).unwrap_or(false);
        if want && !have {
            self.set_grab(true);
        } else if !want && self.grab.as_ref().map(|g| g.state != GrabState::Off).unwrap_or(false) {
            self.set_grab(false);
        }
    }

    fn picture_area(&self) -> (f64, f64, f64, f64) {
        let size = self.window().map(|w| w.inner_size()).unwrap_or_default();
        let top = self.toolbar_h as f64;
        (0.0, top, size.width as f64, (size.height as f64 - top).max(1.0))
    }

    fn placement(&self, p: &Picture) -> Placement {
        let (ax, ay, aw, ah) = self.picture_area();
        place(self.scale, ax, ay, aw, ah, p.fb_w, p.fb_h, self.pointer)
    }

    // ---------------------------------------------------------------- input

    fn on_key(&mut self, el: &ActiveEventLoop, s: Scan, down: bool) {
        if down {
            if !self.local_down.contains(&s) {
                self.local_down.push(s);
            }
        } else {
            self.local_down.retain(|k| *k != s);
        }
        let held = |a: Scan, b: Scan, d: &Vec<Scan>| d.contains(&a) || d.contains(&b);
        let ctrl = held(LCTRL, RCTRL, &self.local_down);
        let alt = held(LALT, RALT, &self.local_down);
        let shift = held(LSHIFT, RSHIFT, &self.local_down);
        if down {
            // G with Ctrl+Alt+Shift: capture or release the keyboard.
            if ctrl && alt && shift && s == (Scan { code: 0x22, ext: false }) {
                self.release_all();
                self.toggle_grab();
                return;
            }
            if ctrl && alt && !shift && s == (Scan { code: 0x4f, ext: true }) {
                self.act(el, Act::Sas);
                return;
            }
            if !ctrl && !alt && !shift && s == (Scan { code: 0x57, ext: false }) {
                self.act(el, Act::Fullscreen);
                return;
            }
        }
        if !self.can_input() {
            return;
        }
        if self.held.key(s, down) {
            self.send(input::key(s, down));
        }
    }

    fn toggle_grab(&mut self) {
        self.grab_wanted = !self.grab_wanted;
        self.sync_grab();
        let msg = match (self.grab_wanted, self.grab.as_ref().map(|g| g.state)) {
            (false, _) => format!("Keyboard released. {GRAB_HOTKEY} captures it again."),
            (true, Some(GrabState::Refused)) => "This desktop did not allow capturing system keys; use the toolbar buttons for those.".to_string(),
            (true, _) => format!("Keyboard captured. {GRAB_HOTKEY} releases it."),
        };
        self.notify(msg);
    }

    fn pointer_wire(&self, clamp: bool) -> Option<(u16, u16, u32)> {
        let (wx, wy) = self.pointer?;
        let p = self.pic.lock().unwrap_or_else(|e| e.into_inner());
        let active = p.active?;
        let at = self.placement(&p);
        let (px, py) = match at.to_picture(wx, wy, p.fb_w, p.fb_h) {
            Some(v) => v,
            None if clamp => (((wx - at.x) / at.scale).clamp(0.0, p.fb_w as f64 - 1.0), ((wy - at.y) / at.scale).clamp(0.0, p.fb_h as f64 - 1.0)),
            None => return None,
        };
        if wy < self.toolbar_h as f64 && !clamp {
            return None;
        }
        Some((to_wire(px, p.fb_w), to_wire(py, p.fb_h), active))
    }

    fn send_mouse(&mut self, force: bool) {
        if !self.can_input() {
            return;
        }
        let b = self.held.buttons;
        let Some((x, y, m)) = self.pointer_wire(b.l || b.r || b.m) else { return };
        if !force && self.last_sent == Some((x, y)) {
            return;
        }
        self.last_sent = Some((x, y));
        self.held.last = Some((x, y, m));
        self.send(input::mouse(x, y, b, m));
    }

    fn act(&mut self, el: &ActiveEventLoop, a: Act) {
        match a {
            Act::Scale => {
                self.scale = if self.scale == Scale::Fit { Scale::OneToOne } else { Scale::Fit };
            }
            Act::Monitor => {
                let next = {
                    let p = self.pic.lock().unwrap_or_else(|e| e.into_inner());
                    let ids: Vec<u32> = p.monitors.iter().map(|m| m.id).collect();
                    let i = ids.iter().position(|id| Some(*id) == p.active).map(|i| (i + 1) % ids.len().max(1)).unwrap_or(0);
                    ids.get(i).copied()
                };
                if let Some(id) = next {
                    self.release_all();
                    self.pic.lock().unwrap_or_else(|e| e.into_inner()).set_active(id);
                    self.send(input::set_monitor(id));
                    self.last_sent = None;
                }
            }
            Act::Quality => {
                self.quality = (self.quality + 1) % QUALITY.len();
                let (_, fps, q) = QUALITY[self.quality];
                self.send(input::quality(fps, q));
            }
            Act::ViewOnly => {
                if self.mode == Mode::View {
                    self.notify("This session was approved for viewing only.");
                } else {
                    if !self.view_only {
                        self.release_all();
                    }
                    self.view_only = !self.view_only;
                    self.sync_grab();
                }
            }
            Act::Sas => {
                if self.attached && !self.view_only && self.live() {
                    self.release_all();
                    self.send(input::sas());
                }
            }
            Act::Fullscreen => {
                self.fullscreen = !self.fullscreen;
                if let Some(w) = self.window() {
                    w.set_fullscreen(self.fullscreen.then_some(Fullscreen::Borderless(None)));
                }
            }
            Act::Grab => self.toggle_grab(),
            Act::End => {
                let ended = matches!(self.pic.lock().unwrap_or_else(|e| e.into_inner()).state, State::Ended(_));
                if ended || self.fatal.is_some() {
                    el.exit();
                } else if self.end_armed.map(|t| t.elapsed() < Duration::from_secs(4)).unwrap_or(false) {
                    self.release_all();
                    self.set_grab(false);
                    self.ending = true;
                    if let Some(tx) = &self.tx {
                        let _ = tx.send(Out::End);
                    }
                } else {
                    self.end_armed = Some(Instant::now());
                }
            }
        }
        self.redraw();
    }

    // ---------------------------------------------------------------- draw

    fn layout_toolbar(&mut self, width: i64) {
        let p = self.pic.lock().unwrap_or_else(|e| e.into_inner());
        let monitors = p.monitors.len();
        let active_idx = p.monitors.iter().position(|m| Some(m.id) == p.active).map(|i| i + 1).unwrap_or(0);
        let ended = matches!(p.state, State::Ended(_));
        drop(p);
        let live = !ended && self.attached && self.fatal.is_none();
        let control = self.mode == Mode::Control && live;
        let grabbed = self.grab.as_ref().map(|g| g.state == GrabState::On).unwrap_or(false);
        let mut specs: Vec<(String, Act, bool, bool)> = vec![
            (format!("Scale: {}", if self.scale == Scale::Fit { "fit" } else { "1:1" }), Act::Scale, false, true),
        ];
        if monitors > 1 {
            specs.push((format!("Screen {active_idx} of {monitors}"), Act::Monitor, false, live));
        }
        specs.push((format!("Quality: {}", QUALITY[self.quality].0), Act::Quality, false, live));
        specs.push(("View only".into(), Act::ViewOnly, self.view_only, control));
        specs.push(("Ctrl+Alt+Del".into(), Act::Sas, false, control && !self.view_only));
        specs.push((if self.fullscreen { "Exit full screen" } else { "Full screen" }.into(), Act::Fullscreen, self.fullscreen, true));
        specs.push((if grabbed { "Keys: captured" } else { "Keys: not captured" }.into(), Act::Grab, grabbed, control && !self.view_only));
        let end_label = if ended || self.fatal.is_some() {
            "Close"
        } else if self.end_armed.map(|t| t.elapsed() < Duration::from_secs(4)).unwrap_or(false) {
            "Click again to end"
        } else {
            "End session"
        };
        specs.push((end_label.into(), Act::End, false, true));
        // 2x text when the toolbar fits, else 1x.
        let status_w = 40;
        let total = |g: i64| specs.iter().map(|s| text_w(&s.0, g) + 16 * g).sum::<i64>() + status_w * g * 4;
        let sf = self.window().map(|w| w.scale_factor()).unwrap_or(1.0);
        self.g = if total(2) <= width || sf >= 1.75 { 2.max(sf.round() as i64) } else { 1.max(sf.round() as i64 - 1).max(1) };
        let g = self.g;
        self.toolbar_h = 8 * g + 14 * g;
        let mut x = width;
        let pad = 8 * g;
        let mut items = Vec::new();
        for (label, act, on, enabled) in specs.into_iter().rev() {
            let w = text_w(&label, g) + 2 * pad;
            x -= w + 4 * g;
            items.push(Item { x, w, label, act, on, enabled });
        }
        items.reverse();
        self.items = items;
    }

    fn draw(&mut self) {
        let Some(win) = self.window.clone() else { return };
        let size = win.inner_size();
        let (Some(w), Some(h)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height)) else { return };
        self.layout_toolbar(size.width as i64);
        let Some(surface) = self.surface.as_mut() else { return };
        if surface.resize(w, h).is_err() {
            return;
        }
        let Ok(mut buf) = surface.buffer_mut() else { return };
        let (bw, bh) = (size.width as usize, size.height as usize);
        let mut c = Canvas { px: &mut buf, w: bw, h: bh };
        c.fill(0, 0, bw as i64, bh as i64, draw::BG);
        let g = self.g;
        let th = self.toolbar_h;
        let pic = self.pic.clone();
        let p = pic.lock().unwrap_or_else(|e| e.into_inner());
        // Picture and cursor.
        let (ax, ay, aw, ah) = (0.0, th as f64, bw as f64, (bh as f64 - th as f64).max(1.0));
        let at = place(self.scale, ax, ay, aw, ah, p.fb_w, p.fb_h, self.pointer);
        let clip = (0, th, bw as i64, bh as i64);
        let ended = matches!(p.state, State::Ended(_));
        c.picture(&p.fb, p.fb_w, p.fb_h, at, clip, ended);
        if let (Some(cur), Some((x, y, true)), false) = (&p.cursor, p.cursor_pos, ended) {
            c.cursor(cur, x, y, at, clip);
        }
        // Toolbar.
        c.fill(0, 0, bw as i64, th, draw::CHROME);
        c.fill(0, th - 1, bw as i64, 1, draw::LINE);
        let ty = (th - 8 * g) / 2;
        let (state_label, tone) = match (&self.fatal, &p.state) {
            (Some(_), _) => ("Not connected".to_string(), draw::CRIT),
            (None, State::Connecting) => ("Connecting".into(), draw::BRAND),
            (None, State::Waiting) => ("Waiting for the screen".into(), draw::BRAND),
            (None, State::Live) => ("Live".into(), draw::OK),
            (None, State::Ended(_)) => ("Ended".into(), draw::DIM),
        };
        let mut x = 8 * g;
        c.fill(x, ty, 3 * g, 8 * g, tone);
        x += 6 * g;
        x += c.text(x, ty, &state_label, g, tone) + 12 * g;
        let first_item = self.items.first().map(|i| i.x).unwrap_or(bw as i64);
        if x + text_w(&self.host, g) < first_item - 8 * g {
            x += c.text(x, ty, &self.host, g, draw::INK) + 12 * g;
        }
        let mode_label = if self.mode == Mode::Control { "Control" } else { "View only" };
        if self.attached && x + text_w(mode_label, g) < first_item - 8 * g {
            c.text(x, ty, mode_label, g, if self.mode == Mode::Control { draw::WARN } else { draw::DIM });
        }
        for it in &self.items {
            let (bg, fg, edge) = match (it.enabled, it.on, it.act) {
                (false, _, _) => (draw::CHROME, draw::FAINT, draw::LINE),
                (true, _, Act::End) => (draw::CHROME, draw::CRIT, draw::CRIT),
                (true, true, _) => (draw::RAISED, draw::BRAND, draw::BRAND),
                (true, false, _) => (draw::RAISED, draw::INK, draw::LINE),
            };
            let by = 3 * g;
            let bh2 = th - 6 * g - 1;
            c.fill(it.x, by, it.w, bh2, bg);
            c.frame(it.x, by, it.w, bh2, 1.max(g / 2), edge);
            c.text(it.x + 8 * g, ty, &it.label, g, fg);
        }
        // The always-visible hint line and any notice, over the picture top.
        let grabbed = self.grab.as_ref().map(|gr| gr.state == GrabState::On).unwrap_or(false);
        let hint = if self.mode == Mode::View || self.view_only || !self.attached {
            None
        } else if grabbed {
            Some(format!("{GRAB_HOTKEY} releases the keyboard | {SAS_HOTKEY} sends Ctrl+Alt+Del | F11 full screen"))
        } else {
            Some(format!("{GRAB_HOTKEY} captures the keyboard | {SAS_HOTKEY} sends Ctrl+Alt+Del | F11 full screen"))
        };
        let notice = match (&self.fatal, &p.state) {
            (Some(e), _) => Some((e.clone(), draw::CRIT)),
            (None, State::Ended(why)) => Some((format!("The session has ended: {why}"), draw::DIM)),
            _ => self.notice.as_ref().filter(|(_, t)| t.elapsed() < NOTICE_FOR).map(|(s, _)| (s.clone(), draw::WARN)),
        };
        let sg = 1.max(g - 1);
        let mut y = th;
        if let Some((text, tone)) = notice {
            for line in wrap(&text, ((bw as i64 - 24 * sg) / (8 * sg)).max(10) as usize) {
                c.fill(0, y, bw as i64, 12 * sg, draw::CHROME);
                c.fill(0, y, 3 * sg, 12 * sg, tone);
                c.text(10 * sg, y + 2 * sg, &line, sg, draw::INK);
                y += 12 * sg;
            }
        }
        if let Some(hint) = hint {
            let hw = text_w(&hint, sg) + 12 * sg;
            let hx = bw as i64 - hw;
            let hy = bh as i64 - 12 * sg;
            c.fill(hx, hy, hw, 12 * sg, draw::CHROME);
            c.text(hx + 6 * sg, hy + 2 * sg, &hint, sg, draw::DIM);
        }
        drop(p);
        let _ = buf.present();
    }
}

fn wrap(s: &str, cols: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut line = String::new();
    for word in s.split(' ') {
        if !line.is_empty() && line.chars().count() + 1 + word.chars().count() > cols {
            out.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        out.push(line);
    }
    out
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, el: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let title = if self.host.is_empty() { "OmniNull screen".to_string() } else { format!("{} | OmniNull screen", self.host) };
        let attrs = Window::default_attributes()
            .with_title(title)
            .with_inner_size(LogicalSize::new(1280.0, 800.0))
            .with_min_inner_size(LogicalSize::new(480.0, 300.0));
        let win = match el.create_window(attrs) {
            Ok(w) => Rc::new(w),
            Err(e) => {
                eprintln!("ominull-screen: cannot open a window: {e}");
                el.exit();
                return;
            }
        };
        let ctx = softbuffer::Context::new(win.clone()).and_then(|ctx| softbuffer::Surface::new(&ctx, win.clone()));
        match ctx {
            Ok(s) => self.surface = Some(s),
            Err(e) => {
                eprintln!("ominull-screen: cannot draw to the window: {e}");
                el.exit();
                return;
            }
        }
        self.grab = Some(Grab::new(&win));
        #[cfg(windows)]
        {
            let p = self.proxy.clone();
            if let Ok(mut s) = crate::grab::WINDOWS_KEY_SINK.lock() {
                *s = Some(Box::new(move |code, ext, down| {
                    let _ = p.send_event(UserEvent::HookKey { code, ext, down });
                }));
            }
        }
        self.window = Some(win);
        self.redraw();
    }

    fn user_event(&mut self, el: &ActiveEventLoop, ev: UserEvent) {
        match ev {
            UserEvent::Redraw => self.redraw_pending.store(false, Ordering::Release),
            UserEvent::Attached { mode, host } => {
                self.mode = mode;
                self.view_only = mode == Mode::View;
                self.host = host;
                self.attached = true;
                if let Some(w) = self.window() {
                    w.set_title(&format!("{} | OmniNull screen", self.host));
                }
            }
            UserEvent::NetEnded(r) => {
                self.release_all();
                self.set_grab(false);
                if self.ending {
                    el.exit();
                    return;
                }
                if let Err(e) = r {
                    self.fatal = Some(e);
                }
            }
            UserEvent::HookKey { code, ext, down } => {
                if self.grab.as_ref().map(|g| g.state == GrabState::On).unwrap_or(false) {
                    self.on_key(el, Scan { code, ext }, down);
                }
            }
        }
        let sas = std::mem::take(&mut self.pic.lock().unwrap_or_else(|e| e.into_inner()).sas_unavailable);
        if sas {
            let host = self.host.clone();
            self.notify(format!("Ctrl+Alt+Del is turned off by policy on {host}, so it wasn't sent."));
        }
        self.sync_grab();
        self.redraw();
    }

    fn window_event(&mut self, el: &ActiveEventLoop, _id: WindowId, ev: WindowEvent) {
        match ev {
            WindowEvent::CloseRequested => {
                self.release_all();
                self.set_grab(false);
                if let Some(tx) = self.tx.take() {
                    let _ = tx.send(Out::Detach);
                }
                el.exit();
            }
            WindowEvent::RedrawRequested => self.draw(),
            WindowEvent::Resized(_) | WindowEvent::ScaleFactorChanged { .. } => self.redraw(),
            WindowEvent::Focused(f) => {
                self.focused = f;
                if !f {
                    self.release_all();
                    self.local_down.clear();
                }
                self.sync_grab();
                self.redraw();
            }
            WindowEvent::KeyboardInput { event, is_synthetic, .. } => {
                // Under the Windows hook the keys arrive as HookKey instead.
                let hooked = cfg!(windows) && self.grab.as_ref().map(|g| g.state == GrabState::On).unwrap_or(false);
                if is_synthetic || hooked {
                    return;
                }
                if let PhysicalKey::Code(code) = event.physical_key {
                    if let Some(s) = keymap::from_keycode(code) {
                        self.on_key(el, s, event.state == ElementState::Pressed);
                    } else if code == KeyCode::F11 {
                        self.act(el, Act::Fullscreen);
                    }
                }
            }
            WindowEvent::CursorMoved { position: PhysicalPosition { x, y }, .. } => {
                self.pointer = Some((x, y));
                self.send_mouse(false);
                if self.scale == Scale::OneToOne {
                    self.redraw();
                }
            }
            WindowEvent::CursorLeft { .. } => {
                if !(self.held.buttons.l || self.held.buttons.r || self.held.buttons.m) {
                    self.pointer = None;
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let pressed = state == ElementState::Pressed;
                let in_bar = self.pointer.map(|(_, y)| y < self.toolbar_h as f64).unwrap_or(false);
                let any = self.held.buttons.l || self.held.buttons.r || self.held.buttons.m;
                if in_bar && !any {
                    if pressed && button == MouseButton::Left {
                        let x = self.pointer.map(|p| p.0 as i64).unwrap_or(-1);
                        if let Some(a) = self.items.iter().find(|i| i.enabled && x >= i.x && x < i.x + i.w).map(|i| i.act) {
                            self.act(el, a);
                        }
                    }
                    return;
                }
                let can = self.can_input();
                let b = &mut self.held.buttons;
                let slot = match button {
                    MouseButton::Left => &mut b.l,
                    MouseButton::Right => &mut b.r,
                    MouseButton::Middle => &mut b.m,
                    _ => return,
                };
                if *slot == pressed {
                    return;
                }
                if !can {
                    *b = RawButtons::default();
                    return;
                }
                *slot = pressed;
                self.send_mouse(true);
            }
            WindowEvent::MouseWheel { delta, .. } => {
                if !self.can_input() || self.pointer_wire(false).is_none() {
                    return;
                }
                let d = match delta {
                    MouseScrollDelta::LineDelta(x, y) => self.wheel.lines(x, y),
                    MouseScrollDelta::PixelDelta(p) => self.wheel.pixels(p.x, p.y),
                };
                if let (Some((dx, dy)), Some((_, _, m))) = (d, self.pointer_wire(false)) {
                    self.send(input::wheel(dx, dy, m));
                }
            }
            _ => {}
        }
    }

    fn about_to_wait(&mut self, el: &ActiveEventLoop) {
        // Wake for timed things: the notice fading, the End confirmation.
        let mut next: Option<Instant> = None;
        if let Some((_, t)) = &self.notice {
            if t.elapsed() < NOTICE_FOR {
                next = Some(*t + NOTICE_FOR);
            } else {
                self.notice = None;
                self.redraw();
            }
        }
        if let Some(t) = self.end_armed {
            if t.elapsed() < Duration::from_secs(4) {
                let at = t + Duration::from_secs(4);
                next = Some(next.map_or(at, |n| n.min(at)));
            } else {
                self.end_armed = None;
                self.redraw();
            }
        }
        el.set_control_flow(next.map_or(ControlFlow::Wait, ControlFlow::WaitUntil));
    }
}
