//! The Windows [`ScreenBackend`]: DXGI Desktop Duplication (primary, incl. the
//! secure desktop as LocalSystem) with a GDI BitBlt fallback, JPEG via the pure
//! `jpeg-encoder`, cursor shapes from `GetFramePointerShape`, and the input/
//! desktop/banner/SAS pieces from the sibling modules (§6.2-§6.4).
//!
//! Recoverable DXGI errors (ACCESS_LOST on a desktop switch, WAIT_TIMEOUT on no
//! new frame) drop the duplication and are retried on the next `capture()`, as
//! §6.2 requires — they are normal, not fatal.

use std::collections::{HashMap, HashSet};
use std::mem::size_of;

use jpeg_encoder::{ColorType, Encoder};
use windows::core::Interface;
use windows::Win32::Foundation::{RECT};
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_11_0,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Resource, ID3D11Texture2D,
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_FLAG, D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ,
    D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_B8G8R8A8_UNORM;
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIFactory1, IDXGIOutput1, IDXGIOutputDuplication, IDXGIResource,
    DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
    DXGI_OUTDUPL_POINTER_SHAPE_INFO, DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR,
    DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR, DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME,
};

use screen_wire::input::InputEvent;
use screen_wire::proto::{
    CURSOR_FORMAT_COLOR_BGRA, CURSOR_FORMAT_MASKED_COLOR, CURSOR_FORMAT_MONO,
};

use std::time::Instant;

use crate::backend::{
    CaptureFrame, Consent, CursorPos, CursorShape, DesktopState, Monitor, ScreenBackend, Tile,
    TILE_SIZE,
};
use crate::stall::{CapturePath, DxgiStall, SwitchReason};

use super::banner::Banner;
use super::desktop::DesktopFollower;
use super::inject::Injector;

/// One monitor plus where to find its adapter/output for duplication.
struct MonEntry {
    monitor: Monitor,
    adapter: u32,
    output: u32,
}

pub struct WindowsBackend {
    factory: IDXGIFactory1,
    entries: Vec<MonEntry>,
    active: usize,
    // Current duplication for the active monitor (re-acquired on ACCESS_LOST).
    device: Option<ID3D11Device>,
    context: Option<ID3D11DeviceContext>,
    dup: Option<IDXGIOutputDuplication>,
    staging: Option<ID3D11Texture2D>,
    staging_w: u32,
    staging_h: u32,
    use_gdi: bool,
    keyframe_pending: bool,
    quality: u8,
    injector: Injector,
    desktop: DesktopFollower,
    banner: Banner,
    pending_desktop: Option<DesktopState>,
    // GDI fallback per-tile hashes, to send only changed tiles.
    gdi_hashes: HashMap<(u16, u16), u64>,
    // Diagnostics (§6/§9): log the capture path and the first frame once each.
    logged_path: bool,
    logged_first_frame: bool,
    logged_bridge: bool,
    // DXGI stall detection (§6.2): DuplicateOutput can succeed on a virtual GPU
    // yet never deliver a frame; this bridges/switches to GDI so the viewer still
    // gets an image. Monotonic clock for the current duplication generation.
    clock: Instant,
    stall: DxgiStall,
}

impl WindowsBackend {
    pub fn new(control: bool, operator: Option<&str>) -> windows::core::Result<Self> {
        let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1()? };
        let entries = enumerate_monitors(&factory);
        Ok(WindowsBackend {
            factory,
            entries,
            active: 0,
            device: None,
            context: None,
            dup: None,
            staging: None,
            staging_w: 0,
            staging_h: 0,
            use_gdi: false,
            keyframe_pending: true,
            quality: 60,
            injector: Injector::new(),
            desktop: DesktopFollower::new(),
            banner: Banner::start(control, operator),
            pending_desktop: None,
            gdi_hashes: HashMap::new(),
            logged_path: false,
            logged_first_frame: false,
            logged_bridge: false,
            clock: Instant::now(),
            stall: DxgiStall::default(),
        })
    }

    /// Record the chosen capture path once (§6/§9 diagnostics).
    fn log_path(&mut self, msg: &str) {
        if !self.logged_path {
            self.logged_path = true;
            crate::diag::log(msg);
        }
    }

    /// Milliseconds since this duplication generation started (for the stall
    /// state machine).
    fn now_ms(&self) -> u64 {
        self.clock.elapsed().as_millis() as u64
    }

    /// Start a fresh duplication generation (session start, desktop switch,
    /// monitor change, mode change/ACCESS_LOST): reset the clock and give DXGI a
    /// clean chance before bridging/switching to GDI again.
    fn reinit_generation(&mut self) {
        self.clock = Instant::now();
        self.stall.reinit(0);
    }

    fn active_monitor(&self) -> Monitor {
        self.entries
            .get(self.active)
            .map(|e| e.monitor)
            .unwrap_or(Monitor { id: 0, x: 0, y: 0, w: 1920, h: 1080, primary: true })
    }

    /// (Re)build the DXGI duplication for the active monitor. On failure, fall
    /// back to GDI for this session.
    fn ensure_dup(&mut self) -> bool {
        if self.use_gdi {
            return false;
        }
        if self.dup.is_some() {
            return true;
        }
        let entry = match self.entries.get(self.active) {
            Some(e) => e,
            None => return false,
        };
        let adapter = match unsafe { self.factory.EnumAdapters1(entry.adapter) } {
            Ok(a) => a,
            Err(e) => {
                self.use_gdi = true;
                self.log_path(&format!("capture path: GDI fallback (EnumAdapters1 failed: {e:?})"));
                return false;
            }
        };
        let adapter_name = unsafe { adapter.GetDesc1() }
            .map(|d| wstr_to_string(&d.Description))
            .unwrap_or_else(|_| "?".into());
        let levels = [D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0];
        let mut device: Option<ID3D11Device> = None;
        let mut context: Option<ID3D11DeviceContext> = None;
        let created = unsafe {
            D3D11CreateDevice(
                &adapter.cast::<windows::Win32::Graphics::Dxgi::IDXGIAdapter>().unwrap(),
                D3D_DRIVER_TYPE_UNKNOWN,
                Default::default(),
                D3D11_CREATE_DEVICE_FLAG(0),
                Some(&levels),
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
        };
        if created.is_err() || device.is_none() || context.is_none() {
            self.use_gdi = true;
            self.log_path(&format!("capture path: GDI fallback (D3D11CreateDevice failed on adapter '{adapter_name}')"));
            return false;
        }
        let device = device.unwrap();
        let output = match unsafe { adapter.EnumOutputs(entry.output) } {
            Ok(o) => o,
            Err(e) => {
                self.use_gdi = true;
                self.log_path(&format!("capture path: GDI fallback (EnumOutputs failed: {e:?})"));
                return false;
            }
        };
        let output_name = unsafe { output.GetDesc() }
            .map(|d| wstr_to_string(&d.DeviceName))
            .unwrap_or_else(|_| "?".into());
        let output1: IDXGIOutput1 = match output.cast() {
            Ok(o) => o,
            Err(e) => {
                self.use_gdi = true;
                self.log_path(&format!("capture path: GDI fallback (IDXGIOutput1 cast failed: {e:?})"));
                return false;
            }
        };
        match unsafe { output1.DuplicateOutput(&device) } {
            Ok(dup) => {
                self.context = Some(context.unwrap());
                self.dup = Some(dup);
                self.device = Some(device);
                self.log_path(&format!("capture path: DXGI duplication (adapter '{adapter_name}', output '{output_name}')"));
                true
            }
            Err(e) => {
                // Hybrid-GPU / non-DWM / disconnected: GDI fallback (§6.2).
                self.use_gdi = true;
                self.log_path(&format!("capture path: GDI fallback (DuplicateOutput failed on adapter '{adapter_name}': {e:?})"));
                false
            }
        }
    }

    fn ensure_staging(&mut self, w: u32, h: u32) -> Option<ID3D11Texture2D> {
        if self.staging.is_some() && self.staging_w == w && self.staging_h == h {
            return self.staging.clone();
        }
        let device = self.device.as_ref()?;
        let desc = D3D11_TEXTURE2D_DESC {
            Width: w,
            Height: h,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut tex: Option<ID3D11Texture2D> = None;
        unsafe {
            device.CreateTexture2D(&desc, None, Some(&mut tex)).ok()?;
        }
        self.staging = tex.clone();
        self.staging_w = w;
        self.staging_h = h;
        tex
    }

    /// One DXGI acquire+encode, assuming `ensure_dup` already succeeded. Returns
    /// the frame and whether a DXGI frame was actually acquired this tick (used
    /// by the stall detector: a tick that only times out is not an acquire).
    fn dxgi_capture_inner(&mut self, mut frame: CaptureFrame) -> (CaptureFrame, bool) {
        let dup = self.dup.clone().unwrap();
        let context = self.context.clone().unwrap();

        let mut fi = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut res: Option<IDXGIResource> = None;
        match unsafe { dup.AcquireNextFrame(15, &mut fi, &mut res) } {
            Ok(()) => {}
            Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return (frame, false),
            Err(e) if e.code() == DXGI_ERROR_ACCESS_LOST => {
                // A desktop switch / mode change: drop the duplication and give
                // DXGI a fresh generation (bridging to GDI during the gap, §6.2).
                self.dup = None;
                self.reinit_generation();
                return (frame, false);
            }
            Err(_) => {
                self.dup = None;
                return (frame, false);
            }
        }

        // Cursor shape + position (§4.1). The cursor is never in the image.
        if fi.PointerShapeBufferSize > 0 {
            frame.cursor_shape = read_pointer_shape(&dup, fi.PointerShapeBufferSize);
        }
        if fi.LastMouseUpdateTime != 0 {
            let p = fi.PointerPosition;
            frame.cursor_pos = Some(CursorPos { x: p.Position.x, y: p.Position.y, visible: p.Visible.as_bool() });
        }

        let want_full = self.keyframe_pending;
        if fi.AccumulatedFrames > 0 || want_full {
            if let Some(resource) = res.as_ref() {
                if let Ok(src) = resource.cast::<ID3D11Texture2D>() {
                    let mut sdesc = D3D11_TEXTURE2D_DESC::default();
                    unsafe { src.GetDesc(&mut sdesc) };
                    let (w, h) = (sdesc.Width, sdesc.Height);
                    if let Some(staging) = self.ensure_staging(w, h) {
                        let coords: Vec<(u32, u32)> = if want_full {
                            full_tile_coords(w, h)
                        } else {
                            dirty_tile_coords(&dup, w, h)
                        };
                        unsafe {
                            let src_res: ID3D11Resource = src.cast().unwrap();
                            let dst_res: ID3D11Resource = staging.cast().unwrap();
                            context.CopyResource(&dst_res, &src_res);
                            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                            if context.Map(&dst_res, 0, D3D11_MAP_READ, 0, Some(&mut mapped)).is_ok() {
                                let base = mapped.pData as *const u8;
                                let pitch = mapped.RowPitch as usize;
                                for (tx, ty) in coords {
                                    let tw = (w - tx).min(TILE_SIZE);
                                    let th = (h - ty).min(TILE_SIZE);
                                    let bgra = extract_tile_bgra(base, pitch, tx, ty, tw, th);
                                    if let Some(jpeg) = encode_jpeg_bgra(&bgra, tw as u16, th as u16, self.quality) {
                                        frame.tiles.push(Tile {
                                            x: tx as u16,
                                            y: ty as u16,
                                            w: tw as u16,
                                            h: th as u16,
                                            keyframe: want_full,
                                            jpeg,
                                        });
                                    }
                                }
                                context.Unmap(&dst_res, 0);
                            }
                        }
                        if want_full {
                            self.keyframe_pending = false;
                        }
                    }
                }
            }
        }

        unsafe {
            let _ = dup.ReleaseFrame();
        }
        (frame, true)
    }

    /// Drain and log a one-shot switch-to-GDI reason (§6.2). The structural
    /// `InitFailed` case is already described in detail by `ensure_dup`'s
    /// `log_path`, so only the "no frames" stall switch is logged here.
    fn log_switch_reason(&mut self) {
        if let Some(reason) = self.stall.take_switch_reason() {
            if reason == SwitchReason::NoFrames {
                crate::diag::log(
                    "capture path: switched to GDI (DXGI initialized but delivered no frame within the stall window)",
                );
            }
        }
    }

    /// GDI BitBlt fallback (§6.2): whole active-monitor grab, per-tile hash diff.
    fn gdi_capture(&mut self, mut frame: CaptureFrame) -> CaptureFrame {
        use windows::Win32::Graphics::Gdi::{
            BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject, GetDC,
            GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
            DIB_RGB_COLORS, HGDIOBJ, SRCCOPY,
        };
        let mon = self.active_monitor();
        let (w, h) = (mon.w, mon.h);
        if w == 0 || h == 0 {
            return frame;
        }
        let full = self.keyframe_pending;
        unsafe {
            let screen = GetDC(None);
            let mem = CreateCompatibleDC(Some(screen));
            let bmp = CreateCompatibleBitmap(screen, w as i32, h as i32);
            let old = SelectObject(mem, HGDIOBJ(bmp.0));
            let _ = BitBlt(mem, 0, 0, w as i32, h as i32, Some(screen), mon.x, mon.y, SRCCOPY);

            let mut bi = BITMAPINFO::default();
            bi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
            bi.bmiHeader.biWidth = w as i32;
            bi.bmiHeader.biHeight = -(h as i32); // top-down BGRA
            bi.bmiHeader.biPlanes = 1;
            bi.bmiHeader.biBitCount = 32;
            bi.bmiHeader.biCompression = BI_RGB.0;

            let mut buf = vec![0u8; (w * h * 4) as usize];
            let got = GetDIBits(
                mem,
                bmp,
                0,
                h,
                Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
                &mut bi,
                DIB_RGB_COLORS,
            );
            SelectObject(mem, old);
            let _ = DeleteObject(HGDIOBJ(bmp.0));
            let _ = DeleteDC(mem);
            ReleaseDC(None, screen);

            if got != 0 {
                let pitch = (w * 4) as usize;
                for (tx, ty) in full_tile_coords(w, h) {
                    let tw = (w - tx).min(TILE_SIZE);
                    let th = (h - ty).min(TILE_SIZE);
                    let bgra = extract_tile_bgra(buf.as_ptr(), pitch, tx, ty, tw, th);
                    let hash = fnv1a(&bgra);
                    let key = (tx as u16, ty as u16);
                    if full || self.gdi_hashes.get(&key) != Some(&hash) {
                        self.gdi_hashes.insert(key, hash);
                        if let Some(jpeg) = encode_jpeg_bgra(&bgra, tw as u16, th as u16, self.quality) {
                            frame.tiles.push(Tile {
                                x: tx as u16,
                                y: ty as u16,
                                w: tw as u16,
                                h: th as u16,
                                keyframe: full,
                                jpeg,
                            });
                        }
                    }
                }
                if full {
                    self.keyframe_pending = false;
                }
            }
        }
        frame
    }
}

impl ScreenBackend for WindowsBackend {
    fn monitors(&self) -> Vec<Monitor> {
        self.entries.iter().map(|e| e.monitor).collect()
    }

    fn set_active_monitor(&mut self, index: u32) -> bool {
        if (index as usize) < self.entries.len() {
            self.active = index as usize;
            self.dup = None; // re-acquire for the new output
            self.staging = None;
            self.gdi_hashes.clear();
            self.keyframe_pending = true;
            self.reinit_generation(); // give DXGI a fresh chance on the new output
            true
        } else {
            false
        }
    }

    fn set_quality(&mut self, jpeg_q: u8) {
        self.quality = jpeg_q.clamp(1, 100);
    }

    fn request_keyframe(&mut self) {
        self.keyframe_pending = true;
    }

    fn capture(&mut self) -> CaptureFrame {
        let mut frame = CaptureFrame::default();
        if let Some(ds) = self.pending_desktop.take() {
            frame.desktop_change = Some(ds);
        }

        // §6.2 stall detection: DuplicateOutput can succeed on a virtual GPU yet
        // never deliver a frame. Decide DXGI / GDI-bridge / GDI for this tick.
        let path = self.stall.decide(self.now_ms());
        self.log_switch_reason();

        let frame = match path {
            CapturePath::Gdi => self.gdi_capture(frame),
            CapturePath::Dxgi | CapturePath::GdiBridge => {
                if !self.ensure_dup() {
                    // Duplication failed to initialize: GDI for this generation.
                    self.stall.force_gdi();
                    self.log_switch_reason();
                    self.gdi_capture(frame)
                } else {
                    let (frame, acquired) = self.dxgi_capture_inner(frame);
                    if acquired {
                        self.stall.on_frame();
                        frame
                    } else if path == CapturePath::GdiBridge {
                        // DXGI is stalled but still being probed; serve the
                        // keyframe via GDI so the viewer gets an initial image.
                        if !self.logged_bridge {
                            self.logged_bridge = true;
                            crate::diag::log(
                                "capture path: GDI bridge (DXGI stalled; serving an image via GDI while still probing DXGI)",
                            );
                        }
                        self.gdi_capture(frame)
                    } else {
                        frame
                    }
                }
            }
        };

        if !frame.tiles.is_empty() && !self.logged_first_frame {
            self.logged_first_frame = true;
            let keyframe = frame.tiles.iter().any(|t| t.keyframe);
            crate::diag::log(&format!("first frame captured: {} tile(s), keyframe={keyframe}", frame.tiles.len()));
        }
        frame
    }

    fn inject(&mut self, ev: &InputEvent) {
        let mon = self.active_monitor();
        self.injector.inject(ev, &mon);
    }

    fn release_all_keys(&mut self) {
        self.injector.release_all();
    }

    fn follow_input_desktop(&mut self) {
        if let Some(state) = self.desktop.follow() {
            crate::diag::log(&format!("desktop switch: {} signed_in={}", state.name, state.signed_in));
            // A desktop switch invalidates duplication and the banner window.
            self.dup = None;
            self.staging = None;
            self.keyframe_pending = true;
            self.reinit_generation(); // retry DXGI on the new desktop before bridging
            self.banner.note_desktop_switch();
            self.pending_desktop = Some(state);
        }
    }

    fn request_consent(&mut self, control: bool, operator: Option<&str>) -> Consent {
        let allowed = self.banner.request_consent(control, operator);
        crate::diag::log(&format!("consent prompt (control={control}): {}", if allowed { "allowed" } else { "denied" }));
        if allowed {
            Consent::Allowed
        } else {
            Consent::Denied
        }
    }

    fn desktop_state(&mut self) -> DesktopState {
        self.desktop.state()
    }
}

// --- free helpers -----------------------------------------------------------

/// A fixed-size wide (UTF-16) Win32 name field (NUL-padded) as a Rust String.
fn wstr_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn enumerate_monitors(factory: &IDXGIFactory1) -> Vec<MonEntry> {
    let mut out = Vec::new();
    let mut ai = 0u32;
    while let Ok(adapter) = unsafe { factory.EnumAdapters1(ai) } {
        let mut oi = 0u32;
        loop {
            match unsafe { adapter.EnumOutputs(oi) } {
                Ok(output) => {
                    if let Ok(desc) = unsafe { output.GetDesc() } {
                        if desc.AttachedToDesktop.as_bool() {
                            let r = desc.DesktopCoordinates;
                            out.push(MonEntry {
                                monitor: Monitor {
                                    id: out.len() as u32,
                                    x: r.left,
                                    y: r.top,
                                    w: (r.right - r.left).max(0) as u32,
                                    h: (r.bottom - r.top).max(0) as u32,
                                    primary: r.left == 0 && r.top == 0,
                                },
                                adapter: ai,
                                output: oi,
                            });
                        }
                    }
                    oi += 1;
                }
                Err(_) => break,
            }
            if out.len() >= 4 {
                break;
            }
        }
        ai += 1;
        if out.len() >= 4 {
            break;
        }
    }
    out
}

fn full_tile_coords(w: u32, h: u32) -> Vec<(u32, u32)> {
    let mut v = Vec::new();
    let mut y = 0;
    while y < h {
        let mut x = 0;
        while x < w {
            v.push((x, y));
            x += TILE_SIZE;
        }
        y += TILE_SIZE;
    }
    v
}

fn dirty_tile_coords(dup: &IDXGIOutputDuplication, w: u32, h: u32) -> Vec<(u32, u32)> {
    let mut required = 0u32;
    unsafe {
        let _ = dup.GetFrameDirtyRects(0, std::ptr::null_mut(), &mut required);
    }
    let count = (required as usize / size_of::<RECT>()).max(1);
    let mut rects = vec![RECT::default(); count];
    let mut got = 0u32;
    let ok = unsafe {
        dup.GetFrameDirtyRects((rects.len() * size_of::<RECT>()) as u32, rects.as_mut_ptr(), &mut got)
    };
    if ok.is_err() {
        // Could not read dirty rects: safest is a full frame.
        return full_tile_coords(w, h);
    }
    let n = got as usize / size_of::<RECT>();
    let mut tiles: HashSet<(u32, u32)> = HashSet::new();
    for r in rects.iter().take(n) {
        let x0 = snap_down(r.left.max(0) as u32);
        let y0 = snap_down(r.top.max(0) as u32);
        let x1 = (r.right.max(0) as u32).min(w);
        let y1 = (r.bottom.max(0) as u32).min(h);
        let mut y = y0;
        while y < y1 {
            let mut x = x0;
            while x < x1 {
                tiles.insert((x, y));
                x += TILE_SIZE;
            }
            y += TILE_SIZE;
        }
    }
    tiles.into_iter().collect()
}

fn snap_down(v: u32) -> u32 {
    v - (v % TILE_SIZE)
}

unsafe fn extract_tile_bgra(base: *const u8, pitch: usize, x: u32, y: u32, tw: u32, th: u32) -> Vec<u8> {
    let row_bytes = (tw * 4) as usize;
    let mut out = vec![0u8; row_bytes * th as usize];
    for row in 0..th {
        let src = base.add((y + row) as usize * pitch + (x as usize) * 4);
        let dst = out.as_mut_ptr().add(row as usize * row_bytes);
        std::ptr::copy_nonoverlapping(src, dst, row_bytes);
    }
    out
}

fn encode_jpeg_bgra(bgra: &[u8], w: u16, h: u16, quality: u8) -> Option<Vec<u8>> {
    if w == 0 || h == 0 || bgra.len() != (w as usize) * (h as usize) * 4 {
        return None;
    }
    let mut buf = Vec::new();
    let encoder = Encoder::new(&mut buf, quality);
    encoder.encode(bgra, w, h, ColorType::Bgra).ok()?;
    Some(buf)
}

fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// Convert a DXGI pointer shape to the wire `CursorShape` (§4.1), repacking to
/// tight rows. Bounds dims to 256; returns None on anything unexpected.
fn read_pointer_shape(dup: &IDXGIOutputDuplication, buf_size: u32) -> Option<CursorShape> {
    let mut buf = vec![0u8; buf_size as usize];
    let mut got = 0u32;
    let mut info = DXGI_OUTDUPL_POINTER_SHAPE_INFO::default();
    unsafe {
        dup.GetFramePointerShape(buf.len() as u32, buf.as_mut_ptr() as *mut core::ffi::c_void, &mut got, &mut info).ok()?;
    }
    let pitch = info.Pitch as usize;
    let shape_type = info.Type;
    if shape_type == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR.0 as u32
        || shape_type == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR.0 as u32
    {
        let w = info.Width as usize;
        let h = info.Height as usize;
        if w == 0 || h == 0 || w > 256 || h > 256 {
            return None;
        }
        let tight = repack(&buf, pitch, w * 4, h)?;
        let format = if shape_type == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR.0 as u32 {
            CURSOR_FORMAT_COLOR_BGRA
        } else {
            CURSOR_FORMAT_MASKED_COLOR
        };
        Some(CursorShape {
            w: w as u16,
            h: h as u16,
            hotspot_x: info.HotSpot.x.max(0) as u16,
            hotspot_y: info.HotSpot.y.max(0) as u16,
            format,
            pixels: tight,
        })
    } else if shape_type == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME.0 as u32 {
        // Monochrome: AND mask then XOR mask; DXGI Height is the combined 2*h.
        let w = info.Width as usize;
        let combined_h = info.Height as usize;
        let actual_h = combined_h / 2;
        if w == 0 || actual_h == 0 || w > 256 || actual_h > 256 {
            return None;
        }
        let tight_pitch = (w + 7) / 8;
        let tight = repack(&buf, pitch, tight_pitch, combined_h)?;
        Some(CursorShape {
            w: w as u16,
            h: actual_h as u16,
            hotspot_x: info.HotSpot.x.max(0) as u16,
            hotspot_y: info.HotSpot.y.max(0) as u16,
            format: CURSOR_FORMAT_MONO,
            pixels: tight,
        })
    } else {
        None
    }
}

/// Repack `rows` rows of `tight_pitch` bytes from a `src_pitch`-strided buffer.
fn repack(buf: &[u8], src_pitch: usize, tight_pitch: usize, rows: usize) -> Option<Vec<u8>> {
    if src_pitch < tight_pitch || buf.len() < src_pitch * rows {
        return None;
    }
    let mut out = vec![0u8; tight_pitch * rows];
    for r in 0..rows {
        out[r * tight_pitch..(r + 1) * tight_pitch]
            .copy_from_slice(&buf[r * src_pitch..r * src_pitch + tight_pitch]);
    }
    Some(out)
}
