//! Coordinates: window pixels <-> monitor picture pixels <-> the 0..65535
//! wire units (REMOTE_SCREEN.md §4.2), the wheel convention, and the
//! screenshot scale `ctl` uses (§8.2).

use screen_wire::WHEEL_LIMIT;

/// Monitor pixel -> 0..65535 across that monitor's picture. The helper maps
/// back with `px = x * w / 65536`, so this lands on the same pixel.
pub fn to_wire(px: f64, size: u32) -> u16 {
    if size == 0 || !px.is_finite() {
        return 0;
    }
    let p = px.floor().clamp(0.0, (size - 1) as f64);
    (((p + 0.5) * 65536.0 / size as f64).floor() as i64).clamp(0, 65535) as u16
}

/// What the helper computes from a wire coordinate (for tests).
pub fn from_wire(v: u16, size: u32) -> u32 {
    (v as u64 * size as u64 / 65536) as u32
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scale {
    Fit,
    OneToOne,
}

/// Where the picture sits inside the window's picture area.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Placement {
    /// Top-left of the picture in window pixels (may be negative in 1:1).
    pub x: f64,
    pub y: f64,
    /// Window pixels per picture pixel.
    pub scale: f64,
}

/// Places a `pic_w` x `pic_h` picture in the area (`ax`,`ay`,`aw`,`ah`).
/// Fit keeps the aspect ratio and centers. 1:1 centers a picture that fits;
/// one that does not pans with the pointer (`pointer` in window pixels), so
/// moving to an edge of the window shows that edge of the remote screen.
#[allow(clippy::too_many_arguments)]
pub fn place(scale: Scale, ax: f64, ay: f64, aw: f64, ah: f64, pic_w: u32, pic_h: u32, pointer: Option<(f64, f64)>) -> Placement {
    let (pw, ph) = (pic_w.max(1) as f64, pic_h.max(1) as f64);
    match scale {
        Scale::Fit => {
            let s = (aw / pw).min(ah / ph).max(1e-6);
            Placement { x: ax + ((aw - pw * s) / 2.0).floor(), y: ay + ((ah - ph * s) / 2.0).floor(), scale: s }
        }
        Scale::OneToOne => {
            let axis = |a0: f64, len: f64, pic: f64, p: Option<f64>| {
                if pic <= len {
                    a0 + ((len - pic) / 2.0).floor()
                } else {
                    let f = p.map(|p| ((p - a0) / len).clamp(0.0, 1.0)).unwrap_or(0.0);
                    a0 - ((pic - len) * f).round()
                }
            };
            Placement {
                x: axis(ax, aw, pw, pointer.map(|p| p.0)),
                y: axis(ay, ah, ph, pointer.map(|p| p.1)),
                scale: 1.0,
            }
        }
    }
}

impl Placement {
    /// Window pixel -> picture pixel, or None outside the picture.
    pub fn to_picture(&self, wx: f64, wy: f64, pic_w: u32, pic_h: u32) -> Option<(f64, f64)> {
        let px = (wx - self.x) / self.scale;
        let py = (wy - self.y) / self.scale;
        (px >= 0.0 && py >= 0.0 && px < pic_w as f64 && py < pic_h as f64).then_some((px, py))
    }
}

/// Collects wheel deltas into Windows units: 120 per notch, +dy scrolls up,
/// +dx scrolls right (§4.2).
#[derive(Default, Debug)]
pub struct Wheel {
    rest_x: f64,
    rest_y: f64,
}

impl Wheel {
    /// winit line deltas: +y means the content moves down (scroll up), +x
    /// means the content moves right (scroll left).
    pub fn lines(&mut self, x: f32, y: f32) -> Option<(i32, i32)> {
        self.add(-(x as f64) * 120.0, y as f64 * 120.0)
    }

    /// winit pixel deltas, same signs; 100 px count as one notch.
    pub fn pixels(&mut self, x: f64, y: f64) -> Option<(i32, i32)> {
        self.add(-x * 1.2, y * 1.2)
    }

    fn add(&mut self, dx: f64, dy: f64) -> Option<(i32, i32)> {
        self.rest_x += dx;
        self.rest_y += dy;
        let lim = WHEEL_LIMIT as f64;
        let ox = self.rest_x.trunc().clamp(-lim, lim);
        let oy = self.rest_y.trunc().clamp(-lim, lim);
        self.rest_x = (self.rest_x - ox).clamp(-lim, lim);
        self.rest_y = (self.rest_y - oy).clamp(-lim, lim);
        (ox != 0.0 || oy != 0.0).then_some((ox as i32, oy as i32))
    }
}

/// The screenshot scale for `ctl` (§8.2): never upscale.
pub fn shot_scale(max_edge: u32, w: u32, h: u32) -> f64 {
    let long = w.max(h).max(1) as f64;
    (max_edge as f64 / long).min(1.0)
}

/// Screenshot size at that scale (at least 1x1).
pub fn shot_size(scale: f64, w: u32, h: u32) -> (u32, u32) {
    (((w as f64 * scale).round() as u32).max(1), ((h as f64 * scale).round() as u32).max(1))
}

/// A screenshot-space point -> wire units for that monitor. Points outside
/// the screenshot are an error, never clamped (§8.2).
pub fn shot_to_wire(x: f64, y: f64, max_edge: u32, w: u32, h: u32) -> Result<(u16, u16), String> {
    let s = shot_scale(max_edge, w, h);
    let (sw, sh) = shot_size(s, w, h);
    if !x.is_finite() || !y.is_finite() || x < 0.0 || y < 0.0 || x >= sw as f64 || y >= sh as f64 {
        return Err(format!("point {x},{y} is outside the {sw}x{sh} screenshot"));
    }
    let px = (x / s).min(w as f64 - 1.0);
    let py = (y / s).min(h as f64 - 1.0);
    Ok((to_wire(px, w), to_wire(py, h)))
}

/// Area-average downscale of an RGB image to `dw` x `dh`.
pub fn downscale_rgb(src: &[u8], w: u32, h: u32, dw: u32, dh: u32) -> Vec<u8> {
    if dw == w && dh == h {
        return src.to_vec();
    }
    let (w, h, dw, dh) = (w as usize, h as usize, dw as usize, dh as usize);
    let mut out = vec![0u8; dw * dh * 3];
    for oy in 0..dh {
        let y0 = oy * h / dh;
        let y1 = ((oy + 1) * h / dh).max(y0 + 1).min(h);
        for ox in 0..dw {
            let x0 = ox * w / dw;
            let x1 = ((ox + 1) * w / dw).max(x0 + 1).min(w);
            let mut acc = [0u64; 3];
            for y in y0..y1 {
                for x in x0..x1 {
                    let i = (y * w + x) * 3;
                    acc[0] += src[i] as u64;
                    acc[1] += src[i + 1] as u64;
                    acc[2] += src[i + 2] as u64;
                }
            }
            let n = ((y1 - y0) * (x1 - x0)) as u64;
            let o = (oy * dw + ox) * 3;
            for k in 0..3 {
                out[o + k] = ((acc[k] + n / 2) / n) as u8;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_roundtrip_every_pixel() {
        for size in [1u32, 2, 3, 1080, 1920, 2560, 3840, 7680] {
            for px in [0, 1, size / 2, size.saturating_sub(2), size - 1].into_iter().filter(|p| *p < size) {
                let v = to_wire(px as f64, size);
                assert_eq!(from_wire(v, size), px, "size {size} px {px}");
            }
        }
        assert_eq!(to_wire(-5.0, 100), to_wire(0.0, 100));
        assert_eq!(to_wire(1e9, 100), to_wire(99.0, 100));
    }

    #[test]
    fn fit_centers_and_maps() {
        let p = place(Scale::Fit, 0.0, 30.0, 1000.0, 500.0, 2000, 1000, None);
        assert_eq!(p, Placement { x: 0.0, y: 30.0, scale: 0.5 });
        assert_eq!(p.to_picture(500.0, 280.0, 2000, 1000), Some((1000.0, 500.0)));
        assert_eq!(p.to_picture(500.0, 10.0, 2000, 1000), None, "the toolbar is not the picture");
        let tall = place(Scale::Fit, 0.0, 0.0, 1000.0, 500.0, 500, 1000, None);
        assert_eq!((tall.x, tall.scale), (375.0, 0.5));
    }

    #[test]
    fn one_to_one_pans_with_pointer() {
        let left = place(Scale::OneToOne, 0.0, 0.0, 800.0, 600.0, 1600, 600, Some((0.0, 0.0)));
        let right = place(Scale::OneToOne, 0.0, 0.0, 800.0, 600.0, 1600, 600, Some((800.0, 0.0)));
        assert_eq!((left.x, right.x), (0.0, -800.0));
        let small = place(Scale::OneToOne, 0.0, 0.0, 800.0, 600.0, 400, 300, None);
        assert_eq!((small.x, small.y, small.scale), (200.0, 150.0, 1.0));
    }

    #[test]
    fn wheel_convention() {
        let mut w = Wheel::default();
        assert_eq!(w.lines(0.0, 1.0), Some((0, 120)), "scroll up is +dy");
        assert_eq!(w.lines(1.0, 0.0), Some((-120, 0)), "content right = scroll left = -dx");
        assert_eq!(w.pixels(0.0, -50.0), Some((0, -60)));
        assert_eq!(w.pixels(0.0, 0.4), None, "sub-unit motion accumulates");
        assert_eq!(w.lines(0.0, 100.0), Some((0, 1200)), "clamped to the helper's bound");
    }

    #[test]
    fn shot_scale_and_bounds() {
        assert_eq!(shot_scale(1280, 2560, 1440), 0.5);
        assert_eq!(shot_scale(1280, 1024, 768), 1.0, "never upscale");
        assert_eq!(shot_size(0.5, 2560, 1440), (1280, 720));
        // Centre of a 1280x720 shot of a 2560x1440 monitor -> monitor pixel 1280,720.
        let (x, y) = shot_to_wire(640.0, 360.0, 1280, 2560, 1440).unwrap();
        assert_eq!((from_wire(x, 2560), from_wire(y, 1440)), (1280, 720));
        assert!(shot_to_wire(1280.0, 0.0, 1280, 2560, 1440).is_err());
        assert!(shot_to_wire(-1.0, 0.0, 1280, 2560, 1440).is_err());
        let (x, _) = shot_to_wire(1279.9, 0.0, 1280, 2560, 1440).unwrap();
        assert_eq!(from_wire(x, 2560), 2559);
    }

    #[test]
    fn downscale_averages() {
        // 2x2 black/white checker -> one mid-grey pixel.
        let src = [0, 0, 0, 255, 255, 255, 255, 255, 255, 0, 0, 0];
        assert_eq!(downscale_rgb(&src, 2, 2, 1, 1), vec![128, 128, 128]);
    }
}
