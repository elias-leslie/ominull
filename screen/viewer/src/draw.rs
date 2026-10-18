//! Software drawing into the window buffer: rectangles, an 8x8 bitmap font,
//! the scaled picture and the cursor. 0x00RRGGBB pixels.

use crate::geometry::Placement;
use crate::session::Cursor;

pub const BG: u32 = 0x14161a;
pub const CHROME: u32 = 0x1b1e24;
pub const RAISED: u32 = 0x22262e;
pub const LINE: u32 = 0x2c313a;
pub const INK: u32 = 0xdadde3;
pub const DIM: u32 = 0x949ba8;
pub const FAINT: u32 = 0x5d636e;
pub const BRAND: u32 = 0x8fa9e8;
pub const OK: u32 = 0x73b87d;
pub const WARN: u32 = 0xe6be6d;
pub const CRIT: u32 = 0xd35a55;

pub struct Canvas<'a> {
    pub px: &'a mut [u32],
    pub w: usize,
    pub h: usize,
}

impl Canvas<'_> {
    pub fn fill(&mut self, x: i64, y: i64, w: i64, h: i64, c: u32) {
        let x0 = x.clamp(0, self.w as i64) as usize;
        let y0 = y.clamp(0, self.h as i64) as usize;
        let x1 = (x + w).clamp(0, self.w as i64) as usize;
        let y1 = (y + h).clamp(0, self.h as i64) as usize;
        for row in y0..y1 {
            self.px[row * self.w + x0..row * self.w + x1].fill(c);
        }
    }

    pub fn frame(&mut self, x: i64, y: i64, w: i64, h: i64, t: i64, c: u32) {
        self.fill(x, y, w, t, c);
        self.fill(x, y + h - t, w, t, c);
        self.fill(x, y, t, h, c);
        self.fill(x + w - t, y, t, h, c);
    }

    /// Draws `s` with the 8x8 font at integer scale `g`; returns the width.
    pub fn text(&mut self, x: i64, y: i64, s: &str, g: i64, c: u32) -> i64 {
        let mut cx = x;
        for ch in s.chars() {
            let glyph = font8x8::legacy::BASIC_LEGACY.get(ch as usize).copied().unwrap_or(font8x8::legacy::BASIC_LEGACY[b'?' as usize]);
            for (row, bits) in glyph.iter().enumerate() {
                for col in 0..8 {
                    if bits >> col & 1 == 1 {
                        self.fill(cx + col * g, y + row as i64 * g, g, g, c);
                    }
                }
            }
            cx += 8 * g;
        }
        cx - x
    }

    /// The monitor picture, nearest-neighbour scaled, clipped to the area.
    pub fn picture(&mut self, fb: &[u32], fw: u32, fh: u32, at: Placement, clip: (i64, i64, i64, i64), dim: bool) {
        if fw == 0 || fh == 0 || fb.len() < (fw * fh) as usize {
            return;
        }
        let (cx0, cy0, cx1, cy1) = clip;
        let dx0 = at.x.max(cx0 as f64).floor() as i64;
        let dy0 = at.y.max(cy0 as f64).floor() as i64;
        let dx1 = (at.x + fw as f64 * at.scale).min(cx1 as f64).ceil() as i64;
        let dy1 = (at.y + fh as f64 * at.scale).min(cy1 as f64).ceil() as i64;
        let (dx0, dy0) = (dx0.max(0), dy0.max(0));
        let (dx1, dy1) = (dx1.min(self.w as i64), dy1.min(self.h as i64));
        if dx1 <= dx0 || dy1 <= dy0 {
            return;
        }
        let cols: Vec<usize> = (dx0..dx1).map(|x| (((x as f64 + 0.5 - at.x) / at.scale) as i64).clamp(0, fw as i64 - 1) as usize).collect();
        for y in dy0..dy1 {
            let sy = (((y as f64 + 0.5 - at.y) / at.scale) as i64).clamp(0, fh as i64 - 1) as usize;
            let src = &fb[sy * fw as usize..(sy + 1) * fw as usize];
            let dst = &mut self.px[y as usize * self.w + dx0 as usize..y as usize * self.w + dx1 as usize];
            for (d, &sx) in dst.iter_mut().zip(&cols) {
                let p = src[sx];
                *d = if dim { (p >> 1) & 0x7f7f7f } else { p };
            }
        }
    }

    /// The remote cursor at its monitor position, scaled like the picture.
    pub fn cursor(&mut self, c: &Cursor, mx: i32, my: i32, at: Placement, clip: (i64, i64, i64, i64)) {
        let s = at.scale.max(0.25);
        let ox = at.x + (mx as f64 - c.hx as f64) * at.scale;
        let oy = at.y + (my as f64 - c.hy as f64) * at.scale;
        let (w, h) = ((c.w as f64 * s).ceil() as i64, (c.h as f64 * s).ceil() as i64);
        for dy in 0..h {
            let y = oy as i64 + dy;
            if y < clip.1 || y >= clip.3 || y < 0 || y >= self.h as i64 {
                continue;
            }
            let sy = ((dy as f64 / s) as u32).min(c.h - 1);
            for dx in 0..w {
                let x = ox as i64 + dx;
                if x < clip.0 || x >= clip.2 || x < 0 || x >= self.w as i64 {
                    continue;
                }
                let sx = ((dx as f64 / s) as u32).min(c.w - 1);
                let p = c.argb[(sy * c.w + sx) as usize];
                let a = p >> 24;
                if a == 0 {
                    continue;
                }
                let i = y as usize * self.w + x as usize;
                self.px[i] = blend(self.px[i], p, a);
            }
        }
    }
}

fn blend(dst: u32, src: u32, a: u32) -> u32 {
    let ch = |shift: u32| {
        let s = (src >> shift) & 0xff;
        let d = (dst >> shift) & 0xff;
        ((s * a + d * (255 - a)) / 255) << shift
    };
    ch(16) | ch(8) | ch(0)
}

/// Text width at scale `g`.
pub fn text_w(s: &str, g: i64) -> i64 {
    s.chars().count() as i64 * 8 * g
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picture_scales_and_clips() {
        let mut px = vec![0u32; 8 * 4];
        let mut c = Canvas { px: &mut px, w: 8, h: 4 };
        let fb = [1u32, 2, 3, 4];
        c.picture(&fb, 2, 2, Placement { x: 0.0, y: 0.0, scale: 2.0 }, (0, 0, 8, 4), false);
        assert_eq!(&px[0..4], &[1, 1, 2, 2]);
        assert_eq!(px[3 * 8], 3);
        assert_eq!(px[5], 0, "outside the picture stays background");
    }

    #[test]
    fn text_draws_pixels() {
        let mut px = vec![0u32; 16 * 8];
        let w = Canvas { px: &mut px, w: 16, h: 8 }.text(0, 0, "Hi", 1, 7);
        assert_eq!(w, 16);
        assert!(px.contains(&7));
    }
}
