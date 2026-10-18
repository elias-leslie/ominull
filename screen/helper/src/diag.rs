//! Bounded diagnostics log for the screen helper (`REMOTE_SCREEN.md` §6/§9).
//!
//! The launcher used to send the helper's stderr to `NUL`, so a session that
//! failed on the endpoint left nothing behind. Instead the helper appends its
//! own diagnostics here: backend init, which capture path is in use and why,
//! adapter/output names, the monitor list, desktop switches, consent results,
//! and fatal errors. The file lives at
//! `C:\ProgramData\Ominull\logs\screen-helper.log` (SYSTEM/Admins ACL inherited
//! from `ProgramData\Ominull`) and is kept under ~256 KiB by rotating to
//! `screen-helper.log.1`.
//!
//! Never written here: tokens, typed text, or any payload/pixel bytes — only the
//! operational facts above.
//!
//! The formatting + rotation logic is platform-neutral so it is unit-tested on
//! the host; only the default directory is Windows-specific.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

/// Keep the active log under this many bytes; rotate to `.1` before it passes.
pub const MAX_BYTES: u64 = 256 * 1024;

/// An append-only, size-bounded text log with a single-generation rotation.
pub struct DiagLog {
    path: PathBuf,
    rotated: PathBuf,
    max: u64,
}

impl DiagLog {
    /// A log named `name` under `dir`, rotating to `<name>.1` at `max` bytes.
    pub fn new(dir: impl AsRef<Path>, name: &str, max: u64) -> DiagLog {
        let dir = dir.as_ref();
        DiagLog { path: dir.join(name), rotated: dir.join(format!("{name}.1")), max }
    }

    /// Append one timestamped line. Best-effort: any I/O error is swallowed, so
    /// diagnostics never take a session down.
    pub fn line(&self, msg: &str) {
        let _ = self.try_line(msg);
    }

    fn try_line(&self, msg: &str) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let formatted = format!("{} {}\n", utc_stamp(), sanitize(msg));
        // Rotate when this line would push the file past the cap. One line that
        // is itself over the cap still rotates and is written to a fresh file.
        if let Ok(meta) = fs::metadata(&self.path) {
            if meta.len() + formatted.len() as u64 > self.max {
                let _ = fs::remove_file(&self.rotated);
                let _ = fs::rename(&self.path, &self.rotated);
            }
        }
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        f.write_all(formatted.as_bytes())
    }
}

/// Collapse anything that would break the one-line-per-event rule (newlines,
/// control chars) to spaces so a single event is always a single line.
fn sanitize(msg: &str) -> String {
    msg.chars().map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// `YYYY-MM-DDTHH:MM:SSZ` for the current time (UTC).
fn utc_stamp() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    fmt_utc(secs)
}

/// Format a UNIX second count as `YYYY-MM-DDTHH:MM:SSZ` (UTC), with no external
/// crate. Days-to-civil is Howard Hinnant's algorithm.
fn fmt_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
}

/// Convert a count of days since 1970-01-01 to (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[allow(dead_code)]
static LOG: OnceLock<DiagLog> = OnceLock::new();

/// Point the global helper log at `dir` (called once at startup). A second call
/// is ignored, so the first wins.
#[allow(dead_code)]
pub fn init(dir: impl AsRef<Path>) {
    let _ = LOG.set(DiagLog::new(dir, "screen-helper.log", MAX_BYTES));
}

/// Append one line to the global helper log, if it has been initialized.
#[allow(dead_code)]
pub fn log(msg: &str) {
    if let Some(l) = LOG.get() {
        l.line(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let uniq = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        p.push(format!("ominull-diag-test-{tag}-{uniq}-{}", std::process::id()));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn utc_stamp_is_fixed_format() {
        // 2021-01-01T00:00:00Z == 1609459200 unix seconds.
        assert_eq!(fmt_utc(1_609_459_200), "2021-01-01T00:00:00Z");
        // A leap-year date with nonzero time of day.
        assert_eq!(fmt_utc(1_582_934_521), "2020-02-29T00:02:01Z");
        assert_eq!(fmt_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn line_formatting_is_one_line_with_stamp() {
        let dir = temp_dir("fmt");
        let log = DiagLog::new(&dir, "x.log", MAX_BYTES);
        // Control characters in the message must not break the one-line rule.
        log.line("backend init ok\nmonitors=1");
        let body = fs::read_to_string(dir.join("x.log")).unwrap();
        assert_eq!(body.lines().count(), 1, "exactly one line written");
        let line = body.lines().next().unwrap();
        assert!(line.ends_with("backend init ok monitors=1"), "control char became a space: {line:?}");
        // Timestamp prefix shape: ....-..-..T..:..:..Z then a space.
        assert_eq!(&line[4..5], "-");
        assert_eq!(&line[10..11], "T");
        assert_eq!(&line[19..21], "Z ");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotates_and_stays_bounded() {
        let dir = temp_dir("rot");
        let max = 2_048u64;
        let log = DiagLog::new(&dir, "r.log", max);
        // Write far more than the cap; the active file must never exceed it and a
        // rotated generation must appear.
        for i in 0..2_000 {
            log.line(&format!("event number {i} with some padding text to add bytes"));
            let active = fs::metadata(dir.join("r.log")).unwrap().len();
            assert!(active <= max, "active log {active} exceeded cap {max}");
        }
        assert!(dir.join("r.log.1").exists(), "a rotated generation was produced");
        // Only one rotated generation is ever kept.
        assert!(!dir.join("r.log.1.1").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_single_line_still_written() {
        let dir = temp_dir("big");
        let log = DiagLog::new(&dir, "b.log", 64);
        log.line("short");
        log.line(&"x".repeat(500)); // bigger than the cap by itself
        // The big line rotated the short one out and was written to a fresh file.
        assert!(dir.join("b.log").exists());
        assert!(dir.join("b.log.1").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
