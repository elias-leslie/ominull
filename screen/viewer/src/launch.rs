//! Console launch (REMOTE_SCREEN.md §9.2):
//! `ominull-screen://open?hub=<origin>&session=<id>&code=<launch code>`.
//! The hub must be one this machine is configured for; the code is redeemed
//! once over TLS pinned to that hub's CA. The code is never logged or shown.

use crate::handshake::{clean_label, parse_origin, valid_session_id, valid_token, Connect, HubAddr, Mode};
use crate::net;
use serde::Deserialize;
use std::path::PathBuf;

pub const SCHEME_PREFIX: &str = "ominull-screen://open?";

/// A parsed launch URL. `Debug` leaves the code out.
#[derive(Clone, PartialEq, Eq)]
pub struct LaunchUrl {
    pub hub: HubAddr,
    pub hub_origin: String,
    pub session_id: String,
    pub code: String,
}

impl std::fmt::Debug for LaunchUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LaunchUrl").field("hub", &self.hub_origin).field("session_id", &self.session_id).field("code", &"<redacted>").finish()
    }
}

fn pct_decode(s: &str) -> Result<String, String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' => {
                let hex = b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok());
                out.push(hex.ok_or("the link has a bad %-escape")?);
                i += 3;
            }
            b'+' => return Err("the link has a '+' where none is allowed".into()),
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| "the link is not UTF-8".to_string())
}

fn valid_code(s: &str) -> bool {
    (16..=256).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Strict parse: the exact scheme and `open` action, the three parameters
/// once each, nothing else. Errors never contain the code.
pub fn parse_url(url: &str) -> Result<LaunchUrl, String> {
    let query = url.strip_prefix(SCHEME_PREFIX).ok_or("this is not an ominull-screen://open link")?;
    if query.contains('#') || query.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("the link has characters it should not".into());
    }
    let (mut hub, mut session, mut code) = (None, None, None);
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').ok_or("the link has a parameter without a value")?;
        let slot = match k {
            "hub" => &mut hub,
            "session" => &mut session,
            "code" => &mut code,
            _ => return Err("the link has an unknown parameter".into()),
        };
        if slot.is_some() {
            return Err(format!("the link names {k} twice"));
        }
        *slot = Some(pct_decode(v)?);
    }
    let hub_origin = hub.ok_or("the link has no hub")?;
    let session_id = session.ok_or("the link has no session")?;
    let code = code.ok_or("the link has no code")?;
    let hub = parse_origin(&hub_origin)?;
    if !valid_session_id(&session_id) {
        return Err("the link's session id is not valid".into());
    }
    if !valid_code(&code) {
        return Err("the link's launch code is not valid".into());
    }
    Ok(LaunchUrl { hub, hub_origin, session_id, code })
}

#[derive(Deserialize, Debug)]
pub struct HubEntry {
    pub origin: String,
    pub ca_pem: String,
}

#[derive(Deserialize, Debug, Default)]
pub struct Config {
    #[serde(default)]
    pub hubs: Vec<HubEntry>,
}

/// `~/.config/ominull/screen.json` (or `$XDG_CONFIG_HOME`), and
/// `%APPDATA%\ominull\screen.json` on Windows.
pub fn config_path() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("ominull").join("screen.json"))
    }
    #[cfg(not(windows))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
        Some(base.join("ominull").join("screen.json"))
    }
}

pub fn load_config() -> Result<Config, String> {
    let path = config_path().ok_or("cannot find the config directory")?;
    let raw = std::fs::read_to_string(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!("this viewer has no hubs set up yet ({} is missing). Run the viewer installer with --hub and --ca.", path.display())
        } else {
            format!("could not read {}: {e}", path.display())
        }
    })?;
    // Windows PowerShell writes UTF-8 with a byte order mark.
    serde_json::from_str(raw.trim_start_matches('\u{feff}')).map_err(|_| format!("{} is not valid JSON", path.display()))
}

/// The configured CA for this hub, or a refusal that names the hub.
pub fn find_hub<'a>(cfg: &'a Config, hub: &HubAddr, origin: &str) -> Result<&'a HubEntry, String> {
    cfg.hubs
        .iter()
        .find(|h| parse_origin(&h.origin).map(|a| &a == hub).unwrap_or(false))
        .ok_or_else(|| format!("this viewer is not set up for the hub {origin}, so it refused the link. Only hubs listed in the viewer's config are trusted."))
}

#[derive(Deserialize)]
struct Redeemed {
    token: String,
    mode: String,
    #[serde(default)]
    host: Option<String>,
}

/// Redeems the launch code once and returns the session to attach to.
pub fn redeem(link: &LaunchUrl, entry: &HubEntry) -> Result<Connect, String> {
    let body = serde_json::json!({ "session_id": link.session_id, "code": link.code }).to_string();
    let (status, answer) = net::post_json(&link.hub, &entry.ca_pem, "/api/v1/screen/launch/redeem", &body)?;
    match status {
        200 | 201 => {}
        400 | 401 | 403 | 404 | 410 => {
            return Err("the hub did not accept this link. Links work once and only for a minute; open the screen again from the console.".into())
        }
        429 => return Err("the hub is limiting link attempts. Wait a moment and open the screen again from the console.".into()),
        s => return Err(format!("the hub could not open the session (HTTP {s})")),
    }
    let r: Redeemed = serde_json::from_str(&answer).map_err(|_| "the hub's answer to the link was not understood".to_string())?;
    if !valid_token(&r.token) {
        return Err("the hub returned a token this viewer cannot use".into());
    }
    let mode = Mode::parse(&r.mode)?;
    Ok(Connect {
        hub: link.hub.clone(),
        ca_pem: entry.ca_pem.clone(),
        session_id: link.session_id.clone(),
        token: r.token,
        mode,
        host_label: clean_label(r.host.as_deref().unwrap_or(""), &link.hub.host),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CODE: &str = "Zx9_k2-abcdefghijklmnop";

    fn url(q: &str) -> String {
        format!("{SCHEME_PREFIX}{q}")
    }

    #[test]
    fn good_link() {
        let l = parse_url(&url(&format!("hub=https%3A%2F%2Fhub.lan%3A9443&session=s-1&code={CODE}"))).unwrap();
        assert_eq!(l.hub.authority(), "hub.lan:9443");
        assert_eq!(l.session_id, "s-1");
        assert!(!format!("{l:?}").contains(CODE));
        // Unencoded origin is accepted too; order does not matter.
        assert!(parse_url(&url(&format!("code={CODE}&session=s-1&hub=https://hub.lan"))).is_ok());
    }

    #[test]
    fn strict_rejections_never_echo_the_code() {
        let base = format!("hub=https://hub.lan&session=s-1&code={CODE}");
        let cases = [
            format!("ominull-screen://close?{base}"),
            format!("ominull-screen:open?{base}"),
            format!("OMINULL-SCREEN://open?{base}"),
            format!("ominull-screen://open/?{base}"),
            url(&format!("{base}&extra=1")),
            url(&format!("{base}&code={CODE}")),
            url(&format!("{base}#frag")),
            url("hub=https://hub.lan&session=s-1"),
            url(&format!("hub=http://hub.lan&session=s-1&code={CODE}")),
            url(&format!("hub=https://hub.lan/path&session=s-1&code={CODE}")),
            url(&format!("hub=https://hub.lan&session=s/1&code={CODE}")),
            url("hub=https://hub.lan&session=s-1&code=short"),
            url(&format!("hub=https://hub.lan&session=s-1&code={CODE}%zz")),
            url(&format!("hub=https://hub.lan&session&code={CODE}")),
        ];
        for c in &cases {
            let e = parse_url(c).expect_err(c);
            assert!(!e.contains(CODE), "{e}");
        }
    }

    #[test]
    fn unlisted_hub_refused() {
        let cfg: Config = serde_json::from_str(r#"{"hubs":[{"origin":"https://hub.lan:9443","ca_pem":"x"}]}"#).unwrap();
        let ok = parse_origin("https://HUB.lan:9443/").unwrap();
        assert!(find_hub(&cfg, &ok, "https://HUB.lan:9443/").is_ok());
        let other = parse_origin("https://hub.lan").unwrap();
        assert!(find_hub(&cfg, &other, "https://hub.lan").unwrap_err().contains("not set up for the hub https://hub.lan"));
    }
}
