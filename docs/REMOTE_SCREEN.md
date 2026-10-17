# Ominull Remote Screen Control

Status: design for v1 (Windows first, Linux designed, built after). This note is
the contract the three build tracks (Windows agent helper, hub relay/approval,
console viewer) work against in parallel. Keep it short and current; code is the
source of truth once it lands.

## 1. What this is

See and control the screen of an enrolled endpoint from the Ominull console,
the same way the terminal already works: the owner taps one approval on their
phone, a session opens over the existing hub relay, it is audited, and it ends
at the hub's session limits. No new listening port on the endpoint (the agent
dials out), no third-party remote tool, no second control channel. A new action
kind `screen_session` reuses the terminal machinery; it does not fork it.

The endpoint shows an always-on, topmost banner while a session is live, so the
person at the keyboard always knows. Input is accepted only while an approved
session is live.

## 2. Reuse map (do not fork)

| Concern | Terminal today | Screen reuses |
|---|---|---|
| Action kind | `terminal_session` | add `screen_session` beside it in `response/dto.go`, `response/trust.go` (CapScreen), authority routing |
| Capability | `terminal` in profile caps / agent caps JSON | add `screen` cap; agent reports `"screen":{...}` in response capabilities |
| Grant + approval | `resolveTerminal` / `ownerApproved` / signed EndpointGrant V2 | `resolveScreen`, same grant path, digest over `{"mode":"control|view"}` |
| Relay | `hub/pkg/terminal` PairedRelay, operator WS + agent WS | `hub/pkg/screen` wraps/generalizes the same pairing; see §5 |
| Session store/limits | `terminal.Manager`, `terminal.Limits` (1.8.77) | screen sessions share the same Limits and per-endpoint/tenant caps |
| Offer to agent | durable response job, heartbeat delivery | same; payload `{"session_id","mode","connect_token"}` |
| Agent worker | `Terminal_RunWindowsWorker` (ConPTY) | `Screen_RunWindowsWorker` (capture/input helper), same WS dial-out |
| Console page | `web-src/terminal.ts` -> `terminal.js` | `web-src/screen.ts` -> `screen.js`, new build.cjs entry |
| CLI | `ominullctl shell open` | `ominullctl screen open ENDPOINT` prints viewer URL |

Generalize where it is cheap: the WS attach handlers, token hashing, session
caps, sweeper, and audit are shared. The frame payloads differ (binary image
tiles and input events, not PTY stdin/stdout), so the frame schema is
screen-specific (§4).

## 3. Session lifecycle & auth

1. Operator (console or `ominullctl`) POSTs `/api/v1/screen/sessions`
   `{endpoint_id, mode}` where `mode` is `control` (default) or `view`.
2. Hub `resolveScreen` builds the approval and returns 202 until the owner taps.
   Approval text, plain owner words, includes duration and mode:
   - control: `See and control the screen on <label>, up to <duration>, for <operator>`
   - view: `Watch the screen on <label> (no control), up to <duration>, for <operator>`
   - if "ask the person first" is on for the machine: append
     `the person at the keyboard is asked to allow it first`.
3. On tap the authority signs an EndpointGrant V2, kind `screen_session`,
   action digest over the canonical payload `{"mode":"control"}` (exactly what
   the agent re-digests; the session length is the hub's to enforce and is shown
   to the owner only, mirroring terminal).
4. Hub creates the session in the shared manager (own token for the agent, own
   operator token minted apart), writes a durable response job with payload
   `{"session_id","mode","connect_token"}`, sets the one-use HttpOnly attach
   cookie on `/api/v1/screen/ws/` for the browser.
5. Agent picks up the offer on heartbeat, verifies the grant against the pinned
   tenant key for this endpoint and kind, checks the replay cache, ACKs, and
   dials `wss://<hub>/api/v1/screen/ws/agent?session_id=&endpoint_id=&token=`.
6. Operator browser dials `/api/v1/screen/ws/operator?session_id=...` with the
   cookie token. Relay pairs them. Session goes active.
7. Ends on: operator close, agent/helper exit, endpoint session end, idle
   timeout, max duration, or hub shutdown. Same states as terminal
   (`waiting/connecting/active/detached/closing/closed/...`). Detach keeps the
   capture helper alive like a detached shell; reattach re-subscribes.

Caps and limits: screen sessions count against the same per-endpoint and
per-tenant live-session caps and the same max-duration / idle timeout as
terminal (terminal.Limits, default 4h). A screen session is heavier than a
shell; v1 allows **1 screen session per endpoint** regardless of the shell cap
(enforced in the screen manager layer, not by lowering the shared cap).

## 4. Wire protocol (over the existing relay)

Two directions over one WebSocket pair, same as terminal. Terminal frames are
one JSON text message each; screen uses **binary** WebSocket messages for image
tiles (JPEG bytes must not be base64-inflated on the hot path, and a tile
carries a small **fixed binary header inside the same binary message** — no
separate JSON header + body) and **JSON text** for control. The relay must
forward both message types unchanged (terminal relay is text-only today;
generalize it, see §5).

### 4.1 Agent -> operator

- `hello` (JSON text), first message:
  `{"type":"hello","monitors":[{"id":0,"w":2560,"h":1440,"x":0,"y":0,"primary":true},...],"active":0}`
- **tile (binary):** one binary WebSocket message per tile = a fixed little-endian
  header then the JPEG bytes. Header (16 bytes):
  `u8 msg_type (1=tile)`, `u8 monitor`, `u8 flags (bit0=keyframe)`, `u8 reserved`,
  `u16 x`, `u16 y`, `u16 w`, `u16 h` (all pre-rotation desktop pixels),
  `u32 seq`. The rest of the message is the JPEG payload.
  - keyframe flag set = whole-monitor repaint (sent on connect, monitor switch,
    and periodically / after a resync); otherwise a dirty-rect tile.
  - Tiles are 256x256 aligned; one tile per binary message, in order within a
    frame.
- `frame_end` (JSON text): `{"type":"frame_end","monitor":0,"frame":N,"tiles":K}`
  closes a frame (the batch of tiles for one captured image). The viewer ACKs
  this for flow control (§4.3).
- **cursor shape (binary):** `u8 msg_type (2=cursor_shape)` + a small header
  (`u16 w`,`u16 h`,`u16 hotspot_x`,`u16 hotspot_y`,`u8 format` where
  0=color BGRA, 1=mono, 2=masked-color) then the pixel/mask bytes. The cursor is
  **never in the captured image** (DXGI excludes it); the agent sends shape
  changes from `GetFramePointerShape` and the viewer draws the cursor itself.
- `cursor_pos` (JSON text): `{"type":"cursor_pos","x":,"y":,"visible":true}`
  position/visibility updates (cheap, frequent).
- `resized` (JSON text): monitor geometry changed, carries a new `monitors` list.
- `sas_unavailable` (JSON text): SendSAS refused by policy (§6.4).
- `bye` (JSON text): `{"type":"bye","reason":"..."}` then close.

### 4.2 Operator -> agent

Only accepted while `mode=control`. In `view` mode the hub drops input frames
(defense in depth: the agent also ignores them, since the grant says view).

- `ack` (JSON text): `{"type":"ack","monitor":0,"frame":N}` the viewer
  acknowledges a `frame_end`. Flow control (§4.3): the agent stops sending new
  frames once `max_unacked` frames are outstanding. This bounds latency, which
  TCP backpressure through the hub does not.
- `input` (JSON text), one event:
  - mouse move/button: `{"type":"input","ev":"mouse","x":<abs 0..65535>,"y":<abs 0..65535>,"buttons":{"l":,"r":,"m":},"monitor":0}`
    `x`/`y` are 0..65535 across the picture of the **active monitor**. The helper
    maps them into that monitor's rect (`px = mon.x + x*mon.w/65536`) and then
    to virtual-desktop absolute `x' = (px - vx) * 65535 / (vw - 1)` (same for y),
    injected with `MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_VIRTUALDESK`, so it is
    resolution- and DPI-agnostic (the helper sets PER_MONITOR_AWARE_V2 first,
    §6.3). Tile and `cursor_pos` x/y are monitor-relative pixels.
  - wheel: `{"type":"input","ev":"wheel","dx":,"dy":,"monitor":0}`, Windows
    convention: 120 per notch, positive `dy` scrolls up, positive `dx` scrolls
    right; the helper drops anything outside ±1200.
  - key: `{"type":"input","ev":"key","code":<scancode>,"down":true,"ext":false}`
    Scancodes (not VKs) so layout is the endpoint's; the viewer maps
    `KeyboardEvent.code` -> scancode (noVNC `xtscancodes.js`, MPL-2.0, vendored
    unmodified, §9). Modifiers are separate key events (down/up), never a chord.
  - text (for phone/IME keyboards that give no usable `code`):
    `{"type":"input","ev":"text","ch":"<unicode>"}` -> injected with
    `KEYEVENTF_UNICODE`.
  - `{"type":"input","ev":"sas"}` -> Ctrl+Alt+Del request (see §6.4).
- `set_monitor` (JSON text): `{"type":"set_monitor","monitor":1}` switch capture
  to another monitor; agent replies with a keyframe of it.
- `quality` (JSON text): `{"type":"quality","fps":<=cap,"jpeg_q":1..100}` the
  viewer may lower fps/quality (phone, slow tunnel). Agent clamps to its caps.
- `close` (JSON text): `{"type":"close"}` operator ends the session.

The agent/helper releases **all keys up** whenever input stops (operator blur,
detach, pause, session end) so no key is left stuck down on the endpoint.

### 4.3 Sizes, fps, limits

- Max fps cap: **10 fps** v1 (hub-enforced quality clamp; viewer may ask lower).
- JPEG quality default 60, range 30..85 v1.
- Tile max 256x256; one binary message per tile; a full keyframe on a 4K monitor
  is many tiles but each binary message stays well under the relay message cap.
- Relay binary message size cap: reuse MaxMessageSize (1 MiB) agent->operator;
  a single 256x256 JPEG tile is a few KiB to ~50 KiB, so one message = one tile
  keeps us far under the cap. Operator->agent input messages are tiny; reuse
  MaxOperatorMessageSize (256 KiB).
- Flow control: the primary bound is the **frame_end + ack** window (§4.1/§4.2).
  The agent sends at most `max_unacked` frames (v1: 2) without an `ack`; TCP
  backpressure through the hub alone does not bound latency, so the ack window
  is what keeps a slow viewer from falling seconds behind. If a frame queue
  still fills, drop stale tiles (coalesce by monitor+tile position, keep newest)
  rather than closing — a lost tile is corrected by the next keyframe. This is
  the key behavioral difference from terminal, where every byte matters.
- Backpressure/detach: there is **no recording by default** (§7), so when
  detached the agent *pauses capture* rather than have the hub buffer; the hub
  signals detach with a `{"type":"pause"}` / `{"type":"resume"}` JSON text
  control frame on the agent socket. On pause the helper also releases all keys
  up (§4.2).

### 4.4 Frame schema ownership

The screen frame/input schema is parsed in **three places**: the Rust helper
(full parse of operator->helper control+input frames, and it builds the
agent->operator frames), the **TS viewer** (builds operator frames, parses
agent frames), and the **Go hub**, which parses only the JSON control frames it
must police (`input` dropped in view mode; `close`). The hub treats every
agent->operator binary message as opaque (the fixed binary tile/cursor header is
not parsed by Go). The C agent parses nothing beyond the pipe length-prefix
framing (§6.5), so there is **no C `screen_frame.h` parser** — the schema is
owned by the Rust crate's `wire` module and mirrored by the viewer and by the
small Go control-frame subset. Keep one canonical table of message shapes in
this doc (§4.1/§4.2); the three implementations cite it.

## 5. Hub relay generalization

`hub/pkg/terminal/relay.go` writes every frame as `websocket.TextMessage` and
unmarshals every incoming message as a `TerminalFrame`. Two cheap changes make
it carry screen too, without disturbing terminal:

- The relay forwards the WebSocket message **type** it received (text or binary)
  rather than always writing text. Terminal only ever sends text, so its
  behavior is unchanged; screen binary tiles pass through.
- Frame policing (which types each side may send) becomes a small policy the
  session kind supplies. Terminal keeps its `{stdin,resize,close}` /
  `{stdout,close}` rule; screen supplies its own (operator: `input,set_monitor,
  quality,close`; agent: `hello,frame,cursor,resized,bye` + binary tiles).

Prefer: put the shared pairing/pumps in `hub/pkg/terminal` (or lift the shared
part into a small `relaycore` the two import) and keep screen-specific session
state, limits-per-kind, and frame policy in `hub/pkg/screen`. Do not copy the
800-line relay. Decide at implementation time which is less churn; either way,
terminal's tests must stay green.

Audit: `SCREEN_SESSION_CREATED` / `SCREEN_SESSION_CLOSED` with operator, mode,
endpoint, grant id, duration — same shape as the terminal audit lines.

## 6. Windows agent helper

The agent runs as SYSTEM in session 0 and cannot capture or inject input in the
interactive desktop from there. So the terminal-style in-process worker is wrong
for screen; instead the agent **launches a helper process in the active console
session** and relays bytes for it over a pipe (§6.5).

**The helper is a separate Rust binary, not C** (coordinator decision,
2026-10-17). It runs as SYSTEM, including on the secure desktop, and it parses
input/control messages that arrive from the network, so memory safety matters
most exactly there. It is a separate process regardless, so there is no FFI with
the agent. The C agent stays minimal: it launches the helper in the console
session with the duplicated SYSTEM token + session id and shuttles bytes between
the hub WebSocket and the helper's pipe/stdio, doing **no message parsing beyond
length-prefix framing** (§6.5).

### 6.0 Rust crate layout, toolchain, supply chain

- Crate at `agent/windows/screen_helper/` (Cargo workspace member or standalone;
  keep it out of any download-at-build path). Binary name e.g.
  `ominull-screen-helper.exe`.
- Use Microsoft's `windows` crate **0.62.x** (or `windows-sys` **0.61.x**) for
  DXGI Desktop Duplication, WIC JPEG, `SendInput`, and desktop switching
  (`OpenInputDesktop`/`SetThreadDesktop`) — all MIT/Apache. JPEG via WIC, or
  `jpeg-encoder` **0.7.1** if WIC is awkward. **Avoid** `turbojpeg` (C build),
  `scrap` (dead), `rdev`, and WGC-based capture crates (`windows-capture`,
  `xcap`) — WGC has no secure-desktop access and shows a yellow border. For the
  later Linux backend: `x11rb` 0.14.x, `ashpd` 0.13.x, `pipewire` 0.10.x (all
  permissive). Every crate added must be listed in `NOTICE` with its license.
- Target **x86_64-pc-windows-gnu** with the mingw toolchain already on this host
  (`rustup target add x86_64-pc-windows-gnu` if missing; cargo/rustc are
  installed). This matches how the Windows agent cross-compiles.
- Supply chain: minimal crates, **exact versions pinned in Cargo.lock**,
  **vendored** (`cargo vendor`), `cargo-audit` clean, **no `build.rs` network
  access or downloads**.
- The helper binary is **signed and digest-pinned in the agent release** exactly
  like the agent binary (add it to the release artifact set and the version /
  digest sites; signing is an owner-tap step via Nightshift).
- **Lay the capture + input backend behind a trait** (e.g. `ScreenBackend`:
  `monitors()`, `capture_tiles(dirty) -> Vec<Tile>`, `inject(input)`,
  `follow_input_desktop()`) with a Windows DXGI/GDI implementation now, so the
  Linux X11 backend (`x11rb` XShm/XTest, §10) drops in later without touching the
  protocol, framing, or session loop.

### 6.1 Launching into the console session

- `WTSGetActiveConsoleSessionId()` -> active session id (may be 0xFFFFFFFF if no
  one is logged on / at secure desktop transitions; retry).
- Duplicate the agent's SYSTEM token: `OpenProcessToken` ->
  `DuplicateTokenEx(TokenPrimary)` -> `SetTokenInformation(TokenSessionId, &sid)`.
- `CreateProcessAsUserW` with that token, `STARTUPINFO.lpDesktop = "winsta0\\default"`,
  `CREATE_UNICODE_ENVIRONMENT` + environment block from
  `CreateEnvironmentBlock` for the session.
- The helper runs as SYSTEM but **in the user's session**, so it can
  `OpenInputDesktop`/`SetThreadDesktop` and follow the input desktop onto the
  secure desktop (UAC, lock screen, sign-in). It re-checks the input desktop on
  a timer and re-attaches when it changes (that is how you keep drawing/injecting
  across a UAC elevation prompt).
- **SetThreadDesktop fails once a thread owns a window or a hook.** So the
  capture thread and the input thread must own **no windows** — they only
  `SetThreadDesktop` and call DXGI/SendInput. The banner window (and the consent
  prompt, §7) live on their **own dedicated UI thread**, and that window is
  **destroyed and recreated on each desktop switch** (you cannot move a window
  between desktops). Model: MeshAgent `CheckDesktopSwitch` / `kvm_relay_restart`.
- **Session changes:** `WTSGetActiveConsoleSessionId` returns `0xFFFFFFFF`
  during transitions (fast-user-switch, sign-out). The **C agent** (a real
  Windows service) handles `SERVICE_CONTROL_SESSIONCHANGE` and **respawns the
  helper** into the new active session (MeshAgent `kvm_relay_restart`, ~500 ms
  retry); the helper does not try to migrate itself.

### 6.2 Capture

- Primary: **DXGI Desktop Duplication** (`IDXGIOutputDuplication`). It **works on
  the secure desktop when running as LocalSystem** — DXGI is the primary path
  there, not the fallback. Create the D3D11 device on the **adapter that owns the
  output** (hybrid-GPU laptops: the wrong adapter fails), per monitor; max 4
  duplications per session. Before `DuplicateOutput`, sync to the input desktop
  (Sunshine `syncThreadDesktop`).
- Recoverable errors (release + re-acquire, ~200 ms retry, do not treat as
  fatal): `DXGI_ERROR_ACCESS_LOST` (desktop switch / mode change / resolution
  change) and `DXGI_ERROR_WAIT_TIMEOUT` (no new frame). After
  `UNSUPPORTED` / `SESSION_DISCONNECTED`, wait for a desktop switch or display
  change before retrying.
- `AcquireNextFrame` -> `GetFrameInfo`: **`AccumulatedFrames == 0` means
  cursor-only** (pointer moved, no pixels changed) — update the cursor, send no
  tiles. Process **move rects and dirty rects** (pre-rotation coords); snap to
  the 256-aligned tile grid; send only changed tiles.
- **Cursor is never in the DXGI image.** Read `GetFramePointerShape` for shape
  changes (handle color BGRA, monochrome, and masked-color formats) and send
  cursor-shape/`cursor_pos` messages (§4.1); the viewer composites it.
- Fallback: **GDI BitBlt** (`CreateCompatibleDC`/`BitBlt`) only for
  **hybrid-GPU / non-DWM / disconnected-session** cases where duplication is
  unavailable — NOT for the secure desktop (DXGI handles that). Lower fps,
  whole-frame; diff tiles against the last frame (per-tile hash/CRC, MeshAgent
  `tile.cpp` model) to find dirty ones.
- Encode tiles to JPEG with **WIC** (`CLSID_WICImagingFactory`, JPEG encoder,
  quality from the quality frame). If WIC is awkward from Rust, `jpeg-encoder`
  0.7.1 (permissive). v2 later: Media Foundation / openh264 full-frame.

### 6.3 Input

- **Call `SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` first**, before
  any capture or input, or coordinates are wrong on scaled displays.
- `SendInput` with `INPUT_MOUSE` + `MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_VIRTUALDESK`
  using the normalized 0..65535 **virtual-desktop** coords
  (`x' = (x - vx) * 65535 / (vw - 1)`, same for y; §4.2).
- Keyboard: `INPUT_KEYBOARD` with `KEYEVENTF_SCANCODE` (+`KEYEVENTF_EXTENDEDKEY`
  when `ext`), so the endpoint's own layout applies; `KEYEVENTF_UNICODE` for a
  `text` event (phone/IME). **Release all keys up** on pause/detach/blur/end.
- Wheel: `MOUSEEVENTF_WHEEL` / `MOUSEEVENTF_HWHEEL`.
- Validate every frame's bounds (monitor index, coord range, scancode range)
  before injecting; drop malformed, never clamp into something else.

### 6.4 Ctrl+Alt+Del

SAS cannot be synthesized with SendInput. The viewer sends an `{"ev":"sas"}`
request; the **agent service** (a real Windows service — the documented,
supported caller) invokes `SendSAS(FALSE)` from `sas.dll`, loaded dynamically
(`LoadLibraryExA` with `LOAD_LIBRARY_SEARCH_SYSTEM32`; mingw lacks the import
lib). `SoftwareSASGeneration` **"not configured" means disabled**, which is the
default — and we **do NOT write that policy** (MeshAgent/RustDesk do; we will
not change a machine policy for a session). If SendSAS is refused, emit
`sas_unavailable` (§4.1) and the viewer shows a plain message
("Ctrl+Alt+Del is turned off by policy on this machine"). Home lock screens
rarely need it, so this is an edge case, not a blocker.

### 6.5 Helper <-> hub (decided: agent relays bytes over a pipe)

The **agent keeps the single hub WebSocket dial-out** (as the ConPTY worker does
via WinHTTP WebSocket) and **relays bytes to/from the helper over an anonymous
pipe / the helper's stdio**. The agent does no message parsing beyond framing:

- WS -> helper: each WebSocket message the agent receives (text control frame or
  binary input — operator side is small) is written to the helper's input pipe
  as a **length-prefixed frame**: `u8 kind (0=text,1=binary)` + `u32le len` +
  `len` bytes. The helper parses the JSON/bytes.
- helper -> WS: the helper writes the same length-prefixed framing on its output
  pipe; the agent reads a frame and sends it as the matching WebSocket message
  type (text for JSON control, binary for a JPEG tile). This keeps the "one
  binary message per tile, header then bytes" contract (§4.1) — the header is a
  text frame, the tile is a binary frame, back to back.

The helper gets its `session_id`, `mode`, and the geometry it needs on the
command line / an initial control frame; the connect token never reaches the
helper (the agent holds the WS). **The helper exits when the session ends or the
agent dies**: launch it inside a Windows Job Object with
`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (as the ConPTY worker does), so a dead agent
tears the helper down, and close its pipes on session end. Only one helper per
endpoint at a time.

### 6.6 Capabilities & versions

- Windows agent reports `"screen":{"input":true}` in its response capabilities
  JSON (alongside `terminal`). Hub `parseResponseCapabilities` learns a new
  `Screen` bool / struct; `screenAvailable` gates the console button and
  `resolveScreen` refuses an endpoint that does not report it (same shape as the
  terminal "endpoint reports no terminal capability" refusal, and the same
  no-response-key refusal).
- Build baseline stays Win10 1809+ (DXGI Desktop Duplication, WIC, SendSAS all
  present). Bump the agent/hub version per `scripts/version.sh` sites.

### 6.7 Keep-awake and process hardening

- `SetThreadExecutionState(ES_CONTINUOUS | ES_DISPLAY_REQUIRED)` for the life of
  a session so the display does not sleep mid-view (Sunshine); clear it at end.
- **Launch/DLL hardening** (secure desktop as SYSTEM is a high-value target):
  the agent launches the helper **only from its own Program Files directory**
  (verify the path), the helper calls
  `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` at startup, loads
  `sas.dll` only via `LOAD_LIBRARY_SEARCH_SYSTEM32`, uses **non-inheritable**
  pipe handles, and **accepts input/commands only from the agent pipe** (never a
  socket of its own). Parse every frame strictly; drop malformed.

## 7. Safety

- **One owner tap per session.** No standing grant. Each open is its own
  approval with its own signed grant, consumed once (replay cache).
- **Always-on banner on the endpoint.** While a session is live the helper shows
  a topmost, click-through-disabled, not-hideable-by-viewer banner:
  `This screen is being viewed remotely (OmniNull)`. It is a separate top-most
  layered window the helper owns, re-asserted on desktop switch, torn down only
  when the session ends. The viewer cannot suppress it.
- **"Ask the person first" per-machine setting** (uses the existing settings
  model, per-machine + fleet default like the terminal limits / maintenance
  settings). Default **off** for home/workgroup machines, **on** recommended for
  domain / Entra-joined / work machines. When on, the helper shows a local
  consent prompt on the endpoint and the session does not go active until the
  person allows it (timeout -> declined). Detect join type to pick the default
  (NetGetJoinInformation); the owner can override per machine.
- **"Ask the person first" with nobody signed in or at the lock screen:** there
  is no one to ask, so the session is **declined** with a plain reason
  ("nobody is signed in on <machine> to allow this") — UNLESS the owner's
  approval explicitly carried "nobody at the keyboard" wording (a distinct
  approval text and grant mode). This stops a silent unattended takeover being
  the default behavior of the consent setting.
- **Operator WebSocket Origin check.** The operator WS is cookie-authenticated,
  so the hub MUST verify the `Origin` header on it (CSWSH; MeshCentral
  CVE-2024-26135). No screen route is reachable unauthenticated (ScreenConnect
  CVE-2024-1709 class).
- **View-only mode.** `mode=view` grant; hub drops operator input; agent ignores
  input even if one slipped through (grant says view).
- **No pixel recording by default.** Unlike terminal (which records frames to
  evidence), screen sessions do **not** record video by default. A per-machine
  setting `record_screen` (default off) can enable capped recording later; v1
  ships the setting off and may defer the recording writer. Audit always records
  who/when/how long/mode regardless.
- **Input only while live.** The helper injects input only while an approved
  session is active and paired; on detach/pause it stops both capture and input.
- No new listening port: the agent/helper always dials out to the hub.

## 8. ominullctl

`ominullctl screen open ENDPOINT [--view] [--ttl DUR]`:
- POSTs `/api/v1/screen/sessions` (202 until the owner taps, like `shell open`),
  then prints the console viewer URL
  `https://<hub>/console#screen=<session_id>` (or the dedicated viewer page
  path) for the owner to open in a browser. The approval is the phone tap; the
  owner views in the browser. ominullctl does not render pixels.
- `--view` requests view-only; `--ttl` requests a shorter session (clamped to
  the hub max, like shell).

## 9. Console viewer page

New server-rendered page like the terminal page (`terminal_page.go` ->
`screen_page.go`, template registered in `pages.go`), script `web-src/screen.ts`
bundled to `screen.js` via a new `build.cjs` entry.

- Layered `<canvas>` (Guacamole `Display.js` model): a base canvas for tiles and
  a top canvas for the cursor. Decode each binary tile with
  `createImageBitmap(blob)` and `drawImage` at the tile's header x/y; a keyframe
  tile repaints its region.
- **Cursor** is drawn by the viewer from the cursor-shape / `cursor_pos`
  messages (it is never in the image). Build an ImageBitmap from the shape
  (handle color / mono / masked formats) and draw it at the position minus the
  hotspot.
- **Flow control:** after each `frame_end`, send an `ack` (§4.2). Do not let the
  agent outrun the viewer; the ack window bounds latency.
- Capture mouse/keyboard on the canvas; translate the pointer to normalized
  0..65535 virtual-desktop coords for the active monitor; send `input` frames.
  Keys: map `KeyboardEvent.code` to scancode via **noVNC `xtscancodes.js`
  (MPL-2.0, vendored unmodified as its own file with a NOTICE entry)**; send a
  `text` event for phone/IME input (`beforeinput`/composition). **Release all
  keys up on blur, detach, and End** (mirror the agent-side release). Pointer
  lock optional.
- Monitor picker (from `hello.monitors`), view-only toggle (disabled if the
  grant is view), an End button, and **viewer buttons for Ctrl+Alt+Del, Win,
  Alt+Tab and Esc** (these are swallowed or reserved by the browser/OS, so
  buttons are the reliable path; the **Keyboard Lock API** captures Win/Alt+Tab/
  Esc directly only in fullscreen Chromium — use it when available, buttons
  otherwise). Show a plain notice on `sas_unavailable`.
- Quality/fps control for phone / slow tunnel; works at phone width (the
  console is already responsive — match terminal.ts's layout approach).
- Launch from the asset card next to the terminal action (app.js: add a "Control
  screen..." / "Watch screen..." menu item beside "Open a terminal...", gated on
  `state.screenAvailable` + endpoint capability; this is the only app.js edit,
  done by the integrator).
- UI copy follows the product copy profile; verify rendered at desktop and phone
  width headless (design-evidence-review).

## 10. Linux (design only; build after Windows works)

Decision (prior-art, 2026-10-17): to match the Windows helper's reach — the
greeter, the lock screen, and Wayland sessions, not just a logged-in X session —
the **primary** Linux path is **root DRM/KMS capture + uinput injection**
(MeshAgent `linux_kvm_drm.c` + `linux_events_evdev.c`). Run as root (the agent
already does): capture from `/dev/dri/card*` (KMS framebuffer, master or a
leased plane), inject via `/dev/uinput`. This reaches the greeter and Wayland
compositors because it is below the display server, and **our always-on banner
is the consent signal** (there is no compositor to show one on the greeter).
This is the Linux equivalent of DXGI-as-SYSTEM.

- **Portals as the in-session alternative:** inside a logged-in Wayland session
  we may instead use `org.freedesktop.portal.ScreenCast` + `RemoteDesktop`
  (PipeWire, `ashpd` crate), which shows the compositor's own consent dialog —
  that satisfies "ask the person first" natively. Offer this where the owner
  prefers the compositor-mediated consent over the banner-only DRM path.
- **X11 (legacy sessions):** XShm (`XShmGetImage`) capture + XTest injection, in
  the user's X session (`DISPLAY` + Xauthority via the session environ); simplest
  but does not reach the greeter — a convenience path, not the primary one.
- The capture/input backend is behind the `ScreenBackend` trait (§6.0), so DRM/
  uinput, portals, and X11 are three implementations under the same wire
  protocol, grant/approval, and banner.

## 11. Threat notes

- The grant is per-session, signed, replay-protected, bound to endpoint + kind +
  mode digest. A stolen operator token only attaches to an already-approved
  session and expires with it; the agent token is separate and single-dial.
- The hub never exposes relay tokens to logs (terminal's zero-exposure invariant
  applies). The operator token reaches the browser only as an HttpOnly cookie on
  the ws path.
- Input injection is the sharp edge: it is gated by (1) a live approved grant,
  (2) mode=control, (3) the helper only running during a paired session, (4) the
  visible banner. There is no API to inject input outside a session.
- The helper runs as SYSTEM in the user session (needed for the secure desktop).
  It must validate every operator frame's bounds (monitor index, coord range,
  scancode range) before calling SendInput; a malformed frame is dropped, never
  clamped into something else.
- No recording by default means a session leaves an audit trail (who/when/mode)
  but not a video the owner must then protect. That is deliberate for a home
  machine.
