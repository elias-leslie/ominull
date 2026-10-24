# Ominull Remote Screen Control

Status: design for v1 (Windows first, Linux designed, built after). This note is
the contract the three build tracks (Windows agent helper, hub relay/authorization +
ominullctl, native Rust viewer) work against in parallel. Keep it short and current; code is the
source of truth once it lands.

## 1. What this is

See and control the screen of an enrolled endpoint in a **native desktop viewer**
(owner decision: no in-browser viewer; the website only has a launch button),
or drive it from `ominullctl` for agents acting on the owner's request, the same
way the terminal already works: the hub has the response authority sign the
grant on the first request (nobody is asked, no phone tap), a session opens over
the existing hub relay, it is audited, and it ends at the hub's session limits. No new listening port on the endpoint (the agent
dials out), no third-party remote tool, no second control channel. A new action
kind `screen_session` reuses the terminal machinery; it does not fork it.

The endpoint shows an always-on, topmost banner while a session is live, so the
person at the keyboard always knows. Input is accepted only while an authorized
session is live.

## 2. Reuse map (do not fork)

| Concern | Terminal today | Screen reuses |
|---|---|---|
| Action kind | `terminal_session` | add `screen_session` beside it in `response/dto.go`, `response/trust.go` (CapScreen), authority routing |
| Capability | `terminal` in profile caps / agent caps JSON | add `screen` cap; agent reports `"screen":{...}` in response capabilities |
| Grant + authorization | `resolveTerminal` / `authorized` / signed EndpointGrant V2 | `resolveScreen`, same grant path, digest over `{"mode":"control|view"}` |
| Relay | `hub/pkg/terminal` PairedRelay, operator WS + agent WS | `hub/pkg/screen` wraps/generalizes the same pairing; see §5 |
| Session store/limits | `terminal.Manager`, `terminal.Limits` (1.8.77) | screen sessions share the same Limits and per-endpoint/tenant caps |
| Offer to agent | durable response job, heartbeat delivery | same; payload `{"session_id","mode","connect_token"}` |
| Agent worker | `Terminal_RunWindowsWorker` (ConPTY) | `Screen_RunWindowsWorker` (capture/input helper), same WS dial-out |
| Viewer | `web-src/terminal.ts` (browser) | **native Rust app** `screen/viewer` (`ominull-screen`), sharing `screen/wire` with the helper; console has only an asset-card "Remote screen" button that launches it via `ominull-screen://` (§9) |
| CLI | `ominullctl shell open` (held session, .ended marker) | `ominullctl screen open` (viewer) + held agent session with `shot/click/type/key/...` (§8) |

Generalize where it is cheap: the WS attach handlers, token hashing, session
caps, sweeper, and audit are shared. The frame payloads differ (binary image
tiles and input events, not PTY stdin/stdout), so the frame schema is
screen-specific (§4).

## 3. Session lifecycle & auth

1. Operator (console button or `ominullctl`) POSTs `/api/v1/screen/sessions`
   `{endpoint_id, mode}` where `mode` is `control` (default) or `view`.
2. Hub `resolveScreen` describes the request and `authorized` calls the response
   authority (`POST /v1/authorize`) at once; there is no 202 and no wait. The
   authority refuses with the reason (HTTP error, audit `ACTION_REFUSED`) if the
   payload is invalid or breaks the steward-run rules. The audit statement
   (`ACTION_AUTHORIZED`) includes duration and mode:
   - control: `See and control the screen on <label>, up to <duration>, for <operator>`
   - view: `Watch the screen on <label> (no control), up to <duration>, for <operator>`
   - api-key caller (an agent via ominullctl): `An agent (admin key) will see
     and control the screen on <label>, up to <duration>` (view: `...will see
     the screen...`), so the audit always shows who controls it.
   - if "ask the person first" is on for the machine: append
     `the person at the keyboard is asked to allow it first`.
3. The authority signs an EndpointGrant V2, kind `screen_session`,
   action digest over the canonical payload `{"mode":"control"}` (exactly what
   the agent re-digests; the session length is the hub's to enforce and is
   audited only, mirroring terminal). The agent still verifies the grant itself.
4. Hub creates the session in the shared manager (own token for the agent, own
   operator token minted apart), writes a durable response job with payload
   `{"session_id","mode","connect_token"}`. There is **no cookie**. The operator
   credential is a one-use token: returned in the body to an api-key caller
   (ominullctl), or, for the console button, exchanged for a **launch code**
   (§9.2) the native viewer redeems once.
5. Agent picks up the offer on heartbeat, verifies the grant against the pinned
   tenant key for this endpoint and kind, checks the replay cache, ACKs, and
   dials `wss://<hub>/api/v1/screen/ws/agent?session_id=&endpoint_id=&token=`.
6. The native viewer or `ominull-screen ctl` dials
   `/api/v1/screen/ws/operator?session_id=...` with header `X-Screen-Token`
   (one-use; `POST /api/v1/screen/sessions/attach` rotates it for the next
   attach). Requests carrying an `Origin` header are rejected, so no web page
   can drive a session. Relay pairs them. Session goes active.
   **Attachments:** one *control* attachment plus any number of *watch*
   (view-only) attachments on the same session (`POST
   /api/v1/screen/sessions/watch` -> token or launch code), so the owner can
   watch an agent-controlled session live. The hub drops input from watchers,
   forwards acks from exactly one *pacer* (the control attachment if connected,
   else the oldest watcher), fans tiles out to all attachments (dropping stale
   tiles per slow watcher), and sends the agent `pause` only when no attachment
   remains. Every attach/detach is audited.
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
- `desktop` (JSON text): `{"type":"desktop","name":"user|secure|lock","signed_in":true}`
  sent in/after `hello` and on every input-desktop switch (used by `screen info`
  and the consent rule in §7).
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
agent->operator frames), the **native viewer / ctl** (`screen/viewer`, same
`screen-wire` crate: builds operator frames, parses agent frames), and the
**Go hub**, which parses only the JSON control frames it
must police (`input` dropped in view mode; `close`). The hub treats every
agent->operator binary message as opaque (the fixed binary tile/cursor header is
not parsed by Go). The C agent parses nothing beyond the pipe length-prefix
framing (§6.5), so there is **no C `screen_frame.h` parser** — the schema is
owned by the `screen/wire` crate (shared by helper and viewer, no mirror) plus
the small Go control-frame subset the hub polices. Keep one canonical table of message shapes in
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

- Crates under `screen/`: `screen/wire` (lib `screen-wire`: message types,
  binary headers, pipe framing, validation; platform-neutral), `screen/helper`
  (`ominull-screen-helper.exe`), `screen/viewer` (`ominull-screen`, §9). Helper
  and viewer each have their own Cargo.lock + vendor dir and depend on wire by
  path. Nothing downloads at build time.
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
  digest sites; signing goes through Nightshift's release signer, which signs without asking anyone).
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
  `Screen` bool / struct; it gates the console's "Remote screen" button and
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

- **One grant per session.** No standing grant. Each open is its own
  authorization with its own signed grant, consumed once (replay cache). Nobody
  is asked; the safety is the signed grant the agent verifies, the capability
  manifest and lock level, the banner, and the audit.
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
  ("nobody is signed in on <machine> to allow this") — UNLESS the request explicitly asked for it (`unattended`: a distinct
  audit text and grant payload). This stops a silent unattended takeover being
  the default behavior of the consent setting.
- **No browser on the operator socket.** Operator auth is a one-use header
  token, never a cookie, and the hub rejects any operator WS upgrade carrying an
  `Origin` header (CSWSH; MeshCentral CVE-2024-26135). No screen route is
  reachable unauthenticated (ScreenConnect CVE-2024-1709 class); the launch-code
  redeem is authenticated by the code itself (§9.2).
- **Agent control is visible and audited.** The banner shows for agent control
  too; the audit names the agent; the owner can watch live; the hub audits
  each agent input (kind + coordinates; typed text by length only, never content;
  mouse moves not logged individually).
- **View-only mode.** `mode=view` grant; hub drops operator input; agent ignores
  input even if one slipped through (grant says view).
- **No pixel recording by default.** Unlike terminal (which records frames to
  evidence), screen sessions do **not** record video by default. A per-machine
  setting `record_screen` (default off) can enable capped recording later; v1
  ships the setting off and may defer the recording writer. Audit always records
  who/when/how long/mode regardless.
- **Input only while live.** The helper injects input only while an authorized
  session is active and paired; on detach/pause it stops both capture and input.
- No new listening port: the agent/helper always dials out to the hub.
- **Remote access off (per machine).** `PUT /api/v1/remote-access/settings`
  `{"endpoint_id":"..","off":true}` switches off every remote terminal and
  screen session on that machine, for everyone (owner, agents, steward); it is
  stored as data (settings row `remote_access.off`), never derived from a
  hostname. Switching it off applies at once and closes the machine's open
  sessions; switching it back on is a loosening that the authority authorizes on the same
  request and the audit records ("Allow remote terminal and screen again").
  Requests for that machine are refused with 403 before the authority is asked. An unreadable settings row refuses everywhere until it
  is rewritten. `GET /api/v1/remote-access/settings[?endpoint_id=]` reads it.
  The agent-side lock levels (docs/HOST_AUTHORITY.md) refuse terminal and screen
  too; this setting is the hub-side half, for any agent version.

## 8. ominullctl

### 8.1 Owner viewing

`ominullctl screen open ENDPOINT [--view] [--ttl DUR] [--viewer PATH] [--agent LABEL]` opens a session
(authorized on the first request, like `shell open`), creates it, then
starts `ominull-screen` (`--viewer`, else next to ominullctl, else PATH) and
writes **one JSON line on its stdin**:
`{"hub_url","ca_pem","session_id","token","mode","host"}`. The token never goes
in argv or env. If the viewer is missing, ominullctl says so and deletes the
session so it does not hold a slot.

### 8.2 Agent control (held session)

For agents acting when the owner asks ("show me", "click this"). Same held-
session model as `shell open`: one session, reused for its life, and
the same `.ended` marker semantics, so a session that ended makes the next
command fail with "open a new one" instead of silently opening a new one.

```
ominullctl screen hold ENDPOINT [--view] [--ttl DUR] [--agent LABEL]   # opens the session; the audit names the agent
ominullctl screen info  ENDPOINT                        # monitors, sizes, desktop (user/secure/lock)
ominullctl screen shot  ENDPOINT [--monitor N] -o file.png   # one full frame, cursor composited
ominullctl screen click ENDPOINT X Y [--button left|right|middle] [--double]
ominullctl screen move  ENDPOINT X Y
ominullctl screen drag  ENDPOINT X1 Y1 X2 Y2
ominullctl screen scroll ENDPOINT X Y DY
ominullctl screen type  ENDPOINT ["text" | -]           # Unicode text events; - or no text: read stdin
ominullctl screen key   ENDPOINT ctrl+alt+del|win+r|enter|...
ominullctl screen watch ENDPOINT                        # owner watches live, view-only
ominullctl screen end   ENDPOINT
```

Screenshots are made for LLM agents: `screen shot` downscales the monitor to a
max long edge (`--max-edge`, default 1280, settable in ominullctl's config) and
prints JSON on stdout: `{"path","width","height","scale","monitor",
"monitor_width","monitor_height"}`. Action coordinates (`click/move/drag/scroll`)
are pixels in that same downscaled screenshot space for the chosen monitor
(`--monitor`, default the primary). The scale is deterministic,
`scale = min(1, max_edge / max(monitor_w, monitor_h))`, so each stateless action
recomputes it from the monitor size and the same `--max-edge`, then converts to
the 0..65535 wire units for that monitor. `ctrl+alt+del` sends the `sas` request (§6.4); other combos become
scancode down/up sequences. Each command rotates the operator token (`/attach`),
spawns `ominull-screen ctl <action>` with the handshake on stdin, which connects,
waits for a keyframe when it needs one, performs the action, and detaches (the
session stays live between commands; the agent pauses capture while nothing is
attached). The wire schema lives only in Rust; ominullctl does held
state, markers and process plumbing. `ominullctl help screen` carries this usage
for agents.

`screen type` text never goes in a process's argv: ominullctl puts it in the
handshake line as `"text"` and runs `ominull-screen ctl type` with no text
argument. With `-` (or no text) ominullctl reads it from its own stdin, one
trailing newline dropped, so a caller can keep a password off every command
line. `--agent LABEL` (default `$OMINULL_AGENT`; at most 64 printable ASCII
characters, checked client-side) is sent as `X-Ominull-Agent` on the session
request and, from the held state, on every later request for that session.

**The agent label is self-declared.** Every agent shares the one hub admin
key, so the hub cannot tell agents apart; `X-Ominull-Agent` is only what the
caller says it is. The hub reads it only from an admin-key request (1 to 64
printable ASCII characters, no `"` or `\`, no leading/trailing space; anything
else is a 400) and always shows it as a claim: the audit statement reads
`An agent calling itself "claude-ops" (admin key) will ...`, the endpoint's
consent prompt and banner get operator `agent "claude-ops" (admin key)`, and
the audit names `admin (agent calling itself "claude-ops", admin key)`. The
label is part of the authorization (as are the session length and ask-first) and
the audit. Per-agent hub keys are
the real fix and would replace the claim with an identity.

## 9. Native viewer (`screen/viewer`, binary `ominull-screen`)

### 9.1 Viewer

Rust, sharing `screen-wire` with the helper. winit for windowing and input,
softbuffer for blitting decoded tiles, a pure-Rust JPEG decoder, tungstenite +
rustls with the hub CA pinned. Linux x86_64 first (X11 and Wayland), Windows too.

- Windowed and true fullscreen (F11 and a toolbar toggle); scale-to-fit and 1:1.
- Monitor picker, view-only toggle (forced on for a view grant or a watch
  attachment), end session.
- Full keyboard capture while focused via the platform keyboard grab (Win,
  Alt+Tab, Esc go to the remote); a release-grab hotkey always shown on screen;
  a toolbar button and hotkey for Ctrl+Alt+Del (`sas`); all keys up on focus
  loss, release-grab, view-only and end.
- Cursor drawn from `cursor_shape` + `cursor_pos`; an `ack` for every `frame_end`.
- `ctl` subcommand (§8.2): headless, no window; same connection code.

### 9.2 Console launch (the only screen UI in the website)

The asset card has a **"Remote screen"** button (when the endpoint reports the
screen capability). It runs the normal authorization, then asks the hub for a
**launch code**: high-entropy, **one use, 60 s expiry, bound to the session and
the operator**. The console opens
`ominull-screen://open?hub=<hub origin>&session=<id>&code=<launch code>`.
The viewer checks that `hub` is one it is configured for (it refuses any other),
then redeems the code once over TLS (`POST /api/v1/screen/launch/redeem
{session_id, code}` -> operator token, unauthenticated except by the code,
rate-limited). A second redeem, an expired code, or a code for another session
fails and is audited. The operator token never appears in the URL or argv.

If the scheme is not registered, the button's sheet shows the exact
`ominullctl screen open <endpoint>` command instead (the console cannot reliably
detect a handler, so the command is always shown as the fallback).

Scheme registration is part of installing the viewer:
- Linux (user level): `scripts/install-screen-viewer.sh` puts `ominull-screen`
  in `~/.local/bin`, a `.desktop` file in `~/.local/share/applications` with
  `MimeType=x-scheme-handler/ominull-screen`, runs
  `xdg-mime default ominull-screen.desktop x-scheme-handler/ominull-screen`, and
  writes the viewer config (hub origin + CA PEM) to `~/.config/ominull/screen.json`.
- Windows: `HKCU\Software\Classes\ominull-screen` (URL Protocol, shell\open\command
  -> `"...\ominull-screen.exe" "%1"`), via a small PowerShell installer.

### 9.3 Diagnostics (so a failed session is not blind)

A screen session that never reaches the viewer leaves a trail on the **endpoint**,
under `C:\ProgramData\Ominull\logs\` (SYSTEM/Admins ACL, inherited from
`ProgramData\Ominull`). Two bounded, append-only logs, each kept under ~256 KiB by
rotating to a single `.1` generation, one line per event with a UTC timestamp.
Neither ever records connect tokens, typed text, or payload/pixel contents.

- `screen.log` — the **C agent**: each screen offer received (session id, mode),
  any refusal with its exact reason (manifest / ceiling / grant / digest / replay),
  the ACK result, the helper digest check (expected vs actual sha256), the console
  session id chosen, the `CreateProcessAsUserW` result (+`GetLastError`), the
  helper exit code, the hub WebSocket connect result/HTTP status, and the session
  end reason.
- `screen-helper.log` — the **Rust helper** (its stderr no longer goes to `NUL`):
  backend init result, which capture path is in use (DXGI duplication vs GDI
  fallback) and why, adapter/output names, the monitor list sent, desktop switches,
  consent result, the first frame captured, and fatal errors.

On a **fatal init failure** the helper also sends the existing `bye` control frame
to the hub before exiting, so `ctl` and the viewer show the reason instead of a bare
timeout. When `ctl` times out waiting for the monitor list it says the endpoint
never sent its screen (it may not have accepted the session) and points here.

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
  protocol, grant/authorization, and banner.

## 11. Threat notes

- The grant is per-session, signed, replay-protected, bound to endpoint + kind +
  mode digest. A stolen operator token only attaches to an already-authorized
  session and expires with it; the agent token is separate and single-dial.
- The hub never exposes relay tokens to logs (terminal's zero-exposure invariant
  applies). The operator token never appears in a URL, argv or env: ominullctl
  hands it to the viewer on stdin; the console path carries only a 60 s one-use
  launch code, redeemed once over TLS (a second redeem fails and is audited).
- The viewer only connects to hubs in its own config (installed with the hub's
  CA), so a crafted `ominull-screen://` link cannot point it at another server.
- Input injection is the sharp edge: it is gated by (1) a live authorized grant,
  (2) mode=control, (3) the helper only running during a paired session, (4) the
  visible banner. There is no API to inject input outside a session.
- The helper runs as SYSTEM in the user session (needed for the secure desktop).
  It must validate every operator frame's bounds (monitor index, coord range,
  scancode range) before calling SendInput; a malformed frame is dropped, never
  clamped into something else.
- No recording by default means a session leaves an audit trail (who/when/mode)
  but not a video the owner must then protect. That is deliberate for a home
  machine.

## 12. The steward (bound to a stuck run)

Nightshift's steward can open a screen session for a stuck maintenance run. It
needs no tap and no stored rule: the hub checks the run, the authority signs
the grant on the first request like any screen session, and the audit says who
asked and why.

- **Key:** `POST /api/v1/integrations/steward/key` (administrator) returns the
  key once; `DELETE` revokes it. The steward reaches only its route list
  (maintenance wait/escalate/list and the screen session routes).
- **No rule:** the per-machine steward rule, its token, `POST
  /api/v1/screen/steward` and `/api/v1/integrations/nightshift/steward-screen`
  are removed, as are `rule_token` and `narrow` on a session request.
- **Opening:** the steward sends `POST /api/v1/screen/sessions` with
  `steward_run` (a maintenance job on that machine in needs_hands or stalled).
  The hub opens it only inside the machine's maintenance window, never
  unattended, for at most 30 minutes, and never on a host-locked machine;
  otherwise it refuses with the reason and the steward escalates the run. The
  audit statement names the steward and the run.
- **Ending:** the hub checks bound sessions every 15 s and closes one (audited
  `SCREEN_SESSION_CLOSED`, `steward_run_resolved`) when its run is no longer
  stuck, or at the session's time limit.
- The endpoint must report the screen capability in its signed profile, and
  host-locked machines refuse.
