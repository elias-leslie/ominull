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
tiles (JPEG bytes must not be base64-inflated on the hot path) and **JSON text**
for everything else. The relay must forward both message types unchanged
(terminal relay is text-only today; generalize it, see §5).

### 4.1 Agent -> operator

- `hello` (JSON text), first message:
  `{"type":"hello","monitors":[{"id":0,"w":2560,"h":1440,"x":0,"y":0,"primary":true},...],"active":0}`
- `frame` header (JSON text) immediately followed by one binary message with the
  JPEG bytes:
  `{"type":"frame","monitor":0,"seq":N,"x":0,"y":0,"w":256,"h":256,"full":false,"ts":<unix_ms>}`
  - `full:true` is a keyframe (whole monitor, sent on connect, monitor switch,
    and every `keyframe_interval`); otherwise a dirty-rect tile.
  - Tiles are 256x256 aligned; a frame is a batch of tiles each as
    header+binary. One binary message per header, in order.
- `cursor` (JSON text): `{"type":"cursor","x":,"y":,"visible":true}` (optional
  v1; cursor may be baked into tiles instead — implementer's choice, note it).
- `resized` (JSON text): monitor geometry changed, carries a new `monitors` list.
- `bye` (JSON text): `{"type":"bye","reason":"..."}` then close.

### 4.2 Operator -> agent

Only accepted while `mode=control`. In `view` mode the hub drops input frames
(defense in depth: the agent also ignores them, since the grant says view).

- `input` (JSON text), one event:
  - mouse move/button: `{"type":"input","ev":"mouse","x":<abs 0..65535>,"y":<abs 0..65535>,"buttons":{"l":,"r":,"m":},"monitor":0}`
    Coordinates are absolute, normalized 0..65535 across the chosen monitor
    (SendInput MOUSEEVENTF_ABSOLUTE semantics), so the agent is resolution- and
    DPI-agnostic.
  - wheel: `{"type":"input","ev":"wheel","dx":,"dy":,"monitor":0}`
  - key: `{"type":"input","ev":"key","code":<scancode>,"down":true,"ext":false}`
    Scancodes (not VKs) so layout is the endpoint's. Modifiers are separate
    key events (down/up), never a chord string.
  - `{"type":"input","ev":"sas"}` -> Ctrl+Alt+Del via SendSAS (see §6.4).
- `set_monitor` (JSON text): `{"type":"set_monitor","monitor":1}` switch capture
  to another monitor; agent replies with a `full` keyframe of it.
- `quality` (JSON text): `{"type":"quality","fps":<=cap,"jpeg_q":1..100}` the
  viewer may lower fps/quality (phone, slow tunnel). Agent clamps to its caps.
- `close` (JSON text): `{"type":"close"}` operator ends the session.

### 4.3 Sizes, fps, limits

- Max fps cap: **10 fps** v1 (hub-enforced quality clamp; viewer may ask lower).
- JPEG quality default 60, range 30..85 v1.
- Tile max 256x256; one binary message per tile; a full keyframe on a 4K monitor
  is many tiles but each binary message stays well under the relay message cap.
- Relay binary message size cap: reuse MaxMessageSize (1 MiB) agent->operator;
  a single 256x256 JPEG tile is a few KiB to ~50 KiB, so one message = one tile
  keeps us far under the cap. Operator->agent input messages are tiny; reuse
  MaxOperatorMessageSize (256 KiB).
- Backpressure: the relay already blocks the reader (TCP backpressure) and
  drops-to-recording when detached. For screen there is **no recording by
  default** (§7), so when detached the agent should *pause capture* rather than
  have the hub buffer; the hub signals detach to the agent with a
  `{"type":"pause"}` / `{"type":"resume"}` JSON text control frame on the
  agent socket. If a frame queue fills on a live slow viewer, drop stale tiles
  (coalesce by monitor+tile position, keep newest) rather than closing — a lost
  tile is corrected by the next keyframe. This is the key behavioral difference
  from terminal, where every byte matters.

### 4.4 Frame schema ownership

The screen frame/input schema lives in one shared header
`agent/include/screen_frame.h` (parser + builders, same style as
`terminal_frame.h`: bounded, no reads past length, ASCII-only). The hub relay
treats agent->operator binary as opaque passthrough and only parses the JSON
control frames it must police (monitor switch echo is not policed; `input`
frames are dropped in view mode). The viewer and the agent must agree on this
header's JSON shapes; the Go side re-declares only the control frames it
inspects.

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
session** and relays for it (or the helper dials the hub itself; see §6.5).

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

### 6.2 Capture

- Primary: **DXGI Desktop Duplication** (`IDXGIOutputDuplication`). Per output
  (monitor); enumerate adapters/outputs for the monitor list. Handle
  `DXGI_ERROR_ACCESS_LOST` (desktop switch, mode change, resolution change) by
  releasing and re-acquiring duplication — this is normal and frequent on the
  secure-desktop transition.
- Fallback: **GDI BitBlt** (`CreateCompatibleDC`/`BitBlt` from the desktop DC)
  when duplication is unavailable — notably the secure desktop under some
  drivers, and session-0-ish edge cases. Lower fps, whole-frame.
- Dirty rects: DXGI gives dirty/move rects in `GetFrameInfo`; snap them to the
  256-aligned tile grid and send only changed tiles. On the GDI path, diff tiles
  against the last frame (hash per tile) to find dirty ones.
- Encode tiles to JPEG with **WIC** (`CLSID_WICImagingFactory`, JPEG encoder,
  quality from the quality frame). v2 later: Media Foundation H.264 full-frame.

### 6.3 Input

- `SendInput` with `INPUT_MOUSE` + `MOUSEEVENTF_ABSOLUTE|MOUSEEVENTF_VIRTUALDESK`
  using the normalized 0..65535 coords mapped to the chosen monitor's rect.
- Keyboard: `INPUT_KEYBOARD` with `KEYEVENTF_SCANCODE` (+`KEYEVENTF_EXTENDEDKEY`
  when `ext`), so the endpoint's own layout applies.
- Wheel: `MOUSEEVENTF_WHEEL` / `MOUSEEVENTF_HWHEEL`.

### 6.4 Ctrl+Alt+Del

SAS cannot be synthesized with SendInput. Use `SendSAS(FALSE)` (from sas.dll),
which requires the policy
`SoftwareSASGeneration` to allow services, OR the caller on the secure desktop.
If policy forbids it, the helper returns a `{"type":"sas_unavailable"}` control
frame and the viewer shows "Ctrl+Alt+Del is blocked by policy on this machine".
Note in the helper: do not try to enable the policy ourselves (that is a machine
policy change; out of scope for a session).

### 6.5 Helper <-> hub

Two options; pick at implementation time and record which:
- **(A) Helper dials the hub directly** (like the ConPTY worker dials via
  WinHTTP WebSocket). Simplest reuse of the existing agent WS client; the helper
  gets the session_id+token passed on its command line / via a pipe from the
  agent. Preferred unless token handling across the process boundary is awkward.
- **(B) Agent keeps the WS, pipes frames to/from the helper** over an anonymous
  pipe. Keeps the single dial-out in the agent but doubles the copy.

Either way: **the helper exits when the session ends or the agent dies** (job
object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, like the ConPTY worker, so a
dead agent tears the helper down). Only one helper per endpoint at a time.

### 6.6 Capabilities & versions

- Windows agent reports `"screen":{"input":true}` in its response capabilities
  JSON (alongside `terminal`). Hub `parseResponseCapabilities` learns a new
  `Screen` bool / struct; `screenAvailable` gates the console button and
  `resolveScreen` refuses an endpoint that does not report it (same shape as the
  terminal "endpoint reports no terminal capability" refusal, and the same
  no-response-key refusal).
- Build baseline stays Win10 1809+ (DXGI Desktop Duplication, WIC, SendSAS all
  present). Bump the agent/hub version per `scripts/version.sh` sites.

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

- `<canvas>` render; apply tiles by `drawImage` of decoded JPEG blobs at
  tile x/y; keyframe clears and repaints.
- Capture mouse/keyboard on the canvas; translate to normalized 0..65535 coords
  for the active monitor; send `input` frames. Pointer lock optional.
- Monitor picker (from `hello.monitors`), view-only toggle (disabled if the
  grant is view), an End button, and a Ctrl+Alt+Del button.
- Quality/fps control for phone / slow tunnel; works at phone width (the
  console is already responsive — match terminal.ts's layout approach).
- Launch from the asset card next to the terminal action (app.js: add a "Control
  screen..." / "Watch screen..." menu item beside "Open a terminal...", gated on
  `state.screenAvailable` + endpoint capability; this is the only app.js edit).
- UI copy follows the product copy profile; verify rendered at desktop and phone
  width headless (design-evidence-review).

## 10. Linux (design only; build after Windows works)

- **X11**: capture with XShm (`XShmGetImage` from the root window of the active
  display); input with XTest (`XTestFakeMotionEvent`, `XTestFakeButtonEvent`,
  `XTestFakeKeyEvent`). The agent helper runs in the user's X session (needs
  `DISPLAY` + Xauthority of the logged-in user — find via the session's
  environ, like the existing Linux worker finds the session). Multi-monitor via
  Xinerama/RandR geometry.
- **Wayland**: no raw capture/injection. Use the desktop portal
  (`org.freedesktop.portal.ScreenCast` + `RemoteDesktop`) via PipeWire, which has
  its **own** consent dialog shown to the user — that satisfies "ask the person
  first" natively. GNOME's `gnome-remote-desktop` is the reference. This means
  Wayland sessions always require the local user to accept the portal prompt;
  document that as expected, not a bug.
- Same wire protocol, same grant/approval, same banner (a Wayland layer-shell or
  a simple always-on-top window).

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
