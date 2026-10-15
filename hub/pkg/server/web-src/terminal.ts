/* The terminal page's script (pages/terminal.tmpl). Two parts: the "Open a
   terminal" form, which waits for the owner's approval, and the session view,
   one xterm pane on the hub's relay socket. Built into web/terminal.js by
   web-build/build.cjs. */

import {
  APPROVAL_POLL_WAIT_S,
  APPROVAL_TEXT,
  ApprovalError,
  ApprovalInfo,
  approvalCountdown,
  approvalFlow,
  PostResult,
  termCtrlChar,
  termKeyBytes,
} from "./approval";

declare global {
  interface Window {
    Terminal: any;
    FitAddon?: { FitAddon: any };
    Unicode11Addon?: { Unicode11Addon: any };
  }
}

const $ = (id: string) => document.getElementById(id);

interface HubError extends Error {
  status?: number;
  body?: any;
}

/* Every call carries the console session cookie; the page never holds a key. */
function api(path: string, method = "GET", body?: unknown, extra: Record<string, string> = {}): Promise<PostResult> {
  const controller = new AbortController();
  const deadline = setTimeout(() => controller.abort(), (APPROVAL_POLL_WAIT_S + 8) * 1000);
  const headers: Record<string, string> = { "Content-Type": "application/json", ...extra };
  return fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    signal: controller.signal,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
    .then(
      (res) =>
        res.text().then((t) => {
          let parsed: any = null;
          try {
            parsed = t ? JSON.parse(t) : null;
          } catch {
            parsed = null;
          }
          if (!res.ok) {
            const err: HubError = new Error((parsed && parsed.error) || t.slice(0, 200) || "HTTP " + res.status);
            err.status = res.status;
            err.body = parsed;
            throw err;
          }
          return { status: res.status, body: parsed };
        }),
      (error) => {
        if (error && error.name === "AbortError") throw new Error("Request timed out");
        throw error;
      },
    )
    .finally(() => clearTimeout(deadline));
}

function bytes(n: number): string {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return (i === 0 ? n : n.toFixed(1)) + " " + units[i];
}

function clock(d: Date): string {
  return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
}

/* ------------------------------------------------------- open a terminal */

function openForm(form: HTMLFormElement) {
  const host = $("term-host") as HTMLSelectElement | null;
  const program = $("term-program") as HTMLSelectElement;
  const runsAs = $("term-runs-as")!;
  const problem = $("term-open-problem")!;
  const button = $("term-open-btn") as HTMLButtonElement;
  const panel = $("term-approval")!;
  const stateEl = $("term-approval-state")!;
  const timeEl = $("term-approval-time")!;
  const stop = $("term-approval-stop") as HTMLButtonElement;
  if (!host) return;

  const showProblem = (text: string) => {
    problem.textContent = text;
    problem.hidden = !text;
  };
  const choose = () => {
    const opt = host.selectedOptions[0];
    program.textContent = "";
    let programs: string[] = [];
    try {
      programs = JSON.parse(opt?.dataset.programs || "[]") || [];
    } catch {
      programs = [];
    }
    for (const p of programs) program.append(new Option(p, p));
    runsAs.textContent = opt ? "Runs as " + opt.dataset.identity + " on " + opt.dataset.name + "." : "";
    showProblem(opt?.dataset.problem || "");
    button.disabled = !!opt?.dataset.problem || !programs.length;
  };
  host.addEventListener("change", choose);
  choose();

  let busy = false;
  let cancelled = false;
  let wake: (() => void) | null = null;
  let ticker = 0;
  stop.addEventListener("click", () => {
    cancelled = true;
    wake?.();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") wake?.();
  });

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (busy) return;
    const opt = host.selectedOptions[0];
    if (!opt || !program.value) return;
    busy = true;
    cancelled = false;
    button.disabled = true;
    button.textContent = "Sending to your phone…";
    showProblem("");
    const body = { endpoint_id: host.value, program: program.value };
    let info: ApprovalInfo | null = null;
    const render = (next: ApprovalInfo) => {
      info = next;
      panel.hidden = false;
      panel.dataset.state = next.state;
      if (next.state === "pending") {
        button.textContent = "Waiting for approval…";
        stateEl.textContent = "Sent to your phone. Open the notification and confirm with your passkey.";
        timeEl.textContent = approvalCountdown(next.expires_at, Date.now());
      } else if (next.state === "approved") {
        stateEl.textContent = "Approved. Opening the terminal.";
        timeEl.textContent = "";
      } else if (next.state === "done") {
        stateEl.textContent = "Approved.";
      } else {
        stateEl.textContent = APPROVAL_TEXT[next.state] || next.state;
        timeEl.textContent = "";
      }
    };
    ticker = window.setInterval(() => {
      if (info && info.state === "pending") timeEl.textContent = approvalCountdown(info.expires_at, Date.now());
    }, 1000);
    approvalFlow({
      post: (headers) => api("/api/v1/terminal/sessions", "POST", body, headers),
      poll: (id) => api("/api/v1/approvals?id=" + encodeURIComponent(id) + "&wait=" + APPROVAL_POLL_WAIT_S).then((r) => r.body),
      sleep: (ms) =>
        new Promise<void>((resolve) => {
          const t = setTimeout(() => {
            wake = null;
            resolve();
          }, ms);
          wake = () => {
            clearTimeout(t);
            wake = null;
            resolve();
          };
        }),
      now: () => Date.now(),
      cancelled: () => cancelled,
      onState: render,
    })
      .then((summary) => {
        if (!summary || !summary.session_id) throw new Error("The hub did not return a session.");
        location.assign("/console/terminal?session=" + encodeURIComponent(summary.session_id) + "&new=1");
      })
      .catch((err: ApprovalError) => {
        busy = false;
        button.disabled = false;
        button.textContent = "Ask for approval";
        if (!err || !err.approvalState) {
          panel.hidden = true;
          showProblem((err && err.message) || "The hub refused the terminal.");
        }
      })
      .finally(() => clearInterval(ticker));
  });
}

/* ------------------------------------------------------------ the session */

/* xterm's scrollback, and how much recording a reattach replays. */
const TERM_SCROLLBACK = 5000;
const TERM_REPLAY_BYTES = 262144;
/* A stdin frame carries at most 4 KiB. Agents before 1.8.53 read one 8 KiB
   WebSocket frame at a time and end the session on a larger one, so a big
   paste goes out as several frames. */
const TERM_STDIN_CHUNK = 4096;
/* Input typed while the relay reconnects is kept, up to this much. */
const TERM_INPUT_QUEUE = 65536;
/* Reconnect backoff tops out here and never gives up while the hub still has
   the session: the hub keeps a detached shell for its idle window (15
   minutes), which is the window a phone has to come back in. */
const TERM_RECONNECT_MAX_MS = 5000;
const TERM_FONT_KEY = "ominull.terminal.fontSize";
const TERM_FONT_MIN = 8;
const TERM_FONT_MAX = 28;

function termFontSize(): number {
  let v = 0;
  try {
    v = parseInt(localStorage.getItem(TERM_FONT_KEY) || "", 10);
  } catch {
    /* storage can be blocked */
  }
  if (v >= TERM_FONT_MIN && v <= TERM_FONT_MAX) return v;
  return window.innerWidth < 600 ? 12 : 13;
}

function b64FromBytes(data: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < data.length; i += 0x8000) bin += String.fromCharCode.apply(null, Array.from(data.subarray(i, i + 0x8000)));
  return btoa(bin);
}

function bytesFromB64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function cssVar(name: string, fallback: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

/* xterm's palette, from the --term-* tokens in app.css. */
function terminalTheme() {
  const ansi = (n: number, fallback: string) => cssVar("--term-ansi-" + n, fallback);
  const bg = cssVar("--term-bg", "#14161A");
  return {
    background: bg,
    foreground: cssVar("--term-fg", "#DADDE3"),
    cursor: cssVar("--brand", "#8FA9E8"),
    cursorAccent: bg,
    selectionBackground: cssVar("--raised", "#22262E"),
    black: ansi(0, "#2C313A"),
    red: ansi(1, "#CD7670"),
    green: ansi(2, "#73B87D"),
    yellow: ansi(3, "#E6BE6D"),
    blue: ansi(4, "#689BDB"),
    magenta: ansi(5, "#BC8CFF"),
    cyan: ansi(6, "#39C5CF"),
    white: ansi(7, "#949BA8"),
    brightBlack: ansi(8, "#878E9B"),
    brightRed: ansi(9, "#D35A55"),
    brightGreen: ansi(10, "#8FD48F"),
    brightYellow: ansi(11, "#F0CE84"),
    brightBlue: ansi(12, "#8FA9E8"),
    brightMagenta: ansi(13, "#D2A8FF"),
    brightCyan: ansi(14, "#6FDDE4"),
    brightWhite: ansi(15, "#DADDE3"),
  };
}

interface Frame {
  type: string;
  data?: string;
  timestamp?: string | number;
}

function sessionView(root: HTMLElement) {
  let session: any = JSON.parse(root.dataset.session || "{}");
  const hostName = root.dataset.host || session.endpoint_id || "this host";
  const fresh = root.dataset.fresh === "1";
  if (fresh) history.replaceState(null, "", "/console/terminal?session=" + encodeURIComponent(session.session_id));

  const statusEl = $("term-status")!;
  const banner = $("term-banner")!;
  const screen = $("term-screen")!;
  const recordingEl = $("term-recording")!;
  const limitsEl = $("term-limits")!;
  const fontEl = $("term-font")!;
  const confirm = $("term-confirm")!;
  const overlay = screen.querySelector(".terminal-overlay-msg");

  /* The session view owns the whole visual viewport (pages.css). */
  document.body.classList.add("term-mode");
  const vv = window.visualViewport;
  const syncViewport = () => {
    if (!vv) return;
    document.body.style.setProperty("--term-vvh", Math.round(vv.height) + "px");
    document.body.style.setProperty("--term-vvt", Math.round(vv.offsetTop) + "px");
  };
  syncViewport();
  vv?.addEventListener("resize", syncViewport);
  vv?.addEventListener("scroll", syncViewport);

  let ended = false;
  let leaving = false;
  let term: any = null;
  let fit: any = null;
  let sock: WebSocket | null = null;
  let reconnectAttempt = 0;
  let reconnectTimer = 0;
  let connecting = false;
  let lastDims = "";
  let statusText = "";
  let ctrlArmed = false;

  const setStatus = (tone: string, text: string) => {
    statusText = text;
    statusEl.dataset.state = tone;
    statusEl.textContent = text;
  };
  const showBanner = (text: string) => {
    banner.textContent = text;
    banner.hidden = !text;
  };
  const removeOverlay = () => overlay?.remove();

  let recordedBytes = Number(session.recording_bytes) || 0;
  let recordedCap = Number(session.max_recording_bytes) || 0;
  let bounded = session.recording_state === "bounded";
  const updateRecording = (sum: any) => {
    if (sum) {
      if (sum.recording_bytes !== undefined) recordedBytes = Number(sum.recording_bytes) || 0;
      if (sum.max_recording_bytes) recordedCap = Number(sum.max_recording_bytes) || 0;
      if (sum.recording_state === "bounded") bounded = true;
    }
    let text = "Recorded";
    if (bounded) text = "Recording stopped at " + bytes(recordedCap || recordedBytes);
    else if (recordedCap > 0) text += " " + bytes(Math.min(recordedBytes, recordedCap)) + " of " + bytes(recordedCap);
    else if (recordedBytes > 0) text += " " + bytes(recordedBytes);
    recordingEl.textContent = text;
    recordingEl.dataset.nearCap = bounded || (recordedCap > 0 && recordedBytes / recordedCap >= 0.9) ? "true" : "false";
    recordingEl.title = bounded
      ? "The recording reached its cap and stopped. The session is still live and audited, but output from here on is not sealed into evidence."
      : "Input, output and window size changes are sealed into evidence when the session ends.";
  };
  const updateLimits = (sum: any) => {
    const parts: string[] = [];
    const expires = Date.parse(sum?.expires_at || "");
    const idle = Date.parse(sum?.idle_expires_at || "");
    if (expires) parts.push("Ends " + clock(new Date(expires)));
    if (idle) parts.push("Idle out " + clock(new Date(idle)));
    limitsEl.textContent = parts.join(" · ");
  };
  const meta = (sum: any) => {
    if (!sum) return;
    session = sum;
    updateRecording(sum);
    updateLimits(sum);
  };
  meta(session);

  const markEnded = (why: string) => {
    if (ended) return;
    ended = true;
    leaving = true;
    clearTimeout(reconnectTimer);
    setStatus("idle", "Ended");
    showBanner("This session has ended" + (why ? " (" + why + ")" : "") + ". Its recording is sealed into evidence.");
    removeOverlay();
    root.querySelectorAll<HTMLButtonElement>("[data-act='end'], .term-key, [data-act='ctrl-c'], [data-act='ctrl-d']").forEach((b) => (b.disabled = true));
  };

  /* ---- input: keystrokes typed within one frame leave as one stdin frame */
  let queue: Uint8Array[] = [];
  let queued = 0;
  let flushPending = false;
  let dropWarned = false;
  const encoder = new TextEncoder();
  const flush = () => {
    flushPending = false;
    if (!queue.length || !sock || sock.readyState !== WebSocket.OPEN) return;
    const all = new Uint8Array(queued);
    let o = 0;
    for (const b of queue) {
      all.set(b, o);
      o += b.length;
    }
    queue = [];
    queued = 0;
    for (let i = 0; i < all.length; i += TERM_STDIN_CHUNK) {
      sock.send(JSON.stringify({ type: "stdin", data: b64FromBytes(all.subarray(i, i + TERM_STDIN_CHUNK)) }));
    }
  };
  const scheduleFlush = () => {
    if (flushPending) return;
    flushPending = true;
    let done = false;
    const run = () => {
      if (!done) {
        done = true;
        flush();
      }
    };
    requestAnimationFrame(run);
    /* animation frames stop in a hidden tab */
    setTimeout(run, 16);
  };
  const input = (data: string) => {
    if (ended || !data) return;
    const b = encoder.encode(data);
    if (queued + b.length > TERM_INPUT_QUEUE) {
      if (!dropWarned) {
        dropWarned = true;
        showBanner("Typing faster than the relay can reconnect; input past 64 KiB was dropped.");
      }
      return;
    }
    queue.push(b);
    queued += b.length;
    scheduleFlush();
  };
  const focus = () => {
    try {
      term?.focus();
    } catch {
      /* not attached yet */
    }
  };
  const paste = (text: string) => {
    if (term && text) {
      term.paste(text);
      focus();
    }
  };
  const pasteFromClipboard = () => {
    navigator.clipboard?.readText?.().then(paste, () => showBanner("This browser did not allow reading the clipboard. Long-press the terminal to paste."));
  };

  /* ---- output */
  let replaying = false;
  let liveBuffer: Frame[] = [];
  let lastReplayTs = 0;
  const writeFrame = (f: Frame) => {
    if (f && f.data && term) term.write(bytesFromB64(f.data));
  };
  const frameTs = (f: Frame) => {
    const t = f && f.timestamp;
    if (typeof t === "number") return t;
    const v = Date.parse(t || "");
    return isNaN(v) ? 0 : v;
  };
  const flushLive = () => {
    replaying = false;
    while (liveBuffer.length) {
      const f = liveBuffer.shift()!;
      /* output that reached both the recording and this socket is written once */
      if (lastReplayTs && frameTs(f) && frameTs(f) <= lastReplayTs) continue;
      writeFrame(f);
    }
  };
  const replayTail = () => {
    replaying = true;
    liveBuffer = [];
    const id = encodeURIComponent(session.session_id);
    return api("/api/v1/terminal/frames?id=" + id + "&session_id=" + id + "&tail_bytes=" + TERM_REPLAY_BYTES)
      .then((r) => {
        const frames: Frame[] = ((r.body && r.body.frames) || []).filter((f: Frame) => f && f.type === "stdout");
        if (!term || !frames.length) return;
        term.reset();
        lastReplayTs = 0;
        let total = 0;
        let start = frames.length;
        while (start > 0 && total < TERM_REPLAY_BYTES) {
          start--;
          total += ((frames[start].data || "").length * 3) / 4;
        }
        if (start > 0) term.write("\x1b[2m[earlier output not replayed]\x1b[0m\r\n");
        for (let i = start; i < frames.length; i++) {
          writeFrame(frames[i]);
          lastReplayTs = Math.max(lastReplayTs, frameTs(frames[i]));
        }
        removeOverlay();
      })
      .catch(() => {
        /* replay is a convenience; live output still works */
      })
      .then(flushLive);
  };

  /* ---- socket */
  const sendResize = (force: boolean) => {
    if (!term || !sock || sock.readyState !== WebSocket.OPEN) return;
    const dims = term.rows + "x" + term.cols;
    if (!force && dims === lastDims) return;
    lastDims = dims;
    sock.send(JSON.stringify({ type: "resize", rows: term.rows, cols: term.cols }));
  };
  let fitTimer = 0;
  const fitSoon = () => {
    clearTimeout(fitTimer);
    fitTimer = window.setTimeout(() => {
      try {
        fit?.fit();
      } catch {
        /* not laid out yet */
      }
      sendResize(false);
    }, 100);
  };

  const connect = (isReconnect: boolean): Promise<void> => {
    if (leaving || ended) return Promise.resolve();
    connecting = true;
    const attach = isReconnect
      ? api("/api/v1/terminal/sessions/attach", "POST", { session_id: session.session_id }).then((r) => meta(r.body))
      : Promise.resolve();
    return attach
      .then(() => {
        if (leaving || ended) return;
        return new Promise<void>((settle) => {
          /* a socket that neither opens nor closes must not hold the page */
          setTimeout(settle, 10000);
          const proto = location.protocol === "https:" ? "wss:" : "ws:";
          const s = new WebSocket(proto + "//" + location.host + "/api/v1/terminal/ws/operator?session_id=" + encodeURIComponent(session.session_id));
          sock = s;
          s.onopen = () => {
            settle();
            if (sock !== s) return;
            connecting = false;
            reconnectAttempt = 0;
            showBanner("");
            setStatus("info", "Attached");
            lastDims = "";
            sendResize(true);
            if (isReconnect || session.state === "detached" || (session.frame_count || 0) > 0) replayTail();
            flush();
          };
          s.onmessage = (event) => {
            if (sock !== s) return;
            let f: Frame;
            try {
              f = JSON.parse(event.data);
            } catch {
              return;
            }
            if (f.type === "stdout") {
              removeOverlay();
              if (statusText !== "Live") setStatus("ok", "Live");
              if (replaying) liveBuffer.push(f);
              else writeFrame(f);
            } else if (f.type === "bounded") {
              bounded = true;
              updateRecording(null);
              term?.write("\r\n\x1b[33m[Recording limit reached; the session continues unrecorded]\x1b[0m\r\n");
            } else if (f.type === "close") {
              markEnded("closed by the host");
              term?.write("\r\n\r\n[The shell on " + hostName + " has exited]\r\n");
            }
          };
          s.onerror = () => {
            if (!leaving && sock === s) setStatus("crit", "Relay error");
          };
          s.onclose = () => {
            settle();
            if (sock !== s) return;
            sock = null;
            connecting = false;
            if (leaving || ended) return;
            scheduleReconnect();
          };
        });
      })
      .catch((err) => {
        connecting = false;
        if (leaving || ended) return;
        checkAlive(err);
      });
  };

  /* A refused reattach is either "the hub still holds the old socket" (a
     phone that slept: it lets go within a minute) or "the session is gone".
     Ask the hub which before giving up. */
  const checkAlive = (err?: Error) => {
    api("/api/v1/terminal/sessions?id=" + encodeURIComponent(session.session_id)).then(
      (r) => {
        const st = r.body && r.body.state;
        if (st && !["active", "detached", "connecting", "waiting"].includes(st)) {
          meta(r.body);
          markEnded(st);
          return;
        }
        scheduleReconnect(err);
      },
      (e2: HubError) => {
        if (e2 && (e2.status === 404 || e2.status === 403)) {
          markEnded("no longer on the hub");
          return;
        }
        scheduleReconnect(err);
      },
    );
  };

  const scheduleReconnect = (err?: Error) => {
    if (leaving || ended || reconnectTimer) return;
    reconnectAttempt++;
    const delay = Math.min(TERM_RECONNECT_MAX_MS, 400 * Math.pow(2, reconnectAttempt - 1));
    setStatus("warn", "Reconnecting");
    showBanner(
      "Reconnecting" +
        (reconnectAttempt > 1 ? " (attempt " + reconnectAttempt + ")" : "") +
        ". The shell keeps running on " +
        hostName +
        " and waits up to 15 minutes for you to come back." +
        (err && err.message ? " Last answer: " + err.message : ""),
    );
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = 0;
      connect(true);
    }, delay);
  };

  const reconnectNow = () => {
    if (leaving || ended || connecting) return;
    if (sock && sock.readyState === WebSocket.OPEN) return;
    clearTimeout(reconnectTimer);
    reconnectTimer = 0;
    reconnectAttempt = 0;
    connect(true);
  };

  /* A phone that slept or changed networks: the relay may look open and be
     dead. Coming back after a while, or getting the network back, replaces
     the socket at once instead of waiting for the backoff. */
  const resume = (replace: boolean) => {
    if (leaving || ended) return;
    if (sock && sock.readyState === WebSocket.OPEN) {
      if (!replace) return;
      /* closing cleanly lets the hub detach this socket at once */
      const s = sock;
      sock = null;
      try {
        s.onclose = null;
        s.close();
      } catch {
        /* already closed */
      }
    }
    reconnectNow();
  };
  let hiddenAt = 0;
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      hiddenAt = Date.now();
      return;
    }
    const away = hiddenAt ? Date.now() - hiddenAt : 0;
    hiddenAt = 0;
    resume(away > 30000);
  });
  window.addEventListener("online", () => resume(true));
  window.addEventListener("orientationchange", () =>
    setTimeout(() => {
      syncViewport();
      fitSoon();
    }, 150),
  );

  /* Leaving the page detaches: the socket closes without a close frame, and
     the shell keeps running. Only End session sends the close frame. */
  window.addEventListener("pagehide", () => {
    leaving = true;
    if (sock) {
      const s = sock;
      sock = null;
      try {
        s.onclose = null;
        s.close();
      } catch {
        /* already closed */
      }
    }
  });

  /* ---- controls */
  const setFont = (n: number) => {
    n = Math.max(TERM_FONT_MIN, Math.min(TERM_FONT_MAX, Math.round(n)));
    try {
      localStorage.setItem(TERM_FONT_KEY, String(n));
    } catch {
      /* storage can be blocked */
    }
    if (term) term.options.fontSize = n;
    fontEl.textContent = n + "px";
    fitSoon();
  };
  fontEl.textContent = termFontSize() + "px";
  const ctrlBtn = root.querySelector<HTMLButtonElement>(".term-key[data-key='ctrl']");
  const setCtrl = (on: boolean) => {
    ctrlArmed = on;
    ctrlBtn?.setAttribute("aria-pressed", on ? "true" : "false");
  };
  root.querySelectorAll<HTMLButtonElement>(".term-key").forEach((b) => {
    /* keep focus in xterm's textarea so the phone keyboard stays up */
    b.addEventListener("pointerdown", (e) => e.preventDefault());
    b.addEventListener("click", () => {
      const name = b.dataset.key || "";
      if (name === "ctrl") {
        setCtrl(!ctrlArmed);
        focus();
        return;
      }
      if (name === "paste") {
        pasteFromClipboard();
        return;
      }
      let appCursor = false;
      try {
        appCursor = !!term?.modes?.applicationCursorKeysMode;
      } catch {
        appCursor = false;
      }
      const data = termKeyBytes(name, ctrlArmed, appCursor);
      setCtrl(false);
      if (data) input(data);
      focus();
    });
  });
  const end = () => {
    if (sock && sock.readyState === WebSocket.OPEN) {
      try {
        sock.send(JSON.stringify({ type: "close" }));
      } catch {
        /* the DELETE below ends it anyway */
      }
    }
    markEnded("ended from this page");
    api("/api/v1/terminal/sessions?id=" + encodeURIComponent(session.session_id), "DELETE").catch((e: Error) =>
      showBanner("The hub did not confirm the end: " + e.message + ". Check the session list."),
    );
  };
  const actions: Record<string, () => void> = {
    "ctrl-c": () => {
      input("\x03");
      focus();
    },
    "ctrl-d": () => {
      input("\x04");
      focus();
    },
    clear: () => {
      term?.clear();
      focus();
    },
    smaller: () => setFont(termFontSize() - 1),
    larger: () => setFont(termFontSize() + 1),
    end: () => {
      confirm.hidden = false;
      confirm.querySelector<HTMLButtonElement>("[data-act='end-cancel']")?.focus();
    },
    "end-cancel": () => {
      confirm.hidden = true;
      focus();
    },
    "end-confirm": () => {
      confirm.hidden = true;
      end();
    },
  };
  root.querySelectorAll<HTMLElement>("button[data-act]").forEach((b) => {
    b.addEventListener("pointerdown", (e) => {
      if ((e as PointerEvent).pointerType !== "mouse") e.preventDefault();
    });
    b.addEventListener("click", () => actions[b.dataset.act || ""]?.());
  });

  /* Pinch adjusts the font size; one finger scrolls the scrollback (xterm has
     no touch scrolling of its own). */
  let pinch: { d: number; size: number } | null = null;
  let swipe: { y: number; rest: number } | null = null;
  const span = (e: TouchEvent) => Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY);
  screen.addEventListener(
    "touchstart",
    (e) => {
      if (e.touches.length === 2) {
        pinch = { d: span(e), size: termFontSize() };
        swipe = null;
      } else if (e.touches.length === 1) swipe = { y: e.touches[0].clientY, rest: 0 };
    },
    { passive: true },
  );
  screen.addEventListener(
    "touchmove",
    (e) => {
      if (pinch && e.touches.length === 2) {
        e.preventDefault();
        const n = Math.round((pinch.size * span(e)) / pinch.d);
        if (n !== termFontSize()) setFont(n);
        return;
      }
      if (!swipe || e.touches.length !== 1 || !term) return;
      e.preventDefault();
      const y = e.touches[0].clientY;
      const cell = term.element ? term.element.clientHeight / term.rows : 16;
      swipe.rest += swipe.y - y;
      swipe.y = y;
      const lines = Math.trunc(swipe.rest / Math.max(cell, 1));
      if (lines) {
        swipe.rest -= lines * cell;
        term.scrollLines(lines);
      }
    },
    { passive: false },
  );
  screen.addEventListener(
    "touchend",
    (e) => {
      if (e.touches.length < 2) pinch = null;
      if (!e.touches.length) swipe = null;
    },
    { passive: true },
  );

  /* ---- start */
  if (!window.Terminal) {
    setStatus("crit", "Not loaded");
    showBanner("The terminal library did not load. Reload the page.");
    return;
  }
  term = new window.Terminal({
    cursorBlink: true,
    cursorStyle: "block",
    /* a pty already sends CR LF; converting bare LF breaks full-screen programs */
    convertEol: false,
    fontFamily: cssVar("--f-mono", "ui-monospace, Menlo, Consolas, monospace"),
    fontSize: termFontSize(),
    lineHeight: 1.2,
    allowTransparency: false,
    theme: terminalTheme(),
    allowProposedApi: false,
    scrollback: TERM_SCROLLBACK,
    macOptionIsMeta: true,
    rightClickSelectsWord: true,
  });
  if (window.FitAddon) {
    fit = new window.FitAddon.FitAddon();
    term.loadAddon(fit);
  }
  /* Unicode 11 widths (emoji, CJK) need xterm's proposed API for one call. */
  if (window.Unicode11Addon) {
    try {
      term.options.allowProposedApi = true;
      term.loadAddon(new window.Unicode11Addon.Unicode11Addon());
      term.unicode.activeVersion = "11";
    } catch {
      /* widths fall back to Unicode 6 */
    }
    try {
      term.options.allowProposedApi = false;
    } catch {
      /* ignore */
    }
  }
  term.open(screen);
  /* Ctrl+Shift+C copies and Ctrl+Shift+V pastes, as in a desktop terminal;
     plain Ctrl+C stays the shell's interrupt. */
  term.attachCustomKeyEventHandler((e: KeyboardEvent) => {
    if (e.type !== "keydown" || !e.ctrlKey || !e.shiftKey) return true;
    const k = String(e.key || "").toLowerCase();
    if (k === "c") {
      const sel = term.getSelection();
      if (sel) navigator.clipboard?.writeText?.(sel).catch(() => undefined);
      e.preventDefault();
      return false;
    }
    if (k === "v") {
      e.preventDefault();
      pasteFromClipboard();
      return false;
    }
    return true;
  });
  let selTimer = 0;
  term.onSelectionChange(() => {
    clearTimeout(selTimer);
    selTimer = window.setTimeout(() => {
      const sel = term && term.getSelection();
      if (sel) navigator.clipboard?.writeText?.(sel).catch(() => undefined);
    }, 200);
  });
  term.onData((data: string) => {
    if (ctrlArmed && data.length === 1) {
      data = termCtrlChar(data) || data;
      setCtrl(false);
    }
    input(data);
  });
  term.onBinary((data: string) => input(data));
  screen.addEventListener("click", focus);
  new ResizeObserver(fitSoon).observe(screen);
  try {
    fit?.fit();
  } catch {
    /* fitted again once laid out */
  }
  focus();
  connect(!fresh);
}

const form = $("term-open");
if (form instanceof HTMLFormElement) openForm(form);
const view = $("term");
if (view) sessionView(view);
