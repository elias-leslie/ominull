/* Owner approval and terminal key helpers, with no DOM in them, so
   web_tests/approval-flow.test.cjs runs them in Node. app.js carries the same
   flow for the views still inside it; the test holds both to the same cases.

   Isolation, release, mesh quarantine, agent updates and terminal shells wait
   for the owner. The hub answers the first POST with 202 and an approval id,
   the owner approves on their phone with one passkey tap, and the identical
   body is sent again with X-Approval-ID. The hub checks the body against what
   was approved, so nothing here can widen it. */

export const APPROVAL_POLL_WAIT_S = 12;

export type ApprovalState = "pending" | "approved" | "done" | "denied" | "expired" | "consumed" | "cancelled" | "gone" | string;

export interface ApprovalInfo {
  id: string;
  state: ApprovalState;
  summary: string;
  expires_at: string;
}

export interface PostResult {
  status: number;
  body: any;
}

export interface ApprovalDeps {
  post(headers: Record<string, string>): Promise<PostResult>;
  poll(id: string): Promise<{ state?: string; expires_at?: string }>;
  sleep(ms: number): Promise<void>;
  now(): number;
  cancelled(): boolean;
  onState(info: ApprovalInfo): void;
}

export const APPROVAL_TEXT: Record<string, string> = {
  denied: "Denied on your phone. Nothing was changed.",
  expired: "The approval request expired before it was approved. Nothing was changed.",
  consumed: "That approval was already used. Request it again.",
  cancelled: "Stopped waiting. The request on your phone expires on its own; approving it now does nothing.",
  gone: "The hub no longer knows this approval request. Nothing was changed.",
};

export interface ApprovalError extends Error {
  approvalState?: string;
  approval?: ApprovalInfo;
  handled?: boolean;
  status?: number;
}

export function approvalError(st: string, info: ApprovalInfo): ApprovalError {
  const e: ApprovalError = new Error(APPROVAL_TEXT[st] || "Approval " + st + ". Nothing was changed.");
  e.approvalState = st;
  e.approval = info;
  e.handled = true;
  return e;
}

/* Resolves with the success body, rejects with the hub's error or an
   approvalError. Never re-posts a denied, expired or used approval. */
export function approvalFlow(deps: ApprovalDeps): Promise<any> {
  return deps.post({}).then((first) => {
    const b = first && first.body;
    if (!first || first.status !== 202 || !b || !b.approval_id) return b;
    const info: ApprovalInfo = { id: String(b.approval_id), state: "pending", summary: b.summary || "", expires_at: b.expires_at || "" };
    deps.onState(info);
    let failures = 0;
    const setState = (next: string) => {
      if (next !== info.state) {
        info.state = next;
        deps.onState(info);
      }
    };
    const step = (): Promise<any> => {
      if (deps.cancelled()) {
        setState("cancelled");
        return Promise.reject(approvalError("cancelled", info));
      }
      const exp = Date.parse(info.expires_at);
      if (exp && deps.now() > exp + 2000) {
        setState("expired");
        return Promise.reject(approvalError("expired", info));
      }
      const started = deps.now();
      return deps.poll(info.id).then(
        (st) => {
          failures = 0;
          if (deps.cancelled()) {
            setState("cancelled");
            return Promise.reject(approvalError("cancelled", info));
          }
          if (st && st.expires_at) info.expires_at = st.expires_at;
          const next = (st && st.state) || "pending";
          if (next === "approved") {
            setState("approved");
            return deps.post({ "X-Approval-ID": info.id }).then((res) => {
              if (res && res.status === 202) {
                setState("consumed");
                throw approvalError("consumed", info);
              }
              setState("done");
              return res && res.body;
            });
          }
          if (next !== "pending") {
            setState(next);
            return Promise.reject(approvalError(next, info));
          }
          const spent = deps.now() - started;
          return (spent < 1500 ? deps.sleep(1500 - spent) : Promise.resolve()).then(step);
        },
        (err: ApprovalError) => {
          if (err && (err.status === 404 || err.status === 410)) {
            setState("gone");
            throw approvalError("gone", info);
          }
          if (err && err.status === 403) throw err;
          failures++;
          return deps.sleep(Math.min(5000, 500 * Math.pow(2, failures))).then(step);
        },
      );
    };
    return step();
  });
}

export function approvalCountdown(expiresAt: string, now: number): string {
  const ms = Date.parse(expiresAt) - now;
  if (!(ms > 0)) return "expiring";
  const s = Math.round(ms / 1000);
  return "expires in " + Math.floor(s / 60) + ":" + String(s % 60).padStart(2, "0");
}

/* Bytes for the extra key row. appCursor is DECCKM (vim, less, htop): arrows
   are ESC O x there and ESC [ x elsewhere; with Ctrl they carry the xterm
   modifier ;5. */
const TERM_KEYS: Record<string, string> = {
  esc: "\x1b", tab: "\t", up: "A", down: "B", right: "C", left: "D",
  home: "\x1b[H", end: "\x1b[F", pgup: "\x1b[5~", pgdn: "\x1b[6~",
  pipe: "|", tilde: "~", slash: "/", dash: "-",
};

export function termKeyBytes(name: string, ctrl: boolean, appCursor: boolean): string {
  const v = TERM_KEYS[name];
  if (v === undefined) return "";
  if (v.length === 1 && /[ABCD]/.test(v)) {
    if (ctrl) return "\x1b[1;5" + v;
    return (appCursor ? "\x1bO" : "\x1b[") + v;
  }
  if (ctrl && v.length === 1) return termCtrlChar(v) || v;
  return v;
}

/* What a sticky Ctrl does to the next typed character: letters and
   @ [ \ ] ^ _ map to C0 controls, space and 2 to NUL, ? to DEL. Anything else
   goes through unchanged. */
export function termCtrlChar(ch: string): string {
  if (!ch || ch.length !== 1) return "";
  const c = ch.charCodeAt(0);
  if (c >= 97 && c <= 122) return String.fromCharCode(c - 96);
  if (c >= 64 && c <= 95) return String.fromCharCode(c - 64);
  if (ch === " " || ch === "2") return "\x00";
  if (ch === "?") return "\x7f";
  return "";
}
