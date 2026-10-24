/* Terminal key helpers, with no DOM in them, so web_tests/keys.test.cjs runs
   them in Node. */

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
