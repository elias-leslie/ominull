/* The evidence page's script (pages/evidence.tmpl, ?id= view): puts a bundle
   on legal hold or releases it, then reloads the server-rendered page. Built
   into web/evidence.js by web-build/build.cjs. */

const $ = (id: string) => document.getElementById(id);

/* Every call carries the console session cookie; the page never holds a key. */
async function setHold(bundleID: string, hold: boolean, reason: string): Promise<void> {
  const res = await fetch("/api/v1/evidence/bundles/hold", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ bundle_id: bundleID, hold, reason }),
  });
  if (res.ok) return;
  let message = "The hub answered " + res.status;
  try {
    const body = await res.json();
    if (body && body.error) message = body.error;
  } catch {
    /* keep the status */
  }
  throw new Error(message);
}

const bundle = $("bundle");
const problem = $("hold-problem");
const send = (hold: boolean, reason: string, buttons: HTMLButtonElement[]) => {
  if (!bundle || !problem) return;
  buttons.forEach((b) => (b.disabled = true));
  problem.hidden = true;
  setHold(bundle.dataset.id || "", hold, reason)
    .then(() => location.reload())
    .catch((err: Error) => {
      problem.textContent = (hold ? "The hold was not set: " : "The hold was not released: ") + err.message;
      problem.hidden = false;
      buttons.forEach((b) => (b.disabled = false));
    });
};

const form = $("hold-form") as HTMLFormElement | null;
const apply = $("hold-apply") as HTMLButtonElement | null;
const reason = $("hold-reason") as HTMLInputElement | null;
if (form && apply) {
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    send(true, (reason && reason.value.trim()) || "", [apply]);
  });
}

/* While the agent is still sending, reload now and then so the page shows
   the bundle sealed, unless the owner is typing a reason or deciding on a
   release. */
if (bundle && bundle.dataset.arriving) {
  setInterval(() => {
    if (document.visibilityState === "hidden") return;
    const deciding = $("hold-confirm");
    if ((reason && (reason.value || document.activeElement === reason)) || (deciding && !deciding.hidden)) return;
    location.reload();
  }, 5000);
}

const release = $("hold-release") as HTMLButtonElement | null;
const confirm = $("hold-confirm");
const keep = $("hold-keep") as HTMLButtonElement | null;
const go = $("hold-release-confirm") as HTMLButtonElement | null;
if (release && confirm && keep && go) {
  const close = () => {
    confirm.hidden = true;
    release.hidden = false;
    release.focus();
  };
  release.addEventListener("click", () => {
    confirm.hidden = false;
    release.hidden = true;
    keep.focus();
  });
  keep.addEventListener("click", close);
  confirm.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !keep.disabled) close();
  });
  go.addEventListener("click", () => send(false, "", [go, keep]));
}
