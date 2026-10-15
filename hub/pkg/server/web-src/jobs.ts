/* The response job page's script (pages/jobs.tmpl, ?id= view). It cancels
   the job, copies its output, and reloads the page when an open job changes,
   so the server-rendered view stays the one source of what is shown. Built
   into web/jobs.js by web-build/build.cjs. */

const POLL_MS = 3000;

const $ = (id: string) => document.getElementById(id);

/* Every call carries the console session cookie; the page never holds a key. */
async function api(path: string, method = "GET", body?: unknown): Promise<any> {
  const res = await fetch(path, {
    method,
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let parsed: any = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  if (!res.ok) throw new Error((parsed && parsed.error) || "The hub answered " + res.status);
  return parsed;
}

function watch(card: HTMLElement): void {
  const id = card.dataset.id || "";
  const live = $("job-live");
  // Times compare as instants, so a formatting difference between the page
  // and the API cannot make the page reload forever.
  const seenAt = Date.parse(card.dataset.updated || "");
  let failures = 0;
  let changed = false;
  const say = (text: string) => {
    if (live) live.textContent = text;
  };
  // A reload must not throw away a cancel the owner is deciding on, or text
  // they are selecting in the output; then the page says so instead.
  const busy = () => {
    const confirm = $("job-confirm");
    const sel = document.getSelection();
    return (confirm && !confirm.hidden) || (sel && !sel.isCollapsed && sel.toString().length > 0);
  };
  const tick = () => {
    if (document.visibilityState === "hidden" || changed) return;
    api("/api/v1/response/jobs?id=" + encodeURIComponent(id))
      .then((job) => {
        if (failures >= 3) say("this page updates when the job changes");
        failures = 0;
        if (!job || (job.state === card.dataset.state && Date.parse(job.updated_at) === seenAt)) return;
        if (!busy()) return location.reload();
        changed = true;
        say("the job has changed; reload to see it");
      })
      .catch((err: Error) => {
        failures++;
        if (failures === 3) say("stopped updating (" + err.message + "); reload to try again");
      });
  };
  setInterval(tick, POLL_MS);
  document.addEventListener("visibilitychange", tick);
}

function cancel(card: HTMLElement): void {
  const open = $("job-cancel") as HTMLButtonElement | null;
  const confirm = $("job-confirm");
  const keep = $("job-cancel-keep") as HTMLButtonElement | null;
  const go = $("job-cancel-confirm") as HTMLButtonElement | null;
  const problem = $("job-cancel-problem");
  if (!open || !confirm || !keep || !go || !problem) return;
  open.addEventListener("click", () => {
    confirm.hidden = false;
    open.hidden = true;
    keep.focus();
  });
  const close = () => {
    confirm.hidden = true;
    open.hidden = false;
    open.focus();
  };
  keep.addEventListener("click", close);
  confirm.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !keep.disabled) close();
  });
  go.addEventListener("click", () => {
    go.disabled = keep.disabled = true;
    problem.hidden = true;
    api("/api/v1/response/jobs/cancel", "POST", { job_id: card.dataset.id })
      .then(() => location.reload())
      .catch((err: Error) => {
        problem.textContent = "The job was not cancelled: " + err.message;
        problem.hidden = false;
        go.disabled = keep.disabled = false;
      });
  });
}

function copyButtons(): void {
  document.querySelectorAll<HTMLButtonElement>("button[data-copy]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const text = $(btn.dataset.copy || "")?.textContent || "";
      const done = (label: string) => {
        btn.textContent = label;
        setTimeout(() => (btn.textContent = "Copy"), 1500);
      };
      if (!navigator.clipboard) return done("Select and copy");
      navigator.clipboard.writeText(text).then(
        () => done("Copied"),
        () => done("Select and copy"),
      );
    });
  });
}

const card = $("job");
if (card) {
  copyButtons();
  cancel(card);
  if (card.dataset.open) watch(card);
}
