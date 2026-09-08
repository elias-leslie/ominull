/* Run in an already loaded console with:
 * st browser --local-ai eval --stdin < scripts/verify-topology-hover.js
 * Exercises the real five-second refresh. Does not save or change policy.
 */
(async () => {
  const assert = (condition, message) => {
    if (!condition) throw new Error(message);
  };
  const control = (text) =>
    [...document.querySelectorAll(".tg-canvas-tools button")].find(
      (b) => b.textContent === text,
    );
  const wasList = !!control("Graph view");
  if (!wasList) control("List view").click();
  const linkButton = () =>
    [...document.querySelectorAll(".tg-list button")].find((b) =>
      b.dataset.topologyId?.startsWith("edge:"),
    );
  const before = linkButton();
  assert(before, "No drawn link rows found; hover check cannot run");
  const id = before.dataset.topologyId;
  before.focus();
  const tip = document.querySelector(".tg-tooltip");
  assert(
    !tip.hidden && tip.textContent.includes("observations"),
    "Link evidence missing on focus",
  );
  await new Promise((resolve) => setTimeout(resolve, 6200));
  const after = linkButton();
  assert(after !== before, "No real refresh observed");
  assert(
    document.activeElement.dataset.topologyId === id,
    "Refresh lost keyboard focus",
  );
  assert(
    !tip.hidden &&
      document.activeElement.getAttribute("aria-describedby") === tip.id,
    "Refresh lost tooltip evidence",
  );
  document.activeElement.dispatchEvent(
    new KeyboardEvent("keydown", { key: "Escape", bubbles: true }),
  );
  assert(tip.hidden, "Escape did not dismiss tooltip");
  await new Promise((resolve) => setTimeout(resolve, 6200));
  assert(tip.hidden, "Refresh reopened a dismissed tooltip");
  assert(
    document.activeElement.dataset.topologyId === id,
    "Refresh lost dismissed trigger focus",
  );
  if (!wasList) control("Graph view").click();
  return {
    refreshed: true,
    focusRetained: true,
    evidenceRetained: true,
    escapeRetained: true,
  };
})();
