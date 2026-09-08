// Run through the managed browser on an authenticated topology route:
// st browser --local-ai eval --stdin < scripts/verify-topology-drill.js
(async () => {
  const assert = (ok, message) => {
    if (!ok) throw Error(message);
  };
  const waitFor = async (fn) => {
    for (let i = 0; i < 100; i++) {
      if (fn()) return;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw Error("UI did not settle");
  };
  const canvas = document.querySelector(".tg-canvas"),
    cy = canvas?._cyreg?.cy;
  assert(cy && cy.nodes().length, "No graph rows found");
  assert(!document.querySelector(".tg-inspector"), "Sidebar remains");
  const btn = (name) =>
    [...document.querySelectorAll(".tg-button")].find(
      (b) => b.textContent === name,
    );
  if (btn("Graph view")) btn("Graph view").click();
  const crumb = document.querySelector(".tg-crumbs").textContent;
  const r = canvas.getBoundingClientRect(),
    x = r.x + r.width * 0.42,
    y = r.y + r.height * 0.45;
  const before = cy.zoom(),
    p = cy.pan(),
    point = { x: (x - r.x - p.x) / before, y: (y - r.y - p.y) / before };
  document
    .elementFromPoint(x, y)
    .dispatchEvent(
      new WheelEvent("wheel", {
        deltaY: before > 2 ? -100 : 100,
        clientX: x,
        clientY: y,
        bubbles: true,
        cancelable: true,
      }),
    );
  assert(cy.zoom() !== before, "Wheel event did not zoom");
  const drift = Math.hypot(
    point.x * cy.zoom() + cy.pan().x + r.x - x,
    point.y * cy.zoom() + cy.pan().y + r.y - y,
  );
  assert(
    drift < 1 && document.querySelector(".tg-crumbs").textContent === crumb,
    "Wheel moved anchor or scope",
  );
  btn("List view").click();
  const inspect = [
    ...document.querySelectorAll(".tg-list button[data-topology-id]"),
  ].find((b) => !b.dataset.topologyId.startsWith("edge:"));
  assert(inspect, "No keyboard drill target");
  const positions = Object.fromEntries(
    cy
      .nodes()
      .filter((n) => !n.isParent())
      .map((n) => [n.id(), { ...n.position() }]),
  );
  const viewport = { zoom: cy.zoom(), pan: { ...cy.pan() } };
  inspect.focus();
  inspect.dispatchEvent(
    new KeyboardEvent("keydown", {
      key: "Enter",
      bubbles: true,
      cancelable: true,
    }),
  );
  await waitFor(
    () => document.querySelector(".tg-crumbs").textContent !== crumb,
  );
  btn("← Back").click();
  assert(
    document.querySelector(".tg-crumbs").textContent === crumb,
    "Back scope changed",
  );
  assert(
    cy.zoom() === viewport.zoom &&
      JSON.stringify(cy.pan()) === JSON.stringify(viewport.pan),
    "Back lost viewport",
  );
  assert(
    Object.entries(positions).every(
      ([id, p]) =>
        Math.hypot(
          cy.getElementById(id).position().x - p.x,
          cy.getElementById(id).position().y - p.y,
        ) < 0.01,
    ),
    "Back lost positions",
  );
  if (btn("Graph view")) btn("Graph view").click();
  return {
    wheelEventZoom: true,
    pointerDrift: drift,
    keyboardDrill: true,
    backPositions: true,
    backViewport: true,
    sidebarRemoved: true,
  };
})();
