(async () => {
  const host = document.createElement("div");
  host.style.cssText = "position:fixed;inset:0;z-index:9999;background:#111";
  document.body.append(host);
  const nodes = Array.from({ length: 1500 }, (_, i) => ({
    data: { id: "n" + i, display: "Host " + i },
    position: { x: (i % 50) * 180, y: Math.floor(i / 50) * 100 },
  }));
  const edges = Array.from({ length: 3000 }, (_, i) => ({
    data: {
      id: "e" + i,
      source: "n" + (i % 1500),
      target: "n" + ((i * 17 + 1) % 1500),
      width: 1,
    },
  }));
  const started = performance.now();
  const cy = OminullCytoscape({
    container: host,
    elements: [...nodes, ...edges],
    layout: { name: "preset" },
    style: [
      {
        selector: "node",
        style: {
          width: 150,
          height: 50,
          label: "data(display)",
          "background-color": "#375860",
        },
      },
      {
        selector: "edge",
        style: { width: 1, "target-arrow-shape": "triangle" },
      },
    ],
  });
  const w = new Worker("vendor/topology-layout.js");
  const result = await new Promise((resolve) => {
    w.onmessage = async (e) => {
      if (e.data.error) {
        resolve({ error: e.data.error });
        return;
      }
      cy.batch(() =>
        Object.entries(e.data.positions).forEach(([id, p]) =>
          cy.getElementById(id).position(p),
        ),
      );
      cy.fit(undefined, 25);
      await new Promise((r) =>
        requestAnimationFrame(() => requestAnimationFrame(r)),
      );
      resolve({
        elapsedMS: performance.now() - started,
        nodes: cy.nodes().length,
        edges: cy.edges().length,
        positions: Object.keys(e.data.positions).length,
      });
    };
    w.postMessage({ id: 1, elements: [...nodes, ...edges], fixed: [] });
  });
  w.terminate();
  cy.destroy();
  host.remove();
  return JSON.stringify(result);
})();
