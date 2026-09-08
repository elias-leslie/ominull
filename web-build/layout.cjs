const cytoscape = require("cytoscape");
cytoscape.use(require("cytoscape-fcose"));
self.onmessage = function (event) {
  const { id, elements, fixed, viewport } = event.data;
  let cy;
  try {
    cy = cytoscape({
      headless: true,
      styleEnabled: true,
      elements,
      style: [
        { selector: "node", style: { width: 150, height: 50 } },
        { selector: "node[groupNode]", style: { width: 190, height: 74 } },
        { selector: ":parent", style: { padding: 32 } },
      ],
    });
    cy.layout({
      name: "fcose",
      animate: false,
      fit: false,
      quality: "default",
      randomize: true,
      packComponents: false,
      numIter: 700,
      nodeSeparation: 100,
      idealEdgeLength: 100,
      nodeRepulsion: 9000,
      fixedNodeConstraint: fixed || [],
    }).run();
    let compact = false;
    // A wide disconnected overview can fit geometrically while its labels become
    // unreadable. Compact only collapsed groups, never user-pinned layouts.
    if (
      viewport &&
      !(fixed || []).length &&
      cy.nodes().every((n) => n.data("groupNode") && !n.isParent())
    ) {
      const width = Math.max(1, viewport.width - 50);
      const height = Math.max(1, viewport.height - 50);
      const bounds = cy.nodes().boundingBox();
      if (15 * Math.min(width / bounds.w, height / bounds.h) < 11) {
        const nodes = cy.nodes();
        let columns = 1,
          best = 0;
        for (let c = 1; c <= nodes.length; c++) {
          const scale = Math.min(
            width / (c * 230 - 38),
            height / (Math.ceil(nodes.length / c) * 110 - 34),
          );
          if (scale > best) {
            best = scale;
            columns = c;
          }
        }
        nodes.forEach((n, i) => {
          const row = Math.floor(i / columns);
          const rowCount = Math.min(columns, nodes.length - row * columns);
          n.position({
            x: ((i % columns) + (columns - rowCount) / 2) * 230,
            y: row * 110,
          });
        });
        compact = true;
      }
    }
    const positions = {};
    cy.nodes().forEach((n) => {
      positions[n.id()] = n.position();
    });
    self.postMessage({ id, positions, compact });
  } catch (e) {
    self.postMessage({ id, error: String(e.message || e) });
  } finally {
    if (cy) cy.destroy();
  }
};
