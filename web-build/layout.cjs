const cytoscape = require("cytoscape");
cytoscape.use(require("cytoscape-fcose"));
self.onmessage = function (event) {
  const { id, elements, fixed } = event.data;
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
    const positions = {};
    cy.nodes().forEach((n) => {
      positions[n.id()] = n.position();
    });
    self.postMessage({ id, positions });
  } catch (e) {
    self.postMessage({ id, error: String(e.message || e) });
  } finally {
    if (cy) cy.destroy();
  }
};
