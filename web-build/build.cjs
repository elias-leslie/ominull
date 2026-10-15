const esbuild = require("esbuild");
const fs = require("node:fs");
const path = require("node:path");
const root = path.join(__dirname, "../hub/pkg/server/web");
const src = path.join(__dirname, "../hub/pkg/server/web-src");
// The topology libraries, and the scripts of the server-rendered pages.
const bundles = [
  { name: "graph", entry: path.join(__dirname, "graph.cjs"), out: "vendor/topology-graph.js" },
  { name: "layout", entry: path.join(__dirname, "layout.cjs"), out: "vendor/topology-layout.js" },
  { name: "terminal", entry: path.join(src, "terminal.ts"), out: "terminal.js", page: true },
];
for (const { name, entry, out, page } of bundles) {
  const outfile = path.join(root, out);
  const result = esbuild.buildSync({
    entryPoints: [entry],
    bundle: true,
    minify: true,
    legalComments: "eof",
    outfile,
    platform: "browser",
    ...(page ? { format: "iife", target: "es2019" } : {}),
    supported: { "template-literal": false },
    write: false,
  });
  const contents = Buffer.from(result.outputFiles[0].text.replace(/[ \t]+$/gm, ""));
  if (process.argv.includes("--check")) {
    if (
      !fs.existsSync(outfile) ||
      !fs.readFileSync(outfile).equals(Buffer.from(contents))
    ) {
      throw new Error(
        `Stale console bundle: run npm --prefix web-build run build (${name})`,
      );
    }
  } else {
    fs.writeFileSync(outfile, contents);
  }
}
