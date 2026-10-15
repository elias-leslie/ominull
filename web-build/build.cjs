const esbuild = require("esbuild");
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const minifyConsole = require("./console-minify.cjs");
const root = path.join(__dirname, "../hub/pkg/server/web");
const src = path.join(__dirname, "../hub/pkg/server/web-src");
// The console script (minified), the topology libraries, and the scripts of
// the server-rendered pages.
const bundles = [
  { name: "graph", entry: path.join(__dirname, "graph.cjs"), out: "vendor/topology-graph.js" },
  { name: "layout", entry: path.join(__dirname, "layout.cjs"), out: "vendor/topology-layout.js" },
  { name: "terminal", entry: path.join(src, "terminal.ts"), out: "terminal.js", page: true },
];
const appSource = fs.readFileSync(path.join(root, "app.js"), "utf8");
const outputs = [
  {
    name: "console",
    outfile: path.join(root, "app.min.js"),
    // The source hash lets the Go suite notice an app.js edit without a rebuild.
    contents: Buffer.from(
      minifyConsole(appSource) +
        `/* app.js sha256:${crypto.createHash("sha256").update(appSource).digest("hex")} */\n`,
    ),
  },
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
  outputs.push({ name, outfile, contents });
}
for (const { name, outfile, contents } of outputs) {
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
