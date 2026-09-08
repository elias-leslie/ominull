const esbuild = require("esbuild");
const fs = require("node:fs");
const path = require("node:path");
const root = path.join(__dirname, "../hub/pkg/server/web");
for (const name of ["graph", "layout"]) {
  const outfile = path.join(root, `vendor/topology-${name}.js`);
  const result = esbuild.buildSync({
    entryPoints: [path.join(__dirname, `${name}.cjs`)],
    bundle: true,
    minify: true,
    legalComments: "eof",
    outfile,
    platform: "browser",
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
        `Stale topology bundle: run npm --prefix web-build run build (${name})`,
      );
    }
  } else {
    fs.writeFileSync(outfile, contents);
  }
}
