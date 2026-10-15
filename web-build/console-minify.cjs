const esbuild = require("esbuild");
// The single-page console script, minified for serving. app.js stays the
// source of record: tests read it, and the fixture minifies its patched copy
// with this same function so the browser suite runs the shipped shape.
// app.js is one IIFE with no inline handlers in index.html, so renaming
// identifiers inside it is safe.
module.exports = function minifyConsole(source) {
  return esbuild
    .transformSync(source, {
      loader: "js",
      minify: true,
      legalComments: "eof",
      supported: { "template-literal": false },
    })
    .code.replace(/[ \t]+$/gm, "");
};
