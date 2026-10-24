const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const esbuild = require(path.join(__dirname, '../../../../web-build/node_modules/esbuild'));

const ts = esbuild.transformSync(fs.readFileSync(path.join(__dirname, '../web-src/keys.ts'), 'utf8'), {loader: 'ts', format: 'cjs'}).code;
const load = () => { const m = {exports: {}}; vm.runInContext(ts, vm.createContext({module: m, exports: m.exports})); return m.exports; };

test('keys.ts: extra keys map to the bytes a terminal sends', () => {
 const c = load();
 assert.equal(c.termKeyBytes('esc'), '\x1b');
 assert.equal(c.termKeyBytes('tab'), '\t');
 assert.equal(c.termKeyBytes('up', false, false), '\x1b[A');
 assert.equal(c.termKeyBytes('up', false, true), '\x1bOA');
 assert.equal(c.termKeyBytes('left', true, true), '\x1b[1;5D');
 assert.equal(c.termKeyBytes('pipe'), '|');
 assert.equal(c.termKeyBytes('pgdn'), '\x1b[6~');
 assert.equal(c.termKeyBytes('nope'), '');
 assert.equal(c.termCtrlChar('c'), '\x03');
 assert.equal(c.termCtrlChar('C'), '\x03');
 assert.equal(c.termCtrlChar('['), '\x1b');
 assert.equal(c.termCtrlChar(' '), '\x00');
 assert.equal(c.termCtrlChar('?'), '\x7f');
 assert.equal(c.termCtrlChar('1'), '');
});
