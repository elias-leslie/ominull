const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const esbuild = require(path.join(__dirname, '../../../../web-build/node_modules/esbuild'));

// The same flow lives in two places while the console moves to pages: the
// approval core inside app.js, and web-src/approval.ts for the page scripts.
// Every case runs against both.
const source = fs.readFileSync(path.join(__dirname, '../web/app.js'), 'utf8');
const core = source.slice(source.indexOf('/* approval-core:start'), source.indexOf('/* approval-core:end */'));
const ts = esbuild.transformSync(fs.readFileSync(path.join(__dirname, '../web-src/approval.ts'), 'utf8'), {loader: 'ts', format: 'cjs'}).code;
const impls = {
 'app.js': () => { const c = vm.createContext({Date, Math, String, Promise}); vm.runInContext(core, c); return c; },
 'approval.ts': () => { const m = {exports: {}}; vm.runInContext(ts, vm.createContext({module: m, exports: m.exports, Date, Math, String, Promise})); return m.exports; },
};

function harness(c, script) {
 // script: list of poll answers; each is a state string or an Error.
 const posts = [], states = [];
 let clock = 0, cancelled = false;
 const deps = {
  post: headers => { posts.push(headers); return Promise.resolve(posts.length === 1 ? script.first : script.second); },
  poll: () => { const next = script.polls.shift(); if (next instanceof Error) return Promise.reject(next); return Promise.resolve({state: next}); },
  sleep: ms => { clock += ms; return Promise.resolve(); },
  now: () => clock,
  cancelled: () => cancelled,
  onState: info => states.push(info.state),
 };
 return {deps, posts, states, cancel: () => { cancelled = true; }};
}

const pending = {status: 202, body: {approval_id: 'a1', state: 'pending', expires_at: ''}};

for (const [name, load] of Object.entries(impls)) {
 test(name + ': a route that is not gated resolves with its body and never polls', async () => {
  const c = load();
  const h = harness(c, {first: {status: 200, body: {ok: 1}}, polls: []});
  assert.deepEqual(await c.approvalFlow(h.deps), {ok: 1});
  assert.equal(h.posts.length, 1);
  assert.deepEqual(h.states, []);
 });

 test(name + ': pending then approved re-posts once with X-Approval-ID and returns the result', async () => {
  const c = load();
  const h = harness(c, {first: pending, second: {status: 201, body: {session_id: 's'}}, polls: ['pending', 'pending', 'approved']});
  assert.deepEqual(JSON.parse(JSON.stringify(await c.approvalFlow(h.deps))), {session_id: 's'});
  assert.equal(h.posts.length, 2);
  assert.deepEqual(JSON.parse(JSON.stringify(h.posts[0])), {});
  assert.deepEqual(JSON.parse(JSON.stringify(h.posts[1])), {'X-Approval-ID': 'a1'});
  assert.deepEqual(h.states, ['pending', 'approved', 'done']);
 });

 for (const st of ['denied', 'expired', 'consumed']) {
  test(`${name}: ${st} rejects without a second post`, async () => {
   const c = load();
   const h = harness(c, {first: pending, polls: ['pending', st]});
   await assert.rejects(c.approvalFlow(h.deps), e => e.approvalState === st && e.handled === true);
   assert.equal(h.posts.length, 1);
  });
 }

 test(name + ': poll failures back off and keep waiting; a 404 ends it as gone', async () => {
  const c = load();
  const h = harness(c, {first: pending, polls: [new Error('net'), new Error('net'), Object.assign(new Error('nf'), {status: 404})]});
  await assert.rejects(c.approvalFlow(h.deps), e => e.approvalState === 'gone');
  assert.equal(h.posts.length, 1);
 });

 test(name + ': stop waiting rejects as cancelled and never posts the approval', async () => {
  const c = load();
  const h = harness(c, {first: pending, polls: ['pending', 'approved']});
  const run = c.approvalFlow(h.deps);
  h.cancel();
  await assert.rejects(run, e => e.approvalState === 'cancelled');
  assert.equal(h.posts.length, 1);
 });

 test(name + ': a hub refusal of the first request is the hub error, not an approval state', async () => {
  const c = load();
  const deps = {post: () => Promise.reject(Object.assign(new Error('no capability'), {status: 409})), poll: () => {}, sleep: () => Promise.resolve(), now: () => 0, cancelled: () => false, onState: () => {}};
  await assert.rejects(c.approvalFlow(deps), e => e.status === 409 && !e.approvalState);
 });

 test(name + ': an approval past its expiry stops polling', async () => {
  const c = load();
  const h = harness(c, {first: {status: 202, body: {approval_id: 'a2', expires_at: new Date(1000).toISOString()}}, polls: ['pending', 'pending', 'pending', 'pending']});
  await assert.rejects(c.approvalFlow(h.deps), e => e.approvalState === 'expired');
 });

 if (name === 'approval.ts') test(name + ': extra keys map to the bytes a terminal sends', () => {
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
}
