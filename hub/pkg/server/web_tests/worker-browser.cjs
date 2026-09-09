// Actual browser workers on the loopback fixture; never an installed production app.
const assert = require('node:assert/strict');
module.exports = async function workerLifecycle(page, context, server, url) {
 assert.ok(server, 'Lifecycle tests require an owned fixture origin');
 let other;
 try {
  await page.evaluate(async () => {
   await caches.open('unrelated-fixture-cache');
   await caches.open('ominull-shell-vobsolete');
   await navigator.serviceWorker.register('/sw.js');
   await navigator.serviceWorker.ready;
  });
  await page.waitForFunction(() => !!navigator.serviceWorker.controller);
  assert.deepEqual((await page.evaluate(() => caches.keys())).sort(),
   ['ominull-shell-vfixture', 'unrelated-fixture-cache']);
  other = await context.newPage();
  await other.goto(url);
  await other.waitForFunction(() => !!window.audit);
  await other.evaluate(() => {
   window.audit.openSheet('Unsaved fixture', window.audit.h('input', {value:'unsent draft'}));
   document.querySelector('.sheet input').dispatchEvent(new Event('input', {bubbles:true}));
  });
  server.fixtureVersion = 'fixture-upgrade';
  await page.evaluate(async () => {
   window.fixtureRegistration = await navigator.serviceWorker.getRegistration();
   await window.fixtureRegistration.update();
  });
  await page.waitForFunction(() => !!window.fixtureRegistration.waiting);
  await page.evaluate(async () => {
   window.fixtureUpdateBlocked = false;
   navigator.serviceWorker.addEventListener('message', event => {
    if(event.data?.type === 'UPDATE_BLOCKED') window.fixtureUpdateBlocked = true;
   });
   (await navigator.serviceWorker.getRegistration()).waiting.postMessage({type:'ACTIVATE_UPDATE'});
  });
  await page.waitForFunction(() => window.fixtureUpdateBlocked);
  assert.ok(await page.evaluate(async () => !!(await navigator.serviceWorker.getRegistration()).waiting));
  assert.equal(await other.locator('.sheet input').inputValue(), 'unsent draft');
  await other.close(); other = null;
  await page.evaluate(async () => {
   window.fixtureControllerChanged = false;
   navigator.serviceWorker.addEventListener('controllerchange', () => {window.fixtureControllerChanged = true;});
   (await navigator.serviceWorker.getRegistration()).waiting.postMessage({type:'ACTIVATE_UPDATE'});
  });
  await page.waitForFunction(() => window.fixtureControllerChanged);
  // controllerchange can precede completion of activate.waitUntil cleanup.
  await page.waitForFunction(() => navigator.serviceWorker.controller?.state === 'activated');
  assert.deepEqual((await page.evaluate(() => caches.keys())).sort(),
   ['ominull-shell-vfixture-upgrade', 'unrelated-fixture-cache']);
  const cachedPaths = await page.evaluate(async () => {
   const cache = await caches.open('ominull-shell-vfixture-upgrade');
   return (await cache.keys()).map(request => new URL(request.url).pathname);
  });
  assert.ok(!cachedPaths.includes('/') && !cachedPaths.some(path => path.startsWith('/api/')));
  // Close incoming sockets rather than relying on browser offline emulation,
  // which did not stop worker networking in the original managed-browser audit.
  server.offline = true;
  await page.reload();
  assert.equal(await page.title(), 'Ominull — Offline');
  const body = await page.locator('body').innerText();
  assert.match(body, /authenticated identity are unavailable/);
  assert.doesNotMatch(await page.content(), /AUDIT_SENTINEL|fixture@example/);
 } finally {
  server.offline = false;
  if(other) await other.close();
 }
};
