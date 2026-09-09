// Actual browser workers on the loopback fixture; never an installed production app.
const assert = require('node:assert/strict');
module.exports = async function workerLifecycle(page, context, server, url) {
 assert.ok(server, 'Lifecycle tests require an owned fixture origin');
 let other;
 const appURL=url.replace("?demo=true", "?demo=true&pwa-fixture=true");
 try {
  await page.evaluate(async () => {
   await caches.open('unrelated-fixture-cache');
   await caches.open('ominull-shell-vobsolete');

  });
  await page.goto(appURL);
  await page.waitForFunction(() => !!navigator.serviceWorker.controller && !!window.audit);
  assert.deepEqual((await page.evaluate(() => caches.keys())).sort(),
   ['ominull-shell-vfixture', 'unrelated-fixture-cache']);
  other = await context.newPage();
  await other.goto(appURL);
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
  await page.locator('#pwa-update').waitFor();
  await page.evaluate(() => {
   window.audit.openSheet('Current window draft', window.audit.h('input', {value:'keep this draft'}));
   document.querySelector('.sheet input').dispatchEvent(new Event('input',{bubbles:true}));
  });
  // Programmatic click exercises navigation guard; normal modal focus keeps the
  // update control behind the dialog inaccessible until the dialog is closed.
  await page.locator('#pwa-update').evaluate(button=>button.click());
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  assert.equal(await page.locator('.sheet input').inputValue(),'keep this draft');
  await page.locator('#pwa-update').evaluate(button=>button.click());
  await page.getByRole('button',{name:'Leave',exact:true}).click();
  await page.getByText('Close other Ominull windows, then select Update available again.',{exact:true}).waitFor();
  assert.ok(await page.evaluate(async () => !!(await navigator.serviceWorker.getRegistration()).waiting));
  assert.equal(await other.locator('.sheet input').inputValue(), 'unsent draft');
  await other.close(); other = null;
  await page.locator('#pwa-update').click();
  await page.waitForFunction(async () => (await caches.keys()).includes('ominull-shell-vfixture-upgrade') && !(await caches.keys()).includes('ominull-shell-vfixture'));
  await page.waitForFunction(() => !!window.audit && !document.getElementById('pwa-update'));
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
