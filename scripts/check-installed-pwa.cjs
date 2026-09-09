// Actual Chromium installation in the ephemeral CI desktop, never the operator's
// browser/profile. PWA domain: https://chromedevtools.github.io/devtools-protocol/tot/PWA/
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),assert=require('node:assert/strict');
if(process.env.GITHUB_ACTIONS!=='true')throw Error('Installed app checks require the isolated CI desktop');
const {chromium}=require('../web-build/node_modules/playwright');
(async()=>{
 const server=require('../hub/pkg/server/web_tests/fixture-server.cjs');
 await new Promise(r=>server.listening?r():server.once('listening',r));
 const profile=fs.mkdtempSync(path.join(os.tmpdir(),'ominull-installed-fixture-'));
 const origin='http://127.0.0.1:18764/';const appURL=origin+'?demo=true&pwa-fixture=true#/assets';
 let context;const evidence={platform:process.platform,display:'isolated Xvfb desktop',checks:[]};
 async function launch(){
  const cdp=await context.browser().newBrowserCDPSession();
  const pages=context.pages();
  const [page,result]=await Promise.all([context.waitForEvent('page'),cdp.send('PWA.launch',{manifestId:origin,url:appURL})]);
  await page.waitForLoadState();
  assert.ok(!pages.includes(page));evidence.checks.push({launch_target:!!result.targetId});
  await cdp.detach();return page;
 }
 try {
  context=await chromium.launchPersistentContext(profile,{headless:false,viewport:{width:1280,height:800}});
  const tab=context.pages()[0];await tab.goto(appURL);await tab.waitForFunction(()=>!!window.audit && !!navigator.serviceWorker.controller);
  const cdp=await context.browser().newBrowserCDPSession();
  await cdp.send('PWA.install',{manifestId:origin,installUrlOrBundleUrl:appURL});
  evidence.installed_state=await cdp.send('PWA.getOsAppState',{manifestId:origin});
  const app=await launch();
  assert.equal(await app.evaluate(()=>matchMedia('(display-mode: standalone)').matches),true);
  await tab.close();
  await require('../hub/pkg/server/web_tests/worker-browser.cjs')(app,context,server,appURL,launch);
  evidence.checks.push({installed_multiwindow_upgrade:true,anonymous_offline_reload:true});
  await context.close();context=null;
  server.offline=true;
  context=await chromium.launchPersistentContext(profile,{headless:false,viewport:{width:1280,height:800}});
  const restarted=await launch();
  assert.equal(await restarted.title(),'Ominull — Offline');
  assert.doesNotMatch(await restarted.content(),/AUDIT_SENTINEL|fixture@example/);
  evidence.checks.push({offline_restart:true,standalone:await restarted.evaluate(()=>matchMedia('(display-mode: standalone)').matches)});
  assert.equal(evidence.checks.at(-1).standalone,true);
  evidence.passed=true;
 }catch(error){evidence.passed=false;evidence.error=error.message;throw error;}
 finally{
  fs.mkdirSync('build',{recursive:true});fs.writeFileSync('build/installed-pwa.json',JSON.stringify(evidence,null,2));
  if(context)await context.close();server.close();
 }
})().catch(error=>{console.error(error);process.exitCode=1;});
