/* Run only against the sanitized fixture. Local Chrome stays in ST's managed
 * headless profile; GitHub CI uses an isolated Playwright browser. */
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process');
const root=path.resolve(__dirname,'..');
const suite=fs.readFileSync(path.join(root,'hub/pkg/server/web_tests/console-browser.js'),'utf8');
const performanceSuite=fs.readFileSync(path.join(root,'hub/pkg/server/web_tests/console-performance.js'),'utf8');
const url='http://127.0.0.1:18764/?demo=true#/assets';
(async()=>{
 let server;
 try {
  try {await fetch(url);} catch {server=require('../hub/pkg/server/web_tests/fixture-server.cjs');await new Promise(r=>server.listening?r():server.once('listening',r));}
  let results, performanceResults;
  if(process.env.GITHUB_ACTIONS==='true') {
   const engine=process.env.OMINULL_TEST_BROWSER || 'chromium';
   if(!['chromium','firefox','webkit'].includes(engine))throw Error('Unsupported fixture browser: '+engine);
   const playwright=require('../web-build/node_modules/playwright');
   const browser=await playwright[engine].launch({headless:true});
   console.log('Fixture browser: '+engine+' '+browser.version());
   const context=await browser.newContext();
   const page=await context.newPage();
   try {
    await page.context().tracing.start({screenshots:true,snapshots:true});
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(url);await page.waitForFunction(()=>window.audit?.state.assets.length>0);
    results=await page.evaluate(suite);
    const {default:AxeBuilder}=require('../web-build/node_modules/@axe-core/playwright');
    const accessibility=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();
    results.push({name:'Assets WCAG A/AA automation',pass:accessibility.violations.length===0,error:accessibility.violations.map(v=>v.id).join(', ')});
    performanceResults=await page.evaluate(performanceSuite);
    fs.mkdirSync(path.join(root,'build'),{recursive:true});
    fs.writeFileSync(path.join(root,'build/console-performance.json'),JSON.stringify({engine,version:browser.version(),...performanceResults},null,2));
    if(errors.length)results.push({name:'browser runtime',pass:false,error:errors.join('; ')});
    if(results.some(r=>!r.pass)) {fs.mkdirSync(path.join(root,'build'),{recursive:true});await page.screenshot({path:path.join(root,'build/console-failure.png'),fullPage:true});}
   } catch(error) {
    fs.mkdirSync(path.join(root,'build'),{recursive:true});
    await page.screenshot({path:path.join(root,'build/console-failure.png'),fullPage:true});
    throw error;
   } finally {
    fs.mkdirSync(path.join(root,'build'),{recursive:true});
    await context.tracing.stop({path:path.join(root,'build/console-trace.zip')});
    await browser.close();
   }
  } else {
   cp.execFileSync('st',['browser','open',url],{stdio:'ignore'});
   cp.execFileSync('st',['browser','eval',`(async()=>{if(location.origin!=='http://127.0.0.1:18764')throw Error('Fixture origin required');await Promise.all((await navigator.serviceWorker.getRegistrations()).map(r=>r.unregister()));await Promise.all((await caches.keys()).filter(k=>k.startsWith('ominull-shell-v')).map(k=>caches.delete(k)));})()`],{stdio:'ignore'});
   cp.execFileSync('st',['browser','reload'],{stdio:'ignore'});
   const output=cp.execFileSync('st',['browser','eval',suite],{encoding:'utf8',maxBuffer:1024*1024});
   const detail=output.match(/details:([^|\s]+)/);
   results=JSON.parse(detail?fs.readFileSync(path.resolve(root,detail[1]),'utf8'):output);
   const perfOutput=cp.execFileSync('st',['browser','eval',performanceSuite],{encoding:'utf8',maxBuffer:1024*1024});
   const perfDetail=perfOutput.match(/details:([^|\s]+)/);
   performanceResults=JSON.parse(perfDetail?fs.readFileSync(path.resolve(root,perfDetail[1]),'utf8'):perfOutput);
  }
  const large=performanceResults.results.find(r=>r.assets===1007);
  // A conservative shared-runner budget; the recorded reference target is
  // 100ms. Timing is secondary to the deterministic mounted-row bound.
  results.push({name:'1007 assets: <=100 mounted rows',pass:!!large && large.mountedRows<=100});
  if(!process.env.OMINULL_TEST_BROWSER || process.env.OMINULL_TEST_BROWSER==='chromium')
   results.push({name:'Chromium: <250ms render budget',pass:!!large && Math.max(...large.renders)<250});
  for(const result of results) console.log(`${result.pass?'PASS':'FAIL'} ${result.name}${result.error?': '+result.error:''}`);
  if(results.some(result=>!result.pass))process.exitCode=1;
 } finally {if(server)server.close();}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
