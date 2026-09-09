/* Run only against the sanitized fixture. Local Chrome stays in ST's managed
 * headless profile; GitHub CI uses an isolated Playwright browser. */
const fs=require('node:fs'),path=require('node:path'),cp=require('node:child_process');
const root=path.resolve(__dirname,'..');
const suite=fs.readFileSync(path.join(root,'hub/pkg/server/web_tests/console-browser.js'),'utf8');
const url='http://127.0.0.1:18764/?demo=true#/assets';
(async()=>{
 let server;
 try {
  try {await fetch(url);} catch {server=require('../hub/pkg/server/web_tests/fixture-server.cjs');await new Promise(r=>server.listening?r():server.once('listening',r));}
  let results;
  if(process.env.GITHUB_ACTIONS==='true') {
   const {chromium}=require('../web-build/node_modules/playwright');
   const browser=await chromium.launch({headless:true});
   try {const page=await browser.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(url);await page.waitForFunction(()=>window.audit?.state.assets.length>0);results=await page.evaluate(suite);if(errors.length)results.push({name:'browser runtime',pass:false,error:errors.join('; ')});} finally {await browser.close();}
  } else {
   cp.execFileSync('st',['browser','open',url],{stdio:'ignore'});
   cp.execFileSync('st',['browser','eval',`(async()=>{if(location.origin!=='http://127.0.0.1:18764')throw Error('Fixture origin required');await Promise.all((await navigator.serviceWorker.getRegistrations()).map(r=>r.unregister()));await Promise.all((await caches.keys()).filter(k=>k.startsWith('ominull-shell-v')).map(k=>caches.delete(k)));})()`],{stdio:'ignore'});
   cp.execFileSync('st',['browser','reload'],{stdio:'ignore'});
   const output=cp.execFileSync('st',['browser','eval',suite],{encoding:'utf8',maxBuffer:1024*1024});
   const detail=output.match(/details:([^|\s]+)/);
   results=JSON.parse(detail?fs.readFileSync(path.resolve(root,detail[1]),'utf8'):output);
  }
  for(const result of results) console.log(`${result.pass?'PASS':'FAIL'} ${result.name}${result.error?': '+result.error:''}`);
  if(results.some(result=>!result.pass))process.exitCode=1;
 } finally {if(server)server.close();}
})().catch(error=>{console.error(error.message);process.exitCode=1;});
