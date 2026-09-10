// Dedicated isolated CI desktop run with an installed standalone Chromium app.
// Real loopback fixture HTTP is throttled; physical battery is not measured.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
if(process.env.GITHUB_ACTIONS!=='true')throw Error('Use isolated CI for this browser soak');
const {chromium}=require('../web-build/node_modules/playwright');
(async()=>{
 const server=require('../hub/pkg/server/web_tests/fixture-server.cjs');
 await new Promise(r=>server.listening?r():server.once('listening',r));
 const context=await chromium.launchPersistentContext(fs.mkdtempSync(path.join(os.tmpdir(),'ominull-soak-')),{headless:false,viewport:{width:1280,height:720}});
 const browser=context.browser();
 const origin='http://127.0.0.1:18764/',url=origin+'?demo=true&pwa-fixture=true#/assets';
 const tab=context.pages()[0];await tab.goto(url);await tab.waitForFunction(()=>!!window.audit && !!navigator.serviceWorker.controller);
 const control=await browser.newBrowserCDPSession();
 await control.send('PWA.install',{manifestId:origin,installUrlOrBundleUrl:url});
 await control.send('PWA.changeAppUserSettings',{manifestId:origin,displayMode:'standalone'});
 const [page]=await Promise.all([context.waitForEvent('page'),control.send('PWA.launch',{manifestId:origin,url})]);
 await page.waitForLoadState();await page.waitForFunction(()=>!!window.audit);await tab.close();
 if(!await page.evaluate(()=>matchMedia('(display-mode: standalone)').matches))throw Error('Installed standalone app required');
 const mode=process.env.OMINULL_SOAK_MODE || 'stress';
 if(!['stress','idle','stress-no-observer'].includes(mode))throw Error('Unknown soak mode');
 const errors=[],samples=[],checkpoints=[];page.on('pageerror',e=>errors.push(e.message));
 try {
 const cdp=await page.context().newCDPSession(page);
 await cdp.send('Emulation.setCPUThrottlingRate',{rate:4});
 await cdp.send('Network.enable');
 await cdp.send('Network.emulateNetworkConditions',{offline:false,latency:150,downloadThroughput:187500,uploadThroughput:93750});
 await page.waitForFunction(()=>window.audit?.state.assets.length);
 await page.evaluate(fs.readFileSync(path.join(__dirname,'../hub/pkg/server/web_tests/console-performance.js'),'utf8'));
 server.fixtureData=await page.evaluate(()=>window.audit.setDemoFleet());
 await page.evaluate(async()=>{window.audit.state.demo=false;await window.audit.refresh();});
 await page.evaluate(mode=>{window.soakTasks=[];if(mode==='stress-no-observer')return;new PerformanceObserver(list=>{for(const e of list.getEntries()) window.soakTasks.push(e.duration);}).observe({type:'longtask',buffered:false});},mode);
 fs.mkdirSync('build',{recursive:true});
 async function snapshot(label){
  const file=fs.openSync('build/heap-'+label+'.heapsnapshot','w');
  const chunk=e=>fs.writeSync(file,e.chunk);cdp.on('HeapProfiler.addHeapSnapshotChunk',chunk);
  try{await cdp.send('HeapProfiler.takeHeapSnapshot',{reportProgress:false});}
  finally{cdp.off('HeapProfiler.addHeapSnapshotChunk',chunk);fs.closeSync(file);}
 }
 await snapshot('start');
 const start=Date.now();let nextCheckpoint=5*60*1000;
 while(Date.now()-start<30*60*1000){
  const measurement=await page.evaluate(mode=>{
   const a=window.audit,start=performance.now();if(mode!=='idle'){a.state.assetSort={col:3,dir:'asc'};a.render();}
   const sort=performance.now()-start;
   if(mode!=='idle'){a.openRoute(a.state.assets[0].key);for(let i=0;i<3;i++)a.renderRoute();a.closeRoute();}
   return {sort_ms:sort,mountedRows:document.querySelectorAll('#view tr.row').length,assets:a.state.assets.length};
  },mode);
  if(measurement.assets!==1007 || measurement.mountedRows>100)throw Error('The soak fixture lost its 1007-asset population');
  await cdp.send('HeapProfiler.collectGarbage');
  samples.push({elapsed_ms:Date.now()-start,...measurement,...await cdp.send('Memory.getDOMCounters'),heap:await cdp.send('Runtime.getHeapUsage')});
  if(Date.now()-start>=nextCheckpoint){
   const before=await cdp.send('Runtime.getHeapUsage');
   await cdp.send('HeapProfiler.collectGarbage');await new Promise(r=>setTimeout(r,1000));
   await cdp.send('HeapProfiler.collectGarbage');
   checkpoints.push({elapsed_ms:Date.now()-start,before,after:await cdp.send('Runtime.getHeapUsage')});
   nextCheckpoint+=5*60*1000;
  }
  fs.writeFileSync('build/console-soak.json',JSON.stringify({running:true,mode,installed_app:true,samples,errors,checkpoints},null,2));
  await new Promise(r=>setTimeout(r,15000));
 }
 await snapshot('end');
 const postSnapshotHeap=await cdp.send('Runtime.getHeapUsage');
 const longTasks=await page.evaluate(()=>window.soakTasks);
 const result={mode,checkpoints,postSnapshotHeap,browser:browser.version(),viewport:[1280,720],cpu_slowdown:4,network:{latency_ms:150,download_bytes_per_second:187500},duration_ms:Date.now()-start,installed_app:true,physical_battery_measured:false,errors,longTasks,samples};
 fs.mkdirSync('build',{recursive:true});fs.writeFileSync('build/console-soak.json',JSON.stringify(result,null,2));
 if(errors.length || samples.some(s=>s.mountedRows>100 || s.assets!==1007))throw Error('Runtime error or mounted row bound exceeded');
 console.log(JSON.stringify({duration_ms:result.duration_ms,samples:samples.length,first:samples[0],last:samples.at(-1),long_tasks:longTasks.length}));
 }finally{await browser.close();server.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
