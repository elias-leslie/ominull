// Dedicated isolated CI run. It measures a throttled headless console, not OS
// installation integration or physical battery consumption.
const fs=require('node:fs'),path=require('node:path');
if(process.env.GITHUB_ACTIONS!=='true')throw Error('Use isolated CI for this browser soak');
const {chromium}=require('../web-build/node_modules/playwright');
(async()=>{
 const server=require('../hub/pkg/server/web_tests/fixture-server.cjs');
 await new Promise(r=>server.listening?r():server.once('listening',r));
 const browser=await chromium.launch({headless:true});
 const page=await browser.newPage({viewport:{width:1280,height:720}});
 const errors=[],samples=[];page.on('pageerror',e=>errors.push(e.message));
 try {
 const cdp=await page.context().newCDPSession(page);
 await cdp.send('Emulation.setCPUThrottlingRate',{rate:4});
 await cdp.send('Network.enable');
 await cdp.send('Network.emulateNetworkConditions',{offline:false,latency:150,downloadThroughput:187500,uploadThroughput:93750});
 await page.goto('http://127.0.0.1:18764/?demo=true#/assets');await page.waitForFunction(()=>window.audit?.state.assets.length);
 await page.evaluate(fs.readFileSync(path.join(__dirname,'../hub/pkg/server/web_tests/console-performance.js'),'utf8'));
 await page.evaluate(()=>{window.soakTasks=[];new PerformanceObserver(list=>{for(const e of list.getEntries()) window.soakTasks.push(e.duration);}).observe({type:'longtask',buffered:false});});
 const start=Date.now();
 while(Date.now()-start<30*60*1000){
  const measurement=await page.evaluate(()=>{
   const a=window.audit,start=performance.now();a.state.assetSort={col:3,dir:'asc'};a.render();
   const sort=performance.now()-start;
   a.openRoute(a.state.assets[0].key);for(let i=0;i<3;i++)a.renderRoute();a.closeRoute();
   return {sort_ms:sort,mountedRows:document.querySelectorAll('#view tr.row').length,assets:a.state.assets.length};
  });
  await cdp.send('HeapProfiler.collectGarbage');
  samples.push({elapsed_ms:Date.now()-start,...measurement,...await cdp.send('Memory.getDOMCounters'),heap:await cdp.send('Runtime.getHeapUsage')});
  await new Promise(r=>setTimeout(r,15000));
 }
 const longTasks=await page.evaluate(()=>window.soakTasks);
 const result={browser:browser.version(),viewport:[1280,720],cpu_slowdown:4,network:{latency_ms:150,download_bytes_per_second:187500},duration_ms:Date.now()-start,installed_app:false,physical_battery_measured:false,errors,longTasks,samples};
 fs.mkdirSync('build',{recursive:true});fs.writeFileSync('build/console-soak.json',JSON.stringify(result,null,2));
 if(errors.length || samples.some(s=>s.mountedRows>100))throw Error('Runtime error or mounted row bound exceeded');
 console.log(JSON.stringify({duration_ms:result.duration_ms,samples:samples.length,first:samples[0],last:samples.at(-1),long_tasks:longTasks.length}));
 }finally{await browser.close();server.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
