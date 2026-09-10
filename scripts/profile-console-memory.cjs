// Causal probes for the retained native objects found by the installed soak.
// Fresh isolated CI browser and sanitized fixtures only.
const fs=require('node:fs'),path=require('node:path'),os=require('node:os');
if(process.env.GITHUB_ACTIONS!=='true')throw Error('Use isolated CI for native memory profiling');
const {chromium}=require('../web-build/node_modules/playwright');
(async()=>{
 const server=require('../hub/pkg/server/web_tests/fixture-server.cjs');
 await new Promise(r=>server.listening?r():server.once('listening',r));
 const context=await chromium.launchPersistentContext(fs.mkdtempSync(path.join(os.tmpdir(),'ominull-memory-')),{headless:false,viewport:{width:1280,height:720}});
 const page=context.pages()[0],measurements=[];fs.mkdirSync('build/memory-profile',{recursive:true});
 async function snapshot(page,label){
  const cdp=await context.newCDPSession(page);const file=fs.openSync('build/memory-profile/'+label+'.heapsnapshot','w');
  cdp.on('HeapProfiler.addHeapSnapshotChunk',e=>fs.writeSync(file,e.chunk));
  try{await cdp.send('HeapProfiler.takeHeapSnapshot',{reportProgress:false});measurements.push({label,...await cdp.send('Runtime.getHeapUsage'),...await cdp.send('Memory.getDOMCounters')});}
  finally{fs.closeSync(file);await cdp.detach();}
 }
 try{
  await page.goto('http://127.0.0.1:18764/?demo=true#/assets');await page.waitForFunction(()=>window.audit?.state.assets.length>0);
  const network=await context.newCDPSession(page);await network.send('Network.enable');
  await snapshot(page,'network-before');
  await page.evaluate(async()=>{for(let i=0;i<500;i++)await (await fetch('/memory-fixture-missing?sample='+i)).text();});
  await snapshot(page,'network-retained');await network.send('Network.disable');await snapshot(page,'network-disabled');await network.detach();
  await snapshot(page,'render-before');
  await page.evaluate(()=>{for(let i=0;i<100;i++){window.audit.render();document.body.getBoundingClientRect();}});
  await snapshot(page,'render-after');
  await page.evaluate(()=>{for(let i=0;i<100;i++){window.audit.openRoute(window.audit.state.assets[0].key);window.audit.renderRoute();document.body.getBoundingClientRect();window.audit.closeRoute();}});
  await snapshot(page,'route-after');
  const css=fs.readFileSync(path.join(__dirname,'../hub/pkg/server/web/app.css'),'utf8');
  // Minimal browser controls: no application scripts or stylesheet participate.
  for(const tag of ['div','button','input','select','checkbox','button-css','checkbox-css']){
   const blank=await context.newPage();await blank.goto('about:blank');if(tag.endsWith('-css'))await blank.setContent('<style>'+css+'</style>');await snapshot(blank,tag+'-before');
   await blank.evaluate(tag=>{for(let i=0;i<1000;i++){const e=document.createElement(tag.startsWith('checkbox')?'input':tag.replace('-css',''));if(tag.startsWith('checkbox'))e.type='checkbox';if(tag==='button-css')e.className='btn';e.textContent='fixture';document.body.append(e);e.getBoundingClientRect();e.remove();}},tag);
   await snapshot(blank,tag+'-after');await blank.close();
  }
  fs.writeFileSync('build/memory-profile/measurements.json',JSON.stringify({browser:context.browser().version(),measurements},null,2));
  console.log(JSON.stringify(measurements));
 }finally{await context.close();server.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
