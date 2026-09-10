// Regression for Chromium retaining functional media queries on table rebuilds.
const assert=require('node:assert/strict');
function mediaQueryCount(snapshot){
 const meta=snapshot.snapshot.meta,fields=meta.node_fields,nodes=snapshot.nodes;
 const name=fields.indexOf('name'),type=fields.indexOf('type');let count=0;
 for(let offset=0;offset<nodes.length;offset+=fields.length)
  if(meta.node_types[type][nodes[offset+type]]==='native' && snapshot.strings[nodes[offset+name]]==='blink::MediaQuerySet')count++;
 return count;
}
function assertBounded(before,after){assert.ok(after<=before,`Table renders retained ${after-before} native media queries (${before} -> ${after})`);}
module.exports=async function(page){
 const cdp=await page.context().newCDPSession(page);
 async function count(){let chunks=[];const receive=e=>chunks.push(e.chunk);cdp.on('HeapProfiler.addHeapSnapshotChunk',receive);
  try{await cdp.send('HeapProfiler.takeHeapSnapshot',{reportProgress:false});return mediaQueryCount(JSON.parse(chunks.join('')));}
  finally{cdp.off('HeapProfiler.addHeapSnapshotChunk',receive);}}
 try{
  const before=await count();
  await page.evaluate(()=>{for(let i=0;i<100;i++){window.audit.render();document.body.getBoundingClientRect();}});
  const after=await count();assertBounded(before,after);
  const screen=await page.evaluate(()=>getComputedStyle(document.querySelector('thead')).breakInside);assert.equal(screen,'auto');
  await page.emulateMedia({media:'print'});
  const print=await page.evaluate(()=>getComputedStyle(document.querySelector('thead')).breakInside);assert.equal(print,'avoid');
  await page.emulateMedia({media:'screen'});
  return {renders:100,before,after,screen,print};
 }finally{await cdp.detach();}
};
module.exports.mediaQueryCount=mediaQueryCount;module.exports.assertBounded=assertBounded;
