const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
function worker(){
 const handlers={},stored=new Map(),deleted=[],precached=[];
 const cache={addAll:async paths=>precached.push(...paths),put:async(key,value)=>stored.set(key,value),match:async key=>stored.get(key)};
 const context={URL,Response,Promise,fetch:async request=>new Response(typeof request === 'string' ? 'public asset' : '<html>Sentinel operator</html>',{headers:{'content-type':typeof request === 'string' ? 'application/javascript' : 'text/html'}}),caches:{open:async()=>cache,keys:async()=>['unrelated-cache','ominull-shell-vold'],delete:async key=>deleted.push(key),match:cache.match},self:{location:{origin:'https://fixture.test'},addEventListener:(key,fn)=>handlers[key]=fn,skipWaiting:async()=>{},clients:{claim:async()=>{}}}};
 vm.runInNewContext(fs.readFileSync(require('node:path').join(__dirname,'../web/sw.js'),'utf8'),context);
 return {handlers,context,stored,deleted,precached};
}
function dispatch(w,name,extra={}){let promise;w.handlers[name]({...extra,waitUntil:p=>promise=p,respondWith:p=>promise=p});return promise;}
test('install never precaches personalized root document',async()=>{const w=worker();await dispatch(w,'install');assert.ok(!w.stored.has('/'));});
test('upgrade preserves other applications caches',async()=>{const w=worker();await dispatch(w,'activate');assert.deepEqual(w.deleted,['ominull-shell-vold']);});
test('navigation never caches personalized HTML',async()=>{const w=worker();await dispatch(w,'fetch',{request:{url:'https://fixture.test/',method:'GET',mode:'navigate'}});await Promise.resolve();assert.equal(w.stored.size,0);});
test('cold offline navigation returns a credential-free response',async()=>{const w=worker();w.context.fetch=async()=>{throw Error('offline');};const response=await dispatch(w,'fetch',{request:{url:'https://fixture.test/',method:'GET',mode:'navigate'}});assert.ok(response instanceof Response);assert.match(await response.text(),/offline/i);});

test('install refuses an HTML authentication response under an asset URL',async()=>{const w=worker();w.context.fetch=async()=>new Response('<html>Sign in</html>',{headers:{'content-type':'text/html'}});await assert.rejects(dispatch(w,'install'));assert.equal(w.stored.size,0);});
