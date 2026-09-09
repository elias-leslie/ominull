(async () => {
 const a = window.audit;
 const results = [];
 const wait = () => new Promise(resolve => setTimeout(resolve, 30));
 async function check(name, fn) {
  try { await fn(); results.push({name, pass:true}); }
  catch (e) { results.push({name, pass:false, error:e.message}); }
 }
 function assert(condition, message) { if (!condition) throw new Error(message); }
 a.state.section = 'assets'; a.render();
 await check('all asset comparators accept real row types and retain sort focus', () => {
  for (let col=2; col<=9; col++) for (const dir of ['asc','desc']) { a.state.assetSort={col,dir}; a.sortAssetRows(a.state.assets); a.render(); }
  a.state.assetSort=null; a.render();
  const button = document.querySelector('button[title="Sort by Asset"]'); button.focus(); button.click();
  assert(document.activeElement.title === 'Sort by Asset','Sort lost keyboard focus');
 });
 await check('navigation links never contain sentinel credential', () => {
  a.openAccountPop(); assert(![...document.querySelectorAll('a')].some(x=>x.href.includes('AUDIT_SENTINEL')), 'Credential in navigation URL'); a.closeAccountPop();
 });
 await check('account keyboard entry and exit', () => {
  document.getElementById('user-avatar-btn').focus(); a.openAccountPop();
  assert(document.querySelector('.account-pop').contains(document.activeElement),'Account did not take focus');
  document.activeElement.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));
  assert(document.activeElement.id==='user-avatar-btn','Account did not restore focus');
 });
 await check('20 route refreshes dispose focus traps', async () => {
  a.openRoute(a.state.assets[0].key); for(let i=0;i<20;i++) a.renderRoute(); await wait(); a.closeRoute();
  for (const shiftKey of [false,true]) { const e=new KeyboardEvent('keydown',{key:'Tab',shiftKey,bubbles:true,cancelable:true}); document.dispatchEvent(e); assert(!e.defaultPrevented,'Detached trap prevents Tab'); }
 });
 await check('sheet isolates Enter and mutation shortcuts', () => {
  a.state.cursorKey=a.state.assets[0].key; a.openSheet('Fixture form',a.h('input',{value:'draft'}));
  for(const key of ['Enter','i','r']) document.querySelector('.sheet button').dispatchEvent(new KeyboardEvent('keydown',{key,bubbles:true,cancelable:true}));
  assert(!document.querySelector('.route'),'Background asset opened'); assert(document.querySelectorAll('.sheet').length===1,'Background action opened confirmation'); a.closeAllSheets(); a.closeRoute();
 });
 await check('dirty navigation keeps draft until explicit discard', () => {
  a.openSheet('Fixture draft',a.h('input',{value:'unsent'})); document.querySelector('.sheet input').dispatchEvent(new Event('input',{bubbles:true}));
  a.go('traffic'); assert(document.querySelector('.sheet'),'Draft silently discarded'); assert(a.state.section==='assets','Navigated before discard');
  const cancel=[...document.querySelectorAll('.sheet button')].find(b=>b.textContent==='Cancel'); assert(cancel,'Missing cancel'); cancel.click();
  assert(document.querySelector('.sheet input').value==='unsent','Cancel lost draft'); a.closeAllSheets();
 });
 await check('timestamps sort by epoch across offsets and year boundaries', () => {
  for(const iso of ['2025-12-31T23:59:59Z','2026-01-01T01:00:00+02:00','2026-09-09T10:02:01Z']) assert(a.cellSortKey(a.cellText(a.stamp(new Date(iso))))===Date.parse(iso),'Time sorted as display text');
 });
 await check('host history ignores globally excluded alerts and unrelated traffic', async () => {
  const original=window.fetch, paths=[]; a.state.demo=false; a.state.anomalies=[]; a.state.events=[];
  window.fetch=async (path) => { paths.push(path); let value={};
   if(path.startsWith('/api/v1/anomalies?')) value={total:73,alerts:[{id:'fixture-alert',endpoint_id:a.state.assets[0].endpoint.id,severity:'HIGH',title:'Scoped fixture finding',timestamp:'2026-09-09T12:00:00Z'}]};
   if(path.startsWith('/api/v1/traffic/flows?')) value={total:120,flows:[]};
   return new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});
  };
  try { a.openRoute(a.state.assets.find(x=>x.endpoint).key); await wait(); assert(document.querySelector('.route').textContent.includes('73 open alerts'),'Host count inherited global page'); assert(paths.some(p=>p.startsWith('/api/v1/traffic/flows?range=24h&limit=25&endpoint_id=')),'No scoped flows read'); }
  finally { a.closeRoute(); window.fetch=original; a.state.demo=true; }
 });
 await check('first load and optional stalls do not impersonate empty access data', async () => {
  const original=window.fetch;
  let operators, credentials, terminal;
  const json=value=>new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});
  a.state.demo=false;
  window.fetch=path=>{
   if(path==='/api/v1/operators')return new Promise(r=>operators=r);
   if(path==='/api/v1/device-auth/credentials')return new Promise(r=>credentials=r);
   if(path==='/api/v1/terminal/sessions')return new Promise(r=>terminal=r);
   a.state.demo=true;const response=a.request(path);a.state.demo=false;return response.then(json);
  };
  try {
   a.go('access');await wait();
   assert(document.getElementById('view').textContent.includes('Loading access'),'First load shown as valid empty data');
   assert(!document.getElementById('view').textContent.includes('shared tenant key'),'Authentication mode inferred while loading');
   operators(json({operators:[{email:'fixture@example.invalid',role:'admin'}],you:'fixture@example.invalid'}));credentials(json({credentials:[]}));
   await wait();
   assert(!document.getElementById('view').textContent.includes('Loading access'),'Healthy section stalled behind terminal read');
  } finally {if(terminal)terminal(json({sessions:[]}));await wait();window.fetch=original;a.state.demo=true;a.state.section='assets';a.render();}
 });
 await check('hanging requests have a deadline', async () => {
  const original=window.fetch, timer=window.setTimeout;a.state.demo=false;
  window.setTimeout=(fn,ms,...args)=>timer(fn,ms===15000?1:ms,...args);
  window.fetch=(_path,opts)=>new Promise((_resolve,reject)=>opts.signal.addEventListener('abort',()=>reject(new DOMException('Aborted','AbortError'))));
  try {let error;try{await a.request('/api/v1/fixture-hanging');}catch(e){error=e;}assert(error && /timed out/.test(error.message),'Hanging request did not produce a timeout');}
  finally{window.fetch=original;window.setTimeout=timer;a.state.demo=true;}
 });
 await check('HTML login, malformed JSON, 401, 403 and 500 reject as errors', async () => {
  const original=window.fetch; a.state.demo=false;
  try { for(const [status,body,type] of [[200,'<html>Sign in</html>','text/html'],[200,'{','application/json'],[401,'{}','application/json'],[403,'{}','application/json'],[500,'{}','application/json']]) {
   window.fetch=async()=>new Response(body,{status,headers:{'Content-Type':type}});
   let rejected=false; try { await a.request('/api/v1/fixture-error-'+status+'-'+type); } catch { rejected=true; } assert(rejected,'Invalid API response accepted');
  } } finally {window.fetch=original;a.state.demo=true;}
 });
 a.state.section='assets';a.render();
 return results;
})()
