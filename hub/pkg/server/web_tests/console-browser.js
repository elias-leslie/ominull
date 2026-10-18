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
 await check('DOM builder treats untrusted text and exceptions as literal text',()=>{
  const payload='<img src=x onerror="window.fixtureExecuted=true">';
  const text=document.createElement('span');text.textContent=payload;
  const exception=new Error(payload);
  const container=a.h('div',{},text.textContent,exception.message,[a.h('span',{text:payload})]);
  document.body.appendChild(container);
  assert(container.textContent===payload.repeat(3),'Text changed during rendering');
  assert(!container.querySelector('img') && !window.fixtureExecuted,'Text interpreted as HTML');
  container.remove();
 });
 await check('needs-you strip and Maintenance badge count what waits on the owner', async () => {
  const saved={d:a.state.maintDecisions,u:a.state.unackAlertsTotal,p:a.state.maintPlaybooks,m:a.state.maintenanceByEndpoint};
  a.state.maintPlaybooks=null; a.state.maintenanceByEndpoint={};
  a.state.maintDecisions={open:[{key:'k1',group:'g',group_title:'G',endpoint_id:'e',package:'p',item:{id:'i',name:'n',reason:'r'},answers:['handled']}]};
  a.state.unackAlertsTotal=0; a.state.section='assets'; a.render();
  const chips=[...document.querySelectorAll('.needs-you .attn')].map(b=>b.textContent);
  assert(chips.includes('1decision'),'Decision missing from needs-you: '+chips.join(','));
  assert(!chips.some(c=>/open alert/.test(c)),'Zero alerts shown as needing the owner');
  const badge=document.getElementById('rail-maint-badge');
  assert(badge && badge.dataset.n==='1','Maintenance badge does not count the open decision');
  a.state.maintDecisions={open:[]}; a.render();
  assert(document.getElementById('rail-maint-badge').dataset.n==='0','Badge stays after decisions close');
  a.state.maintDecisions=saved.d; a.state.unackAlertsTotal=saved.u; a.state.maintPlaybooks=saved.p; a.state.maintenanceByEndpoint=saved.m; a.render();
 });
 await check('Maintenance Run picks a runnable package and only machines it fits', async () => {
  const saved={s:a.state.maintSettings,sec:a.state.section,tab:a.state.maintTab};
  const pk=(name,title,platform,role)=>({name,title,platform,role,category:'maintenance',description:title+' does a thing.',version:1,params:[],fleet_effective:{enabled:false}});
  a.state.maintSettings={window:'',categories:[{name:'maintenance',fleet_enabled:true}],packages:[pk('w-clean','Cleanup','windows'),pk('l-up','Updates','linux'),pk('w-reboot','Restart','windows','reboot')]};
  a.state.maintTab='maintenance'; a.state.section='maintenance'; document.getElementById('view').dataset.section=''; a.render();
  const run=[...document.querySelectorAll('.page-tools .btn-primary')].find(b=>/^Run/.test(b.textContent));
  assert(run && !run.disabled,'Maintenance has no Run button');
  run.click(); await wait();
  const sel=document.querySelector('.sheet select[aria-label="Package"]');
  assert(sel,'Run sheet has no package picker');
  const opts=[...sel.options].map(o=>o.value);
  assert(opts.join(',')==='w-clean,l-up','Run offers '+opts.join(','));
  const names=()=>[...document.querySelectorAll('.sheet .pb-hosts legend, .sheet .empty, .sheet .emptybox')].map(e=>e.textContent).join('|');
  const first=names();
  sel.value='l-up'; sel.dispatchEvent(new Event('change')); await wait();
  assert(names()!==first && /Linux/.test(names()),'Machines do not follow the package platform: '+first+' -> '+names());
  a.closeAllSheets();
  assert(document.querySelectorAll('details.pkg-desc').length===3,'Package descriptions are not on demand');
  a.state.maintSettings=saved.s; a.state.maintTab=saved.tab; a.state.section=saved.sec; document.getElementById('view').dataset.section=''; a.render();
 });
 await check('all asset comparators accept real row types and retain sort focus', () => {
  for (let col=1; col<=6; col++) for (const dir of ['asc','desc']) { a.state.assetSort={col,dir}; a.sortAssetRows(a.state.assets); a.render(); }
  a.state.assetSort=null; a.render();
  const button = document.querySelector('button[title="Sort by Asset"]'); button.focus(); button.click();
  assert(document.activeElement.title === 'Sort by Asset','Sort lost keyboard focus');
 });
 await check('Assets filter bar toggles filters, keeps agent scope exclusive, and the strip stops repeating them', async () => {
  const saved={f:a.state.filters,q:a.state.query,s:a.state.section};
  a.state.filters={}; a.state.query=''; a.state.section='assets'; a.render();
  const chip=label=>[...document.querySelectorAll('.fbar .fchip')].find(b=>b.firstChild.textContent===label);
  assert(chip('All') && chip('With agent') && chip('No agent') && chip('Offline') && chip('Quarantined') && chip('Agent outdated') && chip('Risky ports') && chip('No client cert'),'Filter chip missing');
  assert(chip('All').getAttribute('aria-pressed')==='true','All is not the resting chip');
  chip('With agent').click(); await wait();
  assert(a.state.filters.agented && chip('With agent').getAttribute('aria-pressed')==='true','With agent did not turn on');
  chip('No agent').click(); await wait();
  assert(a.state.filters.noagent && !a.state.filters.agented,'Agent scopes are not exclusive');
  const shown=document.querySelectorAll('tr.row').length;
  assert(shown>0 && [...document.querySelectorAll('tr.row')].every(r=>!r.textContent.includes('Outdated')),'No agent list shows an agent');
  chip('All').click(); await wait();
  assert(!a.state.filters.agented && !a.state.filters.noagent,'All did not reset the scope');
  chip('Quarantined').click(); await wait();
  assert(a.state.filters.quarantined,'Quarantined chip did not filter');
  const clear=[...document.querySelectorAll('.fbar .btn')].find(b=>b.textContent==='Clear filters'); assert(clear,'No way to clear filters'); clear.click(); await wait();
  assert(Object.keys(a.state.filters).length===0,'Clear filters left a filter on');
  const needs=[...document.querySelectorAll('.needs-you .attn')].map(b=>b.textContent).join('|');
  assert(!/quarantined|outdated/.test(needs),'Needs-you still repeats the filter chips: '+needs);
  a.state.filters=saved.f; a.state.query=saved.q; a.state.section=saved.s; a.render();
 });
 await check('stuck supervised runs show their own state, a live line, and reach the needs-you strip and the Maintenance badge', async () => {
  const saved={p:a.state.maintPlaybooks,d:a.state.maintDecisions,u:a.state.unackAlertsTotal,sec:a.state.section,m:a.state.maintenanceByEndpoint};
  const beat=new Date(Date.now()-20000).toISOString();
  const step=live=>({state:'started',job_id:'j',live});
  a.state.maintDecisions={open:[]}; a.state.unackAlertsTotal=0; a.state.maintenanceByEndpoint={};
  a.state.maintPlaybooks={playbooks:[],runs:[{id:'r1',name:'Weekly tidy',started:new Date().toISOString(),deadline:new Date(Date.now()+3600000).toISOString(),done:false,steps:['windows-updates (enforce)'],hosts:{
   'ep-a':[step({state:'needs_hands',reason:'waiting on a window',window:{title:'Restart options',process:'Settings.exe',session:1},progress:{pct:62,message:'Installing 3 of 5',heartbeat_at:beat}})],
   'ep-b':[step({state:'stalled',reason:'no output, CPU or disk activity for 9 min',progress:{pct:-1,message:'',heartbeat_at:beat}})],
   'ep-c':[step({state:'running',progress:{pct:10,message:'Starting',heartbeat_at:beat}})]}}]};
  a.state.section='assets'; a.render();
  const chips=[...document.querySelectorAll('.needs-you .attn')].map(b=>b.textContent);
  assert(chips.includes('1run waiting on a window'),'Needs-you misses the run waiting on a window: '+chips.join(','));
  assert(chips.includes('1run stalled'),'Needs-you misses the stalled run: '+chips.join(','));
  assert(document.getElementById('rail-maint-badge').dataset.n==='2','Maintenance badge does not count stuck runs');
  a.state.section='maintenance'; document.getElementById('view').dataset.section=''; a.render();
  const text=document.getElementById('view').textContent;
  assert(/Waiting on a window/.test(text) && /Stalled/.test(text),'Run states fall back to Failed: '+text.slice(0,200));
  assert(!/Failed/.test(document.querySelector('.card + .card') ? text : ''),'A stuck run reads Failed');
  assert(/62% Installing 3 of 5/.test(text) && /Restart options/.test(text),'Live progress and window missing');
  assert(/no output, CPU or disk activity for 9 min/.test(text),'Stalled reason missing');
  a.state.maintPlaybooks=saved.p; a.state.maintDecisions=saved.d; a.state.unackAlertsTotal=saved.u; a.state.maintenanceByEndpoint=saved.m; a.state.section=saved.sec; document.getElementById('view').dataset.section=''; a.render();
 });
 await check('maintenance windows: line on the asset card, ranges sheet, per-machine override and fleet reset', async () => {
  const until = async (fn, what) => { for (let i = 0; i < 100; i++) { if (fn()) return; await new Promise(r => setTimeout(r, 50)); } throw new Error('Timed out waiting for ' + what); };
  const saved = {tab:a.state.routeTab,key:a.state.routeTabKey,sec:a.state.section,w:a.state.maintWindows,b:a.state.maintWindowByEndpoint};
  a.state.maintWindows=null; a.state.maintWindowByEndpoint={};
  const open = key => { a.state.routeTab='maintenance'; a.state.routeTabKey=key; a.openRoute(key); };
  const line = () => { const el=[...document.querySelectorAll('.maint-window')].find(e=>/^Window/.test(e.textContent)); return el ? el.textContent : ''; };
  const win = a.state.assets.find(x=>x.endpoint && x.endpoint.id==='win11-fin-11');
  open(win.key);
  await until(() => /12:00.13:30, 22:00.02:00/.test(line()), 'the machine window line');
  assert(/this machine's own window/.test(line()),'Source missing: '+line());
  assert(/Open now|Opens in/.test(line()),'Open now or next start missing: '+line());
  assert(!!document.querySelector('button[aria-label^="win11"], button[aria-label$="follows the fleet window"]'),'Use fleet window missing');
  document.querySelector('button[aria-label^="Change the maintenance window"]').click(); await wait();
  const rows = () => document.querySelectorAll('.sheet .win-range').length;
  assert(rows()===2,'Sheet shows '+rows()+' ranges, not 2');
  const add = [...document.querySelectorAll('.sheet button')].find(b=>b.textContent==='Add a range');
  add.click(); add.click(); await wait();
  assert(rows()===4 && add.disabled,'Four ranges should be the limit');
  document.querySelector('.sheet button[aria-label="Remove range 4"]').click(); document.querySelector('.sheet button[aria-label="Remove range 3"]').click(); await wait();
  assert(rows()===2,'Remove did not drop the rows');
  const f=document.querySelector('.sheet input[aria-label="Range 1 starts"]'), t=document.querySelector('.sheet input[aria-label="Range 1 ends"]');
  f.value='06:00'; f.dispatchEvent(new Event('input',{bubbles:true})); t.value='06:00'; t.dispatchEvent(new Event('input',{bubbles:true}));
  [...document.querySelectorAll('.sheet button')].find(b=>b.textContent==='Save').click(); await wait();
  assert(document.querySelector('.sheet'),'Equal start and end saved');
  t.value='07:30'; t.dispatchEvent(new Event('input',{bubbles:true}));
  document.querySelector('.sheet select').value='utc';
  [...document.querySelectorAll('.sheet button')].find(b=>b.textContent==='Save').click();
  await until(() => !document.querySelector('.sheet'), 'the sheet to close after Save');
  await until(() => /06:00.07:30, 22:00.02:00 UTC/.test(line()), 'the saved ranges');
  assert((await a.request('/api/v1/maintenance/windows?endpoint_id=win11-fin-11')).clock==='utc','PUT did not store the clock');
  const own = [...document.querySelectorAll('button')].find(b=>/follows the fleet window$/.test(b.getAttribute('aria-label')||''));
  own.click();
  await until(() => /(standard|fleet) window ·/.test(line()), 'the machine to follow the fleet window');
  assert(!document.querySelector('button[aria-label$="follows the fleet window"]'),'Use fleet window stays after reset');
  /* A Linux machine has not reported its clock: the line says so instead of guessing. */
  a.closeRoute();
  const lin = a.state.assets.find(x=>x.endpoint && /linux/i.test(x.endpoint.os||''));
  open(lin.key);
  await until(() => /01:00.05:00/.test(line()), 'the Linux window line');
  assert(/Machine clock not reported yet/.test(line()),'Linux line should say the clock is not reported: '+line());
  a.closeRoute();
  /* The fleet window: up to four ranges; machines with their own window are named. */
  a.state.section='maintenance'; document.getElementById('view').dataset.section=''; a.render();
  await until(() => a.state.maintWindows, 'the fleet window read'); document.getElementById('view').dataset.section=''; a.render();
  const page = () => (document.querySelector('.maint-window-wrap')||{}).textContent||'';
  assert(/01:00.05:00/.test(page()),'Fleet window missing: '+page());
  document.querySelector('button[aria-label="Change the fleet maintenance window"]').click(); await wait();
  assert(/Fleet maintenance window/.test(document.querySelector('.sheet').getAttribute('aria-label')),'Fleet sheet title');
  assert(!![...document.querySelectorAll('.sheet button')].find(b=>/^Back to 01:00/.test(b.textContent)),'Fleet sheet has no way back to 01:00-05:00');
  a.closeAllSheets();
  a.state.maintWindows=saved.w; a.state.maintWindowByEndpoint=saved.b; a.state.routeTab=saved.tab; a.state.routeTabKey=saved.key; a.state.section=saved.sec; document.getElementById('view').dataset.section=''; a.render();
 });
 await check('access and lock: card, chips, filters, remote access switch and release keys', async () => {
  const until = async (fn, what, n) => { for (let i = 0; i < (n||100); i++) { if (fn()) return; await new Promise(r => setTimeout(r, 50)); } throw new Error('Timed out waiting for ' + what); };
  const saved = {tab:a.state.routeTab,key:a.state.routeTabKey,sec:a.state.section,f:a.state.filters,r:a.state.remoteOff,hold:a.state.demoApprovalHold};
  const asset = id => a.state.assets.find(x=>x.endpoint && x.endpoint.id===id);
  const cardText = () => { const c=[...document.querySelectorAll('.card')].find(x=>/^Access and lock/i.test(x.textContent)); return c ? c.textContent : ''; };
  const head = () => (document.querySelector('.route-chips')||{}).textContent||'';
  await until(() => a.state.fleetTrust && a.state.remoteOff, 'the lock report and remote access settings');
  a.state.routeTab='overview'; a.state.routeTabKey='';
  const db = asset('linux-prod-db-01');
  a.openRoute(db.key);
  await until(() => /Signed scripts/.test(cardText()), 'the db-01 lock card');
  const t = cardText();
  assert(/Host-locked/.test(t) && /Only scripts Nightshift signed run here/.test(t),'Host lock missing: '+t);
  assert(/2 packages run without asking: btrfs-scrub, cleanup/.test(t),'Standing approvals missing: '+t);
  assert(/the lock level does not allow it/.test(t),'Last refusal missing: '+t);
  assert(/Lock: Signed scripts/.test(head()) && /Host-locked/.test(head()) && /Remote access off/.test(head()),'Head chips missing: '+head());
  /* Remote access: db-01 is off, so the button asks to switch back on, which waits for the phone. */
  a.state.demoApprovalHold = false;
  const sw = () => [...document.querySelectorAll('.access-remote button')][0];
  assert(/Switch back on/.test(sw().textContent),'Switch back on button missing');
  sw().click(); await wait();
  assert(/tap on your phone/.test((document.querySelector('.sheet')||{}).textContent||''),'Switch back on does not say it needs a phone tap');
  [...document.querySelectorAll('.sheet button')].find(b=>/Ask on my phone/.test(b.textContent)).click();
  await until(() => !a.state.remoteOff['linux-prod-db-01'], 'remote access to come back on after the tap', 200);
  await until(() => /Switch off/.test((sw()||{}).textContent||''), 'the button to read Switch off');
  assert(!/Remote access off/.test(head()),'Remote access off chip stays after switching on');
  sw().click(); await wait();
  [...document.querySelectorAll('.sheet button')].find(b=>b.textContent==='Switch off').click();
  await until(() => a.state.remoteOff['linux-prod-db-01'], 'remote access to go off at once');
  await until(() => /Remote access off/.test(head()), 'the head chip');
  a.closeRoute();
  /* api-02: the agent and the hub disagree about isolation. */
  const api = asset('linux-prod-api-02');
  a.openRoute(api.key);
  await until(() => /Hub and agent disagree/.test(cardText()), 'the api-02 mismatch');
  assert(/Isolation mismatch/.test(head()) && /Watch and signed scripts/.test(cardText()),'api-02 chips or level missing: '+head());
  a.closeRoute();
  /* An agent too old to report: the card says why instead of staying empty. */
  const hub = asset('win11-fin-11');
  a.openRoute(hub.key);
  await until(() => /too old to check signatures/.test(cardText()), 'the hub-only explanation');
  a.closeRoute();
  /* The asset list filters. */
  a.state.section='assets'; a.state.filters={}; document.getElementById('view').dataset.section=''; a.render();
  const chipBtn = label => [...document.querySelectorAll('button')].find(b=>b.textContent.indexOf(label)===0);
  assert(/Host-locked\s*2/.test(chipBtn('Host-locked').textContent),'Host-locked count: '+chipBtn('Host-locked').textContent);
  assert(/Isolation mismatch\s*1/.test(chipBtn('Isolation mismatch').textContent),'Isolation mismatch count: '+chipBtn('Isolation mismatch').textContent);
  chipBtn('Isolation mismatch').click(); await wait();
  const rows = () => [...document.querySelectorAll('#view')].map(v=>v.textContent).join(' ');
  assert(/prod-api-02/.test(rows()) && !/prod-db-01/.test(rows()),'Isolation mismatch filter shows the wrong machines');
  /* Release keys on the Access page. */
  a.state.filters={}; a.state.section='access'; document.getElementById('view').dataset.section=''; a.render();
  await until(() => /Release keys/.test(document.getElementById('view').textContent) && a.state.routineKeys, 'the release keys card');
  document.getElementById('view').dataset.section=''; a.render();
  const v = document.getElementById('view').textContent;
  assert(/routine-2026-10/.test(v) && /epoch 3/.test(v),'Routine keys missing');
  assert(/Retired/.test(v) && /1\.0\.0/.test(v) && /machines? still run/.test(v),'Retired releases missing');
  a.state.remoteOff=saved.r; a.state.demoApprovalHold=saved.hold; a.state.filters=saved.f; a.state.routeTab=saved.tab; a.state.routeTabKey=saved.key; a.state.section=saved.sec; document.getElementById('view').dataset.section=''; a.render();
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
  /* A demo host read from an earlier check may still be in flight (demo replies take 40 ms); let it land so this read is the mocked one. */
  for (let i=0;i<40 && Object.values(a.hostScopes).some(v=>v.loading);i++) await wait();
  const original=window.fetch, paths=[]; a.state.demo=false; a.state.anomalies=[]; a.state.events=[];
  window.fetch=async (path) => { paths.push(path); let value={};
   if(path.startsWith('/api/v1/anomalies?')) value={total:73,alerts:[{id:'fixture-alert',endpoint_id:a.state.assets[0].endpoint.id,severity:'HIGH',title:'Scoped fixture finding',timestamp:'2026-09-09T12:00:00Z'}]};
   if(path.startsWith('/api/v1/traffic/flows?')) value={total:120,flows:[]};
   return new Response(JSON.stringify(value),{headers:{'Content-Type':'application/json'}});
  };
  try { a.openRoute(a.state.assets.find(x=>x.endpoint).key); for (let i=0;i<40 && !document.querySelector('.route').textContent.includes('Open alerts \u00b7 73');i++) await wait(); assert(document.querySelector('.route').textContent.includes('Open alerts \u00b7 73'),'Host count inherited global page; reads: '+paths.join(' ')+' scope: '+JSON.stringify(Object.fromEntries(Object.entries(a.hostScopes).map(([k,v])=>[k,{l:v.loading,al:v.alertsLoading,fl:v.flowsLoading}])))); assert(paths.some(p=>p.startsWith('/api/v1/traffic/flows?range=24h&limit=25&endpoint_id=')),'No scoped flows read'); }
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
 await check('gated action waits for owner approval and retries with the approval id', async () => {
  const original=window.fetch;a.state.demo=false;const calls=[];
  const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
  let decide;const decided=new Promise(r=>decide=r);
  window.fetch=async(url,opts={})=>{const u=String(url);const hdr=new Headers(opts.headers||{});calls.push({u,method:opts.method||'GET',approval:hdr.get('X-Approval-ID'),body:opts.body});
   if(u.startsWith('/api/v1/approvals')){await decided;return json({id:'ap1',state:'approved',summary:'Isolate fixture-host',expires_at:new Date(Date.now()+60000).toISOString()});}
   if(hdr.get('X-Approval-ID')==='ap1')return json({ok:true});
   return json({approval_id:'ap1',state:'pending',summary:'Isolate fixture-host',expires_at:new Date(Date.now()+300000).toISOString()},202);};
  try {
   const done=a.ownerApproved('/api/v1/endpoints/isolate-bulk',{scope:'ids',ids:['e1']},{label:'Isolate fixture-host'});
   await wait();await wait();
   const panel=document.querySelector('.approval-wait');
   assert(panel&&panel.getAttribute('data-state')==='pending','No pending approval panel');
   assert(panel.textContent.includes('Approve on your phone'),'Pending panel does not say where to approve');
   decide();const result=await done;
   const posts=calls.filter(c=>c.method==='POST');
   assert(posts.length===2&&!posts[0].approval&&posts[1].approval==='ap1','Retry did not carry X-Approval-ID');
   assert(posts[0].body===posts[1].body&&JSON.parse(posts[1].body).scope==='ids','Retry body changed or lost scope');
   assert(result&&result.ok,'Approved result not returned');
  } finally {window.fetch=original;a.state.demo=true;document.querySelectorAll('.approvals').forEach(n=>n.remove());}
 });
 a.state.section='assets';a.render();
 return results;
})()
