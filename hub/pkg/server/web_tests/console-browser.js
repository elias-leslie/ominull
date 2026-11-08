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
  const saved = {tab:a.state.routeTab,key:a.state.routeTabKey,sec:a.state.section,f:a.state.filters,r:a.state.remoteOff};
  const asset = id => a.state.assets.find(x=>x.endpoint && x.endpoint.id===id);
  const cardText = () => { const c=[...document.querySelectorAll('.card')].find(x=>/^Access and lock/i.test(x.textContent)); return c ? c.textContent : ''; };
  const head = () => (document.querySelector('.route-chips')||{}).textContent||'';
  await until(() => a.state.fleetTrust && a.state.remoteOff, 'the lock report and remote access settings');
  a.state.routeTab='overview'; a.state.routeTabKey='';
  const db = asset('linux-prod-db-01');
  a.openRoute(db.key);
  await until(() => /Signed scripts/.test(cardText()), 'the db-01 lock card');
  const t = cardText();
  assert(/Host-locked/.test(t) && /Only scripts signed by a key pinned here run/.test(t),'Host lock missing: '+t);
  assert(/2 packages are allowed to run on this machine: btrfs-scrub, cleanup/.test(t),'Always allowed packages missing: '+t);
  assert(/the lock level does not allow it/.test(t),'Last refusal missing: '+t);
  assert(/Lock: Signed scripts/.test(head()) && /Host-locked/.test(head()) && /Remote access off/.test(head()),'Head chips missing: '+head());
  /* Remote access: db-01 is off, so the button switches it back on, and the hub applies it at once. */
  const sw = () => [...document.querySelectorAll('.access-remote button')][0];
  assert(/Switch back on/.test(sw().textContent),'Switch back on button missing');
  sw().click(); await wait();
  assert(!/phone/.test((document.querySelector('.sheet')||{}).textContent||''),'Switch back on still mentions a phone');
  [...document.querySelectorAll('.sheet button')].find(b=>/^Switch back on$/.test(b.textContent)).click();
  await until(() => !a.state.remoteOff['linux-prod-db-01'], 'remote access to come back on', 200);
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
  /* Retired releases on the Access page. */
  a.state.filters={}; a.state.section='access'; document.getElementById('view').dataset.section=''; a.render();
  await until(() => /Retired agent releases/.test(document.getElementById('view').textContent), 'the retired releases card');
  document.getElementById('view').dataset.section=''; a.render();
  const v = document.getElementById('view').textContent;
  assert(/Retired/.test(v) && /1\.0\.0/.test(v) && /machines? still run/.test(v),'Retired releases missing');
  a.state.remoteOff=saved.r; a.state.filters=saved.f; a.state.routeTab=saved.tab; a.state.routeTabKey=saved.key; a.state.section=saved.sec; document.getElementById('view').dataset.section=''; a.render();
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
 await check('Traffic lists conversations needing a look first, filters by chip, and the panel opens and closes by keyboard', async () => {
  const saved=a.state.trafficFilter;
  a.state.trafficFilter={range:'1h'}; a.state.trafficConversations=null; a.state.section='traffic'; a.render(); a.refresh();
  const rows=()=>[...document.querySelectorAll('.tf-table tbody tr')];
  for(let i=0;i<100 && !rows().length;i++) await wait();
  assert(rows().length>3,'No conversations listed');
  assert(rows()[0].querySelector('.tf-mark[data-kind="finding"]'),'The first row is not the one with a finding');
  assert(rows().every(r=>!/NOTHING FLAGGED|OUTBOUND|INBOUND/.test(r.textContent)),'A row spells its state in words');
  const chip=label=>[...document.querySelectorAll('.tf-filters .tg-chip')].find(b=>b.querySelector('span') && b.querySelector('span').textContent===label);
  const flagged=Number(chip('Flagged').querySelector('b').textContent);
  chip('Flagged').click();
  for(let i=0;i<100 && rows().length!==flagged;i++) await wait();
  assert(a.state.trafficFilter.mark==='flagged' && chip('Flagged').getAttribute('aria-pressed')==='true','Flagged did not turn on');
  assert(/[?&]mark=flagged/.test(location.hash),'The filter is not in the address: '+location.hash);
  assert(rows().length===flagged && rows().every(r=>r.querySelector('.tf-mark[data-kind="finding"]')),'Flagged shows rows without a finding');
  assert(document.querySelector('.tf-shown').textContent===flagged+' conversations','The count does not follow the filter: '+document.querySelector('.tf-shown').textContent);
  const opener=rows()[0].querySelector('.tf-open'); opener.focus(); opener.click(); await wait();
  const panel=document.querySelector('.tf-panel');
  assert(document.querySelector('.tf-workspace').dataset.panel==='open' && panel.contains(document.activeElement),'Details did not open and take focus');
  assert([...panel.querySelectorAll('button')].some(b=>/Open finding/.test(b.textContent)),'No way from a flagged conversation to its finding');
  assert(!/\bnull\b|undefined/.test(panel.textContent),'Panel prints null or undefined');
  const key=opener.dataset.key;
  [...panel.querySelectorAll('.tf-flow')][0]?.click(); await wait();
  if(document.querySelector('.sheet')){
   document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true})); await wait();
   assert(!document.querySelector('.sheet') && document.querySelector('.tf-workspace').dataset.panel==='open','Escape on a sheet closed the details too');
  }
  await a.refresh(); await wait();
  document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true})); await wait();
  assert(document.querySelector('.tf-workspace').dataset.panel!=='open','Escape did not close the details');
  assert(document.activeElement && document.activeElement.dataset.key===key,'Focus did not return to its own row after a poll');
  const second=rows()[1].querySelector('.tf-open'); const secondKey=second.dataset.key; second.focus();
  await a.refresh(); await wait();
  assert(document.activeElement && document.activeElement.dataset.key===secondKey,'A poll moved focus to another row');
  [...document.querySelectorAll('.tf-filters .btn')].find(b=>b.textContent==='Clear filters').click();
  for(let i=0;i<100 && a.state.trafficFilter.mark;i++) await wait();
  assert(!a.state.trafficFilter.mark,'Clear filters left the mark on');
  const box=document.querySelector('.tf-search'); box.focus(); box.value='nginx'; box.dispatchEvent(new Event('input',{bubbles:true}));
  for(let i=0;i<100 && !(rows().length && rows().every(r=>/nginx/.test(r.textContent)));i++) await wait();
  assert(document.activeElement===box,'Search lost focus');
  await a.refresh(); await wait();
  assert(!/paused/.test(document.getElementById('connection-status').textContent),'Traffic claims it is paused while it keeps painting');
  assert(rows().length && rows().every(r=>/nginx/.test(r.textContent)),'The list did not follow the search while the box had focus');
  window.dispatchEvent(new PopStateEvent('popstate',{state:{section:'traffic',range:'7d',mark:'nonsense',tq:'nginx',dst_ip:'203.0.113.9'}}));
  for(let i=0;i<100 && a.state.trafficFilter.range!=='7d';i++) await wait();
  const tf=a.state.trafficFilter;
  assert(tf.range==='7d' && tf.q==='nginx' && tf.dst_ip==='203.0.113.9' && !tf.mark,'An address did not set the filters, or a bad value got through: '+JSON.stringify(tf));
  box.value=''; a.state.trafficFilter=saved; a.state.section='assets'; a.render();
 });
 await check('a running sweep shows on its button, and the installer reaches the enrollment keys', async () => {
  const saved=a.state.scanStatus;
  a.state.section='assets'; a.state.scanStatus={status:'running',progress:40}; a.render();
  const button=text=>[...document.querySelectorAll('button')].find(b=>b.textContent.trim().toLowerCase()===text);
  assert(button('sweeping 40%'),'A running sweep does not show on the button');
  a.state.scanStatus=saved; a.render();
  button('install agent').click();
  await wait();
  button('enrollment keys').click();
  for(let i=0;i<100 && !document.querySelector('.sheet table, [role=dialog] table');i++) await wait();
  assert(/enr-demo-gpo-01/.test(document.body.textContent) && button('revoke'),'The enrollment keys sheet does not list a key to revoke');
  button('close').click();
  await wait();
 });
 await check('a gated-looking action completes on the first request', async () => {
  const original=window.fetch;a.state.demo=false;const calls=[];
  const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers:{'Content-Type':'application/json'}});
  window.fetch=async(url,opts={})=>{calls.push({u:String(url),method:opts.method||'GET',body:opts.body,headers:new Headers(opts.headers||{})});return json({ok:true});};
  try {
   const result=await a.request('/api/v1/endpoints/isolate-bulk','POST',{scope:'ids',ids:['e1']});
   const posts=calls.filter(c=>c.method==='POST');
   assert(posts.length===1&&JSON.parse(posts[0].body).scope==='ids','The request was not sent exactly once with its scope');
   assert(!posts[0].headers.get('X-Approval-ID'),'The request carried an approval id');
   assert(!calls.some(c=>c.u.startsWith('/api/v1/approvals')),'The console polled for an approval');
   assert(!document.querySelector('.approval-wait'),'An approval panel appeared');
   assert(result&&result.ok,'Result not returned');
  } finally {window.fetch=original;a.state.demo=true;}
 });
 await check('Posture card scores packs, opens a control and answers a confirmation', async () => {
  const saved={sec:a.state.section,tab:a.state.maintTab,p:a.state.posture,o:a.state.postureOpen};
  a.state.posture=await a.request('/api/v1/posture');
  a.state.postureOpen={'ir-readiness':true};
  a.state.maintTab='security'; a.state.section='maintenance'; document.getElementById('view').dataset.section=''; a.render();
  const packs=[...document.querySelectorAll('.pst-pack')];
  assert(packs.length===2,'Packs on the card: '+packs.length);
  assert(/%/.test(packs[0].querySelector('summary').textContent),'A pack has no percent');
  const dot=document.querySelector('.pst-dot');
  assert(dot&&dot.title,'A status dot has no words');
  dot.closest('button').click(); await wait();
  assert(document.querySelector('.sheet'),'The dots do not open the control');
  [...document.querySelectorAll('.sheet button')].find(b=>b.textContent==='Close').click(); await wait();
  assert(packs[1].open&&!packs[0].open,'Which packs are open did not survive a repaint');
  const mfa=[...document.querySelectorAll('.pst-open')].find(b=>/second step/.test(b.textContent));
  mfa.click(); await wait();
  const answer=[...document.querySelectorAll('.sheet button')].find(b=>/^Answer/.test(b.textContent));
  assert(answer&&!answer.disabled,'A control nobody can see has no Answer button');
  answer.click(); await wait();
  const choice=document.querySelector('.sheet select');
  assert(choice.value===''&&[...document.querySelectorAll('.sheet button')].find(b=>b.textContent==='Save').disabled,'An answer can be saved without choosing one');
  choice.value='pass'; choice.dispatchEvent(new Event('change',{bubbles:true}));
  assert([...document.querySelectorAll('.sheet button')].find(b=>b.textContent==='Save').disabled,'An answer can be saved with no note');
  const note=document.querySelector('.sheet input[type=text]');
  note.value='Owner confirmed'; note.dispatchEvent(new Event('input',{bubbles:true}));
  [...document.querySelectorAll('.sheet button')].find(b=>b.textContent==='Save').click(); await wait(); await wait();
  assert(!document.querySelector('.sheet'),'Saving left a sheet or discard prompt open');
  const after=await a.request('/api/v1/posture');
  const r=after.packs[1].controls.find(c=>c.id==='ir.console_mfa').results[0];
  assert(r.state==='pass'&&r.actual==='Owner confirmed','Answer not kept: '+JSON.stringify(r));
  await a.request('/api/v1/posture/attest','POST',{control:'ir.console_mfa',state:'clear'});
  a.state.section=saved.sec;a.state.maintTab=saved.tab;a.state.posture=saved.p;a.state.postureOpen=saved.o;a.render();
 });
 await check('Posture on a machine: Linux reads its packs, an accept sticks and undoes, a direct link loads', async () => {
  const eps=await a.request('/api/v1/endpoints');
  const lin=eps.find(e=>/linux/i.test(e.os||'')), win=eps.find(e=>/windows/i.test(e.os||''));
  const one=async id=>a.request('/api/v1/posture?endpoint_id='+encodeURIComponent(id));
  const ids=v=>v.packs.flatMap(p=>p.controls.map(c=>c.id));
  assert(ids(await one(lin.id)).includes('ssh.password_auth_off'),'Linux lost its SSH control');
  assert(!ids(await one(win.id)).includes('ssh.password_auth_off'),'A Windows machine shows a Linux control');
  const fleet=await a.request('/api/v1/posture');
  const logs=fleet.packs[1].controls.find(c=>c.id==='ir.endpoint_logs');
  const bad=logs.results.find(r=>r.state==='fail');
  const put=(accepted)=>a.request('/api/v1/maintenance/settings','PUT',{endpoint_id:bad.endpoint_id,accept_risk:bad.key,accepted,reason:accepted?'Test':undefined});
  const stateNow=async()=>(await a.request('/api/v1/posture')).packs[1].controls.find(c=>c.id==='ir.endpoint_logs').results.find(r=>r.endpoint_id===bad.endpoint_id);
  await put(true);
  const held=await stateNow();
  assert(held.state==='accepted'&&held.reason==='Test','The accept did not stick: '+JSON.stringify(held));
  await put(false);
  assert((await stateNow()).state==='fail','The undo did not stick');
  const asset=a.state.assets.find(x=>x.endpoint&&x.endpoint.id===lin.id);
  assert(asset,'No asset for the Linux machine');
  delete a.state.maintenanceByEndpoint[lin.id];
  a.state.routeKey=asset.key; a.state.routeDetailKey=''; a.renderRoute(); await wait(); await wait();
  assert(a.state.maintenanceByEndpoint[lin.id]&&!a.state.maintenanceByEndpoint[lin.id].loading,'A route opened from a link never read the machine');
  a.closeRoute();
 });
 await check('The routes the trim left: profile, monitor only, correct, networks and retire all work from the console', async () => {
  const buttons=()=>[...document.querySelectorAll('.sheet button')];
  const byText=(list,t)=>list.find(b=>b.textContent===t);
  const type=(el,v)=>{el.value=v;el.dispatchEvent(new Event('input',{bubbles:true}));};
  const reasonOf=()=>document.querySelector('.sheet input[aria-label="Reason"]');
  await a.refresh();
  const trustRows=(await a.request('/api/v1/fleet/trust')).endpoints;
  const reporting=x=>{const r=trustRows.find(t=>t.endpoint_id===x.endpoint.id);return r&&r.verification==='agent'&&!r.ceiling;};
  const asset=a.state.assets.find(x=>x.endpoint&&!x.isolated&&reporting(x));
  const id=asset.endpoint.id;
  a.state.routeTab='overview'; a.openRoute(asset.key); await wait(); await wait();
  const route=()=>document.querySelector('.route');
  const inRoute=t=>[...route().querySelectorAll('button')].find(b=>b.textContent===t);
  const more=[...route().querySelectorAll('.route-actions button')].find(b=>b.textContent==='More…');
  more.click(); await wait();
  assert(document.querySelector('[role=menu]'),'More… on a machine page does not open its menu');
  document.body.click(); await wait();
  assert(/None run here|Scripts the hub signs run here/.test(route().textContent),'The Scripts row does not say whether scripts run');
  inRoute('Change…').click(); await wait();
  const pick=document.querySelector('.sheet select');
  let go=byText(buttons(),'Change');
  assert(go.disabled,'A profile change can go with no reason');
  pick.value='respond'; pick.dispatchEvent(new Event('change',{bubbles:true}));
  type(reasonOf(),'Test'); assert(!go.disabled,'A real change with a reason is held back');
  go.click(); await wait(); await wait();
  assert(!document.querySelector('.sheet'),'The profile sheet stayed open');
  let trust=await a.request('/api/v1/fleet/trust');
  assert(trust.endpoints.find(r=>r.endpoint_id===id).profile==='respond','Profile not sent');
  await a.refresh(); await wait();
  assert(route().textContent.includes('None run here: the respond profile does not allow scripts'),'A profile without scripts does not say so');
  inRoute('Refuse isolation…').click(); await wait();
  type(reasonOf(),'Test'); byText(buttons(),'Refuse isolation').click(); await wait(); await wait();
  assert((await a.request('/api/v1/endpoints')).find(e=>e.id===id).monitor_only===true,'Monitor only not set');
  await a.refresh(); await wait();
  assert([...route().querySelectorAll('.st')].some(c=>c.textContent==='Monitor only'),'No monitor only chip');
  const rev=(await a.request('/api/v1/endpoints')).find(e=>e.id===id).response_profile_rev;
  inRoute('Allow isolation…').click(); await wait();
  type(reasonOf(),'Test'); byText(buttons(),'Allow isolation').click(); await wait(); await wait();
  const after=(await a.request('/api/v1/endpoints')).find(e=>e.id===id);
  assert(after.monitor_only===false&&after.response_profile_rev===rev+1,'Isolation not allowed again');
  await a.refresh(); await wait();
  a.state.routeTab='evidence'; a.renderRoute(); await wait();
  inRoute('Correct…').click(); await wait();
  document.querySelector('.sheet select').value='vendor';
  type(document.querySelector('.sheet input[aria-label="Correct value"]'),'Test Vendor');
  type(reasonOf(),'Test'); byText(buttons(),'Save').click(); await wait(); await wait(); await wait();
  assert([...route().querySelectorAll('.claim .val')].some(v=>v.textContent==='Test Vendor'),'The correction does not show');
  inRoute('Withdraw').click(); await wait(); await wait(); await wait();
  assert(![...route().querySelectorAll('.claim .val')].some(v=>v.textContent==='Test Vendor'),'The withdrawal does not show');
  const isolatedHost=(await a.request('/api/v1/endpoints')).find(e=>e.is_isolated);
  if(isolatedHost){let refused=null; await a.request('/api/v1/endpoints/monitor-only','POST',{endpoint_id:isolatedHost.id,reason:'Test'}).catch(e=>{refused=e;}); assert(refused&&refused.status===409,'Monitor only went through on an isolated machine');}
  a.closeRoute();
  await a.request('/api/v1/topology/networks','PUT',[{cidr:'10.0.9.0/24',label:'Lab',kind:'virtual'}]);
  assert((await a.request('/api/v1/topology/networks'))[0].label==='Lab','Networks not kept');
  a.state.section='topology'; a.render(); await new Promise(r=>setTimeout(r,800));
  const nets=[...document.querySelectorAll('#view button')].find(b=>b.textContent==='Networks');
  assert(nets,'No Networks button on the map');
  nets.click(); await wait(); await wait();
  const rows=[...document.querySelectorAll('.sheet input[aria-label="Address range"]')];
  assert(rows.length===1&&rows[0].value==='10.0.9.0/24','The sheet does not show the saved network');
  byText(buttons(),'Add a network').click(); await wait();
  type([...document.querySelectorAll('.sheet input[aria-label="Address range"]')][1],'10.0.10.0/24');
  byText(buttons(),'Save').click(); await wait(); await wait();
  assert((await a.request('/api/v1/topology/networks')).length===2,'A network added on the sheet was not saved');
  nets.click(); await wait(); await wait();
  byText(buttons(),'Add a network').click(); await wait();
  const lastRow=()=>{const l=document.querySelectorAll('.sheet input[aria-label="Name"]');return l[l.length-1];};
  type(lastRow(),'No range'); byText(buttons(),'Save').click(); await wait(); await wait();
  assert(document.querySelector('.sheet')&&(await a.request('/api/v1/topology/networks')).length===2,'A named network with no range was saved or dropped');
  type([...document.querySelectorAll('.sheet input[aria-label="Address range"]')].pop(),'abc'); byText(buttons(),'Save').click(); await wait(); await wait();
  assert(document.querySelector('.sheet')&&(await a.request('/api/v1/topology/networks')).length===2,'A range that is not an address was saved');
  a.closeSheet();
  await a.request('/api/v1/topology/networks','PUT',[{cidr:'10.0.4.0/24',label:'Office',kind:'physical'}]);
  a.state.section='assets'; a.render();
  await a.refresh(); await wait();
  const lab=a.state.assets.find(x=>x.endpoint&&x.endpoint.id!==id&&!x.isolated);
  a.openRoute(lab.key); await wait(); await wait();
  [...route().querySelectorAll('.route-actions button')].find(b=>b.textContent==='More…').click(); await wait();
  const retireItem=[...document.querySelectorAll('[role=menu] [role=menuitem]')].find(b=>/^Retire/.test(b.textContent));
  assert(retireItem,'No Retire in the machine menu');
  retireItem.click(); await wait();
  assert(/installing the agent again/.test(document.querySelector('.sheet').textContent),'The retire sheet does not say what it costs');
  type(reasonOf(),'Test'); byText(buttons(),'Retire').click(); await wait(); await wait(); await wait();
  const retired=(await a.request('/api/v1/endpoints')).find(e=>e.id===lab.endpoint.id);
  assert(retired&&retired.status==='retired','Retire did not mark the machine');
  assert(!a.state.routeKey&&!a.state.assetByKey[lab.key],'A retired machine stays in the console');
 });
 await check('A machine page opens for every role, and only an admin gets the change controls', async () => {
  for(const [role,canChange] of [['auditor',false],['analyst',false],['admin',true]]){
   const frame=document.createElement('iframe');frame.style.cssText='width:1200px;height:800px;position:fixed;left:-2000px';frame.src='/?demo=true&role='+role+'#/assets';
   document.body.appendChild(frame);
   await new Promise(r=>frame.onload=r);
   const w=frame.contentWindow;let errors=[];w.addEventListener('error',e=>errors.push(e.message));
   for(let i=0;i<40&&!(w.audit&&w.audit.state.assets.length);i++)await new Promise(r=>setTimeout(r,100));
   const target=w.audit.state.assets.find(x=>x.endpoint);
   w.audit.openRoute(target.key);await new Promise(r=>setTimeout(r,300));w.audit.state.routeTab='evidence';w.audit.renderRoute();await new Promise(r=>setTimeout(r,300));
   const route=frame.contentDocument.querySelector('.route');
   assert(route,role+': the machine page did not open');
   assert(!errors.length,role+': '+errors[0]);
   const hasCorrect=[...route.querySelectorAll('button')].some(b=>b.textContent==='Correct…');
   assert(hasCorrect===canChange,role+': the Correct button is '+(hasCorrect?'shown':'hidden'));
   frame.remove();
  }
 });
 await check('A failed first read of the assets keeps the link and does not claim the address is unknown', async () => {
  const frame=document.createElement('iframe');frame.style.cssText='width:1200px;height:800px;position:fixed;left:-2000px';frame.src='/?demo=true#/assets';
  document.body.appendChild(frame);
  await new Promise(r=>frame.onload=r);
  const w=frame.contentWindow;
  for(let i=0;i<40&&!(w.audit&&w.audit.state.assets.length);i++)await new Promise(r=>setTimeout(r,100));
  const target=w.audit.state.assets.find(x=>x.endpoint);
  w.audit.state.assetsLoaded=false;w.audit.state.routeKey='not-read-yet';
  w.audit.renderRoute();
  assert(w.audit.state.routeKey==='not-read-yet','The link was dropped while the list was unread');
  w.audit.state.assetsLoaded=true;w.audit.renderRoute();
  assert(w.audit.state.routeKey==='','A link to a machine that is really gone stayed open');
  assert(target,'No machine in the fixture');
  frame.remove();
 });
 a.state.section='assets';a.render();
 return results;
})()
