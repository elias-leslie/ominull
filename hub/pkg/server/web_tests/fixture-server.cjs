// Sanitized fixture only. No production credentials or write routes exist.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const minifyConsole = require('../../../../web-build/console-minify.cjs');
const root = path.resolve(__dirname, '../web');
const sourceRoot = process.env.OMINULL_FIXTURE_SOURCE || root;
const mime = {'.js':'application/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2','.webmanifest':'application/manifest+json'};
const server = http.createServer((req,res) => {
 if(server.offline) { req.socket.destroy(); return; }
 if(req.method !== 'GET') { res.writeHead(405).end(); return; }
 let name = new URL(req.url,'http://fixture').pathname;
 if(server.fixtureData && name.startsWith('/api/v1/')) {
  res.setHeader('Content-Type','application/json');res.setHeader('Cache-Control','no-store');
  res.end(JSON.stringify(server.fixtureData[name] ?? (name==='/api/v1/traffic/flows' ? {total:0,flows:[]} : [])));return;
 }
 if(name === '/') name = '/index.html';
 let file = path.resolve(root, '.' + name);
 if(!file.startsWith(root + path.sep)) { res.writeHead(403).end(); return; }
 if(name === '/axe.js') file = require.resolve('../../../../web-build/node_modules/axe-core/axe.min.js');
 try {
  // The console loads app.min.js; serve the audit-patched source minified the
  // way the build does, so the browser suite exercises the shipped shape.
  const minified = name === '/app.min.js';
  if(minified) name = '/app.js';
  let body = fs.readFileSync(name === '/app.js' || name === '/sw.js' ? path.join(sourceRoot,name) : file);
  if(name === '/index.html') body = body.toString().replaceAll('{{HUB_VERSION}}','fixture').replaceAll('{{ADMIN_KEY}}','AUDIT_SENTINEL').replaceAll('{{OPERATOR}}','fixture@example.invalid').replaceAll('{{OPERATOR_ROLE}}',new URL(req.url,'http://x').searchParams.get('role')||'admin');
  if(name === '/app.js') body = body.toString().replace('  if (document.readyState === "loading")', '  window.audit={fixtureGraph(){const used={};const byEp={},byIP={};arrayOf(state.scanAssets).forEach(a=>{if(a.ip)byIP[a.ip]=a;if(a.agent_endpoint_id)byEp[a.agent_endpoint_id]=a;});const out=arrayOf(state.endpoints).map(ep=>{const sc=byEp[ep.id]||byIP[ep.ip]||null;if(sc)used[sc.ip]=true;return {id:ep.id,agent_endpoint_id:ep.id,ip:ep.ip||"",mac:ep.mac||"",hostname:ep.hostname,os:ep.os,vendor:sc?sc.vendor:"",category:ep.role_tag,role:ep.role_tag,risk_score:sc?sc.risk_score:"",tenant_id:ep.tenant_id,location_id:ep.location_id,last_seen_at:ep.last_seen_at,ports:sc?arrayOf(sc.open_ports):[],claims:[{field:"os",source:"agent",value:ep.os||"",confidence:1,winner:true}]};});arrayOf(state.scanAssets).forEach(a=>{if(!used[a.ip])out.push({id:"ip:"+a.ip,agent_endpoint_id:"",ip:a.ip,mac:a.mac||"",hostname:a.hostname,os:a.os_guess,vendor:a.vendor,category:a.category,role:"",risk_score:a.risk_score,tenant_id:"",location_id:"",last_seen_at:a.last_seen,ports:arrayOf(a.open_ports),claims:[{field:"os",source:"scan",value:a.os_guess||"",confidence:Number(a.confidence)||0,winner:true}]});});return out;},setDemoFleet(){DEMO_CACHE["/api/v1/endpoints"]=state.endpoints;DEMO_CACHE["/api/v1/assets"]=window.audit.fixtureGraph();DEMO_CACHE["/api/v1/scanner/results"]=state.scanAssets;return DEMO_CACHE;},state,render,renderBody,emptyFleet,applyTheme,buildAssets,sortAssetRows,openRoute,closeRoute,renderRoute,openAccountPop,closeAccountPop,openSheet,closeAllSheets,go,request,stamp,cellText,cellSortKey,refresh,h,launchTerminalShell,closeSheet,hostScopes};\n  if (document.readyState === "loading")');
  if(name === '/app.js') body = body.toString().replace('"serviceWorker" in navigator && !state.demo', '"serviceWorker" in navigator && (!state.demo || location.search.includes("pwa-fixture"))');
  if(minified) body = minifyConsole(body.toString());
  if(name === '/sw.js') body = body.toString().replaceAll('{{HUB_VERSION}}',server.fixtureVersion || 'fixture');
  res.setHeader('Content-Type',mime[path.extname(name)] || 'application/octet-stream');
  res.setHeader('Cache-Control','no-store');
  res.end(body);
 } catch { res.writeHead(404).end(); }
});
server.listen(Number(process.env.OMINULL_FIXTURE_PORT || 18764),'127.0.0.1');
module.exports = server;
