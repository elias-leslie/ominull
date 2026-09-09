// Sanitized fixture only. No production credentials or write routes exist.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
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
  let body = fs.readFileSync(name === '/app.js' || name === '/sw.js' ? path.join(sourceRoot,name) : file);
  if(name === '/index.html') body = body.toString().replaceAll('{{HUB_VERSION}}','fixture').replaceAll('{{ADMIN_KEY}}','AUDIT_SENTINEL').replaceAll('{{OPERATOR}}','fixture@example.invalid').replaceAll('{{OPERATOR_ROLE}}','admin');
  if(name === '/app.js') body = body.toString().replace('  if (document.readyState === "loading")', '  window.audit={setDemoFleet(){DEMO_CACHE["/api/v1/endpoints"]=state.endpoints;DEMO_CACHE["/api/v1/assets"]=[];DEMO_CACHE["/api/v1/scanner/results"]=state.scanAssets;return DEMO_CACHE;},state,render,renderBody,applyTheme,openIPv6Monitor,buildAssets,sortAssetRows,openRoute,closeRoute,renderRoute,openAccountPop,closeAccountPop,openSheet,closeAllSheets,go,request,stamp,cellText,cellSortKey,refresh,h};\n  if (document.readyState === "loading")');
  if(name === '/app.js') body = body.toString().replace('"serviceWorker" in navigator && !state.demo', '"serviceWorker" in navigator && (!state.demo || location.search.includes("pwa-fixture"))');
  if(name === '/sw.js') body = body.toString().replaceAll('{{HUB_VERSION}}',server.fixtureVersion || 'fixture');
  res.setHeader('Content-Type',mime[path.extname(name)] || 'application/octet-stream');
  res.setHeader('Cache-Control','no-store');
  res.end(body);
 } catch { res.writeHead(404).end(); }
});
server.listen(Number(process.env.OMINULL_FIXTURE_PORT || 18764),'127.0.0.1');
module.exports = server;
