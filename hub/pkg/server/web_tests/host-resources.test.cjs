const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../web/app.js'),'utf8');
const code=source.slice(source.indexOf('  var hostScopes ='),source.indexOf('  function openRoute('));
test('host flow failure does not mark successfully loaded alerts unavailable',async()=>{
 const scope={state:{assetByKey:{host:{endpoint:{id:'fixture'}}},routeKey:'host'},renderRoute(){},request(url){return url.includes('/traffic/')?Promise.reject(Error('flow fixture unavailable')):Promise.resolve({total:73,alerts:[]});}};
 vm.runInNewContext(code,scope);scope.loadHostScope('host');await new Promise(r=>setImmediate(r));
 assert.equal(scope.hostScopes.host.alerts.total,73);
 assert.equal(scope.hostScopes.host.error || '', '', 'unrelated flow failure poisons alert status');
});
