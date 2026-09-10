const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../web/app.js'),'utf8');
const code=source.slice(source.indexOf('  var hostScopes ='),source.indexOf('  function openRoute('));
test('host flow failure does not mark successfully loaded alerts unavailable',async()=>{
 const scope={state:{assetByKey:{host:{endpoint:{id:'fixture'}}},routeKey:'host'},renderRoute(){},request(url){return url.includes('/traffic/')?Promise.reject(Error('flow fixture unavailable')):Promise.resolve({total:73,alerts:[]});}};
 vm.runInNewContext(code,scope);scope.loadHostScope('host');await new Promise(r=>setImmediate(r));
 assert.equal(scope.hostScopes.host.alerts.total,73);
 assert.equal(scope.hostScopes.host.error || '', '', 'unrelated flow failure poisons alert status');
});

test('host identifiers cannot inherit or modify object prototypes',async()=>{
 for(const key of ['__proto__','constructor','toString']) {
  const assets=Object.create(null);assets[key]={endpoint:{id:'fixture'}};
  const scope={state:{assetByKey:assets,routeKey:key},renderRoute(){},request(){return Promise.resolve({total:1});}};
  vm.runInNewContext(code,scope);scope.loadHostScope(key);await new Promise(r=>setImmediate(r));
  assert.equal(vm.runInNewContext('Object.prototype.loading',scope),undefined);
  assert.equal(Object.hasOwn(scope.hostScopes,key),true);
  assert.equal(scope.hostScopes[key].alerts.total,1);
 }
});

test('response session identifier uses secure browser randomness',()=>{
 const line=source.split('\n').find(line=>line.includes('var browserSessionId ='));
 const scope={Math:{random(){throw Error('insecure randomness used')}},window:{crypto:require('node:crypto').webcrypto},bufToHex:buf=>Buffer.from(buf).toString('hex')};
 vm.runInNewContext(line,scope);
 assert.match(scope.browserSessionId,/^sess-browser-[a-f0-9]{32}$/);
});
