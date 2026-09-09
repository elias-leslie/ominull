const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(require('node:path').join(__dirname,'../web/app.js'),'utf8');
const body=source.slice(source.indexOf('  function evidenceOf('),source.indexOf('  function buildAssets('));
const scope={arrayOf:x=>x||[],claimGrade:c=>c?'full':false,bestClaim:()=>null};
vm.runInNewContext(body,scope);
test('legacy discovery vendor claim is not proof of an active probe',()=>{
 const asset={claims:[{field:'vendor',source:'scan',value:'RF Code',confidence:.9}],ports:[]};
 assert.equal(scope.evidenceOf(asset).scan,false);
 asset.ports=[{port:443}];
 assert.equal(scope.evidenceOf(asset).scan,'full');
});
