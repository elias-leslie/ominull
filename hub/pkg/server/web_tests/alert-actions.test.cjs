const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname,'../web/app.js'),'utf8');
test('page acknowledgement freezes only visible open IDs at confirmation', async () => {
 const requests=[];let confirmation;
 const context=vm.createContext({
  allAnomalies:[{id:'visible',acknowledged:false},{id:'hidden',acknowledged:false},{id:'done',acknowledged:true}],
  filteredAnomalies:[{id:'visible',acknowledged:false},{id:'done',acknowledged:true}],
  h:(_tag,props)=>props, confirmSheet:options=>{confirmation=options;},
  request:(path,method,body)=>{requests.push({path,method,body});return Promise.resolve({});},
  toast:()=>{},refresh:()=>{},state:{}
 });
 vm.runInContext(source.slice(source.indexOf('    var ackAllBtn ='),source.indexOf('    var clearResolvedBtn =')),context);
 context.ackAllBtn.on.click();
 assert.match(confirmation.confirmLabel,/1/);
 context.filteredAnomalies.push({id:'arrived-later',acknowledged:false});
 confirmation.onConfirm();
 await Promise.resolve();
 assert.deepEqual(JSON.parse(JSON.stringify(requests)),[{path:'/api/v1/anomalies/acknowledge',method:'POST',body:{ids:['visible']}}]);
});
