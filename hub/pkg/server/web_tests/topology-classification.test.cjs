const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../web/app.js'), 'utf8');
// Exercise the rendering model without a DOM; retain the production functions.
const context = vm.createContext({nodeKind: n => n.type});
for (const [start, end] of [['  function getClusterCategory(', '  function layoutTopology('], ['  function topoGroupKey(', '  var TOPO_RISK_ORDER']]) {
  vm.runInContext(source.slice(source.indexOf(start), source.indexOf(end)), context);
}
test('network grouping uses server scope and stable IDs, including IPv6', () => {
 for (const n of [
  {ip:'fd12::2', network_id:'private:', network_label:'Private IPv6'},
  {ip:'2001:db8:4::2', estate_member:true, network_id:'2001:db8:4::/64', network_label:'Lab'},
  {ip:'2001:db8:5::2', estate_member:true, network_id:'2001:db8:5::/64', network_label:'Lab'},
 ]) assert.equal(context.topoGroupKey(n, 'subnet'), n.network_id);
});
test('roles, addresses, and names do not invent management or infrastructure', () => {
 assert.equal(context.getClusterCategory({ip:'10.0.0.58', label:'hub-cap', type:'unmanaged', role:'workstation', estate_member:true}), 'iot');
 assert.equal(context.getClusterCategory({ip:'172.31.0.2', type:'unmanaged', address_scope:'private'}), 'iot');
 assert.equal(context.getClusterCategory({ip:'2001:db8::2', type:'unmanaged', estate_member:true}), 'iot');
 assert.equal(context.getClusterCategory({ip:'2001:db8::3', type:'cloud', address_scope:'public', estate_member:false}), 'cloud');
});
