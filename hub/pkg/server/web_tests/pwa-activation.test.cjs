const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm'),path=require('node:path');
const source=fs.readFileSync(process.env.OMINULL_APP_SOURCE || path.join(__dirname,'../web/app.js'),'utf8');
const code=source.slice(source.indexOf('    if ("serviceWorker" in navigator'),source.indexOf('    /* A hidden tab',source.indexOf('    if ("serviceWorker" in navigator')));
async function fixture(){
 const handlers={},elements={};let reloads=0,sent=0;
 const registration={active:{},waiting:{postMessage(){sent++;}},addEventListener(){}};
 const scope={state:{demo:false},window:{addEventListener(_event,fn){fn();}},navigator:{serviceWorker:{register:()=>Promise.resolve(registration),addEventListener(event,fn){handlers[event]=fn;}}},h(_tag,props){const el={...props,remove(){delete elements[props.id];}};return el;},$(id){return id==='connection-status'?{after(el){elements[el.id]=el;}}:elements[id];},location:{reload(){reloads++;}},guardNavigation(fn){fn();},toast(){}};
 vm.runInNewContext(code,scope);await new Promise(r=>setImmediate(r));
 return {handlers,elements,get reloads(){return reloads;},get sent(){return sent;}};
}
test('controller change without an explicit update never reloads the app',async()=>{
 const f=await fixture();f.handlers.controllerchange();assert.equal(f.reloads,0);
});
test('a blocked update cannot authorize a later unsolicited reload',async()=>{
 const f=await fixture();f.elements['pwa-update'].on.click();assert.equal(f.sent,1);
 f.handlers.message({data:{type:'UPDATE_BLOCKED'}});f.handlers.controllerchange();assert.equal(f.reloads,0);
});
test('an explicitly requested update reloads after controller change',async()=>{
 const f=await fixture();f.elements['pwa-update'].on.click();f.handlers.controllerchange();assert.equal(f.reloads,1);
});
