(()=>{
 const a=audit, seed=a.state.endpoints.slice();
 a.state.section='assets';a.state.assetSort=null;a.state.query='';a.state.filters={};a.state.selected={};a.state.assetGraph=[];
 a.state.scanAssets=a.state.scanAssets.filter(scan=>!seed.some(ep=>ep.ip===scan.ip));
 const results=[];
 for(const size of [14,100,1007]){
  a.state.endpoints=Array.from({length:size-a.state.scanAssets.length},(_,i)=>({...seed[i%seed.length],id:'fixture-'+i,hostname:'fixture-'+i,ip:'10.20.'+Math.floor(i/250)+'.'+(i%250+1),mac:'02:fa:00:00:'+Math.floor(i/256).toString(16).padStart(2,'0')+':'+(i%256).toString(16).padStart(2,'0')}));
  a.buildAssets();const renders=[];for(let i=0;i<6;i++){const start=performance.now();a.render();renders.push(performance.now()-start);}
  results.push({assets:a.state.assets.length,uniqueAddresses:new Set(a.state.assets.map(x=>x.ip)).size,renders,nodes:document.querySelectorAll('*').length,mountedRows:document.querySelectorAll('#view tr.row').length});
 }
 return {browser:navigator.userAgent,viewport:[innerWidth,innerHeight],results};
})()
