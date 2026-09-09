const fs=require('node:fs');
module.exports=async function(page){
 const {default:AxeBuilder}=require('../../../../web-build/node_modules/@axe-core/playwright');
 await page.reload();await page.waitForFunction(()=>window.audit?.state.assets.length>0);
 const results=[];fs.mkdirSync('build/console-design',{recursive:true});
 for(const width of [390,768,1024,1440])for(const theme of ['graphite','bunker','ash','phosphor'])for(const section of ['assets','alerts','traffic','policy','response']){
  await page.setViewportSize({width,height:800});
  await page.evaluate(({theme,section})=>{const a=window.audit;a.state.policyHealth=false;a.state.section=section;a.applyTheme(theme,false);a.render();},{theme,section});
  const violations=(await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa']).analyze()).violations;
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);
  const name=`${section}-${theme}-${width}`;
  await page.screenshot({path:`build/console-design/${name}.png`,fullPage:true});
  results.push({name,overflow,violations:violations.map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)}))});
 }
 fs.writeFileSync('build/console-design/results.json',JSON.stringify(results,null,2));
 if(results.some(r=>r.overflow || r.violations.length))throw Error('Responsive/a11y design checks failed: '+JSON.stringify(results.filter(r=>r.overflow || r.violations.length)));
 await page.setViewportSize({width:1280,height:720});
};
