const fs=require('fs'),vm=require('vm'),assert=require('node:assert/strict');
async function check(file){
 const source=fs.readFileSync(file,'utf8');
 const fn=source.slice(source.indexOf('async function applyTunerResult(){'),source.indexOf('\ndocument.querySelectorAll(".tab")',source.indexOf('async function applyTunerResult(){')));
 for(const mode of ['success','error','mismatch','verify-error','cancel']){
  const els={};for(const id of ['applyTunerResult','tunerApplyStatus','tunerApplyProgress','tunerFoundId'])els[id]={textContent:id==='tunerFoundId'?'abc':'',hidden:true,disabled:false,setAttribute(k,v){this[k]=v}};
  let release,calls=0;const gate=new Promise(r=>release=r);
  async function api(path){calls++;if(path==='/api/tuner/apply'){await gate;if(mode==='error')throw Error('test failure');return {ok:true,output:'ok'}}if(mode==='verify-error')throw Error('read failed');return {profiles:[{installed:true,candidate_id:mode==='mismatch'?'other':'abc'}]}}
  const ctx={document:{getElementById:id=>els[id]},confirm:()=>mode!=='cancel',busy:v=>els.applyTunerResult.disabled=v,api,operation:api,log(){},resultText(){},refresh:async()=>{},refreshProfiles:async()=>{},refreshVersions:async()=>{},refreshTuner:async()=>{},postChecksAfter:async()=>{}};
  ctx.controlHeaders={};vm.createContext(ctx);vm.runInContext(fn,ctx);const pending=ctx.applyTunerResult();
  if(mode==='cancel'){await pending;assert.equal(calls,0);continue}
  assert.equal(els.tunerApplyProgress.hidden,false);assert.equal(els.applyTunerResult.disabled,true);assert.match(els.applyTunerResult.textContent,/Применяется/);
  release();await pending;assert.equal(els.tunerApplyProgress.hidden,true);assert.equal(els.applyTunerResult.disabled,false);assert.equal(els.tunerApplyStatus['aria-busy'],'false');
  assert.match(els.tunerApplyStatus.textContent,mode==='error'?/Ошибка применения/:mode==='mismatch'?/не совпал/:mode==='verify-error'?/подтвердить.*не удалось/:/Применён профиль abc/);
 }
 console.log('PASS '+file);
}
(async()=>{for(const p of (process.argv.length>2?process.argv.slice(2):['tools/router/xkeen_control_script.sh']))await check(p)})().catch(e=>{console.error(e);process.exit(1)});
