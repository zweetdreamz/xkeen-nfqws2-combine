/* Independent checker: cached reads, explicit checks and manual IP approval. */
(()=>{
  const el=id=>document.getElementById(id);
  const statuses={healthy:"IP совпадает, HTTPS доступен","ip-mismatch":"ВНИМАНИЕ: выходной IP изменился",unapproved:"IP ещё не одобрен",partial:"Не все выбранные IP family подтверждены",unreachable:"IP совпадает, HTTPS canary не подтверждён",stale:"Результат устарел или относится к другой ноде",unavailable:"Проверка недоступна",skipped:"Проверка пропущена: проект занят",unknown:"Наблюдений пока нет"};
  let polling=false,dirty=false,monitor=null,formIdentity={};
  const families=()=>el("vpnMonitorFamily").value==="both"?["ipv4","ipv6"]:[el("vpnMonitorFamily").value];
  const post=(url,body)=>api(url,{method:"POST",headers:controlHeaders,body:JSON.stringify(body)});
  function showResult(id,result){
    if(!result){el(id).textContent="Проверок пока нет.";return}
    const rows=[result.scope||"",result.detail||""];
    if(result.checked_at)rows.unshift("Проверено: "+new Date(result.checked_at*1000).toLocaleString());
    (result.routes||[]).forEach(x=>rows.push(x.ip+" → "+x.outbound+" ("+x.path+")"));
    (result.checks||[]).forEach(x=>rows.push([x.name||x.family,x.path,x.tls?"TLS "+x.tls:"",x.ok?"OK":"НЕ ПОДТВЕРЖДЕНО",x.http_code?"HTTP "+x.http_code:"",typeof x.bytes==="number"?x.bytes+" байт":"",x.detail].filter(Boolean).join(" · ")));
    if(result.observed)Object.entries(result.observed).forEach(([f,ip])=>rows.push(f+": "+(ip||"не подтверждён")));
    if(result.note)rows.push(result.note);
    el(id).textContent=rows.filter(Boolean).join("\n");
  }
  function renderMonitor(data){
    monitor=data;
    const result=(data.state||{}).result||{},identity=data.identity||{},expected=data.expected||{};
    el("vpnMonitorSummary").textContent=(data.config.enabled?"Контроль включён":"Контроль выключен")+" · "+(identity.node_id||"нода не подтверждена")+" · "+(statuses[data.verdict]||data.verdict)+(data.detail?" · "+data.detail:"");
    if(!dirty){
      formIdentity=data.identity;
      el("vpnMonitorEnabled").checked=data.config.enabled;el("vpnMonitorInterval").value=data.config.interval_minutes;
      el("vpnMonitorFamily").value=data.config.families.length===2?"both":data.config.families[0];
      el("vpnExpected4").value=(expected.ipv4||[]).join(", ");el("vpnExpected6").value=(expected.ipv6||[]).join(", ");
    }
    const changed=dirty&&JSON.stringify(formIdentity)!==JSON.stringify(identity);
    el("vpnMonitorSave").disabled=changed;
    if(changed)el("vpnMonitorSummary").textContent+=" · Нода изменилась; обновите форму перед сохранением.";
    showResult("vpnMonitorResult",result);
    el("vpnMonitorApprove").disabled=changed||data.active||result.status!=="completed"||result.node_id!==identity.node_id||result.source_digest!==identity.source_digest||Date.now()/1000-result.checked_at>300;
    el("vpnMonitorHistory").textContent=(data.state.history||[]).slice().reverse().map(x=>new Date(x.at*1000).toLocaleString()+" · "+(statuses[x.status]||x.status)+" · "+(x.node_id||"")+" · "+Object.values(x.observed||{}).filter(Boolean).join(", ")).join("\n")||"Событий пока нет.";
  }
  async function refreshInspection(){
    try{
      const [checks,data]=await Promise.all([api("/api/inspection/status"),api("/api/vpn-monitor")]);
      showResult("inspectRouteResult",(checks.results||{}).route);showResult("inspectResourceResult",(checks.results||{}).resources);renderMonitor(data);
      ["inspectRoute","inspectResources","vpnMonitorCheck","inspectSetup"].forEach(id=>el(id).disabled=checks.active);
      return checks;
    }catch(error){el("vpnMonitorSummary").textContent="Ошибка статуса: "+error;return null}
  }
  async function check(kind,body){
    if(polling)return;polling=true;
    try{
      const job=await post("/api/inspection/check/"+kind,body),deadline=Date.now()+190000;
      while(Date.now()<deadline){await delay(800);const state=await refreshInspection();if(!state)continue;if(state.job_id!==job.job_id)throw new Error("ID проверки изменился");if(!state.active){if(state.status==="interrupted")throw new Error("Проверка прервалась");return}}
      throw new Error("Превышено время проверки");
    }catch(error){el(kind==="route"?"inspectRouteResult":kind==="resources"?"inspectResourceResult":"vpnMonitorSummary").textContent="Ошибка: "+error}
    finally{polling=false}
  }
  el("inspectRoute").addEventListener("click",()=>check("route",{domain:el("inspectDomain").value,ip:el("inspectIp").value,inbound:el("inspectInbound").value,network:el("inspectNetwork").value,port:Number(el("inspectPort").value),source:el("inspectSource").value,source_port:Number(el("inspectSourcePort").value)}));
  el("inspectResources").addEventListener("click",()=>{const path=el("inspectPath").value;check("resources",{targets:[el("inspectResource").value],paths:path==="both"?["direct","vpn"]:[path],extended:el("inspectExtended").checked})});
  el("vpnMonitorCheck").addEventListener("click",()=>check("vpn",{families:families()}));
  el("vpnMonitorApprove").addEventListener("click",async()=>{
    if(!monitor)return;const result=monitor.state.result||{},observed=result.observed||{},approval={families:families(),identity:monitor.identity,observation_id:result.observation_id};
    if(!confirm("Одобрить выходные IP текущей ноды для "+families().join(", ")+": "+families().map(f=>observed[f]||"не подтверждён").join(", ")+"?"))return;
    try{await post("/api/vpn-monitor/approve",approval);dirty=false;await refreshInspection()}catch(error){el("vpnMonitorSummary").textContent="Ошибка одобрения: "+error}
  });
  el("vpnMonitorSave").addEventListener("click",async()=>{
    const ips=id=>el(id).value.split(",").map(x=>x.trim()).filter(Boolean);
    if(!monitor)return;
    const body={identity:formIdentity,changes:{enabled:el("vpnMonitorEnabled").checked,interval_minutes:Number(el("vpnMonitorInterval").value),families:families(),expected:{ipv4:ips("vpnExpected4"),ipv6:ips("vpnExpected6")}}};
    if(!confirm("Сохранить вручную указанные разрешённые IP и настройки контроля текущей ноды?"))return;
    try{await post("/api/vpn-monitor/save",body);dirty=false;await refreshInspection()}catch(error){el("vpnMonitorSummary").textContent="Ошибка сохранения: "+error}
  });
  el("inspectSetup").addEventListener("click",async()=>{
    if(!confirm("Подготовить локальные API/SOCKS для диагностики? Xray перезапустится с той же VPN-нодой; трафик кратковременно прервётся."))return;
    try{const job=await post("/api/inspection/setup",{confirm:true});await watchRouteJob(job.job_id,"Подготовка диагностики");await refreshInspection()}catch(error){el("inspectRouteResult").textContent="Ошибка подготовки: "+error}
  });
  document.querySelectorAll("#vpnMonitorCard input,#vpnMonitorCard select").forEach(control=>control.addEventListener("input",()=>{dirty=true}));
  el("vpnMonitorReload").addEventListener("click",()=>{dirty=false;refreshInspection()});
  const visible=()=>document.querySelector('.tab.active[data-tab="vpn-nodes"],.tab.active[data-tab="diagnostics"]');
  document.querySelectorAll('.tab[data-tab="vpn-nodes"],.tab[data-tab="diagnostics"]').forEach(tab=>tab.addEventListener("click",refreshInspection));
  setInterval(()=>{if(visible()&&!polling)refreshInspection()},15000);
  if(visible())refreshInspection();
})();
