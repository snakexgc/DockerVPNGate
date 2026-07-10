const $ = id => document.getElementById(id);
let dashboard = null;
let currentSlot = 1;
let currentScreen = "system";
let nodes = [];
let toastTimer = null;
let nodeUpdateEpoch = 0;
let trafficEpoch = 0;
let singleNodeTestEpoch = 0;
let settingsDirty = false;
let proxyFormDirty = false;
let settingsSavedUsername = "";
let settingsSavedSecretPath = "";

function esc(value) { return String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function showToast(message, error=false) { const el=$("toast"); el.textContent=message; el.className="toast show"+(error?" error":""); clearTimeout(toastTimer); toastTimer=setTimeout(()=>el.className="toast",3200); }
async function api(path, options={}) {
  const response = await fetch(`./api/${path}`, {headers:{"Content-Type":"application/json",...(options.headers||{})}, ...options});
  let body={}; try { body=await response.json(); } catch (_) {}
  if (response.status===401) { location.reload(); throw new Error("登录已失效"); }
  if (!response.ok || body.ok===false) throw new Error(body.error || `请求失败 (${response.status})`);
  return body;
}
function duration(seconds) { seconds=Number(seconds)||0; if(seconds<60)return `${seconds}s`; if(seconds<3600)return `${Math.floor(seconds/60)}m`; if(seconds<86400)return `${Math.floor(seconds/3600)}h ${Math.floor(seconds%3600/60)}m`; return `${Math.floor(seconds/86400)}d ${Math.floor(seconds%86400/3600)}h`; }
function formatBytes(bytes) {
  const value=Math.max(0,Number(bytes)||0), units=["B","KB","MB","GB","TB"];
  if(value<1024)return `${Math.round(value)} B`;
  const unit=Math.min(Math.floor(Math.log(value)/Math.log(1024)),units.length-1), scaled=value/(1024**unit);
  return `${scaled.toFixed(scaled>=100?0:scaled>=10?1:2)} ${units[unit]}`;
}
function formatRate(bytes) { return `${formatBytes(bytes)}/s`; }
function fetchTime(timestamp) { const value=Number(timestamp)||0; return value ? new Date(value*1000).toLocaleString("zh-CN",{hour12:false}) : "-"; }
function statusText(status) { return ({connected:"已连接",connecting:"连接中",degraded:"异常",disconnected:"未连接",disabled:"已停用"})[status]||status; }
function countryChoice(value) {
  if(!value)return null;
  return dashboard?.countries?.find(country=>country.value===value || (country.aliases||[]).includes(value)) || null;
}
function countryLabel(value) { if(!value)return "自动"; return countryChoice(value)?.label || value; }
function countryValue(value) { if(!value)return ""; return countryChoice(value)?.value || value; }
function nodeCountryValue(node) { return countryChoice(node?.country)?.value || node?.country_label || node?.country || ""; }
function nodeStatusValue(status) { return status==="not_checked" || !status ? "queued" : status; }
function probeText(status) { return ({available:"可用",unavailable:"不可用",testing:"检测中",queued:"排队中",not_checked:"排队中"})[status]||status||"排队中"; }
function ipTypeText(type) { return ({residential:"住宅",mobile:"移动",hosting:"数据中心"})[type]||type||"未知"; }
function flagEmoji(code) { return /^[A-Z]{2}$/.test(code||"") ? String.fromCodePoint(...[...code].map(char=>127397+char.charCodeAt())) : "◎"; }
function sleep(ms) { return new Promise(resolve=>setTimeout(resolve,ms)); }
function latencyClass(ms) { ms=Number(ms)||0; return !ms?"":ms<50?"latency-good":ms<150?"latency-medium":"latency-poor"; }
function probeTime(node) { return Number(node?.probed_at)||0 ? fetchTime(node.probed_at) : "-"; }
function marqueeText(value, className="") { const text=esc(value||"-"); return `<span class="marquee ${className}" title="${text}"><span class="marquee-track">${text}</span></span>`; }
function refreshMarquees(root=document) {
  requestAnimationFrame(()=>root.querySelectorAll(".marquee").forEach(item=>{
    const track=item.querySelector(".marquee-track");
    if(!track)return;
    const overflow=track.scrollWidth-item.clientWidth;
    item.classList.toggle("marquee-active", overflow>6);
    item.style.setProperty("--marquee-shift", `${Math.min(0,-overflow)}px`);
    item.style.setProperty("--marquee-duration", `${Math.max(7, Math.min(18, overflow/18+7))}s`);
  }));
}
function activeElementId() { return document.activeElement?.dataset?.selectId || document.activeElement?.id || ""; }
function settingsInputIds() { return ["current-admin-password","admin-username","admin-password","admin-password-confirm","secret-path","proxy-username","proxy-password","node-cache-size"]; }
function isSettingsFormActive() { return settingsInputIds().includes(activeElementId()); }
function isNodeFilterActive() { return ["node-search","node-country","node-ip-type","node-status","all-node-search","all-node-country","all-node-type","all-node-status"].includes(activeElementId()); }
function shouldDeferHeartbeatRender() {
  if(currentScreen==="proxy")return proxyFormDirty || isProxyFormActive() || isNodeFilterActive();
  if(currentScreen==="settings")return settingsDirty || isSettingsFormActive();
  if(currentScreen==="nodes")return isNodeFilterActive();
  return false;
}
function slotStatusIcon(status) {
  if(status==="connected") return '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>';
  if(status==="connecting") return '<svg class="spin" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18"/></svg>';
  return '<svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg>';
}
function trafficMarkup(slotId, traffic={}, nodeLatency="<strong>-</strong>") {
  const rateTotal=(Number(traffic.download_bps)||0)+(Number(traffic.upload_bps)||0);
  return `<div class="active-card-line active-card-line-traffic">
    <span class="metric metric-latency"><em>节点延时:</em>${nodeLatency}</span>
    <span class="metric metric-speed"><em>实时速度:</em><strong class="traffic-value" id="traffic-rate-total-${slotId}">${formatRate(rateTotal)}</strong><span class="traffic-rates"><span class="traffic-down" id="traffic-down-rate-${slotId}">↓ ${formatRate(traffic.download_bps)}</span><span class="traffic-up" id="traffic-up-rate-${slotId}">↑ ${formatRate(traffic.upload_bps)}</span></span></span>
    <span class="metric metric-today"><em>今日流量:</em><strong class="traffic-value" id="traffic-today-${slotId}">${formatBytes(traffic.today_total)}</strong><small class="traffic-split" id="traffic-today-split-${slotId}">↓ ${formatBytes(traffic.today_download)} · ↑ ${formatBytes(traffic.today_upload)}</small></span>
  </div>`;
}
function updateTrafficDisplay(data) {
  const slots=data?.slots||[];
  const aggregate=slots.reduce((total,traffic)=>({
    download_bps:total.download_bps+(Number(traffic.download_bps)||0),
    upload_bps:total.upload_bps+(Number(traffic.upload_bps)||0),
    bytes:total.bytes+(Number(traffic.total)||0)
  }),{download_bps:0,upload_bps:0,bytes:0});
  const summaryValues={
    "sum-download-rate":`↓ ${formatRate(aggregate.download_bps)}`,
    "sum-upload-rate":`↑ ${formatRate(aggregate.upload_bps)}`,
    "sum-traffic-total":`总流量 ${formatBytes(aggregate.bytes)}`
  };
  Object.entries(summaryValues).forEach(([id,value])=>{const element=$(id);if(element)element.textContent=value;});
  slots.forEach(traffic=>{
    const slot=dashboard?.slots?.find(item=>item.id===traffic.id); if(slot)slot.traffic=traffic;
    const values={
      [`traffic-down-rate-${traffic.id}`]:`↓ ${formatRate(traffic.download_bps)}`,
      [`traffic-up-rate-${traffic.id}`]:`↑ ${formatRate(traffic.upload_bps)}`,
      [`traffic-rate-total-${traffic.id}`]:formatRate((Number(traffic.download_bps)||0)+(Number(traffic.upload_bps)||0)),
      [`traffic-today-${traffic.id}`]:formatBytes(traffic.today_total),
      [`traffic-today-split-${traffic.id}`]:`↓ ${formatBytes(traffic.today_download)} · ↑ ${formatBytes(traffic.today_upload)}`
    };
    Object.entries(values).forEach(([id,value])=>{const element=$(id);if(element)element.textContent=value;});
  });
}

function renderNavigation() {
  $("nav-node-count").textContent=dashboard.node_count||0;
  const nav=$("slot-nav"); nav.innerHTML=dashboard.slots.map(slot=>{
    const label=slot.country!=="未连接" ? slot.country : (slot.preferred_country ? countryLabel(slot.preferred_country) : "未配置");
    return `<button class="nav-button ${currentScreen==="proxy"&&currentSlot===slot.id?"active":""}" data-slot="${slot.id}"><span class="nav-icon">${slot.id}</span>代理${slot.id}-${esc(label)}</button>`;
  }).join("");
  nav.querySelectorAll("[data-slot]").forEach(button=>button.onclick=()=>showScreen("proxy",Number(button.dataset.slot)));
  document.querySelectorAll(".sidebar > [data-screen]").forEach(button=>button.classList.toggle("active",button.dataset.screen===currentScreen));
}
function renderSystem() {
  const online=dashboard.slots.filter(slot=>slot.status==="connected").length;
  $("sum-online").textContent=`${online} / 5`; $("side-connected").textContent=`${online} / 5`;
  $("sum-nodes").textContent=dashboard.available_node_count;
  $("sum-uptime").textContent=duration(dashboard.uptime_seconds);
  $("proxy-grid").innerHTML=dashboard.slots.map(slot=>{
    const connected=slot.status==="connected" || slot.status==="degraded";
    const title=connected ? `${flagEmoji(slot.country_code)} ${slot.country} 节点` : slot.status==="connecting" ? "正在与 VPN 节点建立连接" : "当前未连接 VPN 节点";
    const nodeLatency=slot.node_latency_ms ? `<strong class="${latencyClass(slot.node_latency_ms)}">${slot.node_latency_ms} ms</strong>` : "<strong>-</strong>";
    const pulse=slot.status==="connected" || slot.status==="connecting" ? '<span class="badge-pulse"></span>' : "";
    let details="";
    if(connected) {
      details=`<div class="active-card-meta">
        <span class="metric metric-location"><em>物理位置:</em><strong>${marqueeText(slot.location||slot.country||"-")}</strong></span>
        <span class="metric metric-owner"><em>运营主体:</em><strong>${marqueeText(slot.owner||"-")}</strong></span>
        <span class="metric metric-type"><em>IP 类型:</em><strong>${esc(ipTypeText(slot.ip_type))}</strong></span>
        <span class="metric metric-runtime"><em>运行时间:</em><strong>${duration(slot.connected_seconds)}</strong></span>
        <span class="metric metric-policy"><em>失效策略:</em><strong>${slot.switch_mode==="fixed"?"固定选中":"自动切换"}</strong></span>
      </div>`;
    } else {
      const hint=slot.status==="connecting" ? (dashboard.last_check_message||"连接建立后将在这里显示节点地址与线路信息。") : (slot.error||"请进入节点配置，为这个代理选择可用节点。");
      details=`<div class="active-card-meta">${esc(hint)}</div>`;
    }
    const note=slot.using_fallback ? `<div class="slot-note fallback">首选 ${esc(countryLabel(slot.preferred_country))} 暂无可用节点，当前临时使用备用地区；发现首选地区节点后会自动切回。</div>` : "";
    return `<article class="active-card ${slot.status}">
      <div class="active-card-info">
        <div class="active-card-icon">${slotStatusIcon(slot.status)}</div>
        <div class="active-card-details">
          <div class="active-card-title"><span class="badge ${slot.status}">${pulse}代理 ${slot.id} · ${statusText(slot.status)}</span><strong>${esc(title)}</strong></div>
          ${details}${note}${connected?trafficMarkup(slot.id,slot.traffic,nodeLatency):""}
        </div>
      </div>
      <div class="active-card-actions">
        <button class="btn btn-sm" type="button" onclick="showScreen('proxy',${slot.id})">管理代理</button>
      </div>
    </article>`;
  }).join("");
  updateTrafficDisplay({slots:dashboard.slots.map(slot=>({id:slot.id,...(slot.traffic||{})}))});
  refreshMarquees($("proxy-grid"));
}
function isProxyFormActive() {
  const active=document.activeElement;
  return !!active && (["preferred-country","routing-ip-type","slot-enabled"].includes(activeElementId()) || active.name==="switch-mode");
}
function updateProxyReadonly() {
  const current=dashboard?.slots?.[currentSlot-1];
  if(!current)return;
  $("proxy-heading").textContent=`代理 ${currentSlot} 配置 · 内部端口 ${current.port}`;
  $("slot-hint").textContent=current.switch_mode==="fixed"?"固定节点失效后将保持断开，重新可用后只重连该节点。":current.using_fallback?"当前处于跨地区备用状态，发现首选地区节点后会自动切回。":"当前节点失效后会自动连接配置范围内实测延迟最低的节点。";
}
function setCountryOptions(select,baseValue,baseLabel,countries,requestedValue,preferNodeCounts=false) {
  const requested=requestedValue===baseValue?baseValue:countryValue(requestedValue);
  const choices=preferNodeCounts?[]:[...(countries||[])];
  if(preferNodeCounts) {
    (nodes||[]).forEach(node=>{
      const known=countryChoice(node?.country);
      const value=nodeCountryValue(node);
      if(value&&!choices.some(country=>country.value===value))choices.push({...(known||{}),value,label:known?.label||node.country_label||countryLabel(value)});
    });
    choices.sort((a,b)=>String(a.label).localeCompare(String(b.label),"zh-CN"));
  }
  if(requested!==baseValue && !choices.some(country=>country.value===requested))choices.unshift({value:requested,label:countryLabel(requested)});
  const counts=countryCountMap();
  select.innerHTML=`<option value="${esc(baseValue)}">${esc(baseLabel)}</option>`+choices.map(country=>countryOptionMarkup(country,counts,preferNodeCounts)).join("");
  select.value=Array.from(select.options).some(option=>option.value===requested)?requested:baseValue;
  refreshSelect(select);
}
function fillProxyForm(force=false) {
  const current=dashboard?.slots?.[currentSlot-1];
  if(!current)return;
  updateProxyReadonly();
  if(!force && (proxyFormDirty || isProxyFormActive()))return;
  const select=$("preferred-country");
  setCountryOptions(select,"","自动选择",dashboard.countries,current.preferred_country||"");
  $("routing-ip-type").value=current.routing_ip_type||"all"; $("slot-enabled").checked=!!current.enabled;
  refreshSelect($("routing-ip-type"));
  const mode=document.querySelector(`[name="switch-mode"][value="${current.switch_mode||"auto"}"]`); if(mode)mode.checked=true;
  proxyFormDirty=false;
}
function fillProxyNodeFilters(reset=false,preferNodeCounts=false) {
  const current=dashboard?.slots?.[currentSlot-1];
  if(!current)return;
  const countrySelect=$("node-country");
  const previousCountry=countrySelect.value||"all";
  const preferred=countryValue(current.preferred_country)||"";
  const requestedCountry=reset ? (preferred||"all") : previousCountry;
  setCountryOptions(countrySelect,"all","全部地区",dashboard.countries,requestedCountry,preferNodeCounts);
  if(reset)$("node-ip-type").value=current.routing_ip_type||"all";
  refreshSelect($("node-ip-type"));
}
function renderNodes() {
  const search=$("node-search").value.trim().toLowerCase(), country=$("node-country").value, type=$("node-ip-type").value, status=$("node-status").value;
  const preferred=countryValue(dashboard.slots[currentSlot-1].preferred_country);
  const filtered=nodes.filter(node=>{
    const text=`${node.country_label||""} ${node.ip||""} ${node.remote_host||""} ${node.owner||""}`.toLowerCase();
    const countryMatch=country==="all" || node.country===country || (node.country_label||node.country)===countryLabel(country);
    const typeMatch=type==="all" || (type==="residential" ? ["residential","mobile"].includes(node.ip_type) : node.ip_type===type);
    return (!search||text.includes(search)) && countryMatch && typeMatch && (status==="all"||nodeStatusValue(node.probe_status)===status);
  }).sort((a,b)=>{
    const ap=preferred&&(a.country===preferred||(a.country_label||a.country)===countryLabel(preferred))?0:1,bp=preferred&&(b.country===preferred||(b.country_label||b.country)===countryLabel(preferred))?0:1;
    return ap-bp || (a.probe_status==="available"?0:1)-(b.probe_status==="available"?0:1) || (Number(a.latency_ms)||999999)-(Number(b.latency_ms)||999999);
  });
  $("node-body").innerHTML=filtered.length?filtered.map(node=>`<tr><td><strong>${esc(node.country_label||node.country||"-")}</strong><div class="muted">${esc(node.location||node.country_short||"")}</div></td><td class="mono">${esc(node.ip||node.remote_host)}:${esc(node.remote_port||"")}</td><td>${esc(ipTypeText(node.ip_type))}</td><td>${node.latency_ms?node.latency_ms+" ms":"-"}</td><td>${esc(probeTime(node))}</td><td><span class="dot ${esc(nodeStatusValue(node.probe_status))}"></span>${esc(probeText(node.probe_status))}</td><td>${node.active_proxy?`代理 ${node.active_proxy}`:"-"}</td><td><button class="btn btn-sm ${node.active_proxy===currentSlot?"":"btn-primary"}" data-connect="${esc(node.id)}" ${node.active_proxy&&node.active_proxy!==currentSlot?"disabled":""}>${node.active_proxy===currentSlot?"当前节点":"连接"}</button> <button class="btn btn-sm" data-test="${esc(node.id)}">检测</button></td></tr>`).join(""):'<tr><td colspan="8" class="empty">没有符合条件的节点</td></tr>';
  document.querySelectorAll("[data-connect]").forEach(btn=>btn.onclick=()=>connectNode(btn.dataset.connect));
  document.querySelectorAll("[data-test]").forEach(btn=>btn.onclick=()=>testNode(btn.dataset.test));
  refreshMarquees($("node-body"));
}
async function loadNodes() {
  const data=await api(`nodes?slot=${currentSlot}`); nodes=data.nodes;
  if(currentScreen==="proxy") {
    const preferred=$("preferred-country");
    setCountryOptions(preferred,"","自动选择",dashboard.countries,preferred.value,true);
    fillProxyNodeFilters(false,true);
  }
  renderNodes();
}
function renderAllNodes() {
  const search=$("all-node-search").value.trim().toLowerCase();
  const country=$("all-node-country").value, type=$("all-node-type").value, status=$("all-node-status").value;
  const filtered=nodes.filter(node=>{
    const text=`${node.id||""} ${node.country_label||node.country||""} ${node.ip||""} ${node.remote_host||""} ${node.owner||""} ${node.as_name||""}`.toLowerCase();
    const typeMatch=type==="all" || (type==="residential" ? ["residential","mobile"].includes(node.ip_type) : node.ip_type===type);
    const countryMatch=country==="all" || node.country===country || (node.country_label||node.country)===countryLabel(country);
    return (!search||text.includes(search)) && countryMatch && typeMatch && (status==="all"||nodeStatusValue(node.probe_status)===status);
  }).sort((a,b)=>(a.probe_status==="available"?0:1)-(b.probe_status==="available"?0:1)||(Number(a.latency_ms)||999999)-(Number(b.latency_ms)||999999)||(Number(b.score)||0)-(Number(a.score)||0));
  const available=nodes.filter(node=>node.probe_status==="available").length;
  const countries=new Set(nodes.map(node=>nodeCountryValue(node)).filter(Boolean)).size;
  const active=new Set(nodes.map(node=>node.active_proxy).filter(Boolean)).size;
  $("all-node-total").textContent=`${nodes.length} / ${dashboard?.node_cache_size||150}`; $("all-node-available").textContent=available; $("all-node-countries").textContent=countries; $("all-node-active").textContent=`${active} / 5`;
  $("all-node-result-count").textContent=`显示 ${filtered.length} / ${nodes.length} 个节点`;
  $("node-source-message").textContent=dashboard?.maintenance_running ? "正在更新或并发检测节点，请稍候…" : `${dashboard?.last_check_message||"缓存池等待下一个拉取周期"} · 最近拉取 ${fetchTime(dashboard?.last_fetch_at)}`;
  $("all-node-body").innerHTML=filtered.length?filtered.map(node=>`<tr>
    <td><strong>${flagEmoji(node.country_short)} ${esc(node.country_label||node.country||"-")}</strong><div class="muted">${esc(node.location||node.country_short||"")}</div></td>
    <td><span class="mono">${esc(node.ip||node.remote_host)}:${esc(node.remote_port||"")}</span><div class="muted mono">${marqueeText(node.id||"")}</div></td>
    <td><span title="首次拉取：${esc(fetchTime(node.first_fetched_at||node.fetched_at))}">${esc(fetchTime(node.last_fetched_at||node.fetched_at))}</span></td>
    <td><strong>${esc(String(node.proto||"-").toUpperCase())}</strong></td>
    <td>${esc(ipTypeText(node.ip_type))}</td>
    <td>${node.ping?esc(node.ping)+" ms":"-"}</td><td>${node.latency_ms?esc(node.latency_ms)+" ms":"-"}</td><td>${esc(probeTime(node))}</td>
    <td>${Number(node.sessions||0).toLocaleString()}</td><td>${Number(node.score||0).toLocaleString()}</td>
    <td>${esc(node.owner||node.as_name||"-")}<div class="muted">${esc(node.quality||"")}</div></td>
    <td><span class="dot ${esc(nodeStatusValue(node.probe_status))}"></span>${esc(probeText(node.probe_status))}${node.active_proxy?`<div class="badge connected" style="margin-top:5px">代理 ${node.active_proxy}</div>`:""}</td>
  </tr>`).join(""):'<tr><td colspan="12" class="empty">没有符合筛选条件的节点</td></tr>';
  refreshMarquees($("all-node-body"));
}
async function loadAllNodes() {
  const data=await api("nodes?slot=1"); nodes=data.nodes;
  const select=$("all-node-country"), selected=select.value||"all";
  setCountryOptions(select,"all","全部地区",dashboard.countries,selected,true);
  renderAllNodes();
}
async function loadDashboard(quiet=false, options={}) {
  try {
    const heartbeat=!!options.heartbeat;
    dashboard=await api("dashboard");
    if(heartbeat && shouldDeferHeartbeatRender())return;
    renderNavigation();
    renderSystem();
    if(currentScreen==="proxy") heartbeat ? updateProxyReadonly() : fillProxyForm(!!options.forceForms);
    if(currentScreen==="nodes"&&nodes.length)renderAllNodes();
    if(currentScreen==="settings")fillSettings(!!options.forceForms);
  }
  catch(error) { if(!quiet)showToast(error.message,true); }
}
async function loadTraffic(quiet=true) {
  if(currentScreen!=="system")return;
  const epoch=trafficEpoch;
  try { const data=await api("traffic"); if(epoch===trafficEpoch)updateTrafficDisplay(data); }
  catch(error) { if(!quiet)showToast(error.message,true); }
}
async function resetTraffic() {
  if(!window.confirm("确定清除五个代理的全部流量统计吗？清除后将立即重新开始计量。"))return;
  const button=$("reset-traffic"), original=button.textContent;
  trafficEpoch+=1; button.disabled=true; button.textContent="正在清除…";
  try {
    const data=await api("traffic/reset",{method:"POST",body:"{}"});
    updateTrafficDisplay(data);
    showToast("全部流量统计已清零，已重新开始计量");
  } catch(error) { showToast(error.message,true); }
  finally { button.disabled=false; button.textContent=original; }
}
function showScreen(screen, slot=currentSlot) {
  currentScreen=screen; currentSlot=slot; document.querySelectorAll(".screen").forEach(el=>el.classList.remove("active")); $(`screen-${screen}`).classList.add("active");
  const titles={system:["系统状态","代理出口的实时运行状态"],nodes:["节点配置","查看本次获取的全部 VPNGate 节点并手动刷新"],proxy:[`代理 ${slot} 节点配置`,"选择首选地区、线路类型或指定节点"],settings:["设置","管理登录信息与代理端口认证"]};
  $("page-title").textContent=titles[screen][0]; $("page-subtitle").textContent=titles[screen][1]; $("sidebar").classList.remove("open"); $("save-settings").classList.toggle("visible", screen==="settings"); $("reset-traffic").classList.toggle("visible", screen==="system"); renderNavigation();
  if(screen==="system")loadTraffic();
  if(screen==="nodes")loadAllNodes().catch(e=>showToast(e.message,true)); if(screen==="proxy") { proxyFormDirty=false; fillProxyForm(true); fillProxyNodeFilters(true); loadNodes().catch(e=>showToast(e.message,true)); } if(screen==="settings"){fillSettings(); loadSettingsSecrets().catch(e=>showToast(e.message,true));}
}
async function saveSlot() { try { const mode=document.querySelector('[name="switch-mode"]:checked')?.value||"auto"; await api("slots/update",{method:"POST",body:JSON.stringify({slot:currentSlot,preferred_country:$("preferred-country").value,routing_ip_type:$("routing-ip-type").value,switch_mode:mode,enabled:$("slot-enabled").checked})}); proxyFormDirty=false; showToast("代理配置已保存，调度器正在应用"); await loadDashboard(false,{forceForms:true}); fillProxyNodeFilters(true); renderNodes(); } catch(e){showToast(e.message,true);} }
async function connectNode(nodeId) { try { showToast(`代理 ${currentSlot} 正在建立隧道...`); await api("slots/connect",{method:"POST",body:JSON.stringify({slot:currentSlot,node_id:nodeId})}); await loadDashboard(); await loadNodes(); showToast("连接成功"); } catch(e){showToast(e.message,true);} }
async function testNode(nodeId) {
  const epoch=++singleNodeTestEpoch;
  try {
    showToast("正在检测节点，新的检测请求会自动取代旧请求...");
    await api("nodes/test",{method:"POST",body:JSON.stringify({node_id:nodeId})});
    if(epoch!==singleNodeTestEpoch)return;
    if(currentScreen==="nodes")await loadAllNodes(); else await loadNodes();
    showToast("节点检测完成");
  } catch(e) {
    if(epoch===singleNodeTestEpoch)showToast(e.message,true);
  }
}
async function runNodeMaintenance(button, path, successMessage, busyMessage, cancelOnUpdateEpoch=null) {
  const original=button.textContent; button.disabled=true; button.textContent=busyMessage;
  try {
    const result=await api(path,{method:"POST",body:"{}"}); showToast(result.message||"节点任务已启动");
    if(result.discarded)return;
    await sleep(2000);
    let finished=false;
    for(let attempt=0;attempt<1800;attempt++) {
      if(cancelOnUpdateEpoch!==null && cancelOnUpdateEpoch!==nodeUpdateEpoch) { showToast("连接测试已被更新节点取消"); return; }
      await loadDashboard(true,{heartbeat:true});
      if(!dashboard.maintenance_running) { finished=true; break; }
      await sleep(3000);
    }
    if(!finished) throw new Error("节点检测仍在后台运行，请稍后查看进度");
    if(currentScreen==="nodes")await loadAllNodes(); else if(currentScreen==="proxy")await loadNodes();
    showToast(successMessage);
  } catch(error) { showToast(error.message,true); }
  finally { button.disabled=false; button.textContent=original; }
}
function updateNodeRepository(button) { nodeUpdateEpoch+=1; return runNodeMaintenance(button,"nodes/refresh","节点缓存池已更新并完成检测","正在更新…"); }
function testCachedNodes(button) { return runNodeMaintenance(button,"nodes/test-cache","缓存池连接测试完成","正在测试…",nodeUpdateEpoch); }
function fillSettings(force=false) {
  if(!dashboard)return;
  $("node-cache-status").textContent=`当前占用 ${dashboard.node_cache_count||0} / ${dashboard.node_cache_size||150}`;
  if(!force && (settingsDirty || isSettingsFormActive()))return;
  $("admin-username").value=dashboard.username||"";
  $("secret-path").value=dashboard.secret_path||"";
  $("proxy-username").value=dashboard.proxy_username||"";
  $("node-cache-size").value=dashboard.node_cache_size||150;
  if(!force) {
    settingsSavedUsername=dashboard.username||settingsSavedUsername;
    settingsSavedSecretPath=dashboard.secret_path||settingsSavedSecretPath;
  }
  settingsDirty=false;
}
async function loadSettingsSecrets(force=false) {
  const data=await api("settings");
  settingsSavedUsername=data.username||"";
  settingsSavedSecretPath=data.secret_path||"";
  if(dashboard) {
    dashboard.username=data.username||"";
    dashboard.secret_path=data.secret_path||"";
    dashboard.proxy_username=data.proxy_username||"";
    dashboard.node_cache_size=data.node_cache_size||150;
    dashboard.node_cache_count=data.node_cache_count||0;
  }
  $("node-cache-status").textContent=`当前占用 ${data.node_cache_count||0} / ${data.node_cache_size||150}`;
  if(!force && (settingsDirty || isSettingsFormActive()))return;
  $("current-admin-password").value="";
  $("admin-password").value="";
  $("admin-password-confirm").value="";
  $("admin-username").value=data.username||"";
  $("secret-path").value=data.secret_path||"";
  $("proxy-username").value=data.proxy_username||"";
  $("proxy-password").value=data.proxy_password||"";
  $("node-cache-size").value=data.node_cache_size||150;
  settingsDirty=false;
}
function toggleSecretInput(id) {
  const input=$(id);
  input.type=input.type==="password"?"text":"password";
}
async function copyInputValue(id) {
  const value=$(id).value;
  if(!value) { showToast("没有可复制的内容", true); return; }
  try {
    await navigator.clipboard.writeText(value);
    showToast("已复制到剪贴板");
  } catch (_) {
    $(id).focus();
    $(id).select();
    document.execCommand("copy");
    showToast("已复制到剪贴板");
  }
}
async function saveSettings() {
  try {
    const newPassword=$("admin-password").value;
    const newPasswordConfirm=$("admin-password-confirm").value;
    const savedUsername=settingsSavedUsername || dashboard?.username || $("admin-username").value.trim();
    const savedSecretPath=settingsSavedSecretPath || dashboard?.secret_path || $("secret-path").value.trim();
    if(newPassword || newPasswordConfirm) {
      if(!newPassword) throw new Error("请先填写新密码");
      if(newPassword!==newPasswordConfirm) throw new Error("两次输入的新密码不一致");
    }
    const adminChanged=($("admin-username").value.trim() !== savedUsername) || !!newPassword || ($("secret-path").value.trim() !== savedSecretPath);
    if(adminChanged && !$("current-admin-password").value) throw new Error("修改用户信息前，请输入原密码");
    const data=await api("settings",{
      method:"POST",
      body:JSON.stringify({
        current_username:savedUsername,
        current_password:$("current-admin-password").value,
        username:$("admin-username").value,
        password:newPassword,
        password_confirm:newPasswordConfirm,
        secret_path:$("secret-path").value,
        proxy_username:$("proxy-username").value,
        proxy_password:$("proxy-password").value,
        node_cache_size:Number($("node-cache-size").value)
      })
    });
    if(data.reauth_required){
      location.href=`/${data.secret_path}/`;
    }else{
      showToast("设置已保存，缓存池与五端口认证配置已更新");
      settingsDirty=false;
      await loadDashboard(false,{forceForms:true});
      await loadSettingsSecrets(true);
    }
  } catch(e){showToast(e.message,true);}
}

// ===== Custom dropdown widget (keeps native select values/events) =====
let customSelectSerial = 0;
const CUSTOM_SELECT_LABELS = {
  "all-node-country":"节点地区筛选",
  "all-node-type":"节点 IP 类型筛选",
  "all-node-status":"节点状态筛选",
  "node-country":"代理节点地区筛选",
  "node-ip-type":"代理节点 IP 类型筛选",
  "node-status":"代理节点状态筛选"
};
function countryCountMap() {
  const map = {};
  (nodes||[]).forEach(node=>{
    const country=nodeCountryValue(node);
    if(country)map[country]=(map[country]||0)+1;
  });
  return map;
}
function countryOptionMarkup(country,fallbackCounts={},preferFallback=false) {
  const fallback=fallbackCounts[country.value]??0;
  const count=Math.max(0,Math.trunc(Number(preferFallback?fallback:(country.count??fallback))||0));
  return `<option value="${esc(country.value)}" data-count="${count}">${esc(country.label)}</option>`;
}
function selectParts(select) {
  return {wrap:select.closest(".select"),trigger:select._customTrigger,menu:select._customMenu};
}
function enabledOptionIndexes(select) {
  return Array.from(select.options).map((option,index)=>option.disabled?-1:index).filter(index=>index>=0);
}
function buildSelectMenu(select) {
  const {menu}=selectParts(select);
  if(!menu)return;
  const fragment=document.createDocumentFragment();
  Array.from(select.options).forEach((option,index)=>{
    const item=document.createElement("button");
    item.type="button";
    item.id=`${menu.id}-option-${index}`;
    item.className="select-option";
    item.dataset.index=String(index);
    item.dataset.value=option.value;
    item.setAttribute("role","option");
    item.setAttribute("aria-selected",index===select.selectedIndex?"true":"false");
    item.disabled=option.disabled;
    const label=document.createElement("span");
    label.className="opt-label";
    label.textContent=option.textContent;
    item.appendChild(label);
    if(option.hasAttribute("data-count")) {
      const count=document.createElement("span");
      count.className="opt-count";
      count.textContent=`(${Math.max(0,Math.trunc(Number(option.dataset.count)||0))})`;
      item.appendChild(count);
    }
    item.addEventListener("mousedown",event=>event.preventDefault());
    item.addEventListener("mouseenter",()=>setActiveOption(select,index,false));
    item.addEventListener("click",event=>{
      event.stopPropagation();
      chooseSelectOption(select,index);
    });
    fragment.appendChild(item);
  });
  menu.replaceChildren(fragment);
}
function syncTrigger(select) {
  const {trigger,menu}=selectParts(select);
  if(!trigger||!menu)return;
  const option=select.options[select.selectedIndex];
  const value=trigger.querySelector(".select-value");
  value.textContent=option?.textContent||"";
  value.classList.toggle("placeholder",!option);
  trigger.disabled=select.disabled;
  menu.querySelectorAll(".select-option").forEach((item,index)=>{
    const selected=index===select.selectedIndex;
    item.classList.toggle("selected",selected);
    item.setAttribute("aria-selected",selected?"true":"false");
  });
}
function setActiveOption(select,index,ensureVisible=true) {
  const {trigger,menu}=selectParts(select);
  if(!trigger||!menu||!select.options[index]||select.options[index].disabled)return;
  select._activeOptionIndex=index;
  const items=Array.from(menu.querySelectorAll(".select-option"));
  items.forEach((item,itemIndex)=>item.classList.toggle("active",itemIndex===index));
  const active=items[index];
  if(active) {
    trigger.setAttribute("aria-activedescendant",active.id);
    if(ensureVisible)active.scrollIntoView({block:"nearest"});
  }
}
function moveActiveOption(select,direction) {
  const indexes=enabledOptionIndexes(select);
  if(!indexes.length)return;
  const current=indexes.indexOf(select._activeOptionIndex);
  const next=current<0 ? (direction>0?0:indexes.length-1) : (current+direction+indexes.length)%indexes.length;
  setActiveOption(select,indexes[next]);
}
function typeaheadActiveOption(select,key) {
  clearTimeout(select._typeaheadTimer);
  let query=`${select._typeaheadQuery||""}${key}`.toLocaleLowerCase();
  const indexes=enabledOptionIndexes(select);
  const current=Math.max(-1,indexes.indexOf(select._activeOptionIndex));
  const ordered=indexes.slice(current+1).concat(indexes.slice(0,current+1));
  const findMatch=value=>ordered.find(index=>String(select.options[index].textContent||"").trim().toLocaleLowerCase().startsWith(value));
  let match=findMatch(query);
  if(match===undefined&&query.length>1) {
    query=key.toLocaleLowerCase();
    match=findMatch(query);
  }
  select._typeaheadQuery=query;
  select._typeaheadTimer=setTimeout(()=>{select._typeaheadQuery="";},650);
  if(match===undefined)return false;
  if(!select.closest(".select")?.classList.contains("open"))openSelect(select);
  setActiveOption(select,match);
  return true;
}
function chooseSelectOption(select,index) {
  const option=select.options[index];
  if(!option||option.disabled)return;
  const changed=select.selectedIndex!==index;
  select.selectedIndex=index;
  if(changed) {
    select.dispatchEvent(new Event("input",{bubbles:true}));
    select.dispatchEvent(new Event("change",{bubbles:true}));
  }
  syncTrigger(select);
  closeSelect(select);
}
function positionMenu(select) {
  const {wrap,trigger,menu}=selectParts(select);
  if(!wrap||!trigger||!menu)return;
  const rect=trigger.getBoundingClientRect();
  const gap=6, viewportPadding=8;
  const viewportWidth=document.documentElement.clientWidth||window.innerWidth;
  const viewportHeight=document.documentElement.clientHeight||window.innerHeight;
  const width=Math.min(rect.width,Math.max(0,viewportWidth-viewportPadding*2));
  const left=Math.min(Math.max(viewportPadding,rect.left),Math.max(viewportPadding,viewportWidth-viewportPadding-width));
  menu.style.width=`${Math.round(width)}px`;
  menu.style.maxHeight="280px";
  const naturalHeight=Math.min(menu.scrollHeight+2,280);
  const spaceBelow=Math.max(0,viewportHeight-rect.bottom-gap-viewportPadding);
  const spaceAbove=Math.max(0,rect.top-gap-viewportPadding);
  const openAbove=spaceBelow<naturalHeight && spaceAbove>spaceBelow;
  const available=openAbove?spaceAbove:spaceBelow;
  const maxHeight=Math.max(1,Math.min(280,available));
  const menuHeight=Math.min(naturalHeight,maxHeight);
  const top=openAbove ? Math.max(viewportPadding,rect.top-gap-menuHeight) : Math.min(rect.bottom+gap,viewportHeight-viewportPadding-menuHeight);
  menu.style.left=`${Math.round(left)}px`;
  menu.style.top=`${Math.round(Math.max(viewportPadding,top))}px`;
  menu.style.maxHeight=`${Math.round(maxHeight)}px`;
  wrap.classList.toggle("open-up",openAbove);
  menu.classList.toggle("open-up",openAbove);
}
function closeSelect(select) {
  const {wrap,trigger,menu}=selectParts(select);
  if(!wrap)return;
  wrap.classList.remove("open");
  menu?.classList.remove("open");
  trigger?.setAttribute("aria-expanded","false");
  trigger?.removeAttribute("aria-activedescendant");
  select._activeOptionIndex=-1;
  clearTimeout(select._typeaheadTimer);
  select._typeaheadQuery="";
}
function closeAllSelects(except=null) {
  document.querySelectorAll(".select.open select").forEach(select=>{
    if(select!==except)closeSelect(select);
  });
}
function openSelect(select) {
  const {wrap,trigger,menu}=selectParts(select);
  if(!wrap||!trigger||!menu||select.disabled)return;
  closeAllSelects(select);
  buildSelectMenu(select);
  syncTrigger(select);
  positionMenu(select);
  wrap.classList.add("open");
  menu.classList.add("open");
  trigger.setAttribute("aria-expanded","true");
  const indexes=enabledOptionIndexes(select);
  const active=select.options[select.selectedIndex]?.disabled ? indexes[0] : select.selectedIndex;
  if(active>=0)setActiveOption(select,active);
}
function enhanceSelect(select) {
  if(select.dataset.custom==="1")return;
  select.dataset.custom="1";
  select.classList.add("is-custom");
  select.tabIndex=-1;
  select.setAttribute("aria-hidden","true");
  const wrap=document.createElement("div");
  wrap.className="select";
  if(select.style.width)wrap.style.width=select.style.width;
  select.parentNode.insertBefore(wrap,select);
  wrap.appendChild(select);
  const serial=++customSelectSerial;
  const trigger=document.createElement("button");
  trigger.type="button";
  trigger.id=select.id?`${select.id}-trigger`:`custom-select-${serial}-trigger`;
  trigger.className="select-trigger";
  trigger.dataset.selectId=select.id||"";
  trigger.setAttribute("role","combobox");
  trigger.setAttribute("aria-label",select.getAttribute("aria-label")||select.closest(".field")?.querySelector("label")?.textContent.trim()||CUSTOM_SELECT_LABELS[select.id]||"选择选项");
  trigger.setAttribute("aria-haspopup","listbox");
  trigger.setAttribute("aria-expanded","false");
  const value=document.createElement("span");
  value.className="select-value";
  const arrow=document.createElement("span");
  arrow.className="select-arrow";
  arrow.setAttribute("aria-hidden","true");
  trigger.append(value,arrow);
  wrap.appendChild(trigger);
  const menu=document.createElement("div");
  menu.id=select.id?`${select.id}-menu`:`custom-select-${serial}-menu`;
  menu.className="select-menu";
  menu.setAttribute("role","listbox");
  menu.setAttribute("aria-labelledby",trigger.id);
  trigger.setAttribute("aria-controls",menu.id);
  document.body.appendChild(menu);
  select._customTrigger=trigger;
  select._customMenu=menu;
  select._activeOptionIndex=-1;
  buildSelectMenu(select);
  syncTrigger(select);
  trigger.addEventListener("click",event=>{
    event.stopPropagation();
    wrap.classList.contains("open")?closeSelect(select):openSelect(select);
  });
  trigger.addEventListener("keydown",event=>{
    if(event.key==="ArrowDown"||event.key==="ArrowUp") {
      event.preventDefault();
      if(!wrap.classList.contains("open"))openSelect(select);
      else moveActiveOption(select,event.key==="ArrowDown"?1:-1);
    } else if(event.key==="Home"||event.key==="End") {
      if(!wrap.classList.contains("open"))return;
      event.preventDefault();
      const indexes=enabledOptionIndexes(select);
      if(indexes.length)setActiveOption(select,event.key==="Home"?indexes[0]:indexes[indexes.length-1]);
    } else if(event.key==="Enter"||event.key===" ") {
      event.preventDefault();
      if(wrap.classList.contains("open"))chooseSelectOption(select,select._activeOptionIndex);
      else openSelect(select);
    } else if(event.key==="Escape") {
      if(wrap.classList.contains("open"))event.preventDefault();
      closeSelect(select);
    } else if(event.key==="Tab") {
      closeSelect(select);
    } else if(event.key.length===1&&!event.ctrlKey&&!event.metaKey&&!event.altKey) {
      if(typeaheadActiveOption(select,event.key))event.preventDefault();
    }
  });
  select.addEventListener("change",()=>syncTrigger(select));
}
function refreshSelect(select) {
  const {wrap,menu}=selectParts(select);
  if(!wrap){enhanceSelect(select);return;}
  const activeValue=menu?.querySelector(".select-option.active")?.dataset.value;
  buildSelectMenu(select);
  syncTrigger(select);
  if(wrap.classList.contains("open")) {
    positionMenu(select);
    const preserved=activeValue===undefined?-1:Array.from(select.options).findIndex(option=>option.value===activeValue&&!option.disabled);
    const active=preserved>=0?preserved:(select.options[select.selectedIndex]?.disabled?enabledOptionIndexes(select)[0]:select.selectedIndex);
    if(active>=0)setActiveOption(select,active);
  }
}
function enhanceAllSelects() {
  document.querySelectorAll("select.input").forEach(enhanceSelect);
}
document.addEventListener("click",event=>{
  if(!event.target.closest?.(".select-menu"))closeAllSelects();
});
document.addEventListener("focusin",event=>{
  document.querySelectorAll(".select.open select").forEach(select=>{
    const {trigger,menu}=selectParts(select);
    if(event.target!==trigger&&!menu?.contains(event.target))closeSelect(select);
  });
});
window.addEventListener("scroll",event=>{
  if(event.target?.closest?.(".select-menu"))return;
  closeAllSelects();
},true);
window.addEventListener("resize",()=>closeAllSelects());

document.querySelectorAll("[data-screen]").forEach(button=>button.onclick=()=>showScreen(button.dataset.screen));
$("reload").onclick=async()=>{await loadDashboard(false,{forceForms:true});if(currentScreen==="nodes")await loadAllNodes();if(currentScreen==="proxy")await loadNodes();if(currentScreen==="settings")await loadSettingsSecrets(true);};
$("save-slot").onclick=saveSlot; $("node-search").oninput=renderNodes; $("node-country").onchange=renderNodes; $("node-ip-type").onchange=renderNodes; $("node-status").onchange=renderNodes;
$("all-node-search").oninput=renderAllNodes; $("all-node-country").onchange=renderAllNodes; $("all-node-type").onchange=renderAllNodes; $("all-node-status").onchange=renderAllNodes;
settingsInputIds().forEach(id=>$(id).addEventListener("input",()=>{settingsDirty=true;}));
document.querySelectorAll("[data-toggle-secret]").forEach(button=>button.onclick=()=>toggleSecretInput(button.dataset.toggleSecret));
document.querySelectorAll("[data-copy-secret]").forEach(button=>button.onclick=()=>copyInputValue(button.dataset.copySecret));
["preferred-country","routing-ip-type","slot-enabled"].forEach(id=>{
  $(id).addEventListener("input",()=>{proxyFormDirty=true;});
  $(id).addEventListener("change",()=>{proxyFormDirty=true;});
});
document.querySelectorAll('[name="switch-mode"]').forEach(input=>input.addEventListener("change",()=>{proxyFormDirty=true;}));
$("refresh-all-nodes").onclick=()=>updateNodeRepository($("refresh-all-nodes"));
$("test-cache-nodes").onclick=()=>testCachedNodes($("test-cache-nodes"));
$("refresh-nodes").onclick=()=>updateNodeRepository($("refresh-nodes"));
$("disconnect-proxy").onclick=async()=>{try{await api("slots/disconnect",{method:"POST",body:JSON.stringify({slot:currentSlot})});await loadDashboard();showToast("代理已断开并停用");}catch(e){showToast(e.message,true);}};
$("test-proxy").onclick=async()=>{try{const d=await api("slots/test",{method:"POST",body:JSON.stringify({slot:currentSlot})});showToast(`出口 ${d.ip}，延迟 ${d.latency_ms} ms`);await loadDashboard(true,{heartbeat:true});}catch(e){showToast(e.message,true);}};
$("save-settings").onclick=saveSettings; $("mobile-menu").onclick=()=>$("sidebar").classList.toggle("open");
$("reset-traffic").onclick=resetTraffic;
$("logout").onclick=async()=>{try{await api("logout",{method:"POST",body:"{}"});}finally{location.reload();}};
enhanceAllSelects();
loadDashboard().then(()=>showScreen("system")); setInterval(()=>loadDashboard(true,{heartbeat:true}),5000); setInterval(()=>loadTraffic(),2000);
