/* Management panel front-end — Server / Services / Terminal / Logs.
 * Ported from Main.py's dashboard so the look & behaviour match exactly, then
 * trimmed to this panel's four sections and wired to Management's endpoints. */

/* ---------------- helpers ---------------- */
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function escAttr(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function $(id){return document.getElementById(id);}

function appToast(msg, type, ms){
  let wrap = $('app-toast-wrap');
  if(!wrap){ wrap=document.createElement('div'); wrap.id='app-toast-wrap'; wrap.className='app-toast-wrap'; document.body.appendChild(wrap); }
  const t=document.createElement('div');
  t.className='app-toast '+(type==='ok'?'ok':type==='err'?'err':'info');
  t.textContent=msg;
  t.onclick=()=>{ t.classList.remove('show'); setTimeout(()=>t.remove(),220); };
  wrap.appendChild(t); requestAnimationFrame(()=>t.classList.add('show'));
  setTimeout(()=>{ t.classList.remove('show'); setTimeout(()=>t.remove(),220); }, ms||(type==='err'?5200:3600));
}
function appConfirm(msg, opts){ return Promise.resolve(window.confirm(((opts&&opts.title)?opts.title+'\n\n':'')+msg)); }
function uiConfirm(title, msg){ return Promise.resolve(window.confirm(title+'\n\n'+msg)); }
function uiAlert(title, msg){ window.alert(title+'\n\n'+msg); return Promise.resolve(); }
function copyVal(val,label){
  const text=String(val==null?'':val).trim(); if(!text) return;
  label=label||'Value';
  const done=()=>appToast(label+' copied','ok'), fail=()=>appToast('Copy failed','err');
  if(navigator.clipboard&&navigator.clipboard.writeText&&window.isSecureContext){
    navigator.clipboard.writeText(text).then(done,()=>_execCopy(text,done,fail));
  } else _execCopy(text,done,fail);
}
function _execCopy(text,done,fail){
  try{ const ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.top='-9999px';
    document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); done(); }catch(e){ fail(); }
}
/* Public path prefix this panel is published under (nginx strips it before
   proxying, so every URL the browser is given has to carry it back).
   Injected by Management.py; empty string when served at the domain root. */
const BASE = (window.MGMT_BASE||'');
async function api(path, opts){ const r=await fetch(BASE+path, opts); if(r.status===401){ location.href=BASE+'/login'; return null; } return r; }
async function getJSON(p){ const r=await api(p); return r? r.json():null; }
function fmtUptime(sec){ sec=Math.max(0,sec|0); const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60);
  if(d) return `${d}d ${h}h ${m}m`; if(h) return `${h}h ${m}m`; return `${m}m`; }

/* ---------------- theme ---------------- */
function applyTheme(dark){
  document.documentElement.setAttribute('data-theme', dark?'dark':'light');
  const u=$('theme-ic'); if(u) u.setAttribute('href', dark?'#ic-sun':'#ic-moon');
}
function toggleTheme(){ const dark=document.documentElement.getAttribute('data-theme')!=='dark';
  applyTheme(dark); localStorage.setItem('theme', dark?'dark':'light'); }

/* ---------------- nav ---------------- */
let CURRENT='server';
function switchSection(name){
  CURRENT=name;
  document.querySelectorAll('[data-pane]').forEach(p=>p.classList.toggle('visible', p.dataset.pane===name));
  document.querySelectorAll('[data-nav]').forEach(b=>b.classList.toggle('active', b.dataset.nav===name));
  document.querySelectorAll('.mtab').forEach(b=>b.classList.toggle('active', b.dataset.nav===name));
  if(name==='server'){ startServerPolling(); loadServerConfig(); } else stopServerPolling();
  if(name==='services') loadServices();
  if(name==='terminal') setTimeout(initTerminal,30);
  if(name==='logs') loadSecurityLogs();
  if(name==='account') loadAccount();
}

/* ================= ACCOUNT ================= */
async function loadAccount(){
  const el=$('acct-codes-state'); if(!el) return;
  ['acct-cur','acct-new','acct-new2','acct-regen-pw'].forEach(function(id){ const i=$(id); if(i) i.value=''; });
  const out=$('acct-codes-out'); if(out){ out.hidden=true; out.innerHTML=''; }
  el.textContent='Checking…';
  try{
    const r=await api('/api/account/recovery-status'); if(!r) return;
    const d=await r.json();
    if(!r.ok){ el.textContent=d.error||'Could not read recovery codes.'; return; }
    if(!d.total){
      el.innerHTML='<b style="color:var(--danger)">No recovery codes yet.</b> '+
        'Generate a set so a forgotten password is not a lockout.';
    } else if(!d.unused){
      el.innerHTML='<b style="color:var(--danger)">All '+d.total+' codes used.</b> Generate a new set.';
    } else {
      const low=d.unused<=1;
      el.innerHTML='<b style="color:'+(low?'var(--danger)':'#27ae60')+'">'+d.unused+' of '+d.total+
        '</b> code'+(d.unused===1?'':'s')+' unused'+
        (d.generated_at?' <span style="color:var(--gray-500);">(issued '+esc(d.generated_at.slice(0,10))+')</span>':'');
    }
  }catch(e){ el.textContent='Could not reach the server.'; }
}

async function changePassword(){
  const fb=$('acct-feedback'), btn=$('acct-save');
  const cur=$('acct-cur').value, pw=$('acct-new').value, pw2=$('acct-new2').value;
  fb.textContent=''; fb.className='save-feedback';
  if(!cur){ fb.textContent='Enter your current password.'; fb.classList.add('err'); $('acct-cur').focus(); return; }
  if(pw!==pw2){ fb.textContent='The two new passwords do not match.'; fb.classList.add('err'); $('acct-new2').focus(); return; }
  btn.disabled=true; fb.textContent='Saving…'; fb.classList.add('info');
  try{
    const r=await api('/api/account/password',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({current_password:cur,new_password:pw})});
    if(!r){ return; }
    const d=await r.json();
    fb.className='save-feedback';
    if(!r.ok){ fb.textContent=d.error||'Could not change the password.'; fb.classList.add('err'); }
    else{
      fb.textContent='Password changed. Other sessions have been signed out.';
      fb.classList.add('ok');
      ['acct-cur','acct-new','acct-new2'].forEach(function(id){ $(id).value=''; });
      appToast('Password changed','ok');
    }
  }catch(e){ fb.className='save-feedback err'; fb.textContent='Request failed: '+e; }
  btn.disabled=false;
}

async function regenerateRecoveryCodes(){
  const fb=$('acct-regen-feedback'), btn=$('acct-regen'), out=$('acct-codes-out');
  const cur=$('acct-regen-pw').value;
  fb.textContent=''; fb.className='save-feedback';
  if(!cur){ fb.textContent='Enter your current password.'; fb.classList.add('err'); $('acct-regen-pw').focus(); return; }
  if(!(await uiConfirm('Generate new recovery codes?',
       'Every existing code stops working immediately. The new codes are shown once and written to the .recovery file.'))) return;
  btn.disabled=true; fb.textContent='Generating…'; fb.classList.add('info'); out.hidden=true;
  try{
    const r=await api('/api/account/recovery-codes',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({current_password:cur})});
    if(!r){ return; }
    const d=await r.json();
    fb.className='save-feedback';
    if(!r.ok){ fb.textContent=d.error||'Could not generate new codes.'; fb.classList.add('err'); }
    else{
      $('acct-regen-pw').value='';
      fb.textContent=d.file_error?('Codes created, but .recovery could not be written: '+d.file_error)
                                 :('Codes created and written to '+(d.path||'.recovery')+'.');
      fb.classList.add(d.file_error?'err':'ok');
      renderRecoveryCodes(d.codes);
      loadAccount();
      appToast('New recovery codes issued','ok');
    }
  }catch(e){ fb.className='save-feedback err'; fb.textContent='Request failed: '+e; }
  btn.disabled=false;
}

/* Shown exactly once — the server keeps only hashes, so this is the last
   chance to copy them out of the browser. */
function renderRecoveryCodes(codes){
  const out=$('acct-codes-out'); if(!out||!codes||!codes.length) return;
  const items=codes.map(function(c,i){
    return '<li><span class="n">'+(i+1)+'.</span><span class="c">'+esc(c)+'</span></li>';
  }).join('');
  out.innerHTML=
    '<div class="codes-box">'+
      '<div class="codes-title">Your new recovery codes</div>'+
      '<div class="codes-note">Shown once. Each resets the password one time from the login page. '+
        'Store them somewhere safe and offline.</div>'+
      '<ol class="codes-list">'+items+'</ol>'+
      '<button class="db-action-btn" id="acct-copy-codes"><svg class="ic"><use href="#ic-copy"/></svg>Copy all</button>'+
    '</div>';
  out.hidden=false;
  const btn=$('acct-copy-codes');
  if(btn) btn.addEventListener('click', function(){ copyVal(codes.join('\n'),'Recovery codes'); });
  out.scrollIntoView({behavior:'smooth',block:'nearest'});
}

/* ================= SERVER ================= */
const HIST_LEN=40;
let cpuHist=[],ramHist=[],netInHist=[],netOutHist=[];
let serverPollTimer=null, serverStaticLoaded=false;

function startServerPolling(){
  if(!serverStaticLoaded) loadServerStatic();
  pollServerStats();
  if(serverPollTimer) clearInterval(serverPollTimer);
  serverPollTimer=setInterval(pollServerStats,1500);
}
function stopServerPolling(){ if(serverPollTimer){ clearInterval(serverPollTimer); serverPollTimer=null; } }

async function loadServerStatic(){
  try{
    const r=await api('/api/system/static'); if(!r||!r.ok) return; const d=await r.json();
    const rows=[
      ['Hostname',d.hostname],['Operating System',d.distro],['OS Detail',d.os_full],
      ['Kernel',d.kernel],['Architecture',d.arch],['CPU',d.cpu_model],
      ['CPU Cores',`${d.cpu_cores_physical} physical / ${d.cpu_cores_logical} logical`+(d.cpu_max_mhz?` @ ${(d.cpu_max_mhz/1000).toFixed(2)} GHz`:'')],
      ['Total RAM',d.ram_total_h],['Total Disk',d.disk_total_h],['Python',d.python],
      ['Booted',d.boot_time],['Uptime',fmtUptime(d.uptime_seconds)],
      ['Process',`pid ${d.process_pid} as ${d.process_user}`+(d.is_root?' (root)':'')],
    ];
    $('device-grid').innerHTML=rows.map(([k,v])=>`<div class="dev-item"><span class="dev-key">${esc(k)}</span><span class="dev-val">${esc(v||'—')}</span></div>`).join('');
    serverStaticLoaded=true;
  }catch(e){}
}
async function pollServerStats(){
  try{
    const r=await api('/api/system/stats'); if(!r||!r.ok) return; const d=await r.json();
    pushHist(cpuHist,d.cpu_percent); pushHist(ramHist,d.ram.percent);
    pushHist(netInHist,d.net.rate_in); pushHist(netOutHist,d.net.rate_out);
    $('m-cpu-now').textContent=d.cpu_percent.toFixed(0)+'%';
    $('m-cpu-foot').textContent=`${d.processes} procs · uptime ${fmtUptime(d.uptime_seconds)}`;
    $('m-ram-now').textContent=d.ram.percent.toFixed(0)+'%';
    $('m-ram-foot').textContent=`${d.ram.used_h} / ${d.ram.total_h}`+(d.swap.total?` · swap ${d.swap.used_h}`:'');
    $('m-net-now').innerHTML=`&darr;${d.net.rate_in_h} &uarr;${d.net.rate_out_h}`;
    $('m-net-foot').textContent=`total ↓${d.net.total_in_h} ↑${d.net.total_out_h}`;
    $('m-disk-now').textContent=d.disk.percent.toFixed(0)+'%';
    $('m-disk-foot').textContent=`${d.disk.used_h} / ${d.disk.total_h}`;
    $('disk-fill').style.width=d.disk.percent+'%'; $('disk-fill').style.background=barColor(d.disk.percent);
    $('m-load-now').textContent=d.load['1'].toFixed(2);
    $('m-load-foot').textContent=`${d.load['1']} / ${d.load['5']} / ${d.load['15']}`;
    renderCoreBars(d.cpu_per_core);
    drawLineChart('chart-cpu',[cpuHist],100,['--black']);
    drawLineChart('chart-ram',[ramHist],100,['--black']);
    const netMax=Math.max(1,...netInHist,...netOutHist);
    drawLineChart('chart-net',[netInHist,netOutHist],netMax,['#22c55e','#f97316']);
  }catch(e){}
}
function pushHist(a,v){ a.push(v); if(a.length>HIST_LEN) a.shift(); }
function renderCoreBars(cores){
  if(!cores) return; const el=$('core-bars'); if(!el) return;
  el.innerHTML=cores.map(p=>`<div class="core-bar" title="${p.toFixed(0)}%"><span style="height:${Math.max(3,p)}%;background:${barColor(p)}"></span></div>`).join('');
}
function barColor(p){ if(p>=90) return '#c0392b'; if(p>=70) return '#f97316';
  return getComputedStyle(document.documentElement).getPropertyValue('--black').trim()||'#0a0a0a'; }
function drawLineChart(id,series,max,colors){
  const canvas=$(id); if(!canvas) return;
  const w=canvas.clientWidth||canvas.parentElement.clientWidth; const dpr=window.devicePixelRatio||1; const h=canvas.height;
  if(canvas.width!==Math.round(w*dpr)) canvas.width=Math.round(w*dpr);
  const ctx=canvas.getContext('2d'); ctx.setTransform(dpr,0,0,1,0,0); ctx.clearRect(0,0,w,h);
  const grid=getComputedStyle(document.documentElement).getPropertyValue('--gray-100').trim();
  ctx.strokeStyle=grid; ctx.lineWidth=1;
  for(let i=1;i<=2;i++){ const y=(h/3)*i; ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(w,y); ctx.stroke(); }
  series.forEach((data,si)=>{
    if(!data.length) return;
    let col=colors[si]||'#0a0a0a';
    if(col.startsWith('--')) col=getComputedStyle(document.documentElement).getPropertyValue(col).trim()||'#0a0a0a';
    const step=w/(HIST_LEN-1); const x0=w-(data.length-1)*step;
    ctx.beginPath();
    data.forEach((v,i)=>{ const x=x0+i*step; const y=h-3-(Math.min(v,max)/max)*(h-6); i===0?ctx.moveTo(x,y):ctx.lineTo(x,y); });
    ctx.strokeStyle=col; ctx.lineWidth=1.6; ctx.lineJoin='round'; ctx.stroke();
    ctx.lineTo(x0+(data.length-1)*step,h); ctx.lineTo(x0,h); ctx.closePath();
    ctx.globalAlpha=0.07; ctx.fillStyle=col; ctx.fill(); ctx.globalAlpha=1;
  });
}

/* ---- server card drill-down ---- */
let _srvDetailKind=null, _fbPath='/', _accessDetailId=null;
let _ipDetailTarget=null, _ipProfileData=null, _lineDetailObj=null, _lineDetailTitle='';
const _SRV_TITLES={cpu:'CPU — Top Processes',mem:'Memory — Top Processes',net:'Network — Active Connections',disk:'Disk — File Browser'};
function openServerDetail(kind){
  _srvDetailKind=kind;
  $('srv-detail-title').textContent=_SRV_TITLES[kind]||'Detail';
  $('srv-detail-overlay').classList.add('open'); loadServerDetail();
}
function closeServerDetail(){ $('srv-detail-overlay').classList.remove('open'); _srvDetailKind=null; }
function refreshServerDetail(){ loadServerDetail(); }
async function loadServerDetail(){
  if(_srvDetailKind==='cpu'||_srvDetailKind==='mem') return renderProcDetail(_srvDetailKind);
  if(_srvDetailKind==='net') return renderNetDetail();
  if(_srvDetailKind==='disk') return browseDir(_fbPath);
  if(_srvDetailKind==='ip') return renderIpProfile();
  if(_srvDetailKind==='line') return renderLineDetail();
  if(_srvDetailKind==='access') return renderAccessDetail();
}
async function renderProcDetail(by){
  const b=$('srv-detail-body'); b.innerHTML='<div class="empty-state">Sampling processes…</div>';
  try{
    const d=await (await api('/api/system/processes?by='+by)).json();
    const rows=(d.processes||[]).map(p=>`<tr><td>${esc(p.pid)}</td><td>${esc(p.name)}</td><td>${esc(p.user)}</td>
      <td><b>${p.cpu.toFixed(1)}%</b></td><td>${p.mem.toFixed(1)}%</td>
      <td style="white-space:normal;color:var(--gray-600);">${esc(p.cmd)}</td></tr>`).join('');
    b.innerHTML=`<div style="font-size:12px;color:var(--gray-600);margin-bottom:8px;">Sorted by ${by==='mem'?'memory':'CPU'}. CPU is share of the whole machine.</div>
      <table><thead><tr><th>PID</th><th>Process</th><th>User</th><th>CPU</th><th>Mem</th><th>Command</th></tr></thead>
      <tbody>${rows||'<tr><td colspan="6">No data.</td></tr>'}</tbody></table>`;
  }catch(e){ b.innerHTML=`<div class="empty-state">Failed: ${esc(String(e))}</div>`; }
}
async function renderNetDetail(){
  const b=$('srv-detail-body'); b.innerHTML='<div class="empty-state">Reading connections…</div>';
  try{
    const d=await (await api('/api/system/connections')).json();
    if(d.error){ b.innerHTML=`<div class="empty-state">${esc(d.error)}</div>`; return; }
    const rows=(d.connections||[]).map(c=>{
      const isAuth=c.process&&c.process.includes('sshd-auth'), isSess=c.process&&c.process.includes('sshd-session');
      let rowStyle='',stateCell=esc(c.status),processCell=esc(c.process);
      if(isAuth){ rowStyle='background:rgba(231,76,60,0.08);'; stateCell='<span style="color:#e74c3c;font-weight:700;">ESTAB</span>';
        processCell='<span style="color:#e74c3c;font-weight:600;">sshd-auth</span> <span style="font-size:10px;color:#e74c3c;background:rgba(231,76,60,0.12);border-radius:3px;padding:1px 5px;">TCP only — NOT authenticated</span>'; }
      else if(isSess){ rowStyle='background:rgba(39,174,96,0.08);'; stateCell='<span style="color:#27ae60;font-weight:700;">ESTAB</span>';
        processCell=`<span style="color:#27ae60;font-weight:600;">${esc(c.process)}</span> <span style="font-size:10px;color:#27ae60;background:rgba(39,174,96,0.12);border-radius:3px;padding:1px 5px;">SSH authenticated session</span>`; }
      return `<tr style="${rowStyle}"><td>${esc(c.proto)}</td><td>${esc(c.laddr)}</td><td><b>${esc(c.raddr)}</b></td><td>${stateCell}</td><td>${esc(c.pid)}</td><td>${processCell}</td></tr>`;
    }).join('');
    b.innerHTML=`<div style="font-size:12px;color:var(--gray-600);margin-bottom:10px;line-height:1.6;">Listening sockets first. On port 22:
      <span style="color:#e74c3c;font-weight:600;">sshd-auth</span> = connected but not authenticated · <span style="color:#27ae60;font-weight:600;">sshd-session</span> = authenticated shell.</div>
      <table><thead><tr><th>Proto</th><th>Local</th><th>Remote IP</th><th>State</th><th>PID</th><th>Process</th></tr></thead>
      <tbody>${rows||'<tr><td colspan="6">No connections.</td></tr>'}</tbody></table>`;
  }catch(e){ b.innerHTML=`<div class="empty-state">Failed: ${esc(String(e))}</div>`; }
}
async function browseDir(path){
  _fbPath=path; const b=$('srv-detail-body'); b.innerHTML='<div class="empty-state">Loading folder…</div>';
  try{
    const d=await (await api('/api/system/files?path='+encodeURIComponent(path))).json();
    if(d.error&&!(d.entries||[]).length){
      b.innerHTML=`<div class="fb-crumbs">${esc(d.path||path)}</div><div class="empty-state">${esc(d.error)}</div>
        ${d.parent?`<div class="fb-row"><span class="fb-name dir" data-path="${escAttr(d.parent)}" onclick="browseDir(this.dataset.path)">↩ Up</span></div>`:''}`; return;
    }
    _fbPath=d.path;
    const up=d.parent?`<div class="fb-row"><span class="fb-name dir" data-path="${escAttr(d.parent)}" onclick="browseDir(this.dataset.path)">↩ ..</span></div>`:'';
    const rows=(d.entries||[]).map(e=>{
      const name=e.is_dir?`<span class="fb-name dir" data-path="${escAttr(e.path)}" onclick="browseDir(this.dataset.path)"><svg class="ic" style="color:var(--accent)"><use href="#ic-folder"/></svg> ${esc(e.name)}</span>`
        :`<span class="fb-name"><svg class="ic" style="color:var(--gray-400)"><use href="#ic-file-text"/></svg> ${esc(e.name)}</span>`;
      const action=e.is_dir?'':(e.downloadable?`<a class="fb-dl" href="${BASE}/api/system/download?path=${encodeURIComponent(e.path)}" style="display:inline-flex;align-items:center;gap:4px;"><svg class="ic"><use href="#ic-download"/></svg> Download</a>`:`<span class="fb-locked">protected</span>`);
      return `<div class="fb-row">${name}<span class="fb-size">${esc(e.size_h)}</span><span class="fb-dl">${action}</span></div>`;
    }).join('');
    b.innerHTML=`<div class="fb-crumbs">${esc(d.path)}</div>${up}${rows||'<div class="empty-state">Empty folder.</div>'}`;
  }catch(e){ b.innerHTML=`<div class="empty-state">Failed: ${esc(String(e))}</div>`; }
}
function openAccessDetail(id){ _srvDetailKind='access'; _accessDetailId=id;
  $('srv-detail-title').textContent='Request / Response'; $('srv-detail-overlay').classList.add('open'); renderAccessDetail(); }
async function renderAccessDetail(){
  const b=$('srv-detail-body'); b.innerHTML='<div class="empty-state">Loading response…</div>';
  let d; try{ d=await (await api('/api/system/access-log-entry?id='+_accessDetailId)).json(); }
  catch(e){ b.innerHTML=`<div class="empty-state">Error: ${esc(String(e))}</div>`; return; }
  if(d.error){ b.innerHTML=`<div class="empty-state">${esc(d.error)}</div>`; return; }
  const meta=[['Time',String(d.ts).slice(0,19)],['Method',d.method],['Path',d.path],['Query',d.query||'—'],
    ['Status',d.status_code],['Duration',(d.duration_ms??'—')+' ms'],['IP',d.ip],['User',d.authed_user||'—'],
    ['Content-Type',d.content_type||'—'],['Response size',d.response_size!=null?d.response_size.toLocaleString()+' bytes':'—']]
    .map(([k,v])=>`<tr><td style="font-weight:700;white-space:nowrap;vertical-align:top;color:var(--gray-600);padding-right:14px;">${esc(k)}</td><td style="font-family:monospace;font-size:12px;word-break:break-all;">${esc(String(v))}</td></tr>`).join('');
  let bodyText=d.response_body;
  if(bodyText==null) bodyText='(no response body captured)';
  else if((d.content_type||'').includes('json')){ try{ bodyText=JSON.stringify(JSON.parse(d.response_body),null,2); }catch(_){} }
  const sc=d.status_code<300?'#27ae60':d.status_code<400?'#2980b9':d.status_code<500?'#e67e22':'#e74c3c';
  b.innerHTML=`<div style="margin-bottom:6px;"><span style="font-weight:700;color:${sc};font-size:14px;">${d.method} ${esc(d.path)} → ${d.status_code}</span></div>
    <table style="margin-bottom:16px;">${meta}</table>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;"><div style="font-weight:700;font-size:13px;">Response body</div>
      <span style="font-size:11px;color:var(--gray-600);">${esc(d.content_type||'')}</span>
      <button class="db-action-btn" style="margin-left:auto;font-size:11px;" onclick="copyVal(document.getElementById('access-body-pre').textContent,'Body')">Copy</button></div>
    <pre id="access-body-pre" style="background:var(--gray-50);border:1px solid var(--gray-200);border-radius:6px;padding:12px;max-height:48vh;overflow:auto;font-size:12px;line-height:1.45;white-space:pre-wrap;word-break:break-word;font-family:var(--mono);color:var(--black);">${esc(bodyText)}</pre>`;
}
function openIpDetail(ip){ if(!ip) return; _srvDetailKind='ip'; _ipDetailTarget=ip;
  $('srv-detail-title').textContent='IP '+ip+' — full activity'; $('srv-detail-overlay').classList.add('open'); renderIpProfile(); }
function openLineDetail(title,obj){ _srvDetailKind='line'; _lineDetailObj=obj||{}; _lineDetailTitle=title||'Log entry';
  $('srv-detail-title').textContent=_lineDetailTitle; $('srv-detail-overlay').classList.add('open'); renderLineDetail(); }
function renderLineDetail(){
  const b=$('srv-detail-body'); const o=_lineDetailObj||{}; const ip=o.ip||_ipDetailTarget||'';
  const rows=Object.keys(o).map(k=>{ let v=o[k];
    if(v===null||v===undefined||v==='') v='<span style="color:var(--gray-400)">—</span>'; else v=esc(String(v));
    return `<tr><td style="font-weight:700;white-space:nowrap;vertical-align:top;color:var(--gray-600);">${esc(k)}</td><td style="font-family:monospace;font-size:12px;word-break:break-all;">${v}</td></tr>`;}).join('');
  b.innerHTML=`${ip?`<div style="margin-bottom:10px;"><button class="db-action-btn" onclick="openIpDetail('${escAttr(ip)}')"><svg class="ic"><use href="#ic-search"/></svg>See everything from ${esc(ip)}</button></div>`:''}
    <table>${rows||'<tr><td>No fields.</td></tr>'}</table>`;
}
async function renderIpProfile(){
  const b=$('srv-detail-body'); const ip=_ipDetailTarget;
  b.innerHTML='<div class="empty-state">Gathering everything for '+esc(ip)+'…</div>';
  let d; try{ d=await (await api('/api/system/ip-profile?ip='+encodeURIComponent(ip))).json(); }
  catch(e){ b.innerHTML=`<div class="empty-state">Failed: ${esc(String(e))}</div>`; return; }
  if(d.error){ b.innerHTML=`<div class="empty-state">Error: ${esc(d.error)}</div>`; return; }
  _ipProfileData=d; const s=d.summary||{};
  const card=(label,val,color)=>`<div class="metric-card" style="min-width:120px;"><div class="metric-head"><span class="metric-title">${label}</span><span class="metric-now" style="${color?'color:'+color:''}">${val}</span></div></div>`;
  const blocked=s.blocked?`<span style="background:rgba(231,76,60,0.12);color:#c0392b;padding:2px 9px;border-radius:4px;font-weight:700;">BLOCKED</span>`:`<button class="db-action-btn" onclick="blockIpFromProfile('${escAttr(ip)}')">Block this IP</button>`;
  const users=(s.usernames||[]).filter(Boolean);
  const section=(title,inner)=>`<div style="margin-top:18px;"><div style="font-weight:700;font-size:13px;margin-bottom:6px;">${title}</div>${inner}</div>`;
  const none='<div style="color:var(--gray-400);font-size:12px;">None.</div>';
  const http=d.http||{};
  const httpRows=(http.recent||[]).slice(0,60).map((r,i)=>`<tr style="cursor:pointer;" onclick="openLineDetail('HTTP request',_ipProfileData.http.recent[${i}])"><td style="font-size:11px;white-space:nowrap;">${esc(String(r.ts).slice(0,19))}</td><td style="font-weight:700;">${esc(r.method)}</td><td style="font-family:monospace;font-size:11px;">${esc(r.path)}</td><td>${esc(r.status_code)}</td><td style="font-size:11px;color:var(--gray-600);">${esc(r.authed_user||'—')}</td></tr>`).join('');
  const topPaths=(http.top_paths||[]).map(p=>`<span style="display:inline-block;background:var(--gray-100);border-radius:3px;padding:1px 7px;margin:2px;font-size:11px;font-family:monospace;">${esc(p.path)} <b>×${p.count}</b></span>`).join('');
  const wl=d.web_logins||{};
  const wlRows=(wl.recent||[]).slice(0,40).map((r,i)=>`<tr style="cursor:pointer;${r.success?'':'background:rgba(231,76,60,0.05)'}" onclick="openLineDetail('Web login',_ipProfileData.web_logins.recent[${i}])"><td style="font-size:11px;white-space:nowrap;">${esc(String(r.ts).slice(0,19))}</td><td style="font-family:monospace;">${esc(r.username||'—')}</td><td style="color:${r.success?'#27ae60':'#e74c3c'};font-weight:700;">${r.success?'OK':'FAIL'}</td><td>${(!r.success&&r.tried_password)?`<code style="font-size:11px;color:#c0392b;">${esc(r.tried_password)}</code>`:'<span style="color:var(--gray-400)">—</span>'}</td></tr>`).join('');
  const sess=(d.sessions||[]).map((r,i)=>`<tr style="cursor:pointer;" onclick="openLineDetail('Web session',_ipProfileData.sessions[${i}])"><td style="font-size:11px;white-space:nowrap;">${esc(String(r.login_at).slice(0,19))}</td><td style="font-family:monospace;">${esc(r.username)}</td><td>${esc(r.status)}</td><td style="font-size:11px;color:var(--gray-600);">${esc(String(r.logout_at||'').slice(0,19)||'—')}</td></tr>`).join('');
  const ssh=d.ssh||{};
  const sshRows=(ssh.recent||[]).slice(0,40).map((r,i)=>`<tr style="cursor:pointer;" onclick="openLineDetail('SSH event',_ipProfileData.ssh.recent[${i}])"><td style="font-size:11px;white-space:nowrap;">${esc(String(r.ts).slice(0,19))}</td><td>${esc(r.event_type)}</td><td>${esc(r.username||'—')}</td><td style="font-family:monospace;font-size:10px;">${esc(r.fingerprint||'')}</td></tr>`).join('');
  b.innerHTML=`<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:6px;">
      ${card('HTTP requests',s.http_requests??0)}${card('Login attempts',s.web_login_attempts??0)}${card('Failed logins',s.web_login_failed??0,(s.web_login_failed?'#e74c3c':''))}${card('Sessions',s.sessions??0)}${card('SSH events',s.ssh_events??0)}</div>
    <div style="margin:6px 0 2px;">${blocked}${users.length?`<span style="margin-left:10px;font-size:12px;color:var(--gray-600);">Accounts seen: ${users.map(u=>`<b>${esc(u)}</b>`).join(', ')}</span>`:''}</div>
    <div style="font-size:11px;color:var(--gray-500);">First seen ${esc(http.first||'—')} • last ${esc(http.last||'—')} • ${http.distinct_paths??0} distinct paths</div>
    ${section(`HTTP access (${http.total??0}) — most-hit paths`,topPaths||none)}
    ${(http.recent||[]).length?`<table><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>Status</th><th>User</th></tr></thead><tbody>${httpRows}</tbody></table>`:''}
    ${section(`Web-panel logins (${wl.total??0}, ${wl.failed??0} failed)`,(wl.recent||[]).length?`<table><thead><tr><th>Time</th><th>Username</th><th>Result</th><th>Tried password</th></tr></thead><tbody>${wlRows}</tbody></table>`:none)}
    ${section(`Sessions (${(d.sessions||[]).length})`,(d.sessions||[]).length?`<table><thead><tr><th>Login</th><th>User</th><th>Status</th><th>Logout</th></tr></thead><tbody>${sess}</tbody></table>`:none)}
    ${section(`SSH events (${ssh.total??0}, ${ssh.failed??0} failed)`,(ssh.recent||[]).length?`<table><thead><tr><th>Time</th><th>Event</th><th>User</th><th>Fingerprint</th></tr></thead><tbody>${sshRows}</tbody></table>`:none)}
    <div style="margin-top:14px;font-size:11px;color:var(--gray-500);">Tip: click any row above for the full record.</div>`;
}
async function blockIpFromProfile(ip){
  if(!(await appConfirm('Block '+ip+' from the web panel?',{title:'Block IP',danger:true}))) return;
  try{ await api('/api/system/web-block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,note:'Blocked from IP profile'})});
    appToast('Blocked '+ip,'ok'); renderIpProfile(); }catch(e){ appToast('Block failed: '+e,'err'); }
}

/* ---- server configuration + SSH on/off ---- */
async function loadServerConfig(){
  try{
    const r=await api('/api/system/config'); if(r&&r.ok){ const d=await r.json();
      if($('cfg-host')) $('cfg-host').value=d.host; if($('cfg-port')) $('cfg-port').value=d.port;
      const chips=[d.default_host,d.public_host,'127.0.0.1'].filter(Boolean);
      if($('host-chips')) $('host-chips').innerHTML=chips.map(c=>`<span class="host-chip" onclick="document.getElementById('cfg-host').value='${esc(c)}'">${esc(c)}</span>`).join('');
      const live=(d.running_host&&d.running_port)?`Currently serving on <strong>http://${esc(d.running_host)}:${d.running_port}</strong>.`:'';
      const pending=((d.host!==d.running_host||d.port!==d.running_port)&&d.running_host)?` <span class="cfg-warn">Saved ${esc(d.host)}:${d.port} applies after restart.</span>`:'';
      if($('cfg-running')) $('cfg-running').innerHTML=live+pending;
    }
  }catch(e){}
  loadSshStatus();
}
async function saveServerConfig(){
  const host=$('cfg-host').value.trim(), port=parseInt($('cfg-port').value,10);
  const fb=$('cfg-feedback'), btn=$('cfg-save-btn'); fb.textContent=''; fb.className='save-feedback'; btn.disabled=true;
  try{
    const r=await api('/api/system/config',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({host,port})});
    const d=await r.json();
    if(!r.ok){ fb.textContent=d.error||'Save failed'; fb.classList.add('err'); }
    else{ fb.textContent=d.needs_restart?`Saved ${d.host}:${d.port}. Restart to apply.`:`Saved ${d.host}:${d.port}.`; fb.classList.add('ok'); loadServerConfig(); }
  }catch(e){ fb.textContent='Request failed: '+e; fb.classList.add('err'); }
  btn.disabled=false;
}
async function loadSshStatus(){
  const stateEl=$('ssh-state'), btn=$('ssh-toggle-btn'); if(!stateEl||!btn) return; btn.disabled=true;
  try{
    const r=await api('/api/system/ssh-status'); const d=await r.json();
    if(!r.ok||d.error){ stateEl.textContent='Status error: '+esc(d.error||'unknown'); return; }
    const on=!!d.active;
    stateEl.innerHTML=`SSH is <b style="color:${on?'#27ae60':'var(--danger)'}">${on?'ON':'OFF'}</b> <span style="color:var(--gray-500);">(${esc(d.state)}, on boot: ${esc(d.enabled)})</span>`;
    btn.textContent=on?'Turn SSH Off':'Turn SSH On'; btn.dataset.enable=on?'0':'1'; btn.disabled=false;
  }catch(e){ stateEl.textContent='Could not reach server.'; }
}
async function toggleSsh(){
  const btn=$('ssh-toggle-btn'), fb=$('ssh-feedback'); const enable=btn.dataset.enable==='1';
  if(!enable){ if(!(await uiConfirm('Turn SSH off?','This stops and disables the SSH daemon. If SSH is your only way in, you may lock yourself out.'))) return; }
  btn.disabled=true; if(fb) fb.textContent='Applying…';
  try{
    const r=await api('/api/system/ssh-toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enable})});
    const d=await r.json();
    if(!r.ok||d.error){ if(fb) fb.textContent=''; await uiAlert('Failed',esc(d.error||'Toggle failed.')); }
    else{ appToast('SSH is now '+(d.active?'ON':'OFF'),'ok'); if(fb) fb.textContent=''; }
  }catch(e){ if(fb) fb.textContent=''; await uiAlert('Failed','Network error.'); }
  loadSshStatus();
}

/* ================= SERVICES ================= */
let SVC_ALL=[];
async function loadServices(){ const d=await getJSON('/api/services'); if(!d) return; SVC_ALL=d.services||[]; renderServices(); }
function renderServices(){
  const q=($('svc-search')?.value||'').toLowerCase();
  const list=SVC_ALL.filter(s=>!q||s.name.toLowerCase().includes(q)||(s.description||'').toLowerCase().includes(q));
  const body=$('svc-list'); if(!body) return;
  body.innerHTML=`<table><thead><tr><th>Service</th><th>State</th><th>Description</th><th>Actions</th></tr></thead><tbody>`+
    list.map(s=>{ const on=s.active==='active';
      return `<tr><td style="font-family:var(--mono);font-size:12px;">${esc(s.short)}</td>
        <td><span style="font-weight:700;color:${on?'#27ae60':(s.active==='failed'?'#e74c3c':'var(--gray-500)')}">${esc(s.active)}</span><span style="color:var(--gray-500);font-size:11px;"> / ${esc(s.sub)}</span></td>
        <td style="color:var(--gray-600);">${esc(s.description)}</td>
        <td style="white-space:nowrap;"><button class="db-action-btn" onclick="svc('${esc(s.short)}','restart')">Restart</button>
          ${on?`<button class="db-action-btn" style="border-color:#e74c3c;color:#c0392b;" onclick="svc('${esc(s.short)}','stop')">Stop</button>`:`<button class="db-action-btn" style="border-color:#27ae60;color:#1e8449;" onclick="svc('${esc(s.short)}','start')">Start</button>`}
          <button class="db-action-btn" onclick="svcDetail('${esc(s.short)}')">Status</button></td></tr>`;
    }).join('')+`</tbody></table>`;
}
async function svc(name,action){
  if((action==='stop'||action==='restart')&&!(await appConfirm(action+' '+name+'?',{title:'Confirm',danger:true}))) return;
  const r=await api('/api/services/'+encodeURIComponent(name)+'/'+action,{method:'POST'}); if(!r) return;
  const d=await r.json(); if(!d.ok) appToast('Failed: '+(d.message||'error'),'err'); else appToast(name+' '+action+' ✓','ok');
  setTimeout(loadServices,700);
}
async function svcDetail(name){
  _srvDetailKind=null; $('srv-detail-title').textContent='Service — '+name; $('srv-detail-overlay').classList.add('open');
  const b=$('srv-detail-body'); b.innerHTML='<div class="empty-state">Loading…</div>';
  const d=await getJSON('/api/services/'+encodeURIComponent(name)); if(!d) return;
  b.innerHTML=`<div style="margin-bottom:8px;">active: <b>${esc(d.active)}</b> · on boot: <b>${esc(d.enabled)}</b></div>
    <pre style="background:var(--gray-50);border:1px solid var(--gray-200);border-radius:6px;padding:12px;max-height:56vh;overflow:auto;font-size:12px;white-space:pre-wrap;font-family:var(--mono);">${esc(d.status||'')}</pre>`;
}

/* ================= LOGS (security + panel actions) ================= */
let _secSection='panel-actions', _secSSHData=null, _secCounts={};
function showSecSection(name){
  _secSection=name;
  document.querySelectorAll('.sec-section-btn').forEach(b=>b.classList.toggle('active',b.dataset.sec===name));
  renderSecSection();
}
function secHeader(label,clearKind,liveNote){
  const n=_secCounts[clearKind]; const total=(n===undefined||n===null)?'—':n.toLocaleString();
  const clearBtn=clearKind?`<button class="db-action-btn" style="border-color:#e74c3c;color:#c0392b;" onclick="clearSecLog('${clearKind}','${esc(label)}')"><svg class="ic"><use href="#ic-trash-2"/></svg>Clear ${esc(label)}</button>`:'';
  return `<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:10px;"><span style="font-size:12px;color:var(--gray-600);">${esc(liveNote||'')}</span>
    <span style="margin-left:auto;font-size:12px;font-weight:700;padding:3px 9px;border-radius:4px;background:var(--gray-100);">Total stored: ${total}</span>${clearBtn}</div>`;
}
async function clearSecLog(kind,label){
  if(!(await appConfirm(`Permanently delete ALL stored "${label}" records? This cannot be undone.`,{title:'Clear '+label,danger:true}))) return;
  try{ const r=await api('/api/system/clear-log',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({kind})});
    const d=await r.json(); if(d.error){ appToast('Could not clear: '+d.error,'err'); return; }
    appToast(`Cleared ${d.removed} record(s) from ${label}.`,'ok'); loadSecurityLogs();
  }catch(e){ appToast('Network error: '+e,'err'); }
}
async function loadSecurityLogs(){
  const since=$('sec-since-sel')?.value||'';
  $('sec-content').innerHTML='<div class="empty-state">Loading…</div>';
  try{
    const [sshRes,webRes,cntRes]=await Promise.all([
      api('/api/system/ssh-logs?limit=300'+(since?'&since='+encodeURIComponent(since):'')),
      api('/api/system/web-login-logs?limit=100'),
      api('/api/system/log-counts')]);
    try{ _secCounts=await cntRes.json()||{}; }catch(_){ _secCounts={}; }
    _secSSHData=await sshRes.json(); const webData=await webRes.json();
    _secSSHData._webLogs=webData.logs||[]; _secSSHData._webTotal=webData.total||0;
    _secSSHData._webSuccess=webData.success||0; _secSSHData._webFailed=webData.failed||0;
    const s=_secSSHData.summary||{};
    $('sec-total').textContent=s.total_events??'—';
    $('sec-unique-ips').textContent='unique IPs: '+(s.unique_ips??'—');
    $('sec-accepted').textContent=s.accepted_count??'—';
    $('sec-sessions').textContent='active sessions: '+(_secSSHData.current_sessions?.length??0);
    $('sec-failed').textContent=s.failed_count??'—';
    $('sec-attackers').textContent='attacker IPs: '+(s.attacker_ips??'—');
    $('sec-web-total').textContent=webData.total??'—';
    $('sec-web-fail').textContent='failed: '+(webData.failed??'—');
  }catch(e){ _secSSHData={error:String(e)}; }
  renderSecSection();
}
function renderSecSection(){
  const c=$('sec-content');
  if(_secSection==='panel-actions') return loadPanelActions(c);
  if(_secSection==='access-log') return loadAccessLog(c);
  if(_secSection==='web-sessions') return loadWebSessions(c);
  if(_secSection==='fp-blocked') return loadFpBlocked(c);
  if(_secSection==='web-blocked') return loadWebBlocked(c);
  if(!_secSSHData){ c.innerHTML='<div class="empty-state">No data loaded.</div>'; return; }
  if(_secSSHData.error){ c.innerHTML=`<div class="empty-state">Error: ${esc(_secSSHData.error)}</div>`; return; }
  if(_secSection==='ssh-sessions'){
    const rows=(_secSSHData.current_sessions||[]).map(s=>`<tr><td>${esc(s.remote)}</td><td>${esc(s.local)}</td><td>${esc(s.process)}</td><td>${esc(s.pid??'—')}</td></tr>`).join('');
    c.innerHTML=secHeader('SSH Events','ssh','Live SSH connections on port 22 right now.')+`<table><thead><tr><th>Remote IP:Port</th><th>Local</th><th>Process</th><th>PID</th></tr></thead><tbody>${rows||'<tr><td colspan="4" style="color:var(--gray-400);text-align:center;">No active SSH sessions.</td></tr>'}</tbody></table>`; return;
  }
  if(_secSection==='ssh-accepted'){
    const rows=(_secSSHData.accepted||[]).slice(0,100).map(e=>`<tr><td style="white-space:nowrap;">${esc(e.ts)}</td><td><b>${esc(e.ip??'—')}</b></td><td>${esc(e.user??'—')}</td><td>${esc(e.method??'—')}</td><td>${esc(e.port??'—')}</td></tr>`).join('');
    c.innerHTML=secHeader('SSH Events','ssh',`${(_secSSHData.accepted||[]).length} successful SSH logins.`)+`<table><thead><tr><th>Timestamp</th><th>IP</th><th>User</th><th>Method</th><th>Port</th></tr></thead><tbody>${rows||'<tr><td colspan="5" style="color:var(--gray-400);text-align:center;">No successful logins.</td></tr>'}</tbody></table>`; return;
  }
  if(_secSection==='ssh-fingerprints'){
    const rows=(_secSSHData.fingerprints||[]).slice(0,100).map(e=>`<tr><td style="white-space:nowrap;">${esc(e.ts)}</td><td>${esc(e.ip??'—')}</td><td style="font-family:monospace;font-size:11px;">${esc(e.fingerprint??'—')}</td></tr>`).join('');
    c.innerHTML=secHeader('SSH Events','ssh','SSH key fingerprints presented during authentication.')+`<table><thead><tr><th>Timestamp</th><th>IP</th><th>Fingerprint</th></tr></thead><tbody>${rows||'<tr><td colspan="3" style="color:var(--gray-400);text-align:center;">No fingerprint events.</td></tr>'}</tbody></table>`; return;
  }
  if(_secSection==='ssh-top-ips'){
    const rows=(_secSSHData.ip_stats||[]).map(s=>`<tr><td style="cursor:pointer;text-decoration:underline dotted;" onclick="sshAttacker('${escAttr(s.ip)}')"><b>${esc(s.ip)}</b></td><td>${s.attempts}</td><td style="color:${s.success>0?'#27ae60':'#e74c3c'}">${s.success>0?s.success+' ✓':'0'}</td><td style="color:var(--gray-600);font-size:11px;">${esc(s.last_seen)}</td><td><button class="db-action-btn" style="border-color:#e74c3c;color:#c0392b;font-size:11px;padding:2px 8px;" onclick="sshBlock('${escAttr(s.ip)}')">Block device</button></td></tr>`).join('');
    c.innerHTML=secHeader('SSH Events','ssh','Top IPs by connection attempts (green = got in). Click an IP to see what it tried.')+`<table><thead><tr><th>IP</th><th>Attempts</th><th>Success</th><th>Last Seen</th><th>Action</th></tr></thead><tbody>${rows||'<tr><td colspan="5" style="color:var(--gray-400);text-align:center;">No data.</td></tr>'}</tbody></table>`; return;
  }
  if(_secSection==='ssh-events'){
    const rows=(_secSSHData.events||[]).slice(0,200).map(e=>{ const color=e.event==='ACCEPTED'?'#27ae60':e.event==='FAILED'?'#e74c3c':'var(--gray-600)';
      return `<tr><td style="white-space:nowrap;font-size:11px;">${esc(e.ts)}</td><td style="color:${color};font-weight:${e.event==='ACCEPTED'?'700':'400'}">${esc(e.event)}</td><td>${esc(e.ip??'—')}</td><td>${esc(e.user??'—')}</td><td>${esc(e.method??'—')}</td><td style="font-family:monospace;font-size:10px;">${esc(e.fingerprint??'')}</td></tr>`;}).join('');
    c.innerHTML=secHeader('SSH Events','ssh','All SSH events (most recent first), persisted across journald rotation.')+`<table><thead><tr><th>Timestamp</th><th>Event</th><th>IP</th><th>User</th><th>Method</th><th>Fingerprint</th></tr></thead><tbody>${rows||'<tr><td colspan="6" style="color:var(--gray-400);text-align:center;">No events.</td></tr>'}</tbody></table>`; return;
  }
  if(_secSection==='web-logs'){
    const rows=(_secSSHData._webLogs||[]).map((e,i)=>{ const ok=e.success;
      const pwCell=!ok&&e.tried_password?`<code style="background:rgba(231,76,60,0.1);color:#c0392b;padding:1px 5px;border-radius:3px;font-size:11px;">${esc(e.tried_password)}</code>`:'<span style="color:var(--gray-400);">—</span>';
      return `<tr style="${!ok?'background:rgba(231,76,60,0.04)':''}"><td style="white-space:nowrap;font-size:11px;cursor:pointer;text-decoration:underline dotted;" onclick="openLineDetail('Web login',_secSSHData._webLogs[${i}])">${esc(String(e.ts).slice(0,19))}</td><td style="cursor:pointer;text-decoration:underline dotted;" onclick="openIpDetail('${escAttr(e.ip)}')"><b>${esc(e.ip)}</b></td><td style="font-family:monospace;">${esc(e.username??'—')}</td><td style="color:${ok?'#27ae60':'#e74c3c'};font-weight:700">${ok?'OK':'FAIL'}</td><td>${pwCell}</td><td style="font-size:11px;color:var(--gray-600);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escAttr(e.user_agent??'')}">${esc((e.user_agent??'').slice(0,45))}</td><td style="font-size:11px;color:var(--gray-600);">${esc(e.details??'')}</td></tr>`;}).join('');
    c.innerHTML=secHeader('Web Login Logs','web_logins',`Panel login history — ${_secSSHData._webTotal??0} total · ${_secSSHData._webSuccess??0} ok · ${_secSSHData._webFailed??0} failed.`)+`<table><thead><tr><th>Timestamp</th><th>IP</th><th>Username</th><th>Result</th><th>Tried Password</th><th>User Agent</th><th>Details</th></tr></thead><tbody>${rows||'<tr><td colspan="7" style="color:var(--gray-400);text-align:center;">No login records.</td></tr>'}</tbody></table>`; return;
  }
}
async function loadPanelActions(c){
  c.innerHTML='<div class="empty-state">Loading panel actions…</div>';
  const lvl=$('pa-level')?.value||'', cat=$('pa-cat')?.value||'', q=$('pa-q')?.value||'';
  const d=await getJSON('/api/logs?level='+lvl+'&category='+cat+'&q='+encodeURIComponent(q)+'&limit=400'); if(!d) return;
  const cc=await getJSON('/api/logs/counts');
  const lvlColor=l=>({INFO:'var(--gray-600)',ACTION:'var(--accent)',WARN:'#b9772a',ERROR:'#e74c3c'}[l]||'var(--gray-600)');
  const rows=(d.logs||[]).map(l=>`<tr>
    <td style="white-space:nowrap;font-size:11px;font-family:var(--mono);color:var(--gray-600);">${esc(l.ts)}</td>
    <td style="font-weight:700;color:${lvlColor(l.level)};">${esc(l.level)}</td>
    <td><span style="font-size:11px;background:var(--gray-100);border-radius:3px;padding:1px 7px;">${esc(l.category)}</span></td>
    <td>${esc(l.action)}${l.target?` <span style="color:var(--gray-500);">→ ${esc(l.target)}</span>`:''}</td>
    <td>${esc(l.actor)}${l.ip?` <span style="color:var(--gray-500);">· ${esc(l.ip)}</span>`:''}</td>
    <td style="color:${l.status==='ok'?'#27ae60':(l.status==='failed'||l.status==='denied'?'#e74c3c':'var(--gray-600)')};font-weight:600;">${esc(l.status)}</td>
    <td style="font-size:11px;font-family:var(--mono);color:var(--gray-600);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escAttr(l.detail)}">${esc((l.detail||'').slice(0,120))}</td></tr>`).join('');
  const b=cc?cc.by_level:{};
  c.innerHTML=`<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
      <span style="font-size:12px;color:var(--gray-600);">Every action and data movement performed through this panel by any user — logins, service control, terminal commands, security actions.</span>
      <span style="margin-left:auto;"></span>
      <select id="pa-level" onchange="loadPanelActions(document.getElementById('sec-content'))" style="padding:5px 8px;border:1px solid var(--gray-200);border-radius:4px;font-size:12px;background:var(--white);color:var(--black);"><option value="">All levels</option><option>INFO</option><option>ACTION</option><option>WARN</option><option>ERROR</option></select>
      <select id="pa-cat" onchange="loadPanelActions(document.getElementById('sec-content'))" style="padding:5px 8px;border:1px solid var(--gray-200);border-radius:4px;font-size:12px;background:var(--white);color:var(--black);"><option value="">All categories</option><option>AUTH</option><option>SERVICE</option><option>TERMINAL</option><option>SYSTEM</option></select>
      <input id="pa-q" placeholder="search…" onkeydown="if(event.key==='Enter')loadPanelActions(document.getElementById('sec-content'))" style="width:140px;padding:5px 8px;border:1px solid var(--gray-200);border-radius:4px;font-size:12px;background:var(--white);color:var(--black);">
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
      <span style="font-size:12px;font-weight:700;padding:3px 9px;border-radius:4px;background:var(--gray-100);">${cc?cc.total:0} total</span>
      <span style="font-size:12px;padding:3px 9px;border-radius:4px;background:rgba(122,83,38,.12);color:var(--accent);">${b.ACTION||0} actions</span>
      <span style="font-size:12px;padding:3px 9px;border-radius:4px;background:rgba(185,119,42,.14);color:#b9772a;">${b.WARN||0} warn</span>
      <span style="font-size:12px;padding:3px 9px;border-radius:4px;background:rgba(231,76,60,.12);color:#e74c3c;">${b.ERROR||0} error</span></div>
    <table><thead><tr><th>Time</th><th>Level</th><th>Category</th><th>Action</th><th>Actor</th><th>Status</th><th>Detail</th></tr></thead>
    <tbody>${rows||'<tr><td colspan="7" style="color:var(--gray-400);text-align:center;">No actions logged yet.</td></tr>'}</tbody></table>`;
  // restore filter values
  if($('pa-level')) $('pa-level').value=lvl; if($('pa-cat')) $('pa-cat').value=cat; if($('pa-q')) $('pa-q').value=q;
}
let _alPage=1,_alIp='',_alPath='';
async function loadAccessLog(c,page,ipF,pathF){
  page=page??_alPage; ipF=ipF??_alIp; pathF=pathF??_alPath; _alPage=page; _alIp=ipF; _alPath=pathF;
  c.innerHTML='<div class="empty-state">Loading access log…</div>';
  const params=new URLSearchParams({page,limit:100}); if(ipF) params.set('ip',ipF); if(pathF) params.set('path',pathF);
  try{
    const d=await (await api('/api/system/access-log?'+params)).json(); const logs=d.logs||[];
    const methodColor=m=>({GET:'#2980b9',POST:'#27ae60',DELETE:'#e74c3c',PUT:'#e67e22',PATCH:'#8e44ad'}[m]||'#555');
    const statusColor=s=>s<300?'#27ae60':s<400?'#2980b9':s<500?'#e67e22':'#e74c3c';
    const rows=logs.map(r=>{ const ua=r.user_agent||'';
      const browser=ua.match(/Chrome\/[\d.]+/)?'Chrome':ua.match(/Firefox\/[\d.]+/)?'Firefox':ua.match(/Safari\/[\d.]+/)?'Safari':ua.match(/curl/)?'curl':ua.match(/[Pp]ython/)?'Python':ua.match(/bot|crawl|spider/i)?'Bot':ua.slice(0,14)||'—';
      const pathCell=r.query?`${esc(r.path)}<span style="color:var(--gray-400);font-size:10px;">?${esc(r.query.slice(0,40))}</span>`:esc(r.path);
      return `<tr><td style="font-size:11px;white-space:nowrap;cursor:pointer;text-decoration:underline dotted;" onclick="openAccessDetail(${r.id})">${esc(String(r.ts).slice(0,19))}</td><td style="cursor:pointer;text-decoration:underline dotted;" onclick="openIpDetail('${escAttr(r.ip)}')"><b>${esc(r.ip)}</b></td><td style="font-weight:700;color:${methodColor(r.method)}">${esc(r.method)}</td><td style="font-family:monospace;font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer;text-decoration:underline dotted;" onclick="loadAccessLog(document.getElementById('sec-content'),1,'','${escAttr(r.path)}')">${pathCell}</td><td style="font-weight:700;color:${statusColor(r.status_code)}">${r.status_code}</td><td style="font-size:11px;color:var(--gray-600);">${r.duration_ms??'—'}ms</td><td style="font-size:11px;color:var(--gray-600);">${esc(browser)}</td><td style="font-size:11px;color:var(--gray-600);">${esc(r.authed_user||'—')}</td></tr>`;}).join('');
    const totalPages=Math.max(1,Math.ceil((d.total||0)/100));
    const prevBtn=page>1?`<button class="db-action-btn" onclick="loadAccessLog(document.getElementById('sec-content'),${page-1})">← Prev</button>`:'';
    const nextBtn=page<totalPages?`<button class="db-action-btn" onclick="loadAccessLog(document.getElementById('sec-content'),${page+1})">Next →</button>`:'';
    const activeFilter=(ipF||pathF)?`<span style="background:rgba(41,128,185,0.1);color:#2980b9;padding:2px 8px;border-radius:3px;font-size:11px;margin-left:8px;">${ipF?'IP: '+esc(ipF):''}${ipF&&pathF?' · ':''}${pathF?'Path: '+esc(pathF):''} <span style="cursor:pointer;" onclick="loadAccessLog(document.getElementById('sec-content'),1,'','')">× clear</span></span>`:'';
    c.innerHTML=secHeader('Access Log','access','Every page and API request hitting the server (logins and admin actions included).')+`
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px;"><div style="font-size:12px;color:var(--gray-600);"><b>${d.total??0}</b> requests • <b>${d.unique_ips??0}</b> IPs • page ${page}/${totalPages}${activeFilter}</div>
        <div style="margin-left:auto;display:flex;gap:6px;align-items:center;"><input id="al-ip-f" placeholder="Filter IP" value="${escAttr(ipF)}" style="width:120px;padding:5px 8px;border:1px solid var(--gray-200);border-radius:4px;font-size:12px;background:var(--white);color:var(--black);"><input id="al-path-f" placeholder="Filter path" value="${escAttr(pathF)}" style="width:140px;padding:5px 8px;border:1px solid var(--gray-200);border-radius:4px;font-size:12px;background:var(--white);color:var(--black);"><button class="db-action-btn" onclick="loadAccessLog(document.getElementById('sec-content'),1,document.getElementById('al-ip-f').value,document.getElementById('al-path-f').value)">Filter</button>${prevBtn}${nextBtn}</div></div>
      <table><thead><tr><th>Timestamp</th><th>IP</th><th>Method</th><th>Path</th><th>Status</th><th>Time</th><th>Browser</th><th>User</th></tr></thead><tbody>${rows||'<tr><td colspan="8" style="color:var(--gray-400);text-align:center;">No requests logged yet.</td></tr>'}</tbody></table>`;
  }catch(e){ c.innerHTML=`<div class="empty-state">Error: ${esc(String(e))}</div>`; }
}
async function loadWebSessions(c){
  c.innerHTML='<div class="empty-state">Loading sessions…</div>';
  try{
    const d=await (await api('/api/system/web-sessions?limit=100')).json();
    const rows=(d.sessions||[]).map(s=>{ const isActive=s.status==='active', isExpired=s.status==='expired';
      const statusLabel=isActive?'<span style="color:#27ae60;font-weight:700;">● ACTIVE</span>':isExpired?'<span style="color:#e67e22;">EXPIRED</span>':'<span style="color:#999;">LOGGED OUT</span>';
      const ua=s.user_agent||''; const browser=ua.match(/Chrome\/[\d.]+/)?'Chrome':ua.match(/Firefox\/[\d.]+/)?'Firefox':ua.match(/Safari\/[\d.]+/)?'Safari':ua.slice(0,20)||'—';
      return `<tr style="${isActive?'background:rgba(39,174,96,0.05)':''}"><td style="font-family:monospace;font-size:11px;" title="${escAttr(s.session_id)}">${esc((s.session_id||'').slice(0,12))}…</td><td style="font-weight:600;">${esc(s.username)}</td><td style="cursor:pointer;text-decoration:underline dotted;" onclick="openIpDetail('${escAttr(s.ip)}')"><b>${esc(s.ip)}</b></td><td style="font-size:11px;color:var(--gray-600);" title="${escAttr(ua)}">${esc(browser)}</td><td style="font-size:11px;white-space:nowrap;">${esc(String(s.login_at).slice(0,19))}</td><td style="font-size:11px;white-space:nowrap;">${esc(String(s.expires_at).slice(0,19))}</td><td style="font-size:11px;white-space:nowrap;">${s.logout_at?esc(String(s.logout_at).slice(0,19)):'<span style="color:var(--gray-400)">—</span>'}</td><td>${statusLabel}</td></tr>`;}).join('');
    c.innerHTML=secHeader('Sessions','sessions','Every web login session (active, expired, logged out).')+`
      <div style="display:flex;gap:16px;margin-bottom:14px;flex-wrap:wrap;"><div style="padding:10px 18px;border-radius:6px;border:1px solid var(--gray-200);background:var(--gray-50);"><div style="font-size:11px;color:var(--gray-600);text-transform:uppercase;letter-spacing:.6px;">Active Now</div><div style="font-size:22px;font-weight:700;color:#27ae60;">${d.active??0}</div></div><div style="padding:10px 18px;border-radius:6px;border:1px solid var(--gray-200);background:var(--gray-50);"><div style="font-size:11px;color:var(--gray-600);text-transform:uppercase;letter-spacing:.6px;">Total Sessions</div><div style="font-size:22px;font-weight:700;">${d.total??0}</div></div></div>
      <table><thead><tr><th>Session ID</th><th>User</th><th>IP</th><th>Browser</th><th>Login</th><th>Expires</th><th>Logged Out</th><th>Status</th></tr></thead><tbody>${rows||'<tr><td colspan="8" style="color:var(--gray-400);text-align:center;">No sessions yet.</td></tr>'}</tbody></table>`;
  }catch(e){ c.innerHTML=`<div class="empty-state">Error: ${esc(String(e))}</div>`; }
}
async function loadWebBlocked(c){
  try{
    const d=await (await api('/api/system/web-blocked-ips')).json();
    const rows=(d.blocked||[]).map(b=>{ const isB=b.blocked_until&&new Date(b.blocked_until)>new Date();
      return `<tr><td><b>${esc(b.ip)}</b></td><td style="color:#e74c3c;font-weight:600;">${b.fail_count}</td><td style="font-size:11px;">${esc(String(b.first_fail).slice(0,19))}</td><td style="font-size:11px;">${esc(String(b.last_fail).slice(0,19))}</td><td style="font-size:11px;">${isB?`<span style="color:#e74c3c;font-weight:600;">${esc(String(b.blocked_until).slice(0,19))}</span>`:'<span style="color:var(--gray-400)">—</span>'}</td><td style="font-size:11px;color:var(--gray-600);">${esc(b.note??'')}</td><td><button class="db-action-btn" style="color:#e74c3c;" onclick="unblockWebIp('${escAttr(b.ip)}',this)">Unblock</button></td></tr>`;}).join('');
    c.innerHTML=secHeader('Blocked IPs','blocked','IPs locked out of the panel.')+`
      <div style="background:var(--gray-50);border:1px solid var(--gray-200);border-radius:6px;padding:14px 16px;margin-bottom:16px;"><div style="font-weight:700;font-size:13px;margin-bottom:10px;">Block an IP manually</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;"><input id="block-ip-input" placeholder="IP (1.2.3.4 or 1.2.3.0/24)" style="flex:1;min-width:180px;padding:7px 10px;border:1px solid var(--gray-200);border-radius:4px;font-family:monospace;font-size:13px;background:var(--white);color:var(--black);"><select id="block-ip-dur" style="padding:7px 10px;border:1px solid var(--gray-200);border-radius:4px;font-size:13px;background:var(--white);color:var(--black);"><option value="1">1 hour</option><option value="24">24 hours</option><option value="168">1 week</option><option value="8760" selected>1 year</option></select><input id="block-ip-note" placeholder="Note (optional)" style="width:160px;padding:7px 10px;border:1px solid var(--gray-200);border-radius:4px;font-size:13px;background:var(--white);color:var(--black);"><button class="db-action-btn" style="background:var(--black);color:var(--white);padding:7px 16px;" onclick="manualBlockIp()">Block IP</button></div>
        <div id="block-ip-msg" style="margin-top:8px;font-size:12px;min-height:16px;"></div></div>
      <table><thead><tr><th>IP</th><th>Fails</th><th>First Seen</th><th>Last Attempt</th><th>Blocked Until</th><th>Note</th><th>Action</th></tr></thead><tbody>${rows||'<tr><td colspan="7" style="color:var(--gray-400);text-align:center;">No blocked IPs.</td></tr>'}</tbody></table>`;
  }catch(e){ c.innerHTML=`<div class="empty-state">Error: ${esc(String(e))}</div>`; }
}
async function loadFpBlocked(c){
  c.innerHTML='<div class="empty-state">Loading blocked devices…</div>';
  try{
    const d=await (await api('/api/system/fp-blocked')).json();
    const rows=(d.blocked||[]).map(b=>{ const isB=b.blocked_until&&new Date(b.blocked_until)>new Date(); let sample=b.sample||'';
      try{ const o=JSON.parse(b.sample); sample=[o.platform,o.screen,o.timezone,o.gpu].filter(Boolean).join(' · '); }catch(_){}
      return `<tr><td><code style="font-size:11px;">${esc((b.fp_hash||'').slice(0,16))}</code></td><td style="color:#e74c3c;font-weight:600;">${b.fail_count}</td><td style="cursor:pointer;text-decoration:underline dotted;" onclick="openIpDetail('${escAttr(b.last_ip||'')}')"><b>${esc(b.last_ip||'—')}</b></td><td style="font-size:11px;color:var(--gray-600);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escAttr(b.sample||'')}">${esc(sample.slice(0,60))}</td><td style="font-size:11px;">${esc(String(b.last_fail).slice(0,19))}</td><td style="font-size:11px;">${isB?`<span style="color:#e74c3c;font-weight:600;">${esc(String(b.blocked_until).slice(0,19))}</span>`:'<span style="color:var(--gray-400)">expired</span>'}</td><td><button class="db-action-btn" style="color:#e74c3c;" onclick="unblockFp('${escAttr(b.fp_hash)}',this)">Unblock</button></td></tr>`;}).join('');
    c.innerHTML=secHeader('Blocked Devices','fp_blocked','Machines locked out by device fingerprint (stay blocked even if IP changes).')+`<table><thead><tr><th>Device fingerprint</th><th>Fails</th><th>Last IP</th><th>Device summary</th><th>Last Attempt</th><th>Blocked Until</th><th>Action</th></tr></thead><tbody>${rows||'<tr><td colspan="7" style="color:var(--gray-400);text-align:center;">No devices blocked.</td></tr>'}</tbody></table>`;
  }catch(e){ c.innerHTML=`<div class="empty-state">Error: ${esc(String(e))}</div>`; }
}
async function unblockFp(fp,btn){ if(btn){ btn.disabled=true; btn.textContent='…'; }
  try{ await api('/api/system/fp-unblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({fp_hash:fp})}); loadSecurityLogs(); }
  catch(e){ appToast('Error: '+e,'err'); if(btn){ btn.disabled=false; btn.textContent='Unblock'; } } }
async function sshAttacker(ip){
  try{ const d=await (await api('/api/system/ssh-attacker?ip='+encodeURIComponent(ip))).json();
    openLineDetail('SSH attacker '+ip,{ip:d.ip,usernames_tried:(d.usernames_tried||[]).map(u=>`${u.username} (${u.attempts})`).join(', ')||'—',auth_methods:(d.auth_methods||[]).join(', ')||'—',key_fingerprints:(d.key_fingerprints||[]).join('  |  ')||'none',events_by_type:Object.entries(d.events_by_type||{}).map(([k,v])=>`${k}: ${v}`).join(' · ')||'—',password_note:d.password_note}); }
  catch(e){ appToast('Error: '+e,'err'); } }
async function sshBlock(ip){
  if(!(await appConfirm(`Block SSH IP ${ip} at the OS firewall (iptables DROP)?`,{title:'Block SSH device',danger:true}))) return;
  try{ const d=await (await api('/api/system/ssh-block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})})).json();
    if(d.firewall_enforced) appToast(`Firewall rule added — ${ip} dropped.`,'ok'); else appToast(`Recorded but NOT enforced: ${d.detail||''}`,'err',7000); }
  catch(e){ appToast('Error: '+e,'err'); } }
async function manualBlockIp(){
  const ip=($('block-ip-input').value||'').trim(), hours=$('block-ip-dur').value, note=($('block-ip-note').value||'').trim()||'Manually blocked', msg=$('block-ip-msg');
  if(!ip){ msg.style.color='#e74c3c'; msg.textContent='Enter an IP address.'; return; }
  msg.style.color='var(--gray-600)'; msg.textContent='Blocking…';
  try{ const d=await (await api('/api/system/web-block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,hours:parseInt(hours),note})})).json();
    if(d.status==='blocked'){ msg.style.color='#27ae60'; msg.textContent=`${ip} blocked.`; $('block-ip-input').value=''; $('block-ip-note').value=''; setTimeout(()=>loadWebBlocked($('sec-content')),800); }
    else{ msg.style.color='#e74c3c'; msg.textContent=d.error||'Failed.'; } }
  catch(e){ msg.style.color='#e74c3c'; msg.textContent=String(e); } }
async function unblockWebIp(ip,btn){ btn.disabled=true; btn.textContent='…';
  try{ await api('/api/system/web-unblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})}); btn.textContent='Unblocked'; setTimeout(()=>loadWebBlocked($('sec-content')),600); }
  catch{ btn.disabled=false; btn.textContent='Error'; } }

/* ================= TERMINAL (xterm.js PTY, multi-session) ================= */
const TERM_STORE_KEY='management_terminals';
const termTabs=[]; let activeSid=null, termViewReady=false, termLibLoading=null;
function loadScript(src){ return new Promise((res,rej)=>{ const el=document.createElement('script'); el.src=src; el.onload=res; el.onerror=()=>rej(new Error('load '+src)); document.head.appendChild(el); }); }
function ensureTermLib(){
  if(window.Terminal&&window.FitAddon) return Promise.resolve();
  if(termLibLoading) return termLibLoading;
  if(!$('xterm-css')){ const link=document.createElement('link'); link.id='xterm-css'; link.rel='stylesheet'; link.href=BASE+'/assets/xterm/xterm.css'; document.head.appendChild(link); }
  termLibLoading=loadScript(BASE+'/assets/xterm/xterm.js').then(()=>loadScript(BASE+'/assets/xterm/addon-fit.js'));
  return termLibLoading;
}
function genSid(){ const a=new Uint8Array(8); (window.crypto||window.msCrypto).getRandomValues(a); return Array.from(a,b=>b.toString(16).padStart(2,'0')).join(''); }
function termGetTab(sid){ return termTabs.find(t=>t.sid===sid)||null; }
function termStoreSave(){ try{ localStorage.setItem(TERM_STORE_KEY,JSON.stringify(termTabs.map(t=>({sid:t.sid,name:t.name,persist:t.persist})))); }catch(e){} }
function termStoreLoad(){ try{ return JSON.parse(localStorage.getItem(TERM_STORE_KEY))||[]; }catch(e){ return []; } }
function termMakeTab(sid,name,persist){ return {sid,name:name||('Terminal '+(termTabs.length+1)),persist:!!persist,term:null,fit:null,ws:null,els:null,built:false}; }
async function initTerminal(){
  if(termViewReady){ termFitActive(); return; }
  try{ await ensureTermLib(); }catch(e){ appToast('Terminal library failed to load','err'); return; }
  let live=[]; try{ const r=await api('/api/system/terminals'); if(r&&r.ok) live=(await r.json()).sessions||[]; }catch(e){}
  const liveById={}; live.forEach(s=>liveById[s.id]=s);
  const seen={};
  termStoreLoad().forEach(s=>{ if(seen[s.sid]) return; if(s.persist||liveById[s.sid]){ seen[s.sid]=true; termTabs.push(termMakeTab(s.sid,s.name,s.persist||(liveById[s.sid]&&liveById[s.sid].persist))); } });
  live.forEach(s=>{ if(seen[s.id]) return; seen[s.id]=true; termTabs.push(termMakeTab(s.id,null,s.persist)); });
  if(!termTabs.length) termTabs.push(termMakeTab(genSid(),null,false));
  termViewReady=true; termRenderTabs(); termStoreSave(); termActivate(termTabs[0].sid);
}
function termRenderTabs(){
  const bar=$('term-tabs'); if(!bar) return; const addBtn=$('term-add');
  bar.querySelectorAll('.term-tab').forEach(el=>el.remove());
  termTabs.forEach(tab=>{
    const chip=document.createElement('div'); chip.className='term-tab'+(tab.sid===activeSid?' active':''); chip.dataset.sid=tab.sid;
    const dot=document.createElement('span'); dot.className='tt-dot'+(tab.persist?' on':''); dot.title=tab.persist?'Stay on':'Stay off';
    const nm=document.createElement('span'); nm.className='tt-name'; nm.textContent=tab.name;
    const x=document.createElement('button'); x.className='tt-x'; x.textContent='×'; x.onclick=(e)=>{ e.stopPropagation(); termCloseTab(tab.sid); };
    chip.appendChild(dot); chip.appendChild(nm); chip.appendChild(x); chip.onclick=()=>termActivate(tab.sid); bar.insertBefore(chip,addBtn);
  });
}
function termAddTab(){ const tab=termMakeTab(genSid(),null,false); termTabs.push(tab); termRenderTabs(); termStoreSave(); termActivate(tab.sid); }
function termCloseTab(sid){
  const idx=termTabs.findIndex(t=>t.sid===sid); if(idx<0) return; const tab=termTabs[idx];
  try{ if(tab.ws&&tab.ws.readyState===WebSocket.OPEN) tab.ws.send(JSON.stringify({kill:true})); }catch(e){}
  if(tab.ws){ try{ tab.ws.onclose=null; tab.ws.close(); }catch(e){} }
  if(tab._ro){ try{ tab._ro.disconnect(); }catch(e){} tab._ro=null; }
  if(tab.term){ try{ tab.term.dispose(); }catch(e){} }
  if(tab.els&&tab.els.wrap) tab.els.wrap.remove();
  termTabs.splice(idx,1);
  if(!termTabs.length){ const t=termMakeTab(genSid(),null,false); termTabs.push(t); termRenderTabs(); termStoreSave(); termActivate(t.sid); return; }
  termRenderTabs(); termStoreSave(); if(activeSid===sid) termActivate(termTabs[Math.max(0,idx-1)].sid);
}
function termActivate(sid){
  activeSid=sid; const tab=termGetTab(sid); if(!tab) return;
  if(!tab.built) termBuildPanel(tab);
  termTabs.forEach(t=>{ if(t.els) t.els.wrap.style.display=(t.sid===sid)?'flex':'none'; });
  if(!tab.ws) termTabConnect(tab); termRenderTabs(); termFitWhenReady(tab);
}
function termFit(tab){ if(!tab||!tab.term||!tab.fit||!tab.els) return false; const host=tab.els.host;
  if(!host||host.clientWidth<2||host.clientHeight<2) return false; try{ tab.fit.fit(); }catch(e){} return true; }
function termFitWhenReady(tab,tries){ tries=(tries==null)?40:tries; if(termFit(tab)){ try{ tab.term.focus(); }catch(e){} return; } if(tries<=0) return; requestAnimationFrame(()=>termFitWhenReady(tab,tries-1)); }
function termFitActive(){ termFitWhenReady(termGetTab(activeSid)); }
function termSetStatus(tab,text,cls){ if(tab&&tab.els){ tab.els.status.textContent=text; tab.els.status.className='term-status'+(cls?' '+cls:''); } }
function termBuildPanel(tab){
  const stack=$('term-stack'); const wrap=document.createElement('div'); wrap.className='term-wrap'; wrap.dataset.sid=tab.sid; wrap.style.display='none';
  wrap.innerHTML='<div class="term-bar"><span class="term-title">Root terminal — live interactive shell (server process privileges)</span><span class="term-status">connecting…</span>'+
    '<label class="term-stay" title="Keep this session running even after you close the site"><input type="checkbox"'+(tab.persist?' checked':'')+'><span>Stay on</span></label>'+
    '<button class="term-clear t-clear">Clear</button><button class="term-clear t-recon">Reconnect</button><button class="term-clear term-close t-close">Close</button></div>'+
    '<div class="term-host"></div><div class="term-hint">A real PTY: run <code>top</code>, <code>vim</code>, anything interactive. <strong>Stay on</strong> keeps it alive after you close the site.</div>';
  stack.appendChild(wrap);
  const host=wrap.querySelector('.term-host'), status=wrap.querySelector('.term-status'), stay=wrap.querySelector('.term-stay input');
  tab.els={wrap,host,status,stay};
  stay.addEventListener('change',()=>{ tab.persist=stay.checked; try{ if(tab.ws&&tab.ws.readyState===WebSocket.OPEN) tab.ws.send(JSON.stringify({persist:tab.persist})); }catch(e){} termStoreSave(); termRenderTabs(); });
  wrap.querySelector('.t-clear').onclick=()=>{ if(tab.term){ tab.term.clear(); tab.term.focus(); } };
  wrap.querySelector('.t-recon').onclick=()=>termTabReconnect(tab);
  wrap.querySelector('.t-close').onclick=()=>termCloseTab(tab.sid);
  const isDark=document.documentElement.getAttribute('data-theme')==='dark';
  const term=new window.Terminal({cursorBlink:true,fontFamily:'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',fontSize:13,scrollback:5000,
    theme:isDark?{background:'#000000',foreground:'#e0e0e0',cursor:'#7ee787'}:{background:'#0c0c0c',foreground:'#e0e0e0',cursor:'#7ee787'}});
  const fit=new window.FitAddon.FitAddon(); term.loadAddon(fit); term.open(host);
  term.onData(d=>{ if(tab.ws&&tab.ws.readyState===WebSocket.OPEN) tab.ws.send(new TextEncoder().encode(d)); });
  term.onResize(({rows,cols})=>{ if(tab.ws&&tab.ws.readyState===WebSocket.OPEN) tab.ws.send(JSON.stringify({resize:[rows,cols]})); });
  tab.term=term; tab.fit=fit; tab.built=true;
  if(window.ResizeObserver){ tab._ro=new ResizeObserver(()=>termFit(tab)); tab._ro.observe(host); }
}
function termTabConnect(tab){
  if(tab.ws&&(tab.ws.readyState===WebSocket.OPEN||tab.ws.readyState===WebSocket.CONNECTING)) return;
  termSetStatus(tab,'connecting…');
  const proto=location.protocol==='https:'?'wss':'ws'; const rows=tab.term?tab.term.rows:24, cols=tab.term?tab.term.cols:80;
  const qs='?sid='+encodeURIComponent(tab.sid)+'&persist='+(tab.persist?'1':'0')+'&rows='+rows+'&cols='+cols;
  const ws=new WebSocket(proto+'://'+location.host+BASE+'/ws/terminal'+qs); ws.binaryType='arraybuffer'; tab.ws=ws;
  ws.onopen=()=>{ termSetStatus(tab,'connected','ok'); termFit(tab); };
  ws.onmessage=ev=>{ if(typeof ev.data==='string'){ try{ JSON.parse(ev.data); }catch(e){ tab.term.write(ev.data); } return; } tab.term.write(new Uint8Array(ev.data)); };
  ws.onclose=()=>{ termSetStatus(tab,'disconnected','dead'); if(tab.term) tab.term.write('\r\n\x1b[90m[disconnected — press Reconnect]\x1b[0m\r\n'); if(tab.ws===ws) tab.ws=null; };
  ws.onerror=()=>termSetStatus(tab,'error','dead');
}
function termTabReconnect(tab){ if(tab.ws){ try{ tab.ws.onclose=null; tab.ws.close(); }catch(e){} tab.ws=null; } if(tab.term) tab.term.reset(); termTabConnect(tab); }
window.addEventListener('resize',()=>{ if(CURRENT==='terminal') termFitActive(); });
window.addEventListener('orientationchange',()=>{ if(CURRENT==='terminal') setTimeout(termFitActive,60); });

/* ================= boot ================= */
(function init(){
  applyTheme(localStorage.getItem('theme')==='dark');
  document.querySelectorAll('[data-nav]').forEach(b=>b.addEventListener('click',()=>switchSection(b.dataset.nav)));
  const ss=$('svc-search'); if(ss) ss.addEventListener('input',renderServices);
  switchSection('server');
})();
