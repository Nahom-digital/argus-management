/* Management panel front-end, Server / Services / Terminal / Logs.
 * Ported from Main.py's dashboard so the look & behaviour match exactly, then
 * trimmed to this panel's four sections and wired to Management's endpoints. */

/* ---------------- helpers ---------------- */
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function escAttr(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function $(id){return document.getElementById(id);}
/* CSS honours prefers-reduced-motion on its own; a scroll asked for in script
 * does not, so anything that scrolls has to ask. */
function reduceMotion(){
  return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

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
  if(name==='server'){ startServerPolling(); } else stopServerPolling();
  // fromHistory=true: arriving at the tab resets to the card grid without
  // spending a history entry, which is not the same as pressing Back.
  if(name==='config') configBack(true);
  if(name==='terminal') setTimeout(initTerminal,30);
  if(name==='logs') loadSecurityLogs();
  if(name==='mail') loadMail();
  if(name==='account') loadAccount();
}

/* ================= CONFIG ================= */
const CONFIG_LOADERS={
  account: loadMyAccount,
  users: loadUserManagement,
  server: loadServerConfig,
  service: loadServices,
  database: loadDbTables,
  proxy: loadProxyHosts,
  tunnel: loadTunnel,
  firewall: loadFirewall,
  telegram: loadTelegram,
};
/* The drill-down already replaced the card grid rather than sitting under it.
   What made it look like it opened "at the bottom" was the scroll position:
   the pane stayed where it was, so a card near the bottom of a scrolled list
   swapped in a page you were already scrolled past. Both directions now start
   at the top, and the browser's own Back button works too. */
let _configOpenKey=null;

function _configScrollTop(){
  const pane=document.querySelector('[data-pane="config"] .pane-scroll');
  if(pane) pane.scrollTop=0;
}

function configOpen(key, fromHistory){
  const menu=$('config-menu'); if(menu) menu.hidden=true;
  document.querySelectorAll('.config-sub').forEach(el=>{ el.hidden=(el.dataset.cfgsub!==key); });
  _configOpenKey=key;
  _configScrollTop();
  if(!fromHistory){
    try{ history.pushState({config:key},'',location.href); }catch(e){}
  }
  const fn=CONFIG_LOADERS[key]; if(fn) fn();
}

function configBack(fromHistory){
  const menu=$('config-menu'); if(menu) menu.hidden=false;
  document.querySelectorAll('.config-sub').forEach(el=>{ el.hidden=true; });
  const wasOpen=_configOpenKey;
  _configOpenKey=null;
  _configScrollTop();
  // Keep the history stack honest: pressing the in-page Back button should
  // consume the entry it pushed, not leave it for the browser button later.
  if(!fromHistory && wasOpen){
    try{ history.back(); }catch(e){}
  }
}

window.addEventListener('popstate', e=>{
  if(CURRENT!=='config') return;
  const key=(e.state||{}).config;
  if(key) configOpen(key,true); else configBack(true);
});

/* ================= ACCOUNT =================
   Three things live here: who you are, your password, and, for the admin only,
   the recovery codes. A staff member has no recovery codes at all, so the card
   is not on their page to begin with and this code never assumes it is. */
let ME={};

async function loadAccount(){
  loadIdentity();
  ['acct-cur','acct-new','acct-new2','acct-regen-pw'].forEach(function(id){ const i=$(id); if(i) i.value=''; });
  const out=$('acct-codes-out'); if(out){ out.hidden=true; out.innerHTML=''; }
  const el=$('acct-codes-state'); if(!el) return;
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
      el.innerHTML='<b style="color:'+(low?'var(--danger)':'var(--success)')+'">'+d.unused+' of '+d.total+
        '</b> code'+(d.unused===1?'':'s')+' unused'+
        (d.generated_at?' <span style="color:var(--gray-500);">(issued '+esc(d.generated_at.slice(0,10))+')</span>':'');
    }
  }catch(e){ el.textContent='Could not reach the server.'; }
}

function avatarUrl(who){
  return BASE+'/api/account/avatar/'+encodeURIComponent(who.username||'')
         +'?v='+encodeURIComponent((who.avatar_hash||'').slice(0,16));
}

/* A picture always goes in an <img>, never inlined into the page. An SVG in an
   <img> cannot run script or reach the network; the same file written into the
   document could do both. */
function paintFace(img, txt, who){
  if(!img||!txt) return;
  if(who.has_avatar){ img.src=avatarUrl(who); img.hidden=false; txt.hidden=true; }
  else { img.hidden=true; img.removeAttribute('src'); txt.hidden=false;
         txt.textContent=who.initials||'?'; }
}

async function loadIdentity(){
  if(!$('acct-id-name')) return;
  try{
    const r=await api('/api/account/identity'); if(!r) return;
    const d=await r.json(); if(!r.ok) return;
    ME=d; renderIdentity();
  }catch(e){ /* the rest of the page still works without it */ }
}

function renderIdentity(){
  $('acct-id-name').textContent=ME.full_name||ME.username||'';
  $('acct-id-user').textContent='@'+(ME.username||'');
  $('acct-id-role').textContent=ME.role_label||'';
  const input=$('acct-fullname');
  if(input&&document.activeElement!==input) input.value=ME.full_name||'';
  paintFace($('acct-face-img'), $('acct-face-txt'), ME);
  cfShow('acct-pic-clear', !!ME.has_avatar);
  const hint=$('acct-name-hint');
  if(hint) hint.textContent=ME.mail_domain
    ? 'Shown in the top bar, and on every message you send from '+ME.mail_domain+'.'
    : 'Shown in the top bar, and on every message you send.';
  const bimi=$('acct-bimi');
  if(bimi){
    bimi.hidden=!ME.has_avatar;
    bimi.textContent=ME.bimi
      ? 'As a mail logo: '+ME.bimi
      : 'This picture can also be published as your mail logo. The record to add is under Mail settings.';
  }
  syncTopbar();
}

/* The top bar is rendered by the server, so after a change it is updated in
   place rather than left showing the name you just replaced. */
function syncTopbar(){
  const name=$('topbar-name'); if(name) name.textContent=ME.full_name||ME.username||'';
  const face=$('topbar-face'); if(!face) return;
  let img=face.querySelector('img'), txt=face.querySelector('span');
  if(!img){ img=document.createElement('img'); img.width=30; img.height=30; img.alt=''; face.appendChild(img); }
  if(!txt){ txt=document.createElement('span'); face.appendChild(txt); }
  paintFace(img, txt, ME);
}

async function saveFullName(){
  const fb=$('acct-name-feedback'), input=$('acct-fullname');
  fb.className='save-feedback info'; fb.textContent='Saving…';
  try{
    const r=await api('/api/account/name',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({full_name:input.value})});
    if(!r) return;
    const d=await r.json();
    if(!r.ok){ fb.className='save-feedback err'; fb.textContent=d.error||'Could not save that name.'; return; }
    fb.className='save-feedback ok'; fb.textContent='Saved.';
    ME.full_name=d.full_name; ME.initials=(d.full_name||'').trim().split(/\s+/)
      .map(function(p){return p[0]||'';}).join('').slice(0,2).toUpperCase()||ME.initials;
    renderIdentity(); appToast('Name updated','ok');
  }catch(e){ fb.className='save-feedback err'; fb.textContent='Request failed.'; }
}

async function uploadAvatar(input){
  const file=input.files&&input.files[0]; if(!file) return;
  const fb=$('acct-pic-feedback'), maxKb=ME.max_upload_kb||512;
  input.value='';
  if(file.size>maxKb*1024){
    fb.className='save-feedback err';
    fb.textContent='That file is '+Math.round(file.size/1024)+' KB. Use one under '+maxKb+' KB.';
    return;
  }
  fb.className='save-feedback info'; fb.textContent='Checking and storing…';
  try{
    const r=await api('/api/account/avatar',{method:'POST',
      headers:{'Content-Type':file.type||'application/octet-stream'}, body:file});
    if(!r) return;
    const d=await r.json();
    if(!r.ok){ fb.className='save-feedback err'; fb.textContent=d.error||'Could not store that picture.'; return; }
    fb.className='save-feedback ok'; fb.textContent='Picture updated.';
    await loadIdentity(); appToast('Picture updated','ok');
  }catch(e){ fb.className='save-feedback err'; fb.textContent='Upload failed.'; }
}

async function removeAvatar(){
  if(!(await uiConfirm('Remove your picture?','Your initials are shown instead.'))) return;
  const fb=$('acct-pic-feedback');
  try{
    const r=await api('/api/account/avatar',{method:'DELETE'}); if(!r) return;
    if(!r.ok){ fb.className='save-feedback err'; fb.textContent='Could not remove it.'; return; }
    fb.className='save-feedback ok'; fb.textContent='Removed.';
    await loadIdentity();
  }catch(e){ fb.className='save-feedback err'; fb.textContent='Request failed.'; }
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

/* Shown exactly once, the server keeps only hashes, so this is the last
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
let serverPollTimer=null, serverStaticTimer=null, serverStaticLoaded=false;

function startServerPolling(){
  if(!serverStaticLoaded) loadServerStatic();
  pollServerStats();
  if(serverPollTimer) clearInterval(serverPollTimer);
  serverPollTimer=setInterval(pollServerStats,1500);
  // Temperature, fan, battery and the IPs move, so the grid is re-read on a
  // slow clock. One request feeds both the static rows and the moving ones.
  if(serverStaticTimer) clearInterval(serverStaticTimer);
  serverStaticTimer=setInterval(loadServerStatic,15000);
}
function stopServerPolling(){
  if(serverPollTimer){ clearInterval(serverPollTimer); serverPollTimer=null; }
  if(serverStaticTimer){ clearInterval(serverStaticTimer); serverStaticTimer=null; }
}

function fanText(d){
  if(d.fans&&d.fans.length){
    return d.fans.map(function(f){
      return f.percent!=null?f.rpm+' RPM ('+f.percent+'% of max, '+f.label+')':f.rpm+' RPM ('+f.label+')';
    }).join(' · ');
  }
  if(d.fan_not_reported) return 'n/a (sensor hardware fault)';
  return 'no sensor';
}
async function loadServerStatic(){
  try{
    const r=await api('/api/system/static'); if(!r||!r.ok) return; const d=await r.json();
    const rows=[
      ['Hostname',d.hostname],['Operating System',d.distro],['OS Detail',d.os_full],
      ['Kernel',d.kernel],['Architecture',d.arch],['CPU',d.cpu_model],
      ['CPU Cores',`${d.cpu_cores_physical} physical / ${d.cpu_cores_logical} logical`+(d.cpu_max_mhz?` @ ${(d.cpu_max_mhz/1000).toFixed(2)} GHz`:'')],
      ['CPU Temp',d.cpu_temp_c!=null?`${d.cpu_temp_c.toFixed(0)}°C (${d.cpu_temp_label||'sensor'})`:'no sensor'],
      ['Fan',fanText(d)],
      ['Total RAM',d.ram_total_h],['Total Disk',d.disk_total_h],
      ['Battery',d.battery?`${d.battery.percent}% (${d.battery.state||'unknown'})`:'none present'],
      ['IP Private',d.private_ip?d.private_ip+(d.private_ip_iface?` (${d.private_ip_iface})`:''):'none'],
      ['IP Public',d.public_ip||'checking'],
      ['Python',d.python],
      ['Booted',d.boot_time],['Uptime',fmtUptime(d.uptime_seconds)],
      ['Process',`pid ${d.process_pid} as ${d.process_user}`+(d.is_root?' (root)':'')],
    ];
    $('device-grid').innerHTML=rows.map(([k,v])=>`<div class="dev-item"><span class="dev-key">${esc(k)}</span><span class="dev-val">${esc(v||'n/a')}</span></div>`).join('');
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
    // scaleX rather than width: same picture, no layout pass on every sample.
    $('disk-fill').style.transform='scaleX('+Math.max(0,Math.min(1,d.disk.percent/100)).toFixed(4)+')';
    $('disk-fill').style.background=barColor(d.disk.percent);
    $('m-load-now').textContent=d.load['1'].toFixed(2);
    $('m-load-foot').textContent=`${d.load['1']} / ${d.load['5']} / ${d.load['15']}`;
    renderCoreBars(d.cpu_per_core);
    drawLineChart('chart-cpu',[cpuHist],100,['--black']);
    drawLineChart('chart-ram',[ramHist],100,['--black']);
    const netMax=Math.max(1,...netInHist,...netOutHist);
    // drawLineChart resolves a leading "--" through getComputedStyle, so these
    // follow the theme instead of staying light-mode green and orange.
    drawLineChart('chart-net',[netInHist,netOutHist],netMax,['--success','--warn']);
  }catch(e){}
}
function pushHist(a,v){
  if(a.length===0){ for(let i=0;i<HIST_LEN;i++) a.push(v); return; } // full-width from the first sample, not one dot at the right
  a.push(v); if(a.length>HIST_LEN) a.shift();
}
/* Built once, then only the fill is touched. Rebuilding innerHTML every second
   threw the transition away (fresh nodes never transition) and re-laid out the
   row on every tick. scaleY on a bottom-anchored fill stays on the compositor,
   so a 16-core box animates without a single reflow. */
function renderCoreBars(cores){
  if(!cores) return; const el=$('core-bars'); if(!el) return;
  if(el.childElementCount!==cores.length){
    el.innerHTML=cores.map(()=>'<div class="core-bar"><span></span></div>').join('');
  }
  for(let i=0;i<cores.length;i++){
    const cell=el.children[i], fill=cell.firstElementChild, p=cores[i];
    cell.title=p.toFixed(0)+'%';
    fill.style.transform='scaleY('+Math.max(0.03,p/100).toFixed(3)+')';
    fill.style.background=barColor(p);
  }
}

/* These are CSS backgrounds, never canvas fills, so they can stay as var()
   references. That means no getComputedStyle at all and the bars re-theme
   themselves the instant the theme attribute changes. */
function barColor(p){
  if(p>=90) return 'var(--danger)';
  if(p>=70) return 'var(--warn)';
  return 'var(--black)';
}
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
/* The file browser starts with no path at all rather than at "/": the server
   knows which directory this account is allowed to see, and a staff member
   scoped to their own home was being shown "outside your permitted area"
   because the browser asked for the root of the filesystem first. */
let _srvDetailKind=null, _fbPath='', _accessDetailId=null;
let _ipDetailTarget=null, _ipProfileData=null, _lineDetailObj=null, _lineDetailTitle='';
const _SRV_TITLES={cpu:'CPU: Top Processes',mem:'Memory: Top Processes',net:'Network: Active Connections',disk:'Disk: File Browser'};
/* Which grant each drill-down needs. The server refuses without it either way;
   this is so the person sees a sentence instead of a failed request. */
const _SRV_DETAIL_GRANT={cpu:'cpumem_detail',mem:'cpumem_detail',net:'net_detail'};

function _mayOpenDetail(kind){
  const needed=_SRV_DETAIL_GRANT[kind];
  if(kind==='disk') return (window.MGMT_PERMS||{}).disk_scope!=='none';
  if(!needed) return true;
  return !!(window.MGMT_PERMS||{})[needed];
}

const _SRV_DENIED={
  cpu:'Seeing which processes are using the CPU needs the "CPU and memory detail" permission.',
  mem:'Seeing which processes are using memory needs the "CPU and memory detail" permission.',
  net:'Seeing active connections needs the "Network detail" permission.',
  disk:'Browsing files needs disk access.',
};

function openServerDetail(kind){
  _srvDetailKind=kind;
  $('srv-detail-title').textContent=_SRV_TITLES[kind]||'Detail';
  $('srv-detail-overlay').classList.add('open');
  if(!_mayOpenDetail(kind)){
    $('srv-detail-body').innerHTML=`<div class="detail-denied">
      <svg class="ic ic-lg"><use href="#ic-shield-alert"/></svg>
      <p>${esc(_SRV_DENIED[kind]||'You do not have permission to open this.')}</p>
      <p class="detail-denied-sub">An admin can grant it from Config, User Management.</p>
    </div>`;
    return;
  }
  loadServerDetail();
}

/* Marks the meters that cannot be opened, so the pointer and hover state stop
   promising something that will be refused. */
function applyMetricPermissions(){
  document.querySelectorAll('.metric-card[onclick]').forEach(card=>{
    const m=/openServerDetail\('([a-z]+)'\)/.exec(card.getAttribute('onclick')||'');
    if(!m) return;
    const allowed=_mayOpenDetail(m[1]);
    card.classList.toggle('metric-clickable',allowed);
    card.classList.toggle('metric-locked',!allowed);
    if(!allowed) card.title=_SRV_DENIED[m[1]]||'Not permitted';
  });
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
      if(isAuth){ rowStyle='background:color-mix(in srgb, var(--danger) 8%, transparent);'; stateCell='<span style="color:var(--danger);font-weight:700;">ESTAB</span>';
        processCell='<span style="color:var(--danger);font-weight:600;">sshd-auth</span> <span style="font-size:10px;color:var(--danger);background:color-mix(in srgb, var(--danger) 12%, transparent);border-radius:3px;padding:1px 5px;">TCP only, NOT authenticated</span>'; }
      else if(isSess){ rowStyle='background:color-mix(in srgb, var(--success) 8%, transparent);'; stateCell='<span style="color:var(--success);font-weight:700;">ESTAB</span>';
        processCell=`<span style="color:var(--success);font-weight:600;">${esc(c.process)}</span> <span style="font-size:10px;color:var(--success);background:color-mix(in srgb, var(--success) 12%, transparent);border-radius:3px;padding:1px 5px;">SSH authenticated session</span>`; }
      return `<tr style="${rowStyle}"><td>${esc(c.proto)}</td><td>${esc(c.laddr)}</td><td><b>${esc(c.raddr)}</b></td><td>${stateCell}</td><td>${esc(c.pid)}</td><td>${processCell}</td></tr>`;
    }).join('');
    b.innerHTML=`<div style="font-size:12px;color:var(--gray-600);margin-bottom:10px;line-height:1.6;">Listening sockets first. On port 22:
      <span style="color:var(--danger);font-weight:600;">sshd-auth</span> = connected but not authenticated · <span style="color:var(--success);font-weight:600;">sshd-session</span> = authenticated shell.</div>
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
      const dl=e.is_dir?'':(e.downloadable?`<a class="fb-dl" href="${BASE}/api/system/download?path=${encodeURIComponent(e.path)}" style="display:inline-flex;align-items:center;gap:4px;"><svg class="ic"><use href="#ic-download"/></svg> Download</a>`:`<span class="fb-locked">protected</span>`);
      const canDelete=!!(window.MGMT_PERMS&&MGMT_PERMS.disk_delete)&&!e.is_dir&&e.deletable;
      const del=canDelete?`<button class="db-action-btn" style="color:var(--danger);" onclick="deleteFile('${escAttr(e.path)}')"><svg class="ic"><use href="#ic-trash-2"/></svg></button>`:'';
      return `<div class="fb-row">${name}<span class="fb-size">${esc(e.size_h)}</span><span class="fb-dl" style="display:inline-flex;gap:8px;align-items:center;">${dl}${del}</span></div>`;
    }).join('');
    b.innerHTML=`<div class="fb-crumbs">${esc(d.path)}</div>${up}${rows||'<div class="empty-state">Empty folder.</div>'}`;
  }catch(e){ b.innerHTML=`<div class="empty-state">Failed: ${esc(String(e))}</div>`; }
}
async function deleteFile(path){
  if(!(await uiConfirm('Delete this file?', path+'\n\nThis cannot be undone.'))) return;
  try{
    const r=await api('/api/system/delete',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({path})});
    const d=await r.json();
    if(!r.ok){ appToast(d.error||'Delete failed','err'); return; }
    appToast('Deleted','ok'); browseDir(_fbPath);
  }catch(e){ appToast('Network error','err'); }
}
function openAccessDetail(id){ _srvDetailKind='access'; _accessDetailId=id;
  $('srv-detail-title').textContent='Request / Response'; $('srv-detail-overlay').classList.add('open'); renderAccessDetail(); }
async function renderAccessDetail(){
  const b=$('srv-detail-body'); b.innerHTML='<div class="empty-state">Loading response…</div>';
  let d; try{ d=await (await api('/api/system/access-log-entry?id='+_accessDetailId)).json(); }
  catch(e){ b.innerHTML=`<div class="empty-state">Error: ${esc(String(e))}</div>`; return; }
  if(d.error){ b.innerHTML=`<div class="empty-state">${esc(d.error)}</div>`; return; }
  const meta=[['Time',String(d.ts).slice(0,19)],['Method',d.method],['Path',d.path],['Query',d.query||'n/a'],
    ['Status',d.status_code],['Duration',(d.duration_ms??'n/a')+' ms'],['IP',d.ip],['User',d.authed_user||'n/a'],
    ['Content-Type',d.content_type||'n/a'],['Response size',d.response_size!=null?d.response_size.toLocaleString()+' bytes':'n/a']]
    .map(([k,v])=>`<tr><td style="font-weight:700;white-space:nowrap;vertical-align:top;color:var(--gray-600);padding-right:14px;">${esc(k)}</td><td style="font-family:monospace;font-size:12px;word-break:break-all;">${esc(String(v))}</td></tr>`).join('');
  let bodyText=d.response_body;
  if(bodyText==null) bodyText='(no response body captured)';
  else if((d.content_type||'').includes('json')){ try{ bodyText=JSON.stringify(JSON.parse(d.response_body),null,2); }catch(_){} }
  const sc=d.status_code<300?'var(--success)':d.status_code<400?'var(--info)':d.status_code<500?'var(--warn)':'var(--danger)';
  b.innerHTML=`<div style="margin-bottom:6px;"><span style="font-weight:700;color:${sc};font-size:14px;">${d.method} ${esc(d.path)} → ${d.status_code}</span></div>
    <table style="margin-bottom:16px;">${meta}</table>
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px;"><div style="font-weight:700;font-size:13px;">Response body</div>
      <span style="font-size:11px;color:var(--gray-600);">${esc(d.content_type||'')}</span>
      <button class="db-action-btn" style="margin-left:auto;font-size:11px;" onclick="copyVal(document.getElementById('access-body-pre').textContent,'Body')">Copy</button></div>
    <pre id="access-body-pre" style="background:var(--gray-50);border:1px solid var(--gray-200);border-radius:6px;padding:12px;max-height:48vh;overflow:auto;font-size:12px;line-height:1.45;white-space:pre-wrap;word-break:break-word;font-family:var(--mono);color:var(--black);">${esc(bodyText)}</pre>`;
}
function openIpDetail(ip){ if(!ip) return; _srvDetailKind='ip'; _ipDetailTarget=ip;
  $('srv-detail-title').textContent='IP '+ip+', full activity'; $('srv-detail-overlay').classList.add('open'); renderIpProfile(); }
function openLineDetail(title,obj){ _srvDetailKind='line'; _lineDetailObj=obj||{}; _lineDetailTitle=title||'Log entry';
  $('srv-detail-title').textContent=_lineDetailTitle; $('srv-detail-overlay').classList.add('open'); renderLineDetail(); }
function renderLineDetail(){
  const b=$('srv-detail-body'); const o=_lineDetailObj||{}; const ip=o.ip||_ipDetailTarget||'';
  const rows=Object.keys(o).map(k=>{ let v=o[k];
    if(v===null||v===undefined||v==='') v='<span style="color:var(--gray-400)">n/a</span>'; else v=esc(String(v));
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
  const blocked=s.blocked?`<span style="background:color-mix(in srgb, var(--danger) 12%, transparent);color:var(--danger);padding:2px 9px;border-radius:4px;font-weight:700;">BLOCKED</span>`:`<button class="db-action-btn" onclick="blockIpFromProfile('${escAttr(ip)}')">Block this IP</button>`;
  const users=(s.usernames||[]).filter(Boolean);
  const section=(title,inner)=>`<div style="margin-top:18px;"><div style="font-weight:700;font-size:13px;margin-bottom:6px;">${title}</div>${inner}</div>`;
  const none='<div style="color:var(--gray-400);font-size:12px;">None.</div>';
  const http=d.http||{};
  const httpRows=(http.recent||[]).slice(0,60).map((r,i)=>`<tr style="cursor:pointer;" onclick="openLineDetail('HTTP request',_ipProfileData.http.recent[${i}])"><td style="font-size:11px;white-space:nowrap;">${esc(String(r.ts).slice(0,19))}</td><td style="font-weight:700;">${esc(r.method)}</td><td style="font-family:monospace;font-size:11px;">${esc(r.path)}</td><td>${esc(r.status_code)}</td><td style="font-size:11px;color:var(--gray-600);">${esc(r.authed_user||'n/a')}</td></tr>`).join('');
  const topPaths=(http.top_paths||[]).map(p=>`<span style="display:inline-block;background:var(--gray-100);border-radius:3px;padding:1px 7px;margin:2px;font-size:11px;font-family:monospace;">${esc(p.path)} <b>×${p.count}</b></span>`).join('');
  const wl=d.web_logins||{};
  const wlRows=(wl.recent||[]).slice(0,40).map((r,i)=>`<tr style="cursor:pointer;${r.success?'':'background:color-mix(in srgb, var(--danger) 5%, transparent)'}" onclick="openLineDetail('Web login',_ipProfileData.web_logins.recent[${i}])"><td style="font-size:11px;white-space:nowrap;">${esc(String(r.ts).slice(0,19))}</td><td style="font-family:monospace;">${esc(r.username||'n/a')}</td><td style="color:${r.success?'var(--success)':'var(--danger)'};font-weight:700;">${r.success?'OK':'FAIL'}</td><td>${(!r.success&&r.tried_password)?`<code style="font-size:11px;color:var(--danger);">${esc(r.tried_password)}</code>`:'<span style="color:var(--gray-400)">n/a</span>'}</td></tr>`).join('');
  const sess=(d.sessions||[]).map((r,i)=>`<tr style="cursor:pointer;" onclick="openLineDetail('Web session',_ipProfileData.sessions[${i}])"><td style="font-size:11px;white-space:nowrap;">${esc(String(r.login_at).slice(0,19))}</td><td style="font-family:monospace;">${esc(r.username)}</td><td>${esc(r.status)}</td><td style="font-size:11px;color:var(--gray-600);">${esc(String(r.logout_at||'').slice(0,19)||'n/a')}</td></tr>`).join('');
  const ssh=d.ssh||{};
  const sshRows=(ssh.recent||[]).slice(0,40).map((r,i)=>`<tr style="cursor:pointer;" onclick="openLineDetail('SSH event',_ipProfileData.ssh.recent[${i}])"><td style="font-size:11px;white-space:nowrap;">${esc(String(r.ts).slice(0,19))}</td><td>${esc(r.event_type)}</td><td>${esc(r.username||'n/a')}</td><td style="font-family:monospace;font-size:10px;">${esc(r.fingerprint||'')}</td></tr>`).join('');
  b.innerHTML=`<div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:6px;">
      ${card('HTTP requests',s.http_requests??0)}${card('Login attempts',s.web_login_attempts??0)}${card('Failed logins',s.web_login_failed??0,(s.web_login_failed?'var(--danger)':''))}${card('Sessions',s.sessions??0)}${card('SSH events',s.ssh_events??0)}</div>
    <div style="margin:6px 0 2px;">${blocked}${users.length?`<span style="margin-left:10px;font-size:12px;color:var(--gray-600);">Accounts seen: ${users.map(u=>`<b>${esc(u)}</b>`).join(', ')}</span>`:''}</div>
    <div style="font-size:11px;color:var(--gray-500);">First seen ${esc(http.first||'n/a')} • last ${esc(http.last||'n/a')} • ${http.distinct_paths??0} distinct paths</div>
    ${section(`HTTP access (${http.total??0}), most-hit paths`,topPaths||none)}
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
  loadSshKeyStatus();
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
    stateEl.innerHTML=`SSH is <b style="color:${on?'var(--success)':'var(--danger)'}">${on?'ON':'OFF'}</b> <span style="color:var(--gray-500);">(${esc(d.state)}, on boot: ${esc(d.enabled)})</span>`;
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

async function loadSshKeyStatus(){
  const stateEl=$('ssh-key-state'); if(!stateEl) return;
  try{
    const r=await api('/api/config/ssh/status'); const d=await r.json();
    if(!r.ok){ stateEl.textContent='Status error: '+esc(d.error||'unknown'); return; }
    $('ssh-genkey-btn').hidden=!!d.key_exists;
    $('ssh-key-details').hidden=!d.key_exists;
    if(d.key_exists){
      stateEl.textContent='Key generated '+(d.generated_at?String(d.generated_at).slice(0,19):'');
      $('ssh-pubkey').value=d.public_key||'';
      $('ssh-fingerprint').textContent=d.fingerprint||'';
    } else {
      stateEl.textContent='No key generated yet for this box.';
    }
    $('ssh-password').placeholder=d.password_saved?'(saved, leave blank to keep)':'not set';
    $('ssh-allow-password').checked=!!d.allow_password_login;
  }catch(e){ stateEl.textContent='Could not reach server.'; }
}
async function generateSshKey(){
  if(!(await uiConfirm('Generate a new SSH key?','This creates a new keypair on the server and replaces any existing one generated here. The public key is added to root’s authorized_keys.'))) return;
  const fb=$('ssh-key-feedback'), btn=$('ssh-genkey-btn'); btn.disabled=true; fb.textContent=''; fb.className='save-feedback';
  try{
    const r=await api('/api/config/ssh/generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:$('ssh-password').value||''})});
    const d=await r.json();
    if(!r.ok){ fb.textContent=d.error||'Generation failed'; fb.classList.add('err'); }
    else{
      // "Key generated" used to be printed whether or not the key had been
      // installed or would authenticate. Report what actually happened.
      const lines=[];
      if(d.verified){
        lines.push('Key generated and confirmed working: '+(d.verify_detail||''));
        fb.classList.add('ok');
        appToast('SSH key generated and verified','ok');
      }else{
        lines.push('Key generated, but signing in with it did not succeed.');
        if(d.verify_detail) lines.push('SSH said: '+d.verify_detail);
        fb.classList.add('err');
        appToast('SSH key generated but not verified','err');
      }
      (d.problems||[]).forEach(p=>lines.push(p));
      if((d.steps||[]).length) lines.push('Done: '+d.steps.join('; ')+'.');
      fb.innerHTML=lines.map(l=>esc(l)).join('<br>');
    }
  }catch(e){ fb.textContent='Network error'; fb.classList.add('err'); }
  btn.disabled=false; loadSshKeyStatus();
}
function downloadSshPrivateKey(){ window.location.href=BASE+'/api/config/ssh/private-key'; }
async function saveSshPassword(){
  const fb=$('ssh-password-feedback'), btn=$('ssh-password-save'); btn.disabled=true; fb.textContent=''; fb.className='save-feedback';
  try{
    const r=await api('/api/config/ssh/password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:$('ssh-password').value||''})});
    const d=await r.json();
    if(!r.ok){ fb.textContent=d.error||'Save failed'; fb.classList.add('err'); }
    else{ fb.textContent='Saved.'; fb.classList.add('ok'); $('ssh-password').value=''; }
  }catch(e){ fb.textContent='Network error'; fb.classList.add('err'); }
  btn.disabled=false; loadSshKeyStatus();
}
async function toggleSshPasswordLogin(){
  const box=$('ssh-allow-password'), fb=$('ssh-login-mode-feedback'); const allow=box.checked; fb.textContent=''; fb.className='save-feedback';
  try{
    const r=await api('/api/config/ssh/login-mode',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({allow_password_login:allow})});
    const d=await r.json();
    if(!r.ok){ box.checked=!allow; fb.textContent=d.error||'Change failed'; fb.classList.add('err'); }
    else{ appToast(allow?'Password login allowed':'Key-only login enforced','ok'); }
  }catch(e){ box.checked=!allow; fb.textContent='Network error'; fb.classList.add('err'); }
}

/* ================= PERMISSION GRANTS =================
   The form below is generated from /api/config/grants, which serves the same
   registry the server enforces against. That is deliberate: a permission
   cannot appear here without an endpoint honouring it, and an endpoint cannot
   be gated on something the admin has no way to grant. Nothing here is a
   security boundary; every grant is checked again server-side. */
let _GRANT_DEFS=null, _GRANT_GROUPS=null;

async function loadGrantRegistry(){
  if(_GRANT_DEFS) return _GRANT_DEFS;
  const d=await getJSON('/api/config/grants'); if(!d) return null;
  _GRANT_DEFS=d.grants||[]; _GRANT_GROUPS=d.groups||[];
  return _GRANT_DEFS;
}

function grantDefaults(){
  const out={};
  (_GRANT_DEFS||[]).forEach(g=>{ out[g.key]=g.default; });
  return out;
}

/* One renderer for three surfaces: the create form, the edit form, and the
   read-only list a staff member sees on their own account. */
function grantFormHtml(values, opts){
  const readonly=!!(opts&&opts.readonly), idp=(opts&&opts.idPrefix)||'g';
  if(!_GRANT_DEFS||!_GRANT_DEFS.length) return '<div class="empty-state">No permissions defined.</div>';
  return (_GRANT_GROUPS||[]).map(group=>{
    const defs=_GRANT_DEFS.filter(g=>g.group===group.key);
    if(!defs.length) return '';
    const rows=defs.map(g=>{
      const val=values&&(g.key in values)?values[g.key]:g.default;
      const id=idp+'-'+g.key;
      if(g.kind==='choice'){
        const segs=g.choices.map(c=>{
          const on=String(val)===String(c);
          if(readonly) return on?`<span class="grant-seg-on">${esc(CHOICE_LABELS[c]||c)}</span>`:'';
          return `<label class="grant-seg${on?' on':''}">
            <input type="radio" name="${escAttr(id)}" value="${escAttr(c)}"${on?' checked':''}
                   onchange="grantSegSync(this)">
            <span>${esc(CHOICE_LABELS[c]||c)}</span></label>`;
        }).join('');
        return `<div class="grant-row grant-row-choice" data-grant="${escAttr(g.key)}">
          <div class="grant-copy"><span class="grant-label">${esc(g.label)}</span>
            <span class="grant-help">${esc(g.help)}</span></div>
          <div class="grant-seg-group">${segs||'<span class="grant-off">Not granted</span>'}</div>
        </div>`;
      }
      if(readonly){
        return `<div class="grant-row" data-grant="${escAttr(g.key)}">
          <div class="grant-copy"><span class="grant-label">${esc(g.label)}</span>
            <span class="grant-help">${esc(g.help)}</span></div>
          <span class="${val?'grant-on':'grant-off'}">${val?'Allowed':'No'}</span>
        </div>`;
      }
      return `<label class="grant-row grant-row-toggle" data-grant="${escAttr(g.key)}" for="${escAttr(id)}">
        <input type="checkbox" id="${escAttr(id)}" data-grantkey="${escAttr(g.key)}"${val?' checked':''}>
        <div class="grant-copy"><span class="grant-label">${esc(g.label)}</span>
          <span class="grant-help">${esc(g.help)}</span></div>
      </label>`;
    }).join('');
    return `<fieldset class="grant-group">
      <legend class="grant-legend">${esc(group.label)}</legend>${rows}</fieldset>`;
  }).join('');
}

const CHOICE_LABELS={none:'None',limited:'Own account only',root:'Root',
                      own:'Their own files',full:'Whole filesystem'};

/* Radio inputs cannot be styled by :checked on the label alone across the
   whole group, so the active class is moved by hand on change. */
function grantSegSync(input){
  const group=input.closest('.grant-seg-group'); if(!group) return;
  group.querySelectorAll('.grant-seg').forEach(l=>l.classList.remove('on'));
  const label=input.closest('.grant-seg'); if(label) label.classList.add('on');
}

function readGrantForm(idPrefix){
  const out=grantDefaults(), root=$('nu-grants'); if(!root) return out;
  root.querySelectorAll('input[type="checkbox"][data-grantkey]').forEach(cb=>{
    out[cb.dataset.grantkey]=cb.checked;
  });
  (_GRANT_DEFS||[]).filter(g=>g.kind==='choice').forEach(g=>{
    const picked=root.querySelector(`input[name="${idPrefix}-${g.key}"]:checked`);
    if(picked) out[g.key]=picked.value;
  });
  return out;
}

/* ================= USER MANAGEMENT ================= */
let _editingUser=null;

function grantSummary(grants){
  if(!_GRANT_DEFS) return '';
  const parts=[];
  _GRANT_DEFS.forEach(g=>{
    const v=grants?grants[g.key]:g.default;
    if(g.kind==='choice'){ if(v&&v!=='none') parts.push(g.label+': '+(CHOICE_LABELS[v]||v)); }
    else if(v) parts.push(g.label);
  });
  return parts.length?parts.join(', '):'No permissions';
}

async function loadUserManagement(){
  const el=$('user-list'); if(!el) return;
  el.innerHTML='<div class="empty-state">Loading&hellip;</div>';
  try{
    await loadGrantRegistry();
    if(!$('nu-grants').dataset.ready) resetUserForm();
    const d=await getJSON('/api/config/users'); if(!d) return;
    const users=d.users||[];
    if(!users.length){ el.innerHTML='<div class="empty-state">No staff accounts yet. Create one below.</div>'; return; }
    el.innerHTML=users.map(u=>`<div class="staff-row">
      <div class="staff-main">
        <div class="staff-name">${esc(u.username)}${u.full_name?` <span class="staff-full">${esc(u.full_name)}</span>`:''}</div>
        <div class="staff-grants">${esc(grantSummary(u.grants))}</div>
      </div>
      <div class="staff-actions">
        <button class="db-action-btn" onclick="editPanelUser('${escAttr(u.username)}')">
          <svg class="ic"><use href="#ic-settings"/></svg>Edit</button>
        <button class="db-action-btn staff-del" onclick="deletePanelUser('${escAttr(u.username)}')">
          <svg class="ic"><use href="#ic-trash-2"/></svg>Delete</button>
      </div>
    </div>`).join('');
  }catch(e){ el.innerHTML='<div class="empty-state">Failed to load.</div>'; }
}

function resetUserForm(){
  _editingUser=null;
  const box=$('nu-grants'); if(!box) return;
  box.innerHTML=grantFormHtml(grantDefaults(),{idPrefix:'nu'});
  box.dataset.ready='1';
  $('nu-card-title').textContent='Add a user';
  $('nu-card-sub').textContent='Every permission below is off until you grant it.';
  $('nu-username-group').hidden=false;
  $('nu-username').value=''; $('nu-password').value='';
  $('nu-password-hint').textContent='At least 8 characters, and not only digits.';
  $('nu-submit').textContent='Create User';
  $('nu-cancel').hidden=true;
  const fb=$('nu-feedback'); fb.textContent=''; fb.className='save-feedback';
}

async function editPanelUser(username){
  await loadGrantRegistry();
  const d=await getJSON('/api/config/users'); if(!d) return;
  const user=(d.users||[]).find(u=>u.username===username);
  if(!user){ appToast('That account is gone','err'); loadUserManagement(); return; }
  _editingUser=username;
  const box=$('nu-grants');
  box.innerHTML=grantFormHtml(user.grants,{idPrefix:'nu'});
  box.dataset.ready='1';
  $('nu-card-title').textContent='Edit '+username;
  $('nu-card-sub').textContent='Unchecking a permission revokes it, and signs them out straight away.';
  $('nu-username-group').hidden=true;
  $('nu-password').value='';
  $('nu-password-hint').textContent='Leave blank to keep their current password.';
  $('nu-submit').textContent='Save Changes';
  $('nu-cancel').hidden=false;
  const fb=$('nu-feedback'); fb.textContent=''; fb.className='save-feedback';
  $('nu-card').scrollIntoView({behavior:'smooth',block:'nearest'});
}

async function submitPanelUser(){
  const fb=$('nu-feedback'), btn=$('nu-submit');
  fb.textContent=''; fb.className='save-feedback';
  const grants=readGrantForm('nu'), password=$('nu-password').value;
  const editing=_editingUser;
  let url, body;
  if(editing){
    url='/api/config/users/'+encodeURIComponent(editing);
    body={grants}; if(password) body.password=password;
  }else{
    const username=$('nu-username').value.trim();
    if(!username){ fb.textContent='Enter a username.'; fb.classList.add('err'); return; }
    url='/api/config/users'; body={username,password,grants};
  }
  btn.disabled=true;
  try{
    const r=await api(url,{method:'POST',headers:{'Content-Type':'application/json'},
                           body:JSON.stringify(body)});
    const d=await r.json();
    if(!r.ok){ fb.textContent=d.error||'Could not save.'; fb.classList.add('err'); }
    else{
      appToast(editing?'Changes saved':'User created','ok');
      resetUserForm();
      loadUserManagement();
    }
  }catch(e){ fb.textContent='Network error'; fb.classList.add('err'); }
  btn.disabled=false;
}

async function deletePanelUser(username){
  if(!(await uiConfirm('Delete this user?',username+' will lose access immediately.'))) return;
  const r=await api('/api/config/users/'+encodeURIComponent(username),{method:'DELETE'});
  const d=await r.json();
  if(!r.ok){ appToast(d.error||'Delete failed','err'); return; }
  appToast('User deleted','ok');
  if(_editingUser===username) resetUserForm();
  loadUserManagement();
}

/* The staff-facing mirror of the same registry: read-only, no controls. */
async function loadMyAccount(){
  const box=$('acct-grants'); if(!box) return;
  await loadGrantRegistry();
  box.innerHTML=grantFormHtml(window.MGMT_PERMS||{},{readonly:true,idPrefix:'ac'});
  const role=$('acct-role');
  if(role) role.textContent=(window.MGMT_PERMS||{}).role==='admin'?'Administrator':'Staff account';
}

/* ================= DATABASE ================= */
let DB_CURRENT_TABLE='', DB_CURRENT_PAGE=1, DB_WRITE=false, DB_COLUMNS=[];
async function loadDbTables(){
  const sel=$('db-table-sel'); if(!sel) return;
  try{
    const d=await getJSON('/api/config/db/tables'); if(!d) return;
    DB_WRITE=!!d.write;
    sel.innerHTML='<option value="">Pick a table&hellip;</option>'+(d.tables||[]).map(t=>`<option value="${escAttr(t)}">${esc(t)}</option>`).join('');
  }catch(e){}
}
async function loadDbTable(page){
  const sel=$('db-table-sel'), view=$('db-table-view'); if(!sel||!view) return;
  const name=sel.value; DB_CURRENT_TABLE=name;
  if(!name){ view.innerHTML='<div class="empty-state">Pick a table to browse it.</div>'; return; }
  DB_CURRENT_PAGE=page||1;
  view.innerHTML='<div class="empty-state">Loading&hellip;</div>';
  try{
    const d=await getJSON('/api/config/db/table/'+encodeURIComponent(name)+'?page='+DB_CURRENT_PAGE);
    if(!d||d.error){ view.innerHTML='<div class="empty-state">'+esc((d&&d.error)||'Failed to load.')+'</div>'; return; }
    DB_COLUMNS=d.columns||[];
    const pkCol=DB_COLUMNS[0];
    const head=DB_COLUMNS.map(c=>`<th>${esc(c)}</th>`).join('')+(DB_WRITE?'<th></th>':'');
    const rows=(d.rows||[]).map(r=>{
      const pkVal=r[0];
      // The full value goes in title so the hover tooltip still shows
      // everything. The visible text is capped by CSS ellipsis rather than by
      // slicing, so a wide column shortens instead of crushing its neighbours.
      const cells=r.map(v=>{
        const full=v==null?'':String(v);
        const nul=v==null?' db-null':'';
        return `<td class="db-cell${nul}" title="${escAttr(full)}">`
             + `<span class="db-cell-text">${esc(v==null?'null':full.slice(0,400))}</span></td>`;
      }).join('');
      const actions=DB_WRITE?`<td class="db-row-actions"><button class="db-action-btn" onclick='dbEditRow(${JSON.stringify(String(pkVal))})'>Edit</button><button class="db-action-btn" style="color:var(--danger);" onclick="dbDeleteRow('${escAttr(pkCol)}','${escAttr(String(pkVal))}')">Delete</button></td>`:'';
      return `<tr data-pk="${escAttr(String(pkVal))}">${cells}${actions}</tr>`;
    }).join('');
    const totalPages=Math.max(1,Math.ceil((d.total||0)/25));
    const addForm=DB_WRITE?`<div class="db-add-row-form" id="db-add-row-form">${DB_COLUMNS.map(c=>`<input placeholder="${escAttr(c)}" data-col="${escAttr(c)}">`).join('')}<button class="save-btn" onclick="dbInsertRow()">Add Row</button></div>
      <div class="db-add-row-form"><input id="db-newcol-name" placeholder="new column name"><select id="db-newcol-type"><option>TEXT</option><option>INTEGER</option><option>BIGINT</option><option>BOOLEAN</option><option>TIMESTAMPTZ</option><option>NUMERIC</option><option>DATE</option></select><button class="db-action-btn" onclick="dbAddColumn()"><svg class="ic"><use href="#ic-plus"/></svg>Add Column</button></div>`:'';
    view.innerHTML=`<div class="db-toolbar-row"><button class="db-action-btn" onclick="loadDbTable(${Math.max(1,DB_CURRENT_PAGE-1)})" ${DB_CURRENT_PAGE<=1?'disabled':''}>Prev</button><span class="page-info">Page ${DB_CURRENT_PAGE} / ${totalPages} &middot; ${d.total} rows</span><button class="db-action-btn" onclick="loadDbTable(${DB_CURRENT_PAGE+1})" ${DB_CURRENT_PAGE>=totalPages?'disabled':''}>Next</button></div>
      <div style="overflow-x:auto;"><table><thead><tr>${head}</tr></thead><tbody>${rows||'<tr><td colspan="'+(DB_COLUMNS.length+1)+'">No rows.</td></tr>'}</tbody></table></div>${addForm}`;
    markClippedCells(view);
  }catch(e){ view.innerHTML='<div class="empty-state">Failed to load.</div>'; }
}

/* Only cells whose text actually got cut off get the hover affordance. CSS
   cannot ask "did this overflow", so it is measured once after layout. */
function markClippedCells(root){
  root.querySelectorAll('.db-cell').forEach(td=>{
    const span=td.firstElementChild;
    if(span && span.scrollWidth > span.clientWidth + 1) td.classList.add('is-clipped');
  });
}
async function dbInsertRow(){
  const form=$('db-add-row-form'); if(!form) return;
  const values={}; form.querySelectorAll('input[data-col]').forEach(i=>{ if(i.value!=='') values[i.dataset.col]=i.value; });
  try{
    const r=await api('/api/config/db/table/'+encodeURIComponent(DB_CURRENT_TABLE)+'/row',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({values})});
    const d=await r.json();
    if(!r.ok){ appToast(d.error||'Insert failed','err'); return; }
    appToast('Row added','ok'); loadDbTable(DB_CURRENT_PAGE);
  }catch(e){ appToast('Network error','err'); }
}
function dbEditRow(pkVal){
  const row=document.querySelector(`tr[data-pk="${CSS.escape(pkVal)}"]`); if(!row) return;
  const cells=row.querySelectorAll('td'); const pkCol=DB_COLUMNS[0];
  const inputs=DB_COLUMNS.map((c,i)=>`<input data-col="${escAttr(c)}" value="${escAttr(cells[i].getAttribute('title')||'')}" ${c===pkCol?'disabled':''} style="width:100px;">`).join('');
  row.innerHTML=`<td colspan="${DB_COLUMNS.length}"><div class="db-add-row-form" style="margin:0;">${inputs}</div></td>
    <td class="db-row-actions"><button class="save-btn" onclick='dbSaveRow(${JSON.stringify(pkVal)})'>Save</button><button class="db-action-btn" onclick="loadDbTable(DB_CURRENT_PAGE)">Cancel</button></td>`;
}
async function dbSaveRow(pkVal){
  const row=document.querySelector(`tr[data-pk="${CSS.escape(pkVal)}"]`); if(!row) return;
  const values={}; row.querySelectorAll('input[data-col]').forEach(i=>{ if(!i.disabled) values[i.dataset.col]=i.value; });
  try{
    const r=await api('/api/config/db/table/'+encodeURIComponent(DB_CURRENT_TABLE)+'/row',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({pk_column:DB_COLUMNS[0],pk_value:pkVal,values})});
    const d=await r.json();
    if(!r.ok){ appToast(d.error||'Update failed','err'); return; }
    appToast('Row updated','ok'); loadDbTable(DB_CURRENT_PAGE);
  }catch(e){ appToast('Network error','err'); }
}
async function dbDeleteRow(pkCol,pkVal){
  if(!(await uiConfirm('Delete this row?','This cannot be undone.'))) return;
  try{
    const r=await api('/api/config/db/table/'+encodeURIComponent(DB_CURRENT_TABLE)+'/row',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({pk_column:pkCol,pk_value:pkVal})});
    const d=await r.json();
    if(!r.ok){ appToast(d.error||'Delete failed','err'); return; }
    appToast('Row deleted','ok'); loadDbTable(DB_CURRENT_PAGE);
  }catch(e){ appToast('Network error','err'); }
}
async function dbAddColumn(){
  const name=$('db-newcol-name').value.trim(), type=$('db-newcol-type').value;
  if(!name) return;
  try{
    const r=await api('/api/config/db/table/'+encodeURIComponent(DB_CURRENT_TABLE)+'/column',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,type})});
    const d=await r.json();
    if(!r.ok){ appToast(d.error||'Could not add column','err'); return; }
    appToast('Column added','ok'); loadDbTable(DB_CURRENT_PAGE);
  }catch(e){ appToast('Network error','err'); }
}

/* ================= PROXY =================
   A server block has a lot of knobs, so the form is generated from one
   place and read back from the same place. PX_EDITING carries which file
   is being edited (null means a new host), which is the only difference
   between the create and the edit path. */
let PX_EDITING=null, PX_EDITING_CERT='', PX_EDITING_KEY='', PX_STREAM_OK=true, PX_STREAM_WHY='', PX_LOC_SEQ=0;

async function loadProxyHosts(){
  /* The firewall and Cloudflare live on their own Config pages now, each behind
     its own grant, so this loads proxy hosts and nothing else. */
  const el=$('proxy-list'); if(!el) return;
  el.innerHTML='<div class="empty-state">Loading&hellip;</div>';
  try{
    const d=await getJSON('/api/config/proxy/hosts'); if(!d) return;
    if(!d.installed){
      el.innerHTML='<div class="empty-state">nginx is not installed on this server.</div>';
      const nb=$('px-new'); if(nb) nb.disabled=true;
      return;
    }
    PX_STREAM_OK=d.stream_supported!==false;
    PX_STREAM_WHY=d.stream_problem||'';
    const hosts=d.hosts||[];
    if(!hosts.length){
      el.innerHTML='<div class="empty-state">No proxy hosts yet. Add one to route a domain at something running on this server.</div>';
      return;
    }
    el.innerHTML=hosts.map(h=>{
      const s=h.spec||null;
      const meta=[];
      if(s){
        meta.push(s.listen_scheme.toUpperCase()+' in');
        if(s.force_ssl) meta.push('force SSL');
        if(s.hsts) meta.push('HSTS');
        if(s.http2) meta.push('HTTP/2');
        if(s.cache_assets) meta.push('cached');
        if(s.block_exploits) meta.push('exploit guard');
        if(s.websockets) meta.push('websockets');
        if(s.locations&&s.locations.length) meta.push(s.locations.length+' custom location'+(s.locations.length>1?'s':''));
      }else if(h.websockets){ meta.push('websockets'); }
      return `<div class="proxy-host">
      <div class="proxy-host-info">
        <div class="proxy-host-domain">${esc(h.domain||h.file)}</div>
        <div class="proxy-host-target">&rarr; ${esc(h.target||'unknown target')}</div>
        ${meta.length?`<div class="proxy-host-meta">${meta.map(m=>`<span>${esc(m)}</span>`).join('')}</div>`:''}
      </div>
      <span class="proxy-host-badge ${h.managed?'managed':''}">${h.managed?'managed here':'detected'}</span>
      <div class="proxy-host-actions">
        ${h.managed?`<button class="db-action-btn" title="Edit this host" onclick="editProxyHost('${escAttr(h.file)}')"><svg class="ic"><use href="#ic-pencil"/></svg></button>
        <button class="db-action-btn" title="Remove this host" style="color:var(--danger);" onclick="deleteProxyHost('${escAttr(h.file)}')"><svg class="ic"><use href="#ic-trash-2"/></svg></button>`
        :`<span class="proxy-host-readonly" title="This server block was written by hand. Editing or deleting it here would overwrite somebody's work, so it is left alone.">Read-only</span>`}
      </div>
    </div>`;}).join('');
    PX_HOSTS=hosts;
  }catch(e){ el.innerHTML='<div class="empty-state">Failed to load.</div>'; }
}
let PX_HOSTS=[];

function pxRadio(name){
  const el=document.querySelector(`input[name="${name}"]:checked`);
  return el?el.value:'';
}
function pxSetRadio(name, value){
  const el=document.querySelector(`input[name="${name}"][value="${value}"]`);
  if(el){ el.checked=true; }
}
function pxFlag(field){ const el=document.querySelector(`[data-px="${field}"]`); return el?el.checked:false; }
function pxSetFlag(field, on){ const el=document.querySelector(`[data-px="${field}"]`); if(el) el.checked=!!on; }

/* The form shows only what the chosen scheme actually has. A stream host has
   no certificate, no caching and no locations, so those groups go away rather
   than sitting there inert. */
function pxSyncScheme(){
  const listen=pxRadio('px-listen');
  const stream=(listen==='tcp'||listen==='udp');
  const show=(id,on)=>{ const el=$(id); if(el) el.hidden=!on; };
  show('px-tls-group', listen==='https');
  show('px-behaviour-group', !stream);
  show('px-locations-group', !stream);
  const fs=$('px-forward-scheme-field'); if(fs) fs.hidden=stream;
  const note=$('px-stream-note');
  if(note){
    if(stream&&!PX_STREAM_OK){
      note.textContent=PX_STREAM_WHY||'TCP and UDP forwarding is unavailable on this server.';
      note.hidden=false;
    }else if(stream){
      note.textContent='TCP and UDP hosts forward raw connections, so certificates and caching do not apply.';
      note.hidden=false;
    }else{ note.hidden=true; }
  }
  pxSyncHsts();
}
function pxSyncHsts(){
  const hsts=document.querySelector('[data-px="hsts"]');
  const sub=document.querySelector('[data-px="hsts_subdomains"]');
  if(!hsts||!sub) return;
  sub.disabled=!hsts.checked;
  if(!hsts.checked) sub.checked=false;
}

function pxLocationHtml(values){
  const v=values||{};
  const id=++PX_LOC_SEQ;
  const sw=(field,label,help,on)=>`
        <label class="px-toggle-row">
          <span class="grant-copy">
            <span class="grant-label">${label}</span>
            <span class="grant-help">${help}</span>
          </span>
          <span class="px-switch">
            <input type="checkbox" data-loc="${field}"${on?' checked':''}>
            <span class="px-switch-track"><span class="px-switch-knob"></span></span>
          </span>
        </label>`;
  return `<div class="px-location" data-px-location="${id}">
    <div class="px-location-head">
      <div class="px-location-title">Location</div>
      <button class="db-action-btn" style="color:var(--danger);" onclick="removeProxyLocation(this)">Remove</button>
    </div>
    <div class="px-row">
      <div class="px-field px-field-grow">
        <label class="field-label">Path</label>
        <input class="field-input" data-loc="path" type="text" placeholder="/api"
               spellcheck="false" autocomplete="off" value="${escAttr(v.path||'')}">
      </div>
    </div>
    <div class="px-row">
      <div class="px-field">
        <label class="field-label">Scheme</label>
        <select class="field-input" data-loc="forward_scheme">
          <option value="http"${(v.forward_scheme||'http')==='http'?' selected':''}>HTTP</option>
          <option value="https"${v.forward_scheme==='https'?' selected':''}>HTTPS</option>
        </select>
      </div>
      <div class="px-field px-field-grow">
        <label class="field-label">Hostname or IP</label>
        <input class="field-input" data-loc="forward_host" type="text" placeholder="127.0.0.1"
               spellcheck="false" autocomplete="off" value="${escAttr(v.forward_host||'')}">
      </div>
      <div class="px-field px-field-port">
        <label class="field-label">Port</label>
        <input class="field-input" data-loc="forward_port" type="number" min="1" max="65535"
               placeholder="9000" inputmode="numeric" autocomplete="off" value="${escAttr(v.forward_port||'')}">
      </div>
    </div>
    <div class="px-location-toggles">
      ${sw('cache_assets','Cache assets','Browsers may keep static files from this path.',v.cache_assets)}
      ${sw('block_exploits','Block common exploits','Reject the usual injection and traversal probes.',v.block_exploits)}
      ${sw('websockets','Websockets support','Pass the upgrade through on this path.',v.websockets!==false&&!!v.websockets)}
    </div>
  </div>`;
}
function addProxyLocation(values){
  const wrap=$('px-locations'); if(!wrap) return;
  wrap.insertAdjacentHTML('beforeend', pxLocationHtml(values));
}
function removeProxyLocation(btn){
  const row=btn.closest('[data-px-location]'); if(row) row.remove();
}
function pxReadLocations(){
  return Array.from(document.querySelectorAll('#px-locations [data-px-location]')).map(row=>{
    const get=f=>row.querySelector(`[data-loc="${f}"]`);
    return {
      path:(get('path')?.value||'').trim(),
      forward_scheme:get('forward_scheme')?.value||'http',
      forward_host:(get('forward_host')?.value||'').trim(),
      forward_port:parseInt(get('forward_port')?.value||'0',10)||0,
      cache_assets:!!get('cache_assets')?.checked,
      block_exploits:!!get('block_exploits')?.checked,
      websockets:!!get('websockets')?.checked,
    };
  });
}

async function openProxyForm(spec, filename){
  const card=$('px-form-card'); if(!card) return;
  PX_EDITING=filename||null;
  const title=$('px-form-title');
  if(title) title.textContent=PX_EDITING?'Edit proxy host':'Add a proxy host';
  const save=$('px-save'); if(save) save.textContent=PX_EDITING?'Save changes':'Add host';
  const fb=$('px-feedback'); if(fb){ fb.textContent=''; fb.className='save-feedback'; }
  /* The card comes up before its fields are filled: an error while filling
     must never swallow the open. Worst case the form shows with a value
     missing, and Cancel recovers from that. */
  card.hidden=false;

  const s=spec||{listen_scheme:'https',forward_scheme:'http',websockets:true,locations:[]};
  pxSetRadio('px-listen', s.listen_scheme||'https');
  pxSetRadio('px-forward-scheme', s.forward_scheme||'http');
  $('px-domain').value=s.domain||'';
  $('px-listen-port').value=s.listen_port||'';
  $('px-forward-host').value=s.forward_host||'';
  $('px-forward-port').value=s.forward_port||'';
  PX_EDITING_CERT=s.cert_path||'';
  PX_EDITING_KEY=s.cert_key_path||'';
  ['force_ssl','hsts','hsts_subdomains','http2','cache_assets','block_exploits','websockets']
    .forEach(f=>pxSetFlag(f, s[f]));
  const wrap=$('px-locations'); if(wrap) wrap.innerHTML='';
  (s.locations||[]).forEach(loc=>addProxyLocation(loc));

  pxSyncScheme();
  card.scrollIntoView({behavior:'smooth', block:'start'});
}
function closeProxyForm(){
  const card=$('px-form-card'); if(card) card.hidden=true;
  PX_EDITING=null;
  PX_EDITING_CERT=''; PX_EDITING_KEY='';
}
function editProxyHost(filename){
  const host=PX_HOSTS.find(h=>h.file===filename);
  if(!host){ appToast('That host is no longer in the list','err'); return; }
  if(!host.managed){ appToast('This host was written by hand, so it is read-only here','err'); return; }
  if(!host.spec){
    appToast('This host has no saved settings to edit. Remove it and add it again.','err');
    return;
  }
  openProxyForm(host.spec, filename);
}

function pxReadForm(){
  const listen=pxRadio('px-listen');
  const stream=(listen==='tcp'||listen==='udp');
  const body={
    domain:$('px-domain').value.trim(),
    listen_scheme:listen,
    listen_port:parseInt($('px-listen-port').value||'0',10)||0,
    forward_scheme:stream?'http':pxRadio('px-forward-scheme'),
    forward_host:$('px-forward-host').value.trim(),
    forward_port:parseInt($('px-forward-port').value||'0',10)||0,
    cert_path:listen==='https'?PX_EDITING_CERT:'',
    cert_key_path:listen==='https'?PX_EDITING_KEY:'',
    locations:stream?[]:pxReadLocations(),
  };
  ['force_ssl','hsts','hsts_subdomains','http2'].forEach(f=>{ body[f]=listen==='https'&&pxFlag(f); });
  ['cache_assets','block_exploits','websockets'].forEach(f=>{ body[f]=!stream&&pxFlag(f); });
  return body;
}

async function saveProxyHost(){
  const fb=$('px-feedback'), btn=$('px-save');
  fb.textContent=''; fb.className='save-feedback'; btn.disabled=true;
  const body=pxReadForm();
  const editing=PX_EDITING;
  const url=editing?'/api/config/proxy/hosts/'+encodeURIComponent(editing):'/api/config/proxy/hosts';
  try{
    const r=await api(url,{method:editing?'PUT':'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(!r.ok){ fb.textContent=d.error||'Could not save the host.'; fb.classList.add('err'); }
    else{
      let msg=editing?'Changes saved and nginx reloaded.':'Host created and nginx reloaded.';
      if(d.firewall&&d.firewall.port&&d.firewall.opened&&!d.firewall.enforced){
        msg+=' Port '+d.firewall.port+' is on the allow list, but the firewall did not apply it.';
      }else if(d.firewall&&d.firewall.port&&d.firewall.opened){
        msg+=' Port '+d.firewall.port+' opened.';
      }
      fb.textContent=msg; fb.classList.add('ok');
      closeProxyForm();
      appToast(editing?'Proxy host updated':'Proxy host added','ok');
      loadProxyHosts();
    }
  }catch(e){ fb.textContent='Network error'; fb.classList.add('err'); }
  btn.disabled=false;
}
async function deleteProxyHost(filename){
  if(!(await uiConfirm('Remove this proxy host?','nginx will reload without it.'))) return;
  try{
    const r=await api('/api/config/proxy/hosts/'+encodeURIComponent(filename),{method:'DELETE'});
    const d=await r.json();
    if(!r.ok){ appToast(d.error||'Delete failed','err'); return; }
    appToast('Host removed','ok'); loadProxyHosts();
  }catch(e){ appToast('Network error','err'); }
}

/* ================= MAIL =================
   One pane, two audiences. An admin may still have to set the whole thing
   up, so they get the setup cards until a domain exists. Everybody else
   either has an address, in which case they get their mail, or does not,
   in which case they are told so plainly and told who can fix it.

   Which way a message went is part of every row, because "did that leave
   the building" is the first thing anybody asks about a sent message. */
let MAIL={}, MAIL_FOLDER='inbox', MAIL_MSGS=[], MAIL_OPEN=null, _mailBadgeTimer=null;

async function loadMail(){
  const setup=$('mail-setup'); if(!setup) return;
  try{
    const d=await getJSON('/api/mail/overview'); if(!d) return;
    MAIL=d;
    renderMailSetup();
    const hasBox=(d.boxes||[]).length>0;
    cfShow('mail-main', d.configured&&hasBox);
    if(d.configured&&hasBox){
      fillMailBoxes();
      loadMailMessages();
    }
    setMailBadge(d.unread||0);
  }catch(e){
    setup.innerHTML='<div class="empty-state">Could not load mail.</div>';
  }
}

function renderMailSetup(){
  const el=$('mail-setup'); const d=MAIL||{};
  const running=!!d.configured&&(d.boxes||[]).length>0;
  cfShow('mail-settings-btn', !!d.is_admin&&running);
  el.hidden=false;
  if(!d.is_admin){
    if(!d.configured){
      el.innerHTML=`<div class="mail-empty-note">
        <b>Mail is not configured yet.</b><br>
        An administrator has to set up the mail domain before addresses can exist.
        Ask them to do it, and your address will appear here.</div>`;
      return;
    }
    if(!(d.boxes||[]).length){
      el.innerHTML=`<div class="mail-empty-note">
        <b>You do not have an address yet.</b><br>
        Mail is running on <b>${esc(d.domain)}</b>. An administrator can create an
        address for you and assign it to <b>${esc(d.username)}</b>.</div>`;
      return;
    }
    el.innerHTML='';
    return;
  }
  el.innerHTML=mailAdminHtml(d);
  // Nobody opens Mail to look at a relay password. Once there is mail to read,
  // the settings fold away behind the button in the bar; while there is not,
  // they stay open, because they are the whole page.
  el.hidden=running;
  const btn=$('mail-settings-btn');
  if(btn) btn.setAttribute('aria-expanded','false');
}

function mailNothingOpenHtml(){
  return `<div class="mail-read-nothing">
    <svg class="ic"><use href="#ic-mail"/></svg>
    <b>Nothing open</b>
    Pick a message on the left and it opens here. Unread ones carry a red dot.</div>`;
}

function mailToggleSettings(){
  const el=$('mail-setup'); if(!el) return;
  const opening=el.hidden;
  el.hidden=!opening;
  const btn=$('mail-settings-btn');
  if(btn) btn.setAttribute('aria-expanded', opening?'true':'false');
  if(opening) el.scrollIntoView({behavior:reduceMotion()?'auto':'smooth', block:'start'});
}

/* What the panel would have to install before mail can run. Kept out of the
   button's markup so the onclick stays a plain call. */
let MAIL_NEEDS=[];

function mailAdminHtml(d){
  const cfg=d.config||{}, inb=d.inbound||{};
  MAIL_NEEDS=inb.needs||[];
  const boxes=d.all_boxes||[], staff=d.staff||[];
  /* Every value here is the value to paste, not a description of one: the
     A record carries this server's real address and the DKIM row carries the
     key mailcow generated. A row still being worked out says so, rather than
     showing an empty cell that reads as "nothing needed". */
  const dns=(d.dns||[]).map(r=>`<tr><td class="mono">${esc(r.type)}</td>
      <td class="mono">${esc(r.name)}</td>
      <td class="mono dns-val">${r.pending
        ? `<span class="mc-pending">${esc(r.pending)}…</span>`
        : `<span class="dns-v">${esc(r.value)}</span>
           <button class="mc-copy" title="Copy value" onclick="copyVal(this.previousElementSibling.textContent,'${escAttr(r.type)} value')">copy</button>`}</td>
      <td style="color:var(--gray-600);">${esc(r.why)}</td></tr>`).join('');

  const inboundState=inb.ready?'<span class="cf-state cf-ok">receiving</span>'
    :inb.installed?'<span class="cf-state cf-wait">set up, not receiving</span>'
    :'<span class="cf-state">not set up</span>';
  /* The mailcow admin login, kept on the card so it can be found again.
     It is not a secret that is only shown once: this is a personal server
     panel, and the operator logging in tomorrow needs the same URL. */
  const mcHost=inb.hostname||'';
  const mcPw=inb.admin_password||'';
  const mcKey=inb.api_key||'';
  const mcLogin=inb.installed&&mcHost?`
    <div class="field-label" style="margin-top:16px;">mailcow admin login</div>
    <div class="mc-creds">
      <div class="mc-row">
        <span class="mc-k">Web UI</span>
        <span class="mc-v">https://${esc(mcHost)}:${esc(inb.https_port)}</span>
        <button class="mc-copy" title="Copy URL" onclick="copyVal('https://${escAttr(mcHost)}:${escAttr(inb.https_port)}','Web UI URL')">copy</button>
      </div>
      <div class="mc-row">
        <span class="mc-k">Username</span>
        <span class="mc-v">${esc(inb.admin_username||'admin')}</span>
        <button class="mc-copy" title="Copy username" onclick="copyVal('${escAttr(inb.admin_username||'admin')}','Username')">copy</button>
      </div>
      ${mcPw?`<div class="mc-row">
        <span class="mc-k">Password</span>
        <span class="mc-v" id="mailcow-pw" data-real="${escAttr(mcPw)}">••••••••••••</span>
        <button class="mc-copy" id="mailcow-pw-toggle" title="Show or hide the password" onclick="mailcowPwToggle()">show</button>
        <button class="mc-copy" title="Copy password" onclick="copyVal('${escAttr(mcPw)}','Password')">copy</button>
      </div>`:`<div class="mc-row">
        <span class="mc-k">Password</span>
        <span class="mc-v mc-pending">${inb.setup_busy?'Being set…':'Appears once the stack is running.'}</span>
      </div>`}
      <div class="mc-row">
        <span class="mc-k">SMTP</span>
        <span class="mc-v">port 25 in, 587 / 465 out${inb.smtp_listening?'':', nothing listening yet'}</span>
      </div>
      ${mcKey?`<div class="mc-row">
        <span class="mc-k">API key</span>
        <span class="mc-v" id="mailcow-key" data-real="${escAttr(mcKey)}">••••••••••••</span>
        <button class="mc-copy" id="mailcow-key-toggle" title="Show or hide the API key" onclick="mailcowKeyToggle()">show</button>
        <button class="mc-copy" title="Copy API key" onclick="copyVal('${escAttr(mcKey)}','API key')">copy</button>
      </div>`:`<div class="mc-row">
        <span class="mc-k">API key</span>
        <span class="mc-v mc-pending">${inb.setup_busy?'Being created…':'Created automatically once the stack is running.'}</span>
      </div>`}
    </div>
    ${inb.setup_busy?`<div class="mc-working">
      <span class="cf-pulse"></span>Finishing setup: API key, domain, and DKIM key.
    </div>`:''}`:'';
  const outState=cfg.relay_host?'<span class="cf-state cf-ok">configured</span>'
    :'<span class="cf-state">not set up</span>';

  const setup=!d.configured?`
    <div class="cfg-card cfg-card-wide">
      <div class="device-title">Set the mail domain</div>
      <div class="settings-subtitle" style="margin:6px 0 14px;">
        Every address on this system lives under one domain. It is asked once,
        and the two buttons below disappear once it is answered.
      </div>
      <div class="cf-add-row">
        <input class="field-input" id="mail-domain" type="text" maxlength="253"
               placeholder="example.com" autocomplete="off" spellcheck="false">
      </div>
      <div class="cf-btn-row" style="margin-top:12px;">
        <button class="save-btn" onclick="mailConfigureInbound()">Configure inbound mail</button>
        <button class="db-action-btn" onclick="mailConfigureOutbound()">Configure outbound mail</button>
      </div>
      <div class="field-hint" style="margin-top:10px;">
        Inbound sets up mailcow on this server and opens port 25 so mail can
        arrive. Outbound only needs a relay to hand mail to, and works on its own.
      </div>
      <div class="save-feedback" id="mail-domain-feedback"></div>
    </div>`:'';

  return `${setup}
  <div class="mail-setup-grid" ${d.configured?'':'style="margin-top:16px;"'}>
    <div class="cfg-card cfg-card-wide">
      <div class="px-card-head">
        <div><div class="device-title">Inbound mail</div>
          <div class="settings-subtitle" style="margin-top:6px;">mailcow, on port 25.
            Nothing arrives until this is running and DNS points here.</div></div>
        ${inboundState}
      </div>
      <div class="px-fw-status" style="margin-top:12px;">
        <span>Docker: ${inb.docker?'ready':esc(inb.docker_note||'not available')}</span>
        <span>Compose: ${inb.compose?'ready':'missing'}</span>
        <span>Containers: ${inb.containers_running||0}/${inb.containers_total||0}</span>
        <span>Port 25: ${inb.smtp_listening?'listening':'closed'}</span>
      </div>
      ${mcLogin}
      ${(inb.problems||[]).map(p=>`<div class="cf-missing">${esc(p)}</div>`).join('')}
      <div class="cf-btn-row" style="margin-top:14px;">
        ${inb.can_install?`<button class="save-btn" onclick="installMissing()">Install what is missing</button>`:''}
        ${d.configured?`<button class="save-btn" onclick="mailInbound('prepare')">${inb.installed?'Re-run setup':'Set up mailcow'}</button>`:''}
        <button class="db-action-btn" onclick="mailInbound('start')" ${inb.installed?'':'disabled'}>Start containers</button>
        <button class="db-action-btn" onclick="mailInbound('stop')" ${inb.installed?'':'disabled'}>Stop</button>
      </div>
      <div class="save-feedback" id="mail-inbound-feedback">${inb.busy?esc(inb.action+'…'):''}</div>
      <div class="field-group" style="margin-top:16px;">
        <label class="field-label" for="mail-api-key">mailcow API key</label>
        <div class="field-hint">Read and write, from mailcow's own admin page. With it,
          an address created here is created on the mail server too.
          ${cfg.mailcow_key_set?'A key is stored.':'No key stored yet.'}</div>
        <input class="field-input" id="mail-api-key" type="password" maxlength="200"
               autocomplete="off" placeholder="${cfg.mailcow_key_set?'stored, type to replace':''}">
      </div>
      <button class="db-action-btn" onclick="mailSaveKey()">Save key</button>
      ${dns?`<div class="field-label" style="margin-top:18px;">DNS this needs</div>
      <div class="mail-dns"><table><thead><tr><th>Type</th><th>Name</th><th>Value</th><th>Why</th></tr></thead>
      <tbody>${dns}</tbody></table></div>`:''}
    </div>

    <div class="cfg-card cfg-card-wide">
      <div class="px-card-head">
        <div><div class="device-title">Outbound mail</div>
          <div class="settings-subtitle" style="margin-top:6px;">The relay external
            mail is handed to. Internal mail never goes near it.</div></div>
        ${outState}
      </div>
      <div class="field-group" style="margin-top:14px;">
        <label class="field-label" for="mail-relay-host">Relay host</label>
        <input class="field-input" id="mail-relay-host" type="text" maxlength="255"
               value="${escAttr(cfg.relay_host||'')}" placeholder="smtp.example.com"
               autocomplete="off" spellcheck="false">
      </div>
      <div class="cf-route-form">
        <div class="cf-field cf-field-port">
          <label class="field-label" for="mail-relay-port">Port</label>
          <input class="field-input" id="mail-relay-port" type="number" min="1" max="65535"
                 value="${escAttr(cfg.relay_port||587)}" inputmode="numeric">
        </div>
        <div class="cf-field">
          <label class="field-label" for="mail-relay-user">Username</label>
          <input class="field-input" id="mail-relay-user" type="text" maxlength="255"
                 value="${escAttr(cfg.relay_user||'')}" autocomplete="off" spellcheck="false">
        </div>
        <div class="cf-field">
          <label class="field-label" for="mail-relay-pass">Password</label>
          <input class="field-input" id="mail-relay-pass" type="password" maxlength="300"
                 autocomplete="new-password"
                 placeholder="${cfg.relay_secret_set?'stored, type to replace':''}">
        </div>
      </div>
      <label class="px-check-row" style="margin-top:12px;">
        <input type="checkbox" id="mail-relay-tls" ${cfg.relay_starttls!==false?'checked':''}>
        <span class="grant-copy">
          <span class="grant-label">STARTTLS</span>
          <span class="grant-help">Upgrade the connection to TLS before signing in.
            Leave this on unless the relay does not support it.</span></span>
      </label>
      <div class="cf-btn-row" style="margin-top:14px;">
        <button class="save-btn" onclick="mailSaveRelay()">Save relay</button>
        <button class="db-action-btn" onclick="mailCheckRelay()" ${cfg.relay_host?'':'disabled'}>Test connection</button>
      </div>
      <div class="field-hint" style="margin-top:10px;">
        ${cfg.relay_checked_at?esc('Last checked '+cfg.relay_checked_at+', '+(cfg.relay_check_detail||'')):'Not tested yet.'}
      </div>
      <div class="save-feedback" id="mail-relay-feedback"></div>
    </div>
  </div>

  ${d.configured?`
  <div class="cfg-card cfg-card-wide" style="margin-top:16px;">
    <div class="device-title">Addresses on ${esc(d.domain)}</div>
    <div class="settings-subtitle" style="margin:6px 0 14px;">
      Create an address and hand it to somebody. An address with no owner is one
      only you can read.
    </div>
    <div class="cf-route-form">
      <div class="cf-field">
        <label class="field-label" for="mail-new-local">Address</label>
        <input class="field-input" id="mail-new-local" type="text" maxlength="64"
               placeholder="sales" autocomplete="off" spellcheck="false">
      </div>
      <div class="cf-field">
        <label class="field-label" for="mail-new-name">Full name on the message</label>
        <input class="field-input" id="mail-new-name" type="text" maxlength="160"
               placeholder="Sales Desk" autocomplete="off">
      </div>
      <div class="cf-field">
        <label class="field-label" for="mail-new-owner">Belongs to</label>
        <select class="field-input" id="mail-new-owner">
          <option value="">Admin only</option>
          ${staff.map(u=>`<option value="${escAttr(u)}">${esc(u)}</option>`).join('')}
        </select>
      </div>
      <button class="save-btn" onclick="mailCreateBox()">Create address</button>
    </div>
    <div class="save-feedback" id="mail-box-feedback"></div>
    <div style="margin-top:16px;">
      ${boxes.length?boxes.map(b=>`<div class="cf-row">
        <div class="cf-row-main">
          <div class="cf-row-name">${esc(b.address)}${b.server_side?' <span class="cf-badge">on the server</span>':''}</div>
          <div class="cf-row-sub">${esc(b.full_name||'no display name')} · ${b.owner?'belongs to '+esc(b.owner):'admin only'}${b.unread?' · '+b.unread+' unread':''}</div>
        </div>
        <div class="cf-row-acts">
          <select class="field-input" style="padding:5px 8px;font-size:12px;"
                  onchange="mailAssign('${escAttr(b.address)}',this.value)">
            <option value=""${b.owner?'':' selected'}>Admin only</option>
            ${staff.map(u=>`<option value="${escAttr(u)}"${b.owner===u?' selected':''}>${esc(u)}</option>`).join('')}
          </select>
          <button class="db-action-btn cf-danger" onclick="mailDeleteBox('${escAttr(b.address)}')">Delete</button>
        </div></div>`).join('')
      :'<div class="empty-state">No addresses yet.</div>'}
    </div>
  </div>`:''}`;
}

function mailFeedback(id, ok, text){
  const fb=$(id); if(!fb) return;
  fb.className='save-feedback '+(ok?'ok':'err'); fb.textContent=text;
}

async function mailPost(path, payload, feedbackId, okMessage){
  try{
    const r=await api(path,{method:'POST',headers:{'Content-Type':'application/json'},
                            body:JSON.stringify(payload||{})});
    const d=await r.json();
    if(!r.ok){ if(feedbackId) mailFeedback(feedbackId,false,d.error||'That did not work.'); return null; }
    if(feedbackId) mailFeedback(feedbackId,true,d.message||okMessage||'Saved.');
    return d;
  }catch(e){ if(feedbackId) mailFeedback(feedbackId,false,'Network error.'); return null; }
}

async function mailConfigureInbound(){
  const domain=($('mail-domain').value||'').trim().toLowerCase();
  if(!domain){ mailFeedback('mail-domain-feedback',false,'Type the domain first.'); return; }
  const d=await mailPost('/api/mail/inbound/prepare',{domain},'mail-domain-feedback');
  if(d){ appToast('Setting up inbound mail','ok'); mailWatchJob(); loadMail(); }
}
async function mailConfigureOutbound(){
  const domain=($('mail-domain').value||'').trim().toLowerCase();
  if(!domain){ mailFeedback('mail-domain-feedback',false,'Type the domain first.'); return; }
  const d=await mailPost('/api/mail/domain',{domain},'mail-domain-feedback');
  if(d){ appToast('Domain saved, now fill in the relay','ok'); loadMail(); }
}
async function mailInbound(action){
  if(action==='prepare'){
    const domain=(MAIL.domain||'');
    const d=await mailPost('/api/mail/inbound/prepare',{domain},'mail-inbound-feedback');
    if(d) mailWatchJob();
    return;
  }
  const d=await mailPost('/api/mail/inbound/'+action,{},'mail-inbound-feedback');
  if(d) mailWatchJob();
}
function mcReveal(id){
  /* The secret sits masked on the card, and the real value is kept in a data
     attribute on the same element, so showing it is a class flip that never
     re-fetches and never disappears when the card re-renders. */
  const el=$(id), btn=$(id+'-toggle'); if(!el||!btn) return;
  const shown=el.classList.toggle('revealed');
  el.textContent=shown?(el.getAttribute('data-real')||''):'••••••••••••';
  btn.textContent=shown?'hide':'show';
}
function mailcowPwToggle(){ mcReveal('mailcow-pw'); }
function mailcowKeyToggle(){ mcReveal('mailcow-key'); }
async function installMissing(){
  /* apt takes minutes on a cold machine, so this starts a background job and
     reports on it in the same place the mailcow jobs report. */
  const components=MAIL_NEEDS.slice();
  if(!components.length){ loadMail(); return; }
  const d=await mailPost('/api/system/install',{components},'mail-inbound-feedback');
  if(d) installWatchJob();
}

function installWatchJob(){
  const tick=async()=>{
    try{
      const j=await getJSON('/api/system/install'); if(!j) return;
      if(j.busy){ mailFeedback('mail-inbound-feedback',true,j.action+'… '+j.seconds+'s'); setTimeout(tick,4000); return; }
      if(j.error) mailFeedback('mail-inbound-feedback',false,j.error);
      else if(j.action) mailFeedback('mail-inbound-feedback',true,j.output||'Installed.');
      loadMail();
    }catch(e){ /* the next tick may work */ }
  };
  setTimeout(tick,2000);
}

function mailWatchJob(){
  /* Cloning mailcow and pulling its images take minutes, so the server runs it
     in the background and this reports on it until it finishes. */
  const tick=async()=>{
    try{
      const j=await getJSON('/api/mail/inbound-job'); if(!j) return;
      if(j.busy){ mailFeedback('mail-inbound-feedback',true,j.action+'… '+j.seconds+'s'); setTimeout(tick,4000); return; }
      if(j.error){ mailFeedback('mail-inbound-feedback',false,j.error); }
      else if(j.action){ mailFeedback('mail-inbound-feedback',true,j.output||'Done.'); }
      loadMail();
    }catch(e){ /* the next tick may work */ }
  };
  setTimeout(tick,1500);
}
async function mailSaveKey(){
  const key=($('mail-api-key').value||'').trim();
  if(!key){ mailFeedback('mail-inbound-feedback',false,'Paste the API key first.'); return; }
  const d=await mailPost('/api/mail/inbound/key',{key},'mail-inbound-feedback');
  if(d){ $('mail-api-key').value=''; loadMail(); }
}
async function mailSaveRelay(){
  const payload={host:($('mail-relay-host').value||'').trim(),
                 port:($('mail-relay-port').value||'587').trim(),
                 user:($('mail-relay-user').value||'').trim(),
                 password:$('mail-relay-pass').value||'',
                 starttls:$('mail-relay-tls').checked};
  const d=await mailPost('/api/mail/relay',payload,'mail-relay-feedback');
  if(d){ $('mail-relay-pass').value=''; loadMail(); }
}
async function mailCheckRelay(){
  mailFeedback('mail-relay-feedback',true,'Connecting…');
  try{
    const r=await api('/api/mail/relay/check',{method:'POST'});
    const d=await r.json();
    mailFeedback('mail-relay-feedback',!!d.ok,(d.ok?'Works: ':'Failed: ')+(d.detail||''));
    loadMail();
  }catch(e){ mailFeedback('mail-relay-feedback',false,'Network error.'); }
}
async function mailCreateBox(){
  const payload={local_part:($('mail-new-local').value||'').trim().toLowerCase(),
                 full_name:($('mail-new-name').value||'').trim(),
                 owner:$('mail-new-owner').value||''};
  if(!payload.local_part){ mailFeedback('mail-box-feedback',false,'Type the part before the @.'); return; }
  const d=await mailPost('/api/mail/box',payload,'mail-box-feedback');
  if(d){ $('mail-new-local').value=''; $('mail-new-name').value=''; loadMail(); }
}
async function mailAssign(address, owner){
  const d=await mailPost('/api/mail/box/assign',{address,owner},'mail-box-feedback');
  if(d) loadMail();
}
async function mailDeleteBox(address){
  if(!(await uiConfirm('Delete '+address+'?','Every message stored for it goes too.'))) return;
  try{
    const r=await api('/api/mail/box/'+encodeURIComponent(address),{method:'DELETE'});
    const d=await r.json();
    if(!r.ok){ mailFeedback('mail-box-feedback',false,d.error||'Could not delete it.'); return; }
    appToast('Address deleted','ok'); loadMail();
  }catch(e){ mailFeedback('mail-box-feedback',false,'Network error.'); }
}

/* ---- reading ---- */
function fillMailBoxes(){
  const sel=$('mail-box'); if(!sel) return;
  const boxes=MAIL.boxes||[]; const keep=sel.value;
  sel.innerHTML=(boxes.length>1?'<option value="">All my addresses</option>':'')
    +boxes.map(b=>`<option value="${escAttr(b.address)}">${esc(b.address)}${b.unread?' ('+b.unread+')':''}</option>`).join('');
  if(keep&&[...sel.options].some(o=>o.value===keep)) sel.value=keep;
  const sync=$('mail-sync-btn');
  if(sync) sync.hidden=!boxes.some(b=>b.server_side);
}
function mailFolder(folder){
  MAIL_FOLDER=folder;
  document.querySelectorAll('[data-mailfolder]').forEach(b=>
    b.classList.toggle('active', b.dataset.mailfolder===folder));
  loadMailMessages();
}
async function loadMailMessages(){
  const list=$('mail-list'); if(!list) return;
  list.innerHTML='<div class="empty-state">Loading&hellip;</div>';
  const box=$('mail-box')?$('mail-box').value:'';
  try{
    const d=await getJSON(`/api/mail/messages?folder=${encodeURIComponent(MAIL_FOLDER)}&box=${encodeURIComponent(box)}`);
    if(!d) return;
    MAIL_MSGS=d.messages||[];
    renderMailList();
  }catch(e){ list.innerHTML='<div class="empty-state">Could not load messages.</div>'; }
}
function renderMailList(){
  const list=$('mail-list');
  if(!MAIL_MSGS.length){
    list.innerHTML=`<div class="empty-state">${MAIL_FOLDER==='sent'
      ?'Nothing sent yet.':'No mail here yet.'}</div>`;
    return;
  }
  list.innerHTML=MAIL_MSGS.map((m,i)=>{
    const who=MAIL_FOLDER==='sent'?m.to_addr:(m.from_name||m.from_addr);
    const preview=(m.body||'').replace(/\s+/g,' ').slice(0,110);
    return `<button class="mail-item${m.unread&&m.direction==='in'?' unread':''}${MAIL_OPEN===m.id?' active':''}"
      onclick="mailOpen(${i})">
      <div class="mail-item-top">
        <span class="mail-item-who">${esc(who||'unknown')}</span>
        <span class="mail-item-when">${esc(String(m.ts).slice(5,16))}</span>
      </div>
      <div class="mail-item-subject">${esc(m.subject||'(no subject)')}</div>
      <div class="mail-item-preview">${esc(preview)}</div>
    </button>`;
  }).join('');
}
function mailInitials(name, addr){
  const source=(name||addr||'?').trim();
  const parts=source.split(/[\s.@_-]+/).filter(Boolean);
  return ((parts[0]||'?')[0]+((parts[1]||'')[0]||'')).toUpperCase();
}
/* An address on this system belongs to somebody, and if that somebody has a
   picture it goes here. Mail from outside has no account behind it, so it gets
   initials: an honest answer rather than a broken image. */
function mailFace(addr, name){
  const face=((MAIL.faces||{})[String(addr||'').toLowerCase()])||{};
  if(face.avatar) return `<span class="mail-avatar"><img src="${escAttr(face.avatar)}" alt=""></span>`;
  return `<span class="mail-avatar">${esc(face.initials||mailInitials(name,addr))}</span>`;
}
function mailOpen(index){
  const m=MAIL_MSGS[index]; if(!m) return;
  MAIL_OPEN=m.id;
  const split=document.querySelector('.mail-split'); if(split) split.classList.add('reading');
  const routeClass=m.status==='failed'?'failed':(m.route||'internal');
  const routeLabel=m.status==='failed'?'not sent':(m.route==='internal'?'internal':'external');
  const who=m.direction==='in'?(m.from_name||m.from_addr):m.to_addr;
  const addr=m.direction==='in'?m.from_addr:m.to_addr;
  $('mail-read').innerHTML=`
    <div class="mail-read-subject">${esc(m.subject||'(no subject)')}</div>
    <div class="mail-read-meta">
      ${mailFace(addr, m.from_name)}
      <span><span class="mail-who-name">${esc(who||'unknown')}</span><br>
        <span class="mail-who-addr">${esc(addr||'')}</span></span>
      <span class="mail-route ${routeClass}">${esc(routeLabel)}</span>
      <span class="mail-item-when" style="margin-left:auto;">${esc(m.ts)}</span>
    </div>
    ${m.status==='failed'&&m.detail?`<div class="cf-missing">${esc(m.detail)}</div>`:''}
    <div class="mail-read-body">${esc(m.body||'(empty message)')}</div>
    <div class="mail-read-acts">
      <button class="save-btn" onclick="mailReply(${index})"><svg class="ic"><use href="#ic-send"/></svg>Reply</button>
      <button class="db-action-btn" onclick="mailMarkUnread(${m.id})">Mark unread</button>
      <button class="db-action-btn cf-danger" onclick="mailDelete(${m.id})">Delete</button>
    </div>`;
  if(m.unread&&m.direction==='in'){
    m.unread=false; renderMailList();
    mailPost('/api/mail/read',{id:m.id,read:true}).then(()=>refreshMailBadge());
  }
}
async function mailMarkUnread(id){
  await mailPost('/api/mail/read',{id,read:false});
  loadMail();
}
async function mailDelete(id){
  if(!(await uiConfirm('Delete this message?','It is removed from this panel.'))) return;
  try{
    const r=await api('/api/mail/message/'+id,{method:'DELETE'});
    if(!r.ok){ appToast('Could not delete it','err'); return; }
    MAIL_OPEN=null;
    $('mail-read').innerHTML=mailNothingOpenHtml();
    appToast('Deleted','ok'); loadMailMessages(); refreshMailBadge();
  }catch(e){ appToast('Network error','err'); }
}
async function mailSync(){
  const boxes=(MAIL.boxes||[]).filter(b=>b.server_side);
  if(!boxes.length){ appToast('No mailbox on the mail server to collect from','warn'); return; }
  const btn=$('mail-sync-btn'); if(btn){ btn.disabled=true; }
  let added=0;
  for(const b of boxes){
    const d=await mailPost('/api/mail/sync',{address:b.address});
    if(d) added+=d.added||0;
  }
  if(btn) btn.disabled=false;
  appToast(added?added+' new message(s)':'Nothing new', added?'ok':'info');
  loadMail();
}

/* ---- writing ---- */
function mailCompose(prefill){
  const boxes=MAIL.boxes||[]; if(!boxes.length) return;
  const from=boxes[0];
  const mine=MAIL.me||{};
  $('mail-from-row').innerHTML=`
    ${mailFace(from.address, from.full_name)}
    <span><span class="mail-who-name">${esc(from.full_name||mine.full_name||MAIL.username||'')}</span><br>
      <span class="mail-who-addr">${esc(from.address)}</span></span>`;
  $('mail-from-row').dataset.address=from.address;
  $('mail-to').value=(prefill&&prefill.to)||'';
  $('mail-subject').value=(prefill&&prefill.subject)||'';
  $('mail-body').value=(prefill&&prefill.body)||'';
  mailFeedback('mail-send-feedback',true,'');
  cfShow('mail-compose-card', true);
  mailSyncRouteHint();
  $('mail-to').focus();
}
function mailCloseCompose(){ cfShow('mail-compose-card', false); }
function mailReply(index){
  const m=MAIL_MSGS[index]; if(!m) return;
  const quoted=(m.body||'').split('\n').map(l=>'> '+l).join('\n');
  mailCompose({to:m.direction==='in'?m.from_addr:m.to_addr,
               subject:/^re:/i.test(m.subject||'')?m.subject:'Re: '+(m.subject||''),
               body:'\n\n'+quoted});
}
function mailRoute(){
  const el=document.querySelector('input[name="mail-route"]:checked');
  return el?el.value:'internal';
}
function mailSyncRouteHint(){
  const hint=$('mail-to-hint'); if(!hint) return;
  if(mailRoute()==='internal'){
    hint.textContent='Internal: the address has to be one on this system, and the '
      +'message never touches the relay.';
  } else if(!MAIL.outbound_ready){
    hint.textContent='External mail has no relay configured yet, so this cannot be sent.';
  } else {
    hint.textContent='External: handed to the relay and delivered outside.';
  }
}
async function mailSend(){
  const from=$('mail-from-row').dataset.address||'';
  const payload={from, to:($('mail-to').value||'').trim(),
                 subject:($('mail-subject').value||'').trim(),
                 body:$('mail-body').value||'', route:mailRoute()};
  if(!payload.to){ mailFeedback('mail-send-feedback',false,'Who is it going to?'); return; }
  const btn=$('mail-send'); if(btn){ btn.disabled=true; btn.textContent='Sending…'; }
  const d=await mailPost('/api/mail/send',payload,'mail-send-feedback');
  if(btn){ btn.disabled=false; btn.textContent='Send'; }
  if(d){
    appToast(d.route==='internal'?'Delivered internally':'Handed to the relay','ok');
    mailCloseCompose();
    MAIL_FOLDER='sent'; mailFolder('sent');
    loadMail();
  }
}

/* ---- the badge ---- */
function setMailBadge(count){
  [['mail-badge'],['mail-badge-m']].forEach(([id])=>{
    const el=$(id); if(!el) return;
    el.textContent=count>99?'99+':String(count);
    el.hidden=!count;
  });
  const inbox=$('mail-inbox-count');
  if(inbox){ inbox.textContent=count?String(count):''; inbox.style.display=count?'':'none'; }
}
async function refreshMailBadge(){
  if(!$('mail-badge')&&!$('mail-badge-m')) return;
  try{
    const d=await getJSON('/api/mail/unread');
    if(d) setMailBadge(d.unread||0);
  }catch(e){ /* the badge is not worth a message */ }
}
function startMailBadgePolling(){
  if(_mailBadgeTimer) return;
  refreshMailBadge();
  /* A minute is often enough for a mailbox and rare enough to be invisible. */
  _mailBadgeTimer=setInterval(refreshMailBadge, 60000);
}

/* ================= CLOUDFLARE TUNNEL =================
   Four steps, and which one you are on is decided by the server's answer
   rather than by clicking through: no account means step 1, an account and
   no tunnel means step 2, and so on. A step that is not reachable yet is
   dimmed instead of hidden so the whole path is visible from the start.

   While the login link is live the page polls, because the thing being
   waited on happens in a different browser tab and cloudflared exits by
   itself when it is done. The poll stops as soon as the account arrives,
   or when the card is left. */
let CF={}, _cfPoll=null;

function cfStep(id, state, label){
  const step=$('cf-step-'+id); const chip=$('cf-'+state.chip+'-state');
  if(step){
    step.classList.toggle('cf-locked', !!state.locked);
    step.classList.toggle('cf-done', !!state.done);
  }
  if(chip){
    chip.textContent=label;
    chip.className='cf-state'+(state.done?' cf-ok':state.bad?' cf-bad':state.waiting?' cf-wait':'');
  }
}
function cfShow(id, on){ const el=$(id); if(el) el.hidden=!on; }
function cfDisable(id, off){ const el=$(id); if(el) el.disabled=!!off; }

async function loadTunnel(){
  if(!$('cf-card')) return;          /* the card is absent without the grant */
  try{
    const d=await getJSON('/api/config/tunnel'); if(!d) return;
    CF=d;
    renderTunnel();
  }catch(e){
    const fb=$('cf-account-feedback');
    if(fb){ fb.className='save-feedback err'; fb.textContent='Could not read the tunnel state.'; }
  }
}

function renderTunnel(){
  const d=CF||{}, login=d.login||{}, svc=d.service||{};
  const ver=$('cf-version');
  if(ver) ver.textContent=d.version||'';

  const miss=$('cf-missing');
  if(miss){
    if(!d.installed){
      miss.hidden=false;
      miss.textContent='cloudflared is not installed on this server, so tunnels cannot be created. '
        +'Run the installer again, or install cloudflared by hand, and reload this page.';
    } else { miss.hidden=true; }
  }

  /* 1. account */
  const connected=!!d.logged_in, waiting=login.state==='waiting'&&!!login.url;
  cfStep('account', {chip:'account', done:connected, waiting:waiting,
                     bad:login.state==='error', locked:!d.installed},
         connected?'connected':waiting?'waiting':login.state==='error'?'failed':'not connected');
  cfShow('cf-account-idle', d.installed&&!connected&&!waiting);
  cfShow('cf-link-row', waiting);
  cfShow('cf-account-done', connected);
  const link=$('cf-link');
  if(link&&waiting){ link.href=login.url; link.textContent=login.url; }
  const afb=$('cf-account-feedback');
  if(afb&&login.error&&!connected){ afb.className='save-feedback err'; afb.textContent=login.error; }
  else if(afb&&!login.error){ afb.textContent=''; afb.className='save-feedback'; }
  if(waiting) cfStartPoll(); else cfStopPoll();

  /* 2. tunnels */
  const tunnels=d.tunnels||[], remote=d.remote||[], active=d.active||'';
  const conns={}; remote.forEach(t=>{ conns[t.name]=t; });
  cfStep('tunnel', {chip:'tunnel', done:tunnels.length>0, locked:!connected},
         tunnels.length?(tunnels.length+' created'):'none yet');
  const list=$('cf-tunnel-list');
  if(list){
    if(!tunnels.length){
      list.innerHTML='<div class="empty-state">No tunnel yet. One tunnel can carry as many hostnames as you like, so a single one named after this server is usually enough.</div>';
    } else {
      list.innerHTML=tunnels.map(t=>{
        const r=conns[t.name]||null;
        const bits=[t.tunnel_id?t.tunnel_id:'id unknown'];
        if(r) bits.push(r.connections?(r.connections+' live connection'+(r.connections>1?'s':'')):'not connected');
        else if(d.remote_error) bits.push('Cloudflare could not be asked');
        else bits.push('not at Cloudflare any more');
        return `<div class="cf-row">
          <div class="cf-row-main">
            <div class="cf-row-name">${esc(t.name)}${t.name===active?' <span class="cf-badge">runs here</span>':''}</div>
            <div class="cf-row-sub">${esc(bits.join(' · '))}</div>
          </div>
          <div class="cf-row-acts">
            ${t.name===active?'':`<button class="db-action-btn" onclick="tunnelSetActive('${escAttr(t.name)}')">Run this one</button>`}
            <button class="db-action-btn cf-danger" onclick="tunnelDelete('${escAttr(t.name)}')">Delete</button>
          </div></div>`;
      }).join('');
    }
  }
  cfDisable('cf-tunnel-create', !connected);

  /* 3. forwards */
  const routes=d.routes||[];
  cfStep('forward', {chip:'route', done:routes.length>0, locked:!tunnels.length},
         routes.length?(routes.length+' forward'+(routes.length>1?'s':'')):'none yet');
  const rlist=$('cf-route-list');
  if(rlist){
    if(!routes.length){
      rlist.innerHTML='<div class="empty-state">Nothing is forwarded yet. Pick the name people will type and the port it should reach on this machine.</div>';
    } else {
      rlist.innerHTML=routes.map(r=>`<div class="cf-row">
        <div class="cf-row-main">
          <div class="cf-row-name">${esc(r.hostname)}<span class="cf-arrow"> &rarr; </span>${esc(r.local_host)}:${esc(r.local_port)}</div>
          <div class="cf-row-sub">${esc(r.tunnel)} · ${r.dns_ok?'DNS record in place':'DNS record missing'+(r.detail?': '+r.detail:'')}</div>
        </div>
        <div class="cf-row-acts">
          <button class="db-action-btn cf-danger" onclick="tunnelDeleteRoute('${escAttr(r.hostname)}')">Remove</button>
        </div></div>`).join('');
    }
  }
  cfDisable('cf-route-add', !tunnels.length);

  /* 4. running */
  const running=!!svc.active;
  cfStep('run', {chip:'service', done:running, bad:svc.installed&&!running,
                 locked:!routes.length},
         running?'running':svc.installed?(svc.state||'stopped'):'not installed');
  const note=$('cf-service-note');
  if(note){
    note.textContent=running
      ? 'The tunnel is up and will come back by itself after a reboot.'
      : svc.installed
        ? 'The service is installed but not running right now.'
        : 'Installed as a service, the tunnel comes back by itself after a reboot.';
  }
  cfDisable('cf-svc-install', !routes.length);
  cfDisable('cf-svc-restart', !svc.installed);
  cfDisable('cf-svc-stop', !running);
  cfDisable('cf-svc-remove', !svc.installed);
}

function cfStartPoll(){
  if(_cfPoll) return;
  _cfPoll=setInterval(async()=>{
    if(!$('cf-card')||CURRENT!=='config'){ cfStopPoll(); return; }
    try{
      const s=await getJSON('/api/config/tunnel/login'); if(!s) return;
      if(s.state==='connected'){ cfStopPoll(); appToast('Cloudflare account connected','ok'); loadTunnel(); return; }
      if(s.state!=='waiting'){ cfStopPoll(); CF.login=s; renderTunnel(); }
    }catch(e){ /* a poll that fails is not worth a message; the next one may work */ }
  }, 3000);
}
function cfStopPoll(){ if(_cfPoll){ clearInterval(_cfPoll); _cfPoll=null; } }

function cfFeedback(id, ok, text){
  const fb=$(id); if(!fb) return;
  fb.className='save-feedback '+(ok?'ok':'err');
  fb.textContent=text;
}

async function tunnelLogin(){
  const btn=$('cf-login'); if(btn){ btn.disabled=true; btn.textContent='Asking Cloudflare…'; }
  try{
    const r=await api('/api/config/tunnel/login',{method:'POST'});
    const d=await r.json();
    if(!r.ok||d.error){ cfFeedback('cf-account-feedback', false, d.error||'Could not start the login.'); return; }
    CF.login=d;
    if(d.state==='connected'){ loadTunnel(); return; }
    renderTunnel();
  }catch(e){ cfFeedback('cf-account-feedback', false, 'Network error.'); }
  finally{ if(btn){ btn.disabled=false; btn.textContent='Create the link'; } }
}

function tunnelCopyLink(){
  const link=$('cf-link');
  if(link&&link.href) copyVal(link.href,'Login link');
}

async function tunnelDisconnect(){
  if(!(await uiConfirm('Disconnect this Cloudflare account?','Tunnels stay at Cloudflare, but this server cannot manage them until it signs in again.'))) return;
  try{
    const r=await api('/api/config/tunnel/disconnect',{method:'POST'});
    const d=await r.json();
    if(!r.ok){ cfFeedback('cf-account-feedback', false, d.error||'Could not disconnect.'); return; }
    appToast('Account disconnected','ok'); loadTunnel();
  }catch(e){ cfFeedback('cf-account-feedback', false, 'Network error.'); }
}

async function tunnelCreate(){
  const input=$('cf-tunnel-name'); const name=(input?input.value:'').trim().toLowerCase();
  if(!name){ cfFeedback('cf-tunnel-feedback', false, 'Give the tunnel a name.'); return; }
  const btn=$('cf-tunnel-create'); if(btn) btn.disabled=true;
  try{
    const r=await api('/api/config/tunnel/create',{method:'POST',
      headers:{'Content-Type':'application/json'}, body:JSON.stringify({name})});
    const d=await r.json();
    if(!r.ok){ cfFeedback('cf-tunnel-feedback', false, d.error||'Could not create the tunnel.'); return; }
    if(input) input.value='';
    cfFeedback('cf-tunnel-feedback', true, d.message||'Tunnel created.');
    loadTunnel();
  }catch(e){ cfFeedback('cf-tunnel-feedback', false, 'Network error.'); }
  finally{ if(btn) btn.disabled=false; }
}

async function tunnelSetActive(name){
  try{
    const r=await api('/api/config/tunnel/active',{method:'POST',
      headers:{'Content-Type':'application/json'}, body:JSON.stringify({name})});
    const d=await r.json();
    if(!r.ok){ cfFeedback('cf-tunnel-feedback', false, d.error||'Could not switch tunnel.'); return; }
    appToast(name+' will be the one that runs','ok'); loadTunnel();
  }catch(e){ cfFeedback('cf-tunnel-feedback', false, 'Network error.'); }
}

async function tunnelDelete(name){
  if(!(await uiConfirm('Delete the tunnel '+name+'?','Every hostname forwarded through it stops working.'))) return;
  try{
    const r=await api('/api/config/tunnel/'+encodeURIComponent(name),{method:'DELETE'});
    const d=await r.json();
    if(!r.ok){ cfFeedback('cf-tunnel-feedback', false, d.error||'Could not delete the tunnel.'); return; }
    appToast('Tunnel deleted','ok'); loadTunnel();
  }catch(e){ cfFeedback('cf-tunnel-feedback', false, 'Network error.'); }
}

async function tunnelAddRoute(){
  const tunnel=(CF.active||((CF.tunnels||[])[0]||{}).name||'');
  const hostname=($('cf-hostname').value||'').trim().toLowerCase();
  const local_host=($('cf-local-host').value||'').trim().toLowerCase();
  const local_port=($('cf-local-port').value||'').trim();
  if(!tunnel){ cfFeedback('cf-route-feedback', false, 'Create a tunnel first.'); return; }
  if(!hostname||!local_port){ cfFeedback('cf-route-feedback', false, 'A hostname and a local port are both needed.'); return; }
  const btn=$('cf-route-add'); if(btn){ btn.disabled=true; btn.textContent='Adding…'; }
  try{
    const r=await api('/api/config/tunnel/route',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({tunnel, hostname, local_host:local_host||'127.0.0.1', local_port})});
    const d=await r.json();
    if(!r.ok){ cfFeedback('cf-route-feedback', false, d.error||'Could not add the forward.'); loadTunnel(); return; }
    $('cf-hostname').value=''; $('cf-local-port').value='';
    cfFeedback('cf-route-feedback', true, d.message||'Forward added.');
    loadTunnel();
  }catch(e){ cfFeedback('cf-route-feedback', false, 'Network error.'); }
  finally{ if(btn){ btn.disabled=false; btn.textContent='Add forward'; } }
}

async function tunnelDeleteRoute(hostname){
  if(!(await uiConfirm('Stop forwarding '+hostname+'?','The DNS record at Cloudflare is left in place.'))) return;
  try{
    const r=await api('/api/config/tunnel/route/'+encodeURIComponent(hostname),{method:'DELETE'});
    const d=await r.json();
    if(!r.ok){ cfFeedback('cf-route-feedback', false, d.error||'Could not remove the forward.'); return; }
    appToast('Forward removed','ok'); loadTunnel();
  }catch(e){ cfFeedback('cf-route-feedback', false, 'Network error.'); }
}

async function tunnelService(action){
  if(action==='uninstall'&&!(await uiConfirm('Remove the tunnel service?','The tunnel stops and will not come back after a reboot.'))) return;
  const ids={install:'cf-svc-install', restart:'cf-svc-restart', stop:'cf-svc-stop', uninstall:'cf-svc-remove'};
  const btn=$(ids[action]); const label=btn?btn.textContent:'';
  if(btn){ btn.disabled=true; btn.textContent='Working…'; }
  try{
    const r=await api('/api/config/tunnel/service',{method:'POST',
      headers:{'Content-Type':'application/json'}, body:JSON.stringify({action})});
    const d=await r.json();
    if(!r.ok){ cfFeedback('cf-service-feedback', false, d.error||'That did not work.'); return; }
    cfFeedback('cf-service-feedback', true, d.message||'Done.');
    loadTunnel();
  }catch(e){ cfFeedback('cf-service-feedback', false, 'Network error.'); }
  finally{ if(btn){ btn.disabled=false; btn.textContent=label; } }
}

/* ================= FIREWALL SETTINGS ================= */
async function loadFirewall(){
  if(!$('px-fw-in')) return;   /* the card is absent without the grant */
  try{
    const d=await getJSON('/api/config/firewall'); if(!d) return;
    const st=d.status||{};
    const backend=st.backend?st.backend:'none';
    const bits=[`Backend: ${backend==='none'?'no firewall tool found, rules are recorded only':esc(backend)}`,
                `SSH auto-block: ${d.ssh_limit} failures within ${d.ssh_window_minutes} minutes`];
    $('px-fw-status').innerHTML=bits.map(b=>`<span>${b}</span>`).join('');

    const rules=d.rules||[];
    const draw=(dir, el)=>{
      const rows=rules.filter(r=>r.direction===dir);
      if(!rows.length){ el.innerHTML=`<div class="empty-state">No ${dir==='in'?'inbound':'outbound'} rules.</div>`; return; }
      el.innerHTML=rows.map(r=>`<div class="px-fw-rule">
        <div class="px-fw-rule-info">
          <div class="px-fw-rule-port">${r.port}/${esc(r.protocol)}</div>
          ${r.note?`<div class="px-fw-rule-note" title="${escAttr(r.note)}">${esc(r.note)}</div>`:''}
        </div>
        ${r.auto?'<span class="px-fw-auto">auto</span>':''}
        <span class="px-switch" title="${r.enabled?'Allowed':'Closed'}">
          <input type="checkbox"${r.enabled?' checked':''}
                 onchange="toggleFirewallRule(${r.port},'${escAttr(r.protocol)}','${escAttr(r.direction)}',this)">
          <span class="px-switch-track"><span class="px-switch-knob"></span></span>
        </span>
        <button class="db-action-btn" style="color:var(--danger);" title="Delete this rule"
                onclick="deleteFirewallRule(${r.port},'${escAttr(r.protocol)}','${escAttr(r.direction)}')">
          <svg class="ic"><use href="#ic-trash-2"/></svg></button>
      </div>`).join('');
    };
    draw('in', $('px-fw-in'));
    draw('out', $('px-fw-out'));

    const blocks=d.blocks||[];
    $('px-fw-blocks').innerHTML=blocks.length?blocks.map(b=>`<div class="px-fw-block">
      <div style="flex:1;min-width:0;">
        <div class="px-fw-block-ip">${esc(b.ip)}</div>
        <div class="px-fw-block-why">${esc(b.reason||'no reason recorded')}${b.source?' &middot; '+esc(b.source):''}</div>
      </div>
      <button class="db-action-btn" onclick="unblockFirewallIp('${escAttr(b.ip)}')">Unblock</button>
    </div>`).join(''):'<div class="empty-state">Nothing is blocked.</div>';
  }catch(e){
    $('px-fw-in').innerHTML='<div class="empty-state">Failed to load.</div>';
  }
}
async function addFirewallRule(){
  const fb=$('px-fw-feedback'), btn=$('px-fw-add');
  fb.textContent=''; fb.className='save-feedback';
  const port=parseInt($('px-fw-port').value||'0',10);
  if(!port){ fb.textContent='Enter a port number.'; fb.classList.add('err'); return; }
  btn.disabled=true;
  const body={port, protocol:$('px-fw-protocol').value, direction:$('px-fw-direction').value,
              enabled:true, note:$('px-fw-note').value.trim()};
  try{
    const r=await api('/api/config/firewall/rule',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    if(!r.ok){ fb.textContent=d.error||'Could not add the rule.'; fb.classList.add('err'); }
    else{
      fb.textContent=d.enforced?'Rule added and applied.':'Rule recorded. '+(d.detail||'The firewall did not apply it.');
      fb.classList.add(d.enforced?'ok':'err');
      $('px-fw-port').value=''; $('px-fw-note').value='';
      loadFirewall();
    }
  }catch(e){ fb.textContent='Network error'; fb.classList.add('err'); }
  btn.disabled=false;
}
async function toggleFirewallRule(port, protocol, direction, el){
  const enabled=el.checked;
  try{
    const r=await api('/api/config/firewall/rule',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({port, protocol, direction, enabled})});
    const d=await r.json();
    if(!r.ok){ appToast(d.error||'Could not change the rule','err'); el.checked=!enabled; return; }
    appToast(enabled?`Port ${port} allowed`:`Port ${port} closed`,'ok');
  }catch(e){ appToast('Network error','err'); el.checked=!enabled; }
}
async function deleteFirewallRule(port, protocol, direction){
  if(!(await uiConfirm(`Delete the ${direction==='in'?'inbound':'outbound'} rule for ${port}/${protocol}?`,
      'The port goes back to whatever the firewall default is.'))) return;
  try{
    const r=await api('/api/config/firewall/rule',{method:'DELETE',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({port, protocol, direction})});
    const d=await r.json();
    if(!r.ok){ appToast(d.error||'Delete failed','err'); return; }
    appToast('Rule deleted','ok'); loadFirewall();
  }catch(e){ appToast('Network error','err'); }
}
async function unblockFirewallIp(ip){
  if(!(await uiConfirm(`Unblock ${ip}?`,'It will be able to reach this server again.'))) return;
  try{
    const r=await api('/api/system/ssh-unblock',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})});
    const d=await r.json();
    if(!r.ok){ appToast(d.error||'Could not unblock','err'); return; }
    appToast('Unblocked','ok'); loadFirewall();
  }catch(e){ appToast('Network error','err'); }
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
        <td><span style="font-weight:700;color:${on?'var(--success)':(s.active==='failed'?'var(--danger)':'var(--gray-500)')}">${esc(s.active)}</span><span style="color:var(--gray-500);font-size:11px;"> / ${esc(s.sub)}</span></td>
        <td style="color:var(--gray-600);">${esc(s.description)}</td>
        <td style="white-space:nowrap;"><button class="db-action-btn" onclick="svc('${esc(s.short)}','restart')">Restart</button>
          ${on?`<button class="db-action-btn" style="border-color:var(--danger);color:var(--danger);" onclick="svc('${esc(s.short)}','stop')">Stop</button>`:`<button class="db-action-btn" style="border-color:var(--success);color:var(--success);" onclick="svc('${esc(s.short)}','start')">Start</button>`}
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
  _srvDetailKind=null; $('srv-detail-title').textContent='Service, '+name; $('srv-detail-overlay').classList.add('open');
  const b=$('srv-detail-body'); b.innerHTML='<div class="empty-state">Loading…</div>';
  const d=await getJSON('/api/services/'+encodeURIComponent(name)); if(!d) return;
  b.innerHTML=`<div style="margin-bottom:8px;">active: <b>${esc(d.active)}</b> · on boot: <b>${esc(d.enabled)}</b></div>
    <pre style="background:var(--gray-50);border:1px solid var(--gray-200);border-radius:6px;padding:12px;max-height:56vh;overflow:auto;font-size:12px;white-space:pre-wrap;font-family:var(--mono);">${esc(d.status||'')}</pre>`;
}

/* ================= LOGS (security + panel actions) ================= */
let _secSection='panel-actions', _secSSHData=null, _secCounts={};
const LOG_CAT_DEFAULT_SECTION={ssh:'ssh-sessions',web:'access-log',server:'panel-actions'};
function showLogCategory(cat){
  document.querySelectorAll('.log-cat-tab').forEach(b=>b.classList.toggle('active',b.dataset.logcat===cat));
  document.querySelectorAll('.sec-cat-group').forEach(g=>{ g.hidden=(g.dataset.logcat!==cat); });
  showSecSection(LOG_CAT_DEFAULT_SECTION[cat]||'panel-actions');
}
function showSecSection(name){
  _secSection=name;
  document.querySelectorAll('.sec-section-btn').forEach(b=>b.classList.toggle('active',b.dataset.sec===name));
  renderSecSection();
}
function secHeader(label,clearKind,liveNote){
  const n=_secCounts[clearKind]; const total=(n===undefined||n===null)?'n/a':n.toLocaleString();
  const clearBtn=clearKind?`<button class="db-action-btn" style="border-color:var(--danger);color:var(--danger);" onclick="clearSecLog('${clearKind}','${esc(label)}')"><svg class="ic"><use href="#ic-trash-2"/></svg>Clear ${esc(label)}</button>`:'';
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
/* The range control drives both the tiles and the SSH event list, so the
   numbers and the rows below them always describe the same window. The server
   resolves the range name; sending it raw would let a query string pick an
   interval. */
function secRange(){
  const el=document.querySelector('input[name="sec-range"]:checked');
  return el?el.value:'today';
}
const SEC_RANGE_SINCE={today:'today','3days':'3 days ago',week:'7 days ago',month:'30 days ago'};

async function loadSecurityLogs(){
  const range=secRange();
  const since=SEC_RANGE_SINCE[range]||'today';
  $('sec-content').innerHTML='<div class="empty-state">Loading…</div>';
  try{
    const [sshRes,webRes,cntRes,sumRes]=await Promise.all([
      api('/api/system/ssh-logs?limit=300&since='+encodeURIComponent(since)),
      api('/api/system/web-login-logs?limit=100'),
      api('/api/system/log-counts'),
      api('/api/system/security-summary?range='+encodeURIComponent(range))]);
    try{ _secCounts=await cntRes.json()||{}; }catch(_){ _secCounts={}; }
    _secSSHData=await sshRes.json(); const webData=await webRes.json();
    _secSSHData._webLogs=webData.logs||[]; _secSSHData._webTotal=webData.total||0;
    _secSSHData._webSuccess=webData.success||0; _secSSHData._webFailed=webData.failed||0;

    let sum={}; try{ sum=await sumRes.json()||{}; }catch(_){}
    const n=v=>(v==null?'n/a':Number(v).toLocaleString());
    const win=(sum.range_label||'today').toLowerCase();
    $('sec-ssh-ok').textContent=n(sum.ssh_success);
    $('sec-ssh-bad').textContent=n(sum.ssh_failed);
    $('sec-web-ok').textContent=n(sum.web_success);
    $('sec-web-bad').textContent=n(sum.web_failed);
    $('sec-ssh-ok-foot').textContent='accepted over SSH, '+win;
    $('sec-ssh-bad-foot').textContent='refused over SSH, '+win;
    $('sec-web-ok-foot').textContent='signed in here, '+win;
    $('sec-web-bad-foot').textContent='wrong credentials, '+win;
    _secBlocked={ips:sum.blocked_ips||0,devices:sum.blocked_devices||0,sessions:sum.active_sessions||0};
  }catch(e){ _secSSHData={error:String(e)}; }
  renderSecSection();
}
let _secBlocked={ips:0,devices:0,sessions:0};
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
    const rows=(_secSSHData.current_sessions||[]).map(s=>`<tr><td>${esc(s.remote)}</td><td>${esc(s.local)}</td><td>${esc(s.process)}</td><td>${esc(s.pid??'n/a')}</td></tr>`).join('');
    c.innerHTML=secHeader('SSH Events','ssh','Live SSH connections on port 22 right now.')+`<table><thead><tr><th>Remote IP:Port</th><th>Local</th><th>Process</th><th>PID</th></tr></thead><tbody>${rows||'<tr><td colspan="4" style="color:var(--gray-400);text-align:center;">No active SSH sessions.</td></tr>'}</tbody></table>`; return;
  }
  if(_secSection==='ssh-accepted'){
    const rows=(_secSSHData.accepted||[]).slice(0,100).map(e=>`<tr><td style="white-space:nowrap;">${esc(e.ts)}</td><td><b>${esc(e.ip??'n/a')}</b></td><td>${esc(e.user??'n/a')}</td><td>${esc(e.method??'n/a')}</td><td>${esc(e.port??'n/a')}</td></tr>`).join('');
    c.innerHTML=secHeader('SSH Events','ssh',`${(_secSSHData.accepted||[]).length} successful SSH logins.`)+`<table><thead><tr><th>Timestamp</th><th>IP</th><th>User</th><th>Method</th><th>Port</th></tr></thead><tbody>${rows||'<tr><td colspan="5" style="color:var(--gray-400);text-align:center;">No successful logins.</td></tr>'}</tbody></table>`; return;
  }
  if(_secSection==='ssh-fingerprints'){
    const rows=(_secSSHData.fingerprints||[]).slice(0,100).map(e=>`<tr><td style="white-space:nowrap;">${esc(e.ts)}</td><td>${esc(e.ip??'n/a')}</td><td style="font-family:monospace;font-size:11px;">${esc(e.fingerprint??'n/a')}</td></tr>`).join('');
    c.innerHTML=secHeader('SSH Events','ssh','SSH key fingerprints presented during authentication.')+`<table><thead><tr><th>Timestamp</th><th>IP</th><th>Fingerprint</th></tr></thead><tbody>${rows||'<tr><td colspan="3" style="color:var(--gray-400);text-align:center;">No fingerprint events.</td></tr>'}</tbody></table>`; return;
  }
  if(_secSection==='ssh-top-ips'){
    const rows=(_secSSHData.ip_stats||[]).map(s=>`<tr><td style="cursor:pointer;text-decoration:underline dotted;" onclick="sshAttacker('${escAttr(s.ip)}')"><b>${esc(s.ip)}</b></td><td>${s.attempts}</td><td style="color:${s.success>0?'var(--success)':'var(--danger)'}">${s.success>0?s.success+' ✓':'0'}</td><td style="color:var(--gray-600);font-size:11px;">${esc(s.last_seen)}</td><td><button class="db-action-btn" style="border-color:var(--danger);color:var(--danger);font-size:11px;padding:2px 8px;" onclick="sshBlock('${escAttr(s.ip)}')">Block device</button></td></tr>`).join('');
    c.innerHTML=secHeader('SSH Events','ssh','Top IPs by connection attempts (green = got in). Click an IP to see what it tried.')+`<table><thead><tr><th>IP</th><th>Attempts</th><th>Success</th><th>Last Seen</th><th>Action</th></tr></thead><tbody>${rows||'<tr><td colspan="5" style="color:var(--gray-400);text-align:center;">No data.</td></tr>'}</tbody></table>`; return;
  }
  if(_secSection==='ssh-events'){
    /* Every row that names an address carries a Block action. Seeing a source
       hammering the log and then having to go find it in another section to do
       anything about it is where the old layout gave up. */
    const rows=(_secSSHData.events||[]).slice(0,200).map(e=>{ const color=e.event==='ACCEPTED'?'var(--success)':e.event==='FAILED'?'var(--danger)':'var(--gray-600)';
      const act=e.ip?`<button class="db-action-btn" style="border-color:var(--danger);color:var(--danger);font-size:11px;padding:2px 8px;" onclick="sshBlock('${escAttr(e.ip)}')">Block IP</button>`:'';
      return `<tr><td style="white-space:nowrap;font-size:11px;">${esc(e.ts)}</td><td style="color:${color};font-weight:${e.event==='ACCEPTED'?'700':'400'}">${esc(e.event)}</td><td style="cursor:pointer;text-decoration:underline dotted;" onclick="sshAttacker('${escAttr(e.ip||'')}')">${esc(e.ip??'n/a')}</td><td>${esc(e.user??'n/a')}</td><td>${esc(e.method??'n/a')}</td><td style="font-family:monospace;font-size:10px;">${esc(e.fingerprint??'')}</td><td>${act}</td></tr>`;}).join('');
    c.innerHTML=secHeader('SSH Events','ssh',`All SSH events (most recent first), persisted across journald rotation. ${_secSSHData.autoblock_note||''}`)+`<table><thead><tr><th>Timestamp</th><th>Event</th><th>IP</th><th>User</th><th>Method</th><th>Fingerprint</th><th>Action</th></tr></thead><tbody>${rows||'<tr><td colspan="7" style="color:var(--gray-400);text-align:center;">No events.</td></tr>'}</tbody></table>`; return;
  }
  if(_secSection==='web-logs'){
    /* The attempted password used to have a column here. It is no longer stored:
       people mistype, so it was a plaintext password store readable by anyone
       with the Logs grant. What replaced it is the device, which is what you
       actually need to know when the same machine keeps trying. */
    const rows=(_secSSHData._webLogs||[]).map((e,i)=>{ const ok=e.success;
      const dev=e.fingerprint?`<span title="${escAttr((e.fingerprint||'')+' · '+(e.fp_hash||''))}">${esc(e.fingerprint)}</span>`:'<span style="color:var(--gray-400);">not recorded</span>';
      const act=e.ip?`<button class="db-action-btn" style="border-color:var(--danger);color:var(--danger);font-size:11px;padding:2px 8px;" onclick="sshBlock('${escAttr(e.ip)}')">Block IP</button>`:'';
      return `<tr style="${!ok?'background:color-mix(in srgb, var(--danger) 4%, transparent)':''}"><td style="white-space:nowrap;font-size:11px;cursor:pointer;text-decoration:underline dotted;" onclick="openLineDetail('Web login',_secSSHData._webLogs[${i}])">${esc(String(e.ts).slice(0,19))}</td><td style="cursor:pointer;text-decoration:underline dotted;" onclick="openIpDetail('${escAttr(e.ip)}')"><b>${esc(e.ip)}</b></td><td style="font-family:monospace;">${esc(e.username??'n/a')}</td><td style="color:${ok?'var(--success)':'var(--danger)'};font-weight:700">${ok?'OK':'FAIL'}</td><td style="font-size:11px;">${dev}</td><td style="font-size:11px;color:var(--gray-600);">${esc(e.details??'')}</td><td>${act}</td></tr>`;}).join('');
    c.innerHTML=secHeader('Web Login Logs','web_logins',`Panel login history, ${_secSSHData._webTotal??0} total · ${_secSSHData._webSuccess??0} ok · ${_secSSHData._webFailed??0} failed. ${_secBlocked.ips} address(es) and ${_secBlocked.devices} device(s) blocked right now.`)+`<table><thead><tr><th>Timestamp</th><th>IP</th><th>Username</th><th>Result</th><th>Device</th><th>Details</th><th>Action</th></tr></thead><tbody>${rows||'<tr><td colspan="7" style="color:var(--gray-400);text-align:center;">No login records.</td></tr>'}</tbody></table>`; return;
  }
}
async function loadPanelActions(c){
  c.innerHTML='<div class="empty-state">Loading panel actions…</div>';
  const lvl=$('pa-level')?.value||'', cat=$('pa-cat')?.value||'', q=$('pa-q')?.value||'';
  const d=await getJSON('/api/logs?level='+lvl+'&category='+cat+'&q='+encodeURIComponent(q)+'&limit=400'); if(!d) return;
  const cc=await getJSON('/api/logs/counts');
  const lvlColor=l=>({INFO:'var(--gray-600)',ACTION:'var(--accent)',WARN:'#b9772a',ERROR:'var(--danger)'}[l]||'var(--gray-600)');
  const rows=(d.logs||[]).map(l=>`<tr>
    <td style="white-space:nowrap;font-size:11px;font-family:var(--mono);color:var(--gray-600);">${esc(l.ts)}</td>
    <td style="font-weight:700;color:${lvlColor(l.level)};">${esc(l.level)}</td>
    <td><span style="font-size:11px;background:var(--gray-100);border-radius:3px;padding:1px 7px;">${esc(l.category)}</span></td>
    <td>${esc(l.action)}${l.target?` <span style="color:var(--gray-500);">→ ${esc(l.target)}</span>`:''}</td>
    <td>${esc(l.actor)}${l.ip?` <span style="color:var(--gray-500);">· ${esc(l.ip)}</span>`:''}</td>
    <td style="color:${l.status==='ok'?'var(--success)':(l.status==='failed'||l.status==='denied'?'var(--danger)':'var(--gray-600)')};font-weight:600;">${esc(l.status)}</td>
    <td style="font-size:11px;font-family:var(--mono);color:var(--gray-600);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escAttr(l.detail)}">${esc((l.detail||'').slice(0,120))}</td></tr>`).join('');
  const b=cc?cc.by_level:{};
  c.innerHTML=`<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
      <span style="font-size:12px;color:var(--gray-600);">Every action and data movement performed through this panel by any user, logins, service control, terminal commands, security actions.</span>
      <span style="margin-left:auto;"></span>
      <select id="pa-level" onchange="loadPanelActions(document.getElementById('sec-content'))" style="padding:5px 8px;border:1px solid var(--gray-200);border-radius:4px;font-size:12px;background:var(--white);color:var(--black);"><option value="">All levels</option><option>INFO</option><option>ACTION</option><option>WARN</option><option>ERROR</option></select>
      <select id="pa-cat" onchange="loadPanelActions(document.getElementById('sec-content'))" style="padding:5px 8px;border:1px solid var(--gray-200);border-radius:4px;font-size:12px;background:var(--white);color:var(--black);"><option value="">All categories</option><option>AUTH</option><option>SERVICE</option><option>TERMINAL</option><option>SYSTEM</option></select>
      <input id="pa-q" placeholder="search…" onkeydown="if(event.key==='Enter')loadPanelActions(document.getElementById('sec-content'))" style="width:140px;padding:5px 8px;border:1px solid var(--gray-200);border-radius:4px;font-size:12px;background:var(--white);color:var(--black);">
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;">
      <span style="font-size:12px;font-weight:700;padding:3px 9px;border-radius:4px;background:var(--gray-100);">${cc?cc.total:0} total</span>
      <span style="font-size:12px;padding:3px 9px;border-radius:4px;background:rgba(122,83,38,.12);color:var(--accent);">${b.ACTION||0} actions</span>
      <span style="font-size:12px;padding:3px 9px;border-radius:4px;background:rgba(185,119,42,.14);color:#b9772a;">${b.WARN||0} warn</span>
      <span style="font-size:12px;padding:3px 9px;border-radius:4px;background:color-mix(in srgb, var(--danger) 12%, transparent);color:var(--danger);">${b.ERROR||0} error</span></div>
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
    const methodColor=m=>({GET:'var(--info)',POST:'var(--success)',DELETE:'var(--danger)',PUT:'var(--warn)',PATCH:'#8e44ad'}[m]||'#555');
    const statusColor=s=>s<300?'var(--success)':s<400?'var(--info)':s<500?'var(--warn)':'var(--danger)';
    const rows=logs.map(r=>{ const ua=r.user_agent||'';
      const browser=ua.match(/Chrome\/[\d.]+/)?'Chrome':ua.match(/Firefox\/[\d.]+/)?'Firefox':ua.match(/Safari\/[\d.]+/)?'Safari':ua.match(/curl/)?'curl':ua.match(/[Pp]ython/)?'Python':ua.match(/bot|crawl|spider/i)?'Bot':ua.slice(0,14)||'n/a';
      const pathCell=r.query?`${esc(r.path)}<span style="color:var(--gray-400);font-size:10px;">?${esc(r.query.slice(0,40))}</span>`:esc(r.path);
      return `<tr><td style="font-size:11px;white-space:nowrap;cursor:pointer;text-decoration:underline dotted;" onclick="openAccessDetail(${r.id})">${esc(String(r.ts).slice(0,19))}</td><td style="cursor:pointer;text-decoration:underline dotted;" onclick="openIpDetail('${escAttr(r.ip)}')"><b>${esc(r.ip)}</b></td><td style="font-weight:700;color:${methodColor(r.method)}">${esc(r.method)}</td><td style="font-family:monospace;font-size:11px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:pointer;text-decoration:underline dotted;" onclick="loadAccessLog(document.getElementById('sec-content'),1,'','${escAttr(r.path)}')">${pathCell}</td><td style="font-weight:700;color:${statusColor(r.status_code)}">${r.status_code}</td><td style="font-size:11px;color:var(--gray-600);">${r.duration_ms??'n/a'}ms</td><td style="font-size:11px;color:var(--gray-600);">${esc(browser)}</td><td style="font-size:11px;color:var(--gray-600);">${esc(r.authed_user||'n/a')}</td></tr>`;}).join('');
    const totalPages=Math.max(1,Math.ceil((d.total||0)/100));
    const prevBtn=page>1?`<button class="db-action-btn" onclick="loadAccessLog(document.getElementById('sec-content'),${page-1})">← Prev</button>`:'';
    const nextBtn=page<totalPages?`<button class="db-action-btn" onclick="loadAccessLog(document.getElementById('sec-content'),${page+1})">Next →</button>`:'';
    const activeFilter=(ipF||pathF)?`<span style="background:rgba(41,128,185,0.1);color:var(--info);padding:2px 8px;border-radius:3px;font-size:11px;margin-left:8px;">${ipF?'IP: '+esc(ipF):''}${ipF&&pathF?' · ':''}${pathF?'Path: '+esc(pathF):''} <span style="cursor:pointer;" onclick="loadAccessLog(document.getElementById('sec-content'),1,'','')">× clear</span></span>`:'';
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
      const statusLabel=isActive?'<span style="color:var(--success);font-weight:700;">● ACTIVE</span>':isExpired?'<span style="color:var(--warn);">EXPIRED</span>':'<span style="color:#999;">LOGGED OUT</span>';
      const ua=s.user_agent||''; const browser=ua.match(/Chrome\/[\d.]+/)?'Chrome':ua.match(/Firefox\/[\d.]+/)?'Firefox':ua.match(/Safari\/[\d.]+/)?'Safari':ua.slice(0,20)||'n/a';
      return `<tr style="${isActive?'background:color-mix(in srgb, var(--success) 5%, transparent)':''}"><td style="font-family:monospace;font-size:11px;" title="${escAttr(s.session_id)}">${esc((s.session_id||'').slice(0,12))}…</td><td style="font-weight:600;">${esc(s.username)}</td><td style="cursor:pointer;text-decoration:underline dotted;" onclick="openIpDetail('${escAttr(s.ip)}')"><b>${esc(s.ip)}</b></td><td style="font-size:11px;color:var(--gray-600);" title="${escAttr(ua)}">${esc(browser)}</td><td style="font-size:11px;white-space:nowrap;">${esc(String(s.login_at).slice(0,19))}</td><td style="font-size:11px;white-space:nowrap;">${esc(String(s.expires_at).slice(0,19))}</td><td style="font-size:11px;white-space:nowrap;">${s.logout_at?esc(String(s.logout_at).slice(0,19)):'<span style="color:var(--gray-400)">n/a</span>'}</td><td>${statusLabel}</td></tr>`;}).join('');
    c.innerHTML=secHeader('Sessions','sessions','Every web login session (active, expired, logged out).')+`
      <div style="display:flex;gap:16px;margin-bottom:14px;flex-wrap:wrap;"><div style="padding:10px 18px;border-radius:6px;border:1px solid var(--gray-200);background:var(--gray-50);"><div style="font-size:11px;color:var(--gray-600);text-transform:uppercase;letter-spacing:.6px;">Active Now</div><div style="font-size:22px;font-weight:700;color:var(--success);">${d.active??0}</div></div><div style="padding:10px 18px;border-radius:6px;border:1px solid var(--gray-200);background:var(--gray-50);"><div style="font-size:11px;color:var(--gray-600);text-transform:uppercase;letter-spacing:.6px;">Total Sessions</div><div style="font-size:22px;font-weight:700;">${d.total??0}</div></div></div>
      <table><thead><tr><th>Session ID</th><th>User</th><th>IP</th><th>Browser</th><th>Login</th><th>Expires</th><th>Logged Out</th><th>Status</th></tr></thead><tbody>${rows||'<tr><td colspan="8" style="color:var(--gray-400);text-align:center;">No sessions yet.</td></tr>'}</tbody></table>`;
  }catch(e){ c.innerHTML=`<div class="empty-state">Error: ${esc(String(e))}</div>`; }
}
async function loadWebBlocked(c){
  try{
    const d=await (await api('/api/system/web-blocked-ips')).json();
    const rows=(d.blocked||[]).map(b=>{ const isB=b.blocked_until&&new Date(b.blocked_until)>new Date();
      return `<tr><td><b>${esc(b.ip)}</b></td><td style="color:var(--danger);font-weight:600;">${b.fail_count}</td><td style="font-size:11px;">${esc(String(b.first_fail).slice(0,19))}</td><td style="font-size:11px;">${esc(String(b.last_fail).slice(0,19))}</td><td style="font-size:11px;">${isB?`<span style="color:var(--danger);font-weight:600;">${esc(String(b.blocked_until).slice(0,19))}</span>`:'<span style="color:var(--gray-400)">n/a</span>'}</td><td style="font-size:11px;color:var(--gray-600);">${esc(b.note??'')}</td><td><button class="db-action-btn" style="color:var(--danger);" onclick="unblockWebIp('${escAttr(b.ip)}',this)">Unblock</button></td></tr>`;}).join('');
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
      return `<tr><td><code style="font-size:11px;">${esc((b.fp_hash||'').slice(0,16))}</code></td><td style="color:var(--danger);font-weight:600;">${b.fail_count}</td><td style="cursor:pointer;text-decoration:underline dotted;" onclick="openIpDetail('${escAttr(b.last_ip||'')}')"><b>${esc(b.last_ip||'n/a')}</b></td><td style="font-size:11px;color:var(--gray-600);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escAttr(b.sample||'')}">${esc(sample.slice(0,60))}</td><td style="font-size:11px;">${esc(String(b.last_fail).slice(0,19))}</td><td style="font-size:11px;">${isB?`<span style="color:var(--danger);font-weight:600;">${esc(String(b.blocked_until).slice(0,19))}</span>`:'<span style="color:var(--gray-400)">expired</span>'}</td><td><button class="db-action-btn" style="color:var(--danger);" onclick="unblockFp('${escAttr(b.fp_hash)}',this)">Unblock</button></td></tr>`;}).join('');
    c.innerHTML=secHeader('Blocked Devices','fp_blocked','Machines locked out by device fingerprint (stay blocked even if IP changes).')+`<table><thead><tr><th>Device fingerprint</th><th>Fails</th><th>Last IP</th><th>Device summary</th><th>Last Attempt</th><th>Blocked Until</th><th>Action</th></tr></thead><tbody>${rows||'<tr><td colspan="7" style="color:var(--gray-400);text-align:center;">No devices blocked.</td></tr>'}</tbody></table>`;
  }catch(e){ c.innerHTML=`<div class="empty-state">Error: ${esc(String(e))}</div>`; }
}
async function unblockFp(fp,btn){ if(btn){ btn.disabled=true; btn.textContent='…'; }
  try{ await api('/api/system/fp-unblock',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({fp_hash:fp})}); loadSecurityLogs(); }
  catch(e){ appToast('Error: '+e,'err'); if(btn){ btn.disabled=false; btn.textContent='Unblock'; } } }
async function sshAttacker(ip){
  try{ const d=await (await api('/api/system/ssh-attacker?ip='+encodeURIComponent(ip))).json();
    openLineDetail('SSH attacker '+ip,{ip:d.ip,usernames_tried:(d.usernames_tried||[]).map(u=>`${u.username} (${u.attempts})`).join(', ')||'n/a',auth_methods:(d.auth_methods||[]).join(', ')||'n/a',key_fingerprints:(d.key_fingerprints||[]).join('  |  ')||'none',events_by_type:Object.entries(d.events_by_type||{}).map(([k,v])=>`${k}: ${v}`).join(' · ')||'n/a',password_note:d.password_note}); }
  catch(e){ appToast('Error: '+e,'err'); } }
async function sshBlock(ip){
  if(!(await appConfirm(`Block SSH IP ${ip} at the OS firewall (iptables DROP)?`,{title:'Block SSH device',danger:true}))) return;
  try{ const d=await (await api('/api/system/ssh-block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip})})).json();
    if(d.firewall_enforced) appToast(`Firewall rule added, ${ip} dropped.`,'ok'); else appToast(`Recorded but NOT enforced: ${d.detail||''}`,'err',7000); }
  catch(e){ appToast('Error: '+e,'err'); } }
async function manualBlockIp(){
  const ip=($('block-ip-input').value||'').trim(), hours=$('block-ip-dur').value, note=($('block-ip-note').value||'').trim()||'Manually blocked', msg=$('block-ip-msg');
  if(!ip){ msg.style.color='var(--danger)'; msg.textContent='Enter an IP address.'; return; }
  msg.style.color='var(--gray-600)'; msg.textContent='Blocking…';
  try{ const d=await (await api('/api/system/web-block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ip,hours:parseInt(hours),note})})).json();
    if(d.status==='blocked'){ msg.style.color='var(--success)'; msg.textContent=`${ip} blocked.`; $('block-ip-input').value=''; $('block-ip-note').value=''; setTimeout(()=>loadWebBlocked($('sec-content')),800); }
    else{ msg.style.color='var(--danger)'; msg.textContent=d.error||'Failed.'; } }
  catch(e){ msg.style.color='var(--danger)'; msg.textContent=String(e); } }
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
  const perms=window.MGMT_PERMS||{}; const termTitle=perms.terminalAccess==='limited'?'Restricted terminal: your own system account':'Root terminal: live interactive shell';
  wrap.innerHTML='<div class="term-bar"><span class="term-title">'+esc(termTitle)+'</span><span class="term-status">connecting…</span>'+
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
  term.onSelectionChange(()=>{ if(!term.hasSelection()) _hideTermCopyBtn(); });
  host.addEventListener('mouseup',(ev)=>{ setTimeout(()=>{ if(term.hasSelection()) _showTermCopyBtn(term,ev.clientX,ev.clientY); },0); });
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
  ws.onclose=()=>{ termSetStatus(tab,'disconnected','dead'); if(tab.term) tab.term.write('\r\n\x1b[90m[disconnected, press Reconnect]\x1b[0m\r\n'); if(tab.ws===ws) tab.ws=null; };
  ws.onerror=()=>termSetStatus(tab,'error','dead');
}
function termTabReconnect(tab){ if(tab.ws){ try{ tab.ws.onclose=null; tab.ws.close(); }catch(e){} tab.ws=null; } if(tab.term) tab.term.reset(); termTabConnect(tab); }

/* Floating copy button that follows a terminal text selection (dash.css
   already ships .term-copy-btn; this just drives it). */
let _termCopyBtn=null;
function _termCopyBtnEl(){
  if(_termCopyBtn) return _termCopyBtn;
  const btn=document.createElement('button'); btn.type='button'; btn.className='term-copy-btn';
  btn.innerHTML='<svg class="ic"><use href="#ic-copy"/></svg>Copy';
  document.body.appendChild(btn);
  document.addEventListener('mousedown',(e)=>{ if(e.target!==btn) _hideTermCopyBtn(); });
  window.addEventListener('scroll',_hideTermCopyBtn,true);
  _termCopyBtn=btn; return btn;
}
function _hideTermCopyBtn(){ if(_termCopyBtn) _termCopyBtn.classList.remove('show'); }
function _showTermCopyBtn(term,x,y){
  const btn=_termCopyBtnEl();
  btn.style.left=Math.max(8,x-30)+'px'; btn.style.top=Math.max(8,y-40)+'px';
  btn.onclick=(e)=>{ e.stopPropagation(); copyVal(term.getSelection(),'Selection'); _hideTermCopyBtn(); };
  btn.classList.add('show');
}
window.addEventListener('resize',()=>{ if(CURRENT==='terminal') termFitActive(); });
window.addEventListener('orientationchange',()=>{ if(CURRENT==='terminal') setTimeout(termFitActive,60); });

/* ================= boot ================= */
/* ================= TELEGRAM BOT =================
   Three things live on this page and they are deliberately in this order: the
   connection, who is allowed, and the log. The log is last because it is what
   you read to answer the middle one: a stranger's numeric ID only ever appears
   because they wrote in, so the Allow buttons sit on that row rather than
   asking anyone to copy a number into a form. */
let TG={};

async function loadTelegram(){
  if(!$('tg-state')) return;   /* the card is absent without the grant */
  try{
    const d=await getJSON('/api/config/telegram'); if(!d) return;
    TG=d;
    const dom=$('tg-domain'); if(dom && document.activeElement!==dom) dom.value=d.domain||'';
    const nt=$('tg-notify'); if(nt && document.activeElement!==nt) nt.value=d.notify_email||'';
    const hint=$('tg-token-hint');
    if(hint) hint.innerHTML = d.token_set
      ? `A token ending ${esc(d.token_hint)} is stored. Type a new one only to replace it.`
      : 'Stored in this panel’s settings and never shown again after saving.';
    tgRenderState(d);
    tgRenderUsers(d.users||[]);
    tgRenderPending(d.pending||[]);
    tgRenderLog(d.log||[]);
  }catch(e){ $('tg-state').textContent='Could not read the bot settings.'; }
}

function tgRenderState(d){
  const el=$('tg-state'); if(!el) return;
  const who=d.identity||{}, hook=d.webhook||{};
  if(!d.token_set){ el.innerHTML='No bot token yet. Paste one above to begin.'; return; }
  const bits=[];
  bits.push(who.ok ? `Connected to <b>@${esc(who.username)}</b>`
                   : `Telegram would not confirm the token: ${esc(who.detail||'')}`);
  if(d.enabled && hook.ok && hook.url) bits.push(`Delivering to <code>${esc(hook.url)}</code>`);
  else if(d.suggested_url) bits.push(`Not receiving anything yet. Connect it to deliver to <code>${esc(d.suggested_url)}</code>`);
  if(hook.pending) bits.push(`${hook.pending} update(s) waiting`);
  if(hook.last_error) bits.push(`Telegram’s last error: ${esc(hook.last_error)}`);
  el.innerHTML=bits.join('<br>');
}

function tgRenderUsers(rows){
  const el=$('tg-users'); if(!el) return;
  if(!rows.length){ el.innerHTML='<div class="empty-state">Nobody may use the bot yet. Anyone who writes to it shows up in the log below.</div>'; return; }
  el.innerHTML=rows.map(r=>{
    const name=r.tg_username?('@'+r.tg_username):(r.display_name||'unnamed');
    const bound=r.panel_user?` as ${esc(r.panel_user)}`:'';
    return `<div class="px-fw-rule">
      <div class="px-fw-rule-info">
        <div class="px-fw-rule-port">${esc(name)}</div>
        <div class="px-fw-rule-note">${r.telegram_id} &middot; ${esc(r.role)}${bound}${r.last_seen?' &middot; last seen '+esc(r.last_seen):''}</div>
      </div>
      <select class="field-input" style="max-width:130px;" onchange="setTelegramRole('${r.telegram_id}',this.value)">
        ${['admin','user','blocked'].map(x=>`<option value="${x}"${x===r.role?' selected':''}>${x}</option>`).join('')}
      </select>
      <button class="db-action-btn" style="color:var(--danger);" title="Remove from the bot"
              onclick="revokeTelegramId('${r.telegram_id}')">
        <svg class="ic"><use href="#ic-trash-2"/></svg></button>
    </div>`;
  }).join('');
}

function tgRenderPending(rows){
  const el=$('tg-pending'); if(!el) return;
  if(!rows.length){ el.innerHTML=''; return; }
  el.innerHTML='<div class="px-fw-legend">Waiting for a decision</div>'+rows.map(r=>{
    const name=r.tg_username?('@'+r.tg_username):(r.display_name||'unnamed');
    return `<div class="px-fw-rule">
      <div class="px-fw-rule-info">
        <div class="px-fw-rule-port">${esc(name)}</div>
        <div class="px-fw-rule-note">${r.telegram_id} &middot; ${r.messages} message(s) &middot; last ${esc(r.last_seen)}</div>
      </div>
      <button class="db-action-btn" onclick="setTelegramRole('${r.telegram_id}','user')">Allow as user</button>
      <button class="save-btn" onclick="setTelegramRole('${r.telegram_id}','admin')">Allow as admin</button>
      <button class="db-action-btn" onclick="setTelegramRole('${r.telegram_id}','blocked')">Block</button>
    </div>`;
  }).join('');
}

function tgRenderLog(rows){
  const el=$('tg-log'); if(!el) return;
  if(!rows.length){ el.innerHTML='<div class="empty-state">The bot has not been written to yet.</div>'; return; }
  el.innerHTML=rows.map(r=>{
    const name=r.tg_username?('@'+r.tg_username):(r.display_name||'unnamed');
    const dir=r.direction==='in'?'received':'sent';
    const allow=(r.direction==='in'&&!r.allowed)
      ? `<button class="db-action-btn" onclick="setTelegramRole('${r.telegram_id}','user')">Allow</button>
         <button class="save-btn" onclick="setTelegramRole('${r.telegram_id}','admin')">Allow as admin</button>` : '';
    return `<div class="px-fw-rule">
      <div class="px-fw-rule-info">
        <div class="px-fw-rule-note">${esc(r.ts)} &middot; ${dir} &middot; ${esc(name)} &middot; <code>${r.telegram_id}</code>${r.allowed?'':' &middot; not allowed'}</div>
        <div class="px-fw-rule-port" style="font-weight:400;white-space:pre-wrap;">${esc((r.text||'').slice(0,400))}</div>
      </div>
      ${allow}
    </div>`;
  }).join('');
}

async function saveTelegram(){
  const fb=$('tg-feedback'); fb.textContent='Saving…';
  const r=await api('/api/config/telegram',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({token:$('tg-token').value, domain:$('tg-domain').value, notify_email:$('tg-notify').value})});
  if(!r) return;
  const d=await r.json();
  fb.textContent=d.detail||''; fb.className='save-feedback '+(d.ok?'ok':'err');
  if(d.ok){ $('tg-token').value=''; loadTelegram(); }
}

async function connectTelegram(){
  const fb=$('tg-feedback'); fb.textContent='Telling Telegram where to deliver…';
  const r=await api('/api/config/telegram/connect',{method:'POST'}); if(!r) return;
  const d=await r.json();
  fb.textContent=d.detail||''; fb.className='save-feedback '+(d.ok?'ok':'err');
  loadTelegram();
}

async function disconnectTelegram(){
  if(!confirm('Stop the bot from receiving anything?')) return;
  const r=await api('/api/config/telegram/disconnect',{method:'POST'}); if(!r) return;
  const d=await r.json();
  const fb=$('tg-feedback'); fb.textContent=d.detail||''; fb.className='save-feedback '+(d.ok?'ok':'err');
  loadTelegram();
}

async function setTelegramRole(id, role, panelUser){
  const fb=$('tg-users-feedback');
  const r=await api('/api/config/telegram/allow',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({telegram_id:id, role:role, panel_user:panelUser||''})});
  if(!r) return;
  const d=await r.json();
  if(fb){ fb.textContent=d.detail||''; fb.className='save-feedback '+(d.ok?'ok':'err'); }
  loadTelegram();
}

async function allowTelegramId(){
  const id=$('tg-add-id').value.trim();
  if(!id){ appToast('Enter the Telegram ID','err'); return; }
  await setTelegramRole(id, $('tg-add-role').value, $('tg-add-user').value.trim());
  $('tg-add-id').value=''; $('tg-add-user').value='';
}

async function revokeTelegramId(id){
  if(!confirm('Remove '+id+' from the bot?')) return;
  const r=await api('/api/config/telegram/revoke',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({telegram_id:id})});
  if(!r) return;
  const d=await r.json();
  const fb=$('tg-users-feedback'); if(fb){ fb.textContent=d.detail||''; fb.className='save-feedback '+(d.ok?'ok':'err'); }
  loadTelegram();
}

async function clearTelegramLog(){
  if(!confirm('Clear the conversation log? Pending IDs disappear with it.')) return;
  const r=await api('/api/config/telegram/log/clear',{method:'POST'}); if(!r) return;
  loadTelegram();
}


(function init(){
  applyTheme(localStorage.getItem('theme')==='dark');
  document.querySelectorAll('[data-nav]').forEach(b=>b.addEventListener('click',()=>switchSection(b.dataset.nav)));
  const ss=$('svc-search'); if(ss) ss.addEventListener('input',renderServices);
  /* The Add proxy host button opens the form from an inline onclick. The
     delegated listener below is the same open through a second mechanism,
     so the button survives a click even when the attribute is lost,
     stripped, or never bound. */
  document.addEventListener('click', ev=>{
    const hit=ev.target && ev.target.closest ? ev.target.closest('#px-new') : null;
    if(hit) openProxyForm(null);
  });
  /* The proxy form reshapes itself around the chosen scheme, and HSTS
     subdomains only mean anything with HSTS on. Bound once here rather than
     inline so the markup stays readable. */
  document.querySelectorAll('input[name="px-listen"]')
    .forEach(r=>r.addEventListener('change', pxSyncScheme));
  /* The Logs time range re-queries rather than filtering what was already
     fetched, so the tiles show counts over the whole window, not over the last
     page of rows. */
  document.querySelectorAll('input[name="sec-range"]')
    .forEach(r=>r.addEventListener('change', loadSecurityLogs));
  const hstsBox=document.querySelector('[data-px="hsts"]');
  if(hstsBox) hstsBox.addEventListener('change', pxSyncHsts);
  /* Internal and external are not two ways of doing the same thing, so the
     hint under the recipient says which one is about to happen. */
  document.querySelectorAll('input[name="mail-route"]')
    .forEach(r=>r.addEventListener('change', mailSyncRouteHint));
  applyMetricPermissions();
  startMailBadgePolling();
  switchSection('server');
})();
