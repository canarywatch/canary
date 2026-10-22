/* canary — page logic. Reads the agent's public files, renders the wall, runs the checks. No framework, no build. */
window.CANARY = (function () {
  // local previews (file://, localhost) render the bundled sample data; everything else talks to the agent
  const SAMPLE = window.CANARY_SAMPLE || location.protocol === 'file:' || /^(localhost|127\.0\.0\.1|0\.0\.0\.0)$/.test(location.hostname) || /\.local$/.test(location.hostname);
  // where the agent lives: the real api host once DNS exists, the box's sslip.io name until then
  const HOSTS = window.CANARY_API ? [window.CANARY_API] : ['https://canary.162-35-122-197.sslip.io'];
  let API = SAMPLE ? 'sample' : HOSTS[0].replace(/\/$/, '');
  let DEMO = SAMPLE;
  const $ = (s, el) => (el || document).querySelector(s);
  const $$ = (s, el) => Array.from((el || document).querySelectorAll(s));
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const fmt = n => { n = +n || 0; return n >= 1e6 ? (n/1e6).toFixed(1)+'M' : n >= 1e4 ? (n/1e3).toFixed(1)+'K' : String(Math.round(n)).replace(/\B(?=(\d{3})+(?!\d))/g, ','); };
  const ago = ts => { const d = Math.max(0, Math.floor(Date.now()/1000 - ts)); return d < 60 ? d+'s' : d < 3600 ? Math.floor(d/60)+'m' : d < 86400 ? Math.floor(d/3600)+'h' : Math.floor(d/86400)+'d'; };
  const hhmm = ts => new Date(ts * 1000).toISOString().slice(11, 19);
  const hours = h => h == null ? '' : h < 1 ? Math.round(h * 60) + ' min' : h < 48 ? Math.round(h) + ' h' : Math.round(h / 24) + ' d';
  const days = d => d == null ? '–' : d < 1 ? 'today' : d < 30 ? Math.round(d) + ' d' : d < 365 ? Math.round(d / 30) + ' mo' : (d / 365).toFixed(1) + ' y';
  const regUrl = (eco, name, version) => eco === 'npm' ? `https://www.npmjs.com/package/${name}/v/${version}` : `https://pypi.org/project/${name}/${version}/`;
  const catchUrl = c => `catch.html?e=${encodeURIComponent(c.ecosystem)}&n=${encodeURIComponent(c.name)}&v=${encodeURIComponent(c.version)}`;

  function demoBanner(text) {
    if (document.getElementById('demo-banner')) return;
    const d = document.createElement('div'); d.id = 'demo-banner'; d.textContent = text; document.body.prepend(d);
  }
  async function useSampleIfAgentDown() {
    if (API === 'sample') return;
    for (const h of HOSTS) {
      try {
        const c = new AbortController(); const t = setTimeout(() => c.abort(), 4000);
        const r = await fetch(`${h.replace(/\/$/, '')}/state.json`, {cache: 'no-store', signal: c.signal}); clearTimeout(t);
        if (r.ok) { API = h.replace(/\/$/, ''); return; }
      } catch (e) { /* next */ }
    }
    API = 'sample'; DEMO = true;
    demoBanner('Demo. The agent is not reachable from here, so the wall shows sample data (historic, public incidents) and the checks run against it only.');
  }
  let probed = null;
  async function get(name) {
    if (!probed) probed = useSampleIfAgentDown();
    await probed;
    const r = await fetch(`${API}/${name}`, {cache: 'no-store'});
    if (!r.ok) throw new Error(`${name}: http ${r.status}`);
    return r.json();
  }
  async function post(path, body) {
    if (!probed) probed = useSampleIfAgentDown();
    await probed;
    if (API === 'sample') return samplePost(path, body);
    const r = await fetch(`${API}${path}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
    let doc = null; try { doc = await r.json(); } catch (e) { doc = {error: `http ${r.status}`}; }
    if (!r.ok) throw new Error(doc.error || `http ${r.status}`);
    return doc;
  }
  // demo-only stand-in for the agent's POSTs: names are matched against the sample wall, nothing else
  async function samplePost(path, body) {
    const catches = await get('catches.json');
    if (path === '/check') {
      const names = (body.text || '').split(/[\s,"':{}\[\]]+/).filter(n => /^[@a-z0-9][\w./@-]*$/i.test(n) && !/^\d/.test(n)).slice(0, 500);
      const flagged = [];
      for (const n of new Set(names)) {
        const hit = catches.find(c => c.name === n.replace(/@[\d.]+$/, ''));
        if (hit) flagged.push({name: hit.name, version: null, status: 'other-version', versions: [hit.version], rules: hit.rules, ids: (hit.advisories || []).map(a => a.id)});
      }
      return {ecosystem: body.ecosystem === 'auto' ? 'npm' : body.ecosystem, format: 'list', parsed: new Set(names).size, flagged, counts: {}, osv_ok: false, ts: Math.floor(Date.now()/1000), demo: true};
    }
    if (path === '/scan') {
      const hit = catches.find(c => c.ecosystem === body.ecosystem && c.name === body.name);
      if (hit) return hit;
      return {ecosystem: body.ecosystem, name: body.name, version: body.version || 'latest', verdict: 'clean', score: 0, rules: [], evidence: [], ts: Math.floor(Date.now()/1000), demo: true, note: 'demo: the agent is not reachable, so nothing was fetched or read'};
    }
    throw new Error('not available in the demo');
  }

  // ---------------------------------------------------------------- small ui
  function toast(text) {
    let t = $('#toast'); if (!t) { t = document.createElement('div'); t.id = 'toast'; t.className = 'toast'; document.body.appendChild(t); }
    t.textContent = text; t.classList.add('show'); clearTimeout(toast.h); toast.h = setTimeout(() => t.classList.remove('show'), 2200);
  }
  function copyText(t, btn) {
    const done = () => { if (btn) { const o = btn.textContent; btn.textContent = 'copied'; setTimeout(() => { btn.textContent = o; }, 1400); } };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(t).then(done, done);
    else { const ta = document.createElement('textarea'); ta.value = t; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } catch (e) {} ta.remove(); done(); }
  }
  function clock() {
    const el = $('.clock'); if (!el) return;
    const tick = () => { el.textContent = new Date().toISOString().slice(11, 19) + ' UTC'; };
    tick(); setInterval(tick, 1000);
  }
  function agentChip(state) {
    const el = $('#agent'); if (!el) return;
    const age = state && state.updated ? Date.now()/1000 - state.updated : Infinity;
    el.className = 'chip ' + (DEMO ? 'warn' : age < 120 ? 'on' : age < 900 ? 'warn' : 'off');
    el.title = DEMO ? 'sample data' : age < 120 ? `agent wrote ${ago(state.updated)} ago` : `agent last wrote ${ago(state.updated)} ago`;
    el.lastChild.textContent = DEMO ? 'demo' : age < 120 ? 'agent live' : 'agent stale';
  }
  function navSpy() {
    const links = $$('.rail nav a[href^="#"]'); if (!links.length) return;
    const secs = links.map(a => $(a.getAttribute('href'))).filter(Boolean);
    const on = () => {
      let cur = secs[0];
      for (const s of secs) if (s.getBoundingClientRect().top <= 120) cur = s;
      links.forEach(a => a.classList.toggle('on', cur && a.getAttribute('href') === '#' + cur.id));
    };
    document.addEventListener('scroll', on, {passive: true}); on();
  }

  // ---------------------------------------------------------------- pieces
  const vlabel = v => ({confirmed: 'confirmed', tripped: 'tripped', watch: 'watch', clean: 'clean', cleared: 'cleared', 'other-version': 'other version', advisory: 'advisory'})[v] || v;
  const vtag = v => `<span class="v ${esc(v)}">${esc(vlabel(v))}</span>`;
  const ecoTag = e => `<span class="eco ${esc(e)}">${esc(e)}</span>`;

  function evidenceList(c, full) {
    const ev = (c.evidence || []).filter(e => e.weight > 0);
    if (!ev.length) return c.verdict === 'confirmed' ? '<p class="note">On the public record without tripping our rules: the payload was not in the files, or used a shape the rules do not know yet. That is a miss we count.</p>' : '';
    const rows = (full ? ev : ev.slice(0, 3)).map(e => `<li>
      <span class="where"><b>${esc(e.rule)} +${esc(e.weight)}</b> ${esc(e.file)}${e.line ? ':' + esc(e.line) : ''}</span>
      <span class="snip">${esc(e.snippet)}</span>
      ${e.note ? `<span class="why">${esc(e.note)}</span>` : ''}</li>`).join('');
    return `<ul class="ev-list">${rows}</ul>${!full && ev.length > 3 ? `<div class="d" style="font-size:12px;margin-top:6px">+${ev.length - 3} more lines on the catch page</div>` : ''}`;
  }
  function catchCard(c, full) {
    const adv = (c.advisories || []).map(a => `<a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.id)}</a>`).join(', ');
    const ruleChips = (c.rules || []).map(r => { const w = Math.max(0, ...(c.evidence || []).filter(e => e.rule === r).map(e => e.weight)); return `<span class="rule">${esc(r)}<b>+${w}</b></span>`; }).join('');
    const firstRel = c.age_days == null ? '' : c.age_days < 1 ? 'first release today' : `first release ${days(c.age_days)} ago`;
    const meta = [c.version_age_h != null ? `${hours(c.version_age_h)} old when read` : '', firstRel, c.weekly_downloads != null ? `${fmt(c.weekly_downloads)}/wk` : ''].filter(Boolean).join('<br>');
    return `<article class="catch ${esc(c.verdict)}" data-eco="${esc(c.ecosystem)}" data-v="${esc(c.verdict)}">
  <div class="top">${vtag(c.verdict)}${ecoTag(c.ecosystem)}<span class="nm">${esc(c.name)}<small>@${esc(c.version)}</small></span><span class="meta">${meta}</span></div>
  ${c.verdict === 'cleared' ? `<p class="note">cleared by a person: ${esc(c.cleared_reason || 'not malicious')}</p>` : ''}
  <div class="rules">${ruleChips || '<span class="rule d">no rule tripped</span>'}<span class="rule">score<b>${esc(c.score)}</b></span></div>
  ${evidenceList(c, full)}
  ${adv ? `<div class="adv">on the record: ${adv}${c.rules_verdict ? ` <span class="d">· the rules said <b>${esc(c.rules_verdict)}</b> ${c.confirmed_ts && c.ts ? Math.round((c.confirmed_ts - c.ts) / 3600) + ' h earlier' : 'first'}</span>` : ''}</div>` : ''}
  <div class="links">${full ? '' : `<a href="${catchUrl(c)}">the catch →</a>`}<a href="${esc(c.url || regUrl(c.ecosystem, c.name, c.version))}" target="_blank" rel="noopener">${c.ecosystem === 'npm' ? 'npm' : 'pypi'} ↗</a>${c.repository ? `<a href="${esc(c.repository.replace(/^git\+/, '').replace(/\.git$/, '').replace(/^ssh:\/\/git@/, 'https://'))}" target="_blank" rel="noopener">repo ↗</a>` : ''}<span class="d">${c.source === 'request' ? 'asked for · ' : ''}${ago(c.ts)} ago</span></div>
</article>`;
  }

  // ---------------------------------------------------------------- hero terminal
  const term = {lines: [], shown: new Set(), timer: null};
  function termLine(r) {
    const cls = r.verdict === 'tripped' || r.verdict === 'confirmed' ? r.verdict : r.verdict;
    return `<div class="ln ${esc(cls)}"><span class="t">${hhmm(r.ts)}</span><span class="eco">${esc(r.ecosystem)}</span><span class="nm">${esc(r.name)}@${esc(r.version)}</span><span class="vd">${esc(r.verdict)}${r.score ? ' ' + r.score : ''}</span>${r.rules && r.rules.length ? ` <span class="d">${esc(r.rules.join(','))}</span>` : ''}</div>`;
  }
  function renderTerm(state, catches) {
    const body = $('#term-body'); if (!body) return;
    const recent = (state.recent || []).slice().sort((a, b) => a.ts - b.ts);
    const fresh = recent.filter(r => !term.shown.has(`${r.ecosystem}:${r.name}@${r.version}@${r.ts}`));
    fresh.forEach(r => term.shown.add(`${r.ecosystem}:${r.name}@${r.version}@${r.ts}`));
    if (!body.dataset.ready) {
      body.dataset.ready = '1';
      body.innerHTML = '';
      const boot = [`<div class="ln"><span class="t">${hhmm(state.updated || Date.now()/1000)}</span><span class="d">canary agent · npm ${state.feeds && state.feeds.npm && state.feeds.npm.on ? 'on' : 'off'} · pypi ${state.feeds && state.feeds.pypi && state.feeds.pypi.on ? 'on' : 'off'} · read-only, never installs</span></div>`];
      body.innerHTML = boot.join('');
    }
    // type them in one by one, like a log that is being written
    const queue = fresh.slice(-30);
    clearInterval(term.timer);
    let i = 0;
    const step = () => {
      if (i >= queue.length) { clearInterval(term.timer); setCursor(); return; }
      const r = queue[i++];
      body.insertAdjacentHTML('beforeend', termLine(r));
      while (body.children.length > 40) body.removeChild(body.firstChild);
      setCursor();
    };
    const setCursor = () => { $$('.cur', body).forEach(x => x.remove()); body.insertAdjacentHTML('beforeend', '<div class="ln" style="opacity:1"><span class="t">&nbsp;</span><span class="cur"></span></div>'); const c = body.lastChild; body.scrollTop = body.scrollHeight; if (c && c.previousSibling && c.previousSibling.classList && c.previousSibling.classList.contains('ln') && c.previousSibling.querySelector('.cur')) c.previousSibling.remove(); };
    $$('.cur', body).forEach(x => x.parentNode.remove());
    term.timer = setInterval(step, Math.max(120, Math.min(900, 9000 / Math.max(1, queue.length))));
    step();
  }

  // ---------------------------------------------------------------- stats, ticker, feed, wall
  function renderStats(st) {
    const set = (id, v) => { const el = $(id); if (el) el.innerHTML = v; };
    set('#st-scanned', `${fmt(st.scanned_last_h || 0)}<small>/h</small>`);
    set('#st-total', fmt(st.scanned_total || 0));
    set('#st-catches', fmt(st.catches_24h || 0));
    set('#st-confirmed', fmt(st.confirmed_24h || 0));
    const r = st.recall || {};
    set('#st-recall', r.confirmed_seen ? `${Math.round(100 * (r.rules_tripped || 0) / r.confirmed_seen)}<small>% of ${r.confirmed_seen}</small>` : '–<small>no data yet</small>');
    set('#st-checks', fmt(st.checks_total || 0));
    const rec = $('#recall-line');
    if (rec) rec.innerHTML = r.confirmed_seen
      ? `So far the record has confirmed <b>${r.confirmed_seen}</b> packages the agent had read. The rules had already tripped on <b>${r.rules_tripped}</b> of them, watched <b>${r.rules_watched}</b>, and missed <b>${r.rules_missed}</b>. Every miss is a rule we do not have yet.`
      : 'The recall number appears once the public record confirms a package the agent has read. Until then it is blank, not a guess.';
    const f = st.feeds || {};
    const fl = $('#feeds-line');
    if (fl) fl.innerHTML = `feeds: npm ${f.npm && f.npm.on ? (f.npm.ok ? '<b class="g">ok</b>' : '<b class="r">down</b>') : 'off'} · pypi ${f.pypi && f.pypi.on ? (f.pypi.ok ? '<b class="g">ok</b>' : '<b class="r">down</b>') : 'off'} · osv ${f.osv && f.osv.ok ? '<b class="g">ok</b>' : '<b class="r">unreachable</b>'} · ${fmt(st.popular_names || 0)} protected names · up ${hours((st.uptime_s || 0) / 3600)}`;
  }
  function renderTicker(catches) {
    const t = $('#ticker-track'); if (!t) return;
    const items = catches.filter(c => c.verdict !== 'cleared').slice(0, 24);
    if (!items.length) { t.innerHTML = '<span class="d">the wall is empty: nothing has tripped yet</span>'; return; }
    const html = items.map(c => `<span><em class="v ${esc(c.verdict)}">${esc(c.verdict)}</em>${esc(c.ecosystem)} <b>${esc(c.name)}@${esc(c.version)}</b> · ${esc((c.rules || []).join(', ') || 'on the record')} · ${ago(c.ts)} ago</span>`).join('');
    t.innerHTML = html + html;
  }
  function renderFeed(events, state) {
    const el = $('#feed'); if (!el) return;
    const evs = (events.events || []).map(e => ({...e, _k: e.kind})).concat((state.recent || []).map(r => ({...r, _k: 'read'})));
    evs.sort((a, b) => b.ts - a.ts);
    if (!evs.length) { el.innerHTML = '<div class="empty">nothing yet: the agent has just started</div>'; return; }
    el.innerHTML = evs.slice(0, 120).map(e => {
      if (e._k === 'read') return `<div class="ev ${esc(e.verdict)}"><span class="t">${hhmm(e.ts)}</span><span>read <span class="eco">${esc(e.ecosystem)}</span> <span class="nm">${esc(e.name)}@${esc(e.version)}</span> · <span class="vd">${esc(e.verdict)}</span>${e.score ? ` <span class="d">score ${e.score}</span>` : ''}</span></div>`;
      if (e._k === 'catch') return `<div class="ev catch"><span class="t">${hhmm(e.ts)}</span><span><span class="vd">tripped</span> <span class="eco">${esc(e.ecosystem)}</span> <a class="nm" href="${catchUrl(e)}">${esc(e.name)}@${esc(e.version)}</a><br><span class="sub">${esc((e.rules || []).join(', '))} · score ${esc(e.score)}</span></span></div>`;
      if (e._k === 'confirm') return `<div class="ev confirm"><span class="t">${hhmm(e.ts)}</span><span><span class="vd">confirmed</span> <span class="eco">${esc(e.ecosystem)}</span> <a class="nm" href="${catchUrl(e)}">${esc(e.name)}@${esc(e.version)}</a><br><span class="sub">${esc((e.ids || []).join(', '))}${e.text ? ' · ' + esc(e.text) : ''}</span></span></div>`;
      if (e._k === 'clear') return `<div class="ev clear"><span class="t">${hhmm(e.ts)}</span><span>cleared <span class="nm">${esc(e.name)}@${esc(e.version)}</span><br><span class="sub">${esc(e.reason || '')}</span></span></div>`;
      return `<div class="ev ${esc(e._k)}"><span class="t">${hhmm(e.ts)}</span><span>${esc(e.text || e._k)}</span></div>`;
    }).join('');
    const n = $('#feed-n'); if (n) n.textContent = `${fmt(state.scanned_last_min || 0)} read in the last minute`;
  }
  const wall = {filter: 'all', data: []};
  function renderWall(catches) {
    const el = $('#wall'); if (!el) return;
    wall.data = catches;
    const f = wall.filter;
    const list = catches.filter(c => f === 'all' ? c.verdict !== 'cleared' : f === 'cleared' ? c.verdict === 'cleared' : (f === 'npm' || f === 'pypi') ? c.ecosystem === f && c.verdict !== 'cleared' : c.verdict === f);
    const cnt = $('#wall-count'); if (cnt) cnt.textContent = `${list.length} of ${catches.length}`;
    if (!list.length) { el.innerHTML = `<div class="empty">${catches.length ? 'nothing under this filter' : 'the wall is empty. the agent is reading; the first catch shows up here with its lines.'}</div>`; return; }
    el.innerHTML = list.slice(0, 60).map(c => catchCard(c, false)).join('');
  }
  function filters() {
    $$('.filters button[data-f]').forEach(b => b.onclick = () => { wall.filter = b.dataset.f; $$('.filters button[data-f]').forEach(x => x.classList.toggle('on', x === b)); renderWall(wall.data); });
  }

  // ---------------------------------------------------------------- check and scan
  function resultTable(out) {
    const counts = out.counts || {};
    const bad = out.flagged || [];
    const head = `<div class="sum"><span class="big">${bad.length ? `<span class="r">${bad.length}</span> flagged` : `<span class="g">all clear</span>`}</span><span class="d">${esc(out.format)} · ${out.parsed} ${esc(out.ecosystem)} packages · ${out.osv_ok ? 'record checked' : (out.demo ? 'demo: sample wall only' : 'record unreachable, wall only')}</span></div>`;
    if (!bad.length) return head + `<div class="ok"><div class="big">nothing on the record</div><p class="d">none of these names is on the wall or in a public malware advisory${counts.clean ? ` (${counts.clean} checked)` : ''}. that is a statement about the record, not a guarantee.</p></div>`;
    const rows = bad.map(r => `<tr><td>${vtag(r.status)}</td><td class="nm">${esc(r.name)}${r.version ? `<span class="d">@${esc(r.version)}</span>` : ''}</td><td>${r.versions ? `<span class="d">on the wall: ${esc(r.versions.join(', '))}</span><br>` : ''}${(r.rules || []).map(x => `<span class="rule">${esc(x)}</span>`).join(' ')}${(r.advisories || []).map(a => ` <a href="${esc(a.url)}" target="_blank" rel="noopener">${esc(a.id)}</a>`).join('')}${r.note ? `<br><span class="d">${esc(r.note)}</span>` : ''}</td></tr>`).join('');
    return head + `<table><thead><tr><th>status</th><th>package</th><th>why</th></tr></thead><tbody>${rows}</tbody></table>`;
  }
  function checkForm() {
    const ta = $('#check-text'), out = $('#check-out'), btn = $('#check-btn'), eco = $('#check-eco'), drop = $('#check-drop');
    if (!ta || !out) return;
    const run = async () => {
      const text = ta.value.trim();
      if (!text) { out.innerHTML = '<div class="err">paste a dependency file first</div>'; return; }
      btn.disabled = true; out.innerHTML = '<div class="empty">reading…</div>';
      try { out.innerHTML = resultTable(await post('/check', {text, ecosystem: eco ? eco.value : 'auto'})); }
      catch (e) { out.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
      btn.disabled = false;
    };
    btn.onclick = run;
    ta.addEventListener('keydown', e => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run(); });
    const readFile = f => { if (!f || f.size > 2200000) { toast('file too big (2 MB max)'); return; } const r = new FileReader(); r.onload = () => { ta.value = String(r.result); run(); }; r.readAsText(f); };
    if (drop) {
      ['dragenter', 'dragover'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add('over'); }));
      ['dragleave', 'drop'].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove('over'); }));
      drop.addEventListener('drop', e => readFile(e.dataTransfer.files && e.dataTransfer.files[0]));
    }
    const file = $('#check-file'); if (file) file.onchange = () => readFile(file.files[0]);
    const ex = $('#check-example'); if (ex) ex.onclick = () => { ta.value = '{\n  "name": "my-app",\n  "dependencies": {\n    "express": "^4.19.2",\n    "lodash": "4.17.21",\n    "axios": "^1.7.0",\n    "ua-parser-js": "0.7.29",\n    "coa": "2.0.3"\n  }\n}'; run(); };
  }
  function scanForm() {
    const inp = $('#scan-name'), out = $('#scan-out'), btn = $('#scan-btn'), eco = $('#scan-eco');
    if (!inp || !out) return;
    const run = async () => {
      let name = inp.value.trim(), version = null;
      if (!name) return;
      const m = name.match(/^(.+?)(?:@|==)(\d[\w.+-]*)$/); if (m && !(name.startsWith('@') && name.indexOf('@', 1) < 0)) { name = m[1]; version = m[2]; }
      btn.disabled = true; out.innerHTML = '<div class="empty">fetching the package from the registry and reading every file (5-20 s)…</div>';
      try {
        const s = await post('/scan', {ecosystem: eco.value, name, version});
        out.innerHTML = catchCard(s, true) + (s.note ? `<p class="privacy">${esc(s.note)}</p>` : '');
      } catch (e) { out.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
      btn.disabled = false;
    };
    btn.onclick = run; inp.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
  }

  // ---------------------------------------------------------------- rules
  function renderRules(doc) {
    const el = $('#rules-body'); if (!el) return;
    const rows = (doc.rules || []).map(r => `<tr><td class="id">${esc(r.id)}</td><td class="w">${esc(r.weight)}</td><td>${esc(r.what)}${r.why ? `<br><span class="d">${esc(r.why)}</span>` : ''}</td></tr>`).join('');
    el.innerHTML = rows;
    const set = (id, v) => { const x = $(id); if (x) x.textContent = v; };
    set('#th-trip', doc.trip); set('#th-watch', doc.watch); set('#th-strong', doc.strong); set('#th-fresh', doc.fresh_h + ' h');
    const nev = $('#never-list'); if (nev && doc.never) { /* the static list on the page is the same text; nothing to do */ }
  }

  // ---------------------------------------------------------------- the token
  const JUP_SRC = 'https://plugin.jup.ag/plugin-v1.js';
  const SOL_MINT = 'So11111111111111111111111111111111111111112';
  let LINKS = {};
  const SYM = () => LINKS.token_symbol || 'CANARY';
  function buyLinks(mint) {
    return `<a class="btn ghost sm" href="https://pump.fun/coin/${esc(mint)}" target="_blank" rel="noopener">pump.fun ↗</a>
      <a class="btn ghost sm" href="https://dexscreener.com/solana/${esc(mint)}" target="_blank" rel="noopener">dexscreener ↗</a>
      <a class="btn ghost sm" href="https://solscan.io/token/${esc(mint)}" target="_blank" rel="noopener">solscan ↗</a>`;
  }
  function buyModal() {
    let m = $('#buy-modal'); if (m) return m;
    const mint = LINKS.token_mint;
    m = document.createElement('div'); m.id = 'buy-modal'; m.className = 'buy'; m.hidden = true;
    m.innerHTML = `<div class="buy-bg"></div>
<div class="buy-card" role="dialog" aria-label="Buy $${esc(SYM())}">
  <div class="buy-head"><div><p class="eyebrow">the project token</p><h3 class="disp">Buy $${esc(SYM())}</h3></div><button type="button" class="buy-x" aria-label="close">×</button></div>
  <div class="buy-ca"><code>${esc(mint)}</code><button type="button" class="btn ghost sm copy">copy</button></div>
  <div class="jup" id="jup-box"><div class="jup-wait">loading the swap…</div></div>
  <div class="buy-foot">${buyLinks(mint)}<span class="d">swap by Jupiter, in your own wallet. the site never holds anything.</span></div>
</div>`;
    document.body.appendChild(m);
    m.querySelector('.buy-bg').onclick = closeBuy; m.querySelector('.buy-x').onclick = closeBuy;
    m.querySelector('.copy').onclick = e => copyText(mint, e.currentTarget);
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && !m.hidden) closeBuy(); });
    return m;
  }
  function closeBuy() { const m = $('#buy-modal'); if (m) { m.hidden = true; document.body.classList.remove('noscroll'); } }
  async function openBuy() {
    const mint = LINKS.token_mint; if (!mint) return;
    const m = buyModal(); m.hidden = false; document.body.classList.add('noscroll');
    if (openBuy.started) return;
    openBuy.started = true;
    try {
      if (!window.Jupiter) await new Promise((res, rej) => { const sc = document.createElement('script'); sc.src = JUP_SRC; sc.onload = res; sc.onerror = () => rej(new Error('jup')); document.head.appendChild(sc); });
      const wait = m.querySelector('.jup-wait'); if (wait) wait.remove();
      window.Jupiter.init({displayMode: 'integrated', integratedTargetId: 'jup-box', formProps: {initialInputMint: SOL_MINT, initialOutputMint: mint, fixedMint: mint}, containerStyles: {borderRadius: '16px', maxHeight: '560px'}});
    } catch (e) {
      openBuy.started = false;
      const j = $('#jup-box'); if (j) j.innerHTML = `<div class="jup-wait">the swap widget did not load. buy on <a href="https://pump.fun/coin/${esc(mint)}" target="_blank" rel="noopener">pump.fun</a> or <a href="https://jup.ag/swap/SOL-${esc(mint)}" target="_blank" rel="noopener">jup.ag</a>.</div>`;
    }
  }
  function buyButton() {
    if (!LINKS.token_mint) return;
    $$('.rail .right').forEach(r => {
      if (r.querySelector('#buybtn')) return;
      const b = document.createElement('button'); b.type = 'button'; b.id = 'buybtn'; b.className = 'btn'; b.textContent = `Buy $${SYM()}`; b.onclick = openBuy;
      const anchor = r.querySelector('.btn.fill'); r.insertBefore(b, anchor || null);
    });
  }
  async function tokenStats(mint) {
    const el = $('#mintstats'); if (!el || API === 'sample') return;
    try {
      const r = await fetch(`https://api.dexscreener.com/tokens/v1/solana/${mint}`); if (!r.ok) throw new Error('dex');
      const ps = await r.json(); if (!ps.length) { el.textContent = 'on pump.fun · no pair indexed yet'; return; }
      const p = ps.reduce((a, b) => ((b.liquidity && b.liquidity.usd) || 0) > ((a.liquidity && a.liquidity.usd) || 0) ? b : a);
      const mc = p.marketCap || p.fdv, vol = p.volume && p.volume.h24, ch = p.priceChange && p.priceChange.h24;
      el.innerHTML = `market cap <b>${mc ? '$' + fmt(mc) : '–'}</b> · 24h volume <b>${vol ? '$' + fmt(vol) : '–'}</b>${ch != null ? ` · 24h <b class="${ch >= 0 ? 'g' : 'r'}">${ch >= 0 ? '+' : ''}${(+ch).toFixed(1)}%</b>` : ''} · <span class="d">dexscreener</span>`;
    } catch (e) { el.textContent = 'on pump.fun'; }
  }
  function renderLinks(links) {
    LINKS = links || {};
    const x = LINKS.x; $$('a.xlink, a.xlink2').forEach(a => { if (x) { a.href = x; a.hidden = false; } else a.hidden = true; });
    const gh = LINKS.github; if (gh) $$('a.ghlink').forEach(a => { a.href = gh; });
    $$('.sym').forEach(s => { s.textContent = SYM(); });
    const mint = LINKS.token_mint;
    buyButton();
    const el = $('#mint');
    if (el) el.innerHTML = mint
      ? `<div class="mintrow"><span class="eyebrow" style="margin:0">mint</span><code id="ca">${esc(mint)}</code><button type="button" class="btn ghost sm copy">copy</button></div>
<div class="mintbtns"><button type="button" class="btn fill" id="buybtn-2">Buy $${esc(SYM())} →</button>${buyLinks(mint)}</div>
<div class="mintstats d" id="mintstats">on pump.fun · reading the market…</div>`
      : `<div class="mintrow"><span class="eyebrow" style="margin:0">mint</span><code>posted on the project account on launch day</code>${x ? `<a class="btn ghost sm" href="${esc(x)}" target="_blank" rel="noopener">follow for the drop</a>` : ''}</div>`;
    if (el && mint) { el.querySelector('.copy').onclick = e => copyText(mint, e.currentTarget); $('#buybtn-2').onclick = openBuy; tokenStats(mint); }
    const an = $('.api-note'); if (an) an.textContent = API === 'sample' ? 'sample data' : `agent: ${API}`;
  }

  // ---------------------------------------------------------------- pages
  async function init() {
    if (window.CANARY_SAMPLE) demoBanner('Preview with sample data — real public incidents (ua-parser-js, event-stream, ctx and others). The live agent fills the wall once it is deployed.');
    clock(); navSpy(); filters(); checkForm(); scanForm();
    const load = async (first) => {
      try {
        const [st, catches, events] = await Promise.all([get('state.json'), get('catches.json'), get('events.json')]);
        agentChip(st); renderStats(st); renderLinks(st.links); renderTicker(catches); renderFeed(events, st); renderWall(catches); renderTerm(st, catches);
      } catch (e) { console.warn(e); agentChip(null); }
      if (first) { try { renderRules(await get('rules.json')); } catch (e) { console.warn(e); } }
    };
    await load(true);
    setInterval(() => load(false), 20000);
  }
  async function initSmall() {
    if (window.CANARY_SAMPLE) demoBanner('Preview with sample data — real public incidents (ua-parser-js, event-stream, ctx and others). The live agent fills the wall once it is deployed.');
    clock(); checkForm(); scanForm();
    try { const st = await get('state.json'); agentChip(st); renderLinks(st.links); } catch (e) { agentChip(null); }
  }
  async function initCatch() {
    if (window.CANARY_SAMPLE) demoBanner('Preview with sample data — real public incidents (ua-parser-js, event-stream, ctx and others). The live agent fills the wall once it is deployed.');
    clock();
    const q = new URLSearchParams(location.search);
    const eco = q.get('e'), name = q.get('n'), ver = q.get('v');
    const el = $('#single'); if (!el) return;
    try {
      const [st, catches] = await Promise.all([get('state.json'), get('catches.json')]);
      agentChip(st); renderLinks(st.links);
      const c = catches.find(x => x.ecosystem === eco && x.name === name && (!ver || x.version === ver));
      if (c) { el.innerHTML = catchCard(c, true); document.title = `${c.name}@${c.version} · ${c.verdict} · canary`; }
      else el.innerHTML = `<div class="empty">this catch is not on the wall (it may have aged off). <a href="check.html">scan it again →</a></div>`;
    } catch (e) { el.innerHTML = `<div class="err">${esc(e.message)}</div>`; }
  }

  return {get API() { return API; }, get DEMO() { return DEMO; }, SAMPLE, get, post, esc, fmt, ago, init, initSmall, initCatch, catchCard, openBuy, toast, copyText, get LINKS() { return LINKS; }, setMint(m) { renderLinks({...LINKS, token_mint: m}); }};
})();
