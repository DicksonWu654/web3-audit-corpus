// Client-side findings explorer over the sharded search index. Index files load in parallel (only the firms a
// filter needs, or all of them), results update as files arrive, and full text loads on demand from the finding
// shard of the opened result.
import { config, summary, firms as loadFirms, searchManifest, searchShard, findingShard, taxonomy, SEVERITIES, SEVERITY_LABEL,
  STATUSES, STATUS_LABEL, MODE_LABEL, groupLabel, leafInfo, sevBadge } from './data.js';
import { int, esc } from './fmt.js';
import { fail } from './ui.js';
import { copyText, flash } from './share.js';
import { renderMarkdown, withoutTitle } from './md.js';
import { fromCode, dateHTML } from './dates.js';
import { termsCount, setTermsPolicy, TERMS, TERMS_NOTE } from './types.js';

// Publishers whose site terms keep some or all of their report text, and those reports' findings, out of the index.
const termsFirms = () => FIRMS.filter((f) => termsCount(f) > 0);
const released = (f) => Number(f.findings_released ?? f.findings ?? 0) > 0;
const firmLinks = (list) => list.map((f) => `<a href="firms.html?id=${encodeURIComponent(f.firm_id)}">${esc(f.name)}</a>`).join(', ');

const PAGE = 50;
const S = { // struct of arrays
  id: [], title: [], hay: [], projLower: [], date: [], firm: [], project: [], year: [], sev: [], status: [], leaf: [], group: [], mode: [], shard: [], pid: [], sel: [],
};
const leaves = [];
const leafIdx = new Map();
const groups = [];
const groupIdx = new Map();
const MODES = ['firm_review', 'contest'];
let FIRMS = [];
let firmIdx = new Map();
let TAX = null;
let manifest = null;
const loadedFiles = new Set();
const loadingFiles = new Map();
const failedFiles = new Set();
let state = defaultState();
let shown = PAGE;
let lastResults = [];
let lastFocus = null;
let repo = '';
let hasSel = false;
const BASE_TITLE = document.title;

function defaultState() {
  return { q: '', sev: new Set(), status: new Set(), mode: new Set(), group: new Set(), leaf: '', firm: new Set(), from: 0, to: 0, sort: 'relevance', f: '', stats: false, p: '' };
}

/* ------------------------------------------------------------------ URL state */
function parseHash() {
  const p = new URLSearchParams(location.hash.slice(1));
  const set = (k) => new Set((p.get(k) || '').split(',').filter(Boolean));
  return {
    q: p.get('q') || '', sev: set('sev'), status: set('status'), mode: set('mode'), group: set('cls'), leaf: p.get('leaf') || '',
    firm: set('firm'), from: Number(p.get('from')) || 0, to: Number(p.get('to')) || 0, sort: p.get('sort') || 'relevance', f: p.get('f') || '', stats: p.get('stats') === '1',
    p: (p.get('p') || '').toLowerCase(),
  };
}
function toHash(st, extra = {}) {
  const s = { ...st, ...extra };
  const p = new URLSearchParams();
  if (s.q) p.set('q', s.q);
  for (const [k, key] of [['sev', 'sev'], ['status', 'status'], ['mode', 'mode'], ['group', 'cls'], ['firm', 'firm']]) if (s[k].size) p.set(key, [...s[k]].join(','));
  if (s.leaf) p.set('leaf', s.leaf);
  if (s.p) p.set('p', s.p);
  if (s.from) p.set('from', s.from);
  if (s.to) p.set('to', s.to);
  if (s.stats) p.set('stats', '1');
  if (s.sort && s.sort !== 'relevance') p.set('sort', s.sort);
  if (s.f) p.set('f', s.f);
  return `#${p.toString().replace(/%2C/g, ',').replace(/%3A/g, ':')}`;
}
let writing = false;
function commit(push = false) {
  const h = toHash(state);
  if (h !== location.hash && !(h === '#' && !location.hash)) {
    writing = true;
    if (push) history.pushState(null, '', h); else history.replaceState(null, '', h);
    writing = false;
  }
}

/* ------------------------------------------------------------------ index loading */
function addShard(obj, dates = null) {
  let row = 0;
  const fields = obj.fields || manifest.fields || ['id', 'title', 'project', 'year', 'severity', 'status', 'leaf', 'mode', 'shard', 'finding_id'];
  const at = Object.fromEntries(fields.map((f, i) => [f, i]));
  const dicts = obj.dicts || manifest.dicts || {};
  const sevMap = (dicts.severity || SEVERITIES).map((s) => Math.max(0, SEVERITIES.indexOf(s)));
  const stMap = (dicts.status || STATUSES).map((s) => { const i = STATUSES.indexOf(s); return i < 0 ? 4 : i; });
  const modeMap = (dicts.mode || MODES).map((m) => Math.max(0, MODES.indexOf(m)));
  const leafMap = (dicts.leaf || []).map((l) => {
    if (!leafIdx.has(l)) { leafIdx.set(l, leaves.length); leaves.push(l); }
    return leafIdx.get(l);
  });
  const fi = firmIdx.has(obj.firm_id) ? firmIdx.get(obj.firm_id) : -1;
  const fname = fi >= 0 ? FIRMS[fi].name.toLowerCase() : '';
  if (at.selected != null) hasSel = true;
  const projects = obj.projects || [];
  const rows = obj.rows || [];
  for (const r of rows) {
    const proj = typeof r[at.project] === 'number' ? projects[r[at.project]] || '' : r[at.project] || '';
    const sevRaw = r[at.severity];
    const sev = typeof sevRaw === 'number' ? sevMap[sevRaw] ?? 6 : Math.max(0, SEVERITIES.indexOf(sevRaw));
    const stRaw = r[at.status];
    const st = typeof stRaw === 'number' ? stMap[stRaw] ?? 4 : (STATUSES.indexOf(stRaw) < 0 ? 4 : STATUSES.indexOf(stRaw));
    const lfRaw = r[at.leaf];
    let lf = -1;
    if (typeof lfRaw === 'number') lf = lfRaw >= 0 ? leafMap[lfRaw] : -1;
    else if (lfRaw) { if (!leafIdx.has(lfRaw)) { leafIdx.set(lfRaw, leaves.length); leaves.push(lfRaw); } lf = leafIdx.get(lfRaw); }
    const leafName = lf >= 0 ? leaves[lf] : '';
    const gname = leafName ? leafName.split('.')[0] : '';
    let g = -1;
    if (gname) { if (!groupIdx.has(gname)) { groupIdx.set(gname, groups.length); groups.push(gname); } g = groupIdx.get(gname); }
    const mRaw = r[at.mode];
    const mode = typeof mRaw === 'number' ? modeMap[mRaw] ?? 0 : Math.max(0, MODES.indexOf(mRaw));
    const title = r[at.title] || '';
    const pid = r[at.finding_id] || '';
    S.id.push(r[at.id]);
    S.title.push(title);
    S.firm.push(fi);
    S.project.push(proj);
    S.date.push(dates ? dates[row] || 0 : 0);
    row++;
    S.projLower.push(String(proj || '').toLowerCase());
    S.year.push(r[at.year] || 0);
    S.sev.push(sev);
    S.status.push(st);
    S.leaf.push(lf);
    S.group.push(g);
    S.mode.push(mode);
    S.shard.push(r[at.shard] || 0);
    S.pid.push(pid);
    S.sel.push(at.selected == null ? 1 : (r[at.selected] ? 1 : 0));
    S.hay.push(`${title} \u0001${proj} \u0001${fname} \u0001${leafName.replace(/[._]/g, ' ')} \u0001${pid}`.toLowerCase());
  }
}

function filesFor(st) {
  if (st.firm.size) return manifest.shards.filter((s) => st.firm.has(s.firm_id));
  return manifest.shards;
}

async function ensureLoaded(st) {
  const want = filesFor(st).filter((s) => !loadedFiles.has(s.file) && !failedFiles.has(s.file));
  if (!want.length) { setProgress(); return; }
  const queue = want.slice();
  const worker = async () => {
    while (queue.length) {
      const s = queue.shift();
      if (loadedFiles.has(s.file)) continue;
      let p = loadingFiles.get(s.file);
      if (!p) {
        // Exact dates come from a small parallel file (one code per index row) written by the site build.
        const dates = fetch(`assets/sdates/${s.file}`).then((r) => (r.ok ? r.json() : null)).catch(() => null);
        p = Promise.all([searchShard(s.file), dates]).then(([obj, d]) => {
          if (!obj.firm_id) obj.firm_id = s.firm_id;
          addShard(obj, Array.isArray(d) && d.length === (obj.rows || []).length ? d : null);
          loadedFiles.add(s.file);
          loadingFiles.delete(s.file);
          setProgress();
          scheduleUpdate(true);
        }).catch((err) => {
          // One unreadable file should not take the rest of the index down with it.
          failedFiles.add(s.file);
          loadingFiles.delete(s.file);
          console.warn(err);
          setProgress();
        });
        loadingFiles.set(s.file, p);
      }
      await p;
    }
  };
  await Promise.all(Array.from({ length: 6 }, worker));
  setProgress();
}

function setProgress() {
  const el = document.getElementById('progress');
  const need = filesFor(state);
  const done = need.filter((s) => loadedFiles.has(s.file) || failedFiles.has(s.file)).length;
  const failed = need.filter((s) => failedFiles.has(s.file));
  const total = manifest.shards.reduce((a, s) => a + (s.count || 0), 0);
  const ready = done === need.length;
  el.dataset.state = ready ? 'ready' : 'loading';
  el.querySelector('i').style.width = `${(100 * done) / Math.max(1, need.length)}%`;
  el.querySelector('.bar').hidden = ready;
  el.querySelector('.txt').textContent = ready
    ? `${int(S.id.length)} finding records indexed${S.id.length < total ? ` (of ${int(total)}; the rest load when you widen the firm filter)` : ''}.${failed.length ? ` ${failed.length} index ${failed.length === 1 ? 'file' : 'files'} could not load (${failed.map((s) => s.firm_id).join(', ')}); reload the page to try again.` : ''}`
    : `Loading the search index: ${done} of ${need.length} files, ${int(S.id.length)} finding records so far.`;
}

/* ------------------------------------------------------------------ filtering */
function compute() {
  const tokens = state.q.toLowerCase().split(/\s+/).filter(Boolean);
  const sevF = state.sev.size ? new Set([...state.sev].map((s) => SEVERITIES.indexOf(s))) : null;
  const stF = state.status.size ? new Set([...state.status].map((s) => STATUSES.indexOf(s))) : null;
  const modeF = state.mode.size ? new Set([...state.mode].map((s) => MODES.indexOf(s))) : null;
  const grpF = state.group.size ? new Set([...state.group].map((g) => (groupIdx.has(g) ? groupIdx.get(g) : -2))) : null;
  const leafF = state.leaf ? (leafIdx.has(state.leaf) ? leafIdx.get(state.leaf) : -2) : null;
  const firmF = state.firm.size ? new Set([...state.firm].map((f) => (firmIdx.has(f) ? firmIdx.get(f) : -2))) : null;
  // Project filter (p=uniswap or p=makerdao,sky token): any term matching at the start of a word in the project name.
  const projRe = state.p ? state.p.split(',').map((t) => t.trim()).filter(Boolean).map((t) => new RegExp(`(^|[^a-z0-9])${escapeRe(t)}`)) : null;
  const from = state.from || 0;
  const to = state.to || 9999;
  const yearF = state.from || state.to;
  const counts = { sev: new Array(7).fill(0), status: new Array(5).fill(0), mode: [0, 0], group: new Array(groups.length).fill(0), firm: new Array(FIRMS.length).fill(0), year: new Map(), sel: 0 };
  const res = [];
  const N = S.id.length;
  for (let i = 0; i < N; i++) {
    if (tokens.length) {
      const h = S.hay[i];
      let ok = true;
      for (const t of tokens) if (!h.includes(t)) { ok = false; break; }
      if (!ok) continue;
    }
    if (leafF !== null && S.leaf[i] !== leafF) continue;
    if (projRe && !projRe.some((re) => re.test(S.projLower[i]))) continue;
    const fSev = sevF && !sevF.has(S.sev[i]);
    const fSt = stF && !stF.has(S.status[i]);
    const fMode = modeF && !modeF.has(S.mode[i]);
    const fGrp = grpF && !grpF.has(S.group[i]);
    const fFirm = firmF && !firmF.has(S.firm[i]);
    const y = S.year[i];
    const fYear = yearF && (y < from || y > to || !y);
    const fSel = state.stats && !S.sel[i];
    const fails = (fSev ? 1 : 0) + (fSt ? 1 : 0) + (fMode ? 1 : 0) + (fGrp ? 1 : 0) + (fFirm ? 1 : 0) + (fYear ? 1 : 0) + (fSel ? 1 : 0);
    if (fails > 1) continue;
    if (fails === 0) {
      res.push(i);
      counts.sev[S.sev[i]]++; counts.status[S.status[i]]++; counts.mode[S.mode[i]]++;
      if (S.group[i] >= 0) counts.group[S.group[i]]++;
      if (S.firm[i] >= 0) counts.firm[S.firm[i]]++;
      counts.year.set(y, (counts.year.get(y) || 0) + 1);
      if (S.sel[i]) counts.sel++;
    } else if (fSev) counts.sev[S.sev[i]]++;
    else if (fSt) counts.status[S.status[i]]++;
    else if (fMode) counts.mode[S.mode[i]]++;
    else if (fGrp) { if (S.group[i] >= 0) counts.group[S.group[i]]++; }
    else if (fFirm) { if (S.firm[i] >= 0) counts.firm[S.firm[i]]++; }
    else if (fYear) counts.year.set(y, (counts.year.get(y) || 0) + 1);
  }
  if (state.stats) counts.sel = res.length;
  // sort
  const sort = state.sort === 'relevance' && !tokens.length ? 'new' : state.sort;
  if (sort === 'relevance') {
    const res2 = tokens.map((tok) => new RegExp(`(^|[^a-z0-9])${escapeRe(tok)}`));
    const score = new Float64Array(S.id.length);
    for (const i of res) {
      const t = S.hay[i];
      const end = t.indexOf(' \u0001');
      let sc = 0;
      for (let k = 0; k < tokens.length; k++) {
        const at = t.indexOf(tokens[k]);
        sc += at >= 0 && at < end ? (res2[k].test(t.slice(0, end)) ? 3 : 2) : 1;
      }
      score[i] = sc;
    }
    res.sort((a, b) => score[b] - score[a] || dayKey(b, 0) - dayKey(a, 0) || S.sev[a] - S.sev[b] || a - b);
  } else if (sort === 'new') res.sort((a, b) => dayKey(b, 0) - dayKey(a, 0) || a - b);
  else if (sort === 'old') res.sort((a, b) => (dayKey(a, 9999) || 1e9) - (dayKey(b, 9999) || 1e9) || a - b);
  else if (sort === 'sev') res.sort((a, b) => S.sev[a] - S.sev[b] || dayKey(b, 0) - dayKey(a, 0) || a - b);
  return { res, counts, tokens };
}
// Sort key: YYYYMMDD for dated audits; year-only rows take day `pad` of their year (0 sorts them after the dated
// rows of that year when newest comes first). Ties keep index order, which follows report and finding order.
// Index row of a finding (for its date), found once per id.
let rowById = null;
function rowOf(f) {
  if (!rowById || rowById.size !== S.id.length) rowById = new Map(S.id.map((id, i) => [id, i]));
  const i = rowById.get(String(f.finding_uid || '').split(':').pop().slice(0, 12));
  return i == null ? -1 : i;
}
const dayKey = (i, pad) => (S.date[i] ? Math.floor(S.date[i] / 10) : S.year[i] ? S.year[i] * 10000 + pad : 0);
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/* ------------------------------------------------------------------ rendering */
let updTimer = 0;
let lastUpd = 0;
function scheduleUpdate(fromLoad = false) {
  clearTimeout(updTimer);
  const wait = fromLoad ? Math.max(0, 250 - (performance.now() - lastUpd)) : 90;
  updTimer = setTimeout(update, wait);
}

function update() {
  lastUpd = performance.now();
  const { res, counts, tokens } = compute();
  lastResults = res;
  renderFilters(counts);
  renderActive();
  renderResults(res, tokens);
  if (!state.f) searchTitle();
  // Without a query, best match and newest first are the same order; the menu says so.
  const sortEl = document.getElementById('sort');
  if (sortEl) sortEl.value = state.sort === 'relevance' && !state.q ? 'new' : state.sort;
  const share = document.getElementById('share-search');
  if (share) share.hidden = !(state.q || state.p || state.firm.size || state.sev.size || state.group.size || state.leaf || state.status.size || state.mode.size || state.from || state.to);
}

// A search that has a query or filters gets its own tab title, so bookmarks and history read well.
function searchTitle() {
  const what = state.p ? `${state.p.split(',')[0].replace(/^./, (c) => c.toUpperCase())} findings`
    : state.q ? `“${state.q}” findings`
      : state.firm.size === 1 ? `${FIRMS[firmIdx.get([...state.firm][0])]?.name || ''} findings` : '';
  setTitle(what);
}

function facetList(name, items) {
  if (!items.length) return '<p class="facet-note">None in these results.</p>';
  return `<ul class="facet${items.length > 12 ? ' scroll' : ''}">${items.map((it) => `
    <li><label><input type="checkbox" name="${name}" value="${esc(it.value)}"${it.checked ? ' checked' : ''}>
    <span class="lab">${it.swatch || ''}${esc(it.label)}</span><span class="ct">${it.count == null ? '' : int(it.count)}</span></label></li>`).join('')}</ul>`;
}

function renderFilters(counts) {
  const el = document.getElementById('filters');
  const active = document.activeElement;
  const activeKey = active && el.contains(active) ? `${active.name}|${active.value}|${active.id}` : null;
  const firmQ = (document.getElementById('firm-q')?.value || '').toLowerCase();
  const yearsAll = [...new Set(S.year.length ? [...counts.year.keys()] : [])].filter(Boolean).sort();
  const years = yearsAll.length ? yearsAll : [];
  const loadedYears = [...new Set(S.year)].filter(Boolean).sort();
  const loadedFirms = new Set(manifest.shards.filter((s) => loadedFiles.has(s.file)).map((s) => s.firm_id));
  // Publishers with metadata-only audits have no finding index, so they never appear as an empty facet.
  const indexedFirms = new Set(manifest.shards.filter((s) => (s.count ?? 1) > 0).map((s) => s.firm_id));
  const firmItems = FIRMS.map((f, i) => ({ value: f.firm_id, label: f.name, count: loadedFirms.has(f.firm_id) ? counts.firm[i] : null, checked: state.firm.has(f.firm_id) }))
    .filter((it) => it.checked || (indexedFirms.has(it.value) && (it.count == null || it.count > 0)))
    .filter((it) => !firmQ || it.label.toLowerCase().includes(firmQ))
    .sort((a, b) => Number(b.checked) - Number(a.checked) || (b.count ?? -1) - (a.count ?? -1) || a.label.localeCompare(b.label));
  const groupItems = groups.map((g, i) => ({ value: g, label: groupLabel(g, TAX), count: counts.group[i], checked: state.group.has(g) }))
    .filter((it) => it.count > 0 || it.checked).sort((a, b) => b.count - a.count);
  el.innerHTML = `
    ${hasSel ? `<fieldset><legend>Report copies</legend>${facetList('stats', [{ value: '1', label: 'Initial report only', count: counts.sel, checked: state.stats }])}<p class="facet-note">One initial report per audit; leaves out revisions, fix reviews and other copies.</p></fieldset>` : ''}
    <fieldset><legend>Severity</legend>${facetList('sev', SEVERITIES.map((s, i) => ({ value: s, label: SEVERITY_LABEL[s], count: counts.sev[i], checked: state.sev.has(s), swatch: `<i class="swatch sev-${s}"></i>` })))}</fieldset>
    <fieldset><legend>Review type</legend>${facetList('mode', MODES.map((m, i) => ({ value: m, label: MODE_LABEL[m], count: counts.mode[i], checked: state.mode.has(m) })))}</fieldset>
    <fieldset><legend>Fix status</legend>${facetList('status', STATUSES.map((s, i) => ({ value: s, label: STATUS_LABEL[s], count: counts.status[i], checked: state.status.has(s) })))}</fieldset>
    <fieldset><legend>Year</legend><div class="yr-range">
      <label class="sr-only" for="yr-from">From year</label><select id="yr-from"><option value="0">Any</option>${loadedYears.map((y) => `<option value="${y}"${state.from === y ? ' selected' : ''}>${y}</option>`).join('')}</select>
      <span aria-hidden="true">to</span>
      <label class="sr-only" for="yr-to">To year</label><select id="yr-to"><option value="0">Any</option>${loadedYears.map((y) => `<option value="${y}"${state.to === y ? ' selected' : ''}>${y}</option>`).join('')}</select>
    </div></fieldset>
    <fieldset class="wide"><legend>Vulnerability class</legend>${facetList('cls', groupItems)}</fieldset>
    <fieldset class="wide"><legend>Firm or platform</legend>
      <label class="sr-only" for="firm-q">Filter the firm list</label>
      <input type="search" id="firm-q" placeholder="Filter firms" value="${esc(firmQ)}" autocomplete="off" style="width:100%;margin-bottom:8px">
      ${facetList('firm', firmItems)}
      ${termsFirms().length ? `<p class="facet-note terms-facet">Partly in the search: ${firmLinks(termsFirms())}. Findings from reports on ${termsFirms().length === 1 ? 'the publisher\u2019s' : 'their'} own sites are not reproduced, because the site terms do not allow automated copying; those audits are on the firm pages, with links to the originals. Findings these publishers released elsewhere, where reuse is allowed, are searchable.</p>` : ''}</fieldset>`;
  void years;
  if (activeKey) {
    const [n, v, id] = activeKey.split('|');
    const again = id ? document.getElementById(id) : el.querySelector(`input[name="${n}"][value="${CSS.escape(v)}"]`);
    if (again) { again.focus(); if (id === 'firm-q') { again.setSelectionRange(again.value.length, again.value.length); } }
  }
}

function renderActive() {
  const el = document.getElementById('active-filters');
  const pills = [];
  const x = '<svg viewBox="0 0 14 14" aria-hidden="true"><path d="M3.5 3.5l7 7m0-7l-7 7" stroke="currentColor" stroke-width="1.5"/></svg>';
  for (const s of state.sev) pills.push(['sev', s, SEVERITY_LABEL[s]]);
  for (const s of state.mode) pills.push(['mode', s, MODE_LABEL[s]]);
  for (const s of state.status) pills.push(['status', s, STATUS_LABEL[s]]);
  for (const g of state.group) pills.push(['group', g, groupLabel(g, TAX)]);
  if (state.leaf) pills.push(['leaf', state.leaf, leafInfo(state.leaf, TAX)?.name || state.leaf]);
  if (state.p) pills.push(['p', '', `Project: ${state.p.split(',')[0]}`]);
  for (const f of state.firm) pills.push(['firm', f, FIRMS[firmIdx.get(f)]?.name || f]);
  if (state.stats) pills.push(['stats', '', 'Initial report only']);
  if (state.from || state.to) pills.push(['year', '', `${state.from || 'Any'} to ${state.to || 'any'}`]);
  el.innerHTML = pills.map(([k, v, l]) => `<button type="button" class="pill" data-k="${k}" data-v="${esc(v)}" aria-label="Remove filter: ${esc(l)}">${esc(l)}${x}</button>`).join('');
  document.getElementById('clear-all').hidden = !pills.length && !state.q;
}

function hl(text, tokens) {
  let out = esc(text);
  if (!tokens.length) return out;
  const re = new RegExp(`(${tokens.map((t) => escapeRe(esc(t))).join('|')})`, 'gi');
  return out.replace(re, '<mark>$1</mark>');
}

function findingKey(i) {
  const f = FIRMS[S.firm[i]];
  return `${f ? f.firm_id : ''}:${S.shard[i]}:${S.id[i]}`;
}

function renderResults(res, tokens) {
  const total = res.length;
  const ready = document.getElementById('progress').dataset.state === 'ready';
  const unit = state.stats ? (total === 1 ? 'initial finding' : 'initial findings') : (total === 1 ? 'finding record' : 'finding records');
  document.getElementById('res-count').innerHTML = `${int(total)} ${unit}${ready ? '' : ' <span class="muted">so far</span>'}`;
  const list = document.getElementById('results');
  const slice = res.slice(0, shown);
  list.innerHTML = slice.map((i) => {
    const f = FIRMS[S.firm[i]];
    const sev = SEVERITIES[S.sev[i]];
    const key = findingKey(i);
    const g = S.group[i] >= 0 ? groupLabel(groups[S.group[i]], TAX) : '';
    const d = fromCode(S.date[i]);
    return `<li class="result"><a href="finding.html?id=${esc(S.id[i])}" data-f="${esc(key)}"${state.f === key ? ' aria-current="true"' : ''}>
      <span class="r-sev">${sevBadge(sev, S.pid[i])}</span>
      <span class="r-title">${hl(S.title[i] || '(untitled finding)', tokens)}</span>
      <span class="r-meta"><span class="r-firm">${esc(f ? f.name : '')}</span>${S.project[i] ? `<span>${hl(S.project[i], tokens)}</span>` : ''}<span>${dateHTML(d?.iso, d?.basis, S.year[i], esc)}</span>${g ? `<span>${esc(g)}</span>` : ''}<span>${esc(MODE_LABEL[MODES[S.mode[i]]])}</span></span>
    </a></li>`;
  }).join('');
  const more = document.getElementById('more');
  more.innerHTML = total > shown ? `<button type="button" id="more-btn">Show ${int(Math.min(PAGE, total - shown))} more</button>` : '';
  // A selected publisher with terms-restricted reports: say what the results leave out, above them.
  const blocked = termsFirms().filter((f) => state.firm.has(f.firm_id));
  if (ready && blocked.length && total) {
    list.insertAdjacentHTML('afterbegin', `<li class="terms-note">Some reports from ${firmLinks(blocked)} are not reproduced: the publisher\u2019s site terms do not allow automated copying. Their findings are counted on the firm page and are not in these results.</li>`);
  }
  if (!total) {
    const anyFilter = state.p || state.q || state.sev.size || state.status.size || state.mode.size || state.group.size || state.firm.size || state.from || state.to || state.leaf || state.stats;
    list.innerHTML = ready && blocked.length && !(state.q || state.sev.size || state.status.size || state.group.size || state.leaf) && !blocked.some(released)
      ? `<li class="empty terms-note">Report text not reproduced for ${firmLinks(blocked)}: the publisher\u2019s site terms do not allow automated copying. The audits are listed on the firm page, with links to the originals.</li>`
      : ready && blocked.length
      ? `<li class="empty terms-note">No released findings match. Some reports from ${firmLinks(blocked)} are not reproduced, because the publisher\u2019s site terms do not allow automated copying; their findings are counted on the firm page.</li>`
      : ready
      ? `<li class="empty">${anyFilter ? 'No findings match this search. Remove a filter or try a shorter word; search matches titles, projects, firm names and classes.' : 'The index is empty.'}</li>`
      : '<li class="empty">Searching as the index loads…</li>';
  }
}

/* ------------------------------------------------------------------ detail */
async function openDetail(key, { focus = true } = {}) {
  const wrap = document.getElementById('detail');
  const grid = document.getElementById('ex-grid');
  if (!key) { wrap.hidden = true; grid.classList.remove('has-detail'); document.body.style.overflow = ''; return; }
  const [firmId, shardStr, id] = key.split(':');
  grid.classList.add('has-detail');
  wrap.hidden = false;
  if (window.matchMedia('(max-width: 1180px)').matches) document.body.style.overflow = 'hidden';
  wrap.innerHTML = '<p class="loading">Loading the finding…</p>';
  try {
    const match = (list) => list.find((x) => String(x.finding_uid || '').split(':').pop().startsWith(id)) || list.find((x) => x.finding_uid === id);
    let f = match(await findingShard(firmId, Number(shardStr) || 0));
    // Links stay valid across releases: when the shard numbering changed, look through the publisher's other shards.
    const n = FIRMS[firmIdx.get(firmId)]?.finding_shards || 0;
    for (let s = 0; !f && s < n; s++) if (s !== (Number(shardStr) || 0)) f = match(await findingShard(firmId, s));
    if (!f) throw new Error('This finding is not in the current data. Search for it again');
    renderDetail(f, firmId, key);
    setTitle(f.title || '');
    if (focus) wrap.querySelector('h2')?.focus({ preventScroll: false });
  } catch (e) {
    wrap.innerHTML = `<div class="d-top"><span></span><button class="d-close" type="button">Close</button></div><p class="empty">${esc(e.message)}.</p>`;
  }
}

function statusOriginalLabel(value) {
  const label = String(value || '').trim().replace(/\s+/g, ' ');
  const key = (s) => s.toLowerCase().replace(/[\s_-]+/g, '');
  const labels = [...Object.values(STATUS_LABEL), 'Resolved', 'Open', 'Closed', 'Accepted', 'Mitigated', 'Pending', 'Partially resolved', 'Not fixed'];
  return labels.find((s) => key(s) === key(label)) || label;
}

function renderDetail(f, firmId, key) {
  const wrap = document.getElementById('detail');
  const firm = FIRMS[firmIdx.get(firmId)];
  const sev = SEVERITIES.includes(f.severity) ? f.severity : 'unknown';
  const leaf = f.vuln_leaf || '';
  const info = leafInfo(leaf, TAX);
  const pages = f.page_start ? (f.page_end && f.page_end !== f.page_start ? `pages ${f.page_start} to ${f.page_end}` : `page ${f.page_start}`) : '';
  const url = f.url || f.report_url || f.permalink || '';
  const pdfLink = url && /\.pdf($|\?)/i.test(url) && f.page_start && !/github\.com\/.+\/blob\//.test(url) ? `${url}#page=${f.page_start}` : url;
  const sha = f.report_id || f.report_sha256 || f.sha256 || '';
  const sevNorm = (x) => String(x || '').toLowerCase().replace(/[^a-z]/g, '');
  const sevOrig = f.severity_original && ![sev, SEVERITY_LABEL[sev]].map(sevNorm).includes(sevNorm(f.severity_original)) ? ` <span class="muted">(printed as “${esc(f.severity_original)}”)</span>` : '';
  const statusOriginal = statusOriginalLabel(f.status_original);
  const stOrig = statusOriginal && statusOriginal.toLowerCase() !== (STATUS_LABEL[f.status] || f.status || '').toLowerCase() ? ` <span class="muted">(printed as “${esc(statusOriginal)}”)</span>` : '';
  const oak = firmId === 'oak-security' || firmId === 'oak';
  const withheld = Boolean(f.text_withheld) || ['withheld_by_notice', 'publisher_notice', 'oak_transform_required', TERMS].includes(f.body_text_status);
  const body = withheld ? ([f.text_withheld, f.body_text_status].includes(TERMS) ? TERMS_NOTE : f.text_withheld === 'oak_transform_required'
    ? 'Text withheld because the required character changes would alter the CC BY-ND material. Read the original report using the link above.'
    : 'Text withheld under a publisher notice. Read the original report using the link above.') : (f.body_text || f.body || '');
  const excerptNote = oak && !withheld && f.body_truncated;
  const correction = repo ? `${repo}/issues/new?title=${encodeURIComponent(`Correction: ${f.finding_uid || key}`)}&body=${encodeURIComponent(`Finding: ${f.title}\nFirm: ${firm?.name || firmId}\nReport: ${url}\n\nWhat is wrong:\n`)}` : '';
  wrap.innerHTML = `
    <div class="d-top">${sevBadge(sev, f.finding_id)}
    <button class="d-close" type="button">Close</button></div>
    <h2 tabindex="-1">${esc(f.title || '(untitled finding)')}</h2>
    <div class="d-share"><a class="share-page" href="${esc(findingPage(f))}">Open the finding page</a><button type="button" class="share-copy" data-url="${esc(findingURL(f))}">Copy link</button><a class="share-x" href="${esc(`https://x.com/intent/tweet?text=${encodeURIComponent(`${f.title || 'Audit finding'} (${SEVERITY_LABEL[sev]}, ${firm?.name || firmId})`)}&url=${encodeURIComponent(findingURL(f))}`)}" target="_blank" rel="noopener noreferrer">Post on X</a></div>
    <dl class="facts">
      <dt>Publisher</dt><dd><a href="firms.html?id=${encodeURIComponent(firmId)}">${esc(firm?.name || firmId)}</a></dd>
      ${f.project ? `<dt>Project</dt><dd>${esc(f.project)}</dd>` : ''}
      ${(() => { const d = fromCode(S.date[rowOf(f)]); return `<dt>${d ? (d.basis === 'c' ? 'Completed' : 'Report date') : 'Year'}</dt><dd>${dateHTML(d?.iso, d?.basis, f.audit_year, esc)}</dd>`; })()}
      <dt>Review</dt><dd>${esc(MODE_LABEL[f.review_mode] || f.review_mode || 'Unknown')}</dd>
      <dt>Severity</dt><dd>${esc(SEVERITY_LABEL[sev])}${sevOrig}</dd>
      <dt>Status</dt><dd>${esc(STATUS_LABEL[f.status] || f.status || 'Not stated')}${stOrig}</dd>
      ${f.selected_for_stats != null ? `<dt>Report copy</dt><dd>${f.selected_for_stats ? 'Initial report' : 'Additional occurrence: revision, fix review, reference label or alternate copy'}</dd>` : ''}
      <dt>Class</dt><dd>${leaf ? `${esc(info?.group?.name || groupLabel(leaf.split('.')[0], TAX))}: ${esc(info?.name || leaf)}${info?.definition ? `<div class="class-def">${esc(info.definition)}</div>` : ''}<div class="class-def"><a href="${esc(toHash({ ...defaultState(), leaf }))}" data-leaf="${esc(leaf)}">More findings in this class</a></div>` : 'Not classified'}</dd>
    </dl>
    <div class="source-box">
      <h3>Original report</h3>
      ${url ? `<a class="src" href="${esc(pdfLink)}" target="_blank" rel="noopener noreferrer">${esc(shortUrl(url))}</a>` : '<p>No public link recorded.</p>'}
      ${f.permalink && f.permalink !== url ? `<div><a href="${esc(f.permalink)}" target="_blank" rel="noopener noreferrer">Pinned copy</a>${f.archive_url ? ` <a href="${esc(f.archive_url)}" target="_blank" rel="noopener noreferrer" style="margin-left:10px">Archived copy</a>` : ''}</div>` : ''}
      ${pages ? `<div>Finding on ${esc(pages)} of the report.</div>` : ''}
      ${oak ? `<div class="text-rights">Attribution: <a href="${esc(f.text_source_url || url)}" target="_blank" rel="noopener noreferrer">${esc(f.text_attribution || 'Oak Security')}</a>. Licensed under <a href="${esc(f.text_license_url || 'https://creativecommons.org/licenses/by-nd/4.0/')}" target="_blank" rel="license noopener noreferrer">${esc(f.text_license || 'CC BY-ND 4.0')}</a>; released text is a verbatim excerpt.</div>` : ''}
      ${sha ? `<div style="margin-top:6px">SHA-256 <button class="copy" type="button" data-copy="${esc(sha)}">Copy</button><div class="hash">${esc(sha)}</div></div>` : ''}
    </div>
    <div class="body-text${withheld || !body ? '' : ' md-body'}" tabindex="0" aria-label="Finding text as extracted from the report">${withheld ? esc(body) : body ? renderMarkdown(withoutTitle(body, f.title)) : esc(f.source === 'gold_label' ? 'An LLM-annotated reference finding from the accuracy test set. The release records its title, severity and location; read the full text in the original report.' : 'No text was extracted for this finding.')}</div>
    ${excerptNote ? `<p class="body-truncation-note">[truncated; see the linked report] <a href="${esc(f.text_source_url || url)}" target="_blank" rel="noopener noreferrer">Read the original report</a>.</p>` : ''}
    <p class="d-note">${withheld ? 'Metadata and source link retained.' : 'Text as extracted from the report; layout and code listings may be imperfect.'} ${correction ? `<a href="${esc(correction)}" target="_blank" rel="noopener noreferrer">Report a correction</a>.` : ''}</p>`;
  document.querySelectorAll('.result a').forEach((a) => a.toggleAttribute('aria-current', a.dataset.f === key));
}

// Each finding has its own page; that is the link to share.
function findingPage(f) {
  return `finding.html?id=${String(f.finding_uid || '').split(':').pop().slice(0, 12)}`;
}
function findingURL(f) {
  return new URL(findingPage(f), location.href).href;
}

function setTitle(text) {
  document.title = text ? `${text} | ${BASE_TITLE.split(' | ').pop()}` : BASE_TITLE;
}

function shortUrl(u) {
  try {
    const x = new URL(u);
    const path = decodeURIComponent(x.pathname);
    const p = path.length > 60 ? `${path.slice(0, 28)}…${path.slice(-28)}` : path;
    return `${x.hostname}${p}`;
  } catch { return u; }
}

/* ------------------------------------------------------------------ events */
function bind() {
  const q = document.getElementById('q');
  const sort = document.getElementById('sort');
  q.value = state.q;
  sort.value = state.sort;
  q.addEventListener('input', () => { state.q = q.value.trim(); shown = PAGE; commit(); scheduleUpdate(); });
  document.getElementById('search-form').addEventListener('submit', (e) => { e.preventDefault(); scheduleUpdate(); });
  sort.addEventListener('change', () => { state.sort = sort.value; shown = PAGE; commit(); update(); });
  const ft = document.getElementById('filter-toggle');
  ft.addEventListener('click', () => {
    const open = document.getElementById('filters').classList.toggle('open');
    ft.setAttribute('aria-expanded', String(open));
  });
  const filters = document.getElementById('filters');
  filters.addEventListener('change', (e) => {
    const t = e.target;
    if (t.id === 'yr-from' || t.id === 'yr-to') {
      state[t.id === 'yr-from' ? 'from' : 'to'] = Number(t.value) || 0;
    } else if (t.name === 'stats') {
      state.stats = t.checked;
    } else if (t.type === 'checkbox') {
      const key = { sev: 'sev', mode: 'mode', status: 'status', cls: 'group', firm: 'firm' }[t.name];
      if (t.checked) state[key].add(t.value); else state[key].delete(t.value);
      if (key === 'firm') ensureLoaded(state);
    } else return;
    shown = PAGE;
    commit();
    update();
  });
  filters.addEventListener('input', (e) => { if (e.target.id === 'firm-q') update(); });
  document.getElementById('active-filters').addEventListener('click', (e) => {
    const b = e.target.closest('.pill');
    if (!b) return;
    const { k, v } = b.dataset;
    if (k === 'year') { state.from = 0; state.to = 0; } else if (k === 'stats') state.stats = false; else if (k === 'leaf') state.leaf = ''; else if (k === 'p') state.p = ''; else state[k].delete(v);
    if (k === 'firm') ensureLoaded(state);
    shown = PAGE; commit(); update();
    document.getElementById('q').focus();
  });
  const shareBtn = document.getElementById('share-search');
  shareBtn?.addEventListener('click', () => { copyText(location.href).then((ok) => flash(shareBtn, ok, 'Copy link to this search')); });
  document.getElementById('clear-all').addEventListener('click', () => {
    state = { ...defaultState(), sort: state.sort, f: state.f };
    q.value = '';
    shown = PAGE; commit(); ensureLoaded(state); update();
  });
  document.getElementById('more').addEventListener('click', (e) => {
    if (e.target.id !== 'more-btn') return;
    const before = shown;
    shown += PAGE;
    renderResults(lastResults, state.q.toLowerCase().split(/\s+/).filter(Boolean));
    document.querySelectorAll('.result a')[before]?.focus();
  });
  document.getElementById('results').addEventListener('click', (e) => {
    const a = e.target.closest('a[data-f]');
    if (!a || e.metaKey || e.ctrlKey || e.shiftKey || e.button) return;
    e.preventDefault();
    lastFocus = a;
    state.f = a.dataset.f;
    commit(true);
    openDetail(state.f);
  });
  const detail = document.getElementById('detail');
  detail.addEventListener('click', async (e) => {
    if (e.target.closest('.d-close')) { closeDetail(); return; }
    const sc = e.target.closest('.share-copy');
    if (sc) { copyText(sc.dataset.url).then((ok) => flash(sc, ok, 'Copy link')); return; }
    const c = e.target.closest('.copy');
    if (c) {
      try { await navigator.clipboard.writeText(c.dataset.copy); c.textContent = 'Copied'; } catch { c.textContent = 'Select and copy'; }
      setTimeout(() => { c.textContent = 'Copy'; }, 1600);
      return;
    }
    const l = e.target.closest('a[data-leaf]');
    if (l) {
      e.preventDefault();
      state = { ...defaultState(), leaf: l.dataset.leaf };
      q.value = '';
      commit(true); closeDetail(false); ensureLoaded(state); update();
    }
  });
  document.getElementById('detail-wrap').addEventListener('click', (e) => { if (e.target.id === 'detail-wrap') closeDetail(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && state.f) closeDetail(); });
  window.addEventListener('hashchange', () => {
    if (writing) return;
    const prevF = state.f;
    state = parseHash();
    q.value = state.q; sort.value = state.sort;
    shown = PAGE;
    ensureLoaded(state);
    update();
    if (state.f !== prevF) openDetail(state.f, { focus: false });
  });
  window.addEventListener('popstate', () => {});
}

function closeDetail(writeUrl = true) {
  state.f = '';
  searchTitle();
  if (writeUrl) commit(true);
  openDetail('');
  document.querySelectorAll('.result a[aria-current]').forEach((a) => a.removeAttribute('aria-current'));
  if (lastFocus && document.body.contains(lastFocus)) lastFocus.focus();
}

export default async function explorer() {
  try {
    const [cfg, fs, man, tax, sum] = await Promise.all([config(), loadFirms(), searchManifest(), taxonomy(), summary().catch(() => ({}))]);
    setTermsPolicy(sum);
    repo = (cfg.repo || '').replace(/\/$/, '');
    TAX = tax;
    FIRMS = fs.slice().sort((a, b) => a.name.localeCompare(b.name));
    firmIdx = new Map(FIRMS.map((f, i) => [f.firm_id, i]));
    manifest = man;
    // smallest files first, so many firms appear quickly while the large files stream in
    manifest.shards = manifest.shards.slice().sort((a, b) => (a.count || 0) - (b.count || 0));
    state = parseHash();
    bind();
    const total = manifest.shards.reduce((a, s) => a + (s.count || 0), 0);
    if (total) document.getElementById('ex-dek').textContent = `Search ${int(total)} findings by title, project, firm and class; open any finding for its text, metadata and a link to the original report.`;
    setProgress();
    update();
    if (state.f) openDetail(state.f, { focus: false });
    await ensureLoaded(state);
    update();
  } catch (e) {
    fail(document.getElementById('ex-grid'), e);
    document.getElementById('progress').dataset.state = 'error';
  }
}
