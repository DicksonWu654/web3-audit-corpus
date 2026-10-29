// Firms: a sortable directory of publishers and one page per publisher with its audits and findings.
// Everything here is a count from firms.json and the publisher's engagement file.
import { firms as loadFirms, summary, db, engagements, taxonomy, SEVERITIES, SEVERITY_LABEL, MODE_LABEL, KIND_LABEL, groupLabel } from './data.js';
import { int, pct, esc } from './fmt.js';
import { fail } from './ui.js';
import { figure, columns, hbars, shortYear } from './viz.js';
import { engDate, engKey, dateHTML } from './dates.js';
import { TYPE_LABEL, coverageMap, covMark, covBanner, covNotes, termsCount, isTermsEngagement, setTermsPolicy } from './types.js';

let COV = new Map();
const nFind = (f) => f.findings_released ?? f.findings;
const years = (f) => (f.first_year ? `${f.first_year}${f.last_year && f.last_year !== f.first_year ? ` to ${f.last_year}` : ''}` : 'n/a');

export default async function firmsPage() {
  const main = document.getElementById('firms-main');
  const id = new URLSearchParams(location.search).get('id');
  try {
    const [fs, tax, sum, D] = await Promise.all([loadFirms(), taxonomy(), summary().catch(() => ({})), db()]);
    COV = coverageMap(fs, sum);
    setTermsPolicy(sum);
    if (id) {
      const f = fs.find((x) => x.firm_id === id);
      if (!f || !(f.engagements > 0)) {
        history.replaceState(null, '', 'firms.html');
        renderIndex(main, fs);
        return;
      }
      await renderFirm(main, f, tax, D);
    } else renderIndex(main, fs);
  } catch (e) {
    fail(main, e);
  }
}

function renderIndex(main, fs) {
  const active = fs.filter((f) => (f.engagements || 0) > 0).map((f) => ({ ...f, findings_released: nFind(f) }));
  let sortKey = 'engagements';
  let dir = -1;
  let filter = '';
  main.innerHTML = `
    <header class="page-head"><h1>Firms and contest platforms</h1>
      <p class="lede">${int(active.length)} publishers with confirmed audits. Select one for its audits, its findings and a link to every report.</p></header>
    <div class="firm-tools"><label class="sr-only" for="firm-filter">Filter publishers</label><input id="firm-filter" type="search" placeholder="Filter by name" autocomplete="off"><span class="muted" id="firm-n"></span></div>
    <div class="tbl-wrap"><table class="firms"><caption class="sr-only">Publishers, sortable</caption><thead><tr>
      <th scope="col" data-k="name"><button type="button">Publisher</button></th>
      <th scope="col" data-k="kind"><button type="button">Type</button></th>
      <th scope="col" data-k="engagements"><button type="button">Audits</button></th>
      <th scope="col" data-k="reports_released"><button type="button">Report files</button></th>
      <th scope="col" data-k="findings_released"><button type="button">Findings</button></th>
      <th scope="col" data-k="first_year"><button type="button">Years</button></th>
    </tr></thead><tbody></tbody></table></div>
    ${covNotes(active.map((f) => f.firm_id), COV)}
    <p class="note" style="margin-top:20px">Audits count engagements, merging revisions and copies of the same report. Findings count searchable finding records, including fix reviews and alternate copies. Collection coverage for each publisher is on the <a href="methodology.html#coverage">data page</a>.</p>`;
  const tbody = main.querySelector('tbody');
  const draw = () => {
    const rows = active.filter((f) => !filter || f.name.toLowerCase().includes(filter)).sort((a, b) => {
      const av = a[sortKey];
      const bv = b[sortKey];
      if (typeof av === 'string' || typeof bv === 'string') return dir * String(av || '').localeCompare(String(bv || ''));
      return dir * ((av ?? -1) - (bv ?? -1));
    });
    tbody.innerHTML = rows.map((f) => `<tr>
      <td class="name"><a href="firms.html?id=${encodeURIComponent(f.firm_id)}">${esc(f.name)}</a>${covMark(f.firm_id, COV)}</td>
      <td class="kind">${esc(KIND_LABEL[f.kind] || f.kind || '')}</td>
      <td class="n-eng">${int(f.engagements)}</td>
      <td class="n-rep">${f.reports_released != null ? int(f.reports_released) : 'n/a'}</td>
      <td class="n-find">${termsCount(f) >= f.engagements && !nFind(f) ? '<span class="muted">Not reproduced</span>' : nFind(f) != null ? int(nFind(f)) : 'n/a'}</td>
      <td class="years">${years(f)}</td></tr>`).join('');
    main.querySelector('#firm-n').textContent = filter ? `${rows.length} of ${active.length}` : '';
    main.querySelectorAll('thead th[data-k]').forEach((th) => {
      if (th.dataset.k === sortKey) th.setAttribute('aria-sort', dir > 0 ? 'ascending' : 'descending'); else th.removeAttribute('aria-sort');
    });
  };
  main.querySelector('thead').addEventListener('click', (e) => {
    const th = e.target.closest('th[data-k]');
    if (!th) return;
    const k = th.dataset.k;
    if (k === sortKey) dir = -dir; else { sortKey = k; dir = ['name', 'kind'].includes(k) ? 1 : -1; }
    draw();
  });
  main.querySelector('#firm-filter').addEventListener('input', (e) => { filter = e.target.value.trim().toLowerCase(); draw(); });
  draw();
}

async function renderFirm(main, f, tax, D) {
  document.title = `${f.name}: audits and findings | ${document.title.split('|').pop().trim()}`;
  document.querySelector('meta[name="description"]')?.setAttribute('content', `${f.name}: ${f.engagements} public audits${nFind(f) ? ` and ${nFind(f)} searchable findings` : ''}, each linked to the original report.`);
  const T = termsCount(f);
  const searchable = nFind(f) > 0;
  const classes = Object.entries(f.classes || {}).filter(([k]) => k !== 'unclassified').sort((a, b) => b[1] - a[1]);
  main.innerHTML = `
    <header class="firm-head">
      <p class="crumb"><a href="firms.html">All firms and platforms</a></p>
      <h1>${esc(f.name)}</h1>
      ${COV.has(f.firm_id) ? `<p class="cov-banner">${covMark(f.firm_id, COV)} <span>${esc(covBanner(f.firm_id, COV))}</span></p>` : ''}
      <p class="meta"><span>${esc(KIND_LABEL[f.kind] || f.kind || '')}</span>
        ${f.first_year ? `<span>Reports from ${years(f)}</span>` : ''}
        <span>${int(f.engagements)} audits</span>${f.reports_released != null ? `<span>${int(f.reports_released)} report files</span>` : ''}${nFind(f) != null ? `<span>${int(nFind(f))} searchable findings</span>` : ''}<span>Collection coverage: ${f.coverage_pct != null ? `${f.coverage_pct.toFixed(1)}%` : 'not measured'}</span>
        ${f.website ? `<a href="${esc(f.website)}" target="_blank" rel="noopener noreferrer">Website</a>` : ''}</p>
      ${searchable ? `<div class="hero-actions"><a class="btn btn-primary" href="explorer.html#firm=${encodeURIComponent(f.firm_id)}">Search ${esc(f.name)} findings</a></div>` : T ? '' : '<p class="meta-note">No findings were extracted for this publisher; its audits are listed below with links to the source records.</p>'}
      ${T ? termsBanner(f, T) : ''}
    </header>
    <div class="firm-grid">
      <div id="f-years"></div>
      <div id="f-sev"></div>
      <div class="span2" id="f-classes"></div>
      <div class="span2" id="f-eng"><h3 class="chart-title">Reports</h3><p class="loading">Loading reports…</p></div>
    </div>
    ${f.reports_listed != null ? `<p class="note">The publisher's listing shows ${int(f.reports_listed)} reports, and ${int(f.reports_collected)} files were collected from it. Audit counts merge revisions, translations and copies of the same report.</p>` : ''}`;

  const clEl = main.querySelector('#f-classes');
  const clsTotal = classes.reduce((a, [, v]) => a + v, 0);
  if (classes.length) {
    clEl.innerHTML = `<h3 class="chart-title">Findings by vulnerability class</h3><p class="chart-sub">Its ${int(clsTotal)} classified initial findings with released text${searchable ? '. Select a class to search it.' : ''}</p><div class="cl-bars" style="margin-top:12px"></div>`;
    hbars(clEl.querySelector('.cl-bars'), { rows: classes.map(([k, v]) => ({ label: groupLabel(k, tax), value: v, color: ['quality', 'gas'].includes(k) ? 'var(--c-other)' : 'var(--c1)', href: searchable ? `explorer.html#firm=${encodeURIComponent(f.firm_id)}&cls=${encodeURIComponent(k)}` : null })), format: int });
  } else clEl.remove();

  const engEl = main.querySelector('#f-eng');
  let list = [];
  try {
    list = (await engagements(f.firm_id)).slice().sort((a, b) => engKey(b) - engKey(a));
  } catch (e) {
    fail(engEl, e);
    return;
  }
  renderYears(main.querySelector('#f-years'), list, D);
  renderSeverity(main.querySelector('#f-sev'), list, f, T);
  const isMeta = (e) => e.findings_observed === false && !(e.reports || []).length && !isTermsEngagement(e);
  const metaOnly = list.filter(isMeta).length;
  const termsN = list.filter(isTermsEngagement).length;
  if (termsN && !main.querySelector('.terms-note')) main.querySelector('.firm-head').insertAdjacentHTML('beforeend', termsBanner(f, termsN));
  const hasType = list.some((e) => e.audit_type);
  let limit = 25;
  const draw = () => {
    engEl.innerHTML = `<h3 class="chart-title">Reports</h3><p class="chart-sub">${int(list.length)} audits, newest first; each links to the publisher's copy of the report${metaOnly ? `. ${int(metaOnly)} are listing records with no report text, so no findings` : ''}${termsN ? `; report and finding text are not reproduced for ${termsN === list.length ? 'any of them' : `${int(termsN)} of them`}${list.some((e) => isTermsEngagement(e) && e.findings_count != null) ? ', and their finding counts come from report summaries' : ''}` : ''}</p>
    <div class="tbl-wrap"><table class="eng"><thead><tr><th scope="col">Project</th><th scope="col">Date</th><th scope="col">Review</th>${hasType ? '<th scope="col">Type</th>' : ''}<th scope="col" style="text-align:right">Findings</th><th scope="col">Source</th></tr></thead><tbody>
    ${list.slice(0, limit).map((e) => {
      const url = e.report_url || e.url || e.permalink || e.evidence_url;
      const record = isMeta(e);
      const sha = record ? '' : e.report_sha256 || e.sha256 || e.primary_report_id || '';
      return `<tr${record ? ' class="meta-only"' : ''}><td class="proj">${esc(e.project || 'Unnamed project')}</td><td class="yr">${(() => { const d = engDate(e); return dateHTML(d?.iso, d?.basis, e.audit_year, esc); })()}</td><td class="mode">${esc(MODE_LABEL[e.review_mode] || e.review_mode || '')}</td>
      ${hasType ? `<td class="ty">${esc(TYPE_LABEL[e.audit_type] || '')}</td>` : ''}
      <td class="n">${isTermsEngagement(e) ? (e.findings_count != null ? `<span class="terms" title="From report summaries; finding text not reproduced">${int(e.findings_count)}</span>` : '<span class="terms">Not reproduced</span>') : record ? '<span class="none">None, listing only</span>' : e.findings_count != null ? int(e.findings_count) : 'n/a'}</td>
      <td class="rep">${url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${record ? 'Open listing' : 'Open report'}</a>` : 'No link'}${sha ? ` <span class="hash" title="SHA-256 ${esc(sha)}">${esc(String(sha).replace(/^document:/, '').slice(0, 10))}</span>` : ''}</td></tr>`;
    }).join('')}</tbody></table></div>
    ${list.length > limit ? `<div class="more"><button type="button" class="btn-ghost" id="eng-more">Show all ${int(list.length)}</button></div>` : ''}`;
    engEl.querySelector('#eng-more')?.addEventListener('click', () => { limit = list.length; draw(); });
  };
  draw();
}

// Audits per year from the publisher's own engagement list; the snapshot year is year to date.
function renderYears(host, list, D) {
  const counts = new Map();
  let unknown = 0;
  for (const e of list) {
    const y = Number(e.audit_year);
    if (y) counts.set(y, (counts.get(y) || 0) + 1); else unknown += 1;
  }
  if (!counts.size) { host.remove(); return; }
  const lo = Math.min(...counts.keys());
  const hi = Math.max(...counts.keys(), Number(String(D.as_of || '').slice(0, 4)) || 0);
  const cats = [];
  for (let y = lo; y <= hi; y++) cats.push(y);
  const ytdYear = D.as_of && !String(D.as_of).endsWith('-12-31') ? Number(String(D.as_of).slice(0, 4)) : null;
  const ytd = (y) => y === ytdYear;
  const { root, plot } = figure({ title: 'Audits per year', sub: `By completion or issue year${unknown ? `; ${int(unknown)} with no known year` : ''}` });
  host.appendChild(root);
  columns(plot, { cats, series: [{ label: 'Audits', color: 'var(--c1)', values: cats.map((y) => counts.get(y) || 0) }], ytd, height: 230, labelTotals: true, totalFmt: int,
    catLabel: (c, i, short) => (short ? shortYear(c, ytd(c)) : `${c}${ytd(c) ? ' YTD' : ''}`),
    tooltip: (i) => ({ title: `${cats[i]}${ytd(cats[i]) ? ' (year to date)' : ''}`, rows: [{ label: 'Audits', value: int(counts.get(cats[i]) || 0) }] }) });
}

// Findings by severity, summed from each audit's initial report (these counts include reports whose text is withheld).
function renderSeverity(host, list, f, T) {
  const sev = Object.fromEntries(SEVERITIES.map((s) => [s, list.reduce((a, e) => a + (Number(e[`findings_${s}`]) || 0), 0)]));
  const total = SEVERITIES.reduce((a, s) => a + sev[s], 0);
  if (!total) {
    host.innerHTML = `<h3 class="chart-title">Findings by severity</h3><p class="empty">${T ? 'Not reproduced. The publisher’s site terms keep its report text off this site.' : 'No findings were extracted for this publisher.'}</p>`;
    return;
  }
  const max = Math.max(...SEVERITIES.map((s) => sev[s]));
  host.innerHTML = `<h3 class="chart-title">Findings by severity</h3><p class="chart-sub">Counted from the initial report of each audit${T ? ', including report summaries where the text is not reproduced' : ''}</p>
    <table class="sof-t"><caption class="sr-only">${esc(f.name)} findings by severity</caption>
    <thead class="sr-only"><tr><th scope="col">Severity</th><th scope="col">Bar</th><th scope="col">Findings</th><th scope="col">Share</th></tr></thead>
    <tbody>${SEVERITIES.map((s) => `<tr class="sev-${s}"><th scope="row"><i class="swatch sev-${s}" aria-hidden="true"></i>${SEVERITY_LABEL[s]}</th>
      <td class="b" aria-hidden="true"><span><i style="width:${(100 * sev[s]) / max}%"></i></span></td><td class="n">${int(sev[s])}</td><td class="p">${pct(sev[s] / total)}</td></tr>`).join('')}</tbody>
    <tfoot><tr><th scope="row">Total</th><td class="b"></td><td class="n">${int(total)}</td><td class="p">${pct(1, 0)}</td></tr></tfoot></table>`;
}

function termsBanner(f, n) {
  const all = !n || n >= f.engagements;
  const rest = nFind(f) > 0 ? ` Findings published elsewhere where reuse is allowed, such as GitHub repositories, are searchable (${int(nFind(f))}).` : '';
  return `<p class="terms-note"><b>${all && !rest ? 'Report text not reproduced.' : 'Some report text not reproduced.'}</b> ${esc(f.name)}’s site terms do not allow automated copying, so the reports on its site for ${all ? 'its audits' : `${int(n)} of its ${int(f.engagements)} audits`} are linked and their text is not reproduced.${rest}</p>`;
}
