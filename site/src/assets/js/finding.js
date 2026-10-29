// One finding on its own page: finding.html?id=<12 hex>. Loads the id index bucket, then only the one shard
// that holds the finding; the search index is never fetched.
import { config, firms as loadFirms, findingShard, taxonomy, groupLabel, leafInfo, SEVERITIES, SEVERITY_LABEL, STATUS_LABEL, MODE_LABEL, sevBadge } from './data.js';
import { esc } from './fmt.js';
import { renderMarkdown, withoutTitle, excerpt } from './md.js';
import { copyText, flash } from './share.js';
import { TERMS, TERMS_NOTE } from './types.js';
import { fromCode, dateHTML, BASIS_LABEL, dayText } from './dates.js';

const SITE = document.title.split(' | ').pop();
const shortId = (uid) => String(uid || '').split(':').pop().slice(0, 12);
export const findingHref = (uid) => `finding.html?id=${shortId(uid)}`;

function parseId() {
  const raw = (new URLSearchParams(location.search).get('id') || '').trim().toLowerCase().replace(/^finding:/, '');
  return /^[0-9a-f]{12,64}$/.test(raw) ? raw.slice(0, 12) : '';
}

async function locate(id) {
  const r = await fetch(`assets/fidx/${id.slice(0, 2)}.json`);
  if (!r.ok) return null;
  const v = (await r.json())[id];
  if (!v) return null;
  const [firm, shard, code] = v.split(':');
  return { firm, shard: Number(shard) || 0, date: fromCode(code) };
}

function withheldNote(f) {
  if ([f.text_withheld, f.body_text_status].includes(TERMS)) return TERMS_NOTE;
  if (f.text_withheld === 'oak_transform_required') return 'Text withheld because the required character changes would alter the CC BY-ND material. The original report is linked above.';
  return 'Text withheld under a publisher notice. The metadata stays here and the original report is linked above.';
}

function pdfLink(f) {
  const url = f.url || f.permalink || '';
  return url && /\.pdf($|\?)/i.test(url) && f.page_start && !/github\.com\/.+\/blob\//.test(url) ? `${url}#page=${f.page_start}` : url;
}

const sevTag = (sev, pid) => sevBadge(sev, pid);

function render(host, f, firm, where, siblings, tax, repo) {
  const sev = SEVERITIES.includes(f.severity) ? f.severity : 'unknown';
  const leaf = f.vuln_leaf || '';
  const info = leaf ? leafInfo(leaf, tax) : null;
  const group = info?.group?.name || (f.vuln_group ? groupLabel(f.vuln_group, tax) : '');
  const withheld = Boolean(f.text_withheld) || ['withheld_by_notice', 'publisher_notice', 'oak_transform_required', TERMS].includes(f.body_text_status);
  const body = withheld ? '' : (f.body_text || '');
  const url = pdfLink(f);
  const pages = f.page_start ? (f.page_end && f.page_end !== f.page_start ? `pages ${f.page_start} to ${f.page_end}` : `page ${f.page_start}`) : '';
  const firmName = firm?.name || f.firm_id;
  const link = `${location.origin}${location.pathname}?id=${shortId(f.finding_uid)}`;
  const date = where.date;
  const idx = siblings.findIndex((x) => x.finding_uid === f.finding_uid);
  const prev = idx > 0 ? siblings[idx - 1] : null;
  const next = idx >= 0 && idx < siblings.length - 1 ? siblings[idx + 1] : null;
  const rights = f.text_license ? `<p class="text-rights">Text by <a href="${esc(f.text_source_url || f.url || '')}" target="_blank" rel="noopener noreferrer">${esc(f.text_attribution || firmName)}</a>, licensed under <a href="${esc(f.text_license_url || '')}" target="_blank" rel="license noopener noreferrer">${esc(f.text_license)}</a>.</p>` : '';
  const correction = repo ? `${repo}/issues/new?title=${encodeURIComponent(`Correction: ${f.finding_uid}`)}&body=${encodeURIComponent(`Finding: ${f.title}\nFirm: ${firmName}\nPage: ${link}\nReport: ${f.url || ''}\n\nWhat is wrong:\n`)}` : '';
  const sevNorm = (x) => String(x || '').toLowerCase().replace(/[^a-z]/g, '');
  const sevOrig = f.severity_original && ![sev, SEVERITY_LABEL[sev]].map(sevNorm).includes(sevNorm(f.severity_original)) ? ` <span class="muted">(printed as “${esc(f.severity_original)}”)</span>` : '';
  const meta = [
    ['Firm', `<a href="firms.html?id=${encodeURIComponent(f.firm_id)}">${esc(firmName)}</a>`],
    ['Project', f.project ? `<a href="explorer.html#p=${encodeURIComponent(String(f.project).toLowerCase())}">${esc(f.project)}</a>` : 'Not recorded'],
    [date ? (BASIS_LABEL[date.basis] || 'Date') : 'Year', dateHTML(date?.iso, date?.basis, f.audit_year, esc)],
    ['Severity', `${esc(SEVERITY_LABEL[sev])}${sevOrig}`],
    ['Status', esc(STATUS_LABEL[f.status] || f.status || 'Not stated')],
    ['Class', leaf ? `${esc(group)}${info?.name ? `: ${esc(info.name)}` : ''}` : 'Not classified'],
    ['Review', esc(MODE_LABEL[f.review_mode] || f.review_mode || '')],
    ['In the report', pages ? esc(pages) : 'Page not recorded'],
  ].filter(([, v]) => v);
  const share = `https://x.com/intent/tweet?text=${encodeURIComponent(`${f.title} (${SEVERITY_LABEL[sev]}, ${firmName}${f.project ? `, ${f.project}` : ''})`)}&url=${encodeURIComponent(link)}`;
  host.innerHTML = `
    <nav class="crumb fd-crumb" aria-label="Breadcrumb"><a href="explorer.html">Search</a><span aria-hidden="true">/</span><a href="firms.html?id=${encodeURIComponent(f.firm_id)}">${esc(firmName)}</a>${f.project ? `<span aria-hidden="true">/</span><span>${esc(f.project)}</span>` : ''}</nav>
    <header class="fd-head">
      <div class="fd-tags">${sevTag(sev, f.finding_id)}${group ? `<span class="fd-class">${esc(group)}</span>` : ''}</div>
      <h1>${esc(f.title || '(untitled finding)')}</h1>
      <p class="fd-by">${f.project ? `${esc(firmName)} audit of ${esc(f.project)}` : esc(firmName)}, ${dateHTML(date?.iso, date?.basis, f.audit_year, esc)}</p>
      <div class="fd-actions">
        ${url ? `<a class="btn btn-primary" href="${esc(url)}" target="_blank" rel="noopener noreferrer">Original report${f.page_start ? `, page ${esc(f.page_start)}` : ''}</a>` : ''}
        <button type="button" class="btn btn-plain share-copy" data-url="${esc(link)}">Copy link</button>
        <a class="btn btn-plain" href="${esc(share)}" target="_blank" rel="noopener noreferrer">Post on X</a>
      </div>
    </header>
    <div class="fd-grid">
      <article class="fd-main" aria-label="Finding text">
        ${withheld ? `<p class="fd-withheld">${esc(withheldNote(f))}</p>` : body ? `<div class="md-body">${renderMarkdown(withoutTitle(body, f.title))}</div>` : '<p class="fd-withheld">No text was extracted for this finding. The original report is linked above.</p>'}
        ${body ? `<div class="fd-raw"><button type="button" class="btn-ghost" aria-expanded="false" aria-controls="fd-raw-text">View raw text</button><pre id="fd-raw-text" hidden>${esc(body)}</pre></div>` : ''}
        ${rights}
        <p class="d-note">${withheld ? 'Metadata and source link retained.' : 'Text from AI-assisted extraction of the report; layout and code may differ from the original.'} ${correction ? `<a href="${esc(correction)}" target="_blank" rel="noopener noreferrer">Report a correction</a>.` : ''}</p>
      </article>
      <aside class="fd-side">
        <dl class="fd-meta">${meta.map(([k, v]) => `<div><dt>${k}</dt><dd>${v}</dd></div>`).join('')}</dl>
        ${siblings.length > 1 ? `<nav class="fd-nav" aria-label="This report">
          <p class="fd-pos">Finding ${idx + 1} of ${siblings.length} in this report</p>
          <div class="fd-pn">${prev ? `<a rel="prev" href="${findingHref(prev.finding_uid)}"><span>Previous</span>${esc(prev.title || '')}</a>` : '<span></span>'}${next ? `<a rel="next" href="${findingHref(next.finding_uid)}"><span>Next</span>${esc(next.title || '')}</a>` : '<span></span>'}</div>
        </nav>` : ''}
        ${siblings.length > 1 ? `<section class="fd-more"><h2>More from this report</h2><ol>${siblings.slice(0, 40).map((x) => {
          const s = SEVERITIES.includes(x.severity) ? x.severity : 'unknown';
          return `<li${x.finding_uid === f.finding_uid ? ' aria-current="true"' : ''}><a href="${findingHref(x.finding_uid)}"><i class="swatch sev-${s}" title="${esc(SEVERITY_LABEL[s])}"></i><span>${esc(x.title || '(untitled finding)')}</span></a></li>`;
        }).join('')}</ol>${siblings.length > 40 ? `<p class="muted">${siblings.length - 40} more in the report.</p>` : ''}</section>` : ''}
        <section class="fd-more"><h2>Explore</h2><ul class="fd-links">
          ${leaf ? `<li><a href="explorer.html#leaf=${encodeURIComponent(leaf)}">More ${esc(info?.name || group)} findings</a></li>` : ''}
          ${f.vuln_group ? `<li><a href="explorer.html#cls=${encodeURIComponent(f.vuln_group)}&sev=${sev}">${esc(SEVERITY_LABEL[sev])} findings in ${esc(group)}</a></li>` : ''}
          <li><a href="explorer.html#firm=${encodeURIComponent(f.firm_id)}">All ${esc(firmName)} findings</a></li>
          <li><a href="firms.html?id=${encodeURIComponent(f.firm_id)}">${esc(firmName)} audits</a></li>
        </ul></section>
      </aside>
    </div>`;
  document.title = `${f.title} | ${firmName} | ${SITE}`;
  document.querySelector('meta[name="description"]')?.setAttribute('content', `${SEVERITY_LABEL[sev]} finding by ${firmName}${f.project ? ` in ${f.project}` : ''}${date ? `, ${dayText(date.iso)}` : f.audit_year ? `, ${f.audit_year}` : ''}.${body ? ` ${excerpt(body, f.title, 180)}` : ''}`);
  host.querySelector('.share-copy')?.addEventListener('click', (e) => { const b = e.currentTarget; copyText(b.dataset.url).then((ok) => flash(b, ok, 'Copy link')); });
  const raw = host.querySelector('.fd-raw button');
  raw?.addEventListener('click', () => {
    const pre = host.querySelector('#fd-raw-text');
    const open = pre.hidden;
    pre.hidden = !open;
    raw.setAttribute('aria-expanded', String(open));
    raw.textContent = open ? 'Hide raw text' : 'View raw text';
    host.querySelector('.md-body')?.toggleAttribute('hidden', open);
  });
}

export default async function finding() {
  const host = document.getElementById('fd');
  const id = parseId();
  const missing = (msg) => { host.innerHTML = `<div class="fd-missing"><h1>Finding not found</h1><p>${esc(msg)}</p><p><a class="btn btn-primary" href="explorer.html">Search all findings</a></p></div>`; };
  if (!id) { missing('This link has no finding id.'); return; }
  try {
    const [where, cfg, tax, fs] = await Promise.all([locate(id), config(), taxonomy(), loadFirms().catch(() => [])]);
    if (!where) { missing('No finding has this id in the current data.'); return; }
    const list = await findingShard(where.firm, where.shard);
    const f = list.find((x) => shortId(x.finding_uid) === id);
    if (!f) { missing('No finding has this id in the current data.'); return; }
    const siblings = list.filter((x) => x.report_id === f.report_id);
    const firm = fs.find((x) => x.firm_id === where.firm);
    render(host, { ...f, firm_id: where.firm }, firm, where, siblings, tax, (cfg.repo || '').replace(/\/$/, ''));
  } catch (e) {
    missing(`The finding could not be loaded (${e.message}).`);
  }
}
