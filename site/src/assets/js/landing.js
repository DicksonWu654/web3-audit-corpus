// Landing: plain counts from assets/db.json (written by build.py from the release files) and one example record.
import { db, taxonomy, groupLabel, leafInfo, SEVERITIES, SEVERITY_LABEL, STATUS_LABEL, sevBadge } from './data.js';
import { int, pct, esc } from './fmt.js';
import { figure, columns, hbars, shortYear } from './viz.js';
import { bindCodeCopy } from './share.js';
import { dateHTML } from './dates.js';
import { excerpt } from './md.js';
import { fail } from './ui.js';

export default async function landing() {
  const main = document.getElementById('main');
  try {
    const [D, tax] = await Promise.all([db(), taxonomy()]);
    renderCarousel(D.examples || (D.example ? [D.example] : []), tax);
    bindCodeCopy(document.getElementById('download'));
    renderYears(D);
    renderSeverity(D);
    renderClasses(D, tax);
  } catch (e) {
    fail(main, e);
  }
}

// The record carousel: real findings as the database stores them. It advances every 6 seconds, also under
// prefers-reduced-motion (the slides then swap without a fade), and pauses while off screen, while the tab is hidden,
// and on hover or keyboard focus.
const INTERVAL = 6000;

function slide(r, tax, i, n) {
  const leaf = r.vuln_leaf ? leafInfo(r.vuln_leaf, tax) : null;
  const cls = `${leaf?.group?.name || groupLabel(r.vuln_group, tax)}${leaf?.name ? `: ${leaf.name}` : ''}`;
  const page = `finding.html?id=${encodeURIComponent(r.id)}`;
  const rows = [
    ['firm', `<a href="firms.html?id=${encodeURIComponent(r.firm_id)}">${esc(r.firm)}</a>`],
    ['project', esc(r.project || 'n/a')],
    [r.date ? 'date' : 'audit_year', dateHTML(r.date, r.date_basis, r.audit_year, esc)],
    ['severity', sevBadge(r.severity)],
    ['status', esc(STATUS_LABEL[r.status] || r.status || 'n/a')],
    ['class', esc(cls)],
  ];
  return `<article class="rc-slide" role="group" aria-roledescription="slide" aria-label="${i + 1} of ${n}" data-i="${i}">
    <h3 class="rc-title"><a href="${page}">${esc(r.title)}</a></h3>
    <dl class="record-dl">${rows.map(([k, v]) => `<div><dt><code>${k}</code></dt><dd>${v}</dd></div>`).join('')}</dl>
    <p class="rc-body">${esc(excerpt(r.body_head, r.title) || r.body_excerpt)}</p>
    <p class="record-foot"><a href="${page}">Open the finding</a>${r.original_url ? `<a href="${esc(r.original_url)}" target="_blank" rel="noopener noreferrer">Original report</a>` : ''}</p>
  </article>`;
}

function renderCarousel(list, tax) {
  const root = document.getElementById('record');
  if (!root || !list?.length) return;
  const track = root.querySelector('.rc-track');
  const dots = root.querySelector('.rc-dots');
  track.innerHTML = list.map((r, i) => slide(r, tax, i, list.length)).join('');
  dots.innerHTML = list.map((r, i) => `<button type="button" class="rc-dot" aria-label="Finding ${i + 1}: ${esc(r.title)}"></button>`).join('');
  const slides = [...track.children];
  const dotEls = [...dots.children];
  let cur = 0;
  const show = (i) => {
    cur = (i + list.length) % list.length;
    slides.forEach((el, k) => {
      const on = k === cur;
      el.classList.toggle('on', on);
      el.setAttribute('aria-hidden', String(!on));
      el.inert = !on;
    });
    dotEls.forEach((d, k) => d.setAttribute('aria-current', String(k === cur)));
  };
  root.querySelector('.rc-prev').addEventListener('click', () => { show(cur - 1); restart(); });
  root.querySelector('.rc-next').addEventListener('click', () => { show(cur + 1); restart(); });
  dotEls.forEach((d, k) => d.addEventListener('click', () => { show(k); restart(); }));
  root.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowLeft') { show(cur - 1); restart(); }
    if (e.key === 'ArrowRight') { show(cur + 1); restart(); }
  });
  show(0);
  root.hidden = false;

  let visible = false;
  let hover = false;
  let focus = false;
  let timer = 0;
  const running = () => visible && !hover && !focus && !document.hidden;
  function restart() {
    clearInterval(timer);
    timer = 0;
    if (running()) timer = setInterval(() => show(cur + 1), INTERVAL);
    root.dataset.auto = timer ? 'on' : 'off';
  }
  // Only a real mouse pauses on hover: a tap on a phone fires enter without a matching leave.
  root.addEventListener('pointerenter', (e) => { if (e.pointerType === 'mouse') { hover = true; restart(); } });
  root.addEventListener('pointerleave', (e) => { if (e.pointerType === 'mouse') { hover = false; restart(); } });
  // Keyboard focus pauses; a click or tap on the arrows does not.
  root.addEventListener('focusin', (e) => { focus = (() => { try { return e.target.matches(':focus-visible'); } catch { return true; } })(); restart(); });
  root.addEventListener('focusout', (e) => { if (!root.contains(e.relatedTarget)) { focus = false; restart(); } });
  document.addEventListener('visibilitychange', restart);
  if ('IntersectionObserver' in window) {
    new IntersectionObserver((entries) => { visible = entries.some((x) => x.isIntersecting); restart(); }, { threshold: 0.25 }).observe(root);
  } else { visible = true; restart(); }
}

function renderYears(D) {
  const host = document.getElementById('c-years');
  const rows = D.audits_by_year || [];
  if (!host || !rows.length) return host?.remove();
  const last = rows[rows.length - 1].year;
  const ytdYear = D.as_of && String(D.as_of).slice(0, 4) === String(last) && !String(D.as_of).endsWith('-12-31') ? last : null;
  const ytd = (y) => y === ytdYear;
  const sub = `Audits by the year each one was completed${D.audits_unknown_year ? `; ${int(D.audits_unknown_year)} have no known year` : ''}`;
  const { root, plot } = figure({ id: 'audits-year', title: 'Audits per year', sub });
  host.appendChild(root);
  columns(plot, {
    cats: rows.map((r) => r.year), series: [{ label: 'Audits', color: 'var(--c1)', values: rows.map((r) => r.audits) }], ytd, height: 260,
    labelTotals: true, totalFmt: int, catLabel: (c, i, short) => (short ? shortYear(c, ytd(c)) : `${c}${ytd(c) ? ' YTD' : ''}`),
    tooltip: (i) => ({ title: `${rows[i].year}${ytd(rows[i].year) ? ' (year to date)' : ''}`, rows: [{ label: 'Audits', value: int(rows[i].audits) }] }),
  });
}

function renderSeverity(D) {
  const host = document.getElementById('c-sev');
  const sev = D.severity || {};
  const total = SEVERITIES.reduce((a, s) => a + (sev[s] || 0), 0);
  if (!host || !total) return host?.remove();
  const max = Math.max(...SEVERITIES.map((s) => sev[s] || 0));
  host.innerHTML = `<figure class="chart"><figcaption><h3 class="chart-title">Findings by severity</h3><p class="chart-sub">All ${int(total)} finding records, publisher labels mapped to one scale</p></figcaption>
    <table class="sof-t"><caption class="sr-only">Finding records by severity</caption>
    <thead class="sr-only"><tr><th scope="col">Severity</th><th scope="col">Bar</th><th scope="col">Findings</th><th scope="col">Share</th></tr></thead>
    <tbody>${SEVERITIES.map((s) => `<tr class="sev-${s}"><th scope="row"><a href="explorer.html#sev=${s}"><i class="swatch sev-${s}" aria-hidden="true"></i>${SEVERITY_LABEL[s]}</a></th>
      <td class="b" aria-hidden="true"><span><i style="width:${(100 * (sev[s] || 0)) / max}%"></i></span></td><td class="n">${int(sev[s] || 0)}</td><td class="p">${pct((sev[s] || 0) / total)}</td></tr>`).join('')}</tbody>
    <tfoot><tr><th scope="row">Total</th><td class="b"></td><td class="n">${int(total)}</td><td class="p">${pct(1, 0)}</td></tr></tfoot></table></figure>`;
}

function renderClasses(D, tax) {
  const host = document.getElementById('c-classes');
  const entries = Object.entries(D.classes || {}).filter(([k]) => k !== 'unlabelled').sort((a, b) => b[1] - a[1]);
  if (!host || !entries.length) return host?.remove();
  const unlabelled = D.classes?.unlabelled || 0;
  host.innerHTML = `<figure class="chart"><figcaption><h3 class="chart-title">Findings by vulnerability class</h3><p class="chart-sub">Finding records in each taxonomy group${unlabelled ? `; ${int(unlabelled)} records carry no class` : ''}. Select a class to search it.</p></figcaption><div class="cl-bars"></div></figure>`;
  hbars(host.querySelector('.cl-bars'), {
    rows: entries.map(([k, v]) => ({ label: groupLabel(k, tax), value: v, href: `explorer.html#cls=${encodeURIComponent(k)}`, color: ['quality', 'gas'].includes(k) ? 'var(--c-other)' : 'var(--c1)' })),
    format: int,
  });
}
