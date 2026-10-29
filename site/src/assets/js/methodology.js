import { summary, config, db, firms as loadFirms, taxonomy, qualityMetric, KIND_LABEL } from './data.js';
import { int, pct, esc } from './fmt.js';
import { fail } from './ui.js';
import { coverageMap, covMark, covNotes } from './types.js';

export default async function methodology() {
  const [cfg, sum, fs, D, tax] = await Promise.all([config(), summary(), loadFirms().catch(() => []), db(), taxonomy()]);
  const repo = (cfg.repo || '').replace(/\/$/, '');
  for (const [id, fn] of [['m-quality', () => quality(sum)], ['m-taxonomy', () => taxonomySection(sum, D, tax)], ['m-coverage', () => coverage(fs, coverageMap(fs, sum))], ['m-download', () => downloads(cfg, sum, repo)]]) {
    const el = document.getElementById(id);
    try { el.innerHTML = fn(); } catch (e) { fail(el, e); }
  }
  if (location.hash) document.getElementById(location.hash.slice(1))?.scrollIntoView();
}

const q = (sum, m) => qualityMetric(sum, m);
const frac = (r) => (r && r.numerator != null && r.denominator != null ? `${int(r.numerator)} of ${int(r.denominator)}` : '');

function measurementLabel(metric) {
  return String(metric).replace(/_v6$/, ' (current sample)').replace(/_v5$/, ' (earlier sample)')
    .replace(/^gold_/, 'reference_').replace(/_/g, ' ');
}

function measurementDetail(row) {
  if (row.metric === 'annotators') return 'Independent language models labelled the same findings.';
  if (/^(year|firm)_accuracy_v[56]$/.test(row.metric)) return 'Independent random sample checked against the corresponding database snapshot.';
  return row.detail || '';
}

function tile(value, what, n, extra = '') {
  return `<div class="q"><div class="q-val">${value}</div><p class="q-what">${esc(what)}</p>${n ? `<p class="q-n">${esc(n)}</p>` : ''}${extra}</div>`;
}

function quality(sum) {
  const docs = q(sum, 'gold_documents');
  const pubs = q(sum, 'gold_publishers');
  const gf = q(sum, 'gold_findings');
  const rows = [
    ['recall', 'Findings recall', 'reference findings found'],
    ['precision', 'Findings precision', 'extracted findings matching the reference'],
    ['severity_accuracy', 'Severity accuracy', 'matched findings'],
    ['status_accuracy', 'Fix-status accuracy', 'matched findings'],
  ];
  const eng = [
    ['year_accuracy_v6', 'Audit year accuracy'],
    ['firm_accuracy_v6', 'Publisher accuracy'],
    ['confirmed_year_coverage', 'Engagements with a confirmed year'],
  ];
  const tiles = rows.map(([m, what, unit]) => { const r = q(sum, m); return r ? tile(pct(r.value), what, r.numerator != null ? `${frac(r)} ${unit}` : '') : ''; }).join('');
  const engTiles = eng.map(([m, what]) => { const r = q(sum, m); return r ? tile(pct(r.value), what, frac(r)) : ''; }).join('');
  // Incident-link measures belong to the separate analysis, not to the database.
  const all = (sum.quality || []).filter((r) => !/^incident/.test(r.metric || ''));
  return `
    <div class="prose"><p>Extraction was evaluated against a reference set${docs ? ` of <strong>${int(docs.value)}</strong> documents` : ''}${pubs ? ` from ${int(pubs.value)} publishers` : ''}. LLM annotators labelled findings directly from the original documents${gf ? `, producing ${int(gf.value)} reference findings` : ''}. The set was held out from parser development. Accuracy measures agreement with those labels. Engagement dates and publishers were checked on independent random samples against the final database.</p></div>
    <h3 class="chart-title" style="margin-top:28px">Findings extraction</h3>
    <div class="qgrid">${tiles}</div>
    <h3 class="chart-title" style="margin-top:40px">Engagements</h3>
    <div class="qgrid">${engTiles}</div>
    <details class="numbers" style="margin-top:24px"><summary>Every measurement, with its sample</summary><div class="tbl-wrap"><table class="data"><thead><tr><th scope="col">Measurement</th><th scope="col">Value</th><th scope="col">Sample</th><th scope="col" style="text-align:left">Detail</th></tr></thead><tbody>
      ${all.map((r) => `<tr><th scope="row">${esc(measurementLabel(r.metric))}</th><td>${r.value != null && r.value <= 1 && r.denominator ? pct(r.value) : esc(r.value)}</td><td>${esc(frac(r))}</td><td style="text-align:left;white-space:normal;min-width:260px">${esc(measurementDetail(r))}</td></tr>`).join('')}
    </tbody></table></div></details>`;
}

function taxonomySection(sum, D, tax) {
  if (!tax) return '<p class="empty">The taxonomy file is missing from this build.</p>';
  // Finding records per taxonomy group, counted by build.py from the release findings table.
  const counts = { ...(D.classes || {}) };
  const iaaLeafMin = q(sum, 'pairwise_iaa_leaf_min');
  const iaaLeafMax = q(sum, 'pairwise_iaa_leaf_max');
  const iaaGrpMin = q(sum, 'pairwise_iaa_group_min');
  const iaaGrpMax = q(sum, 'pairwise_iaa_group_max');
  const leafAcc = q(sum, 'classifier_leaf_vs_majority');
  const grpAcc = q(sum, 'classifier_group_vs_majority');
  const lo = q(sum, 'classifier_group_ci_low') || (grpAcc?.ci_low != null ? { value: grpAcc.ci_low } : null);
  const hi = q(sum, 'classifier_group_ci_high') || (grpAcc?.ci_high != null ? { value: grpAcc.ci_high } : null);
  const ann = q(sum, 'annotators');
  const sample = q(sum, 'annotated_findings');
  const leaves = tax.classes.reduce((a, c) => a + c.leaves.length, 0);
  const abstention = tax.classes.find((c) => c.id === 'unclassified')?.leaves.find((l) => l.id === 'unclassified.insufficient_evidence');
  const groups = tax.classes.map((c) => c.id === 'unclassified' && abstention
    ? { ...c, name: abstention.name, definition: abstention.definition, count: counts.unclassified || 0 }
    : { ...c, count: counts[c.id] });
  return `
    <div class="prose">
      <p>Each finding gets one primary class: the earliest root cause the text supports, from <strong>${tax.classes.length}</strong> groups and ${leaves} leaves. Groups map loosely to the OWASP Smart Contract Top 10 and the SWC registry; the file defines every leaf with inclusion and exclusion rules. When the text is too thin, the classifier abstains with <em>insufficient evidence</em>.</p>
      ${abstention ? `<p>Findings in the <code>unclassified</code> group carry <code>${esc(abstention.id)}</code>: ${esc(abstention.definition)}${counts.unlabelled ? ` A separate <strong>${int(counts.unlabelled)}</strong> finding records have no class label recorded.` : ''}</p>` : ''}
      ${ann && sample ? `<p>To measure cross-model agreement, ${int(ann.value)} independent LLM annotators labelled the same ${int(sample.value)} findings. ${iaaGrpMin && iaaGrpMax ? `Pairwise they agreed on <strong>${pct(iaaGrpMin.value)} to ${pct(iaaGrpMax.value)}</strong> of groups` : ''}${iaaLeafMin && iaaLeafMax ? ` and ${pct(iaaLeafMin.value)} to ${pct(iaaLeafMax.value)} of leaves` : ''}.</p>
      <p>The production classifier agreed with the annotators' majority label on ${grpAcc ? `<strong>${pct(grpAcc.value)}</strong> of groups (${frac(grpAcc)}${lo && hi ? `; 95% interval ${pct(lo.value)} to ${pct(hi.value)}` : ''})` : ''}${leafAcc ? ` and ${pct(leafAcc.value)} of leaves (${frac(leafAcc)})` : ''}. These scores measure agreement between model labels.</p>` : ''}
    </div>
    <div class="tax">${groups.map((c) => `<details><summary><span class="t-name">${esc(c.name)}</span><span class="t-n">${c.count != null ? `${int(c.count)} findings` : ''}</span><span class="t-def">${esc(c.definition)}</span></summary>
      <ul>${c.leaves.map((l) => `<li><strong>${esc(l.name)}</strong> <code>${esc(l.id)}</code><p>${esc(l.definition)}${l.inclusion ? ` ${esc(l.inclusion)}` : ''}</p></li>`).join('')}</ul></details>`).join('')}</div>`;
}

function coverage(fs, cov) {
  const rows = fs.filter((f) => f.engagements > 0).sort((a, b) => a.name.localeCompare(b.name));
  return `<div class="prose"><p>For each publisher, the number of reports its own listing shows against the number of files collected. A share above 100% means the listing groups several files (revisions, translations, fix reviews) under one entry. Collection follows robots.txt and never bypasses logins, so a few sites stay incomplete.</p>${coverageGaps(rows)}</div>${covNotes(rows.map((f) => f.firm_id), cov)}
    <div class="cov-wrap"><table class="data"><thead><tr><th scope="col">Publisher</th><th scope="col">Type</th><th scope="col">Listed</th><th scope="col">Collected</th><th scope="col">Share</th><th scope="col">Audits</th><th scope="col">Findings</th></tr></thead><tbody>
    ${rows.map((f) => `<tr><th scope="row"><a href="firms.html?id=${encodeURIComponent(f.firm_id)}">${esc(f.name)}</a>${covMark(f.firm_id, cov)}</th><td>${esc(KIND_LABEL[f.kind] || f.kind || '')}</td><td>${f.reports_listed != null ? int(f.reports_listed) : 'n/a'}</td><td>${f.reports_collected != null ? int(f.reports_collected) : 'n/a'}</td><td>${f.coverage_pct != null ? `${Math.round(f.coverage_pct)}%` : 'n/a'}</td><td>${int(f.engagements)}</td><td>${(f.findings_released ?? f.findings) != null ? int(f.findings_released ?? f.findings) : 'n/a'}</td></tr>`).join('')}
    </tbody></table></div>`;
}

function coverageGaps(rows) {
  const byId = new Map(rows.map((f) => [f.firm_id, f]));
  const trust = byId.get('trust-security');
  const gaps = [];
  if (trust) gaps.push(`${esc(trust.name)} has ${int(trust.engagements)} audits and ${int(trust.findings_selected ?? trust.findings)} initial findings, with collection coverage ${trust.coverage_pct == null ? 'not measured' : `${Math.round(trust.coverage_pct)}%`}`);
  for (const id of ['immunefi']) {
    const f = byId.get(id);
    if (f) gaps.push(`${esc(f.name)} has ${int(f.reports_collected)} reports collected and ${int(f.engagements)} confirmed engagements`);
  }
  const shares = ['fuzzland', 'theori', 'three-sigma', 'veridise', 'secure3'].map((id) => byId.get(id))
    .filter((f) => f?.coverage_pct != null).map((f) => `${esc(f.name)} ${Math.round(f.coverage_pct)}%`);
  return gaps.length || shares.length ? `<p>${gaps.length ? `Known coverage gaps: ${gaps.join('; ')}. ` : ''}${shares.length ? `Collection coverage is ${shares.join(', ')}.` : ''}</p>` : '';
}

function downloads(cfg, sum, repo) {
  const assets = cfg.release_assets || [];
  const sizes = Object.fromEntries(assets.map((a) => [a.file, a.bytes]));
  const mb = (b) => (b >= 1e6 ? `${(b / 1e6).toFixed(b >= 1e8 ? 0 : 1)} MB` : `${Math.max(1, Math.round(b / 1e3))} KB`);
  return `
    <ul class="dl-list">${assets.map((a) => `<li><a href="${esc(`${repo}/releases/latest/download/${a.file}`)}">${esc(a.label)}</a><span class="dl-about">${esc(a.about)}</span><span class="dl-file">${esc(a.file)}${sizes[a.file] ? `, ${mb(sizes[a.file])} (${int(sizes[a.file])} bytes)` : ''}</span></li>`).join('')}</ul>
    <div class="prose">
      <p>All files come from the <a href="${esc(`${repo}/releases/latest`)}">latest GitHub release</a>, with checksums for every file. For coding agents, the Markdown and JSON Lines files are described on <a href="agents.html">Use with AI agents</a>. The code that builds the files and this site is in <a href="${esc(repo)}">the repository</a>.</p>
      <p>Code: <a href="${esc(`${repo}/blob/main/LICENSE`)}">MIT licence</a>. Data and quoted text: see the <a href="${esc(`${repo}/blob/main/${cfg.license_file || 'LICENSE-DATA.md'}`)}">data licence</a> and the <a href="${esc(`${repo}/blob/main/docs/RIGHTS.md`)}">publisher rights policy</a>. Original reports belong to their publishers; the dataset links to each one with its SHA-256 hash so anyone can confirm they are reading the same file.</p>
    </div>`;
}
