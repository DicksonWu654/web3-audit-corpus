// Data access for the site. Everything is fetched relative to the page from `data/` (build/data/ in a release).
// The adapter functions accept small variations in shape (array of rows, {rows}, {columns, data}) so the pages do
// not depend on how the release producer serialises a table.

import { esc } from './fmt.js';

let configPromise = null;
const cache = new Map();

export function config() {
  if (!configPromise) {
    configPromise = fetch('config.json').then((r) => (r.ok ? r.json() : {})).catch(() => ({}));
  }
  return configPromise;
}

export async function getJSON(path, { optional = false } = {}) {
  const c = await config();
  const compressed = c.data_compression === 'gzip';
  const url = (c.data_path || 'data/').replace(/\/?$/, '/') + path + (compressed ? '.gz' : '');
  if (cache.has(url)) return cache.get(url);
  const p = fetch(url).then(async (r) => {
    if (!r.ok) {
      if (optional) return null;
      throw new Error(`Could not load ${path} (HTTP ${r.status})`);
    }
    if (!compressed) return r.json();
    const bytes = new Uint8Array(await r.arrayBuffer());
    // Content-Encoding may already have been decoded by the browser.
    const body = bytes[0] === 0x1f && bytes[1] === 0x8b
      ? new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))
      : bytes;
    return JSON.parse(await new Response(body).text());
  });
  cache.set(url, p);
  p.catch(() => cache.delete(url));
  return p;
}

export function rowsOf(obj) {
  if (!obj) return [];
  if (Array.isArray(obj)) {
    if (obj.length && Array.isArray(obj[0])) return [];
    return obj.map(typedRow);
  }
  if (Array.isArray(obj.rows) && obj.rows.length && !Array.isArray(obj.rows[0])) return obj.rows.map(typedRow);
  const cols = obj.columns || obj.fields;
  const data = obj.data || obj.rows;
  if (Array.isArray(cols) && Array.isArray(data)) {
    return data.map((r) => typedRow(Object.fromEntries(cols.map((c, i) => [c, r[i]]))));
  }
  return [];
}

function typedRow(r) {
  const o = {};
  for (const [k, v] of Object.entries(r)) {
    if (typeof v === 'string') {
      if (v === '') o[k] = null;
      else if (v === 'True' || v === 'true') o[k] = true;
      else if (v === 'False' || v === 'false') o[k] = false;
      else if (/^-?\d+(\.\d+)?(e-?\d+)?$/i.test(v)) o[k] = Number(v);
      else o[k] = v;
    } else o[k] = v;
  }
  return o;
}

export async function stat(name, opts) {
  const [raw, cfg] = await Promise.all([getJSON(`stats/${name}.json`, opts), config()]);
  return rowsOf(raw).map((r) => cfg.publisher_names?.[r.publisher_id] ? { ...r, name: cfg.publisher_names[r.publisher_id] } : r);
}

export async function stats(names) {
  const out = {};
  await Promise.all(names.map(async (n) => {
    out[n] = await stat(n, { optional: true });
  }));
  return out;
}

export async function summary() {
  const s = (await getJSON('summary.json', { optional: true })) || {};
  const counts = s.counts || s.headline || s.totals || {};
  let quality = s.quality || [];
  if (!Array.isArray(quality)) {
    // {metric: value} or {metric: {value, numerator, ...}}
    quality = Object.entries(quality).map(([metric, v]) => (typeof v === 'object' && v ? { metric, ...v } : { metric, value: v }));
  }
  return { ...s, counts, quality: quality.map(typedRow) };
}

export function count(sum, ...keys) {
  for (const k of keys) {
    const v = sum.counts?.[k] ?? sum[k];
    if (typeof v === 'number') return v;
  }
  return null;
}

export function qualityMetric(sum, metric) {
  return sum.quality.find((q) => q.metric === metric) || null;
}

export async function firms() {
  const [raw, cfg] = await Promise.all([getJSON('firms.json'), config()]);
  const list = Array.isArray(raw) ? raw : raw.firms || rowsOf(raw);
  return list.map((f) => ({
    ...f,
    firm_id: f.firm_id || f.publisher_id || f.id,
    name: cfg.publisher_names?.[f.firm_id || f.publisher_id || f.id] || f.name || f.firm_id,
    kind: f.kind || f.publisher_kind || 'firm',
  }));
}

export async function engagements(firmId) {
  const raw = await getJSON(`engagements/${encodeURIComponent(firmId)}.json`, { optional: true });
  if (!raw) return [];
  return Array.isArray(raw) ? raw.map(typedRow) : rowsOf(raw.engagements || raw);
}

export async function findingShard(firmId, shard) {
  const raw = await getJSON(`findings/${encodeURIComponent(firmId)}/${shard}.json`);
  return Array.isArray(raw) ? raw : raw.findings || rowsOf(raw);
}

export async function searchManifest() {
  const m = await getJSON('search/manifest.json', { optional: true });
  if (m && Array.isArray(m.shards)) return m;
  const s = await summary();
  if (s.search && Array.isArray(s.search.shards)) return s.search;
  // Fall back to one index file per firm.
  const fs = await firms();
  return { shards: fs.map((f) => ({ file: `index-${f.firm_id}.json`, firm_id: f.firm_id, count: f.findings || 0 })) };
}

export async function searchShard(file) {
  return getJSON(`search/${file}`);
}

// Plain database counts written by build.py from the release files: totals, audits per year, findings by severity
// and class, the findings columns and one example record.
let dbPromise = null;
export function db() {
  if (!dbPromise) dbPromise = fetch('assets/db.json').then((r) => (r.ok ? r.json() : {})).catch(() => ({}));
  return dbPromise;
}

let taxonomyPromise = null;
export function taxonomy() {
  if (!taxonomyPromise) taxonomyPromise = fetch('assets/taxonomy.json').then((r) => (r.ok ? r.json() : null)).catch(() => null);
  return taxonomyPromise;
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'gas', 'unknown'];
export const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Informational', gas: 'Gas', unknown: 'Unknown' };
// Badges use a short label so every badge has the same width; the full word is the accessible name and tooltip.
export const SEVERITY_SHORT = { ...SEVERITY_LABEL, info: 'Info' };
export function sevBadge(sev, pid = '') {
  const s = SEVERITY_LABEL[sev] ? sev : 'unknown';
  return `<span class="sevtag sev-${s}"><span class="bar" role="img" aria-label="${SEVERITY_LABEL[s]} severity" title="${SEVERITY_LABEL[s]}"><i></i>${SEVERITY_SHORT[s]}</span>${pid ? `<span class="pid">${esc(pid)}</span>` : ''}</span>`;
}
export const STATUSES = ['fixed', 'partially_fixed', 'acknowledged', 'unresolved', 'not_stated'];
export const STATUS_LABEL = { fixed: 'Fixed', partially_fixed: 'Partially fixed', acknowledged: 'Acknowledged', unresolved: 'Unresolved', not_stated: 'Not stated' };
export const MODE_LABEL = { firm_review: 'Firm review', contest: 'Contest' };
export const KIND_LABEL = { firm: 'Firm', collective: 'Collective', contest_platform: 'Contest platform', solo: 'Independent' };

export function groupLabel(id, tax) {
  const g = tax?.classes?.find((c) => c.id === id);
  if (g) return g.name;
  if (id === 'unclassified') return 'Unclassified';
  return (id || '').replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());
}

export function leafInfo(leaf, tax) {
  if (!leaf || !tax) return null;
  for (const c of tax.classes || []) {
    for (const l of c.leaves || []) if (l.id === leaf) return { ...l, group: c };
  }
  return null;
}
