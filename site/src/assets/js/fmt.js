const nf = new Intl.NumberFormat('en-US');

export const int = (v) => (v == null || Number.isNaN(v) ? 'n/a' : nf.format(Math.round(v)));
export const dec = (v, d = 1) => (v == null || Number.isNaN(v) ? 'n/a' : new Intl.NumberFormat('en-US', { minimumFractionDigits: d, maximumFractionDigits: d }).format(v));
// share in [0,1] -> "12.6%"
export const pct = (v, d = 1) => (v == null || Number.isNaN(v) ? 'n/a' : `${dec(v * 100, d)}%`);
export const pctTick = (v) => `${Math.round(v * 100)}%`;
export function compact(v) {
  if (v == null) return '';
  const a = Math.abs(v);
  if (a >= 1e6) return `${dec(v / 1e6, a >= 1e7 ? 0 : 1).replace(/\.0$/, '')}M`;
  if (a >= 1e3) return `${dec(v / 1e3, a >= 1e4 ? 0 : 1).replace(/\.0$/, '')}K`;
  return nf.format(v);
}
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// "2026" -> "2026 YTD" when flagged
export const yearLabel = (y, ytd) => (y === 'unknown' || y == null ? 'Unknown' : ytd ? `${y} YTD` : String(y));

export function ratio(num, den) {
  return den ? num / den : null;
}
