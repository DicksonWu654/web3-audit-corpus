// Exact audit dates. Codes are YYYYMMDD * 10 + basis (1: audit completed, 2: report date); month-only dates are
// YYYYMM00 * 10 + 3 (completed) or 4 (report). 0 means year only.
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
export const BASIS_LABEL = { c: 'Audit completed', r: 'Report date' };

export function fromCode(code) {
  const n = Number(code) || 0;
  if (!n) return null;
  const d = String(Math.floor(n / 10));
  const b = n % 10;
  const iso = b >= 3 ? `${d.slice(0, 4)}-${d.slice(4, 6)}` : `${d.slice(0, 4)}-${d.slice(4, 6)}-${d.slice(6, 8)}`;
  return { iso, basis: b === 1 || b === 3 ? 'c' : 'r' };
}

export function dayText(iso) {
  const m = /^(\d{4})-(\d{2})(?:-(\d{2}))?$/.exec(iso || '');
  if (!m) return '';
  return m[3] ? `${Number(m[3])} ${MONTHS[Number(m[2]) - 1]} ${m[1]}` : `${MONTHS[Number(m[2]) - 1]} ${m[1]}`;
}

// "12 Mar 2025" with the basis as a tooltip, or the year alone.
export function dateHTML(iso, basis, year, esc) {
  const t = dayText(iso);
  if (!t) return year ? esc(String(year)) : 'Year unknown';
  return `<time datetime="${esc(iso)}" title="${esc(BASIS_LABEL[basis] || 'Date')}">${esc(t)}</time>`;
}

// The same rule as the site build: audit_date_max for completion and report-issue dates; review_year rows and
// 1 Jan to 31 Dec spans are year placeholders.
export function engDate(e) {
  const basis = String(e?.audit_date_basis || '').split(':')[0];
  const lo = String(e?.audit_date_min || '');
  const hi = String(e?.audit_date_max || '');
  if (!['audit_completion', 'report_issue'].includes(basis) || hi.length !== 10) return null;
  if (lo.endsWith('-01-01') && hi.endsWith('-12-31') && lo.slice(0, 4) === hi.slice(0, 4)) return null;
  const b = basis === 'audit_completion' ? 'c' : 'r';
  // A 1st-to-last-day span means only the month is known.
  const last = new Date(Date.UTC(Number(hi.slice(0, 4)), Number(hi.slice(5, 7)), 0)).getUTCDate();
  if (lo !== hi && lo.slice(0, 7) === hi.slice(0, 7) && lo.endsWith('-01') && Number(hi.slice(8)) === last) return { iso: hi.slice(0, 7), basis: b };
  return { iso: hi, basis: b };
}

export function engKey(e) {
  const d = engDate(e);
  return d ? Number(d.iso.replace(/-/g, '').padEnd(8, '0')) : (Number(e?.audit_year) || 0) * 10000;
}
