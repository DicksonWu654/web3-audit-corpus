// Audit types and publisher coverage flags, shared by every page.
// Types come from each engagement's audit_type.
import { esc } from './fmt.js';

export const TYPES = ['token_only', 'protocol', 'infrastructure', 'wallet_or_account', 'nft_or_game', 'other_or_unclear'];
export const TYPE_LABEL = {
  token_only: 'Token only', protocol: 'Protocol', infrastructure: 'Infrastructure',
  wallet_or_account: 'Wallet or account', nft_or_game: 'NFT or game', other_or_unclear: 'Unclear',
};
export const TYPE_ABOUT = {
  token_only: 'a token contract and nothing else',
  protocol: 'DeFi and other application logic',
  infrastructure: 'chains, bridges, clients and tooling',
  wallet_or_account: 'wallets, smart accounts and key handling',
  nft_or_game: 'NFTs, games and collectibles',
  other_or_unclear: 'too little evidence to tell',
};
/* ---------------------------------------------------------------- publisher coverage flags */
const COV_SHORT = {
  public_sca_api_plus_third_party_copies: 'API records',
};
const COV_LINE = {
  public_sca_api_plus_third_party_copies: (n) => `${n} includes metadata-only audits from its public audits API, which carry no report text or findings.`,
};

export function coverageMap(firms, sum) {
  const out = new Map();
  for (const [id, v] of Object.entries(sum?.publisher_coverage || {})) {
    if (v?.coverage && v.coverage !== 'public_portfolio') out.set(id, { coverage: v.coverage, note: v.note || '', name: id });
  }
  for (const f of firms || []) {
    if (f.coverage && f.coverage !== 'public_portfolio') out.set(f.firm_id, { coverage: f.coverage, note: f.coverage_note || '', name: f.name });
    else if (out.has(f.firm_id)) out.get(f.firm_id).name = f.name;
  }
  return out;
}

export function covMark(id, map) {
  const c = map?.get(id);
  if (!c) return '';
  return `<span class="cov" data-cov="${esc(c.coverage)}">${esc(COV_SHORT[c.coverage] || 'Partial coverage')}</span>`;
}

export function covLine(id, map) {
  const c = map?.get(id);
  if (!c) return '';
  return COV_LINE[c.coverage] ? COV_LINE[c.coverage](c.name) : `${c.name}: ${c.note || 'partial collection coverage.'}`;
}

/* Banner text for a firm page: the standard line plus whatever the data note adds. */
export function covBanner(id, map) {
  const c = map?.get(id);
  if (!c) return '';
  const line = covLine(id, map);
  if (!COV_LINE[c.coverage] || !c.note) return line;
  return `${line} ${c.note}`;
}

/* ---------------------------------------------------------------- publisher terms */
// Publishers whose site terms do not allow automated copying: their audits are listed with a link, without report
// text or findings. Flagged on the engagement (text_withheld or body_text_status 'publisher_terms') and, for the
// publisher, by the same fields, a terms_restricted count, or a publisher_coverage_class row.
export const TERMS = 'publisher_terms';
export const TERMS_NOTE = 'Report text not reproduced: the publisher\u2019s site terms do not allow automated copying. The original is linked.';
export const isTermsEngagement = (e) => e?.text_withheld === TERMS || e?.body_text_status === TERMS;
// Terms-restricted engagements per publisher. Sources, first that answers: summary.terms_policy.publishers
// (engagements), a numeric terms_restricted on the firm, the coverage-class row (terms_restricted_reports or a numeric
// terms_restricted), then a true flag or publisher_terms on the firm itself (all its audits).
let POLICY = new Map();
export function setTermsPolicy(sum) {
  POLICY = new Map((sum?.terms_policy?.publishers || []).map((p) => [p.firm_id ?? p.publisher_id, p]));
}
export const termsPolicy = (id) => POLICY.get(id) || null;
const posNum = (v) => (typeof v === 'number' && v > 0 ? v : typeof v === 'string' && Number(v) > 0 ? Number(v) : 0);
export function termsCount(f, classRow) {
  const p = POLICY.get(f?.firm_id ?? classRow?.publisher_id);
  if (p && posNum(p.engagements)) return posNum(p.engagements);
  const n = posNum(f?.terms_restricted) || posNum(classRow?.terms_restricted_reports) || posNum(classRow?.terms_restricted);
  if (n) return n;
  const flagged = f?.text_withheld === TERMS || f?.body_text_status === TERMS || f?.coverage === TERMS || f?.terms_restricted === true || classRow?.terms_restricted === true;
  return flagged ? (f?.engagements || classRow?.engagements || 1) : 0;
}

/* One line per flagged publisher that appears in `ids`, in a fixed order. */
export function covNotes(ids, map) {
  const present = [...new Set(ids)].filter((id) => map?.has(id)).sort((a, b) => map.get(a).coverage.localeCompare(map.get(b).coverage));
  if (!present.length) return '';
  return `<ul class="cov-notes">${present.map((id) => `<li>${covMark(id, map)} ${esc(covLine(id, map))}</li>`).join('')}</ul>`;
}
