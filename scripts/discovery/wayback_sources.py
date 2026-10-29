#!/usr/bin/env python3
"""Discover Tier A report URLs captured by the Internet Archive CDX API."""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import re
import runpy
import sys
import urllib.parse as up
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/discovery'))
C = runpy.run_path(str(ROOT / 'scripts/discovery/common.py'))
OUT = ROOT / 'data/discovery/_sources'
ROWS_PATH = OUT / 'wayback_sources.jsonl'
STATUS_PATH = OUT / 'wayback_sources.status.json'
CDX = 'https://web.archive.org/cdx/search/cdx'
MAX_ROWS = 2000

# Scope entries without an established listing/repository path. The root URLs
# are documented public domains associated with the publisher names; the four
# entries remain explicit gaps because no report-listing path is in the local
# registry/catalog. Their CDX results are not attributed to reports unless a
# report-like URL is present.
DOMAIN_FALLBACKS = {
    'three-sigma': ('https://threesigma.xyz/', 'Three Sigma'),
    'theori': ('https://theori.io/', 'Theori'),
    'asymmetric-research': ('https://asymmetric.re/', 'Asymmetric Research'),
    'fuzzland': ('https://fuzz.land/', 'Fuzzland'),
}

def read_csv(path):
    with path.open(newline='') as f:
        return list(csv.DictReader(f))

def normalize_url(url):
    p = up.urlsplit(url.strip())
    if p.scheme not in ('https', 'http') or not p.netloc:
        return ''
    return up.urlunsplit((p.scheme, p.netloc, p.path.rstrip('/') or '/', '', ''))

def repo_root(url):
    p = up.urlsplit(url)
    if p.hostname and p.hostname.lower() == 'github.com':
        bits = [x for x in p.path.split('/') if x]
        if len(bits) >= 2:
            return 'https://github.com/' + '/'.join(bits[:2])
    return ''

def reportish(url):
    p = up.urlsplit(url)
    path = p.path.lower()
    return bool(re.search(r'\.(pdf|md|html?|docx?)(?:$|/)', path))

def date_from_filename(url):
    name = up.unquote(up.urlsplit(url).path.rsplit('/', 1)[-1])
    m = re.search(r'(?<!\d)(20\d{2})[-_. ](0?[1-9]|1[0-2])[-_. ](0?[1-9]|[12]\d|3[01])(?!\d)', name)
    if m:
        try:
            return dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat(), 'day'
        except ValueError:
            pass
    m = re.search(r'(?<!\d)(20\d{2})[-_. ](0?[1-9]|1[0-2])(?!\d)', name)
    if m:
        return f'{int(m.group(1)):04d}-{int(m.group(2)):02d}', 'month'
    m = re.search(r'(?<!\d)(20\d{2})(?!\d)', name)
    return (m.group(1), 'year') if m else ('', 'none')

def slug_from_url(url):
    name = up.unquote(up.urlsplit(url).path.rsplit('/', 1)[-1])
    return re.sub(r'[_-]+', ' ', re.sub(r'\.[^.]+$', '', name)).strip()

def source_catalog():
    p = ROOT / 'extracted/audit_analysis/exports/source_registry.json'
    if not p.exists():
        return []
    # This is read-only data from the external aggregate; no code from the
    # extracted directory is loaded or executed.
    return json.loads(p.read_text())

def build_targets(scope_rows, firm_rows, catalog):
    firms = {r['firm_id']: r for r in firm_rows}
    targets = {}
    gaps = {}
    for s in scope_rows:
        fid = s['firm_id']
        if fid == 'certik':
            continue
        current = []
        for col in ('github_reports_url', 'website_reports_url'):
            value = normalize_url(s.get(col, ''))
            if value:
                current.append((value, 'scope_registry'))
        f = firms.get(fid, {})
        if not current:
            website = normalize_url(f.get('website', ''))
            if website:
                current.append((website, 'firm_registry'))
        if not current and fid in DOMAIN_FALLBACKS:
            current.append((DOMAIN_FALLBACKS[fid][0], 'defensible_domain_fallback'))
            gaps[fid] = 'No report listing/repository URL in scope or firm registry; queried associated domain root only.'
        if not current:
            gaps[fid] = 'No report listing/repository URL or firm website in local registry; no defensible publisher domain established.'
            continue
        for url, basis in current:
            # A repo-root prefix includes both the listed GitHub subpath and
            # historical files in the same repository, avoiding redundant
            # exact-path requests. Website listings remain exact queries.
            root = repo_root(url)
            if root:
                key = (fid, root, 'prefix')
                targets[key] = {'firm_id': fid, 'path': root, 'match': 'prefix', 'basis': basis,
                                'attribution_kind': 'publisher_listing_path'}
            else:
                key = (fid, url, 'exact')
                targets[key] = {'firm_id': fid, 'path': url, 'match': 'exact', 'basis': basis,
                                'attribution_kind': 'publisher_listing_path'}
        # Aggregate catalog report URLs supplement paths in the local
        # registry. Query known non-GitHub historical report paths exactly;
        # GitHub examples are already covered by repo-root prefix queries.
        roots = {repo_root(u) for u, _ in current if repo_root(u)}
        hosts = {up.urlsplit(u).hostname for u, _ in current}
        for item in catalog:
            for known in item.get('source_urls', []):
                clean = normalize_url(known)
                if not clean:
                    continue
                known_root = repo_root(clean)
                same_publisher_site = not known_root and up.urlsplit(clean).hostname in hosts and reportish(clean)
                if same_publisher_site:
                    key = (fid, clean, 'exact')
                    targets.setdefault(key, {'firm_id': fid, 'path': clean, 'match': 'exact',
                        'basis': 'aggregate_catalog_path', 'attribution_kind': 'publisher_listing_path',
                        'source_record_id': item.get('source', '')})
    return list(targets.values()), gaps

def query_url(target):
    params = {
        'url': target['path'], 'matchType': target['match'], 'output': 'json',
        'fl': 'original,timestamp,statuscode,mimetype,digest',
        'filter': 'statuscode:200', 'collapse': 'urlkey', 'limit': str(MAX_ROWS),
    }
    return CDX + '?' + up.urlencode(params)

def parse_cdx(data):
    if not isinstance(data, list) or not data or not isinstance(data[0], list):
        return [], 'unexpected CDX JSON shape'
    header = data[0]
    rows = []
    for row in data[1:]:
        if not isinstance(row, list) or len(row) < len(header):
            continue
        rows.append(dict(zip(header, row)))
    return rows, ''

def make_rows(target, query, meta, data):
    captures, parse_error = parse_cdx(data)
    kept = []
    for cap in captures:
        original = normalize_url(cap.get('original', ''))
        if not original or not reportish(original):
            continue
        # Wayback records are evidence for the candidate original. Keep only
        # report-like paths, and do not use capture time as the audit date.
        timestamp = cap.get('timestamp', '')
        if not re.fullmatch(r'\d{14}', timestamp):
            continue
        date_hint, precision = date_from_filename(original)
        record_id = target.get('source_record_id') or hashlib.sha256(
            (target['firm_id'] + '\n' + original).encode()).hexdigest()[:20]
        wayback = f'https://web.archive.org/web/{timestamp}/{original}'
        kept.append({
            'candidate_url': original,
            'original_publisher_url': original,
            'firm_id': target['firm_id'],
            'project_hint': slug_from_url(original),
            'date_hint': date_hint,
            'date_basis': 'filename' if date_hint else 'none',
            'source': 'wayback',
            'wayback_url': wayback,
            'attribution_basis': {'kind': target['attribution_kind'], 'value': target['path'],
                                  'evidence_url': query},
            'source_record_id': record_id,
            'notes': f"CDX capture timestamp {timestamp}; status={cap.get('statuscode')}; "
                     f"mimetype={cap.get('mimetype')}; digest={cap.get('digest')}; date precision={precision}."
        })
    count = len(captures)
    truncated = count >= MAX_ROWS
    result = {'firm_id': target['firm_id'], 'query_url': query, 'path': target['path'],
              'match': target['match'], 'path_basis': target['basis'], 'http_status': meta.get('status', 0),
              'checked_utc': meta.get('checked_utc', ''), 'returned_cdx_rows': count,
              'candidate_rows': len(kept), 'truncated': truncated}
    if meta.get('error'):
        result['error'] = meta['error']
    if parse_error:
        result['error'] = parse_error
    if truncated:
        result['truncation_note'] = f'CDX row cap {MAX_ROWS} reached; remaining results not queried.'
    return kept, result

def main():
    targets, gaps = build_targets(read_csv(ROOT / 'registry/scope_tier_a.csv'),
                                  read_csv(ROOT / 'registry/firms.csv'), source_catalog())
    all_rows, attempts = [], []
    # The shared fetch helper enforces robots.txt, credential-free access, and
    # a cross-process <=1 request/second limit for web.archive.org.
    for t in targets:
        q = query_url(t)
        meta, data = C['get_json'](q, limit=8_000_000, timeout=30)
        rows, attempt = make_rows(t, q, meta, data)
        all_rows.extend(rows)
        attempts.append(attempt)
    unique = {}
    for row in all_rows:
        unique[(row['firm_id'], row['candidate_url'], row['wayback_url'])] = row
    rows = list(unique.values())
    rows.sort(key=lambda r: (r['firm_id'], r['candidate_url'], r['wayback_url']))
    C['write_jsonl'](ROWS_PATH, rows)
    firms = sorted({r['firm_id'] for r in read_csv(ROOT / 'registry/scope_tier_a.csv') if r['firm_id'] != 'certik'})
    status = {
        'collector_script': 'scripts/discovery/wayback_sources.py',
        'source': 'Internet Archive CDX API',
        'collected_utc': C['now'](),
        'scope_firms': len(firms),
        'queried_firms': len({a['firm_id'] for a in attempts}),
        'query_count': len(attempts),
        'candidate_count': len(rows),
        'firms_with_candidates': len({r['firm_id'] for r in rows}),
        'failed_queries': sum(bool(a.get('error')) or a['http_status'] not in (200, 206) for a in attempts),
        'truncated_queries': sum(bool(a['truncated']) for a in attempts),
        'unresolved_domain_or_listing_gaps': gaps,
        'limitations': [
            'Only report-like original URLs with a CDX status-200 capture are emitted; listing HTML was not replayed for link extraction.',
            'CDX timestamps establish archived captures, never audit completion or publication dates.',
            'Prefix queries are bounded to one page of 2,000 rows; saturated results are explicitly marked truncated.',
            'A candidate was not HEAD-checked and its archived body was not downloaded or independently verified.',
        ],
        'attempts': attempts,
    }
    C['write_json'](STATUS_PATH, status)
    print(json.dumps({k: status[k] for k in ('scope_firms','queried_firms','query_count','candidate_count','firms_with_candidates','failed_queries','truncated_queries')}, sort_keys=True))

if __name__ == '__main__':
    main()
