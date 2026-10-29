#!/usr/bin/env python3
"""Deterministically validate website batch 1 and write its collection summary.

Run after the seven collectors: python3 -I scripts/collect/web_batch1_summary.py --write
No network requests; hashes every referenced original and checks the full census.
"""
from __future__ import annotations

import argparse
from collections import Counter
import datetime as dt
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
FIRMS = ['openzeppelin', 'consensys-diligence', 'quantstamp', 'chainsecurity',
         'ottersec', 'least-authority', 'ncc-group']
FIELDS = set('firm_id collector source_kind public_url listing_url sha256 bytes file_format local_path '
             'filename title_hint project_hint date_hint date_precision date_basis doc_kind retrieved_utc notes'.split())


def inspect(firm):
    directory = ROOT / 'data/collect' / firm
    status = json.loads((directory / 'status.json').read_text())
    listing = json.loads((directory / 'listing.json').read_text())
    rows = [json.loads(line) for line in (directory / 'reports.jsonl').read_text().splitlines()]
    skips = json.loads((directory / 'skipped.json').read_text())
    assert status['enumeration_complete'] and isinstance(status['listed_count'], int), firm + ': census incomplete'
    assert status['listed_count'] == status['collected'] + status['failed'] + status['skipped_non_report'], firm + ': count does not reconcile'
    assert len(rows) == status['collected'] and len(skips) == status['skipped_non_report'], firm + ': manifest count mismatch'
    assert len(status['failures']) == status['failed'], firm + ': failure details missing'
    assert listing['listed_count'] == len(listing['items']) == status['listed_count'], firm + ': listing size mismatch'
    assert len({r['public_url'] for r in rows}) == len(rows), firm + ': duplicate public URL'
    formats, dates, dated_listing, total_bytes = Counter(), 0, 0, 0
    for item in listing['items']:
        if item.get('date'):
            dated_listing += 1
    for row in rows:
        assert set(row) == FIELDS, (firm, 'contract fields differ', set(row) ^ FIELDS)
        assert row['firm_id'] == firm and row['source_kind'] in ('website', 'github')
        assert row['file_format'] in ('pdf', 'md', 'html', 'other')
        assert row['date_basis'] in ('listing', 'filename', 'document_text', 'contest_end', 'none')
        if row['source_kind'] == 'github':
            assert 'https://github.com/' in row['public_url']
        assert row['public_url'].startswith('https://') and row['listing_url'].startswith('https://')
        if 'github.com/' in row['public_url']:
            assert re.search(r'/blob/[a-f0-9]{40}/', row['public_url']), row['public_url']
        assert not re.search(r'X-Amz-|X-Goog-|[?&](?:token|sig|signature)=', row['public_url'], re.I), row['public_url']
        local = ROOT / row['local_path']
        expected = ROOT / 'local-cache/originals' / row['sha256'][:2] / (row['sha256'] + '.' + row['file_format'])
        assert local == expected, local
        body = local.read_bytes()
        assert len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256'], local
        if row['file_format'] == 'pdf':
            assert body.startswith(b'%PDF-'), local
        elif row['file_format'] == 'html':
            assert len(body) > 5000, (firm, 'HTML shell too short', local)
        formats[row['file_format']] += 1
        total_bytes += len(body)
        assert row['doc_kind'] in ('audit_report', 'fix_review', 'formal_verification', 'contest_report', 'unknown')
        if row['date_hint']:
            assert re.fullmatch(r'\d{4}(?:-\d{2}(?:-\d{2})?)?', row['date_hint']), row['date_hint']
            assert row['date_precision'] in ('year', 'month', 'day') and row['date_basis'] != 'none'
            assert len(row['date_hint']) == {'year': 4, 'month': 7, 'day': 10}[row['date_precision']]
            dt.date.fromisoformat(row['date_hint'] + {4: '-01-01', 7: '-01', 10: ''}[len(row['date_hint'])])
            dates += 1
        else:
            assert row['date_precision'] == row['date_basis'] == 'none'
        dt.datetime.fromisoformat(row['retrieved_utc'])
    return dict(firm=firm, status=status, listing=listing, formats=dict(formats), dated=dates,
                dated_listing=dated_listing, bytes=total_bytes, rows=rows)


def render(results):
    lines = ['# Website collection — batch 1', '',
             'Live source observations and report retrieval times are preserved in each publisher’s listing/status files. '
             'This is a census of public report artifacts linked by the publishers, including older archive entries, '
             'rather than a count of deduplicated engagements. Multipart files expand a publisher card into multiple artifacts.', '',
             '| Publisher | Listed artifacts/candidates | Collected | Failed | Skipped | Date hints (collected) |',
             '|---|---:|---:|---:|---:|---:|']
    totals = Counter()
    all_rows = []
    for r in results:
        s = r['status']; firm = r['firm']
        for key in ['listed_count', 'collected', 'failed', 'skipped_non_report']:
            totals[key] += s[key]
        totals['dated'] += r['dated']; all_rows.extend(r['rows'])
        coverage = f"{100*r['dated']/s['collected']:.1f}%" if s['collected'] else 'n/a'
        lines.append(f"| {firm} | {s['listed_count']:,} | {s['collected']:,} | {s['failed']:,} | {s['skipped_non_report']:,} | {coverage} |")
    coverage = f"{100*totals['dated']/totals['collected']:.1f}%"
    lines.extend([f"| **Total** | **{totals['listed_count']:,}** | **{totals['collected']:,}** | **{totals['failed']:,}** | **{totals['skipped_non_report']:,}** | **{coverage}** |", '',
                  'Every publisher satisfies `collected + failed + skipped_non_report == listed_count`. '
                  'Failures retain the specific public URL and error; robots-denied URLs were not fetched. '
                  'Date coverage uses collected artifacts as its denominator. Listing/publication dates remain hints '
                  'and are not asserted to be engagement completion dates.', ''])
    unique = {row['sha256']: row['bytes'] for row in all_rows}
    lines.extend([f"Referenced originals: {len(unique):,} distinct SHA-256 values; {sum(unique.values()):,} bytes. "
                  'All referenced local originals were rehashed by the summary script.', ''])
    for r in results:
        s, listing, firm = r['status'], r['listing'], r['firm']
        lines.extend(['## ' + firm, '', 'Listing: ' + ' · '.join(f'[{u}]({u})' for u in s['listing_urls'][:2]), '',
                      'Pagination/enumeration: ' + listing['method'], '', listing.get('notes', ''), '',
                      f"Formats: {', '.join(f'{k}={v:,}' for k,v in sorted(r['formats'].items()))}. "
                      f"Dated listing candidates: {r['dated_listing']:,}/{s['listed_count']:,}. "
                      f"Last completed collection: {s['collected_utc']}.", ''])
        evidence = ROOT / 'data/collect' / firm / 'source-entries.json'
        if evidence.exists():
            lines.extend([f'Expanded source-entry evidence and exclusions: `data/collect/{firm}/source-entries.json`.', ''])
        if s['failures']:
            lines.extend(['Documented failures:', ''])
            for failure in s['failures']:
                lines.append('- ' + failure['url'] + ' — ' + failure['error'].replace('\n', ' '))
            lines.append('')
    lines.extend(['## Verification and reruns', '',
                  'Run a publisher with `python3 scripts/collect/web_<firm_id>.py`. Listings are refreshed, '
                  'successful originals are reused only after checking their SHA-256, and failed downloads are retried. '
                  'The shared client checks robots per origin (RFC 9309 unavailable/invalid-line handling), '
                  'uses credential-free HTTPS, sends a descriptive User-Agent, and takes a shared filesystem host '
                  'lock with at least 1.05 seconds between request starts, including redirects and robots requests.', '',
                  '`python3 -I scripts/collect/web_batch1_summary.py --write` rechecks contract fields, census arithmetic, '
                  'unique public URLs, GitHub commit pinning, date precision, original formats, byte lengths, and every SHA-256. '
                  'Quantstamp’s substantive report-data JavaScript is stored byte-for-byte as `other`, '
                  'with certificate and asset URLs preserved in notes. It is parsed as data and never executed; '
                  'the application HTML shell is not counted as a report original.', '',
                  '## Files written', ''])
    paths = [f'scripts/collect/web_{firm}.py' for firm in FIRMS]
    paths += ['scripts/collect/web_common.py', 'scripts/collect/web_batch1_summary.py', 'docs/collect/web_batch1.md']
    for firm in FIRMS:
        paths += [str(p.relative_to(ROOT)) for p in sorted((ROOT / 'data/collect' / firm).glob('*')) if p.is_file() and not p.name.endswith('.tmp')]
    lines.extend('- `' + path + '`' for path in paths)
    lines.extend(['', 'Each `reports.jsonl` lists every referenced original’s exact gitignored CAS path. '
                  'HTTP response caches, robots snapshots and host pacing locks are local state under '
                  '`local-cache/web-cache/` and `local-cache/web-host-locks/`. No originals are released or committed.', ''])
    return '\n'.join(lines), totals


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    args = parser.parse_args()
    results = [inspect(firm) for firm in FIRMS]
    document, totals = render(results)
    if args.write:
        path = ROOT / 'docs/collect/web_batch1.md'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(document)
    print(json.dumps(dict(totals), indent=2))
    for r in results:
        s = r['status']
        print(r['firm'], 'listed', s['listed_count'], 'collected', s['collected'],
              'failed', s['failed'], 'skipped', s['skipped_non_report'], 'formats', r['formats'])


if __name__ == '__main__':
    main()
