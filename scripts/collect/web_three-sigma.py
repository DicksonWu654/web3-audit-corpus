#!/usr/bin/env python3
"""Collect Three Sigma's official repository, linked by threesigma.xyz."""
from web_batch2_common import *

METHOD = 'Full embedded audit array on /case-studies plus commit-pinned publications ZIP manifest, including older/unindexed repository reports.'
NOTES = 'Security audits collected; economic reports explicitly skipped. Both publisher CDN originals and repository originals retained as distinct listed artifact URLs; identical bytes deduplicate in the local SHA store.'


def enumerate_reports(fetch):
    entries, repo = repo_entries(fetch, 'threesigmaxyz', 'publications', skip_prefixes=('economic-reports/',))
    url = 'https://threesigma.xyz/case-studies'
    objects = [o for o in flight_objects(fetch.text(url, fresh=True)) if 'auditDate' in o and 'pdfLink' in o]
    records = {o['slug']: o for o in objects}
    assert records, 'Empty embedded case-study audit listing'
    for row in records.values():
        for target in [row.get('pdfLink'), row.get('reportLink')]:
            if not target:
                continue
            notes = 'Listing language: ' + str(row.get('language') or '') + '; category: ' + str(row.get('category') or '')
            e = item(target, url, row['title'], row['title'], row.get('auditDate') or '', row.get('type') or '', notes=notes, expected_format='pdf')
            if row.get('type') != 'Code Audit':
                e['skip_reason'] = 'Economic audit/research, not a security code-audit report'
            # Enrich a manifest file already covered by its branch-based listing link.
            match = next((x for x in entries if '/blob/' in target and unquote(x['public_url']).split('/blob/',1)[-1].split('/',1)[-1] == unquote(target).split('/blob/',1)[-1].split('/',1)[-1]), None)
            if match:
                match.update({k:e[k] for k in ('listing_url','title_hint','project_hint','date_hint','date_precision','date_basis','audit_type')})
                match['notes'] += '; ' + notes
            else:
                entries.append(e)
    assert entries, 'Empty Three Sigma repository'
    return entries, [url, repo, 'https://threesigma.xyz/']


def historic_assets(g, wanted):
    """Recover publisher originals by exact Sanity SHA-1, across cover changes.

    ZIP members are read in memory; repository content is never extracted/run.
    Neither the CDN nor an archive of a robots-blocked CDN path is requested.
    """
    found = {}
    root = 'https://github.com/threesigmaxyz/publications'
    for commit in ('4cbc0f8a81edebc9aaddd3bad1abf51fd4c9b43d',
                   'bc3556820b35dcf6efb9486b7fcb0c420f8e443b'):
        detail = g.fetch.json('https://api.github.com/repos/threesigmaxyz/publications/commits/' + commit)
        assert 'audit covers' in detail['commit']['message'], 'Unexpected history provenance'
        parent = detail['parents'][0]['sha']
        meta, body = g.fetch.get('https://codeload.github.com/threesigmaxyz/publications/zip/' + parent)
        archive = zipfile.ZipFile(io.BytesIO(body))
        for member in archive.infolist():
            path = member.filename.split('/', 1)[-1]
            if not path.startswith('audits/') or not path.lower().endswith('.pdf'):
                continue
            payload = archive.read(member)
            sha1 = hashlib.sha1(payload).hexdigest()
            if sha1 in wanted:
                found.setdefault(sha1, (root + '/blob/' + parent + '/' + quote(path, safe='/'), meta, payload))
    paths = {
        'aborean-finance-audit': ['audits/aborean-finance/AboreanFinance.pdf'],
        'magma-finance': ['audits/magma/Magma.pdf'],
        'scoreplay': ['audits/scoreplay/SCOREPLAY.pdf'],
        'maple-finance-5': ['audits/Maple-new/MapleFinance-December2024.pdf'],
        'mitosis': ['audits/mitosis/mitosis-audit.pdf'],
        'maple-finance-4': ['audits/maple-4/MapleSyrupActions.pdf'],
        'meta-zero-2': ['audits/metazero-2/MetazeroStakingAudit.pdf'],
        'm0labs-1': ['audits/m0labs/MZeroAudit.pdf'],
        'clip-finance-1': ['audits/ClipFinance-1/ClipFinanceCore.pdf', 'audits/ClipFinance-1/ClipFinancePCLBaseSwapInside.pdf'],
    }
    for sha1, record in wanted.items():
        if sha1 in found:
            continue
        for path in paths.get(record['slug'], []):
            history = g.fetch.json('https://api.github.com/repos/threesigmaxyz/publications/commits?path=' + quote(path, safe='/') + '&per_page=100')
            for version in history:
                revision = version['sha']
                detail = g.fetch.json('https://api.github.com/repos/threesigmaxyz/publications/commits/' + revision)
                changed = next((f for f in detail['files'] if f['filename'] == path), {})
                candidates = [(revision, path)]
                if detail['parents']:
                    candidates.append((detail['parents'][0]['sha'], changed.get('previous_filename', path)))
                for ref, candidate in candidates:
                    download = 'https://raw.githubusercontent.com/threesigmaxyz/publications/' + ref + '/' + quote(candidate, safe='/')
                    meta, body = g.fetch.get(download)
                    if meta['status'] == 200 and body.startswith(b'%PDF') and hashlib.sha1(body).hexdigest() == sha1:
                        found[sha1] = (root + '/blob/' + ref + '/' + quote(candidate, safe='/'), meta, body)
                        break
                if sha1 in found:
                    break
            if sha1 in found:
                break
        print('three-sigma historic exact asset', record['slug'], sha1 in found, flush=True)
    return found


def main():
    from web_dedaub import Reconcile
    g = Reconcile('three-sigma')
    entries, repo = repo_entries(g.fetch, 'threesigmaxyz', 'publications', skip_prefixes=('economic-reports/',))
    url = 'https://threesigma.xyz/case-studies'
    records = {o['slug']: o for o in flight_objects(g.fetch.text(url, fresh=True))
               if 'auditDate' in o and 'pdfLink' in o}
    assert records, 'Empty embedded audit listing'
    by_sha1 = {}
    for e in entries:
        if e.get('skip_reason'):
            g.exclude(e, e['skip_reason'])
            continue
        meta, body = g.fetch.payloads[e['public_url']]
        by_sha1[hashlib.sha1(body).hexdigest()] = e
        row = g.find(e)
        if row is None:
            row = g.save(e, meta, body)
        g.report(e, row)
    wanted = {o['pdfLink'].rsplit('/', 1)[-1].split('.')[0]: o for o in records.values()
              if o['type'] == 'Code Audit' and o.get('pdfLink')
              and o['pdfLink'].rsplit('/', 1)[-1].split('.')[0] not in by_sha1}
    historical = historic_assets(g, wanted)
    for record in records.values():
        targets = list(dict.fromkeys(t for t in [record.get('pdfLink'), record.get('reportLink')] if t))
        if not targets:
            e = item(url + '/' + record['slug'], url, record['title'], record['title'], record.get('auditDate', ''))
            g.exclude(e, 'Service/case-study card has no published report link; not a public audit report.', 'unpublished')
        for target in targets:
            e = item(target, url, record['title'], record['title'], record.get('auditDate', ''), notes=json.dumps(record))
            if record.get('type') != 'Code Audit':
                g.exclude(e, 'Publisher classifies this as ' + record.get('type', '') + ', not a code security audit.')
                continue
            match = re.search(r'/([0-9a-f]{40})\.pdf$', target)
            mirrored = by_sha1.get(match[1]) if match else None
            if mirrored:
                e['duplicate_of'] = mirrored['public_url']
                e['asset_sha1'] = match[1]
                g.exclude(e, 'Sanity content-addressed asset SHA-1 exactly equals SHA-1 of the independently acquired publisher repository PDF bytes.', 'duplicate')
                continue
            row = g.find(e)
            if row and target.startswith('https://github.com/'):
                e['duplicate_of'] = row['public_url']
                g.exclude(e, 'Same publisher repository report path; branch link duplicates the pinned repository manifest.', 'duplicate')
                continue
            error = ''
            if not row and match and match[1] in historical:
                public, meta, body = historical[match[1]]
                e['historical_repository_original'] = public
                e['asset_sha1'] = match[1]
                e['notes'] += '; Sanity content-addressed SHA-1 verified against historical publisher repository bytes.'
                row = g.save(e, meta, body, public=public)
            if not row:
                try:
                    meta, body = g.attempt(target, fresh=True)
                    row = g.save(e, meta, body)
                except Exception as exc:
                    error = str(exc)
            g.report(e, row, error)
    duplicates = sum(r['classification'] == 'duplicate' for r in g.receipts)
    gaps = [r for r in g.receipts if 'remaining_gap' in r]
    g.finish([url, repo], [
        METHOD, f'Live case-study objects: {len(records)}; pinned repository PDF artifacts: {len(entries)}. Excluded economic reports, no-report-link service cards, and {duplicates} proven duplicate source URLs.',
        'CDN mirrors are excluded only when the Sanity asset content SHA-1 matches independently acquired repository PDF bytes. Similar project/date/title without a byte match is not sufficient to erase a gap.',
        f'Historical publisher GitHub originals recovered by exact CDN asset SHA-1: {len(historical)}. Cover-change revisions are retained as separate original artifacts when bytes differ.',
        'Distinct or unverified CDN PDF versions remain real report units and documented robots-policy gaps. No CDN disallow rule or login was bypassed.'
    ], f'{duplicates} duplicate URLs removed; {len(historical)} historic originals recovered; {len(gaps)} unverified Sanity PDF versions remain robots-blocked.' if gaps else f'{duplicates} duplicate URLs reconciled; {len(historical)} historic originals recovered; no remaining gap.')


if __name__ == '__main__':
    main()
