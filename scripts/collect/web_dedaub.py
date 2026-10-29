#!/usr/bin/env python3
"""Dedaub live report census and shared, append-only collection reconciliation receipts.

Only publisher-specific collectors import these helpers. Existing manifests and
originals are retained; collection counts refer to the enumerated report set, including
acquisitions filed under a canonical publisher alias.
"""
from web_batch2_common import *
import xml.etree.ElementTree as ET

FIRMS = ('three-sigma', 'fuzzland', 'ncc-group', 'theori', 'least-authority',
         'asymmetric-research', 'dedaub')


def rows_for(firm):
    path = ROOT / 'data/collect' / firm / 'reports.jsonl'
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []


def baseline(firm):
    out = ROOT / 'data/collect' / firm
    path = out / 'collection_before.json'
    if not path.exists():
        status = json.loads((out / 'status.json').read_text())
        write_json(path, {'status': status, 'manifest_rows': len(rows_for(firm)),
                          'captured_utc': utc()})
    return json.loads(path.read_text())


def urlkey(url):
    p = urlsplit(unquote(url))
    parts = p.path.strip('/').split('/')
    if p.netloc in ('github.com', 'raw.githubusercontent.com'):
        if p.netloc == 'github.com' and len(parts) >= 5 and parts[2] in ('blob', 'raw'):
            return 'github:' + '/'.join(parts[:2]).lower() + '/' + '/'.join(parts[4:])
        if p.netloc == 'raw.githubusercontent.com' and len(parts) >= 4:
            return 'github:' + '/'.join(parts[:2]).lower() + '/' + '/'.join(parts[3:])
    if p.netloc in ('docs.fuzz.land', 'fuzzland.notion.site'):
        match = re.search(r'[0-9a-f]{32}', p.path)
        if match:
            return 'notion:' + match[0] + ('#' + p.fragment if p.fragment else '')
    return p.netloc.lower().removeprefix('www.') + p.path.rstrip('/') + ('?' + p.query if p.query else '')


def valid_row(row):
    path = ROOT / row['local_path']
    if not path.is_file() or row.get('doc_kind') == 'non_report':
        return False
    body = path.read_bytes()
    return (len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256']
            and (row['file_format'] != 'pdf' or body.startswith(b'%PDF')))


class Reconcile:
    def __init__(self, firm, fetch=None, aliases=()):
        self.firm, self.fetch = firm, fetch or Fetcher()
        self.before = baseline(firm)
        self.out = ROOT / 'data/collect' / firm
        self.rows = rows_for(firm)
        self.pool = self.rows + [r for alias in aliases for r in rows_for(alias)]
        previous_path = self.out / 'collection_receipts.json'
        previous = json.loads(previous_path.read_text()) if previous_path.exists() else {}
        self.receipts, self.attempts = [], list(previous.get('attempts', []))
        self.previous_items = {urlkey(e['public_url']): e for e in previous.get('items', [])}
        self.fetch.evidence.extend(previous.get('observations', []))
        self.index = {}
        for row in self.pool:
            if not valid_row(row):
                continue
            self.index.setdefault(urlkey(row['public_url']), row)
            # Only explicit original/download URLs are matching evidence. A
            # shared listing URL by itself must never match every report.
            for target in re.findall(r'https?://[^\s<>";]+', row.get('notes') or ''):
                self.index.setdefault(urlkey(target.rstrip('.,')), row)

    def find(self, entry):
        for url in [entry['public_url'], entry.get('download_url', '')] + entry.get('aliases', []):
            if url and urlkey(url) in self.index:
                return self.index[urlkey(url)]

    def attempt(self, url, fresh=False):
        try:
            meta, body = self.fetch.get(url, fresh=fresh)
            self.attempts.append(dict(url=url, **{k: meta[k] for k in ('status', 'sha256', 'bytes', 'retrieved_utc')}))
            if meta['status'] != 200:
                raise RuntimeError('HTTP ' + str(meta['status']))
            return meta, body
        except Exception as exc:
            self.attempts.append({'url': url, 'error': str(exc), 'accessed_utc': utc()})
            raise

    def wayback(self, original):
        """Query captures only after a dead/retired original; never policy denial."""
        from urllib.parse import urlencode
        query = 'https://web.archive.org/cdx/search/cdx?' + urlencode({
            'url': original, 'output': 'json', 'filter': 'statuscode:200',
            'collapse': 'digest', 'fl': 'timestamp,original,mimetype'})
        meta, body = self.attempt(query, fresh=True)
        captures = json.loads(body)
        for timestamp, target, mime in reversed(captures[1:]):
            replay = 'https://web.archive.org/web/' + timestamp + 'id_/' + target
            try:
                m, b = self.attempt(replay)
                if b.startswith(b'%PDF'):
                    return replay, m, b
            except Exception:
                continue
        raise RuntimeError('No accessible archived PDF capture: ' + original)

    def save(self, entry, meta, body, public=None):
        public = public or entry['public_url']
        if body.startswith(b'%PDF'):
            fmt = 'pdf'
        elif entry.get('expected_format') == 'html':
            text = DOM(body.decode(errors='replace')).root.visible_text()
            if len(text) < 1000 or not re.search(r'findings|executive summary|audit overview|focus points and recommendations', text, re.I):
                raise RuntimeError('HTML is not a substantive audit report')
            fmt = 'html'
        elif entry.get('expected_format') == 'md':
            if (b'<!DOCTYPE html>' in body[:200] or len(body) < 500
                    or not re.search(rb'(?im)^#.*(?:audit|findings|security review)', body)):
                raise RuntimeError('Not a substantive raw Markdown audit report')
            fmt = 'md'
        else:
            raise RuntimeError('Response is not a PDF audit original')
        sha = hashlib.sha256(body).hexdigest()
        path = Path('local-cache/originals') / sha[:2] / (sha + '.' + fmt)
        (ROOT / path).parent.mkdir(parents=True, exist_ok=True)
        if not (ROOT / path).exists():
            (ROOT / path).write_bytes(body)
        row = {k: entry.get(k, '') for k in ('listing_url', 'title_hint', 'project_hint', 'date_hint')}
        row.update(firm_id=self.firm, collector='web_' + self.firm,
                   source_kind='github' if urlsplit(public).netloc == 'github.com' else 'website',
                   public_url=public, sha256=sha, bytes=len(body), file_format=fmt,
                   local_path=str(path), filename=entry.get('filename_hint') or unquote(urlsplit(public).path.rsplit('/', 1)[-1]),
                   date_precision=entry.get('date_precision', 'none'), date_basis=entry.get('date_basis', 'none'),
                   doc_kind=entry.get('doc_kind', 'audit_report'), retrieved_utc=meta['retrieved_utc'],
                   notes=entry.get('notes', '') + '; collection listing original: ' + entry['public_url'])
        self.rows.append(row)
        self.index[urlkey(public)] = row
        self.index[urlkey(entry['public_url'])] = row
        self.flush_rows()
        return row

    def flush_rows(self):
        path = self.out / 'reports.jsonl'
        tmp = path.with_suffix('.jsonl.tmp')
        tmp.write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in self.rows))
        tmp.replace(path)

    def report(self, entry, row=None, error=''):
        receipt = dict(entry, classification='audit_report')
        prior = self.previous_items.get(urlkey(entry['public_url']), {})
        for key in ('historical_original_url', 'archived_announcement', 'historical_repository_original', 'asset_sha1'):
            if key not in receipt and key in prior:
                receipt[key] = prior[key]
        row = row or self.find(entry)
        if row:
            receipt.update(acquisition={k: row[k] for k in ('firm_id', 'public_url', 'sha256', 'bytes', 'local_path')})
        else:
            receipt['remaining_gap'] = error or 'Report original not acquired'
        self.receipts.append(receipt)

    def exclude(self, entry, reason, classification='non_report'):
        self.receipts.append(dict(entry, classification=classification, reason=reason))

    def finish(self, urls, notes, summary=''):
        reports = [r for r in self.receipts if r['classification'] == 'audit_report']
        missing = [r for r in reports if 'acquisition' not in r]
        assert len({urlkey(r['public_url']) for r in reports}) == len(reports), 'Duplicate report units'
        acquired = [r for r in reports if 'acquisition' in r]
        for r in acquired:
            a = r['acquisition']
            body = (ROOT / a['local_path']).read_bytes()
            assert len(body) == a['bytes'] and hashlib.sha256(body).hexdigest() == a['sha256']
        receipt_path = self.out / 'collection_receipts.json'
        from collections import Counter
        excluded = Counter(r['classification'] for r in self.receipts if r['classification'] != 'audit_report')
        notes = list(notes) + [
            f'collection reconciliation: {len(self.receipts)} reviewed units, {len(reports)} in-scope report units, '
            f'{len(acquired)} SHA-verified acquisitions, {len(missing)} remaining gaps; exclusions by class: '
            + json.dumps(dict(sorted(excluded.items()))) + '. Evidence: ' + str(receipt_path.relative_to(ROOT)) + '.']
        def unique_observations(values):
            return list({json.dumps(v, sort_keys=True): v for v in values}.values())
        write_json(receipt_path, {'firm_id': self.firm, 'measured_utc': utc(), 'listing_urls': urls,
                                 'notes': notes, 'items': self.receipts, 'attempts': unique_observations(self.attempts),
                                 'observations': unique_observations(self.fetch.evidence)})
        status = json.loads((self.out / 'status.json').read_text())
        status.update(listing_urls=urls, listed_count=len(reports), collected=len(acquired),
                      failed=len(missing), failures=[{'url': r['public_url'], 'error': r['remaining_gap']} for r in missing],
                      skipped_non_report=sum(r['classification'] != 'audit_report' for r in self.receipts),
                      collected_utc=utc(), collector_script='scripts/collect/web_' + self.firm + '.py',
                      enumeration_complete=True, processed=len(self.receipts),
                      listed_count_basis='Enumerated in-scope audit report units only; per-item acquisition receipts in collection_receipts.json.',
                      notes=notes, collection_receipts=str(receipt_path.relative_to(ROOT)),
                      collection_summary=summary,
                      collection_before={k: self.before['status'][k] for k in ('collected', 'listed_count')},
                      retained_manifest_rows=len(self.rows),
                      canonical_acquisitions=sum(r['acquisition']['firm_id'] != self.firm for r in acquired))
        if 'doc_kind_counts' in status:
            kinds = Counter(next(r['doc_kind'] for r in self.pool + self.rows
                                 if r['sha256'] == e['acquisition']['sha256'] and r['doc_kind'] != 'non_report')
                            for e in acquired)
            status['doc_kind_counts'] = dict(sorted(kinds.items()))
        # Historical pipeline counters remain provenance, never current collection data.
        if 'report_file_coverage_pct' in status:
            status['report_file_coverage_pct'] = round(100 * len(acquired) / len(reports), 2) if reports else None
        write_json(self.out / 'status.json', status)
        print(self.firm, len(acquired), '/', len(reports), 'remaining', len(missing), flush=True)
        return status


def main():
    g = Reconcile('dedaub')
    index = 'https://dedaub.com/audits/'
    text = g.fetch.text(index, fresh=True)
    sitemap = 'https://dedaub.com/audits/sitemap.xml'
    sm = g.fetch.read(sitemap, fresh=True)
    sitemap_urls = {e.text for e in ET.fromstring(sm).iter() if e.tag.endswith('}loc')}
    # The root contains project cards; each project page lists its report leaves.
    leaves = {}
    projects = {u for u in sitemap_urls if len(urlsplit(u).path.strip('/').split('/')) == 2}
    for target, node in links(text, index):
        parts = urlsplit(target).path.strip('/').split('/')
        if urlsplit(target).netloc == 'dedaub.com' and len(parts) == 2 and parts[0] == 'audits':
            projects.add(target.split('#')[0])
    assert projects, 'Dedaub project listing missing'
    if '--resume-census' in sys.argv:
        saved = json.loads((g.out / 'collection_receipts.json').read_text())
        assert saved['measured_utc'][:10] == utc()[:10], 'Resume requires today’s complete project census'
        leaves = {e['public_url']: e.get('title_hint', '') for e in saved['items']
                  if urlsplit(e['public_url']).netloc == 'dedaub.com'
                  and len(urlsplit(e['public_url']).path.strip('/').split('/')) == 3}
    else:
        for project in sorted(projects):
            for target, node in links(g.fetch.text(project, fresh=True), project):
                parts = urlsplit(target).path.strip('/').split('/')
                if urlsplit(target).netloc == 'dedaub.com' and len(parts) == 3 and parts[0] == 'audits':
                    leaves.setdefault(target.split('#')[0], node.text())
    sitemap_leaves = {u for u in sitemap_urls if len(urlsplit(u).path.strip('/').split('/')) == 3}
    assert set(leaves) == sitemap_leaves, ('Dedaub sidebar/sitemap mismatch', len(leaves), len(sitemap_leaves))
    repo, repo_url = repo_entries(g.fetch, 'Dedaub', 'audits')
    sha, archive = github_snapshot(g.fetch, 'Dedaub', 'audits')
    markdown = []
    for member in archive.infolist():
        path = member.filename.split('/', 1)[-1]
        if not path.startswith('Yearn/') or not path.endswith('.md'):
            continue
        body = archive.read(member)
        dom = DOM(body.decode(errors='replace'))
        title = next(dom.all('title')).text()
        match = re.fullmatch(r'yearn-security/(audits/[^ ]+) at master · yearn/yearn-security', title)
        assert match, 'Unrecognized publisher-saved Markdown wrapper'
        wrapper = repo_url + '/blob/' + sha + '/' + quote(path, safe='/')
        g.exclude(item(wrapper, repo_url, title), 'Publisher file is saved GitHub HTML, not raw Markdown. Expand its original Yearn report link.', 'index_wrapper')
        # Preserve the upstream snapshot bytes and correct their classification;
        # acquire the actual client-published Markdown report separately.
        for row in g.rows:
            if urlkey(row['public_url']) == urlkey(wrapper):
                row['doc_kind'] = 'non_report'
                annotation = '; collection: upstream file contains a saved GitHub page wrapper; actual raw report acquired separately.'
                row['notes'] = row['notes'].split(annotation)[0] + annotation
        g.fetch.text('https://github.com/yearn/yearn-security', fresh=True)
        public, download = pin_github(g.fetch, 'https://github.com/yearn/yearn-security/blob/master/' + match[1])
        markdown.append(item(public, repo_url, title.split(' at master')[0], 'Yearn', expected_format='md',
                             download_url=download, notes='Canonical client original expanded from publisher saved-page wrapper: ' + wrapper))
    entries = [item(u, index, title, urlsplit(u).path.strip('/').split('/')[1], expected_format='html')
               for u, title in sorted(leaves.items())] + repo + markdown
    for e in entries:
        row, error = g.find(e), ''
        if not row:
            try:
                meta, body = g.fetch.payloads.get(e['public_url']) or g.attempt(e.get('download_url') or e['public_url'])
                row = g.save(e, meta, body)
            except Exception as exc:
                error = str(exc)
        g.report(e, row, error)
    gaps = [r for r in g.receipts if 'remaining_gap' in r]
    g.finish([index, sitemap, repo_url] + sorted(projects), [
        f'Live Docusaurus project cards ({len(projects)}) expanded into report leaves and exactly cross-checked against the audit sitemap; project/category indexes are excluded.',
        f'Website report leaves: {len(leaves)}. Publisher GitHub PDF artifacts: {len(repo)}. Actual Yearn Markdown reports expanded from saved-page wrappers: {len(markdown)}. Report renderings are original artifacts, not deduplicated engagements.',
        'Historical client-hosted recoveries outside these enumerated publisher surfaces remain in reports.jsonl but are excluded from the matched collection numerator.'
    ], f'Live website {len(leaves)} reports + {len(repo)} GitHub PDFs + {len(markdown)} actual Markdown originals; {len(gaps)} gaps. Historical extras excluded from collection numerator.')


def validate():
    """Offline contract, set reconciliation, provenance and original-byte checks."""
    from collections import Counter
    import csv
    required = set(('firm_id collector source_kind public_url listing_url sha256 bytes file_format local_path '
                    'filename title_hint project_hint date_hint date_precision date_basis doc_kind retrieved_utc notes').split())
    active = {r['firm_id'] for r in csv.DictReader((ROOT / 'registry/scope_tier_a.csv').open())}
    assert set(FIRMS) <= active
    result, checked, new_rows = {}, set(), []
    for firm in FIRMS:
        out = ROOT / 'data/collect' / firm
        status = json.loads((out / 'status.json').read_text())
        evidence = json.loads((out / 'collection_receipts.json').read_text())
        reports = [e for e in evidence['items'] if e['classification'] == 'audit_report']
        acquired = [e for e in reports if 'acquisition' in e]
        missing = [e for e in reports if 'remaining_gap' in e]
        assert len(reports) == status['listed_count'] == len(acquired) + len(missing)
        assert len(acquired) == status['collected'] and len(missing) == status['failed']
        assert len({urlkey(e['public_url']) for e in reports}) == len(reports)
        assert all(e.get('reason') for e in evidence['items'] if e['classification'] != 'audit_report')
        assert {(e['public_url'], e['remaining_gap']) for e in missing} == {(e['url'], e['error']) for e in status['failures']}
        for e in acquired:
            a = e['acquisition']
            matches = [r for r in rows_for(a['firm_id']) if r['public_url'] == a['public_url'] and r['sha256'] == a['sha256']]
            assert len(matches) == 1 and matches[0]['doc_kind'] != 'non_report', (firm, e['public_url'])
            row = matches[0]
            assert required <= set(row) and valid_row(row)
            assert row['file_format'] in ('pdf', 'md', 'html', 'other')
            assert row['date_precision'] in ('day', 'month', 'year', 'none')
            assert row['source_kind'] in ('github', 'website', 'contest', 'aggregator')
            assert row['local_path'] == f"local-cache/originals/{a['sha256'][:2]}/{a['sha256']}.{row['file_format']}"
            if row['source_kind'] == 'github':
                assert re.match(r'https://github.com/[^/]+/[^/]+/blob/[0-9a-f]{40}/', row['public_url'])
            if row['file_format'] == 'md':
                assert b'<!DOCTYPE html>' not in (ROOT / row['local_path']).read_bytes()[:200]
            if e.get('asset_sha1'):
                assert hashlib.sha1((ROOT / row['local_path']).read_bytes()).hexdigest() == e['asset_sha1']
            checked.add(row['local_path'])
        for e in evidence['items']:
            if e['classification'] == 'duplicate' and e.get('asset_sha1'):
                target = next(r for r in reports if urlkey(r['public_url']) == urlkey(e['duplicate_of']))
                assert hashlib.sha1((ROOT / target['acquisition']['local_path']).read_bytes()).hexdigest() == e['asset_sha1']
        extra = [r for r in rows_for(firm) if '; collection listing original: ' in (r.get('notes') or '')]
        new_rows.extend(extra)
        result[firm] = dict(listed=len(reports), acquired=len(acquired), remaining=len(missing),
                            exclusions=dict(sorted(Counter(e['classification'] for e in evidence['items']
                                                           if e['classification'] != 'audit_report').items())),
                            newly_collected_rows=len(extra))
    # Parsing fresh recovered PDFs catches truncated/non-PDF payloads that a
    # SHA/signature-only validation cannot detect. No network is involved.
    import fitz
    for row in new_rows:
        if row['file_format'] != 'pdf':
            continue
        doc = fitz.open(ROOT / row['local_path'])
        assert doc.page_count > 0
        text = ''.join(doc[n].get_text() for n in range(min(3, doc.page_count)))
        if row['firm_id'] == 'ncc-group':
            assert re.search(r'NCC\s+Group', text, re.I), row['public_url']
        doc.close()
    result = {'publishers': result, 'verified_unique_originals': len(checked),
              'newly_collected_rows': len(new_rows), 'validation': 'passed'}
    write_json(ROOT / 'data/collect/collection_validation.json', result)
    return result


def summary():
    verification = validate()
    access_dates = sorted({json.loads((ROOT / 'data/collect' / firm / 'collection_receipts.json').read_text())['measured_utc'][:10]
                           for firm in FIRMS})
    lines = ['# collection collection gaps', '', 'Generated by `python3 scripts/collect/web_dedaub.py --collection-summary`.', '',
             'Live listing snapshot dates (UTC): ' + ', '.join(access_dates) + '. Source access times, response hashes, exclusions, and every report acquisition or remaining gap are retained in each publisher’s `collection_receipts.json` and summarized in `status.json` notes. Counts describe the same enumerated report set. Historical report rows are preserved; canonical ChainLight acquisitions are referenced without duplicating originals. A zero denominator is not a coverage pass.', '',
             '| Publisher | Before collected/listed | After collected/listed | Coverage | Remaining gap / correction |',
             '| --- | ---: | ---: | ---: | --- |']
    for firm in FIRMS:
        out = ROOT / 'data/collect' / firm
        s = json.loads((out / 'status.json').read_text())
        evidence = json.loads((out / 'collection_receipts.json').read_text())
        b = s['collection_before']
        reason = s['collection_summary']
        pct = f"{100*s['collected']/s['listed_count']:.2f}%" if s['listed_count'] else 'n/a'
        lines.append(f"| {firm} | {b['collected']}/{b['listed_count']} | {s['collected']}/{s['listed_count']} | {pct} | {reason} |")
        assert s['collected'] + s['failed'] == s['listed_count']
        assert s['failed'] == sum('remaining_gap' in r for r in evidence['items'] if r['classification'] == 'audit_report')
    lines += ['', '## Measurement and scope evidence', '',
              'The denominator counts published report artifacts, including audit/fix/design reviews and substantive security testing reports. Distinct report revisions/renderings remain separate artifacts; proven byte-identical mirrors are excluded. These are acquisition counts, not deduplicated engagement counts. Unverified mirrors stay in the denominator. Robots or anonymous-access failures do not make a named audit disappear.', '']
    for firm in FIRMS:
        out = ROOT / 'data/collect' / firm
        s = json.loads((out / 'status.json').read_text())
        lines.append(f"**{firm}** — [status](../../data/collect/{firm}/status.json), [per-item receipts](../../data/collect/{firm}/collection_receipts.json).")
        lines += [''] + [str(note) for note in s['notes']] + ['']
    lines += ['## Item-level remaining gaps', '']
    for firm in FIRMS:
        evidence = json.loads((ROOT / 'data/collect' / firm / 'collection_receipts.json').read_text())
        for e in evidence['items']:
            if 'remaining_gap' in e:
                lines.append(f"- **{firm}** [{e.get('title_hint') or e['public_url']}]({e['public_url']}): {e['remaining_gap']}")
    lines += ['', '## Validation and reproduction', '',
              '`python3 scripts/collect/web_dedaub.py --collection-validate` runs offline. '
              'It verifies contract fields, count equations, one-to-one acquisition receipts, hashes/sizes/CAS paths, PDF signatures and recovered PDF parsing, Markdown originals, pinned GitHub links, and exact Three Sigma duplicate/recovery SHA-1 matches.', '',
              f"Validation passed: {verification['verified_unique_originals']} unique acquired originals checked; {verification['newly_collected_rows']} new report rows collected. Results: [collection_validation.json](../../data/collect/collection_validation.json).", '',
              'Run each `python3 scripts/collect/web_<firm>.py` to remeasure its live sources. NCC and Dedaub also support `--resume-census` only for a complete census from the same UTC day. Existing original rows and immutable bytes are preserved. Re-running the summary above regenerates this document from the saved receipts.', '',
              'No robots disallow, login, paywall, or account access restriction was bypassed. No commit or push was made.', '',
              '## Files written', '']
    written = [f'scripts/collect/web_{firm}.py' for firm in FIRMS]
    written += ['docs/collect/collection_gaps.md', 'data/collect/collection_validation.json']
    for firm in FIRMS:
        written += [f'data/collect/{firm}/{name}' for name in ('collection_before.json', 'collection_receipts.json', 'status.json')]
    written += [f'data/collect/{firm}/reports.jsonl' for firm in ('three-sigma', 'ncc-group', 'dedaub')]
    written += [f'data/collect/{firm}/source-entries.json' for firm in ('least-authority', 'ncc-group')]
    lines += ['- `' + path + '`' for path in written]
    lines += ['', 'Local-only outputs: response metadata/bodies and pacing locks in `local-cache/web-batch2/{http,rate}/` and `local-cache/{web-cache,web-host-locks}/`; task logs `local-cache/collection-*.log`. The newly acquired originals are:', '']
    originals = sorted({r['local_path'] for firm in FIRMS for r in rows_for(firm)
                        if '; collection listing original: ' in (r.get('notes') or '')})
    lines += ['- `' + path + '`' for path in originals] + ['']
    path = ROOT / 'docs/collect/collection_gaps.md'
    path.write_text('\n'.join(lines))
    print('\n'.join(lines[6:15]))


if __name__ == '__main__':
    if '--collection-summary' in sys.argv:
        summary()
    elif '--collection-validate' in sys.argv:
        print(json.dumps(validate(), indent=2))
    else:
        main()
