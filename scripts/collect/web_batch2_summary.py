#!/usr/bin/env python3
"""Deterministically verify website batch 2 and generate its collection summary.

Reads only saved manifests/originals and the read-only Neodyme seed; no network.
Run after the collectors: python3 scripts/collect/web_batch2_summary.py
"""
from web_batch2_common import *
from collections import Counter
import xml.etree.ElementTree as ET
import uuid
from web_fuzzland import expected_blocks, missing_blocks, FINDING_MARKER

FIRMS = ['kudelski-security', 'veridise', 'ackee-blockchain', 'macro', 'neodyme', 'iosiro',
         'three-sigma', 'theori', 'asymmetric-research', 'fuzzland']
CANONICAL = {
    'kudelski-security': 'https://kudelskisecurity.com/blockchain',
    'veridise': 'https://veridise.com/audits-archive/',
    'ackee-blockchain': 'https://ackee.xyz/blog/list-of-our-public-audits/',
    'macro': 'https://0xmacro.com/library',
    'neodyme': 'https://www.neodyme.io/en/reports/',
    'iosiro': 'https://www.iosiro.com/audits',
    'three-sigma': 'https://threesigma.xyz/case-studies',
    'theori': 'https://github.com/theori-io/web3-publications',
    'asymmetric-research': 'https://github.com/asymmetric-research/security-advisories',
    'fuzzland': 'https://docs.fuzz.land/',
}
REPORT_KEYS = set('firm_id collector source_kind public_url listing_url sha256 bytes file_format local_path filename title_hint project_hint date_hint date_precision date_basis doc_kind retrieved_utc notes'.split())
STATUS_KEYS = set('firm_id listing_urls listed_count collected failed skipped_non_report failures collected_utc collector_script'.split())


def identity(url):
    p = urlsplit(url)
    host = p.netloc.lower().removeprefix('www.')
    path = unquote(p.path)
    if host in ('docs.fuzz.land','fuzzland.notion.site'):
        page_id=re.search(r'[0-9a-f]{32}',path)
        if page_id:
            return 'fuzzland.notion.site/'+page_id[0]+('#'+p.fragment if p.fragment else '')
    if host == 'github.com' and '/blob/' in path:
        ownerrepo, rest = path.split('/blob/', 1)
        path = ownerrepo.lower() + '/blob/REF/' + rest.split('/', 1)[1]
    return host + path.rstrip('/') + ('?' + p.query if p.query else '')


def saved_body(url):
    return (CACHE / 'http' / (hashlib.sha256(url.encode()).hexdigest() + '.body')).read_bytes()


def check_helpers():
    assert identity('https://docs.fuzz.land/AlphaX-Audit-Report-51a61ac2ec0f4b27b117ede2d251a076') == identity('https://fuzzland.notion.site/51a61ac2ec0f4b27b117ede2d251a076')
    assert date_hint('Sep 19, 2025')==('2025-09-19','day')
    assert date_hint('September 2025')==('2025-09','month')
    assert date_hint('2024')==('2024','year') and date_hint('')==('','none')
    assert len(links('<a href="https://[broken">bad</a><a href="/ok">ok</a>','https://example.org'))==1
    class FixtureFetcher(Fetcher):
        def get(self,url,**kwargs):
            return {'status':200}, b'User-agent: *\nAllow: /files/allowed/\nDisallow: /*.pdf\n'
    f=FixtureFetcher()
    f._policy('https://example.org/files/allowed/report.pdf')
    try:
        f._policy('https://example.org/files/blocked/report.pdf')
    except RuntimeError:
        pass
    else:
        raise AssertionError('PDF robots Disallow wildcard was not enforced')
    payload='1:'+json.dumps({'audits':[{'auditDate':'2025-09-19','pdfLink':'https://example.org/report.pdf'}]})+'\n'
    script='<script>self.__next_f.push('+json.dumps([1,payload])+')</script>'
    assert any(o.get('auditDate')=='2025-09-19' for o in flight_objects(script))
    prefix='The assessment describes the reward calculation using the following formula: '
    records={'page':{'content':['formula']},'formula':{'type':'text','properties':{'title':[[prefix],['⁍',[['e',r'\frac{x}{y}']]],['.']]}}}
    expected=expected_blocks(records,'page')
    html='<div data-block-id="formula">'+prefix+'<math><annotation>'+r'\frac{x}{y}'+'</annotation></math>.</div>'
    assert not missing_blocks(html,expected), 'Rendered original TeX rejected'
    assert missing_blocks(html.replace(r'\frac{x}{y}',r'\frac{a}{b}'),expected), 'Altered formula accepted'


def neodyme_comparison(rows):
    seed_path = ROOT / 'extracted/neodyme_v1/neodyme_dataset/reports.jsonl'
    seed = [json.loads(line) for line in seed_path.read_text().splitlines()]
    before = {identity(r['source_url']): r for r in seed}
    after = {identity(r['public_url']): r for r in rows}
    shared = sorted(before.keys() & after.keys())
    result = {'seed_reports': len(seed), 'live_reports': len(rows),
              'added_urls': [after[k]['public_url'] for k in sorted(after.keys()-before.keys())],
              'removed_urls': [before[k]['source_url'] for k in sorted(before.keys()-after.keys())],
              'unchanged_sha256': sum(before[k]['sha256']==after[k]['sha256'] for k in shared),
              'changed_sha256': [dict(url=after[k]['public_url'], seed_sha256=before[k]['sha256'], live_sha256=after[k]['sha256']) for k in shared if before[k]['sha256']!=after[k]['sha256']],
              'date_hint_differences': [dict(url=after[k]['public_url'],seed_date=before[k].get('index_published_date'),live_date=after[k]['date_hint']) for k in shared if date_hint(before[k].get('index_published_date',''))[0]!=after[k]['date_hint']],
              'url_host_only_changes': sum(before[k]['source_url']!=after[k]['public_url'] for k in shared),
              'notes': 'Comparison normalizes www and URL percent encoding. Seed files are read only; live originals were collected independently.'}
    write_json(ROOT / 'data/collect/neodyme/seed_comparison.json', result)
    return result


def fuzzland_content_check(rows):
    """Compare rendered HTML with independent saved public Notion block data."""
    checked, missing = 0, []
    for row in rows:
        if row['file_format']!='html':
            continue
        page_id=str(uuid.UUID(re.search(r'[0-9a-f]{32}',row['public_url'])[0]))
        cursor, chunk, records = {'stack':[]}, 0, {}
        while True:
            payload={'pageId':page_id,'limit':1000,'cursor':cursor,'chunkNumber':chunk,'verticalColumns':False}
            url='https://docs.fuzz.land/api/v3/loadPageChunk'
            key=hashlib.sha256(('POST '+url+' '+json.dumps(payload,sort_keys=True)).encode()).hexdigest()
            data=json.loads((CACHE/'http'/(key+'.body')).read_bytes())
            for block_id,value in data['recordMap']['block'].items():
                value=value.get('value',{})
                records[block_id]=value.get('value',value)
            cursor=data.get('cursor',{})
            if not cursor.get('stack'):
                break
            chunk+=1
            assert chunk<=100, 'Notion validation pagination did not terminate'
        expected=expected_blocks(records,page_id)
        checked+=len(expected)
        for block in missing_blocks((ROOT/row['local_path']).read_text(),expected):
            missing.append(dict(url=row['public_url'],block_id=block['block_id'],text=block['text'][:160]))
    return {'source_blocks_checked':checked,'missing_blocks':missing}


def main():
    check_helpers()
    all_reports, stats, listings, errors = [], {}, {}, []
    for firm in FIRMS:
        folder = ROOT / 'data/collect' / firm
        status = json.loads((folder / 'status.json').read_text())
        listing = json.loads((folder / 'listing.json').read_text())
        rows = [json.loads(line) for line in (folder / 'reports.jsonl').read_text().splitlines()]
        evidence = json.loads((folder / 'evidence.json').read_text())
        assert set(status) == STATUS_KEYS, (firm, 'status schema')
        assert len(rows) == status['collected'], (firm, 'report count')
        assert len(status['failures']) == status['failed'], (firm, 'failure count')
        assert len(evidence['skipped']) == status['skipped_non_report'], (firm, 'skip count')
        assert len(listing['items']) == status['listed_count'], (firm, 'listing count')
        assert status['collected'] + status['failed'] + status['skipped_non_report'] == status['listed_count'], (firm, 'reconciliation')
        item_ids = {identity(e['public_url']) for e in listing['items']}
        assert len({r['public_url'] for r in rows}) == len(rows), (firm,'duplicate report URL')
        for row in rows:
            assert set(row) == REPORT_KEYS, (firm, 'report schema', set(row)^REPORT_KEYS)
            assert row['firm_id'] == firm and identity(row['public_url']) in item_ids, (firm,'unlisted original')
            path = ROOT / row['local_path']
            assert path == ROOT / 'local-cache/originals' / row['sha256'][:2] / (row['sha256']+'.'+row['file_format']), (firm,'original path')
            body = path.read_bytes()
            assert len(body) == row['bytes'] and hashlib.sha256(body).hexdigest() == row['sha256'], (firm,'hash/size')
            if row['file_format']=='pdf':
                assert body.startswith(b'%PDF-'), (firm,'PDF signature')
            elif row['file_format']=='html':
                text = DOM(body.decode('utf-8',errors='replace')).root.visible_text()
                assert len(text)>300 and re.search(r'audit|security review',text,re.I), (firm,'HTML content')
                assert (re.search(r'Executive Summary|Audit Summary|Summary of Findings|\bScope\b',text,re.I)
                        or (firm=='fuzzland' and re.search(FINDING_MARKER,text,re.I))), (firm,'HTML report markers',row['public_url'])
            if row['source_kind']=='github':
                assert re.search(r'/blob/[0-9a-f]{40}/',row['public_url']), (firm,'unpinned GitHub URL')
            precision = row['date_precision']
            assert precision in ('day','month','year','none')
            assert bool(row['date_hint']) == (precision!='none')
            if row['date_hint']:
                datetime.strptime(row['date_hint'], {'day':'%Y-%m-%d','month':'%Y-%m','year':'%Y'}[precision])
                assert row['date_basis'] in ('listing','filename','document_text','contest_end')
            else:
                assert row['date_basis']=='none'
            if firm=='neodyme':
                claimed = re.search(r'Listing SHA256:.*?\b([0-9a-f]{64})\b',row['notes'])
                assert claimed and claimed[1]==row['sha256'], 'Neodyme listing SHA mismatch'
        for failure in status['failures']:
            assert failure['url'] in {e['public_url'] for e in listing['items']} and failure['error']
        dated = sum(bool(r['date_hint']) for r in rows)
        listing_dated = sum(bool(r['date_hint']) and r['date_basis']=='listing' for r in rows)
        stats[firm] = dict(status, dated=dated, listing_dated=listing_dated,
                           date_coverage_percent=round(100*dated/len(rows),1) if rows else None,
                           listing_date_coverage_percent=round(100*listing_dated/len(rows),1) if rows else None,
                           distinct_sha256=len({r['sha256'] for r in rows}), formats=dict(Counter(r['file_format'] for r in rows)))
        listings[firm] = listing
        all_reports.extend(rows)
    neo = neodyme_comparison([r for r in all_reports if r['firm_id']=='neodyme'])
    fuzzland_check=fuzzland_content_check([r for r in all_reports if r['firm_id']=='fuzzland'])
    assert not fuzzland_check['missing_blocks'], ('Fuzzland rendered content missing public blocks',fuzzland_check['missing_blocks'])
    # Independent publisher-sitemap check on iosiro's complete pagination.
    ns = {'s':'http://www.sitemaps.org/schemas/sitemap/0.9'}
    root = ET.fromstring(saved_body('https://www.iosiro.com/sitemap.xml'))
    iosiro_sitemap = {identity(n.text) for n in root.findall('s:url/s:loc',ns) if '/audits/' in n.text}
    iosiro_collected = {identity(r['public_url']) for r in all_reports if r['firm_id']=='iosiro'}
    assert iosiro_sitemap == iosiro_collected, 'iosiro sitemap/pagination mismatch'
    totals = {key:sum(s[key] for s in stats.values()) for key in ('listed_count','collected','failed','skipped_non_report','dated','listing_dated')}
    totals.update(publishers=len(FIRMS), distinct_sha256=len({r['sha256'] for r in all_reports}),
                  bytes_unique=sum({r['sha256']:r['bytes'] for r in all_reports}.values()),
                  formats=dict(Counter(r['file_format'] for r in all_reports)))
    totals['date_coverage_percent'] = round(100*totals['dated']/totals['collected'],1)
    validation = {'totals':totals,'publishers':stats,'checks':{'all_counts_reconcile':True,'all_original_hashes_and_sizes_verified':True,
                  'all_report_and_status_schemas_match_contract':True,'all_github_public_urls_commit_pinned':True,
                  'iosiro_sitemap_matches_complete_listing':True,'neodyme_listing_hashes_match':True,
                  'robots_date_link_and_flight_helpers_verified':True,'fuzzland_public_block_content_present':True},
                  'neodyme_comparison':neo,'fuzzland_content_check':fuzzland_check}
    write_json(ROOT/'data/collect/web_batch2/validation.json',validation)
    accessed = max(s['collected_utc'] for s in stats.values())[:10]
    lines = ['# Website collection — batch 2','',f'Live sources accessed {accessed}. Generated by `python3 scripts/collect/web_batch2_summary.py` from saved collection manifests and originals.','',
             f"Totals: **{totals['listed_count']:,} listed artifact/candidate URLs = {totals['collected']:,} collected + {totals['failed']:,} documented failures + {totals['skipped_non_report']:,} skipped entries**, across {len(FIRMS)} publishers. Skips are non-reports or entries explicitly marked nonpublic.",
             f"Collected originals have {totals['distinct_sha256']:,} distinct SHA256 values ({totals['bytes_unique']:,} bytes). Date hints cover {totals['date_coverage_percent']}% of collected rows.",'',
             'Counts are artifact URLs, not deduplicated engagements. Publisher mirrors and revisions may share a SHA256. The local originals store deduplicates bytes; Phase 3 must merge engagements. `listed_count` excludes repeated links to the same URL. Every failure and skip has an item-level reason. Asymmetric candidates are publications reviewed for scope, not claimed audit reports.','',
             'Date coverage below is nonempty date hints / collected rows; listing-only coverage is shown separately. Publication and release dates remain hints, not audit completion dates. No dates come from Git commits or retrieval time.','',
             '| Publisher / canonical listing | Listed | Collected | Failed | Skipped | Date hints | Listing dates |',
             '|---|---:|---:|---:|---:|---:|---:|']
    for firm in FIRMS:
        s=stats[firm]
        cov='n/a' if s['date_coverage_percent'] is None else str(s['date_coverage_percent'])+'%'
        lcov='n/a' if s['listing_date_coverage_percent'] is None else str(s['listing_date_coverage_percent'])+'%'
        lines.append(f"| [{firm}]({CANONICAL[firm]}) | {s['listed_count']} | {s['collected']} | {s['failed']} | {s['skipped_non_report']} | {cov} | {lcov} |")
    lines += ['','## Enumeration and scope','']
    for firm in FIRMS:
        listing=listings[firm]
        lines += [f"**{firm}.** {listing['pagination_method']} {listing['notes']}",
                  f"Source inventory: `data/collect/{firm}/listing.json`; {len(listing['listing_urls'])} listing/discovery URLs retained. Collector: `scripts/collect/web_{firm}.py`.",'']
        skip_reasons=Counter(e['skip_reason'] for e in listing['items'] if e.get('skip_reason'))
        if skip_reasons:
            lines += ['Skip breakdown: '+', '.join(f'{count} — {reason}' for reason,count in sorted(skip_reasons.items())),'']
        if firm=='fuzzland':
            for row in all_reports:
                if row['firm_id']!=firm or '5ad6ca238d9b49bc9187a1c69b852eb0' not in row['public_url']:
                    continue
                text=DOM((ROOT/row['local_path']).read_text()).root.visible_text()
                if re.search(r'Detailed Findings\s+N/A\b',text):
                    lines += [f"Publication caveat: [{row['title_hint']}]({row['public_url']}) publishes a scope table and `Detailed Findings: N/A`. This sparse publisher original is retained; it is not an independently verified zero-finding engagement.",'']
        if stats[firm]['failures']:
            reasons=Counter()
            for failure in stats[firm]['failures']:
                error=failure['error']
                reason=('robots policy' if 'robots' in error.lower() else 'HTTP 404/dead original' if 'HTTP 404' in error else
                        'redirect to non-report HTML' if 'Expected PDF, received HTML' in error else
                        'anonymous public read denied' if 'anonymous public read access' in error else
                        'browser report rendering unavailable' if 'Notion browser' in error or 'Playwright' in error else 'other documented source error')
                reasons[reason]+=1
            lines += ['Failure breakdown: '+', '.join(f'{count} {reason}' for reason,count in sorted(reasons.items()))+'.','']
    lines += ['Three Sigma official repository: https://github.com/threesigmaxyz/publications . Its Sanity CDN robots.txt explicitly disallows PDFs outside an unrelated allowed project path; those URLs were not fetched. Repository copies were collected independently from the official repository source.','',
              'Theori official Web3 listing: https://github.com/theori-io/web3-publications . This is explicitly ChainLight of Theori and overlaps `chainlight` in the registry. Do not sum them as unrelated firms. The linked Drive original remains a documented robots-policy failure.','',
              'Asymmetric official sources: https://asymmetric.com/sitemap.xml , https://github.com/asymmetric-research/security-advisories , https://stride.asymmetric.re/first-findings . No dedicated public engagement-report listing was located. The skipped inventory is a bounded review of official publications; client-hosted reports may exist outside it.','',
              'Fuzzland canonical report listing: https://docs.fuzz.land/ . Publisher-linked Notion subdomains are followed without login; rendered HTML is saved only after content is present.','',
              'HTTP clients use a descriptive User-Agent, live robots checks, and shared per-host locks limiting requests to at most one per second. Browser traffic is restricted to reviewed publisher Notion hosts and rate-limited per host. Missing robots files returning 4xx are treated as unavailable per [RFC 9309 §2.3.1.3](https://www.rfc-editor.org/rfc/rfc9309#section-2.3.1.3); explicit Disallow rules remain enforced. Original files and HTTP/browser response snapshots are local-only under `local-cache/`.','',
              '## Neodyme seed comparison','',
              f"Re-collected {neo['live_reports']} live reports versus {neo['seed_reports']} seed rows: {neo['unchanged_sha256']} unchanged hashes, {len(neo['changed_sha256'])} changed hashes, {len(neo['added_urls'])} added URLs, {len(neo['removed_urls'])} removed URLs, and {len(neo['date_hint_differences'])} listing-date differences. {neo['url_host_only_changes']} source URLs differ only after canonical host/encoding normalization (the live table uses `www.neodyme.io`). The seed was read only and no seed originals were reused. Details: `data/collect/neodyme/seed_comparison.json`.",'',
              '## Validation and reproduction','',
              'The summary script verifies every contract field set, reconciliation equation, original hash/size/path, file signature, date precision, and GitHub commit permalink. It also compares iosiro pagination with its independent sitemap and Neodyme bytes with the live listing hashes. Fuzzland HTML is checked against saved public source blocks: long prose/table text and every code block; Mermaid source may instead appear as a rendered SVG, and inline equations are checked against their original TeX annotations. Machine-readable results: `data/collect/web_batch2/validation.json`.','',
              'Run each `python3 scripts/collect/web_<firm_id>.py`, then the summary script. Existing verified SHA256 originals are reused; listings and robots policies are checked live. Add `--refresh` to re-fetch originals at existing URLs. Fuzzland needs an installed Playwright CLI; `WEB_BATCH2_PLAYWRIGHT_CLI` can select its executable or JS entrypoint. No package is automatically installed. `--resume-index` resumes from a same-day live rendered Notion index and cached report snapshots.','',
              'Files produced are enumerated in `data/collect/web_batch2/files_written.txt` (including local-only original/cache artifacts). Each publisher has `listing.json`, `reports.jsonl`, `status.json`, and `evidence.json`. No registry files, seed data, or inbox archives were changed. No commit or push was made.','']
    (ROOT/'docs/collect').mkdir(parents=True,exist_ok=True)
    (ROOT/'docs/collect/web_batch2.md').write_text('\n'.join(lines))
    paths = {str(p.relative_to(ROOT)) for p in CACHE.rglob('*') if p.is_file()}
    paths.update(r['local_path'] for r in all_reports)
    # Retain superseded Notion snapshots in the output manifest as well.
    for original in (ROOT/'local-cache/originals').glob('*/*.html'):
        body=original.read_bytes()
        if b'notion-html' in body[:1000] and (b'docs.fuzz.land' in body or b'fuzzland.notion.site' in body):
            paths.add(str(original.relative_to(ROOT)))
    # Include superseded local response artifacts from this run as well.
    for meta_path in (CACHE/'http').glob('*.json'):
        meta=json.loads(meta_path.read_text())
        sha=meta.get('sha256','')
        for ext in ('pdf','html','md','other'):
            original=ROOT/'local-cache/originals'/sha[:2]/(sha+'.'+ext)
            if original.is_file():
                paths.add(str(original.relative_to(ROOT)))
    for firm in FIRMS:
        paths.add('scripts/collect/web_'+firm+'.py')
        paths.update(str(p.relative_to(ROOT)) for p in (ROOT/'data/collect'/firm).glob('*') if p.is_file())
    paths.update(['scripts/collect/web_batch2_common.py','scripts/collect/web_batch2_summary.py','docs/collect/web_batch2.md',
                  'data/collect/web_batch2/validation.json','data/collect/web_batch2/files_written.txt'])
    (ROOT/'data/collect/web_batch2/files_written.txt').write_text('\n'.join(sorted(paths))+'\n')
    print(json.dumps({'totals':totals,'checks':validation['checks'],'neodyme_comparison':neo},indent=2))


if __name__=='__main__':
    main()
