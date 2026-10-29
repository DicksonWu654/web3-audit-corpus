#!/usr/bin/env python3
"""Derive bounded, reproducible source measurements from pinned trees and HTTP.

python3 -I scripts/aggregators/analyze.py
Only our own collector is loaded. No external modules, notebooks, JS, or code run.
The output contains counts, schemas, and hashes, never report bodies or secrets.
"""
import collections
import concurrent.futures
import csv
import datetime as dt
import hashlib
import html
import io
import json
import pathlib
import re
import runpy
import urllib.parse
import zipfile

HERE = pathlib.Path(__file__).resolve().parent
helpers = runpy.run_path(str(HERE / 'measure.py'))
fetch, get_json = helpers['fetch'], helpers['get_json']
repos = json.loads((HERE / 'repo_measurements.json').read_text())
urls = json.loads((HERE / 'urls.json').read_text())
out = {}

def tree(repo, path=''):
    r = repos[repo]
    base = 'https://api.github.com/repos/' + repo + '/git/trees/'
    if not path:
        return get_json(r['tree_request']['url'])[1]
    sha = r['commit']
    for part in path.split('/'):
        info, data = get_json(base + sha)
        sha = next(x['sha'] for x in data['tree'] if x['path'] == part)
    info, data = get_json(base + sha + '?recursive=1')
    return data

def paths(repo, path=''):
    t = tree(repo, path)
    assert not t.get('truncated'), (repo, path, 'truncated; do not report as full count')
    return [x['path'] for x in t['tree'] if x['type'] == 'blob']

def raw(repo, path):
    return fetch('https://raw.githubusercontent.com/' + repo + '/' + repos[repo]['commit']
                 + '/' + urllib.parse.quote(path, safe='/'))[1]

def body(key):
    return fetch(urls[key])[1]

def linkset(key, pattern):
    s = body(key).decode(errors='replace')
    return sorted(set(html.unescape(x) for x in re.findall(pattern, s)))

def rsc(key):
    """Decode JSON string arguments to Next Flight push, without evaluating JS."""
    s = body(key).decode(errors='replace')
    chunks = []
    for match in re.finditer(r'self\.__next_f\.push\((\[.*?\])\)</script>', s):
        try:
            obj = json.loads(match[1])
            if len(obj) > 1 and isinstance(obj[1], str):
                chunks.append(obj[1])
        except ValueError:
            pass
    return '\n'.join(chunks)

def archive():
    repo = 'gcf3711/audit-report-archive'
    ps = [p for p in paths(repo) if p.startswith('data/catalog/') and p.endswith('.json')]
    records = []
    def load(p):
        d = json.loads(raw(repo, p))
        return p, d if isinstance(d, list) else d.get('reports', d.get('items', []))
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        per_source = {}
        source_ranges={}
        for p, data in pool.map(load, ps):
            per_source[pathlib.PurePosixPath(p).stem] = len(data)
            ds=sorted(str(x['date']) for x in data if re.match(r'^20\d{2}',str(x.get('date') or '')))
            source_ranges[pathlib.PurePosixPath(p).stem]=[ds[0],ds[-1]] if ds else []
            records += data
    dates = [str(r['date']) for r in records if r.get('date')]
    valid_dates=[d for d in dates if re.fullmatch(r'20\d{2}(?:-(?:0[1-9]|1[0-2])(?:-(?:0[1-9]|[12]\d|3[01]))?)?',d)]
    report_urls = [r.get('report_url') for r in records if r.get('report_url')]
    hashes = [r['sha256'] for r in records if r.get('sha256')]
    available = [r for r in records if r.get('local_path') and r.get('sha256')]
    def canonical_url(url):
        u=urllib.parse.urlsplit(url)
        path=urllib.parse.unquote(u.path)
        if u.hostname=='github.com':path=re.sub(r'^(/[^/]+/[^/]+/blob)/[^/]+/',r'\1/{revision}/',path)
        return urllib.parse.urlunsplit((u.scheme,u.netloc,path,u.query,''))
    out['archive'] = dict(catalog_files=len(ps), records=len(records), per_source=per_source,
        source_date_ranges=source_ranges,
        nonempty_sources=sum(bool(n) for n in per_source.values()),
        distinct_report_urls=len(set(report_urls)), duplicate_url_excess=len(report_urls)-len(set(report_urls)),
        with_date=len(dates), min_date=min(dates), max_date=max(dates),
        syntactically_valid_dates=len(valid_dates),invalid_nonempty_dates=len(dates)-len(valid_dates),
        min_valid_date=min(valid_dates),max_valid_date=max(valid_dates),
        date_precision=dict(collections.Counter({4:'year',7:'month',10:'day'}.get(len(d),'invalid') for d in valid_dates)),
        revision_normalized_urls=len(set(map(canonical_url,report_urls))),
        with_local_path=sum(bool(r.get('local_path')) for r in records),
        with_downloaded_at=sum(bool(r.get('downloaded_at')) for r in records),
        dates_by_year=dict(sorted(collections.Counter(d[:4] for d in dates).items())),
        sha256_records=len(hashes), unique_sha256=len(set(hashes)),
        available_records=len(available), fields=sorted(set().union(*(r.keys() for r in records))),
        sample={k:v for k,v in records[0].items() if k not in ('extra',)},
        catalog_url_template='https://raw.githubusercontent.com/'+repo+'/'+repos[repo]['commit']+'/data/catalog/{source}.json')
    ai = json.loads(body('archive_hf'))
    files = [x['rfilename'] for x in ai.get('siblings',[]) if x['rfilename'].startswith('reports/')]
    out['archive_hf'] = dict(sha=ai.get('sha'), last_modified=ai.get('lastModified'),
        report_files=len(files), extensions=dict(collections.Counter(pathlib.PurePosixPath(p).suffix for p in files)),
        license=ai.get('cardData',{}).get('license'))

def repo_subsets():
    for repo, prefix in [('sherlock-protocol/sherlock-reports','audits/'),
                         ('SunWeb3Sec/DeFiHackLabs','src/test/'),
                         ('slowmist/Knowledge-Base','open-report'),
                         ('agentlisa/bench','dataset/')]:
        ps = [p for p in paths(repo) if p.startswith(prefix)]
        selected = [p for p in ps if p.endswith('.json')] if 'bench' in repo else ps
        out[repo] = dict(files=len(ps), extensions=dict(collections.Counter(pathlib.PurePosixPath(p).suffix for p in ps)),
            path_years=dict(sorted(collections.Counter(y for p in ps for y in re.findall(r'(?<!\d)(20(?:1\d|2\d))[-_.]',p)).items())))
        if 'bench' in repo:
            data = json.loads(raw(repo, selected[0]))
            out[repo].update(json_files=len(selected), sample_schema=list(data) if isinstance(data,dict) else str(type(data)),
                             sample={k:v for k,v in data.items() if k in ('source','firm','project','date','severity','source_link','protocol')})
    repo='l2beat/l2beat'
    ps=[p for p in paths(repo) if p.startswith('packages/config/src/projects/') and p.endswith('.ts')]
    out['l2beat'] = dict(project_ts_files=len(ps), note='configuration files, not audit counts')
    ps=[p for p in paths('trailofbits/publications') if p.startswith('reviews/') and p.lower().endswith('.pdf')]
    out['trailofbits_reviews']=dict(pdf_paths=len(ps),
        filename_years=sorted(set(y for p in ps for y in re.findall(r'(?<!\d)(20\d{2})-',p))),
        note='all reviewed projects, not a Web3-only engagement count')
    # Resolve only report/finding subtrees, bypassing GitHub recursive-root truncation.
    for repo, subpaths in [
        ('shenyimings/FORGE-Artifacts',['dataset/results']),
        ('shenyimings/FORGE-Curated',['dataset-curated/reports','dataset-curated/findings',
                                    'dataset-curated/findings-without-source']),
        ('InPlusLab/DAppSCAN',['DAppSCAN-source'])]:
        out[repo] = {}
        for path in subpaths:
            try:
                ps = paths(repo,path)
                out[repo][path] = dict(files=len(ps),extensions=dict(collections.Counter(pathlib.PurePosixPath(p).suffix for p in ps)),
                    directories=dict(collections.Counter(p.split('/')[0] for p in ps if '/' in p)),sample_paths=ps[:5])
            except (StopIteration,KeyError,AssertionError,TypeError) as e:
                out[repo][path] = dict(unmeasured_reason=str(e) or 'subtree missing')

def portals():
    # Distinct IDs/URLs in the captured response; never infer a global total from a page.
    for key, regex in [
        ('immunefi_competitions',r'href="/audit-competition/([^/"?#]+)'),
        ('cantina_reports',r'https://cdn\.cantina\.xyz/reports/[^\s"<>\\]+'),
        ('code4rena_sitemap',r'<loc>(https://code4rena\.com/reports/[^<]+)</loc>'),
    ]:
        s=body(key).decode(errors='replace')
        vals=sorted(set(re.findall(regex,s)))
        out[key] = dict(distinct_matches=len(vals),selector=regex,sample=vals[:5],
                        scope='captured response, not a certified platform census')
    for key in ['code4rena_reports','code4rena_audits','cantina_reports','cantina_competitions']:
        s=rsc(key)
        out.setdefault(key,{})['flight_bytes']=len(s)
        for label,rx in [('pdf_urls',r'https://cdn\.cantina\.xyz/reports/[^\s"<>\\]+')]:
            vals=sorted(set(re.findall(rx,s)))
            if vals:out[key][label]=dict(count=len(vals),sample=vals[:5])
        # Traverse inert JSON Flight records to find structured audit/listing objects.
        objects=[]
        def walk(v):
            if isinstance(v,dict):
                objects.append(v)
                for x in v.values():walk(x)
            elif isinstance(v,list):
                for x in v:walk(x)
        for line in s.splitlines():
            try:walk(json.loads(line.split(':',1)[1]))
            except (ValueError,IndexError):pass
        if key=='code4rena_reports':
            reports={v['slug']:v for v in objects if all(k in v for k in ('slug','contest','date','findings'))}
            dates=[re.search(r'20\d{2}-\d{2}-\d{2}',v['date'])[0] for v in reports.values() if re.search(r'20\d{2}-\d{2}-\d{2}',v.get('date') or '')]
            out[key]['structured_report_records']=len(reports)
            out[key]['publication_date_range']=[min(dates),max(dates)]
            out[key]['publication_year_counts']=dict(sorted(collections.Counter(d[:4] for d in dates).items()))
        if key=='code4rena_audits':
            audits={v['uid']:v for v in objects if all(k in v for k in ('uid','contestId','startTime','auditType'))}
            out[key].update(structured_audits=len(audits),audit_types=dict(collections.Counter(v['auditType'] for v in audits.values())),
                earliest_start=min((v['startTime'] for v in audits.values()),default=None),
                latest_start=max((v['startTime'] for v in audits.values()),default=None))
        if key=='cantina_reports':
            match=re.search(r'"cantinaManaged":',s)
            if match:
                data,_=json.JSONDecoder().raw_decode(s[match.end():])
                out[key]['managed_review_records']=len(data)
                out[key]['issue_category_counts']=dict(collections.Counter({}))
                counts=collections.Counter()
                for row in data:
                    for issue in row.get('issues') or []:counts[issue['category']]+=issue['count']
                out[key]['issue_category_counts']=dict(counts)
    d=json.loads(body('defillama_protocols'))
    links=[url for p in d for url in (p.get('audit_links') or [])]
    out['defillama'] = dict(protocols=len(d),protocols_with_audit_links=sum(bool(p.get('audit_links')) for p in d),
        audit_link_occurrences=len(links),unique_audit_links=len(set(links)),
        fields_in_sample=sorted(json.loads(body('defillama_aave')).keys()))
    d=json.loads(body('c4audit_zenodo'))
    out['c4audit'] = dict(version=d['metadata'].get('version'),modified=d['modified'],license=d['metadata'].get('license'),
        files=[dict(name=f['key'],bytes=f['size'],checksum=f['checksum'],url=f['links']['self']) for f in d['files']])
    d=json.loads(body('kaggle_discovery'))
    out['kaggle'] = dict(search_hits=len(d),hits=[{k:x.get(k) for k in ['ref','totalBytes','lastUpdated','licenseName']}
                                                for x in d if 'audit-report' in x.get('ref','')])
    d=json.loads(body('zaevlad_hf'))
    out['zaevlad'] = dict(sha=d['sha'],last_modified=d['lastModified'],license=d.get('cardData',{}).get('license'),
        file_count=len(d['siblings']),size_endpoint=json.loads(body('zaevlad_hf_size')),
        fields=[f['name'] for f in json.loads(body('zaevlad_hf_rows'))['features']])
    d=json.loads(body('hacken_public_api'))
    if isinstance(d,list):
        dates=[x['audit_date'] for x in d if x.get('audit_date')]
        out['hacken']=dict(audits=len(d),clients=len(set(x.get('client_name') for x in d)),
            findings=sum(len(x.get('issues') or []) for x in d),
            date_range=[min(dates),max(dates)],fields=sorted(set().union(*(x.keys() for x in d))))
    index=body('immunefi_report_index').decode()
    links=re.findall(r'^- \[.*?\]\((https://reports\.immunefi\.com/[^)]+)\)',index,re.M)
    out['immunefi_report_index']=dict(markdown_links=len(set(links)),
        top_level_pages=sum('/' not in s.removeprefix('https://reports.immunefi.com/') for s in set(links)),
        nested_pages=sum('/' in s.removeprefix('https://reports.immunefi.com/') for s in set(links)),
        note='nested pages include submissions, duplicates, invalids; not accepted unique findings')

def census():
    repo='munimtechnologies/audit-contest-ai-rules'
    out['contest_census']={}
    for p in paths(repo):
        if p.startswith('data/') and p.endswith('.csv'):
            data=list(csv.DictReader(io.StringIO(raw(repo,p).decode())))
            out['contest_census'][p]=dict(rows=len(data),fields=list(data[0]) if data else [],
                kind_counts=dict(collections.Counter(x.get('kind','[not provided]') for x in data)),
                sample={k:v for k,v in (data[0] if data else {}).items() if re.search('(?i)date|start|end|id|name',k)})

def platform_apis():
    # Enumerate every advertised page, reject duplicate IDs or incomplete pagination.
    for key,base in [('code4rena','https://code4rena.com/api/v1/audits?perPage=100&page='),
                     ('sherlock','https://mainnet-contest.sherlock.xyz/contests?per_page=100&page=')]:
        records=[]
        requests=[]
        for page in range(1,51):
            info,data=get_json(base+str(page))
            requests.append(info)
            if info['status']!=200 or not isinstance(data,dict):break
            if key=='code4rena':
                records+=data['data']['audits'];pagination=data['pagination']
                if not pagination.get('nextPage'):break
            else:
                records+=data['items']
                if not data.get('has_next'):break
        idkey='uid' if key=='code4rena' else 'id'
        unique={r[idkey]:r for r in records}
        advertised=data.get('pagination',{}).get('total') if key=='code4rena' else data.get('total')
        complete=info['status']==200 and len(unique)==advertised
        out[key+'_api']=dict(records=len(records),unique_ids=len(unique),advertised_total=advertised,
                            pagination_complete=complete,requests=requests)
        if key=='code4rena':
            out[key+'_api'].update(audit_types=dict(collections.Counter(r['auditType'] for r in unique.values())),
                status_counts=dict(collections.Counter(r['status'] for r in unique.values())),
                date_range=[min(r['startTime'] for r in unique.values()),max(r['startTime'] for r in unique.values())],
                start_year_counts=dict(sorted(collections.Counter(r['startTime'][:4] for r in unique.values()).items())))
        else:
            public=[r for r in unique.values() if r.get('private') is False]
            out[key+'_api'].update(public_records=len(public),type_labels=dict(collections.Counter(r['type_label'] for r in unique.values())),
                date_range=[dt.datetime.fromtimestamp(min(r['starts_at'] for r in public),dt.timezone.utc).isoformat(),
                            dt.datetime.fromtimestamp(max(r['starts_at'] for r in public),dt.timezone.utc).isoformat()])
    d=json.loads(body('cantina_public_api'))
    dates=[x.get('timeframe',{}).get('start') for x in d if x.get('timeframe',{}).get('start')]
    out['cantina_api']=dict(competition_records=len(d),unique_ids=len(set(x['id'] for x in d)),
        date_range=[min(dates),max(dates)],
        kind_counts=dict(collections.Counter(x.get('kind') for x in d)),
        status_counts=dict(collections.Counter(x['status'] for x in d)),
        fields=list(d[0]))

def bulk_archives():
    # Inspect directory entries and parse bounded data in memory; never extract or execute.
    for key in ['kaggle_audit_download','c4audit_reports_download']:
        info,b=fetch(urls[key])
        if info['status']!=200:
            out[key]=dict(request=info,unmeasured_reason='download failed');continue
        if key=='c4audit_reports_download':
            expected=next(f['checksum'].split(':')[1] for f in out['c4audit']['files'] if f['name']=='C4Audit-Reports.zip')
            assert hashlib.md5(b).hexdigest()==expected
        with zipfile.ZipFile(io.BytesIO(b)) as z:
            files=[f for f in z.infolist() if not f.is_dir() and not f.filename.startswith('__MACOSX/') and not f.filename.endswith('.DS_Store')]
            assert sum(f.file_size for f in files)<128_000_000
            assert all(f.file_size<64_000_000 for f in files)
            out[key]=dict(request=info,data_files=len(files),uncompressed_bytes=sum(f.file_size for f in files))
            if key=='kaggle_audit_download':
                csv.field_size_limit(64_000_000)
                data=list(csv.DictReader(io.StringIO(z.read(files[0]).decode('utf-8-sig'))))
                out[key].update(rows=len(data),fields=list(data[0]) if data else [])
            else:
                json_files=0;issue_counts=0;schemas=[];date_slugs=[]
                for f in files:
                    if f.filename.endswith('.json'):
                        json_files+=1;d=json.loads(z.read(f))
                        date_slugs.extend(re.findall(r'20\d{2}-\d{2}',f.filename))
                        if isinstance(d,dict):
                            issue_counts+=len(d.get('issues') or [])
                            if not schemas:schemas=list(d)
                out[key].update(json_files=json_files,
                    issues_in_top_level_issues_arrays=issue_counts,sample_schema=schemas,
                    filename_date_range=[min(date_slugs),max(date_slugs)] if date_slugs else [])
    for key in ['hf_nyx','hf_audits_reasons','hf_forge_curated']:
        d=json.loads(body(key))
        out[key]=dict(sha=d['sha'],last_modified=d['lastModified'],card=d.get('cardData'),
                      files=len(d['siblings']))
    out['hf_nyx_size']=json.loads(body('hf_nyx_size'))

def github_search():
    for key,q in [('code4rena_findings_repos','org:code-423n4 findings in:name'),
                  ('sherlock_judging_repos','org:sherlock-audit judging in:name'),
                  ('hats_vault_repos','org:hats-finance 0x in:name')]:
        url='https://api.github.com/search/repositories?'+urllib.parse.urlencode(dict(q=q,per_page=1))
        info,d=get_json(url)
        out[key]=dict(request=info,total_count=d.get('total_count') if isinstance(d,dict) else None,
                      incomplete_results=d.get('incomplete_results') if isinstance(d,dict) else None,
                      sample=[x['html_url'] for x in d.get('items',[])] if isinstance(d,dict) else [])

if __name__=='__main__':
    for fn in [archive,repo_subsets,portals,github_search,census,platform_apis,bulk_archives]:
        fn()
        print(fn.__name__,'complete',flush=True)
        (HERE/'derived_measurements.json').write_text(json.dumps(out,indent=2,ensure_ascii=False)+'\n')
    (HERE/'derived_measurements.json').write_text(json.dumps(out,indent=2,ensure_ascii=False)+'\n')
