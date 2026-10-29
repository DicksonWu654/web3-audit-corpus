#!/usr/bin/env python3
"""Fetch and count complete public report listings, retaining item-level evidence.

No JavaScript is executed. Endpoints were identified in public site data/bundles.
python3 -I scripts/registry/measure_listings.py
"""
import concurrent.futures
import csv
import html
import importlib.util
import io
import json
from pathlib import Path
import re
import time

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('registry_collect', Path(__file__).with_name('collect.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
CACHE = Path('local-cache/tmp/firm-registry-cache')
CACHE.mkdir(exist_ok=True)


def fetch(url):
    m, b = module.http(url, CACHE)
    for attempt in range(3):
        if m['status'] not in (429, 500, 502, 503, 504, 0):
            break
        # Respect throttling. Keep prior observations; do not discard failures.
        age = (module.dt.datetime.now(module.UTC) - module.dt.datetime.fromisoformat(m['checked_utc'])).total_seconds()
        time.sleep(max(0, 60 - age) if m['status'] == 429 else 5)
        retry_cache = CACHE / ('retry-' + str(attempt))
        retry_cache.mkdir(exist_ok=True)
        m, b = module.http(url, retry_cache)
    if m['status'] != 200:
        raise RuntimeError(f"{url}: HTTP {m['status']}")
    return m, b


def flight_records(text):
    """Decode public React Flight JSON data without executing scripts."""
    chunks=[]
    for block in re.findall(r'self\.__next_f\.push\((.*?)\)</script>',text,re.S):
        try:
            x=json.loads(block)
            if x[0]==1:chunks.append(x[1])
        except (ValueError,IndexError,TypeError):
            continue
    records={}
    for line in ''.join(chunks).splitlines():
        if ':' not in line:continue
        key,payload=line.split(':',1)
        try:records[key]=json.loads(payload)
        except ValueError:continue
    return records


def objects_in(value):
    if isinstance(value,dict):
        yield value
        for v in value.values():yield from objects_in(v)
    elif isinstance(value,list):
        for v in value:yield from objects_in(v)


def resolve_reference(value,records):
    if not isinstance(value,str) or not value.startswith('$'):return value
    bits=value[1:].split(':')
    v=records.get(bits[0])
    try:
        for p in bits[1:]:
            if p=='props' and isinstance(v,list) and v[0]=='$':v=v[3]
            else:v=v[int(p)] if isinstance(v,list) else v[p]
        return v
    except (KeyError,IndexError,TypeError,ValueError):return value


def main():
    results = []
    # Hacken exposes all public report records, unlike its larger completed-audit total.
    m, b = fetch('https://hacken.io/api/audits')
    rows = json.loads(b)
    items = [{'url': r['report_link'], 'date': r.get('audit_date', ''), 'type': r.get('audit_type', '')}
             for r in rows if r.get('report_link') and r.get('audit_type') != 'POR']
    results.append({'firm_id': 'hacken', 'method': 'counted_listing', 'pages': [m], 'items': items,
                    'scope': 'Public API report links; proof-of-reserves records excluded.',
                    'input_records': len(rows), 'excluded_por': sum(r.get('audit_type') == 'POR' for r in rows)})

    # Quantstamp's site requests pages of 15; enumerate all pages, not just total.
    m, b = fetch('https://certificate.quantstamp.com/api/certificates')
    first = json.loads(b)
    total, size = first['total'], len(first['data'])
    pages, rows = [m], list(first['data'])
    urls = ['https://certificate.quantstamp.com/api/certificates?offset=' + str(i)
            for i in range(size, total, size)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        for meta, payload in executor.map(fetch, urls):
            pages.append(meta)
            rows.extend(json.loads(payload)['data'])
    assert len({r['id'] for r in rows}) == total, 'Quantstamp pagination incomplete'
    items = [{'url': 'https://certificate.quantstamp.com/' + r['link'], 'date': r.get('publishedAt', '')}
             for r in rows if r.get('link')]
    results.append({'firm_id': 'quantstamp', 'method': 'counted_listing', 'pages': pages, 'items': items,
                    'scope': 'All certificate pages enumerated; rows without public report links excluded.',
                    'input_records': len(rows)})

    # SourceHat's API returns projects, each containing one or more public reports.
    m, b = fetch('https://api.sourcehat.com/audit_list/?all=1')
    first = json.loads(b)['responseData']['data']
    total, size = first['count'], len(first['results'])
    pages, rows = [m], list(first['results'])
    urls = ['https://api.sourcehat.com/audit_list/?all=1&page=' + str(i)
            for i in range(2, (total + size - 1) // size + 1)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        for meta, payload in executor.map(fetch, urls):
            pages.append(meta)
            rows.extend(json.loads(payload)['responseData']['data']['results'])
    assert len({r['id'] for r in rows}) == total, 'SourceHat pagination incomplete'
    items = [{'url': r['audit_report_link'].replace('http://', 'https://').replace('solidity.finance', 'sourcehat.com').rstrip('/'),
              'date': r.get('completion_date', '')}
             for project in rows for r in project.get('audit_report', [])
             if r.get('audit_status') == 'public' and r.get('audit_report_link')]
    results.append({'firm_id': 'sourcehat', 'method': 'counted_listing', 'pages': pages, 'items': items,
                    'scope': 'All project pages enumerated; only public nested audit_report links counted; old domain normalized.',
                    'input_projects': len(rows)})

    # Static report links from server-rendered pages/data, not promotional counters.
    for firm_id, url, pattern in [
        ('chainsecurity', 'https://www.chainsecurity.com/smart-contract-audit-reports', r'href="(/security-audit/[^"?#]+)"'),
        ('cantina', 'https://cantina.xyz/security-reviews', r'https://cdn\.cantina\.xyz/reports/[^\s"<>\\]+\.pdf'),
        ('neodyme', 'https://www.neodyme.io/en/reports/', r'href="([^"?#]+\.pdf)"'),
    ]:
        m, b = fetch(url)
        text = html.unescape(b.decode().replace('\\"', '"').replace('\\/', '/'))
        links = sorted(set(re.findall(pattern, text)))
        assert links, firm_id + ' empty listing'
        from urllib.parse import urljoin
        items = [{'url': urljoin(url, p)} for p in links]
        results.append({'firm_id': firm_id, 'method': 'counted_listing', 'pages': [m], 'items': items,
                        'pattern': pattern, 'scope': 'Unique public report links exposed by listing; page links, not project/client counts.'})

    m, b = fetch('https://code4rena.com/reports')
    records=flight_records(b.decode())
    objects = [r for payload in records.values() for r in objects_in(payload)
               if r.get('date') and r.get('slug') and 'findings' in r]
    items = [{'url': r.get('alt_url') or 'https://code4rena.com/reports/' + r['slug'], 'date': r['date']}
             for r in objects]
    assert items, 'Code4rena report object parser empty'
    results.append({'firm_id': 'code4rena', 'method': 'counted_listing', 'pages': [m], 'items': items,
                    'scope': 'Published report objects with date and slug in server-rendered report listing; repeated objects deduplicated.'})

    m, b = fetch('https://omniscia.io/assets/data/clients.csv')
    links = set()
    for r in csv.DictReader(io.StringIO(b.decode())):
        links.update(re.findall(r'https://omniscia\.io/reports/[^,\s"|]+', r['audits']))
    assert links, 'Omniscia parser empty'
    results.append({'firm_id': 'omniscia', 'method': 'counted_listing', 'pages': [m],
                    'items': [{'url': u} for u in sorted(links)],
                    'scope': 'Unique report URLs in website clients.csv; N/A/private entries excluded.'})

    m,b=fetch('https://www.openzeppelin.com/research')
    records=flight_records(b.decode())
    entries={r['_id']:r for payload in records.values() for r in objects_in(payload)
             if r.get('_type')=='research' and r.get('_id')}
    reports=[]
    for r in entries.values():
        categories=[resolve_reference(v,records) for v in r.get('categories',[])]
        if any(isinstance(v,dict) and v.get('slug')=='security-audits' for v in categories):
            reports.append({'url':'https://www.openzeppelin.com/news/'+r['slug'],
                            'date':r.get('publishedAt',''),'title':r.get('title','')})
    assert len(reports)>100,'OpenZeppelin category parser incomplete'
    results.append({'firm_id':'openzeppelin','method':'counted_listing','pages':[m], 'items':reports,
                    'scope':'All embedded research entries with resolved Security Audits category; news/research categories excluded.'})

    m,b=fetch('https://osec.io/audits')
    text=html.unescape(b.decode())
    links=set(re.findall(r'href="(/reports/[0-9a-f-]{36})"',text))
    links.update(re.findall(r'href="(https://github\.com/[^"<>]+\.pdf)"',text))
    assert len(links)>100,'OtterSec report listing incomplete'
    from urllib.parse import urljoin
    results.append({'firm_id':'ottersec','method':'counted_listing','pages':[m],
                    'items':[{'url':urljoin('https://osec.io',u),'format':'pdf'} for u in sorted(links)],
                    'scope':'Unique stable report UUID links and externally hosted PDF report links from the full public listing. Stable UUID URLs can redirect to temporary signed downloads.'})

    observations=[json.loads(l) for l in (ROOT/'data/registry/observations.jsonl').read_text().splitlines()]
    observed=next(r for r in observations if r['firm_id']=='spearbit')['readmes'][0]
    m,b=fetch(observed['url'])
    text=b.decode()
    items=[]
    for line in text.splitlines():
        for u in re.findall(r'\[:page_facing_up:\]\(([^)]+)\)',line):
            # Current README links to portfolio pages and a few legacy PDF paths.
            items.append({'url':urljoin('https://github.com/spearbit/portfolio/blob/master/',u),
                          'date':' '.join(re.findall(r'\b20\d\d\b',line))})
    assert items,'Spearbit report table empty'
    results.append({'firm_id':'spearbit','method':'counted_listing','pages':[m],'items':items,
                    'scope':'Report cells in publisher engagement/competition tables; seminars and content excluded. Some legacy PDF paths are no longer present at HEAD; listing count is not a downloadable-file count. Cantina hosts many of the same reports.'})

    for r in results:
        unique = {i['url']: i for i in r['items']}
        r['items'] = [unique[k] for k in sorted(unique)]
        r['count'] = len(r['items'])
        print(r['firm_id'], r['count'], 'pages', len(r['pages']), flush=True)
    (ROOT / 'data/registry/listings.json').write_text(json.dumps(results, ensure_ascii=False, indent=2) + '\n')


if __name__ == '__main__':
    main()
