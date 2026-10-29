#!/usr/bin/env python3
"""Merge, attribute, subtract current listings, and HEAD-check discovery leads.

python3 -I scripts/discovery/discover.py build
python3 -I scripts/discovery/discover.py check
python3 -I scripts/discovery/discover.py report

All generated public artifacts are metadata. Response bodies remain gitignored.
check is resumable through its content-addressed per-request cache. A blocked
HEAD is unknown (null), never a fabricated live/dead result.
"""
from __future__ import annotations
import argparse
import collections
import concurrent.futures
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import runpy
from urllib.parse import unquote,urlsplit,urlunsplit,quote

ROOT=Path(__file__).resolve().parents[2]
H=runpy.run_path(str(ROOT/'scripts/discovery/common.py'))
OUT=H['OUT']; SCOPE=H['scope'](); ALIASES=H['aliases']()
REGISTRY={r['firm_id']:r for r in csv.DictReader((ROOT/'registry/firms.csv').open())}
EXTRA_OWNERS={'Ackee-Blockchain':'ackee-blockchain','crytic':'trail-of-bits',
              'ConsenSys':'consensys-diligence','consensys-diligence':'consensys-diligence',
              'quantstamp':'quantstamp','yAudit':'electisec','pashov':'pashov-audit-group',
              'Trust1995':'trust-security','sec3-service':'sec3','theori-io':'chainlight',
              'sherlock-protocol':'sherlock','code-423n4':'code4rena','immunefi-team':'immunefi',
              'hats-finance':'hats-finance','Secure3Audit':'secure3'}
OWNERS={k.lower():v for k,v in EXTRA_OWNERS.items()}
HOSTS={}
for fid,s in SCOPE.items():
    for r in (s,REGISTRY.get(fid,{})):
        for field in ('github_reports_url','website_reports_url','website'):
            for url in r.get(field,'').split(';'):
                u=urlsplit(url);parts=u.path.strip('/').split('/')
                if u.hostname=='github.com' and len(parts)>=2 and parts[0]!='orgs':OWNERS[parts[0].lower()]=fid
                elif u.hostname and u.hostname!='github.com':HOSTS[u.hostname.removeprefix('www.')]=fid
HOSTS.update({'consensys.net':'consensys-diligence','diligence.consensys.io':'consensys-diligence',
              'openzeppelin.com':'openzeppelin','blog.openzeppelin.com':'openzeppelin',
              'certificate.quantstamp.com':'quantstamp','reports.chainsecurity.com':'chainsecurity'})
HOSTS.update({'threesigma.xyz':'three-sigma','theori.io':'theori','asymmetric.re':'asymmetric-research','fuzz.land':'fuzzland'})

def read_jsonl(p):
    if not p.exists(): return []
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]

def git_parts(url):
    if not url:return None
    try:u=urlsplit(url)
    except ValueError:return None
    p=unquote(u.path).strip('/').split('/')
    if u.hostname=='raw.githubusercontent.com' and len(p)>=4:return p[0],p[1],p[2],'/'.join(p[3:])
    if u.hostname in ('github.com','www.github.com') and len(p)>=5 and p[2] in ('blob','raw'):
        return p[0],p[1],p[3],'/'.join(p[4:])
    return None

def key(url):
    g=git_parts(url)
    if g:return 'github:'+g[0].lower()+'/'+g[1].lower()+'/'+g[3]
    u=urlsplit(url)
    return urlunsplit((u.scheme.lower(),u.netloc.lower().removeprefix('www.'),unquote(u.path).rstrip('/'),u.query,''))

def head_url(url):
    g=git_parts(url)
    return H['raw_url'](g[0]+'/'+g[1],g[2],g[3]) if g else url

def url_firm(url):
    if not url:return None
    u=urlsplit(url)
    if u.hostname in ('github.com','raw.githubusercontent.com','www.github.com'):
        owner=u.path.strip('/').split('/')[0].lower()
        return OWNERS.get(owner)
    host=(u.hostname or '').removeprefix('www.')
    return next((v for h,v in sorted(HOSTS.items(),key=lambda x:-len(x[0])) if host==h or host.endswith('.'+h)),None)

def attributed(row):
    fid=row.get('firm_id'); b=row.get('attribution_basis') or {}
    if fid not in SCOPE or not b.get('evidence_url'):return False,'no scoped attribution evidence'
    kind=b.get('kind',''); label=b.get('value') or b.get('auditor') or ''
    if kind=='catalog_explicit_publisher':
        if ALIASES.get(H['norm'](label))!=fid:return False,'catalog author alias mismatch'
        identities=[url_firm(b.get('listing_url')),url_firm(row.get('original_publisher_url'))]
        if fid not in identities:return False,'catalog author has no independently matching publisher URL'
        b['verified_against']='catalog author label agrees with registered publisher listing/domain or recognized publisher GitHub account'
    elif kind in ('explicit_publisher_directory','named_author_directory','explicit_auditor_field'):
        if ALIASES.get(H['norm'](label))!=fid:return False,'explicit author alias mismatch'
        b['verified_against']='explicit named author metadata, exact scoped alias match; repository host is an aggregator'
    elif kind in ('publisher_canonical_url','publisher_owned_path','publisher_url'):
        if url_firm(row['candidate_url'])!=fid:return False,'publisher URL identity mismatch'
        b['verified_against']='registered publisher domain/repository identity'
    elif kind in ('named_filename','filename_publisher'):
        hits=H['named_firms'](label)
        if hits!={fid}:return False,'ambiguous or missing named author in filename'
        b['verified_against']='unique explicit full author alias in report filename'
    elif kind.startswith('wayback'):
        if url_firm(row['candidate_url'])!=fid:return False,'archive URL not publisher-owned'
        b['verified_against']='CDX capture under registered publisher report path'
    elif kind=='publisher_listing_path':
        if url_firm(row['candidate_url'])!=fid:return False,'archive path not a recognized publisher URL'
        b['verified_against']='CDX capture under registered publisher listing path'
    else:return False,'unsupported attribution evidence kind: '+kind
    b['verified']=True
    return True,None

def basename(url):
    g=git_parts(url)
    path=g[3] if g else unquote(urlsplit(url).path)
    return H['norm'](Path(path).stem)

def meaningful_name(value):
    n=H['norm'](Path(str(value or '')).stem)
    return n if len(n)>=8 and n not in ('auditreport','securityaudit','securityreport','finalreport','auditfinal','smartcontractaudit','smartcontractsecurityaudit','audit','report') else None

def build():
    current=json.loads((OUT/'current_listings.json').read_text())
    known=collections.defaultdict(set); names=collections.defaultdict(set); repo_index={}
    for fid,r in current.items():
        for repo in r['repos']:
            if not repo.get('complete'):continue
            repo_index[(fid,repo['repo'].lower())]=repo
            for p in repo['paths']:
                if Path(p).suffix.lower() not in ('.pdf','.md','.html','.htm','.txt'):continue
                known[fid].add('github:'+repo['repo'].lower()+'/'+p)
                n=meaningful_name(Path(p).stem)
                if n:names[fid].add(n)
        for url in r['website_urls']:
            if not H['public_url'](url):continue
            known[fid].add(key(url));n=meaningful_name(Path(unquote(urlsplit(url).path)).stem)
            if n:names[fid].add(n)
        for item in r.get('listing_items',[]):
            if isinstance(item,str):url=item
            else:url=item.get('url') or item.get('report_url')
            if url:known[fid].add(key(url))
    for fid in SCOPE:
        for row in read_jsonl(ROOT/'data/collect'/fid/'reports.jsonl'):
            if row.get('public_url'):
                known[fid].add(key(row['public_url']));n=meaningful_name(Path(unquote(urlsplit(row['public_url']).path)).stem)
                if n:names[fid].add(n)
            n=meaningful_name(row.get('filename'))
            if n:names[fid].add(n)
    rows=[];superseded=[]
    for p in sorted((OUT/'_sources').glob('*sources.jsonl')):
        if p.name=='ecosystem_sources.jsonl' and (OUT/'_sources/defillama_bulk_sources.jsonl').exists() and (OUT/'_sources/l2beat_snapshot_sources.jsonl').exists():
            superseded.append({'file':str(p.relative_to(ROOT)),
                               'reason':'Optional partial detail scan superseded by complete bulk DeFiLlama and pinned L2BEAT snapshots.'})
            continue
        rows+=read_jsonl(p)
    unique={}; rejected=[]; source_counts=collections.Counter();firm_inputs=collections.defaultdict(collections.Counter)
    for row in rows:
        if not row.get('candidate_url') or not H['public_url'](row['candidate_url']):continue
        if row.get('source')=='dappscan' and len(row.get('source_record_id','').split('/'))!=4:
            rejected.append({'candidate_url':row['candidate_url'],'firm_id':row.get('firm_id'),
                             'source':'dappscan','reason':'nested client repository PDF; report author not evidenced by enclosing audit folder'})
            continue
        if Path(unquote(urlsplit(row['candidate_url']).path)).name.lower() in ('readme.md','license','license.md','license.txt','package.json','index.md'):
            continue
        if row.get('source')=='wayback' and urlsplit(row['candidate_url']).hostname=='github.com' and not git_parts(row['candidate_url']):
            rejected.append({'candidate_url':row['candidate_url'],'firm_id':row.get('firm_id'),'source':'wayback',
                             'reason':'GitHub history/tree page rather than report blob URL'})
            continue
        ok,reason=attributed(row)
        if not ok:
            rejected.append({'candidate_url':row['candidate_url'],'firm_id':row.get('firm_id'),
                             'source':row.get('source'),'reason':reason});continue
        d=row.get('date_hint')
        if not d:row['date_hint']=None;row['date_basis']='none'
        if d:
            try:
                if not re.fullmatch(r'20\d{2}(?:-\d{2}(?:-\d{2})?)?',d):raise ValueError('date format')
                dt.date.fromisoformat(d+'-01-01' if len(d)==4 else d+'-01' if len(d)==7 else d)
            except ValueError:
                row['notes']+=' Invalid source date hint omitted: '+str(d)+'.'
                row['date_hint']=None;row['date_basis']='none'
        fid=row['firm_id'];source_counts[row['source']]+=1
        firm_inputs[fid][row['source']]+=1
        # Merge branch/commit variants, retaining evidence from every source.
        k=(fid,key(row.get('original_publisher_url') or row['candidate_url']))
        evidence={'source':row['source'],'source_record_id':row.get('source_record_id'),
                  'candidate_url':row['candidate_url'],'attribution_basis':row['attribution_basis']}
        if k in unique:
            old=unique[k]
            if evidence not in old['evidence']:old['evidence'].append(evidence)
            old['sources']=sorted(set(old['sources']+[row['source']]))
            if row.get('wayback_url'):
                old['archive_evidence']={'wayback_url':row['wayback_url'],'source':row['source'],
                                         'evidence_url':row['attribution_basis']['evidence_url']}
            if row.get('date_hint') and not old.get('date_hint'):
                old.update(date_hint=row['date_hint'],date_basis=row['date_basis'])
        else:
            r=dict(row);r['candidate_url']=head_url(r['candidate_url'])
            r.update(evidence=[evidence],sources=[row['source']],still_live=None,sha256=None)
            r.setdefault('wayback_url',None)
            if row.get('wayback_url'):r['archive_evidence']={'wayback_url':row['wayback_url'],'source':row['source'],
                                                           'evidence_url':row['attribution_basis']['evidence_url']}
            unique[k]=r
    known_rows=[]; candidates=[]
    for (fid,k),r in sorted(unique.items()):
        if k in known[fid] or key(r['candidate_url']) in known[fid]:
            known_rows.append({'firm_id':fid,'candidate_url':r['candidate_url'],'sources':r['sources'],
                               'reason':'exact revision-normalized URL/path in current publisher inventory'})
            continue
        name=meaningful_name(Path(unquote(urlsplit(r['candidate_url']).path)).stem)
        if name and name in names[fid]:
            known_rows.append({'firm_id':fid,'candidate_url':r['candidate_url'],'sources':r['sources'],
                               'reason':'identical report basename in current publisher inventory; likely mirror or moved path'})
            continue
        g=git_parts(r.get('original_publisher_url') or r['candidate_url'])
        primary=repo_index.get((fid,(g[0]+'/'+g[1]).lower())) if g else None
        if primary:
            r['missing_status']='likely_missing'
            r['missing_basis']={'kind':'absent_from_complete_publisher_tree','evidence_url':primary['evidence_url'],
                                 'checked_utc':primary['checked_utc'],'path':g[3]}
        else:
            r['missing_status']='unresolved_listing'
            r['missing_basis']={'kind':'not_matched_to_current_inventory',
                                 'note':'Current website pagination or mirror identity is incomplete; absence does not prove removal.'}
        candidates.append(r)
    H['write_jsonl'](OUT/'known_listed.jsonl',known_rows)
    H['write_jsonl'](OUT/'attribution_rejected.jsonl',rejected)
    counts=collections.Counter(r['firm_id'] for r in candidates)
    for fid in SCOPE:
        frows=[r for r in candidates if r['firm_id']==fid]
        previous={key(r['candidate_url']):r for r in read_jsonl(OUT/fid/'candidates.jsonl')}
        for r in frows:
            prior=previous.get(key(r['candidate_url']))
            if prior and prior.get('head_check',{}).get('url')==r['candidate_url']:
                for field in ('head_check','still_live','wayback_url','wayback_check','original_head_check',
                              'sha256','local_path','archive_status'):
                    if field in prior:r[field]=prior[field]
                archived=r.get('archive_evidence',{})
                capture=re.search(r'/web/(\d{14})/',archived.get('wayback_url',''))
                if r['still_live'] is False and capture:
                    r['wayback_url']=archived['wayback_url'];r['wayback_check']={
                        'capture_timestamp':capture[1],'status':200,'evidence_url':archived.get('evidence_url'),
                        'basis':'previously captured status-200 CDX response'}
                    r['archive_status']='dead_but_archived'
                if r['still_live'] is False and url_firm(r.get('original_publisher_url') or r['candidate_url'])==fid:
                    origin=r.get('original_head_check') or r['head_check']
                    if live_status(origin) is False:
                        r['missing_status']='likely_missing'
                        if r['missing_basis']['kind']!='absent_from_complete_publisher_tree':
                            r['missing_basis']={'kind':'publisher_report_url_dead','status':origin['status'],
                                                'evidence_url':origin['url'],'checked_utc':origin['checked_utc']}
        H['write_jsonl'](OUT/fid/'candidates.jsonl',frows)
        H['write_json'](OUT/fid/'status.json',{'firm_id':fid,'candidate_count':len(frows),
            'empty_reason':None if frows else ('All verified aggregate report URLs matched the current publisher inventory.' if firm_inputs[fid] else
                'No report URL with a verified scoped firm attribution was found in surveyed aggregates; unavailable archive history remains a coverage gap.'),
            'verified_input_rows_by_source':dict(firm_inputs[fid]),
            'source_counts':dict(collections.Counter(s for r in frows for s in r['sources'])),
            'listing_snapshot':'data/discovery/current_listings.json'})
    H['write_json'](OUT/'build_summary.json',{'input_rows':len(rows),'attributed_source_rows':dict(source_counts),
        'unique_attributed_urls':len(unique),'excluded_known_listed':len(known_rows),'attribution_rejected':len(rejected),
        'candidates':len(candidates),'firms':len(SCOPE),'firms_with_candidates':len(counts),'superseded_inputs':superseded})
    print(json.dumps({'input_rows':len(rows),'unique':len(unique),'listed':len(known_rows),'rejected':len(rejected),
                      'candidates':len(candidates),'top_hosts':collections.Counter(urlsplit(r['candidate_url']).hostname for r in candidates).most_common(10)}))

def live_status(meta):
    status=meta.get('status',0)
    if 200<=status<300:return True
    if status in (404,410):return False
    return None

def archive_lookup(url):
    query='https://web.archive.org/cdx/search/cdx?url='+quote(url,safe='')+'&output=json&filter=statuscode:200&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit=-1'
    m,d=H['get_json'](query,timeout=12,limit=2_000_000)
    result={'cdx_url':query,'status':m['status'],'checked_utc':m['checked_utc'],'error':m.get('error')}
    if isinstance(d,list) and len(d)>1 and len(d[1])>=2:
        result['capture_timestamp']=d[1][0]
        return 'https://web.archive.org/web/'+d[1][0]+'/'+d[1][1],result
    return None,result

def check_one(r):
    meta,_=H['fetch'](r['candidate_url'],method='HEAD',timeout=12)
    r['head_check']={**meta,'method':'HEAD'};r['still_live']=live_status(meta)
    original=r.get('original_publisher_url')
    if original and key(original)!=key(r['candidate_url']):
        om,_=H['fetch'](original,method='HEAD',timeout=12)
        r['original_head_check']={**om,'method':'HEAD'}
    if r['still_live'] is False:
        archived=r.get('archive_evidence',{})
        capture=re.search(r'/web/(\d{14})/',archived.get('wayback_url',''))
        if capture:
            r['wayback_url']=archived['wayback_url'];r['wayback_check']={
                'capture_timestamp':capture[1],'status':200,'evidence_url':archived.get('evidence_url'),
                'basis':'previously captured status-200 CDX response'}
        else:r['wayback_url'],r['wayback_check']=archive_lookup(original or r['candidate_url'])
        r['archive_status']='dead_but_archived' if r['wayback_url'] else 'dead_archive_unverified'
        if url_firm(original or r['candidate_url'])==r['firm_id']:
            origin=r.get('original_head_check',meta)
            if live_status(origin) is False:
                r['missing_status']='likely_missing'
                if r.get('missing_basis',{}).get('kind')!='absent_from_complete_publisher_tree':
                    r['missing_basis']={'kind':'publisher_report_url_dead','status':origin['status'],
                                        'evidence_url':origin['url'],'checked_utc':origin['checked_utc']}
    # Preserve the full origin HEAD outcome without treating 403/robots as dead.
    return r

def check(workers):
    allrows=[]
    for fid in SCOPE:allrows+=read_jsonl(OUT/fid/'candidates.jsonl')
    pending=[r for r in allrows if not r.get('head_check')]
    completed={}
    # Main thread writes checkpoints; worker threads only write URL-specific HTTP cache keys.
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures={pool.submit(check_one,r):r for r in pending}
        for index,f in enumerate(concurrent.futures.as_completed(futures),1):
            row=f.result();completed[(row['firm_id'],key(row['candidate_url']))]=row
            if index%25==0 or index==len(pending):
                for fid in {r['firm_id'] for r in completed.values()}:
                    rows=read_jsonl(OUT/fid/'candidates.jsonl')
                    H['write_jsonl'](OUT/fid/'candidates.jsonl',[completed.get((fid,key(r['candidate_url'])),r) for r in rows])
                print(json.dumps({'checked_this_run':index,'pending_at_start':len(pending),
                                  'live':sum(r['still_live'] is True for r in completed.values()),
                                  'dead':sum(r['still_live'] is False for r in completed.values())}),flush=True)
    report()

def report():
    allrows=[];perfirm={};bysource=collections.Counter();errors=collections.Counter()
    for fid in SCOPE:
        rs=read_jsonl(OUT/fid/'candidates.jsonl');allrows+=rs
        perfirm[fid]={'candidates':len(rs),'likely_missing':sum(r['missing_status']=='likely_missing' for r in rs),
                      'dead_but_archived':sum(r.get('archive_status')=='dead_but_archived' for r in rs),
                      'live':sum(r['still_live'] is True for r in rs),'dead':sum(r['still_live'] is False for r in rs),
                      'unknown':sum(r['still_live'] is None for r in rs),'head_attempted':sum(bool(r.get('head_check')) for r in rs),
                      'by_source':dict(collections.Counter(s for r in rs for s in r['sources']))}
        for r in rs:
            bysource.update(r['sources'])
            if r.get('head_check',{}).get('error'):errors[r['head_check']['error']]+=1
    totals={k:sum(r[k] for r in perfirm.values()) for k in ('candidates','likely_missing','dead_but_archived','live','dead','unknown','head_attempted')}
    summary={'totals':totals,'firms':len(SCOPE),'firms_with_candidates':sum(r['candidates']>0 for r in perfirm.values()),
             'by_source':dict(bysource),'head_errors':dict(errors),'per_firm':perfirm}
    H['write_json'](OUT/'summary.json',summary)
    sources=sorted(set(bysource)|{'gcf_catalog','forge','dappscan','defillama','l2beat','wayback'});build=json.loads((OUT/'build_summary.json').read_text())
    lines=['# Phase 2d — aggregate discovery', '',
           'Generated by `python3 -I scripts/discovery/discover.py report`. Source access date: 2026-10-20.', '',
           f"Scope: **{len(SCOPE)} publishers**, excluding CertiK. **{totals['candidates']:,} candidate URLs** remain after **{build['excluded_known_listed']:,}** known current URLs/mirrors are excluded. **{totals['likely_missing']:,}** are likely missing; **{totals['dead_but_archived']:,}** are confirmed dead but have an evidenced archive capture.", '',
           f"HEAD attempts: **{totals['head_attempted']:,}/{totals['candidates']:,}**; live **{totals['live']:,}**, dead (404/410) **{totals['dead']:,}**, unknown **{totals['unknown']:,}**. Robots refusals, rate limits, access denials and network failures remain unknown. A successful HEAD proves URL reachability, not PDF validity.", '',
           '## Interpretation and reproduction','',
           '- Rows are report URL leads, not deduplicated engagements. Revisions on the same GitHub path collapse; cross-mirror copies can remain until Phase 3 hashes originals.',
           '- Every included row has a verified attribution basis: an explicit author directory/field, a named report filename, or a catalog author corroborated by publisher URL identity. Aggregator ownership is never authorship.',
           '- `likely_missing` means the historical publisher path is absent from a complete same-day publisher tree, or a publisher-origin report URL returned 404/410. A failed third-party mirror does not prove publisher removal. `unresolved_listing` means pagination or mirror identity prevents a removal claim.',
           '- Filename attribution matches complete author tokens. Generic words such as security-audit and preliminary-audit never become yAudit/Electisec attribution.',
           '- Current inventories are same-day captured registry trees/landing pages in `data/discovery/current_listings.json`. Identical filenames are treated as likely listed mirrors and excluded; this can undercount removed revisions.',
           '- `sha256` stays null unless the actual original is cached under `local-cache/originals/`; inherited catalog hashes are not promoted to verified originals. This pass downloads no report bodies.',
           '- FORGE contract-source URLs and JSON findings files are excluded from report URLs. Named input-PDF leads lacking a report URL remain in `_sources/forge_unresolved.jsonl`.',
           '- Source memberships overlap. Summing source columns can exceed the candidate total. Empty candidates files have a reason in the adjacent `status.json`.', '',
           'Reproduce from the repository root: run `catalog_sources.py` (Python with pyarrow), `repository_sources.py`, `defillama_bulk.py`, `l2beat_snapshot.py`, `wayback_sources.py`, and `wayback_prefix.py` in `scripts/discovery/`; then `current_listings.py`, `discover.py build`, `discover.py check`, `discover.py report`, and `validate.py`. Use `python3 -I` for the standard-library scripts. Check resumes cached HTTP observations; validation is offline. `ecosystem_sources.py` supplies shared parsers and an optional protocol-detail scan; the bulk DeFiLlama snapshot is the authoritative complete link enumeration.', '',
           '## Candidates by publisher and source','',
           '| Firm | Candidates | '+' | '.join(sources)+' | Likely missing | Dead but archived | HEAD unknown |',
           '|---|---:|'+'---:|'*(len(sources)+3)]
    for fid,r in perfirm.items():
        lines.append('| '+fid+' | '+str(r['candidates'])+' | '+' | '.join(str(r['by_source'].get(s,0)) for s in sources)+
                     ' | '+str(r['likely_missing'])+' | '+str(r['dead_but_archived'])+' | '+str(r['unknown'])+' |')
    lines+=['','## Top 20 publishers by likely missing report URLs','','| Rank | Firm | Likely missing | Other unresolved candidates |','|---:|---|---:|---:|']
    ranking=sorted(perfirm,key=lambda f:(-perfirm[f]['likely_missing'],-perfirm[f]['candidates'],f))[:20]
    for n,fid in enumerate(ranking,1):
        r=perfirm[fid];lines.append(f"| {n} | {fid} | {r['likely_missing']} | {r['candidates']-r['likely_missing']} |")
    lines+=['','## Source coverage and gaps','']
    for p in sorted((OUT/'_sources').glob('*.status.json')):
        lines+=['- ['+p.name+'](../../'+str(p.relative_to(ROOT))+'): source revision, enumeration, failures and remaining coverage gaps.']
    wp=OUT/'_sources/wayback_sources.status.json'
    if wp.exists():
        w=json.loads(wp.read_text())
        lines+=['',f"Wayback path census: {w.get('queried_firms',w.get('firms_with_completed_query',0))}/{len(SCOPE)} firms, {w.get('query_count',w.get('cached_completed_query_count',0))} queries, {w.get('failed_queries',w.get('failed_cached_queries',0))} failures, {w.get('truncated_queries',w.get('truncated_cached_queries',0))} saturated responses. CDX access failures leave history unobserved. Saturated responses are lower bounds; no exhaustive historical coverage claim is made."]
        failed=collections.defaultdict(list)
        for a in w.get('attempts',[]):
            if a.get('error') or a.get('http_status') not in (200,206):failed[a['firm_id']].append(str(a.get('http_status',0)))
        if failed:
            lines+=['','| Firm with archive gap | CDX failure statuses |','|---|---|']
            for fid,vals in sorted(failed.items()):lines.append('| '+fid+' | '+', '.join(vals)+' |')
    bulk=OUT/'_sources/defillama_bulk_sources.status.json'
    if bulk.exists():
        b=json.loads(bulk.read_text());lines+=['',f"DeFiLlama bulk metadata: {b['config_protocols']:,} protocols plus {b.get('additional_entities_with_audit_links',0):,} other entities with audit links; {b['audit_links_examined']:,} links examined; {b['source_rows']:,} attributable individual report URLs before current-inventory subtraction. Every protocol ID in the captured `/protocols` listing is represented in `/config`. Directories and un-attributed links are excluded."]
    lines+=['','## Files written','',
            '- Scripts: `scripts/discovery/*.py`.',
            '- Discovery metadata: `data/discovery/{firm_id}/candidates.jsonl` and `status.json` for every scoped publisher; `data/discovery/_sources/*`; `current_listings.json`, `known_listed.jsonl`, `attribution_rejected.jsonl`, `build_summary.json`, `summary.json`, `validation.json`.',
            '- This document: `docs/collect/discovery.md`.',
            '- Local HTTP cache: `local-cache/discovery-cache/` (gitignored). No files under `data/collect/` are written.','']
    (ROOT/'docs/collect/discovery.md').write_text('\n'.join(lines))
    print(json.dumps(totals,sort_keys=True))

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('build','check','report'));p.add_argument('--workers',type=int,default=12);a=p.parse_args()
    if a.mode=='build':build()
    elif a.mode=='check':check(a.workers)
    else:report()

if __name__=='__main__':main()
