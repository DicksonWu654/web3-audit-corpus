#!/usr/bin/env python3
"""Recover discovery originals or evidence-backed engagement dates.

Append-only collector records; recovery receipt per candidate makes restarts
idempotent. Never mirrors unapproved aggregator or derived FORGE/DAppSCAN source datasets.
Engagement date modes only write date-recovery evidence and override proposals;
they never publish collector rows, rebuild the DB, or edit the release.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import fcntl
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re
import sys
import threading
from urllib.parse import quote, unquote, urlsplit, urlencode

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/build'))
sys.path.insert(0,str(ROOT/'scripts/collect'))
from metadata_rules import atomic, canonical
from web_common import Client, now

LOCAL=threading.local()

# This mode deliberately does not call publish() or change collector records.
DATE_OUT = ROOT/'data/phase3/date_recovery/engagement_years'


def engagement_inputs():
    import csv
    import duckdb
    with (ROOT/'release/engagements.csv').open() as f:
        engagements = list(csv.DictReader(f))
    with (ROOT/'release/reports.csv').open() as f:
        reports = {r['report_id']: r for r in csv.DictReader(f)}
    con = duckdb.connect(str(ROOT/'data/corpus.duckdb'), read_only=True)
    cur = con.execute('SELECT * FROM documents WHERE NOT is_seed')
    names = [d[0] for d in cur.description]
    documents = [dict(zip(names, r)) for r in cur.fetchall()]
    links = con.execute('SELECT engagement_id,document_id FROM engagement_documents').fetchall()
    cur = con.execute('SELECT * FROM date_claims')
    names = [d[0] for d in cur.description]
    claims = [dict(zip(names, r)) for r in cur.fetchall()]
    con.close()
    docs = {d['document_id']:d for d in documents}
    by_engagement = {}
    for eid, did in links:
        if did in docs:
            by_engagement.setdefault(eid, []).append(docs[did])
    by_doc = {}
    for c in claims:
        if isinstance(c['evidence'], str): c['evidence'] = json.loads(c['evidence'])
        by_doc.setdefault(c['document_id'] or c['engagement_id'], []).append(c)
    return engagements, reports, by_engagement, by_doc


@lru_cache(maxsize=64)
def report_text(digest):
    for source in ['date-text', 'fulltext', 'text']:
        p = ROOT/'local-cache'/source/(digest+'.txt')
        if p.exists():
            return p.read_text(), str(p.relative_to(ROOT))
    return '', None


def engagement_inspection():
    engagements, reports, documents, claims = engagement_inputs()
    targets = [e for e in engagements if not e['audit_year'] or e['audit_year_conflict']=='true']
    rows=[]
    for e in targets:
        texts=[]; seen=set()
        for rid in json.loads(e['report_ids']):
            r=reports[rid]; digest=r['sha256']
            if not digest or digest in seen: continue
            seen.add(digest)
            text,path=report_text(digest)
            signals=[]
            for match in re.finditer(r'(?im)^.*(?:\b20\d{2}\b|\bdate\b|\bcommit\b|\bversion\b|\bend\b|\bcompleted?\b).*$',text):
                signals.append(dict(offset=match.start(),page=text[:match.start()].count('\f')+1,text=match[0][:500]))
            texts.append(dict(report_id=rid,url=r['permalink'] or r['url'],text_path=path,
                              opening=text[:4500],signals=signals[:100]))
        ds=documents.get(e['engagement_id'],[])
        cs=[c for d in ds for c in claims.get(d['document_id'],[])]+claims.get(e['engagement_id'],[])
        rows.append(dict(engagement=e,reports=texts,
                         documents=[{k:d[k] for k in ['document_id','sha256','public_url','listing_url','filename','provenance']} for d in ds],
                         claims=cs))
    summary=dict(engagements=len(engagements),missing=sum(not e['audit_year'] for e in engagements),
                 missing_pct=round(100*sum(not e['audit_year'] for e in engagements)/len(engagements),4),
                 conflicts=sum(e['audit_year_conflict']=='true' for e in engagements),
                 missing_by_firm=dict(Counter(e['firm_id'] for e in engagements if not e['audit_year']).most_common()),
                 input_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'release/engagements.csv',ROOT/'release/reports.csv']})
    atomic(DATE_OUT/'baseline.json',json.dumps(summary,indent=2)+'\n')
    atomic(DATE_OUT/'inspection.json',json.dumps(rows,indent=2,default=str)+'\n')
    print(canonical(summary))


def date_evidence(text, path, digest, start, end, url):
    return dict(kind='report_text',report_sha256=digest,source_url=url,text_path=path,
                text_sha256=hashlib.sha256(text.encode()).hexdigest(),text_start=start,text_end=end,
                page=text[:start].count('\f')+1,quote=text[start:end])


def date_candidates():
    """Produce review proposals; a date-looking string alone never authorizes an override."""
    from metadata_rules import DATE, parse_date
    inspections=json.loads((DATE_OUT/'inspection.json').read_text())
    rows=[]
    for item in inspections:
        e=item['engagement']; candidates=[]
        for r in item['reports']+companion_reports(item):
            digest=r['report_id']; text,path=report_text(digest)
            # Keep full sentence context on prose, and nearby labels on tables.
            for m in DATE.finditer(text):
                value,precision=parse_date(m[0])
                if not value: continue
                start=max(text.rfind('\n',0,m.start())+1,m.start()-250)
                end=text.find('\n',m.end())
                if end<0:end=len(text)
                end=min(end,m.end()+400)
                if end-start<100:
                    start=max(0,text.rfind('\n',0,max(0,start-1))+1)
                evidence=date_evidence(text,path,digest,start,end,r['url'])
                if r.get('association'):
                    evidence['association']=r['association']
                    evidence['associated_report_ids']=json.loads(e['report_ids'])
                candidates.append(dict(date_value=value,precision=precision,evidence=evidence))
        rows.append(dict(engagement_id=e['engagement_id'],firm_id=e['firm_id'],project=e['project'],
                         conflict=e['audit_year_conflict']=='true',candidates=candidates))
    atomic(DATE_OUT/'text_candidates.jsonl',''.join(canonical(r)+'\n' for r in rows))
    print(canonical(dict(engagements=len(rows),with_text_candidates=sum(bool(r['candidates']) for r in rows))))


def companion_reports(item):
    """Same publisher, exact dated basename, different rendition; evidence only, no grouping edits."""
    firm=item['engagement']['firm_id']
    path=ROOT/'data/collect'/firm/'reports.jsonl'
    if not path.exists():return []
    expected=set()
    for r in item['reports']:
        loc=github_location(r['url'])
        if not loc or not loc[2].endswith('.md'):continue
        repo,ref,name=loc
        name=name[:-3]+'.pdf'
        name=name.replace('/md/','/pdf/').replace('reports_md/','reports/')
        expected.add((repo.casefold(),name.casefold()))
    if not expected:return []
    hashes={r['report_id'] for r in item['reports']}
    companions=[]
    for r in collection_rows(firm):
        if r.get('sha256') in hashes or r.get('file_format')!='pdf':continue
        loc=github_location(r.get('public_url',''))
        name=loc[2] if loc else ''
        if not loc or (loc[0].casefold(),name.casefold()) not in expected:continue
        if not report_text(r['sha256'])[0]:continue
        companions.append(dict(report_id=r['sha256'],url=r['public_url'],association='same_publisher_exact_dated_path_pdf_rendition'))
    return companions


@lru_cache(maxsize=None)
def collection_rows(firm):
    path=ROOT/'data/collect'/firm/'reports.jsonl'
    return [json.loads(s) for s in path.read_text().splitlines()] if path.exists() else []


def publisher_listings(network=False):
    inspections=json.loads((DATE_OUT/'inspection.json').read_text())
    locations={}
    for item in inspections:
        for r in item['reports']:
            loc=github_location(r['url'])
            if loc:locations.setdefault((item['engagement']['firm_id'],loc[0],loc[1]),[]).append(loc[2])
    results=[]
    for (firm,repo,ref),paths in sorted(locations.items()):
        # Publisher root catalogs only. This cannot execute project code.
        url=f'https://raw.githubusercontent.com/{repo}/{ref}/README.md'
        try:
            receipt=saved_fetch(url,network)
            results.append(dict(firm_id=firm,repository=repo,ref=ref,url=url,
                                body_sha256=receipt['body_sha256'],retrieved_utc=receipt['retrieved_utc'],text=receipt['text']))
        except Exception as exc:results.append(dict(firm_id=firm,repository=repo,url=url,error=str(exc)))
        print(canonical(dict(firm_id=firm,repository=repo,error=results[-1].get('error'))),flush=True)
    atomic(DATE_OUT/'publisher_listings.jsonl',''.join(canonical(r)+'\n' for r in results))


def fetch_extra(url):
    receipt=saved_fetch(url,True)
    print(canonical(dict(url=url,bytes=len(receipt['text'].encode()),body_sha256=receipt['body_sha256'],
        receipt=str((DATE_OUT/'http'/(hashlib.sha256(url.encode()).hexdigest()+'.json')).relative_to(ROOT)))))


def listing_claims(item):
    from metadata_rules import parse_date
    firm=item['engagement']['firm_id']; results=[]
    saved=DATE_OUT/'publisher_listings.jsonl'
    listings=[json.loads(s) for s in saved.read_text().splitlines()] if saved.exists() else []
    locations=[github_location(r['url']) for r in item['reports']]
    for listing in listings:
        if listing['firm_id']!=firm or 'text' not in listing:continue
        for loc in locations:
            if not loc or loc[0]!=listing['repository']:continue
            target=loc[2]; stem=Path(target).stem
            for lineno,line in enumerate(listing['text'].splitlines(),1):
                decoded=unquote(line)
                # Match a full path, or an exact PDF rendition basename for MDs.
                if target not in decoded and not (target.endswith('.md') and re.search(re.escape(stem)+r'\.pdf(?:[)"\s]|$)',decoded)):
                    continue
                if not line.startswith('|'):continue
                cells=[c.strip() for c in line.strip('|').split('|')]
                index=1 # Sigma Prime and Certora Date column.
                if len(cells)<=index:continue
                value,precision=parse_date(cells[index])
                if not value:continue
                results.append(dict(date_value=value,precision=precision,role='publisher_review_date',basis='publisher_listing',
                    evidence=dict(kind='publisher_listing',source_url=listing['url'],line=lineno,quote=line,
                                  body_sha256=listing['body_sha256'],retrieved_utc=listing['retrieved_utc'],
                                  matched_path=target,matched_by='exact_path' if target in decoded else 'exact_pdf_rendition_basename')))
    return results


def automatic_report_claim(item, candidates):
    """Narrow publisher-template rules, scoped to dated cover/period labels."""
    firm=item['engagement']['firm_id']; selected=[]
    for c in candidates:
        evidence=c['evidence'];payload=evidence['quote']
        if not evidence['source_url'].lower().endswith('.pdf'):continue
        if firm=='pashov-audit-group' and evidence['page']==1 and 'Conducted by:' in payload:
            selected.append(dict(c,role='audit_completion' if len({v['date_value'] for v in candidates if v['evidence']['quote']==payload})>1 else 'report_issue',
                                 basis='report_text',rationale='Dated publisher PDF cover matched to the exact Markdown rendition path; take the end of a stated range, or single report dateline.'))
    if not selected:return None
    years={c['date_value'][:4] for c in selected}
    if len(years)>1:
        # A real cross-year cover period is allowed only within one shared quote.
        if len({c['evidence']['quote'] for c in selected})!=1:return None
    chosen=max(selected,key=lambda c:c['date_value'])
    if chosen['evidence']['report_sha256'] not in json.loads(item['engagement']['report_ids']):
        chosen['evidence']['association']='same_publisher_exact_dated_path_pdf_rendition'
        chosen['evidence']['associated_report_ids']=json.loads(item['engagement']['report_ids'])
    return chosen


def reviewed_claim(item, decision, candidates):
    fold=lambda s:re.sub(r'[\s\u200b\u00ad]+',' ',s.casefold()).strip()
    value=decision['date_value']; needle=fold(decision['needle'])
    options=[]
    for c in candidates:
        if c['date_value'].startswith(value) or value.startswith(c['date_value']):
            if needle in fold(c['evidence']['quote']):options.append(c)
    for c in item['claims']:
        a=c.get('evidence',{}).get('assertion') or {}
        if c['date_value']!=value or not isinstance(a,dict):continue
        payload=a.get('evidence')
        if not isinstance(payload,str) or needle not in fold(payload):continue
        for r in item['reports']:
            if c.get('document_id') not in [d['document_id'] for d in item['documents'] if d['sha256']==r['report_id']]:continue
            paths=[a.get('text_snapshot'),str(Path(a.get('text_source','local-cache/text'))/(r['report_id']+'.txt'))]
            for path in paths:
                if not path or not (ROOT/path).exists():continue
                text=(ROOT/path).read_text();start=text.find(payload)
                if start>=0:
                    options.append(dict(date_value=value,evidence=date_evidence(text,path,r['report_id'],start,start+len(payload),r['url'])))
                    break
    if not options:
        for r in item['reports']+companion_reports(item):
            text,path=report_text(r['report_id'])
            match=re.search(r'[\s\u200b\u00ad]+'.join(re.escape(s) for s in needle.split()),text,re.I)
            if not match:continue
            index=match.start()
            start=text.rfind('\n',0,index)+1
            end=min(len(text),index+len(decision['needle'])+350)
            evidence=date_evidence(text,path,r['report_id'],start,end,r['url'])
            if value[:4] in evidence['quote']:
                options.append(dict(date_value=value,evidence=evidence))
    if not options:raise ValueError('Reviewed evidence no longer matches: '+str(decision))
    chosen=min(options,key=lambda c:len(c['evidence']['quote']))
    return dict(date_value=value,precision={4:'year',7:'month',10:'day'}[len(value)],role=decision['role'],
                basis='report_text',evidence=chosen['evidence'],rationale=decision['rationale'])


def finalize_dates():
    """Offline evidence ledger + integration proposals, never edits release/DB/collector inputs."""
    import csv
    import io
    from metadata_rules import parse_date
    inspections=json.loads((DATE_OUT/'inspection.json').read_text())
    baseline=json.loads((DATE_OUT/'baseline.json').read_text())
    for filename,digest in baseline['input_sha256'].items():
        if hashlib.sha256((ROOT/filename).read_bytes()).hexdigest()!=digest:
            raise ValueError('Release input changed since snapshot: '+filename)
    decisions=[json.loads(s) for s in (DATE_OUT/'reviewed_dates.jsonl').read_text().splitlines() if s.strip()]
    targets={i['engagement']['engagement_id']:i for i in inspections}
    reviewed={}
    for d in decisions:
        ids=[eid for eid in targets if eid.removeprefix('engagement:').startswith(d['engagement_prefix'])]
        if len(ids)!=1:raise ValueError('Nonunique/absent reviewed prefix: '+d['engagement_prefix'])
        if ids[0] in reviewed:raise ValueError('Duplicate reviewed decision: '+ids[0])
        reviewed[ids[0]]=d
    text_rows={r['engagement_id']:r['candidates'] for r in map(json.loads,(DATE_OUT/'text_candidates.jsonl').read_text().splitlines())}
    history_path=DATE_OUT/'histories.jsonl'
    histories={r['report_id']:r for r in map(json.loads,history_path.read_text().splitlines())} if history_path.exists() else {}
    contests=[]
    for path in sorted((ROOT/'data/collect').glob('*/contests.jsonl')):
        if path.parent.name=='certik':continue
        for lineno,line in enumerate(path.read_text().splitlines(),1):
            c=json.loads(line)
            if c.get('end_utc'):
                contests.append((c,str(path.relative_to(ROOT)),lineno))
    outcomes=[];overrides=[];unresolved=[];conflicts=[]
    for item in inspections:
        e=item['engagement'];eid=e['engagement_id']; firm=e['firm_id']
        if firm=='certik':raise ValueError('Out-of-scope publisher')
        row=dict(engagement_id=eid,firm_id=firm,project=e['project'],baseline_audit_year=e['audit_year'] or None,
                 baseline_conflict=e['audit_year_conflict']=='true',report_ids=json.loads(e['report_ids']),attempts=[])
        selected=None; reason=None
        listings=listing_claims(item)
        row['attempts'].append(dict(stage='report_text',candidates=len(text_rows[eid]),reviewed=eid in reviewed))
        row['attempts'].append(dict(stage='publisher_listing',claims=listings))
        if eid in reviewed:
            selected=reviewed_claim(item,reviewed[eid],text_rows[eid])
            if firm=='zellic' and row['baseline_conflict']:
                agreeing=[c for c in listings if c['date_value'][:4]==selected['date_value'][:4]]
                if not agreeing:raise ValueError('Zellic year correction lacks publisher-listing corroboration: '+eid)
                selected['evidence']['corroborating_listing']=agreeing
        index_report=firm=='oak-security' and any(re.search(r'/(?:_tech_stacks/[^/]+|SUMMARY|README)\.md$',r['url'],re.I) for r in item['reports'])
        training=firm=='electisec' and any(re.search(r'/block_\d+/week_\d+/(?:README|[^/]+)\.md$',r['url'],re.I) for r in item['reports'])
        # Source contradictions must be adjudicated, never overwritten by upload dates.
        if row['baseline_conflict'] and not selected:
            reason='conflicting_publisher_dates_or_multiple_review_periods_require_adjudication'
        elif index_report:
            selected=None;reason='publisher_index_of_multiple_reports_no_single_engagement_date'
        elif training and not selected:
            reason='fellowship_training_or_multi_audit_notes_no_single_completion_date'
        if not selected and not reason:
            selected=automatic_report_claim(item,text_rows[eid])
        if not selected and not reason and listings:
            years={c['date_value'][:4] for c in listings}
            if len(years)==1:
                selected=max(listings,key=lambda c:c['date_value'])
                selected['rationale']='Exact report link in the publisher catalog; retain the Date column semantics.'
            else:reason='publisher_listing_has_multiple_years_for_report'
        # Existing listing claims are retained as publication-year proxies, not completion dates.
        if not selected and not reason:
            candidates=[c for c in item['claims'] if c['date_value'] and c['role']=='publication' and c['basis']=='listing'
                        and c['authority'] in {'publisher','collector_hint'}]
            years={c['date_value'][:4] for c in candidates}
            if len(years)==1:
                c=max(candidates,key=lambda c:c['date_value'])
                source=next((d for d in item['documents'] if d['document_id']==c['document_id']),{})
                selected=dict(date_value=c['date_value'][:4],precision='year',role='publication_year_proxy',basis='publisher_listing_publication',
                    rationale='Publisher listing publication year used only as an explicitly inferred audit-year proxy; completion remains unknown.',
                    evidence=dict(kind='retained_listing_claim',source_url=source.get('listing_url') or source.get('public_url'),
                                  claim=c,document_id=source.get('document_id'),provenance=json.loads(source.get('provenance') or '{}')))
        h=[histories[r['report_id']] for r in item['reports'] if r['report_id'] in histories]
        row['attempts'].append(dict(stage='github_report_history',results=h))
        if not selected and not reason and firm=='pashov-audit-group':
            expected_repo='pashov/audits'
            named=[]
            for r in item['reports']:
                loc=github_location(r['url'])
                if not loc or loc[0].casefold()!=expected_repo:continue
                filename=Path(loc[2]).name
                match=re.search(r'(?<!\d)(20\d{2}-\d{2}-\d{2})(?!\d)',filename)
                if match and parse_date(match[1])[0]:named.append((match[1],r,filename))
            if len({n[0][:4] for n in named})==1:
                value,r,filename=max(named,key=lambda n:n[0])
                selected=dict(date_value=value[:4],precision='year',role='publisher_filename_year',basis='publisher_filename',
                    rationale='Explicit ISO date in publisher-controlled report basename supplies an inferred year only; completion remains unknown.',
                    evidence=dict(kind='publisher_filename',source_url=r['url'],quote=filename,report_sha256=r['report_id'],raw_date=value))
        if not selected and not reason:
            dates=[r['claim'] for r in h if r.get('claim')]
            if dates:
                c=min(dates,key=lambda c:c['date_value'])
                # Reject clear bulk archival additions contradicted by publisher year-labelled paths.
                path_years={y for r in item['reports'] for y in re.findall(r'(?<!\d)(20\d{2})(?!\d)',unquote(urlsplit(r['url']).path))}
                if path_years and c['date_value'][:4] not in path_years:
                    reason='github_upload_is_later_archival_import_not_audit_year'
                else:
                    selected=dict(c,date_value=c['date_value'][:4],precision='year',role='publication_year_proxy',
                        rationale='Verified commit adding the report (following renames); publication-year proxy only, completion remains unknown.')
        if not selected and not reason:
            report_hashes={r['report_id'] for r in item['reports']}
            matches=[(c,p,n) for c,p,n in contests if c.get('sha256') in report_hashes]
            dates={c['end_utc'][:10] for c,p,n in matches}
            if len(dates)==1:
                c,p,n=matches[0];value=c['end_utc'][:10]
                selected=dict(date_value=value,precision='day',role='audit_completion',basis='contest_end',
                    rationale='Official contest endpoint associated by exact report SHA256.',
                    evidence=dict(kind='official_contest',source_url=c.get('report_url'),source_file=p,line=n,contest=c))
        if selected:
            value=selected['date_value']
            if parse_date(value)!=(value,selected['precision']):raise ValueError('Invalid normalized selected date: '+eid)
            row.update(status='recovered',selected=selected,audit_year=int(value[:4]),conflict_resolved=row['baseline_conflict'])
            bounds=selected['role'] in {'audit_completion','report_issue'}
            overrides.append(dict(engagement_id=eid,firm_id=firm,report_ids=row['report_ids'],audit_year=int(value[:4]),
                date_value=value if bounds else None,date_precision=selected['precision'] if bounds else 'year',
                audit_date_basis=selected['basis']+':'+selected['role'],year_inferred=selected['role'] in {'publication_year_proxy','scope_commit_year','publisher_filename_year'},
                replace_conflicting_claim_selection=row['baseline_conflict'],original_conflict_retained=row['baseline_conflict'],
                rationale=selected['rationale'],evidence=selected['evidence']))
        else:
            if not reason:
                if any(re.search(r'HTTP (?:403|429)',r.get('error','')) for r in h):reason='github_api_access_limited'
                elif not h and any(github_location(r['url']) for r in item['reports']):reason='report_or_listing_undated_history_not_completed_after_api_access_limit'
                else:reason='no_explicit_completion_or_issue_year_in_available_public_evidence'
            row.update(status='undated',reason=reason)
            unresolved.append(dict(engagement_id=eid,firm_id=firm,project=e['project'],reason=reason,
                report_urls=[r['url'] for r in item['reports']],history_errors=[r['error'] for r in h if r.get('error')],
                eligible_claims=[c for c in item['claims'] if c['eligible_for_audit_year']]))
        if row['baseline_conflict']:
            conflicts.append(dict(engagement_id=eid,firm_id=firm,project=e['project'],resolved=bool(selected),
                selection=selected,reason=reason,original_claims=[c for c in item['claims'] if c['eligible_for_audit_year']]))
        outcomes.append(row)
    summary=dict(baseline=baseline,dated_recovered=len(overrides),residual_undated=len(unresolved),
        residual_pct=round(100*len(unresolved)/baseline['engagements'],4),target_met=len(unresolved)/baseline['engagements']<=.05,
        conflicts_before=baseline['conflicts'],conflicts_resolved=sum(c['resolved'] for c in conflicts),
        conflicts_remaining=sum(not c['resolved'] for c in conflicts),
        by_basis=dict(Counter(o['audit_date_basis'] for o in overrides)),
        recovered_by_firm=dict(Counter(o['firm_id'] for o in overrides)),
        residual_by_firm=dict(Counter(o['firm_id'] for o in unresolved)),
        residual_by_reason=dict(Counter(o['reason'] for o in unresolved)),
        publication_year_proxies=sum(o['audit_date_basis'].endswith(':publication_year_proxy') for o in overrides),
        inferred_years=sum(o['year_inferred'] for o in overrides),
        explicit_years_recovered=sum(not o['year_inferred'] for o in overrides),
        strict_residual_without_proxies=len(unresolved)+sum(o['year_inferred'] for o in overrides),
        strict_residual_pct=round(100*(len(unresolved)+sum(o['year_inferred'] for o in overrides))/baseline['engagements'],4))
    for name,rows in [('evidence.jsonl',outcomes),('date_overrides.jsonl',overrides),
                      ('date_overrides_explicit.jsonl',[r for r in overrides if not r['year_inferred']]),
                      ('date_overrides_inferred.jsonl',[r for r in overrides if r['year_inferred']]),
                      ('residue.jsonl',unresolved),('conflicts.jsonl',conflicts)]:
        atomic(DATE_OUT/name,''.join(canonical(r)+'\n' for r in rows))
    atomic(DATE_OUT/'summary.json',json.dumps(summary,indent=2)+'\n')
    out=io.StringIO();writer=csv.DictWriter(out,fieldnames=['engagement_id','firm_id','project','reason','report_urls','history_errors'])
    writer.writeheader()
    for r in unresolved:writer.writerow({k:canonical(r[k]) if isinstance(r[k],list) else r[k] for k in writer.fieldnames})
    atomic(DATE_OUT/'residue.csv',out.getvalue())
    print(canonical(summary))


def compact_date_http():
    """Keep downloaded HTTP bodies in local cache; tracked receipts hold hashes and locators."""
    for path in sorted((DATE_OUT/'http').glob('*.json')):
        receipt=json.loads(path.read_text())
        if 'text' not in receipt:continue
        text=receipt.pop('text')
        payload=text.encode();digest=hashlib.sha256(payload).hexdigest()
        receipt['text_sha256']=digest
        body=ROOT/'local-cache/date-recovery-http'/(digest+'.txt')
        if not body.exists():atomic(body,text)
        elif body.read_bytes()!=payload:raise ValueError('HTTP body cache integrity failure')
        receipt['cache_body_path']=str(body.relative_to(ROOT))
        atomic(path,canonical(receipt)+'\n')


def validate_date_evidence():
    """Verify membership, evidence hashes, locators, scope and deterministic offline replay."""
    import contextlib
    import io
    from metadata_rules import parse_date
    names=['evidence.jsonl','date_overrides.jsonl','date_overrides_explicit.jsonl','date_overrides_inferred.jsonl',
           'residue.jsonl','conflicts.jsonl','summary.json','residue.csv']
    before={n:hashlib.sha256((DATE_OUT/n).read_bytes()).hexdigest() for n in names}
    with contextlib.redirect_stdout(io.StringIO()):finalize_dates()
    after={n:hashlib.sha256((DATE_OUT/n).read_bytes()).hexdigest() for n in names}
    errors=[];counts=Counter(); cache={}
    if before!=after:errors.append('Offline finalization changed outputs')
    inspection={r['engagement']['engagement_id']:r for r in json.loads((DATE_OUT/'inspection.json').read_text())}
    outcomes=[json.loads(s) for s in (DATE_OUT/'evidence.jsonl').read_text().splitlines()]
    if set(r['engagement_id'] for r in outcomes)!=set(inspection):errors.append('Missing target outcome')
    overrides=[json.loads(s) for s in (DATE_OUT/'date_overrides.jsonl').read_text().splitlines()]
    if len({r['engagement_id'] for r in overrides})!=len(overrides):errors.append('Duplicate override')
    def check_evidence(e,value):
        kind=e['kind'];counts[kind]+=1
        if kind=='report_text':
            path=e['text_path']
            if path not in cache:cache[path]=(ROOT/path).read_text()
            text=cache[path]
            if hashlib.sha256(text.encode()).hexdigest()!=e['text_sha256']:errors.append('Report text hash mismatch: '+path)
            if text[e['text_start']:e['text_end']]!=e['quote']:errors.append('Nonverbatim report evidence: '+path)
            if e['page']!=text[:e['text_start']].count('\f')+1:errors.append('Incorrect report page: '+path)
            if value[:4] not in e['quote']:errors.append('Year absent from quote: '+path)
            for c in e.get('corroborating_listing',[]):check_evidence(c['evidence'],c['date_value'])
        elif kind=='publisher_listing':
            receipt=saved_fetch(e['source_url'])
            if receipt['body_sha256']!=e['body_sha256']:errors.append('Listing body hash mismatch')
            if receipt['text'].splitlines()[e['line']-1]!=e['quote']:errors.append('Listing line mismatch')
        elif kind=='github_api':
            receipt=saved_fetch(e['api_url']); body=json.loads(receipt['text'])
            files=[f for f in body.get('files',[]) if f['filename']==e['path']]
            if receipt['body_sha256']!=e['body_sha256'] or body['sha']!=e['commit_sha']:errors.append('GitHub commit receipt mismatch')
            if not files or files[0]['status']!='added' or files[0]['sha']!=e['git_blob_sha']:errors.append('GitHub added-file proof mismatch')
            if body['commit']['committer']['date'][:4]!=value[:4]:errors.append('GitHub year mismatch')
            for q in e['history_queries']:
                page=saved_fetch(q['url'])
                if page['body_sha256']!=q['body_sha256']:errors.append('GitHub history page hash mismatch')
            for rename in e.get('rename_chain',[]):
                data=json.loads(saved_fetch(rename['api_url'])['text'])
                files=[f for f in data.get('files',[]) if f['filename']==rename['path']]
                if not files or files[0].get('previous_filename')!=rename['previous_filename']:errors.append('GitHub rename proof mismatch')
        elif kind=='retained_listing_claim':
            c=e['claim']
            if c['basis']!='listing' or c['role']!='publication' or c['date_value'][:4]!=value[:4]:errors.append('Invalid publication proxy claim')
            p=e['provenance'];retained=p.get('retained_record',{})
            source=ROOT/retained.get('source_file','missing')
            locator=re.fullmatch(r'line=(\d+)',retained.get('source_locator',''))
            if not source.is_file() or not locator:errors.append('Missing retained listing provenance')
            else:
                raw=json.loads(source.read_text().splitlines()[int(locator[1])-1])
                if raw!=p.get('source_row'):errors.append('Retained source row changed')
        elif kind=='publisher_filename':
            if e['raw_date'] not in e['quote'] or e['raw_date'][:4]!=value[:4]:errors.append('Publisher filename year mismatch')
        elif kind=='official_contest':
            if e['contest']['end_utc'][:10]!=value:errors.append('Contest end mismatch')
        else:errors.append('Unsupported evidence kind: '+kind)
    for r in outcomes:
        if r['firm_id']=='certik':errors.append('CertiK entered date recovery')
        if r['status']!='recovered':continue
        selected=r['selected'];value=selected['date_value']
        if parse_date(value)!=(value,selected['precision']):errors.append('Invalid date: '+value)
        if selected['evidence']['kind']=='report_text':
            allowed=set(r['report_ids'])|{s['report_id'] for s in companion_reports(inspection[r['engagement_id']])}
            if selected['evidence']['report_sha256'] not in allowed:errors.append('Evidence from unrelated rendition')
        check_evidence(selected['evidence'],value)
    for r in overrides:
        if r['year_inferred'] and r['date_value'] is not None:errors.append('Inferred year fabricated an exact date')
    result=dict(check='PASS' if not errors else 'FAIL',outcomes=len(outcomes),overrides=len(overrides),
                verified_evidence=dict(counts),deterministic_replay=before==after,errors=errors)
    atomic(DATE_OUT/'validation.json',json.dumps(result,indent=2)+'\n')
    write_date_handoff()
    print(canonical(result))
    return not errors


def write_date_handoff():
    summary=json.loads((DATE_OUT/'summary.json').read_text())
    lines=[
        'Date recovery handoff (release snapshot; projections until release operator integration)',
        '',
        f"Missing years: {summary['baseline']['missing']} -> {summary['residual_undated']} ({summary['residual_pct']}% of {summary['baseline']['engagements']} engagements).",
        f"Recovered: {summary['explicit_years_recovered']} explicit report/listing/engagement years + {summary['inferred_years']} labelled inferred years.",
        f"Strict coverage with every inferred year withheld: {summary['strict_residual_without_proxies']} undated ({summary['strict_residual_pct']}%).",
        f"Conflicts: {summary['conflicts_before']} before; {summary['conflicts_resolved']} selections resolved; {summary['conflicts_remaining']} unresolved.",
        '',
        'Why years were absent: Markdown renditions omit PDF cover dates; publisher catalog dates were excluded by the strict legacy document-text/contest-end eligibility gate; some date layouts were missed; genuine contradictory dates and multiple review periods produced nulls; technology indexes and fellowship notes do not have a single audit completion date.',
        '',
        'Integration contract:',
        '- date_overrides.jsonl is an engagement-level proposal keyed by engagement_id plus exact report_ids. Verify that the report identity still matches after grouping integration; do not carry an override by project name alone.',
        '- date_overrides_explicit.jsonl and date_overrides_inferred.jsonl split the combined proposal file so the release operator can import source-dated years while retaining inferred proposals separately.',
        '- Completion takes precedence over report issue. Report periods and exact catalog Audit End columns remain completion claims; generic publisher Date columns provide review years only.',
        '- year_inferred=true means publication-history, publication-listing, dated scope-commit or publisher-filename inference. Preserve this label, keep exact completion null, and do not relabel these as publisher completion assertions. The strict coverage figure with these proposals withheld is also reported.',
        '- replace_conflicting_claim_selection=true selects an adjudicated date; original_conflict_retained=true means keep every original contradictory claim and this adjudication rationale. conflicts.jsonl retains those originals. Do not simply append the chosen claim and leave the same preferred-role conflict in place.',
        '- Evidence from matching publisher PDF renditions can have a different report SHA from the engagement Markdown. association and associated_report_ids record that relationship; no engagement grouping was changed.',
        '- Residue is completely listed in residue.csv and residue.jsonl. Oak _tech_stacks files are indexes. The grouping owner should review their eligibility; this task did not exclude or regroup them.',
        '- GitHub history work stopped on HTTP 403 access/rate-limit responses. Missing history is not negative evidence. Histories follow report renames and verify status=added, rather than treating a shallow snapshot or repository reorganization date as first publication.',
        '- After public API access is available again, resume with: python3 -I scripts/collect/recover_dates.py --report-histories --network --retry. Cached failures are retried explicitly and the run stops again on any access/rate-limit response.',
        '- API/README response bodies remain in gitignored local-cache/date-recovery-http; http/*.json contains locators and hashes. Original reports remain in existing local CAS. No collector rows, release files or site code were changed by this task.',
        '',
        'release operator reruns:',
        '1. python3 -I scripts/collect/recover_dates.py --validate-dates',
        '2. Integrate the date override selection in the authoritative date resolver, respecting evidence roles, inferred flags and report identity. The existing strict SQL eligibility gate does not automatically import these new basis values.',
        '3. Run the normal DB/date evidence checks and analysis after all task owners integrate. Then rebuild make release and make site-data and their validators. These builds/analysis were intentionally not run here.',
        '',
        'Deterministic local regeneration: --text-candidates; --finalize-dates; --validate-dates. --engagement-inspection creates a new input snapshot from release + read-only DB; preserve this snapshot until integration. Network collection requires explicit --network and uses web_common.Client robots/pacing/User-Agent controls.',
        '',
        'Residual reasons (engagement counts):',
    ]
    lines += [f'{k}: {v}' for k,v in sorted(summary['residual_by_reason'].items())]
    atomic(DATE_OUT/'HANDOFF.txt','\n'.join(lines)+'\n')
    # Explicit artifacts plus body/cache receipts and command logs. Shared cache
    # entries are listed as touched-or-reused, since an existing cache hit is read-only.
    artifacts=['scripts/collect/recover_dates.py']+[str(p.relative_to(ROOT)) for p in sorted(DATE_OUT.rglob('*')) if p.is_file()]
    artifacts+=['data/phase3/date_recovery/engagement_years/files_written.txt','data/phase3/date_recovery/engagement_years/cache_files.txt']
    artifacts += [str(p.relative_to(ROOT)) for p in sorted((ROOT/'local-cache').glob('date-recovery-*.log'))]
    bodies=set();shared=set()
    for path in sorted((DATE_OUT/'http').glob('*.json')):
        r=json.loads(path.read_text())
        if r.get('cache_body_path'):bodies.add(r['cache_body_path'])
        key=hashlib.sha256(r['url'].encode()).hexdigest()
        for suffix in ['.json','.body']:
            p=ROOT/'local-cache/web-cache'/(key+suffix)
            if p.exists():shared.add(str(p.relative_to(ROOT)))
        u=urlsplit(r['url']);origin=f'{u.scheme}://{u.netloc}'
        key=hashlib.sha256((origin+'/robots.txt').encode()).hexdigest()
        p=ROOT/'local-cache/web-cache'/(key+'.robots.json')
        if p.exists():shared.add(str(p.relative_to(ROOT)))
        key=hashlib.sha256(u.netloc.lower().encode()).hexdigest()
        p=ROOT/'local-cache/web-host-locks'/key
        if p.exists():shared.add(str(p.relative_to(ROOT)))
    atomic(DATE_OUT/'files_written.txt','\n'.join(sorted(set(artifacts)|bodies))+'\n')
    atomic(DATE_OUT/'cache_files.txt','Shared HTTP cache and pacing files touched or reused by this task:\n'+'\n'.join(sorted(shared))+'\n')


def github_location(url):
    p=urlsplit(url); parts=unquote(p.path).strip('/').split('/')
    if p.hostname=='github.com' and len(parts)>=5 and parts[2] in {'blob','raw'}:
        return '/'.join(parts[:2]),parts[3],'/'.join(parts[4:])
    if p.hostname=='raw.githubusercontent.com' and len(parts)>=4:
        return '/'.join(parts[:2]),parts[2],'/'.join(parts[3:])
    return None


def saved_fetch(url, network=False, retry_errors=False):
    """Portable evidence copies with deterministic offline replay; errors are receipts too."""
    key=hashlib.sha256(url.encode()).hexdigest()
    dest=DATE_OUT/'http'/(key+'.json')
    if dest.exists():
        receipt=json.loads(dest.read_text())
        if receipt.get('error') and not (network and retry_errors):raise ValueError(receipt['error'])
        if not receipt.get('error') and 'text' not in receipt:
            body=ROOT/receipt['cache_body_path']
            if not body.exists():raise ValueError('Missing local HTTP body cache; refill from '+url)
            payload=body.read_bytes()
            if hashlib.sha256(payload).hexdigest()!=receipt['text_sha256']:raise ValueError('HTTP body cache hash mismatch')
            receipt['text']=payload.decode('utf-8')
        if not receipt.get('error'):return receipt
    if not network:raise ValueError('not_fetched_offline: '+url)
    try:
        response=client().fetch(url)
        receipt=dict(url=url,final_url=response.url,retrieved_utc=response.retrieved_utc,
                     body_sha256=hashlib.sha256(response.body).hexdigest(),text=response.text)
    except Exception as exc:
        receipt=dict(url=url,error=type(exc).__name__+': '+str(exc),checked_utc=now())
    if 'text' in receipt:
        payload=receipt['text'].encode();digest=hashlib.sha256(payload).hexdigest()
        body_path=ROOT/'local-cache/date-recovery-http'/(digest+'.txt')
        if not body_path.exists():atomic(body_path,receipt['text'])
        elif body_path.read_bytes()!=payload:raise ValueError('HTTP body cache integrity failure')
        saved={k:v for k,v in receipt.items() if k!='text'}
        saved.update(cache_body_path=str(body_path.relative_to(ROOT)),text_sha256=digest)
    else:saved=receipt
    atomic(dest,canonical(saved)+'\n')
    if receipt.get('error'):raise ValueError(receipt['error'])
    return receipt


def github_added(url, network=False, depth=0, retry_errors=False):
    location=github_location(url)
    if not location:return None
    repo,ref,path=location
    commits=[]; queries=[]
    for page in range(1,21):
        query=f'https://api.github.com/repos/{repo}/commits?'+urlencode(dict(path=path,sha=ref,per_page=100,page=page))
        receipt=saved_fetch(query,network,retry_errors)
        data=json.loads(receipt['text'])
        if not isinstance(data,list):raise ValueError('GitHub did not return a commit list')
        queries.append(dict(url=query,body_sha256=receipt['body_sha256'],retrieved_utc=receipt['retrieved_utc']))
        commits+=data
        if len(data)<100:break
    else:raise ValueError('Report history exceeds pagination bound')
    if not commits:raise ValueError('No history at pinned report path')
    oldest=commits[-1]; commit=oldest['sha']
    detail_url=f'https://api.github.com/repos/{repo}/commits/{commit}'
    detail=saved_fetch(detail_url,network,retry_errors); body=json.loads(detail['text'])
    files=[f for f in body.get('files',[]) if f['filename']==path]
    if not files:raise ValueError('First path commit not verifiable in commit file list')
    f=files[0]
    if f['status']=='renamed' and f.get('previous_filename') and body.get('parents') and depth<10:
        previous=f'https://github.com/{repo}/blob/{body["parents"][0]["sha"]}/{quote(f["previous_filename"],safe="/")}'
        original=github_added(previous,network,depth+1,retry_errors)
        original['evidence'].setdefault('rename_chain',[]).append(dict(commit_sha=commit,path=path,
            previous_filename=f['previous_filename'],api_url=detail_url,body_sha256=detail['body_sha256'],history_queries=queries))
        return original
    if f['status']!='added':raise ValueError('First path commit is '+f['status']+'; rename/history requires review')
    date=body['commit']['committer']['date'][:10]
    return dict(date_value=date,precision='day',role='publication',basis='github_report_added',
                evidence=dict(kind='github_api',source_url=body['html_url'],api_url=detail_url,
                              retrieved_utc=detail['retrieved_utc'],body_sha256=detail['body_sha256'],
                              repository=repo,path=path,pinned_ref=ref,commit_sha=commit,
                              author_date=body['commit']['author']['date'],committer_date=body['commit']['committer']['date'],
                              file_status=f['status'],git_blob_sha=f['sha'],history_queries=queries))


def history_recovery(network=False,limit=None,firm=None,retry=False):
    inspections=json.loads((DATE_OUT/'inspection.json').read_text())
    dest=DATE_OUT/'histories.jsonl'
    rows={r['report_id']:r for r in map(json.loads,dest.read_text().splitlines())} if dest.exists() else {}
    count=0
    for item in inspections:
        e=item['engagement']
        if firm and e['firm_id']!=firm:continue
        for r in item['reports']:
            rid=r['report_id']
            if rid in rows and not (rows[rid].get('error','').startswith('First path commit is renamed') or (retry and rows[rid].get('error'))):continue
            if not github_location(r['url']):continue
            if re.search(r'/(?:SUMMARY|README)\.md$',r['url'],re.I) and e['firm_id']=='oak-security':continue
            if limit is not None and count>=limit:break
            result=dict(report_id=rid,engagement_id=e['engagement_id'],firm_id=e['firm_id'],source_url=r['url'])
            try:result['claim']=github_added(r['url'],network,retry_errors=retry)
            except Exception as exc:result['error']=str(exc)
            rows[rid]=result; count+=1
            atomic(dest,''.join(canonical(rows[k])+'\n' for k in sorted(rows)))
            print(canonical(dict(processed=count,firm_id=e['firm_id'],report_id=rid,
                                 date=result.get('claim',{}).get('date_value'),error=result.get('error'))),flush=True)
            if re.search(r'HTTP (?:403|429)',result.get('error','')):
                print('GitHub access/rate limit reached; stopping network history work.',flush=True)
                return
        if limit is not None and count>=limit:break
    print(canonical(dict(history_reports=len(rows),recovered=sum(bool(r.get('claim')) for r in rows.values()),
                         failed=sum(bool(r.get('error')) for r in rows.values()))))


def client():
    if not hasattr(LOCAL,'client'):
        LOCAL.client=Client()
    return LOCAL.client


def github_url(url):
    p=urlsplit(url)
    parts=unquote(p.path).strip('/').split('/')
    if p.hostname=='github.com' and len(parts)>=5 and parts[2] in {'blob','raw'}:
        repo='/'.join(parts[:2]); ref=parts[3]; path='/'.join(parts[4:])
    elif p.hostname=='raw.githubusercontent.com' and len(parts)>=4:
        repo='/'.join(parts[:2]); ref=parts[2]; path='/'.join(parts[3:])
    else:
        return url,url
    if not re.fullmatch('[a-f0-9]{40}',ref):
        data=client().json(f'https://api.github.com/repos/{repo}/commits/{quote(ref,safe="")}')
        ref=data.get('sha','')
        if not re.fullmatch('[a-f0-9]{40}',ref):
            raise ValueError('GitHub revision cannot be pinned')
    return f'https://github.com/{repo}/blob/{ref}/{quote(path,safe="/")}',f'https://raw.githubusercontent.com/{repo}/{ref}/{quote(path,safe="/")}'


def recover(d, retry=False):
    firm,url=d['publisher_id'],d['public_url']
    key=hashlib.sha256(canonical([firm,url]).encode()).hexdigest()
    dest=ROOT/'data/phase3/date_recovery'/f'{key}.json'
    if dest.exists() and not retry:
        return json.loads(dest.read_text())
    result=dict(firm_id=firm,candidate_url=url,engagement_id=d['engagement_id'],attempts=[],status='failed')
    original=d['provenance'].get('source_row',{})
    urls=[url,d.get('wayback_url')]
    urls += [original.get('original_publisher_url')]
    urls += [e.get('candidate_url') for e in original.get('evidence',[]) if isinstance(e,dict)]
    for attempt_url in dict.fromkeys(u for u in urls if u):
        if re.search(r'github(?:usercontent)?\.com/(?:solodit/|shenyimings/FORGE|InPlusLab/DAppSCAN.*(?:source|json))',attempt_url,re.I):
            result['attempts'].append(dict(url=attempt_url,error='derived_or_restricted_mirror_not_original'))
            continue
        try:
            if attempt_url.startswith('http://'):
                attempt_url='https://'+attempt_url[7:]
            public,download=github_url(attempt_url)
            response=client().fetch(download)
            body=response.body
            if body.startswith(b'%PDF'):
                fmt='pdf'
            elif urlsplit(download).path.lower().endswith(('.md','.txt')) and len(body)>500 and re.search(rb'audit|security|assessment|verification',body[:20000],re.I):
                fmt='md'
            elif len(body)>2500 and re.search(rb'<(?:!doctype|html)\b',body[:1000],re.I) and re.search(rb'audit|security|assessment|verification',body,re.I):
                # Article shell/navigation alone is insufficient.
                from metadata_rules import VisibleHTML
                parser=VisibleHTML(); parser.feed(body.decode('utf-8','replace'))
                visible=''.join(parser.article)
                if len(visible)<1800 or not re.search(r'finding|scope|executive summary|vulnerabilit',visible,re.I):
                    raise ValueError('HTML is not a substantive audit report')
                fmt='html'
            else:
                raise ValueError('Response is not an audit report original')
            digest=hashlib.sha256(body).hexdigest()
            path=ROOT/'local-cache/originals'/digest[:2]/(digest+'.'+fmt)
            path.parent.mkdir(parents=True,exist_ok=True)
            if not path.exists():
                path.write_bytes(body)
            elif hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
                raise ValueError('CAS integrity failure')
            listing=original.get('listing_url') or original.get('attribution_basis',{}).get('evidence_url') or url
            row=dict(firm_id=firm,collector='scripts/collect/recover_dates.py',source_kind='github' if 'github.com/' in public else 'website',
                     public_url=public,listing_url=listing,sha256=digest,bytes=len(body),file_format=fmt,
                     local_path=str(path.relative_to(ROOT)),filename=Path(unquote(urlsplit(url).path)).name,
                     title_hint=original.get('title_hint'),project_hint=original.get('project_hint'),
                     date_hint=None,date_precision='none',date_basis='none',doc_kind='audit_report',
                     retrieved_utc=now(),notes='Discovery recovery; original candidate: '+url+'; retrieval: '+download+'; date is extracted separately from the document.')
            result.update(status='collected',sha256=digest,row=row,retrieved_utc=row['retrieved_utc'])
            result['attempts'].append(dict(url=attempt_url,download_url=download,status=200,sha256=digest))
            break
        except Exception as exc:
            result['attempts'].append(dict(url=attempt_url,error=type(exc).__name__+': '+str(exc)[:600]))
    result['checked_utc']=now()
    atomic(dest,canonical(result)+'\n')
    return result


def publish(results):
    firms={r['firm_id'] for r in results}
    for firm in sorted(firms):
        batch=[r for r in results if r['firm_id']==firm]
        directory=ROOT/'data/collect'/firm
        directory.mkdir(parents=True,exist_ok=True)
        with (ROOT/'local-cache'/f'date_classification-append-{firm}.lock').open('a') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            path=directory/'reports.jsonl'
            payload=path.read_text() if path.exists() else ''
            rows=[json.loads(s) for s in payload.splitlines() if s.strip()]
            keys={(r['public_url'],r['sha256']) for r in rows}
            added=[]
            for r in batch:
                row=r.get('row')
                if row and (row['public_url'],row['sha256']) not in keys:
                    rows.append(row); added.append(row); keys.add((row['public_url'],row['sha256']))
            if added:
                atomic(path,payload+('' if not payload or payload.endswith('\n') else '\n')+''.join(canonical(r)+'\n' for r in added))
            sp=directory/'status.json'
            status=json.loads(sp.read_text()) if sp.exists() else dict(firm_id=firm,listing_urls=[],listed_count=0,failed=0,skipped_non_report=0,failures=[],collector_script='scripts/collect/recover_dates.py')
            status.update(collected=len(rows),collected_utc=now())
            recovery_failures=[dict(url=r['candidate_url'],error='; '.join(a.get('error','') for a in r['attempts'] if a.get('error')))
                               for r in batch if r['status']!='collected']
            failures=status.get('failures',[])+recovery_failures
            status['failures']=list({(r.get('url'),r.get('error')):r for r in failures}.values())
            status['failed']=len(status['failures'])
            status['collector_scripts']=sorted(set(status.get('collector_scripts',[])+[status.get('collector_script',''), 'scripts/collect/recover_dates.py'])-{''})
            status['date_recovery']=dict(candidates=len(batch),collected=sum(r['status']=='collected' for r in batch),
                                         failed=sum(r['status']!='collected' for r in batch),receipts='data/phase3/date_recovery/')
            atomic(sp,json.dumps(status,indent=2)+'\n')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--workers',type=int,default=8)
    p.add_argument('--limit',type=int)
    p.add_argument('--retry',action='store_true')
    p.add_argument('--publish-only',action='store_true')
    p.add_argument('--engagement-inspection',action='store_true',help='Read-only release year-gap inventory; no collection/publishing')
    p.add_argument('--text-candidates',action='store_true')
    p.add_argument('--report-histories',action='store_true')
    p.add_argument('--publisher-listings',action='store_true')
    p.add_argument('--fetch-url')
    p.add_argument('--finalize-dates',action='store_true')
    p.add_argument('--compact-date-http',action='store_true')
    p.add_argument('--validate-dates',action='store_true')
    p.add_argument('--network',action='store_true',help='Opt in to public robots-aware paced evidence retrieval')
    p.add_argument('--firm')
    a=p.parse_args()
    if a.compact_date_http:
        compact_date_http()
        raise SystemExit(0)
    if a.validate_dates:
        raise SystemExit(0 if validate_date_evidence() else 1)
    if a.fetch_url:
        if not a.network:p.error('--fetch-url requires --network')
        fetch_extra(a.fetch_url)
        raise SystemExit(0)
    if a.finalize_dates:
        finalize_dates()
        raise SystemExit(0)
    if a.engagement_inspection:
        engagement_inspection()
        raise SystemExit(0)
    if a.text_candidates:
        date_candidates()
        raise SystemExit(0)
    if a.report_histories:
        history_recovery(a.network,a.limit,a.firm,a.retry)
        raise SystemExit(0)
    if a.publisher_listings:
        publisher_listings(a.network)
        raise SystemExit(0)
    if a.publish_only:
        results=[json.loads(p.read_text()) for p in sorted((ROOT/'data/phase3/date_recovery').glob('*.json'))]
    else:
        baseline=json.loads((ROOT/'data/phase3/dates_before.json').read_text())
        docs={ (d['publisher_id'],d['public_url']):d for d in baseline['missing_documents'] if not d['sha256']}
        # Round robin by host avoids occupying every worker with one slow host.
        groups={}
        for d in docs.values(): groups.setdefault(urlsplit(d['public_url']).netloc,[]).append(d)
        pending=[]
        while groups:
            for host in list(groups):
                pending.append(groups[host].pop())
                if not groups[host]: del groups[host]
        results=[]
        with ThreadPoolExecutor(max_workers=a.workers) as pool:
            futures=[pool.submit(recover,d,a.retry) for d in pending[:a.limit]]
            for f in as_completed(futures):
                results.append(f.result())
                if len(results)%25==0:
                    print(canonical(dict(processed=len(results),statuses=dict(Counter(r['status'] for r in results)))),flush=True)
    publish(results)
    summary=dict(candidates=len(results),statuses=dict(Counter(r['status'] for r in results)),
                 by_firm={f:dict(Counter(r['status'] for r in results if r['firm_id']==f)) for f in sorted({r['firm_id'] for r in results})})
    atomic(ROOT/'data/phase3/date_recovery_summary.json',json.dumps(summary,indent=2)+'\n')
    print(canonical(summary),flush=True)
