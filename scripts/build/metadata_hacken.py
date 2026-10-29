"""Offline SCA API identities; match acquired reports before adding metadata rows."""
from collections import Counter, defaultdict
import csv
import hashlib
import json
import re
import unicodedata
from urllib.parse import urlsplit


def key(value):
    return ''.join(c for c in unicodedata.normalize('NFKC',value or '').casefold() if c.isalnum())


def import_metadata_hacken(b):
    from build_db import uid
    path=b.root/'data/collect/hacken/api_audits.jsonl'
    if not path.exists() or 'hacken' not in b.publishers: return
    review=b.root/'registry/hacken_report_scope.csv'
    excluded={r['sha256']:r for r in csv.DictReader(review.open()) if r['include_in_audit_counts']=='no'} if review.exists() else {}
    for link in b.tables['engagement_documents'].values():
        doc=b.tables['documents'][link['document_id']]
        if doc['publisher_id']=='hacken' and doc['sha256'] in excluded:
            e=b.tables['engagements'][link['engagement_id']]
            e['identity_status']='excluded';e['engagement_kind']='other'
            e['evidence']['excluded_non_sca_service']=excluded[doc['sha256']]
    docs=defaultdict(list)
    dates=defaultdict(set)
    for link in b.tables['engagement_documents'].values():
        d=b.tables['documents'][link['document_id']]
        if d['publisher_id']=='hacken' and b.tables['engagements'][link['engagement_id']]['identity_status']=='confirmed': docs[link['engagement_id']].append(d)
    for c in b.tables['date_claims'].values():
        if c.get('document_id') and c.get('date_value'):
            dates[c['document_id']].add(c['date_value'][:10])
    candidates=[]
    for eid, ds in docs.items():
        names={key(b.tables['engagements'][eid]['project'])}
        values=set();commits=set();text=''
        for d in ds:
            names.add(key(d.get('project')))
            values.update(dates[d['document_id']])
            hint=d['provenance'].get('source_row',{}).get('date_hint')
            if hint: values.add(hint[:10])
            p=b.root/'local-cache/fulltext'/(d['sha256']+'.txt')
            if p.exists(): text+='\n'+p.read_text()[:30000]
        names.update(key(m[1]) for m in re.finditer(r'(?im)^\s*Customer:\s*(.+)$',text))
        commits.update(re.findall(r'\b[0-9a-f]{40}\b',text))
        candidates.append((eid,names,values,commits,text))
    # Reviewed identity crosswalk: bind API identity and original/text hashes.
    crosswalk=b.root/'data/collect/hacken/gapfill_api_matches.jsonl'
    gapfill={x['source_url']:x for x in (json.loads(line) for line in crosswalk.read_text().splitlines() if line.strip())} if crosswalk.exists() else {}
    seen=set();matches=[];stats=Counter(non_sca_pdf_excluded=len(excluded));by_year=defaultdict(Counter)
    records=list(b.rows(path,'audit_metadata:hacken','collected','engagement_metadata'))
    dated_projects=Counter((key(r.get('client_name') or r.get('audit_name')),(r.get('audit_date') or '')[:10])
        for r,_,_ in records if r.get('audit_type')=='SCA')
    for r,meta,ledger in records:
        if r.get('audit_type')!='SCA':
            ledger['excluded_scope_rows']+=1;stats['non_sca_excluded']+=1;continue
        url=r.get('report_link');when=(r.get('audit_date') or '')[:10]
        if urlsplit(url or '').scheme!='https' or not url.startswith('https://hacken.io/a/'):
            raise ValueError('SCA API record lacks public report page')
        if url in seen: raise ValueError('Duplicate Hacken API report identity: '+url)
        seen.add(url)
        project=r.get('client_name') or r.get('audit_name')
        commit=(r.get('scope_parameters') or {}).get('commit','').strip()
        receipt=gapfill.get(url)
        receipt_shas=set()
        if receipt and receipt['api_identity']=={k:r.get(k) for k in ('report_link','client_name','audit_date','scope_parameters')}:
            for proof in receipt['matches']:
                s=proof['sha256']
                if not re.fullmatch(r'[0-9a-f]{64}',s): raise ValueError('Invalid gapfill SHA')
                p=b.root/'local-cache/fulltext'/(s+'.txt')
                if p.exists() and hashlib.sha256(p.read_bytes()).hexdigest()==proof['text_sha256']:
                    receipt_shas.add(s)
        matched=[];possible=[]
        for eid,names,values,commits,text in candidates:
            unique_date=dated_projects[(key(project),when)]==1
            if any(d["sha256"] in receipt_shas for d in docs[eid]) or url in text or (key(project) and key(project) in names and ((unique_date and when in values) or (commit and commit in commits))):
                matched.append(eid)
            elif key(project) and key(project) in names and any(value[:4]==when[:4] for value in values):
                possible.append(eid)
        # One API record may connect several PDF versions of the same report.
        # Do not introduce a second engagement in either case.
        for eid in matched:
            b.tables['engagements'][eid]['evidence'].setdefault('sca_api_matches',[]).append(dict(
                source_url=url,source_record=meta,audit_date=when,basis='verified_gapfill_identity_receipt' if receipt_shas else 'exact_project_and_date_or_commit_or_url',gapfill_receipt=receipt if receipt_shas else None))
        stats['api_sca']+=1
        route='api_matched_pdf' if matched else 'unresolved_pdf_overlap' if possible else 'metadata_only'
        stats[route]+=1;by_year[when[:4]][route]+=1
        matches.append(dict(source_url=url,audit_date=when,project=project,matched_engagement_ids=sorted(matched),
            possible_overlap_engagement_ids=sorted(possible),route=route))
        if not matched:
            for eid in possible:
                b.tables['engagements'][eid]['evidence'].setdefault('sca_api_unresolved_overlap',[]).append(dict(
                    source_url=url,source_record=meta,audit_date=when,basis='same_source_project_and_year;identity_unresolved'))
        if not matched and not possible:
            eid=uid('engagement','audit_metadata','hacken',url)
            b.tables['engagements'][eid]=dict(engagement_id=eid,publisher_id='hacken',
                industry_engagement_id=uid('industry',eid),project=project,engagement_kind='audit',
                identity_status='confirmed',identity_basis='publisher_sca_api_metadata',
                evidence=dict(metadata_only=True,source_url=url,listing_url=r['listing_url'],
                    source_record=meta,audit_type='SCA',documents=[],report_ids=[],report_count=0,scope_report_count=0,
                    languages=r.get('languages',[]),chains=r.get('platforms',[])),
                notes=['Public SCA API metadata; original PDF and finding text unobserved.'])
            # The API audit_date is a publisher review-date claim, with its
            # original field and public listing provenance retained.
            b.claim({'engagement_id':eid},meta['source_tag'],'audit_date',when,'audit_completion',
                basis='publisher_api',authority='publisher',evidence=dict(source_url=url,listing_url=r['listing_url'],field='audit_date'))
        ledger['imported_rows']+=1
    target=b.root/'data/coverage/hacken_integration.json'
    target.parent.mkdir(parents=True,exist_ok=True)
    target.write_text(json.dumps(dict(counts=stats,by_year=by_year,matches=matches),sort_keys=True,indent=2)+'\n')
