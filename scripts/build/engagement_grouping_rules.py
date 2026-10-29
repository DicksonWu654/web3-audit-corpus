"""Bundle scope reports after report/rendering identity and date resolution.

Pure functions are shared by the builder and the offline evaluation. There is
no network, date recovery, fuzzy client matching, or sample-specific exception.
"""
from collections import defaultdict
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import unicodedata
from urllib.parse import unquote

RULE_PATH = Path(__file__).resolve().parents[2]/'registry/engagement_grouping.json'
RULES = json.loads(RULE_PATH.read_text())
VERSION = RULES['version']
RULES_SHA256 = hashlib.sha256(RULE_PATH.read_bytes()+Path(__file__).read_bytes()).hexdigest()


def norm(value):
    return ''.join(c for c in unicodedata.normalize('NFKC', value or '').casefold() if c.isalnum())


def client_key(value):
    value = re.split(r'\s*[:–—]|\s+-\s+', value or '')[0]
    value = re.sub(r'\s+(?:(?:security\s+)?(?:audit|review|assessment)(?:\s+report)?|v\d+(?:\.\d+)*|version\s+\d+)\b.*$', '', value, flags=re.I)
    key = norm(value)
    if len(key)<3 or key in {'protocol','project','smartcontract','smartcontracts','security','unknown','none','client','report','code','blockchain','audit','contracts','defi'}:
        return None
    return RULES['client_aliases'].get(key, key)


def source_row(doc):
    return doc.get('provenance', {}).get('source_row', {})


def family(doc):
    """Source-labelled commissioning client, then direct publisher listing.

    A catalogue name alone is insufficient for a third-party mirror. Its
    client must also occur in a cover or explicit commissioning declaration.
    """
    meta=doc['metadata']
    pi=meta.get('project_identity') or {}
    declared=[x['value'] for x in pi.get('entities', [])
              if isinstance(x.get('evidence'),str) and re.search(r'\b(?:engaged|commissioned|client)\b',x['evidence'],re.I)]
    if declared:
        keys={client_key(x) for x in declared}-{None}
        if len(keys)==1:return next(iter(keys))
    raw=source_row(doc)
    hint=raw.get('project_hint')
    cover=meta.get('client',{}).get('value') or ''
    if hint and doc.get('source_kind') in {'website','contest'}:
        return client_key(hint)
    # Source-native exact title/client identity; scopes after ':' are retained
    # in scope_name, but do not masquerade as different commissioning clients.
    return client_key(cover)


def program(doc, contests=()):
    """Explicit competition identity or named service; never a host-name proxy."""
    if doc['doc_kind']=='fix_review':return 'fix_review'
    competitions=sorted({str(c[0]) for c in contests if not str(c[0]).startswith('portfolio:') and c[1]!='mitigation'})
    if competitions:return 'contest:'+','.join(competitions)
    raw=source_row(doc)
    m=re.search(r'Official (cantina_\w+) portfolio',str(raw.get('notes') or ''))
    if m and doc['publisher_id']=='cantina':return m[1]
    name=unquote(doc.get('filename') or '')
    if doc['publisher_id']=='cantina':
        if re.search(r'cantina[-_]solo',name,re.I):return 'cantina_solo'
        if re.search(r'cantina|report-cantinacode',name,re.I):return 'cantina_managed'
    if doc['doc_kind']=='contest_report':return None  # No official event identity.
    if doc['doc_kind']=='formal_verification':return 'formal_verification'
    typ=meta_value(doc,'audit_type')
    if typ in {'formal_verification','penetration_test'}:return typ
    return 'security_review' if doc['doc_kind']=='audit_report' else None


def meta_value(doc,key):
    return (doc['metadata'].get(key) or {}).get('value')


def scope_name(doc):
    cover=meta_value(doc,'client') or ''
    title=source_row(doc).get('title_hint') or meta_value(doc,'report_title') or doc.get('title') or ''
    # The publisher's title distinguishes scopes hidden by a logo-only cover.
    if norm(cover)==family(doc) and len(norm(title))>len(norm(cover))+4:
        cover=title
    if not cover or norm(cover)==family(doc):
        cover=unquote(doc.get('filename') or cover)
    # Component names can follow the word "Audit" (e.g. ERC721F). Removing
    # the entire suffix would erase the very scope distinction being bundled.
    cover=re.sub(r'\b(?:security\s+)?(?:audit|review|assessment)(?:\s+report)?\b', '',cover,flags=re.I)
    cover=re.sub(r'\bv(?:ersion)?\s*\d+(?:\.\d+)*\b|\brevision\s*\d+\b', '', cover,flags=re.I)
    return norm(cover)


def profile(key, documents, claims, contests=()):
    initial=[d for d in documents if d['doc_kind'] not in {'fix_review','unknown','non_report'} and d.get('source_family')!='discovery']
    # A direct publisher occurrence labels all renderings of its report unit.
    declared={client_key(x['value']) for d in initial for x in (d['metadata'].get('project_identity') or {}).get('entities',[])
              if isinstance(x.get('evidence'),str) and re.search(r'\b(?:engaged|commissioned|client)\b',x['evidence'],re.I)}-{None}
    direct={client_key(source_row(d).get('project_hint')) for d in initial
            if d.get('source_kind') in {'website','contest'} and source_row(d).get('project_hint')}-{None}
    families=direct if len(direct)==1 else declared or direct or ({family(d) for d in initial}-{None})
    # Audited repository organizations are source scope evidence, independent
    # of component titles. Do not use findings/dependency URL inventories.
    owners={norm(repo.split('/')[1]) for d in initial
            for repo in (d['metadata'].get('project_identity') or {}).get('repositories',[])
            if len(repo.split('/'))>=3 and repo.split('/')[0] in {'github.com','gitlab.com'}}
    owners-={norm(d['publisher_id']) for d in initial}
    if len(owners)==1:families={'repository-owner:'+next(iter(owners))}
    programs={program(d,contests) for d in initial}-{None}
    eligible=[c for c in claims if c.get('eligible_for_audit_year')]
    role='audit_completion' if any(c['role']=='audit_completion' for c in eligible) else 'report_issue'
    preferred=[c for c in eligible if c['role']==role]
    values={c['date_value'] for c in preferred if c.get('date_value')}
    end=next(iter(values)) if len(values)==1 and len(next(iter(values)))==10 else None
    starts={c['date_value'] for c in claims if c['role']=='audit_start' and c.get('basis')=='document_text'
            and c.get('authority')=='publisher' and len(c.get('date_value') or '')==10}
    starts.update(c[2][:10] for c in contests if len(c)>2 and c[2] and c[1]!='mitigation')
    # Multiple periods are ambiguous; do not invent a convenient start date.
    start=next(iter(starts)) if len(starts)==1 else None
    scopes={scope_name(d) for d in initial}-{''}
    text=' '.join((meta_value(d,'client') or '')+' '+(meta_value(d,'report_title') or '')+' '+(d.get('filename') or '') for d in initial)
    later=bool(re.search(r'\bre[-_ ]?audit\b|\b(?:follow[-_ ]?up|fix(?:es)?[-_ ]review|fixes|remediation|mitigation|retest)\b|\breview\s*\d+\b|\bround\s*[2-9]\b',text.replace('_',' '),re.I))
    own_names={norm(d['publisher_id']) for d in initial}
    families-=own_names
    return dict(key=key,publisher=documents[0]['publisher_id'] if documents else None,
        family=next(iter(families)) if len(families)==1 else None,
        program=next(iter(programs)) if len(programs)==1 else None,
        date=end,date_role=role,start=start,ambiguous_start=len(starts)>1,scopes=sorted(scopes),
        later_review=later,eligible=bool(initial and end and role=='audit_completion' and len(families)==1 and len(programs)==1 and not later),
        # Unacquired discovery occurrences remain provenance, not report files.
        report_ids=sorted({d['sha256'] for d in documents if d['sha256']}),
        documents=sorted(d['document_id'] for d in documents))


def pair_reason(a,b,window=None):
    window=RULES['max_completion_span_days'] if window is None else window
    if not a['eligible'] or not b['eligible']:return 'insufficient_or_later_review_evidence'
    if (a['publisher'],a['family'],a['program'])!=(b['publisher'],b['family'],b['program']):return 'different_client_or_program'
    if a['date_role']!=b['date_role']:return 'different_date_semantics'
    if a['date_role']!='audit_completion':return 'completion_date_required'
    delta=abs((date.fromisoformat(a['date'])-date.fromisoformat(b['date'])).days)
    if delta>window:return 'outside_window'
    if a['ambiguous_start'] or b['ambiguous_start']:return 'ambiguous_review_period'
    if delta and (not a['start'] or not b['start']):return 'missing_review_period_for_window'
    if a['start'] and b['start']:
        if a['start']>a['date'] or b['start']>b['date']:return 'inconsistent_review_period'
        if max(a['start'],b['start'])>min(a['date'],b['date']) or delta and max(a['start'],b['start'])==min(a['date'],b['date']):
            return 'nonoverlapping_review_periods'
    if set(a['scopes']) & set(b['scopes']):return 'same_scope_or_later_review'
    if not a['scopes'] or not b['scopes']:return 'missing_scope'
    return 'merge'


def cluster(profiles,window=None):
    """Sorted, complete-link clustering; no transitive date/scope bridges.

    Every pair in a proposed bundle must pass, including the earliest/latest.
    Membership is independent of input ordering, Python hashes and wall time.
    """
    buckets=defaultdict(list)
    for p in profiles:
        buckets[p['publisher'],p['family'] or '',p['program'] or ''].append(p)
    result=[]
    for _,bucket in sorted(buckets.items()):
        local=[]
        for p in sorted(bucket,key=lambda p:(p['date'] or '',p['key'])):
            target=next((g for g in local if all(pair_reason(p,q,window)=='merge' for q in g)),None)
            if target is None:local.append([p])
            else:target.append(p)
        result.extend([[p['key'] for p in g] for g in local])
    return sorted(result,key=lambda g:min(g))
