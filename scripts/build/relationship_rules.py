"""Evidence for renderings, revisions, fix reviews and contest report parts.

Candidate discovery is broad; decisions require source scope and substantive
agreement. Names, dates, version numbers and common disclaimers never suffice.
"""
from datetime import date
from collections import Counter, defaultdict
from hashlib import sha256
import re


def source_relationships(text):
    from metadata_rules import normalize
    issue_urls=sorted(set(u.rstrip('.,):]') for u in re.findall(r'https?://github\.com/[\w.-]+/[\w.-]+/issues/\d+',text,re.I)))
    report_ids=sorted(set(m[1] for m in re.finditer(r'(?:audit|report)\s*(?:report\s*)?(?:#|no\.?|number|id)\s*[:#]?\s*([A-Z]*[- ]?20\d{2}[-/]\d{2,5})\b',text[:18000],re.I)))
    titles=[]; statuses=[]
    for line in text.splitlines():
        line=re.sub(r'^[\s#*|\[\d.]+','',line)
        m=re.match(r'(?:\[?((?:[CHMLIG]|[A-Z]{2,8})[-_ ]?\d{1,3})\]?[ .:]|(?i:critical|high|medium|low|informational)\s*[-:]\s*)(.{12,200})',line)
        if m:
            title=re.sub(r'\s*[|\[]?(?:status|fixed|resolved|acknowledged|closed|open|mitigated)\b.*$','',m[2],flags=re.I)
            title=re.sub(r'[. ]+\d{1,3}\s*$','',title)
            if len(normalize(title))>=18 and len(title.split())>=3 and not re.search(r'[=;{}]|\b(?:public|private|constant)\b',title): titles.append(normalize(title))
        if re.search(r'\bstatus\b.{0,30}\b(?:fixed|resolved|acknowledged|closed|mitigated)|\b(?:fixed|resolved|acknowledged|closed|mitigated)\b.{0,20}\bstatus\b',line,re.I): statuses.append(line[:200])
    # Layout-independent sketches of substantive prose; paired with findings or
    # initial commits so shared publisher templates cannot authorize a merge.
    words=re.findall(r'[a-z0-9]+',text.lower())[:60000]
    shingles=sorted({sha256(' '.join(words[i:i+8]).encode()).hexdigest()[:16] for i in range(max(0,len(words)-7))})[:128]
    # Scope material ends at detailed findings. A finding's remediation commit
    # and report-host repository are never an initial audited commit.
    front=re.split(r'(?im)^\s*(?:#{1,4}\s*)?(?:\d+(?:\.\d+)*\s+)?(?:detailed\s+findings|audit\s+findings|findings\s+details)\s*$',text[:40000])[0]
    initial=[]; fixes=[]; repos=[]
    for m in re.finditer(r'(?im)^.*(?:commit|revision|hash|repository|codebase|\brepo\b).*(?:\n[^\n]*){0,2}',front):
        s=m[0]
        hs=re.findall(r'\b[a-f0-9]{7,40}\b',s,re.I)
        later=re.search(r'fix|patch|remediat|re[- ]?test|re[- ]?audit|version\s*2',s,re.I)
        (fixes if later else initial).extend(h.lower() for h in hs)
        if not later:
            repos.extend(re.findall(r'https?://(?:github\.com|gitlab\.com)/[\w.-]+/[\w.-]+',s))
    labels=text[:1800]
    revision=bool(re.search(r'fix(?:es)?[- _]*(?:review|verification)|re[- ]?audit|\bv\d+(?:\.\d+)*\b|\bfinal\b|mitigation|re[- ]?test|revis(?:ed|ion)',labels,re.I))
    team_part=bool(re.search(r'contest|competition|defender',text[:10000],re.I) and re.search(r'team\s*[:|]|team\s*(?:solo|0x)|submission|wardens?',text[:10000],re.I))
    return dict(issue_urls=issue_urls,report_ids=report_ids,finding_titles=sorted(set(titles)),
                status_progression=bool(statuses),sketch=shingles,initial_commits=sorted(set(initial)),
                fix_commits=sorted(set(fixes)),scope_repositories=sorted(set(repos)),revision_label=revision,contest_team_part=team_part)


def compatible_hashes(a,b):
    return any(x.startswith(y) or y.startswith(x) for x in a for y in b)


def dates(doc,role='audit_completion'):
    return {c['date_value'] for c in doc['metadata']['dates'] if c.get('date_value') and c['role']==role and c.get('confidence',0)>=.8}


def short_window(a,b,days=60):
    da=dates(a) or dates(a,'report_issue'); db=dates(b) or dates(b,'report_issue')
    # A missing date is not temporal evidence. Finding issue URLs and stable
    # report IDs can independently establish aliases without this check.
    return any(abs((date.fromisoformat(x)-date.fromisoformat(y)).days)<=days for x in da for y in db if len(x)==len(y)==10)


def relationship(a,b,rare_a=None,rare_b=None):
    from metadata_rules import normalize
    from engagement_rules import generic_project
    if a['publisher_id']!=b['publisher_id']: return None
    ma,mb=a['metadata'],b['metadata']
    ra,rb=ma.get('source_relationships',{}),mb.get('source_relationships',{})
    ia,ib=set(ra.get('report_ids',[])),set(rb.get('report_ids',[]))
    if ia and ib and not ia&ib: return None
    ua,ub=set(ra.get('issue_urls',[])),set(rb.get('issue_urls',[]))
    fa,fb=set(ra.get('finding_titles',[])),set(rb.get('finding_titles',[]))
    finding_overlap=len(fa&fb)/max(1,max(len(fa),len(fb)))
    client=ma['client']['value']; other=mb['client']['value']
    same_client=not generic_project(client) and normalize(client)==normalize(other)
    official_overlap={u for u in ua&ub if re.search(r'/[^/]*(?:judging|findings)/issues/',u,re.I)}
    def own_judging_repo(urls):
        counts=Counter(u.split('/issues/')[0] for u in urls)
        top=counts.most_common(2)
        return top[0][0] if top and (len(top)==1 or top[0][1]>top[1][1]) else None
    own_a,own_b=own_judging_repo(ua),own_judging_repo(ub)
    own_overlap={u for u in official_overlap if u.startswith(str(own_a)+'/issues/')}
    if own_a and own_a==own_b and own_overlap and len(ua&ub)/min(len(ua),len(ub))>=.9 and (same_client or len(own_overlap)>=2 or fa&fb and finding_overlap>=.8):
        return 'same_official_finding_issue_rendering'
    ca,cb=set(ra.get('initial_commits',[])),set(rb.get('initial_commits',[]))
    same_commit=compatible_hashes(ca,cb)
    disjoint=bool(ca and cb and not same_commit)
    repos=bool(set(ra.get('scope_repositories',[]))&set(rb.get('scope_repositories',[])))
    sketch_a,sketch_b=set(ra.get('sketch',[])),set(rb.get('sketch',[]))
    agreement=len(sketch_a&sketch_b)/max(1,min(len(sketch_a),len(sketch_b)))
    # Stable publisher-assigned audit number is direct revision evidence. Keep
    # an independent scope/content check to guard incidental cited report IDs.
    if ia&ib and (same_client or same_commit) and (finding_overlap>=.8 and fa&fb or agreement>=.7):
        return 'same_report_number_revision'
    if disjoint: return None
    near=short_window(a,b)
    # Team subreports of the same publisher contest are components, even when
    # the teams found different issues. Independent private reports lack this
    # source-explicit competition/team relationship.
    if ra.get('contest_team_part') and rb.get('contest_team_part') and same_commit and repos and near and same_client:
        return 'same_contest_scope_team_components'
    enda,endb=dates(a),dates(b)
    distinct=enda and endb and not any(x.startswith(y) or y.startswith(x) for x in enda for y in endb)
    filenames=' '.join([a.get('filename') or '',b.get('filename') or ''])
    labels=bool(ra.get('revision_label') or rb.get('revision_label') or a['doc_kind']=='fix_review' or b['doc_kind']=='fix_review' or re.search(r'fix[- _]*review|re[- _]?audit|re[- _]?test|mitigation|\bfinal\b|\bv\d',filenames,re.I))
    repeated_findings=bool(fa&fb) and finding_overlap>=.8
    if same_commit and repeated_findings and near and labels and (agreement>=.45 or ra.get('status_progression') or rb.get('status_progression')):
        return 'same_initial_commit_findings_revision'
    if distinct: return None
    # Empirically common publisher-template shingles are removed before this
    # rendering decision. This also covers narrative studies and zero-finding
    # reports whose native formats have no severity-prefixed finding titles.
    if rare_a and rare_b and (same_client or repos or same_commit) and near and agreement>=.65:
        common=len(rare_a&rare_b)
        if common>=8 and common/max(len(rare_a),len(rare_b))>=.75:
            return 'publisher_distinctive_scope_content_rendering'
    if (same_commit or repos or same_client) and agreement>=.82 and (near or same_commit) and (len(fa&fb)>=2 or same_commit and agreement>=.92):
        return 'layout_independent_scope_content_rendering'
    # A one-finding report still needs both its full title and its actual scope.
    if repeated_findings and same_commit and (near or not enda or not endb) and agreement>=.7:
        return 'same_initial_scope_finding_rendering'
    return None


def candidate_keys(doc):
    from metadata_rules import normalize
    from engagement_rules import generic_project
    m=doc['metadata']; r=m.get('source_relationships',{})
    keys=[('report_id',v) for v in r.get('report_ids',[])]
    keys += [('finding_issue',v) for v in r.get('issue_urls',[])]
    # Prefix indexing allows a printed short commit and a full hash to meet.
    keys += [('initial_commit',v[:7]) for v in r.get('initial_commits',[])]
    keys += [('scope_repository',v) for v in r.get('scope_repositories',[])]
    if not generic_project(m['client']['value']): keys.append(('client',normalize(m['client']['value'])))
    return keys


def distinctive_content(docs):
    """Template frequency uses unique original hashes, not source occurrences.

    A small publisher population cannot establish an empirical template; those
    documents keep the explicit scope/finding rules instead.
    """
    counts=defaultdict(Counter); units=defaultdict(set)
    for d in docs.values():
        key=d['sha256'] or d['document_id']; firm=d['publisher_id']
        if key in units[firm]: continue
        units[firm].add(key)
        counts[firm].update(d['metadata'].get('source_relationships',{}).get('sketch',[]))
    result={}
    for did,d in docs.items():
        firm=d['publisher_id']; n=len(units[firm])
        result[did]={h for h in d['metadata'].get('source_relationships',{}).get('sketch',[]) if counts[firm][h]<=max(3,n*.05)} if n>=20 else set()
    return result


def fix_parent_support(review,parent):
    """Scope + repeated finding titles can support a unique dated fix parent."""
    from metadata_rules import normalize
    from engagement_rules import generic_project
    if review['doc_kind']!='fix_review' or parent['doc_kind'] in {'fix_review','unknown'}: return False
    a,b=review['metadata'],parent['metadata']
    ra,rb=a.get('source_relationships',{}),b.get('source_relationships',{})
    client=a['client']['value']
    same_client=not generic_project(client) and normalize(client)==normalize(b['client']['value'])
    repos=set(ra.get('scope_repositories',[]))&set(rb.get('scope_repositories',[]))
    fa,fb=set(ra.get('finding_titles',[])),set(rb.get('finding_titles',[]))
    findings=bool(fa&fb) and len(fa&fb)/max(1,len(fa))>=.8
    return same_client and bool(repos) and findings and short_window(review,parent)
