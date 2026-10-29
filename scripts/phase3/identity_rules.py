"""Source-evidenced report families and project identity, independent of samples.

Display names are retained with their scopes. Cadence entities are a separate
projection and need repository/scope or explicit protocol-domain corroboration.
"""
from datetime import date
from html.parser import HTMLParser
import hashlib
from pathlib import Path
import re
import unicodedata
from urllib.parse import unquote, urlsplit

VERSION = 'phase3e-1'
RULES_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def norm(value):
    return ''.join(c for c in unicodedata.normalize('NFKC', value or '').casefold() if c.isalnum())


def clean(value):
    return re.sub(r'\s+', ' ', re.sub(r'</?[A-Za-z][A-Za-z0-9:-]*(?:\s[^<>]{0,500})?/?>', ' ', value or '')).strip(' #*_|:–—-')


def boilerplate(value):
    s = clean(value)
    return (not s or len(norm(s)) < 2 or bool(re.fullmatch(r'[\d\W]+', s))
            or s.casefold() in {'methodology','reported','reported issues','client firm','client name','project name','source code','executive summary','risk assessment','https','http','authors','final report','review by'}
            or len(s.split()) > 8 or len(s) > 140
            or bool(re.search(r'^(?:and|this|the|we|our|it|as|all|please|based|note)\b|\b(?:shall|should|must|has been|have been|was|were|construe|liability|warranty|likelihood|commissioned|engaged|performed|conducted)\b|\bmanaged(?: review(?: by)?)?$', s, re.I))
            or bool(re.search(r'^(?:presented|prepared|review)\s+by\b|^(?:report\s+for|final\s+report)$|managed\s+review\s+by|blockchain audits\s*\||^_?note\s*:|^powered by|^copyright|^contents$|^table of|^contact|^https?://|@|\b(?:was commissioned|puts the|likelihood|all rights reserved)\b', s, re.I))
            or bool(re.fullmatch(r'(?:(?:smart\s*)?contracts?|security|code|audit|review|assessment|analysis|report|findings|circuits?|solidity|confidential|private|public)(?:\s+(?:report|audit|review|assessment|analysis|findings|for|of|by))*', s, re.I)))


def source_client(text, current, publisher_names=()):
    """Bind a cover banner to the name above it, stopping at author/date text."""
    lines = [clean(s) for s in text.split('\f')[0][:6000].splitlines() if clean(s)]
    publishers = {norm(s) for s in publisher_names}
    def author_banner(value):
        key=norm(value)
        # OCR can insert vertical strokes in a publisher logo. This is only a
        # rejection rule for author/service banners, never a project alias join.
        strokes=str.maketrans('', '', 'il')
        return (bool(re.search(r'application|security|audit|review|assessment', value or '', re.I))
                and any(len(p)>=5 and (p in key or p.translate(strokes) in key.translate(strokes)) for p in publishers))
    banner = r'(?:[A-Z]{2,8}\s+)?(?:(?:smart\s*contracts?|code|security|comprehensive|application)\s+)*(?:audit|review|assessment|analysis)(?:\s+(?:report|findings))?'
    for i, line in enumerate(lines[:28]):
        if re.fullmatch(banner, line, re.I):
            prior = []
            for s in reversed(lines[max(0, i-4):i]):
                if (boilerplate(s) or norm(s) in publishers or author_banner(s) or len(s) > 110
                        or re.search(r'\b(?:version|prepared|confidential|final|\d{4})\b|https?://|@|^v\.?\s*\d', s, re.I)):
                    break
                prior.insert(0, s)
            value = clean(' '.join(prior))
            if value and len(value) < 150:
                return dict(value=value, method='source_bound_cover_client', confidence=.995, page=1,
                            evidence='\n'.join(prior+[line]))
    # A heading label may have its value on the next line (REPORT FOR, etc.).
    for i, line in enumerate(lines[:40]):
        if re.fullmatch(r'(?:report\s+for|client(?:\s+(?:firm|name))?|project\s+name)\s*:?', line, re.I) and i+1 < len(lines):
            value = lines[i+1]
            if not boilerplate(value) and norm(value) not in publishers and len(value) < 120:
                return dict(value=value, method='source_bound_client_label', confidence=.99, page=1,
                            evidence=line+'\n'+value)
    return None if boilerplate(current.get('value')) or author_banner(current.get('value')) else current


def report_url_key(value):
    url=urlsplit(value or '')
    if url.scheme not in {'https','http'} or not url.hostname:
        return None
    return url.hostname.lower().removeprefix('www.')+unquote(url.path).rstrip('/')+('?' + url.query if url.query else '')


def report_aliases(root,doc):
    """Explicit HTML canonical metadata, read only from hash-addressed originals.

    These are report aliases, never project/protocol domains. No URL is fetched.
    The originals directory may be the declared symlink in a captured replay.
    """
    digest=doc.get('sha256')
    if doc.get('file_format')!='html' or not digest or not re.fullmatch(r'[a-f0-9]{64}',digest):
        return []
    base=(Path(root)/'local-cache/originals').resolve()
    originals=sorted((base/digest[:2]).glob(digest+'.*'))
    if not originals:
        return []
    path=originals[0]
    if not path.resolve().is_relative_to(base) or path.stat().st_size>32*1024*1024:
        return []
    body=path.read_bytes()
    if hashlib.sha256(body).hexdigest()!=digest:
        raise ValueError('Report alias original hash mismatch: '+digest)
    aliases=[]
    class Parser(HTMLParser):
        def handle_starttag(self,tag,attrs):
            attrs=dict(attrs)
            value=kind=None
            if tag=='link' and 'canonical' in (attrs.get('rel') or '').lower().split():
                value,kind=attrs.get('href'),'canonical'
            elif tag=='meta' and (attrs.get('property') or attrs.get('name') or '').lower()=='og:url':
                value,kind=attrs.get('content'),'og:url'
            key=report_url_key(value)
            if key:
                aliases.append(dict(url=value,key=key,kind=kind,original_sha256=digest))
    Parser().feed(body.decode('utf-8','replace'))
    return sorted({(x['key'],x['kind']):x for x in aliases}.values(),key=lambda x:(x['key'],x['kind']))


def repository(value):
    m = re.match(r'https?://(github\.com|gitlab\.com)/([\w.-]+)/([\w.-]+)', value, re.I)
    if not m:
        return None
    owner, name = m[2].lower(), m[3].lower().removesuffix('.git')
    if (re.search(r'audit|report|publication|findings|judging|securityreview', name)
            or owner in {'openzeppelin', 'crytic', 'foundry-rs', 'certora', 'solady', 'transmissions11'}):
        return None
    return m[1].lower()+'/'+owner+'/'+name


def entity(value):
    """No token/substring or fuzzy name keys: preserve the full client entity."""
    s = clean(value).split(':', 1)[0]
    s = re.sub(r'\s+(?:security\s+)?(?:audit|review|assessment|analysis|findings)(?:\s+report)?\b.*$', '', s, flags=re.I)
    s = re.sub(r'\s+(?:v\d+(?:\.\d+)*|version\s+\d+(?:\.\d+)*)\s*$', '', s, flags=re.I)
    return norm(s) if not boilerplate(s) else None


def evidence(text, doc, meta, aliases=()):
    """Extract explicit scope sections and report-family declarations as data."""
    text = unicodedata.normalize('NFKC', text).replace('\u200b', '').replace('\u00ad', '')
    plain = text.replace('__', '').replace('**', '').replace('`', '')
    front = plain[:50000]
    # TOC rows have dot leaders. Detailed findings and test appendices cannot
    # supply scope: shared coverage/test output caused the false merges in v5.
    blocks = []
    for m in re.finditer(r'(?im)^[^\n]{0,25}(?:audit scope(?: & methodology)?|scope(?: of (?:the )?(?:audit|review))?|repositories|repository|codebase|security review summary|project overview)\s*[:|]?\s*$', front):
        block = front[m.end():m.end()+7500]
        block = re.split(r'(?im)^\s*(?:#{1,4}\s*)?(?:\d+(?:\.\d+)*\s+)?(?:findings(?: & resolutions)?|detailed findings|smart contract risk assessment|test(?:ing| coverage)|appendi\w*)\s*$', block)[0]
        blocks.append(block)
    for m in re.finditer(r'(?im)^.*\b(?:repository|repositories|codebase|repo)\b[^\n]*(?:\n[^\n]*){0,3}', front):
        if not re.search(r'fix|patch|remediat|previous|prior|reference', m[0], re.I):
            blocks.append(m[0])
    scope = '\n'.join(blocks)
    repos = {repository(u) for u in re.findall(r'https?://(?:github\.com|gitlab\.com)/[\w.-]+/[\w.-]+', scope)}
    repos.discard(None)
    files = sorted(set(re.findall(r'\b([A-Za-z][\w.-]*\.(?:sol|rs|vy|go|cairo|move|fc|tact))\b', scope)))
    # Common libraries/proxies are not substantive agreement between two scopes.
    assets = [f for f in files if not re.match(r'I[A-Z]', f) and not re.search(r'^I?ERC\d|proxy|upgradeable|ownable|safemath|safeerc|reentrancyguard', f, re.I)]
    domains = []
    for m in re.finditer(r'(?im)^(?:[ #|]*)?(?:project\s+(?:website|domain|url)|client\s+(?:website|domain)|website|homepage)\s*[:|]\s*(https?://[^\s|)>]+)', plain[:24000]):
        host = urlsplit(m[1]).hostname
        if host and host not in {'github.com', 'gitlab.com'}:
            domains.append(dict(value=host.lower().removeprefix('www.'), evidence=m[0]))
    names = []
    client = meta['client']
    if entity(client.get('value')) and client.get('method') not in {'catalog_unverified', 'filename_fallback', 'unavailable'}:
        names.append(dict(value=entity(client['value']), evidence=client))
    for pattern in [r'(?im)^[ \t]*Client(?:[ \t]+(?:Firm|Name))?(?:[ \t]*[:|][ \t]*|[ \t]{2,})([^\n|]{2,100})',
                    r'(?i)\b([A-Z][\w .&-]{1,65}?)\s+(?:engaged|commissioned)\s+[^.\n]{2,70}?\s+to\s+(?:review|audit|assess|perform|conduct)']:
        for m in re.finditer(pattern, plain[:14000]):
            value = clean(m[1])
            if entity(value) and not re.search(r'\b(?:the|this|team|report|audit)\b', value, re.I):
                names.append(dict(value=entity(value), evidence=m[0]))
    result = dict(version=VERSION, rules_sha256=RULES_SHA256, entities=names,
                  repositories=sorted(repos), scope_files=files, scope_assets=assets,
                  domains=domains, declarations=[], mitigation_targets=[])
    result['canonical_report_urls']=list(aliases)
    result['report_url_key']=report_url_key(doc.get('public_url'))
    result['scope_versions'] = sorted(set(re.findall(r'(?im)^\s*(?:Version|(?:Initial|Audited)\s+(?:Commit|Revision))\s*[:|]?\s+([a-f0-9]{7,40})\b', scope)))
    result['substantive_titles'] = []
    result['scope_git_refs'] = []
    for m in re.finditer(r'(https?://(?:github\.com|gitlab\.com)/[\w.-]+/[\w.-]+/(?:tree|commit)/[^\s)\]]+)\s*\(([a-f0-9]{7,40})\)', front, re.I):
        if repository(m[1]):
            result['scope_git_refs'].append(dict(url=m[1],commit=m[2].lower(),evidence=m[0]))
    # Numbered finding headings survive PDF extraction without Markdown/severity
    # prefixes. Restrict them to the detailed-findings chapter, excluding the TOC.
    for m in re.finditer(r'(?im)^\s*(\d+)\.\s+Detailed Findings\b', plain):
        chapter = m[1]
        section = plain[m.end():m.end()+25000]
        section = re.split(r'(?m)^\s*'+str(int(chapter)+1)+r'\.\s+[A-Za-z]', section)[0]
        for title in re.findall(r'\b'+chapter+r'\.\d+\.\s+([^\n]{20,180})', section):
            title=re.sub(r'\s{2,}\d+\s*$', '', title)
            if not re.search(r'\.{3,}', title) and len(title.split()) >= 4:
                result['substantive_titles'].append(norm(title))
    # Native source routes identify an edition, independent of HTML/MD/PDF.
    url = unquote(doc.get('public_url') or '')
    slug = re.search(r'(?:code4rena\.com/reports/|github\.com/code-423n4/)(20\d{2}-\d{2}-[^/\s]+)', url)
    result['report_routes'] = ['c4:'+re.sub(r'-findings$', '', slug[1])] if slug else []
    parts=urlsplit(url).path.strip('/').split('/')
    if urlsplit(url).hostname=='github.com' and len(parts)>=6 and parts[2] in {'blob','raw'}:
        container='/'.join(parts[:2]+parts[4:-1])
        if parts[-2].lower() not in {'reports','audits','audit-reports','publications'}:
            result['source_container']=container
    route = re.search(r'/audits/(20\d{2}/\d{2}/[^/\s]+)', url)
    if route:
        result['report_routes'].append('audit-route:'+route[1])
    # One competition, many implementation-specific reports. The entire named
    # competition/period statement is retained; no implementation allowlist.
    narrative = clean(plain[:50000])
    m = re.search(r'hosted a competition based on[^.]{1,300}\.\s*The\s+present report focuses\s+(?:in|on)\s+[^.]{1,150}implementation', narrative[:22000], re.I)
    if m:
        start = max(narrative.rfind('.', 0, m.start())+1, m.start()-180)
        quote = narrative[start:m.end()]
        result['declarations'].append(dict(kind='implementation_parts', key=norm(quote.split('The present report')[0]), evidence=quote))
    m = re.search(r'(?:The\s+)?developers asked us to split[^.]{1,300}submodules[^.]{0,150}\.', narrative[:22000], re.I)
    if m:
        result['declarations'].append(dict(kind='split_submodules', key=norm(m[0]), evidence=m[0]))
    m = re.search(r'formal verification[^.]{0,200}(?:additional|associated) deliverable[^.]{0,150}\.', narrative, re.I)
    if m:
        result['declarations'].append(dict(kind='additional_fv_deliverable', key='fv', evidence=m[0]))
    cohort = re.search(r'(github\.com/[^/]+/fellowship-audits)/(?:blob|raw)/[^/]+/(block_\d+/week_\d+)/', url)
    if cohort:
        result['cohort'] = cohort[1]+'/'+cohort[2]
    result['team_report'] = bool(re.search(r'(?:Prepared By\s*:.*Team\s*\d|Audit by Team\s*\d)', plain[:3000], re.I))
    result['team_summary'] = bool(re.search(r'\b(?:\d+|six|seven|eight|ten)\s+teams\s+of\s+\d+\s+total auditors', plain[:4000], re.I))
    mitigation = re.search(r'(?:engaged|commissioned)[^.]{0,160}review\s+(?:the\s+)?remediation\s+of\s+[^.]{0,150}(?:prior|previous)\s+engagement[^.]*', plain[:6000], re.I)
    result['mitigation_only'] = mitigation[0] if mitigation else None
    for m in re.finditer(r'(?:Following\s+the[^.]{0,100}audit|mitigation\s+review)[^.]{0,450}mitigated\s+code', plain, re.I):
        quote=plain[m.start():m.end()+450]
        for target in re.findall(r'https?://[^\s)>\]]+', quote):
            result['mitigation_targets'].append(dict(url=target.rstrip('.,'), evidence=quote))
    return result


def dates(doc, role='audit_completion'):
    return {c['date_value'] for c in doc['metadata'].get('dates', []) if c.get('date_value') and c['role'] == role and c.get('confidence', 0) >= .8}


def same_day(a, b):
    da = dates(a) or dates(a, 'report_issue')
    db = dates(b) or dates(b, 'report_issue')
    return bool(da & db)


def halborn_projects(doc):
    """Exact declared client names, for cross-era Halborn renderings only."""
    if doc.get('publisher_id') != 'halborn':
        return set()
    meta=doc['metadata']
    values=[meta.get('client',{}).get('value')]
    values += [x.get('value') for x in meta.get('project_identity',{}).get('entities',[])]
    # The website catalogue's company is the publisher's explicit client.
    if 'halborn.com/audits/' in (doc.get('public_url') or ''):
        values.append(doc.get('provenance',{}).get('source_row',{}).get('project_hint') or doc.get('project'))
    return {entity(v) for v in values if entity(v)}


def family_relation(a, b):
    if a['publisher_id'] != b['publisher_id']:
        return None
    ma, mb = a['metadata'], b['metadata']
    pa, pb = ma.get('project_identity', {}), mb.get('project_identity', {})
    ra, rb = ma.get('source_relationships', {}), mb.get('source_relationships', {})
    ca, cb = set(ra.get('initial_commits', [])), set(rb.get('initial_commits', []))
    shared_commit = any(x.startswith(y) or y.startswith(x) for x in ca for y in cb)
    aliases_a={x['key'] for x in pa.get('canonical_report_urls',[])}
    aliases_b={x['key'] for x in pb.get('canonical_report_urls',[])}
    canonical=(aliases_a & (aliases_b|{pb.get('report_url_key')})) | (aliases_b & {pa.get('report_url_key')})
    shared_assets=set(pa.get('scope_assets',[])) & set(pb.get('scope_assets',[]))
    origins=[('website' if 'halborn.com/audits/' in (d.get('public_url') or '') else
              'github' if 'github.com/HalbornSecurity/PublicReports/' in (d.get('public_url') or '') else None) for d in (a,b)]
    # Same publisher-declared project and exact engagement date bind website
    # and GitHub renderings. Neither a month nor fuzzy token overlap suffices.
    if (a['publisher_id']=='halborn' and set(origins)=={'website','github'}
            and halborn_projects(a) & halborn_projects(b)):
        exact_days=[{x for x in (dates(d) or dates(d,'report_issue')) if len(x)==10} for d in (a,b)]
        if exact_days[0] & exact_days[1]:
            return 'halborn_website_github_same_project_and_engagement_day'
    if canonical and same_day(a,b) and (shared_commit or len(shared_assets)>=2):
        return 'source_canonical_report_alias_and_scope'
    for x in pa.get('declarations', []):
        for y in pb.get('declarations', []):
            if (x['kind'], x['key']) == (y['kind'], y['key']):
                if x['kind'] == 'implementation_parts' and same_day(a, b):
                    return 'explicit_competition_implementation_parts'
                if x['kind'] == 'split_submodules' and shared_commit and dates(a, 'report_issue') & dates(b, 'report_issue'):
                    return 'explicit_split_submodule_report_family'
    # Different report parts can have different source repositories and commits.
    # A complete dated/versioned native basename plus the audit's explicit
    # additional-deliverable statement binds the otherwise differently scoped FV.
    bases = [re.sub(r'(?i)[-_]FV(?=[-_.])', '', Path(unquote(d.get('filename') or '')).stem) for d in (a, b)]
    if norm(bases[0]) == norm(bases[1]) and len(norm(bases[0])) >= 12 and re.search(r'20\d{2}', bases[0]):
        declarations = pa.get('declarations', [])+pb.get('declarations', [])
        if any(x['kind'] == 'additional_fv_deliverable' for x in declarations) and any('FV' in (d.get('filename') or '') for d in (a, b)):
            return 'explicit_additional_formal_verification_deliverable'
    ea, eb = entity(ma['client'].get('value')), entity(mb['client'].get('value'))
    if pa.get('cohort') and pa.get('cohort') == pb.get('cohort') and ea and eb and (ea == eb or min(len(ea), len(eb)) >= 6 and (ea in eb or eb in ea)):
        return 'source_fellowship_cohort_report_parts'
    same_container=pa.get('source_container') and pa.get('source_container')==pb.get('source_container')
    if ((pa.get('team_summary') and pb.get('team_report') or pb.get('team_summary') and pa.get('team_report'))
            and (ea and ea == eb or same_container) and shared_commit and same_day(a, b)):
        return 'explicit_multiteam_summary_component'
    routes = set(pa.get('report_routes', [])) & set(pb.get('report_routes', []))
    if routes and same_day(a, b):
        if any(k.startswith('c4:') for k in routes):
            return 'same_official_contest_report_route'
        sa, sb = set(ra.get('sketch', [])), set(rb.get('sketch', []))
        if len(sa & sb) >= 8 or shared_commit:
            return 'same_publisher_report_route_and_content'
    versions = set(pa.get('scope_versions', [])) & set(pb.get('scope_versions', []))
    headings = set(pa.get('substantive_titles', [])) & set(pb.get('substantive_titles', []))
    sa, sb = set(ra.get('sketch', [])), set(rb.get('sketch', []))
    if (versions and headings and same_day(a, b) and set(pa.get('repositories', [])) & set(pb.get('repositories', []))
            and len(sa & sb)/max(1, min(len(sa), len(sb))) >= .45):
        return 'source_scoped_version_and_findings_revision'
    # Translation filenames encode a language relationship, not different scope.
    def language_base(d):
        base = Path(unquote(d.get('filename') or '')).stem
        return norm(re.sub(r'(?i)([-_ ])(?:en|cn|zh|english|chinese)(?=[-_ ]|$)', '', base))
    git_refs_a={(x['url'],x['commit']) for x in pa.get('scope_git_refs',[])}
    git_refs_b={(x['url'],x['commit']) for x in pb.get('scope_git_refs',[])}
    if language_base(a) == language_base(b) and a.get('filename') != b.get('filename') and (shared_commit or git_refs_a & git_refs_b) and same_day(a, b):
        if re.search(r'(?i)[-_ ](?:en|cn|zh|english|chinese)(?=[-_ .]|$)', (a.get('filename') or '')+' '+(b.get('filename') or '')):
            return 'source_language_variant_same_scope'
    return None


def scope_conflict(a, b):
    """Different implementation assets cannot merge via proxy/template overlap."""
    pa, pb = (d['metadata'].get('project_identity', {}) for d in (a, b))
    aa, ab = set(pa.get('scope_assets', [])), set(pb.get('scope_assets', []))
    aa, ab = {norm(x) for x in aa}, {norm(x) for x in ab}
    return bool(aa and ab and not aa & ab)


def candidate_keys(doc):
    p = doc['metadata'].get('project_identity', {})
    keys = [('report_route', x) for x in p.get('report_routes', [])]
    keys += [('canonical_report_url',x['key']) for x in p.get('canonical_report_urls',[])]
    if p.get('report_url_key'):
        keys.append(('canonical_report_url',p['report_url_key']))
    keys += [('declaration', x['kind']+':'+x['key']) for x in p.get('declarations', [])]
    keys += [('entity', x['value']) for x in p.get('entities', [])]
    keys += [('halborn_project', x) for x in sorted(halborn_projects(doc))]
    keys += [('scope_version', x[:7]) for x in p.get('scope_versions', [])]
    keys += [('source_git_ref', x['url']+'@'+x['commit']) for x in p.get('scope_git_refs', [])]
    if p.get('cohort'):
        keys.append(('cohort', p['cohort']))
    base = re.sub(r'(?i)[-_]FV(?=[-_.])', '', Path(unquote(doc.get('filename') or '')).stem)
    if len(norm(base)) >= 18:
        keys.append(('deliverable_basename', norm(base)))
    return keys


def mitigation_parent(review, candidates):
    """Explicit fix-only work attaches to its latest preceding supported scope."""
    p = review['metadata'].get('project_identity', {})
    if not p.get('mitigation_only'):
        return None
    ends = dates(review) or dates(review, 'report_issue')
    exact = [date.fromisoformat(x) for x in ends if len(x) == 10]
    if not exact:
        return None
    end = min(exact)
    parents = []
    entities = {x['value'] for x in p.get('entities', [])}
    for other in candidates:
        q = other['metadata'].get('project_identity', {})
        if other['document_id'] == review['document_id'] or other['publisher_id'] != review['publisher_id'] or other['doc_kind'] == 'fix_review':
            continue
        if not entities & {x['value'] for x in q.get('entities', [])} or not set(p.get('repositories', [])) & set(q.get('repositories', [])):
            continue
        for d in dates(other) or dates(other, 'report_issue'):
            if len(d) == 10 and 0 < (end-date.fromisoformat(d)).days <= 120:
                parents.append((d, other['document_id']))
    if not parents:
        return None
    latest = max(d for d, _ in parents)
    return sorted({did for d, did in parents if d == latest})
