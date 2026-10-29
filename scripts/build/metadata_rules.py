"""Offline, LLM-free report metadata rules. No source data is executable.

Rules are developed only against non-holdout examples. Extraction itself is uniform,
including held-out artifacts; this module deliberately has no holdout-specific rules.
"""
from __future__ import annotations

from datetime import date, datetime
from html.parser import HTMLParser
import hashlib
import json
from pathlib import Path
import re
import unicodedata
import uuid

RULE_VERSION = 'phase3-rules-7'
RULES_SHA256 = hashlib.sha256(b''.join(Path(__file__).with_name(name).read_bytes() for name in ['metadata_rules.py','date_rules.py','date_layout_rules.py','period_rules.py','engagement_rules.py','relationship_rules.py'])).hexdigest()
AS_OF = date(2026, 10, 22)
MONTH = r'(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?'
DATE = re.compile(r'(?<!\d)(?:20\d{2}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[./-]\d{1,2}[./-]20\d{2}|'
                  + MONTH + r'[,]?\s*\d{1,2}(?:st|nd|rd|th)?[,]?\s+20\d{2}|\d{1,2}(?:st|nd|rd|th)?\s+' + MONTH + r'[,]?\s+20\d{2}|'
                  + MONTH + r'[,]?\s+20\d{2}|20\d{2}[-/]\d{2})(?!\d)', re.I)
SHORT_PERIOD = re.compile('('+MONTH+r')\s*(\d{1,2})(?:st|nd|rd|th)?\s*(?:-|–|—|and|to|through|until)\s*(?:('+MONTH+r')\s*)?(\d{1,2})(?:st|nd|rd|th)?[,]?\s+(20\d{2})',re.I)
REPORT = re.compile(r'\b(audit|(?:security|code)\s+(?:review|assessment|analysis)|formal\s+verification|penetration\s+test)\b', re.I)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).translate({0x85:r'\u0085',0x2028:r'\u2028',0x2029:r'\u2029'})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def normalize(value):
    return re.sub(r'[^a-z0-9]', '', unicodedata.normalize('NFKD', value or '').encode('ascii', 'ignore').decode().lower())


def clean(value):
    return re.sub(r'\s+', ' ', str(value or '')).strip(' \t\n:#*|–—-')


def field(value=None, method='unavailable', confidence=0.0, page=None, evidence=None):
    return dict(value=value or None, method=method, confidence=confidence, page=page, evidence=evidence)


def parse_date(raw):
    text = clean(re.sub(r'(?<=\d)(st|nd|rd|th)\b', '', raw, flags=re.I)).replace(',', '')
    text = re.sub(r'\bSept\b', 'Sep', text, flags=re.I)
    text = re.sub(r'\.(?=\s)', '', text)
    formats = [('%Y-%m-%d', 'day'), ('%Y/%m/%d', 'day'), ('%Y.%m.%d', 'day'),
               ('%B %d %Y', 'day'), ('%b %d %Y', 'day'), ('%d %B %Y', 'day'), ('%d %b %Y', 'day'),
               ('%B %Y', 'month'), ('%b %Y', 'month'), ('%Y-%m', 'month'), ('%Y/%m', 'month'), ('%Y', 'year')]
    # Day-first numeric dates are supported only when ordering is unambiguous.
    m = re.fullmatch(r'(\d{1,2})[./-](\d{1,2})[./-](20\d{2})', text)
    if m and (int(m[1]) > 12 or int(m[1]) == int(m[2])):
        formats += [('%d.%m.%Y', 'day'), ('%d/%m/%Y', 'day'), ('%d-%m-%Y','day')]
    elif m and int(m[2]) > 12:
        formats += [('%m.%d.%Y', 'day'), ('%m/%d/%Y', 'day'), ('%m-%d-%Y','day')]
    for fmt, precision in formats:
        try:
            value = datetime.strptime(text, fmt).date()
            if date(2000, 1, 1) <= value <= AS_OF:
                return value.isoformat()[:{'day': 10, 'month': 7, 'year': 4}[precision]], precision
        except ValueError:
            pass
    return None, 'none'


class VisibleHTML(HTMLParser):
    """Prefer report article/main; retain date metadata independently of layout."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.article, self.titles, self.dates = [], [], [], []
        self.hidden = 0
        self.depth = 0
        self.h1 = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {'script', 'style', 'noscript', 'svg'}:
            self.hidden += 1
        if tag in {'article', 'main'}:
            self.depth += 1
        if tag == 'h1':
            self.h1 += 1
        if tag in {'p', 'div', 'h1', 'h2', 'h3', 'tr', 'li', 'br', 'section'}:
            self.parts.append('\n')
            if self.depth:
                self.article.append('\n')
        if tag == 'meta':
            name = attrs.get('property') or attrs.get('name')
            if name in {'article:published_time', 'datePublished', 'date', 'pubdate'} and attrs.get('content'):
                self.dates.append(attrs['content'])

    def handle_endtag(self, tag):
        if tag in {'script', 'style', 'noscript', 'svg'}:
            self.hidden = max(0, self.hidden - 1)
        if tag in {'article', 'main'}:
            self.depth = max(0, self.depth - 1)
        if tag == 'h1':
            self.h1 = max(0, self.h1 - 1)

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)
            if self.depth:
                self.article.append(data)
            if self.h1:
                self.titles.append(data)


def atomic(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    temp.write_text(text, encoding='utf-8')
    temp.replace(path)


def read_text(root, doc):
    """Use an existing text cache verbatim; otherwise extract PDF pages 1–3."""
    root = Path(root)
    digest = doc.get('sha256')
    if not digest or not re.fullmatch(r'[0-9a-f]{64}', digest):
        return '', {'status': 'no_original_hash', 'method': 'none'}
    cache = root / 'local-cache/text' / (digest + '.txt')
    receipt = cache.with_suffix('.receipt.json')
    if cache.is_file():
        text = cache.read_text(encoding='utf-8', errors='replace')
        info = json.loads(receipt.read_text()) if receipt.exists() else {'method': 'existing_text_cache', 'pages': 'unknown'}
        return text, {**info, 'status': 'ok' if text.strip() else 'empty_text', 'text_sha256': sha(text.encode())}
    original = root / str(doc.get('local_path') or '')
    if not doc.get('local_path') or not original.is_file():
        # Firm exports sometimes share bytes with a collected cache artifact.
        candidates = sorted((root / 'local-cache/originals' / digest[:2]).glob(digest + '.*'))
        original = candidates[0] if candidates else None
    if not original:
        return '', {'status': 'original_unavailable', 'method': 'none'}
    if not original.resolve().is_relative_to((root / 'local-cache').resolve()):
        return '', {'status': 'invalid_local_path', 'method': 'none'}
    body = original.read_bytes()
    if sha(body) != digest:
        return '', {'status': 'original_hash_mismatch', 'method': 'none'}
    info = {'original_sha256_verified': True}
    try:
        if body.startswith(b'%PDF'):
            import pymupdf
            pymupdf.TOOLS.mupdf_display_errors(False)
            pymupdf.TOOLS.mupdf_display_warnings(False)
            pymupdf.TOOLS.mupdf_warnings()
            with pymupdf.open(stream=body, filetype='pdf') as pdf:
                text = '\f'.join(pdf[i].get_text(sort=True) for i in range(min(3, len(pdf))))
                info.update(method='pymupdf_first_three_pages', pages=list(range(1, min(3, len(pdf)) + 1)))
            warnings = pymupdf.TOOLS.mupdf_warnings()
            if warnings:
                info['parser_warnings'] = warnings[:500]
        elif doc.get('file_format') == 'html' or re.search(rb'<(?:!doctype|html)\b', body[:1000], re.I):
            parser = VisibleHTML()
            parser.feed(body.decode('utf-8', 'replace'))
            text = ''.join(parser.article if len(''.join(parser.article)) > 300 else parser.parts)
            info.update(method='html_visible_article', pages=None, html_title=clean(' '.join(parser.titles)), publication_dates=parser.dates)
        else:
            text = body.decode('utf-8', 'replace')
            info.update(method='utf8_text', pages=None)
        text = text.replace('\x00', '')
        # Recheck after extraction: another phase may have completed the shared cache.
        if not cache.exists():
            atomic(cache, text)
            atomic(receipt, canonical(info) + '\n')
        else:
            return read_text(root, doc)
        return text, {**info, 'status': 'ok' if text.strip() else 'empty_text', 'text_sha256': sha(text.encode())}
    except Exception as exc:
        return '', {'status': 'extraction_failed', 'method': 'none', 'error': type(exc).__name__ + ': ' + str(exc)[:200]}


def opening_date_claims(text, receipt):
    claims = []
    seen = set()
    pages_known = isinstance(receipt.get('pages'), list)
    for page, body in enumerate(text.split('\f')[:3], 1):
        lines = [s for s in body.splitlines() if s.strip()]
        for i, line in enumerate(lines):
            short_period=SHORT_PERIOD.search(line)
            if short_period and re.search(r'audit|review|assessment|engagement|period',line,re.I):
                for month,day,role in [(short_period[1],short_period[2],'audit_start'),(short_period[3] or short_period[1],short_period[4],'audit_completion')]:
                    value,precision=parse_date(f'{month} {day} {short_period[5]}')
                    claims.append(dict(raw_value=short_period[0],date_value=value,precision=precision,role=role,basis='document_text',page=page if pages_known else None,method='explicit_abbreviated_audit_period',confidence=.95,evidence=clean(line)[:350]))
                continue
            matches = list(DATE.finditer(line))
            if not matches:
                continue
            # Repository names and commit-log revision/version rows are scope
            # history, never report datelines (even near a Date label).
            if re.search(r'github\s*:|gitlab\s*:',line,re.I) or re.match(r'\s*[a-f0-9]{7,40}\s+20\d{2}[-/.]',line,re.I):
                continue
            url_spans=[m.span() for m in re.finditer(r'https?://\S+',line)]
            matches=[m for m in matches if not any(start<=m.start()<end for start,end in url_spans)]
            if not matches:
                continue
            # Avoid unrelated copyright, references, generated-on dates and navigation.
            context = clean(' '.join(lines[max(0, i-1):i+2]))
            lower = context.lower()
            if re.search(r'copyright|©|all rights reserved|last (?:accessed|retrieved)|downloaded on', line, re.I):
                continue
            local = line.lower().replace('_',' ')
            previous = clean(lines[i-1]).lower().replace('_',' ') if i else ''
            if not clean(DATE.sub('',line)).strip(' ,|.-') and re.search(r'(?:date|completed|issued|published|period|timeline|updated)\s*[:|]?$',previous):
                local=previous+' '+local
            if re.search(r'generated|retrieved|downloaded|accessed|exported',local):
                continue
            role, method, confidence = 'other', 'unlabelled_date', .45
            if re.search(r'(?:report.{0,35}(?:publish|release)|(?:publish|release).{0,35}report|publication\s*date|date\s*published|^published\s*[:|])', local):
                role, method, confidence = 'publication', 'labelled_publication', .95
            elif re.search(r'(?:audit|review|assessment|test)\s*(?:end|complet)|end\s*date|completed\s*(?:on|at|:)|finalized', local):
                role, method, confidence = 'audit_completion', 'labelled_completion', .96
            elif re.search(r'(?:audit|review|assessment|test)\s*(?:start|began)|start\s*date', local):
                role, method, confidence = 'audit_start', 'labelled_start', .96
            elif re.search(r'retest|fix\s*(?:review|verification)|remediation', local):
                role, method, confidence = 'retest', 'labelled_retest', .9
            elif re.search(r'(?:audit|review|assessment|test)\s*(?:time\s*)?(?:period|timeline|dates)|(?:date of )?engagement\s*(?:period|dates|:)|^timeline\s*[:|]|conducted|performed', local):
                role, method, confidence = ('audit_completion' if len(matches)>1 or re.search(r'(?:between|to|through|until|ended|performed.+on)\b',local) else 'other'), 'labelled_period', .92
            elif re.search(r'report\s*date|date\s*(?:of|:)\s*(?:the\s*)?(?:report|issue)|issu(?:ed|e)|final\s*report|\bdate\s*[:|]|\bdate\s*$', local) and not re.search(r'(?:signature|digitally signed)', lower):
                role, method, confidence = 'report_issue', 'labelled_issue', .94
            elif re.search(r'\b(?:version|revision)\b', local):
                role, method, confidence = 'report_issue', 'report_revision_date', .85
            elif page==1 and i<15 and len(matches)==2 and re.fullmatch(r'[\s|,./–—-]*',DATE.sub('',line)):
                role,method,confidence='audit_completion','cover_period',.85
            elif i<15 and re.search(r'(?:audit|project|security) report.{0,100}'+re.escape(matches[0][0]),line,re.I):
                role,method,confidence='report_issue','dated_report_heading',.9
            elif page==1 and i<30 and re.fullmatch(r'[\s|,.-]*(?:v\.?|version|revision)\s*\d+(?:\.\d+)*',DATE.sub('',line),re.I):
                role,method,confidence='report_issue','cover_date_and_report_version',.9
            # A standalone date on a report cover is an issue date, never completion.
            elif page == 1 and i < 80 and not clean(DATE.sub('', line)).strip(' ,|.-') and len(clean(body))<5000:
                role, method, confidence = 'report_issue', 'cover_issue_date', .85
            # Metadata often puts the label on the previous line.
            elif re.search(r'(?:report\s*date|issued|date\s*[:|]?)\s*$', clean(' '.join(lines[max(0, i-2):i])), re.I):
                role, method, confidence = 'report_issue', 'preceding_issue_label', .9
            for j, match in enumerate(matches):
                value, precision = parse_date(match[0])
                this_role = 'audit_start' if method in {'labelled_period','cover_period'} and len(matches) > 1 and j == 0 else role
                key = (page, value or match[0], this_role)
                if key in seen:
                    continue
                seen.add(key)
                claims.append(dict(raw_value=match[0], date_value=value, precision=precision, role=this_role,
                                   basis='document_text', page=page if pages_known else None,
                                   method=method, confidence=confidence, evidence=context[:350]))
    for raw in receipt.get('publication_dates', []):
        value, precision = parse_date(raw[:10])
        claims.append(dict(raw_value=raw, date_value=value, precision=precision, role='publication', basis='document_text',
                           page=None, method='html_publication_meta', confidence=.99, evidence='HTML article:published_time/date metadata'))
    return claims


def date_claims(text, receipt):
    from date_rules import extended_date_claims, supplement_opening_dates
    return supplement_opening_dates(text,receipt,extended_date_claims(text,receipt))


def extract_intrinsic(text, receipt):
    pages = text.split('\f')
    # Existing full-text caches can be longer; metadata rules inspect only the opening.
    front = '\f'.join(pages[:3])[:65000]
    lines = [clean(s) for s in front.splitlines() if clean(s)]
    title = receipt.get('html_title')
    if not title:
        headings = [clean(s.lstrip('#')) for s in front.splitlines()[:70] if re.match(r'^#{1,2}\s+\S', s)]
        title = next((s for s in headings if REPORT.search(s) and len(s) < 180), None)
    if not title:
        title = next((s for s in lines[:30] if REPORT.search(s) and 8 < len(s) < 160
                      and not re.search(r'disclaimer|about\s|table of|contents|www\.|https?://|engaged|performed', s, re.I)), None)
    # Generic cover titles are usually preceded by the actual project name.
    title_index = next((i for i,s in enumerate(lines[:30]) if s==title), None)
    cover_client = None
    if title_index is not None and title_index > 0 and re.fullmatch(r'(?:smart contract |code |security )*(?:audit|assessment|review|analysis)(?: report)?', title, re.I):
        candidate = lines[title_index-1]
        if 2 <= len(candidate) <= 100 and not parse_date(candidate)[0] and not re.search(r'public|confidential|www\.|https?://|version|final', candidate, re.I):
            cover_client = candidate
            title = candidate + ' — ' + title
    client = None
    client_method = 'unavailable'
    for line in lines[:180]:
        m = re.match(r'(?:project(?:\s*name)?|client(?:\s*name)?|prepared\s*for|customer)\s*[:|]\s*(.{2,100})$', line, re.I)
        if m and not re.search(r'^(?:name|description|address|website|contact|the |this )\b', m[1], re.I):
            client, client_method = clean(m[1]), 'labelled_client'
            break
    if not client and title:
        m = re.search(r'(?:audit|security\s+(?:review|assessment)|formal\s+verification)\s+(?:of|for)\s+(.+)', title, re.I)
        if m:
            client, client_method = clean(m[1]), 'report_title_client'
    if not client:
        for line in front.splitlines()[:180]:
            m = re.match(r'\s*(?:client|project(?:\s+name)?)\s{2,}(.{2,100})$', line, re.I)
            if m:
                client, client_method = clean(m[1]), 'labelled_client'
                break
    if not client and cover_client:
        client, client_method = cover_client, 'cover_project_heading'
    versions = re.findall(r'\b(?:report\s*)?(?:version|revision|v\.)\s*[:|]?\s*(v?\d+(?:\.\d+){0,3}|final|draft)\b', front[:14000], re.I)
    version = versions[0] if versions else None
    audit_type = ('formal_verification' if re.search(r'formal\s+verification', front[:6000], re.I) else
                  'penetration_test' if re.search(r'penetration\s+test', front[:6000], re.I) else
                  'security_audit' if REPORT.search(front[:6000]) else None)
    languages = [v for v in ['Solidity', 'Vyper', 'Rust', 'Move', 'Cairo', 'Go', 'TypeScript', 'JavaScript', 'Python', 'Haskell', 'Yul', 'FunC', 'Tact', 'Clarity', 'C++']
                 if re.search(r'(?<![\w])' + re.escape(v) + r'(?![\w])', front)]
    # Go/Move are English words: require a programming/scope label for these.
    languages = [v for v in languages if v not in {'Go', 'Move'} or re.search(r'(?:language|written|code|contracts?)\s*[:|]?\s*(?:in\s+)?'+v+r'\b|\b'+v+r'\s+(?:language|contracts?|modules?)', front, re.I)]
    chain_labels = ['Ethereum', 'Solana', 'Arbitrum', 'Optimism', 'Polygon', 'Avalanche', 'Cosmos', 'Sui', 'Aptos', 'Starknet', 'Bitcoin', 'Polkadot', 'Near', 'TON', 'Tron', 'BNB Chain', 'BSC', 'Algorand', 'Tezos', 'Sei', 'Base']
    chains = [v for v in chain_labels if re.search(r'\b'+re.escape(v)+r'\b', front)]
    chains = [v for v in chains if v not in {'Base', 'Near', 'Sei'} or re.search(r'(?:chain|network|blockchain|deployed(?:\s+on)?)\s*[:|]?\s*'+v+r'\b|\b'+v+r'\s+(?:chain|network|blockchain)', front, re.I)]
    repositories = sorted(set(re.findall(r'https?://(?:github\.com|gitlab\.com)/[\w.-]+/[\w.-]+(?:/(?:tree|commit)/[a-f0-9]{7,40})?', front)))
    commits = sorted({h for line in front.splitlines() if not re.search(r'fix(?:es)? review|remediation',line,re.I)
                      for h in re.findall(r'(?i)(?:\b(?:commit|revision|hash)\s*(?:id)?\s*[:|`*_\s-]*\[?|/(?:tree|commit)/)([a-f0-9]{40})\b',line)})
    coauthors = [clean(m[1]) for m in re.finditer(r'(?im)^.{0,15}(?:co[- ]auditors?|jointly audited by|joint audit by)\s*[:|]?\s*(.{2,150})$', front)]
    parents = sorted({u for line in front.splitlines() if re.search(r'initial|original|parent|previous',line,re.I) and re.search(r'report|audit|review',line,re.I)
                      for u in re.findall(r'https?://[^\s)>\]]+',line)})
    result = dict(client=field(client, client_method, .95 if client_method=='labelled_client' else .8 if client else 0),
                report_title=field(title, 'document_title' if title else 'unavailable', .9 if title else 0, 1 if receipt.get('pages') else None),
                version=field(version, 'labelled_version' if version else 'unavailable', .9 if version else 0),
                audit_type=field(audit_type, 'document_scope' if audit_type else 'unavailable', .9 if audit_type else 0),
                chains=field(chains, 'explicit_text_mentions' if chains else 'unavailable', .7 if chains else 0),
                languages=field(languages, 'explicit_text_mentions' if languages else 'unavailable', .8 if languages else 0),
                repositories=field(repositories, 'document_repository_urls' if repositories else 'unavailable', .8 if repositories else 0),
                commits=field(commits, 'labelled_commit_hash' if commits else 'unavailable', .95 if commits else 0),
                co_auditors=field(coauthors, 'explicit_joint_auditor_label' if coauthors else 'unavailable', .95 if coauthors else 0),
                parent_report_urls=field(parents, 'explicit_parent_report_reference' if parents else 'unavailable', .95 if parents else 0),
                dates=date_claims(front, receipt),
                normalized_text_sha256=sha(re.sub(r'\W+', '', front.lower()).encode()) if len(front)>200 else None,
                text_receipt=receipt, rule_version=RULE_VERSION, rules_sha256=RULES_SHA256)
    structured = embedded_report(text)
    if structured:
        setup = structured.get('setup') or {}
        summary = structured.get('summary') or {}
        name = setup.get('projectName')
        repos = [r for r in setup.get('repos', []) if isinstance(r,dict) and not r.get('hidden')]
        result.update(structured_report=True, client=field(name, 'embedded_report.setup.projectName', .99),
                      report_title=field(name+' Security Audit' if name else None, 'embedded_report.setup.projectName', .95),
                      audit_type=field('security_audit', 'embedded_report_content', .99),
                      repositories=field(sorted({r['repoLink'] for r in repos if r.get('repoLink')}), 'embedded_report.setup.repos', .99),
                      commits=field(sorted({r['commit'] for r in repos if re.fullmatch(r'[a-f0-9]{40}',r.get('commit',''))}), 'embedded_report.setup.repos.commit', .99),
                      languages=field([k for k,v in (summary.get('languages') or {}).items() if v is True], 'embedded_report.summary.languages', .99), dates=[])
        timeline = summary.get('timeline') or {}
        items = [('summary.timeline.start',timeline.get('start'),'audit_start'),('summary.timeline.end',timeline.get('end'),'audit_completion')]
        items += [(f'summary.changeLogArray[{i}]',r.get('date'),'report_issue') for i,r in enumerate(summary.get('changeLogArray') or []) if isinstance(r,dict)]
        for path,raw,role in items:
            if raw:
                value,precision = parse_date(raw[:10])
                result['dates'].append(dict(raw_value=raw, date_value=value, precision=precision, role=role, basis='document_text', page=None, method='embedded_report.'+path, confidence=.99, evidence=path))
    # Locate each scalar's literal evidence when the extraction retained page bounds.
    for key in ['client','report_title','version','chains','languages','repositories','commits','co_auditors']:
        item=result[key]
        value=item['value']
        if value:
            needles=value if isinstance(value,list) else [value]
            hits=[]
            for page,body in enumerate(pages[:3],1):
                for line in body.splitlines():
                    if any(str(needle) in line for needle in needles):
                        hits.append({'page':page if isinstance(receipt.get('pages'),list) else None,'text':clean(line)[:250]})
                        break
            if hits:
                item['page']=hits[0]['page']
                item['evidence']=hits
    return result


def embedded_report(text):
    """Decode a JSON.parse string literal without evaluating JavaScript."""
    match = re.search(r"JSON\.parse\('((?:\\.|[^'\\])*)'\)", text, re.S)
    if not match:
        return None
    def unescape(m):
        value = m[1]
        if value[0] in {'u','x'}:
            return chr(int(value[1:],16))
        return {'n':'\n','r':'\r','t':'\t','b':'\b','f':'\f','v':'\v','0':'\x00'}.get(value,value)
    try:
        literal = re.sub(r'\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)', unescape, match[1], flags=re.S)
        value = json.loads(literal)
        report = value.get('reportContent') if isinstance(value,dict) else None
        return report if isinstance(report,dict) and isinstance(report.get('setup'),dict) else None
    except (ValueError,TypeError):
        return None


def process_artifact(args):
    root, doc = args
    text, receipt = read_text(root, doc)
    meta = extract_intrinsic(text, receipt)
    from date_rules import load_date_text, extended_date_claims
    complete, date_receipt = load_date_text(root, doc['sha256'], text, receipt)
    meta['date_text_receipt'] = date_receipt
    # Full text is always parsed: a cover issue date must not hide completion.
    if not meta.get('structured_report'):
        from date_rules import supplement_opening_dates
        meta['dates'] = supplement_opening_dates(text, receipt, meta['dates'] + extended_date_claims(complete, date_receipt))
    from engagement_rules import content_kind, project_from_text, report_content
    candidate = project_from_text(text, meta)
    if not candidate:
        candidate = project_from_text(complete, meta)
    from engagement_rules import generic_project
    if candidate and (generic_project(meta['client']['value']) or candidate['confidence'] >= meta['client']['confidence']):
        meta['client'] = candidate
    if generic_project(meta['client']['value']):
        meta['client'] = field()
    meta['content_kind'] = content_kind(complete, meta, doc.get('file_format'))
    meta['report_content'] = report_content(complete)
    from relationship_rules import source_relationships
    meta['source_relationships'] = source_relationships(complete)
    parent_urls=set(meta['parent_report_urls']['value'] or [])
    for m in re.finditer(r'(?im)^.*(?:initial|original|parent|previous).{0,60}(?:report|audit|review).*(?:\n[^\n]*){0,2}',complete):
        parent_urls.update(re.findall(r'https?://[^\s)>\]]+',m[0]))
    if parent_urls:
        meta['parent_report_urls']=field(sorted(parent_urls),'explicit_parent_report_reference',.95)
    # Intrinsic period semantics are cached once per original, including in the
    # parallel warm pass. Occurrence-specific LLM proposals are revalidated by
    # the builder, without serially re-parsing every unchanged original.
    from phase3_engagements import source_year_claims
    source_year_claims(root,doc,meta)
    if not meta.get('structured_report'):
        from period_rules import reconcile_source_periods
        sources=[(text,receipt)]
        if date_receipt.get('text_sha256')!=receipt.get('text_sha256'):
            sources.append((complete,date_receipt))
        reconcile_source_periods(meta['dates'],sources)
    meta['source_periods_resolved']=True
    return doc['sha256'], meta
