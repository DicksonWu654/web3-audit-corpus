"""Verichains section-aware findings across the 2018–2026 layouts."""
from core import SeverityLookup, severity, Candidate, clean, field_severity
import re
DESCRIPTION = 'Finding/recommendation sections, legacy 2.n and modern 3.n headings; textual risk/status labels; icon risks remain unknown'
RISK = r'(?:VERY LOW|INFORMATIONAL|INFORMATIVE|CRITICAL|MEDIUM|HIGH|LOW|INFO)'
NUMBER = re.compile(r'^(\d+(?:\.\d+)*)\.?\s+(.+)')
SECTION = re.compile(r'^(?:(?:Draft|Code Review|Solana)\s+)?Findings$|^(?:Additional (?:notes|information) and recommendations|DISCOVERED VULNERABILITIES|AUDIT RESULTS?)$',re.I)


def _text(s):
    return re.sub(r'^[✔✓]\s*','',s.replace('\u200b','').replace('\u2060','').replace('\ufeff',''))


def _tocpages(report):
    return {p['page'] for p in report.meta['pages'] if re.search(r'TABLE\s+OF\s+CONTENTS',p['text'],re.I) or sum(bool(re.search(r'\.{4}|(?:\. ){4}',line)) for line in p['text'].splitlines())>=3}


def _is_toc(line,pages):
    return line.page in pages or bool(re.search(r'(?:\.\s*){3,}\s*\d+\s*$',_text(line.text)))


def _sections(report, toc=False):
    pages=_tocpages(report);out={}
    for l in report.lines:
        if (l.page in pages) != toc: continue
        m=NUMBER.match(_text(l.content))
        if not m: continue
        title=re.split(r'(?:\.\s*){3,}',m[2])[0].strip()
        if SECTION.fullmatch(title): out[m[1]]=title
    return {k:v for k,v in out.items() if not any(q.startswith(k+'.') for q in out)}


def _toc_entries(report):
    pages=_tocpages(report); sections=_sections(report,True); out=[]
    for i,l in enumerate(report.lines):
        if l.page not in pages:continue
        m=NUMBER.match(_text(l.content))
        if not m:continue
        pid,title=m.groups();parent=pid.rsplit('.',1)[0]
        if '.' not in pid or parent not in sections:continue
        title=re.split(r'(?:\.\s*){3,}',title)[0].strip()
        # Keep wrapped TOC titles until the dot leader or next numbered entry.
        if not re.search(r'(?:\.\s*){3,}',l.content):
            for nxt in report.lines[i+1:i+4]:
                if nxt.page!=l.page or NUMBER.match(_text(nxt.content)):break
                if nxt.content:
                    title+=' '+re.split(r'(?:\.\s*){3,}',_text(nxt.content))[0].strip()
                    if re.search(r'(?:\.\s*){3,}',nxt.content):break
        out.append((pid,clean(title)))
    return out


def _label(title):
    patterns=[r'^\[('+RISK+r')\]\s*',r'^('+RISK+r')\s*[-–]\s*',r'\[('+RISK+r')\]',r'\s('+RISK+r')\s*$']
    for pat in patterns:
        m=re.search(pat,title)
        if m:return m[1]
    return None


def _status(text):
    header=re.search(r'(?:\[|[-–]\s*)(FIXED|ACKED|ACKNOWLEDGED|UNRESOLVED|RESOLVED|MITIGATED)\]?\s*$',text,re.I)
    if header:return header[1]
    # Only explicit statements about this issue, never report-wide remediation prose.
    m=re.search(r'\b(?:This |The )?issue\s+(?:has been |was |is )?(acknowledged and fixed|fixed|resolved|acknowledged|mitigated)\b',text,re.I)
    if m:return 'fixed' if m[1].lower()=='acknowledged and fixed' else m[1]
    return None


def _title(title):
    title=re.sub(r'^\['+RISK+r'\]\s*|^'+RISK+r'\s*[-–]\s*','',title)
    title=re.sub(r'\s*\['+RISK+r'\]|\s+'+RISK+r'\s*$','',title)
    title=re.sub(r'\s*(?:\[(?:FIXED|ACKED|ACKNOWLEDGED|RESOLVED|MITIGATED)\]|[-–]\s*(?:FIXED|ACKED|ACKNOWLEDGED|RESOLVED|MITIGATED))\s*$','',title,flags=re.I)
    return clean(title.strip(' -–'))


def layout(report):
    sections=_sections(report)
    if any(k=='3' for k in sections):return 'modern-3.n-text-risk'
    if '2' in sections:return 'legacy-2.n-audit-result'
    if '2.3' in sections:return 'legacy-2.3-findings'
    if '2.2' in sections:return '2.2-findings-icon-or-text-risk'
    if _legacy(report):return 'legacy-risk-heading-or-recommendation-bullets'
    if '2.4' in sections:return '2.4-findings-icon-or-text-risk'
    return 'unnumbered-or-unrecognized'


def _legacy(report):
    """Pre-numbered reports explicitly label each risk and use recommendation bullets."""
    out=[];active=False;recommendations=False;limit=len(report.text)
    for i,l in enumerate(report.lines):
        text=_text(l.content)
        if re.fullmatch(r'VULNERABILITIES FINDINGS(?: / RECOMMENDATIONS)?',text):
            active=True;recommendations='RECOMMENDATIONS' in text;continue
        if re.fullmatch(r'(?:OTHER )?RECOMMENDATIONS / SUGGESTIONS',text):
            active=True;recommendations=True;continue
        if active and re.match(r'^(?:CONCLUSION|LIMITATIONS|APPENDIX)\b',text):
            active=False;limit=l.start
            if out:out[-1].end=l.start
            continue
        if not active:continue
        m=re.fullmatch(r'(?:(FIXED|REJECTED|UNRESOLVED|ACKNOWLEDGED)\s+)?('+RISK+r')',text,re.I)
        bracket=re.match(r'^\[('+RISK+r')\]\s+(.+)',text,re.I)
        if m or bracket:
            titlelines=[]
            if bracket:titlelines=[bracket[2]]
            else:
                for nxt in report.lines[i+1:i+8]:
                    if not nxt.content:
                        if titlelines:break
                        continue
                    if re.search(r'Security Audit of|Smart Contracts? \|',nxt.content,re.I):continue
                    titlelines.append(nxt.content)
                    if len(titlelines)>=3:break
            if titlelines:
                out.append(Candidate(l.start,clean(' '.join(titlelines)),m[2] if m else bracket[1],status_raw=m[1] if m else None,
                    method='verichains-legacy-risk-heading',confidence=.9))
        elif recommendations:
            bullet=re.match(r'^[•●]\s+(.+)',text)
            if bullet and not re.search(r'(?:identified|found|discovered) no (?:security )?(?:issues|vulnerabilit)',text,re.I):
                title=bullet[1]
                for nxt in report.lines[i+1:i+4]:
                    if not nxt.content or re.match(r'^[•●]',nxt.content):break
                    title+=' '+nxt.content
                out.append(Candidate(l.start,clean(title),record_kind='recommendation',method='verichains-legacy-recommendation-bullet',confidence=.8,
                    evidence={'severity_availability':'not_textual_or_absent'}))
    for c,n in zip(out,out[1:]):c.end=min(c.end or n.start,n.start)
    return out


def parse(report, era=None):
    pages=_tocpages(report);sections=_sections(report);toc=dict(_toc_entries(report));out=[]
    if era == 'chapter3': sections={k:v for k,v in sections.items() if k == '3'}
    if era == 'nested': sections={k:v for k,v in sections.items() if k.startswith('2')}
    cutoff=min((l.start for l in report.lines if not _is_toc(l,pages) and re.match(r'^(?:[3-9]\.\s*)?VERSION HISTORY|^APPENDIX',l.content,re.I)),default=len(report.text))
    # The report's actual section label determines which numbered headings are findings.
    for i,l in enumerate(report.lines):
        if _is_toc(l,pages) or l.code or l.start>=cutoff:continue
        m=NUMBER.match(_text(l.content))
        if not m:continue
        pid,title=m.groups();parent=pid.rsplit('.',1)[0]
        if '.' not in pid or parent not in sections:continue
        rawtitle=title
        # Wrapped heading text is in the TOC even when the PDF omits section numbers in body.
        if pid in toc and clean(toc[pid]).startswith(clean(title)):
            title=toc[pid]
        elif pid not in toc:
            indent=len(l.text)-len(l.text.lstrip())
            for nxt in report.lines[i+1:i+4]:
                if not nxt.content or nxt.page!=l.page:break
                nindent=len(nxt.text)-len(nxt.text.lstrip())
                if nindent>=indent+3 and not re.match(r'Description|RECOMMENDATION|[•●]|\d',nxt.content,re.I):
                    title+=' '+_text(nxt.content)
                else:break
        raw=_label(title) or field_severity(report.near(i,5))
        c=Candidate(l.start,_title(title),raw,pid,normalized=severity(raw, report.firm),method='verichains-section-detail',confidence=.91,
                    evidence={'section':sections[parent],'severity_availability':'explicit_text' if raw else 'not_textual_or_absent'})
        out.append(c)
    # Some 2021 Word exports print body subsection titles without their numbers.
    used={c.printed_id for c in out}
    for pid,title in toc.items():
        if pid in used or pid.rsplit('.',1)[0] not in sections:continue
        parent=pid.rsplit('.',1)[0]
        for i,l in enumerate(report.lines):
            if _is_toc(l,pages) or l.code or l.start>=cutoff or NUMBER.match(_text(l.content)):continue
            if clean(_text(l.content))==title and l.page>max(pages or {0}):
                raw=_label(title)
                out.append(Candidate(l.start,_title(title),raw,pid,method='verichains-unnumbered-detail',confidence=.86,
                    evidence={'section':sections.get(parent),'id_basis':'printed_toc_subsection','severity_availability':'explicit_text' if raw else 'not_textual_or_absent'}));break
    if era is None:out.extend(_legacy(report))
    out.sort(key=lambda c:c.start)
    # Bound before the next finding or the next same/higher-level section (incl. appendices).
    for j,c in enumerate(out):
        end=min(c.end or len(report.text),out[j+1].start if j+1<len(out) else len(report.text))
        depth=len(c.printed_id.split('.')) if c.printed_id else 0
        for l in report.lines:
            if not c.start<l.start<end or _is_toc(l,pages):continue
            m=NUMBER.match(_text(l.content))
            if (m and len(m[1].split('.'))<depth) or re.match(r'APPENDIX\b|VERSION HISTORY\b',l.content,re.I):
                end=l.start;break
        c.end=end
        c.status_raw=c.status_raw or _status(report.text[c.start:end])
        if c.status_raw is None:
            c.status_raw=_status(next((l.content for l in report.lines if l.start==c.start),''))
    return out


def sequence_evidence(report):
    entries=_toc_entries(report)
    if entries:return {'basis':'printed_toc_finding_subsections','ids':[pid for pid,_ in entries],
                       'titles':[title for _,title in entries]}
    # Separate source-line census, not the detail parser, for pre-numbered layouts.
    active=False;count=0
    for l in report.lines:
        if re.fullmatch(r'VULNERABILITIES FINDINGS(?: / RECOMMENDATIONS)?',l.content):active=True;continue
        if re.match(r'^(?:CONCLUSION|LIMITATIONS|APPENDIX|(?:OTHER )?RECOMMENDATIONS / SUGGESTIONS)\b',l.content):active=False
        if active and (re.fullmatch(r'(?:(?:FIXED|REJECTED|UNRESOLVED|ACKNOWLEDGED)\s+)?'+RISK,l.content,re.I) or re.match(r'^\['+RISK+r'\]',l.content,re.I)):count+=1
    if count:return {'basis':'legacy_risk_heading_census','expected_count':count,'limitation':'Structural heading completeness; no independent printed index.'}
    return None


def printed_counts(report):
    # Verichains' usual issue lists enumerate rows but do not print numeric aggregate totals.
    # Do not turn icon severities, row counts, or prose about clean audits into numeric totals.
    return None


from variants import Variant, Fingerprint
from parsers.group3_status import FIELD, STATE, fields, claim


def parse_risk_headings(report):
    return _legacy(report)


def parse_nested(report):
    return parse(report,'nested')


def parse_status_index(report):
    return parse(report,'nested')


def parse_chapter3(report):
    return parse(report,'chapter3')


def status_legacy(report,candidates):
    fields(report,candidates,(FIELD,('risk_heading_status',r'^[ \t]*[✔✓]?[ \t]*('+STATE+r')\s+(?:'+RISK+r')\s*$')))


def status_nested(report,candidates):
    fields(report,candidates,(FIELD,
        ('finding_update',r'\b(?:This|The) (?:issue|finding|vulnerability)\s+(?:has been|was|is)\s+(Acknowledged\s+and\s+(?:fixed|resolved)|'+STATE+r')\b'),
        ('heading_status',r'^[ \t]*\d+(?:\.\d+)+\.?[^\n]*?(?:[-–]|\[)[ \t]*('+STATE+r')\]?[ \t]*$')))
    for c in candidates:
        if c.status_raw and re.fullmatch(r'acknowledged\s+and\s+(?:fixed|resolved)',c.status_raw,re.I):
            c.normalized_status='fixed'


def status_index(report,candidates):
    # Status-index rows carry titles rather than IDs. Join only a complete,
    # unique detail title; never transfer a page/report-wide status.
    key=lambda s:re.sub(r'[^a-z0-9]','',s.casefold())
    titles={}
    for c in candidates:
        if len(key(c.title))>=12:titles.setdefault(key(c.title),[]).append(c)
    tables={}
    active=False
    for i,line in enumerate(report.lines):
        if re.search(r'\bSeverity\s+Name\s+Status\b',line.text,re.I):active=True;continue
        if not active:continue
        if NUMBER.match(_text(line.content)):
            active=False;continue
        m=re.search(r'\s{2,}('+STATE+r')\s*$',line.text,re.I)
        if not m:continue
        # A verdict is printed on the FIRST line of its row. Wrapped name
        # continuations belong forward to that row, never to the prior title.
        parts=[re.sub(r'^[ \t]*'+RISK+r'\s+','',line.text[:m.start()],flags=re.I)]
        for following in report.lines[i+1:i+9]:
            if (not following.content or following.page!=line.page or NUMBER.match(_text(following.content))
                    or re.search(r'\s{2,}('+STATE+r')\s*$',following.text,re.I)
                    or re.search(r'\bSeverity\s+Name\s+Status\b|^Page\s+\d+',following.content,re.I)):
                break
            parts.append(following.content)
        joined=key(' '.join(parts))
        found=[cs[0] for t,cs in titles.items() if len(cs)==1 and t==joined]
        if len(found)==1:tables.setdefault(found[0].printed_id,[]).append(claim(report,m,line.start,'title_linked_status_index'))
    fields(report,candidates,(),tables=tables,preserve=False)
    status_nested(report,candidates)


def status_chapter3(report,candidates):
    status_nested(report,candidates)


VARIANTS=(
    Variant('verichains/v2025_chapter3',Fingerprint((('findings_chapter',r'^\s*3\.\s+(?:(?:Draft|Code Review|Solana)\s+)?Findings\s*$',8),),('2025','2026')),parse_chapter3,('verichains_chapter3',),status_chapter3,printed_counts),
    Variant('verichains/v2023_status_index',Fingerprint((('title_status_index',r'\bSeverity\s+Name\s+Status\b',7),('nested_chapter',r'^\s*2\.[234]\.\s+Findings\s*$',3)),('2023','2025')),parse_status_index,('verichains_status_index',),status_index,printed_counts),
    Variant('verichains/v2021_nested_findings',Fingerprint((('audit_findings',r'^\s*2(?:\.[234])?\.\s+(?:Findings|AUDIT RESULTS?|DISCOVERED VULNERABILITIES)\s*$',7),),('2021','2025')),parse_nested,('verichains_nested',),status_nested,printed_counts),
    Variant('verichains/v2018_risk_headings',Fingerprint((('legacy_findings',r'^\s*VULNERABILITIES FINDINGS(?: / RECOMMENDATIONS)?\s*$',8),('legacy_suggestions',r'^\s*(?:OTHER )?RECOMMENDATIONS / SUGGESTIONS\s*$',6)),('2018','2021')),parse_risk_headings,('verichains_risk',),status_legacy,printed_counts),
)
