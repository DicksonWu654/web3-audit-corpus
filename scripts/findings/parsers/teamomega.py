"""Team Omega contract-scoped finding IDs and older unnumbered reports."""
import re
from core import Candidate, clean, severity
DESCRIPTION = "Contract-prefix numbered detail headings with severity/status brackets; legacy TOC-backed titles"
RISK = r"critical|high|medium|low|info(?:rmational)?"


def _key(text):
    # Contents often retain an earlier remediation tag. Identity is the
    # printed title; current body Severity/Status fields remain authoritative.
    text=re.sub(r'\[[^\]]*\]','',text)
    return re.sub(r'\s+','',text.replace('\u200b','')).casefold()


def parse(report, scoped=None):
    out=[]
    toc_pages={p['page'] for p in report.meta['pages'] if sum(bool(re.search(r'\s{2,}\d+\s*$',l.replace('\u200b',''))) for l in p['text'].splitlines()) >= 7}
    prior_start=min((l.start for l in report.lines if l.page not in toc_pages and re.fullmatch(r'Fixes from older reports',l.content,re.I)),default=len(report.text))
    for i,line in enumerate(report.lines):
        if line.page in toc_pages:
            continue
        m=re.match(r"^-?([A-Z]{1,8}\d+[a-z]?)(?:\.\s*|\s+)(.+)",line.content.replace('\u200b',''))
        if not m:
            continue
        pieces=[line.content.replace('\u200b','')]
        for following in report.lines[i+1:i+8]:
            joined=' '.join(pieces)
            if re.search(r'\[(?:'+RISK+r')\]', joined,re.I) and joined.count('[')==joined.count(']') and not following.content.startswith('['):
                break
            if not following.content:
                break
            pieces.append(following.content.replace('\u200b',''))
        heading=clean(' '.join(pieces))
        if re.search(r"\]\s*\d+\s*$",heading) or line.excluded:
            continue
        risk=re.search(r'\[('+RISK+r')\]',heading,re.I)
        if not risk:
            # Later short reports retain scoped IDs but put grade only in the
            # body (or omit it entirely). Require an explicit resolution badge.
            if not re.search(r'\[(?:not resolved|resolved|acknowledged)\]',heading,re.I):continue
        title=re.sub(r'\s*\[[^\]]*\]','',re.sub(r'^-?'+re.escape(m[1])+r'\.?\s*','',heading)).strip()
        tags=re.findall(r'\[([^\]]+)\]',heading)
        st=next((v for v in tags if not re.fullmatch(RISK,v,re.I)),None)
        evidence={}
        if line.start>=prior_start:evidence['previous_audit_finding']=True
        out.append(Candidate(line.start,title,risk[1] if risk else None,m[1],status_raw=st,
                             method="contract-id-bracket-heading",confidence=.96,evidence=evidence))
    if not out and scoped is not True:
        out=_legacy(report)
    for n,c in enumerate(out):
        end=out[n+1].start if n+1<len(out) else len(report.text)
        if c.start<prior_start<end:end=prior_start
        stop=re.search(r"\n\s*(?:Severity definitions|New stuff - not part of our audit[^\n]*|Appendix)\s*\n",report.text[c.start:end],re.I)
        c.end=c.start+stop.start() if stop else end
        # Preserve disagreement without regrading during status review.
        grade=re.search(r'(?im)^[ \t]*Severity\s*:\s*('+RISK+r')\b',report.text[c.start:c.end])
        if grade:
            if c.severity_raw and c.severity_raw.casefold()!=grade[1].casefold():
                c.evidence['heading_severity_raw']=c.severity_raw
            c.evidence['body_severity_raw']=grade[1]
    return out


def _legacy(report):
    """Match body titles against the independent, printed contents list.

    Repeated titles (e.g. Wrong error message) stay separate. Only body sections
    with their own explicit severity are emitted, so contract group labels and
    unscoped afterthoughts cannot become findings.
    """
    titles=set();toc_end=0
    for page in report.meta['pages']:
        ls=page['text'].splitlines()
        if sum(bool(re.search(r'\s{2,}\d+\s*$',l)) for l in ls)<7:
            continue
        toc_end=max(toc_end,page['end']);pending=[]
        for l in ls:
            m=re.match(r'^\s*(?:(.*?)\s+)?(\d+)\s*$',l)
            if m:
                title=clean(' '.join(pending+[m[1] or '']));pending=[]
                if len(title)>5:titles.add(_key(title))
            elif l.strip() and not re.fullmatch(r'\d+',l.strip()):pending=[l.strip()] if not pending else pending+[l.strip()]
            else:pending=[]
    starts=[]
    for i,line in enumerate(report.lines):
        if line.start < toc_end or not line.content:
            continue
        for width in range(1,4):
            group=report.lines[i:i+width]
            if any(not x.content for x in group):break
            title=clean(' '.join(x.content for x in group))
            if _key(title) in titles:
                starts.append((line.start,title));break
    out=[]
    for n,(start,title) in enumerate(starts):
        end=starts[n+1][0] if n+1<len(starts) else len(report.text)
        body=report.text[start:end]
        risks=list(re.finditer(r'(?im)^\s*Severity\s*:\s*('+RISK+r')\b',body))
        if len(risks)!=1:continue
        st=re.search(r'(?im)^\s*Status\s*:\s*([^\n]+)',body)
        title=re.sub(r'\s*\[[^\]]*\]','',title)
        out.append(Candidate(start,title,risks[0][1],end=end,status_raw=clean(st[1]) if st else None,
                             method="legacy-contents-backed-title",confidence=.91))
    return out


def printed_counts(report):
    from summary_counts import printed_counts as generic_counts
    return generic_counts(report)


from variants import Variant, Fingerprint
from parsers.group3_status import FIELD, STATE, fields


def parse_legacy_titles(report):
    return _legacy(report)


def parse_scoped_ids(report):
    return parse(report,True)


def parse_status_only(report):
    return parse(report,True)


def status_legacy_titles(report,candidates):
    fields(report,candidates,(FIELD,('resolution_response',r'^[ \t]*Resolution\s*:\s*(?:(?:This|The)\s+)?(?:issue\s+)?(?:(?:has been|was|is)\s+)?('+STATE+r')\b')))


def status_scoped_ids(report,candidates):
    fields(report,candidates,(FIELD,('heading_status',r'^[ \t]*-?[A-Z]{1,8}\d+[a-z]?\.?[^\n]*\[('+STATE+r')\][ \t]*$'),
        ('resolution_response',r'^[ \t]*Resolution\s*:\s*(?:(?:This|The)\s+)?(?:issue\s+)?(?:(?:has been|was|is)\s+)?('+STATE+r')\b')))


VARIANTS=(
    Variant('teamomega/v2024_status_only',Fingerprint((('status_heading',r'^\s*-?[A-Z]{1,8}\d+[a-z]?\.?\s+[^\n]*\[(?:not resolved|resolved|acknowledged)\]',7),),('2024','2026'),reject_signatures=(r'^\s*-?[A-Z]{1,8}\d+[a-z]?\.?\s+[^\n]*\[(?:'+RISK+r')\]',)),parse_status_only,('omega_status_only',),status_scoped_ids,printed_counts),
    Variant('teamomega/v2021_scoped_ids',Fingerprint((('scoped_bracket_heading',r'^\s*-?[A-Z]{1,8}\d+[a-z]?\.?\s+[^\n]*\[(?:'+RISK+r')\]',8),('wrapped_scoped_title',r'^\s*-?[A-Z]{1,8}\d+[a-z]?\.\s+\S',3),('body_grade',r'^\s*Severity\s*:',3)),('2021','2026')),parse_scoped_ids,('omega_scoped',),status_scoped_ids,printed_counts),
    Variant('teamomega/v2021_unnumbered',Fingerprint((('severity_field',r'^\s*Severity\s*:',3),('status_field',r'^\s*Status\s*:',3),('findings_chapter',r'^\s*Findings\s*$',2)),('2021','2022')),parse_legacy_titles,('omega_legacy',),status_legacy_titles,printed_counts),
)
