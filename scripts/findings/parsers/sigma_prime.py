"""Sigma Prime detail cards and pre-card Markdown audits."""
from core import SeverityLookup, severity, Candidate, clean, status
from variants import Variant, Fingerprint
import re
from collections import Counter

DESCRIPTION = "Project-ID detail cards with Rating metadata and legacy Markdown recommendation sections"
ID_PREFIX = r"[A-Z0-9][A-Z0-9.]{1,15}"
ID = ID_PREFIX + r"-\d{2,3}"
RISK = r"Critical|High|Medium|Low|Informational"


def parse(report):
    if report.meta.get("file_format") == "md":
        return _markdown(report)
    return rating_cards(report)


def rating_cards(report):
    out = []
    for i, line in enumerate(report.lines):
        if line.excluded:
            continue
        m = re.match(r"^("+ID_PREFIX+r"-\d{0,3})(?:\s+(.+))?$", line.content)
        if not m:
            continue
        split_id = m[1].endswith('-')
        printed_id = m[1]
        if split_id:
            number = report.lines[i+1].content if i+1 < len(report.lines) else ''
            if not re.fullmatch(r'\d{2,3}', number):
                continue
            printed_id += number
        after = report.near(i+1, 28)
        # Detail card metadata always precedes Description; summary tables do not.
        header = re.split(r"\n\s*Description\s*\n", after, maxsplit=1)[0]
        if re.search(r"(?m)^\s*"+ID+r"\s", header):
            continue
        rating = re.search(r"\bRating\s+(?:Severity\s*:\s*)?("+RISK+r")\b", header, re.I)
        if not rating:
            continue
        parts = [m[2]] if m[2] else []
        start=line.start
        if not m[2]:
            for prev in reversed(report.lines[max(0,i-3):i]):
                if not prev.content or prev.page != line.page or 'Detailed Findings' in prev.content:
                    break
                parts.insert(0,prev.content);start=prev.start
        for following in report.lines[i+1+int(split_id):i+7]:
            if not following.content or re.match(r"(?:Asset|Target|Status|Rating)\b",following.content):
                break
            parts.append(following.content)
        st = re.search(r"(?m)^\s*Status\s+([^:\n]+)",header)
        out.append(Candidate(start,clean(' '.join(parts)),rating[1],printed_id,status_raw=clean(st[1]) if st else None,
                             method="project-id-rating-card",confidence=.97))
    for n,c in enumerate(out):
        end=out[n+1].start if n+1<len(out) else len(report.text)
        stop=re.search(r"\n\s*(?:[A-Z]\s+)?(?:Test Suite|Automated Testing|Vulnerability Severity Classiﬁcation|Vulnerability Severity Classification|References)\s*\n",report.text[c.start:end])
        c.end=c.start+stop.start() if stop else end
    return out


def _markdown(report):
    return numbered_markdown(report) or recommendation_markdown(report)


def numbered_markdown(report):
    out=[]
    # Aave's later Markdown notes use explicit LOW/INFORMATIONAL/INF headings,
    # plus separately labelled miscellaneous and gas optimisation sections.
    section=None
    for line in report.lines:
        if not line.heading or line.code:
            continue
        if line.content in {'Miscellaneous','Gas Optimisations'}:
            section=line.content;continue
        m=re.match(r'^(\d+)\.\s*(LOW|INFORMATIONAL|INF):\s*(.+)',line.content)
        other=re.match(r'^([MG]\d+)\.\s*(.+)',line.content) if section else None
        if m:
            out.append(Candidate(line.start,m[3],m[2],m[1],normalized=severity(m[2], report.firm),
                                 method='markdown-explicit-risk',confidence=.96))
        elif other:
            out.append(Candidate(line.start,other[2],section,other[1],normalized=severity(section, report.firm),
                                 method='markdown-miscellaneous-heading',confidence=.94))
    return out


def recommendation_markdown(report):
    out=[]; active=False; raw=None; level=0; container_level=0; stop=len(report.text)
    for line in report.lines:
        if line.code:
            continue
        if line.heading and line.content == "Recommendations":
            active=True;container_level=line.heading;continue
        if not active:
            continue
        if line.heading and line.heading <= container_level:
            stop=line.start
            break
        if line.heading and re.fullmatch(r"High|Severe|Moderate|Low|General Suggestions",line.content):
            raw=line.content;level=line.heading;continue
        if line.heading and line.heading <= level:
            raw=None
        if raw is None:
            continue
        m=re.match(r"^\*\*([SMLIG]\d+):\s*(.*?)\*\*(.*)",line.content)
        title = line.content if line.heading > level else None
        if m:
            title=m[2]
        if title:
            norm=SeverityLookup(report.firm, ('Severe', 'Moderate', 'High', 'Low', 'General Suggestions'))[raw]
            out.append(Candidate(line.start,title,raw,m[1] if m else None,normalized=severity(raw, report.firm),
                                 method="legacy-recommendation-heading",confidence=.90,
                                 evidence={"severity_basis":"printed_recommendation_section"}))
        elif raw == "General Suggestions" and line.content.startswith('**') and ' - ' in line.content:
            out.append(Candidate(line.start,line.content.split(' - ',1)[1],raw,normalized=severity(raw, report.firm),
                                 method="legacy-general-suggestion",confidence=.82))
    for i,c in enumerate(out):
        c.end=out[i+1].start if i+1<len(out) else stop
    return out


def nested_markdown(report):
    return recommendation_markdown(report)


def summary_entries(report):
    """Independent printed overview list: never inspect Rating/detail metadata."""
    entries=[]; active=False
    for page in report.meta['pages']:
        if re.search(r"\bID\s+Description\s+Severity\s+Status\b",page['text']):
            active=True
        if active and re.search(r'(?m)^\s*Rating\s+',page['text']):
            break
        if not active:
            continue
        # Continuation descriptions can start with e.g. EIP-712; only column-one
        # labels are overview IDs, independently of any detailed findings.
        text=page['text']; matches=list(re.finditer(r"(?m)^[ \t]{0,2}("+ID+r")\b([^\n]*)",text))
        for n,m in enumerate(matches):
            end=matches[n+1].start() if n+1<len(matches) else len(text)
            row=text[m.start():end]
            risk=re.search(r"(?:\s{2,}|\n\s*)("+RISK+r")\s+(?:Resolved|Closed|Open|Acknowledged)\b",row,re.I)
            # Wrapped titles can precede the ID; risk remains on/after the ID row.
            entries.append((m[1],risk[1] if risk else None,page['start']+m.start(),page['start']+end,page['page']))
    return entries


def printed_counts(report):
    entries=summary_entries(report)
    if not entries or any(x[1] is None for x in entries):
        return None
    counts=Counter(severity(x[1], report.firm) for x in entries)
    return {"basis":"printed_overview_classifications","counts":dict(counts),
            "evidence":[{"start":a,"end":b,"page":p,"text":report.text[a:b]} for _,_,a,b,p in entries]}


STATUS = r'(?:Partially (?:Resolved|Fixed|Implemented)|Not (?:Resolved|Fixed|Implemented)|Acknowledged|Unresolved|Resolved|Closed|Fixed|Open|Pending|Implemented|Addressed|Risk Accepted|Invalid)'


def _attach(report, row, m, base, basis):
    raw = m[1]
    row.status_raw = raw
    row.normalized_status = {'addressed': 'resolved'}.get(raw.casefold(), status(raw))
    a, b = base+m.start(1), base+m.end(1)
    row.evidence['status_evidence'] = {'raw': raw, 'start': a, 'end': b, 'text': report.text[a:b],
                                      'basis': basis, 'profile': 'sigma-prime'}


def card_status(report, candidates):
    """Printed card Status wins over the overview and resolution narrative."""
    index = {}
    for pid, _, a, b, _ in summary_entries(report):
        m = re.search(r'\b('+STATUS+r')\s*$', report.text[a:b].strip(), re.I)
        if m:
            # Use a second search in the untrimmed source to preserve offsets.
            source = report.text[a:b]
            m = re.search(r'\b('+STATUS+r')\s*$', source, re.I)
            index.setdefault(pid, []).append((m, a))
    for c in candidates:
        body = report.text[c.start:c.end]
        header = re.split(r'(?m)^\s*Description\s*$', body, maxsplit=1)[0]
        m = re.search(r'(?im)^\s*Status\s*:?\s+('+STATUS+r')\b', header)
        if m:
            _attach(report, c, m, c.start, 'labelled_status_field')
            continue
        # Explicit resolution/fix-review outcomes may fill an absent card field.
        # Imperatives such as "Consider implementing" are never closure evidence.
        m = re.search(r'(?im)^\s*(?:Resolution|Fix Review)\s*\n\s*(?:This (?:issue|finding) (?:has been|was|is)\s+)?('+STATUS+r')\b', body)
        if m:
            _attach(report, c, m, c.start, 'resolution_section')
            continue
        claims = index.get(c.printed_id, [])
        if len({status(m[1]) for m, _ in claims}) == 1:
            m, a = claims[-1]
            _attach(report, c, m, a, 'printed_id_status_table')
        elif claims:
            c.evidence['status_conflict'] = True
            c.status_raw = c.normalized_status = None


def numbered_markdown_status(report, candidates):
    """Latest prose notes: require a labelled status or explicit review outcome."""
    for c in candidates:
        body = report.text[c.start:c.end]
        m = re.search(r'(?im)^\s*(?:\*\*)?(?:Status|Resolution Status)(?:\*\*)?\s*:\s*('+STATUS+r')\b', body)
        if not m:
            m = re.search(r'(?im)^\s*(?:\*\*)?(?:Resolution|Fix Review)(?:\*\*)?\s*\n\s*(?:This (?:issue|finding) (?:has been|was|is)\s+)?('+STATUS+r')\b', body)
        if m:
            _attach(report, c, m, c.start, 'labelled_status_or_resolution')
        else:
            c.status_raw = c.normalized_status = None


def recommendation_status(report, candidates):
    """Legacy checked responses are publisher remediation receipts, not risk."""
    numbered_markdown_status(report, candidates)
    for c in candidates:
        body = report.text[c.start:c.end]
        responses = list(re.finditer(r'(?im)^\s*[*-]\s*\[[xX]\]\s*([^\n]+(?:\n[ \t]+[^\n]+)*)', body))
        for response in reversed(responses):
            value = response[1]
            # "Comment from authors: Not Implemented" remains open even though
            # the publisher checked that the response was received.
            m = re.search(r'\b(Not Implemented|Not Resolved|Partially Resolved|Fixed|Addressed|Acknowledged)\b', value, re.I)
            if m:
                _attach(report, c, m, c.start+response.start(1), 'checked_publisher_response')
                break


def reference_material(report):
    return []


def reference_status(report, candidates):
    return None


VARIANTS = (
    Variant('sigma-prime/v2017_markdown_recommendations', Fingerprint((
        ('recommendations', r'^\s*\#\#\s+Recommendations\s*$', 5),
        ('risk_sections', r'^\s*\#{3,4}\s+(?:Severe|Moderate|High|Low|General Suggestions)\s*$', 3)), ('2017', '2018'), formats=('md',)),
        recommendation_markdown, ('sigma_legacy_checked', 'sigma_legacy_comment'), recommendation_status,
        notes='Markdown risk sections, bold finding IDs and checked remediation responses.'),
    Variant('sigma-prime/v2022_markdown_notes', Fingerprint((
        ('risk_headings', r'^\s*\#{2,3}\s+\d+[.]\s+(?:LOW|INFORMATIONAL|INF):', 6),
        ('misc_gas', r'^\s*\#\#\s+(?:Miscellaneous|Gas Optimisations)\s*$', 2)), ('2022', '2023'), formats=('md',)),
        numbered_markdown, ('sigma_numbered_notes',), numbered_markdown_status,
        notes='Explicit numbered LOW/INF notes with separate miscellaneous and gas headings; recommendations do not imply closure.'),
    Variant('sigma-prime/v2018_nested_markdown', Fingerprint((
        ('detailed_audit', r'^\s*\#\#\s+Detailed Audit\s*$', 3),
        ('recommendations', r'^\s*\#\#\#\s+Recommendations\s*$', 5),
        ('nested_risk', r'^\s*\#{4}\s+(?:High|Moderate|Low|General Suggestions)\s*$', 3)), ('2018', '2018'), formats=('md',)),
        nested_markdown, ('sigma_nested_notes',), recommendation_status,
        notes='Nested recommendation/risk/title headings with unnumbered general suggestions; later attack examples and privilege inventories excluded.'),
    Variant('sigma-prime/v2018_rating_cards', Fingerprint((
        ('rating', r'^\s*Rating\s+(?:Severity\s*:\s*)?(?:'+RISK+r')\b', 6),
        ('status', r'^\s*Status\s+(?:Closed|Resolved|Open|Acknowledged)\b', 2),
        ('project_id', r'^\s*'+ID+r'\b', 2)), ('2018', '2026'), formats=('pdf',)),
        rating_cards, ('sigma_rating_card', 'sigma_split_id', 'sigma_dotted_id'), card_status,
        notes='Stable PDF project-ID/Asset/Status/Rating template used from 2018 through 2026, including wrapped titles and split IDs.'),
    Variant('sigma-prime/v2017_reference_material', Fingerprint((
        ('token_particulars', r'Token\s*Sale\s*-\s*Token\s*Particulars', 6),
        ('sale_terms', r'Price\s*per\s*token|Token\s*Distribution', 2)), ('2017', '2018'), formats=('pdf',)),
        reference_material, ('sigma_reference_material',), reference_status,
        notes='Collected token-sale reference specification; no audit findings.'),
)
