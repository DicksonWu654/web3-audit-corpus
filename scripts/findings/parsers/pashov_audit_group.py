"""Pashov solo/team reports, including the 2025 and 2026 PDF templates."""
from core import severity, Candidate, SHORT, bracket_findings, clean, numbered_metadata
import re
from summary_counts import printed_counts as common_counts
DESCRIPTION = "Severity-ID details after the findings index; wrapped PDF titles and publisher index statuses"

ID = r'(?:QA|NC|C|H|M|L|I|G)-\d+'
HEADING = re.compile(r'^\[(?P<id>(?P<code>QA|NC|C|H|M|М|L|I|G)-\d+)\]\s*(?P<title>.*)', re.I)
STATUS = r'(?:Partially (?:Resolved|Fixed)|Acknowledged|Unresolved|Resolved|Fixed|Open|Mitigated|Accepted)'


def _index_statuses(report):
    """Read explicitly printed index statuses, including wrapped title rows."""
    result = {}
    for line in report.lines:
        m = re.search(r'^\s*\|?\s*\[?(' + ID + r')\]?(?:\s|\|).*?\b(' + STATUS + r')\s*\|?\s*$', line.text, re.I)
        if m:
            result.setdefault(m[1], m[2])
    return result


def _title(report, i, title):
    parts = [title]
    for line in report.lines[i+1:i+9]:
        s = line.content.strip()
        if not s or re.match(r'^(?:Severity|Description|Recommendations?|Discussion|Impact|Likelihood|Proof of Concept|\[|\d+\.)\b', s, re.I):
            break
        # PDF title lines share left indentation. Explanatory paragraphs under
        # low/info headings are indented, while the heading itself is flush left.
        first_indent = len(report.lines[i].text) - len(report.lines[i].text.lstrip())
        indent = len(line.text) - len(line.text.lstrip())
        if indent != first_indent or re.fullmatch(r'\d+', s):
            break
        parts.append(s)
    return clean(' '.join(parts))


def _parse(report):
    statuses = _index_statuses(report)
    if report.meta.get('file_format') != 'pdf':
        result, fence_language, in_fence = [], None, False
        for i, line in enumerate(report.lines):
            marker = re.fullmatch(r'(`{3,}|~{3,})([^`~]*)', line.content)
            if marker:
                if in_fence and not marker[2].strip():
                    in_fence, fence_language = False, None
                else:
                    in_fence, fence_language = True, marker[2].strip().lower()
            m = HEADING.match(line.content) if line.heading else None
            card_metadata = bool(re.search(r'^\s*(?:##\s+(?:Severity|Description)|Vulnerable code:)\s*', report.near(i+1, 8), re.I|re.M))
            recover = fence_language in {'solidity', 'sol', 'rust', 'diff'} or card_metadata
            if not m or (in_fence and (line.heading != 1 or fence_language in {'md','markdown'} or not recover)):
                continue
            # One publisher Markdown file has mismatched 3/4-backtick Solidity
            # fences spanning genuine top-level finding headings. Recover only
            # the firm's own level-one ID syntax; quoted Markdown stays excluded.
            code = m['code'].upper().replace('М', 'M')
            result.append(Candidate(line.start, m['title'], m['code'], m['id'], severity(m['code'], report.firm),
                                    status_raw=statuses.get(m['id']), method='pashov-markdown-id', confidence=.85 if in_fence else .96,
                                    evidence={'severity_basis': 'printed_id_prefix', 'label_is_code': True,
                                              'publisher_malformed_fence_recovery': in_fence,
                                              'unicode_prefix_mapping': 'Cyrillic М to medium' if m['code'] == 'М' else None}))
        return result or numbered_metadata(report, levels=(2, 3))
    # The PDF table of contents may continue for several pages without repeating
    # its Contents header. The summary index can also continue without its header.
    # Both precede the first actual severity section of the detailed findings.
    sections = [l.start for l in report.lines if l.page > 2 and re.fullmatch(
        r'(?:\d+(?:\.\d+)*\.?\s+)?(?:Critical|High|Medium|Low|Informational|Info|QA|Gas)(?:\s+Risk)?\s+(?:[Ff]indings|Severity)', l.content)]
    floor = min(sections) if sections else 0
    out, seen = [], set()
    for i, line in enumerate(report.lines):
        if line.start < floor:
            continue
        m = HEADING.match(line.content)
        if not m or m['id'] in seen:
            continue
        title = m['title'].strip()
        if re.search(r'(?:\.\s*){4,}\s*\d+\s*$|\s{2,}\d+\s*$', title):
            continue
        if re.search(r'\s{2,}(?:Critical|High|Medium|Low|Informational|QA|'+STATUS+r')\b', title, re.I):
            continue
        if re.fullmatch(r'(?:Critical|High|Medium|Low|Informational|Info|QA)\s+(?:'+STATUS+r')', title, re.I):
            continue
        if not sections and line.excluded:
            continue
        title = _title(report, i, title)
        out.append(Candidate(line.start, title, m['code'], m['id'], severity(m['code'], report.firm),
                             status_raw=statuses.get(m['id']), method='pashov-detail-id', confidence=.97,
                             evidence={'severity_basis': 'printed_id_prefix', 'label_is_code': True}))
        seen.add(m['id'])
    result = out or numbered_metadata(report, levels=(2, 3))
    for j, c in enumerate(result):
        upper = result[j+1].start if j+1 < len(result) else len(report.text)
        stop = re.search(r'\n\s*(?:#{1,3}\s+)?(?:\d+[.]?\s+)?Appendi(?:x|ces)(?:\s+[A-Z0-9]+)?\s*(?::[^\n]*)?\n', report.text[c.start:upper], re.I)
        if stop:
            c.end = c.start + stop.start()
    return result


def printed_counts(report):
    # QA is an explicit publisher bucket in early solo reports. Do not infer
    # omitted zero buckets from either the index or detailed headings.
    result = common_counts(report)
    if result:
        # The latest PDFs have a finding index but no numeric aggregate. A TOC
        # entry such as "Medium Severity 8" is a page number, never a count.
        first = result['evidence'][0]['start']
        context = report.text[max(0, first-650):first]
        if not re.search(r'Findings\s+Count|Severity\s*\|?\s*(?:Amount|Count|Number)', context, re.I):
            return None
    for i, line in enumerate(report.lines):
        m = re.fullmatch(r'QA\s+(\d+)', line.content)
        if result and m and result['evidence'] and abs(line.start-result['evidence'][-1]['end']) < 250:
            result['counts']['info'] = int(m[1])
            result['evidence'].append({'page': line.page, 'start': line.start, 'end': line.end, 'text': line.text})
            break
    return result


def read_status(report,candidates):
    from layout_support import bounded
    from core import set_status_claim
    bounded(report,candidates)
    for c in candidates:
        c.evidence['status_reader_complete']=True
        body=report.text[c.start:c.end]
        for m in re.finditer(r'\bStatus[ \t]*:(?:\*\*)?[ \t]*('+STATUS+r')\b',body,re.I):
            if any(line.code and line.start <= c.start+m.start(1) < line.end for line in report.lines):continue
            set_status_claim(report,c,m,c.start,'pashov_inline_status_field')
        # Locate existing ID-linked index statuses outside the detail body.
        if c.status_raw and 'status_evidence' not in c.evidence:
            for line in report.lines:
                m=re.search(r'^\s*\|?\s*\[?'+re.escape(c.printed_id or '<no-id>')+r'\]?(?:\s|\|).*?\b('+re.escape(c.status_raw)+r')\s*\|?\s*$',line.text,re.I)
                if m:
                    set_status_claim(report,c,m,line.start,'pashov_id_status_index');break


def parse(report):
    candidates=_parse(report)
    read_status(report,candidates)
    return candidates


# Direct calls and the legacy adapter share the same completed status reader.
from variants import legacy as _legacy_variant
VARIANTS = (_legacy_variant('pashov-audit-group', parse),)
