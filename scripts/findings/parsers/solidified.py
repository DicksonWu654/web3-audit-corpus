"""Solidified's numbered issue sections (2018–2024), independent of its index."""
from core import SeverityLookup, severity, Candidate, clean, explicit_status, field_severity
import re
from collections import Counter

DESCRIPTION = "Numbered detail issues under Critical/Major/Minor/Notes sections; excludes bounty appendices"
SECTION = re.compile(r"^(Critical|Major|Moderate|Minor|Informational|Informative|Notes|Warnings)(?:\s+(?:Issues|Notes))?(?:/Precaution)?\s*:?$", re.I)
NUMBER = re.compile(r"^\s*\*?(\d{1,3}[a-z]?|x)[.．](?=[\s\u200b\ufeffA-Za-z])[\s\u200b\ufeff]*(\S.*)$",re.I)
STOP = re.compile(r"^(?:Appendix\b|Bug Bounty\b|Bounty (?:Program|Results)\b|Suggestion For Tips\b|Closing Summary\b|Disclaimer\b)", re.I)


def parse(report):
    out, active, raw, last, heading_indent = [], False, None, 0, None
    section_changed=False;sequence_group=0
    index = index_entries(report)
    detail_start=max((e["end"] for e in index),default=0)
    for i, line in enumerate(report.lines):
        s = clean(line.content)
        if STOP.match(s) and active:
            if out:
                out[-1].end = line.start
            break
        if re.fullmatch(r"(?:Issues Found|Solidified Stamp|Findings|Detailed Findings)\s*:?", s, re.I):
            active = True
        m = SECTION.fullmatch(s)
        if m:
            if out and out[-1].end is None:
                out[-1].end=line.start
            active = True
            raw = m[1]
            section_changed=True
            continue
        m = NUMBER.match(line.text)
        if not m or not active or line.start<detail_start:
            continue
        resets=section_changed and m[1]=='1' and last>0
        if m[1].isdigit() and int(m[1])<last-1 and not resets:continue
        if i+1<len(report.lines) and NUMBER.match(report.lines[i+1].text):
            # Contiguous numbered requirements/exploit steps are prose lists,
            # not separated issue headings; they must not advance last-ID.
            continue
        # Actual headings have a blank line before them. Numbered exploit steps
        # are contiguous prose, often with a deeper indentation.
        explicit=field_severity(report.near(i,6))
        if i and report.lines[i-1].content and not explicit and not SECTION.fullmatch(clean(report.lines[i-1].content)):
            continue
        indent=len(line.text)-len(line.text.lstrip())
        if heading_indent is not None and indent>heading_indent+2:
            continue
        if heading_indent is None:
            heading_indent=indent
        title = m[2]
        for following in report.lines[i+1:i+5]:
            if not following.content or following.page != line.page:
                break
            if re.match(r"^(?:Description|Recommendation|Update|AMENDED)\b", following.content, re.I):
                break
            if re.match(r"^(?:In |The |This |Since |At |According to |Currently,|When |It )",following.content):
                break
            title += " " + following.content
        risk=explicit or raw
        if resets:
            sequence_group+=1;last=0
        out.append(Candidate(line.start, clean(title), risk, m[1], normalized=severity(risk, report.firm),
                             method="solidified-numbered-detail", confidence=.9,
                             evidence={"severity_basis":"printed_section" if raw else "not_printed",
                                       "container_id":f'solidified-source-sequence-{sequence_group}'}))
        section_changed=False
        # The index explicitly leaves miscellaneous recommendation containers
        # ungraded, outside its counted Notes. Keep the container as advice.
        entry=next((e for e in index if e['key']==m[1]),None)
        if entry and entry['severity'] is None and re.match(r'Misc(?:ellaneous)?[ .]*(?:notes|issues|suggestions)',clean(title),re.I):
            out[-1].record_kind='recommendation'
            out[-1].severity_raw=None
            out[-1].evidence['severity_basis']='ungraded_miscellaneous_recommendation_container'
        if m[1].isdigit():
            last = max(last,int(m[1]))
    # A heading can be on the same physical page as its index; do not use the
    # framework's whole-page TOC flag. Spans end at the next detailed issue.
    for j, c in enumerate(out):
        c.end = c.end or (out[j+1].start if j+1 < len(out) else len(report.text))
        c.status_raw = explicit_status(report.text[c.start:c.end])
    return out


def index_entries(report):
    """Source issue-table rows, independently bounded before detailed sections."""
    active=False;stop=len(report.text)
    rows=[]
    for line in report.lines:
        if re.search(r"Issue\s*#?\s+(?:Description|Severity)",line.content,re.I):
            active=True
        if active and SECTION.fullmatch(clean(line.content)):
            stop=line.start
            break
        m=re.match(r"^\s*(\d{1,3}[a-z]?)[.]?\s{2,}\S",line.text)
        if not (m and active):
            continue
        risk=re.search(r"\b(Critical|Major|Minor|Warning|Note|Informational)\s+(Resolved|Fixed|Acknowledged|Unresolved|Pending|Open|-)(?:\s|$)",line.text,re.I)
        rows.append({"key":m[1],"start":line.start,"end":line.end,
                     "severity":severity(risk[1], report.firm) if risk else None})
    for i,row in enumerate(rows):
        row['end']=rows[i+1]['start'] if i+1<len(rows) else stop
        risk=re.search(r'\b(Critical|Major|Minor|Warning|Notes?|Informational)\s+(?:Resolved|Fixed|Acknowledged|Unresolved|Pending|Open|-)(?:\s|$)',report.text[row['start']:row['end']],re.I)
        if risk:row['severity']=severity(risk[1],report.firm)
    return rows


def printed_counts(report):
    """Read numeric prose totals before the first detailed severity section."""
    start = re.search(r"\bIssues Found\b", report.text)
    if not start:
        return None
    tail = report.text[start.end():]
    end = re.search(r"(?m)^\s*(?:Critical|Major|Minor)(?: Issues)?\s*$", tail)
    text = tail[:end.start()] if end else tail[:2200]
    labels = SeverityLookup(report.firm, ('critical', 'major', 'minor', 'informational', 'note', 'notes', 'warning'))
    counts, proof, native = Counter(), [], {}
    for m in re.finditer(r"\b(no|zero|one|two|three|four|five|six|seven|eight|nine|ten|\d+)\s+(?:end-user\s+)?(critical|major|minor|informational|warning)(?:\s+(?:issues?|notes?))?\b", text, re.I):
        n = {"no":0,"zero":0,"one":1,"two":2,"three":3,"four":4,"five":5,"six":6,"seven":7,"eight":8,"nine":9,"ten":10}.get(m[1].lower())
        n = int(m[1]) if n is None else n
        key = labels[m[2].lower()]
        if m[2].lower() in native and native[m[2].lower()] != n:
            return None
        if m[2].lower() not in native:counts[key] += n
        native[m[2].lower()] = n
        a, b = start.end()+m.start(), start.end()+m.end()
        proof.append({"start":a,"end":b,"text":report.text[a:b]})
    if len(counts)<2:
        return None
    result={"counts":counts,"basis":"printed_issue_totals_prose","evidence":proof}
    rows=index_entries(report)
    if rows and all(x['severity'] is not None for x in rows):
        tally=Counter(x['severity'] for x in rows)
        if any(tally[k]!=v for k,v in counts.items()):
            result|={"ambiguous":True,"ambiguity_reason":"Numeric overview contradicts independently printed issue-index severity labels",
                     "issue_index_tally":dict(tally),"issue_index_evidence":rows}
    return result


from variants import Variant, Fingerprint
from parsers.group3_status import FIELD, STATE, fields, claim


def parse_grouped(report):
    # Early reports have section-level grades and no independent issue index.
    return parse(report)


def parse_ungraded(report):
    return parse(report)


def parse_indexed(report):
    # Index entries establish the lower boundary before numbered detail cards.
    return parse(report)


def parse_status_fields(report):
    return parse(report)


def parse_severity_fields(report):
    out=[];active=False;component='';stop=len(report.text)
    for i,line in enumerate(report.lines):
        if re.fullmatch(r'Detailed Findings',line.content,re.I):active=True;continue
        if not active or line.code:continue
        if STOP.match(line.content):stop=line.start;break
        if re.search(r'Smart Contracts?$|Implementation Review$',line.content,re.I):component=line.content
        m=NUMBER.match(line.text)
        if not m:continue
        raw=field_severity(report.near(i+1,7))
        if raw:
            title=[m[2]]
            for nxt in report.lines[i+1:i+5]:
                if re.match(r'^Severity\s*:',nxt.content,re.I):break
                if nxt.content:title.append(nxt.content)
            out.append(Candidate(line.start,clean(' '.join(title)),raw,m[1],
                method='solidified-numbered-severity-field',confidence=.96,
                evidence={'severity_basis':'explicit_field','component':component}))
    for i,c in enumerate(out):c.end=out[i+1].start if i+1<len(out) else stop
    return out


def status_grouped(report,candidates):
    fields(report,candidates,(FIELD,('inline_heading_status',r'\bSTATUS\s*:\s*('+STATE+r')\b'),('amendment',r'^[ \t]*(?:Update|AMENDED)\s*[-:–]?\s*('+STATE+r')\b'),
        ('resolved_section',r'^[ \t]*(Resolved|Acknowledged|Unresolved)\s*:\s*$'),
        ('explicit_issue_update',r'\b(?:(?:This|The)\s+)?issue (?:has been|was|is)\s+(?:also\s+)?('+STATE+r')\b')),preserve=False)


def status_indexed(report,candidates):
    tables={}
    entries=index_entries(report)
    for entry in entries:
        m=re.search(r'\b(?:Critical|Major|Minor|Warning|Notes?|Informational)\s+('+STATE+r')\b',report.text[entry['start']:entry['end']],re.I)
        if m:tables.setdefault(entry['key'],[]).append(claim(report,m,entry['start'],'issue_index_status'))
    fields(report,candidates,(FIELD,('inline_heading_status',r'\bSTATUS\s*:\s*('+STATE+r')\b'),('amendment',r'^[ \t]*(?:Update|AMENDED)\s*[-:–]?\s*('+STATE+r')\b'),
        ('resolved_section',r'^[ \t]*(Resolved|Acknowledged|Unresolved)\s*:\s*$'),
        ('explicit_issue_update',r'\b(?:(?:This|The)\s+)?issue (?:has been|was|is)\s+(?:also\s+)?('+STATE+r')\b')),tables=tables,preserve=False)


def status_fields(report,candidates):
    status_indexed(report,candidates)


VARIANTS=(
    Variant('solidified/v2018_ungraded',Fingerprint((('issues_chapter',r'^\s*Issues Found\s*:?\s*$',6),('approval_stamp',r'^\s*Solidified Stamp\s*$',6)),('2018','2021'),reject_signatures=(r'^\s*(?:Critical|Major|Minor|Notes|Warnings)(?:\s+(?:Issues|Notes))?(?:/Precaution)?\s*:?\s*$',r'Issue\s*#?\s+(?:Description|Severity)')),parse_ungraded,('solidified_ungraded','solidified_ungraded_stamp'),status_grouped,printed_counts),
    Variant('solidified/v2020_severity_fields',Fingerprint((('explicit_severity',r'^\s*Severity\s*:',6),('detailed_findings',r'^\s*Detailed Findings\s*$',3)),('2020','2022')),parse_severity_fields,('solidified_severity_fields',),status_fields,printed_counts),
    Variant('solidified/v2023_status_fields',Fingerprint((('standalone_status',r'^\s*Status\s*\n\s*(?:Resolved|Acknowledged|Unresolved)',10),),('2023','2024')),parse_status_fields,('solidified_status_fields',),status_fields,printed_counts),
    Variant('solidified/v2019_issue_index',Fingerprint((('issue_index',r'Issue\s*#?\s+(?:Description|Severity)',8),),('2019','2024')),parse_indexed,('solidified_indexed',),status_indexed,printed_counts),
    Variant('solidified/v2018_grouped_issues',Fingerprint((('graded_chapter',r'^\s*(?:Critical|Major|Minor|Notes|Warnings)(?:\s+(?:Issues|Notes))?(?:/Precaution)?\s*:?\s*$',6),('issues_found',r'^\s*Issues Found\s*:?',2)),('2018','2019')),parse_grouped,('solidified_grouped',),status_grouped,printed_counts),
)
