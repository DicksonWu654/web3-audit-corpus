"""Conservative, publisher-independent finding inventory excerpts.

Only source-labelled finding tables qualify. Numeric totals, TOCs, matrices,
badges and narrative lists cannot establish an inventory. Coordinates always
refer to the original text; matching views never rewrite it.
"""
import re
from core import Candidate, SEV, clean
from layout_support import STATUS, visible

GRADE = re.compile(r'(?<!\w)('+SEV+r')(?!\w)', re.I)
STATE = re.compile(r'(?<!\w)('+STATUS+r'|SOLVED|FUTURE RELEASE)(?!\w)', re.I)
IDENT = re.compile(r'^\s*(?:\d+\s+(?=[A-Z]))?[\[(]?(?P<id>[A-Z][A-Z0-9]*(?:[-_][A-Z0-9]+)*[-_]\d+|\d{1,3})[\])]?\s*[.:]?\s+(?P<tail>.*)$')
HEADER = re.compile(r'\b(?:ID|No\.?|Number)\b|(?:^|\s)#(?:\s|$)',re.I)
TITLE = re.compile(r'\b(?:Title|Description|Finding|Issue|Security Analysis)\b',re.I)
RISK = re.compile(r'\b(?:Severity|Risk(?: Level)?)\b',re.I)
STOP = re.compile(r'^(?:(?:\d+[.)]?\s+)?(?:Detailed Findings|Technical Details|Description|Recommendations?|Conclusion|Disclaimer|Appendix|Methodology|Scope|Severity Matrix)\b|(?:Issue|Recommendation)\s*#\d+)',re.I)


def inventory_header(text):
    text=visible(text)
    return bool(TITLE.search(text) and RISK.search(text) and
                (HEADER.search(text) or re.search(r'Security Analysis',text,re.I)))


def footer(text):
    return bool(re.search(r'©|All Rights Reserved|Confidential and Proprietary|Trail of Bits|Page \d+|Version \d',text,re.I)
                or re.fullmatch(r'\d+|EXECUTIVE OVERVIEW|PUBLIC',text,re.I))


def _source_label(report, line, label):
    pattern=r'[ \t]*'.join(re.escape(c) for c in re.sub(r'\s','',label))
    m=re.search(pattern,line.text,re.I)
    if not m:return label,dict(start=line.start,end=line.end,text=report.text[line.start:line.end])
    start=line.start+m.start();end=line.start+m.end()
    return report.text[start:end],dict(start=start,end=end,text=report.text[start:end])


def inventory(report):
    out=[];active=False;pending=[];prefix=[];row_prefix=[];header=None;last_page=None

    def flush(force=True):
        nonlocal pending,row_prefix
        if not pending:return
        first,pid,tail=pending[0]
        lines=[(l,visible(l.text).strip()) for l in row_prefix]+[(first,tail)]+[(l,visible(l.text).strip()) for l in pending[1:]]
        risk=None;state=None;proof=None;status_proof=None;fragments=[]
        # Padded columns keep category/difficulty out of titles. A wrapped
        # metadata-first row may carry its entire title on subsequent lines.
        for l,value in lines:
            cells=[c.strip() for c in re.split(r'\s{2,}|\|',value) if c.strip()]
            titles=[]
            for cell in cells:
                cell=cell.strip(' •|[]')
                if cell.startswith('(') and cell.endswith(')'):cell=cell[1:-1]
                gm=re.fullmatch('('+SEV+r')(?:\s*\([\d./ ]+\))?',cell,re.I)
                sm=STATE.fullmatch(cell)
                combined=re.fullmatch('('+SEV+r')\s+('+STATE.pattern+r')',cell,re.I)
                dated_state=re.match('^('+STATE.pattern+r')\s*[-:]\s*\d',cell,re.I)
                if gm or combined:
                    if risk is None:risk,proof=_source_label(report,l,(gm or combined)[1])
                    if combined and state is None:state,status_proof=_source_label(report,l,combined[2])
                    continue
                if sm or dated_state:
                    if state is None:state,status_proof=_source_label(report,l,(sm or dated_state)[1])
                    continue
                # Some compact inventories omit padding after the ID/grade.
                leading=re.match('^('+SEV+r')\s+(.+)',cell,re.I)
                if leading and risk is None and re.search(r'(?:Severity|Risk).*?(?:Title|Description)',header,re.I):
                    if risk is None:risk,proof=_source_label(report,l,leading[1])
                    cell=leading[2]
                if re.search(r'[A-Za-z]{2}',cell):titles.append(cell)
            # The title is the first text column; category/difficulty follow.
            if titles:fragments.append(titles[0])
        title=clean(' '.join(fragments))
        if title and risk:
            start=lines[0][0].start
            end=lines[-1][0].end
            evidence=dict(severity_basis='printed_inventory_label',severity_span=proof,
                inventory_header=header, inventory_wrapped=len(lines)>1,
                inventory_span=dict(start=start,end=end,text=report.text[start:end]))
            if status_proof:
                evidence['status_evidence']=dict(raw=state,basis='printed_inventory_status',profile=report.firm,**status_proof)
            out.append(Candidate(start,title,risk,pid,end=end,status_raw=state,
                record_kind='summary_excerpt',method='summary_inventory',confidence=.55,evidence=evidence))
        elif not force:return
        pending=[];row_prefix=[]

    for l in report.lines:
        value=visible(l.text).strip().strip('|').strip()
        if l.code:flush();active=False;continue
        if inventory_header(value) and not re.search(r'(?:\.\s*){4,}',value):
            flush();active=True;prefix=[];header=visible(l.text);last_page=l.page;continue
        if not active:continue
        if re.search(r'Table (?:of Contents|of content)',value,re.I) or STOP.match(value):
            flush();active=False;continue
        if not value:
            # A PDF row's title can begin above its vertically centered ID.
            # A complete blank-delimited row ends before the next title.
            flush(force=False)
            continue
        if footer(value):continue
        if re.match(r'^\d+(?:\.\d+)+\b|^The details are provided',value,re.I):
            flush();active=False;continue
        m=IDENT.match(value)
        if m:
            if l.page!=last_page:
                # A new page needs a titled row or its own table header.
                # "5 Low RESOLVED" beside narrative is an OCR card badge.
                title=GRADE.sub('',STATE.sub('',m['tail'])).strip(' •|[]()')
                if not re.search(r'[A-Za-z]{2}',title):
                    flush();active=False;continue
            flush();pending=[(l,m['id'],m['tail'])];row_prefix=prefix;prefix=[];last_page=l.page;continue
        if pending and l.page==last_page and len(pending)<7:
            if re.match(r'^(?:Table \d|Figure \d|During |The following |Based on |We |This )',value,re.I):
                flush();active=False;continue
            pending.append(l)
        elif pending:
            flush();active=False
        elif not re.fullmatch(r'[-:| ]+',value):
            column=re.search(r'\b(?:Title|Description|Security Analysis)\b',header,re.I)
            leading=len(l.text)-len(l.text.lstrip())
            metadata=bool(GRADE.fullmatch(value) or STATE.fullmatch(value))
            if (metadata or column and abs(leading-column.start())<=4) and len(prefix)<3 and l.page==last_page:
                prefix.append(l)
            else:active=False
    flush()
    return out
