"""Bailsec Issue_nn detail tables; IDs may be vertically centered inside the title."""
from core import severity, Candidate, clean
import re
from collections import Counter
from parsers.shieldify import bounded
DESCRIPTION = 'Bailsec Issue_nn cards with vertically centered IDs, native risk labels and resolutions'


def parse(report, identified=None):
    out=[]
    for i,line in enumerate(report.lines):
        m=re.match(r'^(Issue[_ -]\d+)\b\s*(.*)',line.content,re.I)
        if not m:
            m=re.fullmatch(r'(Issue)(?:\s{2,}(.*))?',line.content,re.I)
        if not m:
            continue
        if identified is not None and bool(re.search(r'\d',m[1])) != identified:
            continue
        stop=None
        for j in range(i+1,min(i+14,len(report.lines))):
            if re.match(r'^Issue(?:[_ -]\d+)?(?:\s{2,}|$)',report.lines[j].content,re.I):
                break
            if re.match(r'^Severity(?:\s+|$)',report.lines[j].content,re.I):
                stop=j
                break
        if stop is None:
            continue
        sm=re.match(r'^Severity\s+(.+)',report.lines[stop].content,re.I)
        raw=sm[1].strip() if sm else next((l.content for l in report.lines[stop+1:stop+5] if l.content),None)
        # The title column sometimes starts above the vertically centered ID.
        before=[]
        indent=len(line.text)-len(line.text.lstrip())
        for prev in reversed(report.lines[max(0,i-3):i]):
            if not prev.content or prev.page!=line.page or len(prev.text)-len(prev.text.lstrip())<=indent+4:
                break
            before.insert(0,prev.content)
        title=before+[m[2] or '']+[l.content for l in report.lines[i+1:stop] if l.content]
        start=report.lines[i-len(before)].start
        # Asterisks qualify the risk; retain them while normalizing the risk word.
        label=re.match(r'(Critical|High|Medium|Low|Informational)\*?$',raw or '',re.I)
        title=clean(' '.join(title))
        if out and out[-1].title==title and out[-1].severity_raw==raw and out[-1].printed_id==m[1]:
            out[-1].evidence.setdefault('continuation_heading_offsets',[]).append(start)
            continue
        out.append(Candidate(start,title,raw,m[1] if re.search(r'\d',m[1]) else None,
                             normalized=severity(raw, report.firm),method='bailsec-issue-card',confidence=.96))
        if re.fullmatch(r'Quality assurance',raw or '',re.I):
            out[-1].record_kind='recommendation'
            out[-1].evidence['kind']='recommendation'
            out[-1].evidence['classification_basis']='native_nonrisk_quality_assurance_class'
    for j,c in enumerate(out):
        body=report.text[c.start:out[j+1].start if j+1<len(out) else len(report.text)]
        st=re.search(r'\b(?:Resolution|Status)\s*:?\s*(?:\n\s*)?(Partially (?:Fixed|Resolved)|Fixed|Resolved|Acknowledged|Open|Won.t Fix|Mitigated|Accepted)\b',body,re.I)
        if st:
            c.status_raw=st[1]
    return bounded(report,out)


def printed_counts(report):
    groups=[]
    counts,proof={},[]
    last=-100
    for i,line in enumerate(report.lines):
        m=re.fullmatch(r'(Critical|High|Medium|Low|Informational)\s+(\d+)(?:\s+\d+)*\s*',line.content,re.I)
        if not m:
            continue
        key=severity(m[1], report.firm)
        if i-last>12 or key in counts:
            if len(counts)>=2:
                groups.append((counts,proof))
            counts,proof={},[]
        counts[key]=int(m[2])
        proof.append({'start':line.start,'end':line.end,'page':line.page,'text':line.text})
        last=i
    if len(counts)>=2:
        groups.append((counts,proof))
    if not groups:
        return None
    if len(groups)>1:
        # Compound PDFs append independent audit/extension sections, each with
        # its own printed Found table. Sum only when detail cards separate them.
        separate=all(re.search(r'^\s*Issue(?:[_ -]\d+)?\b',report.text[groups[j][1][-1]['end']:groups[j+1][1][0]['start']],re.M)
                     for j in range(len(groups)-1))
        if not separate:
            return {'counts':groups[0][0],'evidence':groups[0][1],'basis':'bailsec_found_tables','ambiguous':True,
                    'alternatives':[{'counts':c,'evidence':e} for c,e in groups[1:]]}
    total=Counter()
    for counts,proof in groups:
        total.update(counts)
    return {'counts':dict(total),'evidence':[p for c,ps in groups for p in ps],'basis':'bailsec_independent_section_found_tables',
            'sections':[{'counts':c,'evidence':p} for c,p in groups]}


from variants import Variant, Fingerprint
from parsers.group3_status import FIELD, STATE, fields


def parse_unnumbered(report):
    return parse(report,False)


def parse_identified(report):
    return parse(report,True)


def parse_clean_detection(report):
    return []


def status_comments(report,candidates):
    # In PDF reading order the response sits beside Comments /, before the
    # continuation line "Resolution". Only that labelled response cell counts.
    patterns=(FIELD,('comments_resolution_cell',r'^[ \t]*(?:Comments[ \t]*/?|Resolution|Status)[ \t]*:?[ \t]*(?:\n[ \t]*)?('+STATE+r')\b'))
    fields(report,candidates,patterns,preserve=False)


def status_unnumbered(report,candidates):
    status_comments(report,candidates)


VARIANTS=(
    Variant('bailsec/v2024_clean_detection',Fingerprint((('detection_overview',r'^\s*2\. Detections? Overview\s*$',6),),('2024','2026'),reject_signatures=(r'^\s*Issue(?:[_ -]\d+|\s{2,}\S)',)),parse_clean_detection,('bailsec_clean',),status_comments,printed_counts),
    Variant('bailsec/v2024_issue_ids',Fingerprint((('issue_id',r'^\s*Issue[_ -]\d+\b',8),),('2024','2026')),parse_identified,('bailsec_identified',),status_comments,printed_counts),
    Variant('bailsec/v2023_unnumbered',Fingerprint((('issue_cell',r'^\s*Issue\s{2,}\S',6),('severity_cell',r'^\s*Severity\s{2,}\S',2)),('2023','2024')),parse_unnumbered,('bailsec_unnumbered',),status_unnumbered,printed_counts),
)
