"""Informal Systems PDF metadata cards, including old IF identifiers and modern layouts."""
from core import severity, Candidate, clean
from collections import Counter
import unicodedata
import re
from summary_counts import printed_counts as generic_counts
DESCRIPTION='Informal legacy, numeric, modern stacked/compact and ungraded cards with explicit remediation receipts'
LABEL=r'(Critical|High|Medium|Low|Informational|Informative|Information|Info|Rec|Unknown|None|Potentially High|Recommendation)'
META=re.compile(r'^(?:ID|Project|Type|Category|Severity|Impact|Exploitability|Difficulty|Issue|Status(?: Update)?)\s*[:：]?\s+\S',re.I)

def _metadata_cards(report, unrated=False, method='legacy-metadata-card'):
    if report.meta.get('file_format')!='pdf':return []
    lines=report.lines; out=[]
    for i,l in enumerate(lines):
        m=re.match(r'^\s*Severity\s*:?\s+(?:[0-4](?:X)?\s+[-–]?\s*)?'+LABEL+r'\b',l.text,re.I)
        conditional=re.match(r'^\s*Severity\s+(With[^\n]+)',l.text,re.I)
        if not m and not conditional:continue
        # Require an actual card, not the methodology's SeverityScore definitions.
        nearby=report.near(max(0,i-8),20)
        if not re.search(r'(?mi)^\s*(?:Type|Category|Issue|Impact|Exploitability|Difficulty|Status|Involved artifacts|Description)\b',nearby):continue
        begin=i
        while begin>0 and i-begin<18:
            prev=lines[begin-1]
            if not prev.content or META.match(prev.content):begin-=1;continue
            break
        # The title block directly precedes the metadata block.
        last=begin-1
        while last>=0 and not lines[last].content:last-=1
        first=last
        while first>0 and lines[first-1].content and last-first<7 and lines[first-1].page==lines[last].page:first-=1
        if last<0:continue
        title_lines=lines[first:last+1]
        titlefield=next((j for j in range(max(0,i-22),i) if re.match(r'^Title\s+',lines[j].content)),None)
        if titlefield is not None:
            last=titlefield-1
            while last>=0 and (not lines[last].content or lines[last].content=='Description'):last-=1
            first=last
            while first>0 and lines[first-1].content and lines[first-1].page==lines[last].page and last-first<7:first-=1
            title_lines=lines[first:last+1]
        title=clean(' '.join(x.content for x in title_lines))
        if not title or re.search(r'©|Table of Contents|^Severity|^Finding Severity|^Severity Summary',title,re.I):continue
        pid=None
        idmatch=re.match(r'(IF-[A-Z0-9_-]+)\s*:\s*(.*)',title)
        if idmatch:pid=idmatch[1];title=idmatch[2]
        if not pid:
            explicit=re.search(r'(?m)^\s*ID\s*:?\s+(IF-[A-Z0-9_-]+)',report.text[lines[first].start:l.end])
            if explicit:pid=explicit[1]
        # Earliest reports print ID as a separate block above the title.
        if not pid:
            for prev in reversed(lines[max(0,first-5):first]):
                if re.fullmatch(r'IF-[A-Z0-9_-]+',prev.content):pid=prev.content;first=lines.index(prev);break
        if re.fullmatch(r'IF-[A-Z0-9_-]+',title):continue
        raw=m[1] if m else clean(' '.join(x.content for x in lines[i:i+3] if x.content and not META.match(x.content) or x is l))
        out.append(Candidate(lines[first].start,title,raw,pid,normalized=severity(raw, report.firm),method=method,confidence=.95,
                             evidence={'severity_basis':'conditional_publisher_severity' if conditional else 'explicit_severity_field'}))
    # Reports with no severity scheme (e.g. Skip) have standalone title/Description cards.
    if not out and unrated:
        for i,l in enumerate(lines):
            if l.content!='Description':continue
            last=i-1
            while last>=0 and not lines[last].content:last-=1
            first=last
            while first>0 and lines[first-1].content and lines[first-1].page==lines[last].page and last-first<6:first-=1
            title=clean(' '.join(x.content for x in lines[first:last+1]))
            if not title or re.search(r'©|^Severity|^Finding|^Type|^Impact|\s{3}',title):continue
            tail=report.text[l.start:l.start+10000]
            if not re.search(r'(?m)^\s*(?:Recommendation|Status Update)\s*$',tail):continue
            out.append(Candidate(lines[first].start,title,method='unrated-description-card',confidence=.85,evidence={'severity_basis':'unprinted_unknown'}))
    for n,c in enumerate(out):
        end=out[n+1].start if n+1<len(out) else len(report.text)
        tail=report.text[c.start:end]
        stop=re.search(r'(?mi)^\s*(?:Appendix(?:\s+[A-Z])?\s*[:\n]|About Informal Systems|Vulnerability Classification|Severity Classification|Methodology|Disclaimer)\s*',tail)
        c.end=c.start+stop.start() if stop and stop.start()>80 else end
    return out

def _aggregate_counts(report):
    generic=generic_counts(report)
    if generic:return generic
    counts={};evidence=[]
    for l in report.lines:
        m=re.match(r'^\s*Total\s+'+LABEL+r'[- ]Severity Issues\s+(\d+)\b',l.text,re.I)
        if m:
            key=severity(m[1], report.firm);counts[key]=int(m[2]);evidence.append({'start':l.start,'end':l.end,'text':l.text})
    return {'counts':counts,'basis':'printed_total_severity_issues','evidence':evidence} if counts else None


def printed_counts(report):
    summary=_aggregate_counts(report)
    if not summary:return None
    # Conditional source grades cannot be compared to a single unconditional
    # normalized bucket. The report's own footnote is the ambiguity evidence.
    conditional=re.search(r'(?im)^\s*\[\*\]\s*-\s*only for[^\n]+',report.text)
    if conditional and re.search(r'(?im)^\s*Severity\s+With\b',report.text):
        return dict(summary,ambiguous=True,comparison_limit='Conditional publisher grades have no single unconditional severity.',
                    conditional_evidence={'start':conditional.start(),'end':conditional.end(),'text':conditional[0]})
    # Compare independent publisher summary presentations, never parsed detail
    # rows. A complete finding/status index can contradict the numeric table.
    values=Counter();proof=[]
    for page in report.meta['pages']:
        lines=page['text'].splitlines(keepends=True)
        if not any(re.match(r'^\s*Finding\s+Type\s+Severity\s+Status\s*$',l,re.I) for l in lines):continue
        offset=page['start'];active=False
        for line in lines:
            if re.match(r'^\s*Finding\s+Type\s+Severity\s+Status\s*$',line,re.I):active=True
            if active:
                m=re.search(r'\s{2,}(?:Protocol|Implementation|Documentation|Design|Practice)\s+(?:[0-4]\s+)?'+LABEL+r'\s{2,}'+STATUS+r'\s*$',line,re.I)
                if m:
                    values[severity(m[1],report.firm)]+=1
                    proof.append({'start':offset,'end':offset+len(line.rstrip('\r\n')),'text':line.rstrip('\r\n')})
            offset+=len(line)
    if values and sum(values.values())==sum(summary['counts'].values()) and any(values[k]!=v for k,v in summary['counts'].items()):
        return dict(summary,ambiguous=True,comparison_limit='Publisher numeric overview and complete finding/status index disagree.',
                    alternatives=[{'counts':dict(values),'evidence':proof,'basis':'printed_finding_status_index'}])
    return summary


from variants import Variant, Fingerprint, dispatch
from layout_support import status_value

STATUS = r'(?:Patched Without Reaudit|Partially (?:Resolved|Fixed|Implemented)|Not (?:Resolved|Fixed|Implemented)|Risk Accepted|In Progress|PR created|Reported|Outdated|Disputed|Acknowledged|Unresolved|Resolved|Fixed|Patched|Open|Pending|Implemented|Mitigated|Accepted|Invalid|Won[’\x27]t Fix)'


def _title_key(value):
    value=unicodedata.normalize('NFKC',value).casefold()
    value=re.sub(r'(?<=\w)-\s+(?=\w)','',value)
    return re.sub(r'\s+','',value).replace('\u00ad','')


def _table_statuses(report):
    claims={}
    for page in report.meta['pages']:
        header=None;parts=[];pending=None
        def emit():
            if pending and parts:claims.setdefault(_title_key(' '.join(parts)),[]).append(pending)
        for line in [l for l in report.lines if l.page==page['page']]:
            if re.match(r'^\s*Finding\s+Type\s+Severity\s+Status\s*$',line.text,re.I):
                header=line.text.lower().index('type');continue
            if header is None:continue
            m=re.search(r'\s{2,}'+LABEL+r'\s{2,}('+STATUS+r')\s*$',line.text,re.I)
            if m:
                emit();parts=[line.text[:header].strip()];pending=(line.start+m.start(2),line.start+m.end(2));continue
            if not line.content:
                emit();parts=[];pending=None;continue
            if pending and not line.text[header:].strip() and not re.fullmatch(r'\d+',line.content):
                parts.append(line.text[:header].strip())
        emit()
    return claims


def _status_cards(report,candidates,sections=True):
    table=_table_statuses(report)
    for c in candidates:
        body=report.text[c.start:c.end]
        claims=[]
        # Match only status labels; preserve exact tokens, including qualifiers
        # such as "Patched Without Reaudit" and "Risk Accepted".
        for m in re.finditer(r'(?im)(?:^[ \t]*|[ \t]{2,})Status(?: Update)?[ \t]*:?[ \t]*(?:\n[ \t]*)?('+STATUS+r')\b',body):
            claims.append((m.start(1),m.end(1),'labelled_status_field'))
        if sections:
            for m in re.finditer(r'(?im)^[ \t]*(?:Resolution|Fix Review|Status Update)[ \t]*[:.]?[ \t]*\n[ \t]*('+STATUS+r')\b',body):
                claims.append((m.start(1),m.end(1),'resolution_section'))
            # Explicit decisions/actions in a named status update are claims,
            # even when the publisher writes a sentence instead of a badge.
            section_pattern=r'(?im)^[ \t]*(?:Status Update|Resolution|Fix Review)[ \t]*[:.]?[ \t]*\n[ \t]*'
            for heading in re.finditer(section_pattern,body):
                tail=body[heading.end():heading.end()+700]
                m=re.match(r'(?:The [^\n.]{0,90}?team (?:has decided not to address[^\n.]*|is not going to address[^\n.]*))',tail,re.I)
                normalized='acknowledged'
                if not m:
                    m=re.match(r'(?:Removed dead code|(?:All )?Addressed)(?:[^\n.]*)',tail,re.I)
                    normalized='resolved'
                if m:claims.append((heading.end()+m.start(),heading.end()+m.end(),'publisher_status_update_decision',normalized))
        c.status_raw=None;c.normalized_status=None
        if not claims:
            indexed=table.get(_title_key(c.title),[])
            unique={status_value(report.text[s:e],'informalsystems') for s,e in indexed}
            if len(unique)==1:
                start,end=indexed[-1];claims=[(start-c.start,end-c.start,'printed_title_status_table')]
            else:
                if indexed:c.evidence['status_conflict']=True
                continue
        chosen=max(claims,key=lambda x:x[0]);start,end,basis=chosen[:3]
        start+=c.start;end+=c.start;raw=report.text[start:end]
        c.status_raw=raw;c.normalized_status=chosen[3] if len(chosen)>3 else {'pr created':'open'}.get(raw.casefold()) or status_value(raw,'informalsystems')
        c.evidence['status_evidence']={'raw':raw,'text':raw,'start':start,'end':end,'basis':basis,'profile':'informalsystems'}


def legacy_cards(report):return _metadata_cards(report,method='legacy-if-metadata-card')
def numeric_cards(report):return _metadata_cards(report,method='numeric-severity-metadata-card')
def modern_stacked_cards(report):return _metadata_cards(report,method='modern-stacked-metadata-card')
def modern_compact_cards(report):return _metadata_cards(report,method='modern-compact-metadata-card')
def ungraded_cards(report):return _metadata_cards(report,True)
def protocol_assessment(report):return []

def legacy_status(report,candidates):return _status_cards(report,candidates)
def numeric_status(report,candidates):return _status_cards(report,candidates)
def stacked_status(report,candidates):return _status_cards(report,candidates)
def compact_status(report,candidates):return _status_cards(report,candidates)
def ungraded_status(report,candidates):return _status_cards(report,candidates)
def fragment_status(report,candidates):return _status_cards(report,candidates)


def markdown_index(report):
    out=[]
    for l in report.lines:
        m=re.match(r'^\|\s*(IF-[A-Z0-9_-]+)\s*\|\s*\[([^\]]+)\]\([^)]*\)\s*\|[^|]*\|\s*'+LABEL+r'\s*\|',l.content,re.I)
        if not m:continue
        out.append(Candidate(l.start,m[2],m[3],m[1],end=l.end,record_kind='summary_excerpt',
                             method='markdown-finding-index',confidence=.98,
                             evidence={'severity_basis':'explicit_index_label','linked_details_not_in_artifact':True}))
    return out


def markdown_fragments(report):
    # Dashboard, scope, coverage and narrative summaries link to separately
    # published findings. Their counts are not substitutes for detail cards.
    return []


def fragment_counts(report):
    summary=printed_counts(report)
    return dict(summary,ambiguous=True,comparison_limit='Summary-only report fragment; detailed findings are linked artifacts.') if summary else None


def parse(report):return dispatch(report,VARIANTS)

VARIANTS=(
 Variant('informalsystems/v2025_compact_cards',Fingerprint((('compact_severity_metadata',r'^\s*Severity\s+'+LABEL+r'[^\n]+(?:Impact|Exploitability)\s+',10),),('2025','2026'),('pdf',)),modern_compact_cards,('informal_compact',),compact_status),
 Variant('informalsystems/v2025_stacked_cards',Fingerprint((('modern_finding_id',r'^\s*ID\s+IF-FINDING-\d+',10),('plain_severity',r'^\s*Severity\s+'+LABEL+r'\s*$',2)),('2025','2026'),('pdf',)),modern_stacked_cards,('informal_stacked',),stacked_status),
 Variant('informalsystems/v2022_numeric_metadata',Fingerprint((('scored_severity',r'^\s*Severity\s+(?:[0-4](?:X)?\s+(?:[-–]\s*)?'+LABEL+r'|With\b)',10),('project_field',r'^\s*Project\s+\S',2)),('2022','2024'),('pdf',)),numeric_cards,('informal_numeric','informal_conditional'),numeric_status),
 Variant('informalsystems/v2021_legacy_metadata',Fingerprint((('legacy_if_title',r'^\s*IF-[A-Z0-9_-]+\s*:',8),('standalone_if_id',r'^\s*IF-[A-Z0-9_-]+\s*$',3),('severity_field',r'^\s*Severity\s*:?\s+'+LABEL+r'\b',4),('category_type',r'^\s*(?:Category|Type)\s*:?\s+\S',2)),('2021','2023'),('pdf',)),legacy_cards,('informal_legacy',),legacy_status),
 Variant('informalsystems/v2023_ungraded',Fingerprint((('ungraded_skip',r'\bSkip:\s*mev-tendermint\b',8),('description_section',r'^\s*Description\s*$',2),('status_update_section',r'^\s*Status Update\s*$',2)),('2023','2023'),('pdf',)),ungraded_cards,('informal_ungraded',),ungraded_status),
 Variant('informalsystems/v2022_protocol_assessment',Fingerprint((('protocol_analysis',r'(?:Formal Methods Assessment Report|Neutron Dex Model)',6),('assessment_author',r'Informal Systems',1)),('2021','2024'),('pdf',)),protocol_assessment,('informal_protocol',),fragment_status),
 Variant('informalsystems/v2020_markdown_index',Fingerprint((('findings_index',r'^\s*\|\s*\*\*(?:#|ID)\*\*\s*\|\s*\*\*Title\*\*\s*\|',8),),('2020','2022'),('md',)),markdown_index,('informal_markdown_index',),fragment_status,fragment_counts),
 Variant('informalsystems/v2020_markdown_fragments',Fingerprint((('report_fragment_heading',r'^\s*#\s+(?:\*\*)?(?:Audit (?:overview|Dashboard)|Engagement Goals|Coverage|Recommendations|Collaboration scope|Code review of the payment module|Osmosis|NMT Audit summary)\b',7),),('2020','2023'),('md',)),markdown_fragments,('informal_markdown_fragment',),fragment_status,fragment_counts),
)
