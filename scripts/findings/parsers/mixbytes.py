"""MixBytes detail cards and pre-card numbered severity sections."""
from core import SeverityLookup, severity, Candidate, clean
import re
from summary_counts import printed_counts as generic_counts
from layout_support import status_value, visible
from variants import Variant, Fingerprint

DESCRIPTION = 'MixBytes explicit-severity detail cards, legacy numbered severity sections; preserves native status and IDs'
LABEL = r'Critical|High|Medium|Low|Informational|Major|Warning|Comment'
# The legacy report defines Warning as broken intended logic/DoS, matching its
# later Medium definition; Comment is explicitly other issues/recommendations.
MAPPING = SeverityLookup('mixbytes', ('warning', 'warnings', 'comment', 'comments', 'major', 'serious', 'severe', 'note', 'notes', 'remarks', 'remark', 'критические', 'серьезные', 'предупреждения', 'замечания'))


def _map(raw):
    return MAPPING.get(raw.lower())


def _cards(report, layout):
    entries=[]
    detail=False
    for i,line in enumerate(report.lines):
        if re.match(r'^(?:2\s*\.?\s*FINDINGS REPORT|\[\s*2\s+FINDINGS REPORT\s*\])$',line.content,re.I):detail=True
        m=re.match(r'^(CRT|CR|MJR|WRN|CMT|C|H|M|L|I)-\s*(\d+)\s+(.+)',line.content)
        if not m or line.code or re.search(r'(?:\.\s*){4,}\s*\d+\s*$',line.text):continue
        window=report.lines[i+1:i+24]
        field=next((l for l in window if re.match(r'^Severity\s*[:|]?\s+('+LABEL+r')\b',l.content,re.I)),None)
        # A summary row never has a separate Severity label before another ID.
        nextid=next((l.start for l in window if re.match(r'^(?:CRT|CR|MJR|WRN|CMT|C|H|M|L|I)-\s*\d+\b',l.content)),len(report.text))
        if field is None or field.start>nextid:
            # 2026 redesign: severity/status occupy the right of the title card.
            risk=re.search(r'\s{3,}(CRITICAL|HIGH|MEDIUM|LOW)\s*$',m[3])
            if layout!='badge' or not detail or not risk:continue
            titles=[m[3][:risk.start()]]; raw=risk[1];rawstatus=None
            for l in window:
                if re.match(r'^DESCRIPTION\b',l.content,re.I):break
                val=l.content
                st=re.search(r'(?:^|\s{3,})(PARTIALLY FIXED|FIXED|ACKNOWLEDGED|NO ISSUE)\s*$',val,re.I)
                if st:rawstatus=st[1];val=val[:st.start()]
                if val:titles.append(val)
            entries.append(Candidate(line.start,clean(' '.join(titles)),raw,f'{m[1]}-{m[2]}',status_raw=rawstatus,method='mixbytes-redesigned-card',confidence=.98,evidence={'severity_basis':'explicit_publisher_label'}))
            continue
        if layout=='badge':continue
        parallel=bool(re.search(r'\bStatus[ \t]+',field.text,re.I))
        if layout=='parallel' and not parallel:continue
        if layout=='stacked' and parallel:continue
        raw=re.match(r'^Severity\s*[:|]?\s+('+LABEL+r')\b',field.content,re.I)[1]
        title=[m[3]]
        for l in window:
            if l.start>=field.start or re.match(r'^(?:Files?|Status|Description)\b',l.content,re.I):break
            if l.content and not l.content.isdigit():title.append(l.content)
        metadata_end=min(nextid,next((l.start for l in window if l.start>field.start and re.match(r'^Description\b',l.content,re.I)),report.lines[min(i+28,len(report.lines)-1)].end))
        stat=re.search(r'\bStatus\s*[:|]?\s+([^\n]+)',report.text[field.start:metadata_end],re.I)
        rawstatus=clean(stat[1]) if stat else None
        entries.append(Candidate(line.start,clean(' '.join(title)),raw,f'{m[1]}-{m[2]}',normalized=severity(raw, report.firm),status_raw=rawstatus,method='mixbytes-detail-card',confidence=.97,evidence={'severity_basis':'explicit_publisher_label','legacy_mapping':_map(raw)}))
    return _bound(report,entries)


def _sections(report):
    """Native numbered issues; severity/project headings define ID namespaces."""
    entries=[]; current=None; reference_series=None; anchor=None
    global_series=bool(re.search(r'^#{3,6}[ \t]+\[SEVERE\]',report.text,re.M))
    for i,line in enumerate(report.lines):
        s=line.content.replace('\u200b','').strip(' []')
        s=re.sub(r'\*\*(\d+[.)]?)\*\*',r'\1',s).strip('* ')
        if re.search(r'(?:SECURITY ASSES+MENT METHODOLOGY|AUDIT METHODOLOGY|МЕТОДИКА АУДИТА)',s,re.I):
            current=None
            continue
        parent=re.fullmatch(r'(CRITICAL|MAJOR|WARNINGS?|COMMENTS?|HIGH|MEDIUM|LOW|SEVERE|NOTES?|SERIOUS|REMARKS?|КРИТИЧЕСКИЕ|СЕРЬЕЗНЫЕ|ПРЕДУПРЕЖДЕНИЯ|ЗАМЕЧАНИЯ)',s,re.I)
        if parent:
            current=parent[1];reference_series=None;anchor=line;continue
        if re.fullmatch(r'PROPOSALS?|SUGGESTIONS?',s,re.I):
            current='recommendation';reference_series=None;anchor=line;continue
        if re.match(r'^(?:APPENDIX|CONCLUSION|(?:\d+\.)?\s*ABOUT MIXBYTES|Scope of the audit|Detected Issues)\b',s,re.I) or (line.heading and line.heading<=2):current=None
        m=re.match(r'^(\d+)\\?[.)]\s*(?!\d)(\S.*)',s)
        if current and m and not line.code:
            title=m[2]
            reference=bool(re.match(r'(?:https?://|[<\[]|[A-Za-z_][\w./-]*\.(?:sol|vy|rs|js)(?:#|:))',title))
            if report.meta.get('file_format')=='md' and not (line.heading or reference or re.match(r'^\d+\\[.)]',s) or re.match(r'^\*\*\d+',line.content)):continue
            if report.meta.get('file_format')=='pdf':
                if reference_series is None:reference_series=reference
                if reference_series and not reference and re.search(r'(?:attack vector|Consider the situation|Let.s say)',report.text[max(0,line.start-700):line.start],re.I):continue
            # URLs and source links are printed titles in the oldest format.
            recommendation=current=='recommendation'
            entries.append(Candidate(line.start,title,None if recommendation else current,m[1],record_kind='recommendation' if recommendation else 'formal_finding',method='mixbytes-legacy-severity-section',confidence=.88,evidence={'severity_basis':'publisher_recommendation_section' if recommendation else 'explicit_severity_parent','container_id':'mixbytes-global' if global_series else 'mixbytes-section:'+str(anchor.start),'source_section':current}))
    return _bound(report,entries)


def _bound(report,entries):
    entries.sort(key=lambda c:c.start)
    for j,c in enumerate(entries):
        end=entries[j+1].start if j+1<len(entries) else len(report.text)
        tail=report.text[c.start:end]
        stop=re.search(r'(?im)^\s*(?:#{1,3}\s*)?(?:3\s*\.?\s*ABOUT MIXBYTES|\[\s*3\s+ABOUT MIXBYTES\s*\]|APPENDIX\b|CONCLUSION|2\.[1-5]\s+(?:Critical|High|Medium|Low)|(?:CRITICAL|MAJOR|WARNINGS?|COMMENTS?)\s*$)',tail)
        if stop and stop.start()>0:end=c.start+stop.start()
        c.end=end
        if c.status_raw is None:
            m=re.search(r'(?im)^\s*\*?(Fixed|Acknowledged|No issue)\b[^\n]*',report.text[c.start:end])
            if m:c.status_raw=clean(m[0].strip('* '))
    return entries


def markdown_sections(report):return _sections(report)
def numbered_sections(report):return _sections(report)
def stacked_cards(report):return _cards(report,'stacked')
def parallel_cards(report):return _cards(report,'parallel')
def badge_cards(report):return _cards(report,'badge')


def parse(report):
    """Direct-call compatibility; the dispatcher selects an era before parsing."""
    return _cards(report,'stacked') or _cards(report,'parallel') or _cards(report,'badge') or _sections(report)


_STATE=r'(?:Partially[ \t]+(?:Fixed|Resolved|Implemented)|Not[ \t]+(?:Fixed|Resolved|Implemented)|No[ \t]+issue|Acknowledged|Fixed|Resolved|Unresolved|Open|Pending|Implemented|Removed)'
_RESPONSE=r'(?:(?!Removed\b)'+_STATE+r'|Almost all fixed|This (?:issue )?(?:has been|was) (?:fully )?(?:fixed|resolved)|A check has been added in|This (?:has been|was already) (?:updated|done|added) in|Реализовано в|Исправлено в)'


def _state(raw):
    value=clean(visible(raw)).strip('* ').casefold().rstrip('.')
    if re.match(r'^no issue\b',value):return 'invalid'
    if re.match(r'^(?:not (?:fixed|resolved|implemented)|unresolved|open|pending)\b',value):return 'open'
    if re.match(r'^partially (?:fixed|resolved|implemented)\b',value):return 'partial'
    if re.match(r'^acknowledged\b',value):return 'acknowledged'
    if re.match(r'^(?:fixed|implemented)\b',value):return 'fixed'
    if re.match(r'^resolved\b',value):return 'resolved'
    if re.match(r'^(?:this (?:issue )?(?:has been|was) (?:fully )?fixed|a check has been added in|реализовано в|исправлено в)\b',value):return 'fixed'
    if re.match(r'^this (?:(?:issue )?(?:has been|was) (?:fully )?resolved|(?:has been|was already) (?:updated|done|added) in)\b',value):return 'resolved'
    return status_value(raw,'mixbytes')


def _statuses(report,candidates,profile):
    # Only explicitly printed ID/status rows are eligible as fallback evidence.
    tables={}
    for line in report.lines:
        m=re.match(r'^[ \t]*((?:CRT|CR|MJR|WRN|CMT|C|H|M|L|I)-[ \t]*\d+)\b',line.text)
        state=re.search(r'\b(?:'+LABEL+r')[ \t]{2,}('+_STATE+r')\b[^\n]*$',line.text,re.I)
        if m and state and re.search(r'\s{2,}',line.text):
            start=line.start+state.start(1);end=line.start+state.end()
            tables.setdefault(re.sub(r'\s','',m[1]),[]).append((report.text[start:end].strip(),start,end,'id_status_table'))
    for c in candidates:
        body=report.text[c.start:c.end]; claims=[]
        # The metadata row may have severity and status side by side.
        for m in re.finditer(r'(?im)^[ \t]*(?:Severity[ \t]+(?:'+LABEL+r')[ \t]+)?Status[ \t]*[:|]?[ \t]*(?:\n[ \t]*){0,3}('+_STATE+r')\b[^\n]*',body):
            claims.append((m[0][m.start(1)-m.start():].rstrip(),c.start+m.start(1),c.start+m.end(),'labelled_status_field'))
        if not claims:
            # Legacy responses and new Client's Commentary are standalone,
            # publisher-labelled remediation statements, never recommendations.
            for m in re.finditer(r'(?im)^[ \t]*\*?('+_RESPONSE+r')\b[^\n]*',body):
                claims.append((m[0][m.start(1)-m.start():].strip().rstrip('*'),c.start+m.start(1),c.start+m.end(),'resolution_response'))
        if not claims and c.status_raw:
            # Badge status is attached by the title grammar, with an exact span.
            m=re.search(re.escape(c.status_raw),body,re.I)
            if m:claims.append((m[0],c.start+m.start(),c.start+m.end(),'printed_card_badge'))
        if not claims:
            table=tables.get(c.printed_id,[])
            if len({_state(claim[0]) for claim in table})==1:claims=table[-1:]
            elif table:c.evidence['status_conflict']=True
        if claims:
            raw,start,end,basis=claims[-1]
            # The claim reader trims trailing Markdown delimiters/whitespace;
            # its evidence span must end at the same exact source character.
            end=start+len(raw)
            c.status_raw=raw;c.normalized_status=_state(raw)
            c.evidence['status_evidence']={'raw':raw,'start':start,'end':end,'text':report.text[start:end],'basis':basis,'profile':profile}
            if basis=='resolution_response':c.resolution=report.text[start:end]


def markdown_status(report,candidates):return _statuses(report,candidates,'mixbytes-markdown')
def numbered_status(report,candidates):return _statuses(report,candidates,'mixbytes-numbered')
def stacked_status(report,candidates):return _statuses(report,candidates,'mixbytes-stacked')
def parallel_status(report,candidates):return _statuses(report,candidates,'mixbytes-parallel')
def badge_status(report,candidates):return _statuses(report,candidates,'mixbytes-badge')


def printed_counts(report):
    # Redesigned aggregate charts print counts ABOVE labels, including Total.
    for i,l in enumerate(report.lines):
        if re.fullmatch(r'CRITICAL\s+HIGH\s+MEDIUM\s+LOW\s+TOTAL',l.content,re.I):
            prev=next((p for p in reversed(report.lines[max(0,i-5):i]) if p.content),None)
            if prev and re.fullmatch(r'\d+\s+\d+\s+\d+\s+\d+\s+\d+',prev.content):
                nums=list(map(int,prev.content.split()))
                return {'counts':dict(zip(('critical','high','medium','low'),nums[:4])),'basis':'mixbytes_printed_reverse_chart','evidence':[{'start':prev.start,'end':l.end,'page':l.page,'text':report.text[prev.start:l.end]}]}
    return generic_counts(report)


VARIANTS=(
 Variant('mixbytes/v2026_badge_cards',Fingerprint((('bracketed_findings',r'^\s*\[[ \t]*2[ \t]+FINDINGS REPORT[ \t]*\]',8),('title_badge',r'^\s*(?:CRT|CR|C|H|M|L|I)-[ \t]*\d+[ \t]+[^\n]+[ \t]{3,}(?:CRITICAL|HIGH|MEDIUM|LOW)[ \t]*$',9)),('2026',None),formats=('pdf',)),badge_cards,('mixbytes_badge',),badge_status),
 Variant('mixbytes/v2025_parallel_cards',Fingerprint((('parallel_fields',r'^\s*Severity[ \t]+(?:'+LABEL+r')[ \t]+Status[ \t]+',10),('summary_table',r'^\s*Severity[ \t]+(?:# of Findings|Count)[ \t]*$',6),('modern_summary',r'^\s*1\.6[ \t]+Summary of Findings[ \t]*$',6)),('2025',None),formats=('pdf',)),parallel_cards,('mixbytes_parallel','mixbytes_parallel_clean'),parallel_status,notes='Side-by-side severity/status cards in 2025–2026; the same summary shell covers clean reports from 2023 onward.'),
 Variant('mixbytes/v2020_stacked_cards',Fingerprint((('stacked_field',r'^\s*Severity[ \t]+(?:'+LABEL+r')[ \t]*$',9),('old_breakdown',r'^\s*FINDINGS SEVERITY BREAKDOWN[ \t]*$',7)),('2020',None),formats=('pdf',)),stacked_cards,('mixbytes_stacked',),stacked_status,notes='Separate severity/status metadata rows; this template remains in use through 2026.'),
 Variant('mixbytes/v2018_markdown_sections',Fingerprint((('severity_parent',r'^\s*#{2,6}[ \t]+\[?(?:CRITICAL|MAJOR|WARNINGS?|COMMENTS?|SERIOUS|SEVERE|NOTES?|REMARKS?|КРИТИЧЕСКИЕ|СЕРЬЕЗНЫЕ|ПРЕДУПРЕЖДЕНИЯ|ЗАМЕЧАНИЯ)\]?[ \t]*$',8),),('2018','2020'),formats=('md',)),markdown_sections,('mixbytes_markdown',),markdown_status),
 Variant('mixbytes/v2019_numbered_sections',Fingerprint((('detected_issues',r'^\s*(?:DETECTED ISSUES|Identified Issues)(?:[ \t]*\([^\n]*\))?[ \t]*$',4),('severity_parent',r'^\s*(?:CRITICAL|MAJOR|WARNINGS?|COMMENTS?|SERIOUS|SEVERE|NOTES?|REMARKS?)[ \t]*$',6)),('2019','2021'),formats=('pdf',)),numbered_sections,('mixbytes_numbered',),numbered_status),
)
