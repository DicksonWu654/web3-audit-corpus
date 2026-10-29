"""Least Authority issue/suggestion cards; severity is never inferred from kind."""
import re
from core import Candidate, clean
DESCRIPTION = 'Lettered Issue and numbered Suggestion detail cards with explicit Impact labels or unknown severity'
HEADER = re.compile(r'^((?:Known\s+)?Issue\s+[A-Z]{1,3}|Suggestion\s+\d+)\s*:\s*(.*)', re.I)
FIELD = re.compile(r'^(?:Location(?:s)?|Synopsis|Description|Impact|Preconditions|Recommendation(?:s)?|Mitigation|Remediation|Status|Resolution)\s*[:：]?$',re.I)
STATUS = re.compile(r'\b(Partially (?:Resolved|Fixed)|Resolved|Unresolved|Acknowledged|Fixed|Open|Void|Not Resolved)\b',re.I)

def parse(report, family=None):
    lines=report.lines; out=[]; index={}
    for line in lines if family in {None,'risk_index'} else []:
        head=HEADER.match(clean(line.content))
        if not head:continue
        risk=re.search(r'\s{3,}(Critical|High|Medium|Low|Informational)\s{2,}(?:Partially|Resolved|Unresolved|Acknowledged|Void)',line.text,re.I)
        if risk:index[head[1]]={'raw':risk[1],'start':line.start,'end':line.end,'text':line.text}

    for i,line in enumerate(lines):
        s=clean(line.content); m=HEADER.match(s)
        if not m or line.code: continue
        if re.search(r'\s{3,}Reported:',line.text,re.I):continue
        # Index rows have a right-hand status; detail cards have their own fields.
        if re.search(r'\s{3,}(?:Partially )?(?:Resolved|Unresolved|Void|Acknowledged)\b',line.text,re.I): continue
        nexthead=next((j for j in range(i+1,min(i+28,len(lines))) if HEADER.match(clean(lines[j].content))),min(i+28,len(lines)))
        fields=[j for j in range(i+1,nexthead) if (FIELD.fullmatch(clean(lines[j].content)) or re.match(r'^(?:Synopsis|Reported):',clean(lines[j].content),re.I))]
        if not fields or fields[0]-i>16:
            following=next((l for l in lines[i+1:i+4] if l.content),None)
            if following and re.match(r'^(?:While|We|This|The|In|For)\s',following.content) and len(following.content)>55 and len(line.text)-len(line.text.lstrip())<3:
                out.append(Candidate(line.start,m[2],printed_id=m[1],method='issue-suggestion-prose',confidence=.85,evidence={'severity_basis':'unprinted_unknown','kind':m[1].split()[0]}))
            continue
        if re.fullmatch(r'(?:Status|Resolution)',clean(lines[fields[0]].content),re.I):continue
        if lines[fields[0]].page>line.page+1:continue
        if line.excluded and re.search(r'Table\s+of\s+Contents',report.meta['pages'][line.page-1]['text'],re.I):continue
        first=fields[0]
        if re.fullmatch(r'Recommendations',clean(lines[first].content),re.I) and any(l.content=='About Least Authority' for l in lines[first+1:first+5]):continue
        title=clean(' '.join([m[2]]+[l.content for l in lines[i+1:first] if l.content]))
        if not title:continue
        out.append(Candidate(line.start,title,printed_id=m[1],method='issue-suggestion-card',confidence=.93,
                             evidence={'severity_basis':'unprinted_unknown','kind':m[1].split()[0],'layout_grammar':family or 'compatibility'}))
    for n,c in enumerate(out):
        end=out[n+1].start if n+1<len(out) else len(report.text)
        body=report.text[c.start:end]
        stop=re.search(r'\n\s*(?:About Least Authority|Our Methodology|Appendix(?:\s+[A-Z0-9]+)?\s*(?:[:–—-]|\n))',body,re.I)
        c.end=c.start+stop.start() if stop else end
        body=report.text[c.start:c.end]
        impact=re.search(r'(?mi)^\s*(?:Impact|Severity)\s*:?\s*(?:\n\s*)?(Critical|High|Medium|Low|Informational|Information|Info)\b',body)
        if impact:
            c.severity_raw=impact[1]; c.evidence['severity_basis']='explicit_impact_label'
        if not c.severity_raw and c.printed_id in index:
            label=index[c.printed_id];c.severity_raw=label['raw'];c.evidence['severity_basis']='printed_id_risk_index';c.evidence['severity_index']=label
        statuses=list(re.finditer(r'(?mi)^\s*(?:Verification|Status)\s*:?\s*(?:\n\s*)?([^\n]+)',body))
        status=statuses[-1] if statuses else None
        if status:
            label=STATUS.match(clean(status[1]))
            c.status_raw=label[1] if label else clean(status[1]).strip('.')
            c.evidence['status_basis']='printed_verification_or_status_field'
    if out:
        # A plain "Known Issues" entry in the early contents pages otherwise
        # opens a spurious prior-audit range through the rest of this report.
        # Real Known Issue cards remain excluded by their explicit native ID.
        from prior_findings import prior_sections
        first=min(c.start for c in out)
        report._prior_sections=[r for r in prior_sections(report) if r['start']>=first]
    return out


from variants import Variant, Fingerprint
from parsers.group2_layouts import statuses

def parse_reported(report):return parse(report,'reported')
def parse_status_cards(report):return parse(report,'status_cards')
def parse_risk_index(report):return parse(report,'risk_index')
def parse_narrative(report):return []
def status_reported(report,candidates):statuses(report,candidates,fields=('Status','Verification','Resolution'),headings=True,index_id=r'(?:Issue\s+[A-Z]{1,3}|Suggestion\s+\d+)')
def status_cards(report,candidates):statuses(report,candidates,fields=('Status','Verification','Resolution'),headings=True,index_id=r'(?:Issue\s+[A-Z]{1,3}|Suggestion\s+\d+)')
def status_risk_index(report,candidates):status_cards(report,candidates)
def status_narrative(report,candidates):return None

VARIANTS=(
    Variant('least-authority/v2026_risk_index',Fingerprint((('risk index',r'(?:Issue [A-Z]{1,3}|Suggestion \d+):[^\n]*\s{3,}(?:Critical|High|Medium|Low|Informational)\s{2,}(?:Partially|Resolved|Unresolved|Acknowledged)',10),),('2026','2026')),parse_risk_index,('least_risk_index',),status_risk_index,notes='Issue/Suggestion cards plus a risk/status index; severity comes from explicit Impact fields or ID-linked risk cells.'),
    Variant('least-authority/v2017_reported',Fingerprint((('reported issue row',r'(?:Issue [A-Z]{1,3}:[^\n]*\s{3,}Reported:|^\s*Reported:)',8),),('2017','2018')),parse_reported,('least_reported',),status_reported,notes='Early Reported/Synopsis issue cards; Reported is a date field, never an open-status assertion. Only explicit Status/Verification or index cells determine status.'),
    Variant('least-authority/v2019_status_cards',Fingerprint((('issue namespace',r'(?:Issue\s+[A-Z]{1,3}|Suggestion\s+\d+)\s*:',5),('card field',r'^\s*(?:Synopsis|Description|Location|Status|Verification|Recommendation)\s*[:：]?\s*$',2)),('2018','2026')),parse_status_cards,('least_status_cards',),status_cards,notes='Lettered Issues and numbered Suggestions, ungraded unless an explicit risk is printed; final Verification overrides original Status; index fallback is ID-linked.'),
    Variant('least-authority/v2015_narrative',Fingerprint((('narrative review',r'Ethereum Analysis: Gas Economics and Proof of Work|review of the Marmot Protocol|Protocol Review Summary',8),),('2015','2026')),parse_narrative,('least_narrative',),status_narrative,notes='Research README and protocol-review summary without formal issue cards; no manufactured findings or statuses.'),
)
