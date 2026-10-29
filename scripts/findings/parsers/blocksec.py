"""BlockSec numbered findings, recommendations and notes, with explicit labels."""
from core import severity, Candidate, clean
import re
from summary_counts import printed_counts as generic_counts

DESCRIPTION = 'BlockSec numbered Chapter 2 details, explicit risk/status metadata and native recommendations/notes'


def parse(report, family=None):
    entries=[]; parent=None; table_severity={}
    toc_pages={p['page'] for p in report.meta['pages'] if re.search(r'^\s*Contents\s*$',p['text'],re.M)}
    if toc_pages:
        first=min(toc_pages)
        for p in report.meta['pages']:
            if p['page']<=first:continue
            if re.search(r'^\s*(?:Report Manifest|Chapter 1 Introduction)\s*$',p['text'],re.M):break
            toc_pages.add(p['page'])
    nested=family=='nested' or (family is None and bool(re.search(r'(?m)^\s*[23]\.\d+\.\d+\.\d+\s+[^\n]+\n\n(?:Severity|Status)',report.text)))
    # Early editions put severity only in the printed issue index, not the card.
    # Read row labels independently of aggregate totals and attach by printed order.
    detail_start=next((l.start for l in report.lines if re.match(r'^[23]\.\d+\.\d+(?:\.\d+)?\s+',l.content) and not re.search(r'(?:\.\s*){4,}',l.text) and l.page not in toc_pages),len(report.text))
    for l in report.lines:
        if l.start>=detail_start:break
        m=re.match(r'^\s*(\d+)\s+(Critical|High|Medium|Middle|Low)',l.text,re.I)
        if m:table_severity[int(m[1])]=(m[2],l.start,l.end)
    for i,line in enumerate(report.lines):
        if line.code or line.page in toc_pages or re.search(r'(?:\.\s*){4,}\s*\d+\s*$',line.text):continue
        p=re.match(r'^[23]\.\d+\s+(.+)',line.content)
        if p:parent=p[1]
        m=re.match(r'^([23]\.\d+\.\d+(?:\.\d+)?)\s+(.+)',line.content)
        if not m or (nested and len(m[1].split('.'))!=4):continue
        if family in {'index','fields','version'} and len(m[1].split('.'))!=3:continue
        following=[]
        for l in report.lines[i+1:i+20]:
            if re.match(r'^[23]\.\d+(?:\.\d+){0,2}\s+',l.content):break
            following.append(l)
        # Metadata may wrap across a page; limit to the initial metadata block.
        near='\n'.join(l.text for l in following)
        sev=re.search(r'(?im)^\s*Severity\s*:?\s*(Critical|High|Medium|Middle|Low|Informational|Information|Undetermined)\b',near)
        title=[m[2]]
        for l in following:
            if not l.content:break
            if re.match(r'^(?:Severity|Status|Introduced by|Description|Impact|Suggestion|Feedback)\b',l.content,re.I):break
            if l.content and not l.content.isdigit():title.append(l.content)
        st=re.search(r'(?im)^\s*Status\s*:?\s*([^\n]+)',near)
        if nested and not (sev or st):continue
        kind='formal_finding';raw=sev[1] if sev and family!='index' else None;evidence={'section':m[1],'severity_basis':'explicit_publisher_label','layout_grammar':family or 'compatibility'}
        if parent and re.search(r'Recommendation',parent,re.I):kind='recommendation'
        elif parent and re.fullmatch(r'(?:Additional )?(?:Notes?|Comments?)',parent,re.I):kind='observation'
        if nested and re.search(r'Recommendation\s+Confirmed',report.text[max(0,line.start-900):line.start]):kind='recommendation'
        # Versioned editions can retain old cards without a Severity field.
        # The separately printed issue-index risk remains valid evidence for
        # those cards; an explicit detail field always takes precedence.
        if raw is None and kind=='formal_finding' and len(entries)+1 in table_severity:
            raw,a,b=table_severity[len(entries)+1];evidence|={'severity_basis':'printed_issue_index_row','severity_span':{'start':a,'end':b}}
        entries.append(Candidate(line.start,clean(' '.join(title)),raw,m[1],normalized=severity(raw, report.firm),status_raw=clean(st[1]) if st else None,method='blocksec-numbered-detail',confidence=.96,record_kind=kind,evidence=evidence))
    for j,c in enumerate(entries):
        end=entries[j+1].start if j+1<len(entries) else len(report.text)
        tail=report.text[c.start:end]
        stop=re.search(r'(?im)^\s*(?:[23]\.\d+\s+(?:Software Security|DeFi Security|NFT Security|Additional Recommendations?|Notes?|Security Issues)|(?:Chapter\s+)[34]\s+|Appendix\b)',tail)
        if stop and stop.start()>0:end=c.start+stop.start()
        # Signature-only final pages are outside the finding narrative.
        for p in report.meta['pages']:
            if c.start<p['start']<end and (not p['text'].strip() or p['text'].lstrip().startswith('ROUGH vy')):
                end=p['start'];break
        if nested:
            for l in report.lines:
                if c.start<l.start<end and re.match(r'^[23]\.\d+(?:\.\d+){0,2}\s+',l.content):
                    end=l.start;break
        c.end=end
    return entries


def printed_counts(report):
    found=generic_counts(report)
    if found:
        # Recommendation/Note totals are distinct record kinds, not printed
        # Informational severity totals. The generic vocabulary also maps the
        # word Recommendation to info; that convention does not fit this index.
        proof='\n'.join(e.get('text','') for e in found.get('evidence',[]))
        if 'info' in found['counts'] and re.search(r'Recommendation',proof,re.I) and not re.search(r'Informational|Information\s+(?:Risk|\d)',proof,re.I):
            found={**found,'counts':{k:v for k,v in found['counts'].items() if k!='info'},'excluded_nonseverity_totals':'Recommendation totals count a distinct record kind, not formal Informational findings.'}
        if found['counts']:return found
    # A single explicitly printed risk bullet is usable without invented zeros.
    details=next((l.start for l in report.lines if re.match(r'^[23]\.\d+\.\d+\s+',l.content) and not l.excluded),len(report.text))
    proof=[];counts={}
    for l in report.lines:
        if l.start>=details:break
        m=re.fullmatch(r'\s*[-–]?\s*(High|Medium|Low)\s+Risk\s*:\s*(\d+)\s*',l.text,re.I)
        if m:
            counts[m[1].lower()]=int(m[2]);proof.append({'start':l.start,'end':l.end,'page':l.page,'text':l.text})
    if counts:return {'counts':counts,'basis':'blocksec_printed_risk_bullets','evidence':proof}
    return None


from variants import Variant, Fingerprint
from parsers.group2_layouts import statuses

def parse_index_cards(report):return parse(report,'index')
def parse_field_cards(report):return parse(report,'fields')
def parse_version_cards(report):return parse(report,'version')
def parse_nested_cards(report):return parse(report,'nested')
def status_index(report,candidates):statuses(report,candidates,narrative=True,headings=True)
def status_fields(report,candidates):statuses(report,candidates,narrative=True,headings=True)
def status_versions(report,candidates):statuses(report,candidates,narrative=True,headings=True)
def status_nested(report,candidates):statuses(report,candidates,narrative=True,headings=True)

VARIANTS=(
    Variant('blocksec/v2025_version_fields',Fingerprint((('version metadata',r'^\s*Introduced by\s+Version',10),),('2024','2026')),parse_version_cards,('blocksec_version',),status_versions,printed_counts,notes='Modern version-qualified numbered cards, Introduced by/Status metadata; recommendations and notes remain distinct kinds, Informational security cards remain formal findings.'),
    Variant('blocksec/v2022_nested',Fingerprint((('nested finding',r'^\s*[23]\.\d+\.\d+\.\d+\s+[^\n]+',9),),('2022','2024')),parse_nested_cards,('blocksec_nested',),status_nested,printed_counts,notes='Four-component subsection finding IDs below security categories; nested title/card boundaries prevent metadata borrowing.'),
    Variant('blocksec/v2022_severity_fields',Fingerprint((('severity field',r'^\s*Severity\s*:?\s*(?:High|Medium|Low|Informational)',5),('numbered finding',r'^\s*[23]\.\d+\.\d+\s+',3)),('2022','2026')),parse_field_cards,('blocksec_fields',),status_fields,printed_counts,notes='Three-component numbered cards with explicit severity/status fields; numeric executive risk bullets stay independent of details.'),
    Variant('blocksec/v2021_index_risk',Fingerprint((('issue index',r'ID\s+Severity\s+Description',4),('chapter finding',r'^\s*Chapter [23] Findings',3)),('2021','2022')),parse_index_cards,('blocksec_index',),status_index,printed_counts,notes='Early cards omit severity; attach the independent printed issue-index risk by order. Status Confirmed means open; Confirmed and fixed means fixed.'),
)
