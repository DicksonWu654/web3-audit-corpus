"""Theori format eras; collector attribution is never rewritten here."""
from parsers.chainlight import parse as _chain_cards, printed_counts
from layout_support import attach_status
from variants import Variant, Fingerprint
from core import Candidate, clean, is_toc
from layout_support import bounded
DESCRIPTION='Theori legacy Issue cards, THE-prefixed cards and bilingual ID Code tables'
import re


def cards(report):
    """Constrain the compatibility grammar's metadata to its own card."""
    headings=[l.start for l in report.lines if re.match(
        r'^(?:Issue|Recommendation)\s*#\d+|^#\d+\s+(?:THE-)?[A-Z0-9-]+-\d{3}\b|^4\.2\.\d+\.\s+[A-Z0-9-]+-\d{3}:',l.content,re.I)
        and not is_toc(l)]
    out=[]
    for c in _chain_cards(report):
        following=next((p for p in headings if p>c.start),len(report.text))
        span=c.evidence.get('severity_span')
        if span and span['start']>=following:continue
        out.append(c)
    return bounded(report,out,r'Appendix.*|Revisions|Revision History')


def legacy_cards(report):
    """Issue cards, including vertically serialized Summary/Severity tables.

    Never read grades from the front finding inventory or the next card.
    """
    out=cards(report);occupied={c.start for c in out};lines=report.lines
    heading=re.compile(r'^Issue\s*#(\d+)\s*:?\s*(.*)',re.I)
    for i,line in enumerate(lines):
        m=heading.match(line.content)
        if not m or line.start in occupied or is_toc(line):continue
        ahead=[]
        for q in lines[i+1:i+30]:
            if re.match(r'^(?:Issue|Recommendation)\s*#\d+',q.content,re.I):break
            if re.fullmatch(r'Description\.?|Root Cause|Type|Target',q.content,re.I):break
            ahead.append(q)
        header=next((j for j,q in enumerate(ahead) if re.search(r'\bSummary\b',q.content)),None)
        if header is None:continue
        meta=ahead[header:]
        if not re.search(r'\bSeverity\b','\n'.join(q.content for q in meta)):continue
        risk=None;riskline=None
        for q in meta:
            grade=re.search(r'(?:^\s*(?:(?:Severity\s*:?|Fixed\s*\()\s*)?|[ \t]{2,})(Critical|High|Medium|Low|Minor|Informational|Information|Note)\)?\s*$',q.text,re.I)
            if grade and not re.search(r'\bSummary\b',q.content,re.I):risk=grade[1];riskline=q;break
        if not risk:continue
        title=clean(' '.join([m[2]]+[q.content for q in ahead[:header] if q.content]))
        if not title:continue
        fixed=re.search(r'\b(Fixed)\s*\(',riskline.text,re.I)
        out.append(Candidate(line.start,title,risk,'Issue #'+m[1],status_raw=fixed[1] if fixed else None,
                             method='theori-vertical-summary-card',confidence=.95,
                             evidence={'severity_basis':'detail_card_severity',
                                       'severity_span':dict(start=riskline.start,end=riskline.end,text=riskline.text)}))
    return bounded(report,out,r'Appendix.*|Revisions|Revision History')

def numbered_cards(report):return cards(report)

def bilingual_cards(report):return cards(report)


def remediation_status(report,candidates):
    attach_status(report,candidates,'theori')
    for c in candidates:
        body=report.text[c.start:c.end]
        fix=re.search(r'(?:^|\n)[ \t]*Fix[ \t]*\n',body,re.I)
        if fix:
            tail=body[fix.end():]
            partial=re.search(r'[^\n.]*\b(?:fix was incomplete|partially (?:fixed|resolved))\b[^\n.]*',tail,re.I)
            paragraph=re.split(r'\n[ \t]*\n',tail.lstrip(),1)[0]
            if partial:
                raw=partial[0].strip();start=c.start+fix.end()+partial.start()+len(partial[0])-len(partial[0].lstrip());norm='partial'
            elif re.search(r'\(commit [a-f0-9]{7,40}\)',paragraph,re.I) and not re.search(r'\b(?:will|should|could|would|proposed|suggested)\b',paragraph,re.I):
                raw=paragraph.strip();start=c.start+fix.end()+tail.index(raw);norm='partial' if 'decided to keep' in raw.lower() else 'fixed'
            else:raw=None
            if raw:
                end=start+len(raw);c.status_raw=raw;c.normalized_status=norm
                c.evidence['status_evidence']=dict(raw=raw,start=start,end=end,text=report.text[start:end],basis='explicit_fix_section_commit_or_partial_assertion',profile='theori')
        if not c.status_raw:
            c.normalized_status='unknown'
            c.evidence['status_availability']=dict(status='unknown',reason='not_stated',checked='detail metadata, ID status index and labelled remediation; future Fix plans are not completed fixes')


def missing_glyphs(report):
    report.layout_disposition={'reason':'missing_narrative_glyphs','basis':'BiFi revision report: formula/code text survives; narrative/issue headings are missing in both the rendering and text layer'}
    return []

VARIANTS=(
 Variant('theori/v2021_issue_cards',Fingerprint((('issue_heading',r'^\s*(?:Issue|Recommendation)\s*#\d+(?:\s*:|\s+\S)',7),('summary_severity',r'Summary\s+Severity',2)),('2020','2022')),legacy_cards,('theori_issue',),remediation_status,printed_counts),
 Variant('theori/v2021_vertical_issue_cards',Fingerprint((('issue_heading',r'^\s*Issue\s*#\d+(?:\s*:|\s*$)',7),('vertical_metadata',r'^\s*Summary\s*\n\s*Severity\s*$',4)),('2020','2023')),legacy_cards,('theori_vertical',),remediation_status,printed_counts),
 Variant('theori/v2023_the_cards',Fingerprint((('the_heading',r'^\s*#\d+\s+(?:THE-)?[A-Z0-9-]+-\d{3}\s+\S',7),('summary_severity',r'Summary\s+Severity',2)),('2022','2026')),numbered_cards,('theori_modern',),remediation_status,printed_counts),
 Variant('theori/v2022_bilingual',Fingerprint((('id_code',r'ID Code.*Severity',6),('orb_heading',r'4\.2\.\d+\.\s+[A-Z0-9-]+-\d{3}:',3)),('2022','2026')),bilingual_cards,('theori_bilingual',),remediation_status,printed_counts),
)

VARIANTS += (Variant('theori/v2021_missing_glyphs',Fingerprint((('reward_code',r'rewardPerBlock',3),('reward_lane',r'_calcNewRewardLane',3)),reject_signatures=(r'^\s*Issue\s*#\d+(?:\s*:|\s+\S)',)),missing_glyphs,('theori_missing_glyphs',)),)
