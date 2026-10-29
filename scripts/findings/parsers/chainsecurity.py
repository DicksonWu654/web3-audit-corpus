"""ChainSecurity's inline grades, classification cards and versioned cards."""
import re
from core import Candidate, numbered_metadata, is_toc, SEV as BASE_SEV, clean
from layout_support import view, visible, bounded, attach_status, STATUS
from variants import Variant, Fingerprint
DESCRIPTION = 'Inline legacy grades, classification cards and versioned risk/status cards'
SEV = '(?:' + BASE_SEV + '|Note)'
VERSION_BADGE = r'^(?:[A-Za-z][A-Za-z:/-]*[ \t]+){0,4}('+SEV+r')[ \t]+Version[ \t]+\d+\b'


def version_cards(report):
    r=view(report)
    out=[]
    for i,line in enumerate(r.lines):
        if is_toc(line):continue
        heading=re.match(r'^(\d+\.\d+(?:\.\d+)?)\s+(.+)',line.content)
        if not heading:continue
        block=[]
        for q in r.lines[i+1:i+19]:
            if re.match(r'^\d+\.\d+(?:\.\d+)?\s+',q.content):break
            block.append(q)
        grade=next((re.search(VERSION_BADGE,q.content,re.I) for q in block
                    if re.search(r'\bVersion\s+\d+',q.content)),None)
        if not grade:
            grade=next((re.match(r'^Severity\s*:\s*('+SEV+r')\b',q.content,re.I) for q in block if re.match(r'^Severity\s*:',q.content,re.I)),None)
        if grade:
            out.append(Candidate(line.start,heading[2],grade[1],heading[1],method='chainsecurity-version-card',confidence=.95))
    # Titles may wrap before the classification line. Restrict continuation to
    # the heading block, not the finding's description or a following card.
    for c in out:
        i=next(i for i,l in enumerate(r.lines) if l.start==c.start)
        parts=[c.title]
        for l in r.lines[i+1:i+9]:
            if re.search(r'\b(?:'+SEV+r')\s+Version\s+\d+',l.content,re.I):break
            if not l.content:continue
            if l.page!=r.lines[i].page or re.match(r'^\d|^(?:Description|Security|Correctness|Design)\b',l.content):break
            parts.append(l.content)
        c.title=clean(' '.join(parts))
    return bounded(report,out,r'(?:\d+\s+)?(?:Audit Notes|Notes|Disclaimer|Appendix|Conclusion)')


def inline(report):
    r=view(report);out=[];active=False
    for i,l in enumerate(r.lines):
        if is_toc(l):continue
        if re.match(r'^\d+\s+(?:Details of the Findings|Findings|Security Issues)',l.content,re.I):active=True
        m=re.match(r'^(\d+(?:\.\d+)+)\s+(.+?)\s+('+SEV+r')(?:\s+[Ë✓]?\s*('+STATUS+r'))?\s*$',l.content,re.I)
        if m and active:
            out.append(Candidate(l.start,m[2],m[3],m[1],status_raw=m[4],method='chainsecurity-inline-grade',confidence=.93))
    return bounded(report,out,r'(?:\d+\s+)?(?:Conclusion|Disclaimer|Appendix)')


def classification(report):
    r=view(report);out=numbered_metadata(r,levels=(2,3),chain=True)
    occupied={c.start for c in out}
    for i,l in enumerate(r.lines):
        if is_toc(l) or l.start in occupied:continue
        m=re.match(r'^(\d+\.\d+(?:\.\d+)?)\s+(.+)',l.content)
        if not m:continue
        near=r.near(i+1,5)
        raw=re.search(r'(?:^|\n)\s*(?:Security|Correctness|Design|Trust|Gas|Code)\s+('+SEV+r')\b',near,re.I)
        if raw:out.append(Candidate(l.start,m[2],raw[1],m[1],method='chainsecurity-classification-card',confidence=.9))
    return bounded(report,out,r'(?:\d+\s+)?(?:Disclaimer|Appendix|Conclusion)')


def parse(report):return version_cards(report)


def legacy_codes(report):
    """Early unnumbered risk-code headings, including Issue N cards."""
    out=[];active=False;section=None;excluded=[]
    for line in report.lines:
        if is_toc(line): continue
        if re.fullmatch(r'(?:\d+\s+)?(?:Findings|Issues|Security Issues|Trust Issues|Design Issues)',line.content,re.I):
            active=True;section=line.content;continue
        if re.match(r'^(?:Appendix|Conclusion|Disclaimer)\b',line.content,re.I): active=False
        if not active: continue
        m=re.match(r'^(?:(Issue\s+\d+|\d+(?:\.\d+)+|[IVXLCDM]+\.)\s*:?\s+)?(.{4,180}?)\s+([CHML])(?:\s+(?:[3Ë✓✔]\s*)?('+STATUS+r'))?\s*$',line.content,re.I)
        if m:
            out.append(Candidate(line.start,m[2],m[3],m[1],status_raw=m[4],method='chainsecurity-legacy-risk-code',confidence=.94,
                                 evidence={'source_section':section,'severity_basis':'printed_inline_grade'}))
        else:
            # Ungraded trust/design cards still carry a source disposition.
            m=re.match(r'^([IVXLCDM]+\.)\s+(.{4,180}?)\s+(?:[3Ë✓✔]\s*)?('+STATUS+r')\s*$',line.content,re.I)
            if m and section and re.search(r'Trust|Design',section,re.I):
                out.append(Candidate(line.start,m[2],None,m[1],status_raw=m[3],record_kind='observation',
                                     method='chainsecurity-ungraded-legacy-card',confidence=.9,evidence={'source_section':section}))
            if re.search(r'\bNo Issue\s*$',line.content,re.I):
                excluded.append(dict(start=line.start,end=line.end,text=line.text,reason='publisher_no_issue_disposition'))
    if excluded:report.layout_disposition={'reason':'legacy_graded_cards_and_no_issue_dispositions','excluded':excluded}
    return bounded(report,out,r'(?:Appendix.*|Conclusion|Disclaimer|Recommendations / Suggestions|(?:\d+\s+)?(?:System Risk|Risk Assessment))')


def overview(report):
    # This contract recognizes the findings/notes-only template even when there
    # are no graded cards. It never derives findings from numeric totals.
    out=version_cards(report)
    if not out:
        report.layout_disposition={'reason':'no_graded_detail_cards','basis':'publisher_findings_overview_and_full_detail_census'}
    return out


def supporting(report):
    reason='deployment_validation' if re.search(r'Deployment Validation|Verified Contracts',report.text,re.I) else 'management_summary_only'
    report.layout_disposition={'reason':reason,'basis':'explicit_source_document_heading'}
    return []


def remediation_status(report,candidates):
    attach_status(report,candidates,'chainsecurity')
    for c in candidates:
        body=report.text[c.start:c.end]
        m=list(re.finditer(r'(?:^|\n)[ \t]*(Code Partially Corrected|Code Corrected|Specification Changed|Risk Accepted|Fixed|Addressed|Acknowledged)\s*:',body,re.I))
        if m:
            claim=m[-1];raw=claim[1];start=c.start+claim.start(1);end=c.start+claim.end(1)
            c.status_raw=raw;c.normalized_status={'fixed':'fixed','addressed':'resolved','acknowledged':'acknowledged',
                'code corrected':'fixed','code partially corrected':'partial','specification changed':'resolved','risk accepted':'acknowledged'}[raw.lower()]
            c.evidence['status_evidence']=dict(raw=raw,start=start,end=end,text=report.text[start:end],basis='labelled_resolution_response',profile='chainsecurity')
        if not c.status_raw:
            c.normalized_status='unknown';c.evidence['status_availability']=dict(status='unknown',reason='not_stated',checked='classification, version badge and resolution response')

VARIANTS=(
 Variant('chainsecurity/v2021_version_cards',Fingerprint((('risk_version',r'^[ \t]*'+VERSION_BADGE[1:],8),),('2021','2026')),version_cards,('chainsecurity_version',),remediation_status),
 Variant('chainsecurity/v2017_inline',Fingerprint((('inline_grade',r'^\s*\d+\.\d+\s+[^\n]{3,160}\b(?:Critical|High|Medium|Low)\s*(?:[3Ë✓]|$)',8),('details',r'Details of the Findings',2)),('2017','2019')),inline,('chainsecurity_inline',),remediation_status),
 Variant('chainsecurity/v2018_classification',Fingerprint((('classification',r'^\s*(?:Security|Correctness|Design)\s+(?:'+SEV+r')\b',7),('findings',r'\bFindings\b',1)),('2018','2021')),classification,('chainsecurity_classification',),remediation_status),
 Variant('chainsecurity/v2018_risk_codes',Fingerprint((('legacy_code',r'^\s*[^\n]{4,180}\s+[CHML]\s+(?:[3Ë✓]\s*)?(?:Fixed|Addressed|Acknowledged)\s*$|^\s*(?:Issue \d+:|\d+\.\d+|[IVXLCDM]+\.)\s+[^\n]{4,180}\s+[CHML]\s*$',8),),('2017','2020')),legacy_codes,('chainsecurity_risk_codes',),remediation_status),
 Variant('chainsecurity/v2021_overview',Fingerprint((('overview',r'Overview of the Findings|numerical overview of the identified findings|Total number of findings',6),),('2020','2026')),overview,('chainsecurity_overview',),remediation_status),
 Variant('chainsecurity/v2019_supporting',Fingerprint((('supporting',r'^\s*Management Summary\s*$|^\s*\d+(?:\.\d+)?\s+Verified Contracts\s*$',6),)),supporting,('chainsecurity_supporting',)),
)
