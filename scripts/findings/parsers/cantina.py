"""Cantina 3.x.x private-review PDFs and severity-coded competition reports."""
from core import bracket_findings, numbered_metadata
from prior_findings import exclude_prior_findings, PRIOR
DESCRIPTION = "Private-review numbered severity sections and competition severity-ID headings"


def parse(report):
    return exclude_prior_findings(report, bracket_findings(report) or numbered_metadata(report, levels=(3,), inherit=True))

import re
from core import Candidate, SEV, clean, is_toc
from layout_support import view, bounded, attach_status, status_value, RISK, STATUS
import unicodedata
from variants import Variant, Fingerprint
RISK = r"(?:Major|Minor|" + RISK[3:]


def remediation_status(report,candidates):
    attach_status(report,candidates,'cantina')
    for c in candidates:
        body=report.text[c.start:c.end]; claims=[]
        # NFKC expands the publisher PDF's fi ligatures. Locate each original
        # line first so all saved spans remain in the original coordinate system.
        for line in report.lines:
            if not c.start<=line.start<c.end or line.code: continue
            raw=line.text; text=unicodedata.normalize('NFKC',raw)
            m=re.match(r'^\s*([\w][\w .&’\x27()/+-]{0,70}):\s*(.*)',text)
            if not m or m[1].casefold() in {'recommendation','description','context','note','severity','exploit scenario'}: continue
            response=m[2]
            action=re.match(r'(?:(?:Fix\s+)?(?:verified|confirmed|OK)|'+STATUS+r')\b',response,re.I)
            if not action: continue
            token=action[0]
            # Find the equivalent substring without assuming NFKC length equals
            # source length (e.g. Veri\ufb01ed -> Verified).
            prefix=raw[:raw.index(':')+1];tail=raw[len(prefix):]
            end=0
            while end<len(tail) and len(unicodedata.normalize('NFKC',tail[:end]).lstrip())<len(token): end+=1
            start=len(prefix)+len(tail)-len(tail.lstrip())
            original=raw[start:len(prefix)+end]
            norm='resolved' if re.fullmatch(r'(?:Fix\s+)?(?:verified|OK)',token,re.I) else status_value(token,'cantina')
            # Confirmed alone confirms the finding, not a fix. Use the client's
            # explicit Fixed/Resolved assertion when it exists, retain its actor.
            claims.append((line.start+start,line.start+len(prefix)+end,original,norm,m[1]))
        actionable=[x for x in claims if x[3]!='other']
        if claims:
            start,end,raw,norm,actor=(actionable or claims)[-1];c.status_raw=raw;c.normalized_status=norm
            c.evidence['status_evidence']=dict(raw=raw,start=start,end=end,text=report.text[start:end],basis='attributed_resolution_response',profile='cantina',actor=actor)
        if not c.status_raw:
            c.normalized_status='unknown';c.evidence['status_availability']=dict(status='unknown',reason='not_stated',checked='publisher/client labelled responses, card fields and fix-review text')


def scoped_report(report):
    out=numbered_cards(report)
    if not out:
        for line in report.lines:
            if is_toc(line): continue
            m=re.fullmatch(r'(\d+\.\d+\.\d+)\s+(Comment \d+)',line.content,re.I)
            if m:
                out.append(Candidate(line.start,m[2],None,m[1],record_kind='recommendation',method='cantina-review-comment',confidence=.9))
        out=bounded(report,out)
    if not out:
        clean=re.search(r'No (?:new )?issues were identi[fﬁ]+ed|identi[fﬁ]+ed no issues|No high nor medium risk issues',report.text,re.I)
        report.layout_disposition={'reason':'no_in_scope_findings' if clean else 'scope_or_summary_without_detailed_findings',
                                   'basis':'publisher_scope_and_full_detail_census'}
    return out


def deployment_report(report):
    report.layout_disposition={'reason':'deployment_verification_checklist','basis':'publisher_verification_headings'}
    return []


def numbered_cards(report):
    r=view(report);out=[];parent=None;parent_id=None
    for i,l in enumerate(r.lines):
        if is_toc(l):continue
        m=re.match(r'^(\d+(?:\.\d+)+)\.?\s+(.+)',l.content)
        if not m:continue
        number,title=m.groups()
        section=re.fullmatch(r'('+RISK+r')(?: Risk| Severity)?(?: & Informational)?(?: \((?:Gas|Informational)\))?(?: (?:Findings|Issues))?',title,re.I)
        if PRIOR.fullmatch(title):
            parent_id=number;parent=None;continue
        if section and not (parent_id and number.startswith(parent_id+'.') and re.fullmatch(r'Minor issues',title,re.I)):
            parent=section[1];parent_id=number;continue
        if not parent_id or not number.startswith(parent_id+'.') or len(number.split('.'))!=len(parent_id.split('.'))+1:continue
        # Explicit detail risk overrides a section label, but never steal the
        # next finding's field through a fixed lookahead window.
        block=[];continuation=[]
        for q in r.lines[i+1:]:
            if re.match(r'^\d+(?:\.\d+)+\.?\s+',q.content):break
            block.append(q.content)
            if len(block)>20:break
        near=l.content+'\n'+'\n'.join(block)
        raw=re.search(r'\bSeverity\s*:\s*('+RISK+r')(?: Risk)?',near,re.I)
        for q in r.lines[i+1:i+6]:
            if not q.content:break
            if re.match(r'^(?:Severity|Description|Context|Recommendation|[A-Z][a-z]+:)|^\d',q.content):break
            continuation.append(q.content)
        title=re.split(r'\s+Severity\s*:',title,flags=re.I)[0].strip()
        out.append(Candidate(l.start,clean(' '.join([title]+continuation)),raw[1] if raw else parent,number,
                             method='cantina-numbered-detail',confidence=.94))
    return expand_containers(report,bounded(report,out,r'(?:\d+\s+)?(?:Appendix|Disclaimer|Conclusion|References)'))


def competition_cards(report):return bracket_findings(view(report)) or numbered_cards(report)


def parse(report):return competition_cards(report)

VARIANTS=(
 Variant('cantina/v2023_competition',Fingerprint((('competition_heading',r'^\s*#{0,6}\s*\[?[CHMLIG]-\d+\]?[ .:–-]+\S',8),('competition_text',r'(?:competition|contest) (?:report|provides)',3)),('2023','2026')),competition_cards,('cantina_competition',),remediation_status),
 Variant('cantina/v2023_numbered_reviews',Fingerprint((('numbered_risk_section',r'^\s*\d+\.\d+\s+(?:'+RISK+r')(?: Risk)?\s*$',7),('severity_field',r'Severity\s*:',2),('combined_low_info',r'^\s*\d+\.\d+\s+Low Risk & Informational\s*$',7)),('2023','2026')),numbered_cards,('cantina_numbered',),remediation_status),
)


def printed_counts(report):
    from summary_counts import printed_counts as read_counts
    result=read_counts(report)
    if not result:return None
    # Published contest totals cover more than this artifact. Apply only an
    # explicit publisher restriction, never infer missing scope from parsed rows.
    m=re.search(r'(?:The present|This) report only (?:outlines|includes|covers|contains)\s+(?:the\s+)?((?:critical|high|medium|low)(?:[\s,/-]+(?:and\s+)?(?:critical|high|medium|low))*)\s+(?:risk\s+)?(?:issues|findings)',report.text,re.I)
    if m:
        allowed={x.lower() for x in re.findall(r'critical|high|medium|low',m[1],re.I)}
        applicable={k:v for k,v in result['counts'].items() if k in allowed}
        if applicable:
            result=result|{'counts':applicable,'publisher_totals_outside_detail_scope':{k:v for k,v in result['counts'].items() if k not in allowed},
                           'comparison_scope':{'basis':'explicit_publisher_detail_scope','start':m.start(),'end':m.end(),'text':m[0]}}
    return result

VARIANTS=(
 Variant('cantina/v2023_major_minor',Fingerprint((('qualified_grade',r'Severity:\s*(?:Major|Minor)\b',9),),('2023','2024')),numbered_cards,('cantina_major_minor',),remediation_status,printed_counts),
 Variant('cantina/v2023_competition_numbered',Fingerprint((('limited_report',r'report only (?:outlines|includes|covers)',10),('contest_description',r'hosted a competition',2)),('2023','2026')),numbered_cards,('cantina_limited_competition',),remediation_status,printed_counts),
)+VARIANTS


def expand_containers(report,candidates):
    result=[]
    for c in candidates:
        if not re.fullmatch(r'Minor issues',c.title or '',re.I):result.append(c);continue
        lines=[l for l in report.lines if c.start<l.start<c.end]
        active=False;children=[]
        for l in lines:
            if re.match(r'Description/Recommendation:',l.content,re.I):active=True;continue
            if active and re.match(r'(?!(?:Description|Recommendation|Context|Note|Severity|Footnote)\b)[A-Z][A-Za-z]*(?: [A-Z][A-Za-z]*){0,2}:',l.content):break
            m=re.match(r'^ {0,4}(\d+)\.\s+(.+)',l.text)
            if active and m:
                if children and int(m[1])<=int(children[-1][1][1]):break
                children.append((l,m))
        if len(children)<2:result.append(c);continue
        c.evidence['container_recommendations']=len(children)
        result.append(c)
        for i,(line,m) in enumerate(children):
            end=children[i+1][0].start if i+1<len(children) else c.end
            result.append(Candidate(line.start,m[2],None,m[1],end=end,record_kind='recommendation',method='cantina-container-recommendation',confidence=.88,
                                    evidence={'container_id':c.printed_id,'severity_basis':'unrated_recommendation','title_basis':'leading_source_text'}))
    return result

VARIANTS=(Variant('cantina/v2024_nested_sections',Fingerprint((('nested_finding',r'^\s*\d+\.\d+\.\d+\.\d+\s+\S',9),),('2024','2026')),numbered_cards,('cantina_nested',),remediation_status,printed_counts),)+VARIANTS

VARIANTS += (
 Variant('cantina/v2024_deployment_checks',Fingerprint((('verification',r'^\s*(?:\d+(?:\.\d+)*\s+)?(?:Deployment Validation Results|Deployment Verification|Deployment validation|Verification Results|Bytecode fetching script|Perfect matches|Target Address Whitelist)\s*$',10),)),deployment_report,('cantina_deployment',)),
 Variant('cantina/v2023_scope_only',Fingerprint((('publisher',r'About Cantina|Cantina Managed|Cantina Security|cantina\.xyz|Cantina|concluded that there were no issues found',3),('risk_assessment',r'Risk assessment',3))),scoped_report,('cantina_scope_only',),remediation_status),
)
