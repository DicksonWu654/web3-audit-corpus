"""Three Sigma detailed finding cards: Classification is final risk, Severity is impact."""
from __future__ import annotations
import re
from core import Candidate, clean
from layout_support import status_value, visible, bounded
from variants import Variant, Fingerprint
from summary_counts import printed_counts as aggregate_counts
DESCRIPTION = 'Three Sigma ID cards with final Classification (legacy Severity), wrapped titles and explicit statuses'


def _cards(report, risk_field):
    out=[]
    for i,line in enumerate(report.lines):
        ident=re.match(r'^\s*Id\s+(.+?)\s*$',line.text,re.I)
        if not ident or not re.match(r'3S[- ]',ident[1]):
            continue
        # Require an actual standalone card heading before this metadata row.
        start=None
        for j in range(i-1,max(-1,i-14),-1):
            v=report.lines[j].content.replace('\u200b','').strip()
            if re.fullmatch(r'3S[- ].*-[A-Z0-9]+',v):
                start=j;break
        if start is None:
            continue
        header=report.lines[start]
        h=re.match(r'^(3S[- ].*-[A-Z0-9]+)\s*$',header.content.replace('\u200b',''))
        title=[]
        title.extend(l.content for l in report.lines[start+1:i] if l.content and not l.content.isdigit())
        if not title:
            continue
        metadata=[]
        for l in report.lines[i+1:i+24]:
            if re.match(r'^(?:Description|Occurrences|Recommendation)\s*:?$',l.content,re.I):
                break
            metadata.append(l)
        labels={}
        for l in metadata:
            m=re.match(r'^\s*(Classification|Severity|Status)\s+(.+?)\s*$',l.text,re.I)
            if m: labels[m[1].lower()]=(m[2],l)
        risk=labels.get(risk_field) or (labels.get('severity') if risk_field=='classification' else None)
        if not risk:
            continue
        raw,riskline=risk
        evidence={'severity_basis':'explicit_classification' if 'classification' in labels else 'legacy_explicit_severity',
                  'severity_span':{'start':riskline.start,'end':riskline.end},'metadata_printed_id':ident[1]}
        state=labels.get('status')
        state_text=state[0] if state else None
        if state:
            column=state[1].text.find(state[0])
            k=metadata.index(state[1])+1
            while k<len(metadata):
                continuation=metadata[k]
                if not continuation.content or len(continuation.text)-len(continuation.text.lstrip())<column-3:
                    break
                state_text+=' '+continuation.content
                k+=1
        if state:
            evidence['status_source']={'start':state[1].start+state[1].text.find(state[0]),
                                       'end':metadata[k-1].end if k>metadata.index(state[1])+1 else state[1].end}
        out.append(Candidate(header.start,clean(' '.join(title)),raw,h[1],status_raw=state_text,
                             method='id-classification-card',confidence=.97,evidence=evidence))
    for n,c in enumerate(out):
        end=out[n+1].start if n+1<len(out) else len(report.text)
        # Older cards label a standalone Status section, not a metadata cell.
        if not c.status_raw:
            within=[l for l in report.lines if c.start<=l.start<end]
            for k,line in enumerate(within):
                if not re.fullmatch(r'Status',visible(line.content),re.I):
                    continue
                for value in within[k+1:]:
                    v=value.content.replace('\u200b','').strip()
                    if not v or v.isdigit():
                        continue
                    c.status_raw=v
                    c.evidence['status_source']={'start':value.start+len(value.text)-len(value.text.lstrip()),'end':value.end}
                    break
                break
        c.end=end
    return out


def severity_sections(report):return _cards(report,'severity')
def classification_sections(report):return _cards(report,'classification')
def matrix_metadata(report):return _cards(report,'classification')
def classification_metadata(report):return _cards(report,'classification')


def dashboard_only(report):
    """Known dashboard template; absent detail pages never manufacture rows."""
    return []


def fix_review(report):
    """PR-by-PR remediation verification is distinct from a fresh audit finding."""
    out=[]
    for line in report.lines:
        m=re.match(r'^PR[ \t]+#(\d+):[ \t]+(.+)',line.content)
        if m:
            out.append(Candidate(line.start,m[2],printed_id='PR #'+m[1],record_kind='remediation_review',
                                 finding_phase='fix_review',method='three-sigma-pr-remediation-review',confidence=.95))
    return bounded(report,out,r'Conclusion')


def parse(report):
    """Direct-call compatibility; dispatcher always uses the selected era."""
    return _cards(report,'classification') or _cards(report,'severity')


def _state(raw):
    text=clean(visible(raw)).casefold().rstrip('.')
    if re.match(r'^(?:partially|partly) (?:fixed|addressed|resolved|mitigated)\b',text):return 'partial'
    if re.match(r'^(?:not (?:fixed|addressed|resolved)|unaddressed|unresolved|currently being reviewed|under review|in progress|pending|open|new issue|to be addressed)\b',text):return 'open'
    if re.match(r'^(?:acknowledged|risk accepted|won.t fix)\b',text):return 'acknowledged'
    if re.match(r'^the team acknowledged\b',text):return 'acknowledged'
    if re.search(r'\baddressed\b',text) and re.search(r'\backnowledged\b',text):return 'partial'
    if re.match(r'^(?:fixed|patched|implemented)\b',text):return 'fixed'
    if re.match(r'^(?:addressed|resolved|mitigated)\b',text):return 'resolved'
    if re.match(r'^this issue has been (?:fully )?(?:addressed|resolved)\b',text):return 'resolved'
    if re.match(r'^this issue has been (?:fully )?fixed\b',text):return 'fixed'
    if re.match(r'^issue addressed\b',text):return 'resolved'
    return status_value(raw,'three-sigma')


def _statuses(report,candidates,profile):
    for c in candidates:
        if not c.status_raw:continue
        body=report.text[c.start:c.end]
        raw=c.status_raw
        # The card parser retains wrapped status cells and skips PDF footers.
        # Recover the source span without forcing normalized text into evidence.
        source=c.evidence.get('status_source')
        pattern=r'\s+'.join(re.escape(p) for p in raw.split())
        match=re.search(pattern,body,re.I) if not source else None
        if source:
            start,end=source['start'],source['end']
        elif match:
            start,end=c.start+match.start(),c.start+match.end()
        else:
            # Cross-page values may have page numbers between continuation rows.
            first=raw.split(' ',1)[0]
            match=re.search(re.escape(first),body,re.I)
            if not match:continue
            start=c.start+match.start();end=c.start+body.find('\n',match.start())
            if end<c.start:end=c.end
        c.normalized_status=_state(raw)
        # Preserve wrapped PDF source text in status_raw; normalization above
        # uses the matching view retained by the metadata grammar.
        c.status_raw=report.text[start:end]
        c.evidence['status_evidence']={'raw':c.status_raw,'start':start,'end':end,'text':report.text[start:end],
                                     'basis':'labelled_status_section' if profile.endswith('sections') else 'labelled_status_cell','profile':profile}
        c.resolution=report.text[start:end]


def severity_status(report,candidates):return _statuses(report,candidates,'three-sigma-severity-sections')
def classification_status(report,candidates):return _statuses(report,candidates,'three-sigma-classification-sections')
def matrix_status(report,candidates):return _statuses(report,candidates,'three-sigma-matrix-metadata')
def metadata_status(report,candidates):return _statuses(report,candidates,'three-sigma-classification-metadata')
def dashboard_status(report,candidates):return None


def fix_review_status(report,candidates):
    # The conclusion explicitly covers all the enumerated PRs, including those
    # whose local subsection explains a change without repeating its status.
    matches=list(re.finditer(r'The issue has been fully fixed across all PRs\.',report.text,re.I))
    if not matches:return
    claim=matches[-1]
    for c in candidates:
        c.status_raw=claim[0];c.normalized_status='fixed';c.resolution=claim[0]
        c.evidence['status_evidence']={'raw':claim[0],'start':claim.start(),'end':claim.end(),'text':claim[0],
                                     'basis':'fix_review_conclusion_all_prs','profile':'three-sigma-fix-review'}


def printed_counts(report):
    # Read the Found column from the publisher's dashboard. Generic totals can
    # accidentally count methodology matrix rows (notably "None") instead.
    for i,line in enumerate(report.lines):
        if not re.match(r'^Issue Classification[ \t]+Found\b',line.content,re.I):continue
        counts={};proof=[]
        for item in report.lines[i+1:i+22]:
            m=re.match(r'^[ \t]*(Critical|High|Medium|Low|None)[ \t]+(\d+)\b',item.text,re.I)
            if m:
                key='info' if m[1].lower()=='none' else m[1].lower()
                counts[key]=int(m[2]);proof.append({'page':item.page,'start':item.start,'end':item.end,'text':item.text})
        if counts:return {'counts':counts,'basis':'three_sigma_dashboard_found_column','evidence':proof}
    result=aggregate_counts(report)
    if result:
        return result
    # Early dashboard uses Nº <severity> Severity Issues instead of a numeric grid.
    counts={};proof=[]
    for line in report.lines:
        m=re.match(r'^\s*N[ºo°]\s+(Critical|High|Medium|Low)\s+Severity\s+Issues\s+(\d+)\s*$',line.text,re.I)
        if m:
            counts[m[1].lower()]=int(m[2]);proof.append({'page':line.page,'start':line.start,'end':line.end,'text':line.text})
    return {'counts':counts,'basis':'printed_legacy_dashboard','evidence':proof} if counts else None


_ID=r'^\s*Id[ \t]+3S[- ]'
_CLASS=r'^\s*Classification[ \t]+(?:Critical|High|Medium|Low|None)[ \t]*$'
_IMPACT=r'^\s*Severity[ \t]+(?:Critical|High|Medium|Low|None)[ \t]*$'
_CELL=r'^\s*Status[ \t]+\S'


def _missing(pattern):
    # A layout-defining field is mandatory. Additive votes for fields shared
    # with other eras must not admit a report missing this era's distinctive one.
    return r'\A(?![\s\S]*' + pattern.replace(r'^\s*',r'^[ \t]*') + ')'


VARIANTS=(
 Variant('three-sigma/v2025_fix_review',Fingerprint((('pr_breakdown',r'^\s*Breakdown of PRs[ \t]*$',6),('pr_title',r'^\s*PR[ \t]+#\d+:[ \t]+',5)),('2025',None)),fix_review,('three_sigma_fix_review',),fix_review_status),
 Variant('three-sigma/v2023_matrix_metadata',Fingerprint((('id',_ID,3),('classification',_CLASS,4),('impact_field',_IMPACT,5),('status_cell',_CELL,6)),('2023','2025'),reject_signatures=(_missing(_CELL),_missing(_CLASS),_missing(_IMPACT))),matrix_metadata,('three_sigma_matrix_metadata',),matrix_status),
 Variant('three-sigma/v2023_classification_metadata',Fingerprint((('id',_ID,3),('classification',_CLASS,4),('status_cell',_CELL,6)),('2023',None),reject_signatures=(_IMPACT,_missing(_CELL))),classification_metadata,('three_sigma_classification_metadata',),metadata_status),
 Variant('three-sigma/v2023_classification_sections',Fingerprint((('id',_ID,3),('classification',_CLASS,4),('impact_field',_IMPACT,5)),('2023','2024'),reject_signatures=(_CELL,_missing(_CLASS))),classification_sections,('three_sigma_classification_sections',),classification_status),
 Variant('three-sigma/v2022_severity_sections',Fingerprint((('id',_ID,3),('impact_field',_IMPACT,5)),('2022','2023'),reject_signatures=(_CLASS,)),severity_sections,('three_sigma_severity_sections',),severity_status),
 Variant('three-sigma/v2023_dashboard_only',Fingerprint((('dashboard',r'^\s*Project Dashboard[ \t]*$',3),('vulnerability_summary',r'^\s*Vulnerability Summary[ \t]*$',2),('dashboard_columns',r'^\s*Issue Classification[ \t]+Found[ \t]+Addressed[ \t]+Acknowledged[ \t]*$',6),('explicit_clean',r'no (?:vulnerabilities|issues) (?:were )?(?:found|identified)',4)),('2023',None)),dashboard_only,('three_sigma_dashboard',),dashboard_status),
)
