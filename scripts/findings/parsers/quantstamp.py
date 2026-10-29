"""Quantstamp static report JSON and QSP-numbered legacy PDFs; no JS evaluation."""
from core import severity, Candidate, SEV, field_severity, is_toc, clean
import re
DESCRIPTION = "Native report JSON vulnerability arrays, separate recommendations, and legacy QSP PDF details"


def label(value):
    return value.get("label") if isinstance(value, dict) else value


def parse(report):
    if report.native:
        data = report.native["report"]["reportContent"].get("breakdownAndAutomatedAnalysis") or {}
        out = []
        for key, kind in (("vulnerabilitiesArray", "formal_finding"), ("suggestionsArray", "recommendation")):
            for i, finding in enumerate(data.get(key) or []):
                pointer = f"/reportContent/breakdownAndAutomatedAnalysis/{key}/{i}"
                span = report.native["spans"][pointer]
                title = finding.get("otherTitle") or label(finding.get("title"))
                out.append(Candidate(span["start"], title, label(finding.get("severity")), finding.get("id"),
                                     end=span["end"], status_raw=label(finding.get("status")), method="quantstamp-native-json",
                                     confidence=.98, record_kind=kind, evidence={"json_pointer":pointer},
                                     recommendation=finding.get("recommendation") or None))
        return out
    out = []
    for i, line in enumerate(report.lines):
        if is_toc(line):
            continue
        m = re.match(r"^(QSP-\d+)\s+(.+)", line.content)
        if not m:
            continue
        nearby=report.near(i,8)
        full=re.search(r"\bSeverity:\s*("+SEV+r"(?:\s+Risk)?)\b",nearby,re.I)
        raw=full[1] if full else field_severity(nearby)
        if raw and not re.search(r"\s{3,}(?:" + SEV + r"|Fixed|Resolved)\b", m[2], re.I):
            base=re.sub(r"\s+Risk$","",raw,flags=re.I)
            out.append(Candidate(line.start, m[2], raw, m[1], normalized=severity(raw, report.firm),
                                 method="quantstamp-qsp-detail", confidence=.93))
    return out

from layout_support import view, visible, bounded, status_parser, RISK, STATUS, attach_status
from variants import Variant, Fingerprint
_native_or_qsp=parse


def native(report):return _native_or_qsp(report)


def qsp_cards(report):
    r=view(report);out=[]
    for i,l in enumerate(r.lines):
        if l.code or re.search(r"(?:\.\s*){4,}\s*\d+\s*$",l.text):continue
        m=re.match(r"^(QSP-\d+)\s+(.+)",l.content)
        if not m:continue
        if re.search(r"\s{3,}(?:High|Medium|Low|Informational|Fixed|Resolved)\b",m[2],re.I):continue
        ahead=[]
        for q in r.lines[i+1:i+25]:
            if re.match(r"^QSP-\d+\b",q.content):break
            ahead.append(q.content)
        raw=re.search(r"\bSeverity:\s*("+RISK+r"(?:\s+Risk)?)\b",'\n'.join(ahead),re.I)
        if raw:out.append(Candidate(l.start,m[2],raw[1],m[1],method="quantstamp-qsp-detail",confidence=.95))
    return bounded(report,out,r"(?:Test Results|Code Coverage|Automated Analyses|About Quantstamp|Appendix)")


def field_cards(report):
    r=view(report);out=[]
    # These old report exports have no QSP IDs. Each Severity field follows its
    # title, including containers titled 'Other issues'; numbered children of
    # that container are not additional graded findings.
    active=False
    for i,l in enumerate(r.lines):
        if re.fullmatch(r'Findings|Audit Findings',l.content,re.I):active=True
        if re.fullmatch(r'Test Results|Automated Analyses|About Quantstamp|Appendix',l.content,re.I):active=False
        m=re.fullmatch(r'Severity\s*:\s*('+RISK+r'(?: Risk)?)',l.content,re.I)
        if not m or not active:continue
        previous=[]
        for q in reversed(r.lines[max(0,i-6):i]):
            if not q.content:
                if previous:break
                continue
            if re.fullmatch(r'Findings|Audit Findings',q.content,re.I):break
            previous.insert(0,q)
            if len(previous)>=3:break
        title=' '.join(q.content for q in previous) or None
        start=previous[0].start if previous else l.start
        out.append(Candidate(start,title,m[1],method='quantstamp-unnumbered-field-card',confidence=.94))
    return bounded(report,out,r'(?:Test Results|Test Suite Results|Code Coverage|Automated Analyses|About Quantstamp|Appendix)')


def parse(report):
    if report.native:return native(report)
    return qsp_cards(report) or field_cards(report)

VARIANTS=(
 Variant('quantstamp/v2020_native_json',Fingerprint(date_range=('2020','2026'),structured=True),native,('quantstamp_native',),status_parser('quantstamp')),
 Variant('quantstamp/v2019_qsp_cards',Fingerprint((('qsp_id',r'^\s*QSP-\d+\s+\S',6),('severity_field',r'Severity\s*:',2)),('2019','2026'),structured=False),qsp_cards,('quantstamp_qsp',),status_parser('quantstamp')),
 Variant('quantstamp/v2018_unnumbered_fields',Fingerprint((('findings_section',r'^\s*(?:Audit )?Findings\s*$',2),('severity_field',r'^\s*Severity\s*:\s*'+RISK,6)),('2018','2020'),structured=False),field_cards,('quantstamp_fields',),status_parser('quantstamp')),
)


def column_cards(report):
    """Source field census for the early two-column single-sheet PDF export."""
    out=[];active=True
    for i,l in enumerate(report.lines):
        if re.match(r'^\s*(?:Findings|Audit Findings)\s*$',l.text,re.I):active=True
        if re.match(r'^\s*(?:Test Results|About Quantstamp|Automated Analyses)\s*$',l.text,re.I):active=False
        if not active:continue
        for m in re.finditer(r'(?:^|[ \t]{4,})(Severity\s*:\s*('+RISK+r'(?: Risk)?))\b',l.text,re.I):
            col=m.start(1);title=None;proof=None
            for q in reversed(report.lines[max(0,i-9):i]):
                # Layout columns align within a small indent tolerance.
                cell=q.text[max(0,col-3):] if col>40 else re.split(r'\s{8,}',q.text.strip(),maxsplit=1)[0]
                cell=cell.strip()
                if col>40:cell=re.split(r'\s{8,}',cell,maxsplit=1)[0]
                if not cell:continue
                if re.match(r'(?:Severity|Status|Contract\(s\)|Description|Recommendation|Findings|Exploit)',cell,re.I) or '.sol' in cell:continue
                if len(cell)<150:
                    title=cell;proof={'start':q.start,'end':q.end,'text':report.text[q.start:q.end]}
                    break
            start=l.start+m.start(1)
            out.append(Candidate(start,title,m[2],method='quantstamp-two-column-field',confidence=.85,evidence={'title_span':proof,'column':col}))
    for c in out:
        col=c.evidence['column']
        following=next((n.start for n in out if n.start>c.start and abs(n.evidence['column']-col)<15),len(report.text))
        c.end=following
        for line in report.lines:
            if not c.start-200<line.start<c.end:continue
            cell=line.text[max(0,col-3):] if col>40 else re.split(r'\s{8,}',line.text.strip(),maxsplit=1)[0]
            m=re.search(r'\bStatus:\s*(Fixed|Resolved|Acknowledged|Open)\b',cell,re.I)
            if m:
                c.status_raw=m[1]
                break
    return out

def column_status(report,candidates):
    # The column parser bounds status to its own printed column.
    for c in candidates:
        if not c.status_raw:
            c.normalized_status='unknown';c.evidence['status_availability']=dict(status='unknown',reason='not_stated',checked='own printed detail column')
    return candidates

VARIANTS=(Variant('quantstamp/v2018_columns',Fingerprint((('column_field',r'^[ \t]{40,}Severity\s*:',8),('parallel_fields',r'^.*Severity:[^\n]{0,150}[ \t]{8,}Severity:',8)),('2018','2019'),structured=False),column_cards,('quantstamp_columns',),column_status),)+VARIANTS


def project_cards(report):
    out=[];active=False
    for i,line in enumerate(report.lines):
        if re.fullmatch(r'Findings|Audit Findings',line.content,re.I):active=True;continue
        if re.fullmatch(r'Definitions|Appendix.*|Test Results|Code Coverage|Automated Analyses|About Quantstamp',line.content,re.I):active=False
        if line.code or not active: continue
        # Some PDF fonts decode the printed ID separator as U+FFFD. Require a
        # complete ID and the same card's risk/status badge; never match prose.
        m=re.match(r'^([A-Z][A-Z0-9]{1,15}[-–�](?:\d+[-–�])*\d+)(?:\s+(.+))?$',line.content)
        if not m: continue
        parts=[];raw=None;state=None
        for q in report.lines[i:i+7]:
            badge=re.search(r'[•●]\s*('+RISK+r')\s+('+STATUS+r')\s*$',q.content,re.I)
            if badge:
                prefix=q.content[:badge.start()]
                prefix=re.sub(r'^'+re.escape(m[1])+r'\s*','',prefix)
                if prefix: parts.append(prefix)
                raw,state=badge[1],badge[2]
                break
            if q.start==line.start:
                if m[2]: parts.append(m[2])
            elif q.content and not re.match(r'Update|File\(s\)|Description|[A-Z][A-Z0-9]+-\d+',q.content): parts.append(q.content)
        if raw:
            out.append(Candidate(line.start,clean(' '.join(parts)),raw,re.sub('[-–�]','-',m[1]),status_raw=state,method='quantstamp-project-id-badge',confidence=.95,
                evidence={'native_id_text':m[1],'id_separator_normalization':'PDF separator glyph only'}))
    return bounded(report,out,r'(?:Definitions|Appendix.*|Test Results|Code Coverage|Automated Analyses|About Quantstamp)')


def outcome_only(report):
    if len(report.text.strip())<200: reason='insufficient_text_layer'
    elif re.search(r'Total Issues\s+0\b',report.text): reason='publisher_reports_zero_findings'
    else: reason='summary_only_without_finding_details'
    report.layout_disposition={'reason':reason,'basis':'publisher_outcome_or_available_text_layer'}
    return []


VARIANTS += (
 Variant('quantstamp/v2024_project_cards',Fingerprint((('project_bullet',r'^.*[•●]\s*'+RISK+r'\s+'+STATUS+r'\s*$',8),),structured=False),project_cards,('quantstamp_project',),status_parser('quantstamp')),
 Variant('quantstamp/v2019_outcome_only',Fingerprint((('outcome',r'Total Issues\s+\d+|no issues to report|Summary of Findings',6),),structured=False),outcome_only,('quantstamp_outcome',)),
 Variant('quantstamp/v2021_sparse_text',Fingerprint((('methods_only',r'Architecture Review, Unit Testing, Functional\s+Testing, Computer-Aided Verification, Manual\s+Review',6),),structured=False,reject_signatures=(r'Findings|Issues|Quantstamp',)),outcome_only,('quantstamp_sparse',)),
)


def remediation_status(report,candidates):
    attach_status(report,candidates,'quantstamp')
    for c in candidates:
        if not c.status_raw:
            c.normalized_status='unknown';c.evidence['status_availability']=dict(status='unknown',reason='not_stated',checked='native status, labelled detail fields and ID-linked fix-review index')


from dataclasses import replace as _replace
VARIANTS=tuple(_replace(v,status_parser=remediation_status) if v.status_parser and v.status_parser is not column_status else v for v in VARIANTS)
