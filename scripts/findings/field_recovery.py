"""Conservative, publisher-scoped repairs to existing finding fields only.

Does not create findings or change identity, body spans, phases, dates or kinds.
All text claims retain exact source offsets. Outlined badges use separately
hash-bound PDF/OCR evidence rather than fabricated text-cache coordinates.
"""
import re
from bisect import bisect_right
from core import set_status_claim

RISK=r'(?:Critical|High|Medium|Low|Informational|Information|Info)'
STATE=(r'Partially\s+(?:Fixed|Resolved|Addressed|Mitigated)|Not\s+(?:Fixed|Resolved|Addressed)|'
       r'Risk\s+Accepted|Won[’\x27]t\s+Fix|Unresolved|Acknowledged|Resolved|Fixed|Mitigated|Addressed|Confirmed|Open')


def severity_claim(report,c,m,offset,basis):
    a,b=offset+m.start(1),offset+m.end(1)
    c.severity_raw=report.text[a:b]
    c.evidence['severity_basis']=basis
    c.evidence['severity_label_span']={'start':a,'end':b,'text':report.text[a:b]}


def in_code(report,position):
    if report.lines:
        if not hasattr(report,'_field_line_starts'):report._field_line_starts=[l.start for l in report.lines]
        i=bisect_right(report._field_line_starts,position)-1
        return i>=0 and report.lines[i].code
    fence=None
    for m in re.finditer(r'(?m)^\s*(`{3,}|~{3,})([^\n]*)',report.text[:position]):
        if fence and m[1][0]==fence and not m[2].strip():fence=None
        elif not fence:fence=m[1][0]
    return fence is not None


def recover_fields(report,c):
    before={'severity_raw':c.severity_raw,'status_raw':c.status_raw}
    body=report.text[c.start:c.end]
    if report.firm=='openzeppelin' and c.severity_raw in {'C','H','M','L'}:
        # Full printed parent labels define these codes in the same report.
        parent=None
        for line in report.lines:
            if line.start>=c.start:break
            m=re.fullmatch(r'\s*(?:#{1,6}\s+)?('+RISK+r')(?:\s+(?:Severity|Risk))?(?:\s+Issues)?\s*',line.text,re.I)
            if m:parent=(line,m)
        if parent and parent[1][1][0].upper()==c.severity_raw:
            severity_claim(report,c,parent[1],parent[0].start,'printed_parent_severity_heading')
    if report.firm in {'teamomega','code4rena'} and c.severity_raw is None:
        m=re.search(r'(?mi)^[ \t]*Severity[ \t]*:[ \t]*('+RISK+r')\b',body[:1500])
        if m:severity_claim(report,c,m,c.start,'explicit_severity_field')
    if (report.firm=='verichains' and c.severity_raw is None) or (report.firm=='zokyo' and c.severity_raw in {None,'Hi','Mei'}):
        from verichains_badges import evidence
        if not hasattr(report,'_badge_evidence'):report._badge_evidence=evidence(report)
        proof=report._badge_evidence.get(str(c.start),{})
        if proof.get('accepted') and proof.get('native_id')==c.printed_id:
            c.severity_raw=proof['raw'];c.evidence['severity_basis']='pdf_labelled_risk_cell_ocr' if report.firm=='zokyo' else 'pdf_heading_badge_ocr'
            c.evidence['severity_pdf_evidence']=proof
            if report.firm=='zokyo' and c.status_raw is None and proof.get('status_raw'):
                c.status_raw=proof['status_raw'];c.evidence['status_pdf_evidence']=proof
    if report.firm=='slowmist' and c.severity_raw=='P2P':
        for line in report.lines:
            if not c.start<=line.start<c.end:continue
            m=re.match(r'^\s*'+re.escape(c.printed_id or '<none>')+r'\s+.*?\s{2,}('+RISK+r')\s{2,}(?:Acknowledged|Fixed|Ignored)\s*$',line.text,re.I)
            if m:severity_claim(report,c,m,line.start,'native_id_summary_severity_cell');break
    if c.status_raw is None and not any(c.evidence.get(k) for k in ('status_conflict','status_index_conflict')):
        # Legacy readers require a colon and miss Markdown section headings.
        patterns=[('labelled_status_heading',r'(?mi)^[ \t]*(?:#{1,6}[ \t]+)?(?:\*\*)?(?:Status|Remediation Status|Resolution Status)(?:\*\*)?(?::[ \t]*|[ \t]*\n(?:[ \t]*\n)*[ \t]*|[ \t]{2,})(?:\*\*)?('+STATE+r')\b')]
        if report.firm=='openzeppelin':
            patterns+=[('publisher_update',r'(?mi)^[ \t]*(?:\*\*)?Update(?:\*\*)?[ \t]*:[ \t]*(?:\*\*)?('+STATE+r')\b')]
        elif report.firm=='pashov-audit-group':
            discussion_pattern=('publisher_discussion_response',r'(?mi)^[ \t]*(?:\*\*)?(?:pashov|Pashov Audit Group|Pashov|[A-Za-z0-9_-]+)[ \t]*:(?:\*\*)?[ \t]*('+STATE+r')\b')
            # Discussion responses are read only inside the labelled section.
            section=re.search(r'(?mi)^#{1,6}\s+Discussion\s*$',body)
            if section:patterns.append(discussion_pattern)
        elif report.firm=='electisec':
            patterns+=[('remediation_status_section',r'(?mi)^#{1,6}\s+Remediation Status\s*\n(?:[ \t]*\n)*[ \t]*(?:\*\*)?(?:(?:This|The) issue (?:has been|was|is)\s+)?('+STATE+r')\b')]
            patterns+=[('remediation_status_assertion',r'(?mi)^#{1,6}\s+Remediation Status\s*\n(?:[ \t]*\n)*[ \t]*(?:This|The) (?:issue|finding) (?:(?:has|have) (?:been )?|was |is )(?:successfully |fully )?('+STATE+r'|not been remediated)\b')]
        elif report.firm=='verichains':
            patterns+=[('finding_update_assertion',r'\b(?:This|The)\s+(?:issue|finding|vulnerability)\s+(?:has\s+been|was|is)\s+('+STATE+r')\b')]
        for basis,pattern in patterns:
            matches=list(re.finditer(pattern,body,re.I))
            if basis=='publisher_discussion_response':matches=[m for m in matches if m.start()>section.end()]
            matches=[m for m in matches if not in_code(report,c.start+m.start(1))
                and not re.search(r'^\s*(?:/|&|and|but)\s*(?:'+STATE+r')\b',body[m.end(1):m.end(1)+100],re.I)]
            if matches:set_status_claim(report,c,matches[-1],c.start,basis)
    after={'severity_raw':c.severity_raw,'status_raw':c.status_raw}
    if before!=after:
        c.evidence['field_recovery']={'reader':'field-recovery-v1','before':before,'after':after}
    return c


def status_availability(report,c,receipt):
    """Explain missing remediation without treating missing as unresolved.

    No-column is a structural observation; prose remediation might still exist.
    Undetected prose stays an explicit review gap, never an asserted open issue.
    """
    if c.status_raw:
        reason=('explicit_status' if receipt['normalized']!='not_stated' else
                'explicit_non_remediation_disposition' if receipt['mapped'] else 'unmapped_status_label')
    elif c.evidence.get('status_conflict'):
        reason='conflicting_source_statuses'
    else:
        if not hasattr(report,'_has_status_structure'):
            report._has_status_structure=bool(re.search(
                r'(?mi)^\s*(?:#{1,6}\s+)?(?:Status|Remediation Status|Resolution|Verification|Update[s]?)\b|'
                r'\bSeverity\s+Name\s+Status\b|\b(?:Description|Title)\s+Status\b',report.text))
        reason='report_status_structure_present_no_finding_claim' if report._has_status_structure else 'report_has_no_status_column_or_field'
    return {'reason':reason,'basis':'source_structure_and_extracted_claims',
            'limitation':'No-column detection does not rule out unstructured prose responses.'}
