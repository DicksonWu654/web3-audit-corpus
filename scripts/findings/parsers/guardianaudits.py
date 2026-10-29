"""Guardian legacy project IDs, pipe detail tables and spaced severity/status cards."""
from core import severity, Candidate, SPACED_SEV, SHORT, clean
import re
from parsers.shieldify import bounded
DESCRIPTION = 'Guardian project-ID tables and modern spaced-label cards; continued pages excluded'
# Some early contracts are named 20A / 721A or SQD[1-F]. The report's
# Global-1 casing also differs from the GLOBAL-1 overview; retain detail spelling.
PID=r'(?:R\d+-)?[A-Z0-9]+(?:\[[A-Z0-9-]+\])?-\d+(?:\.\d+)?'


def parse(report):
    out=[]
    round_label=None
    for i,line in enumerate(report.lines):
        # Some Markdown headings place the ID/title inside the anchor itself.
        value=re.sub(r'</?a\b[^>]*>','',line.content).strip()
        compact=re.sub(r'\s+','',value).upper()
        if re.fullmatch(r'(?:ROUND|REVIEWROUND)[1-9]+',compact):
            round_label=compact
        if (line.code and report.meta.get('file_format')!='pdf') or 'CONTINUED' in value.upper() or re.search(r'(?:\.\s*){4,}\s*\d+\s*$',value):
            continue
        # Project-specific IDs (GMXC-1, SGE-01, etc.) require detail metadata.
        pipe=re.match(r'^('+PID+r')\s*\|\s*(.+)',value,re.I)
        md=re.match(r'^('+PID+r')\s+(.+)',value,re.I) if line.heading else None
        if pipe or md:
            match=pipe or md
            near=report.near(i,10)
            if not (line.heading or re.search(r'\bCategory\s+Severity\b',near,re.I)):
                continue
            risk=re.search(r'[●•]\s*(Critical|High|Medium|Low|Informational|Info)\b',near,re.I)
            if not risk:
                for j in range(i+1,min(i+7,len(report.lines))):
                    header=report.lines[j].text
                    if not re.search(r'Category\s+Severity\b',header,re.I):
                        continue
                    start=header.lower().index('severity')
                    end=re.search(r'Commit|Location|Status',header[start+8:],re.I)
                    end=start+8+end.start() if end else len(header)
                    fields='\n'.join(l.text[max(0,start-3):end] for l in report.lines[j+1:j+5])
                    risk=re.search(r'\b('+SPACED_SEV+r'|Discussion)\b',fields,re.I)
                    if not risk:
                        rows='\n'.join(l.text for l in report.lines[j+1:j+4])
                        labels=list(re.finditer(r'(?<!\S)(Critical|High|Medium|Low|Informational|Info)(?!\S)',rows,re.I))
                        risk=labels[-1] if labels else None
                    break
            code=re.match(r'(?:R\d+-)?([A-Z])',match[1])
            raw=risk[1] if risk else code[1] if code else None
            norm=None if risk else SHORT.get(raw,'unknown')
            title=[match[2]]
            if not line.heading:
                for nxt in report.lines[i+1:i+6]:
                    if re.search(r'\bCategory\s+Severity\b',nxt.content,re.I):
                        break
                    if nxt.content:
                        title.append(nxt.content)
            st=re.search(r'\s{2,}(Partially Resolved|Unresolved|Resolved|Acknowledged|Pending|Open|Declined|Risk Accepted|Accepted|Fixed|Mitigated|Reported)\s*$',near,re.I|re.M)
            title=clean(' '.join(title))
            continuation=bool(re.search(r'Description\s+PoC',near,re.I) or
                              (re.search(r'^\s*Resolution\s*$',near,re.I|re.M) and not re.search(r'^\s*Description\b',near,re.I|re.M)))
            if out and out[-1].printed_id==match[1] and out[-1].title==title and continuation:
                out[-1].evidence.setdefault('continuation_heading_offsets',[]).append(line.start)
                continue
            out.append(Candidate(line.start,title,raw,match[1],severity(raw, report.firm),
                                 status_raw=st[1] if st else None,method='guardian-legacy-detail',confidence=.95,
                                 record_kind='observation' if (raw or '').lower()=='discussion' else 'formal_finding',
                                 evidence={'severity_basis':'explicit_field' if risk else 'printed_id_prefix','round':round_label}))
            continue
        card=re.fullmatch(r'(?:(?P<sev>'+SPACED_SEV+r')\s+)?(?P<id>'+PID+r')\s*(?P<status>.*)',value,re.I)
        if not card:
            continue
        status=card['status'].strip()
        compact_status=re.sub(r'\s+','',status).upper()
        if compact_status and compact_status not in {'RESOLVED','ACKNOWLEDGED','PARTIALLYRESOLVED','PENDING','OPEN','FIXED','MITIGATED','REPORTED','UNRESOLVED','DECLINED','ACCEPTED','RISKACCEPTED'}:
            continue
        raw=card['sev']
        if not raw:
            previous=next((l for l in reversed(report.lines[max(0,i-4):i]) if l.content),None)
            if previous and re.fullmatch(SPACED_SEV,previous.content,re.I):
                raw=previous.content
        code=re.search(r'([CHMLIG])-\d+',card['id'])
        if not compact_status and (not raw or not re.search(r'C\s*A\s*T\s*E?\s*G\s*O\s*R\s*Y',report.near(i,14),re.I)):
            continue
        norm=None if raw else SHORT.get(code[1] if code else '', 'unknown')
        raw=raw or (code[1] if code else None)
        title=[]
        for nxt in report.lines[i+1:i+20]:
            if not nxt.content:
                if title:
                    break
                continue
            if re.match(r'C\s*A\s*T\s*E?\s*G\s*O\s*R\s*Y|CATEGORY|DESCRIPTION',nxt.content,re.I):
                break
            title.append(nxt.content)
        if title:
            out.append(Candidate(line.start,clean(' '.join(title)),raw,card['id'],severity(raw, report.firm),status_raw=status or None,
                                 method='guardian-detail-card',confidence=.97,
                                 evidence={'severity_basis':'explicit_card_label' if card['sev'] else 'adjacent_label_or_id',
                                           'round':re.match(r'R\d+',card['id'])[0] if re.match(r'R\d+',card['id']) else round_label,
                                           'status_pdf_letter_spacing':True}))
    for c in out:
        nearby=report.text[c.start:c.start+1200]
        review=re.search(r'\bREVIEW\s+(Main Review|Remediation Review(?:\s+\d+)?)\b',nearby,re.I)
        if review:
            c.evidence['round']=review[1]
            if hasattr(c,'finding_phase'):
                c.finding_phase='fix_review' if 'remediation' in review[1].lower() else 'initial_audit'
    return bounded(report,out)


# Phase 4d compatibility contract; preserve the existing parser until era review.
from variants import legacy as _legacy_variant
VARIANTS = (_legacy_variant('guardianaudits', parse),)
