"""Hats contest reports: numbered entries within severity sections and early L01 PDFs."""
import re
from core import Candidate, clean, severity
from parsers.shieldify import bounded
DESCRIPTION = 'Hats numbered findings under explicit severity headings and bracketed L01 PDF details'


def parse(report):
    out=[]
    current=None
    active=False
    for i,line in enumerate(report.lines):
        value=line.content.replace('**','').replace('ﬁ','fi')
        if re.fullmatch(r'Findings',value,re.I):
            active=True
        if re.match(r'Conclusion|Disclaimer',value,re.I) and line.heading:
            active=False
        section=re.match(r'^(Critical|High|Medium|Low|Informational|Info)\s+(?:severity\s+)?(?:findings?|issues?)\s*:?$',value,re.I)
        if section:
            current=section[1]
            active=True
            continue
        if not active or line.code:
            continue
        m=re.match(r'^\[([CHMLI])(\d+)\]\s*[-:]\s*(.+)',value)
        numbered=re.match(r'^(\d+)\.\s+(.+)',value)
        if m:
            title=[m[3]]
            for nxt in report.lines[i+1:i+4]:
                if not nxt.content or re.match(r'(?:The |This |In |A |Assum)',nxt.content):
                    break
                title.append(nxt.content)
            out.append(Candidate(line.start,clean(' '.join(title)),current,m[1]+m[2],method='hats-pdf-detail',confidence=.93))
        elif (numbered or re.match(r'^[-*]\s+\*\*',line.content)) and current and report.meta.get('file_format')=='md' and not line.text.startswith((' ', '\t')):
            if not numbered:
                title=re.match(r'^[-*]\s+\*\*(.+?)\*\*',line.content)
                out.append(Candidate(line.start,title[1],current,None,method='hats-severity-section-entry',confidence=.92,
                                     evidence={'severity_basis':'explicit_section_label','id_scheme':'unnumbered'}))
                continue
            title=re.match(r'^\*\*(.+?)\*\*',line.content.split('.',1)[1].strip())
            # Native contest entries mark their titles in bold. Plain numbered
            # attack/scenario steps inherit the same section grade but remain
            # narrative inside the current finding, even when unindented.
            if not title:continue
            rawtitle=title[1]
            out.append(Candidate(line.start,rawtitle,current,numbered[1],method='hats-severity-section-entry',confidence=.92,
                                 evidence={'severity_basis':'explicit_section_label','round':current.lower(),
                                           'container_id':current.lower()}))
    return bounded(report,out)


def printed_counts(report):
    counts,proof={},[]
    for line in report.lines:
        value=line.content.replace('ﬁ','fi')
        m=re.search(r'A total of (\d+) valid (Critical|High|Medium|Low|Informational) severity findings',value,re.I)
        zero=re.fullmatch(r'No (critical|high|medium|low|informational) severity findings were identified\.',value,re.I)
        if m or zero:
            key=severity(m[2] if m else zero[1], report.firm)
            count=int(m[1]) if m else 0
            if key in counts and counts[key]!=count:
                return {'counts':counts,'evidence':proof,'ambiguous':True,'basis':'hats_printed_severity_totals'}
            counts[key]=count
            proof.append({'start':line.start,'end':line.end,'page':line.page,'text':line.text})
    return {'counts':counts,'evidence':proof,'basis':'hats_printed_severity_totals'} if counts else None


from variants import Variant, Fingerprint
VARIANTS = (
    Variant('hats-finance/v2023_contest_sections',
            Fingerprint((('severity sections',r'^(?:#{1,6}\s+)?(?:\*\*)?(?:Critical|High|Medium|Low|Informational|Info)\s+(?:severity\s+)?(?:findings?|issues?)\s*:?',8),),formats=('md','html')),
            parse,('hats_contest',),printed_counts=printed_counts),
    Variant('hats-finance/v2022_letter_ids',
            Fingerprint((('bracket IDs',r'^\s*\[[CHMLI]\d+\]\s*[-:]',8),),formats=('pdf',)),
            parse,('hats_pdf',),printed_counts=printed_counts),
)


def client_audit(report):
    # This is a client-side archive of an external auditor's report, not a
    # Hats-published contest. Retain the occurrence and make no publisher claim.
    report.layout_disposition={'reason':'external_auditor_client_archive',
        'basis':'Auditor: Adam Levi; Hats DAO is the audited client, not the author'}
    return []


VARIANTS += (Variant('hats-finance/v2021_client_archive',
    Fingerprint((('named external auditor',r'Auditor:\s*Adam Levi',8),('client preface',r'thank Hats DAO.*auditing their code',3))),
    client_audit,('hats_client_archive',)),)
