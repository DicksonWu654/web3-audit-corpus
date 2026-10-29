"""Decurity numbered risk cards, legacy DETAILS and verification reports."""
import re
from core import Candidate, clean, severity

DESCRIPTION = "Numbered Risk Level detail cards, legacy 4.1.n findings and explicit verification risk headings"
RISK = r"Critical|High|Medium|Low|Info(?:rmational)?"
NUMBER = re.compile(r"^(\d+(?:\.\d+){1,2})\.?\s+(.+)")


def parse(report):
    out = []
    lines = report.lines
    for i, line in enumerate(lines):
        if line.excluded or line.code or re.search(r"(?:\.\s*){3,}|\s{3,}\d+\s*$", line.text):
            continue
        m = NUMBER.match(line.content.replace('\u200b',''))
        if not m:
            continue
        nearby = report.near(i, 12)
        risk = re.search(r"Risk\s+Level\s*:\s*(" + RISK + r")\b", nearby, re.I)
        classified=re.match(r'^\[('+RISK+r')\]\s*(.+)',m[2],re.I)
        if classified:
            out.append(Candidate(line.start,classified[2],classified[1],m[1],
                                 method="verification-classified-section",confidence=.94))
            continue
        legacy = len(m[1].split('.')) == 3 and re.search(r"^\s*Summary:", nearby, re.M)
        if not risk and not legacy:
            continue
        # Never borrow metadata from the following numbered heading.
        prefix = nearby[:risk.start()] if risk else nearby[:nearby.find('Summary:')]
        if any(NUMBER.match(x.strip()) for x in prefix.splitlines()[1:]):
            continue
        title_parts = [m[2]]
        for following in lines[i+1:i+6]:
            v = following.content
            if not v or re.match(r"(?:Risk\s+Level|Summary|Status|Contracts?)\s*:", v, re.I):
                break
            title_parts.append(v)
        out.append(Candidate(line.start, clean(' '.join(title_parts)), risk[1] if risk else None,
                             m[1], method="numbered-risk-card", confidence=.96,
                             evidence={"severity_basis": "explicit_risk_level" if risk else "unprinted"}))
    # Older TON report prints the only classified issue descriptions in Summary.
    if not out:
        for i, line in enumerate(lines):
            if line.excluded or re.search(r"(?:\.\s*){3,}|\s{3,}\d+\s*$", line.text):
                continue
            m = re.match(r"^\[(" + RISK + r")\]\s+(.+)", line.content, re.I)
            if m:
                out.append(Candidate(line.start, m[2], m[1], method="verification-classified-heading", confidence=.92))
    # Early DETAILS cards omit risk labels, but print an ordered per-finding
    # Issue/Risk Level/Probability/Status table. Use its risk *column*, never its
    # probability column, and only when its row count exactly equals the detail
    # sequence. Keep the table evidence as the explicit source of each label.
    unknown=[c for c in out if c.severity_raw is None]
    legacy_rows=[];active=False;column=None
    for index,line in enumerate(lines):
        if re.search(r'Issue\s+Risk Level\s+Probability\s+Status',line.text):
            active=True;column=line.text.index('Risk Level');continue
        if active and re.match(r'^3\s+GENERAL RECOMMENDATIONS',line.content):
            break
        if active:
            cell=line.text[max(0,column-3):column+12].strip()
            hit=re.match(r'^('+RISK+r')\b',cell,re.I)
            if hit:
                context=' '.join(x.text[:max(0,column-3)] for x in lines[max(0,index-4):index+5])
                legacy_rows.append((hit[1],line,context))
    if unknown and len(unknown)==len(out)==len(legacy_rows):
        def key(value):
            return re.sub(r'[^a-z0-9]','',re.sub(r'\[[^\]]*\]','',value).lower())
        aligned=all(key(c.title)[:22] in key(context) for c,(_,_,context) in zip(unknown,legacy_rows))
        for c,(risk,line,context) in zip(unknown,legacy_rows) if aligned else []:
            c.severity_raw=risk
            c.evidence={'severity_basis':'ordered_per_finding_summary_risk_column',
                        'severity_evidence':{'start':line.start,'end':line.end,'page':line.page,'text':line.text},
                        'alignment':'equal_length_row_order_with_matching_title_prefix'}
    # Bound findings before proof-of-concept appendices and publisher boilerplate.
    for n, c in enumerate(out):
        end = out[n+1].start if n+1 < len(out) else len(report.text)
        tail = report.text[c.start:end]
        stop = re.search(r"\n\s*\d+\.?\s+(?:APPENDIX|Appendix|Proofs? of Concept)\b", tail)
        if c.method=='verification-classified-section':
            section_stop=re.search(r'\n\s*\d+\.\d+\.?\s+(?:Possible issues|Possible attacks)\b',tail,re.I)
            if section_stop and (not stop or section_stop.start()<stop.start()):
                stop=section_stop
        if stop:
            end = c.start + stop.start()
        c.end = end
        body = report.text[c.start:c.end]
        m = re.search(r"\bStatus\s*:\s*([^\n]+(?:\n(?!\s*(?:Description|Contracts?|Resources?|References?|Remediation|Proofs?)\s*:)[^\n]+)?)", body, re.I)
        if m:
            c.status_raw = clean(m[1])
    return out


def printed_counts(report):
    """Count only classifications in the publisher's separate Suggestions table."""
    from collections import Counter
    start = None
    counts, evidence = Counter(), []
    for line in report.lines:
        if re.search(r"(?:Issue|Weakness).*?(?:Risk\s+Level|Severity).*?Status", line.text, re.I):
            start = line.start
            continue
        if start is None:
            continue
        if re.match(r"^\d+\.?\s+(?:General Recommendations|GENERAL RECOMMENDATIONS|DETAILS|Findings)", line.content.replace('\u200b','')):
            break
        # Each Suggestions row has one printed risk; continued contract lists have none.
        hits = re.findall(r"\b(" + RISK + r")\b", line.text, re.I)
        if len(hits) == 1 and (re.search(r"\s{2,}(?:"+RISK+r")\b", line.text, re.I) or re.fullmatch(RISK, line.content, re.I)
                               or re.search(r'\b(?:'+RISK+r')\s+(?:Fixed|Acknowledged|Not fixed|Partially Fixed)\b',line.text,re.I)):
            counts[severity(hits[0], report.firm)] += 1
            evidence.append({"start":line.start,"end":line.end,"page":line.page,"text":line.text})
    return {"basis":"printed_suggestions_table_classifications", "counts":dict(counts), "evidence":evidence} if evidence else None


from variants import Variant, Fingerprint
from parsers.group2_layouts import statuses

def parse_risk_cards(report):return [c for c in parse(report) if c.method=='numbered-risk-card']
def parse_details(report):return parse(report)
def parse_verification(report):return [c for c in parse(report) if c.method.startswith('verification-')]
def parse_clean(report):return []
def status_risk_cards(report,candidates):statuses(report,candidates,narrative=True,headings=True)
def status_details(report,candidates):statuses(report,candidates,narrative=True,headings=True)
def status_verification(report,candidates):statuses(report,candidates,narrative=True,headings=True)
def status_clean(report,candidates):return None

VARIANTS=(
    Variant('decurity/v2023_risk_level',Fingerprint((('risk field',r'Risk\s+Level\s*:\s*(?:Critical|High|Medium|Low|Info)',8),),('2022','2026')),parse_risk_cards,('decurity_risk',),status_risk_cards,printed_counts,notes='Numbered Risk Level cards; extracts Not fixed, commit-linked Fixed, customer acknowledgement and resolution assertions from Status fields.'),
    Variant('decurity/v2021_details',Fingerprint((('details chapter',r'^\s*4\.?\s+DETAILS',5),('legacy summary field',r'^\s*Summary\s*:',3)),('2020','2023')),parse_details,('decurity_details',),status_details,printed_counts,notes='Legacy 4.1.n Summary/DETAILS cards with ordered risk/status summary columns; probability is never treated as risk.'),
    Variant('decurity/v2022_verification',Fingerprint((('classified heading',r'^\s*(?:\d+(?:\.\d+){1,2}\.?\s+)?\[(?:Critical|High|Medium|Low|Info(?:rmational)?)\]\s+',8),),('2021','2024')),parse_verification,('decurity_verification',),status_verification,printed_counts,notes='Verification reports with bracket-labelled issue sections, excluding unclassified possible-attack narrative; explicit remediation only.'),
    Variant('decurity/v2024_clean',Fingerprint((('publisher identity',r'The Decurity team',3),('clean summary',r'no (?:issues|vulnerabilities)|no security|not discovered any security issues|haven.t identified any exploitable security issues|No suggestions|Suggestions\s*\n',4)),('2024','2026')),parse_clean,('decurity_clean',),status_clean,printed_counts,notes='Modern clean-audit summary without Risk Level detail cards; empty findings are retained as genuine document coverage outcomes.'),
)
