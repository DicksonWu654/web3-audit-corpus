"""Secure3 PDF detail metadata; chart counts remain independent of detail risk."""
from core import severity, Candidate, clean
import re

DESCRIPTION = "Secure3 ID detail headings with columnar severity/status, including wrapped titles and native Information labels"
RISK = r"Critical|High|Medium|Low|Informational|Information"
STATUS = r"Acknowledged|Fixed|Mitigated|Declined|Reported|Partially Fixed|Open"


def parse(report, competitive=None):
    out=[]
    for i,line in enumerate(report.lines):
        m=re.match(r"^([A-Z][A-Z0-9]*-\d+):\s*(.*)",line.content)
        wrapped=False
        if not m and re.fullmatch(r'[A-Z][A-Z0-9]*-',line.content) and i+1<len(report.lines):
            m=re.match(r'^([A-Z][A-Z0-9]*-\d+):\s*(.*)',line.content+report.lines[i+1].content)
            wrapped=bool(m)
        if not m:
            continue
        ahead=report.lines[i+1+int(wrapped):i+14]
        columns='Client Response' if competitive is True else r'Code Reference\s+Status' if competitive is False else r'(?:Client Response|Code Reference\s+Status)'
        hi=next((j for j,l in enumerate(ahead) if re.search(r'Category\s+Severity\s+'+columns,l.text)),None)
        if hi is None:
            continue
        header=ahead[hi]
        title=clean(" ".join([m[2]]+[l.content for l in ahead[:hi] if l.content]))
        raw,risk_line,stat=None,None,None
        for l in ahead[hi+1:]:
            if re.match(r"^\s*Code\s*$",l.text):
                break
            risk=re.search(r"\b("+RISK+r")\b",l.text)
            if risk:
                raw,risk_line=risk[1],l
                # Code reference text sometimes occupies the space preceding
                # Status; match the explicit status word rather than slicing
                # at a header column which shifts between PDF rows.
                st=re.search(r"\b("+STATUS+r")\b",l.text[risk.end():])
                stat=st[1] if st else None
                break
        if raw:
            out.append(Candidate(line.start,title,raw,m[1],
                                 normalized=severity(raw, report.firm),
                                 status_raw=stat,method="secure3-detail-metadata",confidence=.98,
                                 evidence={"severity_basis":"detail_metadata_severity","severity_span":{"start":risk_line.start,"end":risk_line.end},
                                           "wrapped_id_span":{"start":line.start,"end":report.lines[i+1].end} if wrapped else None}))
    for i,c in enumerate(out):
        limit=out[i+1].start if i+1<len(out) else len(report.text)
        c.end=limit
        for line in report.lines:
            if c.start<line.start<limit and re.fullmatch(r"Disclaimer",line.content):
                c.end=line.start
                break
    return out


def printed_counts(report):
    """Use chart totals only: index rows are retained as independent ID tests."""
    for page in report.meta["pages"]:
        if not re.search(r"^Code Assessment Findings\s*$",page["text"],re.M):
            continue
        # The PDF chart is rendered in separated columns. Labels and their
        # counts have matching left positions, even across a center total.
        chart=page["text"].split("\nID",1)[0]
        if "Total Issues" not in chart:
            continue
        rows=chart.splitlines(keepends=True)
        counts,proof={},[]
        offset=page["start"]
        positions=[]
        for line in rows:
            for m in re.finditer(r"\b("+RISK+r")\b",line):
                positions.append((offset,m.start(),m[1],line))
            offset+=len(line)
        for start,col,label,line in positions:
            # A chart label is followed by its integer on the next nonempty
            # row. Both left and right aligned labels occur in these reports.
            remainder=chart[start-page["start"]+len(line):]
            number_line=next((l for l in remainder.splitlines() if l.strip()),"")
            numbers=list(re.finditer(r"\d+",number_line))
            if not numbers:
                continue
            n=min(numbers,key=lambda m:min(abs(m.start()-col),abs(m.end()-(col+len(label)))))
            if min(abs(n.start()-col),abs(n.end()-(col+len(label))))>3:
                continue
            counts[severity(label, report.firm)]=int(n[0])
            end=start+len(line)+remainder.index(number_line)+len(number_line)
            proof.append({"page":page["page"],"start":start,"end":end,"text":report.text[start:end]})
        if len(counts)>=2:
            return {"counts":counts,"basis":"secure3_printed_chart","evidence":proof}
    return None


from variants import Variant, Fingerprint
from parsers.group2_layouts import statuses

def parse_chart_cards(report):return parse(report,competitive=False)
def parse_contract_cards(report):return parse(report,competitive=True)
def status_chart(report,candidates):statuses(report,candidates,headings=True,index_id=r'\b[A-Z][A-Z0-9]*-\d+\b')
def status_contracts(report,candidates):statuses(report,candidates,headings=True,index_id=r'\b[A-Z][A-Z0-9]*-\d+\b')

VARIANTS=(
    Variant('secure3/v2023_competitive',Fingerprint((('contributor metadata',r'Category\s+Severity\s+Client Response\s+Contributor',10),),('2023','2024')),parse_contract_cards,('secure3_competitive',),status_contracts,printed_counts,notes='Competitive assessments add Client Response/Contributor columns and place Code Reference below the metadata table; Declined remains other because the label does not distinguish rejected findings from accepted risk.'),
    Variant('secure3/v2022_chart_cards',Fingerprint((('chart section',r'Code Assessment Findings',4),('detail metadata',r'Category\s+Severity\s+Code Reference\s+Status',4)),('2022','2024')),parse_chart_cards,('secure3_chart',),status_chart,printed_counts,notes='Identifier cards with Category/Severity/Code Reference/Status columns and independent risk charts; preserve source disagreements between chart and detail.'),
)
