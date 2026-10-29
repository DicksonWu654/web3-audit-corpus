"""Pessimistic severity-ID findings and pre-ID titled detail sections."""
from core import SeverityLookup, severity, Candidate, clean
import re

DESCRIPTION = "C01/M01/L01/N01 detail headings and legacy titled issues under printed severity sections"
ID = re.compile(r"^\s*([CHMLNI]\d{1,3})[.:]\s*(\S.*)$", re.I)
SECTION = re.compile(r"^(Critical issues|High[ -]severity issues|Medium[ -]severity issues|Low[ -]severity issues|Notes?)$", re.I)
MAP = SeverityLookup('pessimistic', ('c', 'h', 'm', 'l', 'n', 'i'))
DOTS = re.compile(r"\s*\.{4,}.*$")


def index_entries(report):
    """Independent TOC inventory, including genuinely unnumbered old headings."""
    out, section = [], None
    for line in report.lines:
        if out and re.fullmatch(r"(?:Abstract|Summary|Disclaimer)",line.content,re.I):
            break
        if not re.search(r"\.{4,}", line.content):
            continue
        title = clean(DOTS.sub("", line.content))
        if re.match(r"^(?:Appendix|Automated analysis|A\d+\.|Cargo (?:clippy|audit))",title,re.I):
            if out:
                break
            section=None
            continue
        if SECTION.fullmatch(title):
            section = title
        elif section and title and not re.match(r"^(?:This analysis|Appendix|Conclusion)", title, re.I):
            m = ID.match(title)
            out.append({"key":m[1] if m else title,"title":title,"section":section,"start":line.start,"end":line.end})
    return out


def parse(report):
    out, section, active = [], None, False
    index = index_entries(report)
    bare=lambda s: re.sub(r"\s*\([^()]*\)\s*$","",s)
    legacy_titles = {bare(x["title"]) for x in index if not ID.match(x["title"])}
    for i, line in enumerate(report.lines):
        s = clean(line.content)
        if re.search(r"\.{4,}", s):
            continue
        if re.match(r"^(?:This analysis was performed|Appendix|Analysis performed by)", s, re.I):
            if out:
                out[-1].end = line.start
                break
            continue
        if SECTION.fullmatch(s):
            if out and out[-1].end is None:
                out[-1].end=line.start
            section, active = s, True
            continue
        if s.lower()=="manual analysis":
            active=True
        if not active:
            continue
        m = ID.match(s)
        if m:
            title, pid, raw, norm = m[2], m[1], m[1][0], MAP[m[1][0].lower()]
        elif bare(s) in legacy_titles and section:
            title, pid, raw = s, None, section
            norm = SeverityLookup(report.firm, ('critical issues', 'high severity issues', 'medium severity issues', 'low severity issues', 'notes', 'note'))[section.lower().replace('-',' ')]
        else:
            continue
        # Parenthetic source status is retained verbatim. In particular,
        # "commented" is not silently relabelled as acknowledged or resolved.
        status = re.search(r"\(([^()]*)\)\s*$", title)
        status_raw = status[1] if status and re.search(r"fixed|addressed|commented|issue|resolved|new|acknowledged",status[1],re.I) else None
        title = title[:status.start()].strip() if status_raw else title
        out.append(Candidate(line.start,title,raw,pid,normalized=severity(raw, report.firm),status_raw=status_raw,
                             method="pessimistic-id-detail" if m else "pessimistic-legacy-title",
                             confidence=.92 if m else .85,
                             evidence={"severity_basis":"printed_id_prefix" if m else "printed_section"}))
    return out


def printed_counts(report):
    # Explicit aggregate statements only; TOC item counts are a distinct sequence
    # check in pessimistic_metrics.py, never manufactured numeric summaries.
    counts, proof = {}, []
    for m in re.finditer(r"The audit showed no (critical issues|issues of medium severity|issues of low severity)\.", report.text, re.I):
        key = "critical" if m[1].lower().startswith("critical") else "medium" if "medium" in m[1].lower() else "low"
        counts[key] = 0
        proof.append({"start":m.start(),"end":m.end(),"text":m[0]})
    return {"counts":counts,"basis":"explicit_zero_issue_statements","evidence":proof} if counts else None


from variants import Variant, Fingerprint
from parsers.group2_layouts import statuses

def parse_titled(report):return [c for c in parse(report) if c.printed_id is None]
def parse_identified(report):return [c for c in parse(report) if c.printed_id]
def parse_modern(report):
    # New visual cards use a bare severity-ID heading without a trailing dot.
    from core import Candidate
    out=[]
    for i,l in enumerate(report.lines):
        m=re.fullmatch(r'([CHMLNI]\d{1,3})\s+(.*)',l.content,re.I)
        if not m or l.excluded:continue
        out.append(Candidate(l.start,m[2],m[1][0],m[1],method='visual-id-card',confidence=.91))
    return out
def status_titled(report,candidates):statuses(report,candidates,headings=True)
def status_identified(report,candidates):statuses(report,candidates,headings=True,index_id=r'\b[CHMLNI]\d{1,3}\b')
def status_modern(report,candidates):statuses(report,candidates,headings=True,narrative=True,index_id=r'\b[CHMLNI]\d{1,3}\b')

VARIANTS=(
    Variant('pessimistic/v2025_visual_cards',Fingerprint((('visual cover',r'^\s*SECURITY\s*$',4),('publisher',r'^\s*PESSIMISTIC\s*$',3)),('2025','2026')),parse_modern,('pessimistic_visual',),status_modern,printed_counts,notes='Visual SECURITY/PESSIMISTIC template with ID cards and explicit status or resolution sections; no inference from developer recommendations.'),
    Variant('pessimistic/v2022_severity_ids',Fingerprint((('ID title',r'^\s*[CHMLNI]\d{1,3}[.:]\s+\S',8),),('2021','2026')),parse_identified,('pessimistic_ids',),status_identified,printed_counts,notes='Severity-prefix IDs with parenthetic dispositions. Commented remains other; explicit removed/false-positive IDs are not manufactured to fill sequence gaps.'),
    Variant('pessimistic/v2020_titled',Fingerprint((('manual review',r'Manual analysis',4),('publisher',r'by Pessimistic|PESSIMISTIC',3)),('2020','2024')),parse_titled,('pessimistic_titled',),status_titled,printed_counts,notes='Pre-ID titled findings matched to the independent contents list and severity section, including clean audits with no issue cards.'),
)
