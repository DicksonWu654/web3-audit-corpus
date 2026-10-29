"""Sherlock's official Markdown has '# Issue H-1: title' entries."""
from core import severity, Candidate, SHORT, bracket_findings, is_toc, clean
import re
from parsers.shieldify import bounded
from core import set_status_claim
DESCRIPTION = "Official Issue H-n/M-n detail headers; discussion text remains inside its finding"


def parse(report):
    candidates=bracket_findings(report)
    if report.meta.get("file_format")!="pdf":
        return bounded(report,candidates)
    explicit={}
    for i,line in enumerate(report.lines):
        if re.search(r'(?:\.\s*){4,}',line.content):
            continue
        m=re.fullmatch(r"Issue\s+([CHMLIG]-\d+)(?:\s+\(([^)]*)\))?(?:(?:\s*:\s*|\s+)(.*))?",line.content,re.I)
        if not m:
            continue
        if not re.search(r'(?:^|\n)\s*(?:Source\s*:|Severity\s*$|Summary\s*$|Issue Detail\s*$|Vulnerability Detail\s*$)',report.near(i,18),re.M):
            continue
        title=[m[3]] if m[3] else []
        for nextline in report.lines[i+1:i+14]:
            if not nextline.content:
                if title:
                    break
                continue
            if re.match(r"(?:Source\s*:|Severity\b|Summary\b|Issue Detail\b|Issue\s+[CHMLIG]-|Found by\b|\d+\s*/\s*\d+)",nextline.content,re.I):
                break
            title.append(nextline.content)
        if title:
            code=m[1][0].upper()
            risk=re.search(r'\bSeverity\s*:?\s*\n\s*(Critical|High|Medium|Low|Informational|Info)\b',report.near(i,18),re.I)
            explicit[line.start]=Candidate(line.start,"\n".join(title),risk[1] if risk else code,m[1],severity(risk[1] if risk else code, report.firm),
                                           status_raw='invalid' if m[2] and 'invalid' in m[2].lower() else None,
                                           method="sherlock-pdf-issue-card",confidence=.95,
                                           evidence={"severity_basis":"explicit_field" if risk else "printed_id_prefix",
                                                     "id_annotation":m[2]})
    return bounded(report,list(explicit.values()))


STATE = (r'Partially (?:fixed|resolved|mitigated)|Not (?:fixed|fixing|resolved)|Won[’\x27]t fix|'
         r'Confirmed fix|Fix confirmed|Acknowledged and fixed|Acknowledged|Fixed|Resolved|Unresolved|Invalid')


def read_status(report, candidates):
    bounded(report,candidates)
    from bisect import bisect_right
    starts=[l.start for l in report.lines]
    def eligible(pos):return not report.lines[max(0,bisect_right(starts,pos)-1)].code
    for c in candidates:
        c.evidence['status_reader_complete'] = True
        c.status_raw=c.normalized_status=None
        body = report.text[c.start:c.end]
        claims = []
        # Modern report exports put the outcome immediately after Source.
        intro = re.split(r'(?mi)^\s*(?:#{1,6}\s*)?(?:Found by|Summary|Vulnerability Detail|Issue Detail)\b', body, maxsplit=1)[0]
        for m in re.finditer(r'\bIssue\s+[CHMLIG]-\d+\s*\((Invalid)\)',intro,re.I):
            claims.append((m,0,'sherlock_issue_annotation'))
        for m in re.finditer(r'(?i)\bThis issue (?:has been|was|is)\s+('+STATE+r')\b', intro):
            claims.append((m, 0, 'sherlock_published_outcome'))
        for m in re.finditer(r'(?mi)^[ \t]*(?:\*\*)?Status(?:\*\*)?\s*:\s*('+STATE+r')\b',body):
            claims.append((m, 0, 'sherlock_status_field'))
        # Legacy reports attribute fix assertions to team/Watson sections.
        for section in re.finditer(r'(?mi)^[ \t]*(?:#{1,6}\s+)?(?:Lead Senior Watson|Lead Senior|Sherlock|[A-Za-z0-9 ._-]{1,70} Team)\s*:?\s*\n',body):
            tail = body[section.end():]
            stop = re.search(r'(?m)^#{1,6}\s+',tail)
            response = tail[:stop.start() if stop else len(tail)]
            m = re.search(r'^\s*('+STATE+r')\b',response,re.I)
            if m: claims.append((m, section.end(), 'sherlock_attributed_fix_response'))
            else:
                m = re.search(r'\b(?:This issue|The issue|It)\s+(?:has been|was|is)\s+('+STATE+r')\b',response,re.I)
                if m: claims.append((m, section.end(), 'sherlock_attributed_fix_response'))
        # Judging exports represent each discussion author as a bold line.
        # Only an assertion at the beginning of that author's reply counts;
        # escalation decisions and recommendations are not fix verdicts.
        for author in re.finditer(r'(?m)^[ \t]*\*\*[^*\n]{1,90}\*\*[ \t]*\n',body):
            tail=body[author.end():]
            m=re.match(r'\s*('+STATE+r')\b',tail,re.I)
            if not m:
                m=re.match(r'\s*(?:The protocol team|The team)\s+(?:has\s+)?(fixed|resolved|acknowledged|partially fixed)\s+(?:this|the) issue\b',tail,re.I)
            if m and eligible(c.start+author.end()+m.start(1)):
                claims.append((m,author.end(),'sherlock_discussion_author_verdict'))
        if claims:
            claims=[x for x in claims if eligible(c.start+x[1]+x[0].start(1))]
        if claims:
            m, offset, basis = max(claims,key=lambda x:x[0].start(1)+x[1])
            set_status_claim(report,c,m,c.start+offset,basis)


from variants import Variant, Fingerprint
VARIANTS = (
    Variant('sherlock/v2024_published_outcomes', Fingerprint((('published_outcome',r'This issue has been (?:fixed|acknowledged)',9),)),parse,('sherlock_outcome',),read_status),
    Variant('sherlock/v2022_team_responses', Fingerprint((('watson_response',r'^\s*(?:#{1,6}\s*)?Lead Senior Watson',8),)),parse,('sherlock_team',),read_status),
    Variant('sherlock/legacy',Fingerprint(legacy=True),parse,('legacy_contract',),read_status),
)
