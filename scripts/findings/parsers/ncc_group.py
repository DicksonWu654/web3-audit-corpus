"""NCC Group legacy Finding/Risk/Identifier and modern Overall Risk cards."""
import re
from core import Candidate, SEV, clean
from summary_counts import printed_counts
DESCRIPTION = "NCC legacy Finding cards and modern Overall Risk/Finding ID cards; full native IDs retained"


def parse(report, era=None):
    out = []
    for i, line in enumerate(report.lines):
        modern = re.search(r"\bOverall Risk\s+("+SEV+r")\b.*?Finding ID\s+(\S+)", line.content, re.I)
        legacy = re.match(r"^Finding\s+(.+)", line.content)
        if era == 'legacy':modern=None
        if era == 'modern':legacy=None
        if modern:
            # Title begins with risk in the left margin; wrapped continuations end at metadata.
            begin = None
            for j in range(i-1,max(-1,i-8),-1):
                if re.match(r"^(?:Critical|High|Medium|Low|Info(?:rmational)?)\s{2,}\S", report.lines[j].content, re.I):
                    begin = j
                    break
            if begin is None:
                continue
            title = re.sub(r"^(?:Critical|High|Medium|Low|Info(?:rmational)?)\s+", "", report.lines[begin].content, flags=re.I)
            title = clean(" ".join([title] + [l.content for l in report.lines[begin+1:i] if l.content]))
            raw, pid = modern[1], modern[2]
            start = report.lines[begin].start
        elif legacy and not re.match(r"^(?:Details|Summary|ID)\b", legacy[1]):
            near = report.near(i+1,13)
            risk = re.search(r"(?m)^\s*Risk\s+("+SEV+r")\b", near, re.I)
            identifier = re.search(r"\bIdentifier\s+(\S+)", near)
            if not risk or not identifier:
                continue
            firstmeta = next((j for j in range(i+1,min(i+8,len(report.lines))) if re.match(r"^(?:Risk|Identifier)\b",report.lines[j].content)),i+1)
            title = clean(" ".join([legacy[1]]+[l.content for l in report.lines[i+1:firstmeta] if l.content]))
            raw, pid, start = risk[1], identifier[1], line.start
        else:
            continue
        near = report.near(i,16)
        stat = re.search(r"\bStatus\s+(Partially Fixed|Risk Accepted|Not Fixed|Fixed|New|Open|Acknowledged|Resolved|Not Retested)\b", near, re.I)
        out.append(Candidate(start,title,raw,pid,status_raw=stat[1] if stat else None,
                             method="ncc-overall-risk" if modern else "ncc-legacy-card", confidence=.97,
                             evidence={"severity_basis":"explicit_overall_risk", "parser_revision":"phase4b-group4-v1"}))
    if out:
        for l in report.lines:
            if l.start > out[-1].start and re.match(r"^(?:\d+\s+|[A-Z]\s+)?(?:Appendix|Risk Rating|Risk Ratings|Risk Methodology|Finding Field|Technical Review|Conclusions?)(?:\b|:)", l.content,re.I):
                out[-1].end=l.start
                break
    return out


from variants import Variant, Fingerprint
from parsers.group3_status import FIELD, STATE, fields


def parse_finding_risk(report):
    return parse(report,'legacy')


def parse_vulnerability_risk(report):
    out=[]
    for i,line in enumerate(report.lines):
        m=re.match(r'^Vulnerability\s+(?!Details\b)(.+)',line.content)
        if not m:continue
        near=report.near(i+1,12)
        grade=re.search(r'^\s*Risk\s+('+SEV+r')\b',near,re.I|re.M)
        pid=re.search(r'\bIdenti(?:fi|ﬁ)er\s+(NCC-\S+)',near)
        if not grade or not pid:continue
        title=[m[1]]
        for nxt in report.lines[i+1:i+7]:
            if re.match(r'^(?:Risk|Identi)',nxt.content):break
            if nxt.content:title.append(nxt.content)
        out.append(Candidate(line.start,clean(' '.join(title)),grade[1],pid[1],
            method='ncc-vulnerability-risk-card',confidence=.98,evidence={'severity_basis':'explicit_risk_field'}))
    for i,c in enumerate(out):
        c.end=out[i+1].start if i+1<len(out) else len(report.text)
    return out


def parse_primitives_review(report):
    return []


def parse_overall_risk(report):
    return parse(report,'modern')


def parse_narrative_review(report):
    # This cryptographic specification review publishes comments by file and
    # a retest narrative, rather than individually graded finding cards.
    return []


def status_finding_risk(report,candidates):
    status_overall_risk(report,candidates)


def status_overall_risk(report,candidates):
    fields(report,candidates,(FIELD,
        ('ncc_parallel_status_cell',r'\bExploitability\b[^\n]*?[ \t]{2,}Status[ \t]+('+STATE+r')\b'),
        ('ncc_dated_retest_verdict',r'\bRetest Results[ \t]*\n(?:[ \t]*\n)*[ \t]*\d{4}-\d{2}-\d{2}[ \t]*[–—-][ \t]*('+STATE+r')\b')),
        preserve=False)


def status_narrative_review(report,candidates):
    fields(report,candidates,(),preserve=False)


def counts_finding_risk(report):
    from collections import Counter
    from core import severity
    result=printed_counts(report)
    if not result:return None
    tally=Counter();invalid=Counter();proof=[];active=False
    for line in report.lines:
        if re.fullmatch(r'Table of Findings',line.content):active=True;continue
        if active and re.fullmatch(r'Finding Details',line.content):break
        if not active:continue
        row=re.search(r'\s{2,}(False Positive|Partially Fixed|Risk Accepted|Fixed|Reported)\s+(\d{3})\s+('+SEV+r')\s*$',line.text,re.I)
        if row:
            key=severity(row[3],report.firm);tally[key]+=1
            if row[1].casefold()=='false positive':invalid[key]+=1
            proof.append({'start':line.start,'end':line.end,'text':line.text})
    # The full source index includes the invalidated cards while this dashboard
    # excludes them. Preserve both source populations rather than changing rows
    # to force the dashboard's restricted scope onto the complete report stream.
    if invalid and all(tally[k]-invalid[k]==v for k,v in result['counts'].items()):
        result=result|{'ambiguous':True,'ambiguity_reason':'Original Assessment dashboard excludes False Positive cards retained in the complete source index.',
                       'source_index_counts':dict(tally),'source_false_positive_counts':dict(invalid),'source_index_evidence':proof}
    return result


VARIANTS=(
    Variant('ncc-group/v2016_vulnerability_risk',Fingerprint((('vulnerability_title',r'^\s*Vulnerability\s+(?!Details\b)\S',4),('native_identifier',r'Identi(?:fi|ﬁ)er\s+NCC-',4)),('2016','2019')),parse_vulnerability_risk,('ncc_vulnerability',),status_finding_risk,printed_counts),
    Variant('ncc-group/v2020_primitives_review',Fingerprint((('primitives_title',r'AES/GCM and ChaCha20\+Poly1305',7),('ghash',r'^\s*GHASH\s*$',2)),('2020','2020')),parse_primitives_review,('ncc_primitives',),status_narrative_review,printed_counts),
    Variant('ncc-group/v2022_overall_risk',Fingerprint((('overall_risk_id',r'\bOverall Risk\s+(?:'+SEV+r')\b[^\n]*\bFinding ID\b',9),),('2022','2026')),parse_overall_risk,('ncc_modern',),status_overall_risk,printed_counts),
    Variant('ncc-group/v2020_finding_risk',Fingerprint((('finding_title',r'^\s*Finding\s+(?!Details|Summary|ID)\S',3),('risk_identifier',r'^\s*Identifier\s+NCC-',5)),('2020','2022')),parse_finding_risk,('ncc_legacy',),status_finding_risk,counts_finding_risk),
    Variant('ncc-group/v2022_narrative_review',Fingerprint((('spec_review',r'Decaf377 Specification and\s*\n\s*Implementation Review',6),('documentation_review',r'^\s*Documentation Review\s*$',3)),('2022','2022')),parse_narrative_review,('ncc_narrative',),status_narrative_review,printed_counts),
)
