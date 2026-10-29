"""Macro's HTML audit cards, from the 2022 reports through the 2026 layout.

The page repeats every issue in the navigation; only cards after Issue Details
are findings. Q is Code Quality (article informational), I is Informational,
and G is Gas Optimization. Impact and likelihood are not overall severity.
"""
from __future__ import annotations

from core import severity, Candidate, clean
import re
from collections import Counter, defaultdict


DESCRIPTION = "Macro Issue Details cards; C/H/M/L/Q/I/G IDs, native status and independent Overall Assessment totals"
REVIEWED_SHA256 = (
    "39094fa77158ab0cf79458f4b576c33f41e99be2c1effae3c50a116c729d864a",
    "83a4916275652119bfe056fc6e288e74eefa01f895b6fc830c2c115b9c17dbd6",
    "4718145ad4135d0605a74e8630844563816e39c9a9ad0ada65dae9b83db32ed6",
    "88e877764dd380431fcd0f6de0dcf64ca1cd635acfca4de1c83b1eb7fc1c2301",
    "b918dfe26620729c1d517ec853dee9c420e9d0a584f47fd74a0f7fb97b140ef0",
    "533ee69badf261b478c582d2a123d4273a623598aa8337119f848274ed4c699a",
    "2906ffdc186bc058914451ca70fae628363713c021446bb7ca40b977380827a0",
    "5a9019843abbf126f8d394db63414c8ce990384f2be9e7d38d5d74ab1dcde223",
    "83c33b055bcf5724f643b906f44e6360eecd2960906f43cb3ea5abcd3df9fcf1",
    "3c419e9f1a23427a11adf7c012dfb0fcb7e6d00165e911da4e0d9bfd76d18920",
    "6f24308883c07e27fee4805b96abbc6c351acb837ff50b1953669afe269925f1",
    "1954c32fe7327fb1e5e1bc45e51d0b8ec721eaeab3607c732ea8241104cebdea",
    "5670c81432f285d1fce17851d814017185127ee202795ccab81b49b4c5be1110",
    "c17c28c864582fb4989921257b75e45c8ba0819158656d0f256b557593d3f257",
    "67bf9c30e1968e6ec860c88c72faa6becaee25422829795925f393f1e848aa24",
    "3530915497ce6d9eeefda8fccb12f9cea47f89873a9a021004c2702ecc64a2be",
    "74bc8cbaf19d71355c8c8f22fac32d980a189426abd1786f70f739a73c1d62c0",
    "b2603c97fd49ef1343325c40b6f5f0406493a235045a7f58167dd648c72d9191",
)

NATIVE = {"C": "Critical", "H": "High", "M": "Medium", "L": "Low",
          "Q": "Code Quality", "I": "Informational", "G": "Gas Optimization"}


def _tokens(report, start=0, end=None):
    return [(i, clean(line.content).strip(" |")) for i, line in enumerate(report.lines)
            if line.start >= start and (end is None or line.start < end)
            and clean(line.content).strip(" |")]


def parse(report):
    lines = report.lines
    sections = [line for line in lines if line.heading == 2 and clean(line.content) == "Issue Details"]
    if not sections:
        return []  # Zero-issue reports omit the whole details section.
    start = sections[-1].end
    end = next((line.start for line in lines if line.start > start and line.heading <= 2
                and re.fullmatch(r"(?:Disclaimer|Security Levels? Reference|Appendix.*)", clean(line.content), re.I)), len(report.text))
    tokens = _tokens(report, start, end)
    out = []
    for j, (i, value) in enumerate(tokens):
        m = re.fullmatch(r"([CHMLQIG])-(\d+)", value)
        if not m or j + 2 >= len(tokens):
            continue
        # The extractor emits a blank `##` line followed by the card title.
        # Also accept an inline H2 title for already-normalized HTML fixtures.
        next_i, next_text = tokens[j + 1]
        if next_text == "##":
            title_i, title = tokens[j + 2]
        elif lines[next_i].heading == 2:
            title_i, title = next_i, next_text
        else:
            continue
        following = tokens[j + 2:j + 19]
        status_raw = None
        for k, (_, field) in enumerate(following[:-1]):
            if field == "Status":
                value_after = following[k + 1][1]
                if value_after not in {"Impact", "Quality Impact", "Likelihood", "Topic"}:
                    status_raw = value_after
                break
        raw = NATIVE[m[1]]
        out.append(Candidate(lines[i].start, title, m[1], value, severity(m[1], report.firm),
                             status_raw=status_raw, method="macro-detail-card", confidence=.98,
                             normalized_status={"addressed": "resolved", "partially addressed": "partial"}.get((status_raw or "").lower()),
                             evidence={"severity_basis": "printed_id_prefix", "label_is_code": True,
                                       "native_class": raw, "title_start": lines[title_i].start}))
    for j, candidate in enumerate(out):
        candidate.end = out[j + 1].start if j + 1 < len(out) else end
    return out


def printed_counts(report):
    """Read the independent Count column, not the status columns or issue IDs."""
    sections = [line for line in report.lines if line.heading == 2 and clean(line.content) == "Overall Assessment"]
    if not sections:
        return None
    start = sections[-1].end
    end = next((line.start for line in report.lines if line.start > start and line.heading == 2), len(report.text))
    tokens = _tokens(report, start, end)
    buckets = {raw.lower(): severity(raw, report.firm) for raw in NATIVE.values()}
    counts, evidence = Counter(), []
    for j, (i, value) in enumerate(tokens[:-1]):
        bucket = buckets.get(value.lower())
        next_i, number = tokens[j + 1]
        if bucket is None or not re.fullmatch(r"\d+", number):
            continue
        counts[bucket] += int(number)
        evidence.append({"start": report.lines[i].start, "end": report.lines[next_i].end,
                         "page": report.lines[i].page,
                         "text": report.text[report.lines[i].start:report.lines[next_i].end]})
    if len(counts) < 2:
        return None
    return {"counts": dict(counts), "basis": "macro_overall_assessment_count_column", "evidence": evidence}


def sequence_diagnostics(report, candidates):
    groups = defaultdict(list)
    for candidate in candidates:
        m = re.fullmatch(r"([CHMLQIG])-(\d+)", candidate.printed_id or "")
        if m:
            groups[m[1]].append(int(m[2]))
    if not groups:
        return {"complete": None, "reason": "no_printed_detail_ids", "gaps": [], "duplicates": []}
    gaps, duplicates = [], []
    for prefix, numbers in sorted(groups.items()):
        gaps.extend(f"{prefix}-{number}" for number in sorted(set(range(1, max(numbers) + 1)) - set(numbers)))
        duplicates.extend(f"{prefix}-{number}" for number, n in Counter(numbers).items() if n > 1)
    return {"complete": not gaps and not duplicates, "reason": "per_native_severity_prefix",
            "gaps": gaps, "duplicates": duplicates}


from variants import Variant, Fingerprint
from parsers.group3_status import FIELD, fields, apply, claim


def parse_html_fragments(report):
    # Cards use ID / blank H2 / title fragments after the repeated navigation.
    return parse(report)


def parse_trust_model(report):
    # The expanded 2025 template adds accepted-risk observations before cards.
    # Those sections do not change risk counts or become additional findings.
    return parse(report)


def parse_printed_html(report):
    out=[];active=False
    for i,line in enumerate(report.lines):
        if re.fullmatch(r'Issue Details',line.content):active=True;continue
        if not active or line.code:continue
        m=re.match(r'^([CHMLQIG]-\d+)\s+(.+)',line.content)
        if not m:continue
        title=[m[2]]
        for nxt in report.lines[i+1:i+7]:
            if not nxt.content:break
            if re.match(r'TOPIC\b|STATUS\b',nxt.content):break
            title.append(nxt.content)
        out.append(Candidate(line.start,clean(' '.join(title)),m[1][0],m[1],method='macro-printed-html-card',confidence=.98,
                             evidence={'severity_basis':'printed_id_prefix'}))
    for i,c in enumerate(out):c.end=out[i+1].start if i+1<len(out) else len(report.text)
    return out


def status_printed_html(report,candidates):
    for c in candidates:
        claims=[];col=None
        for line in report.lines:
            if not c.start<=line.start<c.end:continue
            header=re.search(r'\bSTATUS\b',line.text)
            if header:col=header.start()
            elif col is not None and line.content:
                m=re.search(r'\b(Fixed|Acknowledged|Partially Addressed|Addressed|Won[’\x27]t Do)\b',line.text,re.I)
                if m and abs(m.start()-col)<15:claims.append(claim(report,m,line.start,'printed_html_status_column'))
                col=None
        apply(report,c,claims)


def counts_printed_html(report):
    active=False;counts=Counter();proof=[]
    start=max((l.start for l in report.lines if re.fullmatch(r'Overall Assessment',l.content)),default=len(report.text))
    for line in report.lines:
        if line.start<start:continue
        if re.fullmatch(r'Overall Assessment',line.content):active=True;continue
        if active and re.fullmatch(r'Specification',line.content):break
        m=re.match(r'^(Critical|High|Medium|Low|Code Quality|Informational|Gas Optimization)\s+(\d+)\b',line.content)
        if active and m:
            counts[severity(m[1],report.firm)]+=int(m[2]);proof.append({'start':line.start,'end':line.end,'text':line.text})
    return {'counts':dict(counts),'basis':'printed_html_assessment_count_column','evidence':proof} if len(counts)>1 else None


def status_html(report,candidates):
    for c in candidates:
        # HTML puts one exact value on its own line after the Status label.
        # Preserve unfamiliar dispositions as other instead of discarding them.
        body=report.text[c.start:c.end]
        matches=list(re.finditer(r'^[ \t]*Status[ \t]*\n(?:[ \t]*\n)*[ \t]*([^\n]+)',body,re.M))
        apply(report,c,[claim(report,m,c.start,'native_html_status_field') for m in matches])


def status_trust_model(report,candidates):
    status_html(report,candidates)


VARIANTS=(
    Variant('macro/v2024_printed_html',Fingerprint((('printed_assessment',r'^\s*Overall Assessment\s*$',4),('printed_cards',r'^\s*Issue Details\s*$',4),('status_columns',r'TOPIC\s+STATUS\s+IMPACT\s+LIKELIHOOD',2)),('2024','2026'),formats=('pdf',)),parse_printed_html,('macro_printed',),status_printed_html,counts_printed_html),
    Variant('macro/v2025_trust_model',Fingerprint((('trust_model',r'^## Trust Model, Assumptions, and Accepted Risks',8),('assessment',r'^## Overall Assessment\s*$',2)),('2025','2026')),parse_trust_model,('macro_trust_model',),status_trust_model,printed_counts),
    Variant('macro/v2022_html_cards',Fingerprint((('assessment',r'^## Overall Assessment\s*$',4),('native_issue_section',r'^## (?:Issue Details|Issue Descriptions and Recommendations)\s*$',4)),('2022','2026')),parse_html_fragments,('macro_html',),status_html,printed_counts),
)
