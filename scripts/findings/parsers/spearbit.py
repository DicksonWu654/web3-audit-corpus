"""Spearbit/Cantina Managed numbered detailed review findings, 2021 onward.

Severity is the complete printed label (including Risk), mapped explicitly rather
than inferred from the issue's prose. Gas and informational remain separate. The
2021 mixed Gas/Informational section has no lossless article-v1 bucket; its
individual explicit labels are retained. Responses are attributed in the body;
only explicit status words on Spearbit/Cantina Managed response lines set status.
TOCs and numbered narrative sections without a Severity field are excluded.
The 2023 cryptography review uses unnumbered paragraph titles with parenthetical
Minor/Informational/Inconsistency/Optimization labels. Computational Optimization
is retained as unknown rather than assumed to mean EVM gas savings.
"""
from core import severity, Candidate, clean
import re
from collections import Counter, defaultdict

DESCRIPTION = "Three-component numbered detail headers with full explicit severity labels and wrapped titles; excludes TOCs, narrative subsections and appendices"
REVIEWED_SHA256 = (
    "8cef506637589c445fe320ad94d320375dc6fa1735756cee86645e81e0fd51eb",
    "1f11486466d58ca89f756964798e49b09beadf6136b6ad3764ba8dda8cd5c6ad",
    "03180b22251ef4d21e91835acc094e775e26c70548ec39b7de3c5fc9568e056f",
    "68355c87e03347b2c170d53a2d16fcd1ca7dbe7abbfdc0cc7c9f2ae2bff8b04b",
    "1c1dc324fac9d348ceed4abd42314c1a976b10ff47f80ffced7eac0ac64edf5b",
    "ac55c2e07f12aca359858f4059d9f4a60a11d9744ef89b4f11ad1d97476025fe",
    "b8fb732fa227c6f2c7b69e19024d7c83250cfda414e71ea1bee1d733604c72ee",
    "655203af78f53366b886e22c440d340d541d4b00f8db2ab2cf051ab69cb26ef0",
    "20fa0bf1471986884ce435add052e39fb1f29484cc884fc4e20fdbdd26701f33",
    "6b6f9a640a8a282f23ecdc4e0250ce6179e233ff68dceb7f4be0766cbce0330e",
    "de3bbed6ca87afbccecfa2a6b2f0360ec1cba23add53734af51f6b53a15cdc2f",
    "85b7f7c2b35f9582e4cecce673c8a4fa281a3bafa8ca01401b0768e4aaf3fb9b",
    "e005f94bd750e067fcc589255f6147b6afad7ffb93b9598daae70aba14f1c045",
    "bee0d71fe212e4505f3c4b5b38cf559f9819c39c7fd20a5f5ab3d6a8a4553978",
    "247e6fb232d9909b44b134953bde00c53ef9128cf3b285a9bdf9dab5b4fcdf19",
    "be1641d996f2ad0557ac98c90fdd0c96becb7e2049d91ca2d3cf94a7ac08d9d0",
)
# Documentary exceptions only: these do not alter parsing or comparability.
RESIDUAL_EXAMPLES = {
    "03180b22251ef4d21e91835acc094e775e26c70548ec39b7de3c5fc9568e056f": "Art Gobblers: numeric totals say gas 4 / informational 16, but numbered detail sections contain gas 3 / informational 17.",
    "194b15386c3a29256be8675c48d109f8588a138d2954ce20c978e8c4b0fe5618": "Beets Looped Sonic: summary prints one informational issue but the published detail has no informational finding section or entry.",
    "49f262deefa18c473047c3437d24bb63d822687f0beefc17dd71f79a9ecfcc02": "Biconomy: explicit detail Severity fields contradict their enclosing severity sections, producing medium 13 / informational 27 rather than printed 12 / 28.",
    "1c1dc324fac9d348ceed4abd42314c1a976b10ff47f80ffced7eac0ac64edf5b": "Connext: informational-section finding 5.6.9 explicitly says Low Risk; preserve the explicit field despite summary disagreement.",
    "ac55c2e07f12aca359858f4059d9f4a60a11d9744ef89b4f11ad1d97476025fe": "LI.FI: an explicit Low Risk field occurs in the Medium Risk section; preserve it instead of relabelling to the summary.",
    "c7dca1bb25756556a3f37565bd4ab247a21b965d98861545f40964be2d0ff539": "Seadrop: numeric totals say gas 10 / informational 22; explicit fields classify gas 9 / informational 23.",
    "c2ceceeec3f1dec9bf0b3bedc2fd734acaf7b54cd312daf46a10271f843ad8ee": "Sense: twenty numbered Low Risk detailed entries versus nineteen in the summary.",
    "2d83631ffc65338ffb9ecad216b876c52f590bacc782d7845ef8becc2e9a0369": "Tradable: 5.1.4 explicitly says Critical Risk despite placement in High Risk; the summary prints no critical issue.",
    "e6aa3829bff14266870f0e88cec8e252a985410604977679eb56045c5caeb377": "Aragon July 2025: separate initial/second-review numeric tables; retained as ambiguous rather than selecting a convenient total.",
    "66dceed84c7d9a012d1c799d8b1d737b649786741ade4dd47c1a38c7a2cd6fe2": "Upgrade Proposal 15a: two informational validation assessments, retained as observations; no numeric totals or finding-ID sequence.",
    "be1641d996f2ad0557ac98c90fdd0c96becb7e2049d91ca2d3cf94a7ac08d9d0": "Cryptography review: unnumbered parenthetical-label findings, without numeric totals or finding IDs; Inconsistency/Optimization retain unknown article severity.",
}
_TITLE = re.compile(r"^(\d+\.\d+\.\d+)\.?(?:\s+(.+))?$")
_LABEL = re.compile(r"^\s*Severity\s*:\s*(.+)", re.I)
_PARENT = re.compile(r"^(\d+\.\d+)\s+((?:Critical|High|Medium|Low) Risk|Gas Optimizations?|Informational)\s*$", re.I)


def _normalized(raw):
    return severity(raw, 'spearbit')


def parse(report, family=None):
    out, parents, appendix_observations = [], {}, False
    for i, line in enumerate(report.lines):
        if re.fullmatch(r"\d+\s+Appendix", line.content, re.I):
            appendix_observations = bool(re.search(r"yet to be scrutinized|not (?:been )?reviewed", report.near(i, 7), re.I))
        parent = _PARENT.match(line.content)
        if parent and not re.search(r"(?:\.\s*){4,}", line.text):
            parents[parent[1]] = parent[2]
        assessment = re.match(r"^(\d+\.\d+)\s+(Upgrade Proposal #.+)", line.content)
        if assessment and not line.excluded:
            title = [assessment[2]]
            for following in report.lines[i + 1:i + 6]:
                found = _LABEL.match(following.text)
                if found:
                    raw = found[1]
                    out.append(Candidate(line.start, clean(" ".join(title)), raw, assessment[1],
                                         normalized=severity(raw, report.firm), record_kind="observation", finding_phase="other",
                                         method="upgrade-validation-assessment", confidence=.96,
                                         evidence={"severity_basis": "explicit_field", "layout": "upgrade_validation"}))
                    break
                if following.content:
                    title.append(following.content)
        match = _TITLE.match(line.content)
        if not match or line.code or re.search(r"(?:\.\s*){4,}", line.text):
            continue
        title = [match[2]] if match[2] else []
        label = None
        detail = False
        for following in report.lines[i + 1:i + 9]:
            if following.page != line.page or _TITLE.match(following.content):
                break
            found = _LABEL.match(following.text)
            if found:
                label = found[1]
                # Metadata occasionally shares one line in older reports.
                label = re.split(r"\s+(?:Context|Description):", label)[0]
                break
            if re.match(r"(?:Context|Description):", following.content):
                detail = True
                break
            if following.content:
                title.append(following.content)
        basis = "explicit_field"
        if label is None and detail:
            label = parents.get(match[1].rsplit(".", 1)[0])
            basis = "severity_section"
        redacted = bool(match[2] and match[2].strip() == "REDACTED")
        if redacted:
            title = [match[2]]
        if label is None and redacted:
            label = parents.get(match[1].rsplit(".", 1)[0])
            basis = "severity_section_redacted_finding"
        if label is None and not (detail and appendix_observations):
            continue
        # A draft-watermark layout positions the title between Severity and
        # Context rather than next to the number. Read it from this card only.
        if not title:
            for following in report.lines[i + 1:i + 12]:
                value = following.content
                if value.startswith("Description:"):
                    break
                if not value or _LABEL.match(value) or value.startswith("Context:") or value in {"D", "RA", "FT", "DRAFT"}:
                    continue
                title.append(value)
        if not title:
            continue
        out.append(Candidate(line.start, clean(" ".join(title)), label, match[1],
                             normalized=severity(label, report.firm), method="numbered-explicit-severity",
                             record_kind="observation" if appendix_observations else "formal_finding",
                             finding_phase="other" if appendix_observations else None,
                             confidence=.97, evidence={"severity_basis": basis, "section": match[1],
                                                       "appendix_observation": appendix_observations}))
    if family != 'numbered' and "Protocol Documentation / White Paper Review" in report.text:
        out.extend(_cryptography_narrative(report))
        out.sort(key=lambda c: c.start)
    for index, c in enumerate(out):
        end = out[index + 1].start if index + 1 < len(out) else len(report.text)
        body = report.text[c.start:end]
        # The next risk parent belongs to the next finding, and narrative
        # appendices/scope pages never belong to the final issue.
        stop = re.search(r"(?im)^\s*\d+(?:\.\d+)?\s+(?:Appendix\b|Disclaimers?\b|A note on\b|(?:Critical|High|Medium|Low) Risk\s*$|Gas Optimizations?\s*$|Informational\s*$)", body)
        if stop and stop.start() > 0:
            end = c.start + stop.start()
            body = report.text[c.start:end]
        c.end = end
        responses = list(re.finditer(r"(?im)^\s*(?:Spearbit|Cantina Managed):\s*(Acknowledged|Resolved|Fixed|Verified|Confirmed|Not fixed)\b", body))
        if responses:
            c.status_raw = responses[-1][1]
    return out


def _cryptography_narrative(report):
    label = r"(?:Informational|Informa-\s*\ntional|Minor|Inconsistency|Inconsis-\s*\ntency|Optimization)"
    pattern = re.compile(r"^([A-Z][^\n]*(?:\n[^\n]+?){0,2}?)\s*\((" + label + r")\)")
    out = []
    for i, line in enumerate(report.lines):
        if line.excluded or line.code or not re.match(r"^[A-Z]", line.text):
            continue
        # Narrative issue titles start a paragraph or follow a numbered review
        # subsection. Prose mentioning a classification mid-paragraph is not one.
        if i and report.lines[i - 1].content and not re.match(r"\d+\.\d+\.\d+\s", report.lines[i - 1].content):
            continue
        m = pattern.match(report.text[line.start:line.start + 500])
        if not m or len(m[1]) > 300:
            continue
        raw = m[2]
        out.append(Candidate(line.start, clean(m[1]), raw,
                             normalized=severity(raw, report.firm), method="cryptography-parenthetical-label",
                             confidence=.94, evidence={"severity_basis": "explicit_parenthetical_label", "layout": "cryptography_narrative"}))
    return out


def sequence_diagnostics(report, candidates):
    groups = defaultdict(list)
    for c in candidates:
        if c.printed_id and re.fullmatch(r"\d+\.\d+\.\d+", c.printed_id):
            parent, last = c.printed_id.rsplit(".", 1)
            groups[parent].append(int(last))
    if not groups:
        return {"complete": None, "reason": "Unnumbered narrative findings or upgrade-validation assessments without finding IDs", "gaps": [], "duplicates": []}
    gaps, duplicates = [], []
    for group, values in groups.items():
        gaps.extend(f"{group}.{n}" for n in range(1, max(values) + 1) if n not in values)
        duplicates.extend(f"{group}.{n}" for n, count in Counter(values).items() if count > 1)
    return {"complete": not gaps and not duplicates, "gaps": gaps, "duplicates": duplicates}


def printed_counts(report):
    # Native executive-summary vertical tables include plural Gas Optimizations,
    # which the broad framework reader cannot safely recognize for all firms.
    # First column is total; later columns describe remediation, not extra rows.
    pattern = re.compile(r"^((?:Critical|High|Medium|Low) Risk|Informational|Gas Optimizations?)\s+(\d+)(?:\s+\d+)*\s*$", re.I)
    groups, current, proof, last = [], {}, [], -100
    for i, line in enumerate(report.lines):
        m = pattern.fullmatch(line.content)
        if not m:
            continue
        bucket = _normalized(m[1])
        if i - last > 12 or bucket in current:
            if len(current) >= 2:
                groups.append((current, proof))
            current, proof = {}, []
        current[bucket] = int(m[2])
        proof.append({"page": line.page, "start": line.start, "end": line.end, "text": line.text})
        last = i
    if len(current) >= 2:
        groups.append((current, proof))
    if not groups:
        return None
    groups.sort(key=lambda g: (-len(g[0]), g[1][0]["start"]))
    counts, evidence = groups[0]
    alternatives = [{"counts": c, "evidence": p} for c, p in groups[1:] if set(c) == set(counts) and c != counts]
    result = {"counts": counts, "evidence": evidence, "basis": "spearbit_printed_numeric_total_columns"}
    if alternatives:
        result.update(ambiguous=True, alternatives=alternatives)
    return result


from variants import Variant, Fingerprint
from parsers.group2_layouts import statuses

def parse_numbered(report):return parse(report,'numbered')
def parse_crypto(report):return _cryptography_narrative(report)
def parse_upgrade(report):return [c for c in parse(report,'numbered') if c.record_kind=='observation']
def parse_inherited(report):return [c for c in parse(report,'numbered') if c.evidence.get('severity_basis','').startswith('severity_section')]
def parse_clean(report):return []
def status_numbered(report,candidates):statuses(report,candidates,responses=True,headings=True,index_id=r'\b\d+\.\d+\.\d+\b')
def status_crypto(report,candidates):statuses(report,candidates,responses=True,headings=True)
def status_upgrade(report,candidates):statuses(report,candidates,responses=True,headings=True)
def status_inherited(report,candidates):statuses(report,candidates,responses=True,headings=True,index_id=r'\b\d+\.\d+\.\d+\b')
def status_clean(report,candidates):return None

VARIANTS=(
    Variant('spearbit/v2023_cryptography',Fingerprint((('whitepaper review',r'Protocol Documentation\s*/\s*White Paper Review',8),),('2023','2023')),parse_crypto,('spearbit_crypto',),status_crypto,printed_counts,notes='Unnumbered cryptography review paragraph titles with parenthetical Minor/Informational/Inconsistency/Optimization; no inferred severity or remediation.'),
    Variant('spearbit/v2025_upgrade_assessment',Fingerprint((('upgrade title',r'^\s*\d+\.\d+\s+Upgrade Proposal #',8),),('2025','2026')),parse_upgrade,('spearbit_upgrade',),status_upgrade,printed_counts,notes='Numbered upgrade validation assessments remain observations; publisher resolution responses only.'),
    Variant('spearbit/v2021_numbered',Fingerprint((('numbered detail',r'^\s*\d+\.\d+\.\d+\.?\s+\S',4),('severity field',r'^\s*Severity\s*:',3)),('2021','2026')),parse_numbered,('spearbit_numbered',),status_numbered,printed_counts,notes='Three-component finding IDs and explicit severity fields; includes old mixed gas/info section and later Cantina Managed responses. Fix verified/Verified are publisher fix assertions.'),
    Variant('spearbit/v2023_section_severity',Fingerprint((('numbered detail',r'^\s*\d+\.\d+\.\d+\.?\s+\S',4),('context field',r'^\s*Context:',2)),('2023','2024')),parse_inherited,('spearbit_inherited',),status_inherited,printed_counts,notes='Numbered cryptography findings omit Severity and inherit a printed risk parent; summary totals never supply a missing label.'),
    Variant('spearbit/v2023_clean_review',Fingerprint((('review result',r'^\s*\d+\s+Review result',4),('clean assertion',r"we don.t see any security issues",3)),('2023','2025')),parse_clean,('spearbit_clean',),status_clean,printed_counts,notes='PR review with explicit clean Review result and zero aggregate totals; narrative observations do not create graded findings.'),
)
