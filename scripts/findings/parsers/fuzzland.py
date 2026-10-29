"""Fuzzland's Notion/HTML reports: source risk headings and split inline-code titles.

2023/early-2024 reports have no aggregate table or finding IDs; later reports use
Number/Resolved severity tables. No ID sequence is invented for either layout.
"""
from __future__ import annotations

from core import SeverityLookup, severity, Candidate, clean
import re

DESCRIPTION = "Fuzzland bracketed risk headings; joined inline-code title fragments; native status fields and Number totals"
REVIEWED_SHA256 = (
    "0d3b84edad2c7cc35a48f897bb18984d3afcd58b5f28eb1d2adb1fc773e5d0ef",
    "19e5f2276cba194c96be85c9e130c417d5e8781c12e2841ce9d81cfbd1a48a1c",
    "1b44ef08cee4267eeb3916b6bebcc2e0d261cac1d7a51a237c84f98fbc717e49",
    "2f1b552dbc09c7865960b671f10f8a2aad6bb2345e03f20e0db63aece65f5e86",
    "3de19cf18f73b8857da2a5c5a6688666cd934621342036e7fb9f4be3dcafd3f6",
    "48bf00806f93d93e03f99f9e22d7300ba46fb9268fe5d68df6a708b51a7501d8",
    "5375a9c6b9fe2898d42a71daaaa415ceb227c77b9bd10ac0d3d349a4e58ccfad",
    "72637f951cdf371210fafe88b159f3d9e0377337a30f07314d27c3ae4213cfdd",
    "75a83eaee616eb8e11b8a8ffdd9966ce7dad635319b8bd1724562a29f506bdd8",
    "7ed052c1fe30dc46d4b88b1af932cf297160dac7fe34fc2d0b35906004a49b9f",
    "8643ca29571109d2ed24c73bef4f0e967de7ac976568990da5cf588feae5053e",
    "87948dda9d7181f4152bb5a597e9a632625beda013784e8a7de0164efc33f196",
    "8cc65ceb1dd96ebf90c7643bcb8778d8bc84551470c5d2f9faaaa7ec9cabc582",
    "8d051c2b6e28fbc71d9901420373f4fa99769cc05245608354c4ce1d4c357113",
    "8d677c8f8749440c23a44b6cb9df7c3a828d04c575e95995edd9b6fc9957ed5e",
    "8dc28f4f079cf9139c952f091579a34e17ab7603f66c8a14b93cb76e2cd97f14",
    "8e79d45f8764b63561327502f80c679bb3ee2a152c6f978b792ee14502e59fcf",
    "969a4c29d4702a7946febda6fbd6570677a867040f69a9665e87edbc9f55c7db",
    "a279edcedf6266af707427210dc11d121adab97754aa772cface9d00993eae4b",
    "af2af7c54d7053a311a314757153fd79dbb3afab8e70b0c46ec81c27c122f751",
    "b31e6d01ffaaa137197ee5f55ae994e6b92fccc977276a4817337572a51b1126",
    "c45fdbe28334f64cef25ea6ed723aad03f201f910163071aac37547b53ccc17e",
    "c7768d19f2fc4c1357fdc37891ebab1d8aaa0fbbceff915f7c5aca811436f359",
    "c93e4ee86f349c6b875b49d4e9ead190f7c5a1cffd7d388f30e3631806aa051c",
    "ca3e645251aef91ce7848fc53af51e14cb7447e8bbd7fe0b8d1bc341290c5324",
    "e4771e9a2d0b47c9b3be08378be2c6c3aaceffb9d113c669c563f800ebf16240",
    "ed2bd15c2ca1ad598cf4184334d88c0f1c2d4815d633f51e5644bc2dfcc7b2ac",
    "f411e19982098db7411465cb5f54b5a7929f9fb1dacc10b2c3fdc0fb45982109",
)

RISK = re.compile(r"^\[(Critical|High|Medium|Med|Low|Info|Informational)\]\s*(.*)", re.I)
STATUS = re.compile(r"\bStatus\s*[:：]?\s*(Partially Fixed|Acknowledged|Resolved|Unresolved|Fixed|Open|Pending)\b", re.I)


def parse(report):
    out = []
    for i, line in enumerate(report.lines):
        match = RISK.match(line.content) if line.heading and not line.code else None
        if not match:
            continue
        # HTML extraction emits inline code fragments on separate, consecutive
        # lines inside the same source heading. A blank line ends the heading.
        title = [match[2]]
        for following in report.lines[i + 1:]:
            if not following.content or following.heading:
                break
            title.append(following.content)
        end = next((l.start for l in report.lines[i + 1:]
                    if l.heading and l.heading <= line.heading), len(report.text))
        body = report.text[line.start:end]
        state = STATUS.search(body)
        status_raw = state[1] if state else None
        if status_raw is None:
            # Nubit cards use a horizontal metadata table (all five headers,
            # then all five values) rather than an adjacent Status: field.
            cells = [clean(s) for s in re.split(r"\n[ \t]*\|[ \t]*\n", body)]
            if cells[1:6] == ["Severity", "Category", "Code Location", "Status", "Fix Commit"] and len(cells) > 9:
                status_raw = cells[9] or None
        if status_raw is None:
            # Preserve an explicitly labelled publisher response even when it
            # is not part of the standard status vocabulary (e.g. IXO).
            native = re.search(r"(?:^|\n)Status\s*[:：]\s*([^\n]+)", body, re.I)
            status_raw = native[1].strip() if native else None
        raw = match[1]
        out.append(Candidate(line.start, clean(" ".join(title)), raw,
                             normalized=severity(raw, report.firm),
                             normalized_status="acknowledged" if (status_raw or "").lower() == "ack" else None,
                             end=end, status_raw=status_raw,
                             method="notion-risk-heading", confidence=.96,
                             evidence={"severity_basis": "explicit_heading_label",
                                       "id_scheme": "publisher_does_not_print_finding_ids"}))
    return out


def printed_counts(report):
    """Read only the numeric Number column, independently of finding headings."""
    table = re.search(r"(?:^|\n)Number\s*\n[\s|]*Resolved\s*\n", report.text)
    if not table:
        return None
    values, proof = {}, []
    for line in report.lines:
        if line.start < table.end():
            continue
        if line.heading:
            break
        m = re.fullmatch(r"(Critical|High|Medium|Low|Info|Informational) Severity Issues", line.content, re.I)
        if not m:
            continue
        # A cell can be separated by several blank and table-separator lines.
        following = re.match(r"[\s|]*(\d+)\b", report.text[line.end:])
        if not following:
            continue
        key = SeverityLookup(report.firm, ('informational',)).get(m[1].lower(), m[1].lower())
        values[key] = int(following[1])
        end = line.end + following.end()
        proof.append({"page": line.page, "start": line.start, "end": end,
                      "text": report.text[line.start:end]})
    if values:
        return {"counts": values, "basis": "publisher_number_resolved_aggregate_table", "evidence": proof}
    return None


def sequence_diagnostics(report, candidates):
    # Absence of IDs is not a successful sequence-completeness check.
    clean_audit = bool(re.search(r"^## Detailed Findings\s+N/A\s*$", report.text, re.M))
    return {"complete": None, "reason": "explicit_no_findings_na" if clean_audit else "publisher_has_no_printed_finding_ids",
            "gaps": [], "duplicates": []}


from variants import Variant, Fingerprint
VARIANTS = (
    Variant('fuzzland/v2024_number_resolved',
        Fingerprint((('aggregate table',r'^Number\s*\n[\s|]*Resolved\s*\n',8),)),
        parse,('fuzzland_table',),printed_counts=printed_counts),
    Variant('fuzzland/v2023_bracket_headings',
        Fingerprint((('graded heading',r'^#{1,6}\s+\[(?:Critical|High|Medium|Med|Low|Info|Informational)\]',8),)),
        parse,('fuzzland_brackets',),printed_counts=printed_counts),
    Variant('fuzzland/v2024_clean_na',
        Fingerprint((('explicit clean detail',r'^## Detailed Findings\s+N/A\s*$',8),)),
        parse,('fuzzland_clean',),printed_counts=printed_counts),
)
