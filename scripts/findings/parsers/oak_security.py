"""Oak detail cards, 2021–2026, including zero-width-spaced and phased reports.

The publisher's Major/Minor scale maps to high/low. Numeric IDs restart in
explicit phases. Summary finding indexes have no aggregate numeric totals;
they are not treated as printed counts. Appendices and the Dexter report's
historical findings for excluded contracts are outside the current findings.
Dusk's 2024 protocol review has 11 ungraded findings: severity stays unknown.
"""
import re
from core import Candidate, clean, is_toc, status
from variants import Fingerprint, Variant

DESCRIPTION = "Oak numeric detail cards, wrapped titles, phase-local IDs, explicit statuses and appendix bounds"
REVIEWED_SHA256 = (
    "bbc246f949033aab9521f4bcba3b142f45b74f660f782b90b0f493893a4d0b32",
    "50f5ed9a3fe064f847128b3c118be853ebe0236b03c3f9495263b06c9e710441",
    "5b75ee082693fc4fcb53580267721664f0ed00a7070d96e67ec6262fa984aa71",
    "80ca7d6ab39d179f1980837ab2087c427b0f1e9a670964a168b34da479ebc79f",
    "f06a0e5286f7b6e3318d95c81335af356894d4085ed3ec664319dc9bbab259ca",
    "4187c84054fe41a49df444824c72143f3ef2d3962f1e672cdfc233289e56c20e",
    "a2038dd13a0f56b2857ce8bd1f07fc152a3a6a8c7966efd726bd787fe998db64",
    "001e525c1c3a1e493e41e8ec6513f8ccc8cdf286cd8f307374ccea43d1f3229a",
    "b6b3176c16d297629e9e2930bbd44a7ff51c335f80188006e9cb67a7aa258d32",
    "d0b759cad1a3829e3643c9358ad1514605405ea141ebb53c830559053b841c8a",
    "3049b54487b86d04ce1e40db77d55aff4c1a8940db42219121e9d5219082cfc1",
    "06af4d1ebf18b8ec760b71727be54e885c6fdf4746651f779021cb4549288503",
    "e38678ce6930082cb7dfe861a2ee0f1b88dbf5ad96df06c33c93a607c9e2ef7c",
    "69f69e47a77a7f933f786a6eeb9356f25dd4f6e448da79a34ccefba548041d0c",
    "b84931dd9ed67cde1b46b0c6284614e0ccbe7269f892e134782ebd8df668d7d9",
    "af1a9702e07d501f50555cc622ddca51d8039c2ccab3e8842c797b06191605b5",
    "e900280ee75d8edc9021884813d3e6a687eacd36d72c3f88fb513d803dc0d583",
    "0cc1c6b812247a29b9d521144a7049083028d9a7d236e118226dfcc3cb724349",
    "b3ab5a3c02bb9731dc12af21c909ad52d11e2c5c3e72268ae04e81b08893d22b",
    "e97e71a99cb8a1f8ef26bfa56c7cc31ba6547aa13b04b80d149e5b4d1ecdba44",
)
REVIEW_NOTES = "2021 compact and 2022–24 standard cards; 2025–26 zero-width spaces; Escher phase restart; Dexter excluded past scope; Dock appendix dependency output; Dusk ungraded protocol review."


def parse(report):
    out, active, group, stops = [], False, "1", []
    ungraded = bool(re.match(r"Protocol Security Review", report.text))
    for i, line in enumerate(report.lines):
        text = clean(line.content)
        if is_toc(line):
            continue
        m = re.fullmatch(r"Detailed Findings(?: for (.+))?", text, re.I)
        if m:
            active = True
            group = m[1] or group
            continue
        if active and re.match(r"^(?:Appendix(?:\s+[A-Z0-9]+)?$|Past Findings for Contracts Excluded|Summary of Findings)", text, re.I):
            stops.append(line.start)
            active = False
            continue
        if not active:
            continue
        m = re.match(r"^(\d{1,3})[.)]\s*(.+)", text)
        if not m:
            continue
        title = [m[2]]
        raw = None
        # Severity immediately follows the (possibly wrapped) title, never a
        # later card after blank lines or prose/list items within a finding.
        for nxt in report.lines[i + 1:i + 9]:
            value = clean(nxt.content)
            sev = re.fullmatch(r"Severity:\s*(Critical|Major|Minor|Informational|Medium|High|Low)[,:]?", value, re.I)
            if sev:
                raw = sev[1]
                break
            if re.match(r"^\d{1,3}[.)]\s*", value):
                break
            if value:
                title.append(value)
        if raw is None:
            # The protocol review uses the same title typography but no grades.
            if not ungraded or not re.match(r"^ {3}\d+[.]", line.text):
                continue
            title = [m[2]]
            for nxt in report.lines[i + 1:i + 5]:
                if not clean(nxt.content) or not re.match(r"^\s{6,}\S", nxt.text):
                    break
                title.append(clean(nxt.content))
        out.append(Candidate(line.start, " ".join(title), raw, m[1], method="oak-detail-card", confidence=.96,
                             evidence={"severity_basis": "explicit_field" if raw else "absent_in_source",
                                       "sequence_group": group}))
    for i, candidate in enumerate(out):
        end = out[i + 1].start if i + 1 < len(out) else len(report.text)
        end = min([end] + [x for x in stops if candidate.start < x < end])
        candidate.end = end
        body = report.text[candidate.start:end]
        state = re.search(r"(?m)^Status:[ \t]*([^\n]+)", body)
        if state:
            candidate.status_raw = clean(state[1])
            if candidate.status_raw.casefold() == "partially":
                continuation = re.match(r"\s*(Resolved|Fixed)\b", body[state.end():], re.I)
                if continuation:
                    candidate.status_raw += " " + continuation[1]
            key = candidate.status_raw.lower()
            candidate.normalized_status = {"resolved": "resolved", "acknowledged": "acknowledged", "pending": "open", "reported": "open", "partially resolved": "partial", "partially fixed": "partial"}.get(key)
    return out


def printed_counts(report):
    # Oak prints an index of individual findings rather than numeric buckets.
    return None


def sequence_groups(report, candidates):
    # Some phases continue the previous phase's IDs; others restart from one.
    groups = []
    for candidate in candidates:
        if not groups or candidate.printed_id == "1":
            groups.append([])
        groups[-1].append(candidate.printed_id)
    return groups


OAK_STATE = r"(?:Partially[\s\u200b]+(?:Resolved|Fixed)|Externally[\s\u200b]+(?:Resolved|Reported)|Acknowledged|Resolved|Pending|Reported)"


def _status_value(raw):
    key = clean(raw).casefold()
    return {"externally resolved": "resolved", "externally reported": "open", "reported": "open"}.get(key) or status(clean(raw))


def _attach_status(report, candidates, allow_index=True):
    """Read labelled fields and same-phase publisher index rows, never prose."""
    index, active, group = {}, False, "1"
    if allow_index:
        for line in report.lines:
            heading = clean(line.content)
            match = re.fullmatch(r"Summary of Findings(?: for (.+))?", heading, re.I)
            if match:
                active, group = True, match[1] or "1"
                continue
            if re.fullmatch(r"Detailed Findings(?: for (.+))?", heading, re.I):
                active = False
            if not active:
                continue
            row = re.match(r"^[ \t]*(\d{1,3})[ \t]+.+\b(?:Critical|Major|Minor|Informational|Medium|High|Low)[ \t]+(" + OAK_STATE + r")[ \t\u200b]*$", line.text, re.I)
            if row:
                index.setdefault((group.casefold(), row[1]), []).append((row[2], line.start + row.start(2), line.start + row.end(2)))
    for candidate in candidates:
        candidate.status_raw = candidate.normalized_status = None
        body = report.text[candidate.start:candidate.end]
        fields = list(re.finditer(r"(?m)^[ \t]*Status:[ \t\u200b]*(" + OAK_STATE + r")(?!\w)", body, re.I))
        if fields:
            match = fields[-1]
            raw, start, end = match[1], candidate.start + match.start(1), candidate.start + match.end(1)
            basis = "labelled_status_field"
        else:
            key = (str(candidate.evidence.get("sequence_group", "1")).casefold(), candidate.printed_id)
            claims = index.get(key, [])
            if not claims:
                continue
            if len({_status_value(claim[0]) for claim in claims}) != 1:
                candidate.evidence["status_conflict"] = True
                continue
            raw, start, end = claims[-1]
            basis = "same_phase_printed_id_status_table"
        candidate.status_raw = raw
        candidate.normalized_status = _status_value(raw)
        candidate.evidence["status_evidence"] = {"raw": raw, "start": start, "end": end,
                                                  "text": report.text[start:end], "basis": basis,
                                                  "profile": "oak-security"}


def numbered_cards(report):
    return parse(report)


def phased_cards(report):
    rows = parse(report)
    # IDs restart in some phases. Retain the native phase namespace for the
    # framework's structural diagnostic and status-table matching.
    namespace, prior = 1, None
    for row in rows:
        if row.printed_id == "1" and prior is not None:
            namespace += 1
        row.evidence["container_id"] = "oak-review-round-" + str(namespace)
        row.method = "oak-phased-detail-card"
        prior = row.printed_id
    return rows


def protocol_review(report):
    rows = parse(report)
    for row in rows:
        row.method = "oak-ungraded-protocol-detail"
    return rows


def catalog_links(report):
    # The collector also retained technology landing pages. Linked report
    # titles are navigation, not published detail findings.
    return []


def numbered_status(report, candidates):
    _attach_status(report, candidates)


def phased_status(report, candidates):
    _attach_status(report, candidates)


def protocol_status(report, candidates):
    _attach_status(report, candidates, allow_index=False)


def catalog_status(report, candidates):
    _attach_status(report, candidates, allow_index=False)


VARIANTS = (
    Variant("oak-security/v2024_protocol_review", Fingerprint((
        ("protocol_cover", r"^Protocol Security Review$", 8),
        ("protocol_details", r"^\s*Detailed Findings$", 2),
    ), ("2024", "2024")), protocol_review, ("oak_protocol_review",), protocol_status, printed_counts,
            "Ungraded protocol review; missing grades and statuses remain absent."),
    Variant("oak-security/v2025_phased_cards", Fingerprint((
        ("phase_detail", r"^\s*Detailed Findings for (?:Phase|Stage|Round)\b", 10),
        ("native_grade", r"^\s*Severity:", 2),
    ), ("2025", "2026")), phased_cards, ("oak_phased_cards",), phased_status, printed_counts,
            "Explicit phased findings; phase-local status tables and restarted IDs."),
    Variant("oak-security/v2021_numbered_cards", Fingerprint((
        ("detail_section", r"^\s*Detailed Findings(?: for .+)?$", 5),
        ("native_grade", r"^\s*Severity:\s*(?:Critical|Major|Minor|Informational|Medium|High|Low)\b", 3),
    ), ("2021", "2026")), numbered_cards, ("oak_numbered_cards", "oak_wrapped_status", "oak_status_index"), numbered_status, printed_counts,
            "Stable numbered severity-field template, including later zero-width glyph extraction."),
    Variant("oak-security/v2022_catalog_links", Fingerprint((
        ("report_counter", r"^\*\*\d+ reports?\*\*$", 5),
        ("publisher_links", r"https://github\.com/oak-security/audit-reports/blob/", 3),
    ), ("2022", "2026"), formats=("md",)), catalog_links, ("oak_catalog_links",), catalog_status, printed_counts,
            "Technology catalog accidentally collected as a report; emits no findings."),
)
