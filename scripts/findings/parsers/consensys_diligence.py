"""Diligence Markdown (2018), website and PDF Findings/Issues sections.

Only detail children of the report's numbered Findings, Issues or explicit
Recommendations sections are emitted. The sidebar/TOC, threat specifications,
tool output and appendices are excluded. Native ungraded recommendations stay
unknown instead of receiving a guessed security severity.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from copy import copy
from dataclasses import replace

from core import Candidate, clean, severity, status
from variants import Fingerprint, Variant

DESCRIPTION = "Diligence numbered Findings/Issues/Recommendations detail sections, inline native risk/status and legacy metadata/icon tables"
REVIEWED_SHA256 = (
    "24af4a69149e58addac9fb0f0000d7a988c3a46b8584395a8089725b898d9399",
    "7245cb260fb05ddb811bc1040ca00f106a17fc3db4b48d09fb75d92d732bbfb9",
    "ccf410736d28d405c5f0994934c3ba1333e446d63a6f7c56e20e992d6c0801ac",
    "36ba1cc2a1fa0c4b90fd00cffa0f232845dd29c02c52211f33668cf1853bd3f8",
    "fc98d0dea09f8be1b78e0c3747174f9f3dc790820efaf0357d32354b3a740ed0",
    "f7ca97e6bb786ede88f20092b2ef5d2b04b5e83aa41d904db4179ab2a546c871",
    "92c3c94798ac6a8233741f41965a24f690263e00f76a2cf5aaeef1036bb97d5b",
    "37dd627567d246512debb21dabb27412605da51b9a41363add4bfef421824592",
    "91bae4155d2b48486d5edf19048577c76dace1807c8d52799a6290dd2f0490b3",
    "9dfcb7cea411e6d02fda5423a1c5efc4aabccb7c2bdb9642a0a9a896728a1f14",
    "d2604f520cf08af9e330b0fd956368f9b8741dda9776ec1cba0a3b0669da1f07",
    "0a0a6e4342877528d98eede666dbf302b3c744c63d6461af2b08450f1fa0cf42",
    "8a9c0ef74da3ac42beda3c275a2344767d32d5fab1b0dd407b4441a289e6d558",
    "9701d66c3c460334dfc6657d09ad79e2f3109b396bcb3c2355fa82a2c11a460a",
    "0f25e4e5f40ec4461489dba0c3b366cab8c502e948af2308665e15164e49c4c3",
    "e74cd0a5e7b9cfe9cff67bab6283b87ab0c876f218895f9339910879c6b5692b",
    "e9511ae1835e4f019c979a9d115ede933a61a5c9a2fedf9e43ef97040cf37519",
    "f388453a8dea5c78853ab515e2227bdd8fd5976bbf286dc1bc7e74cc5090cfc8",
    "148b6bd1b20abf5659465342bb29d1131eb8fac96e31e1e329ec0a108abb42a7",
    "291764b6635d15eca15485503b2264770e9a5cf6c47cc35cf84fe70dc2e3147e",
    "f9ef641a82cc531eef4194d23213544d1c0beea7a43062dd28bbca78cb28c04d",
    "397ac3c3353e079f94ca3ffb2baf2070c7ecd3f5f61ae4ac6a71086b67b6bf5d",
    "6b0b1c0edac9c795a9fc7497fe08b90637d78c1a2c5f153883220b797738d8ef",
    "c8f0b3c02c4162aee1a237f7099c9a5fc32609b152f0312718e799414d692049",
    "40ec99e7332fdc6b75a86c085a6f9257d336c36b0c10fb40fa3403dbd0c96fc5",
)

RISK = r"Critical|Major|High|Medium|Minor|Low|Informational|Information|Info|Undetermined|Unknown"
STATE = r"(?:Partially\s+(?:Fixed|Addressed|Resolved)|Not\s+(?:Fixed|Addressed|a\s+Bug)|Won[’']?t\s+(?:Fix|Do)|Acknowledged|Unresolved|Resolved|Addressed|Mitigated|Accepted|Pending|Closed|Fixed|Open)"
PARENT = re.compile(r"^(\d+)\s+((?:General\s+)?Findings(?:\s*[:꞉]\s*[^\n]+|\s+from Other Sources)?|Issues|Issue Details?|Recommendations(?: and Advice)?|Infrastructure Security(?: Assessment)?|Contracts V2|Strategy Vaults|1inch Contract|Limit Order Protocol|Solidity Utils|Smart Contracts|Other Code)$", re.I)
STOP = re.compile(r"^(?:Appendix\b|\d+\s+(?:Tool[- ]Based Analysis|Automated Analysis|Security Specification|System Overview|Conclusion|Artifacts|Audit Scope|Threat Model)\b)", re.I)


def _body_view(report):
    """Remove the initial PDF navigation column for heading recognition only.

    The web-to-PDF renderer places a long navigation tree beside the report;
    it can continue over several physical pages and its width changes between
    pages. Exact evidence/body slices still refer to the unmodified cache.
    """
    if report.meta.get("file_format") != "pdf":
        return report
    columns = {}
    for page in report.meta["pages"]:
        raw = page["text"].splitlines()
        indents = Counter(len(line) - len(line.lstrip()) for line in raw
                          if line.strip() and 20 <= len(line) - len(line.lstrip()) <= 80)
        if not indents:
            break
        common = [(column, frequency) for column, frequency in indents.items() if frequency >= 3]
        if not common:
            break
        column, frequency = min(common)
        left = [line[:column] for line in raw]
        markers = sum(bool(re.match(r"^\s{0,3}(?:\d+(?:\.\d+)?\s|Appendix\b|A\.\d)", line)) for line in left)
        if frequency < 3 or markers < 2:
            break
        # Real full-width prose does not consist of a short left navigation
        # label followed by a gutter and a separate right paragraph.
        wide_left = sum(bool(line.strip()) and len(line) >= column
                        and not re.search(r"\s{2,}$", line[:column])
                        and not re.search(r"\s{3,}", line[:column]) for line in raw)
        if wide_left > max(5, len(raw) // 7):
            break
        columns[page["page"]] = column
    if not columns:
        return report
    view = copy(report)
    view.lines = []
    for line in report.lines:
        column = columns.get(line.page)
        if column is None:
            view.lines.append(line)
            continue
        indent = len(line.text) - len(line.text.lstrip())
        cut = column
        if indent >= column - 6:
            cut = indent
        else:
            gutter = [match for match in re.finditer(r" {2,}", line.text)
                      if match.start() <= column + 5 and match.end() >= column - 6]
            if gutter:
                cut = min(gutter, key=lambda match: abs(match.end() - column)).end()
        value = line.text[cut:] if len(line.text) > cut else ""
        view.lines.append(replace(line, text=value, content=value.strip(),
                                  start=min(line.end, line.start + cut),
                                  excluded=line.excluded or bool(line.content and not value.strip())))
    return view


def _regions(report):
    """Select actual body sections; websites have H2s and PDFs repeat TOCs."""
    parents = {}
    markup = report.meta.get("file_format") in {"md", "html"}
    for i, line in enumerate(report.lines):
        if line.code or (markup and line.heading != 2):
            continue
        match = PARENT.fullmatch(clean(line.content))
        if match:
            parents[match[1]] = (i, match[2])  # Last occurrence is detail, not navigation.
    result = []
    for section, (i, label) in sorted(parents.items(), key=lambda item: item[1][0]):
        end = len(report.lines)
        for j in range(i + 1, len(report.lines)):
            line = report.lines[j]
            if line.code or (markup and not line.heading):
                continue
            value = clean(line.content)
            if PARENT.fullmatch(value) or STOP.match(value):
                end = j
                break
            if markup and line.heading <= 2 and re.match(r"^\d+\s", value):
                end = j
                break
        result.append((section, label, i + 1, end))
    return result


def _metadata(report, index):
    """Read source-native Severity/Status cells, including legacy image names."""
    lines = report.lines[index + 1:index + 11]
    text = "\n".join(line.text for line in lines)
    raw = state = None
    if re.search(r"\bSeverity\b", text, re.I):
        icon = re.search(r"(?:src=[\"'][^\"']*/)(critical|major|medium|minor|high|low|info)\.png", text, re.I)
        if icon:
            raw = icon[1]
        else:
            table = re.search(r"^\s*\|\s*(" + RISK + r")\s*\|\s*([^|\n]+)", text, re.I | re.M)
            if table:
                raw, state = table[1], table[2].strip()
        icon_status = re.search(r"src=[\"'][^\"']*/(open|closed)\.png", text, re.I)
        if icon_status:
            state = icon_status[1]
    return raw, state


def _header(report, index):
    line = report.lines[index]
    match = re.match(r"^(\d+\.\d+)\s+(.+)", line.content)
    if not match:
        return None
    number, title = match.groups()
    # PDF titles wrap before their risk/status badge. Join only the compact
    # heading block, never the description or the first prose paragraph.
    if report.meta.get("file_format") == "pdf":
        for following in report.lines[index + 1:index + 6]:
            value = clean(following.content)
            if not value and following.excluded:
                continue  # A navigation-only line removed from a PDF column.
            if not value or re.match(r"^(?:\d+\.\d+\s|Description\b|Resolution\b|Recommendation\b)", value, re.I):
                break
            if re.match(r"^(?:(?:The|This|There|We|It|Consider|Currently|However)\s|UPDATE\s*:)", value, re.I):
                break
            if re.search(r"\b(?:" + RISK + r")\s*(?:[✓✔]\s*)?(?:" + STATE + r")?\s*$", title, re.I):
                if re.match(r"^[✓✔]\s*\S", value) or re.fullmatch(r"[✓✔]?\s*(?:" + STATE + r")", value, re.I):
                    title += " " + value
                break
            title += " " + value
    state = None
    status_badge = re.search(r"\s*[✓✔]\s*(\S.*)$", title)
    status_match = re.search(r"\s+(" + STATE + r")\s*$", title, re.I)
    if status_badge:
        state = status_badge[1]
        title = title[:status_badge.start()].rstrip()
    elif status_match:
        state = status_match[1]
        title = title[:status_match.start()].rstrip()
    risk_match = re.search(r"\s+(" + RISK + r")\s*$", title, re.I)
    raw = risk_match[1] if risk_match else None
    if risk_match:
        title = title[:risk_match.start()].rstrip()
    if raw is None:
        raw, metadata_state = _metadata(report, index)
        state = state or metadata_state
    return number, title, raw, state


def _numbered_sections(report):
    result = []
    markup = report.meta.get("file_format") in {"md", "html"}
    for section, label, start, end in _regions(report):
        entries = []
        for i in range(start, end):
            line = report.lines[i]
            if line.code or (markup and not line.heading):
                continue
            match = re.match(r"^(\d+)\.(\d+)\s+", line.content)
            if not match or (match[1] != section and not label.lower().startswith("issue detail")):
                continue
            value = _header(report, i)
            if value is None:
                continue
            number, title, raw, state = value
            if re.match(r"^[‑–—-]\s", title):
                continue  # A quoted client response referring to an earlier ID.
            if not markup and raw is None and any(c.printed_id == number for c in entries) and i > 0 and report.lines[i - 1].content:
                continue  # A wrapped prose reference to an earlier finding.
            state_key = (state or "").lower()
            normalized_status = {"closed": "resolved", "addressed": "resolved", "partially addressed": "partial", "not fixed": "open"}.get(state_key)
            if state_key.startswith("fixed in "):
                normalized_status = "fixed"
            entries.append(Candidate(line.start, title, raw, number, status_raw=state,
                                     normalized_status=normalized_status,
                                     method="diligence-numbered-detail", confidence=.96 if raw else .88,
                                     evidence={"severity_basis": "inline_heading_or_legacy_metadata" if raw else "publisher_ungraded",
                                               "parent_section": section, "parent_title": label,
                                               "ungraded_native_recommendation": raw is None}))
        bound = report.lines[end].start if end < len(report.lines) else len(report.text)
        for j, candidate in enumerate(entries):
            candidate.end = entries[j + 1].start if j + 1 < len(entries) else bound
        result.extend(entries)
    return result


def parse(report):
    return _numbered_sections(_body_view(report))


def printed_counts(report):
    """The 2018 dashboard prints status-by-severity numeric matrices."""
    lines = report.lines
    for i, line in enumerate(lines):
        if not re.search(r"Number of issues (?:per|by) severity", line.content, re.I):
            continue
        block = lines[i + 1:i + 15]
        labels, rows, evidence = [], [], []
        for entry in block:
            icons = re.findall(r"src=[\"'][^\"']*/(critical|major|medium|minor|high|low|info)\.png", entry.text, re.I)
            if len(icons) >= 2 and not rows:
                labels = icons
            cells = [cell.strip().strip("*").strip() for cell in entry.text.strip().strip("|").split("|")]
            text_labels = [cell for cell in cells if re.fullmatch(RISK, cell, re.I)]
            if len(text_labels) >= 2 and not rows:
                labels = text_labels
            if labels and (re.search(r"/(?:open|closed)\.png", entry.text) or cells and re.fullmatch(r"open|closed", cells[0], re.I)):
                # Count only standalone table cells, not HTML image dimensions.
                numbers = [cell for cell in cells[1:] if re.fullmatch(r"\d+", cell)]
                if len(numbers) == len(labels):
                    rows.append([int(n) for n in numbers])
                    evidence.append({"page": entry.page, "start": entry.start, "end": entry.end, "text": entry.text})
        if labels and len(rows) == 2:
            counts = Counter()
            for row in rows:
                for raw, count in zip(labels, row):
                    counts[severity(raw, report.firm)] += count
            return {"counts": dict(counts), "basis": "diligence_numeric_dashboard_status_matrix", "evidence": evidence}
    return None


def sequence_diagnostics(report, candidates):
    groups = defaultdict(list)
    for candidate in candidates:
        match = re.fullmatch(r"(\d+)\.(\d+)", candidate.printed_id or "")
        if match:
            groups[match[1]].append(int(match[2]))
    if not groups:
        return {"complete": None, "reason": "no_numbered_detail_sections", "gaps": [], "duplicates": []}
    gaps, duplicates = [], []
    for section, numbers in sorted(groups.items()):
        gaps.extend(f"{section}.{number}" for number in sorted(set(range(1, max(numbers) + 1)) - set(numbers)))
        duplicates.extend(f"{section}.{number}" for number, n in Counter(numbers).items() if n > 1)
    return {"complete": not gaps and not duplicates, "reason": "per_numbered_finding_parent_section", "gaps": gaps, "duplicates": duplicates}


def _markdown_view(report):
    """Recognize source Markdown fences closed on the same line.

    An inline triple-backtick example must not mark every later genuine
    Severity/Status finding table as code. Source offsets remain unchanged.
    """
    result = copy(report)
    result.lines, fence = [], None
    for line in report.lines:
        marker = re.match(r"^[ \t]*(`{3,}|~{3,})(.*)$", line.text)
        code = fence is not None
        if marker:
            token, tail = marker.groups()
            code = True
            if fence is None:
                if not tail.rstrip().endswith(token):
                    fence = token
            elif token[0] == fence[0] and len(token) >= len(fence) and not tail.strip():
                fence = None
        result.lines.append(replace(line, code=code))
    return result


def markdown_tables(report):
    return _numbered_sections(_markdown_view(report))


def web_badges(report):
    return _numbered_sections(report)


def fullwidth_pdf(report):
    return _numbered_sections(report)


def sidebar_pdf(report):
    return _numbered_sections(_body_view(report))


def narrative_supporting(report):
    # These source-explicit supporting/clean/narrative reviews contain no
    # numbered finding cards. Do not invent rows from generic prose or tool
    # output; the collection attribution of the foreign ABDK artifact remains
    # visible upstream and is not silently reassigned by this parser.
    return []


def contract_sections(report):
    rows = _numbered_sections(_body_view(report))
    for row in rows:
        row.method = "diligence-named-contract-section"
        if row.evidence.get("parent_title", "").casefold() == "other code":
            row.evidence["source_scope"] = "publisher_explicit_out_of_scope_findings"
    return rows


def supporting_inputs(report):
    return []


def mythx_exports(report):
    # Raw scanner diagnostics are supporting artifacts, not publisher-reviewed
    # detailed audit findings. The audit report may separately cite them.
    return []


def _state_value(raw):
    key = clean(raw).casefold()
    return {"addressed": "resolved", "partially addressed": "partial",
            "partly addressed": "partial", "remediated": "resolved",
            "not addressed": "open", "not fixed": "open", "done": "fixed",
            "implemented a fix": "fixed", "implemented the fix": "fixed"}.get(key) or status(raw)


def _raw_span(text, raw, start, end):
    if not raw:
        return None
    # The matching view joins PDF wraps, while evidence keeps exact source
    # whitespace and the original Unicode label spelling.
    pattern = r"[\s\u200b]+".join(re.escape(word) for word in clean(raw).split())
    match = re.search(pattern, text[start:end], re.I)
    if match:
        return text[start + match.start():start + match.end()], start + match.start(), start + match.end()
    return None


def _resolution_regions(report, candidate):
    body = report.text[candidate.start:candidate.end]
    result = []
    for match in re.finditer(r"(?m)^[ \t]*(?:#{1,6}[ \t]+)?(?:Resolution|Remediation Notes?|Fix Review)[ \t]*[:꞉]?[ \t]*$", body, re.I):
        begin = match.end()
        following = re.search(r"(?m)^[ \t\f\r]*(?:#{1,6}[ \t]+)?(?:Description(?:[ \t]+and[ \t]+Recommendations?)?|Recommendations?|Examples?|References?|Details|Impact)[ \t]*[:꞉]?[ \t]*$", body[begin:], re.I)
        end = begin + following.start() if following else len(body)
        result.append((candidate.start + begin, candidate.start + end, "resolution_section"))
    # The older template uses explicit UPDATE paragraphs in place of a box.
    for match in re.finditer(r"(?m)^[ \t]*(?:\*\*)?UPDATE[ \t]*(?:\*\*)?[:꞉][ \t]*([^\n]*(?:\n(?![ \t]*\n)[^\n]+)*)", body, re.I):
        result.append((candidate.start + match.start(1), candidate.start + match.end(1), "labelled_update"))
    return result


def _resolution_claim(text, start, end):
    block = text[start:end]
    label = r"(?:Partially|Partly)\s+(?:Addressed|Fixed|Resolved)|Not\s+(?:Addressed|Fixed|Resolved)|Acknowledged|Addressed|Resolved|Fixed|Implemented|Remediated|Mitigated|Invalid"
    patterns = (
        r"^[ \t\r\n]*(" + label + r")\b",
        r"\b(?:This(?:\s+(?:issue|finding|recommendation))?|(?:The\s+)?(?:issue|finding|recommendation)|It)\s+(?:(?:has|have)\s+been|was|is)\s+(?:(?:now|fully|already)\s+)?(" + label + r")\b",
        r"\b(?:team|client)(?:\s+has)?(?:\s+agreed\b[^\n.!?]{0,80}?\band)?\s+(implemented\s+(?:a|the)\s+fix)\b",
        r"\b(?:team|client)\s+(?:(?:has|have)\s+)?(acknowledged|addressed|resolved|fixed|remediated)\b",
    )
    claims = []
    for pattern in patterns:
        for match in re.finditer(pattern, block, re.I):
            prefix = re.split(r"[.!?\n]", block[:match.start()])[-1]
            if re.search(r"\b(?:recommend|should|must|will|would|could|may|if)\b", prefix, re.I):
                continue
            claims.append((match[1], start + match.start(1), start + match.end(1)))
    return max(claims, key=lambda claim: claim[1]) if claims else None


def _attach_status(report, candidates, tables=False):
    view = _body_view(report)
    positions = {line.start: i for i, line in enumerate(view.lines)}
    for candidate in candidates:
        candidate.status_raw = candidate.normalized_status = None
        index = positions.get(candidate.start)
        claim = None
        if index is not None:
            header = _header(view, index)
            state = header[3] if header else None
            header_end = min(candidate.end, view.lines[min(index + 8, len(view.lines) - 1)].end)
            claim = _raw_span(report.text, state, candidate.start, header_end)
            if claim:
                basis = "printed_heading_badge_or_metadata"
            if tables:
                # Icon filenames encode the publisher's native status; keep
                # their exact substring as evidence rather than inventing alt text.
                cell = re.search(r"src=[\"'][^\"']*/(open|closed)\.png", report.text[candidate.start:header_end], re.I)
                if cell:
                    claim = (cell[1], candidate.start + cell.start(1), candidate.start + cell.end(1))
                    basis = "legacy_status_icon_filename"
            if not claim:
                done = re.search(r"\[(Done)\]", report.text[candidate.start:header_end], re.I)
                if done:
                    claim = (done[1], candidate.start + done.start(1), candidate.start + done.end(1))
                    basis = "printed_completion_badge"
        regions = _resolution_regions(report, candidate)
        if regions:
            candidate.resolution = report.text[regions[0][0]:regions[0][1]].strip() or None
            candidate.evidence["resolution_evidence"] = [{"start": start, "end": end, "text": report.text[start:end], "basis": source}
                                                          for start, end, source in regions]
        resolution_claims = [(value, source) for start, end, source in regions
                             if (value := _resolution_claim(report.text, start, end))]
        if claim and resolution_claims:
            contradictory = [(value, source) for value, source in resolution_claims if _state_value(value[0]) != _state_value(claim[0])]
            if contradictory:
                candidate.evidence["status_conflict"] = True
                candidate.evidence["alternate_status_claims"] = [{"raw": value[0], "start": value[1], "end": value[2], "text": report.text[value[1]:value[2]], "basis": source}
                                                                 for value, source in contradictory]
        if not claim and resolution_claims:
            claim, basis = resolution_claims[-1]
        if claim:
            raw, start, end = claim
            candidate.status_raw = raw
            candidate.normalized_status = _state_value(raw)
            candidate.evidence["status_evidence"] = {"raw": raw, "start": start, "end": end,
                                                      "text": report.text[start:end], "basis": basis,
                                                      "profile": "consensys-diligence"}


def markdown_status(report, candidates):
    _attach_status(report, candidates, tables=True)


def web_status(report, candidates):
    _attach_status(report, candidates)


def fullwidth_status(report, candidates):
    _attach_status(report, candidates)


def sidebar_status(report, candidates):
    _attach_status(report, candidates)


def supporting_status(report, candidates):
    _attach_status(report, candidates)


def contract_status(report, candidates):
    _attach_status(report, candidates)


def input_status(report, candidates):
    _attach_status(report, candidates)


def mythx_status(report, candidates):
    _attach_status(report, candidates)


VARIANTS = (
    Variant("consensys-diligence/v2022_contract_sections", Fingerprint((
        ("smart_contract_section", r"^\s*\d+[ \t]+Smart Contracts[ \t]*$", 4),
        ("other_code_section", r"^\s*\d+[ \t]+Other Code[ \t]*$", 4),
        ("native_risk_definitions", r"Each issue has an assigned severity", 2),
    ), ("2022", "2022")), contract_sections, ("diligence_contract_sections",), contract_status, printed_counts,
            "Named Smart Contracts and Other Code finding sections; source-explicit out-of-scope findings retain that scope in evidence."),
    Variant("consensys-diligence/v2020_mythx_exports", Fingerprint((
        ("scanner_report_id", r"^\s*REPORT[ \t]+[A-F0-9]{20,}[ \t]*$", 3),
        ("scanner_analysis_counter", r"^\s*Number of analyses[ \t]+\d+", 3),
        ("scanner_analysis_id", r"^\s*Analysis[ \t]+[a-f0-9]{8}-[a-f0-9-]{27,}[ \t]*$", 3),
        ("scanner_client_tool", r"^\s*Client Tool[ \t]+Mythx-Cli-", 4),
        ("scanner_diagnostics", r"^\s*DETECTED VULNERABILITIES[ \t]*$", 2),
    ), ("2020", "2020"), formats=("pdf",)), mythx_exports, ("diligence_mythx_export",), mythx_status, printed_counts,
            "Unreviewed MythX automated diagnostics; zero audit-finding rows are intentional."),
    Variant("consensys-diligence/v2020_supporting_inputs", Fingerprint((
        ("architecture_document", r"^\s*Mooniswap V2[ \t]+\(legacy\)[ \t]*$", 8),
        ("audit_planning_agenda", r"^\s*Zer0 Audit Plan[ \t]*$", 8),
        ("intake_checklist", r"^\s*Essential items:[ \t]*$", 8),
        ("specification_cover", r"^\s*zAuction[ \t]*\n[ \t]*OVERVIEW[ \t]*$", 8),
    ), ("2020", "2021"), formats=("pdf",)), supporting_inputs,
            ("diligence_intake_checklist", "diligence_specification"), input_status, printed_counts,
            "Collected client specifications, architecture notes and audit-intake/planning material; no published findings."),
    Variant("consensys-diligence/v2018_markdown_tables", Fingerprint((
        ("native_severity_status_table", r"\|\s*Severity\s*\|\s*Status\s*\|", 8),
        ("numbered_details", r"^#{2,4}\s+\d+\.\d+\s+", 2),
    ), ("2018", "2019"), formats=("md",)), markdown_tables,
            ("diligence_markdown_icons", "diligence_markdown_text", "diligence_markdown_inline_fence"), markdown_status, printed_counts,
            "2018–19 Markdown tables, including native open/closed icon filenames."),
    Variant("consensys-diligence/v2020_narrative_supporting", Fingerprint((
        ("audit_log_summary", r"Audit Log\s*[-–]\s*Phase\s*[12]", 8),
        ("cryptographic_clean_review", r"No significant issues were found in the cryptographic review", 8),
        ("safetychecker_review", r"SafetyChecker Summary", 8),
        ("metrics_export", r"Solidity Metrics", 8),
        ("foreign_abdk_artifact", r"ABDK(?: Consulting)?", 8),
        ("explicit_clean_review", r"No issues (?:are|were) found", 6),
    ), ("2020", "2023"), reject_signatures=(
        r"^(?:#{2}\s+)?[ \t]*\d+\s+(?:Findings(?:\s*[:꞉]\s*[^\n]+)?|Issues|Issue Details?|Recommendations(?: and Advice)?|Infrastructure Security(?: Assessment)?|Contracts V2|Strategy Vaults|1inch Contract|Limit Order Protocol|Solidity Utils)[ \t]*$",
    )), narrative_supporting,
            ("diligence_supporting_narrative", "diligence_clean_review", "diligence_safetychecker"), supporting_status, printed_counts,
            "Explicit clean reviews, unnumbered supporting narratives and a collector-attributed foreign report; zero finding rows are intentional."),
    Variant("consensys-diligence/v2019_web_badges", Fingerprint((
        ("numbered_native_section", r"^##\s+\d+\s+(?:(?:General\s+)?Findings|Issues|Recommendations|Issue Details|Infrastructure Security|Contracts V2|Strategy Vaults|1inch Contract|Limit Order Protocol|Solidity Utils)\b", 8),
        ("detail_heading", r"^###\s+\d+\.\d+\s+", 2),
    ), ("2019", "2026"), formats=("html",)), web_badges,
            ("diligence_web_badges", "diligence_web_resolution", "diligence_web_update"), web_status, printed_counts,
            "Native numbered web headings with risk/status badges and labelled resolution/update boxes."),
    Variant("consensys-diligence/v2019_sidebar_pdf", Fingerprint((
        ("side_navigation_summary", r"^[ \t]*\d+[ \t]+(?:Executive[ \t]+)?Summary[ \t]{8,}\S", 8),
        ("side_navigation_findings", r"^[ \t]*\d+[ \t]+(?:Findings|Issues)[ \t]{8,}\S", 8),
        ("right_column_section", r"^[ ]{20,80}\d+[ \t]+(?:(?:Executive[ \t]+)?Summary|(?:General[ \t]+)?Findings|Issues|Recommendations|Issue Details|Infrastructure Security|Contracts V2|Strategy Vaults|1inch Contract|Limit Order Protocol|Solidity Utils)\b", 8),
        ("numbered_native_section", r"^\s*\d+\s+(?:(?:General\s+)?Findings(?:\s*[:꞉]\s*[^\n]+)?|Issues|Recommendations|Issue Details|Infrastructure Security|Contracts V2|Strategy Vaults|1inch Contract|Limit Order Protocol|Solidity Utils)\s*$", 3),
    ), ("2019", "2026"), formats=("pdf",)), sidebar_pdf,
            ("diligence_sidebar_pdf",), sidebar_status, printed_counts,
            "PDF web renderings whose navigation column shares lines with the report body."),
    Variant("consensys-diligence/v2020_fullwidth_pdf", Fingerprint((
        ("numbered_native_section", r"^\s*\d+\s+(?:(?:General\s+)?Findings(?:\s*[:꞉]\s*[^\n]+)?|Issues|Recommendations|Issue Details|Infrastructure Security|Contracts V2|Strategy Vaults|1inch Contract|Limit Order Protocol|Solidity Utils)\s*$", 6),
        ("detail_heading", r"^\s*\d+\.\d+\s+", 2),
    ), ("2020", "2026"), formats=("pdf",)), fullwidth_pdf,
            ("diligence_fullwidth_pdf",), fullwidth_status, printed_counts,
            "Full-width numbered PDF sections and inline native risk/status cards."),
)
