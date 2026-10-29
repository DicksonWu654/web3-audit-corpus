"""Statemind finding cards (2022 unnumbered sections, 2023+ severity IDs).

Titles/IDs/statuses are columns, sometimes vertically centered and wrapped over
several rows. Only a card followed by its Description field is a formal finding.
The severity-breakdown definitions, contents, conclusions, Slither/linter output
and deployment-validation narrative are not findings. There is no Low category
in the observed native scale; informational includes publisher gas suggestions.
"""
from core import severity, Candidate, clean
import re
from collections import Counter, defaultdict
from summary_counts import printed_counts as _printed_counts

DESCRIPTION = "Detailed Description cards with native severity IDs, multiline title/status columns, and legacy unnumbered severity sections; appendices excluded"
REVIEWED_SHA256 = (
    "916f0c78c50b4c6f782f54a7b4248e2e2380bb250be21fe8f468857dd0cc593a",
    "bf05a22a4c0d4854255f2783a884befc62094e3b6be8962fdd04cb31e0cc94a9",
    "cfdf25fd0e901cfe07150fa68576c5f43f1ffeb686a74a447de9f87c761e22bd",
    "f3718d43154ae0664b536688b06e94556cea4466c891ab3ad071d90211cacb86",
    "476f9e25ccf021ed73614296fe64bea90b21eccaa63528023e3c415a9e259e8e",
    "f9d261537865d1c02197dd62ec03c6974d99db376afb664af2e879aa15b6410a",
    "6f668b17b895740dd7a152ac38d6735d4bbf8cb6355c598f70bf3d3965124b72",
    "c71184758ca80ce55bb13dd67a3296b758ed8217fb55d1e7da40a36c1a6713ff",
    "2c51f905de58dc87eb3cd7f3cf98bfc5cdc01850e31aeafa8cc5be49c770bd46",
    "72f49d9cb953701e57c11370d27ceaf32bd251c5b7d28982d17aee026c93ad74",
    "1036145ab27ce97f7f504dfc484e29515bc23e20b62cf631774ed721eebdd19f",
    "4ae740bdc4fa6c4cbf6ca798c1a1bd286b34315636d040d3f2c30434dd69e8dd",
    "8cdc3503fd69800e961c4ec829a9e20ccdb0344cd8102b4f84563043e3af3ffb",
    "1d4a2926755df68fe1363f1ab3ff80d4fae7d81a16236b12e901510054afcfc4",
    "356754f1aa4f7933f4c1c3f4716dc4c0fec6a0b3197ccaf55d319d366fe97515",
    "e2d3377686efc5b9adc93c6d6e20ef59e94ffb11ca80225ee0d2dbf15279b7e8",
)
RESIDUAL_EXAMPLES = {
    "ab129f3d407b63cb1062f604a0df69671a33a4bc77810b89c8a61530b39e0d21": "Myso v2: summary prints 103 informational findings, but detailed IDs jump from INFORMATIONAL-68 to INFORMATIONAL-70 and contain only 102; missing entry is never manufactured.",
    "6e27248be0a8a9fb65eed5fbaf13f604d7ee3cf48d2ab29a3540c5ea4e69a35b": "Lido CSM V3/CM V2: the source repeats INFORMATIONAL-05 and has no INFORMATIONAL-07; both real occurrences are preserved and sequence diagnostics remain incomplete.",
    "8fe5729ba8d52de58dbe607cb7097cf962f22b4ce33b1ab77deb401fc58f61c9": "Lido Roles Analysis: its role-impact/attack-complexity matrix is not a findings count table. Narrative recommendations and role descriptions have no native finding IDs/cards.",
    "8dbb9dfbd9662b2867969b8c16f5abcb74f8f42e0ba20c0d77a503551cbc6403": "Lido deployment validation is a narrative validation report, without finding cards or IDs; zero extracted findings does not establish a clean audit.",
}
_RISK = r"(?:CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)"
_ID = re.compile(r"^\s*(" + _RISK + r")(?:(-)(\d+)?)?(?:\s{2,}|$)")
_STATUS = re.compile(r"\b(?:Fixed(?:\s+at\s*:?\s*[^\s]+)?|Acknownledged|Acknowledged|Pending|New|Partially fixed|Resolved|Not fixed)\b", re.I)
_SEVERITY = re.compile(r"^(Critical|High|Medium|Low|Informational)$", re.I)


def _section(report):
    starts = [i for i, l in enumerate(report.lines) if re.fullmatch(r"5\.\s*Findings report", l.content, re.I)]
    if not starts:
        return None
    start = starts[-1]
    end = next((i for i in range(start + 1, len(report.lines)) if re.match(r"\d+\.\s*Appendix\b", report.lines[i].content, re.I)), len(report.lines))
    return start, end


def _header(report, i, lower):
    # Cards have a blank separator before Description. A wrapped heading has
    # consecutive nonempty rows; a few modern cards place an empty row between
    # the severity prefix and its numeric suffix.
    end = i
    while end > lower and (not report.lines[end - 1].content or re.fullmatch(r"\s{30,}\d+", report.lines[end - 1].text)):
        end -= 1
    start = end - 1
    while start > lower and end - start < 7:
        prev = report.lines[start - 1]
        if not prev.content:
            # The only internal blank observed is inside a wrapped ID card.
            if start > lower + 1 and _ID.match(report.lines[start - 2].text):
                start -= 2
                continue
            break
        if prev.page != report.lines[end - 1].page or re.fullmatch(r"\s{30,}\d+", prev.text) or _SEVERITY.fullmatch(prev.content):
            break
        start -= 1
    return start, end


def parse(report):
    bounds = _section(report)
    if bounds is None:
        return []
    lower, upper = bounds
    out, inherited = [], None
    for i in range(lower + 1, upper):
        line = report.lines[i]
        risk = _SEVERITY.fullmatch(line.content)
        if risk:
            inherited = risk[1]
        if line.content != "Description":
            continue
        start, end = _header(report, i, lower + 1)
        if start < lower + 1:
            continue
        lines = report.lines[start:end]
        found = next(((n, _ID.match(l.text)) for n, l in enumerate(lines) if _ID.match(l.text)), None)
        raw, pid = inherited, None
        title, statuses = [], []
        if found:
            n, match = found
            raw = match[1]
            number = match[3]
            if match[2] and not number:
                number = next((m[1] for l in lines[n + 1:] if (m := re.match(r"^\s*(\d{1,3})(?:\s{2,}|$)", l.text))), None)
            if number is not None:
                pid = raw + "-" + number
        if raw is None:
            continue
        for headerline in lines:
            value = headerline.text
            m = _ID.match(value)
            if m:
                value = value[m.end():]
            elif found and re.match(r"^\s*\d{1,3}(?:\s{2,}|$)", value):
                value = re.sub(r"^\s*\d{1,3}(?:\s{2,}|$)", "", value)
            sm = next(reversed(list(_STATUS.finditer(value))), None)
            if sm:
                statuses.append(sm[0])
                value = value[:sm.start()]
            cells = [c.strip() for c in re.split(r"\s{2,}", value.strip()) if c.strip()]
            for cell in cells:
                if re.fullmatch(r"[a-f0-9]{5,40}|PR#?\d+|\d+", cell, re.I):
                    continue
                if not _SEVERITY.fullmatch(cell):
                    title.append(cell)
        if not title or not statuses:
            continue
        status_raw = statuses[-1]
        normalized_status = ("fixed" if status_raw.lower().startswith("fixed") else
                             "acknowledged" if status_raw.lower() in {"acknowledged", "acknownledged"} else
                             "open" if status_raw.lower() in {"pending", "new", "not fixed"} else None)
        out.append(Candidate(report.lines[start].start, clean(" ".join(title)), raw, pid,
                             normalized=severity(raw, report.firm), status_raw=status_raw, method="description-card",
                             normalized_status=normalized_status,
                             confidence=.97, evidence={"severity_basis": "printed_id_prefix" if found else "severity_section", "layout": "id_card" if found else "legacy_section_card"}))
    for index, c in enumerate(out):
        c.end = out[index + 1].start if index + 1 < len(out) else (report.lines[upper].start if upper < len(report.lines) else len(report.text))
    return out


def sequence_diagnostics(report, candidates):
    groups = defaultdict(list)
    for c in candidates:
        if c.printed_id and (match := re.fullmatch(r"([A-Z]+)-(\d+)", c.printed_id)):
            groups[match[1]].append(int(match[2]))
    if not groups:
        return {"complete": None, "reason": "Unnumbered cards or narrative validation report", "gaps": [], "duplicates": []}
    gaps, duplicates = [], []
    for group, values in groups.items():
        gaps.extend(f"{group}-{n:02}" for n in range(1, max(values) + 1) if n not in values)
        duplicates.extend(f"{group}-{n:02}" for n, count in Counter(values).items() if count > 1)
    return {"complete": not gaps and not duplicates, "gaps": gaps, "duplicates": duplicates}


def printed_counts(report):
    # Role-impact/attack-complexity matrices are classifications, not findings
    # totals. Only Statemind's labelled findings summary is comparable.
    if not any(re.fullmatch(r"3\.\s*Summary of findings", l.content, re.I) for l in report.lines):
        return None
    return _printed_counts(report)


# Phase 4d compatibility contract; preserve the existing parser until era review.
from variants import legacy as _legacy_variant
VARIANTS = (_legacy_variant('statemind', parse),)
