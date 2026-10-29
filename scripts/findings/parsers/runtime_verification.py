"""Runtime Verification's A/B, bracketed review/fuzzing and legacy report eras.

2019--20 reports use named/numbered findings under risk sections; 2021--23 use
A01/B01 and A1/B1/C1 IDs; 2024 onward use [A1], [CI1], [F1], etc. A/B/C are
review categories, NOT severity prefixes. Explicit per-finding risk wins, including
when a B finding has High risk. Informative is the publisher's informational risk.
P1--P5 is its separate priority scale and is deliberately retained as unknown risk.
Appendices, invariants, methodology, code examples and the front index are excluded.
"""
from core import SeverityLookup, severity, Candidate, clean
from collections import Counter, defaultdict
from difflib import SequenceMatcher
import re

DESCRIPTION = "Runtime Verification native finding IDs/risk metadata, legacy risk sections and distinct tracker excerpts/design recommendations"

REVIEWED_SHA256 = (
    "71d57d260714fcfcaaa47bbed46f5af2198f12caf3838f45b8ffadb67dc3f83b",
    "db5094fab2bc9b809deaea841fde1daba2811339a0eeb704ee0de1f7dff3a0e4",
    "6b46b8731e85a99d9fb8e6251022f10fc992c90c0dcf269534c551b1604fbd1f",
    "ffd77916cd17b83cace0c42ac654533841b982fa96519d0c023f20adac6027c9",
    "4ce14b15ea8e295993c93ef34bed0de049fdef618fd231a3e64e5d9d902dec0b",
    "d12350728a44ff95f642537d968c368c5bfba8cb1431dd3b4fa2512c04fea44e",
    "dd1271b3c20e485db85bc67525adbaa93dfd4dcb091d7287181fb2afb56466a4",
    "41e5ab4243f46c6d151167220e2b9e92cd34d6d1834a2bad67a79250b7c9711c",
    "64cac879fe42c00243888d2dba1694ac13999b58cb8afdf97df0b589ceee15ee",
    "44082e4c2a7edb05752c68fff37608b4adae116bfddad44c6b15d529b4e1bbb8",
    "d5de38bb9f3b503f6556992b9d05f2b1d7e0951db71fc3d414e55b385794e5f3",
    "73dc2dd9aff3d097a7d0f4785a16f622edbe1cfe77fd79820e617d8446739559",
    "63404a576d2690b619865b55f1642fca987dea2e2c0a5c7e2777aced4df5409d",
    "fb59277aa2920f05ac35ea14cbe7986bafce7b3ee31d7312061b58f3350f1f74",
    "23bd0701fd732d987fdf7e6083d5d9025ccaffa267dda195de85b2c4b41807d1",
    "8c87e9fc4d1784812537fe39951c3f85c34e9df3cd963bec9bb94258f037d837",
    "a646d62454d11e43f7c379ef0a3274e817b878384ec93213b0e45e9cc07f1d67",
    "b0227e567454683acf8abd727f5c2bd854e102f5a7815ca95074317d3ef86975",
)

_ID = re.compile(r"^(?:\[(?P<bracket>(?:[ABCDF]I?|TSI?)-?\d{1,3})\]|(?P<plain>[ABCDF]\d{1,3})(?:\s*[:.\-]\s*|\s+))\s*(?P<title>.*)$")
_RISK = re.compile(r"\bSeverity\s*:\s*(Critical|High|Medium|Mid|Low|Informational|Informative|Info|N/A|P[1-5]|-)(?=\W|$)", re.I)
_STOP = re.compile(r"^(?:Appendix\b|Bytecode(?:[- ]Level)? (?:Test|Coverage)|Common Anti.Pattern|Test Coverage Analysis|References\s*$)", re.I)


def _risk(body, prefix=None):
    m = _RISK.search(body)
    basis = "explicit_severity_field"
    if not m:
        m = re.search(r"\((Critical|High|Medium|Mid|Low|In-\s*formative|Informative|Informational)\)", body[:400], re.I)
        basis = "parenthesized_heading_severity"
    if m:
        raw = m[1]
        norm = severity(raw, 'runtime-verification')
        return raw, norm, basis
    if prefix in {"B", "CI"}:
        return "Informative", "info", "informative_finding_section"
    return None, "unknown", "not_printed"


def _status(body):
    m = re.search(r"\b(?:Partially addressed by client|Not addressed by client|Addressed by client|Acknowledged by client)\b", body, re.I)
    if m:
        return m[0]
    m = re.search(r"(?:^|\n)\s*Status\s*:?\s*(?:\n\s*)?([^\n]+)", body, re.I)
    return clean(m[1]) if m else None


def _normalized_status(raw):
    if not raw:
        return None
    s = raw.lower()
    if "not addressed" in s or "not to be fixed" in s or re.search(r'\b(?:not|never) (?:fixed|resolved)\b|\bno fix\b', s):
        return "open"
    if re.search(r'\b(?:intends? to address|will (?:be )?(?:address|fix)|not yet)\b', s):
        return "open"
    if "partially" in s:
        return "partial"
    if "acknowledged" in s:
        return "acknowledged"
    if re.match(r'(?:fixed|solved|fix implemented)\b', s):
        return 'fixed'
    if re.search(r"\b(?:fixed|resolved|addressed|solved)\b", s):
        return "resolved"
    return None


def _title(report, i, first):
    lines, parts = report.lines, [first]
    # Risk cards have title wrapping immediately before their metadata row.
    for j in range(i + 1, min(i + 6, len(lines))):
        s = lines[j].content
        if _RISK.search(s):
            return clean(" ".join(parts))
        if not s or re.match(r"^(?:Description|Recommendations?|Classification|Scenario|Status|Issue|Exploit|Context|Finding|Recommended Action|Difficulty|(?:Not |Partially )?Addressed|Acknowledged)\b", s, re.I):
            break
        if re.match(r"^(?:The|There|In|On|When|For|We|Here|This|These|It|A|An)\s", s) and not any(_RISK.search(l.content) for l in lines[j:min(i + 6, len(lines))]):
            break
        if _ID.match(s) or lines[j].code or len(s) > 105:
            break
        indent = len(lines[j].text) - len(lines[j].text.lstrip())
        original_indent = len(lines[i].text) - len(lines[i].text.lstrip())
        if indent > original_indent + 1:
            break
        parts.append(s)
    return clean(" ".join(parts))


def _parse_cards(report):
    lines = report.lines
    index_titles = {}
    for i, line in enumerate(lines):
        m = _ID.match(line.content)
        indent = len(line.text) - len(line.text.lstrip())
        if m and (line.excluded or 3 <= indent <= 9) and not line.code:
            pid = m["bracket"] or m["plain"]
            title = _title(report, i, m["title"])
            title = re.sub(r"\s*(?:\.\s*){4,}\s*\d+\s*$", "", title).strip()
            if title:
                index_titles.setdefault(pid, title)
    # ID headings can appear in the front index without a labelled Contents page.
    # Detail occurrences have substantial following text or explicit risk metadata.
    found = []
    for i, line in enumerate(lines):
        if line.code or line.excluded or re.search(r"(?:\.\s*){4,}\s*\d+\s*$", line.text):
            continue
        m = _ID.match(line.content)
        if m:
            if m["plain"] and len(line.text) - len(line.text.lstrip()) > 3 and not line.heading:
                continue
            found.append((i, m["bracket"] or m["plain"], m["title"]))
    out, alternatives = [], defaultdict(list)
    for n, (i, pid, title) in enumerate(found):
        line = lines[i]
        end = lines[found[n + 1][0]].start if n + 1 < len(found) else len(report.text)
        for later in lines[i + 1:]:
            if later.start >= end:
                break
            if _STOP.match(later.content):
                end = later.start
                break
        body = report.text[line.start:end]
        # Short adjacent index entries and references do not become findings.
        if len(body.strip()) < 110:
            continue
        prefix = re.match(r"[A-Z]+", pid)[0]
        raw, norm, basis = _risk(body, prefix)
        if prefix == "C" and raw is None and re.search(r"^\s*Checked properties\s*$", report.text[:line.start], re.I | re.M):
            continue
        title = index_titles.get(pid) or _title(report, i, title)
        title = re.sub(r"\s*\(?Severity\s*:.*$", "", title, flags=re.I).strip()
        if not title:
            paragraph = re.search(r"\n\s*Description\s*\n+\s*([^\n]+)", body, re.I)
            title = clean(paragraph[1]) if paragraph else None
        c = Candidate(line.start, title, raw, pid, severity(raw, report.firm), end=end,
                      status_raw=_status(body), method="native-finding-id", confidence=.94,
                      evidence={"severity_basis": basis})
        score = (bool(_RISK.search(body[:1200])), len(body), line.start)
        alternatives[pid].append((score, c))
    for matches in alternatives.values():
        out.append(max(matches, key=lambda item: item[0])[1])
    # Several 2022 reports use descriptive headings and an explicit risk row,
    # rather than IDs. Locate the title by walking back from the risk row.
    occupied = [(c.start, c.end) for c in out]
    for i, line in enumerate(lines):
        if line.code or line.excluded or not _RISK.search(line.content):
            continue
        if any(start <= line.start < end for start, end in occupied):
            continue
        if not re.match(r"^[\[(]?\s*Severity\s*:", line.content, re.I):
            continue
        parts, indices, j = [], [], i - 1
        while j >= 0 and i - j <= 5:
            if lines[j].page != line.page:
                break
            s = lines[j].content
            if not s and parts:
                break
            if re.match(r"^(?:Status|Conclusion|Notable Findings|Informative findings|Issues)\s*:", s, re.I):
                break
            if s and not re.match(r"^\d+(?:/\d+)?$", s):
                parts.insert(0, s)
                indices.insert(0, j)
                if re.match(r"^\d{1,2}[.)]\s+", s):
                    break
            j -= 1
        if not parts or any(_STOP.match(s) for s in parts):
            continue
        title = clean(" ".join(parts))
        pidm = re.match(r"(\d+)[.)]\s*(.+)", title)
        pid = pidm[1] if pidm else None
        if pidm:
            title = pidm[2]
        start = lines[indices[0]].start
        raw, norm, basis = _risk(line.content)
        out.append(Candidate(start, title, raw, pid, severity(raw, report.firm), method="explicit-risk-card",
                             confidence=.9, evidence={"severity_basis": basis}))
    out.sort(key=lambda c: c.start)
    for i, c in enumerate(out):
        if c.end is None:
            c.end = out[i + 1].start if i + 1 < len(out) else len(report.text)
            tail = report.text[c.start:c.end]
            stop = re.search(r"\n\s*Appendix\b", tail, re.I)
            if stop:
                c.end = c.start + stop.start()
            c.status_raw = _status(report.text[c.start:c.end])
    if not out:
        out = _legacy(report)
    if not out:
        out = _issue_tables(report)
    if not out and re.search(r"None\s+of these points represented a design flaw or a security vulnerability", report.text):
        out = _design_recommendations(report)
    for c in out:
        c.normalized_status = _normalized_status(c.status_raw)
    return out


def _issue_tables(report):
    """Keep tracker-table excerpts distinct from detailed security findings."""
    out, category_col, status_col, active = [], None, None, False
    for i, line in enumerate(report.lines):
        header = re.search(r"\bIssue\s+Category\b", line.text)
        if header:
            category_col = line.text.index("Category")
            status_col = line.text.find("Status")
            active = True
            continue
        if re.match(r"^(?:Findings in|Status:|Future Directions)", line.content):
            active = False
        m = re.match(r"^\s*(#\d{1,3})\s+", line.text)
        if not active or not m or line.code:
            continue
        title, categories, statuses = [], [], []
        last = i
        for j in range(i, min(i + 6, len(report.lines))):
            later = report.lines[j]
            if j > i and (not later.content or later.page != line.page or re.match(r"^\s*#\d+\s", later.text)):
                break
            left = later.text[:category_col].strip()
            if j == i:
                left = re.sub(r"^#\d+\s*", "", left)
            title.append(left)
            categories.append(later.text[category_col:status_col if status_col and status_col > 0 else None].strip())
            if status_col and status_col > 0:
                statuses.append(later.text[status_col:].strip())
            last = j
        raw_status = "Addressed by client" if re.search(r"Addressed\d* by\s+client", " ".join(statuses)) else None
        out.append(Candidate(line.start, clean(" ".join(title)), printed_id=m[1], normalized=severity(None, report.firm),
                             end=report.lines[last].end, status_raw=raw_status,
                             record_kind="summary_excerpt", method="native-issue-table", confidence=.7,
                             evidence={"severity_basis": "not_printed", "category_raw": clean(" ".join(categories)), "tracker_ids_are_not_sequential": True}))
        if raw_status:
            # Preserve an exact native status token when the remaining label
            # wraps down the right-hand column around unrelated title cells.
            for status_line in report.lines[i:last+1]:
                cell=status_line.text[status_col:]
                sm=re.search(r'\b((?:(?:Partially|Not)[ \t]+)?Addressed)(?=\d*\b)', cell, re.I)
                if sm:
                    start=status_line.start+status_col+sm.start(1); end=status_line.start+status_col+sm.end(1)
                    out[-1].status_raw=sm[1]
                    out[-1].evidence['status_evidence']=dict(raw=sm[1],start=start,end=end,
                        text=report.text[start:end],basis='tracker_status_column',profile='runtime-verification')
                    break
    return out


def _design_recommendations(report):
    out = []
    for line in report.lines:
        if line.excluded or line.code or line.text.startswith(" "):
            continue
        m = re.match(r"^(\d{1,2})\.\s+(.+)", line.content)
        if m:
            out.append(Candidate(line.start, m[2], printed_id=m[1], normalized=severity(None, report.firm),
                                 record_kind="recommendation", method="design-review-discussion", confidence=.9,
                                 evidence={"severity_basis": "not_printed", "publisher_explicitly_disclaims_security_vulnerability": True}))
    return out


def _legacy(report):
    """Match an old risk-index entry to its separately printed detail heading."""
    lines, entries = report.lines, []
    for page in report.meta["pages"]:
        if not re.search(r"^\s*List of Findings(?: in the second round)?\s*$", page["text"], re.I | re.M):
            continue
        risk = None
        for line in lines:
            if line.page != page["page"]:
                continue
            m = re.fullmatch(r"(Critical|High|Medium|Low|Informative)(?:\s*\(non-critical\))?\s*:?", line.content, re.I)
            if m:
                risk = m[1]
            m = re.match(r"^(\d{1,2})\.\s+(.+)", line.content)
            if risk and m:
                entries.append((page["page"], m[1], clean(m[2]), risk, line.start))
    out = []
    for index_page, pid, title, risk, index_offset in entries:
        needle = title.lower()
        matches = []
        for i, line in enumerate(lines):
            if line.page <= index_page or line.excluded:
                continue
            if len(line.text) - len(line.text.lstrip()) > 1 or not line.content:
                continue
            if i and lines[i - 1].page == line.page and lines[i - 1].content:
                continue
            parts = [line.content]
            for later in lines[i + 1:i + 4]:
                if not later.content or later.page != line.page or len(later.text) - len(later.text.lstrip()) > 1:
                    break
                parts.append(later.content)
            actual_title = clean(" ".join(parts))
            if actual_title.split()[0].lower() != needle.split()[0]:
                continue
            ratio = SequenceMatcher(None, needle, actual_title.lower()).ratio()
            if ratio >= (.7 if len(needle) < 30 else .78) or actual_title.lower().startswith(needle):
                matches.append((ratio, line, actual_title))
        if matches:
            _, line, actual_title = max(matches, key=lambda item: item[0])
            out.append(Candidate(line.start, actual_title, risk, pid,
                                 severity(risk, report.firm),
                                 method="legacy-index-linked-detail", confidence=.9,
                                 evidence={"severity_basis": "native_finding_index", "index_offset": index_offset, "sequence_group": index_page}))
    # A 2020 template has named minor findings, repeated in its front contents.
    if not out and re.search(r"^\s*Minor Findings\s*$", report.text, re.M):
        start = max(l.start for l in lines if l.content == "Minor Findings")
        for i, line in enumerate(lines):
            if line.start <= start or not line.content or line.excluded:
                continue
            if line.text.startswith(" ") or len(line.content) > 80:
                continue
            if line.content in {"Recommendation", "Status", "Exploit Scenario"}:
                continue
            if not re.search(r"\b(?:Disable|Avoid|Use|Update|Front-Running)\b", line.content):
                continue
            if any(line.content == previous.content for previous in lines if previous.start < start):
                out.append(Candidate(line.start, line.content, "Minor", normalized=severity("Minor", report.firm),
                                     method="legacy-named-minor-finding", confidence=.9,
                                     evidence={"severity_basis": "minor_finding_section"}))
    out.sort(key=lambda c: c.start)
    for i, c in enumerate(out):
        c.end = out[i + 1].start if i + 1 < len(out) else len(report.text)
        tail = report.text[c.start:c.end]
        stop = re.search(r"\n\s*(?:Bytecode(?:[- ]Level)? (?:Test|Coverage)|Common Anti.Pattern|Appendix\b)", tail, re.I)
        if stop:
            c.end = c.start + stop.start()
        c.status_raw = _status(report.text[c.start:c.end])
    return out


def sequence_diagnostics(report, candidates):
    """Check native prefix sequences; title-only reports are explicitly N/A."""
    groups = defaultdict(list)
    numeric_group, previous = 0, 0
    for c in candidates:
        m = re.fullmatch(r"([A-Z]+)-?(\d+)", c.printed_id or "")
        if m:
            groups[m[1]].append(int(m[2]))
        elif re.fullmatch(r"\d+", c.printed_id or ""):
            value = int(c.printed_id)
            if value < previous:
                numeric_group += 1
            group = c.evidence.get("sequence_group", numeric_group)
            groups[f"numbered_round_{group}:"].append(value)
            previous = value
    if not groups:
        return {"complete": None, "reason": "no_native_sequential_ids", "gaps": [], "duplicates": []}
    gaps, dup = [], []
    for prefix, values in groups.items():
        counts = Counter(values)
        gaps += [f"{prefix}{n}" for n in range(1, max(values) + 1) if n not in counts]
        dup += [f"{prefix}{n}" for n, count in counts.items() if count > 1]
    return {"complete": not gaps and not dup, "reason": "native_prefix_sequences", "gaps": gaps, "duplicates": dup}


def parse_letter_cards(report):
    return _parse_cards(report)


def parse_bracket_cards(report):
    return _parse_cards(report)


def parse_risk_cards(report):
    cs = _parse_cards(report)
    for c in cs:
        if not (c.printed_id or '').isdigit():
            continue
        parent = next((l for l in reversed(report.lines) if l.start < c.start and not l.excluded
                       and re.fullmatch(r'(?:Notable Findings|Informative findings|Issues)\s*:?', l.content, re.I)), None)
        if parent:
            c.evidence['container_id'] = parent.content.rstrip(':').casefold() + '@' + str(parent.start)
            c.evidence['id_namespace_evidence'] = dict(start=parent.start, end=parent.end, text=parent.text)
    return cs


def parse_legacy_index(report):
    cs = _legacy(report)
    for c in cs:
        if 'sequence_group' in c.evidence:
            c.evidence['container_id'] = 'finding_index_page_' + str(c.evidence['sequence_group'])
    return cs


def parse_tracker(report):
    out = _issue_tables(report)
    for c in out:
        c.normalized_status = _normalized_status(c.status_raw)
    return out


def parse_design(report):
    if re.search(r'None\s+of these points represented a design flaw or a security vulnerability', report.text):
        return _design_recommendations(report)
    return _parse_cards(report)


def parse_verification(report):
    # Proof papers and generated specifications are separate from finding cards.
    # Still retain any explicit legacy finding index or detail metadata.
    return _parse_cards(report)


def parse_specification(report):
    return []  # Generated definitions/properties are not finding records.


def parse_narrative(report):
    return _parse_cards(report)


def parse_named_sections(report):
    # The early Tezos template uses an unnumbered TOC and repeats the exact
    # titles above their full narratives. A TOC entry alone is never a finding.
    titles={}
    for l in report.lines:
        if not l.excluded: continue
        m=re.match(r'^\s*(\S.*?)\s+(?:\.\s*){3,}\d+\s*$', l.text)
        if m:
            titles[clean(m[1])] = l
    out=[]; parent=None
    for i,l in enumerate(report.lines):
        if l.excluded or l.code: continue
        if re.fullmatch(r'Findings|Informative Findings|Optimization|Appendix', l.content, re.I):
            parent=l
            continue
        if parent is None or parent.content.lower()=='appendix': continue
        parts=[]
        for nxt in report.lines[i:i+3]:
            if nxt.page!=l.page or not nxt.content: break
            parts.append(nxt.content)
            title=clean(' '.join(parts))
            if title in titles:
                informative=parent.content.lower()=='informative findings'
                recommendation=parent.content.lower()=='optimization'
                raw='Informative' if informative else None
                out.append(Candidate(l.start,title,raw,method='unnumbered_toc_linked_detail',confidence=.92,
                    record_kind='recommendation' if recommendation else 'formal_finding',
                    evidence={'severity_basis':'printed_informative_section' if informative else 'unprinted_unknown',
                              'index_span':dict(start=titles[title].start,end=titles[title].end,text=titles[title].text),
                              'section':parent.content}))
                break
    for i,c in enumerate(out):
        c.end=out[i+1].start if i+1<len(out) else len(report.text)
        stop=next((l.start for l in report.lines if c.start<l.start<c.end and not l.excluded and l.content=='Appendix'),None)
        if stop is not None: c.end=stop
    return out


def parse_milestone(report):
    return []  # Delivered verification work and tool exploration, not issue cards.


def read_status(report, candidates):
    """Prefer a labelled status narrative over its earlier summary badge."""
    from core import status
    from status_sentences import sentence_span
    from bisect import bisect_right
    line_starts=[l.start for l in report.lines]
    def eligible(offset):
        line=report.lines[max(0,bisect_right(line_starts,offset)-1)]
        return not line.code or report.meta.get('file_format')=='pdf'
    token = (r'Partially (?:addressed by client|fixed|resolved)|Not addressed by client|'
             r'Not to be fixed|Addressed by client|Acknowledged by client|'
             r'Not (?:fixed|resolved|addressed)|Fix implemented|Fixed|Resolved|Addressed|Acknowledged|Open|Pending|Unresolved')
    for c in candidates:
        c.evidence['status_reader_complete'] = True
        body = report.text[c.start:c.end]
        matches = []
        # Do not allow Status to cross a blank section boundary into a later
        # recommendation, and never match arbitrary occurrences in narrative.
        for m in re.finditer(r'(?mi)^[ \t\f]*Status[ \t]*:?[ \t\u200b]*(?:\n[ \t\u200b]*){0,5}(' + token + r'|Solved)\b', body):
            if not eligible(c.start+m.start(1)): continue
            matches.append((m, 'labelled_status_section'))
        # Legacy reports state remediation in prose under an explicit Status
        # heading. Keep the full first sentence rather than a detached verb.
        for m in re.finditer(r'(?mi)^[ \t\f]*Status[ \t]*:?[ \t\u200b]*(?:\n[ \t\u200b]*){0,5}([^\n]+)', body):
            if not eligible(c.start+m.start(1)): continue
            a,b=sentence_span(body,m.start(1))
            raw = body[a:b]
            if _normalized_status(raw) and not re.search(r'\b(?:should|could|recommend|if|unless)\b', raw, re.I):
                # Keep the whole source sentence, including wrapped PR/commit
                # references, instead of only its first printed line.
                full=re.match(r'([\s\S]+)',body[a:b])
                matches.append((full, 'explicit_status_response_sentence', a))
        if not matches:
            # Legacy Status sections may begin with an explanatory paragraph
            # and state the actual outcome later. Read explicit assertions
            # within that section, never recommendation/description prose.
            for section in re.finditer(r'(?mi)^[ \t\f]*Status[ \t]*:?[ \t]*\n',body):
                tail=body[section.end():]
                stop=re.search(r'(?mi)^[ \t]*(?:Description|Recommendations?|Appendix|Informative findings|Notable Findings)\s*:?\s*$',tail)
                response=tail[:stop.start() if stop else len(tail)]
                patterns=(
                    r'\b(?:This|The) (?:issue|finding|bug)\s+(?:has been|was|is)\s+(partially (?:fixed|resolved|addressed)|not (?:fixed|resolved|addressed)|fixed|resolved|addressed|acknowledged)\b',
                    r'\b(fully aware of the issue|Taken into consideration|Currently left as is)\b',
                    r'\b((?:The client|The [A-Z][A-Za-z]+ Foundation) is aware of this(?: discrepancy)?)\b',
                    r'\b((?:A check|The check)[^.\n]{0,160}has been introduced)\b',
                    r'\b(?:We|The client|The team)\s+(?:has|have)\s+(fixed|resolved|addressed|acknowledged)\b',
                )
                for pattern in patterns:
                    for hit in re.finditer(pattern,response,re.I):
                        if not eligible(c.start+section.end()+hit.start(1)):continue
                        # Adapt an offset match without rewriting the source.
                        start=c.start+section.end()+hit.start(1);end=c.start+section.end()+hit.end(1)
                        c.status_raw=report.text[start:end]
                        c.normalized_status=_normalized_status(c.status_raw) or status(c.status_raw)
                        c.evidence['status_evidence']=dict(raw=c.status_raw,text=c.status_raw,start=start,end=end,
                            basis='legacy_status_section_assertion',profile='runtime-verification')
            if c.status_raw and c.evidence.get('status_evidence',{}).get('basis')=='legacy_status_section_assertion':continue
        if not matches:
            for m in re.finditer(r'\b(Partially addressed by client|Not addressed by client|Addressed by client|Acknowledged by client)\b', body[:1800], re.I):
                if not eligible(c.start+m.start(1)): continue
                matches.append((m, 'metadata_client_response_badge'))
        if matches:
            item=matches[-1];m,basis=item[:2];offset=item[2] if len(item)>2 else 0
            raw = m[1]
            start, end = c.start+offset+m.start(1), c.start+offset+m.end(1)
        elif c.record_kind == 'summary_excerpt':
            continue  # Tracker row statuses can wrap across columns.
        else:
            c.status_raw = None; c.normalized_status = None
            continue
        c.status_raw = raw
        c.normalized_status = _normalized_status(raw) or status(raw)
        # Keep the shared fixed/resolved distinction for exact source labels.
        if raw.lower() == 'fixed': c.normalized_status = 'fixed'
        c.evidence['status_evidence'] = dict(raw=raw, start=start, end=end,
            text=report.text[start:end], basis=basis, profile='runtime-verification')


def read_named_status(report, candidates):
    read_status(report, candidates)
    for c in candidates:
        if c.status_raw: continue
        body=report.text[c.start:c.end]
        for m in re.finditer(r'(?m)^Response:\s*([^\n]+(?:\n(?!\s*\n)[^\n]+){0,3})', body):
            # Attributed completed actions only. An intention or recommended
            # change in the response does not establish remediation.
            raw=m[1]
            if re.search(r'\b(?:should|could|will|intends?|recommend|not fixed)\b',raw,re.I): continue
            if not re.search(r'\b(?:fixed|has been addressed|applied .{0,100}to resolve)\b',raw,re.I): continue
            start,end=c.start+m.start(1),c.start+m.end(1)
            c.status_raw=raw; c.normalized_status='fixed' if re.search(r'\bfixed\b',raw,re.I) else 'resolved'
            c.evidence['status_evidence']=dict(raw=raw,start=start,end=end,text=report.text[start:end],
                basis='attributed_resolution_response',profile='runtime-verification')


from variants import Variant, Fingerprint, dispatch

VARIANTS = (
    Variant('runtime-verification/v2024_bracket_cards', Fingerprint((
        ('bracketed_native_id', r'^\s*\[(?:[ABCDF]I?|TSI?)-?\d{1,3}\]\s+\S', 14),
        ('severity_metadata', r'\bSeverity\s*:', 2)), ('2024', '2026')),
        parse_bracket_cards, ('rv_brackets',), read_status),
    Variant('runtime-verification/v2021_letter_cards', Fingerprint((
        ('letter_id_title', r'^\s*[ABCDF]\d{1,3}[.:]\s*\S', 12),
        ('finding_sections', r'^\s*(?:Findings|Notable Findings|Informative Findings)\s*$', 2)), ('2021', '2026')),
        parse_letter_cards, ('rv_letters',), read_status),
    Variant('runtime-verification/v2022_risk_cards', Fingerprint((
        ('risk_metadata', r'^[ \t]*[\[(]?[ \t]*Severity\s*:', 7),
        ('status_heading', r'^[ \t]*Status\s*:', 1)), ('2022', '2026')),
        parse_risk_cards, ('rv_risk',), read_status),
    Variant('runtime-verification/v2019_indexed_findings', Fingerprint((
        ('legacy_finding_index', r'^\s*List of Findings(?: in the second round)?\s*$', 8),
        ('minor_finding_section', r'^\s*Minor Findings\s*$', 8)), ('2019', '2022')),
        parse_legacy_index, ('rv_index', 'rv_minor'), read_status),
    Variant('runtime-verification/v2022_tracker', Fingerprint((
        ('tracker_columns', r'^\s*Issue\s+Category\s+Status', 9),), ('2022', '2022')),
        parse_tracker, ('rv_tracker',), read_status),
    Variant('runtime-verification/v2021_design_review', Fingerprint((
        ('design_review', r'Design Review|design flaw or a security vulnerability', 6),
        ('findings_section', r'^\s*Findings\s*$', 2)), ('2021', '2024')),
        parse_design, ('rv_design',), read_status),
    Variant('runtime-verification/v2022_specification_attachments', Fingerprint((
        ('specification_attachment', r'helper module for (?:the main spec of )?tinyman2|(?:Structural |Partial )?Alloy specification|Audit Report Appendix', 10),
        ('generated_specification', r'^\s*(?:module tinyman|open tinyman)|all_transactions_for|assert\s+\w+\s*\{', 7)), ('2021', '2023')),
        parse_specification, ('rv_specification',), read_status,
        notes='Generated Alloy/property attachments; no remediation status is asserted for proven properties.'),
    Variant('runtime-verification/v2026_verification_milestones', Fingerprint((
        ('rust_verification_tooling', r'Rust Verification (?:with Hax|Through Lean)|Tooling Investigation', 10),
        ('milestone_work', r'Implementation and Verification.*Milestone|Discovery Report.*Milestone', 7)), ('2026', '2026')),
        parse_milestone, ('rv_milestone',), read_status),
    Variant('runtime-verification/v2022_narrative_reviews', Fingerprint((
        ('narrative_review', r'Security Review Report|Suggestions and Issues', 8),), ('2022', '2023')),
        parse_narrative, ('rv_narrative',), read_status,
        notes='Ungraded narrative exploit/design reviews; remaining non-card narratives are coverage gaps.'),
    Variant('runtime-verification/v2021_named_sections', Fingerprint((
        ('informative_section', r'^\s*Informative Findings\s*$', 3),
        ('optimization_section', r'^\s*Optimization\s*$', 3),
        ('native_safety_classification', r'\((?:Potential )?Safety Violation\)|\(Race Condition\)', 4)), ('2021', '2022')),
        parse_named_sections, ('rv_named',), read_named_status,
        notes='Early unnumbered Tezos narratives; actual body headings matched against the source TOC.'),
    Variant('runtime-verification/v2018_verification_papers', Fingerprint((
        ('formal_report', r'Formal Verification|Verification Report|Formalizing|Tooling Investigation', 6),
        ('paper_abstract', r'^\s*Abstract\b', 6),
        ('executable_model', r'An Executable K Model|Formalizing Correct.By.Construction', 6),
        ('theorem', r'Theorem|Lemma|Proof of Neutrality', 2)), ('2018', '2026')),
        parse_verification, ('rv_proof',), read_status,
        notes='Proof papers and FV summaries; zero finding coverage is not a clean-audit assertion.'),
)


def parse(report):
    return dispatch(report, VARIANTS)
