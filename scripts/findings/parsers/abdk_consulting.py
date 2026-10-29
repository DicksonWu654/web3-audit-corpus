"""ABDK legacy issue lists, explicit CVF cards and severity-parent CVF cards.

2017–20 issues use section-local numeric/bullet lists, frequently without risk
labels or titles. 2020–22 cards use explicit Severity/Status fields. Later
cards inherit Critical/Major/Moderate/Minor/Recommendations from parent
sections; INFO on a card is a status, never its severity. Spaced PDF letters
are removed for matching only. Combined CVF-2,3 IDs remain one detail card
with both printed members retained for sequence checks. Description/recommendation excerpts provide
an explicitly labelled fallback when no finding title was printed.

Legacy ungraded issues remain unknown, rather than receiving a guessed risk.
Revised reports can intentionally omit IDs (LemmaLabs/Reya), and zkLink
explicitly documents removed/downgraded IDs in its changelog. No gaps are
filled. Chart-only unlabeled numbers are not comparable summaries. Numeric statements
in Our findings and clearly labelled Active/Fixed tables are independent totals.
"""
from core import SeverityLookup, severity, Candidate, clean, is_toc, status
from variants import Variant, Fingerprint
from text_patterns import index_line
import re

DESCRIPTION = "ABDK section-local issue lists and CVF detail cards across explicit-field and severity-section eras"
REVIEWED_SHA256 = (
    "006d32b84015cff8dcbdf978572d3c077e900271dc43e10d403ec4273c486383",
    "cde5e9749d13abbe5e3cf8f1641951cd4c112c00a887920618fe476c4446af9a",
    "77f57deddf4f2376d3ad5d7aa0afa3c9485ff1f0c2c91cf4536f58ecd5945b03",
    "3c6f9944684f183116a70ae0c04fb21f6d3025d12b2c4e667cb232216308f1ae",
    "2704d71f2cfe59b196cd715b2995b3ab3f954c410bf8dc9997ac64d1149a4b7c",
    "f8eb506a0cebe55fa9fcf91643bde1effa07efc4528200e02eb5993ca3f85a09",
    "23df951f08ccbc556456574bd0ffe829f4fe32f2075ea35b6d93352a1fbca832",
    "6edcfaf5c695cb671b74a12f60959d62a0b719f170e76e6cbc3947451ac55920",
    "24579458607115c5651aaa5a54d1677d6686fbdadfe56b33d997fe84b22f6e3c",
    "f779359d182792b54519777adda306c28c8f8098cafccadf83d08086971a5c4e",
    "f79d17d665e63d5eda00d0bb7508daad6f491dc625c8ac8a28d0e6ff206ffac5",
    "ab227208a51964a2ae89bc320045c16db333020332302b5c93b9fe1cb171abec",
    "d397b041e831764eddb6cdd39e414abc823205878406e5a398897f6e714cea63",
    "a4d9de345e660d81285358c2699eda71ffc9e365bc970df019a6995bfe0700f4",
    "cf375c29ebe38e98ed064645b62ef507d46abd7162d6c984305e74e497717f89",
    "a58eec8d0689b0deec53a53214adb5de2b73bf7bede99d0e75dea1be8aa6ed76",
    "9a976f3dd709329252f3eaacacb936d4367ebea6ed68c21957b1a4f77741dbe6",
    "7f50e1fe12634b28da958838a39b44f68e62e1b50f6aaa30d7fcc9ea13ddee43",
    "1c76d52dbcf0ec5b16bc7b41f871f4df4080135d8cd948a1a829c1113af89da4",
)
REVIEW_NOTES = "2017 Hive/eSports; 2018 Set; 2019 Wallet; 2021 Matter Labs/Maker/Gambit; 2021–22 CVF cards; 2022–24 wide-letter CVF sections; 2025 INFO/FIXED cards."
RISK = SeverityLookup('abdk-consulting', ('critical', 'major', 'moderate', 'minor', 'recommendations'))
RISK_WORD = r"(Critical|Major|Moderate|Minor|Recommendations)"
CVF = re.compile(r"^(?:(\d+(?:\.\d+)+)\s+)?(C\s*V\s*F\s*[-–]\s*\d(?:[ \t]*\d)*(?:[ \t]*[.][ \t]*\d(?:[ \t]*\d)*)*(?:[ \t]*,[ \t]*\d(?:[ \t]*\d)*)*)[ \t]*[.]?\s*(.*?)\s*$", re.I)


def compact(value):
    return re.sub(r"\s+", "", value).replace("\u200b", "")


def word(value):
    return r"\s*".join(re.escape(x) for x in value)


def excerpt(report, start, end):
    """Use source narrative without inventing an absent printed heading."""
    body = report.text[start:end]
    for label in ("Description", "ABDK Comment", "Recommendation"):
        pattern = re.compile(r"(?m)^\s*" + word(label) + r"\b[ \t:]*([^\n]+)", re.I)
        match = pattern.search(body)
        if match:
            value = clean(match[1])
            value = re.split(r"(?<=\.)\s+(?=[A-Z])", value)[0]
            return value[:700], label.lower() + "_excerpt"
    return None, "absent_in_source"


def parse(report):
    """Compatibility entrypoint; formal dispatch uses the era functions below."""
    return _cvf_cards(report) or legacy(report)


def _cvf_cards(report, mode=None):
    out, current, section_starts = [], None, []
    for i, line in enumerate(report.lines):
        if is_toc(line):
            continue
        value = clean(line.content)
        squeezed = compact(value)
        parent = re.fullmatch(r"\d+(Critical|Major|Moderate|Minor)(?:Issues|Flaws)|\d+(Recommendations)", squeezed, re.I)
        if parent:
            key = (parent[1] or parent[2]).lower()
            # Preserve the source's label (including letter spacing).
            raw = re.sub(r"^\d+\s*", "", value)
            raw = re.sub(word("Issues") + r"$|" + word("Flaws") + r"$", "", raw, flags=re.I).strip()
            current = raw, RISK[key]
            section_starts.append(line.start)
            continue
        match = CVF.fullmatch(value)
        if not match:
            continue
        suffix = match[3]
        following = []
        for nxt in report.lines[i + 1:i + 18]:
            if CVF.fullmatch(clean(nxt.content)):
                break
            following.append(nxt.text)
        tail = "\n".join(following)
        sev = re.search(word("Severity") + r"\s*:?[ \t]*(" + "|".join(word(w) for w in ("Critical", "Major", "Moderate", "Minor")) + r")\b", tail, re.I)
        status_match = re.fullmatch(r"(?:FIXED|INFO|OPENED|OPEN|CLOSED|ACKNOWLEDGED|RESOLVED|PARTIALLYFIXED|PARTIALLYRESOLVED|REPORTED|SKIPPED|REPLIED|RULEDOUT)", compact(suffix), re.I)
        if sev and mode != 'parent':
            raw, norm = sev[1], RISK[compact(sev[1]).lower()]
        elif current and status_match and mode != 'explicit':
            raw, norm = current
        else:
            continue
        stat = re.search(word("Status") + r"\s*:?[ \t]*([^•\n]+)", tail, re.I)
        title = suffix if suffix and not status_match else None
        printed_id = compact(match[2]).upper().replace('–', '-')
        out.append(Candidate(line.start, title, raw, printed_id, severity(raw, report.firm),
                             status_raw=suffix if status_match else clean(stat[1]) if stat else None,
                             method="abdk-cvf-detail", confidence=.96,
                             evidence={"severity_basis": "explicit_field" if sev else "severity_parent_section",
                                       "title_basis": "printed_heading" if title else "pending_excerpt",
                                       "publisher_finding_ids": ["CVF-" + part for part in printed_id[4:].split(",")],
                                       "sequence_group": printed_id.rsplit(".", 1)[0] if "." in printed_id else "CVF"}))
    for i, row in enumerate(out):
        end = out[i + 1].start if i + 1 < len(out) else len(report.text)
        end = min([end] + [x for x in section_starts if row.start < x < end])
        # Contact pages and appendices do not belong to the last detail.
        stop = re.search(r"(?mi)^\s*(?:Appendix\b|dmitry@abdkconsulting[.]com)", report.text[row.start:end])
        if stop:
            end = row.start + stop.start()
        row.end = end
        if row.status_raw:
            row.normalized_status = {"fixed": "fixed", "info": "info", "reported": "open", "opened": "open", "open": "open", "resolved": "resolved", "acknowledged": "acknowledged", "partiallyfixed": "partial"}.get(compact(row.status_raw).lower())
        if not row.title:
            row.title, row.evidence["title_basis"] = excerpt(report, row.start, end)
    return out


def legacy(report):
    """Legacy numbered issue lists: one row per printed item, not per category."""
    lines = report.lines
    heads = []
    for i, line in enumerate(lines):
        if is_toc(line):
            continue
        match = re.match(r"^(\d+(?:\.\d+)+)[.]?\s+(.+)", line.content)
        if match and not re.search(r"\.{3}|\s{4,}\d+$", line.text):
            heads.append((i, match[1], match[2], False))
            continue
        parent = re.match(r'^(\d+)[.]\s+(.+)', line.content)
        next_text = next((q.content for q in lines[i+1:i+8] if q.content), '')
        if parent and re.match(r'In this section we describe issues', next_text, re.I):
            heads.append((i, parent[1], parent[2], True))
    out = []
    for n, (i, section, title, parent_scope) in enumerate(heads):
        end_i = heads[n + 1][0] if n + 1 < len(heads) else len(lines)
        # A following top-level contract heading is a boundary, never another
        # numbered issue inside the preceding section's local item namespace.
        indent = len(lines[i].text)-len(lines[i].text.lstrip())
        parent_boundaries = []
        next_scope = heads[n+1][1].split('.')[0] if n+1 < len(heads) else None
        for j in range(i+1, end_i):
            leading = len(lines[j].text)-len(lines[j].text.lstrip())
            parent = re.match(r'^(\d+)[.]\s+([A-Z].*)', lines[j].content)
            if leading <= indent and parent and parent[1] == next_scope and next_scope != section.split('.')[0]:
                parent_boundaries.append(j)
        if parent_boundaries:
            end_i = parent_boundaries[-1]
        body_start = lines[i].start
        end = lines[end_i].start if end_i < len(lines) else len(report.text)
        stop = re.search(r"(?mi)^\s*(?:\d+[.]?\s+)?(?:Our Recommendations|Summary|Conclusion|Appendix)\s*$", report.text[body_start:end])
        if stop:
            end = body_start + stop.start()
        block = report.text[body_start:end]
        if re.search(r"^(?:About ABDK|Disclaimer|Methodology|Introduction|Project scope|Version|Contact)\b", title, re.I):
            continue
        # These headings describe real issues, but many have no severity scale.
        raw_match = re.search(r"\b(Critical|Major|Moderate|Minor)\b", title, re.I)
        if not raw_match:
            raw_match = re.search(r"This section lists[^.]{0,180}\b(minor) issues", clean(block[:600]), re.I)
        raw = raw_match[1] if raw_match else None
        norm = RISK[raw.lower()] if raw else "unknown"
        items = [(j, re.match(r"^\s*(\d+)[.)]\s+(.+)", lines[j].text)) for j in range(i + 1, end_i) if lines[j].start < end]
        items = [(j, m) for j, m in items if m]
        # A singular issue section may contain numbered exploit steps rather
        # than independent issues. Keep the narrative as one printed finding.
        single_issue = bool(re.search(r'\b(?:Issue|Flaw)\s*$', title, re.I))
        if items and not single_issue:
            for k, (j, m) in enumerate(items):
                item_end = lines[items[k + 1][0]].start if k + 1 < len(items) else end
                # Parent contract headings between issue subsections are not body.
                parent = re.search(r"(?m)^\s*\d+[.]\s+[A-Z][^\n]+\n", report.text[lines[j].end:item_end])
                if parent:
                    item_end = lines[j].end + parent.start()
                out.append(Candidate(lines[j].start, clean(m[2]), raw, m[1], severity(raw, report.firm), end=item_end,
                                     method="abdk-legacy-list", confidence=.86,
                                     evidence={"severity_basis": "severity_parent_section" if raw else "absent_in_source",
                                               "section": section, "sequence_group": section, "container_id": section,
                                               "publisher_explicit_short_detail": True,
                                               "title_basis": "list_item_excerpt"}))
        elif not parent_scope and len(block.strip()) > len(title) + 50:
            out.append(Candidate(body_start, title, raw, section, severity(raw, report.firm), end=end,
                                 method="abdk-legacy-section", confidence=.85,
                                 evidence={"severity_basis": "severity_parent_section" if raw else "absent_in_source",
                                           "section": section, "sequence_group": "sections", "title_basis": "printed_heading"}))
    return out or bullet_sections(report)


def bullet_sections(report):
    """Untitled bullet findings in the older circuit/audit-summary layout."""
    lines = report.lines
    heads = []
    for i, line in enumerate(lines):
        match = re.fullmatch(r"(\d+)[.]\s+(.+)", clean(line.content))
        if match:
            heads.append((i, match[1], match[2]))
    out = []
    for k, (i, section, title) in enumerate(heads):
        if not re.search(r"Issues?|Phase (?:One|Two|Three)", title, re.I):
            continue
        end_i = heads[k + 1][0] if k + 1 < len(heads) else len(lines)
        bullets = [(j, re.match(r"^\s*[●•]\s+(.+)", lines[j].text)) for j in range(i + 1, end_i)]
        bullets = [(j, m) for j, m in bullets if m]
        heading_risk = re.search(r"\b(Critical|Major|Moderate|Minor)\b", title, re.I)
        raw = heading_risk[1] if heading_risk else None
        for n, (j, match) in enumerate(bullets):
            end = lines[bullets[n + 1][0]].start if n + 1 < len(bullets) else lines[end_i].start if end_i < len(lines) else len(report.text)
            fixed = bool(re.search(r"Fixed Issues", title, re.I))
            out.append(Candidate(lines[j].start, clean(match[1]), raw, None, severity(raw, report.firm), end=end,
                                 status_raw="Fixed" if fixed else None, normalized_status="fixed" if fixed else None,
                                 method="abdk-legacy-bullet", confidence=.83,
                                 evidence={"severity_basis": "severity_parent_section" if raw else "absent_in_source",
                                           "section": section, "title_basis": "list_item_excerpt", "sequence_group": "unlabelled"}))
    return out


def printed_counts(report):
    """Read numeric prose and labelled Active/Fixed tables independently."""
    for page in report.meta["pages"]:
        source = page["text"]
        squashed = compact(source)
        if not re.search(r"^\d+Ourfindings", squashed, re.I):
            continue
        match = re.search(r"Wefound([^.]*)[.]", squashed, re.I)
        prose = {RISK[r.lower()]: int(n) for n, r in re.findall(r"(\d+)(critical|major|moderate|minor)", match[1], re.I)} if match else {}
        table, previous = {}, []
        if "Active" in source and "Fixed" in source:
            for line in source.splitlines():
                cells = [cell for cell in re.split(r"\s{3,}", line.strip()) if cell]
                if not cells:
                    continue
                if cells[0].lower() in RISK:
                    values = [compact(cell) for cell in cells[1:]]
                    if len(values) == 1 and values[0].isdigit():
                        # Critical's active count is sometimes printed above
                        # its label, with Severity/Fixed between the two.
                        above = next((compact(x) for x in reversed(previous[-5:]) if compact(x).isdigit()), None)
                        if above is not None:
                            values.insert(0, above)
                    if len(values) == 2 and all(x.isdigit() for x in values):
                        table[RISK[cells[0].lower()]] = sum(map(int, values))
                previous.append(line.strip())
        counts = table if len(table) >= 2 else prose
        if not counts:
            continue
        proof = [{"page": page["page"], "start": page["start"], "end": page["end"], "text": source}]
        result = {"counts": counts, "basis": "printed_active_plus_fixed_table" if counts is table else "printed_our_findings_numeric_statement", "evidence": proof}
        conflict = any(k in table and table[k] != n for k, n in prose.items())
        total = re.search(r"Fixed\d+outof(\d+)issues", squashed, re.I)
        # Some revised reports assert more critical+major issues than their
        # independently printed total permits. This is source ambiguity.
        impossible = bool(total and sum(prose.values()) > int(total[1]))
        if conflict or impossible:
            result.update(ambiguous=True, prose_counts=prose, printed_total=int(total[1]) if total else None,
                          ambiguity_reason="Conflicting printed aggregate statements/table; no parsed finding counts were used.")
        return result
    return None


def sequence_groups(report, candidates):
    groups = {}
    for row in candidates:
        group = groups.setdefault(row.evidence.get("sequence_group", "CVF"), [])
        group.extend(row.evidence.get("publisher_finding_ids", [row.printed_id]))
    return list(groups.values())


def section_lists(report):
    return legacy(report)


def issue_bullets(report):
    return bullet_sections(report)


def explicit_cvf(report):
    return _cvf_cards(report, 'explicit')


def grouped_cvf(report):
    return _cvf_cards(report, 'parent')


def protocol_review(report):
    """One ungraded attack described as prose rather than numbered CVF cards."""
    head = next((l for l in report.lines if re.fullmatch(r'2\s+Our attack in brief', l.content, re.I)), None)
    end = next((l.start for l in report.lines if head and l.start > head.start and re.fullmatch(r'5\s+Lessons Learned', l.content, re.I)), len(report.text))
    return [Candidate(head.start, 'Our attack in brief', end=end, method='abdk-protocol-attack-narrative', confidence=.9,
                      evidence={'severity_basis': 'absent_in_source', 'title_basis': 'printed_heading'})] if head else []


def engagement_summary(report):
    # This publication links to the substantive reports and summarizes rounds;
    # it does not enumerate recoverable individual findings.
    return []


def clean_audit(report):
    """A complete audit layout with an explicitly empty findings section."""
    return []


STATUS_WORDS = ('Partially Fixed', 'Partially Resolved', 'Acknowledged', 'Ruled out',
                'Resolved', 'Reported', 'Opened', 'Skipped', 'Replied', 'Closed', 'Fixed', 'Open', 'Info')
STATUS_PATTERN = '(?:' + '|'.join(word(w) for w in STATUS_WORDS) + ')'


def _status_receipt(report, row, match, offset, basis):
    raw = match[1]
    row.status_raw = raw
    row.normalized_status = {'opened': 'open', 'reported': 'open', 'ruledout': 'invalid',
                             'partiallyfixed': 'partial', 'partiallyresolved': 'partial'}.get(compact(raw).lower(), status(compact(raw)))
    a, b = offset + match.start(1), offset + match.end(1)
    row.evidence['status_evidence'] = {'raw': raw, 'start': a, 'end': b, 'text': report.text[a:b],
                                      'basis': basis, 'profile': 'abdk-consulting'}


def cvf_status(report, candidates):
    """Prefer the card's printed status, then an unambiguous ID-linked table.

    Empty legacy Status columns often put the actual value in the inventory
    table. Client Comment Info is not itself a substitute for that field.
    """
    index = {}
    for line in report.lines:
        if index_line(line.text, padded=False):
            continue
        m = re.match(r'^\s*(C\s*V\s*F\s*-\s*\d+)\s+.*?\b(' + STATUS_PATTERN + r')\s*$', line.text, re.I)
        if m:
            # Require the independently printed severity/category columns.
            between = line.text[m.end(1):m.start(2)]
            if re.search(word('Critical')+'|'+word('Major')+'|'+word('Moderate')+'|'+word('Minor'), between, re.I):
                index.setdefault(compact(m[1]).upper(), []).append((m[2], line.start+m.start(2), line.start+m.end(2)))
    for c in candidates:
        body = report.text[c.start:c.end]
        header = re.split(word('Description')+'|'+word('ABDK Comment')+'|'+word('Recommendation'), body, maxsplit=1, flags=re.I)[0]
        # Inline badges are authoritative in the grouped layout. Limit to the
        # first heading so a continuation/reference cannot donate its status.
        first_line = body.splitlines()[0] if body.splitlines() else ''
        badge = re.search(r'(?:C\s*V\s*F\s*-\s*[\d\s.,]+)\s+(' + STATUS_PATTERN + r')\s*$', first_line, re.I)
        field = re.search(word('Status') + r'\s*:?[ \t]*(' + STATUS_PATTERN + r')\b', header, re.I)
        selected = badge or field
        if selected:
            _status_receipt(report, c, selected, c.start, 'printed_cvf_badge' if badge else 'labelled_status_field')
            continue
        claims = index.get(c.printed_id, [])
        distinct = {compact(raw).lower() for raw, _, _ in claims}
        if len(distinct) == 1:
            raw, a, b = claims[-1]
            c.status_raw = raw
            c.normalized_status = {'opened': 'open', 'reported': 'open', 'ruledout': 'invalid'}.get(compact(raw).lower(), status(compact(raw)))
            c.evidence['status_evidence'] = {'raw': raw, 'start': a, 'end': b, 'text': report.text[a:b],
                                            'basis': 'printed_id_status_table', 'profile': 'abdk-consulting'}
        else:
            # Preserve genuinely absent status, rather than a parser fragment.
            c.status_raw = None
            c.normalized_status = None
            if claims:
                c.evidence['status_conflict'] = True


def legacy_status(report, candidates):
    """Read explicit labels or the source's fixed/unresolved issue headings."""
    for c in candidates:
        body = report.text[c.start:c.end]
        labelled = re.search(r'(?im)^\s*(?:Status|Resolution Status)\s*:\s*(' + STATUS_PATTERN + r')\b', body)
        if labelled:
            _status_receipt(report, c, labelled, c.start, 'labelled_status_field')
        elif (resolution := re.search(r'(?im)^\s*(Resolved) as\s*:', body)):
            _status_receipt(report, c, resolution, c.start, 'publisher_resolved_as_section')
        else:
            section = c.evidence.get('section')
            # Numeric finding IDs repeat independently in each printed section.
            # Scope the heading lookup to the exact publisher section number.
            parent = list(re.finditer(r'(?im)^\s*'+re.escape(section)+r'[.]?\s+((?:Unresolved|Resolved|Unfixed|Fixed))\b[^\n]*$', report.text[:c.end])) if section else []
            if parent:
                _status_receipt(report, c, parent[-1], 0, 'issue_status_parent_section')
                if c.status_raw.casefold() == 'unfixed':
                    c.normalized_status = 'open'
            else:
                c.status_raw = None
                c.normalized_status = None


def protocol_status(report, candidates):
    legacy_status(report, candidates)


def summary_status(report, candidates):
    legacy_status(report, candidates)


def signature_word(value):
    return word(value).replace(r'\s*', r'[ \t]*')


CVF_SIGNATURE = r'C[ \t]*V[ \t]*F[ \t]*[-–][ \t]*\d+'
PARENT_SIGNATURE = r'^\s*\d+[ \t]*(?:' + '|'.join(signature_word(w) for w in ('Critical Issues', 'Major Issues', 'Moderate Issues', 'Minor Issues', 'Recommendations')) + r')[ \t]*$'
VARIANTS = (
    Variant('abdk-consulting/v2022_severity_groups', Fingerprint((
        ('cvf', CVF_SIGNATURE, 2), ('graded_parent', PARENT_SIGNATURE, 5),
        ('status_badge', CVF_SIGNATURE+r'[\d \t.,]*[ \t]+(?:'+signature_word('FIXED')+'|'+signature_word('INFO')+r')[ \t]*$', 3)), ('2022', '2026')),
        grouped_cvf, ('abdk_grouped', 'abdk_spaced_grouped'), cvf_status, notes='Severity parent plus CVF status badge; grouped and hierarchical IDs retained.'),
    Variant('abdk-consulting/v2020_explicit_cvf', Fingerprint((
        ('cvf', CVF_SIGNATURE, 3), ('severity_field', signature_word('Severity')+r'[ \t]*:?[ \t]*(?:'+ '|'.join(signature_word(w) for w in ('Critical', 'Major', 'Moderate', 'Minor')) +r')\b', 5)), ('2020', '2024')),
        explicit_cvf, ('abdk_explicit', 'abdk_empty_status_table'), cvf_status, notes='CVF metadata fields and independent ID/severity/category/status inventories.'),
    Variant('abdk-consulting/v2020_protocol_attack', Fingerprint((
        ('attack_section', r'^\s*2\s+Our attack in brief\s*$', 6), ('fix_section', r'^\s*4\s+Fix\s*$', 2)), ('2020', '2020')),
        protocol_review, ('abdk_protocol_attack',), protocol_status, notes='Ungraded narrative attack and proposed fixes; no invented remediation status.'),
    Variant('abdk-consulting/v2025_clean_audit', Fingerprint((
        ('findings_section', r'^\s*5\s+Our findings\s*$', 3), ('clean_result', r'No vulnerabilities have been found|We have not found any issues|No issues (?:were )?found', 5)), ('2025', '2026'),
        reject_signatures=(CVF_SIGNATURE,)), clean_audit, ('abdk_clean_audit',), summary_status,
        notes='Complete modern audit with an explicitly empty findings section; no detailed rows invented.'),
    Variant('abdk-consulting/v2020_engagement_summary', Fingerprint((
        ('phases', r'^\s*[123][.]\s+Phase [123]\s*$', 5), ('linked_reports', r'no security\s+issues left|did not prepare a new report', 3)), ('2020', '2020')),
        engagement_summary, ('abdk_engagement_summary',), summary_status, notes='Round summary with links; contains no individually enumerated findings.'),
    Variant('abdk-consulting/v2020_issue_bullets', Fingerprint((
        ('issue_phase_sections', r'^\s*\d+[.]\s+(?:[^\n]*(?:Issues?|Phase (?:One|Two|Three)))\s*$', 5), ('bullet', r'^\s*[●•]\s+', 2)), ('2019', '2021')),
        issue_bullets, ('abdk_bullets',), legacy_status, notes='Section-local untitled bullet findings; fixed-issue heading status retained.'),
    Variant('abdk-consulting/v2017_section_lists', Fingerprint((
        ('numbered_issue_sections', r'^\s*\d+(?:\.\d+)+\s+(?:[^\n]*(?:Issues?|Flaws|Contract|Review|Audit)|[A-Za-z][^\n]*)$', 5),
        ('review_vocabulary', r'ABDK|Our Recommendations|This section lists|We.ve been asked', 2)), ('2017', '2023')),
        section_lists, ('abdk_legacy_lists',), legacy_status, notes='Legacy section-local lists, including ungraded documentation and protocol findings.'),
)
