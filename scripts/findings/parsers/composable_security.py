"""Composable Security 2022 numeric cards and 2023+ commit-qualified ID cards."""
from __future__ import annotations

from collections import Counter, defaultdict
import re
from core import Candidate, clean, severity

DESCRIPTION = "Composable commit-qualified finding cards and legacy section cards, explicit severity/status, latest aggregate retest totals"
REVIEWED_SHA256 = (
    "0338a482f73f4ec016155f92667c5322569d63e7006c045f22c446dbf17a1d4f",
    "054d73122133a5976d53891551950a19006ba4e31ce008ee8dd359f17418e060",
    "12bc8c54632780f57bd4ea49e7741923e8e798bea5b015d62f406e75df5638cb",
    "29d979346140cb1525882b181a68865c5efc81b2d3fea2e2325a35f4624b8ddc",
    "4b5ad1124f396a1b2f276fd05700ac66d59c84665ed2d5b0bdd8a6de01577737",
    "6d27e40f6f892abb93ed0ea916280573ca99dbb4c8e9225de4955721b7496398",
    "6e6f53407a613bc7bb986c60edc0ab39aff5ae14de14c814a9bccc76a7244c6a",
    "901bf9054103b6b0556d79a186d7fa6aa900ed387dab03f841cce749af669a93",
    "99ca21781f65ba049ce69e144866e731dcec019b29d25a00eee3ccce89b6f38f",
    "a1f19d87802cd91da1fc5b1cce60b1f0d72cd2940e7a6c03bd688da7384f0ec4",
    "a44a8efcfbbc0c111dcc45042789dc0ec38b061319812219e281b676c5756cf6",
    "ae375535c4c227648f418a7248fbc8cbd29a920ca78cb9234ae68de2938fbe9c",
    "b10609c2af23308431909133b552fb696b16f3c271c420047d852f3c34ee450f",
    "b8815cd1ecc2d6830635c8f31e337bd4dc22b3485415980ce791b947545327f1",
    "b9394a1737ac7deb297666f726e6cf3495fe878789de7976b1b66d6521a6b6ff",
    "b969a411f42a0ecf16a4f9d94dbdf586d4a693113123e6d67943668adf07272f",
    "bedf4908f8d681ece4680baf18f3ee44425c8a23cf45a6e92476e333fdb48186",
    "d0ac97d638f313af4299a750395e52060119ad8a9a1fe5b3925184c6e5e600f7",
    "dd581b01154a9be9f039afb76428cecb33f24762c5e99b10fc5551cba7403a00",
    "e4a0dbed82a55d3aad53fd84691fc67c29c664cc86aaa1d55c8a1041aba45a99",
    "e5393bb0ba25c2bf018599ed5220b8a8e414e0307d0cdff58afa3a65669c8512",
    "e80181bc3399e997fe7873482e81cb3c995b0834b2e8199b63581087fc73ba4f",
    "eb0859e4d53af19eea36cc3088dcba14ccc1715a09c2b347d2344b5ec4085e33",
    "f0a8a2ee77406088aeb70c82287c4e495475d819e2a34bdfc21f97d41d589d2e",
    "fa677a55ecf97b28ac90487cc45196e7f97b8acf840f72bfd23e01a252ae34d0",
)

CONTROLS = re.compile("[\u202a-\u202e\u2066-\u2069]")
RISK = r"CRITICAL|HIGH|MEDIUM|LOW|MAJOR|MINOR|INFO"
STATE = r"PARTIALLY IMPLEMENTED|PARTIALLY FIXED|NOT IMPLEMENTED|ACKNOWLEDGED|IMPLEMENTED|FIXED|OPEN"
CARD = re.compile(r"^\[([A-Z0-9]+-[a-f0-9]+-[CHMLR]\d+)\]\s*(.*)", re.I)
OLD = re.compile(r"^([56]\.\d+)\.\s*(?:\[([^]]+)\]\s*)?(.+)")


def visible(value):
    return CONTROLS.sub("", value).strip()


def parse(report):
    starts = []
    for i, line in enumerate(report.lines):
        value = visible(line.content)
        if line.code or re.search(r"(?:\.\s*){4,}\s*\d+\s*$", value):
            continue
        modern, old = CARD.match(value), OLD.match(value)
        if modern:
            starts.append((i, modern[1], modern[2], False, None))
        elif old:
            starts.append((i, old[1], old[3], True, old[2]))
    out = []
    for n, (i, pid, title, legacy, rounds) in enumerate(starts):
        line = report.lines[i]
        limit = report.lines[starts[n + 1][0]].start if n + 1 < len(starts) else len(report.text)
        # Final cards end before risk-classification or long-term best-practice
        # appendices; neither is an additional finding.
        for following in report.lines[i + 1:]:
            if following.start >= limit:
                break
            if re.match(r"^[7-9]\.\s+(?:Impact on risk|Long.term|Contact|Recommendations)", visible(following.content), re.I):
                limit = following.start
                break
        chunk_lines = [l for l in report.lines[i + 1:] if l.start < limit]
        raw, state = None, None
        title_lines = [title]
        if legacy:
            # DIVA retest explanations can span a page before the original risk
            # metadata; require the actual labelled Severity field, never prose.
            for j, following in enumerate(chunk_lines):
                if visible(following.content) == "Severity":
                    label = next((visible(l.content) for l in chunk_lines[j + 1:] if visible(l.content)), "")
                    if re.fullmatch(RISK, label, re.I):
                        raw = label
                    break
            for following in chunk_lines:
                value = visible(following.content)
                if not value or value.startswith(("Severity", "Status")):
                    break
                title_lines.append(value)
            body = visible(report.text[line.start:limit])
            match = re.search(r"Status\s+\d{4}-\d{2}-\d{2}\s+(" + STATE.replace(" ", r"\s+") + r")\b", body, re.I)
            state = match[1] if match else None
        else:
            for following in chunk_lines[:8]:
                value = visible(following.content)
                match = re.fullmatch(r"(" + RISK + r")(?:\s+(" + STATE + r"))?", value, re.I)
                if match:
                    raw, state = match[1], match[2]
                    break
                if value:
                    title_lines.append(value)
        if not raw:
            continue  # TOC/narrative reference, not a card with risk metadata.
        out.append(Candidate(line.start, clean(" ".join(title_lines)), raw, pid,
                             end=limit, status_raw=state, method="legacy-section-card" if legacy else "commit-id-card",
                             confidence=.96, evidence={"severity_basis": "explicit_card_label", "round_labels": rounds}))
    return out


WORDS = {"zero": 0, "no": 0, "one": 1, "the": 1, "two": 2, "both": 2, "three": 3,
         "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10}
NUMBER = r"\d+|zero|no|one|the|two|both|three|four|five|six|seven|eight|nine|ten"


def number(value):
    return int(value) if value.isdigit() else WORDS[value.lower()]


def aggregate(text):
    """Interpret explicit aggregate prose only, never a finding-ID/card listing."""
    s = clean(visible(text))
    values = defaultdict(int)
    observed = set()
    patterns = (
        r"\b(" + NUMBER + r")\s+vulnerabilit(?:y|ies)\s+with\s+(?:a\s+)?(?:an?\s+)?(critical|high|medium|low|major|minor)\s+impact\s+on\s+risk\b",
        r"\b(?:all\s+)?\(?((?:" + NUMBER + r"))\)?\s+(critical|high|medium|low|major|minor)(?:\s+risk(?:\s+impact)?)?\s+vulnerabilit(?:y|ies)\b",
    )
    for pattern in patterns:
        for m in re.finditer(pattern, s, re.I):
            key = severity(m[2], 'composable-security'); values[key] += number(m[1]); observed.add(key)
    info_number = NUMBER.replace("|the", "")
    for m in re.finditer(r"\b(" + info_number + r")\s*(?:security\s+)?recommendations?\b", s, re.I):
        values["info"] += number(m[1]); observed.add("info")
    if re.search(r"\bThe security recommendation (?:has|was)\b", s, re.I):
        values["info"] += 1; observed.add("info")
    # Explicit printed zero statements can name more than one bucket.
    for m in re.finditer(r"\b(?:No|Neither)\s+(?:vulnerabilities\s+with\s+)?(critical|high|medium|low|major|minor)(?:\s+(?:or|nor|and)\s+(critical|high|medium|low|major|minor))?\s+(?:risk\s+impact|impact\s+on\s+risk|risk|impact)", s, re.I):
        for raw in (m[1], m[2]):
            if raw:
                key = severity(raw, 'composable-security'); observed.add(key)
    if re.search(r"\bNo vulnerabilities were identified\b", s, re.I):
        observed.update(("critical", "high", "medium", "low"))
    return {key: values[key] for key in observed}


def printed_counts(report):
    # The current/retest summary incorporates added/reclassified findings. Keep
    # its explicitly printed buckets; omitted buckets remain unasserted.
    normalized = CONTROLS.sub("", report.text)
    selections = (
        (r"The current status of (?:the )?detected issues is as follows:|Currently, the status of the identified issues is as follows:",
         "publisher_current_retest_aggregate_prose"),
        (r"The summary of findings is as follows:|Audit findings:|During the first round the following issues were identified:|The following results were reported:",
         "publisher_audit_aggregate_prose"),
    )
    for pattern, basis in selections:
        marker = re.search(pattern, normalized)
        if not marker:
            continue
        after = normalized[marker.end():]
        ending = re.search(r"\n\s*(?:\d+\.\d+\.\s+)?Scope\b|Composable Security recommends", after)
        end = marker.end() + (ending.start() if ending else min(len(after), 6500))
        counts = aggregate(normalized[marker.end():end])
        # A retest stating only that "all" items are fixed lacks numeric totals;
        # the earlier complete audit aggregate remains the comparable summary.
        if len(counts) >= 2:
            break
    else:
        return None
    # Convert normalized offsets back to original coordinates for auditable
    # evidence. Bidi controls are ignored only for matching.
    offsets = [i for i, c in enumerate(report.text) if not CONTROLS.fullmatch(c)]
    start_original = offsets[marker.start()]
    end_original = offsets[end - 1] + 1 if end else start_original
    return {"counts": counts, "basis": basis,
            "selection_note": "Latest explicit retest aggregates take precedence over earlier audit totals; absent buckets are not zero.",
            "evidence": [{"start": start_original, "end": end_original,
                          "text": report.text[start_original:end_original]}]}


def sequence_diagnostics(report, candidates):
    groups = defaultdict(list)
    for c in candidates:
        match = re.fullmatch(r"(.+-[CHMLR])(\d+)", c.printed_id or "", re.I)
        if match:
            groups[match[1]].append(int(match[2]))
        elif re.fullmatch(r"[56]\.\d+", c.printed_id or ""):
            prefix, n = c.printed_id.split("."); groups[prefix].append(int(n))
    if not groups:
        consultation = bool(re.search(r"Security consultation summary", report.text, re.I))
        return {"complete": None if consultation else False,
                "reason": "consultation_without_numbered_findings" if consultation else "no_finding_ids", "gaps": [], "duplicates": []}
    gaps, duplicates = [], []
    for prefix, values in groups.items():
        gaps += [f"{prefix}:{n}" for n in range(1, max(values) + 1) if n not in values]
        duplicates += [f"{prefix}:{n}" for n, count in Counter(values).items() if count > 1]
    return {"complete": not gaps and not duplicates, "reason": "printed_id_sequence", "gaps": gaps, "duplicates": duplicates}


from variants import Variant, Fingerprint
from parsers.group2_layouts import statuses

def parse_sections(report):return [c for c in parse(report) if c.method=='legacy-section-card']
def parse_commits(report):return [c for c in parse(report) if c.method=='commit-id-card']
def parse_consultation(report):
    report.layout_disposition={'reason':'consultation_scenarios_without_new_finding_cards',
        'basis':'Security consultation summary and covered scenarios; prior vulnerabilities and mitigation advice are not new graded findings'}
    return []
def status_sections(report,candidates):
    statuses(report,candidates,headings=True)
    # Legacy retest metadata prints Status, ISO date, then disposition.
    from parsers.group2_layouts import receipt,normalize
    for c in candidates:
        body=report.text[c.start:c.end]
        matches=list(re.finditer(r'Status\s+\d{4}-\d{2}-\d{2}\s+('+STATE.replace(' ',r'\s+')+r')\b',CONTROLS.sub('',body),re.I))
        if matches and c.status_raw:
            # Preserve raw source controls by locating the label in original text.
            raw=matches[-1][1];m=re.search(re.escape(raw),body,re.I)
            if m:receipt(report,c,m[0],c.start+m.start(),c.start+m.end(),'dated_retest_status',normalize(raw,report.firm))
def status_commits(report,candidates):statuses(report,candidates,headings=True,index_id=r'[A-Z0-9]+-[a-f0-9]+-[CHMLR]\d+')
def status_consultation(report,candidates):return None

VARIANTS=(
    Variant('composable-security/v2022_section_cards',Fingerprint((('legacy severity label',r'(?:^|\n)[ \t\u202a-\u202e\u2066-\u2069]*Severity[\u202a-\u202e\u2066-\u2069]*[ \t]*\n',4),('numeric card',r'[56]\.\d+\.[ \u202a-\u202e\u2066-\u2069]+(?:\[|[A-Z])',3)),('2022','2023')),parse_sections,('composable_sections',),status_sections,printed_counts,notes='Numeric section cards, including bidirectional PDF controls and dated retest statuses; original text coordinates are preserved.'),
    Variant('composable-security/v2023_commit_cards',Fingerprint((('commit ID',r'\[[A-Z0-9]+-[a-f0-9]+-[CHMLR]\d+\]',8),),('2023','2026')),parse_commits,('composable_commits',),status_commits,printed_counts,notes='Commit-qualified IDs with explicit severity/status badges; latest explicit retest aggregates remain separate from detail extraction.'),
    Variant('composable-security/v2025_consultation',Fingerprint((('consultation title',r'Security consultation summary',8),),('2025','2026')),parse_consultation,('composable_consultation',),status_consultation,printed_counts,notes='Consultation-only summaries without numbered finding cards; statuses are not inferred from consultation advice.'),
)
