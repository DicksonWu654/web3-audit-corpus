"""Independently read published aggregate counts; never derive them from parsed findings."""
import re
from collections import Counter
from core import SEV, SPACED_SEV, severity, severity_context


def printed_counts(report):
    with severity_context(report):
        return _printed_counts(report)


def _normalize_counts(report, counts):
    result = Counter()
    for raw, count in counts.items():
        result[severity(raw, report.firm)] += count
    return dict(result)


def _printed_counts(report):
    if report.native:
        source = report.native["report"].get("reportContent", {}).get("summary", {}).get("issues", {})
        keys = {"criticalRisk":"Critical", "highRisk":"High", "mediumRisk":"Medium", "lowRisk":"Low", "infoRisk":"Informational", "undetRisk":"Undetermined"}
        values = {severity(label, report.firm): int(source[k]) for k,label in keys.items() if k in source and str(source[k]).isdigit()}
        if len(values) >= 2:
            return {"counts": values, "basis": "publisher_report_json_summary", "evidence": [{"json_pointer": "/reportContent/summary/issues", "value": source}]}
    groups, current, evidence, last = [], {}, [], -100
    def usable(counts, proof):
        if len(counts) >= 2:
            return True
        if not proof:
            return False
        before = report.text[max(0,proof[0]["start"]-500):proof[0]["start"]]
        return bool(re.search(r"(?:Severity|Impact\s+Level)[^\n]{0,80}(?:Count|Amount|Number|Total|Findings)",before,re.I))
    # Contest section totals are independently printed aggregates even when the
    # high and medium sections are separated by hundreds of finding-body lines.
    section_values, section_evidence = {}, []
    for line in report.lines:
        m = re.fullmatch(r"(Critical|High|Medium|Low|Informational|Gas)\s+(?:Risk\s+)?(?:Findings|Issues)\s*\((\d+)\)", line.content, re.I)
        if m:
            key = m[1].casefold()
            section_values.setdefault(key, set()).add(int(m[2]))
            section_evidence.append({"page":line.page,"start":line.start,"end":line.end,"text":line.text})
    if section_values and all(len(v) == 1 for v in section_values.values()):
        return {"counts":_normalize_counts(report, {k:next(iter(v)) for k,v in section_values.items()}),"basis":"printed_contest_section_totals","evidence":section_evidence}
    # Summary tables normally occur near the front. C4 section headings may occur anywhere.
    for i, line in enumerate(report.lines):
        s = line.content.replace("**", "").strip(" |\t•-–■▪●")
        spaced = re.match(r"^("+SPACED_SEV+r")(?=\s*[:|\d])",s,re.I)
        if spaced:
            s = re.sub(r"\s+", "", spaced[1]) + s[spaced.end():]
        row = re.match(r"^(" + SEV + r")(?:\s*[-–]?\s*(?:Risk|Severity))?(?:\s+(?:Findings|Issues|Vulnerabilities))?\s*(?:[:|]\s*|\s+|\s*\(\s*)(\d{1,4})(?:\s*\)|\b)", s, re.I)
        proof_end=line.end
        bucket_override=None
        if not row:
            label=re.fullmatch(r"("+SEV+r")(?:\s+(?:Risk|Severity))?(?:\s+(?:Findings|Issues|Vulnerabilities))?",s,re.I)
            notes=re.fullmatch(r"Notes?\s*(?:&|and)\s*Additional Information",s,re.I)
            following=next((l for l in report.lines[i+1:i+5] if l.content),None)
            number=re.fullmatch(r"(\d{1,4})(?:\s*\(\d+\s+(?:resolved|fixed|acknowledged)\))?",following.content,re.I) if following else None
            if not ((label or notes) and number):
                continue
            raw=label[1] if label else s
            count=int(number[1])
            suffix=""
            proof_end=following.end
            bucket_override="info" if notes else None
        else:
            raw, count = row[1], int(row[2])
            suffix = s[row.end():]
        # Reject severity definitions with percentages, numbered explanations and scoring examples.
        if re.match(r"\s*[%.-]", suffix) or re.search(r"points?\b|deduct|example", suffix, re.I):
            continue
        # Only aggregate-looking suffixes: blank, numeric columns, chart labels or resolution counts.
        if suffix.strip() and not re.match(r"\s*(?:\|?\s*\d+|\(\d+\s+\w+|Low\b|Info\b|Access Controls\b|Data Validation\b|Category\b)", suffix, re.I):
            continue
        if severity(raw, report.firm) == "unknown" and raw.lower() not in {"unknown", "undetermined"}:
            continue
        bucket = raw.casefold()
        if i - last > 14 or bucket in current:
            if usable(current,evidence):
                groups.append((current, evidence))
            current, evidence = {}, []
        current[bucket] = count
        evidence.append({"page": line.page, "start": line.start, "end": proof_end, "text": report.text[line.start:proof_end]})
        last = i
    if usable(current,evidence):
        groups.append((current, evidence))
    # Horizontal tables: severity header row then matching integral count cells.
    for i, line in enumerate(report.lines[:-1]):
        labels = re.findall(r"\b(Critical|High|Medium|Low|Informational|Info|Gas|Undetermined)\b", line.content, re.I)
        if len(labels) < 3 or len(set(x.lower() for x in labels)) != len(labels):
            continue
        for nextline in report.lines[i+1:i+5]:
            s = nextline.content.strip().strip("|")
            if not s or re.fullmatch(r"[\s|:-]+", s):
                continue
            numbers = re.findall(r"\d+", s)
            residue = re.sub(r"\d+|\s|\||,", "", s)
            if len(numbers) == len(labels) and not residue:
                values = {k.casefold(): int(n) for k,n in zip(labels, numbers)}
                groups.append((values, [{"page":line.page,"start":line.start,"end":nextline.end,"text":report.text[line.start:nextline.end]}]))
            break
    if not groups:
        return None
    groups = [(_normalize_counts(report, counts), proof) for counts, proof in groups]
    # Prefer the table with the widest explicit severity coverage, then earliest position.
    groups.sort(key=(lambda g:g[1][0]["start"]) if report.firm=="chainsecurity" else (lambda g:(-len(g[0]),g[1][0]["start"])))
    counts, proof = groups[0]
    distinct = [g for g in groups if len(g[0]) == len(counts) and set(g[0]) == set(counts) and g[0] != counts]
    if distinct and report.firm == "chainsecurity":
        return {"counts":counts,"basis":"printed_front_overview_table","evidence":proof,
                "later_subset_tables":[{"counts":c,"evidence":e} for c,e in distinct],
                "selection_note":"Front overview includes resolved findings; later open-findings tables count a subset."}
    if distinct:
        return {"counts": counts, "basis":"printed_aggregate_table", "evidence":proof, "ambiguous":True,
                "alternatives":[{"counts":c,"evidence":e} for c,e in distinct]}
    return {"counts":counts,"basis":"printed_aggregate_table","evidence":proof}
