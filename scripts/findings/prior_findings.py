"""Exclude explicit earlier-engagement findings, preserving new mitigation bugs.

Only structural section headings and explicit provenance fields qualify. A
finding mentioning an earlier audit or having a Fixed status is insufficient.
"""
import re
from text_patterns import index_line

PRIOR = re.compile(
    r"Previously[- ]known (?:issues|findings)|"
    r"(?:Known|Previously reported) (?:issues|findings)|"
    r"(?:Issues|Findings)(?: from| of| identified in| reported in) (?:the )?(?:previous|prior|earlier|original) (?:audits?|reports?)|"
    r"(?:Re[- ]?checks?|Review|Verification|Status|Mitigation|Remediation|Resolution|Fix[- ]review)(?: of| for)? (?:the )?(?:previous|prior|earlier|original)(?:ly reported)? (?:audit(?:'s)? )?(?:issues|findings)",
    re.I)


def section(line):
    value = line.content.strip().strip("* ")
    # Reject navigation, index entries, and code. PDF headings can share a
    # page with detail, so the whole-page index flag alone is insufficient.
    if (line.code or re.search(r"\.{3}|(?:\.\s+){4,}", line.text)
            or index_line(line.text, dotted=False)):
        return None
    number = re.match(r"^(\d+(?:\.\d+)*)\.?\s+(.+)$", value)
    if number:
        return number[2].strip().rstrip(":"), len(number[1].split(".")), number[1]
    if line.heading:
        return value.rstrip(":"), line.heading, None
    if PRIOR.fullmatch(value.rstrip(":")):
        return value.rstrip(":"), 1, None
    return None


def prior_sections(report):
    if hasattr(report, "_prior_sections"):
        return report._prior_sections
    heads = [(line, section(line)) for line in report.lines]
    heads = [(line, head) for line, head in heads if head]
    ranges = []
    for i, (line, (title, depth, number)) in enumerate(heads):
        if not PRIOR.fullmatch(title):
            continue
        end = len(report.text)
        for nxt, (next_title, next_depth, next_number) in heads[i+1:]:
            if next_depth <= depth and (next_number is not None) == (number is not None):
                end = nxt.start
                break
        ranges.append({"start": line.start, "end": end, "page": line.page,
                       "heading": title, "heading_text": line.text})
    report._prior_sections = ranges
    return ranges


def exclude_prior_findings(report, candidates):
    ranges = prior_sections(report)
    output = []
    excluded = getattr(report, "excluded_prior_findings", {})
    ordered = sorted(candidates, key=lambda c: c.start)
    for i, candidate in enumerate(ordered):
        section_proof = next((r for r in ranges if r["start"] <= candidate.start < r["end"]), None)
        reason = "previous_audit_section" if section_proof else None
        if re.match(r"^(?:Known|Previously reported) Issue\b", candidate.printed_id or "", re.I):
            reason = "explicit_known_issue_id"
        if candidate.evidence.get("previous_audit_finding") is True:
            reason = "explicit_previous_audit_provenance"
        if reason:
            end = candidate.end or (ordered[i+1].start if i+1 < len(ordered) else len(report.text))
            excluded[candidate.start] = {"start": candidate.start, "end": end, "title": candidate.title,
                                         "publisher_finding_id": candidate.printed_id, "reason": reason,
                                         "section": section_proof}
            continue
        # Do not let the preceding new issue absorb an excluded section's text.
        boundary = next((r["start"] for r in ranges if r["start"] > candidate.start), None)
        if boundary is not None and (candidate.end is None or boundary < candidate.end):
            candidate.end = min(boundary, ordered[i+1].start if i+1 < len(ordered) else len(report.text))
        output.append(candidate)
    report.excluded_prior_findings = excluded
    return output
