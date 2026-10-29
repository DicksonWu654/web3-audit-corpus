"""Prepare local publisher-definition page candidates for editorial review.

This selects evidence, never decides severity mappings. Candidates must be
reviewed before they enter schema/severity_map.yaml. Holdouts are denied before
opening any cache. Date hints order samples; they do not determine policy eras.
"""
import argparse
from collections import defaultdict
import json
import re

from common import ROOT, holdouts, read_snapshot, write_json
from core import definition_text

HEADING = re.compile(
    r"(?:(?:vulnerability\s+)?(?:severity|risk|finding)\s*(?:\d[\d.\s]*)?"
    r"(?:classification|categor(?:ies|ization)|rating|reference|definitions|levels)|"
    r"classification system|scoring system|finding severity breakdown|detection definitions?|"
    r"findings?\s+classification|severity\s+of\s+issues|issue level|classification of vulnerabilities|"
    r"severity breakdown|risk methodology|risk scale|severity matrix|findings explanation|"
    r"each issue has an assigned severity|security levels? reference)", re.I)


def page_score(page):
    text = definition_text(page["text"])
    levels = set(re.findall(r"\b(critical|high|medium|low|major|moderate|minor|warning|info(?:rmational)?|suggestions?)\b", text, re.I))
    score = 20 * len(HEADING.findall(text)) + 5 * len(levels)
    score += 5 * len(re.findall(r"\b(?:defined|means|implies|classified|risk|likelihood|impact)\b", text, re.I))
    if len(levels) < 3:
        score -= 200
    if re.search(r"(?:\.\s*){5,}", text) or re.search(r"(?mi)^\s*(?:Table of Contents|Contents)\s*$", page["text"]):
        score -= 500
    if len(text) > 10000:  # One-page HTML/MD reports: measure definition, not body size.
        score = 20 * bool(HEADING.search(text)) + 5 * len(levels)
    return score


def excerpt(text):
    if len(text) <= 5000:
        return text
    matches = list(re.finditer(HEADING, text))
    # Prefer an actual heading over a navigation link on single-page reports.
    if matches:
        headings = [m for m in matches if re.search(r"(?:^|\n)\s*#{1,6}\s+[^\n]{0,35}$", text[max(0, m.start()-45):m.start()])]
        explicit = [m for m in matches if re.match(r"each issue has an assigned severity|security levels? reference", m[0], re.I)]
        start = max(0, (explicit or headings or matches)[0].start()-30)
    else:
        start = 0
    return text[start:start+3500]


def candidates(root, firms=None):
    blocked = holdouts(root)
    grouped = defaultdict(dict)
    for doc in read_snapshot(root):
        row = doc["row"]
        if not firms or row["firm_id"] in firms:
            grouped[row["firm_id"]].setdefault(row["sha256"], row)
    result = {}
    for firm, docs in sorted(grouped.items()):
        source = root / "data/findings/severity_review/definitions" / (firm+".json")
        mined = json.loads(source.read_text())["sample"] if source.exists() else []
        chosen = list(dict.fromkeys(r["sha256"] for r in mined))
        if len(chosen) < 3:
            ordered = sorted(docs, key=lambda sha: (docs[sha].get("date_hint") or "", sha))
            chosen += [ordered[i] for i in sorted({0, len(ordered)//4, len(ordered)//2, 3*len(ordered)//4, len(ordered)-1})]
        evidence = []
        for sha in dict.fromkeys(chosen):
            if sha in blocked:
                raise RuntimeError("Holdout evidence access denied")
            path = root / "local-cache/fulltext" / (sha+".pages.json")
            if not path.exists():
                continue
            meta = json.loads(path.read_text())
            pages = sorted(meta["pages"], key=page_score, reverse=True)
            if not pages:
                continue
            page = pages[0]
            evidence.append({"sha256": sha, "page": page["page"], "page_basis": "pdf_page" if docs[sha]["file_format"]=="pdf" else "logical_text_page",
                             "public_url": docs[sha]["public_url"], "date_hint": docs[sha].get("date_hint"),
                             "candidate_score": page_score(page), "kind": "definition_candidate" if HEADING.search(definition_text(page["text"])) else "scale_or_example",
                             "quote": excerpt(page["text"]), "full_page": page["text"]})
        result[firm] = evidence
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--firms", nargs="*")
    a = p.parse_args()
    result = candidates(ROOT, a.firms)
    write_json(ROOT / "data/findings/severity_review/evidence_candidates.json", result)
    for firm, rows in result.items():
        print(firm, [(r["sha256"][:12], r["page"], r["candidate_score"]) for r in rows])


if __name__ == "__main__":
    main()
