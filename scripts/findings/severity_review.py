"""Local, holdout-guarded severity census, definition review, and change report.

All corpus figures in docs/phase4/severity_map.md are produced here. No network
or model calls. Review excerpts are data, never executable instructions.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import unicodedata
import xml.etree.ElementTree as ET

from common import ROOT, SEVERITIES, digest, holdouts, read_snapshot, write_json
from core import severity_mapping, severity_policy, select_severity_era


def census(root):
    blocked = holdouts(root)
    result = {}
    for path in sorted((root / "data/findings").glob("*.jsonl")):
        if path.name.startswith("_"):continue
        counts, labels, samples, ids = Counter(), Counter(), {}, []
        for line in path.open():
            row = json.loads(line)
            if row["sha256"] in blocked:
                raise RuntimeError("Holdout finding denied")
            counts[row["severity"]] += 1
            key = json.dumps(row["severity_original"], ensure_ascii=False)
            labels[key] += 1
            samples.setdefault(key, {k: row[k] for k in ("sha256", "page", "publisher_finding_id", "title", "record_kind")})
            ids.append(row["finding_id"])
        result[path.stem] = {"counts": dict(counts), "labels": dict(labels), "samples": samples,
                             "rows": sum(counts.values()), "ids": ids, "file_sha256": digest(path.read_bytes())}
    return result


DEFINITION = re.compile(
    r"severity (?:classification|definitions?|levels?|rating|categories)|risk (?:rating|classification|levels?|assessment)|"
    r"classification of (?:issues|findings|severity)|findings? (?:classification|severity)|"
    r"vulnerability (?:classification|severity)|rating (?:methodology|scale)|severity description|severity criteria|"
    r"warning.{0,100}(?:exploit|risk)|(?:major|moderate|minor).{0,100}(?:defined|impact|severity)|"
    r"(?:critical|high|medium|low)\s*[:–—-]\s*(?:the|an?|this|issues?|vulnerabilit)", re.I)


def mine(root, firms):
    """Pick several definition-bearing reports across dated metadata eras.

    Hints order the review only, never select a dated severity mapping.
    """
    blocked = holdouts(root)
    grouped = defaultdict(dict)
    for doc in read_snapshot(root):
        row = doc["row"]
        if not firms or row["firm_id"] in firms:
            grouped[row["firm_id"]].setdefault(row["sha256"], row)
    out = {}
    for firm, docs in sorted(grouped.items()):
        matches = []
        for sha, row in sorted(docs.items(), key=lambda x: (x[1].get("date_hint") or "", x[0])):
            if sha in blocked:
                raise RuntimeError("Holdout text denied")
            path = root / "local-cache/fulltext" / (sha + ".pages.json")
            if not path.exists():
                continue
            meta = json.loads(path.read_text())
            hits = []
            for page in meta["pages"]:
                text = page["text"]
                squashed = re.sub(r"\s+", " ", unicodedata.normalize("NFKC", text))
                hit = DEFINITION.search(squashed)
                # Definitions, not a TOC or a numbered finding titled Risk.
                if not hit or len(re.findall(r"\b(?:critical|high|medium|low|major|moderate|minor|warning|info(?:rmational)?)\b", squashed, re.I)) < 3:
                    continue
                if len(text) < 100 or text.count("....") > 4:
                    continue
                score = 10*len(re.findall(r"(?:severity|risk|finding) (?:classification|definitions?|levels?|rating|criteria)|classif.{0,40}following", squashed, re.I))
                score += len(re.findall(r"\b(?:defined|means|indicates|refers|severity|impact|likelihood)\b", squashed, re.I))
                if text.count("....") > 2 or "Table of Contents" in text:
                    score -= 50
                hits.append({"sha256": sha, "page": page["page"], "score": score, "date_hint": row.get("date_hint"),
                             "public_url": row["public_url"], "file_format": row["file_format"], "text": text})
            if hits:
                matches.append(sorted(hits, key=lambda p: (-p["score"], p["page"]))[:2])
        # First/middle/latest plus early/late quartiles, preserving complete pages.
        indexes = sorted({0, len(matches)//4, len(matches)//2, 3*len(matches)//4, len(matches)-1}) if matches else []
        out[firm] = {"definition_documents": len(matches), "sample": [h for i in indexes for h in matches[i][:3]]}
        write_json(root / "data/findings/severity_review/definitions" / (firm + ".json"), out[firm])
        print(f"Reviewed candidate pages: {firm}", flush=True)
    return out


def verify_evidence(root):
    policy, _, policy_sha = severity_policy()
    blocked = holdouts(root)
    allowed = {(d["row"]["firm_id"], d["row"]["sha256"]) for d in read_snapshot(root)}
    verified, gaps = [], []
    for firm, entry in policy["publishers"].items():
        for era in entry["eras"]:
            definitions = set()
            for proof in era["evidence"]:
                sha = proof["sha256"]
                if sha in blocked or (firm, sha) not in allowed:
                    raise RuntimeError("Out-of-scope or holdout severity evidence denied")
                meta = json.loads((root / "local-cache/fulltext" / (sha+".pages.json")).read_text())
                text = "\f".join(p["text"] for p in meta["pages"])
                assert digest(text.encode()) == meta["text_sha256"], sha
                page = next(p for p in meta["pages"] if p["page"] == proof["page"])
                assert proof["quote"] and proof["quote"] in page["text"], (firm, sha, proof["page"])
                if proof["kind"] == "definition":
                    definitions.add(sha)
                if era.get("definition_regex"):
                    assert select_severity_era(firm, report_text=text) == era["id"], (firm, sha, era["id"])
                verified.append({"publisher": firm, "era": era["id"], "sha256": sha, "page": proof["page"], "kind": proof["kind"]})
            if len(definitions) < 2:
                gaps.append({"publisher": firm, "era": era["id"], "definition_documents": len(definitions),
                             "reason": entry.get("evidence_limitations", "Only a native scale/example or one definition-bearing report was recovered in the reviewed sample.")})
    return {"policy_sha256": policy_sha, "verified_citations": verified, "evidence_gaps": gaps, "holdouts_opened": 0}


def export(root):
    source = root / "schema/severity_map.yaml"
    policy = json.loads(source.read_text())
    write_json(root / "schema/severity_map.json", policy)
    assert json.loads((root / "schema/severity_map.json").read_text()) == policy


def refresh_receipts(root):
    """Refresh fingerprints after evidence-only/unobserved-label map edits.

    Fail rather than silently relabel if any emitted row's interpretation,
    mapped state or rule would change. Semantic changes require run.py.
    """
    from common import canonical
    blocked = holdouts(root)
    rows = 0
    for path in sorted((root / "data/findings").glob("*.jsonl")):
        if path.name.startswith("_"):continue
        temp = path.with_suffix(".jsonl.tmp")
        with path.open() as source, temp.open("w") as output:
            for line in source:
                row = json.loads(line)
                assert row["sha256"] not in blocked
                old = row["severity_mapping"]
                new = severity_mapping(row["severity_original"], row["publisher_id"], era=old["era"],
                                       kind=(old.get("rule") or "").removeprefix("unrated_"), log=False)
                for key in ("normalized", "mapped", "era", "rule"):
                    assert new.get(key) == old.get(key), f"Semantic change for {row['finding_id']}: rerun run.py"
                row["severity_mapping"] = new | {"basis": old["basis"]}
                output.write(canonical(row)+"\n")
                rows += 1
        temp.replace(path)
    print(json.dumps({"refreshed_receipts": rows, "semantic_changes": 0}))


def write_manifest(root):
    """List persistent repository files written by this task, including ignored outputs."""
    parser_names = "abdk_consulting ackee_blockchain bailsec blocksec cantina certora chainlight code4rena composable_security consensys_diligence decurity dedaub electisec fuzzland guardianaudits halborn hats_finance informalsystems iosiro macro mixbytes movebit openzeppelin ottersec oxorio pashov_audit_group peckshield pessimistic quantstamp runtime_verification sec3 secure3 sherlock shieldify sigma_prime slowmist solidified spearbit statemind verichains veridise zokyo".split()
    sources = {"schema/README.md", "schema/severity_map.yaml", "schema/severity_map.json", "scripts/build/build_db.py",
               "scripts/findings/core.py", "scripts/findings/run.py", "scripts/findings/check.py", "scripts/findings/report.py",
               "scripts/findings/summary_counts.py", "scripts/findings/parsers/__init__.py",
               "scripts/findings/prior_findings.py", "scripts/findings/severity_review.py", "scripts/findings/severity_evidence.py",
               "scripts/findings/severity_baseline_replay.py", "scripts/findings/test_severity_map.py",
               "scripts/findings/parsers/least_authority_test.py", "scripts/findings/parsers/test_group4_parent.py",
               "scripts/findings/parsers/slowmist_review.py", "scripts/findings/test_framework.py",
               "scripts/findings/test_fuzzland_composable.py", "scripts/findings/test_group1_code4rena.py",
               "scripts/findings/test_group3.py", "scripts/findings/test_runtime_dedaub.py",
               "docs/phase4/severity_map.md", "docs/phase4/severity_map_before.json", "docs/phase4/severity_map_files_written.txt"}
    sources.update("scripts/findings/parsers/"+name+".py" for name in parser_names)
    outputs = {str(p.relative_to(root)) for p in (root / "data/findings").glob("*.jsonl")}
    cutoff = (root / "data/findings/severity_review/before.json").stat().st_mtime
    for p in (root / "data/findings").rglob("*.json"):
        if p.stat().st_mtime >= cutoff:
            outputs.add(str(p.relative_to(root)))
    outputs.update(str(p.relative_to(root)) for p in (root / "data/findings/validation").glob("*.jsonl"))
    outputs.update(str(p.relative_to(root)) for p in (root / "local-cache/severity-baseline").rglob("*.py"))
    content = ["Persistent repository files written by the severity-crosswalk task.",
               "Includes ignored regenerated data and the local pre-task replay sources; excludes transient atomic-write files, bytecode and temporary test fixtures/logs.",
               "Unrelated concurrent changes are not listed.", "", "Source, schema, tests and review documents:", ""]
    content += sorted(sources)
    content += ["", "Regenerated local outputs and verification receipts:", ""] + sorted(outputs)
    (root / "docs/phase4/severity_map_files_written.txt").write_text("\n".join(content)+"\n")


def change_report(root, junit=None):
    before_path = root / "data/findings/severity_review/before.json"
    before = json.loads(before_path.read_text())
    after = census(root)
    write_json(root / "data/findings/severity_review/after.json", after)
    # Small release-review baseline: distribution and original-label inventory;
    # full row identities stay in the ignored local receipt.
    baseline_path = root / "docs/phase4/severity_map_before.json"
    baseline = {f: {k:v for k,v in d.items() if k in {"counts", "labels", "rows", "file_sha256"}} for f,d in before.items()}
    if baseline_path.exists():
        assert json.loads(baseline_path.read_text()) == baseline, "Frozen severity baseline changed"
    else:
        write_json(baseline_path, baseline)
    policy, _, policy_sha = severity_policy()
    proof = verify_evidence(root)
    unmapped, unknown, removals, removed_ids, added_ids, eras = [], [], Counter(), set(), set(), Counter()
    excluded_ids = set()
    from common import VERSION, uid
    for path in sorted((root / "data/findings/validation").glob("*.jsonl")):
        if path.stem not in policy["publishers"]:
            continue
        for line in path.open():
            diag = json.loads(line)
            for excluded in diag.get("excluded_prior_findings", []):
                sid = diag["document_id"] + ":" + VERSION + ":" + str(excluded["start"])
                excluded_ids.add(uid("finding", "collect:"+path.stem, sid))
    unknown_counts = defaultdict(Counter)
    unmapped_counts = defaultdict(Counter)
    for path in sorted((root / "data/findings").glob("*.jsonl")):
        if path.name.startswith("_"):continue
        for line in path.open():
            row = json.loads(line)
            mapping = row["severity_mapping"]
            assert mapping["map_sha256"] == policy_sha, "Stale findings: regenerate all publishers"
            expected = severity_mapping(row["severity_original"], row["publisher_id"], era=mapping["era"],
                                        kind=(mapping.get("rule") or "").removeprefix("unrated_"), log=False)
            assert expected["normalized"] == row["severity"], row["finding_id"]
            eras[(path.stem, mapping["era"])] += 1
            label = json.dumps(row["severity_original"], ensure_ascii=False)
            if row["severity"] == "unknown":
                unknown_counts[path.stem][label] += 1
            if not mapping["mapped"]:
                unmapped_counts[path.stem][label] += 1
    for firm in sorted(before):
        removed = set(before[firm]["ids"]) - set(after[firm]["ids"])
        added = set(after[firm]["ids"]) - set(before[firm]["ids"])
        removed_ids.update(removed)
        added_ids.update(added)
        removals[firm] = len(removed)
    unexplained = removed_ids - excluded_ids
    replay_path = root / "data/findings/severity_review/baseline_replay.json"
    replay = json.loads(replay_path.read_text()) if replay_path.exists() else {"finding_ids": []}
    unexplained_additions = added_ids - set(replay["finding_ids"])
    if unexplained or unexplained_additions:
        raise AssertionError(f"Unexpected enumeration changes: {len(unexplained)} unexplained removals, {len(unexplained_additions)} unexplained additions")
    tests = None
    if junit:
        tree = ET.parse(junit).getroot()
        suites = [tree] if tree.tag == "testsuite" else list(tree.iter("testsuite"))
        tests = {k:sum(int(s.get(k, 0)) for s in suites) for k in ("tests", "failures", "errors", "skipped")}
        assert not tests["failures"] and not tests["errors"], tests
    receipt = {"publishers": len(after), "before_findings": sum(d["rows"] for d in before.values()),
               "after_findings": sum(d["rows"] for d in after.values()), "removed_prior_findings": sum(removals.values()),
               "removed_by_publisher": dict(removals), "unexplained_removals": len(unexplained), "added_findings": len(added_ids),
               "added_rows_preexisting_parser": len(added_ids), "baseline_replay_revision": replay.get("revision"),
               "distinct_publisher_original_values": sum(len(d["labels"]) for d in after.values()),
               "unmapped_original_values": sum(len(c) for c in unmapped_counts.values()),
               "unmapped_rows": sum(sum(c.values()) for c in unmapped_counts.values()),
               "unknown_rows": sum(sum(c.values()) for c in unknown_counts.values()),
               "map_sha256": policy_sha, "tests": tests, "evidence": proof, "holdouts_opened": 0}
    write_json(root / "data/findings/severity_review/check.json", receipt)
    stats = [json.loads((root / "data/findings/validation" / (firm+".json")).read_text()) for firm in sorted(after)]
    write_json(root / "data/findings/summary.json", {"version": VERSION, "by_firm": stats,
        "findings": sum(s["findings"] for s in stats), "documents": sum(s["documents"] for s in stats),
        "severity_policy": policy["policy"], "severity_map_sha256": policy_sha, "holdouts_opened": 0})
    lines = ["# Publisher severity crosswalk", "", "Generated by `python3 scripts/findings/severity_review.py report --junit local-cache/tmp/severity-tests.xml`. Counts cover every emitted row, including explicitly labelled observations, recommendations and summary excerpts. Document occurrences are retained; these are not counts of unique vulnerabilities.", "",
             f"Reviewed source: `schema/severity_map.yaml` (JSON-compatible YAML 1.2), SHA-256 `{policy_sha}`. `schema/severity_map.json` is the identical-content export. The central normalizer in `scripts/findings/core.py` is authoritative at dispatch, span finalization and row emission; parser hints cannot override it. Raw strings and nulls remain unchanged.", "",
             f"Coverage: {len(after)} publishers; {receipt['distinct_publisher_original_values']} distinct (publisher, severity_original) values; {receipt['unmapped_original_values']} unmapped values / {receipt['unmapped_rows']} rows. Explicitly unresolved classifications, placeholders and ungraded issues account for {receipt['unknown_rows']:,} unknown rows. Before: {receipt['before_findings']:,}; after: {receipt['after_findings']:,}; excluded earlier-audit re-checks: {receipt['removed_prior_findings']:,}. Every removed finding ID has an explicit exclusion receipt.", "",
             f"The rebuild also emits {len(added_ids)} short Code4rena/SlowMist summary excerpts that were absent from the cached before output ({json.dumps(replay.get('by_publisher', {}), sort_keys=True)}). `python3 scripts/findings/severity_baseline_replay.py --revision {replay.get('revision', '')}` reproduces every added ID with the pre-task parser source and verifies their `summary_excerpt` kind. This is cached-output drift, not new finding-detection logic or additional formal findings from the crosswalk change.", "",
             "Unrated issues map to unknown; source-explicit suggestions/recommendations map to info. Below-risk advice maps to info. QA/gas interpretation is publisher-specific. Familiar label spellings do not override a publisher definition. Definition-specific eras are selected from quoted template text, with hash selectors exported for the reviewed non-holdout reports; collection/filename date hints never select an era. An external evaluator can supply `era`, `sha256` or `report_text` to `core.severity_mapping`.", "",
             "The before distribution and original-label inventory are frozen in `docs/phase4/severity_map_before.json`. The full local ID census, exclusion receipts and verification details are in `data/findings/severity_review/` and `data/findings/validation/`. All report/cache access excludes the holdout hashes before opening text. No gold document was opened.", "",
             "## Severity distribution", "", "Each cell is before → after. Re-check exclusions also affect these totals.", "",
             "| Publisher | Critical | High | Medium | Low | Info | Gas | Unknown | Re-check rows removed |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for firm in sorted(before):
        cells = [f"{before[firm]['counts'].get(s,0):,} → {after[firm]['counts'].get(s,0):,}" for s in SEVERITIES]
        lines.append("| " + " | ".join([firm]+cells+[str(removals[firm])]) + " |")
    lines += ["", "## Residual unknowns", "", "These labels remain explicit review items. A mapped unknown is distinguished from a missing crosswalk entry. Null is not filled with an invented source label.", "", "| Publisher | Original label | Rows | In crosswalk |", "|---|---|---:|---|"]
    for firm, labels in sorted(unknown_counts.items()):
        for label, n in sorted(labels.items()):
            lines.append(f"| {firm} | `{label.replace('|', '&#124;')}` | {n:,} | {'no' if label in unmapped_counts[firm] else 'yes (intentional unknown)'} |")
    lines += ["", "## Evidence and era review", "", "SHA-256 identifies the publisher original; PDF page numbers are one-based physical pages. Markdown/HTML references use the extractor's logical page, with exact quotes in the crosswalk. Native scale/examples are identified separately where a full prose definition was not recovered; such references must not be represented as full definition review.", ""]
    for firm, entry in sorted(policy["publishers"].items()):
        lines += [f"### {firm}", ""]
        if entry.get("evidence_limitations"):
            lines += [entry["evidence_limitations"], ""]
        for era in entry["eras"]:
            lines += [f"`{era['id']}`: {era['description']}", ""]
            for e in era["evidence"]:
                lines.append(f"- [{e['sha256']}, p. {e['page']}]({e['public_url']}) ({e['kind']}; {e['page_basis']}).")
            lines.append("")
    if proof["evidence_gaps"]:
        lines += ["Evidence limitations requiring further publisher-source review:", ""]
        for g in proof["evidence_gaps"]:
            lines.append(f"- {g['publisher']} / {g['era']}: {g['reason']}")
        lines.append("")
    lines += ["## Content exclusions", "", "Structural headings for previously-known issues and earlier-audit re-checks, explicit known-issue IDs, and publisher-specific earlier-audit provenance exclude rows. Code4rena mitigation rechecks of original IDs are excluded; new MR-prefixed mitigation vulnerabilities remain. Fixed status, code changes, a repeated title, or a mention of an earlier audit alone never triggers exclusion. Per-document reason, original heading, page and spans remain in validation receipts. The table above reports removed existing rows for every publisher.", "", "## Verification", ""]
    if tests:
        lines += [f"Regression suite: {tests['tests']} tests; {tests['failures']} failures, {tests['errors']} errors, {tests['skipped']} skipped.", ""]
    check_path = root / "data/findings/check.json"
    if check_path.exists():
        check = json.loads(check_path.read_text())
        lines += [f"Full pipeline checker: `{check.get('ok')}`; {check.get('documents',0):,} document occurrences and {check.get('findings',0):,} findings; {check.get('holdout_rows_found',0)} holdout rows. Severity review independently verified {len(proof['verified_citations'])} citations against hash-checked text pages and every emitted row against the current crosswalk.", ""]
    (root / "docs/phase4/severity_map.md").write_text("\n".join(lines))
    write_manifest(root)
    print(json.dumps({k:v for k,v in receipt.items() if k != "evidence"}, indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("before", "census", "mine", "export", "verify-evidence", "refresh-receipts", "report"))
    p.add_argument("--root", type=Path, default=ROOT)
    p.add_argument("--firms", nargs="*")
    p.add_argument("--junit", type=Path)
    a = p.parse_args()
    if a.command in {"before", "census"}:
        output = a.root / "data/findings/severity_review" / (a.command + ".json")
        if a.command == "before" and output.exists():
            raise FileExistsError("Frozen before snapshot already exists")
        result = census(a.root)
        write_json(output, result)
        for firm, data in result.items():
            print(firm, data["rows"], json.dumps(data["labels"], ensure_ascii=False))
    elif a.command == "mine":
        result = mine(a.root, a.firms)
        write_json(a.root / "data/findings/severity_review/definition_candidates.json", result)
        for firm, data in result.items():
            print(firm, data["definition_documents"], [(r["sha256"][:12], r["page"], r["date_hint"]) for r in data["sample"]])
    elif a.command == "export":
        export(a.root)
    elif a.command == "verify-evidence":
        result = verify_evidence(a.root)
        write_json(a.root / "data/findings/severity_review/evidence_check.json", result)
        print(json.dumps({"citations": len(result["verified_citations"]), "gaps": result["evidence_gaps"]}, indent=2))
    elif a.command == "refresh-receipts":
        refresh_receipts(a.root)
    else:
        change_report(a.root, a.junit)


if __name__ == "__main__":
    main()
