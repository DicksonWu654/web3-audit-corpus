"""Reproduce the severity-canonicalization census, tests and change report locally."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest

from common import ROOT, SEVERITIES, VERSION, digest, holdouts, read_snapshot, write_json, write_jsonl
from core import severity_mapping, severity_policy
from severity_resolve import RESOLVER_VERSION


def census(root):
    """Read generated rows only; refuse holdout rows before examining content."""
    blocked = holdouts(root)
    result = {}
    for path in sorted((root / "data/findings").glob("*.jsonl")):
        if path.name.startswith("_"):
            continue
        rows, counts, labels = {}, Counter(), Counter()
        for line in path.open():
            row = json.loads(line)
            if row["sha256"] in blocked:
                raise RuntimeError("Holdout finding denied")
            assert row["finding_id"] not in rows, "Duplicate finding ID"
            assert row["severity_original"] == row["severity_raw"]
            assert row["severity_original"] == row["provenance"]["extraction_record"]["severity_raw"]
            # Stable evidence fingerprint proves raw labels and finding spans survive.
            evidence = {k: row[k] for k in ("sha256", "document_id", "publisher_finding_id", "severity_original",
                        "title_raw", "body_span", "record_kind", "finding_phase", "status_raw", "status")}
            rows[row["finding_id"]] = [row["severity"], row["severity_original"], digest(evidence)]
            counts[row["severity"]] += 1
            labels[json.dumps(row["severity_original"], ensure_ascii=False)] += 1
        result[path.stem] = {"counts": dict(counts), "labels": dict(labels), "rows": rows}
    return result


def tests(root, all_tests=False):
    if all_tests:
        suite = unittest.defaultTestLoader.discover(str(ROOT / "scripts/findings"), pattern="test*.py")
    else:
        # Resolver policy, runner invariants and the affected publishers' parsers.
        modules = ("test_severity_map", "test_severity_resolve", "test_framework", "test_variants",
                   "test_group1_code4rena", "test_runtime_dedaub", "test_variants_group1_c4_runtime",
                   "test_group2", "test_hexens_informal_variants", "parsers.informalsystems_test",
                   "parsers.test_solidified_certora_pessimistic")
        suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    command = "test-all" if all_tests else "test"
    receipt = {"command": "python3 -S scripts/findings/severity_canon.py " + command, "tests": result.testsRun,
               "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
               "failure_details": {case.id(): detail for case, detail in result.failures + result.errors},
               "ok": result.wasSuccessful()}
    name = "all_tests.json" if all_tests else "tests.json"
    write_json(root / "data/findings/severity_canon" / name, receipt)
    if not result.wasSuccessful():
        raise SystemExit(1)


def preexisting_tests(root):
    """Reproduce broad-suite failures with the pre-change core, without edits."""
    path = root / "data/findings/severity_canon/all_tests.json"
    current = json.loads(path.read_text())
    names = sorted(current["failure_details"])
    saved = root / "data/findings/severity_canon/preexisting_tests.json"
    revision = (json.loads(saved.read_text())["revision"] if saved.exists() else
                subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip())
    source = subprocess.check_output(["git", "show", revision + ":scripts/findings/core.py"], cwd=ROOT)
    with tempfile.TemporaryDirectory(prefix="severity-baseline-tests-") as tmp:
        (Path(tmp) / "core.py").write_bytes(source)
        program = '''import json, sys, unittest
sys.path[:0] = [sys.argv[1], sys.argv[2]]
suite = unittest.defaultTestLoader.loadTestsFromNames(json.loads(sys.argv[3]))
r = unittest.TextTestRunner().run(suite)
print(json.dumps({"tests": r.testsRun, "failures": len(r.failures), "errors": len(r.errors),
                 "failure_details": {case.id(): detail for case, detail in r.failures + r.errors}}))
'''
        output = subprocess.run([sys.executable, "-I", "-B", "-S", "-c", program, tmp,
                                 str(ROOT / "scripts/findings"), json.dumps(names)],
                                cwd=ROOT, capture_output=True, text=True, check=True)
    baseline = json.loads(output.stdout)
    assert sorted(baseline["failure_details"]) == names, "New broad-suite regression"
    receipt = {"revision": revision, "core_sha256": digest(source), "baseline": baseline,
               "all_current_failures_preexisting": True}
    write_json(root / "data/findings/severity_canon/preexisting_tests.json", receipt)
    print(json.dumps({"revision": revision, "all_current_failures_preexisting": True,
                      "failed_test_ids": names}, indent=2))


def refresh_receipts(root):
    from severity_review import refresh_receipts as refresh
    # Semantic changes must already have been rebuilt by run.py --firms ... .
    refresh(root)
    firms = sorted({doc["row"]["firm_id"] for doc in read_snapshot(root)})
    stats = [json.loads((root / "data/findings/validation" / (firm + ".json")).read_text()) for firm in firms]
    write_json(root / "data/findings/summary.json", {"version": VERSION, "by_firm": stats,
        "findings": sum(s["findings"] for s in stats), "documents": sum(s["documents"] for s in stats),
        "holdouts_opened": 0})


def sync_cache_receipts(root):
    """Reconcile completed cache pairs only; never extract or modify source text."""
    blocked = holdouts(root)
    docs = read_snapshot(root)
    firms = {}
    for doc in docs:
        firms.setdefault(doc["row"]["sha256"], set()).add(doc["row"]["firm_id"])
    rows, changed, text_changed = [], [], []
    for line in (root / "data/fulltext/extractions.jsonl").open():
        old = json.loads(line)
        sha = old["sha256"]
        assert sha not in blocked, "Holdout cache access denied"
        text_path = root / "local-cache/fulltext" / (sha + ".txt")
        meta_path = text_path.with_suffix(".pages.json")
        new = old
        if text_path.exists() and meta_path.exists():
            meta = json.loads(meta_path.read_text())
            assert meta["sha256"] == sha
            text = text_path.read_bytes().decode("utf-8")
            assert digest(text.encode()) == meta["text_sha256"], "Cache pair changed during receipt sync"
            assert "\f".join(p["text"] for p in meta["pages"]) == text
            assert meta["characters"] == len(text) and meta["page_count"] == len(meta["pages"])
            new = {k: v for k, v in meta.items() if k not in {"pages", "coordinate_system", "structured"}}
            new |= {"text_path": str(text_path.relative_to(root)), "pages_path": str(meta_path.relative_to(root))}
        if old != new:
            changed.append(sha)
        if old.get("text_sha256") != new.get("text_sha256"):
            text_changed.append(sha)
        rows.append(new)
    write_jsonl(root / "data/fulltext/extractions.jsonl", rows)
    write_jsonl(root / "data/fulltext/failures.jsonl", [row for row in rows if row["status"] != "ok"])
    index = {row["sha256"]: row for row in rows}
    counts = Counter(index[doc["row"]["sha256"]]["status"] for doc in docs)
    write_json(root / "data/fulltext/summary.json", {"documents": len(docs), "unique_artifacts": len(rows),
        "document_status": {s: counts[s] for s in ("ok", "partial", "failed", "pending")},
        "fulltext_percent": round(100 * counts["ok"] / len(docs), 4),
        "text_cache_percent": round(100 * (counts["ok"] + counts["partial"]) / len(docs), 4),
        "unique_status": {s: sum(row["status"] == s for row in rows) for s in ("ok", "partial", "failed", "pending")},
        "pages": sum(row.get("page_count", 0) for row in rows), "holdouts_opened": 0})
    receipt = {"updated_receipt_hashes": sorted(changed), "text_changed_hashes": sorted(text_changed),
               "text_changed_firms": sorted({firm for sha in text_changed for firm in firms.get(sha, set())}),
               "originals_or_text_modified": 0, "holdouts_opened": 0}
    write_json(root / "data/findings/severity_canon/cache_sync.json", receipt)
    print(json.dumps(receipt, indent=2))


def report(root):
    base = root / "data/findings/severity_canon"
    before = json.loads((base / "before.json").read_text())
    after = census(root)
    preexisting = json.loads((base / "preexisting_tests.json").read_text())
    # Replay the exact predecessor against the CURRENT policy and CURRENT rows.
    # This separates canonicalization from concurrent policy/parser changes.
    source = subprocess.check_output(["git", "show", preexisting["revision"] + ":scripts/findings/core.py"], cwd=ROOT)
    assert digest(source) == preexisting["core_sha256"]
    baseline_core = types.ModuleType("_severity_canon_baseline_core")
    sys.modules[baseline_core.__name__] = baseline_core
    exec(compile(source, "<pre-canonicalization-core>", "exec"), baseline_core.__dict__)
    changes, totals, modified = {}, Counter(), []
    map_sha = severity_policy()[2]
    for publisher in sorted(set(before) | set(after)):
        old = before.get(publisher, {"counts": {}, "rows": {}})
        new = after.get(publisher, {"counts": {}, "rows": {}})
        transitions, labels, evidence_changes, raw_changes = Counter(), Counter(), [], []
        common = old["rows"].keys() & new["rows"].keys()
        for fid in common:
            a, b = old["rows"][fid], new["rows"][fid]
            if a[1] != b[1]:
                raw_changes.append(fid)
            if a[2] != b[2]:
                evidence_changes.append(fid)
            if a[0] != b[0]:
                transitions[a[0] + " → " + b[0]] += 1
                labels[json.dumps([a[1], a[0], b[0]], ensure_ascii=False)] += 1
        changes[publisher] = {"before": old["counts"], "after": new["counts"],
            "delta": {s: new["counts"].get(s, 0) - old["counts"].get(s, 0) for s in SEVERITIES},
            "transitions": dict(transitions), "changed_original_labels": dict(labels),
            "added": len(new["rows"].keys() - old["rows"].keys()),
            "added_ids": sorted(new["rows"].keys() - old["rows"].keys()),
            "removed": len(old["rows"].keys() - new["rows"].keys()), "retained": len(common),
            "removed_ids": sorted(old["rows"].keys() - new["rows"].keys()),
            "other_evidence_changed_ids": sorted(evidence_changes), "original_label_changed_ids": sorted(raw_changes)}
        if transitions:
            modified.append(publisher)
        totals.update({"before_rows": len(old["rows"]), "after_rows": len(new["rows"]),
                       "reclassified_rows": sum(transitions.values()), "added_rows": changes[publisher]["added"],
                       "removed_rows": changes[publisher]["removed"], "retained_rows": len(common),
                       "other_evidence_changed_rows": len(evidence_changes), "original_label_changed_rows": len(raw_changes)})
        # Revalidate every emitted row, including receipt version and raw input.
        path = root / "data/findings" / (publisher + ".jsonl")
        if not path.exists():
            continue
        canonical_labels, canonical_transitions, exact_counts = Counter(), Counter(), Counter()
        for line in path.open():
            row = json.loads(line)
            mapping = row["severity_mapping"]
            expected = severity_mapping(row["severity_original"], publisher, era=mapping["era"],
                                       kind=(mapping.get("rule") or "").removeprefix("unrated_"), log=False)
            assert mapping["resolver"] == RESOLVER_VERSION and mapping["map_sha256"] == map_sha
            assert mapping["input"] == mapping["raw"] == row["severity_original"]
            assert mapping["canonical_label"] == expected["canonical_label"]
            assert row["severity"] == row["severity_normalized"] == expected["normalized"]
            assert mapping["mapped"] == expected["mapped"]
            exact = baseline_core.severity_mapping(row["severity_original"], publisher, era=mapping["era"],
                kind=(mapping.get("rule") or "").removeprefix("unrated_"), log=False)
            exact_counts[exact["normalized"]] += 1
            if exact["normalized"] != row["severity"]:
                canonical_transitions[exact["normalized"] + " → " + row["severity"]] += 1
                canonical_labels[json.dumps([row["severity_original"], exact["normalized"], row["severity"]], ensure_ascii=False)] += 1
        changes[publisher].update(canonicalization_transitions=dict(canonical_transitions),
            canonicalization_labels=dict(canonical_labels), exact_resolver_on_current_rows=dict(exact_counts))
        totals["canonicalization_rows"] += sum(canonical_transitions.values())
    test_result = json.loads((base / "tests.json").read_text())
    all_tests = json.loads((base / "all_tests.json").read_text())
    assert preexisting["all_current_failures_preexisting"]
    assert sorted(all_tests["failure_details"]) == sorted(preexisting["baseline"]["failure_details"])
    check_run = json.loads((base / "pipeline_check.json").read_text())
    check = check_run.get("result", {})
    assert test_result["ok"]
    if check_run["ok"]:
        assert check["findings"] == totals["after_rows"] and check["holdout_rows_found"] == 0
    else:
        assert check_run["reason"] == "concurrent_cache_change", "Unresolved findings checker error"
    receipt = {"resolver": RESOLVER_VERSION, "map_sha256": map_sha, "totals": dict(totals),
               "changed_publishers": modified, "by_publisher": changes, "tests": test_result,
               "all_tests": all_tests, "preexisting_tests": preexisting,
               "checker": check_run, "holdouts_opened": 0}
    write_json(base / "comparison.json", receipt)
    lines = ["# Severity label canonicalization", "",
        "Generated by `python3 -S scripts/findings/severity_canon.py report` from the frozen before census and regenerated findings. Counts include all emitted record kinds and document occurrences; they are not unique-vulnerability counts.", "",
        "The shared resolver is `scripts/findings/severity_resolve.py`; `core.py` adds active parser context. Both policy labels and input labels use Unicode NFKC/casefold, leading count/bullet/number removal, punctuation/spacing removal, trailing risk/severity/issue/finding removal and singularization. PDF line-end hyphenation is rejoined. Parenthesized trailing counts are presentation only. Abbreviations resolve only when the selected publisher/era defines them. Unknown publishers, ambiguous eras, unsupported abbreviations and substantive risk qualifiers retain unknown behavior. Source labels and nulls stay verbatim.", "",
        "The canonical base definition wins over an old decorated spelling with a different mapping. In particular, ABDK's `0 M i n o r` resolves through its native `Minor` definition. Contradictory definitions of the same base label raise an error. Stable alias ordering makes JSON and YAML receipts agree apart from the hash of the supplied artifact.", "",
        "No YAML label rows were added or edited by this task. The JSON export mirrors the current YAML, including concurrent publisher-profile additions. The legacy `matching.whitespace` prose in that artifact describes the previous resolver; the callable module and schema README document the current matching contract.", "",
        f"Resolver: `{RESOLVER_VERSION}`. Reviewed YAML SHA-256: `{map_sha}`.", "",
        f"Before: {totals['before_rows']:,} rows. After: {totals['after_rows']:,} rows. Retained rows with bucket changes: {totals['reclassified_rows']:,} across {len(modified)} publishers. Added: {totals['added_rows']:,}; removed: {totals['removed_rows']:,}. Canonicalization alone changes {totals['canonicalization_rows']:,} rows when the exact predecessor is replayed on the same current rows and current crosswalk. Verbatim severity labels match across {totals['retained_rows'] - totals['original_label_changed_rows']:,} retained rows; {totals['original_label_changed_rows']:,} inputs changed during concurrent parser work. Source/evidence fingerprints match for {totals['retained_rows'] - totals['other_evidence_changed_rows']:,} retained rows; {totals['other_evidence_changed_rows']:,} have other evidence changes, listed separately below. Every current row's raw/original label equals the parser extraction record verbatim.", "",
        "## External evaluator usage", "", "Load the module with Python's ordinary import machinery (including `importlib.util.spec_from_file_location`); it performs no file reads or repo-path changes at import. It can be copied beside the exported JSON without other repository modules. Supply the artifact explicitly:", "", "```python",
        'from severity_resolve import severity_mapping, resolve_severity',
        'resolve_severity("Low Risk", "code4rena", policy_path="severity_map.json")  # "low"',
        'severity_mapping("0 INFORMATIONAL", "informalsystems", policy_path="severity_map.json")',
        "```", "",
        "`severity_mapping` returns the original input/raw, canonical key, bucket, selected era, policy/artifact hash and resolver version. `severity` and `resolve_severity` return the bucket. Optional `era`, `sha256`, `report_text`, `date` and `kind` selectors have the same semantics as parser calls. The default artifact is the reviewed repository YAML; no report is opened by this module.", "",
        "## Publisher distributions", "", "Each cell is before → after. Publishers without changes are included.", "",
        "| Publisher | " + " | ".join(SEVERITIES) + " |", "|---|" + "---:|"*len(SEVERITIES)]
    for publisher, change in changes.items():
        cells = [f"{change['before'].get(s, 0):,} → {change['after'].get(s, 0):,}" for s in SEVERITIES]
        lines.append("| " + publisher + " | " + " | ".join(cells) + " |")
    lines += ["", "## Canonicalization-only source-label changes", "",
        "The predecessor resolver is replayed from the pinned revision on current rows with the current policy. This holds policy additions and parser updates constant. The full per-publisher comparison also records `exact_resolver_on_current_rows` and all observed before/after transitions.", "",
        "| Publisher | Verbatim original label | Transition | Rows |", "|---|---|---|---:|"]
    for publisher, change in changes.items():
        for label, count in sorted(change.get("canonicalization_labels", {}).items()):
            raw, a, b = json.loads(label)
            printed = json.dumps(raw, ensure_ascii=False).replace("|", "\\|")
            lines.append(f"| {publisher} | `{printed}` | {a} → {b} | {count:,} |")
    lines += ["", "## Other changes during regeneration", "",
        "The full runner uses the current shared worktree. Concurrent publisher-parser/visual-receipt changes and cited ChainSecurity crosswalk additions were preserved. Added/removed rows, changed parser inputs and other evidence differences are reported separately; they are not attributed to canonicalization. The fingerprint covers original hash, document/native finding ID, raw severity/title, body span, record kind/phase and status fields. Exact changed IDs remain in `comparison.json`.", "",
        "| Publisher | Added rows | Removed rows | Original label changed | Other evidence changed |", "|---|---:|---:|---:|---:|"]
    for publisher, change in changes.items():
        if change["added"] or change["removed"] or change["other_evidence_changed_ids"]:
            lines.append(f"| {publisher} | {change['added']:,} | {change['removed']:,} | {len(change['original_label_changed_ids']):,} | {len(change['other_evidence_changed_ids']):,} |")
    lines += ["", "## Verification and reproduction", "",
        f"Severity and affected-publisher regression suite: {test_result['tests']:,} tests; {test_result['failures']} failures, {test_result['errors']} errors, {test_result['skipped']} skipped. Includes every named publisher, abbreviation boundaries, era semantics, JSON/YAML parity, isolated standalone import and verbatim row emission.", "",
        f"The additional broad sweep ran {all_tests['tests']:,} tests with {all_tests['failures']} failure and {all_tests['errors']} error. Both reproduce against the original `core.py` at `{preexisting['revision']}`: Oxorio zero-width heading detection and Veridise overview status extraction. These unrelated parser failures remain unchanged; exact IDs/tracebacks and baseline source hash are in `all_tests.json` and `preexisting_tests.json`. `python3 -S scripts/findings/severity_canon.py test-all` reproduces the sweep; `preexisting-tests` rechecks the failures against the original core.", "",
        (f"Full findings checker: `True`; {check['documents']:,} document occurrences, {check['findings']:,} findings, {check['holdout_rows_found']} holdout rows." if check_run["ok"] else
         "Full findings checker: blocked by concurrent full-text cache/receipt updates. The exact failure is retained in `data/findings/severity_canon/pipeline_check.json`; this is an outstanding global span/cache check, not a passing result. Rerun the affected publisher outputs and checker after the extraction job settles."), "",
        f"The independent severity census above verifies all {totals['after_rows']:,} current rows against the canonical resolver and parser-original label, and rejects holdout rows. Existing cache access guards filter hashes before any text is opened. This task opened no holdout documents and made no network or model calls.", "", "```sh",
        "# Before the first rebuild; refuses to replace the frozen baseline:",
        "python3 -S scripts/findings/severity_canon.py before",
        "python3 scripts/findings/run.py",
        "# Reconcile concurrent policy/parser and completed cache updates:",
        "python3 -S scripts/findings/severity_canon.py sync-cache-receipts",
        "python3 scripts/findings/run.py --firms chainsecurity kudelski-security ottersec zokyo",
        "python3 -S scripts/findings/severity_canon.py refresh-receipts",
        "python3 -S scripts/findings/severity_canon.py test",
        "# This broad sweep currently returns nonzero for the documented baseline failures:",
        "python3 -S scripts/findings/severity_canon.py test-all",
        "python3 -S scripts/findings/severity_canon.py preexisting-tests",
        "python3 -S scripts/findings/severity_canon.py check",
        "python3 -S scripts/findings/severity_canon.py report", "```", "",
        "The local baseline, machine-readable comparison and test receipt are in `data/findings/severity_canon/`. Regeneration preserves the existing full-text membership snapshot and does not run collection, OCR, classification or DB rebuilding. `sync-cache-receipts` reconciles only completed hash-checked cache pairs with extraction receipts; it never changes originals or cached text. Concurrent YAML changes and the original severity-map review/baseline are preserved.", ""]
    (root / "docs/phase4/severity_canon.md").write_text("\n".join(lines))
    written = {"schema/README.md", "scripts/findings/core.py", "scripts/findings/severity_resolve.py",
               "scripts/findings/severity_canon.py", "scripts/findings/test_severity_resolve.py",
               "docs/phase4/severity_canon.md", "docs/phase4/severity_canon_files_written.txt",
               "data/findings/_unknown_layouts.jsonl", "data/findings/summary.json"}
    if check_run["ok"]:
        written.add("data/findings/check.json")
    if (base / "cache_sync.json").exists():
        written.update({"data/fulltext/extractions.jsonl", "data/fulltext/failures.jsonl", "data/fulltext/summary.json"})
    for publisher in after:
        written.update({f"data/findings/{publisher}.jsonl", f"data/findings/validation/{publisher}.jsonl",
                        f"data/findings/validation/{publisher}.json"})
    written.update(str(p.relative_to(root)) for p in base.glob("*.json"))
    (root / "docs/phase4/severity_canon_files_written.txt").write_text(
        "Persistent repository files written by the severity canonicalization task.\n"
        "Includes ignored generated findings/receipts; excludes bytecode and temporary logs/files.\n\n"
        + "\n".join(sorted(written)) + "\n")
    print(json.dumps({"totals": dict(totals), "changed_publishers": modified}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("before", "test", "test-all", "preexisting-tests", "refresh-receipts", "sync-cache-receipts", "check", "report"))
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    if args.command == "before":
        path = args.root / "data/findings/severity_canon/before.json"
        if path.exists():
            raise FileExistsError("Frozen canonicalization baseline already exists")
        write_json(path, census(args.root))
    elif args.command in {"test", "test-all"}:
        tests(args.root, all_tests=args.command == "test-all")
    elif args.command == "preexisting-tests":
        preexisting_tests(args.root)
    elif args.command == "refresh-receipts":
        refresh_receipts(args.root)
    elif args.command == "sync-cache-receipts":
        sync_cache_receipts(args.root)
    elif args.command == "check":
        checked = subprocess.run([sys.executable, "-S", str(ROOT / "scripts/findings/check.py"), "--root", str(args.root)],
                                 cwd=ROOT, capture_output=True, text=True)
        receipt = {"command": "python3 -S scripts/findings/check.py", "ok": checked.returncode == 0,
                   "returncode": checked.returncode, "stderr": checked.stderr, "stdout": checked.stdout}
        if receipt["ok"]:
            receipt["result"] = json.loads((args.root / "data/findings/check.json").read_text())
        elif "Extraction receipt/cache mismatch:" in checked.stderr:
            receipt["reason"] = "concurrent_cache_change"
        else:
            receipt["reason"] = "checker_error"
        write_json(args.root / "data/findings/severity_canon/pipeline_check.json", receipt)
        print(json.dumps(receipt, indent=2))
        raise SystemExit(checked.returncode)
    else:
        report(args.root)


if __name__ == "__main__":
    main()
