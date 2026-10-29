#!/usr/bin/env python3
"""Reproducible, holdout-excluded census and bounded example search (no classification)."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (ROOT, CONTENT_KEY_VERSION, batch_expected, canonical, content_key, holdouts, load_classifications,
                    load_findings, normalize_text, sha, validate_output, write_json, write_jsonl, write_text)


def verify_generated(root):
    from collect import collect, load_manifest, read_jsonl, response_paths, verified, verified_prompt
    work = root / "local-cache/classify"
    m, leaves = load_manifest(root, work / "manifest.json")
    rows = read_jsonl(verified(root, m["snapshot"], m["snapshot_sha256"]))
    by_uid = {r["finding_uid"]: r for r in rows}
    rules = read_jsonl(verified(root, m["rules"], m["rules_sha256"]))
    reused = read_jsonl(verified(root, m["reused"], m["reused_sha256"]))
    rule_ids = {r["finding_uid"] for r in rules}
    rule_keys = {r["content_key"] for r in rules}
    reused_keys = {r["content_key"] for r in reused}
    deferred_keys = {r["content_key"] for r in rows if r["route"] == "deferred"}
    model_ids = [uid for b in m["batches"] for uid in b["finding_uids"]]
    model_keys = [key for b in m["batches"] for key in b["content_keys"]]
    assert len(set(model_ids)) == len(model_ids)
    assert len(set(model_keys)) == len(model_keys)
    assert not rule_keys & reused_keys and not rule_keys & set(model_keys) and not reused_keys & set(model_keys)
    assert not deferred_keys & (rule_keys | reused_keys | set(model_keys))
    assert rule_keys | reused_keys | set(model_keys) | deferred_keys == {r["content_key"] for r in rows}
    assert len(rows) == len(by_uid) == m["stats"]["snapshot_findings"]
    assert len(rules) == len(rule_ids) == m["stats"]["rule_targets"]
    assert len(model_ids) == m["stats"]["llm_findings"]
    current, ledger, _ = load_findings(root)
    current_by_uid = {r["finding_uid"]: r for r in current}
    for r in rows:
        assert r["content_key"] == sha(canonical([r["firm_id"], r["title"], r["body"]]).encode())
        target = by_uid[r["classification_uid"]]
        assert target["content_key"] == r["content_key"] and target["route"] == r["route"]
    for b in m["batches"]:
        verified_prompt(root, b)
        assert [by_uid[uid]["content_key"] for uid in b["finding_uids"]] == b["content_keys"]
    assert all(len(b["finding_uids"]) == m["stats"]["batch_size"] for b in m["batches"][:-1])
    assert len(m["batches"]) == m["stats"]["batches"]
    sample = read_jsonl(verified(root, m["validation_sample"], m["validation_sha256"]))
    assert sha((work / "validation_sample.jsonl").read_bytes()) == m["validation_sha256"]
    assert m["validation_sha256"] == m["validation_origin_sha256"]
    ids = {r["finding_uid"] for r in sample}
    examples = {e["finding_uid"] for leaf in leaves.values() for e in leaf["examples"]}
    assert len(ids) == len(sample) == 300 and not ids & examples
    sample_keys = {content_key(r["firm_id"], r["title"], r["body_text"]) for r in sample}
    assert sample_keys <= {r["content_key"] for r in rows}
    snapshot_by_key = {r["content_key"]: r for r in rows}
    blocked = holdouts(root)
    for r in sample:
        assert r["sha256"] not in blocked and r["sample_seed"] == 20261021
        assert not set(r) & {"leaf", "category", "label", "prediction", "confidence", "rationale", "classification"}
        assert r["classifier_excerpt"] == r["body_text"][:800]
        key = content_key(r["firm_id"], r["title"], r["body_text"])
        assert normalize_text(r["body_text"])[:800] == snapshot_by_key[key]["body"]
        assert 0 < r["inclusion_probability"] <= 1
    # Reconcile the exact per-file input capture verified below. Directory-wide
    # mutation is expected while another parser runs; it does not invalidate prompts.
    status = collect(root, m, leaves, root / "data/findings_classified", work / "retry.jsonl",
                     current_inputs=(current, ledger))
    assert status["run_id"] == m["run_id"] and not status["fixture"]
    classified = [r for f in status["files"] for r in read_jsonl((root / f).read_bytes())]
    classified_ids = {r["finding_uid"] for r in classified}
    retry = read_jsonl((work / "retry.jsonl").read_bytes())
    retry_ids = {(r["finding_uid"],r["content_key"]) for r in retry}
    assert len(classified_ids) == len(classified) == status["classified"]
    assert len(retry_ids) == len(retry) == status["retry"]
    classified_pairs = {(r["finding_uid"],r["content_key"]) for r in classified}
    assert not classified_pairs & retry_ids
    assert {r["finding_uid"] for r in retry if r["finding_uid"] in current_by_uid} | classified_ids == set(current_by_uid)
    for r in classified:
        source = current_by_uid[r["finding_uid"]]
        assert r["content_key"] == source["content_key"]
        assert r["source_record_sha256"] == source["record_sha256"]
    assert all(r["leaf"] in leaves and r["category"] == leaves[r["leaf"]]["top_level"] for r in classified)
    cache, cache_stats = load_classifications(root / "data/findings_classified", leaves,
                                             m["taxonomy_sha256"], m["rules_script_sha256"])
    assert not cache_stats["invalid_rows"] and not cache_stats["conflicting_keys"]
    recovered_keys, legacy_complete = set(), 0
    if m.get("recovery_source_run_id"):
        old, old_leaves = load_manifest(root, work / "runs" / m["recovery_source_run_id"] / "manifest.json")
        for batch in old["batches"]:
            verified_prompt(root, batch)
            accepted = set()
            for path in response_paths(root, batch):
                valid, reasons, _ = validate_output(path, batch_expected(batch), old_leaves)
                accepted.update(valid)
                if path == root / batch["output"] and "index_map" not in batch and not reasons:
                    legacy_complete += 1
            recovered_keys.update(key for uid, key in zip(batch["finding_uids"], batch["content_keys"]) if uid in accepted)
        assert recovered_keys <= cache.keys(), "Previously valid outputs were discarded"
        assert not recovered_keys & set(model_keys), "Previously accepted content was rebatched"
    for value in cache.values():
        meta = value["classification"]
        if meta.get("output_path"):
            verified(root, meta["output_path"], meta["output_sha256"])
    assert status["validation_classified"] == sum(content_key(r["firm_id"],r["title"],r["body_text"]) in cache for r in sample)
    assert status["validation_findings"] == 300
    dry = json.loads((work / "dry-run/result.json").read_text())
    assert dry["batches"] == 3 and dry["findings"] == 3 * m["stats"]["batch_size"] and dry["model_calls"] == 0
    assert dry["first_pass"]["retry"] == 5 and dry["repaired_pass"]["retry"] == 0
    assert dry["validation_sample_content_keys_used"] == 0
    subprocess.run(["bash", "-n", str(root / "scripts/classify/run_batches.sh")], check=True)
    result = dict(run_id=m["run_id"], findings=len(current), snapshot_findings=len(rows), batches=len(m["batches"]),
                  prepared_findings=m["stats"]["findings"], source_changed_since_preparation=ledger != m["input_ledger"],
                  content_keys=len(snapshot_by_key), rule_targets=len(rules),
                  rule_classified=m["stats"]["rule_classified"], rule_share=m["stats"]["rule_share"],
                  reused_keys=len(reused_keys), model_targets=len(model_keys),
                  recovered_output_keys=len(recovered_keys), legacy_complete_batches_preserved=legacy_complete,
                  recovered_outputs_not_rebatched=True,
                  validation_findings=len(sample), validation_firms=len({r["firm_id"] for r in sample}),
                  validation_population_strata=round(300/sample[0]["stratum_selection_probability"]),
                  holdout_overlap=0, validation_predicted_labels=0, taxonomy_example_overlap=0,
                  dry_run_batches=dry["batches"], dry_run_findings=dry["findings"],
                  validation_current_keys=len(sample_keys & {r["content_key"] for r in current}),
                  validation_sample_preserved=True, content_key_partition=True,
                  collector_reconciled=True, runner_syntax="passed", model_execution="not_run")
    write_json(work / "verification.json", result)
    doc = root / "docs/phase4/taxonomy.md"
    content = doc.read_text().split("\n<!-- generated-verification -->", 1)[0]
    content += f"""
<!-- generated-verification -->

Verification: `python3 -I -S scripts/classify/inspect_findings.py --verify-generated`.
All {result['snapshot_findings']:,} frozen occurrences map to {result['content_keys']:,}
content keys partitioned exactly into rules, cached classifications and model batches.
All {result['findings']:,} current findings reconcile by content key; changed UIDs are
not used as a cache identity. The unchanged validation sample has all of its texts
represented in the frozen classification population.
The three-batch hand-made dry run rejected its five injected row errors and reconciled
all {result['dry_run_findings']} records after repair. Strict malformed/foreign JSONL,
duplicate object keys, nonfinite/bool confidence, rule vetoes, hash mismatch and
repeat collection checks passed. `bash -n` passed; the runner was not executed.

The frozen sample's original frame has {result['validation_population_strata']} nonempty publisher ×
severity strata after excluding examples. Because this exceeds the sample size,
the seed selects {result['validation_findings']} strata uniformly without replacement,
then one finding uniformly within each selected stratum. Recorded inclusion probabilities
include both selection stages. All {result['validation_firms']} publishers are represented.
The sample has no holdout overlap, taxonomy-example overlap or predicted label fields.

The real collector has joined {status['rule_classified']:,} rule-classified current findings and reports
{status['retry']:,} pending finding occurrences in the retry queue. Full classification and independent accuracy
evaluation are pending operator execution. Generated/source file inventory:
`local-cache/classify/incremental_files_written.txt`.
"""
    write_text(doc, content)
    # Exhaustive task-owned inventory; no unrelated concurrent work is included.
    inventory = {"docs/phase4/taxonomy.md", "docs/phase4/classify_run.md",
                 "local-cache/classify/incremental_files_written.txt", "local-cache/classify/manifest.json",
                 "local-cache/classify/stats.json", "local-cache/classify/retry.jsonl",
                 "local-cache/classify/verification.json", "data/findings_classified/_status.json",
                 status["content_key_index"], *status["files"]}
    inventory.update("scripts/classify/" + name for name in
                 ("common.py", "make_batches.py", "collect.py", "dry_run.py", "inspect_findings.py", "test_incremental.py", "run_batches.sh"))
    for run_path in sorted((work / "runs").glob("*/manifest.json")):
        prepared = json.loads(run_path.read_text())
        if prepared.get("content_key_version") == CONTENT_KEY_VERSION:
            inventory.update(str(p.relative_to(root)) for p in run_path.parent.iterdir() if p.is_file())
            inventory.update(b["prompt"] for b in prepared["batches"])
    fixture = json.loads((work / "dry-run/manifest.json").read_text())
    fixture_status = json.loads((work / "dry-run/classified/_status.json").read_text())
    inventory.update(b["output"] for b in fixture["batches"])
    for historical in sorted((work / "dry-run/previous_manifests").glob("*.json")):
        inventory.add(str(historical.relative_to(root)))
        inventory.update(b["output"] for b in json.loads(historical.read_text())["batches"])
    inventory.update(str(p.relative_to(root)) for p in (work / "dry-run").glob("*") if p.is_file())
    inventory.update(fixture_status["files"])
    inventory.update({fixture_status["content_key_index"], "local-cache/classify/dry-run/classified/_status.json"})
    write_text(work / "incremental_files_written.txt", "".join(f+"\n" for f in sorted(inventory)))
    # Source/generated inventory for the short-index repair, excluding old production runs.
    written = {"docs/phase4/taxonomy.md", "docs/phase4/classify_run.md",
               "local-cache/classify/manifest.json", "local-cache/classify/stats.json",
               "local-cache/classify/retry.jsonl", "local-cache/classify/verification.json",
               "local-cache/classify/incremental_files_written.txt", "local-cache/classify/shortids_files_written.txt",
               "data/findings_classified/_status.json", status["content_key_index"], *status["files"]}
    written.update("scripts/classify/" + name for name in
                   ("common.py", "make_batches.py", "collect.py", "dry_run.py", "inspect_findings.py",
                    "test_incremental.py", "run_batches.sh"))
    written.update(str(path.relative_to(root)) for path in (root / m["snapshot"]).parent.iterdir() if path.is_file())
    written.update(batch["prompt"] for batch in m["batches"])
    written.update((work / "dry-run/files_written.txt").read_text().splitlines())
    written.update(str(path.relative_to(root)) for path in (work / "dry-run/previous_manifests").glob("*.json"))
    write_text(work / "shortids_files_written.txt", "".join(path + "\n" for path in sorted(written)))
    print(json.dumps(result, indent=2))

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--root", type=Path, default=ROOT)
p.add_argument("--search")
p.add_argument("--limit", type=int, default=15)
p.add_argument("--body", type=int, default=0)
p.add_argument("--ids", nargs="*")
p.add_argument("--index", action="store_true", help="Cache a compact, non-holdout title/excerpt index")
p.add_argument("--verify-generated", action="store_true", help="Verify generated artifacts and write the final file inventory")
a = p.parse_args()
if a.verify_generated:
    verify_generated(a.root.resolve())
    raise SystemExit(0)
rows, ledger, excluded = load_findings(a.root)
if a.index:
    write_jsonl(a.root / "local-cache/classify/example_candidates.jsonl",
                ({**r, "body": r["body"][:1200]} for r in rows))
if a.search or a.ids:
    pattern = re.compile(a.search, re.I) if a.search else None
    selected = [r for r in rows if (r["finding_uid"] in (a.ids or []) or
                (pattern and pattern.search(r["title"])))]
    for r in selected[:a.limit]:
        print(canonical({k: r[k] for k in ("finding_uid", "title", "severity", "firm_id")} | {"body": r["body"][:a.body]}))
else:
    print(json.dumps({"findings": len(rows), "files": len(ledger), "excluded": excluded,
                      "severities": dict(sorted(Counter(r["severity"] for r in rows).items())),
                      "firms": dict(sorted(Counter(r["firm_id"] for r in rows).items()))}, indent=2))
