#!/usr/bin/env python3
"""Validate model JSONL against a frozen manifest and write classification sidecars."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (ROOT, CONTENT_KEY_VERSION, batch_expected, canonical, classification_issues, content_key,
                    classified_dir, content_key_version, error_diagnostics, retryable_capacity, usage_guard_error, work_dir,
                    holdouts, load_classifications, load_findings, load_taxonomy,
                    read_jsonl, sha, valid_cached, validate_output, write_json, write_jsonl)


def under(root, value):
    path = (root / value).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("Manifest path escapes root")
    return path


def verified(root, path, digest):
    path = under(root, path)
    data = path.read_bytes()
    if sha(data) != digest:
        raise ValueError(f"Changed frozen input: {path}")
    return data


def verified_prompt(root, batch):
    data = verified(root, batch["prompt"], batch["prompt_sha256"])
    batch_expected(batch)
    if "index_map" in batch:
        reference = sha(canonical(batch["index_map"]).encode())
        if ("\n\nBATCH REFERENCE (metadata only): " + reference + "\n").encode() not in data:
            raise ValueError("Prompt differs from frozen index map")
    return data


def load_manifest(root, path):
    manifest = json.loads(path.read_text())
    if manifest.get("content_key_version") != content_key_version(manifest.get("max_body_chars", 800)):
        raise ValueError("Regenerate batches with the content-keyed builder")
    if manifest.get("run_version") == "v2":
        from v2 import validate_settings
        validate_settings(manifest)
    verified(root, manifest["taxonomy"], manifest["taxonomy_sha256"])
    taxonomy, leaves = load_taxonomy(under(root, manifest["taxonomy"]))
    if taxonomy["version"] != manifest["taxonomy_version"]:
        raise ValueError("Taxonomy version mismatch")
    if sha((root / "data/holdout/gold_sha256.txt").read_bytes()) != manifest["holdout_sha256"]:
        raise ValueError("Holdout boundary changed; regenerate preparation")
    if "retry_source" in manifest:
        verified(root, manifest["retry_source"], manifest["retry_source_sha256"])
    seen, keys = set(), set()
    for b in manifest["batches"]:
        if not re.fullmatch(r"[0-9a-f]{64}", b["batch_id"]) or b["batch_id"] != b["prompt_sha256"]:
            raise ValueError("Invalid batch identity")
        limit = 25 if manifest.get("run_version") == "v2" and manifest["pass"] in {"retry", "topup", "extra"} else 100
        if not 1 <= len(b["finding_uids"]) <= limit or len(set(b["finding_uids"])) != len(b["finding_uids"]):
            raise ValueError("Invalid batch membership")
        if seen.intersection(b["finding_uids"]):
            raise ValueError("Finding is in multiple batches")
        seen.update(b["finding_uids"])
        if (len(b.get("content_keys", [])) != len(b["finding_uids"]) or
                any(not re.fullmatch(r"[0-9a-f]{64}", key) for key in b["content_keys"]) or
                len(set(b["content_keys"])) != len(b["content_keys"]) or keys.intersection(b["content_keys"])):
            raise ValueError("Invalid/duplicate content-key batch membership")
        keys.update(b["content_keys"])
        under(root, b["prompt"])
        under(root, b["output"])
        batch_expected(b)
    return manifest, leaves


def enrichment(row, value, method, manifest, leaves):
    """Keep classification origin separate from the source row used for the join."""
    uid = row["finding_uid"]
    return dict(finding_uid=uid, finding_id=uid, content_key=row["content_key"],
        content_key_version=manifest.get("content_key_version", CONTENT_KEY_VERSION), document_id=row["document_id"],
        firm_id=row["firm_id"], sha256=row["sha256"], source_file=row["source_file"],
        source_record_sha256=row["record_sha256"], leaf=value["leaf"],
        category=leaves[value["leaf"]]["top_level"], confidence=value["confidence"],
        rationale=value["rationale"], needs_review=value["confidence"] < .7 or value["leaf"].startswith("unclassified."),
        classification=dict(**method, classified_finding_uid=uid,
                            run_id=manifest["run_id"], taxonomy_version=manifest["taxonomy_version"],
                            taxonomy_sha256=manifest["taxonomy_sha256"],
                            input_body_characters=min(manifest.get("max_body_chars", 800), row["body_characters"]),
                            confidence_is="uncalibrated_judgement", fixture=manifest.get("fixture", False)))


def join_current_findings(rows, by_content_key):
    """One sidecar per current occurrence. Never fall back to matching its UID."""
    joined, missing = [], []
    for row in rows:
        value = by_content_key.get(row["content_key"])
        if value is None or value["firm_id"] != row["firm_id"]:
            missing.append(row)
            continue
        uid = row["finding_uid"]
        joined.append({**value, "finding_uid": uid, "finding_id": uid,
                       "document_id": row["document_id"], "sha256": row["sha256"],
                       "source_file": row["source_file"], "source_record_sha256": row["record_sha256"]})
    return joined, missing


def response_paths(root, batch):
    output = under(root, batch["output"])
    return ([output] if output.exists() else []) + sorted(
        [*output.parent.glob(output.name + ".partial.*"),
         *output.parent.glob(output.name + ".rejected.*")])


def frozen_assignments(root, manifest, leaves, assignments=None):
    """Recover valid rows from canonical responses and retained interrupted attempts.

    Only paths bound to this manifest are read; logs/locks are never responses.
    Canonical rows take precedence over partial/rejected attempts for the same UID.
    """
    # Validate outputs against their frozen excerpts, then join to a fresh source
    # snapshot. A regenerated UID or metadata-only change must not waste a label.
    snapshot = read_jsonl(verified(root, manifest["snapshot"], manifest["snapshot_sha256"]))
    rules = read_jsonl(verified(root, manifest["rules"], manifest["rules_sha256"]))
    reused = read_jsonl(verified(root, manifest["reused"], manifest["reused_sha256"]))
    rows = {r["finding_uid"]: r for r in snapshot}
    if len(rows) != len(snapshot):
        raise ValueError("Duplicate snapshot UID")
    blocked = holdouts(root)
    if any(r["sha256"] in blocked for r in rows.values()):
        raise ValueError("Holdout finding in snapshot")
    for r in snapshot:
        if sha(canonical([r["firm_id"], r["title"], r["body"]]).encode()) != r["content_key"]:
            raise ValueError("Snapshot content key differs from classifier input")
    route_keys = {route: {r["content_key"] for r in snapshot if r["route"] == route}
                  for route in ("rule", "reused", "llm", "deferred")}
    expected_keys = set().union(*route_keys.values())
    if len(expected_keys) != sum(map(len, route_keys.values())) or expected_keys != {r["content_key"] for r in snapshot}:
        raise ValueError("Snapshot content routes disagree")
    if ({r["content_key"] for r in rules} != route_keys["rule"] or len(rules) != len(route_keys["rule"]) or
            {r["content_key"] for r in reused} != route_keys["reused"] or len(reused) != len(route_keys["reused"]) or
            {key for b in manifest["batches"] for key in b["content_keys"]} != route_keys["llm"]):
        raise ValueError("Rules/reuse/batches do not partition frozen content keys")
    assignments = dict(assignments or {})
    assignments = {k: r for k,r in assignments.items() if r.get("sha256") not in blocked}
    reasons_by_key, batch_errors = {}, []
    for value in reused:
        if not valid_cached(value, leaves, manifest["taxonomy_sha256"], manifest["rules_script_sha256"], manifest["content_key_version"]):
            raise ValueError("Invalid frozen reused classification")
        if value.get("sha256") in blocked:
            raise ValueError("Holdout classification in reuse cache")
        assignments[value["content_key"]] = value
    for rule in rules:
        clean = {k: rule[k] for k in ("finding_uid", "leaf", "confidence", "rationale")}
        r = rows[clean["finding_uid"]]
        if classification_issues(clean, leaves) or r["content_key"] != rule["content_key"] or r["route"] != "rule":
            raise ValueError("Invalid frozen rule assignment")
        assignments[r["content_key"]] = enrichment(r, clean, dict(method="rule", rule_id=rule["rule_id"],
            rules_sha256=manifest["rules_script_sha256"]), manifest, leaves)
    valid_batches = 0
    for batch in manifest["batches"]:
        if any(uid not in rows or rows[uid]["content_key"] != key or rows[uid]["route"] != "llm" or
               rows[uid]["classification_uid"] != uid for uid,key in zip(batch["finding_uids"], batch["content_keys"])):
            raise ValueError("Batch content-key/UID binding differs from snapshot")
        verified_prompt(root, batch)
        accepted, reasons, errors = {}, {}, []
        for path in response_paths(root, batch):
            path = under(root, path)
            try:
                output_bytes = path.read_bytes()
            except OSError as exc:
                errors.append(f"{path.name}: {exc}")
                continue
            valid, invalid, diagnostics = validate_output(path, batch_expected(batch), leaves, data=output_bytes)
            errors.extend(f"{path.name}: {error}" for error in diagnostics)
            output_sha, output_path = sha(output_bytes), str(path.relative_to(root))
            for uid, value in valid.items():
                accepted.setdefault(uid, (value, output_sha, output_path))
            for uid, why in invalid.items():
                reasons.setdefault(uid, []).extend(why)
        reasons = {uid: reasons.get(uid, ["missing_index" if "index_map" in batch else "missing_uid"])
                   for uid in batch["finding_uids"] if uid not in accepted}
        done = bool(accepted) if manifest.get("run_version") == "v2" else not reasons
        if done:
            valid_batches += 1
        if errors:
            batch_errors.append(dict(batch_id=batch["batch_id"], errors=errors))
        for uid, (value, output_sha, output_path) in accepted.items():
            r = rows[uid]
            assignments[r["content_key"]] = enrichment(r, value, dict(method="llm", model=manifest["model"],
                                          reasoning_effort=manifest["reasoning_effort"],
                                          batch_id=batch["batch_id"], prompt_sha256=batch["prompt_sha256"],
                                          output_sha256=output_sha, output_path=output_path), manifest, leaves)
        for uid, why in sorted(reasons.items()):
            reasons_by_key[rows[uid]["content_key"]] = dict(batch_id=batch["batch_id"],
                i=batch["finding_uids"].index(uid) + 1 if "index_map" in batch else None,
                reasons=sorted(set(why)))
    return assignments, reasons_by_key, batch_errors, valid_batches, snapshot


def collect(root, manifest, leaves, output_dir, retry_path, current_inputs=None):
    if manifest.get("fixture") and output_dir.resolve().is_relative_to(root / "data"):
        raise ValueError("Synthetic dry-run labels may never be written under data/")
    if "base_manifests" in manifest:
        assignments = {}  # Chained runs reuse only the recorded completed state, never loose sidecars.
    else:
        assignments, _ = load_classifications(output_dir, leaves, manifest["taxonomy_sha256"], manifest["rules_script_sha256"], manifest["content_key_version"])
    assignments, reasons_by_key, batch_errors, valid_batches, snapshot = frozen_assignments(
        root, manifest, leaves, assignments)
    expected_keys = {r["content_key"] for r in snapshot}
    if manifest.get("fixture"):
        current, ledger, sample = snapshot, [], []
    else:
        if current_inputs is None:
            current, ledger, _ = load_findings(root, manifest.get("max_body_chars", 800))
        else:
            current, ledger = current_inputs
        sample = read_jsonl(verified(root, manifest["validation_sample"], manifest["validation_sha256"]))
    joined, missing = join_current_findings(current, assignments)
    grouped = defaultdict(list)
    for value in joined:
        grouped[value["firm_id"]].append(value)
    retry, seen_missing = [], set()
    # Include both current gaps and frozen targets (including frozen sample texts).
    for r in missing + snapshot:
        identity = (r["finding_uid"], r["content_key"])
        if r["content_key"] not in assignments and identity not in seen_missing:
            retry.append(dict(finding_uid=r["finding_uid"], content_key=r["content_key"],
                              **reasons_by_key.get(r["content_key"], dict(batch_id=None, reasons=["unclassified_content"]))))
            seen_missing.add(identity)
    sample_keys = [content_key(r["firm_id"], r["title"], r["body_text"], manifest.get("max_body_chars", 800)) for r in sample]
    if not set(sample_keys) <= expected_keys:
        raise ValueError("Frozen validation findings missing from classification targets")
    # Write all publisher partitions, including empty ones, so stale assignments do not survive.
    firms = {r["firm_id"] for r in current} | {r["firm_id"] for r in snapshot}
    firms.update(p.stem for p in output_dir.glob("*.jsonl") if not p.stem.startswith("_"))
    write_jsonl(output_dir / "_by_content_key.jsonl", (assignments[k] for k in sorted(assignments)))
    for firm in sorted(firms):
        write_jsonl(output_dir / (firm+".jsonl"), sorted(grouped[firm], key=lambda r:r["finding_uid"]))
    write_jsonl(retry_path, sorted(retry, key=lambda r: (r["finding_uid"], r["content_key"])))
    stats = dict(run_id=manifest["run_id"], fixture=manifest.get("fixture", False), findings=len(current),
                 classified=len(joined), rule_classified=sum(r["classification"]["method"] == "rule" for r in joined),
                 llm_classified=sum(r["classification"]["method"] == "llm" for r in joined),
                 cached_content_keys=len(assignments), frozen_findings=len(snapshot),
                 frozen_pending_keys=len(expected_keys - assignments.keys()), current_retry=len(missing),
                 source_changed_since_preparation=ledger != manifest["input_ledger"], current_input_ledger=ledger,
                 validation_findings=len(sample_keys), validation_classified=sum(k in assignments for k in sample_keys),
                 validation_pending=sum(k not in assignments for k in sample_keys),
                 retry=len(retry), batches=len(manifest["batches"]), valid_batches=valid_batches,
                 needs_review=sum(r["needs_review"] for group in grouped.values() for r in group),
                 retry_reasons=dict(sorted(Counter(reason for r in retry for reason in r["reasons"]).items())),
                 batch_errors=batch_errors,
                 content_key_index=str((output_dir / "_by_content_key.jsonl").relative_to(root)),
                 files=[str((output_dir / (firm+".jsonl")).relative_to(root)) for firm in sorted(firms)])
    if manifest.get("run_version") == "v2":
        from v2 import extra_sources_changed
        stats["source_changed_since_preparation"] |= extra_sources_changed(root, manifest)
    if "base_manifests" in manifest:
        extra_stats = collect_extra(root, manifest, leaves, output_dir / "extra", retry_path.parent / "extra/retry.jsonl",
                                    recovery=(assignments, reasons_by_key, batch_errors, valid_batches, snapshot))
        stats.update(extra_classified=extra_stats["classified"], extra_retry=extra_stats["retry"],
                     extra_excluded=extra_stats["excluded"])
    write_json(output_dir / "_status.json", stats)
    return stats


def collect_extra(root, manifest, leaves, output_dir, retry_path, recovery=None):
    """Sidecars for the extra-source pass under data/findings_classified_v2/extra/.

    Model and content-key-reused labels come from the frozen manifest exactly like other passes;
    joined rows carry their twin's base-pass label verbatim plus a label_join receipt. Every row
    records extra_pass provenance. Excluded rows go to _excluded.jsonl, never to a label file.
    """
    assignments, reasons_by_key, batch_errors, valid_batches, snapshot = recovery or frozen_assignments(root, manifest, leaves)
    if "base_manifests" in manifest:
        snapshot = [r for r in snapshot if r["stream"] != "findings"]
        extra_keys = {r["content_key"] for r in snapshot}
        assignments = {k: r for k, r in assignments.items() if k in extra_keys}
    joins = read_jsonl(verified(root, manifest["joins"], manifest["joins_sha256"]))
    excluded = read_jsonl(verified(root, manifest["excluded"], manifest["excluded_sha256"]))
    sidecars, retry = [], []
    for r in snapshot:
        value = assignments.get(r["content_key"])
        if value is None:
            retry.append(dict(finding_uid=r["finding_uid"], content_key=r["content_key"],
                              **reasons_by_key.get(r["content_key"], dict(batch_id=None, reasons=["unclassified_content"]))))
            continue
        sidecars.append({**value, "finding_uid": r["finding_uid"], "finding_id": r["finding_uid"],
                         "document_id": r["document_id"], "sha256": r["sha256"], "source_file": r["source_file"],
                         "source_record_sha256": r["record_sha256"],
                         "extra_pass": dict(run_id=manifest["run_id"], route=r["route"], stream=r["stream"])})
    for j in joins:
        label = j["label"]
        sidecars.append({**label, **{k: j[k] for k in ("content_key", "document_id", "sha256", "source_file",
                                                        "source_record_sha256", "label_join")},
                         "finding_uid": j["finding_uid"], "finding_id": j["finding_uid"],
                         "extra_pass": dict(run_id=manifest["run_id"], route="joined", stream=j["stream"])})
    grouped = defaultdict(list)
    for value in sidecars:
        grouped[value["firm_id"]].append(value)
    firms = set(grouped) | {p.stem for p in output_dir.glob("*.jsonl") if not p.stem.startswith("_")}
    write_jsonl(output_dir / "_by_content_key.jsonl", (assignments[k] for k in sorted(assignments)))
    write_jsonl(output_dir / "_excluded.jsonl", excluded)
    for firm in sorted(firms):
        write_jsonl(output_dir / (firm + ".jsonl"), sorted(grouped[firm], key=lambda r: r["finding_uid"]))
    write_jsonl(retry_path, sorted(retry, key=lambda r: (r["finding_uid"], r["content_key"])))
    routes = Counter(r["extra_pass"]["route"] for r in sidecars)
    stats = dict(run_id=manifest["run_id"], pass_name=manifest["pass"], base_run_id=manifest["base_run_id"],
                 fixture=manifest.get("fixture", False), sources=manifest["stats"].get("sources", manifest["stats"].get("extra_sources", 0)),
                 classified=len(sidecars), routes=dict(sorted(routes.items())),
                 llm_classified=sum(r["classification"]["method"] == "llm" and
                                    r["classification"]["run_id"] == manifest["run_id"] for r in sidecars),
                 excluded=dict(sorted(Counter(r["reason"] for r in excluded).items())),
                 retry=len(retry), batches=len(manifest["batches"]), valid_batches=valid_batches,
                 needs_review=sum(r["needs_review"] for r in sidecars),
                 retry_reasons=dict(sorted(Counter(reason for r in retry for reason in r["reasons"]).items())),
                 batch_errors=batch_errors, validation_pending=0,
                 files=[str((output_dir / (firm + ".jsonl")).relative_to(root)) for firm in sorted(firms)])
    write_json(output_dir / "_status.json", stats)
    return stats


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, default=ROOT)
    p.add_argument("--version", choices=("v1", "v2"), default="v1")
    p.add_argument("--max-body-chars", type=int)
    p.add_argument("--model")
    p.add_argument("--effort", "--reasoning-effort", dest="effort")
    p.add_argument("--manifest", type=Path)
    p.add_argument("--output-dir", type=Path)
    p.add_argument("--retry-path", type=Path)
    p.add_argument("--check-batch", help="Read-only response check; v1 requires completeness, v2 at least one valid row")
    p.add_argument("--output", type=Path, help="Response path for --check-batch")
    p.add_argument("--allow-partial", action="store_true",
                   help="With --check-batch, exit 0 if at least one row is valid (no writes)")
    p.add_argument("--list-batches", action="store_true", help="Print batch ID, prompt and output, separated by tabs")
    p.add_argument("--require-complete", action="store_true")
    p.add_argument("--runner-settings", action="store_true", help="Read-only model, effort, body limit and pass TSV")
    p.add_argument("--finish-pass", action="store_true", help="Record successful runner pass after collection (v2 only)")
    p.add_argument("--pass-finished", action="store_true", help="Read-only check for a completed v2 runner pass")
    p.add_argument("--retryable-capacity", nargs=2, type=Path, metavar=("LOG", "PROMPT"))
    p.add_argument("--guard-failure", nargs=2, type=Path, metavar=("LOG", "PROMPT"))
    a = p.parse_args()
    root = a.root.resolve()
    if a.retryable_capacity:
        return 0 if retryable_capacity(*a.retryable_capacity) else 1
    if a.guard_failure:
        return 0 if usage_guard_error(error_diagnostics(*a.guard_failure)) else 1
    work = work_dir(root, a.version)
    manifest, leaves = load_manifest(root, a.manifest or work / "manifest.json")
    if manifest.get("run_version", "v1") != a.version:
        p.error("--version differs from frozen manifest")
    for name, supplied, frozen in (("max-body-chars", a.max_body_chars, manifest.get("max_body_chars", 800)),
                                   ("model", a.model, manifest["model"]),
                                   ("effort", a.effort, manifest["reasoning_effort"])):
        if supplied is not None and supplied != frozen:
            p.error(f"--{name} differs from frozen manifest")
    if a.runner_settings:
        print("\t".join(map(str, (manifest["model"], manifest["reasoning_effort"],
                                  manifest.get("max_body_chars", 800), manifest.get("pass", "main")))))
        return 0
    if a.pass_finished:
        if a.version != "v2":
            p.error("--pass-finished requires --version v2")
        from v2 import require_finished
        try:
            require_finished(root, manifest)
        except ValueError:
            return 1
        return 0
    if a.list_batches:
        if manifest.get("fixture"):
            raise ValueError("Runner may not launch a fixture manifest")
        for b in manifest["batches"]:
            verified_prompt(root, b)
            print("\t".join((b["batch_id"], str(under(root,b["prompt"])), str(under(root,b["output"])))))
        return 0
    if a.check_batch:
        matches = [b for b in manifest["batches"] if b["batch_id"] == a.check_batch]
        if len(matches) != 1:
            raise ValueError("Batch not in manifest")
        batch = matches[0]
        verified_prompt(root, batch)
        accepted, reasons, errors = validate_output(a.output or under(root, batch["output"]), batch_expected(batch), leaves)
        if reasons or errors:
            print(canonical(dict(batch_id=batch["batch_id"], accepted=len(accepted), rejected=len(reasons), errors=errors)), file=sys.stderr)
        if manifest.get("run_version") == "v2" or a.allow_partial:
            return 0 if accepted else 1
        if reasons:
            return 1
        return 0
    extra = manifest.get("pass") == "extra"
    if extra:
        # The extra pass owns its own work and sidecar subdirectories; it never rewrites base-pass files.
        work = work / "extra"
    output_dir = a.output_dir or classified_dir(root, a.version) / ("extra" if extra else "")
    retry_path = a.retry_path or work / "retry.jsonl"
    if a.version == "v2" and (not output_dir.resolve().is_relative_to(classified_dir(root, "v2") / ("extra" if extra else "")) or
                               not retry_path.resolve().is_relative_to(work)):
        p.error("v2 sidecars and retries must stay in their versioned directories")
    if a.finish_pass:
        if a.version != "v2":
            p.error("--finish-pass requires --version v2")
        from v2 import assert_pass_attempted
        assert_pass_attempted(root, manifest)
    if extra:
        output_dir.mkdir(parents=True, exist_ok=True)
    stats = (collect_extra if extra else collect)(root, manifest, leaves, output_dir, retry_path)
    if a.finish_pass:
        write_json(work / "passes" / (manifest["run_id"] + ".json"),
                   dict(run_id=manifest["run_id"], pass_name=manifest["pass"]))
    print(json.dumps({k:v for k,v in stats.items() if k not in {"files", "batch_errors", "current_input_ledger"}}, indent=2))
    return 1 if a.require_complete and (stats["retry"] or stats["validation_pending"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
