"""Fresh production preparation, one retry, and chained source top-ups. No model calls."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (ROOT, canonical, classified_dir, classifier_row, content_key, content_key_version, holdouts,
                    load_findings, load_taxonomy, normalize_text, read_jsonl, sha, work_dir,
                    write_json, write_jsonl, write_text)
from pilot_make import CONFIGS, FINDINGS_MARKER, PILOT, PROMPT

CONFIG = "D_sol61_medium_3000"
MODEL, EFFORT, BODY_LIMIT = CONFIGS[CONFIG]
FOLLOW_UP_PASSES = {"retry", "topup"}
# Separate, single-round pass over analysis-selected rows outside data/findings/*.jsonl (own work dir).
EXTRA_PASS = "extra"
SMALL_BATCH_PASSES = FOLLOW_UP_PASSES | {EXTRA_PASS}


def validate_settings(manifest):
    round_number = manifest.get("retry_round")
    valid_round = (type(round_number) is int and
                   (round_number >= 1 if manifest.get("pass") == "topup" else
                    round_number == (1 if manifest.get("pass") == "retry" else 0)))
    if valid_round and manifest.get("pass") == "topup" and round_number > 1 and not manifest.get("base_manifests"):
        valid_round = False
    if "topup_round" in manifest or (manifest.get("pass") == "retry" and "base_manifests" in manifest):
        if (manifest.get("pass") != "retry" or not manifest.get("base_manifests") or
                manifest.get("base_pass") != "topup" or type(manifest.get("topup_round")) is not int or
                manifest["topup_round"] < 1):
            valid_round = False
    if (manifest.get("max_body_chars") != BODY_LIMIT or manifest.get("model") != MODEL or
            manifest.get("reasoning_effort") != EFFORT or
            manifest.get("pass") not in {"main", EXTRA_PASS, *FOLLOW_UP_PASSES} or
            not valid_round):
        raise ValueError("v2 requires D_sol61_medium_3000, one retry, and positive numbered top-up rounds")


def pilot_taxonomy(root):
    data = (root / "schema/taxonomy.yaml").read_bytes()
    taxonomy, leaves = load_taxonomy(root / "schema/taxonomy.yaml")
    pilot = json.loads((root / PILOT / "manifest.json").read_text())
    shared = PROMPT + canonical(taxonomy)
    if pilot["taxonomy_sha256"] != sha(data) or pilot["shared_prompt_sha256"] != sha(shared.encode()):
        raise ValueError("Taxonomy/shared instructions differ from the frozen pilot")
    config = pilot["configs"][CONFIG]
    if (config["model"], config["effort"], config["max_body_chars"]) != (MODEL, EFFORT, BODY_LIMIT):
        raise ValueError("Frozen pilot configuration differs")
    return data, taxonomy, leaves, shared


def prepare(args):
    from collect import frozen_assignments, load_manifest
    root = args.root.resolve()
    work = work_dir(root, "v2")
    output = classified_dir(root, "v2")
    topup = bool(getattr(args, "topup", False))
    if topup and args.from_retry is not None:
        raise ValueError("Choose either --from-retry or --topup")
    settings = dict(run_version="v2", model=args.model or MODEL, reasoning_effort=args.effort or EFFORT,
                    max_body_chars=args.max_body_chars if args.max_body_chars is not None else BODY_LIMIT,
                    pass_name="topup" if topup else "retry" if args.from_retry is not None else "main")
    settings["pass"] = settings.pop("pass_name")
    settings["retry_round"] = int(settings["pass"] in FOLLOW_UP_PASSES)
    validate_settings(settings)
    if args.skip_classified is not None:
        if settings["pass"] != "retry" or (root / args.skip_classified).resolve() != output:
            raise ValueError("A fresh v2 main pass cannot reuse labels; retry recovery uses only its own frozen main pass")
    taxonomy_bytes, taxonomy, leaves, shared = pilot_taxonomy(root)
    active = work / "manifest.json"
    previous = None
    if active.exists():
        previous, _ = load_manifest(root, active)
        for key in ("run_version", "model", "reasoning_effort", "max_body_chars"):
            if previous.get(key) != settings[key]:
                raise ValueError("Existing v2 settings differ; existing artifacts were preserved")
        if previous["taxonomy_sha256"] != sha(taxonomy_bytes):
            raise ValueError("Existing v2 taxonomy differs")
    if args.from_retry is not None and previous and previous["pass"] == "topup":
        return prepare_topup_retry(root, previous, settings, taxonomy_bytes, shared, args.from_retry)
    if topup and previous and (previous["pass"] != "main" or (extra_dir(root) / "sources.jsonl").exists()):
        return prepare_chained_topup(root, previous, settings, taxonomy_bytes, taxonomy, leaves, shared)
    if settings["pass"] == "main":
        rows, ledger, excluded = load_findings(root, BODY_LIMIT)
        if previous:
            if previous["pass"] != "main" or previous["input_ledger"] != ledger:
                raise ValueError("v2 is already frozen; resume its current manifest instead of regenerating")
            verify(root)
            print(json.dumps(previous["stats"], indent=2))
            return previous
        if any(output.glob("*.jsonl")) or any((work / "outputs").glob("*")):
            raise ValueError("Fresh v2 requires an empty destination; existing files were preserved")
        rows = [classifier_row(r, BODY_LIMIT) for r in rows]
        assignments, retry_bytes, retry_keys, topup_targets = {}, None, None, None
    else:
        if not previous or previous["pass"] != "main":
            raise ValueError("The one v2 retry/top-up pass is already prepared or no main pass exists; resume the active manifest")
        marker = work / "passes" / (previous["run_id"] + ".json")
        if not marker.exists() or json.loads(marker.read_text()) != dict(run_id=previous["run_id"], pass_name="main"):
            raise ValueError("Retry preparation requires a completed main runner pass (--finish-pass)")
        from_retry = Path("retry.jsonl") if topup else args.from_retry
        retry_path = work / "retry.jsonl" if from_retry == Path("retry.jsonl") else root / from_retry
        if retry_path.resolve() != work / "retry.jsonl":
            raise ValueError("v2 retries must use the collector's versioned retry list")
        retry_bytes = retry_path.read_bytes()
        retry_rows = read_jsonl(retry_bytes)
        if any(not isinstance(r, dict) or not isinstance(r.get("content_key"), str) or
               not isinstance(r.get("finding_uid"), str) for r in retry_rows):
            raise ValueError("Invalid content-keyed retry list")
        assignments, main_reasons, _, _, rows = frozen_assignments(root, previous, leaves)
        retry_keys = {r["content_key"] for r in retry_rows}
        topup_targets = None
        if topup:
            rows, ledger, excluded, retry_keys, topup_targets, topup_stats = topup_plan(
                root, previous, rows, assignments, main_reasons, retry_keys)
        else:
            if not retry_keys <= {r["content_key"] for r in rows}:
                raise ValueError("Retry list contains keys outside the frozen main pass; the source changed since "
                                 "the main pass froze, so prepare a top-up pass with make_batches.py --version v2 --topup")
            ledger, excluded = previous["input_ledger"], previous["stats"]["excluded"]
    groups = defaultdict(list)
    for row in rows:
        groups[row["content_key"]].append(row)
    pending, reused, snapshot = [], [], []
    for key, group in sorted(groups.items()):
        representative = group[0]
        if key in assignments:
            route = "reused"
            reused.append(assignments[key])
        elif retry_keys is None or key in retry_keys:
            route = "llm"
            pending.append(representative)
        else:
            route = "deferred"
        snapshot.extend({**r, "route": route, "classification_uid": representative["finding_uid"]} for r in group)
    rule_sha = sha(Path(__file__).with_name("rules.py").read_bytes())
    run_id = sha(canonical(dict(settings=settings, inputs=ledger, taxonomy=sha(taxonomy_bytes),
                                shared=sha(shared.encode()), retry=sha(retry_bytes) if retry_bytes is not None else None,
                                reused=reused, main_run=previous["run_id"] if previous else None)).encode())
    run = work / "runs" / run_id
    write_text(run / "taxonomy.yaml", taxonomy_bytes.decode())
    write_jsonl(run / "inputs.jsonl", snapshot)
    write_jsonl(run / "rules.jsonl", [])
    write_jsonl(run / "reused.jsonl", reused)
    write_jsonl(run / "validation_sample.jsonl", [])  # v2 targets current findings only
    if retry_bytes is not None:
        write_text(run / "retry_source.jsonl", retry_bytes.decode())
    if topup_targets is not None:
        write_jsonl(run / "topup_targets.jsonl", topup_targets)
    batch_size = 25 if settings["pass"] in FOLLOW_UP_PASSES else 100
    batches = build_batches(root, work, pending, shared, batch_size,
                            run_id=run_id if settings["pass"] in FOLLOW_UP_PASSES else None)
    stats = dict(findings=len(rows), input_files=len(ledger), excluded=excluded, content_keys=len(groups),
                 llm_findings=len(pending), reused_keys=len(reused), rule_targets=0,
                 deferred_keys=len(groups) - len(pending) - len(reused), batches=len(batches),
                 batch_size=batch_size, last_batch_size=len(batches[-1]["finding_uids"]) if batches else 0)
    if topup_targets is not None:
        stats.update(topup_stats)
    manifest = dict(**settings, version="phase4c-production-v2", content_key_version=content_key_version(BODY_LIMIT),
                    run_id=run_id, fixture=False, pilot_config=CONFIG, shared_prompt_sha256=sha(shared.encode()),
                    taxonomy_version=taxonomy["version"], taxonomy_sha256=sha(taxonomy_bytes),
                    rules_script_sha256=rule_sha, input_ledger=ledger,
                    holdout_sha256=sha((root / "data/holdout/gold_sha256.txt").read_bytes()),
                    batches=batches, stats=stats)
    for key, filename in (("taxonomy", "taxonomy.yaml"), ("snapshot", "inputs.jsonl"), ("rules", "rules.jsonl"),
                          ("reused", "reused.jsonl"), ("validation_sample", "validation_sample.jsonl")):
        manifest[key] = str((run / filename).relative_to(root))
        manifest["validation_sha256" if key == "validation_sample" else key + "_sha256"] = sha((run / filename).read_bytes())
    if previous:
        manifest.update(main_manifest=str((work / "runs" / previous["run_id"] / "manifest.json").relative_to(root)),
                        retry_source=str((run / "retry_source.jsonl").relative_to(root)), retry_source_sha256=sha(retry_bytes))
    if topup_targets is not None:
        manifest.update(main_run_id=previous["run_id"], topup_targets=str((run / "topup_targets.jsonl").relative_to(root)),
                        topup_targets_sha256=sha((run / "topup_targets.jsonl").read_bytes()))
    (work / "outputs").mkdir(parents=True, exist_ok=True)
    write_json(run / "manifest.json", manifest)
    write_json(active, manifest)
    write_json(work / "stats.json", stats)
    if settings["pass"] == "main":
        report(root, manifest)
    result = verify(root)
    write_json(work / "verification.json", result)
    write_inventory(root)
    print(json.dumps(stats, indent=2))
    return manifest


def build_batches(root, work, pending, shared, batch_size, run_id=None):
    """Content-addressed prompts: shared pilot instructions + index reference + normalized inputs."""
    batches = []
    for offset in range(0, len(pending), batch_size):
        group = pending[offset:offset + batch_size]
        indexes = [dict(i=i, finding_uid=r["finding_uid"], content_key=r["content_key"])
                   for i, r in enumerate(group, 1)]
        prompt = (shared + "\n\nBATCH REFERENCE (metadata only): " + sha(canonical(indexes).encode()) +
                  FINDINGS_MARKER + "".join(canonical(dict(i=i, title=r["title"], body=r["body"])) + "\n"
                                           for i, r in enumerate(group, 1)))
        ident = sha(prompt.encode())
        path = work / "batches" / (ident + ".md")
        if path.exists() and path.read_bytes() != prompt.encode():
            raise ValueError("Content-addressed prompt collision")
        write_text(path, prompt)
        outputs = work / "outputs" / run_id if run_id else work / "outputs"
        batches.append(dict(batch_id=ident, prompt=str(path.relative_to(root)), prompt_sha256=ident,
                            output=str((outputs / (ident + ".jsonl")).relative_to(root)),
                            finding_uids=[r["finding_uid"] for r in group],
                            content_keys=[r["content_key"] for r in group], index_map=indexes))
    return batches


def topup_plan(root, main, main_snapshot, assignments, main_reasons, retry_keys):
    """Targets of the single top-up pass, used when findings changed after the main pass froze.

    Queues current content keys absent from the frozen main pass plus current keys that the
    main pass attempted without a valid label. Every other current key reuses its main-pass
    label verbatim; nothing already classified is sent to the model again.
    """
    current, ledger, excluded = load_findings(root, BODY_LIMIT)
    if ledger == main["input_ledger"]:
        raise ValueError("Current findings equal the frozen main pass; use --from-retry instead of --topup")
    current = [classifier_row(r, BODY_LIMIT) for r in current]
    main_keys = {r["content_key"] for r in main_snapshot}
    current_keys = {r["content_key"] for r in current}
    pending = main_keys - assignments.keys()
    if pending != set(main_reasons):
        raise ValueError("Main-pass pending keys disagree with its recorded failures")
    new = current_keys - main_keys
    targets = new | (pending & current_keys)
    if not targets <= retry_keys or not retry_keys - targets <= pending - current_keys:
        raise ValueError("Collector retry list differs from the top-up targets; collect the main pass "
                         "against the current findings first")
    first = {}
    for row in current:  # sorted by finding UID, like the representative chosen in prepare()
        first.setdefault(row["content_key"], row)
    rows = [dict(content_key=key, finding_uid=first[key]["finding_uid"], firm_id=first[key]["firm_id"],
                 origin="new_since_main" if key in new else "main_pending",
                 main_reasons=None if key in new else main_reasons[key]["reasons"]) for key in sorted(targets)]
    stats = dict(main_run_id=main["run_id"], main_findings=len(main_snapshot), main_content_keys=len(main_keys),
                 main_keys_not_current=len(main_keys - current_keys),
                 reused_main_keys=len(current_keys & assignments.keys()),
                 topup_new_keys=len(new), topup_new_findings=sum(r["content_key"] in new for r in current),
                 topup_main_pending_keys=len(pending & current_keys),
                 main_pending_not_current=len(pending - current_keys))
    return current, ledger, excluded, targets, rows, stats


def manifest_reference(root, path):
    from collect import under
    path = under(root, path)
    data = path.read_bytes()
    return dict(path=str(path.relative_to(root)), sha256=sha(data), run_id=json.loads(data)["run_id"])


def require_finished(root, manifest):
    work = extra_dir(root) if manifest["pass"] == EXTRA_PASS else work_dir(root, "v2")
    marker = work / "passes" / (manifest["run_id"] + ".json")
    if not marker.exists() or json.loads(marker.read_text()) != dict(run_id=manifest["run_id"], pass_name=manifest["pass"]):
        raise ValueError("Top-up requires a completed active v2 pass (--finish-pass); an already prepared pass must be resumed")


def assert_unattempted(root, manifest):
    from collect import response_paths, under
    for batch in manifest["batches"]:
        output = under(root, batch["output"])
        if (response_paths(root, batch) or output.with_name(output.name + ".lock").exists() or
                any(output.parent.glob(output.name + ".log.*"))):
            raise ValueError("An already prepared top-up has model attempts; resume it instead of refreshing")


def completed_state(root, references, settings):
    """Recover only manifest-bound labels from the recorded completed ancestry, never loose sidecars.

    Removed keys remain in the state, so reintroducing one reuses its original label too.
    Legacy main/top-up/extra manifests remain readable without rewriting any of them.
    """
    from collect import frozen_assignments, load_manifest, under, verified
    assignments, attempted, reasons, runs, visiting = {}, set(), {}, [], set()

    def visit(reference):
        data = verified(root, reference["path"], reference["sha256"])
        m = json.loads(data)
        if m["run_id"] != reference["run_id"] or m["run_id"] in visiting:
            raise ValueError("Invalid/cyclic top-up base provenance")
        if m["run_id"] in runs:
            return
        visiting.add(m["run_id"])
        m, leaves = load_manifest(root, under(root, reference["path"]))
        require_finished(root, m)
        for key in ("model", "reasoning_effort", "max_body_chars", "taxonomy_sha256", "shared_prompt_sha256"):
            if m[key] != settings[key]:
                raise ValueError("Top-up base configuration differs from the frozen pass")
        dependencies = m.get("base_manifests")
        if dependencies is None:
            dependencies = [manifest_reference(root, m[key]) for key in ("main_manifest", "base_manifest") if key in m]
        for dependency in dependencies:
            visit(dependency)
        labels, pending, _, _, snapshot = frozen_assignments(root, m, leaves)
        for key, label in labels.items():
            if label["classification"]["run_id"] != m["run_id"] and assignments.get(key) != label:
                raise ValueError("Reused base label differs from its original completed run")
            if key in assignments and assignments[key] != label:
                raise ValueError("Conflicting labels in completed v2 state")
            if label["classification"]["run_id"] not in {*runs, m["run_id"]}:
                raise ValueError("Base label has an unrecorded run ID")
            assignments[key] = label
        attempted.update(r["content_key"] for r in snapshot)
        reasons.update(pending)
        visiting.remove(m["run_id"])
        runs.append(m["run_id"])

    for reference in references:
        visit(reference)
    return assignments, attempted, {k: v for k, v in reasons.items() if k not in assignments}, runs


def current_extra_sources(root):
    """The exported extra streams are an explicit input; never open the database or gold corpus here."""
    path = extra_dir(root) / "sources.jsonl"
    if not path.exists():
        if (extra_dir(root) / "manifest.json").exists():
            raise ValueError("Missing current extra sources; restore the export before preparing a top-up")
        return b"", b""
    data = path.read_bytes()
    ledger = (path.parent / "sources_ledger.json").read_bytes()
    if json.loads(ledger).get("sources_sha256") != sha(data) or data != path.read_bytes():
        raise ValueError("Extra sources differ from their export ledger; rerun export_extra.py")
    return data, ledger


def extra_sources_changed(root, manifest):
    sources, _ = current_extra_sources(root)
    baseline = manifest.get("sources_sha256")
    if baseline is None:
        active = extra_dir(root) / "manifest.json"
        baseline = json.loads(active.read_text())["sources_sha256"] if active.exists() else sha(b"")
    return sha(sources) != baseline


def chained_plan(root, current, assignments, attempted, reasons, sources):
    primary = [{**r, "stream": "findings"} for r in current]
    extra = route_extra_sources(root, primary, assignments, sources)
    groups = defaultdict(list)
    for row in sorted(primary + [{k: v for k, v in r.items() if k not in {"route", "classification_uid"}}
                                 for r in extra["snapshot"]], key=lambda r: r["finding_uid"]):
        groups[row["content_key"]].append(row)
    snapshot, reused, pending, targets = [], [], [], []
    for key, group in sorted(groups.items()):
        representative = group[0]
        route = "reused" if key in assignments else "llm"
        if route == "reused":
            reused.append(assignments[key])
        else:
            pending.append(representative)
            targets.append(dict(content_key=key, finding_uid=representative["finding_uid"],
                                firm_id=representative["firm_id"],
                                origin="base_pending" if key in attempted else "new_since_base",
                                base_reasons=reasons.get(key, {}).get("reasons"),
                                origins=[{k: r[k] for k in ("finding_uid", "firm_id", "stream", "source_file", "record_sha256")}
                                         for r in group]))
        snapshot.extend({**r, "route": route, "classification_uid": representative["finding_uid"]} for r in group)
    return dict(snapshot=snapshot, reused=reused, pending=pending, targets=targets,
                joins=extra["joins"], excluded=extra["excluded"])


def prepare_chained_topup(root, previous, settings, taxonomy_bytes, taxonomy, leaves, shared):
    """Freeze another top-up against the latest completed primary and extra state."""
    from collect import load_manifest, under
    work = work_dir(root, "v2")
    superseded = None
    marker = work / "passes" / (previous["run_id"] + ".json")
    if not marker.exists() and previous["pass"] == "topup" and "base_manifests" in previous:
        # Concurrent collection may outgrow a dry-run plan. Preserve that run and refresh
        # only if no worker could have started it; its completed base remains the same.
        assert_unattempted(root, previous)
        current, ledger, _ = load_findings(root, BODY_LIMIT)
        del current
        if ledger == previous["input_ledger"] and not extra_sources_changed(root, previous):
            require_finished(root, previous)
        superseded = manifest_reference(root, work / "runs" / previous["run_id"] / "manifest.json")
        reference = previous["base_manifests"][0]
        previous, _ = load_manifest(root, under(root, reference["path"]))
    require_finished(root, previous)
    references = [manifest_reference(root, work / "runs" / previous["run_id"] / "manifest.json")]
    extra_active = extra_dir(root) / "manifest.json"
    extra = None
    if extra_active.exists():
        extra, _ = load_manifest(root, extra_active)
        require_finished(root, extra)
        references.append(manifest_reference(root, extra_dir(root) / "runs" / extra["run_id"] / "manifest.json"))
    current, ledger, excluded = load_findings(root, BODY_LIMIT)
    sources, sources_ledger = current_extra_sources(root)
    old_sources_sha = previous.get("sources_sha256", extra["sources_sha256"] if extra else sha(b""))
    if ledger == previous["input_ledger"] and sha(sources) == old_sources_sha:
        raise ValueError("Current sources equal the already prepared v2 state; resume it (use --from-retry after main)")
    settings = {**settings, "retry_round": previous.get("topup_round", previous["retry_round"]) + 1,
                "taxonomy_sha256": sha(taxonomy_bytes), "shared_prompt_sha256": sha(shared.encode())}
    assignments, attempted, reasons, runs = completed_state(root, references, settings)
    plan = chained_plan(root, [classifier_row(r, BODY_LIMIT) for r in current], assignments, attempted, reasons, sources)
    run_id = sha(canonical(dict(settings=settings, inputs=ledger, sources=sha(sources),
                                bases=references, superseded=superseded,
                                targets=plan["targets"], reused=plan["reused"], joins=plan["joins"])).encode())
    run = work / "runs" / run_id
    if run.exists():
        raise ValueError("Top-up run already exists; resume its recorded manifest")
    manifest = dict(**settings, version="phase4c-production-v2", content_key_version=content_key_version(BODY_LIMIT),
                    run_id=run_id, fixture=False, pilot_config=CONFIG, taxonomy_version=taxonomy["version"],
                    rules_script_sha256=sha(Path(__file__).with_name("rules.py").read_bytes()),
                    holdout_sha256=sha((root / "data/holdout/gold_sha256.txt").read_bytes()),
                    input_ledger=ledger, base_run_id=previous["run_id"], base_run_ids=runs, base_manifests=references)
    if superseded:
        manifest["supersedes_unattempted"] = superseded
    files = dict(taxonomy=("taxonomy.yaml", taxonomy_bytes.decode()), snapshot=("inputs.jsonl", plan["snapshot"]),
                 rules=("rules.jsonl", []), reused=("reused.jsonl", plan["reused"]),
                 validation_sample=("validation_sample.jsonl", []), topup_targets=("topup_targets.jsonl", plan["targets"]),
                 sources=("sources.jsonl", sources.decode()), sources_ledger=("sources_ledger.json", sources_ledger.decode()),
                 joins=("joins.jsonl", plan["joins"]), excluded=("excluded.jsonl", plan["excluded"]))
    for key, (filename, value) in files.items():
        (write_text if isinstance(value, str) else write_jsonl)(run / filename, value)
        manifest[key] = str((run / filename).relative_to(root))
        manifest["validation_sha256" if key == "validation_sample" else key + "_sha256"] = sha((run / filename).read_bytes())
    manifest["batches"] = build_batches(root, work, plan["pending"], shared, 25, run_id=run_id)
    manifest["stats"] = dict(findings=len(plan["snapshot"]), primary_findings=len(current), input_files=len(ledger),
                             extra_sources=len(read_jsonl(sources)), excluded=excluded,
                             extra_excluded=dict(sorted(Counter(r["reason"] for r in plan["excluded"]).items())),
                             joined_findings=len(plan["joins"]), content_keys=len(plan["reused"]) + len(plan["pending"]),
                             llm_findings=len(plan["pending"]), reused_keys=len(plan["reused"]),
                             rule_targets=0, deferred_keys=0, batches=len(manifest["batches"]), batch_size=25,
                             last_batch_size=len(manifest["batches"][-1]["finding_uids"]) if manifest["batches"] else 0)
    write_json(run / "manifest.json", manifest)
    write_json(work / "manifest.json", manifest)
    write_json(work / "stats.json", manifest["stats"])
    del assignments, attempted, reasons, plan, files, current
    write_json(work / "verification.json", verify(root))
    write_inventory(root)
    print(json.dumps(manifest["stats"], indent=2))
    return manifest


def topup_retry_plan(root, base, assignments, reasons, retry_bytes):
    """Retry exactly the completed top-up's gaps, preserving its frozen occurrence routes."""
    from collect import verified
    original = read_jsonl(verified(root, base["snapshot"], base["snapshot_sha256"]))
    expected = sorted((dict(finding_uid=r["finding_uid"], content_key=r["content_key"],
                            **reasons[r["content_key"]])
                       for r in original if r["content_key"] not in assignments),
                      key=lambda r: (r["finding_uid"], r["content_key"]))
    if not expected or read_jsonl(retry_bytes) != expected:
        raise ValueError("Retry list differs from the completed top-up's residual failures; collect it first")
    groups = defaultdict(list)
    for row in original:
        groups[row["content_key"]].append(row)
    snapshot, reused, pending = [], [], []
    for key, group in sorted(groups.items()):
        representative = group[0]
        route = "reused" if key in assignments else "llm"
        if route == "reused":
            reused.append(assignments[key])
        else:
            pending.append(representative)
        snapshot.extend({**r, "stream": r.get("stream", "findings"), "route": route,
                         "classification_uid": representative["finding_uid"]} for r in group)
    return dict(snapshot=snapshot, reused=reused, pending=pending)


def prepare_topup_retry(root, previous, settings, taxonomy_bytes, shared, retry_path):
    """One separate retry pass per completed top-up; never replace its inputs or responses."""
    from collect import verified
    work = work_dir(root, "v2")
    require_finished(root, previous)
    retry_path = work / "retry.jsonl" if retry_path == Path("retry.jsonl") else root / retry_path
    if retry_path.resolve() != work / "retry.jsonl":
        raise ValueError("v2 retries must use the collector's versioned retry list")
    current, ledger, _ = load_findings(root, BODY_LIMIT)
    del current
    if ledger != previous["input_ledger"] or extra_sources_changed(root, previous):
        raise ValueError("Sources changed since the top-up; prepare --topup instead of --from-retry")
    settings = {**settings, "topup_round": previous["retry_round"],
                "taxonomy_sha256": sha(taxonomy_bytes), "shared_prompt_sha256": sha(shared.encode())}
    references = [manifest_reference(root, work / "runs" / previous["run_id"] / "manifest.json")]
    assignments, _, reasons, runs = completed_state(root, references, settings)
    retry_bytes = retry_path.read_bytes()
    plan = topup_retry_plan(root, previous, assignments, reasons, retry_bytes)
    run_id = sha(canonical(dict(settings=settings, bases=references, retry=sha(retry_bytes),
                                reused=plan["reused"])).encode())
    run = work / "runs" / run_id
    if run.exists():
        raise ValueError("Top-up retry already exists; resume its recorded manifest")
    manifest = {**previous, **settings, "run_id": run_id, "base_run_id": previous["run_id"],
                "base_pass": "topup", "base_run_ids": runs, "base_manifests": references}
    for key in ("main_manifest", "main_run_id", "topup_targets", "topup_targets_sha256", "supersedes_unattempted"):
        manifest.pop(key, None)
    files = dict(taxonomy=("taxonomy.yaml", taxonomy_bytes), retry_source=("retry_source.jsonl", retry_bytes),
                 snapshot=("inputs.jsonl", plan["snapshot"]), reused=("reused.jsonl", plan["reused"]),
                 rules=("rules.jsonl", []), validation_sample=("validation_sample.jsonl", []))
    for key, filename in (("sources", "sources.jsonl"), ("sources_ledger", "sources_ledger.json"),
                          ("joins", "joins.jsonl"), ("excluded", "excluded.jsonl")):
        files[key] = (filename, verified(root, previous[key], previous[key + "_sha256"]) if key in previous else b"")
    for key, (filename, value) in files.items():
        (write_text if isinstance(value, bytes) else write_jsonl)(
            run / filename, value.decode() if isinstance(value, bytes) else value)
        manifest[key] = str((run / filename).relative_to(root))
        manifest["validation_sha256" if key == "validation_sample" else key + "_sha256"] = sha((run / filename).read_bytes())
    manifest["batches"] = build_batches(root, work, plan["pending"], shared, 25, run_id=run_id)
    manifest["stats"] = {**previous["stats"], "llm_findings": len(plan["pending"]),
                         "reused_keys": len(plan["reused"]), "deferred_keys": 0,
                         "batches": len(manifest["batches"]), "batch_size": 25,
                         "last_batch_size": len(manifest["batches"][-1]["finding_uids"])}
    write_json(run / "manifest.json", manifest)
    write_json(work / "manifest.json", manifest)
    write_json(work / "stats.json", manifest["stats"])
    del assignments, reasons, plan, files
    write_json(work / "verification.json", verify(root))
    write_inventory(root)
    print(json.dumps(manifest["stats"], indent=2))
    return manifest


def extra_dir(root):
    return work_dir(root, "v2") / EXTRA_PASS


def title_key(title):
    return normalize_text(title or "").casefold()


def tier_a_scope(root):
    with (root / "registry/scope_tier_a.csv").open() as stream:
        return {r["firm_id"] for r in csv.DictReader(stream)
                if r["scope_group"] in {"firm", "contest_platform"}}


def extra_base(root, settings):
    """The completed active v2 pass whose labels the extra pass may reuse or join."""
    from collect import load_manifest
    work = work_dir(root, "v2")
    base, leaves = load_manifest(root, work / "manifest.json")
    marker = work / "passes" / (base["run_id"] + ".json")
    if not marker.exists() or json.loads(marker.read_text()) != dict(run_id=base["run_id"], pass_name=base["pass"]):
        raise ValueError("The extra pass requires a completed active v2 pass (--finish-pass)")
    for key in ("model", "reasoning_effort", "max_body_chars"):
        if base[key] != settings[key]:
            raise ValueError("Extra pass settings differ from the active v2 pass")
    return base, leaves


def extra_plan(root, base, leaves, sources_bytes):
    """Route each frozen outside-source row: reuse, join to its classified twin, model, or exclude.

    - excluded/holdout and excluded/out_of_scope: the classifier's own boundary, before any text is read.
    - reused: identical v2 content key (firm, normalized title, body[:3000]) already labelled by the base pass.
    - joined: same firm, same original SHA-256 and same casefolded normalized title as current
      data/findings rows that all carry the same base-pass leaf (an alternate rendering of one report).
    - excluded/no_body_text: no body text and no unambiguous twin (title-only input is outside config D).
    - llm: everything else, deduplicated by content key, with the identical pilot prompt.
    """
    from collect import frozen_assignments
    assignments, reasons, _, _, _ = frozen_assignments(root, base, leaves)
    current, ledger, _ = load_findings(root, BODY_LIMIT)
    if ledger != base["input_ledger"]:
        raise ValueError("data/findings changed since the active v2 pass; finish that pass first")
    current = [classifier_row(r, BODY_LIMIT) for r in current]
    if any(r["content_key"] not in assignments for r in current) or reasons:
        raise ValueError("The active v2 pass is incomplete; complete it before the extra pass")
    return {**route_extra_sources(root, current, assignments, sources_bytes), "ledger": ledger}


def route_extra_sources(root, current, assignments, sources_bytes):
    """Apply the existing extra-source boundary and twin rule using a completed label state."""
    twins = defaultdict(list)
    primary_uids = {r["finding_uid"] for r in current}
    for r in current:
        twins[(r["firm_id"], r["sha256"], title_key(r["title"]))].append(r)
    blocked, scope = holdouts(root), tier_a_scope(root)
    sources = read_jsonl(sources_bytes)
    if len({r.get("finding_id") for r in sources}) != len(sources):
        raise ValueError("Duplicate finding in extra sources")
    candidates, joins, excluded = [], [], []
    for s in sorted(sources, key=lambda r: r["finding_id"]):
        uid, firm, digest = s.get("finding_id"), s.get("firm_id"), s.get("sha256")
        if (not isinstance(uid, str) or not uid.startswith("finding:") or not isinstance(firm, str) or
                not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or
                not re.fullmatch(r"[0-9a-f]{64}", str(s.get("record_sha256")))):
            raise ValueError(f"Invalid extra source identity: {uid}")
        base_row = dict(finding_uid=uid, firm_id=firm, document_id=s["document_id"], stream=s["stream"],
                        engagement_id=s.get("engagement_id"))
        # Check identities/hashes before accessing title or body.
        if digest in blocked or firm not in scope:
            excluded.append(dict(base_row, reason="holdout" if digest in blocked else "out_of_scope"))
            continue
        if uid in primary_uids:
            excluded.append(dict(base_row, reason="in_primary_stream"))
            continue
        if not isinstance(s.get("title"), str) or not isinstance(s.get("body"), str):
            raise ValueError(f"Non-text title/body: {uid}")
        row = classifier_row(dict(base_row, sha256=digest, severity=s.get("severity", "unknown"), title=s["title"],
                                  body=s["body"], public_url=s.get("public_url"), source_file=s["source_file"],
                                  record_sha256=s["record_sha256"],
                                  content_key=content_key(firm, s["title"], s["body"], BODY_LIMIT)), BODY_LIMIT)
        if row["content_key"] in assignments:
            candidates.append(row)
            continue
        matches = sorted(twins.get((firm, digest, title_key(row["title"])), []) if row["title"] else [],
                         key=lambda r: r["finding_uid"])
        labels = {assignments[m["content_key"]]["leaf"] for m in matches if m["content_key"] in assignments}
        if len(labels) == 1 and all(m["content_key"] in assignments for m in matches):
            twin = matches[0]
            joins.append(dict(finding_uid=uid, content_key=row["content_key"], firm_id=firm,
                              document_id=row["document_id"], sha256=digest, source_file=row["source_file"],
                              source_record_sha256=row["record_sha256"], stream=row["stream"],
                              engagement_id=row["engagement_id"],
                              label_join=dict(basis="same_firm_original_sha256_and_normalized_title",
                                              twin_finding_uids=[m["finding_uid"] for m in matches],
                                              from_finding_uid=twin["finding_uid"], from_document_id=twin["document_id"],
                                              from_content_key=twin["content_key"],
                                              from_source_record_sha256=twin["record_sha256"]),
                              label=assignments[twin["content_key"]]))
        elif not row["body"]:
            excluded.append(dict(base_row, reason="no_body_text", ambiguous_twins=len(matches)))
        else:
            candidates.append(row)
    groups = defaultdict(list)
    for row in candidates:
        groups[row["content_key"]].append(row)
    snapshot, reused, pending = [], [], []
    for key, group in sorted(groups.items()):
        representative = group[0]
        route = "reused" if key in assignments else "llm"
        if route == "reused":
            reused.append(assignments[key])
        else:
            pending.append(representative)
        snapshot.extend({**r, "route": route, "classification_uid": representative["finding_uid"]} for r in group)
    return dict(snapshot=snapshot, reused=reused, pending=pending, joins=joins, excluded=excluded)


def prepare_extra(args):
    """One extra pass, recorded as its own run, for selected findings outside data/findings/*.jsonl."""
    from collect import load_manifest
    root = args.root.resolve()
    if args.from_retry is not None or args.skip_classified is not None or getattr(args, "topup", False):
        raise ValueError("--extra cannot be combined with --from-retry, --topup or --skip-classified")
    settings = dict(run_version="v2", model=args.model or MODEL, reasoning_effort=args.effort or EFFORT,
                    max_body_chars=args.max_body_chars if args.max_body_chars is not None else BODY_LIMIT)
    settings["pass"], settings["retry_round"] = EXTRA_PASS, 0
    validate_settings(settings)
    work = extra_dir(root)
    active = work / "manifest.json"
    if active.exists():
        previous, _ = load_manifest(root, active)
        for key in ("run_version", "model", "reasoning_effort", "max_body_chars"):
            if previous.get(key) != settings[key]:
                raise ValueError("Existing extra-pass settings differ; existing artifacts were preserved")
        verify_extra(root)
        print(json.dumps(previous["stats"], indent=2))
        return previous
    taxonomy_bytes, taxonomy, leaves, shared = pilot_taxonomy(root)
    base, _ = extra_base(root, settings)
    if base["taxonomy_sha256"] != sha(taxonomy_bytes) or base["shared_prompt_sha256"] != sha(shared.encode()):
        raise ValueError("Extra pass prompt/taxonomy differ from the active v2 pass")
    sources_bytes = (work / "sources.jsonl").read_bytes()
    sources_ledger_bytes = (work / "sources_ledger.json").read_bytes()
    if json.loads(sources_ledger_bytes).get("sources_sha256") != sha(sources_bytes):
        raise ValueError("Extra sources differ from their export ledger; rerun export_extra.py")
    plan = extra_plan(root, base, leaves, sources_bytes)
    run_id = sha(canonical(dict(settings=settings, inputs=plan["ledger"], taxonomy=sha(taxonomy_bytes),
                                shared=sha(shared.encode()), sources=sha(sources_bytes), base_run=base["run_id"],
                                reused=plan["reused"], joins=plan["joins"])).encode())
    run = work / "runs" / run_id
    files = dict(taxonomy=("taxonomy.yaml", taxonomy_bytes.decode()), snapshot=("inputs.jsonl", plan["snapshot"]),
                 rules=("rules.jsonl", []), reused=("reused.jsonl", plan["reused"]),
                 validation_sample=("validation_sample.jsonl", []), sources=("sources.jsonl", sources_bytes.decode()),
                 sources_ledger=("sources_ledger.json", sources_ledger_bytes.decode()),
                 joins=("joins.jsonl", plan["joins"]), excluded=("excluded.jsonl", plan["excluded"]))
    manifest = dict(**settings, version="phase4c-production-v2", content_key_version=content_key_version(BODY_LIMIT),
                    run_id=run_id, fixture=False, pilot_config=CONFIG, shared_prompt_sha256=sha(shared.encode()),
                    taxonomy_version=taxonomy["version"], taxonomy_sha256=sha(taxonomy_bytes),
                    rules_script_sha256=sha(Path(__file__).with_name("rules.py").read_bytes()),
                    input_ledger=plan["ledger"], holdout_sha256=sha((root / "data/holdout/gold_sha256.txt").read_bytes()),
                    base_run_id=base["run_id"], base_pass=base["pass"],
                    base_manifest=str((work_dir(root, "v2") / "runs" / base["run_id"] / "manifest.json").relative_to(root)))
    for key, (filename, value) in files.items():
        (write_text if isinstance(value, str) else write_jsonl)(run / filename, value)
        manifest[key] = str((run / filename).relative_to(root))
        manifest["validation_sha256" if key == "validation_sample" else key + "_sha256"] = sha((run / filename).read_bytes())
    manifest["batches"] = build_batches(root, work, plan["pending"], shared, 25)
    excluded = defaultdict(int)
    for r in plan["excluded"]:
        excluded[r["reason"]] += 1
    manifest["stats"] = dict(sources=len(read_jsonl(sources_bytes)), findings=len(plan["snapshot"]),
                             content_keys=len({r["content_key"] for r in plan["snapshot"]}),
                             llm_findings=sum(r["route"] == "llm" for r in plan["snapshot"]),
                             llm_content_keys=len(plan["pending"]),
                             reused_findings=sum(r["route"] == "reused" for r in plan["snapshot"]),
                             reused_keys=len(plan["reused"]), joined_findings=len(plan["joins"]),
                             excluded=dict(sorted(excluded.items())), batches=len(manifest["batches"]), batch_size=25)
    (work / "outputs").mkdir(parents=True, exist_ok=True)
    write_json(run / "manifest.json", manifest)
    write_json(active, manifest)
    write_json(work / "verification.json", verify_extra(root))
    write_inventory(root)
    print(json.dumps(manifest["stats"], indent=2))
    return manifest


def verify_extra(root):
    """Read-only: the frozen extra plan equals a recomputation and every prompt is the pilot prompt."""
    from collect import frozen_assignments, load_manifest, under, verified, verified_prompt
    m, leaves = load_manifest(root, extra_dir(root) / "manifest.json")
    if m["pass"] != EXTRA_PASS:
        raise ValueError("Not an extra-pass manifest")
    _, _, _, shared = pilot_taxonomy(root)
    base = json.loads(under(root, m["base_manifest"]).read_text())
    if base["run_id"] != m["base_run_id"] or base["shared_prompt_sha256"] != m["shared_prompt_sha256"]:
        raise ValueError("Extra pass base run differs")
    base_runs = {base["run_id"], base.get("main_run_id"), *base.get("base_run_ids", [])}
    if "main_manifest" in base:
        base_runs.add(Path(base["main_manifest"]).parent.name)
    sources = verified(root, m["sources"], m["sources_sha256"])
    plan = extra_plan(root, base, leaves, sources)
    frozen = {key: read_jsonl(verified(root, m[key], m[key + "_sha256"]))
              for key in ("snapshot", "reused", "joins", "excluded")}
    if any(frozen[key] != plan[key] for key in frozen) or plan["ledger"] != m["input_ledger"]:
        raise ValueError("Frozen extra plan differs from its recomputation")
    if any(r["classification"]["run_id"] not in base_runs for r in plan["reused"] + [j["label"] for j in plan["joins"]]):
        raise ValueError("Extra pass reuses a label outside its base v2 runs")
    by_uid = {r["finding_uid"]: r for r in plan["snapshot"]}
    observed = []
    for batch in m["batches"]:
        prompt = verified_prompt(root, batch).decode()
        if not prompt.startswith(shared + "\n\nBATCH REFERENCE"):
            raise ValueError("Prepared taxonomy/instructions differ from pilot")
        inputs = read_jsonl(prompt.split(FINDINGS_MARKER, 1)[1].encode())
        if inputs != [dict(i=i, title=by_uid[uid]["title"], body=by_uid[uid]["body"])
                      for i, uid in enumerate(batch["finding_uids"], 1)]:
            raise ValueError("Prompt differs from frozen normalized input")
        observed.extend(batch["content_keys"])
    if sorted(observed) != sorted(r["content_key"] for r in plan["pending"]):
        raise ValueError("Batches do not deduplicate/cover pending extra content keys")
    assignments, reasons, _, done, _ = frozen_assignments(root, m, leaves)
    return dict(run_id=m["run_id"], base_run_id=m["base_run_id"], findings=len(plan["snapshot"]),
                joined=len(plan["joins"]), excluded=len(plan["excluded"]), batches=len(m["batches"]),
                targets=len(observed), done_batches=done, accepted_content_keys=len(assignments),
                pending_content_keys=len(reasons), pilot_prompt_identical=True, model_execution="not_run_by_preparer")


def write_inventory(root):
    work = work_dir(root, "v2")
    files = {".gitignore", "docs/phase4/classify_v2.md", "docs/phase4/classify_v2_topup.md", "docs/phase4/classify_v2_topup2.md",
             "docs/phase4/classify_v2_extra.md", "local-cache/classify/v2/files_written.txt"}
    files.update("scripts/classify/" + name for name in
                 ("common.py", "make_batches.py", "collect.py", "v2.py", "test_v2.py",
                  "export_extra.py"))
    files.update(str(p.relative_to(root)) for p in work.rglob("*") if p.is_file())
    write_text(work / "files_written.txt", "".join(path + "\n" for path in sorted(files)))


def assert_pass_attempted(root, manifest):
    from collect import response_paths, under
    from common import retryable_capacity
    for batch in manifest["batches"]:
        output = under(root, batch["output"])
        if response_paths(root, batch):
            continue
        logs = sorted(output.parent.glob(output.name + ".log.*"))
        if not any(retryable_capacity(log, under(root, batch["prompt"])) for log in logs):
            raise ValueError("Cannot finish a pass with unattempted batches")


def verify(root):
    """Read-only, deterministic verification of every prepared target and prompt."""
    from collect import frozen_assignments, load_manifest, under, verified, verified_prompt
    work = work_dir(root, "v2")
    m, leaves = load_manifest(root, work / "manifest.json")
    _, _, _, shared = pilot_taxonomy(root)
    assignments, reasons, errors, done, snapshot = frozen_assignments(root, m, leaves)
    by_uid = {r["finding_uid"]: r for r in snapshot}
    expected = {r["content_key"] for r in snapshot if r["route"] == "llm"}
    observed = []
    for batch in m["batches"]:
        prompt = verified_prompt(root, batch).decode()
        if not prompt.startswith(shared + "\n\nBATCH REFERENCE"):
            raise ValueError("Prepared taxonomy/instructions differ from pilot")
        inputs = read_jsonl(prompt.split(FINDINGS_MARKER, 1)[1].encode())
        wanted = [dict(i=i, title=by_uid[uid]["title"], body=by_uid[uid]["body"])
                  for i, uid in enumerate(batch["finding_uids"], 1)]
        if inputs != wanted or any(len(r["body"]) > BODY_LIMIT for r in inputs):
            raise ValueError("Prompt differs from frozen normalized input")
        observed.extend(batch["content_keys"])
    if set(observed) != expected or len(observed) != len(expected):
        raise ValueError("Batches do not deduplicate/cover pending content keys")
    if "base_manifests" in m:
        (verify_topup_retry if m["pass"] == "retry" else verify_chained_topup)(root, m, snapshot, shared)
    current, ledger, excluded = load_findings(root, BODY_LIMIT)
    if m["pass"] == "main" and ({r["content_key"] for r in current} != expected or
                                ledger != m["input_ledger"] or len(snapshot) != len(current)):
        raise ValueError("Current findings differ from the prepared full v2 run")
    if m["pass"] in FOLLOW_UP_PASSES and "base_manifests" not in m:
        retry = read_jsonl(verified(root, m["retry_source"], m["retry_source_sha256"]))
        if not expected <= {r["content_key"] for r in retry}:
            raise ValueError("Retry targets are outside the retry list")
    if m["pass"] == "topup" and "base_manifests" not in m:
        targets = read_jsonl(verified(root, m["topup_targets"], m["topup_targets_sha256"]))
        main = json.loads(under(root, m["main_manifest"]).read_text())
        main_keys = {r["content_key"] for r in read_jsonl(verified(root, main["snapshot"], main["snapshot_sha256"]))}
        if (main["run_id"] != m["main_run_id"] or main["shared_prompt_sha256"] != m["shared_prompt_sha256"] or
                {r["content_key"] for r in targets} != expected or len(targets) != len(expected) or
                any((r["origin"] == "new_since_main") == (r["content_key"] in main_keys) for r in targets) or
                {r["content_key"] for r in snapshot if r["route"] == "deferred"}):
            raise ValueError("Top-up targets differ from current keys missing from the frozen main pass")
        reused = read_jsonl(verified(root, m["reused"], m["reused_sha256"]))
        if any(r["classification"]["run_id"] != m["main_run_id"] or r["content_key"] not in main_keys
               for r in reused):
            raise ValueError("Top-up reuses a label that is not from its frozen main pass")
    return dict(run_id=m["run_id"], findings=len(snapshot), content_keys=len({r["content_key"] for r in snapshot}),
                batches=len(m["batches"]), targets=len(observed), done_batches=done,
                accepted_content_keys=len(assignments), pending_content_keys=len(reasons),
                input_files=len(ledger), excluded=excluded, pilot_prompt_identical=True,
                source_changed_since_preparation=ledger != m["input_ledger"] or extra_sources_changed(root, m),
                model_execution="not_run_by_preparer")


def verify_chained_topup(root, manifest, snapshot, shared):
    """Recompute the frozen plan against its hash-bound completed base, independently of outputs."""
    from collect import verified
    assignments, attempted, reasons, runs = completed_state(root, manifest["base_manifests"], manifest)
    base = json.loads(verified(root, manifest["base_manifests"][0]["path"], manifest["base_manifests"][0]["sha256"]))
    if (manifest["pass"] != "topup" or base["run_id"] != manifest["base_run_id"] or
            manifest["retry_round"] != base.get("topup_round", base["retry_round"]) + 1 or runs != manifest["base_run_ids"] or
            manifest["shared_prompt_sha256"] != sha(shared.encode())):
        raise ValueError("Chained top-up base runs, round or prompt differ")
    if "supersedes_unattempted" in manifest:
        reference = manifest["supersedes_unattempted"]
        old = json.loads(verified(root, reference["path"], reference["sha256"]))
        if (old["run_id"] != reference["run_id"] or old["retry_round"] != manifest["retry_round"] or
                old["base_run_id"] != manifest["base_run_id"]):
            raise ValueError("Refreshed dry-run provenance differs")
        assert_unattempted(root, old)
    for batch in manifest["batches"]:
        wanted = work_dir(root, "v2") / "outputs" / manifest["run_id"] / (batch["batch_id"] + ".jsonl")
        if batch["output"] != str(wanted.relative_to(root)):
            raise ValueError("Chained top-up output must belong to its own run")
    sources = verified(root, manifest["sources"], manifest["sources_sha256"])
    ledger = verified(root, manifest["sources_ledger"], manifest["sources_ledger_sha256"])
    if ledger and json.loads(ledger).get("sources_sha256") != sha(sources):
        raise ValueError("Frozen extra sources differ from their ledger")
    primary = [{k: v for k, v in r.items() if k not in {"route", "classification_uid"}}
               for r in snapshot if r["stream"] == "findings"]
    plan = chained_plan(root, primary, assignments, attempted, reasons, sources)
    for key in ("snapshot", "reused", "topup_targets", "joins", "excluded"):
        wanted = plan["targets" if key == "topup_targets" else key]
        if read_jsonl(verified(root, manifest[key], manifest[key + "_sha256"])) != wanted:
            raise ValueError(f"Chained top-up {key} differs from its completed base state")


def verify_topup_retry(root, manifest, snapshot, shared):
    """Recompute residual membership and reuse from the hash-bound completed top-up."""
    from collect import verified
    references = manifest["base_manifests"]
    if len(references) != 1:
        raise ValueError("Top-up retry must have exactly one completed base")
    assignments, _, reasons, runs = completed_state(root, references, manifest)
    base = json.loads(verified(root, references[0]["path"], references[0]["sha256"]))
    if (base["pass"] != "topup" or manifest.get("base_pass") != "topup" or
            base["run_id"] != manifest["base_run_id"] or manifest["retry_round"] != 1 or
            manifest.get("topup_round") != base["retry_round"] or runs != manifest["base_run_ids"] or
            manifest["shared_prompt_sha256"] != sha(shared.encode()) or manifest["input_ledger"] != base["input_ledger"]):
        raise ValueError("Top-up retry base runs, round, inputs or prompt differ")
    retry_bytes = verified(root, manifest["retry_source"], manifest["retry_source_sha256"])
    plan = topup_retry_plan(root, base, assignments, reasons, retry_bytes)
    if snapshot != plan["snapshot"] or read_jsonl(verified(root, manifest["reused"], manifest["reused_sha256"])) != plan["reused"]:
        raise ValueError("Top-up retry snapshot/reuse differs from its completed base")
    expected = [r["content_key"] for r in plan["pending"]]
    if [key for b in manifest["batches"] for key in b["content_keys"]] != expected:
        raise ValueError("Top-up retry batches differ from the exact residual keys")
    for key in ("sources", "sources_ledger", "joins", "excluded"):
        wanted = verified(root, base[key], base[key + "_sha256"]) if key in base else b""
        if verified(root, manifest[key], manifest[key + "_sha256"]) != wanted:
            raise ValueError(f"Top-up retry {key} differs from its frozen base")
    for batch in manifest["batches"]:
        wanted = work_dir(root, "v2") / "outputs" / manifest["run_id"] / (batch["batch_id"] + ".jsonl")
        if batch["output"] != str(wanted.relative_to(root)):
            raise ValueError("Top-up retry output must belong to its own run")


def report(root, m):
    """Record reproducible classification preparation settings."""
    write_text(root / "docs/classification.md", "# Classification\n\nPrepare batches with make_batches.py. Supply JSONL responses matching the frozen prompts, then run collect.py --require-complete. Manifest hashes bind inputs, prompts and outputs. Quota, usage-guard and unknown-reset failures stop execution.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--verify", action="store_true", required=True)
    parser.add_argument("--extra", action="store_true", help="Verify the extra-source pass instead of the active pass")
    args = parser.parse_args()
    print(json.dumps((verify_extra if args.extra else verify)(args.root.resolve()), indent=2))
