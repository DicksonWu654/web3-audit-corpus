#!/usr/bin/env python3
"""Validate pilot JSONL outputs and restore finding UIDs (no scoring/label reads).

python3 -I -S scripts/classify/pilot_collect.py [--config A_luna_low_800]
Partial valid rows are saved; exit status is nonzero until every selected arm is
complete and has no malformed/foreign lines. Details go to <config>/status.json.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, read_jsonl, sha, validate_output, write_json, write_jsonl
from pilot_make import CONFIGS, PILOT, prepare


def retryable_capacity(log_path, prompt_path):
    """Inspect diagnostics, excluding the CLI's verbatim echo of untrusted data.

    Finding/taxonomy text can mention guards, quotas, or capacity. It must not
    determine whether a failed launch is a transient service error.
    """
    log = log_path.read_text(encoding="utf-8", errors="replace")
    prompt = prompt_path.read_text(encoding="utf-8")
    diagnostics = log.replace(prompt.strip(), "")
    if re.search(r"usage.?limit|quota|usage[-_ ]?reset|reset[-_ ]?(guard|credit|mechanism)|"
                 r"guard.*(block|unknown|reject|fail)|(block|unknown|reject|fail).*guard|"
                 r"unknown.*reset|credits?.*(exhausted|depleted)", diagnostics, re.I):
        return False
    return bool(re.search(r"server is at capacity|server (is )?(overloaded|at capacity)|"
                          r"429 Too Many Requests|503 Service Unavailable|"
                          r"stream disconnected before completion", diagnostics, re.I))


def check_batch(root, batch, leaves, output=None):
    expected = {row["i"]: row["finding_uid"]
                for row in read_jsonl((root / PILOT / batch["index_map"]).read_bytes())}
    path = output if output is not None else root / PILOT / batch["output"]
    data = path.read_bytes() if path.is_file() else None
    accepted, reasons, errors = validate_output(path, expected, leaves, data=data)
    status = dict(k=batch["k"], expected=len(expected), accepted=len(accepted),
                  complete=len(accepted) == len(expected) and not reasons and not errors,
                  output=batch["output"], output_sha256=sha(data) if data is not None else None,
                  rejected_or_missing=reasons, errors=errors)
    return accepted, status, expected


def collect_config(root, name, config, manifest, leaves):
    predictions, statuses = [], []
    for batch in config["batches"]:
        accepted, status, expected = check_batch(root, batch, leaves)
        statuses.append(status)
        # Map by index, never response order; emit in the frozen sample order.
        for uid in expected.values():
            if uid in accepted:
                row = accepted[uid]
                predictions.append({key: row[key] for key in ("finding_uid", "leaf", "confidence")})
    status = dict(config=name, model=config["model"], effort=config["effort"],
                  max_body_chars=config["max_body_chars"],
                  sample_sha256=manifest["sample_sha256"],
                  taxonomy_sha256=manifest["taxonomy_sha256"],
                  complete=all(s["complete"] for s in statuses),
                  expected=manifest["findings"], accepted=len(predictions), batches=statuses)
    write_jsonl(root / PILOT / name / "predictions.jsonl", predictions)
    write_json(root / PILOT / name / "status.json", status)
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--config", action="append", choices=CONFIGS, help="Default: every configuration")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--list-batches", action="store_true", help="Read-only, verified TSV runner plan")
    modes.add_argument("--check-batch", nargs=2, metavar=("CONFIG", "K"), help="Read-only completeness check")
    modes.add_argument("--retryable-capacity", nargs=2, type=Path, metavar=("LOG", "PROMPT"),
                       help="Read-only runner diagnostic check, excluding echoed prompt data")
    parser.add_argument("--output", type=Path, help="Alternative response file for --check-batch only")
    args = parser.parse_args()
    if args.output is not None and args.check_batch is None:
        parser.error("--output requires --check-batch")
    root = args.root.resolve()
    try:
        if args.retryable_capacity:
            return 0 if retryable_capacity(*args.retryable_capacity) else 1
        manifest, leaves = prepare(root, verify=True)
        if args.check_batch:
            name, k = args.check_batch
            if name not in CONFIGS or k not in {"1", "2", "3"}:
                raise ValueError("Unknown pilot config/batch")
            batch = manifest["configs"][name]["batches"][int(k) - 1]
            _, status, _ = check_batch(root, batch, leaves, args.output)
            print(json.dumps(status, sort_keys=True))
            return 0 if status["complete"] else 1
        names = args.config or list(CONFIGS)
        if args.list_batches:
            for name in names:
                config = manifest["configs"][name]
                for batch in config["batches"]:
                    print("\t".join([name, config["model"], config["effort"], str(batch["k"]),
                                     str(root / PILOT / batch["prompt"]),
                                     str(root / PILOT / batch["output"])]))
            return 0
        statuses = [collect_config(root, name, manifest["configs"][name], manifest, leaves) for name in names]
        print(json.dumps([{k: s[k] for k in ("config", "expected", "accepted", "complete")}
                          for s in statuses], indent=2))
        return 0 if all(s["complete"] for s in statuses) else 1
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(1, f"Pilot collection failed: {exc}\n")


if __name__ == "__main__":
    sys.exit(main())
