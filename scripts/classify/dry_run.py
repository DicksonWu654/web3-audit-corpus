#!/usr/bin/env python3
"""Three-batch, hand-made collector fixtures; never launch server or label the validation sample."""
import copy
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, batch_expected, canonical, content_key, load_taxonomy, sha, validate_output, write_json, write_jsonl, write_text
from collect import read_jsonl
from rules import classify


def main():
    root = ROOT
    work = root / "local-cache/classify"
    target = work / "dry-run"
    original = json.loads((work / "manifest.json").read_text())
    archived = None
    if (target / "manifest.json").exists():
        previous_bytes = (target / "manifest.json").read_bytes()
        previous = json.loads(previous_bytes)
        if previous.get("content_key_version") == original["content_key_version"]:
            # Retain the inventory of fixtures made for earlier incremental runs.
            archived = target / "previous_manifests" / (sha(previous_bytes) + ".json")
            write_json(archived, previous)
    sample = {r["finding_uid"] for r in read_jsonl((work / "validation_sample.jsonl").read_bytes())}
    sample_keys = {content_key(r["firm_id"], r["title"], r["body_text"])
                   for r in read_jsonl((work / "validation_sample.jsonl").read_bytes())}
    batch_size = original["stats"]["batch_size"]
    chosen = [b for b in original["batches"] if len(b["finding_uids"]) == batch_size and
              not sample.intersection(b["finding_uids"]) and not sample_keys.intersection(b["content_keys"])][:3]
    assert len(chosen) == 3
    selected = {uid for b in chosen for uid in b["finding_uids"]}
    snapshot = [r for r in read_jsonl((root / original["snapshot"]).read_bytes()) if r["finding_uid"] in selected]
    count = 3 * batch_size
    assert len(snapshot) == count and not selected & sample
    write_jsonl(target / "inputs.jsonl", snapshot)
    write_jsonl(target / "rules.jsonl", [])
    write_jsonl(target / "reused.jsonl", [])
    manifest = copy.deepcopy(original)
    manifest.update(fixture=True, run_id="hand-made-three-batch-fixture", source_run_id=original["run_id"], input_ledger=[],
                    snapshot=str((target / "inputs.jsonl").relative_to(root)), snapshot_sha256=sha((target / "inputs.jsonl").read_bytes()),
                    rules=str((target / "rules.jsonl").relative_to(root)), rules_sha256=sha(b""),
                    reused=str((target / "reused.jsonl").relative_to(root)), reused_sha256=sha(b""), batches=copy.deepcopy(chosen))
    clean = []
    for b in manifest["batches"]:
        b["output"] = str((target / "outputs" / (b["batch_id"]+".jsonl")).relative_to(root))
        expected = batch_expected(b)
        clean.append([dict(**({"i": identity} if isinstance(expected, dict) else {"finding_uid": identity}),
                           leaf="unclassified.insufficient_evidence", confidence=.25,
                           rationale="Synthetic parser fixture only; no substantive label assigned.")
                      for identity in (expected if isinstance(expected, dict) else b["finding_uids"])])
    write_json(target / "manifest.json", manifest)
    bad = copy.deepcopy(clean)
    bad[1][0]["leaf"] = "unknown.not_in_taxonomy"
    bad[1].pop(1)
    missing_uid = manifest["batches"][1]["finding_uids"][1]
    label = "index" if "index_map" in chosen[0] else "uid"
    bad[2].append(copy.deepcopy(bad[2][0]))
    bad[2][1]["confidence"] = True
    bad[2][2]["rationale"] = " ".join(["word"]*21)
    for b, records in zip(manifest["batches"], bad):
        write_jsonl(root / b["output"], records)
    command = [sys.executable, "-I", "-B", "-S", str(Path(__file__).with_name("collect.py")),
               "--root", str(root), "--manifest", str(target / "manifest.json"),
               "--output-dir", str(target / "classified"), "--retry-path", str(target / "retry.jsonl"),
               "--require-complete"]
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    assert proc.returncode == 1, (proc.stdout,proc.stderr)
    first = json.loads((target / "classified/_status.json").read_text())
    assert (first["classified"],first["retry"],first["valid_batches"]) == (count-5,5,1), first
    retries = read_jsonl((target / "retry.jsonl").read_bytes())
    assert any(r["finding_uid"] == missing_uid and "missing_"+label in r["reasons"] for r in retries)
    assert set(first["retry_reasons"]) == {"unknown_leaf","missing_"+label,"duplicate_"+label,"invalid_confidence","invalid_rationale"}
    write_json(target / "rejection_result.json", first)
    write_jsonl(target / "rejected_retry.jsonl", retries)
    _, leaves = load_taxonomy(root / original["taxonomy"])
    # Malformed/foreign rows are rejected individually, including duplicate keys and NaN.
    adversarial = target / "malformed.jsonl"
    cases = ["```json\n"+canonical(clean[0][0])+"\n```\n",
             canonical(clean[0][0])+"\n{" ,
             canonical({**clean[0][0], **({"i": 101} if label == "index" else {"finding_uid":"finding:foreign"})})+"\n",
             canonical(clean[0][0])[:-1]+',"confidence":0.9}\n',
             canonical(clean[0][0]).replace('"confidence":0.25','"confidence":NaN')+"\n"]
    for content, valid_count in zip(cases, [1, 1, 0, 0, 0]):
        write_text(adversarial, content)
        accepted, reasons, _ = validate_output(adversarial, batch_expected(chosen[0]), leaves)
        assert len(accepted) == valid_count and len(reasons) == batch_size - valid_count
    # Rule positives are separate fixtures; security-bearing/ambiguous titles must abstain.
    base = dict(finding_uid="synthetic", title="Cache storage variables to save gas", body="Reducing gas cost.", severity="gas")
    assert classify(base)["leaf"] == "gas.storage"
    assert classify({**base,"body":"Unbounded storage iteration causes denial of service."}) is None
    assert classify({**base,"title":"Storage and calldata optimization saves gas"}) is None
    assert classify({**base,"title":"Gas optimization"}) is None
    info = {**base,"title":"Unused imports","body":"Remove the unused imports.","severity":"info"}
    assert classify(info)["leaf"] == "quality.maintainability"
    assert classify({**info,"severity":"high"}) is None
    assert classify({**info,"body":"Missing import causes an authorization bypass."}) is None
    # Repair the same three outputs and verify complete reconciliation/resume checks.
    for b,records in zip(manifest["batches"],clean):
        write_jsonl(root / b["output"],records)
    proc = subprocess.run(command, capture_output=True, text=True, check=False)
    assert proc.returncode == 0,(proc.stdout,proc.stderr)
    final = json.loads((target / "classified/_status.json").read_text())
    assert (final["classified"],final["retry"],final["valid_batches"]) == (count,0,3),final
    again = subprocess.run(command,capture_output=True,text=True,check=False)
    assert again.returncode == 0 and (target / "classified/_status.json").read_text() == json.dumps(final,ensure_ascii=False,indent=2,sort_keys=True)+"\n"
    # Frozen prompt tampering must be detected without changing the real prompt.
    from collect import verified
    try:
        verified(root,manifest["snapshot"],"0"*64)
        raise AssertionError("Tampered snapshot accepted")
    except ValueError:
        pass
    result = dict(batches=3,findings=count,batch_size=batch_size,hand_made=True,model_calls=0,validation_sample_uids_used=0,
                  validation_sample_content_keys_used=0,
                  first_pass=dict(classified=first["classified"],retry=first["retry"],reasons=first["retry_reasons"]),
                  repaired_pass=dict(classified=final["classified"],retry=final["retry"],valid_batches=final["valid_batches"]),
                  malformed_foreign_nan_checks="passed",rule_positive_negative_checks="passed",
                  frozen_hash_check="passed",idempotent_collect="passed",production_labels_written=False)
    write_json(target / "result.json",result)
    written = {str((target / name).relative_to(root)) for name in
               ("inputs.jsonl", "rules.jsonl", "reused.jsonl", "manifest.json", "rejection_result.json",
                "rejected_retry.jsonl", "malformed.jsonl", "retry.jsonl", "result.json", "files_written.txt")}
    written.update(b["output"] for b in manifest["batches"])
    written.update(final["files"])
    written.update({final["content_key_index"], str((target / "classified/_status.json").relative_to(root))})
    if archived:
        written.add(str(archived.relative_to(root)))
    write_text(target / "files_written.txt", "".join(path + "\n" for path in sorted(written)))
    print(json.dumps(result,indent=2))


if __name__ == "__main__":
    main()
