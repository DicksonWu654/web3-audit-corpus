"""Explain newly emitted short excerpts against the pre-task parser source.

The cached before output predates its source's short-excerpt support. This
read-only local Git replay verifies that additions already come from the
pre-task parser, rather than from the severity policy. Never opens a holdout.
Only the explicitly supplied local revision's reviewed core/C4/SlowMist files
are staged; no archives, package installation, or network is involved.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess
import sys

from common import ROOT, holdouts, read_snapshot, write_json


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--revision", required=True)
    a = p.parse_args()
    revision = subprocess.check_output(["git", "rev-parse", "--verify", a.revision+"^{commit}"], cwd=ROOT, text=True).strip()
    folder = ROOT / "local-cache/severity-baseline" / revision
    folder.mkdir(parents=True, exist_ok=True)
    for name in ("core.py", "common.py", "summary_counts.py", "parsers/code4rena.py", "parsers/slowmist.py"):
        payload = subprocess.check_output(["git", "show", revision+":scripts/findings/"+name], cwd=ROOT)
        path = folder / Path(name).name
        path.write_bytes(payload)
    worker = folder / "replay.py"
    worker.write_text('''import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from core import Report, finish
from common import digest, uid, VERSION, holdouts, read_snapshot
import code4rena, slowmist
root=Path(sys.argv[1]); blocked=holdouts(root)
request=json.loads(Path(sys.argv[2]).read_text())
docs={d["document_id"]:d for d in read_snapshot(root)}
result=[]
for did, item in request.items():
    expected=item["ids"]; firm=item["publisher"]
    parser={"code4rena":code4rena,"slowmist":slowmist}[firm]
    d=docs[did];sha=d["row"]["sha256"]
    assert sha not in blocked
    meta=json.loads((root/"local-cache/fulltext"/(sha+".pages.json")).read_text())
    text=(root/"local-cache/fulltext"/(sha+".txt")).read_text()
    assert digest(text.encode())==meta["text_sha256"]
    r=Report(text,meta,firm)
    ids={uid("finding","collect:"+firm,did+":"+VERSION+":"+str(c.start)):c for c in finish(r,parser.parse(r))}
    for fid in expected:
        assert fid in ids, "New row not produced by pre-task source: "+fid
        assert ids[fid].record_kind=="summary_excerpt", fid
        result.append(fid)
Path(sys.argv[3]).write_text(json.dumps(result))
''')
    before = json.loads((ROOT / "data/findings/severity_review/before.json").read_text())
    requested = {}
    kinds = Counter()
    by_publisher = Counter()
    blocked = holdouts()
    for firm in ("code4rena", "slowmist"):
        baseline_ids = set(before[firm]["ids"])
        for line in (ROOT / "data/findings" / (firm+".jsonl")).open():
            row = json.loads(line)
            assert row["sha256"] not in blocked
            if row["finding_id"] not in baseline_ids:
                requested.setdefault(row["document_id"], {"publisher": firm, "ids": []})["ids"].append(row["finding_id"])
                kinds[row["record_kind"]] += 1
                by_publisher[firm] += 1
    request_path = ROOT / "data/findings/severity_review/replay_request.json"
    result_path = ROOT / "data/findings/severity_review/replay_ids.json"
    write_json(request_path, requested)
    subprocess.run([sys.executable, "-I", "-B", str(worker), str(ROOT), str(request_path), str(result_path)], check=True, cwd="/tmp")
    ids = json.loads(result_path.read_text())
    receipt = {"revision": revision, "by_publisher": dict(by_publisher), "added_rows_reproduced": len(ids),
               "documents": len(requested), "record_kinds": dict(kinds), "finding_ids": ids, "holdouts_opened": 0}
    write_json(ROOT / "data/findings/severity_review/baseline_replay.json", receipt)
    print(json.dumps({k:v for k,v in receipt.items() if k != "finding_ids"}, indent=2))


if __name__ == "__main__":
    main()
