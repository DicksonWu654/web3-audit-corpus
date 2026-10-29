"""Freeze collection metadata for a reproducible, holdout-excluded Phase 4a run."""
import argparse
from collections import Counter
from pathlib import Path
from common import ROOT, documents, holdouts, write_json, write_jsonl


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    docs, ledger, excluded = documents(args.root)
    by_firm = Counter(d["row"]["firm_id"] for d in docs)
    hashes = {d["row"]["sha256"] for d in docs}
    top = sorted(by_firm, key=lambda f: (-by_firm[f], f))[:15]
    summary = {"documents": len(docs), "unique_artifacts": len(hashes), "by_firm": dict(by_firm.most_common()),
               "formats": dict(Counter(d["row"]["file_format"] for d in docs)),
               "other_extensions": dict(Counter(Path(d["row"]["filename"]).suffix.lower() for d in docs if d["row"]["file_format"] == "other")),
               "top15": top, "excluded": excluded, "holdout_hashes": len(holdouts(args.root)),
               "scope_sha256":__import__("hashlib").sha256((args.root/"registry/scope_tier_a.csv").read_bytes()).hexdigest(),
               "holdout_list_sha256":__import__("hashlib").sha256((args.root/"data/holdout/gold_sha256.txt").read_bytes()).hexdigest(),
               "collection_files": ledger}
    write_jsonl(args.root / "data/fulltext/input_documents.jsonl", docs)
    write_json(args.root / "data/fulltext/inventory.json", summary)
    print(__import__("json").dumps({k: v for k, v in summary.items() if k != "collection_files"}, indent=2))


if __name__ == "__main__":
    main()
