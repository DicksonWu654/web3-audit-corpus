"""Read only Phase 4a's own cache receipts for an extraction progress snapshot."""
import json
from collections import Counter
from common import ROOT, holdouts, read_snapshot


def main():
    blocked = holdouts()
    snapshot=read_snapshot()
    eligible = {d["row"]["sha256"] for d in snapshot}
    firms={}
    for d in snapshot:
        firms.setdefault(d["row"]["sha256"],set()).add(d["row"]["firm_id"])
    states, methods, image_flags, partial_firms = Counter(),Counter(),Counter(),Counter()
    for sha in sorted(eligible - blocked):
        path = ROOT/"local-cache/fulltext"/(sha+".pages.json")
        if path.exists():
            meta = json.loads(path.read_text())
            states[meta["status"]]+=1
            methods[meta["method"]]+=1
            if meta["status"]=="partial":
                partial_firms.update(firms[sha])
            image_flags.update(i["kind"] for i in meta["issues"] if "ocr" in i["kind"] or "image" in i["kind"])
        else:
            states["no_cache"]+=1
    temporary = {p.name:len(list(p.glob("*.png"))) for p in sorted((ROOT/"local-cache/fulltext").glob("ocr-*")) if p.is_dir()}
    details=[]
    index=ROOT/"data/fulltext/extractions.jsonl"
    if index.exists():
        details=[{k:r.get(k) for k in ("sha256","error","detail")} for r in map(json.loads,index.read_text().splitlines()) if r["status"]=="failed" and r["sha256"] not in blocked]
    print(json.dumps({"cache_artifacts":dict(states),"methods":dict(methods),"ocr_page_flags":dict(image_flags),"partial_firms":dict(partial_firms.most_common()),"active_ocr_images":temporary,"last_index_failure_counts":dict(Counter(r["error"] for r in details)),"last_index_failure_examples":details[:5]},indent=2))


if __name__=="__main__":
    main()
