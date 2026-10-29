"""Inspect deterministic development samples, with a mandatory holdout guard."""
import argparse
import json
import re
from common import ROOT, holdouts, original_path, read_snapshot


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("firms", nargs="*")
    p.add_argument("--index", type=int, default=0)
    p.add_argument("--lines", type=int, default=100)
    p.add_argument("--page", type=int)
    p.add_argument("--sha")
    p.add_argument("--headings", action="store_true")
    p.add_argument("--other", action="store_true", help="Print other-format metadata only")
    p.add_argument("--native", action="store_true")
    p.add_argument("--parsed", action="store_true")
    p.add_argument("--match")
    p.add_argument("--mismatches", action="store_true")
    p.add_argument("--ocr-fail",action="store_true")
    p.add_argument("--render",action="store_true",help="Render the selected PDF page into the local review cache")
    p.add_argument("--errors",action="store_true",help="Show parser errors from development diagnostics only")
    a = p.parse_args()
    blocked = holdouts()
    docs = read_snapshot()
    if a.errors:
        for path in sorted((ROOT/"data/findings/validation").glob("*.jsonl")):
            for line in path.read_text().splitlines():
                r=json.loads(line)
                if r["sha256"] not in blocked and r["validation"]=="parser_error":
                    print(json.dumps({k:r.get(k) for k in ("firm_id","sha256","document_id","error")}))
        return
    if a.native:
        from structured import quantstamp_payload
        d = next(d for d in docs if d["row"]["firm_id"] == "quantstamp" and d["row"]["file_format"] == "other")
        value = quantstamp_payload(original_path(d["row"]).read_text())
        def skeleton(v, depth=0):
            if depth > 4:
                return str(v)[:100]
            if isinstance(v, dict):
                return {k:skeleton(x, depth+1) for k,x in v.items()}
            if isinstance(v, list):
                return {"length": len(v), "first": skeleton(v[0], depth+1) if v else None}
            return str(v)[:200]
        print(json.dumps(skeleton(value), indent=2))
        return
    if a.other:
        from collections import Counter
        selected = [d["row"] for d in docs if d["row"]["file_format"] == "other"]
        print(Counter((d["firm_id"], d["doc_kind"]) for d in selected))
        for d in selected[:8]:
            print(json.dumps({k: d[k] for k in ("sha256", "firm_id", "filename", "local_path", "doc_kind", "notes")}))
        return
    if a.sha in blocked:
        raise SystemExit("Holdout inspection denied")
    firms = a.firms or json.loads((ROOT / "data/fulltext/inventory.json").read_text())["top15"]
    for firm in firms:
        mismatch_hashes = None
        if a.mismatches:
            path = ROOT/"data/findings/validation"/(firm+".jsonl")
            mismatch_hashes = {r["sha256"] for r in map(json.loads,path.read_text().splitlines()) if r["validation"]=="mismatch" and r["sha256"] not in blocked}
        candidates = {d["row"]["sha256"]: d for d in docs if d["row"]["firm_id"] == firm
                      and (mismatch_hashes is None or d["row"]["sha256"] in mismatch_hashes)
                      and (not a.sha or d["row"]["sha256"] == a.sha)
                      and (ROOT / "local-cache/fulltext" / (d["row"]["sha256"] + ".pages.json")).exists()}
        if not candidates:
            continue
        if a.ocr_fail:
            candidates = {sha:d for sha,d in candidates.items() if any(i["kind"]=="ocr_failed" for i in json.loads((ROOT/"local-cache/fulltext"/(sha+".pages.json")).read_text())["issues"])}
            if not candidates:
                continue
        sha = sorted(candidates)[a.index % len(candidates)]
        if sha in blocked:
            raise SystemExit("Holdout inspection denied")
        if a.render:
            import fitz
            row=candidates[sha]["row"]
            if row["file_format"]!="pdf" or not a.page:
                raise SystemExit("Rendering requires a PDF and --page")
            target=ROOT/"local-cache/fulltext/review"/(sha+f"-p{a.page}.png")
            target.parent.mkdir(parents=True,exist_ok=True)
            with fitz.open(original_path(row)) as pdf:
                pdf[a.page-1].get_pixmap(matrix=fitz.Matrix(2,2)).save(target)
            print(target)
            continue
        meta = json.loads((ROOT / "local-cache/fulltext" / (sha + ".pages.json")).read_text())
        print(f"\nFIRM {firm} SHA {sha} FILE {candidates[sha]['row']['filename']}")
        if a.parsed:
            from core import Report, finish
            from parsers import module
            from summary_counts import printed_counts
            text = (ROOT / "local-cache/fulltext" / (sha + ".txt")).read_bytes().decode("utf-8")
            report = Report(text, meta, firm)
            entries = finish(report, module(firm).parse(report))
            print("SUMMARY", json.dumps(printed_counts(report)))
            from collections import Counter
            from core import severity
            print("PARSED",json.dumps(dict(Counter(c.normalized or severity(c.severity_raw) for c in entries))))
            for c in entries[:a.lines]:
                print(json.dumps({k:v for k,v in c.__dict__.items() if k != "evidence"}))
            continue
        pages = meta["pages"]
        if a.ocr_fail:
            failed_pages = {i["page"] for i in meta["issues"] if i["kind"]=="ocr_failed"}
            print("OCR_FAILED_PAGES",sorted(failed_pages))
            pages = [p for p in pages if p["page"] in failed_pages]
        if a.page:
            pages = pages[a.page - 1:a.page]
        count = 0
        for page in pages:
            for line in page["text"].splitlines():
                if a.match and not re.search(a.match,line,re.I):
                    continue
                if a.headings and not re.search(r"critical|high|medium|low|informational|severity|risk|\[[HMLIGC]-?\d|^\s*#{1,5} |^\s*\d+\.\d+\s|^\s*[A-Z]{1,5}-?\d{1,3}[\s\]:.)]", line, re.I):
                    continue
                print(f"p{page['page']}: {line[:230]}")
                count += 1
                if count >= a.lines:
                    break
            if count >= a.lines:
                break


if __name__ == "__main__":
    main()
