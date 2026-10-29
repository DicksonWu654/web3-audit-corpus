"""Retry completed, low-text OCR failures using sparse-text and inverted-image modes."""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import io
import json
from pathlib import Path
import subprocess
import tempfile
from common import ROOT, digest, holdouts, original_path, read_snapshot, write_json
from extract import FITZ_LOCK, tool, tool_environment


def retry(item,extended=False):
    sha,row=item
    if sha in holdouts():
        raise RuntimeError("Holdout OCR denied")
    cache=ROOT/"local-cache/fulltext"
    path=cache/(sha+".pages.json")
    meta=json.loads(path.read_text())
    pages=[i["page"] for i in meta["issues"] if i["kind"]=="ocr_failed"]
    recovered=[]
    try:
        import fitz
        from PIL import Image, ImageOps
        source_path=original_path(row)
        if digest(source_path.read_bytes())!=sha:
            raise ValueError("Original hash mismatch before OCR retry")
        with tempfile.TemporaryDirectory(dir=cache,prefix="ocr-retry-") as tmp:
            with FITZ_LOCK,fitz.open(source_path) as pdf:
                for page in pages:
                    pdf[page-1].get_pixmap(matrix=fitz.Matrix(4,4),colorspace=fitz.csGRAY).save(Path(tmp)/f"{page}.png")
            for page in pages:
                png=Path(tmp)/f"{page}.png"
                for variant in (("block","inverted-block") if extended else ("sparse","inverted")):
                    image=png
                    if variant.startswith("inverted"):
                        image=Path(tmp)/f"{page}-inverted.png"
                        with Image.open(png) as source:
                            ImageOps.invert(ImageOps.autocontrast(source.convert("L"))).save(image)
                    result=subprocess.run([tool("tesseract",ROOT),str(image),"stdout","-l","eng","--psm","6" if extended else "11","tsv"],
                                          capture_output=True,env=tool_environment(ROOT),timeout=120)
                    if result.returncode:
                        continue
                    words=list(csv.DictReader(io.StringIO(result.stdout.decode("utf-8","replace")),delimiter="\t",quoting=csv.QUOTE_NONE))
                    confident=[w for w in words if w.get("text","").strip() and float(w.get("conf",-1))>=35]
                    if len(confident)<2 or sum(c.isalnum() for w in confident for c in w["text"])<15:
                        continue
                    groups={}
                    for w in words:
                        if w.get("text","").strip() and float(w.get("conf",-1))>=0:
                            key=(w.get("block_num"),w.get("par_num"),w.get("line_num"))
                            groups.setdefault(key,[]).append(w["text"])
                    text="\n".join(" ".join(v) for v in groups.values())+"\n"
                    meta["pages"][page-1]["text"]=text
                    recovered.append(page)
                    meta["issues"].append({"kind":"ocr_page","page":page,"retry_mode":variant,"confident_words":len(confident)})
                    break
        meta["issues"]=[i for i in meta["issues"] if not (i["kind"]=="ocr_failed" and i["page"] in recovered)]
        previous=meta.get("ocr_retry",{})
        meta["ocr_retry"]={"attempted_pages":sorted(set(pages+previous.get("attempted_pages",[]))),
                           "recovered_pages":sorted(set(recovered+previous.get("recovered_pages",[]))),
                           "modes":previous.get("modes",[])+(["block-288dpi","inverted-block-288dpi"] if extended else ["sparse-288dpi","inverted-sparse-288dpi"]),
                           "acceptance":"at least 2 words with confidence >=35 and >=15 alphanumeric characters"}
        meta["status"]="partial" if any(i["kind"]=="ocr_failed" for i in meta["issues"]) else "ok"
        offset=0
        for page in meta["pages"]:
            page["start"],page["end"]=offset,offset+len(page["text"])
            offset=page["end"]+1
        text="\f".join(p["text"] for p in meta["pages"])
        meta["characters"]=len(text)
        meta["text_sha256"]=digest(text.encode())
        txt=cache/(sha+".txt")
        temporary=txt.with_suffix(".txt.tmp")
        temporary.write_text(text)
        temporary.replace(txt)
        write_json(path,meta)
        return {"sha256":sha,"recovered_pages":len(recovered),"remaining_pages":len(pages)-len(recovered)}
    except Exception as exc:
        return {"sha256":sha,"error":str(exc)}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workers",type=int,default=4)
    p.add_argument("--max-new",type=int,default=100)
    p.add_argument("--extended",action="store_true",help="Try block/inverted-block segmentation on failures remaining after sparse OCR")
    a=p.parse_args()
    blocked=holdouts()
    unique={d["row"]["sha256"]:d["row"] for d in read_snapshot() if d["row"]["sha256"] not in blocked}
    jobs=[]
    for sha,row in sorted(unique.items()):
        path=ROOT/"local-cache/fulltext"/(sha+".pages.json")
        if not path.exists():
            continue
        meta=json.loads(path.read_text())
        attempted="block-288dpi" in meta.get("ocr_retry",{}).get("modes",[]) if a.extended else bool(meta.get("ocr_retry"))
        if meta["status"]=="partial" and not attempted and any(i["kind"]=="ocr_failed" for i in meta["issues"]):
            jobs.append((sha,row))
    print(f"OCR retry eligible {len(jobs)}; scheduling {min(len(jobs),a.max_new)}",flush=True)
    results=[]
    with ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures=[pool.submit(retry,item,a.extended) for item in jobs[:a.max_new]]
        for f in as_completed(futures):
            results.append(f.result())
            if len(results)%20==0:
                print(f"Retried {len(results)}; recovered {sum(r.get('recovered_pages',0) for r in results)} pages",flush=True)
    write_json(ROOT/"data/fulltext/ocr_retry_last_batch.json",sorted(results,key=lambda r:r["sha256"]))
    print(json.dumps({"retried":len(results),"recovered_pages":sum(r.get("recovered_pages",0) for r in results),
                      "remaining_pages":sum(r.get("remaining_pages",0) for r in results),"errors":sum("error" in r for r in results)},indent=2))


if __name__=="__main__":
    main()
