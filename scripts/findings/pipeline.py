"""Resume the local Phase 4a pipeline; refresh source membership only when requested."""
import argparse
import json
import subprocess
import sys
from common import ROOT


def run(name,*arguments):
    subprocess.run([sys.executable,str(ROOT/"scripts/findings"/name),*arguments],cwd=ROOT,check=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--refresh-inputs",action="store_true")
    p.add_argument("--workers",type=int,default=8)
    a=p.parse_args()
    if a.refresh_inputs or not (ROOT/"data/fulltext/input_documents.jsonl").exists():
        run("inventory.py")
    previous=None
    while True:
        run("extract.py","--workers",str(a.workers),"--max-new","250")
        summary=json.loads((ROOT/"data/fulltext/summary.json").read_text())
        pending=summary["document_status"].get("pending",0)
        if not pending:
            break
        if pending==previous:
            raise RuntimeError("Extraction pending count did not decrease; inspect failure receipts")
        previous=pending
    for extended in (False,True):
        previous=None
        while True:
            run("retry_ocr.py","--workers",str(min(4,a.workers)),"--max-new","100",*(["--extended"] if extended else []))
            results=json.loads((ROOT/"data/fulltext/ocr_retry_last_batch.json").read_text())
            if not results:
                break
            signature=tuple(r["sha256"] for r in results)
            if signature==previous:
                raise RuntimeError("OCR retry could not advance; inspect retry errors")
            previous=signature
    run("extract.py","--workers",str(a.workers))  # Refresh receipts after OCR retries and retry terminal failures.
    run("test_framework.py")
    run("test_variants.py")
    run("run.py")
    run("check.py")
    run("report.py")
    run("variants_report.py")


if __name__=="__main__":
    main()
