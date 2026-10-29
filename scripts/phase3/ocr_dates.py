#!/usr/bin/env python3
"""Warm missing complete text and OCR date-bearing covers/tables, offline.

Only non-holdout collected originals are opened. Cache receipts verify original
bytes, native/full-text hash, per-page OCR decisions and the resulting text hash.
No verifier samples, filename dates, network, models or collector edits are used.
"""
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

import duckdb

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/build'))
sys.path.insert(0,str(ROOT/'scripts/phase3'))
from metadata_rules import atomic,canonical,sha
from dates import holdouts

VERSION='phase3c-ocr-1'


def extract(job):
    root,row=job
    digest,rel,fmt,needs_date=row
    folder=root/'local-cache/date-text'
    out=folder/(digest+'.txt'); receipt=out.with_suffix('.pages.json')
    if out.exists() and receipt.exists():
        info=json.loads(receipt.read_text())
        if info.get('version')==VERSION and info.get('text_sha256')==sha(out.read_bytes()):
            return dict(sha256=digest,status='cached',ocr_pages=info.get('ocr_pages',[]))
    full=root/'local-cache/fulltext'/(digest+'.txt')
    # Existing full text is sufficient unless the engagement lacks an eligible year.
    if full.exists() and not needs_date: return dict(sha256=digest,status='fulltext_present')
    candidates=[root/rel] if rel else []
    candidates+=sorted((root/'local-cache/originals'/digest[:2]).glob(digest+'.*'))
    original=next((p for p in candidates if p.is_file() and p.resolve().is_relative_to((root/'local-cache').resolve())),None)
    if not original: return dict(sha256=digest,status='original_unavailable')
    if sha(original.read_bytes())!=digest: raise ValueError('Original hash mismatch')
    if fmt!='pdf': return dict(sha256=digest,status='not_pdf')
    import pymupdf
    pymupdf.TOOLS.mupdf_display_errors(False)
    pymupdf.TOOLS.mupdf_display_warnings(False)
    tools=root/'local-cache/fulltext/tools/usr'
    env=os.environ.copy()
    env['LD_LIBRARY_PATH']=str(tools/'lib/x86_64-linux-gnu')
    env['TESSDATA_PREFIX']=str(tools/'share/tesseract-ocr/5/tessdata')
    env['OMP_THREAD_LIMIT']='1'
    tess=tools/'bin/tesseract'
    folder.mkdir(parents=True,exist_ok=True)
    try:
        with pymupdf.open(original) as pdf:
            if pdf.needs_pass: return dict(sha256=digest,status='encrypted')
            bodies=[p.get_text(sort=True) for p in pdf]
            ocr_pages=[]; failures=[]; attempted=0
            for i,page in enumerate(pdf):
                native=bodies[i]
                interesting=(i<8 or i>=len(pdf)-3 or re.search(r'timeline|revision\s+history|audit\s+date|assessment\s+period',native,re.I))
                if not interesting or not needs_date: continue
                area=sum(r.width*r.height for im in page.get_images() for r in page.get_image_rects(im[0]))
                if sum(c.isalnum() for c in native)>=220 and area<.15*page.rect.width*page.rect.height: continue
                # Bound work for long scanned appendices; this job is date-page
                # recovery, not a second full findings OCR pipeline.
                if attempted>=16:
                    failures.append(dict(page=i+1,error='date_page_ocr_budget')); continue
                attempted+=1
                if not tess.exists(): failures.append(dict(page=i+1,error='tesseract_unavailable')); continue
                with tempfile.TemporaryDirectory(prefix='phase3c-ocr-',dir=None) as tmp:
                    png=Path(tmp)/'page.png'
                    page.get_pixmap(matrix=pymupdf.Matrix(2.5,2.5)).save(png)
                    proc=subprocess.run([str(tess),str(png),'stdout','-l','eng','--psm','3'],env=env,capture_output=True,timeout=90)
                    value=proc.stdout.decode('utf-8','replace')
                    if proc.returncode==0 and sum(c.isalnum() for c in value)>=20:
                        bodies[i]=value
                        ocr_pages.append(i+1)
                    else: failures.append(dict(page=i+1,error='ocr_failed'))
            # Preserve higher-fidelity layout text if nothing needed OCR.
            if not ocr_pages and full.exists(): return dict(sha256=digest,status='fulltext_present',failures=failures)
            text='\f'.join(bodies)
            info=dict(version=VERSION,original_sha256=digest,original_hash_verified=True,
                      file_format='pdf',method='pymupdf_complete'+('+tesseract_date_pages' if ocr_pages else ''),
                      status='partial' if failures else 'ok',page_count=len(bodies),ocr_pages=ocr_pages,
                      failures=failures,text_sha256=sha(text.encode()))
            atomic(out,text); atomic(receipt,canonical(info)+'\n')
            return dict(sha256=digest,status=info['status'],ocr_pages=ocr_pages,failures=failures)
    except Exception as exc:
        return dict(sha256=digest,status='failed',error=type(exc).__name__+': '+str(exc)[:200])


def main(root,workers):
    blocked=holdouts(root)
    with duckdb.connect(str(root/'local-cache/phase3c/before.duckdb'),read_only=True) as con:
        rows=con.execute("SELECT d.sha256,min(d.local_path),min(d.file_format),bool_or(y.audit_year IS NULL) FROM documents d JOIN engagement_documents ed USING(document_id) JOIN engagement_years y USING(engagement_id) WHERE NOT d.is_seed AND d.file_format='pdf' AND d.sha256 IS NOT NULL GROUP BY d.sha256 ORDER BY d.sha256").fetchall()
    jobs=[(root,r) for r in rows if r[0] not in blocked]
    results=[]
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for i,future in enumerate(as_completed([pool.submit(extract,job) for job in jobs]),1):
            r=future.result()
            results.append(r)
            if i%100==0: print(f'checked {i}/{len(jobs)} PDF originals',flush=True)
    results.sort(key=lambda r:r['sha256'])
    atomic(root/'data/phase3/fixes_identity_repairs_ocr.json',json.dumps(dict(version=VERSION,holdouts_opened=0,results=results),indent=2)+'\n')
    from collections import Counter
    print(canonical(dict(statuses=dict(Counter(r['status'] for r in results)),ocr_artifacts=sum(bool(r.get('ocr_pages')) for r in results))))


def render_review(root):
    """Hash-order visual QA pages, never verifier-selected examples or holdouts."""
    import pymupdf
    blocked=holdouts(root); selected=[]
    out=Path('local-cache/tmp/phase3c-visual');out.mkdir(exist_ok=True)
    for path in sorted((root/'local-cache/date-text').glob('*.pages.json')):
        digest=path.name.removesuffix('.pages.json')
        if digest in blocked: continue
        info=json.loads(path.read_text())
        if not info.get('ocr_pages'): continue
        originals=sorted((root/'local-cache/originals'/digest[:2]).glob(digest+'.*'))
        if not originals or sha(originals[0].read_bytes())!=digest: continue
        page=info['ocr_pages'][0]
        with pymupdf.open(originals[0]) as pdf:
            png=out/(digest+'.png')
            pdf[page-1].get_pixmap(matrix=pymupdf.Matrix(1.5,1.5)).save(png)
        selected.append(dict(sha256=digest,page=page,image=str(png),ocr_text=(root/'local-cache/date-text'/(digest+'.txt')).read_text().split('\f')[page-1]))
        if len(selected)==3: break
    atomic(out/'review.json',json.dumps(selected,indent=2)+'\n')
    print(canonical([dict(sha256=r['sha256'],page=r['page'],image=r['image']) for r in selected]))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=ROOT)
    p.add_argument('--workers',type=int,default=4)
    p.add_argument('--render-review',action='store_true')
    a=p.parse_args(); render_review(a.root) if a.render_review else main(a.root,a.workers)
