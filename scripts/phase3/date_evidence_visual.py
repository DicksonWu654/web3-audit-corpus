"""Render hash-ordered, non-holdout date evidence pages for local visual QA."""
import json
from pathlib import Path
import sys

import pymupdf

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/phase3'))
sys.path.insert(0,str(ROOT/'scripts/build'))
from date_evidence_dates import capture, documents
from date_layout_rules import layout_date_claims
from metadata_rules import sha,atomic,canonical


def main():
    wanted={'date_evidence_closing_author_dateline','date_evidence_report_revision_wrapped_year','date_evidence_localized_date_label','date_evidence_report_title_dateline'}
    folder=Path('local-cache/tmp/date_evidence-visual');folder.mkdir(exist_ok=True)
    snap=capture(ROOT,ROOT/'local-cache/phase3f/before.duckdb');results=[]
    for d,text,receipt,cause in sorted(documents(ROOT,snap),key=lambda r:r[0]['sha256'] or ''):
        if cause or d['file_format']!='pdf' or not d['sha256']:continue
        claims=layout_date_claims(text,receipt)
        for c in claims:
            if c['method'] not in wanted:continue
            original=sorted((ROOT/'local-cache/originals'/d['sha256'][:2]).glob(d['sha256']+'.*'))
            if not original:continue
            assert sha(original[0].read_bytes())==d['sha256']
            png=folder/(c['method']+'.png')
            with pymupdf.open(original[0]) as pdf:
                if c['page']>len(pdf):continue
                pdf[c['page']-1].get_pixmap(matrix=pymupdf.Matrix(1.5,1.5)).save(png)
            results.append(dict(method=c['method'],sha256=d['sha256'],filename=d['filename'],public_url=d['public_url'],page=c['page'],date_value=c['date_value'],raw_value=c['raw_value'],image=str(png)))
            wanted.remove(c['method'])
        if not wanted:break
    atomic(ROOT/'local-cache/phase3f/visual.json',canonical(dict(holdouts_opened=0,pages=results))+'\n')
    print(json.dumps(results,indent=2))


if __name__=='__main__':main()
