#!/usr/bin/env python3
"""Warm complete text only for newly recovered originals, excluding holdouts."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/findings'))
from common import holdouts, write_json
from extract import extract_one


def main():
    blocked=holdouts(ROOT)
    docs={}
    for path in sorted((ROOT/'data/phase3/date_recovery').glob('*.json')):
        r=json.loads(path.read_text())
        if r.get('row') and r['sha256'] not in blocked:
            docs[r['sha256']]=r['row']
    results=[]
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures=[pool.submit(extract_one,item,ROOT,blocked) for item in sorted(docs.items())]
        for f in as_completed(futures):
            results.append(f.result())
    write_json(ROOT/'data/phase3/date_recovery_text.json',sorted(results,key=lambda r:r['sha256']))
    print(json.dumps(dict(hashes=len(results),ok=sum(r.get('status')=='ok' for r in results))))


if __name__=='__main__':
    main()
