#!/usr/bin/env python3
"""Extract/cache one intrinsic metadata record per collected original hash, offline."""
import argparse
from concurrent.futures import ProcessPoolExecutor
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts/build'))
from metadata_rules import atomic, canonical, process_artifact
from build_db import load_publishers


def extract(root=ROOT, workers=4):
    docs = {}
    publishers=load_publishers(root)
    for path in sorted((root/'data/collect').glob('*/reports.jsonl')):
        if path.parent.name not in publishers:
            continue
        data = path.read_bytes()
        for line in data.decode().splitlines():
            if line.strip():
                row = json.loads(line)
                if row.get('sha256'):
                    docs.setdefault(row['sha256'], row)
    results = {}
    with ProcessPoolExecutor(max_workers=workers) as pool:
        for i, (digest, meta) in enumerate(pool.map(process_artifact, ((root, d) for _,d in sorted(docs.items())), chunksize=8), 1):
            results[digest] = meta
            if i % 500 == 0:
                print(f'processed {i}/{len(docs)} hashes', flush=True)
    path = root/'data/phase3/artifact_metadata.jsonl'
    atomic(path, ''.join(canonical({'sha256': digest, **meta})+'\n' for digest,meta in sorted(results.items())))
    print(canonical({'unique_sha256': len(results), 'text_ok': sum(m['text_receipt']['status']=='ok' for m in results.values())}), flush=True)
    return results


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--workers', type=int, default=4)
    args = parser.parse_args()
    extract(args.root, args.workers)
