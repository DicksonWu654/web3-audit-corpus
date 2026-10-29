#!/usr/bin/env python3
"""Offline input census; never expose holdout examples during rule development."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def profile(root=ROOT, examples=False):
    holdout = root / 'data/holdout/gold_sha256.txt'
    held = set(holdout.read_text().split()) if holdout.exists() else set()
    rows = [json.loads(s) for p in sorted((root/'data/collect').glob('*/reports.jsonl'))
            for s in p.read_text().splitlines() if s.strip()]
    hashes = {r['sha256'] for r in rows}
    result = {'rows': len(rows), 'unique_sha256': len(hashes),
              'held_out_sha256': len(hashes & held),
              'formats': dict(Counter(r['file_format'] for r in rows)),
              'kinds': dict(Counter(r['doc_kind'] for r in rows)),
              'date_basis': dict(Counter(r['date_basis'] for r in rows)),
              'firms': dict(sorted(Counter(r['firm_id'] for r in rows).items()))}
    result['firm_unique_sha256'] = {firm:len({r['sha256'] for r in rows if r['firm_id']==firm}) for firm in result['firms']}
    result['firm_doc_kinds'] = {firm:dict(Counter(r['doc_kind'] for r in rows if r['firm_id']==firm)) for firm in result['firms']}
    candidates = [json.loads(s) for p in sorted((root/'data/discovery').glob('*/candidates.jsonl'))
                  for s in p.read_text().splitlines() if s.strip()]
    result['discovery'] = {'rows': len(candidates),
                           'attribution': dict(Counter(str(r.get('attribution_basis', {}).get('kind')) for r in candidates)),
                           'dates': sum(bool(r.get('date_hint')) for r in candidates),
                           'hashes': sum(bool(r.get('sha256')) for r in candidates)}
    contests = [json.loads(s) for p in sorted((root/'data/collect').glob('*/contests.jsonl'))
                for s in p.read_text().splitlines() if s.strip()]
    result['contest_formats'] = dict(Counter(r.get('format') for r in contests))
    if examples:
        result['non_holdout_examples'] = [
            {k: r.get(k) for k in ('firm_id','filename','title_hint','project_hint','date_hint','date_basis','local_path')}
            for firm in sorted(result['firms'])
            for r in [next((r for r in rows if r['firm_id']==firm and r['sha256'] not in held), {})] if r]
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=ROOT)
    p.add_argument('--examples', action='store_true')
    args = p.parse_args()
    print(json.dumps(profile(args.root, args.examples), indent=2))
