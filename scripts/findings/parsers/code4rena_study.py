"""Guarded reproducible C4 era sampling and mismatch inspection; metadata is never executed."""
import argparse
import json
from pathlib import Path
import re
import sys
from collections import Counter, defaultdict
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, holdouts, read_snapshot


def selected():
    docs = {d['row']['sha256']: d for d in read_snapshot() if d['row']['firm_id'] == 'code4rena'}
    ordered = sorted(docs.values(), key=lambda d:(d['row'].get('date_hint') or '', d['row']['sha256']))
    return ordered[::35]


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--mismatches', action='store_true')
    p.add_argument('--sha')
    p.add_argument('--limit', type=int, default=24)
    p.add_argument('--text', action='store_true')
    p.add_argument('--include-excerpts', action='store_true')
    a = p.parse_args()
    blocked = holdouts()
    docs = {d['row']['sha256']: d for d in read_snapshot() if d['row']['firm_id'] == 'code4rena'}
    diag = {r['sha256']:r for r in map(json.loads,(ROOT/'data/findings/validation/code4rena.jsonl').read_text().splitlines())}
    if a.include_excerpts:
        counts=defaultdict(Counter)
        with (ROOT/'data/findings/code4rena.jsonl').open() as stream:
            for r in map(json.loads,stream):
                assert r['sha256'] not in blocked
                if r['record_kind'] in {'formal_finding','summary_excerpt'}:
                    counts[r['sha256']][r['severity']]+=1
        comparable=[d for d in diag.values() if d['validation'] in {'match','mismatch'}]
        mismatches=[d for d in comparable if any(counts[d['sha256']][s]!=n for s,n in d['printed_summary']['counts'].items())]
        print('INCLUDING_LINK_ONLY_EXCERPTS',len(comparable)-len(mismatches),'/',len(comparable))
        for d in mismatches[:a.limit]:
            print(d['sha256'],docs[d['sha256']]['row']['public_url'],d['printed_summary']['counts'],dict(counts[d['sha256']]))
        return
    ds = selected()
    if a.mismatches:
        ds = [docs[sha] for sha,d in diag.items() if d['validation']=='mismatch']
    if a.sha:
        if a.sha in blocked:
            raise SystemExit('Holdout inspection denied')
        ds = [docs[a.sha]]
    for d in ds[:a.limit]:
        row=d['row']; sha=row['sha256']
        assert sha not in blocked
        text=(ROOT/'local-cache/fulltext'/(sha+'.txt')).read_text()
        print('\nDOC',sha,row.get('date_hint'),row['file_format'],row['public_url'])
        print('COUNTS',diag[sha].get('parsed_counts'),diag[sha].get('printed_summary',{}))
        if a.text:
            print(text[:24000])
        else:
            headings=[l for l in text.splitlines() if re.match(r'^#{1,3} ',l)]
            print('\n'.join(headings[:14]))
            print('TAIL','\n'.join(headings[-5:]))


if __name__=='__main__':
    main()
