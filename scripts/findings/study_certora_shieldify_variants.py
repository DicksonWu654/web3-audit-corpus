"""Holdout-safe local census, source inspection, and per-variant metrics for Phase 4e."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, holdouts, read_snapshot


def inputs():
    blocked = holdouts()
    docs = [d for d in read_snapshot() if d['row']['firm_id'] in {'certora', 'shieldify'}]
    assert all(d['row']['sha256'] not in blocked for d in docs)
    return docs


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=('census', 'source', 'metrics', 'failures', 'audit'))
    p.add_argument('--sha')
    p.add_argument('--pattern')
    p.add_argument('--context', type=int, default=5)
    p.add_argument('--all', action='store_true')
    p.add_argument('--visible', action='store_true',help='Matching-only removal of PDF directional glyphs')
    a = p.parse_args()
    docs = inputs()
    if a.mode == 'source':
        matching = [d for d in docs if d['row']['sha256'].startswith(a.sha or '!')]
        hashes = {d['row']['sha256'] for d in matching}
        if len(hashes) != 1:
            raise ValueError('Expected one non-holdout development hash')
        sha = hashes.pop()
        text = (ROOT/'local-cache/fulltext'/f'{sha}.txt').read_text()
        print(json.dumps(matching[0]['row'], ensure_ascii=False))
        if not a.pattern:
            print(text)
        else:
            lines = text.splitlines()
            if a.visible:
                from layout_support import visible
                lines=[visible(l) for l in lines]
            selected = set()
            for i, line in enumerate(lines):
                if re.search(a.pattern, line, re.I):
                    selected.update(range(max(0,i-a.context), min(len(lines),i+a.context+1)))
            for i in sorted(selected):
                print(f'{i+1}: {lines[i]}')
        return
    if a.mode == 'census':
        for firm in ('certora', 'shieldify'):
            groups = defaultdict(list)
            for d in docs:
                r=d['row']
                if r['firm_id']==firm:
                    groups[(r.get('date_hint') or 'unknown')[:4]].append(r)
            for year, rows in sorted(groups.items()):
                print(firm, year, len(rows), dict(Counter(r['file_format'] for r in rows)))
                for r in sorted(rows,key=lambda r:r['sha256'])[:None if a.all else 2]:
                    sha=r['sha256']; path=ROOT/'local-cache/fulltext'/f'{sha}.txt'
                    if not path.exists():continue
                    text=path.read_text()
                    signatures=Counter()
                    for tag,pat in [('card',r'^\s*Issue:'),('id',r'^\s*(?:High|Low|Medium|Informational|[CHMLIG])[-–]\s*\d+'),('finding',r'^\s*FINDING\s+'),('severity',r'^\s*Severity\b'),('status',r'^\s*Status\b')]:
                        signatures[tag]=len(re.findall(pat,text,re.M|re.I))
                    print(sha, r.get('filename'), dict(signatures))
        return
    from variants_report import metric, cell
    for firm in ('certora', 'shieldify'):
        ds=[json.loads(l) for l in (ROOT/'data/findings/validation'/f'{firm}.jsonl').read_text().splitlines()]
        rs=[json.loads(l) for l in (ROOT/'data/findings'/f'{firm}.jsonl').open()]
        assert not ({r['sha256'] for r in rs}|{d['sha256'] for d in ds}) & holdouts()
        if a.mode == 'audit':
            texts={};counts=Counter();missing=[]
            for r in rs:
                counts['rows']+=1
                if not r.get('status_raw'):continue
                counts['status_rows']+=1
                e=r.get('evidence',{}).get('status_evidence')
                if not e:
                    missing.append([r['sha256'],r.get('publisher_finding_id'),r.get('status_raw')]);continue
                sha=r['sha256']
                if sha not in texts:texts[sha]=(ROOT/'local-cache/fulltext'/f'{sha}.txt').read_bytes().decode('utf-8')
                assert texts[sha][e['start']:e['end']]==e['text']==r['status_raw'],(sha,r.get('publisher_finding_id'))
                counts['exact_status_spans']+=1
            print(json.dumps({'firm':firm,'counts':dict(counts),'missing_status_evidence':missing},ensure_ascii=False))
            continue
        if a.mode == 'metrics':
            for variant in sorted({d.get('variant_id',firm+'/extraction_failed') for d in ds}):
                m=metric(firm,variant,[d for d in ds if d.get('variant_id',firm+'/extraction_failed')==variant],[r for r in rs if r.get('variant_id')==variant])
                print('|',variant,'|',m['documents'],'|',cell(m['summary_matching'],m['summary_comparable']),'|',cell(m['sequence_complete'],m['sequence_comparable']),'|',cell(m['documents_with_findings'],m['documents']),'|',cell(m['known_status_rows'],m['detailed_rows']),'|')
        else:
            from variants_report import sequence
            bydoc=defaultdict(list)
            for r in rs:bydoc[r['document_id']].append(r)
            for d in ds:
                seq=sequence(bydoc[d['document_id']],firm)
                if d['validation']=='mismatch' or d.get('unknown_layout') or not d.get('findings') or (seq and not seq['complete']):
                    print(json.dumps({k:d.get(k) for k in ('firm_id','sha256','year','variant_id','validation','findings','parsed_counts')}|{'summary':(d.get('printed_summary') or {}).get('counts'),'sequence':seq},ensure_ascii=False))


if __name__ == '__main__':
    main()
