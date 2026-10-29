"""Deterministic development layout inspection; deny holdouts before opening text."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest, holdouts, read_snapshot, write_json

TARGETS = ('chainsecurity','ottersec','kudelski-security','theori','cantina','zokyo','quantstamp')

def load(doc, root=ROOT):
    sha = doc['row']['sha256']
    if sha in holdouts(root):
        raise ValueError('Holdout inspection denied')
    path = root/'local-cache/fulltext'/(sha+'.pages.json')
    meta = json.loads(path.read_text())
    text = path.with_suffix('').with_suffix('.txt').read_bytes().decode('utf-8')
    if digest(text.encode()) != meta['text_sha256']:
        raise ValueError('Text hash mismatch')
    return text, meta

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--firms',nargs='*',default=list(TARGETS))
    p.add_argument('--sha')
    p.add_argument('--progress',action='store_true')
    p.add_argument('--failures',action='store_true')
    p.add_argument('--candidates',action='store_true')
    p.add_argument('--page',type=int)
    p.add_argument('--match',default=r'(?:OS-[A-Z]|QSP-|Severity|Classification|Version|Status|Correctness|Security|^\s*\d+(?:\.\d+)+\s|High-|Medium-|Low-|Issue #|Summary|SUMMARY|Finding|FINDING|Resolution|Resolved|Fixed|Patched|Acknowledg)')
    p.add_argument('--sample',type=int,default=3)
    p.add_argument('--limit',type=int,default=80)
    p.add_argument('--mismatches',action='store_true')
    p.add_argument('--capture-baseline',action='store_true')
    a=p.parse_args();docs=read_snapshot();group=defaultdict(list)
    for d in docs:
        if d['row']['firm_id'] in a.firms:group[d['row']['firm_id']].append(d)
    if a.failures:
        for firm in group:
            path=ROOT/'data/findings/validation'/(firm+'.jsonl')
            for diag in map(json.loads,path.read_text().splitlines()):
                if diag['validation']!='mismatch':continue
                row=next(d['row'] for d in group[firm] if d['document_id']==diag['document_id'])
                print(firm,diag['sha256'][:12],row.get('date_hint'),diag.get('variant_id'),row['filename'], 'expected',diag['printed_summary']['counts'],'parsed',{k:v for k,v in diag['parsed_counts'].items() if v})
        return
    if a.progress:
        for firm,rows in group.items():
            temp=ROOT/'data/findings'/(firm+'.jsonl.tmp')
            if not temp.exists():continue
            lines=temp.read_text().splitlines();last=json.loads(lines[-1]) if lines else {}
            i=next((i for i,d in enumerate(rows) if d['document_id']==last.get('document_id')),-1)
            print(firm,'completed_through_index',i,'last_sha',last.get('sha256'),'next',[(d['row']['sha256'],d['row']['filename']) for d in rows[i+1:i+4]])
        return
    if a.capture_baseline:
        out=ROOT/'local-cache/phase4d/baseline.json'
        if out.exists():raise ValueError('Baseline is immutable')
        result={}
        for firm,rows in group.items():
            path=ROOT/'data/findings/validation'/(firm+'.jsonl')
            result[firm]={'diagnostics':list(map(json.loads,path.read_text().splitlines())), 'rows':[]}
            with (ROOT/'data/findings'/(firm+'.jsonl')).open() as stream:
                for line in stream:
                    r=json.loads(line); result[firm]['rows'].append({k:r.get(k) for k in ('document_id','publisher_finding_id','status','record_kind','severity','title','body_span')})
        write_json(out,result)
        print(out);return
    for firm,rows in group.items():
        unique={d['row']['sha256']:d for d in rows}
        path=ROOT/'data/findings/validation'/(firm+'.jsonl')
        diags={r['sha256']:r for r in map(json.loads,path.read_text().splitlines())} if path.exists() else {}
        ordered=sorted(unique.values(),key=lambda d:(d['row'].get('date_hint') or '',d['row']['sha256']))
        if a.sha: selected=[d for d in ordered if d['row']['sha256'].startswith(a.sha)]
        elif a.mismatches: selected=[d for d in ordered if diags.get(d['row']['sha256'],{}).get('validation')=='mismatch'][:a.sample]
        else:selected=[ordered[i] for i in sorted({int(i*(len(ordered)-1)/max(1,a.sample-1)) for i in range(min(a.sample,len(ordered)))})]
        print('FIRM',firm,'occurrences',len(rows),'hashes',len(unique),'years',dict(sorted(Counter((d['row'].get('date_hint') or 'unknown')[:4] for d in rows).items())))
        for d in selected:
            sha=d['row']['sha256'];print('DOC',sha,d['row'].get('date_hint'),d['row']['filename']);diag=diags.get(sha,{});print('DIAG',{k:diag.get(k) for k in ('findings','validation','parsed_counts')},'EXPECTED',diag.get('printed_summary',{}).get('counts') if diag.get('printed_summary') else None)
            try:text,meta=load(d)
            except FileNotFoundError: print('NO TEXT');continue
            if a.candidates:
                from core import Report
                from parsers import module
                r=Report(text,meta,firm)
                for c in module(firm).parse(r):print(c.printed_id,c.record_kind,c.severity_raw,c.title,c.evidence.get('container_children'))
                continue
            if a.page:
                for page in meta['pages']:
                    if page['page']==a.page:print(page['text'])
            else:
                budget=a.limit
                for page in meta['pages']:
                    matching=[l for l in page['text'].splitlines() if re.search(a.match,l,re.I)]
                    if matching and budget>0:
                        print('PAGE',page['page'],'\n'+'\n'.join(matching[:budget]));budget-=len(matching)

if __name__=='__main__':main()
