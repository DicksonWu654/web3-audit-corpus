"""Holdout-denying Phase 4e group 3 development census and scoped metrics.

Uses the existing variants_report.metric implementation without overwriting
the shared report or another group's findings. Text is opened only by load().
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, holdouts, read_snapshot, write_json, documents, digest
from variants_study import load

FIRMS = ('verichains', 'halborn', 'solidified', 'dedaub', 'macro',
         'ackee-blockchain', 'bailsec', 'teamomega', 'sec3', 'ncc-group')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--firms', nargs='+', choices=FIRMS, default=FIRMS)
    p.add_argument('--sha')
    p.add_argument('--page', type=int)
    p.add_argument('--match', default=r'Finding|Severity|Status|Resolution|Remediation|Resolved|Fixed|AMENDED|Update|ACKNOWLEDGED|Overall Risk|Risk\s|Issue[_ -]|^[CHMLIWNAQG][ -]?\d|^[23](?:\.\d+)*[. ]')
    p.add_argument('--limit', type=int, default=30)
    p.add_argument('--after')
    p.add_argument('--context', type=int, default=0)
    p.add_argument('--metrics', action='store_true')
    p.add_argument('--residuals', action='store_true')
    p.add_argument('--unselected', action='store_true')
    p.add_argument('--details', action='store_true')
    p.add_argument('--findings', action='store_true')
    p.add_argument('--sequences', action='store_true')
    p.add_argument('--membership', action='store_true')
    p.add_argument('--verify', action='store_true')
    a = p.parse_args()
    blocked = holdouts()
    grouped = defaultdict(list)
    for d in read_snapshot():
        if d['row']['firm_id'] in a.firms:
            grouped[d['row']['firm_id']].append(d)
    if a.membership:
        live,_,_=documents()
        result={}
        for firm in a.firms:
            snapshot={d['document_id'] for d in grouped[firm]}
            current={d['document_id']:d for d in live if d['row']['firm_id']==firm}
            result[firm]={'snapshot':len(snapshot),'collection':len(current),
                          'missing_from_snapshot':[{'document_id':did,'sha256':d['row']['sha256'],'filename':d['row']['filename']} for did,d in current.items() if did not in snapshot]}
        print(json.dumps(result,indent=2));return
    if a.verify:
        from core import Report, severity_policy, severity_mapping
        from parsers import module
        from variants import select
        counts=Counter();source_hashes={};seen=set();layouts={}
        for firm in a.firms:
            docmap={d['document_id']:d for d in grouped[firm]};cache={}
            ds=[json.loads(l) for l in (ROOT/'data/findings/validation'/f'{firm}.jsonl').read_text().splitlines()]
            assert set(docmap)=={d['document_id'] for d in ds}
            assert not any(d['sha256'] in blocked for d in ds)
            assert not any(d['validation']=='parser_error' for d in ds)
            path=ROOT/'data/findings'/f'{firm}.jsonl';source_hashes[str(path.relative_to(ROOT))]=digest(path.read_bytes())
            for row in map(json.loads,path.read_text().splitlines()):
                assert row['sha256'] not in blocked
                parent=docmap[row['document_id']]
                if row['sha256'] not in cache:
                    cache.clear();cache[row['sha256']]=load(parent)
                    counts['artifacts_checked']+=1
                text,meta=cache[row['sha256']]
                if row['document_id'] not in layouts:
                    r=Report(text,meta|{'date_hint':parent['row'].get('date_hint')},firm);select(r,module(firm).VARIANTS)
                    layouts[row['document_id']]=r.layout_selection['variant_id']
                assert row['variant_id']==layouts[row['document_id']]
                assert row['variant_id']==row['provenance']['variant_id']==row['evidence']['variant_id']
                assert row['sha256']==parent['row']['sha256']
                assert row['source_record_sha256']==parent['source_record_sha256']
                assert row['finding_id'] not in seen;seen.add(row['finding_id'])
                start,end=row['body_span']['start'],row['body_span']['end']
                assert 0<=start<end<=len(text) and text[start:end]==row['body_text']
                assert row['body_span']['text_sha256']==meta['text_sha256']
                mapping=row['severity_mapping'];assert mapping['map_sha256']==severity_policy()[2], 'Severity crosswalk changed; rerun'
                expected=severity_mapping(row['severity_raw'],firm,era=mapping['era'],kind=(mapping.get('rule') or '').removeprefix('unrated_'),log=False)
                assert expected['normalized']==row['severity']
                proof=row['evidence'].get('status_evidence')
                fragments=row['evidence'].get('status_fragments')
                if proof:
                    assert text[proof['start']:proof['end']]==proof['raw']==proof['text']==row['status_raw']
                    counts['status_spans_checked']+=1
                if fragments:
                    for f in fragments:assert text[f['start']:f['end']]==f['text']
                    assert ' '.join(f['text'] for f in fragments)==row['status_raw']
                    counts['status_fragment_sets_checked']+=1
                if row['status_raw']:assert proof or fragments,('Status without exact evidence',firm,row['sha256'],row['publisher_finding_id'],row['status_raw'])
                counts['finding_rows_checked']+=1
            counts['documents_checked']+=len(ds)
        result={'ok':True,'holdouts_opened':0,'scope':list(a.firms),'counts':dict(counts),
                'finding_stream_sha256':source_hashes,'severity_map_sha256':severity_policy()[2],
                'input_snapshot_sha256':digest((ROOT/'data/fulltext/input_documents.jsonl').read_bytes())}
        write_json(ROOT/'data/findings/variants/group3_verification.json',result)
        print(json.dumps(result,indent=2));return
    if a.metrics:
        from variants_report import metric, sequence, cell
        from parsers import module
        metrics, residuals, examples = [], [], []
        for firm in a.firms:
            ds = [json.loads(l) for l in (ROOT/'data/findings/validation'/f'{firm}.jsonl').read_text().splitlines()]
            rs = [json.loads(l) for l in (ROOT/'data/findings'/f'{firm}.jsonl').read_text().splitlines()]
            assert not any(r['sha256'] in blocked for r in ds+rs)
            assert {d['document_id'] for d in grouped[firm]} == {d['document_id'] for d in ds}, 'Rerun with current inputs'
            bydoc = defaultdict(list)
            for r in rs:
                bydoc[r['document_id']].append(r)
                ev = r['evidence'].get('status_evidence')
                if ev:
                    assert ev['raw'] == ev['text']
            variants = {v.variant_id:v for v in module(firm).VARIANTS}
            for variant in sorted(set(variants)|{d.get('variant_id', firm+'/extraction_failed') for d in ds}):
                selected = [d for d in ds if d.get('variant_id',firm+'/extraction_failed') == variant]
                metrics.append(metric(firm, variant, selected, [r for r in rs if r.get('variant_id') == variant]))
                years = defaultdict(list)
                source_docs={d['document_id']:d for d in grouped[firm]}
                for d in selected:
                    filename=source_docs[d['document_id']]['row']['filename']
                    hints=re.findall(r'\b20[0-3]\d\b',filename)
                    study_year=d.get('year') or (hints[-1] if hints else 'unknown')
                    years[study_year].append(d)
                for year, items in sorted(years.items()):
                    ordered = sorted(items,key=lambda d:d['sha256'])
                    for d in {x['sha256']:x for x in (ordered[0],ordered[-1])}.values():
                        examples.append({k:d.get(k) for k in ('firm_id','sha256','document_id','year','variant_id','scores','validation')}|{'study_year':year,'study_year_basis':'collector_hint' if d.get('year') else 'filename_hint' if year!='unknown' else 'none'})
            for d in ds:
                seq = sequence(bydoc[d['document_id']],firm)
                classes = []
                if d['validation'] in {'mismatch','parser_error','extraction_failed'}: classes.append(d['validation'])
                if d.get('unknown_layout'): classes.append('unknown_layout')
                if not d.get('findings'): classes.append('no_findings')
                if seq and not seq['complete']: classes.append('source_id_gap_or_parser_omission')
                if classes: residuals.append(d|{'classes':classes,'sequence':seq})
        queue = [json.loads(l) for l in (ROOT/'data/findings/_unknown_layouts.jsonl').read_text().splitlines()]
        unknown = [r for r in queue if r['firm'] in FIRMS]
        result = {'metric_implementation':'scripts/findings/variants_report.py:metric', 'holdouts_opened':0,
                  'metrics':metrics,'residuals':residuals,'unknown_layouts':unknown,'year_examples':examples}
        write_json(ROOT/'data/findings/variants/group3.json',result)
        print('| Publisher / variant | Docs | Summary agreement | ID completeness | Docs with findings | Status coverage |')
        print('|---|---:|---:|---:|---:|---:|')
        for m in metrics:
            print('| '+m['variant_id']+' | '+str(m['documents'])+' | '+' | '.join((
                cell(m['summary_matching'],m['summary_comparable']),cell(m['sequence_complete'],m['sequence_comparable']),
                cell(m['documents_with_findings'],m['documents']),cell(m['known_status_rows'],m['detailed_rows'])))+' |')
        print('Residual classes:',dict(Counter(c for r in residuals for c in r['classes'])))
        print('Unknown group 3 layouts:',len(unknown))
        return
    for firm, docs in grouped.items():
        ds = [json.loads(l) for l in (ROOT/'data/findings/validation'/f'{firm}.jsonl').read_text().splitlines()]
        diagnostics = {d['sha256']:d for d in ds}
        if a.sequences:
            from variants_report import sequence
            bydoc=defaultdict(list)
            for line in (ROOT/'data/findings'/f'{firm}.jsonl').read_text().splitlines():
                row=json.loads(line);bydoc[row['document_id']].append(row)
            for d in ds:
                seq=sequence(bydoc[d['document_id']],firm)
                if seq and not seq['complete']:print(firm,d['sha256'],d.get('variant_id'),seq)
            continue
        unique = {d['row']['sha256']:d for d in docs}
        years = defaultdict(list)
        for d in unique.values():
            # Sampling only: URL/filename years do not become audit dates or
            # affect the dispatcher's deliberately weak collector date hint.
            hinted=d['row'].get('date_hint')
            filename_year=re.findall(r'\b20[0-3]\d\b',d['row']['filename'])
            years[hinted[:4] if hinted else filename_year[-1] if filename_year else 'unknown'].append(d)
        print('FIRM',firm,'occurrences',len(docs),'years',dict(sorted((y,len(v)) for y,v in years.items())))
        if a.sha:
            selected = [d for sha,d in unique.items() if sha.startswith(a.sha)]
        elif a.residuals:
            selected = [d for sha,d in unique.items() if diagnostics[sha]['validation']=='mismatch' or not diagnostics[sha].get('findings')]
        elif a.unselected:
            from parsers import module
            from core import Report
            from variants import select
            selected=[]
            for d in unique.values():
                text,meta=load(d)
                report=Report(text,meta|{'date_hint':d['row'].get('date_hint')},firm)
                if select(report,module(firm).VARIANTS) is None: selected.append(d)
        else:
            selected=[min(v,key=lambda d:d['row']['sha256']) for y,v in sorted(years.items())]
        for d in selected:
            row=d['row']; diag=diagnostics.get(row['sha256'],{})
            print('DOC',row['sha256'],row.get('date_hint'),row['filename'],'DIAG',diag.get('variant_id'),diag.get('validation'),diag.get('findings'))
            if a.details: print('VALIDATION',json.dumps(diag,ensure_ascii=False))
            if a.findings:
                for r in map(json.loads,(ROOT/'data/findings'/f'{firm}.jsonl').read_text().splitlines()):
                    if r['sha256']==row['sha256']:
                        print(r['publisher_finding_id'],r['record_kind'],r['severity_raw'],r['status_raw'],r['title'],'CONTAINER',r['evidence'].get('container_id'))
                continue
            text, meta=load(d)
            if a.page:
                print(next((p['text'] for p in meta['pages'] if p['page']==a.page),''));continue
            lines=[(p['page'],l) for p in meta['pages'] for l in p['text'].splitlines()]
            if a.after:
                at=next((i for i,(_,l) in enumerate(lines) if re.search(a.after,l,re.I)),len(lines))
                lines=lines[at:]
            indices={j for i,(_,l) in enumerate(lines) if re.search(a.match,l,re.I) for j in range(max(0,i-a.context),min(len(lines),i+a.context+1))}
            matched=[v for i,v in enumerate(lines) if i in indices]
            print('\n'.join(f'{page}: {l}' for page,l in matched[:a.limit]))


if __name__ == '__main__': main()
