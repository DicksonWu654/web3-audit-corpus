"""Group 2 development inspection/reporting; deny holdouts before cache access.

Metrics reuse variants_report.metric/sequence/cell, so denominators are identical.
Only group 2 outputs are written; other publishers and shared reports stay untouched.
"""
import argparse
from collections import Counter, defaultdict
from dataclasses import asdict
import json
from pathlib import Path
import re
import subprocess
import tempfile
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, documents, holdouts, read_snapshot, write_json, write_jsonl
from core import Report
from parsers import module
from variants_study import load
from variants_report import metric, cell, sequence

FIRMS = ('peckshield', 'spearbit', 'blocksec', 'least-authority', 'pessimistic',
         'iosiro', 'decurity', 'coinspect', 'composable-security', 'secure3')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--firms', nargs='+', default=FIRMS, choices=FIRMS)
    p.add_argument('--sha')
    p.add_argument('--page', type=int)
    p.add_argument('--match', default=r'Severity|Status|Resolution|Verification|Fixed|Resolved|Acknowledg|Risk|PVE-|Issue [A-Z]:|Suggestion \d+:|^\s*[2-6]\.\d+|^\s*[CHMLNI]\d+[.:]')
    p.add_argument('--limit', type=int, default=35)
    p.add_argument('--failures', action='store_true')
    p.add_argument('--gaps', action='store_true')
    p.add_argument('--empty', action='store_true')
    p.add_argument('--cards', action='store_true')
    p.add_argument('--around')
    p.add_argument('--membership',action='store_true')
    p.add_argument('--unknown',action='store_true')
    p.add_argument('--refresh',action='store_true',help='Regenerate only selected publishers from live collector metadata and available fulltext pairs')
    p.add_argument('--survey',action='store_true')
    p.add_argument('--verify',action='store_true')
    p.add_argument('--framework-report',action='store_true',help='Execute variants_report.py in a separate group-only output root')
    p.add_argument('--finalize',action='store_true',help='Verify all source receipts, run the unchanged report, then write this group report')
    p.add_argument('--report', action='store_true')
    a = p.parse_args()
    blocked = holdouts()
    input_path=ROOT/'data/findings/variants/group2_inputs.jsonl'
    source=list(map(json.loads,input_path.read_text().splitlines())) if input_path.exists() else read_snapshot()
    docs = [d for d in source if d['row']['firm_id'] in a.firms and d['row']['sha256'] not in blocked]
    if a.refresh:return regenerate(a.firms,blocked)
    if a.finalize:
        verify(docs,blocked,a.firms)
        framework_report(docs,blocked)
        return report(docs,blocked)
    if a.verify:return verify(docs,blocked,a.firms)
    if a.framework_report:return framework_report(docs,blocked)
    if a.survey:
        policy=json.loads((ROOT/'schema/severity_map.yaml').read_text())
        for firm in a.firms:
            print('POLICY',firm,[{'id':e['id'],'unrated':e.get('unrated'),'labels':{k:v['normalized'] for k,v in e['labels'].items()}} for e in policy['publishers'][firm]['eras']])
            rows={d['row']['sha256']:d for d in docs if d['row']['firm_id']==firm}
            for sha,d in sorted(rows.items()):
                text,meta=load(d)
                matches=[(p['page'],l.strip()) for p in meta['pages'] for l in p['text'].splitlines() if re.search(a.match,l,re.I)]
                print(sha,d['row'].get('date_hint'),d['row']['filename'],matches[:a.limit])
        return
    if a.membership:
        live,_,_=documents();old={d['document_id'] for d in docs};new=[d for d in live if d['row']['firm_id'] in a.firms and d['document_id'] not in old]
        print('new occurrences',dict(Counter(d['row']['firm_id'] for d in new)))
        print('new hashes',dict(Counter(f for f,s in {(d['row']['firm_id'],d['row']['sha256']) for d in new})))
        print('cached new',dict(Counter(d['row']['firm_id'] for d in new if (ROOT/'local-cache/fulltext'/(d['row']['sha256']+'.pages.json')).exists())))
        return
    if a.report:
        return report(docs, blocked)
    for firm in a.firms:
        rows = [d for d in docs if d['row']['firm_id'] == firm]
        unique = {d['row']['sha256']:d for d in rows}
        ds = {d['sha256']:d for d in map(json.loads, (ROOT/'data/findings/validation'/(firm+'.jsonl')).read_text().splitlines())}
        by_year = defaultdict(list)
        for d in unique.values():by_year[(d['row'].get('date_hint') or 'unknown')[:4]].append(d)
        print('FIRM', firm, 'occurrences', len(rows), 'artifacts',len(unique),'years',dict(sorted(Counter((d['row'].get('date_hint') or 'unknown')[:4] for d in rows).items())))
        findings = defaultdict(list)
        if a.gaps:
            for line in (ROOT/'data/findings'/(firm+'.jsonl')).open():
                r=json.loads(line)
                if r['sha256'] in blocked:raise ValueError('Holdout findings denied')
                findings[r['document_id']].append(r)
        selected = sorted(unique.values(), key=lambda d:((d['row'].get('date_hint') or ''),d['row']['sha256']))
        if a.sha:selected=[d for d in selected if d['row']['sha256'].startswith(a.sha)]
        elif a.failures:selected=[d for d in selected if ds.get(d['row']['sha256'],{}).get('validation')=='mismatch']
        elif a.empty:selected=[d for d in selected if not ds.get(d['row']['sha256'],{}).get('findings')]
        elif a.unknown:selected=[d for d in selected if ds.get(d['row']['sha256'],{}).get('unknown_layout')]
        elif a.gaps:selected=[d for d in selected if (sequence(findings[d['document_id']],firm) or {}).get('complete') is False]
        else:selected=[sorted(v,key=lambda d:d['row']['sha256'])[0] for _,v in sorted(by_year.items())]
        for d in selected:
            sha=d['row']['sha256'];diag=ds.get(sha,{'validation':'not_yet_regenerated'})
            print('DOC',sha,d['row'].get('date_hint'),d['row']['filename'],diag.get('variant_id'),diag['validation'],'EXPECTED',(diag.get('printed_summary') or {}).get('counts'),'PARSED',{k:v for k,v in diag.get('parsed_counts',{}).items() if v})
            if a.gaps:print('SEQUENCE',sequence(findings[d['document_id']],firm))
            if a.limit==0:continue
            text,meta=load(d)
            if a.around:
                for m in list(re.finditer(a.around,text,re.I|re.M))[:10]:print(text[max(0,m.start()-180):m.end()+a.limit])
                continue
            if a.cards:
                r=Report(text,meta|{'date_hint':d['row'].get('date_hint')},firm)
                for c in module(firm).parse(r):
                    print(c.printed_id,c.severity_raw,c.status_raw,c.title,'SPAN',c.start,c.end)
                    print(text[c.start:min(c.end,c.start+a.limit)])
                continue
            if a.page:
                print(next((p['text'] for p in meta['pages'] if p['page']==a.page),''));continue
            matches=[(l.page,l.text) for l in Report(text,meta,firm).lines if re.search(a.match,l.text,re.I)]
            for page,value in matches[:a.limit]:print(page,value[:700])


def report(docs, blocked):
    metrics=[]; catalog=[]; residuals=[]; samples=[]
    for firm in FIRMS:
        ds=list(map(json.loads,(ROOT/'data/findings/validation'/(firm+'.jsonl')).read_text().splitlines()))
        rs=list(map(json.loads,(ROOT/'data/findings'/(firm+'.jsonl')).read_text().splitlines()))
        assert all(d['sha256'] not in blocked for d in ds+rs)
        assert {d['document_id'] for d in ds}=={d['document_id'] for d in docs if d['row']['firm_id']==firm}
        variants={v.variant_id:v for v in module(firm).VARIANTS}
        for vid in sorted(set(variants)|{d.get('variant_id',firm+'/extraction_failed') for d in ds}):
            subset=[d for d in ds if d.get('variant_id',firm+'/extraction_failed')==vid]
            metrics.append(metric(firm,vid,subset,[r for r in rs if r.get('variant_id')==vid]))
            if vid in variants:
                v=variants[vid]
                catalog.append(dict(variant_id=vid,fingerprint=asdict(v.fingerprint),parser=v.parse.__name__,status_parser=v.status_parser.__name__,fixtures=v.fixtures,notes=v.notes))
            years=defaultdict(list)
            for d in subset:years[d.get('year') or 'unknown'].append(d)
            for year,items in sorted(years.items()):
                ordered=sorted(items,key=lambda d:d['sha256'])
                for d in {x['sha256']:x for x in (ordered[0],ordered[-1])}.values():
                    samples.append({k:d.get(k) for k in ('firm_id','sha256','document_id','year','variant_id','scores','validation')})
        for d in ds:
            if d['validation'] in {'mismatch','parser_error','extraction_failed'} or d.get('unknown_layout') or not d.get('findings'):
                residuals.append(d)
    live,_,_=documents()
    snapshot_ids={d['document_id'] for d in docs}
    added=[{k:d[k] for k in ('document_id','source_file','source_locator')}|{'firm_id':d['row']['firm_id'],'sha256':d['row']['sha256']} for d in live if d['row']['firm_id'] in FIRMS and d['document_id'] not in snapshot_ids]
    queue=[json.loads(l) for l in (ROOT/'data/findings/_unknown_layouts.jsonl').open()]
    unknown=[r for r in queue if r['firm'] in FIRMS]
    gates=[]
    for m in metrics:
        if m['summary_comparable']:
            measure='summary_agreement_percent';value=m[measure]
        elif m['sequence_comparable']:
            measure='id_sequence_completeness_percent';value=m[measure]
        else:measure=None;value=None
        gates.append(dict(variant_id=m['variant_id'],measure=measure,percent=value,
                          gate='pass' if value is not None and value>=95 else 'below_target' if value is not None else 'unassessable'))
    verification_path=ROOT/'data/findings/variants/group2_verification.json'
    verification=json.loads(verification_path.read_text()) if verification_path.exists() else None
    framework_path=ROOT/'data/findings/variants/group2_framework_report.json'
    framework=json.loads(framework_path.read_text()) if framework_path.exists() else None
    if framework and sorted(framework['per_variant'],key=lambda m:m['variant_id'])!=sorted(metrics,key=lambda m:m['variant_id']):
        raise ValueError('Refresh --framework-report after changing group 2 outputs')
    result=dict(per_variant=metrics,gates=gates,catalog=catalog,residuals=residuals,development_examples=samples,unknown=unknown,new_collector_occurrences=added,verification=verification,framework_report=framework,holdouts_opened=0)
    write_json(ROOT/'data/findings/variants/group2.json',result)
    lines=['# Phase 4e — group 2 layout variants','',
           'Generated by `python3 -I -S scripts/findings/variants_group2.py --report`; metrics use the existing `variants_report.py` metric and sequence readers. Holdouts are excluded before text access. Dates are weak hints; signatures select overlapping format eras independently of severity policy.','',
           '| Publisher / variant | Documents | Summary agreement | ID completeness | Docs with findings | Status coverage |',
           '|---|---:|---:|---:|---:|---:|']
    for m in metrics:
        lines.append(f"| {m['variant_id']} | {m['documents']} | {cell(m['summary_matching'],m['summary_comparable'])} | {cell(m['sequence_complete'],m['sequence_comparable'])} | {cell(m['documents_with_findings'],m['documents'])} | {cell(m['known_status_rows'],m['detailed_rows'])} |")
    lines+=['',f'Unknown layout receipts for this group: {len(unknown)}. Collector occurrences not yet included in this group’s refreshed input snapshot: {len(added)}. Holdout texts opened: 0.','',
            f"Documents: {sum(m['documents'] for m in metrics)}. Findings: {sum(m['findings'] for m in metrics)}. Known detailed statuses: {cell(sum(m['known_status_rows'] for m in metrics),sum(m['detailed_rows'] for m in metrics))}.",
            '','## Target checks','',
            '| Variant | Applicable measure | Result | Gate |','|---|---|---:|---|']
    for g in gates:
        value=f"{g['percent']:.2f}%" if g['percent'] is not None else 'N/A'
        lines.append(f"| {g['variant_id']} | {g['measure'] or 'No comparable summary or numeric ID sequence'} | {value} | {g['gate']} |")
    if verification:
        lines+=['',f"Exact source-span verification: {verification['counts'].get('findings',0)} finding bodies and {verification['counts'].get('known_status',0)} known-status evidence receipts; {len(verification['errors'])} errors."]
    if framework:lines+=['','The unchanged `variants_report.py` was also executed against an isolated group-only output root. Its per-variant metrics match this table exactly; receipt: `data/findings/variants/group2_framework_report.json`.']
    lines+=['',
            '## Layout contracts','']
    for c in catalog:lines.append(f"- `{c['variant_id']}`: {c['notes']}")
    lines+=['','## Residual failure classes','',
            'Summary comparisons retain all comparable mismatches, including source contradictions; neither layout selection nor finding emission uses aggregate totals. ID completeness tests printed numeric namespaces; it cannot establish recall for unnumbered findings or a missing final ID. Status coverage measures availability, not independently labelled accuracy. Missing or ambiguous publisher status stays null.','',
            '| Publisher | Validation | Documents |','|---|---|---:|']
    for (firm,state),n in sorted(Counter((d['firm_id'],d['validation']) for d in residuals).items()):lines.append(f'| {firm} | {state} | {n} |')
    notes=ROOT/'scripts/findings/fixtures/group2/residual_notes.json'
    if notes.exists():
        lines+=['']+[f"- **{k}**: {v}" for k,v in json.loads(notes.read_text()).items()]
    lines+=['','Detailed mismatch receipts, evidence and year/era samples: `data/findings/variants/group2.json`.','']
    owned=[f'scripts/findings/parsers/{f.replace("-","_")}.py' for f in FIRMS]
    owned+=['scripts/findings/parsers/group2_layouts.py','scripts/findings/fixtures_group2_variants.py','scripts/findings/fixtures/group2/residual_notes.json','scripts/findings/test_variants_group2.py','scripts/findings/variants_group2.py','docs/phase4/variants_group2.md']
    generated=[f'data/findings/{f}.jsonl' for f in FIRMS]+[f'data/findings/validation/{f}{suffix}' for f in FIRMS for suffix in ('.json','.jsonl')]
    generated+=['data/findings/_unknown_layouts.jsonl','data/findings/variants/group2_inputs.jsonl','data/findings/variants/group2.json','data/findings/variants/group2_verification.json','data/findings/variants/group2_framework_report.json']
    lines+=['## Files written','','No shared framework source was changed. The shared unknown-layout queue was rebuilt using the existing framework, preserving other publishers’ diagnostics. Temporary regeneration roots are printed by `--refresh`; originals, fulltext caches, collectors and shared input snapshots are not modified.','']
    lines += [f'- `{path}`' for path in owned+generated]
    (ROOT/'docs/phase4/variants_group2.md').write_text('\n'.join(lines))
    print('\n'.join(lines[:8+len(metrics)]))


def verify(docs,blocked,firms):
    by_id={d['document_id']:d for d in docs};cached={};errors=[];counts=Counter()
    for firm in firms:
        for line in (ROOT/'data/findings'/(firm+'.jsonl')).open():
            row=json.loads(line);sha=row['sha256']
            if sha in blocked:raise ValueError('Holdout findings denied')
            if sha not in cached:
                text,meta=load(by_id[row['document_id']]);cached={sha:(text,meta)}
            text,meta=cached[sha]
            span=row['body_span'];a,b=span['start'],span['end'];counts['findings']+=1
            if text[a:b]!=row['body_text'] or not 0<=a<b<=len(text) or span['text_sha256']!=meta['text_sha256']:errors.append((firm,sha,'body_span',row['publisher_finding_id']))
            if row['review']['unknown_layout']:counts['unknown_rows']+=1
            if row.get('status') not in {None,'other'}:
                counts['known_status']+=1;e=row['evidence'].get('status_evidence')
                if not e or text[e['start']:e['end']]!=e['text']:errors.append((firm,sha,'status_evidence',row['publisher_finding_id']))
    result={'counts':dict(counts),'errors':errors,'holdouts_opened':0}
    write_json(ROOT/'data/findings/variants/group2_verification.json',result)
    print(json.dumps(result,indent=2))
    if errors:raise SystemExit(1)


def framework_report(docs,blocked):
    stage=Path(tempfile.mkdtemp(prefix='phase4e-group2-metrics-'))
    (stage/'data/fulltext').mkdir(parents=True)
    (stage/'data/findings/validation').mkdir(parents=True)
    (stage/'docs/phase4').mkdir(parents=True)
    (stage/'data/holdout').symlink_to(ROOT/'data/holdout',target_is_directory=True)
    write_jsonl(stage/'data/fulltext/input_documents.jsonl',docs)
    for firm in FIRMS:
        for suffix in (firm+'.jsonl','validation/'+firm+'.jsonl','validation/'+firm+'.json'):
            (stage/'data/findings'/suffix).symlink_to(ROOT/'data/findings'/suffix)
    queue=[json.loads(l) for l in (ROOT/'data/findings/_unknown_layouts.jsonl').open()]
    write_jsonl(stage/'data/findings/_unknown_layouts.jsonl',[q for q in queue if q['firm'] in FIRMS])
    command=[sys.executable,'-I','-B','-S',str(ROOT/'scripts/findings/variants_report.py'),'--root',str(stage)]
    with (stage/'framework_report.log').open('w') as log:subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
    result=json.loads((stage/'data/findings/variants/metrics.json').read_text())
    metrics=[m for m in result['per_variant'] if m['firm'] in FIRMS]
    write_json(ROOT/'data/findings/variants/group2_framework_report.json',dict(command=command,per_variant=metrics,holdouts_opened=0,retained_output_root=str(stage)))
    print('Unchanged framework report receipt:',stage)


def regenerate(firms,blocked):
    from run import main as run_main, rebuild_unknown_queue
    source=read_snapshot();live,_,_=documents()
    merged={d['document_id']:d for d in source if d['row']['firm_id'] in FIRMS}
    merged.update({d['document_id']:d for d in live if d['row']['firm_id'] in FIRMS})
    docs=sorted((d for d in merged.values() if d['row']['sha256'] not in blocked),key=lambda d:(d['row']['firm_id'],d['source_file'],int(d['source_locator'].split('=')[1]),d['document_id']))
    write_jsonl(ROOT/'data/findings/variants/group2_inputs.jsonl',docs)
    stage=Path(tempfile.mkdtemp(prefix='phase4e-group2-'))
    (stage/'data/fulltext').mkdir(parents=True)
    (stage/'data/holdout').symlink_to(ROOT/'data/holdout',target_is_directory=True)
    (stage/'local-cache').symlink_to(ROOT/'local-cache',target_is_directory=True)
    (stage/'data/fulltext/extractions.jsonl').symlink_to(ROOT/'data/fulltext/extractions.jsonl')
    write_jsonl(stage/'data/fulltext/input_documents.jsonl',docs)
    previous=sys.argv
    try:
        sys.argv=['run.py','--root',str(stage),'--live-cache','--firms',*firms]
        run_main()
    finally:sys.argv=previous
    for firm in firms:
        for suffix in (firm+'.jsonl','validation/'+firm+'.jsonl','validation/'+firm+'.json'):
            dest=ROOT/'data/findings'/suffix
            tmp=dest.with_suffix(dest.suffix+'.group2.tmp')
            tmp.write_bytes((stage/'data/findings'/suffix).read_bytes());tmp.replace(dest)
    rebuild_unknown_queue(ROOT)
    print('Scoped regeneration receipt:',stage)


if __name__=='__main__':main()
