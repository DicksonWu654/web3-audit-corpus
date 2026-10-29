"""Reproduce the second recall census without opening holdout originals or text.

The frozen findings snapshot plus the prior recall census define membership.
Before/after rows count distinct (publisher, original SHA-256) pairs. Local
baselines keep source receipts; public diagnostics contain metadata and links.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
import logging
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest, holdouts, read_snapshot, write_json, write_jsonl
from streams import finding_rows, supplemental_only
from core import clean, finish
from parsers import module
from recall_push import inputs as recall_inputs, load

LOCAL = ROOT / 'local-cache/phase4-recall2'


def inputs():
    receipt = json.loads((LOCAL/'inputs.json').read_text())
    assert receipt['holdout_sha256'] == digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes())
    blocked = holdouts()
    assert not {d['row']['sha256'] for d in receipt['documents']} & blocked
    return receipt['documents']


def freeze():
    if (LOCAL/'inputs.json').exists():
        raise ValueError('Refusing to replace recall2 baseline')
    union = {d['document_id']: d for d in read_snapshot()}
    union.update({d['document_id']: d for d in recall_inputs()})
    (LOCAL/'before_policy.yaml').parent.mkdir(parents=True,exist_ok=True)
    (LOCAL/'before_policy.yaml').write_bytes((ROOT/'schema/severity_map.yaml').read_bytes())
    write_json(LOCAL/'inputs.json', dict(documents=sorted(union.values(),
        key=lambda d: (d['row']['firm_id'], d['row']['sha256'], d['document_id'])),
        holdout_sha256=digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes())))
    for p in sorted((ROOT/'scripts/findings').rglob('*.py')):
        dest = LOCAL/'before_sources'/p.relative_to(ROOT/'scripts/findings')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(p.read_bytes())
    census('before')


def census(phase,refresh=False):
    logging.getLogger('severity_resolve').setLevel(logging.ERROR)
    previous={(r['firm'],r['sha256']):r for r in map(json.loads,(LOCAL/(phase+'.jsonl')).open())} if refresh else {}
    seen=set(); rows=[]
    for d in inputs():
        firm=d['row']['firm_id']; sha=d['row']['sha256']; key=(firm,sha)
        if key in seen: continue
        seen.add(key)
        if key in previous and any(c['kind']!='summary_excerpt' for c in previous[key].get('entries',[])):
            meta=json.loads((ROOT/'local-cache/fulltext'/(sha+'.pages.json')).read_text())
            if previous[key]['text_sha256']==meta['text_sha256']:
                rows.append(previous[key]);continue
        row=dict(firm=firm,sha256=sha,filename=d['row']['filename'],public_url=d['row']['public_url'])
        try:
            r=load(d); cs=finish(r,module(firm).parse(r))
            row.update(text_sha256=r.meta['text_sha256'], variant_id=r.layout_selection['variant_id'],
                entries=[dict(start=c.start,end=c.end,id=c.printed_id,title=c.title,
                    severity_raw=c.severity_raw,severity=c.normalized,kind=c.record_kind,
                    method=c.method,confidence=c.confidence,evidence=c.evidence) for c in cs],
                issues=r.meta.get('issues',[]))
        except (FileNotFoundError, ValueError) as exc:
            row['error']=str(exc)
        rows.append(row)
        if len(rows)%500==0: print(phase,len(rows),flush=True)
    write_jsonl(LOCAL/(phase+'.jsonl'),rows)
    print(json.dumps(dict(documents=len(rows),findings=sum(len(r.get('entries',[])) for r in rows),
        errors=sum('error' in r for r in rows)),sort_keys=True))


def inspect(prefix, pattern=None):
    docs=[d for d in inputs() if d['row']['sha256'].startswith(prefix)]
    if not docs: raise ValueError('No allowed corpus match')
    d=docs[0]; r=load(d)
    print(d['row']['firm_id'],d['row']['filename'],d['row']['public_url'])
    lines=r.lines
    selected=set(range(len(lines))) if not pattern else {j for i,l in enumerate(lines)
        if re.search(pattern,l.content,re.I) for j in range(max(0,i-3), min(len(lines),i+8))}
    for i in sorted(selected):
        l=lines[i];print(f'{l.page}:{l.start}: {l.text}')


def candidates(prefix):
    d=next(d for d in inputs() if d['row']['sha256'].startswith(prefix));r=load(d)
    cs=finish(r,module(r.firm).parse(r))
    for c in cs:print(c.start,c.end,c.printed_id,repr(c.title),repr(c.severity_raw),repr(c.status_raw))


def zeros():
    diagnostics={r['document_id']: r for p in (ROOT/'data/findings/validation').glob('*.jsonl')
                 for r in map(json.loads,p.open()) if 'document_id' in r}
    for d in inputs():
        if diagnostics.get(d['document_id'],{}).get('findings',1): continue
        r=load(d)
        for p in r.meta['pages']:
            if re.search(r'(?:ID|No\.|#)\s+(?:Severity|Title|Description)|Findings? (?:Overview|Summary)|Summary of Findings',p['text'],re.I):
                print(r.firm,d['row']['sha256'][:12],d['row']['filename'],p['page'])
                print(p['text'][:3500]);break


def targets():
    seen=set()
    for d in inputs():
        firm=d['row']['firm_id']; sha=d['row']['sha256']
        if firm not in {'theori','chainlight','hats-finance'} or (firm,sha) in seen:continue
        seen.add((firm,sha));r=load(d)
        print(firm,sha[:12],d['row']['filename'])
        if firm=='hats-finance':
            for i,l in enumerate(r.lines):
                if re.match(r'^\d+\.\s',l.content): print(repr(l.text), 'preceded by', [q.content for q in r.lines[max(0,i-2):i]])
        else:
            for l in r.lines:
                if re.search(r'Minor|^(?:Issue|Recommendation)\s*#\d+\s+[^:]',l.content,re.I):print(l.page,repr(l.content))
            for q in r.meta.get('issues',[]):
                if q['kind']=='poppler_warning': print(q)


def inventories():
    from summary_inventory import inventory
    diagnostics={r['document_id']:r for p in (ROOT/'data/findings/validation').glob('*.jsonl')
                 for r in map(json.loads,p.open()) if 'document_id' in r}
    seen=set();rows=[]
    for d in inputs():
        firm=d['row']['firm_id'];sha=d['row']['sha256']
        if (firm,sha) in seen:continue
        seen.add((firm,sha))
        diag=diagnostics.get(d['document_id'],{})
        if diag.get('findings',0) and diag.get('formal_findings',0):continue
        try:r=load(d)
        except FileNotFoundError:continue
        cs=inventory(r)
        if cs:
            row=dict(firm=firm,sha256=sha,filename=d['row']['filename'],before_findings=diag.get('findings'),
                rows=[dict(id=c.printed_id,title=c.title,risk=c.severity_raw,status=c.status_raw,
                           start=c.start,end=c.end,wrapped=c.evidence['inventory_wrapped']) for c in cs])
            rows.append(row)
            print(firm,sha[:12],d['row']['filename'],len(cs),flush=True)
            for c in cs[:3]:print(c.printed_id,repr(c.title),c.severity_raw,c.status_raw,flush=True)
    write_json(LOCAL/'inventory_candidates.json',rows)


def refresh_fonts():
    from extract import extract_one
    from extraction_normalization import needs_font_mapping_retry, missing_font_mapping
    assert (LOCAL/'before.jsonl').is_file(), 'Finish the baseline before changing text'
    targets={r['sha256'] for r in map(json.loads,(LOCAL/'before.jsonl').open())
             if any(q['kind']=='poppler_warning' and missing_font_mapping(q.get('detail','')) for q in r.get('issues',[]))}
    seen=set();results=[]
    for d in inputs():
        sha=d['row']['sha256']
        if sha in seen or sha not in targets:continue
        seen.add(sha)
        try:r=load(d)
        except FileNotFoundError:continue
        if not needs_font_mapping_retry(r.meta):continue
        for suffix in ('.txt','.pages.json'):
            src=ROOT/'local-cache/fulltext'/(sha+suffix)
            dst=LOCAL/'before_text'/src.name
            dst.parent.mkdir(parents=True,exist_ok=True)
            if not dst.exists():dst.write_bytes(src.read_bytes())
        result=extract_one((sha,d['row']),ROOT,holdouts(),timeout=300,retry=True)
        results.append(result)
        print(sha,result['status'],Counter(q['kind'] for q in result.get('issues',[])),flush=True)
    write_json(LOCAL/'font_refresh.json',results)
    # Supplemental artifacts stay outside the frozen extraction ledger.
    path=ROOT/'data/fulltext/extractions.jsonl'
    old={r['sha256']:r for r in map(json.loads,path.open())}
    for r in results:
        if r['sha256'] in old:old[r['sha256']]=r
    write_jsonl(path,[old[k] for k in sorted(old)])


def minor_policy():
    d=next(d for d in inputs() if d['row']['firm_id']=='theori' and d['row']['sha256'].startswith('e09814e92ebc'))
    r=load(d);page=next(p for p in r.meta['pages'] if 'Use only approved relayers' in p['text'] and 'Minor' in p['text'])
    path=ROOT/'schema/severity_map.yaml';policy=json.loads((LOCAL/'before_policy.yaml').read_text())
    era=policy['publishers']['theori']['eras'][0]
    era['labels']['Minor']=dict(normalized='low',rationale='Theori grades both code-quality and security recommendations Minor, below Medium in its published recommendation inventory. Group this native minor tier as low; this is an editorial grouping, not a universal alias. See the BiFi recommendation inventory evidence.')
    proof=dict(sha256=d['row']['sha256'],page=page['page'],page_basis='pdf_page',
        public_url=d['row']['public_url'],kind='scale_or_example',quote=page['text'],accessed_utc='2026-10-21',
        interpretation='Minor is grouped as low, while the explicitly printed Medium tier remains medium. The source is a graded inventory, not a complete severity definition.')
    if proof not in era['evidence']:era['evidence'].append(proof)
    path.write_text(json.dumps(policy,ensure_ascii=False,indent=2)+'\n')
    exported=ROOT/'schema/severity_map.json'
    # Preserve the external export's existing key order as well.
    external=json.loads(exported.read_text())
    external['publishers']['theori']['eras'][0]['labels']['Minor']=era['labels']['Minor']
    external['publishers']['theori']['eras'][0]['evidence']=era['evidence']
    exported.write_text(json.dumps(external,ensure_ascii=False,indent=2)+'\n')
    assert external==policy


def regenerate(selected=None):
    from run import main as run_main, finding_rows
    from unittest.mock import patch
    with patch.object(sys,'argv',['run.py']+(['--firms',*selected] if selected else [])):run_main()
    frozen={d['document_id'] for d in read_snapshot()}
    firms=sorted({d['row']['firm_id'] for d in inputs() if d['document_id'] not in frozen})
    path=ROOT/'data/findings/validation/recall_push_supplemental.json'
    stats={s['firm_id']:s for s in json.loads(path.read_text())['by_firm']} if path.exists() else {}
    for firm in firms:
        if selected and firm not in selected:continue
        rows=[];ids=[]
        for d in inputs():
            if d['document_id'] in frozen or d['row']['firm_id']!=firm:continue
            r=load(d);cs=finish(r,module(firm).parse(r))
            rows.extend(finding_rows(d,r,cs,firm.replace('-','_')));ids.append(d['document_id'])
        rows=supplemental_only(rows,ROOT/'data/findings',firm)
        write_jsonl(ROOT/'data/findings/supplemental'/(firm+'.jsonl'),rows)
        stats[firm]=dict(firm_id=firm,documents=len(ids),findings=len(rows),document_ids=ids)
        print('supplemental',firm,len(ids),len(rows),flush=True)
    write_json(path,dict(by_firm=[stats[k] for k in sorted(stats)],holdouts_opened=0,
        note='Later collector occurrences; separate from the unchanged frozen extraction snapshot.'))
    if selected:
        stats=[json.loads(p.read_text()) for p in sorted((ROOT/'data/findings/validation').glob('*.json'))
               if p.stem in {d['row']['firm_id'] for d in read_snapshot()}]
        summary=json.loads((ROOT/'data/findings/summary.json').read_text())
        summary.update(by_firm=stats,findings=sum(r['findings'] for r in stats),documents=sum(r['documents'] for r in stats))
        write_json(ROOT/'data/findings/summary.json',summary)


def verify_census():
    representatives={}
    for d in inputs():representatives.setdefault((d['row']['firm_id'],d['row']['sha256']),d['document_id'])
    ids=set(representatives.values());actual={}
    for path, row in finding_rows(ROOT/'data/findings'):
        if row['document_id'] not in ids:continue
        key=(row['firm_id'],row['sha256'])
        actual.setdefault(key,[]).append((row['publisher_finding_id'],row['title'],row['severity_raw'],row['record_kind'],
            row['body_span']['start'],row['body_span']['end'],row['body_span']['text_sha256']))
    differences=[]
    for r in map(json.loads,(LOCAL/'after.jsonl').open()):
        key=(r['firm'],r['sha256'])
        expected=[(c['id'],clean(c['title']) if c['title'] else None,c['severity_raw'],c['kind'],c['start'],c['end'],r['text_sha256']) for c in r.get('entries',[])]
        if expected!=actual.get(key,[]):differences.append(dict(firm=key[0],sha256=key[1],expected=len(expected),actual=len(actual.get(key,[]))))
    result=dict(ok=not differences,differences=differences,holdouts_opened=0)
    write_json(LOCAL/'census_check.json',result)
    print(json.dumps(result,indent=2))
    if differences:raise ValueError('Census/generated findings differ')


def manifest():
    names=('check.py','extract.py','extraction_normalization.py','run.py','variants.py',
           'summary_inventory.py','recall2.py','test_recall2.py','test_variants.py',
           'parsers/chainlight.py','parsers/theori.py','parsers/zokyo.py','parsers/hats_finance.py',
           'parsers/chainlight_secure3_test.py')
    paths={ROOT/'scripts/findings'/n for n in names}
    paths.update(ROOT/p for p in ('schema/severity_map.yaml','schema/severity_map.json',
        'docs/phase4/recall2.md','docs/phase4/recall2_files_written.txt',
        'data/findings/summary.json','data/findings/check.json','data/findings/_unknown_layouts.jsonl',
        'data/findings/validation/recall2.json','data/findings/validation/group2_tests.json','data/findings/validation/recall_push_supplemental.json',
        'data/findings/severity_canon/cache_sync.json',
        'data/fulltext/extractions.jsonl','data/fulltext/failures.jsonl','data/fulltext/summary.json'))
    for firm in sorted({d['row']['firm_id'] for d in read_snapshot()}):
        paths.update(ROOT/'data/findings'/p for p in (firm+'.jsonl','validation/'+firm+'.jsonl','validation/'+firm+'.json'))
    paths.update((ROOT/'data/findings/supplemental').glob('*.jsonl'))
    paths.update(p for p in LOCAL.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    for p in (LOCAL/'before_text').glob('*.txt'):
        paths.update(ROOT/'local-cache/fulltext'/(p.stem+s) for s in ('.txt','.pages.json'))
        q=ROOT/'local-cache/fulltext/normalization'/(p.stem+'.json')
        if q.exists():paths.add(q)
    audit=ROOT/'local-cache/findings-integration'
    paths.update(p for p in audit.glob('tests*') if p.is_file())
    path=ROOT/'docs/phase4/recall2_files_written.txt'
    path.write_text('Persistent task files, including ignored data and local baselines. Temporary logs and bytecode are omitted.\n\n'+
                    '\n'.join(sorted(str(p.relative_to(ROOT)) for p in paths))+'\n')


def font_status():
    from extraction_normalization import missing_font_mapping
    rows=[r for r in map(json.loads,(LOCAL/'before.jsonl').open())
          if any(q['kind']=='poppler_warning' and missing_font_mapping(q.get('detail','')) for q in r.get('issues',[]))]
    print('Affected publisher/artifact pairs:',len(rows),dict(Counter(r['firm'] for r in rows)))
    seen=set()
    for d in rows:
        sha=d['sha256']
        if sha in seen:continue
        seen.add(sha)
        path=ROOT/'local-cache/fulltext'/(sha+'.pages.json')
        if not path.exists():continue
        meta=json.loads(path.read_text())
        if any(q['kind']=='missing_font_mapping' for q in meta.get('issues',[])):
            print(d['firm'],sha,meta['status'])
            print([q for q in meta['issues'] if q['kind']=='ocr_failed'])
        else:print(d['firm'],sha,'pending',meta['page_count'],'pages')


def report_result():
    from extraction_normalization import missing_font_mapping
    from parsers.zokyo import _summary_pages, RISK, STATUS, _text
    before={(r['firm'],r['sha256']):r for r in map(json.loads,(LOCAL/'before.jsonl').open())}
    after={(r['firm'],r['sha256']):r for r in map(json.loads,(LOCAL/'after.jsonl').open())}
    assert before.keys()==after.keys()
    firms=sorted({k[0] for k in before});inventory_counts={f:Counter() for f in firms}
    changes=[];badge_docs=[];font_docs=[];colon_docs=[];minor_docs=[];hats_docs=[];ocr=Counter()
    docs={(d['row']['firm_id'],d['row']['sha256']):d for d in inputs()}
    for key,b in before.items():
        a=after[key];f,sha=key;old=b.get('entries',[]);new=a.get('entries',[])
        excerpts=[c for c in new if c['method']=='summary_inventory']
        if excerpts:
            n=inventory_counts[f];n['documents']+=1;n['zero_before']+=not old
            n['before_rows']+=len(old);n['after_rows']+=len(excerpts)
            wrapped=[c for c in excerpts if c['evidence']['inventory_wrapped']]
            n['wrapped_documents']+=bool(wrapped);n['wrapped_rows']+=len(wrapped)
            old_titles={(c['id'],c['title']) for c in old}
            n['wrapped_titles_before']+=sum((c['id'],c['title']) in old_titles for c in wrapped)
        signature=lambda cs:[(c['id'],c['title'],c['severity_raw'],c['kind'],c['method']) for c in cs]
        if signature(old)!=signature(new):
            changes.append(dict(firm=f,sha256=sha,public_url=a['public_url'],filename=a['filename'],
                before=len(old),after=len(new),before_kinds=dict(Counter(c['kind'] for c in old)),
                after_kinds=dict(Counter(c['kind'] for c in new)),summary_inventory=bool(excerpts)))
        bi=b.get('issues',[]);ai=a.get('issues',[])
        if any(q['kind']=='ocr_page' for q in ai):ocr[f]+=1
        if any(q['kind']=='poppler_warning' and missing_font_mapping(q.get('detail','')) for q in bi):
            font_docs.append(dict(firm=f,sha256=sha,public_url=a['public_url'],
                before_ocr_pages=sorted({q['page'] for q in bi if q['kind']=='ocr_page'}),
                mapping_pages=sorted({q['page'] for q in ai if q['kind']=='missing_font_mapping'}),
                forced_ocr_pages=sorted({q['page'] for q in ai if q['kind']=='ocr_page' and q.get('reason')=='missing_font_mapping'}),
                failures=[q for q in ai if q['kind']=='ocr_failed'],before_findings=len(old),after_findings=len(new)))
        if f not in {'zokyo','theori','chainlight','hats-finance'} or a.get('error'):continue
        r=load(docs[key])
        if f=='zokyo':
            # Reproduce the original page heuristic against the same text.
            legacy=set();active=False
            for p in r.meta['pages']:
                t=_text(p['text']);lines=t.splitlines()
                h=bool(re.search(r'Findings?\s+summary',t,re.I))
                row=any(len(l)<600 and re.match(r'^\s*\d+\s+',l) and re.search(RISK+r'\s+'+STATUS+r'\s*$',l,re.I) for l in lines)
                col=bool(re.search(r'^\s*Risk\s+Status\s*$|^\s*(?:Title\s+)?Risk\s*$',t,re.I|re.M) and (re.search(r'^\s*Status\s*$',t,re.I|re.M) or len(re.findall(r'^\s*\d+\s+\S',t,re.M))>=3))
                sep=sum(bool(re.fullmatch(RISK,l.strip(),re.I)) for l in lines)>=3 and sum(bool(re.fullmatch(STATUS,l.strip(),re.I)) for l in lines)>=3
                if h or active and (row or col or sep):legacy.add(p['page']);active=True
                else:active=False
            removed=sorted(legacy-_summary_pages(r))
            if removed:badge_docs.append(dict(firm=f,sha256=sha,public_url=a['public_url'],pages=removed,
                before_findings=len(old),after_findings=len(new),
                gained_cards=sum(c['start'] not in {q['start'] for q in old} and c['kind']!='summary_excerpt' for c in new)))
        elif f in {'theori','chainlight'}:
            headings=[l for l in r.lines if re.match(r'^(?:Issue|Recommendation)\s*#\d+\s+[^:\s]',l.content,re.I)
                      and not re.search(r'(?:\.\s*){4,}|\s{3,}\d+\s*$',l.text)]
            if headings:colon_docs.append(dict(firm=f,sha256=sha,public_url=a['public_url'],headings=len(headings),
                before=sum(any(c['start']==l.start for c in old) for l in headings),
                after=sum(any(c['start']==l.start for c in new) for l in headings)))
            if any(re.search(r'\s{2,}Minor\s*$',l.text) for l in r.lines):
                minor_docs.append(dict(firm=f,sha256=sha,public_url=a['public_url'],
                    before=sum((c['severity_raw'] or '').casefold()=='minor' for c in old),
                    after=sum((c['severity_raw'] or '').casefold()=='minor' for c in new)))
        elif f=='hats-finance' and re.search(r'Attack Scenario|two main weaknesses',r.text,re.I):
            hats_docs.append(dict(firm=f,sha256=sha,public_url=a['public_url'],
                before=sum(bool(re.match(r'(?:Alice|Bob|Carol|Permission Oversight|Flawed Access Control)',c['title'])) for c in old),
                after=sum(bool(re.match(r'(?:Alice|Bob|Carol|Permission Oversight|Flawed Access Control)',c['title'])) for c in new)))
    metrics=dict(documents=len(before),before_findings=sum(len(r.get('entries',[])) for r in before.values()),
        after_findings=sum(len(r.get('entries',[])) for r in after.values()),
        before_errors=sum('error' in r for r in before.values()),after_errors=sum('error' in r for r in after.values()),
        changed_documents=len(changes),inventory_by_publisher={f:dict(c) for f,c in inventory_counts.items()},
        inventory_totals=dict(sum(inventory_counts.values(),Counter())),font_documents=font_docs,
        colonless_documents=colon_docs,minor_inventory_documents=minor_docs,badge_documents=badge_docs,
        hats_narrative_documents=hats_docs,ocr_documents_by_publisher=dict(sorted(ocr.items())),holdouts_opened=0,
        inputs_sha256=digest((LOCAL/'inputs.json').read_bytes()),
        before_sha256=digest((LOCAL/'before.jsonl').read_bytes()),after_sha256=digest((LOCAL/'after.jsonl').read_bytes()),
        changes=changes)
    write_json(ROOT/'data/findings/validation/recall2.json',metrics)
    n=metrics['inventory_totals'];before_font=sum(len(d['before_ocr_pages']) for d in font_docs)
    pages=sum(len(d['mapping_pages']) for d in font_docs);forced=sum(len(d['forced_ocr_pages']) for d in font_docs)
    lines=['# Phase 4 recall pass 2','',
        'Generated by `python3 -I scripts/findings/recall2.py report`. No model calls or network. Holdout hashes are filtered before text/original access; the holdout list and input membership are unchanged.','',
        f"The census covers **{len(before):,} distinct publisher/original pairs**, using the frozen findings snapshot plus the previous recall census. Alias occurrences do not inflate these counts. Findings: **{metrics['before_findings']:,} → {metrics['after_findings']:,}**; documents with changed rows: **{len(changes):,}**. Unavailable text artifacts remain **{metrics['before_errors']} → {metrics['after_errors']}**. Later collector occurrences retain their separate `data/findings/supplemental/` streams.",'',
        '## Per-class results','',
        '| Class / corpus measure | Before | After |','|---|---:|---:|',
        f"| Inventory-bearing documents with zero emitted rows | {n.get('zero_before',0)} | 0 |",
        f"| Inventory excerpt rows in the affected documents | {n.get('before_rows',0)} | {n.get('after_rows',0)} |",
        f"| Exact joined titles for wrapped inventory rows ({n.get('wrapped_documents',0)} documents) | {n.get('wrapped_titles_before',0)} | {n.get('wrapped_rows',0)} |",
        f"| Colonless Theori/ChainLight detail headings emitted ({len(colon_docs)} documents) | {sum(d['before'] for d in colon_docs)} | {sum(d['after'] for d in colon_docs)} |",
        f"| Theori Minor vocabulary entries | 0 | 1 |",
        f"| Missing-font documents with page-local OCR diagnostics | 0 | {len(font_docs)} |",
        f"| Missing-font pages explicitly sent through OCR | 0 | {forced}/{pages} |",
        f"| Zokyo pages incorrectly excluded by the old continuation heuristic ({len(badge_docs)} documents) | {sum(len(d['pages']) for d in badge_docs)} | 0 |",
        f"| Narrative steps emitted as Hats findings ({len(hats_docs)} source examples) | {sum(d['before'] for d in hats_docs)} | {sum(d['after'] for d in hats_docs)} |",'',
        'The heading and Hats counts describe observed corpus instances. Where the corpus already had a protective layout/indentation or no colonless heading, format-derived regressions exercise the failure independently; zero corpus impact is not a claim of held-out validation. Minor is cited to the non-holdout BiFi recommendation inventory (PDF page 17), explicitly marked a scale example rather than a complete severity definition. Recommendation kinds remain separate from graded findings.','',
        f'Before this pass, {before_font} pages in the missing-font documents had ordinary sparse-page OCR. The new trigger uses page-specific Poppler diagnostics, regardless of surviving text density. OCR output and prior text receipts are kept locally. Remaining OCR failures: {sum(len(d["failures"]) for d in font_docs)}.','',
        '## Inventory fallback by publisher','',
        'Each row counts distinct publisher/original pairs using the fallback. Publishers with no affected documents are retained. Excerpts use exact `method=summary_inventory`, `record_kind=summary_excerpt`, confidence 0.55, source-native IDs/grades/statuses, and exact row spans. Partial detail extraction is never supplemented from inventories; printed aggregate totals never create rows. Prior-audit retests and externally attributed client archives retain their existing exclusions.','',
        '| Publisher | Documents | Zero rows before | Rows before → after | Wrapped documents / rows |',
        '|---|---:|---:|---:|---:|']
    for f in firms:
        c=inventory_counts[f]
        lines.append(f"| {f} | {c['documents']} | {c['zero_before']} | {c['before_rows']} → {c['after_rows']} | {c['wrapped_documents']} / {c['wrapped_rows']} |")
    lines+=['','## Evidence and reproduction','',
        'Per-document before/after counts, links, OCR diagnostics, page exclusions and publisher totals are in `data/findings/validation/recall2.json`. The local immutable baseline and its source files are in `local-cache/phase4-recall2/`; changed text is archived in `before_text/`.','',
        'Reproduce on the frozen census with `recall2.py after`, `recall2.py regenerate`, and `recall2.py report`. The original baseline was captured by `recall2.py freeze` before parser changes. `recall2.py refresh-fonts` retries source-diagnosed missing-font pages; it never refreshes input membership.','',
        'Useful source examples:','']
    sample_prefixes=('1f1529cafb53','4ac2a5c1cc43','3b8840d82c2c','02b6cbc53e62','d4d38e84670e')
    for prefix in sample_prefixes:
        a=next(r for r in after.values() if r['sha256'].startswith(prefix))
        lines.append(f"- [{a['firm']}: {a['filename']}]({a['public_url']}) — `{a['sha256']}`.")
    tests_path=LOCAL/'tests.json';check_path=ROOT/'data/findings/check.json'
    if tests_path.exists():
        t=json.loads(tests_path.read_text());lines+=['',f"Full repository tests: {t['totals']}. All groups passed: {t['ok']}."]
    if check_path.exists():
        c=json.loads(check_path.read_text());lines+=['',f"`scripts/findings/check.py`: ok={c['ok']}; {c['documents']:,} occurrences, {c['findings']:,} findings; holdout rows found={c['holdout_rows_found']}."]
    (ROOT/'docs/phase4/recall2.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({k:v for k,v in metrics.items() if k not in {'changes','inventory_by_publisher'}},indent=2))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('action',choices=('freeze','before','after','refresh-census','inspect','candidates','zeros','targets','inventories','refresh-fonts','minor-policy','regenerate','verify-census','font-status','report','manifest'))
    p.add_argument('prefix',nargs='?');p.add_argument('--match')
    p.add_argument('--firms',nargs='+')
    a=p.parse_args()
    if a.action=='freeze': freeze()
    elif a.action in ('before','after'):census(a.action)
    elif a.action=='refresh-census':census('after',refresh=True)
    elif a.action=='inspect':inspect(a.prefix,a.match)
    elif a.action=='candidates':candidates(a.prefix)
    elif a.action=='zeros':zeros()
    elif a.action=='targets':targets()
    elif a.action=='inventories':inventories()
    elif a.action=='refresh-fonts':refresh_fonts()
    elif a.action=='minor-policy':minor_policy()
    elif a.action=='regenerate':regenerate(a.firms)
    elif a.action=='verify-census':verify_census()
    elif a.action=='manifest':manifest()
    elif a.action=='font-status':font_status()
    elif a.action=='report':report_result()


if __name__=='__main__':main()
