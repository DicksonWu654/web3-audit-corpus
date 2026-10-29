"""Regenerate per-variant metrics from holdout-excluded findings and diagnostics."""
import argparse
from collections import Counter,defaultdict
from dataclasses import asdict
import json
from pathlib import Path
import re
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import ROOT,digest,holdouts,read_snapshot,write_json
from parsers import module
from variants_study import TARGETS

# Supported distinct formats already documented in Phase 4b; these wrappers
# deliberately preserve parser behavior pending formal migration.
LEGACY_ERAS={
 'code4rena':'PDF, linked Markdown, HTML and anchored Markdown (group1.md)',
 'oak-security':'Numbered severity fields and ungraded protocol reviews (group1.md)',
 'consensys-diligence':'Legacy Markdown tables, HTML headings and PDF sidebars (group1.md)',
 'abdk-consulting':'CVF cards, grouped CVF IDs and legacy section lists (group1.md)',
 'macro':'Native HTML cards and split title fragments (group1.md)',
 'spearbit':'Numbered severity fields and unnumbered cryptography reviews (group1.md)',
 'runtime-verification':'Legacy A/B/CI cards and modern Severity fields (group1.md)',
 'dedaub':'Numbered and unnumbered web detail fields (group1.md)',
 'composable-security':'Legacy and modern severity/status cards (group1.md)',
 'mixbytes':'Legacy Markdown and PDF Finding-ID cards (group2.md)',
 'blocksec':'Legacy numbered cards and modern BS-identified cards (group2.md)',
 'least-authority':'Legacy Issue headings and newer finding cards (group2.md)',
 'hexens':'HEX-prefixed and bracket-severity detail cards (group2.md)',
 'iosiro':'Numbered PDF and HTML detail headings (group2.md)',
 'three-sigma':'Severity fields and impact/likelihood matrices (group2.md)',
 'informalsystems':'Legacy IDs and later severity cards (group2.md)',
 'coinspect':'Legacy numbered findings and modern identifiers (group2.md)',
 'sec3':'Older and newer detail-card layouts (group2.md)',
 'chainlight':'Theori Issue cards, THE IDs and bilingual Orb tables (group2.md)',
 'secure3':'Identifier cards and per-contract summary layouts (group2.md)',
 'halborn':'Numbered severity sections and newer detail cards (group3.md)',
 'shieldify':'Legacy severity cards and modern severity-ID headings (group3.md)',
 'veridise':'Older VID identifiers and modern detail metadata (group3.md)',
 'ackee-blockchain':'Older and modern issue headings (group3.md)',
 'bailsec':'Numbered and ID-based finding cards (group3.md)',
 'oxorio':'Legacy and modern risk/status cards (group3.md)',
 'neodyme':'Legacy and modern finding cards (group3.md)',
 'peckshield':'Legacy PVE cards and newer numbered details (group4.md)',
 'verichains':'Legacy risk labels, numbered and modern status headings (group4.md)',
 'solidified':'Legacy Major/Minor and modern severity cards (group4.md)',
 'certora':'Legacy and modern severity/status cards (group4.md)',
 'pessimistic':'Legacy and modern finding blocks (group4.md)',
 'sigma-prime':'Legacy identifiers and modern risk cards (group4.md)',
 'decurity':'Legacy DETAILS and modern Risk Level cards (group4.md)',
 'teamomega':'Legacy unnumbered fields and scoped IDs (group4.md)',
 'movebit':'Legacy numbered findings and component IDs (group4.md)',
 'ncc-group':'Finding/Risk/Identifier and Overall Risk/Finding ID cards (group4.md)',
 'scalebit':'Legacy numbered findings and component IDs (group4.md)',
}


def sequence(rows,firm):
    groups=defaultdict(list)
    for row in rows:
        if row['record_kind']!='formal_finding':continue
        pid=row.get('publisher_finding_id') or ''
        m=re.fullmatch(r'([A-Za-z0-9_. -]{0,60}?)(\d{1,4})',pid)
        if not m:continue
        prefix=m[1].casefold();n=int(m[2])
        if not prefix and n>999:continue
        if re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}',pid):continue
        if prefix and not re.search(r'[- .]$',prefix) and not re.fullmatch(r'[A-Za-z]{1,4}',prefix):continue
        # Dotted section IDs are independent namespaces; OS namespaces start 0.
        namespace=(row.get('evidence') or {}).get('container_id') or ''
        groups[namespace+'|'+prefix if namespace else prefix].append(n)
    if not groups:return None
    gaps={};dupes={}
    for prefix,nums in groups.items():
        start=0 if prefix.startswith('os-') else 1
        absent=sorted(set(range(start,max(nums)+1))-set(nums))
        duplicate=sorted(n for n,k in Counter(nums).items() if k>1)
        if absent:gaps[prefix]=absent
        if duplicate:dupes[prefix]=duplicate
    return {'complete':not(gaps or dupes),'gaps':gaps,'duplicates':dupes,'basis':'native_id_namespace_contiguity'}


def pct(n,d):return round(100*n/d,2) if d else None

def metric(firm,variant,diags,rows):
    by_doc=defaultdict(list)
    for r in rows:by_doc[r['document_id']].append(r)
    seq=[sequence(by_doc[d['document_id']],firm) for d in diags]
    seq=[s for s in seq if s is not None]
    matched=sum(d['validation']=='match' for d in diags)
    comparable=sum(d['validation'] in {'match','mismatch'} for d in diags)
    detailed=[r for r in rows if r['record_kind']!='summary_excerpt']
    known=sum(r.get('status') not in {None,'other'} for r in detailed)
    covered=sum(bool(by_doc[d['document_id']]) for d in diags)
    return dict(firm=firm,variant_id=variant,documents=len(diags),artifacts=len({d['sha256'] for d in diags}),
                findings=len(rows),formal_findings=sum(r['record_kind']=='formal_finding' for r in rows),
                summary_matching=matched,summary_comparable=comparable,summary_agreement_percent=pct(matched,comparable),
                sequence_complete=sum(s['complete'] for s in seq),sequence_comparable=len(seq),
                id_sequence_completeness_percent=pct(sum(s['complete'] for s in seq),len(seq)),
                documents_with_findings=covered,documents_with_findings_percent=pct(covered,len(diags)),
                detailed_rows=len(detailed),known_status_rows=known,status_coverage_percent=pct(known,len(detailed)),
                raw_status_rows=sum(r.get('status_raw') is not None for r in detailed),
                validation_states=dict(Counter(d['validation'] for d in diags)))


def cell(n,d):
    percent=pct(n,d)
    return f'{n}/{d} ({percent:.2f}%)' if percent is not None else 'N/A'


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=ROOT);a=p.parse_args();root=a.root
    blocked=holdouts(root);docs=read_snapshot(root);firms=sorted({d['row']['firm_id'] for d in docs})
    metrics=[];diagnostics={};examples=[];catalog=[];all_diags=[]
    for firm in firms:
        print('metrics:',firm,flush=True)
        ds=list(map(json.loads,(root/'data/findings/validation'/(firm+'.jsonl')).read_text().splitlines()))
        rs=[]
        for line in (root/'data/findings'/(firm+'.jsonl')).open():
            r=json.loads(line)
            if r['sha256'] in blocked:raise ValueError('Holdout findings denied')
            rs.append(r)
        for d in ds:
            if d['sha256'] in blocked:raise ValueError('Holdout diagnostics denied')
        all_diags+=ds
        if any('variant_id' not in d and d['validation']!='extraction_failed' for d in ds):raise ValueError('Run every publisher through dispatcher before reporting: '+firm)
        diagnostics[firm]=ds
        variants={v.variant_id:v for v in module(firm).VARIANTS}
        used=sorted(set(variants)|{d.get('variant_id',firm+'/extraction_failed') for d in ds})
        for variant in used:
            selected=[d for d in ds if d.get('variant_id',firm+'/extraction_failed')==variant]
            selected_rows=[r for r in rs if r.get('variant_id')==variant]
            metrics.append(metric(firm,variant,selected,selected_rows))
            v=variants.get(variant)
            if v:catalog.append({'firm':firm,'variant_id':variant,'fingerprint':asdict(v.fingerprint),'fixtures':v.fixtures,'parser':v.parse.__name__,'notes':v.notes})
            # Early and late source examples from every observed year, including
            # unknown year; these are receipts, not a hand-labelled gold set.
            by_year=defaultdict(list)
            for d in selected:by_year[d.get('year') or 'unknown'].append(d)
            for year,items in sorted(by_year.items()):
                ordered=sorted(items,key=lambda d:d['sha256'])
                for d in {x['sha256']:x for x in (ordered[0],ordered[-1])}.values():
                    examples.append({k:d.get(k) for k in ('firm_id','sha256','document_id','year','variant_id','scores','validation')})
    # Keep declarations with no source occurrences visible, especially Theori.
    for firm in TARGETS:
        if firm in firms:continue
        for v in module(firm).VARIANTS:
            metrics.append(metric(firm,v.variant_id,[],[]))
            catalog.append({'firm':firm,'variant_id':v.variant_id,'fingerprint':asdict(v.fingerprint),'fixtures':v.fixtures,'parser':v.parse.__name__,'notes':v.notes})
    queue=[json.loads(l) for l in (root/'data/findings/_unknown_layouts.jsonl').open()]
    unknown=Counter(r['firm'] for r in queue)
    assert all(r['sha256'] not in blocked for r in queue)
    legacy=[f for f in firms if len(module(f).VARIANTS)==1 and module(f).VARIANTS[0].fingerprint.legacy]
    totals={'documents':len(docs),'findings':sum(m['findings'] for m in metrics),'variants':len(catalog),
            'unknown_artifact_publisher_pairs':len(queue),'unknown_occurrences':sum(len(q['document_ids']) for q in queue),
            'unknown_by_firm':dict(sorted(unknown.items())),'legacy_publishers':legacy,'holdouts_opened':0}
    targets=[]
    for firm in TARGETS:
        ms=[m for m in metrics if m['firm']==firm]
        n=sum(m['summary_matching'] for m in ms);d=sum(m['summary_comparable'] for m in ms)
        targets.append({'firm':firm,'documents':sum(m['documents'] for m in ms),'matching':n,'comparable':d,'agreement_percent':pct(n,d),'gate':'pass' if d and n/d>=.95 else 'no_comparable_documents' if not d else 'below_target'})
    firm_stats=[json.loads((root/'data/findings/validation'/(firm+'.json')).read_text()) for firm in firms]
    write_json(root/'data/findings/summary.json',{'version':'phase4a-v1','layout_framework':'phase4d-v1','by_firm':firm_stats,'findings':totals['findings'],'documents':len(docs),'holdouts_opened':0})
    result=dict(totals=totals,target_firms=targets,per_variant=metrics,catalog=catalog,legacy_multiple_eras={f:LEGACY_ERAS[f] for f in legacy if f in LEGACY_ERAS})
    write_json(root/'data/findings/variants/metrics.json',result)
    write_json(root/'data/findings/variants/development_examples.json',examples)
    lines=['# Phase 4d layout variants','',
           'Generated by `python3 -I -S scripts/findings/variants_report.py`. Frozen development snapshot; holdouts excluded before text access. No model calls or network.','',
           'Each module exposes an ordered `VARIANTS` contract (ID, fingerprint, parser, fixtures and status reader). Text signatures vote once; dates add only one hint point. Threshold is 6; best score wins, declaration order breaks ties. Date ranges describe overlapping template eras rather than asserted cutover dates. Layout eras and severity-policy eras are independent. Severity still comes exclusively from `schema/severity_map.yaml`.','',
           'Unknown layouts receive `<firm>/generic_fallback`, exact `method=generic_fallback`, a review flag, and one queue receipt per original hash/publisher with all occurrence IDs and top scores. Extraction failures are a separate denominator bucket. Legacy wrappers are explicit compatibility contracts with an unconditional score; their era validation is deferred.','',
           'Summary agreement compares formal detail rows with independently printed numeric severity totals. Cantina limits comparison to a publisher-explicit detail scope (such as high/medium-only competition reports), retaining the other contest totals and the scope quote. Zokyo records conflicts between its scoring totals and a separate complete numbered summary as ambiguous, without consulting parsed detail counts. Every retained comparable mismatch stays in the denominator; neither row counts nor summary totals select a layout. No-count/ambiguous documents are excluded only from summary comparison. ID completeness excludes opaque UUID/hash identifiers and tests native prefix/section namespaces with case-insensitive prefix matching, starting at zero for OS IDs and one otherwise; absent IDs are N/A. This structural diagnostic cannot detect an unprinted last ID or prove recall. Repeated IDs are flagged, not deduplicated. Coverage includes any emitted finding kind; status coverage is known normalized statuses / detailed rows (all kinds except summary excerpts). A missing publisher status remains null. Status tables, labelled fields, resolution responses and fix-review references carry exact-text evidence.','',
           '| Firm / variant | Documents | Summary agreement | ID sequence complete | ≥1 finding | Status coverage |',
           '|---|---:|---:|---:|---:|---:|']
    for m in metrics:
        lines.append(f"| {m['variant_id']} | {m['documents']} | {cell(m['summary_matching'],m['summary_comparable'])} | {cell(m['sequence_complete'],m['sequence_comparable'])} | {cell(m['documents_with_findings'],m['documents'])} | {cell(m['known_status_rows'],m['detailed_rows'])} |")
    lines+=['','## Target gates','', '| Firm | Documents | Agreement | Gate |','|---|---:|---:|---|']
    for target in targets:lines.append(f"| {target['firm']} | {target['documents']} | {cell(target['matching'],target['comparable'])} | {target['gate']} |")
    lines+=['','## Unknown layouts','',f"{totals['unknown_artifact_publisher_pairs']} artifact/publisher pairs; {totals['unknown_occurrences']} source occurrences. `data/findings/_unknown_layouts.jsonl` is auxiliary metadata, excluded by finding-stream consumers.",'','| Firm | Unknown artifacts |','|---|---:|']
    for f in sorted(set(firms)|set(TARGETS)):lines.append(f'| {f} | {unknown[f]} |')
    lines+=['','## Legacy publishers with multiple known layouts','',
            'These format families were documented by the earlier parser studies; formal era splitting remains pending. Links refer to the development studies in this directory.','']
    for f in legacy:
        if f in LEGACY_ERAS:lines.append(f'- `{f}/legacy`: {LEGACY_ERAS[f]}.')
    lines+=['','## Coverage limits','',
            'The frozen input snapshot contains no Theori-labelled occurrences. Its module and fixtures cover Theori/ChainLight format families, but the zero-document Theori rows are N/A, not successful validation. The authoritative severity crosswalk also has no Theori profile, so a future Theori input retains unmapped grades as unknown until that policy is reviewed. Existing ChainLight-attributed reports remain under their original collector receipts and legacy parser. Newly recovered Theori collection rows are outside this snapshot.','',
            'Hypothetical scoring tables, contradictory source summaries, missing text layers and linked-only/container entries limit agreement. Zokyo badge OCR locates white card strips separately from dark page bodies, attaches recovered risk/status text only beside a matching existing title, and preserves existing text and risk labels. OCR receipts and pre-change page caches are retained locally under `local-cache/phase4d/`; no original is changed. Summary-only Kudelski entries remain excerpts. Cantina numbered recommendations inside a formally graded container stay recommendations; explicit nested finding sections remain formal entries. Per-document scores, comparison evidence and parser errors remain in `data/findings/validation/`; sampled era/year receipts are in `data/findings/variants/development_examples.json`. Status coverage measures extraction availability, not independent accuracy.','']
    (root/'docs/phase4/variants.md').write_text('\n'.join(lines))
    print(json.dumps(totals,indent=2))
    print('TARGET VARIANTS')
    for m in metrics:
        if m['firm'] in TARGETS:print(m['variant_id'],m['documents'],cell(m['summary_matching'],m['summary_comparable']),cell(m['sequence_complete'],m['sequence_comparable']),cell(m['documents_with_findings'],m['documents']),cell(m['known_status_rows'],m['detailed_rows']))

if __name__=='__main__':main()
