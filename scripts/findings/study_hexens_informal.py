"""Holdout-safe era inspection and reproducible metrics for Phase 4e group 1."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, read_snapshot
from variants_study import load
from variants_report import metric, cell

FIRMS = ('hexens', 'informalsystems')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sha')
    p.add_argument('--year')
    p.add_argument('--metrics', action='store_true')
    p.add_argument('--page', type=int)
    p.add_argument('--cards', action='store_true')
    p.add_argument('--all', action='store_true')
    p.add_argument('--head', type=int)
    p.add_argument('--grep')
    p.add_argument('--firm', choices=FIRMS)
    p.add_argument('--unknown', action='store_true')
    p.add_argument('--missing-status', action='store_true')
    p.add_argument('--verify', action='store_true')
    a = p.parse_args()
    docs = [d for d in read_snapshot() if d['row']['firm_id'] in FIRMS and (not a.firm or d['row']['firm_id']==a.firm)]
    if a.verify:
        permitted={d['row']['sha256']:d for d in docs};cache={};counts=Counter()
        for firm in FIRMS:
            if a.firm and a.firm!=firm:continue
            for line in (ROOT/'data/findings'/f'{firm}.jsonl').open():
                row=json.loads(line);sha=row['sha256'];assert sha in permitted
                if sha not in cache:cache[sha]=load(permitted[sha])[0]
                text=cache[sha];span=row['body_span']
                assert text[span['start']:span['end']]==row['body_text']
                counts['finding_rows']+=1
                if row['status_raw'] is not None:
                    s=row['evidence']['status_evidence']
                    assert text[s['start']:s['end']]==s['text']==s['raw']==row['status_raw']
                    counts['status_spans']+=1
        queue=[json.loads(l) for l in (ROOT/'data/findings/_unknown_layouts.jsonl').open()]
        counts['unknown_layouts']=sum(r['firm'] in FIRMS for r in queue)
        assert counts['unknown_layouts']==0
        print('VERIFIED',json.dumps(dict(counts),sort_keys=True));return
    if a.metrics:
        for firm in FIRMS:
            ds = [json.loads(l) for l in (ROOT/'data/findings/validation'/f'{firm}.jsonl').read_text().splitlines()]
            rs = [json.loads(l) for l in (ROOT/'data/findings'/f'{firm}.jsonl').open()]
            permitted = {d['row']['sha256'] for d in docs if d['row']['firm_id'] == firm}
            assert all(r['sha256'] in permitted for r in ds + rs)
            from parsers import module
            for variant in sorted({v.variant_id for v in module(firm).VARIANTS} | {d.get('variant_id',firm+'/extraction_failed') for d in ds}):
                m = metric(firm, variant, [d for d in ds if d.get('variant_id',firm+'/extraction_failed') == variant], [r for r in rs if r.get('variant_id') == variant])
                print('|', variant, '|', m['documents'], '|', cell(m['summary_matching'],m['summary_comparable']), '|', cell(m['sequence_complete'],m['sequence_comparable']), '|', cell(m['documents_with_findings'],m['documents']), '|', cell(m['known_status_rows'],m['detailed_rows']), '|')
            bad = [d for d in ds if d.get('unknown_layout') or d['validation'] in {'mismatch','parser_error'}]
            print('RESIDUALS', firm, json.dumps([{k:d.get(k) for k in ('sha256','variant_id','validation','parsed_counts','printed_summary')} for d in bad]))
        return
    grouped = defaultdict(list)
    for d in docs: grouped[(d['row']['firm_id'], (d['row'].get('date_hint') or 'unknown')[:4])].append(d)
    for (firm, year), items in sorted(grouped.items()):
        if a.year and year != a.year: continue
        ordered = sorted(items, key=lambda d:d['row']['sha256'])
        selected = [d for d in ordered if d['row']['sha256'].startswith(a.sha)] if a.sha else ordered if a.all else [ordered[0],ordered[-1]] if len(items)>1 else ordered
        if selected:print('YEAR', firm, year, 'documents', len(items))
        for d in selected:
            text, meta = load(d)
            if a.unknown:
                from core import Report
                from parsers import module
                report = Report(text, meta | {'date_hint': d['row'].get('date_hint')}, firm)
                module(firm).parse(report)
                if not report.layout_selection['unknown_layout']:continue
            print('DOC', d['row']['sha256'], d['row'].get('date_hint'), d['row']['filename'])
            if a.grep:
                print('\n'.join(f'{i+1}: {l}' for i,l in enumerate(text.splitlines()) if re.search(a.grep,l,re.I)))
            elif a.head:
                print(text[:a.head])
            elif a.page:
                for page in meta['pages']:
                    if page['page'] == a.page:print(page['text'])
            else:
                from core import Report
                from parsers import module
                report = Report(text, meta | {'date_hint': d['row'].get('date_hint')}, firm)
                cs = module(firm).parse(report)
                print('VARIANT', report.layout_selection['variant_id'], 'CARDS', len(cs))
                if a.missing_status:
                    for c in cs:
                        if c.status_raw:continue
                        body=text[c.start:c.end]
                        matches=list(re.finditer(r'(?im)^\s*(?:Status(?: Update)?|Resolution|Fix Review)\b[^\n]*',body))
                        if matches:
                            print('MISSING STATUS',c.printed_id,repr(c.title))
                            for m in matches:print(repr(body[m.start():m.end()+250]))
                    continue
                for c in (cs if a.cards else cs[:1]):
                    print('CARD', c.printed_id, repr(c.title), repr(c.severity_raw), repr(c.status_raw), 'PAGE', next((p['page'] for p in meta['pages'] if p['start']<=c.start<p['end']), None))
                    print(text[c.start:min(c.end,c.start+1100)])
                if not cs:
                    print('SIGNATURES', '\n'.join(l for l in text.splitlines() if re.search(r'Finding|Report|Severity|Review|Issue',l,re.I))[:1500])

if __name__ == '__main__':main()
