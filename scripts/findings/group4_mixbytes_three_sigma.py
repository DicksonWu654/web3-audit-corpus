"""Holdout-guarded, local-only development census for two Phase 4e publishers.

This reads every available development text for a year/template census and can
emit the same per-variant metrics as variants_report without touching shared
findings artifacts. Originals and holdouts are never opened.
"""
from collections import Counter, defaultdict
import argparse
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest, holdouts, read_snapshot, write_json, documents as fresh_documents
from core import Report, finish
from parsers import module
from run import finding_rows
from variants_report import metric

FIRMS = ('mixbytes', 'three-sigma')


def load(doc):
    sha = doc['row']['sha256']
    if sha in holdouts():
        raise ValueError('Holdout inspection denied')
    folder = ROOT / 'local-cache/fulltext'
    meta = json.loads((folder / (sha + '.pages.json')).read_text())
    text = (folder / (sha + '.txt')).read_bytes().decode('utf-8')
    if digest(text.encode()) != meta['text_sha256']:
        raise ValueError('Fulltext hash mismatch')
    return Report(text, meta | {'date_hint': doc['row'].get('date_hint')}, doc['row']['firm_id'])


def documents(firms=FIRMS, fresh=False):
    source = fresh_documents()[0] if fresh else read_snapshot()
    return sorted((d for d in source if d['row']['firm_id'] in firms),
                  key=lambda d: (d['row']['firm_id'], d['row'].get('date_hint') or '', d['row']['sha256']))


def evaluate(docs):
    diagnostics, all_rows, census = [], [], []
    for doc in docs:
        try:
            report = load(doc)
        except FileNotFoundError:
            diagnostics.append(dict(document_id=doc['document_id'], sha256=doc['row']['sha256'],
                                    firm_id=doc['row']['firm_id'], variant_id=doc['row']['firm_id']+'/extraction_failed',
                                    validation='extraction_failed', unknown_layout=False,
                                    filename=doc['row']['filename'], year=(doc['row'].get('date_hint') or 'unknown')[:4],
                                    findings=0, printed_summary=None, parsed_counts={}, ids=[], statuses={}))
            continue
        adapter = module(report.firm)
        candidates = finish(report, adapter.parse(report))
        summary = adapter.printed_counts(report)
        rows = list(finding_rows(doc, report, candidates, adapter.__name__))
        counts = Counter(row['severity'] for row in rows if row['record_kind'] == 'formal_finding')
        state = ('no_usable_printed_counts' if not summary else 'ambiguous_printed_counts' if summary.get('ambiguous') else
                 'match' if all(counts[k] == n for k, n in summary['counts'].items()) else 'mismatch')
        diag = dict(document_id=doc['document_id'], sha256=doc['row']['sha256'], firm_id=report.firm,
                    variant_id=report.layout_selection['variant_id'], validation=state,
                    unknown_layout=report.layout_selection['unknown_layout'], filename=doc['row']['filename'],
                    year=(doc['row'].get('date_hint') or 'unknown')[:4], findings=len(rows),
                    printed_summary=summary, parsed_counts=dict(counts), ids=[c.printed_id for c in candidates],
                    statuses=dict(Counter((row['status_raw'] or '<missing>') for row in rows)))
        diagnostics.append(diag)
        all_rows.extend(rows)
        fields = Counter()
        for line in report.lines:
            for label in ('Classification', 'Severity', 'Status', 'Fixed', 'Acknowledged', 'Finding ID'):
                if re.match(r'^' + label + r'\b', line.content, re.I):
                    fields[label] += 1
        census.append(dict(sha256=diag['sha256'], firm=report.firm, year=diag['year'], filename=diag['filename'],
                           pages=len(report.meta['pages']), characters=len(report.text), fields=dict(fields)))
    metrics = []
    for firm in sorted({d['firm_id'] for d in diagnostics}):
        for variant in module(firm).VARIANTS:
            ds = [d for d in diagnostics if d['variant_id'] == variant.variant_id]
            rs = [r for r in all_rows if r['variant_id'] == variant.variant_id]
            metrics.append(metric(firm, variant.variant_id, ds, rs))
        declared={variant.variant_id for variant in module(firm).VARIANTS}
        for extra in sorted({d['variant_id'] for d in diagnostics if d['firm_id']==firm}-declared):
            metrics.append(metric(firm, extra, [d for d in diagnostics if d['variant_id'] == extra],
                                  [r for r in all_rows if r['variant_id'] == extra]))
    return dict(metrics=metrics, diagnostics=diagnostics, census=census, holdouts_opened=0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firms', nargs='+', choices=FIRMS, default=FIRMS)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--inspect')
    parser.add_argument('--page', type=int)
    parser.add_argument('--match', default=r'Classification|Severity|Status|3S[- ]|[CHMLI]-\d|^\s*(?:MAJOR|COMMENTS?|WARNINGS?|NOTES?|SERIOUS|SEVERE)|Resolution|Fixed|Acknowledg|Findings|DETECTED')
    parser.add_argument('--limit', type=int, default=140)
    parser.add_argument('--study', action='store_true')
    parser.add_argument('--fresh', action='store_true', help='Read the current collection census instead of the frozen snapshot')
    args = parser.parse_args()
    docs = documents(args.firms, fresh=args.fresh)
    if args.inspect:
        for doc in docs:
            if not doc['row']['sha256'].startswith(args.inspect):
                continue
            report = load(doc)
            print('DOC', doc['row']['sha256'], doc['row'].get('date_hint'), doc['row']['filename'])
            budget = args.limit
            for page in report.meta['pages']:
                if args.page and page['page'] != args.page:
                    continue
                selected = page['text'].splitlines() if args.page else [l for l in page['text'].splitlines() if re.search(args.match, l, re.I)]
                if selected and budget > 0:
                    print('PAGE', page['page'], '\n' + '\n'.join(selected[:budget]))
                    budget -= len(selected)
        return
    result = evaluate(docs)
    if args.output:
        write_json(args.output, result)
    print(json.dumps(result['metrics'], indent=2))
    if args.study:
        by_year = defaultdict(list)
        for row in result['census']:
            by_year[(row['firm'], row['year'])].append(row)
        for key, rows in sorted(by_year.items()):
            print('YEAR', key, len(rows), 'FIELD_LAYOUTS', dict(Counter(tuple(sorted(r['fields'])) for r in rows)))
            for row in rows[:1] + rows[-1:]:
                print('EXAMPLE', json.dumps(row))


if __name__ == '__main__':
    main()
