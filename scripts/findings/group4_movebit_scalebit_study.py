"""Read-only per-era development census; deny gold hashes before any fulltext open."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, SEVERITIES, digest, documents, holdouts, read_snapshot
from core import Report, finish
from parsers import module
from run import finding_rows
from variants_report import cell, metric, sequence

FIRMS = ('movebit', 'scalebit')


def census(fresh=False):
    blocked = holdouts()
    diags, rows, receipts = [], [], []
    inputs = documents()[0] if fresh else read_snapshot()
    for doc in inputs:
        source = doc['row']
        if source['firm_id'] not in FIRMS:
            continue
        sha = source['sha256']
        if sha in blocked:
            raise ValueError('Holdout inspection denied')
        text = (ROOT / 'local-cache/fulltext' / (sha + '.txt')).read_text()
        meta = json.loads((ROOT / 'local-cache/fulltext' / (sha + '.pages.json')).read_text())
        if digest(text.encode()) != meta['text_sha256']:
            raise ValueError('Text hash mismatch: ' + sha)
        firm = source['firm_id']
        parser = module(firm)
        report = Report(text, meta | {'date_hint': source.get('date_hint')}, firm)
        candidates = finish(report, parser.parse(report))
        summary = parser.printed_counts(report)
        current = list(finding_rows(doc, report, candidates, firm.replace('-', '_')))
        counts = Counter(r['severity'] for r in current if r['record_kind'] == 'formal_finding')
        validation = ('no_usable_printed_counts' if not summary else
                      'ambiguous_printed_counts' if summary.get('ambiguous') else
                      'match' if all(counts[s] == n for s, n in summary['counts'].items()) else 'mismatch')
        diag = {'firm_id': firm, 'document_id': doc['document_id'], 'sha256': sha,
                'year': (source.get('date_hint') or '')[:4] or None,
                'validation': validation, 'printed_summary': summary,
                'parsed_counts': {s: counts[s] for s in SEVERITIES}, **report.layout_selection}
        diags.append(diag)
        rows.extend(current)
        receipts.append({'firm': firm, 'sha256': sha, 'text_characters': len(text),
                         'date_hint': source.get('date_hint'), 'filename': source['filename'],
                         'variant_id': report.layout_selection['variant_id'], 'findings': len(current),
                         'validation': validation, 'sequence': sequence(current, firm),
                         'text_dates': sorted(set(re.findall(r'\b20\d\d[-/]\d{1,2}[-/]\d{1,2}\b', text))),
                         'unreceipted_statuses': sum(r.get('status_raw') is not None and not r['evidence'].get('status_evidence') for r in current)})
    return diags, rows, receipts


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--details', action='store_true')
    p.add_argument('--fresh', action='store_true', help='Use current holdout-filtered collector metadata without modifying the frozen snapshot')
    a = p.parse_args()
    diags, rows, receipts = census(a.fresh)
    print('| Variant | Documents | Summary agreement | ID completeness | Docs with findings | Status coverage |')
    print('|---|---:|---:|---:|---:|---:|')
    for firm in FIRMS:
        variants = sorted({v.variant_id for v in module(firm).VARIANTS} |
                          {d['variant_id'] for d in diags if d['firm_id'] == firm})
        for variant in variants:
            ds = [d for d in diags if d['variant_id'] == variant]
            rs = [r for r in rows if r['variant_id'] == variant]
            m = metric(firm, variant, ds, rs)
            print('| ' + variant + ' | ' + str(m['documents']) + ' | ' +
                  ' | '.join((cell(m['summary_matching'], m['summary_comparable']),
                              cell(m['sequence_complete'], m['sequence_comparable']),
                              cell(m['documents_with_findings'], m['documents']),
                              cell(m['known_status_rows'], m['detailed_rows']))) + ' |')
    if a.details:
        for receipt in receipts:
            print(json.dumps(receipt, sort_keys=True))
        for diag in diags:
            if diag['validation'] == 'mismatch':
                print('MISMATCH', json.dumps(diag, sort_keys=True))
    print('holdouts_opened=0')


if __name__ == '__main__':
    main()
