"""Local, holdout-denied study and temporary variant metrics for group 4e.

Run with ``python3 -I -S scripts/findings/group4_abdk_sigma_prime_study.py``.
No generated release files are written; ``--out`` accepts a temporary JSON path.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest, holdouts, read_snapshot, documents
from core import Report, finish, status
from parsers import module
from run import finding_rows
from variants_report import metric, sequence

FIRMS = ('abdk-consulting', 'sigma-prime')


def load(doc):
    sha = doc['row']['sha256']
    if sha in holdouts():
        raise ValueError('Holdout inspection denied')
    path = ROOT / 'local-cache/fulltext' / sha
    meta = json.loads(path.with_suffix('.pages.json').read_text())
    text = path.with_suffix('.txt').read_text()
    if digest(text.encode()) != meta['text_sha256']:
        raise ValueError('Text hash mismatch')
    return Report(text, meta | {'date_hint': doc['row'].get('date_hint')}, doc['row']['firm_id'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--sha')
    p.add_argument('--match')
    p.add_argument('--page', type=int)
    p.add_argument('--compact', action='store_true', help='Remove PDF letter spacing for study matching/display only')
    p.add_argument('--out', type=Path)
    p.add_argument('--fresh', action='store_true', help='Use current collector metadata rather than the frozen text-input snapshot')
    a = p.parse_args()
    docs = [d for d in (documents()[0] if a.fresh else read_snapshot()) if d['row']['firm_id'] in FIRMS]
    if a.sha:
        for doc in docs:
            if not doc['row']['sha256'].startswith(a.sha):
                continue
            r = load(doc)
            print('DOCUMENT', doc['row']['sha256'], doc['row'].get('date_hint'), doc['row']['filename'])
            for page in r.meta['pages']:
                if a.page and page['page'] != a.page:
                    continue
                if a.match:
                    lines = page['text'].splitlines()
                    if a.compact:
                        lines = [re.sub(r'\s+', '', line) for line in lines]
                    selected = set()
                    for i, line in enumerate(lines):
                        if re.search(a.match, line, re.I):
                            selected.update(range(max(0, i-2), min(len(lines), i+4)))
                    if selected:
                        print('PAGE', page['page'], '\n'+'\n'.join(lines[i] for i in sorted(selected)))
                else:
                    print('PAGE', page['page'], '\n'+page['text'])
        return
    result = {'holdouts_opened': 0, 'variants': [], 'residuals': [], 'studies': []}
    grouped = defaultdict(lambda: {'diagnostics': [], 'rows': []})
    years = Counter()
    for doc in docs:
        r = load(doc)
        parser = module(r.firm)
        cs = finish(r, parser.parse(r))
        rows = list(finding_rows(doc, r, cs, parser.__name__))
        summary = parser.printed_counts(r)
        counts = Counter(row['severity'] for row in rows if row['record_kind'] == 'formal_finding')
        state = 'no_usable_printed_counts'
        if summary:
            state = 'ambiguous_printed_counts' if summary.get('ambiguous') else 'match' if all(counts[k] == v for k, v in summary['counts'].items()) else 'mismatch'
        diag = {'document_id': doc['document_id'], 'sha256': doc['row']['sha256'], 'validation': state, 'variant_id': r.layout_selection['variant_id']}
        g = grouped[(r.firm, diag['variant_id'])]
        g['diagnostics'].append(diag)
        g['rows'].extend(rows)
        seq = sequence(rows, r.firm)
        if state == 'mismatch' or (seq and not seq['complete']) or r.layout_selection['unknown_layout'] or not rows:
            result['residuals'].append(diag | {'filename': doc['row']['filename'], 'date_hint': doc['row'].get('date_hint'), 'printed_counts': summary['counts'] if summary else None, 'parsed_counts': dict(counts), 'sequence': seq, 'findings': len(rows), 'scores': r.layout_selection['scores']})
        year = (doc['row'].get('date_hint') or '')[:4] or 'unknown'
        years[(r.firm, year)] += 1
        result['studies'].append({'firm': r.firm, 'sha256': doc['row']['sha256'], 'filename': doc['row']['filename'], 'year': year, 'variant_id': diag['variant_id'], 'format': r.meta['file_format'], 'pages': len(r.meta['pages']), 'findings': len(rows), 'statuses': dict(Counter(c.status_raw for c in cs)), 'signatures': dict(r.layout_selection['scores'][0])})
    for (firm, variant), g in grouped.items():
        result['variants'].append(metric(firm, variant, g['diagnostics'], g['rows']))
    result['years'] = {firm: dict(sorted((year, n) for (f, year), n in years.items() if f == firm)) for firm in FIRMS}
    if a.out:
        a.out.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'variants': result['variants'], 'years': result['years'], 'residuals': result['residuals']}, indent=2))


if __name__ == '__main__':
    main()
