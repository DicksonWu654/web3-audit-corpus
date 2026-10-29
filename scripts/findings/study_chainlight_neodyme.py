"""Guarded full-census study and existing per-variant metrics for Phase 4e.

Print JSON without changing shared outputs. --live evaluates current parsers;
default reads the regenerated per-firm outputs. Every text access is downstream
of common.read_snapshot's holdout exclusion. No original or network is opened.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, SEVERITIES, digest, holdouts, read_snapshot
from core import Report, finish
from parsers import module
from run import finding_rows
from variants_report import metric

FIRMS = ('chainlight', 'neodyme')


def live_study():
    docs = [d for d in read_snapshot() if d['row']['firm_id'] in FIRMS]
    blocked = holdouts()
    diagnostics = []
    rows = []
    manifest = []
    for d in docs:
        row = d['row']
        firm, sha = row['firm_id'], row['sha256']
        assert sha not in blocked
        base = ROOT / 'local-cache/fulltext'
        meta = json.loads((base / (sha + '.pages.json')).read_text())
        text = (base / (sha + '.txt')).read_bytes().decode()
        assert digest(text.encode()) == meta['text_sha256']
        report = Report(text, meta | {'date_hint': row.get('date_hint')}, firm)
        parser = module(firm)
        candidates = finish(report, parser.parse(report))
        summary = parser.printed_counts(report)
        found = list(finding_rows(d, report, candidates, firm))
        for r in found:
            if not r.get('status_raw'):
                continue
            proof = r['evidence']['status_evidence']
            assert text[proof['start']:proof['end']] == proof['text'] == r['status_raw']
        parsed = Counter(r['severity'] for r in found if r['record_kind'] == 'formal_finding')
        validation = ('no_usable_printed_counts' if not summary else
                      'ambiguous_printed_counts' if summary.get('ambiguous') else
                      'match' if all(parsed[s] == n for s, n in summary['counts'].items()) else 'mismatch')
        diag = dict(document_id=d['document_id'], sha256=sha, firm_id=firm,
                    year=(row.get('date_hint') or '')[:4] or None,
                    findings=len(found), validation=validation,
                    parsed_counts={s: parsed[s] for s in SEVERITIES}, printed_summary=summary,
                    **report.layout_selection)
        diagnostics.append(diag)
        rows += found
        manifest.append(dict(firm=firm, sha256=sha, filename=row.get('filename'),
                             year=diag['year'],
                             copyright_years=sorted(set(re.findall(r'©\s*(20\d{2})', text))),
                             variant=report.layout_selection['variant_id'],
                             status_rows=sum(bool(r.get('status_raw')) for r in found),
                             finding_rows=len(found), validation=validation,
                             unknown_layout=report.layout_selection['unknown_layout'],
                             unmatched_status_ids=[r.get('publisher_finding_id') for r in found if not r.get('status_raw')]))
    return diagnostics, rows, manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--live', action='store_true')
    a = p.parse_args()
    if a.live:
        diagnostics, rows, manifest = live_study()
    else:
        diagnostics, rows, manifest = [], [], []
        blocked = holdouts()
        for firm in FIRMS:
            ds = [json.loads(l) for l in (ROOT / 'data/findings/validation' / (firm + '.jsonl')).read_text().splitlines()]
            rs = [json.loads(l) for l in (ROOT / 'data/findings' / (firm + '.jsonl')).read_text().splitlines()]
            assert all(r['sha256'] not in blocked for r in ds + rs)
            diagnostics += ds
            rows += rs
    metrics = []
    for firm in FIRMS:
        variants = sorted({v.variant_id for v in module(firm).VARIANTS} |
                          {d['variant_id'] for d in diagnostics if d['firm_id'] == firm})
        for variant in variants:
            metrics.append(metric(firm, variant,
                                  [d for d in diagnostics if d['firm_id'] == firm and d['variant_id'] == variant],
                                  [r for r in rows if r['firm_id'] == firm and r['variant_id'] == variant]))
    result = dict(per_variant=metrics, manifest=manifest, holdouts_opened=0,
                  unknown_layouts=[dict(firm=d['firm_id'], sha256=d['sha256']) for d in diagnostics if d.get('unknown_layout')])
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
