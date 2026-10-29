"""Read-only local Halborn payload coverage check, excluding holdouts before reads."""
import json
from collections import Counter
from pathlib import Path
from common import ROOT, holdouts, original_path
from halborn_website import applies, extract

def main():
    blocked = holdouts(ROOT)
    stats = Counter()
    problems = []
    for row in map(json.loads, (ROOT / 'data/collect/halborn/reports.jsonl').read_text().splitlines()):
        if not applies(row) or row['sha256'] in blocked:
            continue
        text, meta = extract(original_path(row, ROOT).read_text())
        stats['pages'] += 1
        stats['findings'] += meta['finding_count']
        stats['pages_with_payload'] += bool(meta['reports'])
        stats['pages_with_findings'] += bool(meta['finding_count'])
        for report in meta['reports']:
            stats['report_type_' + str(report['reportType'])] += 1
        for finding in meta['findings']:
            stats['findings_with_description'] += finding['has_public_description']
            stats['findings_without_description'] += not finding['has_public_description']
            for key, value in finding['fields'].items():
                stats['present_' + key] += value['present']
                stats['references_' + key] += bool(value['source_reference'])
        if not meta['reports'] or meta['issues'] or meta['unresolved_references']:
            problems.append({'sha256': row['sha256'], 'issues': meta['issues'], 'unresolved': meta['unresolved_references'], 'reports': len(meta['reports'])})
    print(json.dumps({'counts': dict(stats), 'problems': problems}, indent=2))

if __name__ == '__main__':
    main()
