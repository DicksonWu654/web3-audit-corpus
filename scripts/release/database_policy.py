"""Explicit descriptive-table contract for the database edition."""
from __future__ import annotations

import csv
import io
import json

from common import EXCLUDED_AT_PUBLISHER_REQUEST, contains_excluded_url

# New tables require review here before entering the database edition.
STATS = {
    'contests_year': ('end_year,format', 'Official listing counts by contest end year and format; observed finding summaries retain their denominators.'),
    'engagements_dimensions': ('series,dimension,label,year', 'Engagement counts by language, chain family and publisher kind. Multi-tag counts use the recorded counting unit.'),
    'engagements_year': ('series,year', 'Industry identities and publisher participations by audit or publication year.'),
    'findings_by_firm': ('publisher_id', 'Selected initial finding counts, severity, recorded status and observed-stream denominators by publisher.'),
    'findings_firm_year': ('series,year,publisher_id', 'Selected initial findings by publisher and audit or publication year.'),
    'findings_overall': ('', 'Selected initial finding totals, observed-stream denominators and descriptive severity/status summaries.'),
    'findings_year': ('series,year', 'Selected initial finding counts and descriptive summaries by year.'),
    'firm_audit_types': ('publisher_id,audit_type', 'Publisher engagement counts and shares by audited scope.'),
    'firm_counts': ('publisher_id', 'Publisher engagement counts, including token-only and unclear scope counts.'),
    'firm_first_last_year': ('publisher_id', 'First and last observed audit/publication years and unknown-year counts; these describe this collection.'),
    'publisher_coverage_class': ('publisher_id', 'Collection source class and measured listing coverage. Unmeasured values remain null; text restrictions are recorded separately.'),
    'report_pages_year': ('series,year', 'Observed physical PDF page counts and descriptive summaries; pages do not measure audit effort.'),
    'review_modes_year': ('series,year,mode', 'Engagement counts by recorded review mode and year.'),
    'vulnerability_class_coverage': ('series,year', 'Counts of classified, abstained and unlabelled selected findings and their denominators.'),
    'vulnerability_class_inputs': ('classification_source', 'Classification annotation counts and receipt coverage.'),
    'vulnerability_class_shares_year': ('series,year,vulnerability_class', 'Observed vulnerability-class counts and shares with explicit classification denominators.'),
    'vulnerability_classes_year': ('series,year,vulnerability_class', 'Selected initial finding counts by vulnerability class and year.'),
    'vulnerability_leaves': ('leaf', 'Selected initial finding counts and shares by taxonomy leaf.'),
}
DROP_COLUMNS = {'firm_counts': {'rank', 'rank_excluding_token_only'},
                'vulnerability_class_inputs': {'label_routes', 'unlabelled_selected_reasons'}}
CORE_ASSETS = ('findings.parquet', 'findings.csv.gz', 'reports.csv', 'engagements.csv', 'firms.csv',
               'taxonomy.yaml', 'RIGHTS_WITHHELD.csv')
HELD_PREFIXES = ('docs/analysis/', 'data/analysis/', 'scripts/analysis/')
# The launch analysis (claims, chart CSVs and the scripts that produce them) is published with the site's Analysis page.
LAUNCH_PREFIXES = ('data/analysis/launch/', 'scripts/analysis/launch/')
LAUNCH_PRIVATE_FILES = {
    'scripts/analysis/launch/dev_judge_check.py',
    'data/analysis/launch/core_judge_inputs.csv',
    'data/analysis/launch/core_judge_comparison.csv',
    'data/analysis/launch/t26_pipeline_sources.csv',
}


def private_launch_path(name):
    return (name in LAUNCH_PRIVATE_FILES or name.startswith('data/analysis/launch/dev/')
            or (name.startswith(LAUNCH_PREFIXES) and
                (any(part.endswith('_tmp') or part == '__pycache__' for part in name.split('/'))
                 or name.endswith(('.log', '.pyc')))))


def held_path(name):
    return (private_launch_path(name) or name == 'REPORT.md'
            or (name.startswith(HELD_PREFIXES) and not name.startswith(LAUNCH_PREFIXES)))


def descriptive_csv(name, text):
    if name not in STATS:
        raise ValueError('Table outside database contract: ' + name)
    reader = csv.DictReader(io.StringIO(text))
    fields = [f for f in reader.fieldnames if f not in DROP_COLUMNS.get(name, set())]
    rows = [{key: row[key] for key in fields} for row in reader]
    for row in rows:
        if (row.get('firm_id') or row.get('publisher_id') or '').casefold() in EXCLUDED_AT_PUBLISHER_REQUEST:
            raise ValueError('Publisher-request excluded publisher')
        if any(contains_excluded_url(value) for key, value in row.items()
               if key in {'url', 'public_url', 'permalink', 'archive_url', 'source_url', 'evidence_url'}):
            raise ValueError('Publisher-request excluded URL')
        if (row.get('firm_id') or row.get('publisher_id') or '').casefold() == 'certik':
            raise ValueError('Out-of-scope publisher')
    rows.sort(key=lambda row: tuple(row[f] for f in fields))
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=fields, lineterminator='\n')
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def stats_schema(release):
    out = io.StringIO(newline='')
    writer = csv.DictWriter(out, fieldnames=['table', 'key_columns', 'columns', 'notes'], lineterminator='\n')
    writer.writeheader()
    for name, (keys, note) in sorted(STATS.items()):
        text = descriptive_csv(name, (release / 'stats' / (name + '.csv')).read_text())
        fields = next(csv.reader(io.StringIO(text)))
        writer.writerow(dict(table=name, key_columns=json.dumps(keys.split(',') if keys else [], separators=(',', ':')),
                             columns=json.dumps(fields, separators=(',', ':')), notes=note))
    return out.getvalue()
