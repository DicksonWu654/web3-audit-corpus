#!/usr/bin/env python3
"""Prepare database-edition assets from an existing release without changing it."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_formats import build, csv_rows, zip_write
from database_policy import CORE_ASSETS, STATS, descriptive_csv, stats_schema
import common as C

EXPECTED = dict(publishers=63, industry_engagements=12767, reports=13522, projects=11027,
                findings=175640, full_text=160239, first_audit_year=2015, last_audit_year=2026)


def headline(release):
    import duckdb
    firms = csv_rows(release / 'firms.csv')
    engagements = csv_rows(release / 'engagements.csv')
    reports = csv_rows(release / 'reports.csv')
    years = [int(r['audit_year']) for r in engagements if r['audit_year']]
    for rows in (firms, engagements, reports):
        if any(C.is_excluded_publisher(r.get('firm_id')) for r in rows):
            raise ValueError('Publisher-request excluded publisher in release')
        if any(C.contains_excluded_url(r) for r in rows):
            raise ValueError('Publisher-request excluded URL in release')
        if any(r.get('firm_id','').casefold() == 'certik' for r in rows):
            raise ValueError('Out-of-scope publisher in release')
    con = duckdb.connect(config={'threads': 2, 'memory_limit': '512MB'})
    try:
        findings, present, certik = con.execute("SELECT count(*), count(*) FILTER (WHERE body_text_status = 'present' "
            "AND coalesce(text_withheld, '') = '' AND length(body_text) > 0), "
            "count(*) FILTER (WHERE lower(firm_id) = 'certik') FROM read_parquet(?)",
            [str(release / 'findings.parquet')]).fetchone()
        excluded_rows = con.execute("SELECT count(*) FROM read_parquet(?) WHERE lower(firm_id) IN (SELECT unnest(?))",
                                    [str(release / 'findings.parquet'), sorted(C.EXCLUDED_AT_PUBLISHER_REQUEST)]).fetchone()[0]
    finally:
        con.close()
    if certik:
        raise ValueError('Out-of-scope finding rows')
    if excluded_rows:
        raise ValueError('Publisher-request excluded finding rows')
    # Distinct nonempty released project strings; identities are not fuzzy merged.
    result = dict(publishers=len(firms), industry_engagements=len({r['industry_engagement_id'] for r in engagements}),
                  publisher_engagements=len(engagements), reports=len(reports),
                  projects=len({r['project'] for r in engagements if r['project']}), findings=findings,
                  full_text=present, first_audit_year=min(years), last_audit_year=max(years),
                  certik_rows=certik, excluded_publisher_rows=excluded_rows)
    return result


def build_candidate(release, out, root=ROOT):
    release, out = release.resolve(), out.resolve()
    if release == out or release in out.parents or out in release.parents:
        raise ValueError('Candidate must be separate from the source release')
    if out.exists() and any(out.iterdir()):
        raise ValueError('Use an empty candidate directory')
    counts = headline(release)
    mismatches = {key: dict(expected=value, actual=counts[key]) for key, value in EXPECTED.items() if counts[key] != value}
    out.mkdir(parents=True, exist_ok=True)
    for name in CORE_ASSETS:
        shutil.copyfile(release / name, out / name)
    quality = csv_rows(release / 'quality.csv')
    quality = [r for r in quality if r.get('area') != 'incidents' and not r['metric'].startswith('incident_')]
    with (out / 'quality.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(quality[0]), lineterminator='\n')
        writer.writeheader()
        writer.writerows(quality)
    for source, target in [('LICENSE-DATA.md', 'LICENSE-DATA.md'), ('docs/DATA_DICTIONARY.md', 'DATA_DICTIONARY.md')]:
        text = (root / source).read_text()
        # Preserve private source attribution for the later analysis edition.
        text = '\n'.join(line for line in text.splitlines() if not line.startswith('Incident aggregate inputs')) + '\n'
        (out / target).write_text(text)
    schema = stats_schema(release)
    (out / 'STATS_SCHEMA.csv').write_text(schema)
    (out / 'stats').mkdir(exist_ok=True)
    with zipfile.ZipFile(out / 'stats.zip', 'w') as archive:
        for name in sorted(STATS):
            text = descriptive_csv(name, (release / 'stats' / (name + '.csv')).read_text())
            (out / 'stats' / (name + '.csv')).write_text(text)
            zip_write(archive, 'stats/' + name + '.csv', text.encode())
    formats = build(release, out)
    source_summary = json.loads((release / 'release_summary.json').read_text())
    summary = dict(version='1.3.0', edition='database', as_of=source_summary['as_of'],
                   latest_year_is_ytd=True, counts=counts, body_text_status=source_summary['body_text_status'],
                   stats_tables=sorted(STATS), headline_mismatches=mismatches)
    (out / 'release_summary.json').write_text(json.dumps(summary, sort_keys=True, indent=2) + '\n')
    entries = []
    for path in sorted(out.rglob('*')):
        if path.is_file() and path.name != 'CHECKSUMS.sha256':
            digest = hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()
            entries.append(f'{digest}  {path.relative_to(out).as_posix()}\n')
    (out / 'CHECKSUMS.sha256').write_text(''.join(entries))
    return dict(counts=counts, headline_mismatches=mismatches, agent_formats=formats,
                stats_tables=len(STATS), assets=[dict(name=p.name, bytes=p.stat().st_size) for p in sorted(out.iterdir()) if p.is_file()])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, default=ROOT / 'release')
    parser.add_argument('--out', type=Path)
    parser.add_argument('--counts-only', action='store_true')
    parser.add_argument('--schema-out', type=Path)
    args = parser.parse_args()
    if args.schema_out:
        args.schema_out.write_text(stats_schema(args.release))
    if args.counts_only:
        counts = headline(args.release)
        result = dict(counts=counts, headline_mismatches={key: dict(expected=value, actual=counts[key])
                      for key, value in EXPECTED.items() if counts[key] != value})
    elif args.out:
        result = build_candidate(args.release, args.out)
    else:
        parser.error('--out or --counts-only is required')
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
