#!/usr/bin/env python3
"""Check every agent-format row/body against released Parquet and audit the candidate."""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from agent_formats import RIGHTS, ZIP_DATE, csv_rows, joined, keyed
from database_policy import CORE_ASSETS, STATS
from build_database_release import EXPECTED, headline
import common as C

MD_FIELDS = ('finding_uid', 'finding_id', 'title', 'severity', 'status', 'vuln_group', 'vuln_leaf',
             'engagement_id', 'body_text_status', 'text_withheld', 'body_truncated', 'body_text_redactions', *RIGHTS)
SECTION = re.compile(r'(?m)^## ("(?:[^"\\\n]|\\.)*")\n\nfinding_uid: ')


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def validate(release, source=None):
    import pyarrow.parquet as pq

    release, source = Path(release), Path(source or release)
    counts = headline(source)
    reports = keyed(csv_rows(source / 'reports.csv'), 'report_id')
    engagements = keyed(csv_rows(source / 'engagements.csv'), 'engagement_id')
    firms = keyed(csv_rows(source / 'firms.csv'), 'firm_id')
    if set(firms) & C.EXCLUDED_AT_PUBLISHER_REQUEST:
        raise ValueError('Publisher-request excluded publisher in firms')
    expected, unavailable = {}, 0
    for batch in pq.ParquetFile(source / 'findings.parquet').iter_batches(batch_size=256, use_threads=False):
        for row in batch.to_pylist():
            uid = row['finding_uid']
            if uid in expected:
                raise ValueError('Duplicate source finding UID')
            obj = joined(row, reports, engagements, firms)
            permitted = not row.get('text_withheld') and row.get('body_text_status') == 'present'
            body = row.get('body_text') if permitted else None
            unavailable += not permitted
            expected[uid] = (digest(obj), digest({k: row.get(k) for k in MD_FIELDS}), digest(body), row['report_id'])
    json_seen = set()
    with gzip.open(release / 'findings.jsonl.gz', 'rt', encoding='utf-8') as stream:
        for line in stream:
            obj = json.loads(line); uid = obj['finding_uid']
            if uid in json_seen or uid not in expected or digest(obj) != expected[uid][0]:
                raise ValueError('JSON row differs from released data: ' + uid)
            if (obj.get('text_withheld') or obj.get('body_text_status') != 'present') and obj['body_text'] is not None:
                raise ValueError('Withheld JSON body')
            json_seen.add(uid)
    if json_seen != set(expected):
        raise ValueError('JSON row census differs')
    md_seen = set()
    with zipfile.ZipFile(release / 'audits-markdown.zip') as archive:
        if archive.namelist() != sorted(archive.namelist()):
            raise ValueError('Archive paths are unsorted')
        if any(info.date_time != ZIP_DATE for info in archive.infolist()):
            raise ValueError('Variable ZIP timestamp')
        index = list(csv.DictReader(io.StringIO(archive.read('INDEX.csv').decode())))
        if {r['report_id'] for r in index} != set(reports) or len(index) != len(reports):
            raise ValueError('Markdown report census differs')
        if set(archive.namelist()) != {r['path'] for r in index} | {'INDEX.csv', 'README.md'}:
            raise ValueError('Unindexed Markdown entry')
        for entry in index:
            text = archive.read(entry['path']).decode('utf-8')
            front, content = text[4:].split('\n---\n\n', 1)
            meta = {k: json.loads(v) for k, v in (line.split(': ', 1) for line in front.splitlines())}
            if meta['report_id'] != entry['report_id'] or C.is_excluded_publisher(meta['firm_id']) or meta['firm_id'].casefold() == 'certik':
                raise ValueError('Markdown report identity differs')
            matches = list(SECTION.finditer(content)); severity = Counter(); full = 0
            for i, match in enumerate(matches):
                title = json.loads(match[1])
                section = content[match.end() - len('finding_uid: '):matches[i+1].start() if i+1 < len(matches) else len(content)]
                fields, body_section = section.split('\n\n', 1)
                fields = {k: json.loads(v) for k, v in (line.split(': ', 1) for line in fields.splitlines())}
                uid = fields['finding_uid']
                if title != (fields['title'] or uid):
                    raise ValueError('Markdown heading differs')
                prefix, suffix = '<!-- body_text:start -->\n', '\n<!-- body_text:end -->\n\n'
                if body_section.startswith(prefix) and body_section.endswith(suffix):
                    body = body_section[len(prefix):-len(suffix)]
                    if fields.get('text_withheld') or fields.get('body_text_status') != 'present':
                        raise ValueError('Withheld Markdown body')
                    full += bool(body)
                else:
                    body = None
                    report = reports[entry['report_id']]
                    url = report.get('permalink') or report['url']
                    if body_section != 'Text unavailable. See original report: ' + url + '\n\n':
                        raise ValueError('Unexpected unavailable-body content')
                if uid in md_seen or uid not in expected:
                    raise ValueError('Duplicate or unknown Markdown finding')
                if (digest(fields), digest(body), entry['report_id']) != expected[uid][1:]:
                    raise ValueError('Markdown finding differs from Parquet: ' + uid)
                severity[fields['severity'] or 'unknown'] += 1
                md_seen.add(uid)
            if len(matches) != int(entry['finding_records']) or len(matches) != meta['finding_records']:
                raise ValueError('Markdown finding count differs')
            if full != int(entry['full_text_records']) or any(meta['severity_counts'][s] != severity[s] for s in meta['severity_counts']):
                raise ValueError('Markdown severity/body counts differ')
    if md_seen != json_seen or sum(int(r['finding_records']) for r in index) != counts['findings']:
        raise ValueError('Markdown/JSON/Parquet census differs')
    expected_files = set(CORE_ASSETS) | {'quality.csv', 'LICENSE-DATA.md', 'DATA_DICTIONARY.md', 'STATS_SCHEMA.csv',
        'stats.zip', 'audits-markdown.zip', 'findings.jsonl.gz', 'release_summary.json', 'CHECKSUMS.sha256'}
    optional_assets = {'web3-audits.sqlite','audit-corpus-v1.3.0.sqlite.gz','SOURCE-SQLITE.json','VALIDATION-SQLITE.json','CHECKSUMS-SQLITE.sha256'}
    expected_files |= {name for name in optional_assets if (release / name).exists()}
    actual_files = {p.name for p in release.iterdir() if p.is_file()}
    if actual_files != expected_files:
        raise ValueError('Candidate asset census differs: ' + repr(actual_files ^ expected_files))
    stats_counts = {}
    schema = keyed(csv_rows(release / 'STATS_SCHEMA.csv'), 'table')
    if set(schema) != set(STATS):
        raise ValueError('Statistics schema census differs')
    with zipfile.ZipFile(release / 'stats.zip') as archive:
        if set(archive.namelist()) != {'stats/' + name + '.csv' for name in STATS}:
            raise ValueError('Statistics archive census differs')
        for name in STATS:
            data = archive.read('stats/' + name + '.csv')
            if data != (release / 'stats' / (name + '.csv')).read_bytes():
                raise ValueError('Packed/unpacked statistics differ')
            reader = csv.DictReader(io.StringIO(data.decode()))
            if reader.fieldnames != json.loads(schema[name]['columns']):
                raise ValueError('Statistics columns differ from schema')
            rows = list(reader); stats_counts[name] = len(rows)
            if any(C.is_excluded_publisher(r.get('publisher_id') or r.get('firm_id')) or
                   (r.get('publisher_id') or r.get('firm_id') or '').casefold() == 'certik' for r in rows):
                raise ValueError('Out-of-scope statistic')
    if any(r.get('area') == 'incidents' or r['metric'].startswith('incident_') for r in csv_rows(release / 'quality.csv')):
        raise ValueError('Deferred quality measurement')
    checksums = {}
    for line in (release / 'CHECKSUMS.sha256').read_text().splitlines():
        sha, name = line.split('  ', 1); checksums[name] = sha
        with (release / name).open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != sha:
                raise ValueError('Checksum mismatch: ' + name)
    if set(checksums) != {p.relative_to(release).as_posix() for p in release.rglob('*') if p.is_file() and p.name != 'CHECKSUMS.sha256'}:
        raise ValueError('Checksum census differs')
    if source != release:
        for name in CORE_ASSETS:
            with (source / name).open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != checksums[name]:
                    raise ValueError('Retained asset differs from source: ' + name)
    asset_rows = {name: len(csv_rows(release / name)) for name in ('reports.csv', 'engagements.csv', 'firms.csv', 'quality.csv', 'RIGHTS_WITHHELD.csv', 'STATS_SCHEMA.csv')}
    with gzip.open(release / 'findings.csv.gz', 'rt', newline='') as stream:
        asset_rows['findings.csv.gz'] = sum(1 for _ in csv.DictReader(stream))
    if asset_rows['findings.csv.gz'] != counts['findings']:
        raise ValueError('CSV/Parquet census differs')
    asset_rows.update({'findings.parquet': counts['findings'], 'findings.jsonl.gz': len(json_seen),
                       'audits-markdown.zip': len(index), 'stats.zip': sum(stats_counts.values())})
    return dict(counts=counts, headline_mismatches={k: dict(expected=v, actual=counts[k]) for k, v in EXPECTED.items() if counts[k] != v},
                markdown_reports=len(index), markdown_findings=len(md_seen), jsonl_findings=len(json_seen),
                withheld_or_unavailable_rows=unavailable, withheld_text_leaks=0, certik_rows=0,
                source_rows_and_rights_identical=True, stats_rows=stats_counts, checksums_verified=len(checksums), unresolved=0,
                assets=[dict(name=p.name, bytes=p.stat().st_size, rows=asset_rows.get(p.name))
                        for p in sorted(release.iterdir()) if p.is_file()])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=Path, required=True)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    result = validate(args.release, args.source)
    text = json.dumps(result, sort_keys=True, indent=2) + '\n'
    if args.report:
        args.report.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
