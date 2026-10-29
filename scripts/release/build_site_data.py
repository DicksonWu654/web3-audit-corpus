#!/usr/bin/env python3
"""Build the website's static data (`build/data/`) from the release files (`make site-data`).

    python3 -I scripts/release/build_site_data.py [--release release] [--out build/data]

Layout (docs/DATA_CONTRACT.md, in the shapes `site/src/assets/js/data.js` reads):
  summary.json                   {as_of, counts{...}, quality[rows], selected_severity, ..., key_results}
  stats/<table>.json             {name, columns, rows[[...]]}: one per release/stats/*.csv aggregate table
  firms.json                     [{firm_id, name, kind, website, reports_listed, reports_collected, coverage_pct,
                                   first_year, last_year, engagements, audit_types{}, token_only_share,
                                   engagements_excluding_token_only, momentum{}, momentum_excluding_token_only{},
                                   findings, severity{}, status{}, classes{}, ...}]
                                 (findings/severity/status/classes count the findings selected for statistics)
  engagements/<firm_id>.json     [{engagement_id, project, review_mode, audit_year, ..., report_url, report_sha256,
                                   pages, reports[...]}]  (no finding text)
  findings/<firm_id>/<n>.json    {firm_id, shard, findings[{finding_uid, ..., body_text, url, permalink, project,
                                   audit_year, review_mode, selected_for_stats, ...}]}, each file <= 2 MB
  search/manifest.json           {version, fields, dicts, shards[{file, firm_id, count}]}
  search/index-<firm_id>[-k].json {firm_id, fields, dicts, projects, rows}; row = [uid12, title, project_idx,
                                   year|0, severity_idx, status_idx, leaf_idx|-1, mode_idx, shard, finding_id,
                                   selected]  (no body text)
Budget (asserted here and by validate.py): every file <= 5 MB, finding shards <= 2 MB,
summary.json + firms.json <= 1.5 MB.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import common as C  # noqa: E402
from database_policy import STATS, descriptive_csv

SHARD_LIMIT = 2_000_000
INDEX_LIMIT = 2_000_000
INDEX_ROWS = 25_000
FILE_LIMIT = 5_000_000
FIRST_LOAD_LIMIT = 1_500_000
TITLE_INDEX_CHARS = 200
MODES = ['firm_review', 'contest']
INDEX_FIELDS = ['id', 'title', 'project', 'year', 'severity', 'status', 'leaf', 'mode', 'shard', 'finding_id', 'selected']
INT_RE = re.compile(r'^-?\d+$')
FLOAT_RE = re.compile(r'^-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?$')
INT_COLUMNS = {'reports_listed', 'reports_collected', 'first_year', 'last_year', 'engagements', 'reports_released',
               'findings_selected', 'findings_released', 'audit_year', 'publication_year', 'findings_count', 'pages'}
FLOAT_COLUMNS = {'coverage_pct'}
INT_COLUMNS.update({'findings_withheld', 'initial_findings_withheld', *('findings_' + severity for severity in C.SEVERITIES)})
BOOL_COLUMNS = {'audit_year_conflict', 'publication_year_conflict', 'findings_observed'}
JSON_COLUMNS = {'chain_families', 'languages', 'report_ids', 'engagement_ids', 'firm_ids', 'alternate_urls'}
SHARD_FIELDS = ('finding_uid', 'finding_id', 'title', 'severity', 'severity_original', 'status', 'status_original',
                'vuln_group', 'vuln_leaf', 'vuln_confidence', 'vuln_needs_review', 'body_text', 'body_text_status',
                'text_withheld', 'body_text_redactions', 'body_truncated', 'page_start', 'page_end', 'engagement_id',
                'report_id', 'source', 'finding_phase', 'selected_for_stats')
SHARD_FIELDS += C.TEXT_RIGHTS_FIELDS
SOURCE_ORDER = {'report_extraction': 0, 'phase4': 0, 'phase4_supplemental': 1, 'legacy_database': 2, 'gold_label': 3}


def typed_known(row):
    out = {}
    for k, v in row.items():
        if v == '':
            out[k] = None
        elif k in INT_COLUMNS:
            out[k] = int(v)
        elif k in FLOAT_COLUMNS:
            out[k] = float(v)
        elif k in BOOL_COLUMNS:
            out[k] = v == 'true'
        elif k in JSON_COLUMNS:
            out[k] = json.loads(v)
        else:
            out[k] = v
    return out


def typed_stat(value):
    """Aggregate cells: numbers become numbers and booleans booleans; other text is kept verbatim."""
    if value == '':
        return None
    if value in ('True', 'true'):
        return True
    if value in ('False', 'false'):
        return False
    if INT_RE.match(value):
        return int(value)
    if FLOAT_RE.match(value):
        return float(value)
    return value


def object_stats(release, name):
    path = release / 'stats' / (name + '.csv')
    return [{key: typed_stat(value) for key, value in row.items()}
            for row in C.read_csv(path)] if path.exists() else []


class Writer:
    def __init__(self, out):
        self.out = out
        self.sizes = {}

    def raw(self, rel, data, limit=FILE_LIMIT):
        if len(data) > limit:
            raise SystemExit(f'size budget exceeded: {rel} would be {len(data):,} bytes (limit {limit:,})')
        C.write_bytes(self.out / rel, data)
        self.sizes[rel] = len(data)
        return len(data)

    def json(self, rel, obj, limit=FILE_LIMIT):
        return self.raw(rel, C.dumps(obj).encode('utf-8'), limit)


def pack(items, limit, overhead, max_items=None):
    """Greedy packing of serialized JSON items so each array (plus overhead) stays within limit."""
    chunks, current, size = [], [], overhead
    for item in items:
        n = len(item.encode('utf-8')) + 1
        if n + overhead > limit:
            raise SystemExit(f'size budget exceeded: one item is {n:,} bytes')
        if current and (size + n > limit or (max_items and len(current) >= max_items)):
            chunks.append(current)
            current, size = [], overhead
        current.append(item)
        size += n
    if current:
        chunks.append(current)
    return chunks


def write_stats(release, writer):
    names = sorted(p.stem for p in (release / 'stats').glob('*.csv') if p.stem in STATS)
    for name in names:
        text = descriptive_csv(name, (release / 'stats' / (name + '.csv')).read_text())
        reader = csv.DictReader(io.StringIO(text))
        header = reader.fieldnames
        writer.json(f'stats/{name}.json', dict(name=name, columns=header,
                    rows=[[typed_stat(row[c]) for c in header] for row in reader]))
    return names


def firm_audit_type_data(release, engagements):
    by_firm = defaultdict(list)
    for row in engagements:
        by_firm[row['firm_id']].append(row)
    out = {}
    for firm, rows in sorted(by_firm.items()):
        mix = C.audit_type_counts(rows)
        out[firm] = dict(audit_types=mix, token_only_engagements=mix['token_only'],
                         token_only_share=mix['token_only'] / len(rows),
                         engagements_excluding_token_only=len(rows)-mix['token_only'])
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--root', type=Path, default=C.ROOT)
    parser.add_argument('--release', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    import pyarrow.parquet as pq
    root = args.root.resolve()
    release = (args.release or root / 'release').resolve()
    out = (args.out or root / 'build/data').resolve()
    if not (release / 'CHECKSUMS.sha256').exists():
        raise SystemExit(f'no release at {release}; run make release first')
    summary_in = json.loads((release / 'release_summary.json').read_bytes())
    firms = [typed_known(r) for r in C.read_csv(release / 'firms.csv')]
    engagements = [typed_known(r) for r in C.read_csv(release / 'engagements.csv')]
    reports = {r['report_id']: typed_known(r) for r in C.read_csv(release / 'reports.csv')}
    quality = C.read_csv(release / 'quality.csv')
    eng_by_id = {e['engagement_id']: e for e in engagements}
    audit_type_data = firm_audit_type_data(release, engagements)
    table = pq.read_table(release / 'findings.parquet', use_threads=False)
    col = {c: table.column(c).to_pylist() for c in table.column_names}
    n = table.num_rows

    if out.exists():
        if out.name != 'data':
            raise SystemExit(f'refusing to clear {out}')
        shutil.rmtree(out)
    out.mkdir(parents=True)
    w = Writer(out)
    w.json('taxonomy.json', json.loads((release / 'taxonomy.yaml').read_bytes()))

    # stats: one file per aggregate table
    stat_names = write_stats(release, w)

    # findings shards and search index, per firm
    by_firm = defaultdict(list)
    for i in range(n):
        by_firm[col['firm_id'][i]].append(i)
    firm_ids = sorted(f['firm_id'] for f in firms)
    leaves, leaf_index = [], {}
    manifest = []
    shard_counts, firm_stats = {}, {}
    for firm in firm_ids:
        order = sorted(by_firm.get(firm, []), key=lambda i: (
            -(eng_by_id[col['engagement_id'][i]]['audit_year'] or 0), col['engagement_id'][i], col['report_id'][i],
            SOURCE_ORDER[col['source'][i]], col['ordinal'][i] if col['ordinal'][i] is not None else 1 << 30,
            col['finding_uid'][i]))
        items = []
        for i in order:
            eng = eng_by_id[col['engagement_id'][i]]
            rep = reports[col['report_id'][i]]
            item = {k: col[k][i] for k in SHARD_FIELDS if k not in C.TEXT_RIGHTS_FIELDS or col[k][i] is not None}
            if isinstance(item.get('body_text_redactions'), str):
                item['body_text_redactions'] = json.loads(item['body_text_redactions'] or '{}')
            if item.get('text_withheld') or item.get('body_text_status') != 'present':
                item['body_text'] = None
            item.update(url=rep['url'], permalink=rep['permalink'], archive_url=rep['archive_url'],
                        file_type=rep['file_type'], project=eng['project'], audit_year=eng['audit_year'],
                        review_mode=eng['review_mode'])
            items.append(C.dumps(item))
        overhead = len(C.dumps(dict(findings=[], firm_id=firm, shard=9999)).encode('utf-8'))
        chunks = pack(items, SHARD_LIMIT, overhead)
        shard_counts[firm] = len(chunks)
        shard_of = []
        for s, chunk in enumerate(chunks):
            body = '{"findings":[' + ','.join(chunk) + '],"firm_id":' + json.dumps(firm, ensure_ascii=False) + ',"shard":' + str(s) + '}'
            w.raw(f'findings/{firm}/{s}.json', body.encode('utf-8'), SHARD_LIMIT)
            shard_of += [s] * len(chunk)
        rows = []
        for i, s in zip(order, shard_of):
            eng = eng_by_id[col['engagement_id'][i]]
            leaf = col['vuln_leaf'][i] or col['vuln_group'][i]
            if leaf and leaf not in leaf_index:
                leaf_index[leaf] = len(leaves)
                leaves.append(leaf)
            rows.append((i, eng, leaf, s))
        firm_stats[firm] = dict(
            severity=Counter(col['severity'][i] for i in order if col['selected_for_stats'][i]),
            status=Counter(col['status'][i] for i in order if col['selected_for_stats'][i]),
            classes=Counter(col['vuln_group'][i] for i in order if col['selected_for_stats'][i] and col['vuln_group'][i]),
            index_rows=rows)  # serialized below, once the global leaf dictionary is complete

    dicts = dict(severity=list(C.SEVERITIES), status=list(C.STATUSES), leaf=leaves, mode=MODES)
    for firm in firm_ids:
        part_rows = firm_stats[firm].pop('index_rows')
        projects_all = []
        serial = []
        for i, eng, leaf, s in part_rows:
            serial.append((eng['project'] or '', [col['finding_uid'][i].split(':')[-1][:12], (col['title'][i] or '')[:TITLE_INDEX_CHARS],
                           None, eng['audit_year'] or 0, C.SEVERITIES.index(col['severity'][i]), C.STATUSES.index(col['status'][i]),
                           leaf_index[leaf] if leaf else -1, MODES.index(eng['review_mode']), s, col['finding_id'][i] or '',
                           1 if col['selected_for_stats'][i] else 0]))
            projects_all.append(eng['project'] or '')
        header = len(C.dumps(dict(dicts=dicts, fields=INDEX_FIELDS, firm_id=firm, projects=[], rows=[])).encode('utf-8'))
        estimated = [C.dumps(r) for _, r in serial]
        groups = pack(estimated, INDEX_LIMIT - header - 200_000, 0, INDEX_ROWS) if serial else []
        start = 0
        for k, group in enumerate(groups):
            part = serial[start:start + len(group)]
            start += len(group)
            projects, pidx = [], {}
            rows = []
            for project, r in part:
                if project not in pidx:
                    pidx[project] = len(projects)
                    projects.append(project)
                rows.append([r[0], r[1], pidx[project]] + r[3:])
            name = f'index-{firm}.json' if len(groups) == 1 else f'index-{firm}-{k}.json'
            w.json(f'search/{name}', dict(firm_id=firm, fields=INDEX_FIELDS, dicts=dicts, projects=projects, rows=rows), INDEX_LIMIT)
            manifest.append(dict(file=name, firm_id=firm, count=len(rows)))
    w.json('search/manifest.json', dict(version=1, fields=INDEX_FIELDS, dicts=dicts, shards=manifest,
                                        shard_path='findings/{firm_id}/{shard}.json', title_chars=TITLE_INDEX_CHARS))

    # engagements per firm (no finding text)
    eng_by_firm = defaultdict(list)
    for e in engagements:
        e = dict(e)
        primary = reports.get(e['primary_report_id']) or {}
        e['report_url'] = primary.get('url') or e.get('evidence_url')
        e['report_sha256'] = primary.get('sha256')
        e['report_permalink'] = primary.get('permalink')
        e['pages'] = primary.get('pages')
        e['reports'] = [{k: reports[rid][k] for k in ('report_id', 'url', 'permalink', 'archive_url', 'file_type', 'pages',
                                                       'doc_kind', 'document_role', 'link_status', 'text_withheld', 'body_text_status', 'text_source_sha256', 'text_source_equivalence')}
                        for rid in e.pop('report_ids') if rid in reports]
        eng_by_firm[e['firm_id']].append(e)
    for firm in firm_ids:
        rows = sorted(eng_by_firm.get(firm, []), key=lambda e: (-(e['audit_year'] or 0), e['project'] or '', e['engagement_id']))
        w.json(f'engagements/{firm}.json', rows)

    # firms + summary (first page load)
    firm_rows = []
    for f in sorted(firms, key=lambda f: f['firm_id']):
        st = firm_stats.get(f['firm_id'], {})
        firm_rows.append(dict(f, **audit_type_data[f['firm_id']], findings=f['findings_selected'],
                              severity={s: st['severity'][s] for s in C.SEVERITIES if st and st['severity'][s]},
                              status={s: st['status'][s] for s in C.STATUSES if st and st['status'][s]},
                              classes=dict(sorted(st['classes'].items(), key=lambda kv: (-kv[1], kv[0]))) if st else {},
                              finding_shards=shard_counts.get(f['firm_id'], 0),
                              engagements_file=f'engagements/{f["firm_id"]}.json'))
    first = w.json('firms.json', firm_rows)
    run = {}
    counts = dict(engagements=len(engagements), publisher_engagements=len(engagements),
        industry_engagements=len({e['industry_engagement_id'] for e in engagements}),
        reports=len(reports), findings=n, finding_records=n, findings_released=n,
        findings_selected_for_stats=sum(col['selected_for_stats']),
        projects=len({e['project'] for e in engagements if e.get('project')}))
    kinds = Counter(f['kind'] for f in firms)
    counts.update(
        publisher_engagements=counts['engagements'], findings=counts['findings_released'],
        findings_analysed=counts['findings_selected_for_stats'], publishers=len(firms),
        firms=len(firms), firm_publishers=kinds['firm'], collectives=kinds['collective'],
        contest_platforms=kinds['contest_platform'])
    type_counts = C.audit_type_counts(engagements)
    counts.update(token_only_engagements=type_counts['token_only'],
                  engagements_excluding_token_only=len(engagements) - type_counts['token_only'],
                  industry_engagements_excluding_token_only=len({e['industry_engagement_id'] for e in engagements
                                                                if e['audit_type'] != 'token_only'}))
    counts['finding_records_label'] = 'Finding records (including fix reviews and alternate copies)'
    counts['initial_findings_label'] = 'Initial findings selected for statistics'
    quality_rows = [dict({k: typed_stat(v) for k, v in q.items()}, detail=q['sample']) for q in quality]
    summary = dict(as_of=summary_in['as_of'], counts=counts, quality=quality_rows,
        selected_severity=dict(Counter(col['severity'][i] for i in range(n) if col['selected_for_stats'][i])),
        selected_status=dict(Counter(col['status'][i] for i in range(n) if col['selected_for_stats'][i])),
        audit_types=type_counts, stats=stat_names, search_manifest='search/manifest.json')
    first += w.json('summary.json', summary)
    if first > FIRST_LOAD_LIMIT:
        raise SystemExit(f'size budget exceeded: first-load data {first:,} bytes')
    largest = max(w.sizes.items(), key=lambda kv: kv[1])
    print(C.dumps(dict(files=len(w.sizes), total_bytes=sum(w.sizes.values()), first_load_bytes=first, largest=list(largest),
                       finding_shards=sum(shard_counts.values()), search_files=len(manifest), findings=n)))


if __name__ == '__main__':
    main()
