#!/usr/bin/env python3
"""Collect the complete official Sherlock listing, public Markdown and audit PDFs.

python3 -I scripts/collect/contest_sherlock.py [--offline|--refresh]
Private listing metadata is retained; confidential report bodies are not requested.
Archive PDFs without an official contest-ID link stay documents, not invented contests.
"""
import collections
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from contest_common import Client, ROOT, args, finish, github_root, github_urls, iso, repo_tree, store_report
from contest_pdf_text import sherlock_counts

LISTING = 'https://audits.sherlock.xyz/contests'
API = 'https://mainnet-contest.sherlock.xyz/contests'
REPO = 'sherlock-protocol/sherlock-reports'


def main():
    opts = args()
    client = Client(opts.refresh, opts.offline)
    rows, pages, reports, failures = [], [], [], []
    for page in range(1, 101):
        url = f'{API}?per_page=100&page={page}'
        data = client.json(url)
        pages.append(dict(url=url, rows=len(data['items']), total=data['total']))
        rows.extend(data['items'])
        if not data['has_next']:
            break
    ids = [r['id'] for r in rows]
    assert len(set(ids)) == len(rows) == data['total'], 'Incomplete/duplicate Sherlock pagination'
    stats_url = API + '/stats'
    running_url = API + '?status=RUNNING&per_page=100&page=1'
    stats, running = client.json(stats_url), client.json(running_url)
    stats_counts = stats if isinstance(stats, list) else stats.get('items', stats.get('data', []))
    running_count = next((s['count'] for s in stats_counts if s.get('status') == 'RUNNING'), None)
    discrepancy = (f'Official stats RUNNING={running_count}; explicit RUNNING query total={running["total"]}; '
                   'unidentified running contest and year remain unresolved.' if running_count != running['total'] else None)
    contests = []
    for index, r in enumerate(rows):
        label = r['type_label']
        kind = 'private' if r['private'] else ('bounty_boost' if 'Bounty' in label else 'public_contest')
        item = dict(contest_id=str(r['id']), platform='sherlock', name=r['title'],
                    **{'sponsor/project': r['title']}, start_utc=iso(r['starts_at']), end_utc=iso(r['ends_at']),
                    format=kind, report_url=None, findings_high=None, findings_medium=None, sha256=None,
                    listing_url=f'{LISTING}/{r["id"]}', status_raw=r['status'], type_raw=label,
                    access='private' if r['private'] else 'public', is_best_efforts=r['is_best_efforts'],
                    finalized=r['status'] == 'FINISHED', report_state='private' if r['private'] else 'not_published',
                    findings_basis=None)
        if not r['private']:
            try:
                endpoint = f'{API}/{r["id"]}'
                detail = client.json(endpoint)
                item['judging_repo'] = detail.get('judging_repo_name')
                text = detail.get('report')
                if text and item['finalized']:
                    public_url = f'{LISTING}/{r["id"]}'
                    report, body = store_report(client, 'sherlock', item, public_url, endpoint, fmt='md',
                        content=text.encode('utf-8'),
                        notes=f'Exact UTF-8 Markdown from official contest detail JSON report field: {endpoint}. Contest ID {r["id"]}.')
                    reports.append(report)
                    report['filename'] = f'sherlock-{r["id"]}.md'
                    item.update(report_url=public_url, sha256=report['sha256'], report_state='collected')
                    # Only top-level canonical report headings, not issue/submission counts.
                    headings = re.findall(r'^# Issue ([HM])-([0-9]+):', text, re.M)
                    item['findings_high'] = len({n for s, n in headings if s == 'H'})
                    item['findings_medium'] = len({n for s, n in headings if s == 'M'})
                    item['findings_basis'] = 'Unique canonical # Issue H-n / M-n headings in official final report'
                    if not headings:
                        item['findings_high'] = item['findings_medium'] = None
                        item['findings_basis'] = 'Report has no recognized canonical severity headings; not assumed zero'
                elif item['finalized'] and item['judging_repo']:
                    repo = item['judging_repo']
                    commit, root_files = github_root(client, repo)
                    item['judging_commit'] = commit
                    paths = [f['path'] for f in root_files]
                    groups = [re.fullmatch(r'(\d+)-([HM])', p) for p in paths]
                    groups = [m.groups() for m in groups if m]
                    candidates = [p for p in paths if re.fullmatch(r'(?:Audit[_ -]?Report|report|final[_ -]?report)\.(?:pdf|md)', p, re.I)]
                    if groups:
                        item['findings_high'] = sum(s == 'H' for n, s in groups)
                        item['findings_medium'] = sum(s == 'M' for n, s in groups)
                        item['findings_basis'] = 'Final judging-repository canonical NNN-H / NNN-M exported groups; excludes invalid directory and duplicate submissions'
                    for path in candidates:
                        blob, raw = github_urls(repo, commit, path)
                        report, body = store_report(client, 'sherlock', item, blob, raw,
                            fmt=Path(path).suffix.removeprefix('.').lower(),
                            notes=f'Official final judging-repository report for contest {r["id"]}; API report field absent.')
                        reports.append(report)
                        item.update(report_url=blob, sha256=report['sha256'], report_state='collected')
                        if path.lower().endswith('.pdf'):
                            high, medium = sherlock_counts(body)
                            if high is not None:
                                item.update(findings_high=high, findings_medium=medium,
                                            findings_basis='Official final judging-repository PDF canonical issue headings or Issues Found severity summary table')
            except Exception as exc:
                if str(exc).startswith('HTTP 404: https://github.com/'):
                    item['judging_repo_state'] = 'unavailable'
                else:
                    failures.append(dict(url=f'{API}/{r["id"]}', error=str(exc)))
                    item['report_state'] = 'error'
        contests.append(item)
        if index % 20 == 0:
            print(f'Sherlock details {index + 1}/{len(rows)}, reports={len(reports)}, failures={len(failures)}', flush=True)
    # This public archive includes private-to-public engagements and early pre-platform audits.
    commit, paths = repo_tree(client, REPO)
    pdfs = [p for p in paths if p.startswith('audits/') and p.lower().endswith('.pdf')]
    preliminary = [p for p in pdfs if 'preliminary' in p.lower()]
    final = [p for p in pdfs if p not in preliminary]
    for index, path in enumerate(final):
        public_url, raw_url = github_urls(REPO, commit, path)
        title = Path(path).stem
        item = dict(name=title, **{'sponsor/project': re.sub(r'^.*? - (?:Final|FINAL) - ', '', title)},
                    end_utc=None, format='private', listing_url=f'https://github.com/{REPO}/blob/{commit}/README.md')
        try:
            report, body = store_report(client, 'sherlock', item, public_url, raw_url, fmt='pdf',
                notes='Official audit archive; no exact contest-ID association asserted. Filename date is report issue date, not contest end.')
            report['doc_kind'] = 'audit_report'
            date = re.match(r'(\d{4})\.(\d{2})\.(\d{2})', title)
            if date:
                report.update(date_hint='-'.join(date.groups()), date_precision='day', date_basis='filename')
            reports.append(report)
        except Exception as exc:
            failures.append(dict(url=public_url, error=str(exc)))
        if index % 20 == 0:
            print(f'Sherlock archive {index + 1}/{len(final)}, failures={len(failures)}', flush=True)
    evidence = dict(listing_url=LISTING, api_pages=pages, listing_total=data['total'],
                    official_stats=stats, running_query=running, stats_url=stats_url, running_url=running_url,
                    stats_listing_discrepancy=discrepancy,
                    listing_end_years=dict(sorted(collections.Counter(iso(r['ends_at'])[:4] for r in rows).items())),
                    listing_public=sum(not r['private'] for r in rows), listing_private=sum(r['private'] for r in rows),
                    report_archive_repo=REPO, report_archive_commit=commit, archive_pdf_paths=len(pdfs),
                    archive_final_pdf_paths=len(final), excluded_preliminary=preliminary,
                    archive_documents_are_not_additional_contest_ids=True,
                    private_report_policy='Only public audit-archive PDFs; private contest detail bodies are not requested.')
    for item in contests:
        item.update(sponsor=item['sponsor/project'], project=item['name'])
    finish('sherlock', contests, reports, failures, [LISTING, API, f'https://github.com/{REPO}'], data['total'], evidence,
           skipped_non_report=len(preliminary) + sum(p.startswith('coverage-agreements/') and p.lower().endswith('.pdf') for p in paths))


if __name__ == '__main__':
    main()
