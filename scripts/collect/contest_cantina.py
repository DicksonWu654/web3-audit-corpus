#!/usr/bin/env python3
"""Cantina competitions plus its managed/solo public report portfolio.

Use inert public-page Flight JSON and a preserved official competition snapshot.
The API is currently disallowed by robots.txt and is NEVER requested here.
The preserved response predates this collector and is identified by digest/date.
Spearbit-guild portfolio entries belong to the separate Spearbit firm collector.
"""
import argparse
from collections import Counter
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contest_common import (Client, ROOT, STORE, finish, flight_objects, objects,
                            read_jsonl, store_report, utc, write_jsonl, write_json)

PLATFORM = 'cantina'
PORTFOLIO = 'https://cantina.xyz/portfolio'
MANAGED = 'https://cantina.xyz/security-reviews'
LISTING = 'https://cantina.xyz/opportunities/competitions'
ENDED = 'https://cantina.xyz/opportunities/ended'
API = 'https://cantina.xyz/api/v0/competitions'


def flight_text(text):
    # JSON.parse equivalent on script text only, never JavaScript evaluation.
    chunks = []
    for match in re.finditer(r'self\.__next_f\.push\((\[.*?\])\)</script>', text, re.S):
        chunks.extend(x for x in json.loads(match[1]) if isinstance(x, str))
    return '\n'.join(chunks)


def array_property(text, key):
    match = re.search('"' + re.escape(key) + '":', flight_text(text))
    if not match:
        raise ValueError('Missing portfolio section: ' + key)
    result = json.JSONDecoder().raw_decode(flight_text(text)[match.end():])[0]
    if not isinstance(result, list) or len({r['id'] for r in result}) != len(result):
        raise ValueError('Malformed or duplicate portfolio IDs: ' + key)
    return result


def snapshot_competitions():
    """Read a previously captured first-party response; no network fallback."""
    saved = ROOT/'data/collect/cantina/competition_listing.json'
    if saved.exists():
        snapshot = json.loads(saved.read_text())
        return snapshot['records'], snapshot['source']
    key = hashlib.sha256(API.encode()).hexdigest()
    for folder in (STORE/'contest-http', Path('local-cache/tmp/web3-aggregators-http')):
        bp, mp = folder/(key+'.body'), folder/(key+'.json')
        if bp.exists() and mp.exists():
            body, meta = bp.read_bytes(), json.loads(mp.read_text())
            if meta['status'] != 200 or hashlib.sha256(body).hexdigest() != meta['sha256']:
                raise ValueError('Invalid preserved official competition snapshot')
            rows = json.loads(body)
            if not isinstance(rows, list) or len({r['id'] for r in rows}) != len(rows):
                raise ValueError('Invalid official competition IDs')
            source = dict(url=API, sha256=meta['sha256'], accessed_at=meta['accessed_at'],
                acquisition='Preserved earlier first-party research response; never re-requested because /api/ is disallowed by robots.txt.')
            # Public factual metadata only; do not publish instructions/source code.
            records = [{k: r.get(k) for k in ('id', 'name', 'url', 'timeframe', 'status', 'kind')}
                       | {'company': {'name': r['company']['name']} if r.get('company') else None,
                          'ctf_format': bool(r.get('requiredCtfAddress'))}
                       for r in rows]
            write_json(saved, dict(source=source, records=records))
            return records, source
    raise RuntimeError('Preserved official competition snapshot missing. API is robots-disallowed; obtain an official export instead.')


def date(value):
    if not value:
        return None
    return dt.datetime.strptime(value, '%d %B %Y').strftime('%Y-%m-%dT00:00:00Z')


def normal(value):
    return re.sub('[^a-z0-9]', '', (value or '').lower())


def classify(title, kind):
    title = title or ''
    if re.search(r'\b(mitigation|remediation|fix review)\b', title, re.I):
        return 'mitigation'
    if kind in ('cantina_managed', 'cantina_solo'):
        return 'other'
    if kind == 'private_contest':
        return 'private'
    if re.search(r'\b(ctf|hackathon)\b', title, re.I):
        return 'other'
    return 'public_contest'


def match_competition(portfolio, competitions):
    direct = [r for r in competitions if r['id'] in portfolio['id']+' '+(portfolio['pdfLink'] or '')]
    if len(direct) == 1:
        return direct[0], 'competition UUID present in official report filename'
    start, end = date(portfolio['timeline']['start']), date(portfolio['timeline']['end'])
    same = [r for r in competitions if (r.get('timeframe') or {}).get('start', '')[:10] == (start or '')[:10]
            and (r.get('timeframe') or {}).get('end', '')[:10] == (end or '')[:10]]
    client = [r for r in same if normal((r.get('company') or {}).get('name')) == normal(portfolio['client']['name'])]
    if len(client) == 1:
        return client[0], 'same official sponsor and full competition period'
    # Pectra has separate platform IDs per client, with the same period/sponsor.
    suffix = portfolio['title'].partition(': ')[2]
    names = {'Protocol Specifications': 'Ethereum-Protocol', 'Go Ethereum': 'go-ethereum',
             'Nimbus ETH2': 'nimbus-eth2'}
    named = [r for r in same if normal(r['name']) == normal(names.get(suffix, suffix))]
    if len(named) == 1:
        return named[0], 'same official period and Pectra client name'
    if len(same) == 1:
        # Three publisher rename cases, explicitly inspected against both pages.
        renames = {'Size Credit': 'Rheo', 'Term Structure': 'TermMax',
                   'Babylonchain': 'Babylonchain - archive'}
        if renames.get(portfolio['client']['name']) == (same[0].get('company') or {}).get('name'):
            return same[0], 'same full period; official sponsor rename/archived handle'
    return None, 'unmatched official report portfolio entry'


def summarize(rows):
    result = {}
    for kind in ('competition', 'managed_security_review', 'solo_security_review'):
        subset = [r for r in rows if r['engagement_kind'] == kind]
        result[kind] = dict(count=len(subset),
            per_year_end_utc=dict(sorted(Counter((r['end_utc'] or 'unknown')[:4] if r['end_utc'] else 'unknown' for r in subset).items())),
            formats=dict(sorted(Counter(r['format'] for r in subset).items())),
            with_report=sum(bool(r['sha256']) for r in subset),
            missing_period=sum(not r['start_utc'] or not r['end_utc'] for r in subset))
    return result


def collect(client):
    api, api_source = snapshot_competitions()
    pm, pb = client.get(PORTFOLIO)
    if pm['status'] != 200:
        raise RuntimeError('Official report portfolio unavailable')
    text = pb.decode()
    managed = array_property(text, 'cantinaManaged')
    solo = array_property(text, 'cantinaSolo')
    comp_reports = array_property(text, 'cantinaCompetitions')
    spearbit = array_property(text, 'spearbitGuild')
    mm, mb = client.get(MANAGED)
    managed_ids = {r['id'] for r in array_property(mb.decode(), 'cantinaManaged')}
    if managed_ids != {r['id'] for r in managed}:
        raise ValueError('Managed portfolio and security-reviews listing disagree')
    lm, lb = client.get(LISTING)
    em, eb = client.get(ENDED)
    queries = [o for body in (lb, eb) for f in flight_objects(body.decode()) for o in objects(f)
               if isinstance(o.get('groups'), dict) and 'completedAll' in o['groups']]
    groups = [r['groups'] for r in queries]
    if not groups or len({g['completedAll'] for g in groups}) != 1:
        raise ValueError('Official listing completed-count missing or inconsistent')
    complete_count = sum(r['status'] == 'complete' for r in api)
    live_count = sum(r['status'] == 'live' for r in api)
    if complete_count != groups[0]['completedAll'] or live_count != groups[0]['currentCompetitions']:
        raise ValueError('Preserved competition IDs no longer reconcile with live listing counters')
    contests, reports, failures = [], [], []
    by_id = {}
    for row in api:
        kind = row['kind']
        fmt = classify(row['name'], kind)
        ctf = row.get('ctf_format', False) or bool(re.search(r'\bctf\b', row['name'] or '', re.I))
        if ctf:
            fmt = 'other'
        contest = dict(contest_id=row['id'], platform=PLATFORM, name=row['name'],
            **{'sponsor/project': (row.get('company') or {}).get('name')},
            start_utc=(row.get('timeframe') or {}).get('start'),
            end_utc=(row.get('timeframe') or {}).get('end'),
            format=fmt, raw_kind=kind, engagement_kind='competition',
            engagement_subtype='ctf_or_hackathon' if fmt == 'other' else 'competition',
            access='private' if kind == 'private_contest' else 'public',
            report_url=None, findings_high=None, findings_medium=None, sha256=None,
            listing_url=row['url'], finalization_status=row['status'],
            findings_count_basis='unknown; totalFindings is submissions, never accepted findings',
            eligible_public_cohort=False,
            excluded_reason=('ctf_format_separate' if ctf else 'hackathon_exercise') if fmt == 'other' else None,
            date_precision='second' if row.get('timeframe') else 'none')
        contests.append(contest)
        by_id[row['id']] = contest
    portfolio_rows = []
    report_jobs = []
    join_gaps = []
    for section, records in [('managed_security_review', managed), ('solo_security_review', solo), ('competition', comp_reports)]:
        for row in records:
            if section == 'competition':
                matched, basis = match_competition(row, api)
                if not matched:
                    join_gaps.append(row['id'])
                    # Still collect every published report, without inventing a contest ID.
                    contest = dict(contest_id='portfolio:'+row['id'], name=row['title'],
                        **{'sponsor/project': row['client']['name']}, listing_url=PORTFOLIO,
                        start_utc=date(row['timeline']['start']), end_utc=date(row['timeline']['end']),
                        format='public_contest')
                else:
                    contest = by_id[matched['id']]
            else:
                basis = 'official portfolio ID; separate from competitions'
                contest = dict(contest_id='portfolio:'+row['id'], platform=PLATFORM, name=row['title'],
                    **{'sponsor/project': row['client']['name']},
                    start_utc=date(row['timeline']['start']), end_utc=date(row['timeline']['end']),
                    date_precision='day', raw_kind=row['kind'], engagement_kind=section,
                    engagement_subtype=section,
                    format=classify(row['title'], row['kind']), access='managed_private',
                    report_url=None, findings_high=None, findings_medium=None, sha256=None,
                    listing_url=MANAGED if section == 'managed_security_review' else PORTFOLIO,
                    finalization_status='published', eligible_public_cohort=False,
                    excluded_reason='managed_review' if section == 'managed_security_review' else 'solo_review')
                contests.append(contest)
            categories = {v['category']: v['count'] for v in row['issues']}
            published_url = row['pdfLink'] if row['pdfLink'] and (row['pdfLink'].startswith('https://cdn.cantina.xyz/') or row['pdfLink'].lower().endswith('.pdf')) else None
            contest.update(report_url=published_url, portfolio_id=row['id'],
                publisher_report_url=row['pdfLink'],
                findings_high=categories.get('high', 0), findings_medium=categories.get('medium', 0),
                findings_count_basis='Official final report portfolio severity groups; omitted H/M category = zero',
                report_join_basis=basis, portfolio_url=PORTFOLIO+'/'+row['id'])
            contest['eligible_public_cohort'] = (section == 'competition' and contest['format'] == 'public_contest'
                                                and contest.get('finalization_status') == 'complete')
            if contest['start_utc'] and contest['end_utc'] and contest['end_utc'] < contest['start_utc']:
                contest.update(raw_period_start=contest['start_utc'], raw_period_end=contest['end_utc'],
                               period_validation='publisher_end_precedes_start; retain measured official end, usable start is unknown', start_utc=None)
            if published_url:
                report_jobs.append((contest, row))
            portfolio_rows.append(dict(portfolio_id=row['id'], contest_id=contest['contest_id'], section=section,
                name=row['title'], sponsor=row['client']['name'], timeline=row['timeline'],
                report_url=row['pdfLink'], issues=row['issues'], join_basis=basis))
    write_jsonl(ROOT/'data/collect/cantina/portfolio.jsonl', portfolio_rows)
    write_jsonl(ROOT/'data/collect/cantina/contests.jsonl', contests)
    for n, (contest, portfolio) in enumerate(report_jobs, 1):
        url = portfolio['pdfLink']
        try:
            note = f"Official {portfolio['kind']} portfolio {portfolio['id']}; contest_id={contest['contest_id']}; {contest['report_join_basis']}."
            try:
                report, body = store_report(client, PLATFORM, contest, url, fmt='pdf', notes=note)
            except RuntimeError as original_error:
                if 'HTTP 404' not in str(original_error) or '/report/' not in url:
                    raise
                repaired = url.replace('/report/', '/reports/')
                report, body = store_report(client, PLATFORM, contest, repaired, fmt='pdf',
                    notes=note+' Official CDN prefix typo corrected after 404; publisher link='+url)
                contest.update(report_url=repaired, report_url_repair_basis='404 at /report/; same filename returns PDF under official /reports/')
            if contest.get('engagement_kind') != 'competition':
                report['doc_kind'] = 'fix_review' if contest['format'] == 'mitigation' else 'audit_report'
                report['date_basis'] = 'listing'
            reports.append(report)
            contest['sha256'] = report['sha256']
        except Exception as exc:
            failures.append(dict(url=url, error=str(exc)))
            print('Cantina report failure: '+url+' '+str(exc), flush=True)
        if n % 25 == 0:
            print(f'Cantina report files processed {n}/{len(report_jobs)}; failures={len(failures)}', flush=True)
            write_jsonl(ROOT/'data/collect/cantina/reports.jsonl', reports)
    summary = summarize(contests)
    # Keep the complete engagement ledger and explicit cohorts for statistics.
    write_jsonl(ROOT/'data/collect/cantina/competitions.jsonl', [c for c in contests if c['engagement_kind'] == 'competition'])
    write_jsonl(ROOT/'data/collect/cantina/reviews.jsonl', [c for c in contests if c['engagement_kind'] != 'competition'])
    placeholder_ids = [r['contest_id'] for r in contests if r.get('portfolio_id') and not r['report_url']]
    evidence = dict(platform=PLATFORM, official_listing_url=LISTING, managed_listing_url=MANAGED,
        portfolio_listing_url=PORTFOLIO, official_listing_groups=groups[0],
        listed_competition_count=len(api), listed_completed_competitions=complete_count,
        listed_live_competitions=live_count, competition_count_matches_official_listing=True,
        listed_managed_review_count=len(managed), managed_listing_matches_portfolio=True,
        listed_solo_review_count=len(solo), listed_competition_report_count=len(comp_reports),
        excluded_spearbit_guild_count=len(spearbit), downloaded_unique_urls=len({r['public_url'] for r in reports}),
        portfolio_placeholder_report_ids=placeholder_ids,
        repaired_report_urls=[dict(contest_id=r['contest_id'], publisher_url=r['publisher_report_url'], public_url=r['report_url']) for r in contests if r.get('report_url_repair_basis')],
        invalid_publisher_period_ids=[r['contest_id'] for r in contests if r.get('period_validation')],
        downloaded_unique_sha256=len({r['sha256'] for r in reports}), report_download_failures=len(failures),
        report_join_gaps=join_gaps, sections=summary,
        source_snapshots=[api_source]+[dict(url=m['url'], sha256=m['sha256'], accessed_at=m['accessed_at']) for m in (pm, mm, lm, em)],
        coverage=dict(contest_listing_complete=True, published_portfolio_reports_complete=not failures,
            final_reports_for_unpublished_competitions_unknown=True,
            limitations='Only published portfolio reports are collected. A completed platform status is not proof of published findings. Private metadata does not expose confidential findings. Portfolio IDs count publisher records, not deduplicated engagements. Spearbit guild excluded as a separate firm; Cantina Solo kept separate. Preserved API snapshot is used read-only because current robots.txt disallows /api/. Dates are original contest periods, not crawl/Git dates.'),
        original_files=sorted({r['local_path'] for r in reports}), collected_utc=utc())
    finish(PLATFORM, contests, reports, failures, [LISTING, ENDED, MANAGED, PORTFOLIO],
           len(api)+len(managed)+len(solo), evidence)
    status_path = ROOT/'data/collect/cantina/status.json'
    status = json.loads(status_path.read_text())
    status['skipped_non_report'] = len(placeholder_ids)
    write_json(status_path, status)
    # A report hosted/listed by Cantina may be published by Spearbit.
    if (ROOT/'data/collect/spearbit/reports.jsonl').exists():
        from publisher_identity import reconcile
        reconcile('spearbit', ['cantina'])


def check():
    out = ROOT/'data/collect/cantina'
    contests, reports = read_jsonl(out/'contests.jsonl'), read_jsonl(out/'reports.jsonl')
    rec, status = [json.loads((out/p).read_text()) for p in ('reconciliation.json', 'status.json')]
    assert len(contests) == status['listed_count']
    assert len({r['contest_id'] for r in contests}) == len(contests)
    assert summarize(contests) == rec['sections']
    assert len(reports) == status['collected'] == rec['downloaded_unique_urls']
    hashes = {r['sha256'] for r in reports}
    for r in reports:
        body = (ROOT/r['local_path']).read_bytes()
        assert body.startswith(b'%PDF-') and len(body) == r['bytes']
        assert hashlib.sha256(body).hexdigest() == r['sha256']
    for c in contests:
        assert c['sha256'] is None or c['sha256'] in hashes
        if c['start_utc'] and c['end_utc']:
            assert c['start_utc'] <= c['end_utc']
    assert not rec['report_join_gaps']
    print(json.dumps(dict(verified=True, contests=len(contests), reports=len(reports), sections=rec['sections']), sort_keys=True))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--offline', action='store_true')
    p.add_argument('--refresh', action='store_true')
    p.add_argument('--check', action='store_true')
    a = p.parse_args()
    check() if a.check else collect(Client(refresh=a.refresh, offline=a.offline))
