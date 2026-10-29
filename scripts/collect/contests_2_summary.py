#!/usr/bin/env python3
"""Offline contract/hash validation and Phase 2c-2 reconciliation document.

Run after all four collectors. --check verifies the generated Markdown/JSON.
Every displayed count is computed from the retained official-source metadata.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
PLATFORMS = ('cantina', 'immunefi', 'hats-finance', 'secure3')
FORMATS = ('public_contest', 'private', 'mitigation', 'bounty_boost', 'other')
REPORT_FIELDS = set('firm_id collector source_kind public_url listing_url sha256 bytes file_format local_path filename title_hint project_hint date_hint date_precision date_basis doc_kind retrieved_utc notes'.split())
CONTEST_FIELDS = set('contest_id platform name sponsor/project start_utc end_utc format report_url findings_high findings_medium sha256'.split())


def read_rows(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def year(row):
    return row['end_utc'][:4] if row['end_utc'] else 'unknown'


def finding_summary(rows):
    return {sev: dict(known=sum(r['findings_'+sev] is not None for r in rows),
                     sum_known=sum(r['findings_'+sev] or 0 for r in rows))
            for sev in ('high', 'medium')}


def table(rows):
    lines = ['| UTC end year | Public contest | Private | Mitigation | Boost | Other | All records | Report cached |',
             '|---|---:|---:|---:|---:|---:|---:|---:|']
    for y in sorted({year(r) for r in rows}):
        sub = [r for r in rows if year(r) == y]
        counts = Counter(r['format'] for r in sub)
        lines.append('| '+' | '.join([y]+[str(counts[f]) for f in FORMATS]+[str(len(sub)), str(sum(bool(r['sha256']) for r in sub))])+' |')
    counts = Counter(r['format'] for r in rows)
    lines.append('| **Total** | '+' | '.join(str(counts[f]) for f in FORMATS)+f" | {len(rows)} | {sum(bool(r['sha256']) for r in rows)} |")
    return '\n'.join(lines)


def build():
    data = {}
    for platform in PLATFORMS:
        base = ROOT/'data/collect'/platform
        cs, rs = read_rows(base/'contests.jsonl'), read_rows(base/'reports.jsonl')
        status, rec = [json.loads((base/p).read_text()) for p in ('status.json', 'reconciliation.json')]
        assert len({r['contest_id'] for r in cs}) == len(cs), platform
        assert len({r['public_url'] for r in rs}) == len(rs), platform
        assert status['collected'] == len(rs) and status['failed'] == len(status['failures'])
        hashes = {r['sha256'] for r in rs}
        for r in cs:
            assert CONTEST_FIELDS <= r.keys(), (platform, r['contest_id'])
            assert r['platform'] == platform and r['format'] in FORMATS
            assert r['sha256'] is None or r['sha256'] in hashes
            for sev in ('high', 'medium'):
                assert r['findings_'+sev] is None or (isinstance(r['findings_'+sev], int) and r['findings_'+sev] >= 0)
            if r['start_utc'] and r['end_utc']:
                assert r['start_utc'] <= r['end_utc'], (platform, r['contest_id'])
        for r in rs:
            assert REPORT_FIELDS <= r.keys(), (platform, r['public_url'])
            assert r['firm_id'] == platform
            assert r['date_precision'] in ('day', 'month', 'year', 'none')
            path = ROOT/r['local_path']
            assert path.is_relative_to(ROOT/'local-cache/originals')
            body = path.read_bytes()
            assert len(body) == r['bytes'] and hashlib.sha256(body).hexdigest() == r['sha256']
            assert path.stem == r['sha256'] and path.parent.name == r['sha256'][:2]
            if r['file_format'] == 'pdf':
                assert body.startswith(b'%PDF-')
            if 'github.com/' in r['public_url']:
                assert re.search(r'/blob/[0-9a-f]{40}/', r['public_url'])
        data[platform] = dict(contests=cs, reports=rs, status=status, reconciliation=rec)

    c, i, h, s = [data[p] for p in PLATFORMS]
    competition_rows = [r for r in c['contests'] if r['engagement_kind'] == 'competition']
    managed = [r for r in c['contests'] if r['engagement_kind'] != 'competition']
    secure_audits = [r for r in s['contests'] if r.get('format_detail') != 'educational_exercise']
    cr, ir, hr, sr = [d['reconciliation'] for d in (c, i, h, s)]
    all_reports = [r for d in data.values() for r in d['reports']]
    interim_urls = {u for row in s['contests'] if row['finalization_status'] == 'interim' for u in row['report_urls']}
    final_reports = [r for r in all_reports if r['doc_kind'] != 'non_report' and r['public_url'] not in interim_urls]
    originals = sorted({r['local_path'] for r in all_reports})
    source_files = [f'scripts/collect/contest_{p.replace("-", "_")}.py' for p in PLATFORMS]
    source_files += ['scripts/collect/contest_common.py', 'scripts/collect/contests_2_summary.py',
                     'docs/collect/contests_2.md', 'data/collect/contests_2_summary.json']
    source_files += [f'data/collect/{p}/{name}' for p in PLATFORMS for name in ('contests.jsonl', 'reports.jsonl', 'status.json', 'reconciliation.json')]
    source_files += ['data/collect/cantina/portfolio.jsonl', 'data/collect/cantina/competition_listing.json']
    summary = dict(platforms={p: dict(records=len(d['contests']), documents=len(d['reports']),
        non_report_documents=sum(r['doc_kind'] == 'non_report' for r in d['reports']),
        end_year_counts=dict(sorted(Counter(year(r) for r in d['contests']).items())),
        formats=dict(sorted(Counter(r['format'] for r in d['contests']).items())),
        findings=finding_summary(d['contests']), listed_count=d['status']['listed_count']) for p, d in data.items()},
        totals=dict(records=sum(len(d['contests']) for d in data.values()),
            contest_and_program_records=len(competition_rows)+len(i['contests'])+len(h['contests'])+len(s['contests']),
            cantina_managed_and_solo_records=len(managed), documents=len(all_reports),
            report_documents=len(final_reports), interim_report_documents=len(sr['interim_contest_ids']),
            non_report_documents=sum(r['doc_kind'] == 'non_report' for r in all_reports),
            unique_originals=len(originals), bytes_unique_originals=sum((ROOT/p).stat().st_size for p in originals)),
        phase_finish_line_met=False, written_files=sorted(source_files), original_files=originals)

    lines = [
        '# Phase 2c-2 — Cantina, Immunefi, Hats Finance and Secure3',
        '', f"Access cutoff: **{max(d['status']['collected_utc'][:10] for d in data.values())} UTC**. Generated by `scripts/collect/contests_2_summary.py` from the manifests and reconciliations. **Partial completion:** Cantina and Immunefi listing metadata reconcile; Immunefi final-file access and the Hats/Secure3 platform denominators remain unresolved.",
        '', '## Counting and collection', '',
        'Tables use official UTC contest end years and retain an unknown bucket. They show listing/archive records by format, including private, mitigation and finite Boost programs separately. They are inventory tables, not a claim that every record is a finalized public engagement. The live Cantina cohort remains separate from completed contests. Ordinary continuous Immunefi bounties and confidential reports are excluded. Exercises are identified explicitly; Secure3’s educational record is excluded from its audit table.',
        '', 'Missing findings are null. Accepted totals use final official severity groups or canonical report entries; submissions, leaderboard totals, duplicates, declined issues, rewards and payout sums never stand in for accepted findings. Critical is retained separately from High. Managed-review dates have day precision; crawl and Git dates never become contest dates. File and portfolio-record counts are not deduplicated engagement counts.',
        '', 'HTTP collectors share a host lock limiting requests to one per second, use a descriptive User-Agent, check robots.txt, and use no authentication or publisher code execution. Originals and source-response caches remain under gitignored `local-cache/`. GitHub report URLs are commit-pinned. **READ-ONLY REVIEW OK** applies only to data intake; this is not execution approval of upstream repositories.',
        '', '## Cantina', '',
        f"Compared [competition listing]({cr['official_listing_url']}) and [ended listing](https://cantina.xyz/opportunities/ended): the preserved [official competition response](https://cantina.xyz/api/v0/competitions) has **{cr['listed_competition_count']} IDs**, matching the current page’s **{cr['listed_completed_competitions']} completed + {cr['listed_live_competitions']} live** counters. That response is read as a preserved snapshot; the collector never requests the currently robots-disallowed API. Its date/digest and the live-page digests are in `data/collect/cantina/reconciliation.json`. The metadata-only source snapshot is retained in `competition_listing.json`. Per-year values below come from those official periods; the page publishes no separate annual aggregate.",
        '', table(competition_rows), '',
        f"[Managed reviews]({cr['managed_listing_url']}) contain **{cr['listed_managed_review_count']} records**, exactly matching the managed section of the [full portfolio]({cr['portfolio_listing_url']}). The portfolio separately exposes **{cr['listed_solo_review_count']} Solo reviews**, included below, and **{cr['listed_competition_report_count']} competition report records**, joined to competition IDs by UUID or official sponsor/period/client evidence. **{cr['excluded_spearbit_guild_count']} Spearbit-guild entries are excluded** as the separate firm’s portfolio.",
        '', '| End year | Managed review | Solo review |', '|---|---:|---:|']
    for y in sorted({year(r) for r in managed}):
        counts = Counter(r['engagement_kind'] for r in managed if year(r) == y)
        lines.append(f"| {y} | {counts['managed_security_review']} | {counts['solo_security_review']} |")
    lines += [f"| **Total** | {cr['listed_managed_review_count']} | {cr['listed_solo_review_count']} |", '',
        f"Cached **{c['status']['collected']} report URLs / {cr['downloaded_unique_sha256']} distinct report hashes**, with **{cr['report_download_failures']} download failures**. The **{len(cr['portfolio_placeholder_report_ids'])}** homepage/self-referencing report placeholders are retained as metadata with no usable report URL. Recovered **{len(cr['repaired_report_urls'])}** official CDN links by correcting `/report/` to `/reports/` after a 404; both URLs and successful PDF hashes are retained. **{len(cr['invalid_publisher_period_ids'])}** reversed publisher period is preserved raw: the measured official end date is retained and the inconsistent usable start is null. Duplicate links remain linked to each publisher ID but are downloaded once. These anomalies and exact IDs are in the reconciliation.",
        '', '## Immunefi', '',
        f"Compared the [official audit competition listing]({ir['official_listing_url']}): **{ir['listed_count']} rendered canonical slugs = {ir['collected_contest_count']} structured records**, with Boost aliases merged. All official detail pages were inspected for summary links. The listing marks all retained records finished; the separate formats below preserve IOP/private, mitigation, finite Boosts and attackathons.",
        '', table(i['contests']), '',
        f"The publisher supplies **{ir['final_summary_links']} final-summary links**; **{ir['collected_final_summaries']} PDF** is cached. **{sum(e.get('error_type') == 'robots_disallowed' for e in ir['gaps']['final_summary_download_failures'])}** public Drive viewers expose downloads disallowed by robots.txt, so their URLs and failures are retained without bypass. **{len(ir['gaps']['contests_without_linked_final_summary'])} contests** have no verified final-summary link. **{ir['downloaded_result_documents']} result indexes** are also cached, explicitly `doc_kind=non_report`; their submission severity lists do not establish accepted findings. The downloaded summary states zero High; its combined Low/Medium category leaves Medium unknown. Exact missing contest IDs, viewer links, sample submission-state checks and document hashes are in the reconciliation.",
        '', '## Hats Finance', '',
        f"The [official competition app](https://app.hats.finance/audit-competitions) fails DNS resolution, the website competition route returns 404, and the frontend’s published production-service robots endpoint fails. The [official organization listing](https://github.com/orgs/hats-finance/repositories?type=all) reconciles **{hr['organization_pagination']['enumerated_repositories']} repositories across {hr['organization_pagination']['pages']} pages**. That is a repository denominator, not a competition denominator. Only an explicit final competition report establishes a retained contest; vault repository existence alone is insufficient.",
        '', table(h['contests']), '',
        f"Cached **{len(h['reports'])} final reports**. All retained contest years remain unknown: duration-only statements and a month/day range without year/timezone are preserved without inventing UTC periods. Official report sections supply **{finding_summary(h['contests'])['high']['sum_known']} High** across **{finding_summary(h['contests'])['high']['known']} known High categories** and **{finding_summary(h['contests'])['medium']['sum_known']} Medium** across **{finding_summary(h['contests'])['medium']['known']} known Medium categories**; these are partial observed totals. Palmera retains a report-prose validity caveat with its raw canonical section count. Candidate/exclusion classifications, raw period evidence and pinned canonical issue/line locators are retained in the reconciliation and contest rows. **The full contest denominator and annual reconciliation remain unverified.**",
        '', '## Secure3', '',
        f"The [official contest URL](https://secure3.io/contest/) and app route return the marketing homepage; the official reports route leads to an unavailable archive, and the frontend enum endpoint returns an internal-error envelope. The [official GitHub organization](https://github.com/orgs/Secure3Audit/repositories) reconciles **{sr['github_organization']['measured_repository_count']} repositories across {sr['github_organization']['page_count']} page(s)**. **{len(secure_audits)} audit contests** have explicit official repository/report evidence; **{len(s['contests'])-len(secure_audits)} educational exercise** is retained separately and excluded below. Public report release does not prove public participation, so access remains unknown (`format=other`).",
        '', table(secure_audits), '',
        f"Cached **{len(s['reports'])} PDFs**, including **{len(sr['interim_contest_ids'])} explicitly interim ParaSpace report** and **{sr['released_non_interim_report_contests']} non-interim released reports**. Mantle V2 and Parity-subxt have official contest IDs but no released report in the inspected archive. Final severity/status tables yield **{finding_summary(s['contests'])['medium']['sum_known']} accepted Medium findings**, calculated as Acknowledged + Fixed + Mitigated, excluding Reported/Declined. The tables have no High row, so High stays null and Critical remains separate. PDF cover dates do not establish contest periods. **The full platform denominator and annual reconciliation remain unverified.**",
        '', '## Totals and reproduction', '',
        f"Retained **{summary['totals']['contest_and_program_records']} contest/program records** (including separately identified exercises) and **{len(managed)} Cantina managed/Solo portfolio records**. Cached **{len(all_reports)} document rows**: **{len(final_reports)} report documents**, **{len(sr['interim_contest_ids'])} interim report**, and **{summary['totals']['non_report_documents']} non-report indexes**. They resolve to **{len(originals)} distinct cached originals**, totaling **{summary['totals']['bytes_unique_originals']} bytes**. No originals are added to Git. These totals describe this inventory, not industry or complete platform totals.",
        '', '```sh',
        'python3 -I scripts/collect/contest_cantina.py --offline',
        'python3 -I scripts/collect/contest_immunefi.py --offline',
        'python3 -I scripts/collect/contest_hats_finance.py --offline',
        'python3 -I scripts/collect/contest_secure3.py --offline',
        'python3 -I scripts/collect/contest_cantina.py --check',
        'python3 -I scripts/collect/contest_immunefi.py --check',
        'python3 -I scripts/collect/contest_hats_finance.py --check',
        'python3 -I scripts/collect/contests_2_summary.py --check', '```', '',
        'Normal collector runs fetch only missing cached responses; `--refresh` explicitly refreshes permitted sources. Offline replay requires the local source-response cache. The final check verifies required fields, distinct IDs/URLs, hash-addressed original paths, original hashes/byte sizes/PDF signatures, GitHub revision pins, valid periods, status arithmetic and exact regeneration of this document. Individual collectors also verify source pagination/listing joins and their severity evidence. No confidential bounty reports or publisher tooling were accessed or executed.',
        '', 'The release-file list and every collected original path are enumerated in [`data/collect/contests_2_summary.json`](../../data/collect/contests_2_summary.json). Per-platform manifests also enumerate each original. Source-response cache files are local operational state under gitignored `local-cache/contest-http/`.',
        '', '**Finish line not met:** obtain a working official historical export with periods for Hats and Secure3, permitted Immunefi final-summary files, and evidence for any still-unpublished final reports. Missing coverage is explicitly preserved; it is never reported as a market zero.', '']
    return '\n'.join(lines), summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--check', action='store_true')
    a = p.parse_args()
    text, summary = build()
    doc, output = ROOT/'docs/collect/contests_2.md', ROOT/'data/collect/contests_2_summary.json'
    serialized = json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True)+'\n'
    if a.check:
        assert doc.read_text() == text and output.read_text() == serialized
    else:
        doc.parent.mkdir(parents=True, exist_ok=True)
        doc.write_text(text)
        output.write_text(serialized)
    print(json.dumps(dict(verified=True, **summary['totals']), sort_keys=True))


if __name__ == '__main__':
    main()
