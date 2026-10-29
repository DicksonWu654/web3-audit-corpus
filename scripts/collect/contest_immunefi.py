#!/usr/bin/env python3
"""Collect public Immunefi competition metadata and published result indexes.

Only data is fetched. Result indexes include invalid/duplicate submissions and
are not adjudicated finding totals. Perpetual bounties are never enumerated.
"""
import argparse
from collections import Counter
import hashlib
import html
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contest_common import (Client, ROOT, finish, flight_objects, github_urls,
                            iso, objects, read_jsonl, store_report, utc)

PLATFORM = 'immunefi'
LISTING = 'https://immunefi.com/audit-competition/'
INDEX = 'https://reports.immunefi.com/llms.txt'
REPO = 'immunefi-team/Past-Audit-Competitions'
REPO_URL = 'https://github.com/' + REPO
# Explicit alias join: publisher result titles differ from competition slugs.
# Missing aliases remain visible gaps instead of speculative project/date joins.
ALIASES = dict(line.split('=', 1) for line in '''alchemix-boost=alchemix
ebtc-boost=badgerdao-ebtc
boosteddegatebugbounty=degate
firedancer-boost=firedancer-v0.1
folksfinance-boost=folks-finance
fuel-network-attackathon=fuel-network-or-attackathon
boost-idex=idex
immunefiarbitration-boost=immunefi-arbitration
boost-lido=lido-mellow-vault
mitigation-audit-folksfinance=mitigation-audit-or-folks-finance
pufferfinance-boost=puffer-finance
shardeum-ancillaries-boost=shardeum-ancillaries
shardeum-core-boost=shardeum-core
thundernft-iop=thundernft-or-iop
zerolend-boost=zerolend
iop-swaylend=swaylend_iop
boost-acre=acre
shardeum-core-ii-boost=shardeum-core-ii
shardeum-ancillaries-ii-boost=shardeum-ancillaries-ii
audit-comp-anvil=anvil
audit-comp-anvil-letters-of-credit=anvil-letters-of-credit
iop-fluid-protocol=fluid-protocol
folks-finance-liquid-staking-audit-competition=folks-liquid-staking
jito-restaking-audit-competition=jito-restaking
swaylend-frontend-iop=swaylend-frontend
audit-comp-celo=celo
stacks-attackathon-1=stacks-i-attackathon
audit-comp-lombard=lombard
audit-comp-butter=butter
iop-zano=zano-iop
audit-comp-shardeum-ancillaries-iii=shardeum-ancillaries-iii
audit-comp-yeet=yeet
audit-comp-shardeum-core-iii=shardeum-core-iii
ethereum-protocol-attackathon=ethereum-protocol-or-attackathon
stacks-attackathon-2=stacks-ii-attackathon
movement-labs-attackathon=movement-labs-attackathon
iop-circuitdao=circuitdaoiop
audit-comp-spectra-finance=spectra-finance
iop-term-structure=term-structure-institutional_iop
iop-zano-trade=zano-trade-iop
iop-paradex=iop-paradex
audit-comp-flare-fassets=flare-fassets-or-mainnet-audit-comp
flare-fassets--mitigation-audit=flare-fassets-or-mitigation-audit
folks-sc-library=folks-smart-contract-library
audit-comp--folks-finance-wormhole-ntt-on-algorand=folks-finance-wormhole-ntt-on-algorand
plume-network-attackathon=plume-or-attackathon
vechain-hayabusa-upgrade-attackathon=vechain-hayabusa-upgrade-or-attackathon
audit-comp-firelight=firelight
audit-comp-vechain-stargate-hayabusa=vechain-or-stargate-hayabusa
audit-comp-belong=belong
alchemix-v3-audit-competition=alchemix-v3
audit-comp-folks-finance-staking-contracts=folks-finance-staking-contracts
audit-comp-base-azul=base
audit-comp-quantus=quantus-or-audit-competition
audit-comp-firelight-1=firelight-sep.2026-or-audit-competition
audit-competition-ens=ens-or-audit-competition'''.splitlines())


def result_links(text):
    # Select only direct child pages: never infer submissions are findings.
    return sorted(set(re.findall(r'\(https://reports\.immunefi\.com/([^/()]+)\.md\)', text)) - {'readme'})


def github_metadata(client):
    """Use ordinary public HTML when the API robots endpoint is unavailable."""
    meta, body = client.get(REPO_URL)
    if meta['status'] != 200:
        raise RuntimeError('GitHub repository page HTTP ' + str(meta['status']))
    for script in re.findall(r'<script[^>]*type="application/json"[^>]*>(.*?)</script>', body.decode(), re.S):
        try:
            route = json.loads(script)['payload']['codeViewRepoRoute']
        except (KeyError, ValueError, TypeError):
            continue
        commit = route['refInfo']['currentOid']
        if not re.fullmatch(r'[a-f0-9]{40}', commit):
            raise ValueError('Invalid official GitHub commit')
        public, raw = github_urls(REPO, commit, 'SUMMARY.md')
        summary = client.body(raw).decode()
        # Top-level only, preserving paths with spaces and pipes.
        tops = []
        for line in summary.splitlines():
            if line.startswith('* ') and '/README.md' in line:
                name, path = line[3:].rsplit('](', 1)
                tops.append(dict(title=name, path=path[:-1].strip('<>')))
        return dict(url=REPO_URL, sha256=meta['sha256'], commit=commit,
                    summary_url=public, competition_result_indexes=tops,
                    result_index_count=len(tops),
                    note='Pinned SUMMARY.md enumerated as data; upstream scripts and dependencies never run.')
    raise ValueError('GitHub public route metadata absent')


def classify(record):
    slug, title = record['slug'], record['project'].lower()
    if 'mitigation' in title or 'mitigation' in slug:
        return 'mitigation'
    # IOP titles are authoritative even where inviteOnly is incorrectly false.
    if record.get('inviteOnly') or title.startswith('iop |') or slug.endswith('-iop'):
        return 'private'
    if 'boost' in slug or 'bug-bounty-competition' in slug:
        return 'bounty_boost'
    return 'public_contest'


def summarize(contests):
    return dict(per_year_end_utc=dict(sorted(Counter(c['end_utc'][:4] if c['end_utc'] else 'unknown' for c in contests).items())),
                formats=dict(sorted(Counter(c['format'] for c in contests).items())),
                finalization_statuses=dict(sorted(Counter(c['finalization_status'] for c in contests).items())))


def detail_evidence(client, url):
    meta, body = client.get(url)
    if meta['status'] != 200:
        raise RuntimeError('Detail HTTP ' + str(meta['status']))
    text = body.decode()
    fields = {}
    decoder = json.JSONDecoder()
    # Some Flight records span text frames and cannot be parsed as whole JSON
    # objects. Decode only named JSON values in the ordinary public payload.
    for match in re.finditer(r'self\.__next_f\.push\((\[.*?\])\)</script>', text, re.S):
        for payload in json.loads(match[1]):
            if not isinstance(payload, str):
                continue
            for field in ('boostedSummaryReport', 'findingsUrl', 'boostedIntroFinished'):
                for found in re.finditer('"' + field + r'"\s*:\s*', payload):
                    fields[field] = decoder.raw_decode(payload[found.end():])[0]
    links = sorted(set(re.findall(r'https://immunefi\.com/blog/[^\s<>"\\)]+', text)) - {'https://immunefi.com/blog/research/'})
    return dict(url=url, sha256=meta['sha256'], accessed_at=meta['accessed_at'],
                summary_report_url=fields.get('boostedSummaryReport'),
                findings_url=fields.get('findingsUrl'), linked_official_wrapups=links,
                finished_intro=fields.get('boostedIntroFinished'))


def summary_document(client, contest, url):
    """Follow the publicly exposed viewer download link, subject to robots."""
    evidence = dict(url=url)
    download = url
    if url.startswith('https://reports.immunefi.com/'):
        evidence.update(document_kind='published_submission_index',
                        error_type='source_not_summary',
                        error='Publisher summary field points to a submission index, not a final summary')
        return None, evidence
    if url.startswith('https://drive.google.com/drive/folders/'):
        meta, body = client.get(url)
        text = body.decode()
        project = re.sub(r'[^a-z0-9]+', ' ', contest['sponsor/project'].lower()).strip()
        candidates = []
        for file_id, title in re.findall(r'data-id="([^"<>]+)"[^>]*data-tooltip="([^"<>]+)"', text):
            normalized = re.sub(r'[^a-z0-9]+', ' ', html.unescape(title).lower()).strip()
            if project in normalized and 'summary report' in normalized:
                candidates.append((file_id, html.unescape(title)))
        candidates = sorted(set(candidates))
        if len(candidates) != 1:
            evidence.update(folder_sha256=meta['sha256'],
                            error='Public summary folder does not expose exactly one matching summary PDF')
            return None, evidence
        file_id, title = candidates[0]
        resolved = 'https://drive.google.com/file/d/' + file_id + '/view'
        row, child = summary_document(client, contest, resolved)
        child.update(publisher_folder_url=url, folder_sha256=meta['sha256'],
                     resolved_public_url=resolved, folder_file_title=title)
        return row, child
    if url.startswith('https://docs.google.com/presentation/d/'):
        download = re.sub(r'/edit(?:\?.*)?$', '/export/pdf', url)
        evidence['download_url'] = download
        meta, body = client.get(url)
        title = re.search(r'<title>(.*?)</title>', body.decode(), re.S)
        evidence.update(viewer_sha256=meta['sha256'],
                        title=html.unescape(title[1]).removesuffix(' - Google Slides') if title else None)
        # Preserve the publisher's direct overview statement. Do not sum its
        # per-researcher leaderboard, which may include duplicate reports.
        statements = re.findall(r'During this event, [^"<>]+?target contracts\.', body.decode())
        evidence['official_overview_statements'] = statements
    if url.startswith('https://drive.google.com/file/d/'):
        meta, body = client.get(url)
        if meta['status'] != 200:
            raise RuntimeError('Public summary viewer HTTP ' + str(meta['status']))
        text = body.decode()
        title = re.search(r'<title>(.*?)</title>', text, re.S)
        evidence.update(viewer_sha256=meta['sha256'],
                        title=title[1] if title else None,
                        pdf_mime_declared='application/pdf' in text)
        link = re.search(r'https://drive\.usercontent\.google\.com/uc[^"<>\s]+', text)
        if not link:
            evidence['error'] = 'Public viewer exposes no downloadable document link'
            return None, evidence
        download = json.loads('"' + link[0] + '"')
        evidence['download_url'] = download
    try:
        # Explicitly reapply captured robots rules even for offline rebuilds;
        # an absent cached download must retain its real access-block reason.
        client.allowed(download)
        row, _ = store_report(client, PLATFORM, contest, url, download_url=download,
                              fmt='pdf', notes='Official competition summary linked by boostedSummaryReport on the publisher detail page.')
        if evidence.get('title'):
            row['filename'] = evidence['title'] + ('' if evidence['title'].lower().endswith('.pdf') else '.pdf')
        evidence['pdf_sha256'] = row['sha256']
        return row, evidence
    except Exception as exc:
        evidence['error'] = str(exc)
        evidence['error_type'] = 'robots_disallowed' if 'robots.txt disallows' in str(exc) else 'download_error'
        return None, evidence


def sample_submission_evidence(client):
    # A bounded sample tests whether nested public reports expose final state.
    urls = [
        'https://reports.immunefi.com/alchemix/30555-sc-low-precision-loss-when-calculating-the-flux-amount....md',
        'https://reports.immunefi.com/alchemix/30634-sc-critical-unauthorized-minting-of-unlimited-flux-in-tran....md',
    ]
    index = client.body(INDEX).decode()
    fuel = sorted(set(re.findall(r'https://reports\.immunefi\.com/fuel-network-or-attackathon/[^()\s]+\.md', index)))
    if fuel:
        urls.append(fuel[0])
    samples = []
    for url in urls:
        meta, body = client.get(url)
        if meta['status'] != 200:
            samples.append(dict(url=url, error='HTTP ' + str(meta['status'])))
            continue
        lines = body.decode().splitlines()
        state = [line for line in lines if re.match(r'(?i)^(?:#{1,4} )?(?:report status|status|validity|resolution|duplicate|invalid|reward|payout)\s*:', line)]
        samples.append(dict(url=url, sha256=meta['sha256'],
                            final_adjudication_fields=state,
                            reason='Sample exposes submitted date, report ID and reported severity; no explicit final adjudication/status field found.' if not state else 'State fields require individual interpretation; no automatic accepted-findings count.'))
    return samples


def collect(client):
    failures, sources, contests, reports = [], [], [], []
    lm, lb = client.get(LISTING)
    if lm['status'] != 200:
        raise RuntimeError('Official competition listing unavailable')
    sources.append(dict(url=LISTING, sha256=lm['sha256'], accessed_at=lm['accessed_at']))
    text = lb.decode()
    listed_slugs = set(re.findall(r'href="/audit-competition/([^/"?#]+)/', text))
    records = {o['slug']: o for f in flight_objects(text) for o in objects(f)
               if 'slug' in o and 'endDate' in o and 'auditCompetitionStatus' in o}
    if set(records) != listed_slugs:
        raise ValueError('Structured metadata and rendered listing disagree: ' + repr(sorted(set(records) ^ listed_slugs)))
    im, ib = client.get(INDEX)
    if im['status'] != 200:
        raise RuntimeError('Official result index unavailable')
    sources.append(dict(url=INDEX, sha256=im['sha256'], accessed_at=im['accessed_at']))
    top_pages = set(result_links(ib.decode()))
    if len(set(ALIASES.values())) != len(ALIASES):
        raise ValueError('Alias collision')
    unmatched_pages = sorted(top_pages - {v for k, v in ALIASES.items() if k in records})
    github = None
    try:
        github = github_metadata(client)
    except Exception as exc:
        failures.append(dict(url=REPO_URL, error=str(exc)))
    missing_reports, download_gaps, details, summary_evidence = [], [], [], []
    for slug, o in sorted(records.items()):
        fmt = classify(o)
        contest = dict(contest_id=slug, platform=PLATFORM, name=o['project'],
                       **{'sponsor/project': o['project'].partition(' | ')[2] or o['project']},
                       start_utc=iso(o.get('launchDate')), end_utc=iso(o.get('endDate')),
                       format=fmt, report_url=None, findings_high=None, findings_medium=None,
                       sha256=None, listing_url='https://immunefi.com' + o['url'],
                       finalization_status=o['auditCompetitionStatus'],
                       evaluation_end_utc=iso(o.get('evaluationEndDate')),
                       access='invite_only' if fmt == 'private' else 'public',
                       raw_features=o.get('features', []),
                       result_document_kind=None, final_report_status='not_located',
                       result_index_url=None, result_index_sha256=None,
                       publisher_summary_url=None,
                       findings_count_basis='unknown; result indexes are not unique accepted findings')
        page = ALIASES.get(slug)
        if page in top_pages:
            url = 'https://reports.immunefi.com/' + page + '.md'
            contest['result_index_url'] = url
            try:
                row, body = store_report(client, PLATFORM, contest, url, fmt='md',
                    notes='Official published competition results index, not a final adjudicated audit report. '
                          'Contains submission titles grouped by severity, including duplicates and invalids. '
                          'Accepted unique finding counts are unknown. No nested submission pages collected.')
                if b'## Reports by Severity' not in body:
                    raise ValueError('Expected competition results heading absent')
                row['doc_kind'] = 'non_report'
                reports.append(row)
                contest.update(result_index_sha256=row['sha256'], result_document_kind='published_submission_index',
                               final_report_status='results_index_only')
            except Exception as exc:
                failures.append(dict(url=url, error=str(exc)))
                download_gaps.append(slug)
        else:
            missing_reports.append(slug)
        try:
            detail = detail_evidence(client, contest['listing_url'])
            detail['contest_id'] = slug
            details.append(detail)
            summary_url = detail['summary_report_url']
            if summary_url:
                contest['publisher_summary_url'] = summary_url
                contest['report_url'] = summary_url
                row, evidence = summary_document(client, contest, summary_url)
                evidence['contest_id'] = slug
                summary_evidence.append(evidence)
                if row:
                    reports.append(row)
                    contest.update(sha256=row['sha256'], final_report_status='summary_pdf_collected')
                    if evidence.get('official_overview_statements'):
                        statement = evidence['official_overview_statements'][0]
                        high = re.search(r'(\d+) high', statement)
                        # A direct zero is unaffected by duplicate ambiguity.
                        if high and int(high[1]) == 0:
                            contest.update(findings_high=0,
                                findings_count_basis='Official summary overview directly states zero high; low/medium combined, so medium remains unknown.')
                else:
                    contest['final_report_status'] = 'summary_linked_download_failed'
                    failures.append(dict(url=summary_url, error=evidence['error']))
                if evidence.get('resolved_public_url'):
                    contest['report_url'] = evidence['resolved_public_url']
                if evidence.get('document_kind') == 'published_submission_index':
                    contest.update(report_url=None, final_report_status='results_index_only')
        except Exception as exc:
            failures.append(dict(url=contest['listing_url'], error=str(exc)))
        contests.append(contest)
    summary = summarize(contests)
    reconciliation = dict(platform=PLATFORM, official_listing_url=LISTING,
        listed_count=len(listed_slugs), collected_contest_count=len(contests),
        contest_count_matches_official_listing=len(contests) == len(listed_slugs),
        published_result_index_count=len(top_pages), downloaded_result_documents=sum(r['doc_kind'] == 'non_report' for r in reports),
        downloaded_documents=len(reports),
        final_summary_links=sum(bool(c['report_url']) for c in contests),
        publisher_summary_field_links=sum(bool(c['publisher_summary_url']) for c in contests),
        collected_final_summaries=sum(c['final_report_status'] == 'summary_pdf_collected' for c in contests),
        original_files=sorted(r['local_path'] for r in reports),
        **summary, sources=sources, github=github,
        detail_sources=details, summary_sources=summary_evidence,
        official_linked_wrapup_urls=sorted(set(u for d in details for u in d['linked_official_wrapups'])),
        submission_samples=sample_submission_evidence(client),
        gaps=dict(missing_contest_ids=sorted(listed_slugs-set(records)),
                  contests_without_published_result_index=missing_reports,
                  result_index_download_failures=download_gaps,
                  unmatched_official_result_pages=unmatched_pages,
                  contests_without_linked_final_summary=sorted(c['contest_id'] for c in contests if not c['report_url']),
                  contests_without_collected_final_summary=sorted(c['contest_id'] for c in contests if not c['sha256']),
                  final_summary_download_failures=[e for e in summary_evidence if e.get('error')],
                  contests_without_accepted_findings_counts=sorted(c['contest_id'] for c in contests if c['findings_high'] is None or c['findings_medium'] is None)),
        coverage=dict(contest_listing_complete=True, final_report_collection_complete=False,
          scope='Official audit-competition listing, including finite Boosts/attackathons and separately labelled IOP/mitigation programs. No perpetual bounty inventory.',
          format_basis='mitigation title; IOP title/inviteOnly -> private; historical boost/bug-bounty-competition slug -> bounty_boost; other audit/attackathon -> public_contest',
          count_unit='One canonical competition slug, Boost route aliases merged.',
          private_program_policy='Only metadata explicitly published on competition listing and published result landing documents; no confidential submissions.',
          limitations='Published submission indexes are non_report. Final summary links are taken from the official boostedSummaryReport detail field. Public viewer download links are followed only when robots permits. Leaderboard severity sums include duplicates and are not accepted unique findings. Missing counts stay null.'),
        collected_utc=utc())
    finish(PLATFORM, contests, reports, failures, [LISTING, INDEX, REPO_URL], len(listed_slugs), reconciliation)


def check():
    out = ROOT / 'data/collect' / PLATFORM
    contests, reports = read_jsonl(out/'contests.jsonl'), read_jsonl(out/'reports.jsonl')
    status, rec = (json.loads((out/p).read_text()) for p in ('status.json', 'reconciliation.json'))
    assert len(contests) == status['listed_count'] == rec['listed_count']
    assert len({c['contest_id'] for c in contests}) == len(contests)
    assert len(reports) == status['collected'] == rec['downloaded_documents']
    assert status['failed'] == len(status['failures'])
    assert rec['collected_final_summaries'] == sum(c['sha256'] is not None for c in contests)
    assert len(rec['detail_sources']) == len(contests)
    assert summarize(contests)['per_year_end_utc'] == rec['per_year_end_utc']
    assert summarize(contests)['formats'] == rec['formats']
    assert rec['gaps']['contests_without_published_result_index'] == sorted(c['contest_id'] for c in contests if c['result_index_url'] is None)
    assert rec['original_files'] == sorted(r['local_path'] for r in reports)
    hashes = {r['sha256'] for r in reports}
    for c in contests:
        assert c['findings_high'] in (None, 0) and c['findings_medium'] is None
        assert c['sha256'] is None or c['sha256'] in hashes
        assert c['result_index_sha256'] is None or c['result_index_sha256'] in hashes
        assert c['start_utc'] and c['end_utc'] and c['start_utc'] < c['end_utc']
    for r in reports:
        assert all(k in r for k in ('firm_id', 'collector', 'source_kind', 'public_url', 'listing_url', 'sha256', 'bytes', 'file_format', 'local_path', 'filename', 'title_hint', 'project_hint', 'date_hint', 'date_precision', 'date_basis', 'doc_kind', 'retrieved_utc', 'notes'))
        body = (ROOT/r['local_path']).read_bytes()
        assert hashlib.sha256(body).hexdigest() == r['sha256']
        assert len(body) == r['bytes'] and r['file_format'] in ('md', 'pdf')
        if r['file_format'] == 'md':
            assert r['doc_kind'] == 'non_report'
        if 'github.com/' in r['public_url']:
            assert re.search(r'/blob/[0-9a-f]{40}/', r['public_url'])
    print(json.dumps(dict(verified=True, contests=len(contests), documents=len(reports),
                         **summarize(contests), final_summary_links=rec['final_summary_links'],
                         collected_final_summaries=rec['collected_final_summaries'],
                         result_indexes=rec['downloaded_result_documents'],
                         detail_sources=len(rec['detail_sources']),
                         summary_failure_types=dict(sorted(Counter(e.get('error_type', 'other') for e in rec['gaps']['final_summary_download_failures']).items())),
                         submission_samples=len(rec['submission_samples']),
                         missing_summary_links=rec['gaps']['contests_without_linked_final_summary'],
                         summary_download_failures=len(rec['gaps']['final_summary_download_failures'])), sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--check', action='store_true', help='Verify stored contract rows and original hashes offline')
    opts = parser.parse_args()
    # The coverage repair preserves recovered client mirrors and exposes
    # metadata-only engagements; the historical collector below used to replace
    # enriched receipts and mixed contest totals with index-document totals.
    from coverage_immunefi import discover, enrich, verify
    if opts.check:
        verify()
    else:
        discover(opts.refresh, opts.offline)
        enrich(opts.refresh, opts.offline)
        verify()


if __name__ == '__main__':
    main()
