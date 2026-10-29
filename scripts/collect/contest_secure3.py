#!/usr/bin/env python3
"""Collect Secure3's publicly evidenced historical contest archive.

GitHub HTML's embedded JSON is read as data (no checkout or publisher code).
The organization's repository count is NOT treated as its contest denominator.
Public release of a report does not establish open participation in its contest.
"""
import collections
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import sys
import urllib.parse
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contest_common import Client, ROOT, args, finish, github_urls, store_report, utc, write_json

ORG = 'https://github.com/orgs/Secure3Audit/repositories'
HOME = 'https://secure3.io/'
FAQ = 'https://docs.secure3.io/faqs.md'
LISTINGS = ['https://secure3.io/contest/', HOME, 'https://app.secure3.io',
            'https://secure3.io/reports', ORG, FAQ]


def embedded(body, key):
    for value in re.findall(r'<script[^>]*type="application/json"[^>]*>(.*?)</script>',
                            body.decode('utf-8'), re.S):
        payload = json.loads(value).get('payload', {})
        if key in payload:
            return payload[key]
    raise ValueError('GitHub HTML has no ' + key)


def readme_time(text, label):
    match = re.search(label + r' on:\s*`([^`]+)`', text)
    if not match:
        return None
    return dt.datetime.strptime(match[1], '%b %d, %Y - %H:%M UTC').replace(
        tzinfo=dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def pdf_evidence_text(body):
    """Bounded text evidence for these PDFs; never execute PDF actions or code.

    Supports literal strings and 16-bit Identity-H strings with explicit ToUnicode
    bfchar/bfrange maps. Ambiguous font aliases and unsupported glyphs stay unknown.
    This is deliberately not a general PDF parser or a findings-body extractor.
    """
    objects = dict(re.findall(rb'(?m)^(\d+) 0 obj\b(.*?)\bendobj\b', body, re.S))
    if len(objects) > 10000:
        return ''
    streams, total = {}, 0
    for oid, value in objects.items():
        match = re.search(rb'stream\r?\n(.*?)\r?\nendstream', value, re.S)
        if not match or b'/Subtype /Image' in value[:match.start()]:
            continue
        if b'/FlateDecode' in value[:match.start()]:
            try:
                value = zlib.decompressobj().decompress(match[1], 4_000_001)
            except zlib.error:
                continue
        elif b'/Filter' not in value[:match.start()]:
            value = match[1]
        else:
            continue
        if len(value) > 4_000_000:
            continue
        total += len(value)
        if total > 24_000_000:
            return ''
        streams[oid] = value
    cmaps = {}
    for oid, value in objects.items():
        ref = re.search(rb'/ToUnicode\s+(\d+) 0 R', value)
        if not ref or b'/Identity-H' not in value:
            continue
        mapping = {}
        cmap = streams.get(ref[1], b'')
        for section in re.findall(rb'beginbfchar(.*?)endbfchar', cmap, re.S):
            for source, dest in re.findall(rb'<([0-9a-fA-F]{4})>\s*<([0-9a-fA-F]+)>', section):
                try:
                    mapping[int(source, 16)] = bytes.fromhex(dest.decode()).decode('utf-16-be')
                except (ValueError, UnicodeError):
                    continue
        for section in re.findall(rb'beginbfrange(.*?)endbfrange', cmap, re.S):
            for lo, hi, dest in re.findall(rb'<([0-9a-fA-F]{4})>\s*<([0-9a-fA-F]{4})>\s*<([0-9a-fA-F]{4})>', section):
                start, end, base = int(lo, 16), int(hi, 16), int(dest, 16)
                if end - start > 512 or base + end - start > 0xffff:
                    continue
                for source in range(start, end + 1):
                    mapping[source] = chr(base + source - start)
        cmaps[oid] = mapping
    aliases = collections.defaultdict(set)
    for value in objects.values():
        for font_dict in re.findall(rb'/Font\s*<<(.*?)>>', value, re.S):
            for alias, oid in re.findall(rb'/([A-Za-z][A-Za-z0-9]*)\s+(\d+) 0 R', font_dict):
                aliases[alias].add(oid)
    font_maps = {name: cmaps.get(next(iter(ids)), {}) for name, ids in aliases.items() if len(ids) == 1}
    result = []
    tokens = rb'/([A-Za-z][A-Za-z0-9]*)\s+[0-9.]+\s+Tf|<([0-9a-fA-F\s]+)>|\(((?:\\.|[^\\)])*)\)'
    for stream in streams.values():
        for block in re.findall(rb'BT\s+(.*?)\s+ET', stream, re.S):
            font, parts = None, []
            for token in re.finditer(tokens, block, re.S):
                if token[1]:
                    font = token[1]
                elif token[2]:
                    value = re.sub(rb'\s+', b'', token[2])
                    if len(value) % 4:
                        parts.append('\ufffd')
                    else:
                        mapping = font_maps.get(font, {})
                        parts.append(''.join(mapping.get(int(value[i:i + 4], 16), '\ufffd') for i in range(0, len(value), 4)))
                else:
                    value = re.sub(rb'\\([()\\])', rb'\1', token[3])
                    parts.append(value.decode('latin1'))
            if parts:
                result.append(''.join(parts))
    return '\n'.join(result)


def pdf_summary_evidence(body, public_url, filename):
    text = re.sub(r'\s+', ' ', pdf_evidence_text(body)).strip()
    # Some PDF text objects split the initial capital from the rest of a word.
    text = re.sub(r'V\s+ulnerability', 'Vulnerability', text)
    text = re.sub(r'T\s+otal', 'Total', text)
    interim = bool(re.search(r'\binterim\b', filename.replace('_', ' '), re.I))
    period_candidates = re.findall(r'\b(?:audit|contest)\s+(?:period|duration|start|end|time)\b.{0,160}|\b(?:starts?|ends?)\s+on\s*:?.{0,120}', text, re.I)
    evidence = dict(public_url=public_url, parser='bounded_pdf_literal_or_identity_h_tounicode_v1',
                    finalization_status='interim' if interim else 'report_released',
                    interim_basis='Official filename states Interim Audit Update Subject To Change; document findings remain Reported with Client Response TBD.' if interim else None,
                    interim_excerpt=text[:650] if interim else None,
                    summary_rows={}, accepted_counts={}, summary_excerpt=None,
                    contest_period=None,
                    period_label_candidates=period_candidates,
                    period_note=('Possible period labels require verification; no UTC contest period established.' if period_candidates else 'No explicit labelled contest period recovered from the document text. Cover/report dates are not substituted for contest end dates.'))
    header = re.search(r'Vulnerability\s+Level\s+Total\s+Reported\s+(?:Acknowledged|Acknowleged)\s+Fixed\s+Mitigated(\s+Declined)?\s+', text)
    if not header:
        evidence['summary_note'] = 'No complete severity/status summary table recovered; accepted counts remain unknown.'
        return evidence
    columns = ['total', 'reported', 'acknowledged', 'fixed', 'mitigated']
    if header[1]:
        columns.append('declined')
    position = header.end()
    while True:
        row = re.match(r'(Critical|High|Medium|Low|Informational)\s+' + r'(\d+)\s+' * len(columns), text[position:])
        if not row:
            break
        values = dict(zip(columns, map(int, row.groups()[1:])))
        if values['total'] != sum(value for key, value in values.items() if key != 'total'):
            evidence['summary_note'] = 'Severity/status row arithmetic failed; accepted counts remain unknown.'
            evidence['summary_rows'] = {}
            return evidence
        evidence['summary_rows'][row[1]] = values
        position += row.end()
    if len(evidence['summary_rows']) < 3 or 'Medium' not in evidence['summary_rows']:
        evidence['summary_rows'] = {}
        evidence['summary_note'] = 'Incomplete severity/status table; accepted counts remain unknown.'
        return evidence
    evidence['summary_excerpt'] = text[header.start():position].strip()
    # Declined findings and unresolved Reported findings do not become accepted.
    if not interim and all(row['reported'] == 0 for row in evidence['summary_rows'].values()):
        evidence['accepted_counts'] = {severity: sum(row.get(status, 0) for status in ['acknowledged', 'fixed', 'mitigated'])
                                       for severity, row in evidence['summary_rows'].items()}
    evidence['summary_note'] = 'Accepted = Acknowledged + Fixed + Mitigated; Reported and Declined excluded. Critical retained as Critical; an absent High row remains unknown.'
    return evidence


def validate(contests, reports):
    if len({row['contest_id'] for row in contests}) != len(contests):
        raise ValueError('Duplicate contest IDs')
    report_hashes = set()
    for row in reports:
        public = urllib.parse.urlsplit(row['public_url'])
        if public.scheme != 'https' or not public.hostname or public.username or public.password:
            raise ValueError('Report URL is not a credential-free HTTPS URL')
        # GitHub originals must be revision-pinned. A report hosted by a client
        # CDN or another public publisher keeps its stable HTTPS URL.
        if public.hostname.lower() == 'github.com' and not re.search(r'/blob/[0-9a-f]{40}/', public.path):
            raise ValueError('GitHub report URL is not commit-pinned')
        original = ROOT / row['local_path']
        body = original.read_bytes()
        if hashlib.sha256(body).hexdigest() != row['sha256'] or len(body) != row['bytes']:
            raise ValueError('Original bytes do not reconcile')
        if row['file_format'] == 'pdf' and not body.startswith(b'%PDF-'):
            raise ValueError('Invalid PDF signature')
        report_hashes.add(row['sha256'])
    for row in contests:
        if row['sha256'] is not None and row['sha256'] not in report_hashes:
            raise ValueError('Contest report does not join to collected report')
        if row['start_utc'] and row['end_utc'] and row['start_utc'] > row['end_utc']:
            raise ValueError('Contest dates out of order')
    return dict(unique_contest_ids=True, report_hashes_and_bytes=True,
                commit_pinned_github_report_urls=True, external_public_report_urls_https=True,
                contest_report_joins=True,
                unique_report_hashes=len(report_hashes), original_bytes=sum(row['bytes'] for row in reports))


def main():
    if sys.argv[1:] == ['--verify-local']:
        out = ROOT / 'data/collect/secure3'
        contests = [json.loads(line) for line in (out / 'contests.jsonl').read_text().splitlines() if line.strip()]
        reports = [json.loads(line) for line in (out / 'reports.jsonl').read_text().splitlines() if line.strip()]
        validation = validate(contests, reports)
        status = json.loads((out / 'status.json').read_text())
        if status.get('collected') != len(reports):
            raise ValueError('Status collected count does not reconcile with manifest rows')
        print(json.dumps(dict(firm_id='secure3', manifest_rows=len(reports),
                              distinct_report_hashes=len({row['sha256'] for row in reports}),
                              status_collected=status.get('collected'), validation=validation), sort_keys=True))
        return
    options = args()
    client = Client(options.refresh, options.offline)
    sources, failures, gaps = [], [], []
    bodies = {}

    def capture(url):
        meta, body = client.get(url)
        # Retain response provenance, not public-page session/CSRF fields.
        sources.append(dict(requested_url=url, response_url=meta.get('effective_url', meta['url']),
                            status=meta['status'], bytes=len(body), sha256=hashlib.sha256(body).hexdigest(),
                            accessed_at=meta['accessed_at']))
        bodies[url] = body
        return meta, body

    for url in LISTINGS:
        try:
            capture(url)
        except Exception as exc:
            failures.append(dict(url=url, error=str(exc)))
    frontend_source_urls = []
    # Inspect the site's own linked bundles only as text to retain endpoint provenance.
    for path in re.findall(r'<script src="([^"]+)"', bodies.get(HOME, b'').decode('utf-8', 'replace')):
        if '(landing)/page-' in path or '/%5Blocale%5D/layout-' in path:
            source_url = urllib.parse.urljoin(HOME, path)
            try:
                _, body = capture(source_url)
                if b'/api/v2/auditContest/basic/enum' in body or b'https://app.secure3.io' in body:
                    frontend_source_urls.append(source_url)
            except Exception as exc:
                gaps.append(dict(url=source_url, reason='Linked frontend source unavailable: ' + str(exc)))
    homepage_sha = hashlib.sha256(bodies.get(HOME, b'')).hexdigest()
    for url in ['https://secure3.io/contest/', 'https://app.secure3.io']:
        if url in bodies and hashlib.sha256(bodies[url]).hexdigest() == homepage_sha:
            gaps.append(dict(url=url, reason='Returns the same body as the marketing homepage; no contest listing.'))
    gaps.append(dict(url='https://secure3.io/reports',
                     reason='Official FAQ report link currently leads to unavailable Secure3Academy GitHub page; no complete report archive.'))
    # Probe only first-party routes linked in docs/source; do not enumerate guessed API IDs.
    for url in ['https://docs.secure3.io/llms.txt',
                'https://docs.secure3.io/projects/how-audit-contest-works.md',
                'https://secure3.io/sitemap.xml', 'https://secure3.io/en/contest',
                'https://secure3.io/api/v2/auditContest/basic/enum']:
        try:
            meta, body = capture(url)
            if url.endswith('/enum'):
                value = json.loads(body)
                if value.get('status') != 200 or value.get('data') is None:
                    gaps.append(dict(url=url, reason='Public frontend enum endpoint returns an internal-error JSON envelope, not an inventory.'))
        except Exception as exc:
            failures.append(dict(url=url, error=str(exc)))

    contests, reports, repositories, excluded = [], [], [], []
    org = embedded(bodies[ORG], 'orgReposPageRoute')
    if org.get('errorMessage') or org['pageCount'] < 1:
        raise ValueError('Invalid GitHub organization listing')
    repository_rows = list(org['repositories'])
    for page in range(2, org['pageCount'] + 1):
        _, body = capture(ORG + '?page=' + str(page))
        repository_rows.extend(embedded(body, 'orgReposPageRoute')['repositories'])
    if len({row['name'] for row in repository_rows}) != org['repositoryCount']:
        raise ValueError('GitHub repository page count does not reconcile')

    for item in sorted(repository_rows, key=lambda row: row['name']):
        name = item['name']
        repo = 'Secure3Audit/' + name
        url = 'https://github.com/' + repo
        print('Inspecting ' + repo, flush=True)
        try:
            _, body = capture(url)
            root = embedded(body, 'codeViewRepoRoute')
            commit = root['refInfo']['currentOid']
            if not re.fullmatch('[0-9a-f]{40}', commit):
                raise ValueError('Unpinned GitHub revision')
            readme_public, readme_raw = github_urls(repo, commit, 'README.md')
            readme_meta, readme_body = capture(readme_raw)
            if readme_meta['status'] != 200:
                raise ValueError('README unavailable: HTTP ' + str(readme_meta['status']))
            readme = readme_body.decode('utf-8')
            ids = re.findall(r'https://(?:www\.)?secure3\.io/contest/([A-Za-z0-9]+)', readme)
            if not (name.endswith('Audit_Contest') or ids):
                excluded.append(dict(repository=repo, commit=commit, readme_url=readme_public,
                                     reason='README describes code similarity analysis; no Secure3 contest link or contest identification.'))
                for entry in root['tree']['items']:
                    if entry['contentType'] == 'file' and entry['path'].lower().endswith('.pdf'):
                        excluded.append(dict(url=github_urls(repo, commit, entry['path'])[0],
                                             reason='Code similarity analysis PDF; not a contest report.'))
                continue
            contest_id = ids[0] if ids else 'github:' + name
            education = 'Educational' in name
            # Do not infer public participation from public code or released reports.
            contest = dict(contest_id=contest_id, platform='secure3',
                           name=name.replace('_', ' '),
                           **{'sponsor/project': name.removesuffix('_Audit_Contest').removeprefix('code_').replace('_', ' ')},
                           start_utc=readme_time(readme, 'Starts'), end_utc=readme_time(readme, 'Ends'),
                           format='other', format_detail='educational_exercise' if education else 'historical_contest_access_unverified',
                           access='educational' if education else 'unknown',
                           public_evidence=True, eligible_public_cohort=False,
                           listing_url=readme_public, report_url=None, findings_high=None,
                           findings_medium=None, sha256=None, report_urls=[],
                           source_repository=repo, source_commit=commit,
                           evidence_urls=[readme_public], finalization_status='unknown',
                           notes='Public repository/report availability does not verify original participation access. No Git timestamps used as audit dates.')
            if ids:
                contest['historical_contest_url'] = 'https://www.secure3.io/contest/' + ids[0]
                contest['evidence_urls'].append(contest['historical_contest_url'])
                try:
                    meta, _ = capture(contest['historical_contest_url'])
                    gaps.append(dict(contest_id=contest_id, url=contest['historical_contest_url'],
                                     reason='Historical contest route does not expose usable contest metadata in the captured response.',
                                     response_status=meta['status']))
                except Exception as exc:
                    gaps.append(dict(contest_id=contest_id, url=contest['historical_contest_url'],
                                     reason='Historical contest route unavailable: ' + str(exc)))
            paths = []
            for entry in root['tree']['items']:
                if entry['contentType'] == 'directory' and entry['path'] == 'audit_report':
                    tree_url = f'https://github.com/{repo}/tree/{commit}/audit_report'
                    _, tree_body = capture(tree_url)
                    tree = embedded(tree_body, 'codeViewTreeRoute')['tree']
                    if len(tree['items']) != tree['totalCount']:
                        raise ValueError('Truncated audit_report directory')
                    paths.extend(row['path'] for row in tree['items'] if row['contentType'] == 'file'
                                 and row['path'].lower().endswith(('.pdf', '.md')))
            repositories.append(dict(repository=repo, commit=commit, readme_url=readme_public,
                                     report_paths=paths, educational=education))
            for path in paths:
                public, raw = github_urls(repo, commit, path)
                if education:
                    excluded.append(dict(url=public, reason='Educational audit contest; excluded from research contest cohort and report collection.'))
                    continue
                try:
                    report, report_body = store_report(client, 'secure3', contest, public, raw,
                                             fmt='pdf' if path.lower().endswith('.pdf') else 'md',
                                             notes='Historical official Secure3 contest archive; contest access and end date unverified unless supplied by README. Severity evidence retained with contest metadata.')
                    if report['file_format'] == 'pdf':
                        document_evidence = pdf_summary_evidence(report_body, public, report['filename'])
                        contest.setdefault('report_evidence', []).append(document_evidence)
                        if document_evidence['finalization_status'] == 'interim':
                            contest['finalization_status'] = 'interim'
                            contest['notes'] += ' Official report is an interim audit update subject to change; excluded from final accepted-finding counts.'
                            report['notes'] += ' Interim audit update subject to change; not a final report.'
                        else:
                            accepted = document_evidence['accepted_counts']
                            contest['findings_high'] = accepted.get('High')
                            contest['findings_medium'] = accepted.get('Medium')
                            contest['findings_critical'] = accepted.get('Critical')
                    reports.append(report)
                    contest['report_urls'].append(public)
                    if contest['report_url'] is None:
                        contest['report_url'], contest['sha256'] = public, report['sha256']
                except Exception as exc:
                    failures.append(dict(url=public, error=str(exc)))
            if contest['report_url'] and contest['finalization_status'] != 'interim':
                contest['finalization_status'] = 'report_released'
            elif not contest['report_url'] and not education:
                gaps.append(dict(contest_id=contest_id, url=readme_public,
                                 reason='Contest evidenced by official code-sharing README; final report unavailable in this repository.'))
            contests.append(contest)
        except Exception as exc:
            failures.append(dict(url=url, error=str(exc)))

    unknown_end = [row['contest_id'] for row in contests if not row['end_utc']]
    unknown_access = [row['contest_id'] for row in contests if row['access'] == 'unknown']
    counts = collections.Counter(row['end_utc'][:4] if row['end_utc'] else 'unknown' for row in contests)
    audit_counts = collections.Counter(row['end_utc'][:4] if row['end_utc'] else 'unknown'
                                       for row in contests if row['access'] != 'educational')
    evidence = dict(platform='secure3', accessed_utc=utc(), official_listing_urls=LISTINGS,
                    listed_count=None, listed_count_verified=False, public_denominator_verified=False,
                    frontend_source_urls=frontend_source_urls,
                    completion='partial_official_historical_archive',
                    denominator_reason='No working complete contest listing/export. FAQ marketing claim includes unpublished private contests and is not a public denominator.',
                    publisher_claim=dict(url=FAQ, text='over 200 audit contests', treated_as_denominator=False),
                    github_organization=dict(url=ORG, page_count=org['pageCount'],
                                             listed_repository_count=org['repositoryCount'],
                                             measured_repository_count=len(repository_rows),
                                             repository_count_is_contest_count=False),
                    evidenced_contests=len(contests), collected_reports=len(reports),
                    finalization_status_counts=dict(collections.Counter(row['finalization_status'] for row in contests)),
                    released_non_interim_report_contests=sum(row['finalization_status'] == 'report_released' for row in contests),
                    interim_contest_ids=[row['contest_id'] for row in contests if row['finalization_status'] == 'interim'],
                    accepted_medium_known_contests=sum(row['findings_medium'] is not None for row in contests),
                    accepted_medium_sum_known_cohort=sum(row['findings_medium'] for row in contests if row['findings_medium'] is not None),
                    per_year_by_end_utc=dict(sorted(counts.items())),
                    per_year_non_educational_by_end_utc=dict(sorted(audit_counts.items())),
                    per_year_eligible_public_by_end_utc={},
                    formats=dict(collections.Counter(row['format'] for row in contests)),
                    format_details=dict(collections.Counter(row['format_detail'] for row in contests)),
                    private_invitation_mitigation=dict(private=[], invitation=[], mitigation=[],
                                                      unknown_access=unknown_access,
                                                      note='Unknown participation access is excluded from eligible public cohort; not inferred public from released artifacts.'),
                    unknown_end_utc_contest_ids=unknown_end,
                    unknown_accepted_counts_contest_ids=[row['contest_id'] for row in contests if row['findings_high'] is None or row['findings_medium'] is None],
                    sources=sources, repositories=repositories, excluded=excluded, exact_gaps=gaps,
                    validation=validate(contests, reports),
                    no_zero_imputation=True, no_git_dates_as_audit_dates=True)
    finish('secure3', contests, reports, failures, LISTINGS, None, evidence)
    # Separate exclusions in status without confusing repository exclusions with files.
    status_path = ROOT / 'data/collect/secure3/status.json'
    status = json.loads(status_path.read_text())
    status['skipped_non_report'] = sum('url' in row for row in excluded)
    write_json(status_path, status)


if __name__ == '__main__':
    main()
