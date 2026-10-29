#!/usr/bin/env python3
"""Collect official Hats competition reports using the fully paginated public org.

Remote HTML/Markdown/JSON are data only. No clone or upstream tooling execution.
The organization repository total is NOT the competition denominator. A final
competition report evidences an engagement; unreported vaults remain candidates.
"""
import collections
import datetime as dt
import hashlib
import html
import json
from pathlib import Path
import re
import sys
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contest_common import Client, ROOT, args, finish, github_urls, store_report, utc

PLATFORM = 'hats-finance'
ORG = 'https://github.com/orgs/hats-finance/repositories?type=all'
APP = 'https://app.hats.finance/audit-competitions'
API = 'https://api.github.com/orgs/hats-finance/repos?per_page=100&type=public&page=1'
FRONTEND_COMMIT = '9f65879f430eb94aa43502b8e36d00a73ad3dae0'
SECONDARY = 'https://raw.githubusercontent.com/gcf3711/audit-report-archive/40b90b653a847338b1b48c324956a23e2ea00622/data/catalog/hatsfinance.json'
EMBED = r'<script type="application/json" data-target="react-app.embeddedData">(.*?)</script>'


def payload(body):
    match = re.search(EMBED, body.decode('utf-8'), re.S)
    if not match:
        raise ValueError('Missing GitHub embedded JSON')
    return json.loads(match[1])['payload']


def text_html(value):
    return html.unescape(re.sub('<[^>]+>', ' ', value or ''))


def period(text):
    """Only explicitly labelled ISO date/times; no publication/commit inference."""
    dates = {}
    for field, label in [('start_utc', r'(?:start(?:s|ed)?(?:\s+date)?|from)'),
                         ('end_utc', r'(?:end(?:s|ed)?(?:\s+date)?|until)')]:
        m = re.search(r'(?im)^\s*[-*| ]*' + label + r'\s*[:|]\s*[* ]*(\d{4}-\d{2}-\d{2}(?:T[0-9:.]+(?:Z|[+-]\d\d:\d\d))?)', text)
        dates[field] = None
        if m:
            raw = m[1]
            # A date alone does not establish midnight UTC.
            if 'T' in raw:
                dates[field] = dt.datetime.fromisoformat(raw.replace('Z', '+00:00')).astimezone(dt.timezone.utc).isoformat().replace('+00:00', 'Z')
    return dates


def accepted_counts(text, public_url, markdown=True):
    """Count canonical entries in the publisher's final severity sections.

    An entry must be a top-level bold list title followed by exactly one official
    issue identity. Nested explanatory lists, submissions and grouped low issues
    never contribute to H/M. Missing categories remain null, not implicit zeros.
    """
    result = {'findings_high': None, 'findings_medium': None}
    evidence = {}
    lines = text.splitlines()
    headings, in_fence = [], False
    for index, line in enumerate(lines):
        if re.match(r'^\s{0,3}(?:```|~~~)', line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = re.match(r'^\s{0,3}(#{1,6})\s+(.+?)\s*$', line)
        if match:
            label = re.sub(r'[*_`]', '', match[2]).strip(' :').lower()
            headings.append((index, len(match[1]), label))
    sections = {}
    if markdown:
        for position, (index, level, label) in enumerate(headings):
            match = re.fullmatch(r'(high|medium|low|minor|critical) severity (?:issues|findings?)', label)
            if not match:
                continue
            end = next((i for i, depth, _ in headings[position + 1:] if depth <= level), len(lines))
            entries, in_fence = [], False
            for i in range(index + 1, end):
                line = lines[i]
                if re.match(r'^\s{0,3}(?:```|~~~)', line):
                    in_fence = not in_fence
                    continue
                if not in_fence and re.match(r'^(?:[-*+] |\d+[.)] )\*\*[^*]+\*\*', line):
                    entries.append(i)
            items = []
            for offset, first in enumerate(entries):
                last = entries[offset + 1] if offset + 1 < len(entries) else end
                block = '\n'.join(lines[first:last])
                links = sorted(set(re.findall(r'https://github\.com/hats-finance/[^/\s)]+/issues/\d+\b', block)))
                item = dict(title_line=first + 1, locator=public_url + '#L' + str(first + 1),
                            canonical_issue_urls=links)
                uncertainty = re.search(r'[^.\n]*(?:making this issue invalid|additional verification is suggested|final status[^.\n]*(?:pending|uncertain))[^.\n]*\.?', block, re.I)
                if uncertainty:
                    item['status_caveat'] = uncertainty[0].strip()
                items.append(item)
            links = [item['canonical_issue_urls'][0] for item in items if len(item['canonical_issue_urls']) == 1]
            sections.setdefault(match[1], []).append(dict(
                method='official_final_report_canonical_severity_section',
                raw_severity=lines[index].strip(), raw_entry_count=len(entries),
                canonical_issue_count=len(set(links)),
                complete_canonical_mapping=bool(entries) and len(links) == len(entries),
                locator=public_url + '#L' + str(index + 1), items=items))
    for severity in ('high', 'medium'):
        found_sections = sections.get(severity, [])
        if len(found_sections) == 1 and found_sections[0]['complete_canonical_mapping']:
            result['findings_' + severity] = found_sections[0]['canonical_issue_count']
            evidence[severity] = found_sections[0]
            continue
        # Preserve explicit zero findings even when font ligatures were omitted
        # from the restricted PDF evidence extraction (findings -> ndings).
        zero = re.search(rf'No {severity} severity (?:findings|issues|ndings) were (?:identified|identied)\b[^.]*\.', text, re.I)
        if zero:
            result['findings_' + severity] = 0
            evidence[severity] = dict(method='explicit_official_zero_statement', raw_count=0,
                                      raw_text=zero[0], locator=public_url)
            continue
        # Only an explicit all-low statement corroborated by the final canonical
        # low section establishes zero H/M. Generic submission totals are ignored.
        all_low = re.search(r'Valid Submissions:\s*(\d+)\s*\(all low severity\)', text, re.I)
        low_sections = sections.get('low', [])
        if (all_low and len(low_sections) == 1 and low_sections[0]['complete_canonical_mapping']
                and int(all_low[1]) == low_sections[0]['canonical_issue_count']):
            line_no = text[:all_low.start()].count('\n') + 1
            result['findings_' + severity] = 0
            evidence[severity] = dict(method='explicit_all_low_with_canonical_section_reconciliation',
                                      raw_count=0, raw_text=all_low[0],
                                      low_canonical_issue_count=int(all_low[1]),
                                      locator=public_url + '#L' + str(line_no),
                                      corroborating_section=low_sections[0]['locator'])
            continue
        patterns = [rf'(?im)^\s*\|\s*{severity}(?:\s+severity)?\s*\|\s*(\d+)\s*\|',
                    rf'(?im)^\s*[-* ]*{severity}(?:\s+severity)?\s+(?:findings|issues)\s*:\s*(\d+)\b']
        for pattern in patterns:
            matches = list(re.finditer(pattern, text))
            if len(matches) == 1:
                result['findings_' + severity] = int(matches[0][1])
                line_no = text[:matches[0].start()].count('\n') + 1
                evidence[severity] = dict(method='explicit_official_summary_count', raw_count=int(matches[0][1]),
                                          raw_text=matches[0][0].strip(), locator=public_url + '#L' + str(line_no))
                break
        if severity not in evidence:
            evidence[severity] = dict(method='unverified', reason='No verified canonical section or explicit summary; absent category is not zero')
    result['finding_count_evidence'] = evidence
    result['finding_count_basis'] = 'publisher_final_report_severity_sections_or_explicit_summary; individual_issue_arbitration_not_requeried'
    return result


def competition_period_evidence(text, report_url, readme, readme_url):
    """Inspect labelled calendar periods and durations without date proxies."""
    evidence = []
    months = '(?:January|February|March|April|May|June|July|August|September|October|November|December)'
    for content, source_url, source_kind in [(text, report_url, 'final_report'), (readme, readme_url, 'rendered_official_readme')]:
        if not content:
            continue
        for match in re.finditer(r'(?im)\b(?:Duration|Competition (?:period|dates)|Start(?:s| date)?|End(?:s| date)?)\s*:\s*[^\n]{1,200}', content):
            raw = match[0].strip()
            # PDF BT blocks may join the following field; stop at that boundary.
            raw = re.split(r'\\225|Maximum Reward:|Total Payout:|Scope of', raw)[0].strip()
            row = dict(source_kind=source_kind, locator=source_url, raw_text=raw)
            calendar = re.search(rf'From\s+({months})\s+(\d{{1,2}})(?:,?\s+(20\d{{2}}))?\s+(?:to|until|through|[-–])\s+(?:({months})\s+)?(\d{{1,2}})(?:,?\s+(20\d{{2}}))?', raw, re.I)
            if calendar:
                row['partial_calendar_range'] = dict(start_month=calendar[1], start_day=int(calendar[2]),
                                                     start_year=int(calendar[3]) if calendar[3] else None,
                                                     end_month=calendar[4] or calendar[1], end_day=int(calendar[5]),
                                                     end_year=int(calendar[6]) if calendar[6] else None,
                                                     timezone=None)
                row['utc_resolved'] = False
            evidence.append(row)
    return dict(start_utc=period(text)['start_utc'] or period(readme)['start_utc'],
                end_utc=period(text)['end_utc'] or period(readme)['end_utc'],
                period_evidence=evidence,
                period_sources_checked=[dict(locator=report_url, source_kind='final_report'),
                                        dict(locator=readme_url, source_kind='rendered_official_readme', available=bool(readme))])


def pdf_evidence_text(body):
    """Restricted evidence text from literal strings in Flate PDF content streams.

    This is not a general PDF parser or findings extractor. It handles the Hats
    Cairo-generated report used here; missing glyphs/layout never establish counts.
    """
    result = []
    for match in re.finditer(rb'stream\r?\n(.*?)\r?\nendstream', body, re.S):
        try:
            decoder = zlib.decompressobj()
            stream = decoder.decompress(match[1], 4_000_001)
            if len(stream) > 4_000_000:
                continue
        except zlib.error:
            continue
        if b'BT' not in stream:
            continue
        for block in re.findall(rb'BT\s+(.*?)\s+ET', stream, re.S):
            result.append(''.join(part.decode('latin1') for part in
                                 re.findall(rb'\(((?:\\.|[^\\)])*)\)', block)))
    return '\n'.join(result)


def main():
    options = args()
    client = Client(refresh=options.refresh, offline=options.offline)
    failures, sources, repositories, candidates, exclusions = [], [], [], [], []
    reports, contests = [], []

    def get(url):
        meta, body = client.get(url)
        sources.append({k: meta[k] for k in ('url', 'accessed_at', 'status', 'sha256', 'bytes') if k in meta})
        if meta['status'] != 200:
            raise RuntimeError(f'HTTP {meta["status"]}: {url}')
        return body

    # Check the official live listing, without treating DNS failure as no contests.
    for url in (APP, 'https://hats.finance', 'https://hats.finance/audit-competitions', API,
                'https://prod.hats.finance/v1',
                f'https://raw.githubusercontent.com/hats-finance/hats/{FRONTEND_COMMIT}/packages/web/src/constants/constants.ts'):
        try:
            get(url)
        except Exception as exc:
            failures.append(dict(url=url, error=str(exc)))

    try:
        first = payload(get(ORG))['orgReposPageRoute']
        pages, org_count = first['pageCount'], first['repositoryCount']
        repositories.extend(first['repositories'])
        for page in range(2, pages + 1):
            data = payload(get(ORG + '&page=' + str(page)))['orgReposPageRoute']
            if data['repositoryCount'] != org_count or data['pageCount'] != pages:
                raise ValueError('Organization pagination changed during collection')
            repositories.extend(data['repositories'])
        if len({r['name'] for r in repositories}) != org_count:
            raise ValueError('Organization pagination does not reconcile')
        org_complete = True
    except Exception as exc:
        failures.append(dict(url=ORG, error=str(exc)))
        org_complete, org_count, pages = False, None, None

    secondary_rows = json.loads(get(SECONDARY))
    secondary_hashes = collections.Counter(r.get('sha256') for r in secondary_rows if r.get('sha256'))

    for repo in repositories:
        name = repo['name']
        if not re.search(r'0x[0-9a-fA-F]{40}', name):
            exclusions.append(dict(repository=name, reason='No vault identity; infrastructure/non-vault repository, not counted as a competition'))
            continue
        url = 'https://github.com/hats-finance/' + name
        candidate = dict(repository=name, repository_url=url, description=repo.get('description'), report_paths=[])
        candidates.append(candidate)
        try:
            data = payload(get(url))['codeViewRepoRoute']
            commit = data['refInfo']['currentOid']
            if not re.fullmatch('[0-9a-f]{40}', commit):
                raise ValueError('Invalid commit identity')
            items = data['tree']['items']
            if len(items) != data['tree']['totalCount']:
                raise ValueError('Root listing truncated')
            candidate['commit'] = commit
            candidate['root_paths'] = [p['path'] for p in items]
            candidate['report_paths'] = [p['path'] for p in items if p['contentType'] == 'file' and re.fullmatch(r'(?:report|audit[-_ ]report|final[-_ ]report)\.(?:md|pdf)', p['name'], re.I)]
            overview = data.get('overview', {}).get('overviewFiles', [])
            readme = '\n'.join(text_html(p.get('richText')) for p in overview if p.get('preferredFileType') == 'readme')
            candidate['readme_competition_statement'] = bool(re.search(r'(?:audit|security)\s+competition', readme, re.I))
            if re.search(r'(?i)(?:^|[-_])(?:test|draft)(?:[-_]|$)|^v3-gov-fee|^latest-v3|^pointing-system|^audit-competition[-_]', name):
                candidate['classification'] = 'excluded_test_or_placeholder'
                continue
            # Inspect likely report directories; prior audits are not current contests.
            candidate['nested_report_listing'] = []
            for item in items:
                if item['contentType'] != 'directory' or item['name'].lower() not in ('audit', 'audits', 'report', 'reports'):
                    continue
                directory_url = url + '/tree/' + commit + '/' + item['path']
                nested = payload(get(directory_url))['codeViewTreeRoute']['tree']
                if len(nested['items']) != nested['totalCount']:
                    raise ValueError('Nested report directory truncated: ' + directory_url)
                candidate['nested_report_listing'].extend(p['path'] for p in nested['items'])
                for document in nested['items']:
                    if document['contentType'] == 'file' and re.search(r'(?i)hats.*\.(?:md|pdf)$', document['name']):
                        candidate['report_paths'].append(document['path'])
            if not candidate['report_paths']:
                candidate['classification'] = 'unresolved_vault_without_final_report'
                continue
            text_parts, documents = [], []
            for path in candidate['report_paths']:
                public, raw = github_urls('hats-finance/' + name, commit, path)
                body = get(raw)
                document_text = body.decode('utf-8') if path.lower().endswith('.md') else pdf_evidence_text(body)
                if re.search(r'(?:audit|security)\s+competition', document_text, re.I):
                    text_parts.append(document_text)
                    documents.append((path, public, raw))
                else:
                    candidate.setdefault('excluded_documents', []).append(dict(path=path, sha256=hashlib.sha256(body).hexdigest(), reason='No competition statement established by restricted evidence text; document not accepted as a final competition report'))
            text = '\n'.join(text_parts)
            if not re.search(r'(?:audit|security)\s+competition', text, re.I):
                candidate['classification'] = 'unresolved_report_without_competition_statement'
                continue
            vault = re.search(r'0x[0-9a-fA-F]{40}', name)[0].lower()
            project = re.sub(r'-*0x[0-9a-fA-F]{40}.*$', '', name)
            readme_file = next((p['path'] for p in overview if p.get('preferredFileType') == 'readme'), 'README.md')
            readme_url = github_urls('hats-finance/' + name, commit, readme_file)[0]
            period_data = competition_period_evidence(text, documents[0][1], readme, readme_url)
            counts = accepted_counts(text, documents[0][1], markdown=documents[0][0].lower().endswith('.md'))
            contest = dict(contest_id=name, vault_address=vault, platform=PLATFORM, name=project + ' audit competition',
                           **{'sponsor/project': project}, **period_data, format='public_contest',
                           report_url=documents[0][1], **counts, sha256=None,
                           listing_url=url, finalization_status='final_report_published',
                           competition_evidence_url=documents[0][1], period_basis='explicit_competition_timestamp_or_calendar_period; incomplete_year_or_timezone_remains_unknown',
                           period_text=(re.search(r'Duration\s*:\s*([^\n]{1,110})', text, re.I)[1]
                                        if re.search(r'Duration\s*:\s*([^\n]{1,110})', text, re.I) else None))
            if re.search(r'(?i)(?:type\s*:\s*[^\n]{0,30}private|private\s+audit\s+competition)', text):
                contest['format'] = 'private'
            for path, public, raw in documents:
                row, _ = store_report(client, PLATFORM, contest, public, raw,
                                      fmt='pdf' if path.lower().endswith('.pdf') else 'md',
                                      notes='Official final competition report. Report existence evidences competition; unknown period and accepted severity totals remain null. Repository and report links pinned to captured default-branch commit.')
                row['collector'] = 'contest_hats_finance.py'
                reports.append(row)
                if public == contest['report_url']:
                    contest['sha256'] = row['sha256']
            candidate['classification'] = 'final_report_competition'
            candidate['contest_id'] = name
            contests.append(contest)
            print(json.dumps(dict(repository=name, result=candidate['classification'])), flush=True)
        except Exception as exc:
            candidate['classification'] = 'fetch_or_parse_failure'
            candidate['error'] = str(exc)
            failures.append(dict(url=url, error=str(exc)))

    # Use official repository identities: an address alone can be reused across chains.
    ids = [c['contest_id'] for c in contests]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate official competition repository identity')
    formats = dict(sorted(collections.Counter(c['format'] for c in contests).items()))
    years = dict(sorted(collections.Counter(c['end_utc'][:4] if c['end_utc'] else 'unknown' for c in contests).items()))
    evidence = dict(platform=PLATFORM, access_cutoff_utc=utc(), official_listing_urls=[APP, ORG],
                    listed_count=None, competition_denominator_verified=False,
                    collection_state='partial_denominator_and_period_gaps',
                    collected_contests=len(contests), collected_reports=len(reports),
                    candidate_classification_counts=dict(sorted(collections.Counter(c['classification'] for c in candidates).items())),
                    secondary_discovery=dict(url=SECONDARY, raw_rows=len(secondary_rows),
                                             repeated_report_hashes={sha: count for sha, count in secondary_hashes.items() if count > 1},
                                             note='Secondary dates are not competition dates; repeated inherited PDFs and test vaults do not establish competitions.'),
                    finding_count_summary=dict(high_known=sum(c['findings_high'] is not None for c in contests),
                                               medium_known=sum(c['findings_medium'] is not None for c in contests),
                                               high_total_known=sum(c['findings_high'] or 0 for c in contests),
                                               medium_total_known=sum(c['findings_medium'] or 0 for c in contests)),
                    per_year_by_end_utc=years, formats=formats,
                    organization_pagination=dict(complete=org_complete, pages=pages, listed_repository_count=org_count,
                                                 enumerated_repositories=len(repositories)),
                    candidates=candidates, excluded_non_vault_repositories=exclusions,
                    gaps=[
                        'Official app competition listing fails DNS; website /audit-competitions returns 404. The frontend-published production data service has robots HTTP 530 (origin DNS error). No complete historical competition export/denominator verified; listed_count is null.',
                        'Organization repository count is fully paginated when complete=true, but is not a competition count. Deleted/private repositories and competitions without final root reports may be absent.',
                        'Vaults without final reports are unresolved candidates, not completed competitions; arbitrary repository existence is insufficient.',
                        'Root final reports and immediate audit/audits/report/reports directories are inspected; only competition-evidencing report text is accepted. Deeper or unlinked reports, off-platform arbitration, zero-finding competitions without reports and cancelled competitions remain unverified.',
                        'No UTC competition end timestamps are inferred from publication, repository creation, issue creation or commit dates. Unknown dates remain an explicit bucket.',
                        'H/M counts derive from official final report canonical severity sections or explicit summaries, with raw entry counts and issue/line locators retained. Individual issue arbitration is not requeried; report status caveats are retained. Missing categories stay null; submission/issue totals and payouts are excluded.'
                    ], sources=sources, failures=failures)
    finish(PLATFORM, contests, reports, failures, [APP, ORG], None, evidence)
    # The platform slug has a hyphen; the actual Python collector uses underscores.
    status_path = ROOT / 'data/collect' / PLATFORM / 'status.json'
    status = json.loads(status_path.read_text())
    status['collector_script'] = 'scripts/collect/contest_hats_finance.py'
    status['skipped_non_report'] = len(exclusions) + sum(c['classification'] == 'excluded_test_or_placeholder' for c in candidates)
    status_path.write_text(json.dumps(status, indent=2, ensure_ascii=False, sort_keys=True) + '\n')


def validate():
    """Offline contract, report-byte, identity and reconciliation checks."""
    out = ROOT / 'data/collect' / PLATFORM
    load_lines = lambda filename: [json.loads(line) for line in (out / filename).read_text().splitlines()]
    reports, contests = load_lines('reports.jsonl'), load_lines('contests.jsonl')
    evidence = json.loads((out / 'reconciliation.json').read_text())
    status = json.loads((out / 'status.json').read_text())
    required_report = {'firm_id', 'collector', 'source_kind', 'public_url', 'listing_url', 'sha256', 'bytes', 'file_format', 'local_path', 'filename', 'title_hint', 'project_hint', 'date_hint', 'date_precision', 'date_basis', 'doc_kind', 'retrieved_utc', 'notes'}
    required_contest = {'contest_id', 'platform', 'name', 'sponsor/project', 'start_utc', 'end_utc', 'format', 'report_url', 'findings_high', 'findings_medium', 'sha256'}
    assert len({c['contest_id'] for c in contests}) == len(contests)
    for report in reports:
        assert required_report <= report.keys()
        assert re.search(r'/blob/[0-9a-f]{40}/', report['public_url'])
        body = (ROOT / report['local_path']).read_bytes()
        assert len(body) == report['bytes']
        assert hashlib.sha256(body).hexdigest() == report['sha256']
        assert str(Path(report['local_path']).parts[:2]) == str(('local-cache', 'originals'))
        if report['file_format'] == 'pdf':
            assert body.startswith(b'%PDF-')
    report_urls = {r['public_url']: r for r in reports}
    for contest in contests:
        for severity in ('high', 'medium'):
            item = contest['finding_count_evidence'][severity]
            count = contest['findings_' + severity]
            if item['method'] == 'official_final_report_canonical_severity_section':
                links = [entry['canonical_issue_urls'][0] for entry in item['items']]
                assert len(set(links)) == item['canonical_issue_count'] == count
                assert item['raw_entry_count'] == len(item['items'])
            if count is None:
                assert item['method'] == 'unverified'
        assert len(contest['period_sources_checked']) == 2
    for contest in contests:
        assert required_contest <= contest.keys()
        assert report_urls[contest['report_url']]['sha256'] == contest['sha256']
        for key in ('findings_high', 'findings_medium'):
            assert contest[key] is None or isinstance(contest[key], int) and contest[key] >= 0
    # The manifest preserves duplicate report copies and archival rows; the
    # reconciliation's collected_reports field counts report-bearing contests.
    # Keep both units explicit instead of requiring them to match.
    assert status['collected'] == len(reports)
    assert evidence['collected_reports'] == sum(bool(c.get('report_url')) for c in contests)
    assert evidence['collected_reports'] <= len(reports)
    assert status['listed_count'] is None and evidence['listed_count'] is None
    assert status['failed'] == len(status['failures'])
    assert status['collector_script'] == 'scripts/collect/contest_hats_finance.py'
    assert evidence['collected_contests'] == len(contests)
    assert sum(evidence['per_year_by_end_utc'].values()) == len(contests)
    assert sum(evidence['formats'].values()) == len(contests)
    org = evidence['organization_pagination']
    if org['complete']:
        assert org['enumerated_repositories'] == org['listed_repository_count']
        assert len(evidence['candidates']) + len(evidence['excluded_non_vault_repositories']) == org['listed_repository_count']

    sample_url = 'https://github.com/hats-finance/fixture/blob/' + 'a' * 40 + '/report.md'
    issue_url = 'https://github.com/hats-finance/fixture/issues/1'
    fixture = ('## High severity issues\n- **Canonical title**\n'
               '  1. **Nested explanatory step**\n' + issue_url + '\n'
               '- **Duplicate reference**\n' + issue_url + '\n'
               '```md\n## Medium severity issues\n- **Fenced fake issue**\n```\n'
               '## Low severity issues\n- **Grouped lows**\n')
    parsed = accepted_counts(fixture, sample_url)
    assert parsed['findings_high'] == 1 and parsed['findings_medium'] is None
    assert parsed['finding_count_evidence']['high']['raw_entry_count'] == 2
    ambiguous = accepted_counts('## Medium severity issues\n- **Unlinked entry**\n', sample_url)
    assert ambiguous['findings_medium'] is None
    # Frozen official regression examples: only enforce while source hashes match.
    expected = {
        'adeb91bed9b6b558d1211ef1a75c724a55e59481ada8871c259fe14c2d7a3ca6': (1, 4),
        '9ad148b0ce344f4119a5db64c5f8095d444b10b2526419fcec71dfb04c402020': (0, 0),
        '2f2e1c6f33959da9ae18fa29a8b01f7c14aefcc3576098d75fc0a80f282cd8da': (None, 1),
        'ca57ed98e487f5d55760eb5c7d23a4e94f8c9dae32762f6037fda9cc0005350d': (None, 16),
    }
    for contest in contests:
        if contest['sha256'] in expected:
            assert (contest['findings_high'], contest['findings_medium']) == expected[contest['sha256']]

    summary = dict(check='passed', contests=len(contests), manifest_rows=len(reports),
                   reconciliation_report_bearing_contests=evidence['collected_reports'],
                   unique_report_hashes=len({r['sha256'] for r in reports}),
                   report_bytes=sum(r['bytes'] for r in reports),
                   report_formats=dict(sorted(collections.Counter(r['file_format'] for r in reports).items())),
                   candidates=evidence['candidate_classification_counts'], formats=evidence['formats'],
                   per_year_by_end_utc=evidence['per_year_by_end_utc'], listed_count=None,
                   high_total_known=sum(c['findings_high'] or 0 for c in contests),
                   medium_total_known=sum(c['findings_medium'] or 0 for c in contests),
                   accepted_high_known=sum(c['findings_high'] is not None for c in contests),
                   accepted_medium_known=sum(c['findings_medium'] is not None for c in contests))
    print(json.dumps(summary, sort_keys=True), flush=True)
    return summary


if __name__ == '__main__':
    if '--check' not in sys.argv:
        main()
    validate()
