#!/usr/bin/env python3
"""Collect all official C4 audit pages and published final reports.

Native website HTML is preserved byte-for-byte and a Markdown reading rendition is
also cached, explicitly labelled as derived. The two historical IPFS PDFs remain
native PDFs. No issue counts or raw GitHub labels become accepted finding totals.
"""
import collections
import concurrent.futures
import html
import hashlib
from html.parser import HTMLParser
import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from contest_common import Client, args, finish, flight_objects, github_root, github_urls, iso, objects, repo_tree, store_report
from contest_pdf_text import pdf_text

LISTING = 'https://code4rena.com/reports'
API = 'https://code4rena.com/api/v1/audits?perPage=100&page='


class Markdown(HTMLParser):
    """A conservative text rendition; native HTML remains the source of truth."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.links, self.skip = [], [], 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('script', 'style', 'svg'):
            self.skip += 1
        if self.skip:
            return
        if tag in ('p', 'div', 'section', 'table', 'tr', 'ul', 'ol'):
            self.parts.append('\n\n' if tag != 'tr' else '\n')
        elif re.fullmatch('h[1-6]', tag):
            self.parts.append('\n\n' + '#' * int(tag[1]) + ' ')
        elif tag == 'li':
            self.parts.append('\n- ')
        elif tag == 'br':
            self.parts.append('\n')
        elif tag == 'pre':
            self.parts.append('\n\n```\n')
        elif tag in ('td', 'th'):
            self.parts.append(' | ')
        elif tag == 'a':
            self.links.append(attrs.get('href'))
            self.parts.append('[')

    def handle_endtag(self, tag):
        if tag in ('script', 'style', 'svg'):
            self.skip = max(0, self.skip - 1)
            return
        if self.skip:
            return
        if tag == 'a' and self.links:
            url = self.links.pop()
            self.parts.append('](' + url + ')' if url else ']')
        elif tag == 'pre':
            self.parts.append('\n```\n\n')
        elif tag in ('p', 'div', 'section') or re.fullmatch('h[1-6]', tag):
            self.parts.append('\n\n')

    def handle_data(self, text):
        if not self.skip:
            self.parts.append(text)

    def text(self):
        return re.sub(r'\n{3,}', '\n\n', ''.join(self.parts)).strip() + '\n'


def findings(text):
    summary = re.search(r'id="summary"[^>]*>.*?</h[1-6]>(.*?)(?=<h[1-6]\b|\Z)', text, re.S)
    if not summary:
        summary = re.search(r'^#{1,6} Summary\s*\n(.*?)(?=^#{1,6} |\Z)', text, re.M | re.S)
    summary_text = summary[1] if summary else text
    clean = html.unescape(re.sub('<[^>]*>', ' ', re.sub(r'<script\b.*?</script>', '', summary_text, flags=re.S)))
    clean = re.sub(r'\s+', ' ', clean)
    if re.search(r'(?:aggregated total of 0 (?:High and Medium|unique vulnerabilities)|no (?:High or Medium|high-risk or medium-risk|high or medium)(?: severity)? (?:vulnerabilities|issues)|no high or medium risk)', clean, re.I):
        return 0, 0, 'Official report explicitly states zero high/medium vulnerabilities'
    if re.search(r'\b0\s+(?:unique\s+)?(?:vulnerabilities\b[^.!?]{0,140})?HIGH(?:\s+severity)?\s+(?:or|and)\s+MEDIUM\b', clean, re.I):
        return 0, 0, 'Official report explicitly states zero high/medium vulnerabilities'
    values = []
    for severity in ('HIGH', 'MEDIUM'):
        match = re.search(r'(\d+) received (?:a )?risk rating (?:in (?:the )?category of|of) ' + severity + r'\b', clean, re.I)
        values.append(int(match[1]) if match else None)
    if all(v is not None for v in values):
        return *values, 'Official report Summary severity totals'
    headings = [html.unescape(re.sub('<[^>]*>', '', h)) for h in re.findall(r'<h[1-6][^>]*>(.*?)</h[1-6]>', text, re.S)]
    headings.extend(re.findall(r'^#{1,6}\s+(.*)$', text, re.M))
    canonical = [re.search(r'\[([HM])-([0-9]+)\]', h) for h in headings]
    canonical = [m.groups() for m in canonical if m]
    if canonical:
        return (len({n for s, n in canonical if s == 'H'}), len({n for s, n in canonical if s == 'M'}),
                'Unique canonical H/M report headings; no raw issues or TOC entries')
    return None, None, 'No recognized severity summary; missing is not zero'


def recover_pdf(client, r, item):
    """Recover the official CID, or a pinned mirror verified against its catalog."""
    original = r['alt_url']
    gateway = original.replace('https://ipfs.io/', 'https://ipfs.filebase.io/')
    try:
        result, body = store_report(client, 'code4rena', item, gateway, fmt='pdf',
            notes='Official publisher-linked IPFS CID through a public gateway. Original URL: ' + original)
        return result, body
    except Exception:
        repo = 'gcf3711/audit-report-archive'
        commit, _ = repo_tree(client, repo)
        catalog_url = github_urls(repo, commit, 'data/catalog/code4rena.json')[1]
        catalog = client.json(catalog_url)
        entry = next(e for e in catalog if e.get('download_url') == original)
        metadata = client.json('https://huggingface.co/api/datasets/gcf3711/audit-report-archive')
        path = entry['local_path'].removeprefix('data/')
        assert any(e['rfilename'] == path for e in metadata['siblings']), 'PDF absent from inspected public mirror'
        mirror = f'https://huggingface.co/datasets/gcf3711/audit-report-archive/resolve/{metadata["sha"]}/{path}'
        body = client.body(mirror)
        assert hashlib.sha256(body).hexdigest() == entry['sha256'] and len(body) == entry['size_bytes'], 'Mirror digest mismatch'
        result, body = store_report(client, 'code4rena', item, mirror, fmt='pdf',
            notes=f'Public mirror recovery, exact size and SHA-256 verified against {repo} catalog at {commit}. Original publisher URL: {original}')
        result['source_kind'] = 'aggregator'
        return result, body


def mitigation_counts(text):
    """Count only explicitly summarized NEW issues, not old unmitigated ones."""
    start = re.search(r'^#{1,3} Mitigation Review\s*$', text, re.M)
    if not start:
        start = re.search(r'id="mitigation-review"', text)
    if not start:
        return None, None
    section = text[start.start():]
    section = re.split(r'^#{1,3} Disclosures\s*$|id="disclosures"', section, maxsplit=1, flags=re.M)[0]
    section = html.unescape(re.sub('<[^>]*>', ' ', section))
    section = re.sub(r'\s+', ' ', section)
    # The summary precedes the original-issue disposition table; findings marked
    # unmitigated in that table are not additional vulnerabilities.
    marker = re.search(r'Mitigation Review (?:Scope (?:&|and) )?Summary', section, re.I)
    if not marker:
        return None, None
    summary = section[marker.end():].split('Original Issue')[0][:1800]
    if re.search(r'no new (?:(?:high[- ]? (?:or|and) medium[- ]?(?:risk|severity)?|high or medium)(?:[- ]risk)? )?(?:issues|findings|vulnerabilities)', summary, re.I):
        return 0, 0
    new = re.findall(r'(\d+) new (High|Medium|Low|Informational)(?:[- ]severity)? (?:findings?|issues?)', summary, re.I)
    if new:
        return (sum(int(n) for n, severity in new if severity.lower() == 'high'),
                sum(int(n) for n, severity in new if severity.lower() == 'medium'))
    return None, None


def main():
    opts = args()
    client = Client(opts.refresh, opts.offline)
    rows, pages = [], []
    for page in range(1, 101):
        data = client.json(API + str(page))
        page_rows = data['data']['audits']
        pages.append(dict(url=API + str(page), rows=len(page_rows), pagination=data['pagination']))
        rows.extend(page_rows)
        if not data['pagination']['nextPage']:
            break
    assert len(rows) == len({r['uid'] for r in rows}) == data['pagination']['total']
    published = {o['uid']: o for v in flight_objects(client.body(LISTING).decode()) for o in objects(v)
                 if o.get('date') and o.get('slug') and 'findings' in o}
    assert published, 'Empty report listing'
    contests = {}
    for r in rows:
        access = 'public' if r['codeAccess'] == 'public' else 'private'
        kind = 'mitigation' if r['auditType'] == 'Mitigation review' else ('private' if access == 'private' else 'public_contest')
        contests[r['contestId']] = dict(contest_id=str(r['contestId']), platform='code4rena', name=r['title'],
            **{'sponsor/project': r['org']['name']}, start_utc=iso(r['startTime']), end_utc=iso(r['endTime']),
            format=kind, report_url=None, findings_high=None, findings_medium=None, sha256=None,
            listing_url='https://code4rena.com/audits/' + r['slug'], audit_uid=r['uid'], audit_type_raw=r['auditType'],
            code_access_raw=r['codeAccess'], access=access, status_raw=r['status'], finalized=r['status'] == 'Completed',
            mitigation_of=r['mitigationOf'], findings_repo=r['findingsRepo'], listing_member=True,
            report_state='not_published', findings_basis=None)
    reports, failures, archive_only = [], [], []
    for index, r in enumerate(sorted(published.values(), key=lambda r: r['slug'])):
        cid = r['contest']
        if cid not in contests:
            # Report index is independently official evidence; do not drop retired audit IDs.
            archive_only.append(dict(contest_id=cid, slug=r['slug']))
            contests[cid] = dict(contest_id=str(cid), platform='code4rena', name=r['title'],
                **{'sponsor/project': r['sponsor']}, start_utc=None, end_utc=None, format='public_contest',
                report_url=None, findings_high=None, findings_medium=None, sha256=None,
                listing_url=LISTING, listing_member=False, finalized=True, status_raw='published_report_only',
                access='public', report_state='not_published', findings_repo=r['findings'], findings_basis=None)
        item = contests[cid]
        if str(cid) in ('146', '158', '197'):
            item.update(format='other', engagement_subtype='solo_security_review',
                        format_basis='Official report-only record describes a solo review; not a public contest')
        public_url = r.get('alt_url') or LISTING + '/' + r['slug']
        item.update(report_url=public_url, report_published_at=r['date'], report_listing_uid=r['uid'],
                    finalized=True, finalization_basis='official_final_report_index')
        try:
            if r.get('alt_url'):
                try:
                    report, body = store_report(client, 'code4rena', item, public_url, fmt='pdf', notes=f'Official report index; contest ID {cid}.')
                except Exception as origin_error:
                    report, body = recover_pdf(client, r, item)
                    item.update(report_alt_url=public_url, report_url=report['public_url'])
                pdf = pdf_text(body)
                # Early reports include a separately labelled disputed appendix.
                # Accepted canonical headings before that appendix define the numerator.
                start = re.search(r'\[[HM]-\d+\]', pdf)
                accepted = re.split(r'\n\s*Disputed\s+Findings\s*\n', pdf[start.start():], maxsplit=1)[0] if start else pdf
                labels = re.findall(r'\[([HM])-(\d+)\]', accepted)
                if labels:
                    item.update(findings_high=len({n for s, n in labels if s == 'H'}),
                                findings_medium=len({n for s, n in labels if s == 'M'}),
                                findings_basis='Unique canonical PDF H/M identifiers in accepted findings section; separately labelled disputed appendix excluded')
                else:
                    high, medium, basis = findings(pdf)
                    item.update(findings_high=high, findings_medium=medium, findings_basis=basis)
            else:
                report, body = store_report(client, 'code4rena', item, public_url, fmt='html', notes=f'Native published HTML final report; contest ID {cid}.')
                text = body.decode('utf-8')
                detail = next((o['report'] for v in flight_objects(text) for o in objects(v)
                               if isinstance(o.get('report'), dict) and o['report'].get('contest') == cid), None)
                if detail:
                    period = detail.get('contest_data') or {}
                    if isinstance(period, dict):
                        item['start_utc'] = item['start_utc'] or iso(period.get('start_time'))
                        item['end_utc'] = item['end_utc'] or iso(period.get('end_time'))
                        if item['end_utc']:
                            report.update(date_hint=item['end_utc'][:10], date_precision='day', date_basis='contest_end')
                high, medium, basis = findings(text)
                item.update(findings_high=high, findings_medium=medium, findings_basis=basis)
                # Reading rendition only; original HTML is separately hashed and retained.
                article = re.search(r'<article\b[^>]*>(.*?)</article>', text, re.S)
                content = article[1] if article else re.sub(r'<script\b.*?</script>', '', text, flags=re.S)
                md = Markdown()
                md.feed(content)
                rendition, _ = store_report(client, 'code4rena', item, public_url, fmt='md',
                    content=md.text().encode(), notes=f'Derived Markdown reading rendition of native HTML SHA-256 {report["sha256"]}; not publisher Markdown. Contest ID {cid}.')
                rendition['filename'] = r['slug'] + '.md'
                reports.append(rendition)
            reports.append(report)
            item.update(sha256=report['sha256'], report_state='collected')
        except Exception as exc:
            failures.append(dict(url=public_url, error=str(exc)))
            item['report_state'] = 'error'
        if index % 20 == 0:
            print(f'C4 reports {index + 1}/{len(published)}, failures={len(failures)}', flush=True)
    # Publisher Markdown is preferred to locally rendered text when publicly
    # available. Independent root/raw hosts are pipelined; each has a shared 1/s lock.
    native_failures = []
    def native_report(r):
        cid = r['contest']
        item = contests[cid]
        if r.get('alt_url'):
            return r, None, None
        repo = (r['findings'] or '').removeprefix('https://github.com/').removesuffix('/issues').rstrip('/')
        if not repo:
            return r, None, 'Official report index has no findings-repository URL'
        try:
            worker_client = Client(opts.refresh, opts.offline)
            commit, files = github_root(worker_client, repo)
            if not any(f['path'] == 'report.md' for f in files):
                return r, None, 'No root report.md in official findings repository'
            blob, raw = github_urls(repo, commit, 'report.md')
            body = worker_client.body(raw)
            if len(body) < 1000:
                return r, None, 'Short report.md is not accepted as a full report'
            result, body = store_report(worker_client, 'code4rena', item, blob, raw, fmt='md',
                notes=f'Native official findings-repository final report; contest ID {cid}. Website rendering retained where available.')
            return r, (result, body), None
        except Exception as exc:
            return r, None, str(exc)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for index, (r, native, error) in enumerate(pool.map(native_report, sorted(published.values(), key=lambda r: r['slug']))):
            item = contests[r['contest']]
            if error:
                native_failures.append(dict(contest_id=item['contest_id'], error=error))
            if native:
                report, body = native
                # Replace only the derived reading rendition; keep native HTML.
                reports = [p for p in reports if not (p['public_url'] == LISTING + '/' + r['slug'] and p['file_format'] == 'md')]
                reports.append(report)
                item.update(report_url=report['public_url'], sha256=report['sha256'], report_state='collected')
                high, medium, basis = findings(body.decode('utf-8'))
                if high is not None:
                    item.update(findings_high=high, findings_medium=medium, findings_basis=basis)
                failures = [f for f in failures if f['url'] != LISTING + '/' + r['slug']]
            if index % 20 == 0:
                print(f'C4 native Markdown {index + 1}/{len(published)}, available={sum("Native official findings-repository" in p["notes"] for p in reports)}', flush=True)
    # Mitigation reviews are often appended to their parent's final report. Only
    # link a review when its exact official scope-repository URL is in that report.
    by_uid = {c['audit_uid']: c for c in contests.values() if c.get('audit_uid')}
    by_sha = {r['sha256']: r for r in reports}
    documents = {}
    for cid, item in contests.items():
        if item.get('report_listing_uid') and item.get('sha256'):
            doc = by_sha[item['sha256']]
            if doc['file_format'] != 'pdf':
                documents[cid] = (doc, (Path(__file__).resolve().parents[2] / doc['local_path']).read_text())
    mitigation_links = []
    for source in rows:
        item = contests[source['contestId']]
        if item['format'] != 'mitigation' or item.get('sha256') or not source.get('repo'):
            continue
        parent = by_uid.get(source['mitigationOf']) if source['mitigationOf'] else None
        candidates = [int(parent['contest_id'])] if parent else list(documents)
        scope_link = re.compile(re.escape(source['repo'].rstrip('/')) + r'(?=[/"<>\s)#]|$)')
        matches = [cid for cid in candidates if cid in documents and scope_link.search(documents[cid][1])]
        if len(matches) == 1:
            parent = contests[matches[0]]
            item.update(report_url=parent['report_url'], sha256=parent['sha256'], report_state='collected',
                        report_relation='mitigation_appendix', parent_contest_id=parent['contest_id'],
                        report_locator=source['repo'], finalized=True, finalization_basis='official_final_mitigation_appendix',
                        findings_basis='Mitigation appendix collected; standalone H/M totals not separately stated/extracted')
            mitigation_links.append(dict(contest_id=item['contest_id'], parent_contest_id=parent['contest_id']))
    reviews_per_parent = collections.Counter(link['parent_contest_id'] for link in mitigation_links)
    for link in mitigation_links:
        item = contests[int(link['contest_id'])]
        high, medium = mitigation_counts(documents[int(link['parent_contest_id'])][1])
        if reviews_per_parent[link['parent_contest_id']] > 1:
            item['combined_review_findings_high'] = high
            item['combined_review_findings_medium'] = medium
            # A zero across all rounds proves zero in each; a positive aggregate
            # cannot be assigned to each round without inflating findings.
            high = 0 if high == 0 else None
            medium = 0 if medium == 0 else None
        if high is not None or medium is not None:
            item.update(findings_high=high, findings_medium=medium,
                        findings_basis='Official mitigation review summary NEW finding counts; old unmitigated findings excluded; positive combined-round totals left unassigned')
    # Formal-verification-only competitions are not ordinary vulnerability contests.
    for item in contests.values():
        if 'formal verification' in item['name'].lower() and 'audit' not in item['name'].lower():
            item['format'] = 'other'
            item['engagement_subtype'] = 'formal_verification'
            for report in reports:
                if report['sha256'] == item.get('sha256') or report['title_hint'] == item['name']:
                    report['doc_kind'] = 'formal_verification'
    evidence = dict(listing_url='https://code4rena.com/audits', api_pages=pages, listing_total=len(rows),
                    listing_end_years=dict(sorted(collections.Counter(iso(r['endTime'])[:4] for r in rows).items())),
                    report_listing_url=LISTING, report_listing_count=len(published), report_only_contests=archive_only,
                    mitigation_report_links=mitigation_links,
                    repository_note='Both code-423n4/reports and Code4rena/reports returned 404 in same-day primary-source research; native website originals used.',
                    native_markdown_unavailable=native_failures,
                    markdown_policy='Native findings-repository Markdown preferred; native HTML also retained. Derived reading renditions only when native Markdown unavailable. IPFS originals are PDFs.')
    for item in contests.values():
        item.update(sponsor=item['sponsor/project'], project=item['name'])
    finish('code4rena', list(contests.values()), reports, failures,
           ['https://code4rena.com/audits', LISTING, API + '1'], len(rows), evidence)


if __name__ == '__main__':
    main()
