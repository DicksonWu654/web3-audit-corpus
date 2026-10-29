#!/usr/bin/env python3
"""Exhaust Least Authority's live year grids and audit blog archive.

The firm's portfolio includes ordinary software audits. Those entries are kept
as explicit scope exclusions; they are not silently counted as Web3 reports.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from urllib.parse import urljoin, urlsplit, quote
from bs4 import BeautifulSoup
from web_common import Client, Item, Listing, ROOT, atomic_json, collect, enumeration_failed

FIRM = 'least-authority'
INDEX = 'https://leastauthority.com/security-consulting/published-audits/'
ARCHIVE = 'https://leastauthority.com/blog/category/audit/'
EXCLUDED = {
    'oauth2-0-server': 'OAuth server; ordinary authentication infrastructure',
    'knot-dns': 'DNS server; ordinary Internet infrastructure',
    'gnu-libmicrohttpd': 'HTTP server library; ordinary Internet infrastructure',
    'globaleaks': 'Whistleblowing platform; ordinary application security',
    'ooni': 'Internet censorship measurement backend',
    'cryptocat': 'Encrypted chat application',
    'spideroak': 'Cloud backup application',
    'matrix-vodozemac': 'Matrix encrypted messaging library; ordinary communications infrastructure',
}
REFERENCE_HOSTS = {
    'blog.ipfs.io': 'Client announcement linking the audit; not the audit original',
    'gateway.ipfs.io': 'Gossipsub development-team evaluation report, cited as background by the audit announcement',
    'docs.beam.mw': 'Mimblewimble protocol specification, cited as background',
    'eprint.iacr.org': 'Cryptographic research paper, cited as background',
    'loopring.org': 'Loopring whitepaper, cited as background',
}


def entries_from(soup, listing_url, entries):
    for article in soup.select('article.elementor-post'):
        a = article.select_one('.elementor-post__title a[href]')
        if not a:
            continue
        url = urljoin(listing_url, a['href'])
        date_node = article.select_one('.elementor-post-date')
        date = ''
        if date_node:
            try:
                date = dt.datetime.strptime(date_node.get_text(' ', strip=True), '%B %d, %Y').date().isoformat()
            except ValueError:
                pass
        previous = entries.get(url, {})
        entries[url] = {'url': url, 'title': a.get_text(' ', strip=True),
                        'listing_url': previous.get('listing_url', listing_url),
                        'date': date or previous.get('date', ''),
                        'classes': article.get('class', [])}


def enumerate_entries(client):
    entries, urls, widgets = {}, [], []
    response = client.fetch(INDEX, refresh=True)
    urls.append(INDEX)
    soup = BeautifulSoup(response.text, 'html.parser')
    entries_from(soup, INDEX, entries)
    grids = soup.select('[data-widget_type="posts.classic"]')
    if not grids:
        raise RuntimeError('Published-audits year grids absent')
    for grid in grids:
        anchor = grid.select_one('.e-load-more-anchor')
        if not anchor:
            continue
        widget = grid['data-id']
        max_page = int(anchor['data-max-page'])
        widgets.append({'widget': widget, 'max_page': max_page})
        for page in range(2, max_page + 1):
            url = INDEX + f'?e-page-{widget}={page}'
            response = client.fetch(url, refresh=True)
            urls.append(url)
            page_soup = BeautifulSoup(response.text, 'html.parser')
            target = page_soup.select_one(f'[data-id="{widget}"]')
            if target is None or not target.select('article.elementor-post'):
                raise RuntimeError('Missing widget/page: ' + url)
            entries_from(target, url, entries)
    published_urls = set(entries)
    pending, seen = [ARCHIVE], set()
    while pending:
        url = pending.pop(0)
        if url in seen:
            continue
        if len(seen) > 100:
            raise RuntimeError('Unexpected archive pagination beyond 100 pages')
        response = client.fetch(url, refresh=True)
        seen.add(url); urls.append(url)
        archive_soup = BeautifulSoup(response.text, 'html.parser')
        if not archive_soup.select('article.elementor-post'):
            raise RuntimeError('No archive cards: ' + url)
        entries_from(archive_soup, url, entries)
        for a in archive_soup.select('.elementor-pagination a[href]'):
            following = urljoin(url, a['href'])
            if following.startswith(ARCHIVE) and following not in seen:
                pending.append(following)
    if not entries:
        raise RuntimeError('Empty audit enumeration')
    return entries, urls, {'year_grid_pagination': widgets, 'published_unique_blog_entries': len(published_urls),
                           'audit_archive_pages': len(seen), 'archive_only_entries': sorted(set(entries) - published_urls)}


def report_links(soup, base):
    content = soup.select_one('.elementor-widget-theme-post-content') or soup.select_one('.entry-content')
    if content is None:
        raise RuntimeError('Audit blog content container absent')
    links = {}
    for a in content.select('a[href]'):
        url = urljoin(base, a['href'])
        text = a.get_text(' ', strip=True)
        lower = url.lower()
        if ('.pdf' in urlsplit(url).path.lower() or
            re.search(r'(?:final[-_])?(?:audit[-_])?report', urlsplit(url).path, re.I) or
            ('github.com/LeastAuthority/audit-reports/' in url) or
            re.search(r'\b(?:report|full audit|full security audit)\b', text, re.I)):
            if urlsplit(url).scheme == 'http':
                url = 'https:' + url[5:]
            if urlsplit(url).scheme == 'https' and not lower.endswith(('.png','.jpg','.jpeg')):
                links.setdefault(url, text)
    return content, links


def report_item(client, url, entry, label, date, date_note):
    reference = REFERENCE_HOSTS.get(urlsplit(url).hostname)
    if 'tezos-foundation-response' in url.lower():
        reference = 'Client response to audit; not an auditor report'
    if reference:
        return Item(url, entry['listing_url'], title=entry['title'] + ' — ' + label,
                    project=entry['title'], doc_kind='non_report', notes=reference)
    match = re.match(r'https://github.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)', url)
    if match:
        owner, repo, ref, path = match.groups()
        if not re.fullmatch(r'[a-f0-9]{40}', ref):
            try:
                revision = client.json(f'https://api.github.com/repos/{owner}/{repo}/commits/{quote(ref,safe="")}')['sha']
            except Exception:
                # The same public linked file page exposes its immutable revision;
                # this is useful when unauthenticated GitHub REST quota is exhausted.
                html = client.text(url)
                oid = re.search(r'"currentOid":"([a-f0-9]{40})"', html)
                if not oid:
                    raise RuntimeError('Cannot establish immutable revision of linked GitHub report: ' + url)
                revision = oid[1]
        else:
            revision = ref
        public = f'https://github.com/{owner}/{repo}/blob/{revision}/{path}'
        download = f'https://raw.githubusercontent.com/{owner}/{repo}/{revision}/{path}'
    else:
        # WordPress attachment slugs redirect to original PDF URLs. Preserve the
        # stable publisher link while downloading the actual bytes, never the blog.
        public, download = url, url
    return Item(public, entry['listing_url'], title=entry['title'] + (' — ' + label if label and label.lower() != 'report' else ''),
                project=entry['title'], date=date, date_precision='day' if len(date) == 10 else ('year' if len(date) == 4 else 'none'),
                date_basis='listing',
                download_url=download,
                doc_kind='fix_review' if re.search(r'fix[-_ ](?:review|log)|follow[-_ ]up', label+' '+url, re.I) else 'audit_report',
                notes=f"Publisher audit announcement: {entry['url']}. {date_note}")


def build_listing(client, fresh_details=True):
    entries, urls, evidence = enumerate_entries(client)
    directory = ROOT / 'data' / 'collect' / FIRM
    atomic_json(directory / 'source-entries.json', {'entries': list(entries.values()), 'evidence': evidence, 'listing_urls': urls})
    items = []
    for n, (url, entry) in enumerate(sorted(entries.items()), 1):
        exclusion = next((reason for token,reason in EXCLUDED.items() if token in url), None)
        if exclusion:
            items.append(Item(url, entry['listing_url'], title=entry['title'], project=entry['title'],
                              doc_kind='non_report', notes='Outside Web3 scope: ' + exclusion))
            continue
        try:
            response = client.fetch(url, refresh=fresh_details)
            soup = BeautifulSoup(response.text, 'html.parser')
            content, links = report_links(soup, response.url)
            text = content.get_text(' ', strip=True)
            date, note = entry['date'], 'Date is publisher announcement date.'
            completed = re.search(r'(?:final\s+(?:audit\s+)?report\s+(?:was\s+)?completed\s+on|audit\s+was\s+completed\s+on)\s+([A-Z][a-z]+\s+\d{1,2},?\s+\d{4})', text)
            if completed:
                completion = dt.datetime.strptime(completed[1].replace(',', ''), '%B %d %Y').date().isoformat()
                note += ' Completion date separately stated in announcement: ' + completion + '.'
            if not date:
                meta = soup.select_one('meta[property="article:published_time"]')
                if meta and meta.get('content'):
                    date = meta['content'][:10]
            if not links:
                items.append(Item(url, entry['listing_url'], title=entry['title'], project=entry['title'],
                                  date=date, date_precision='day' if date else 'none',
                                  notes='ERROR: No report link found in audit announcement; do not cache the announcement as report.'))
            else:
                for report_url, label in links.items():
                    items.append(report_item(client, report_url, entry, label, date, note))
        except Exception as exc:
            items.append(Item(url, entry['listing_url'], title=entry['title'], project=entry['title'],
                              notes='ERROR: Announcement/report discovery failed: ' + str(exc)))
        if n % 20 == 0 or n == len(entries):
            print(f'{FIRM}: resolved announcement {n}/{len(entries)}', flush=True)
    return Listing(items, urls,
                   'Exhaust all per-year Elementor data-max-page grids; crawl all linked audit-category archive pages; expand each announcement into linked report artifacts.',
                   'listed_count counts unique report-link candidates plus explicit excluded/no-link announcement entries, not engagements. '
                   'source-entries.json preserves publisher card counts, archive reconciliation and scope tags. '
                   'Multi-part reports are separate original files; duplicate public links merge. '
                   'General software audits, cited reference papers/specifications, and client responses are explicit non_report skips. '
                   'Date hints preserve publisher listing/announcement dates; separately stated completion dates remain in notes.'), evidence


def resolve(client, item):
    if item.doc_kind != 'non_report' and item.notes.startswith('ERROR:'):
        raise RuntimeError(item.notes)
    if item.doc_kind != 'non_report':
        response = client.fetch(item.download_url or item.public_url)
        if not response.body.startswith(b'%PDF-') and not urlsplit(response.url).path.endswith('.md'):
            raise RuntimeError('Linked target is not a report PDF/Markdown original: ' + response.url)
    return item


def main():
    from web_dedaub import Reconcile, item
    g = Reconcile(FIRM)
    client = Client()
    try:
        listing, evidence = build_listing(client, fresh_details=False)
    except Exception as exc:
        enumeration_failed(FIRM, [INDEX, ARCHIVE], exc)
        raise
    for original in {i.public_url: i for i in listing.items}.values():
        e = item(original.public_url, original.listing_url, original.title, original.project,
                 original.date, download_url=original.download_url, notes=original.notes)
        if original.doc_kind == 'non_report':
            g.exclude(e, original.notes)
            continue
        row, error = g.find(e), ''
        if row is None:
            try:
                response = client.fetch(original.download_url or original.public_url, refresh=True)
                row = g.save(e, {'retrieved_utc': response.retrieved_utc}, response.body)
            except Exception as exc:
                error = str(exc)
                if 'robots' not in error and '403' not in error:
                    try:
                        replay, meta, body = g.wayback(original.download_url or original.public_url)
                        row = g.save(e, meta, body, public=replay)
                    except Exception as archive_error:
                        error += '; Wayback: ' + str(archive_error)
        g.report(e, row, error)
    g.fetch.evidence.extend(client.observations)
    excluded = sum(r['classification'] != 'audit_report' for r in g.receipts)
    g.finish(listing.urls, [
        'Live year-grid pagination and complete audit-category archive re-enumerated. ' + json.dumps(evidence),
        'Successful previously resolved report links reuse timestamped public announcement snapshots; newly missing originals are fetched live. No announcement is collected as a report.',
        f'Excluded {excluded} references, client responses and ordinary-software scope exclusions; all exclusions are itemized. Historical recoveries outside the live listing remain in reports.jsonl.'
    ], f'{excluded} references/out-of-scope entries excluded; historical recoveries retained separately. ' +
       ('No remaining gap.' if all('acquisition' in r for r in g.receipts if r['classification']=='audit_report') else 'See item-level gaps.'))


if __name__ == '__main__':
    main()
