#!/usr/bin/env python3
"""Collect the complete server-rendered ChainSecurity public audit archive."""
import argparse
import dataclasses
import html
import re
from dataclasses import replace
from html.parser import HTMLParser
from pathlib import Path
import sys
from urllib.parse import quote, urljoin, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from web_common import Client, Item, Listing, ROOT, atomic_json, collect, enumeration_failed, now

LISTING = 'https://www.chainsecurity.com/smart-contract-audit-reports'


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.report_links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a' and attrs.get('href'):
            self.links.append(attrs['href'])
            if 'cs-cta-primary' in attrs.get('class', '').split():
                self.report_links.append(attrs['href'])


def enumerate_listing(client):
    text = client.text(LISTING, refresh=True)
    starts = list(re.finditer(r'<div\b[^>]*\bdata-title="([^"]*)"[^>]*>', text))
    items = {}
    for index, match in enumerate(starts):
        row = text[match.start():starts[index + 1].start() if index + 1 < len(starts) else len(text)]
        link = re.search(r'href="(/security-audit/[^"?#]+)"', row)
        if not link:
            continue
        url = urljoin(LISTING, html.unescape(link[1]))
        date_match = re.search(r'cs-audit-row__date[^>]*>\s*(\d{4}-\d{2}-\d{2})', row)
        project_match = re.search(r'\bdata-client="([^"]*)"', match[0])
        title = html.unescape(match[1])
        date = date_match[1] if date_match else ''
        items[url] = Item(public_url=url, listing_url=LISTING, title=title,
                          project=html.unescape(project_match[1]) if project_match else '',
                          date=date, date_precision='day' if date else 'none',
                          doc_kind='formal_verification' if 'formal verification' in title.lower() else 'audit_report',
                          notes='Date and client are from the publisher public archive row.')
    all_links = {urljoin(LISTING, html.unescape(u)) for u in
                 re.findall(r'href="(/security-audit/[^"?#]+)"', text)}
    if set(items) != all_links or len(items) < 100:
        raise RuntimeError('Incomplete or changed ChainSecurity listing row parser')
    return Listing(items=[items[k] for k in sorted(items)], urls=[LISTING],
                   method='All server-rendered public audit archive rows; cross-checked against every security-audit link.',
                   notes='All archive rows are embedded in the public listing, independent of client-side filters.')


def report_urls(client, item, refresh=False):
    response = client.fetch(item.public_url, refresh=refresh)
    parser = Links()
    parser.feed(response.text)
    # Inline descriptions can cite external whitepapers. Retain the explicit
    # report buttons plus inline originals in the publisher's report directory
    # (e.g. Conic's deployment-validation report), not every cited PDF.
    candidates = list(parser.report_links)
    candidates.extend(u for u in parser.links
                      if urlparse(urljoin(response.url, html.unescape(u))).hostname in
                      ('www.chainsecurity.com', 'chainsecurity.com')
                      and urlparse(urljoin(response.url, html.unescape(u))).path.startswith('/reports/'))
    links = list(dict.fromkeys(quote(urljoin(response.url, html.unescape(u)),
                                    safe=":/?&=#%[]@!$'()*+,;~") for u in candidates
                               if urlparse(html.unescape(u)).path.lower().endswith('.pdf')))
    if not links:
        raise ValueError('No original PDF report linked from publisher audit page')
    return links


def expand_listing(client, source, refresh=True):
    """A publisher engagement page may link multiple originals/revisions."""
    items, evidence = {}, []
    path = ROOT / 'data' / 'collect' / 'chainsecurity' / 'source_pages.json'
    for n, page in enumerate(source.items, 1):
        urls = report_urls(client, page, refresh=refresh)
        evidence.append({'page': dataclasses.asdict(page), 'report_urls': urls})
        for index, url in enumerate(urls, 1):
            # Each publisher-linked file has its own stable public URL. Keep
            # revisions separately at collection time; engagement dedup is later.
            item = replace(page, public_url=url, listing_url=page.public_url,
                           download_url=url,
                           notes=page.notes + ' Original PDF linked from publisher detail page.'
                           + (f' File {index} of {len(urls)} linked originals.' if len(urls) > 1 else ''))
            items.setdefault(url, item)
        atomic_json(path, {'firm_id': 'chainsecurity', 'source_page_count': len(source.items),
                          'processed_source_pages': n, 'report_file_count': len(items),
                          'measured_utc': now(), 'pages': evidence})
        if n % 20 == 0 or n == len(source.items):
            print(f'chainsecurity listing: {n}/{len(source.items)} pages; '
                  f'{len(items)} unique original PDF URLs', flush=True)
    return Listing(items=[items[k] for k in sorted(items)], urls=source.urls,
                   method=source.method + ' Each detail page expanded to all linked original PDF URLs.',
                   notes=f'source_page_count={len(source.items)}; listed_count counts unique live original '
                   'PDF URLs, including revisions/additional reports linked from one engagement page. '
                   'Report actions and inline publisher /reports/ PDFs included; external whitepaper citations excluded. '
                   'Source-page evidence and metadata are in source_pages.json.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reuse-detail-cache', action='store_true',
                        help='Reuse detail pages fetched during an immediately preceding collection pass; '
                             'default refreshes every live detail listing.')
    parser.add_argument('--enumerate-only', action='store_true',
                        help='Write source-page/PDF-link evidence without changing collected reports.')
    args = parser.parse_args()
    client = Client()
    try:
        listing = expand_listing(client, enumerate_listing(client), refresh=not args.reuse_detail_cache)
    except Exception as error:
        enumeration_failed('chainsecurity', [LISTING], error)
        raise
    if not args.enumerate_only:
        collect('chainsecurity', listing, client)


if __name__ == '__main__':
    main()
