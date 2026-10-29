#!/usr/bin/env python3
"""Collect all report links in OtterSec's full server-rendered audit archive.

Run: python3 -I scripts/collect/web_ottersec.py
Stable /reports/ UUID URLs remain public URLs; signed redirect targets stay private.
"""
from __future__ import annotations

from datetime import datetime
import html
import importlib.util
import json
from pathlib import Path
import re
import sys
from urllib.parse import urljoin, urlsplit, quote

_spec = importlib.util.spec_from_file_location('web_common', Path(__file__).with_name('web_common.py'))
common = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = common
_spec.loader.exec_module(common)

BASE = 'https://osec.io'
URL = BASE + '/audits'


def plain(value):
    return ' '.join(html.unescape(re.sub(r'<[^>]*>', ' ', value)).split())


def field(row, tag):
    match = re.search(r'<' + tag + r'\b[^>]*>(.*?)</' + tag + '>', row, re.S)
    return plain(match.group(1)) if match else ''


def listing(client):
    text = client.fetch(URL, refresh=True).text
    rows = re.findall(r'<audit-row\b[^>]*>(.*?)</audit-row>', text, re.S)
    if not rows:
        raise ValueError('OtterSec archive has no audit rows')
    items = {}
    no_report = 0
    for row in rows:
        project, date_text, chain = (field(row, name) for name in ('audit-name', 'audit-date', 'audit-chain'))
        date = datetime.strptime(date_text, '%B %d, %Y').date().isoformat() if date_text else ''
        links = [html.unescape(href) for href in re.findall(r'href="([^"]+)"', row)]
        report_links = [u for u in links if re.fullmatch(r'/reports/[0-9a-f-]{36}', u)
                        or (u.startswith('https://github.com/') and urlsplit(u).path.lower().endswith('.pdf'))]
        if not report_links:
            no_report += 1
        bugs = {severity: plain(label) for severity, label in re.findall(
            r'<audit-bug\b[^>]*data-severity="([^"]+)"[^>]*>(.*?)</audit-bug>', row, re.S)}
        for link in report_links:
            url = urljoin(BASE, link)
            notes = json.dumps({'listing_chain': chain, 'listing_findings': bugs,
                                'listing_date_text': date_text,
                                'alternate_report_links': [urljoin(BASE, u) for u in report_links if u != link]},
                               ensure_ascii=False)
            items[url] = common.Item(public_url=url, listing_url=URL, title=project,
                                     project=project, date=date, date_precision='day' if date else 'none', notes=notes)
    # Ensure every UUID and external PDF is accounted for, even if markup changes.
    exposed = {urljoin(BASE, html.unescape(u)) for u in re.findall(r'href="(/reports/[0-9a-f-]{36})"', text)}
    exposed.update(urljoin(BASE, html.unescape(u)) for u in re.findall(
        r'<a\b[^>]*data-report\b[^>]*href="([^"]+)"', text))
    exposed.update(html.unescape(u) for u in re.findall(r'href="(https://github\.com/[^"<>]+\.pdf)"', text))
    if not exposed or exposed != set(items):
        raise ValueError('OtterSec archive contains report links outside parsed audit rows')
    return common.Listing(items=list(items.values()), urls=[URL],
                          method='All server-rendered audit rows, stable UUID report links and external GitHub PDFs.',
                          notes=f'Archive audit rows={len(rows)}; rows without a report link={no_report}. '
                                'GitHub PDF source links are retained as separately listed artifact URLs; '
                                'alternate links are noted for later engagement deduplication. '
                                'Report UUID redirects may use temporary signed PDF downloads.')


def resolve(client, item):
    if urlsplit(item.public_url).netloc != 'github.com':
        return item
    parts = urlsplit(item.public_url).path.strip('/').split('/')
    if len(parts) < 5 or parts[2] not in ('blob', 'raw'):
        raise ValueError('Unexpected GitHub PDF link')
    owner, repo, _, ref = parts[:4]
    if not re.fullmatch('[0-9a-f]{40}', ref):
        commit = json.loads(client.fetch(f'https://api.github.com/repos/{owner}/{repo}/commits/{quote(ref, safe="")}').text)
        ref = commit['sha']
    path = '/'.join(parts[4:])
    item.public_url = f'https://github.com/{owner}/{repo}/blob/{ref}/{path}'
    item.download_url = f'https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}'
    return item


def main():
    client = common.Client()
    try:
        inventory = listing(client)
    except Exception as exc:
        common.enumeration_failed('ottersec', [URL], exc)
        raise
    common.collect('ottersec', inventory, client, resolve=resolve)


if __name__ == '__main__':
    main()
