#!/usr/bin/env python3
"""Collect NCC's live blockchain and Web3 cryptography report originals.

The former research.nccgroup.com archive redirects to www.nccgroup.com.
Enumerate the new public-report, cryptography and blockchain category APIs,
cross-check its sitemap for older audit announcements, then expand every
in-scope announcement into its linked report files. Never execute site scripts.
"""
from __future__ import annotations

import dataclasses
import html
from html.parser import HTMLParser
import importlib.util
import json
from pathlib import Path
import re
import sys
import time
from urllib.parse import urljoin, urlsplit
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('web_common', Path(__file__).with_name('web_common.py'))
common = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = common
spec.loader.exec_module(common)

BASE = 'https://www.nccgroup.com'
INDEX = BASE + '/research/research-articles/'
API = BASE + '/api/related/query?culture=en'
SITEMAP = BASE + '/sitemap.xml'
CATEGORIES = {'public_reports': '18157', 'cryptography': '18140', 'blockchain': '18144'}
AUDIT = re.compile(r'public.report|audit|assessment|(?:implementation|cryptograph\w*|code|security).{0,30}review', re.I)
WEB3 = re.compile(r'zcash|electric.coin|aleo|snark|zendoo|horizen|solana|threshold|ecdsa|qredo|milagro|rustcrypto|groth16|o.?1.labs|mina|coda|penumbra|decaf377|r1cs|powhsm|iov.labs|filecoin|blst|vechain|vetkeys|xmtp|boneh|blockchain|bitcoin|ethereum|wallet|entropy.?rust|entropyrust|schnorr|sapling|orchard|keyfork', re.I)


def plain(value):
    return ' '.join(html.unescape(re.sub(r'<[^>]+>', ' ', value)).split())


class Anchors(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.active = None

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            attrs = dict(attrs)
            self.active = [attrs.get('href', ''), '']

    def handle_data(self, data):
        if self.active:
            self.active[1] += data

    def handle_endtag(self, tag):
        if tag == 'a' and self.active:
            self.links.append(tuple(self.active))
            self.active = None


def enumerate_category(client, category):
    rows = {}
    for _ in range(200):
        query = {'ContentTypes': ['research'], 'ResourceTypes': [], 'Categories': [category],
                 'Sectors': [], 'Services': [], 'SortOrder': None, 'RootNode': '16856',
                 'Authors': [], 'ExcludedIds': sorted(rows), 'ResultAmount': '9',
                 'IsUserQuery': True, 'CultureFallback': False}
        page = client.post_json(API, query, refresh=True)
        fresh = [r for r in page['content'] if r['id'] not in rows]
        if not fresh:
            return list(rows.values())
        rows.update({r['id']: r for r in fresh})
        # The migrated API sometimes says moreResultsAvailable=false on an
        # intermediate batch. Exhaust by IDs until an empty response instead.
    raise ValueError('NCC category did not terminate')


def report_links(text, page):
    main = re.search(r'<main\b[^>]*>(.*?)</main>', text, re.S)
    parser = Anchors()
    parser.feed(main.group(1) if main else text)
    files = {}
    for href, label in parser.links:
        href = html.unescape(href)
        if href.startswith('~/'):
            href = BASE + href[1:]
        href = urljoin(page, href).replace('http://', 'https://')
        if re.search(r'\.pdf(?:$|[?#])', href, re.I) or re.search(r'download.*(?:public\s+)?report', label, re.I):
            if re.search(r'annual.*research', href, re.I):
                continue
            files.setdefault(href.split('#')[0], plain(label))
    return files


def listing(client):
    page = client.fetch(INDEX, refresh=True).text
    counts = {}
    for name, category in CATEGORIES.items():
        match = re.search(r'<option\b[^>]*value="' + category + r'"[^>]*>[^<]*\((\d+)\)', page)
        if not match:
            raise ValueError('Missing NCC category counter: ' + name)
        counts[name] = int(match.group(1))
    records = {}
    measured = {}
    for name, category in CATEGORIES.items():
        rows = enumerate_category(client, category)
        measured[name] = len(rows)
        if len(rows) != counts[name]:
            raise ValueError(f'NCC {name}: enumerated {len(rows)} vs live category count {counts[name]}')
        for row in rows:
            records.setdefault(urljoin(BASE, row['url']), row)
        print('ncc-group category', name, len(rows), flush=True)

    sitemap = client.fetch(SITEMAP, refresh=True)
    urls = {e.text for e in ET.fromstring(sitemap.body).iter() if e.tag.rsplit('}', 1)[-1] == 'loc'}
    for url in sorted(urls):
        if '/research/' in url and WEB3.search(url) and AUDIT.search(url):
            records.setdefault(url, {'url': url, 'title': urlsplit(url).path.strip('/').split('/')[-1].replace('-', ' '),
                                     'postedDateFormatted': '', 'sitemap_only': True})
    candidates, excluded = [], []
    for url, row in sorted(records.items()):
        title = html.unescape(row['title'])
        if not (AUDIT.search(title) and WEB3.search(title + ' ' + url)):
            excluded.append({'url': url, 'title': title, 'reason': 'Outside blockchain/Web3 cryptography audit scope'})
            continue
        candidates.append((url, row))

    items, sources = [], []
    for n, (url, row) in enumerate(candidates, 1):
        title, date = html.unescape(row['title']), row.get('postedDateFormatted') or ''
        source = {'url': url, 'title': title, 'date': date, 'sitemap_only': row.get('sitemap_only', False)}
        try:
            try:
                response = client.fetch(url, refresh=True)
            except common.FetchError as error:
                key = __import__('hashlib').sha256(url.encode()).hexdigest()
                if not (client.cache / (key + '.json')).exists():
                    raise
                # A fresh detail-page denial does not erase earlier successful
                # public evidence. Read only the local snapshot; no bypass.
                response = client.fetch(url)
                source['refresh_error'] = str(error)
                source['detail_snapshot_utc'] = response.retrieved_utc
            links = report_links(response.text, url)
            source['report_urls'] = list(links)
            if not date:
                # Publication metadata exposed by the article page is listing
                # metadata; sitemap lastmod is never substituted for audit dates.
                match = re.search(r'(?:article:published_time[^>]*content|datePublished["\s:]*)[="\s]+(20\d\d-\d\d-\d\d)', response.text)
                date = match.group(1) if match else ''
            if not links:
                # Preserve the live listing item as a documented file failure.
                item = common.Item(url, url, title, title, date, 'day' if date else 'none')
                item.notes = 'No PDF report original found in live announcement; do not archive announcement as report.'
                items.append(item)
                source['error'] = item.notes
            else:
                for report_url, label in links.items():
                    items.append(common.Item(
                        public_url=report_url if report_url.startswith(BASE) or len(links) > 1 else url,
                        download_url=report_url, listing_url=url, title=title + (' — ' + label if len(links) > 1 else ''),
                        project=re.sub(r'^Public Report\s*[:–—-]\s*', '', title, flags=re.I),
                        date=date[:10], date_precision='day' if date else 'none',
                        original_format='pdf',
                        notes=json.dumps({'announcement_url': url, 'original_download_url': report_url,
                                          'audit_type_hint': title, 'listing_date_semantics': 'publication date'}, ensure_ascii=False)))
        except Exception as e:
            source['error'] = str(e)
            items.append(common.Item(url, url, title, title, date, 'day' if date else 'none', notes='Listing resolution failed: ' + str(e)))
        sources.append(source)
        print('ncc-group source', n, '/', len(candidates), len(items), flush=True)
    common.atomic_json(common.ROOT / 'data/collect/ncc-group/source-entries.json', {
        'category_live_counters': counts, 'category_enumerated': measured,
        'scope': 'Blockchain projects and Web3 cryptographic primitives; generic infrastructure, messaging and VPN audits excluded.',
        'source_entries': sources, 'excluded_entries': excluded})
    return common.Listing(items, [INDEX, SITEMAP] + [INDEX + '?category=' + c for c in CATEGORIES.values()],
                          'Exhaust live public-report, cryptography and blockchain category API via ExcludedIds; '
                          'reconcile live category counters, cross-check sitemap, expand report file links.',
                          f'Category counters {counts}; in-scope announcement pages={len(sources)}. '
                          'listed_count is distinct linked report artifact URLs after expanding multipart reports; '
                          'unresolved in-scope announcements remain individual documented failures. '
                          'A denied detail refresh can reuse an earlier successfully retrieved public detail snapshot; '
                          'source-entries.json preserves that refresh error and snapshot timestamp. '
                          'Publication dates are hints, not asserted audit completion dates.')


def resolve(client, item):
    if not item.download_url:
        raise ValueError(item.notes)
    return item


def main():
    from web_dedaub import Reconcile, item
    g = Reconcile('ncc-group')
    client = common.Client()
    try:
        if '--resume-census' in sys.argv:
            saved = json.loads((g.out / 'collection_receipts.json').read_text())
            assert saved['measured_utc'][:10] == common.now()[:10], 'Resume requires today’s live census'
            inventory = common.Listing([common.Item(e['public_url'], e['listing_url'], e['title_hint'],
                e['project_hint'], e['date_hint'], e['date_precision'], download_url=e.get('download_url', ''),
                notes=e.get('notes', '')) for e in saved['items']], saved['listing_urls'],
                'Resume today’s completely enumerated live category/sitemap census.',
                'Original census receipts retained in the local HTTP cache and source-entries.json.')
        else:
            inventory = listing(client)
    except Exception as e:
        common.enumeration_failed('ncc-group', [INDEX, SITEMAP], e)
        raise
    # Separate Client's enumeration scheduler from Fetcher's download scheduler
    # when switching clients on the same publisher host.
    if client.observations:
        time.sleep(1.05)
    for original in {i.public_url: i for i in inventory.items}.values():
        e = item(original.public_url, original.listing_url, original.title, original.project,
                 original.date, download_url=original.download_url, notes=original.notes)
        row, error = g.find(e), ''
        if not row:
            try:
                meta, body = g.attempt(original.download_url or original.public_url, fresh=True)
                row = g.save(e, meta, body)
            except Exception as exc:
                error = str(exc)
                if not re.search(r'robots|login', error, re.I) and original.download_url:
                    try:
                        replay, meta, body = g.wayback(original.download_url)
                        row = g.save(e, meta, body, public=replay)
                    except Exception as archive_error:
                        error += '; Wayback: ' + str(archive_error)
                if (row is None and not re.search(r'robots|login', error, re.I)
                        and '/link/' in original.public_url and original.public_url.endswith('.aspx')):
                    # The migrated /link/ IDs are not historic file URLs. The
                    # original announcement captures establish their old asset
                    # paths; query those public originals, not guessed mirrors.
                    historic_pages = {
                        '7404a7d008c54067b1530499447f55bd': 'https://web.archive.org/web/20231130011930id_/https://research.nccgroup.com/2016/10/31/zcash-cryptography-and-code-review/',
                        '637973666fcf4159ba9994e5ac6f9bd3': 'https://web.archive.org/web/20240508061107id_/https://research.nccgroup.com/2019/01/31/zcash-overwinter-consensus-and-sapling-cryptography-review/',
                    }
                    asset_id = original.public_url.rsplit('/', 1)[-1].removesuffix('.aspx')
                    if asset_id in historic_pages:
                        try:
                            _, body = g.attempt(historic_pages[asset_id])
                            old_asset = 'https://research.nccgroup.com/wp-content/uploads/episerver-images/assets/' + asset_id + '.aspx'
                            if old_asset not in body.decode(errors='replace'):
                                raise ValueError('Archived announcement does not establish old asset URL')
                            e['archived_announcement'] = historic_pages[asset_id]
                            e['historical_original_url'] = old_asset
                            replay, meta, body = g.wayback(old_asset)
                            row = g.save(e, meta, body, public=replay)
                        except Exception as archive_error:
                            error += '; Historical publisher asset: ' + str(archive_error)
                    if row is None and asset_id in historic_pages:
                        # Earlier NCC report URLs used the publisher's .trust
                        # domain. Its public CDX index establishes the original
                        # file paths, which survived in Wayback even though the
                        # migrated Episerver attachment IDs did not.
                        from urllib.parse import urlencode
                        old_origins = {
                            '7404a7d008c54067b1530499447f55bd': 'https://www.nccgroup.trust/globalassets/our-research/us/public-reports/2016/october/ncc-group-zcash-crypto-report-2016--10-10.pdf',
                            '637973666fcf4159ba9994e5ac6f9bd3': 'https://www.nccgroup.trust/globalassets/our-research/us/public-reports/2019/ncc_group_zcash2018_public_report_2019-01-30_v1.3.pdf',
                        }
                        try:
                            query = 'https://web.archive.org/cdx/search/cdx?' + urlencode({
                                'url': '*.nccgroup.trust/*', 'output': 'json',
                                'filter': ['statuscode:200', 'urlkey:.*zcash.*'],
                                'collapse': 'urlkey', 'fl': 'timestamp,original,mimetype'}, doseq=True)
                            _, body = g.attempt(query)
                            captures = json.loads(body)
                            old_origin = old_origins[asset_id]
                            assert any(r[1] == old_origin and r[2] == 'application/pdf' for r in captures[1:]), 'Old publisher PDF absent from capture index'
                            e['historical_original_url'] = old_origin
                            e['notes'] += '; Historical publisher original=' + old_origin
                            replay, meta, body = g.wayback(old_origin)
                            row = g.save(e, meta, body, public=replay)
                        except Exception as archive_error:
                            error += '; Earlier publisher host: ' + str(archive_error)
        g.report(e, row, error)
        print('ncc-group collection', original.title, bool(row), error[:100], flush=True)
    g.fetch.evidence.extend(client.observations)
    gaps = [r for r in g.receipts if 'remaining_gap' in r]
    measured = json.loads((g.out / 'source-entries.json').read_text())
    g.finish(inventory.urls, [inventory.method, inventory.notes,
        'Live category counters: ' + json.dumps(measured['category_live_counters']) + '; enumerated: ' + json.dumps(measured['category_enumerated']) + '. See source-entries.json for each in-scope and excluded announcement.',
        'Category API counters and sitemap measured live; all enumerated in-scope announcements describe real commissioned cryptographic/code reviews. Dead PDF redirects remain report gaps, not non-report exclusions.',
        'Wayback queried for retired original URLs only; policy denials were not bypassed. Historical extra recovered originals do not inflate the matched numerator.'
    ], f'{len(gaps)} real report originals remain inaccessible; per-URL live/Wayback results recorded.' if gaps else 'All real report originals acquired; retired URLs recovered via Wayback.')


if __name__ == '__main__':
    main()
