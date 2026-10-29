#!/usr/bin/env python3
"""Collect the complete public Quantstamp certificate API, including legacy PDFs.

Run: python3 -I scripts/collect/web_quantstamp.py
The public API's publishedAt is a publication hint, never an inferred audit date.
"""
from __future__ import annotations

import ast
from collections import Counter
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import sys
from urllib.parse import urljoin, urlsplit

_spec = importlib.util.spec_from_file_location('web_common', Path(__file__).with_name('web_common.py'))
common = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = common
_spec.loader.exec_module(common)

BASE = 'https://certificate.quantstamp.com/'
API = BASE + 'api/certificates'


def listing(client):
    first = json.loads(client.fetch(API, refresh=True).text)
    rows = list(first['data'])
    row_pages = {row['id']: API for row in rows}
    total = int(first['total'])
    size = len(rows)
    if not size or total < size:
        raise ValueError('Unexpected Quantstamp pagination')
    urls = [API]
    for offset in range(size, total, size):
        url = API + '?offset=' + str(offset)
        page = json.loads(client.fetch(url, refresh=True).text)
        if int(page['total']) != total:
            raise ValueError('Quantstamp total changed during pagination; rerun')
        rows.extend(page['data'])
        row_pages.update({row['id']: url for row in page['data']})
        urls.append(url)
    unique = {r['id']: r for r in rows}
    if len(unique) != total or len(rows) != total:
        raise ValueError(f'Incomplete Quantstamp pagination: {len(unique)} unique / {total}')
    items = []
    missing = 0
    for row in unique.values():
        link = row.get('link')
        if not link:
            missing += 1
            continue
        name = row.get('projectName', '')
        tags = [tag['name'] for tag in row.get('tags', []) if tag.get('name')]
        published = row.get('publishedAt', '')
        notes = json.dumps({'certificate_id': row['id'], 'listing_publishedAt': published,
                            'project_group': row.get('projectGroupName', ''), 'listing_tags': tags,
                            'date_semantics': 'publication date from certificate listing'}, ensure_ascii=False)
        items.append(common.Item(public_url=urljoin(BASE, link), listing_url=row_pages[row['id']], title=name,
                                 project=name, date=published[:10],
                                 date_precision='day' if published else 'none', notes=notes))
    return common.Listing(items=items, urls=urls,
                          method='Complete live public certificate API offset pagination; assert unique IDs equal API total.',
                          notes=f'API records={total}; records without public report link={missing}. '
                                'Includes historical PDFs and newer interactive HTML report payloads. '
                                'publishedAt is publication metadata, not audit completion date.')


def decode_payload(text):
    """Read a literal JSON payload from source text without evaluating code."""
    pattern = r"JSON\.parse\(('(?:\\.|[^'\\])*')\)"
    for match in re.finditer(pattern, text, re.S):
        try:
            report = json.loads(ast.literal_eval(match.group(1)))
        except (ValueError, SyntaxError):
            continue
        if isinstance(report, dict) and isinstance(report.get('reportContent'), dict):
            if all(key in report['reportContent'] for key in ('setup', 'summary')):
                return report
    return None


def resolve(client, item):
    if urlsplit(item.public_url).path.lower().endswith('.pdf'):
        return item
    if not item.public_url.endswith('/index.html'):
        raise ValueError('Unexpected Quantstamp report link format')
    # CRA's public asset manifest names the report's data chunk. Read bytes only;
    # neither the application bundle nor the report chunk is ever executed.
    manifest_url = urljoin(item.public_url, 'asset-manifest.json')
    manifest = json.loads(client.fetch(manifest_url).text)
    rewritten = {}

    def asset_url(value):
        url = urljoin(item.public_url, value)
        current_directory = urljoin(item.public_url, '.')
        if url.startswith(BASE) and '/static/' in url and not url.startswith(current_directory):
            fixed = urljoin(current_directory, 'static/' + url.split('/static/', 1)[1])
            rewritten[url] = fixed
            return fixed
        return url

    candidates = [asset_url(value) for key, value in manifest['files'].items()
                  if re.fullmatch(r'static/js/[0-9]+\.[0-9a-f]+\.chunk\.js', key)]
    if not candidates and manifest['files'].get('main.js'):
        # Older reports inline their report JSON in the application bundle.
        candidates = [asset_url(manifest['files']['main.js'])]
    payloads = []
    for url in dict.fromkeys(candidates):
        payload = client.fetch(url).text
        if decode_payload(payload) is not None:
            payloads.append(url)
    if len(payloads) != 1:
        raise ValueError(f'Expected one substantive Quantstamp report data chunk, found {len(payloads)}')
    item.download_url = payloads[0]
    item.original_format = 'other'
    notes = json.loads(item.notes)
    notes.update({'original_representation': 'Official interactive report JSON embedded in JavaScript asset (data chunk or older application bundle); never executed',
                  'asset_manifest_url': manifest_url, 'report_payload_url': item.download_url,
                  'stale_asset_urls_rebased_to_current_report_directory': rewritten})
    item.notes = json.dumps(notes, ensure_ascii=False)
    return item


def verify_local():
    """Validate exact local originals; decode a string literal, never JS code."""
    directory = common.ROOT / 'data/collect/quantstamp'
    rows = [json.loads(line) for line in (directory / 'reports.jsonl').read_text().splitlines()]
    seen = set()
    for row in rows:
        if row['public_url'] in seen:
            raise ValueError('Duplicate public URL: ' + row['public_url'])
        seen.add(row['public_url'])
        body = (common.ROOT / row['local_path']).read_bytes()
        if hashlib.sha256(body).hexdigest() != row['sha256'] or len(body) != row['bytes']:
            raise ValueError('Local original checksum/size mismatch: ' + row['local_path'])
        if row['file_format'] == 'pdf':
            if not body.startswith(b'%PDF-'):
                raise ValueError('Invalid PDF signature')
        elif row['file_format'] == 'other':
            # Ignore surrounding application code and read only its JSON string.
            if decode_payload(body.decode()) is None:
                raise ValueError('Report content structure absent: ' + row['public_url'])
        else:
            raise ValueError('Unexpected Quantstamp original format: ' + row['file_format'])
    status = json.loads((directory / 'status.json').read_text())
    if status['collected'] != len(rows):
        raise ValueError('Status collected count does not match report rows')
    print(json.dumps({'firm_id': 'quantstamp', 'verified_records': len(rows),
                      'file_formats': dict(Counter(row['file_format'] for row in rows)),
                      'listed_count': status['listed_count'], 'failed': status['failed']}))


def main():
    client = common.Client()
    try:
        inventory = listing(client)
    except Exception as exc:
        common.enumeration_failed('quantstamp', [API], exc)
        raise
    common.collect('quantstamp', inventory, client, resolve=resolve)


if __name__ == '__main__':
    if sys.argv[1:] == ['--verify-local']:
        verify_local()
    elif sys.argv[1:]:
        raise SystemExit('Usage: web_quantstamp.py [--verify-local]')
    else:
        main()
