#!/usr/bin/env python3
"""Collect OpenZeppelin's complete public Security Audits research archive.

Decode server-provided React Flight JSON as data; never execute page JavaScript.
The listing embeds its complete archive, including 2016 reports, independently of
the browser's client-side pagination. Dates are publication dates from the listing.
"""
import html
import json
import re
from dataclasses import replace
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from web_common import Client, Item, Listing, collect, enumeration_failed

LISTING = 'https://www.openzeppelin.com/research'
SERPENT = 'https://www.openzeppelin.com/news/serpent-compiler-audit-3095d1257929'
SERPENT_DOC = 'https://docs.google.com/document/d/1_PqXuAkvgUAOG3jbBvaUvqN6W90eJ3N4IdTLNMRAijo/edit'
# These category entries are announcements/disclosures or an audit OF the
# publisher, rather than reports of engagements performed by OpenZeppelin.
NON_REPORT_TITLES = {
    'Matter Labs Reveals Results of OpenZeppelin’s First zkSync 2.0 Security Audit',
    'Augur REP Token Critical Vulnerability Disclosure',
    'External audit of OpenZeppelin',
}


def flight_records(text):
    chunks = []
    for block in re.findall(r'self\.__next_f\.push\((.*?)\)</script>', text, re.S):
        try:
            row = json.loads(block)
            if row[0] == 1:
                chunks.append(row[1])
        except (ValueError, IndexError, TypeError):
            continue
    records = {}
    for line in ''.join(chunks).splitlines():
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        try:
            records[key] = json.loads(value)
        except ValueError:
            continue
    return records


def objects_in(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects_in(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects_in(child)


def resolve_reference(value, records):
    if not isinstance(value, str) or not value.startswith('$'):
        return value
    bits = value[1:].split(':')
    current = records.get(bits[0])
    try:
        for bit in bits[1:]:
            if bit == 'props' and isinstance(current, list) and current[0] == '$':
                current = current[3]
            else:
                current = current[int(bit)] if isinstance(current, list) else current[bit]
        return current
    except (KeyError, IndexError, TypeError, ValueError):
        return value


def enumerate_listing(client):
    records = flight_records(client.text(LISTING, refresh=True))
    entries = {r['_id']: r for payload in records.values() for r in objects_in(payload)
               if r.get('_type') == 'research' and r.get('_id')}
    items = {}
    for row in entries.values():
        categories = [resolve_reference(v, records) for v in row.get('categories', [])]
        if not any(isinstance(v, dict) and v.get('slug') == 'security-audits'
                   for v in categories):
            continue
        title = row.get('title', '')
        url = 'https://www.openzeppelin.com/news/' + row['slug']
        date = row.get('publishedAt', '')[:10]
        if date and not re.fullmatch(r'\d{4}-\d{2}-\d{2}', date):
            raise ValueError('Unexpected listing date: ' + date)
        kind = 'non_report' if title in NON_REPORT_TITLES else 'audit_report'
        if 'bugfix' in title.lower() or title == 'The Graph Rewards Manager Upgrade Audit':
            kind = 'fix_review'
        items[url] = Item(public_url=url, listing_url=LISTING, title=title, project=title,
                          date=date, date_precision='day' if date else 'none',
                          doc_kind=kind,
                          notes='Listing date is publication date, not asserted audit completion date. '
                          'Project hint is the unnormalized publisher listing title.'
                          + (' Category entry is announcement/disclosure or inbound external audit.'
                             if kind == 'non_report' else ''))
    if len(items) < 100:
        raise RuntimeError('Incomplete or changed OpenZeppelin category listing')
    summary = items[SERPENT]
    summary.notes += ' Engagement relation: Serpent compiler; artifact_role=finding-title HTML summary; full original='+SERPENT_DOC
    items[SERPENT_DOC] = Item(SERPENT_DOC, SERPENT, 'Zeppelin Solutions Serpent Compiler Audit v1.0.0',
        'Serpent compiler / Augur', summary.date, summary.date_precision,
        download_url=SERPENT_DOC.removesuffix('/edit')+'/export?format=txt', original_format='other',
        notes='artifact_role=full_report; engagement_summary='+SERPENT+'. Native full plain-text Google document export; same engagement as publisher HTML summary, not another audit.')
    return Listing(items=[items[k] for k in sorted(items)], urls=[LISTING],
                   method='Complete server-embedded React Flight research entries, resolving category references.',
                   notes='Security Audits category only; archive includes older reports from 2016 onward. '
                   'Non-report category entries are retained as explicit exclusions.')


def resolve(client, item):
    if item.doc_kind == 'non_report':
        return item
    if item.public_url == SERPENT_DOC:
        body = client.fetch(item.download_url).text
        if len(body) < 10000 or 'Serpent' not in body or not re.search(r'critical|finding', body, re.I):
            raise ValueError('Public Google document export does not contain full Serpent audit')
        return item
    response = client.fetch(item.public_url)
    text = response.text
    # Audit reports are publisher-native HTML, not PDF landing pages. Verify
    # report prose is present before storing HTML as a report original.
    visible = re.sub(r'<script\b[^>]*>.*?</script>', ' ', text, flags=re.S | re.I)
    visible = html.unescape(re.sub(r'<[^>]+>', ' ', visible))
    if not re.search(r'(?i)(critical severity|high severity|medium severity|low severity|'
                     r'critical issues|high.severity|medium.severity|low.severity|'
                     r'findings|audit scope|security assessment|audit report|'
                     r'security review|audited code|issues found|potential problems|'
                     r'assessment and recommendations|pull request has been audited)', visible):
        raise ValueError('No full audit report prose detected on category entry')
    return replace(item, download_url=item.public_url,
                   notes=item.notes + ' Full report is native publisher HTML.')


def main():
    client = Client()
    try:
        listing = enumerate_listing(client)
    except Exception as error:
        enumeration_failed('openzeppelin', [LISTING], error)
        raise
    collect('openzeppelin', listing, client, resolve=resolve)


if __name__ == '__main__':
    main()
