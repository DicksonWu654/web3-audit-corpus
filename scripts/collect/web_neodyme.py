#!/usr/bin/env python3
"""Collect the live Neodyme report table, independently of the seed dataset."""
from web_batch2_common import *

METHOD = 'Complete server-rendered report table; all PDF download cells; no pagination.'
NOTES = 'Listing dates are publication dates. Live bytes are re-fetched independently of extracted/neodyme_v1.'


def enumerate_reports(fetch):
    url = 'https://www.neodyme.io/en/reports/'
    entries = []
    for target, n in links(fetch.text(url, fresh=True), url):
        if urlsplit(target).path.lower().endswith('.pdf'):
            row = n.up('tr')
            cells = [c.text() for c in row.all('td')]
            entries.append(item(target, url, cells[0], cells[0], cells[1], 'Security audit/review', expected_format='pdf',
                                notes='Listing SHA256: ' + cells[2]))
    assert entries, 'Empty report table'
    return entries, [url]


if __name__ == '__main__':
    collect('neodyme', enumerate_reports, METHOD, NOTES)
