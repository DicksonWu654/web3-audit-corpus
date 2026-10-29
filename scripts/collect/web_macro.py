#!/usr/bin/env python3
"""Collect Macro's complete library of original HTML audit reports."""
from web_batch2_common import *

METHOD = 'All Full Report links in the complete server-rendered library; no pagination.'
NOTES = 'HTML Full Report pages are the original reports. Audit Report Release Date is retained as a listing hint.'


def enumerate_reports(fetch):
    url = 'https://0xmacro.com/library'
    entries = []
    for target, n in links(fetch.text(url, fresh=True), url):
        if '/library/audits/' not in target:
            continue
        dl = n.up('dl')
        date = ''
        for block in dl.children:
            if isinstance(block, Node) and block.text().startswith('Audit Report Release Date'):
                date = block.text().removeprefix('Audit Report Release Date')
        card = dl.parent.parent
        headings = [h.text() for h in card.all() if h.tag in ('h2', 'h3', 'h4')]
        title = headings[0] if headings else target.rsplit('/', 1)[-1]
        entries.append(item(target, url, title, title, date, 'Smart contract audit'))
    assert entries, 'Empty Macro library'
    return entries, [url]


if __name__ == '__main__':
    collect('macro', enumerate_reports, METHOD, NOTES)
