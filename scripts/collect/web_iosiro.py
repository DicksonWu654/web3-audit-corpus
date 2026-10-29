#!/usr/bin/env python3
"""Follow every Webflow collection pagination link and save original HTML reports."""
from web_batch2_common import *

METHOD = 'Breadth-first traversal of every Webflow Next link; desktop/mobile duplicates merged by report URL.'
NOTES = 'Original HTML audit report pages; listing card publication dates retained.'


def enumerate_reports(fetch):
    start = 'https://www.iosiro.com/audits'
    queue, seen, entries = [start], set(), []
    while queue:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        text = fetch.text(url, fresh=True)
        for target, n in links(text, url):
            if '_page=' in target and 'Next' in n.text() and target not in seen:
                queue.append(target)
            if urlsplit(target).path.startswith('/audits/'):
                card = n.up(cls='w-dyn-item')
                if card is None:
                    continue
                headings = [h.text() for h in card.all() if h.tag in ('h2', 'h3', 'h4')]
                title = headings[0] if headings else n.text()
                entries.append(item(target, url, title, title.removesuffix(' Smart Contract Audit'), card.text(), 'Smart contract audit'))
        print('iosiro: enumerated ' + url, flush=True)
    assert entries, 'Empty iosiro listing'
    return entries, sorted(seen)


if __name__ == '__main__':
    collect('iosiro', enumerate_reports, METHOD, NOTES)
