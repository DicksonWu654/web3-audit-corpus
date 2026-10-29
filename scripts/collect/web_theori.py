#!/usr/bin/env python3
"""Measure Theori's historical public list against canonical ChainLight originals."""
from web_dedaub import *


def main():
    g = Reconcile('theori', aliases=('chainlight',))
    url = 'https://github.com/theori-io/web3-publications'
    text = g.fetch.text(url, fresh=True)
    article = next(DOM(text).all('article'))
    entries = {}
    for node in article.all('a'):
        target = urljoin(url, node.attrs.get('href', ''))
        if not (urlsplit(target).path.lower().endswith('.pdf') or 'drive.google.com/file/d/' in target):
            continue
        entries.setdefault(target, item(target, url, node.text(), node.text(), expected_format='pdf'))
    assert entries, 'Theori report links absent'
    for e in entries.values():
        row, error = g.find(e), ''
        if row is None:
            try:
                target = e['public_url']
                if 'drive.google.com/file/d/' in target:
                    download = 'https://drive.google.com/uc?export=download&id=' + target.split('/d/')[1].split('/')[0]
                    public = target
                else:
                    public, download = pin_github(g.fetch, target)
                meta, body = g.attempt(download, fresh=True)
                row = g.save(e, meta, body, public=public)
            except Exception as exc:
                error = str(exc)
        g.report(e, row, error)
    g.finish([url], [
        'Re-enumerated all PDF/Drive report links in the live historical Theori Web3 README. These are real audit reports, not achievements/CTFs.',
        'The README identifies ChainLight of Theori. Existing originals filed under canonical publisher chainlight count via SHA-verified acquisition references; they are not copied or counted as new engagements.',
        'The remaining Blend original is on Google Drive; its download path is robots-disallowed. No login, alternate export route, or archive workaround was attempted.'
    ], 'Canonical ChainLight acquisitions reconciled; Blend remains blocked by Google Drive robots.txt.')

if __name__ == '__main__':
    main()
