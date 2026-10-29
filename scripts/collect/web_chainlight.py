#!/usr/bin/env python3
"""Collect ChainLight of Theori under one canonical SHA-deduplicated identity."""
from pathlib import Path
import re
import sys
from urllib.parse import quote, unquote, urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parent))
from web_common import Client, Item, Listing, ROOT, atomic_json, collect
from publisher_identity import reconcile

REPO = 'chainlight-io/publications'
INDEX = 'https://github.com/'+REPO


def pin(client, url):
    parts = urlsplit(url).path.strip('/').split('/')
    owner, repo, _, ref = parts[:4]
    path = quote(unquote('/'.join(parts[4:])), safe='/')
    if not re.fullmatch('[a-f0-9]{40}', ref):
        ref = client.json(f'https://api.github.com/repos/{owner}/{repo}/commits/{ref}')['sha']
    return (f'https://github.com/{owner}/{repo}/blob/{ref}/{path}',
            f'https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}')


def main():
    client = Client()
    head = client.json('https://api.github.com/repos/'+REPO+'/commits/HEAD', refresh=True)['sha']
    tree = client.json(f'https://api.github.com/repos/{REPO}/git/trees/{head}?recursive=1')
    if tree.get('truncated'):
        raise ValueError('Truncated ChainLight tree')
    listing = INDEX+'/blob/'+head+'/README.md'
    text = client.text(f'https://raw.githubusercontent.com/{REPO}/{head}/README.md')
    items, failures = [], []
    note = 'Canonical publisher=chainlight; publisher README identifies ChainLight of Theori (also The Duck/Theori). Historical theori records reconciled by SHA-256.'
    for blob in tree['tree']:
        path = blob['path']
        if blob['type'] != 'blob' or not path.lower().endswith('.pdf') or not path.startswith('audit-reports/'):
            continue
        public, download = pin(client, INDEX+'/blob/'+head+'/'+quote(path, safe='/'))
        items.append(Item(public, listing, Path(path).stem, Path(path).stem,
                          original_format='pdf', download_url=download, notes=note))
    year = ''
    for line in text.splitlines():
        if line.startswith('## '):
            years = re.findall(r'20\d{2}', line)
            year = years[0] if len(years) == 1 else ''
        if '](' in line and line.startswith('- '):
            url = line.split('](', 1)[1].split(') [', 1)[0].removesuffix(')')
            title = line[2:].split('](', 1)[0].lstrip('[').replace('\\', '')
        elif re.match(r'^\[[^]]+\]: https://', line):
            title, url = line.split(': ', 1)
            title = title.strip('[]')
        else:
            continue
        if not url.startswith('https://') or not (url.lower().endswith('.pdf') or 'drive.google.com/file/' in url):
            continue
        original = url
        try:
            if url.startswith('https://github.com/'):
                url, download = pin(client, url)
            elif 'drive.google.com/file/d/' in url:
                file_id = url.split('/d/', 1)[1].split('/')[0]
                download = 'https://drive.google.com/uc?export=download&id='+file_id
            else:
                download = url
            items.append(Item(url, listing, title, title, year, 'year' if year else 'none',
                original_format='pdf', download_url=download, notes=note+' Publisher-linked original='+original))
        except Exception as exc:
            failures.append(dict(url=original, error=str(exc)))
    result = collect('chainlight', Listing(items, [listing, 'https://theori.io/', 'https://chainlight.io/'],
        'Complete publisher audit-reports PDF tree plus client-hosted README report links.', note), client)
    result['failures'].extend(failures)
    result['failed'] = len(result['failures'])
    atomic_json(ROOT/'data/collect/chainlight/status.json', result)
    reconcile('chainlight', ['theori'], merge_all=True)


if __name__ == '__main__':
    main()
