#!/usr/bin/env python3
"""Follow Spearbit's engagement-table Cantina details to original PDF files."""
import datetime as dt
import re
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from web_common import Client, Item, Listing, ROOT, atomic_json, collect
from publisher_identity import reconcile

REPO = 'spearbit/portfolio'
INDEX = 'https://github.com/' + REPO


def main():
    client = Client()
    head = client.json('https://api.github.com/repos/'+REPO+'/commits/HEAD', refresh=True)['sha']
    listing = INDEX+'/blob/'+head+'/README.md'
    text = client.text('https://raw.githubusercontent.com/'+REPO+'/'+head+'/README.md')
    section = text.split('## Engagements', 1)[1].split('\n## ', 1)[0]
    items, evidence, failures, detail_urls = [], [], [], set()
    engagement_rows = sum(line.startswith('|') and len(line.split('|')) > 3 and
                          bool(re.search(r'20\d{2}', line.split('|')[2])) for line in section.splitlines())
    for line in section.splitlines():
        if not line.startswith('|'):
            continue
        cells = line.split('|')
        if len(cells) < 5:
            continue
        match = re.search(r'\[([^]]+)\]', cells[1])
        project = match[1] if match else cells[1].strip()
        date = ''
        try:
            date = dt.datetime.strptime(cells[2].strip().replace('Februrary', 'February'), '%B %Y').strftime('%Y-%m')
        except ValueError:
            pass
        targets = re.findall(r'\]\((https://cantina\.xyz/portfolio/[^)]+)\)', cells[3])
        for url in targets:
            detail_urls.add(url)
            try:
                response = client.fetch(url)
                # Inert Flight/HTML string extraction; never execute scripts.
                page = response.text.replace('\\"', '"').replace('\\/', '/')
                pdfs = sorted(set(re.findall(r'https://cdn\.cantina\.xyz/[^\s"<>\\]+?\.pdf', page)))
                if len(pdfs) != 1:
                    raise ValueError('Expected one original PDF in Cantina portfolio detail, found '+str(len(pdfs)))
                pdf = pdfs[0]
                items.append(Item(pdf, url, project+' Spearbit security review', project,
                    date, 'month' if date else 'none', original_format='pdf',
                    notes=f'Publisher: Spearbit; publisher portfolio={listing}; Cantina detail/listing={url}; original host=cdn.cantina.xyz. Engagement date from Spearbit table.'))
                evidence.append(dict(detail_url=url, pdf_url=pdf, publisher_listing=listing))
            except Exception as exc:
                failures.append(dict(url=url, error=str(exc)))
        for local in re.findall(r'\]\((pdf/[^)]+\.pdf)\)', cells[3]):
            public = INDEX+'/blob/'+head+'/'+local
            items.append(Item(public, listing, project+' Spearbit security review', project,
                              date, 'month' if date else 'none', original_format='pdf',
                              download_url='https://raw.githubusercontent.com/'+REPO+'/'+head+'/'+local,
                              notes='Publisher-linked local PDF candidate; preserve failure if absent.'))
    result = collect('spearbit', Listing(items, [listing], 'Publisher engagement rows → Cantina detail → original CDN PDF; SHA-256 publisher reconciliation.'), client)
    result['failures'].extend(failures)
    result['failed'] = len(result['failures'])
    result['detail_discovery_complete'] = not failures
    result.update(publisher_engagement_rows=engagement_rows, cantina_detail_links=len(detail_urls),
                  listed_count_basis='Unique linked original-file candidates; publisher engagement rows include unpublished/no-report entries and are recorded separately.')
    atomic_json(ROOT/'data/collect/spearbit/status.json', result)
    atomic_json(ROOT/'data/collect/spearbit/detail_evidence.json', dict(reports=evidence, failures=failures))
    reconcile('spearbit', ['cantina'])


if __name__ == '__main__':
    main()
