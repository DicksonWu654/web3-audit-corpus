#!/usr/bin/env python3
"""Collect the Blockchain Report Archive and relevant older research posts."""
from web_batch2_common import *

METHOD = 'Follow all Webflow Load More archive pages and all Next research-blog pages; resolve report-page PDF embeds.'
NOTES = 'Only Blockchain Report Archive entries and publisher-authored blockchain/cryptography audit-report links from research posts are included. Other security research PDFs excluded.'


def enumerate_reports(fetch):
    start = 'https://kudelskisecurity.com/blockchain'
    queue, seen, entries = [start], set(), []
    while queue:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        text = fetch.text(url, fresh=True)
        for card in DOM(text).all('div'):
            if 'blockchain-card' not in card.attrs.get('class', '').split():
                continue
            targets = [(urljoin(url, n.attrs['href']), n) for n in card.all('a')
                       if n.attrs.get('href') and 'w-condition-invisible' not in n.attrs.get('class', '')]
            targets = [(u, n) for u, n in targets if u.startswith(('https://', 'http://'))]
            if not targets:
                raise RuntimeError('Archive card has no report link: ' + card.text())
            target, n = targets[0]
            textcard = card.text()
            title = re.sub(r'^[A-Za-z]+\s+20\d{2}\s*', '', textcard).split('Services')[0].strip()
            audit_type = textcard.split('Services', 1)[-1].split('Technologies', 1)[0].strip()
            entries.append(item(target, url, title, title, textcard, audit_type, expected_format='pdf'))
        for target, n in links(text, url):
            if 'w-pagination-next' in n.attrs.get('class', '') and target not in seen:
                queue.append(target)
        print('kudelski-security: archive ' + url, flush=True)
    # The migrated research blog embeds each article body on its listing page.
    queue = ['https://kudelskisecurity.com/research-blog']
    blogseen = set()
    while queue:
        url = queue.pop(0)
        if url in blogseen:
            continue
        blogseen.add(url)
        text = fetch.text(url, fresh=True)
        for target, n in links(text, url):
            if 'w-pagination-next' in n.attrs.get('class', '') and target not in blogseen:
                queue.append(target)
            if not urlsplit(target).path.lower().endswith('.pdf'):
                continue
            card = n.up(cls='w-dyn-item')
            if card is None:
                continue
            context = card.text()
            if not re.search(r'blockchain|smart.contract|cryptograph|\bcrypto\b', context, re.I):
                continue
            if not re.search(r'audit|secure code review|security assessment', context, re.I):
                continue
            explicit_report = (re.search(r'(?:audit|report|assessment).*\.pdf$', unquote(urlsplit(target).path), re.I)
                               and re.search(r'\bour report\b|performed assessments', n.parent.text(), re.I))
            if 'kudelski' not in target.lower() and not explicit_report:
                continue
            headings = [h.text() for h in card.all() if h.tag in ('h2', 'h3')]
            title = headings[0] if headings else n.text()
            dates = [x.text() for x in card.all() if re.fullmatch(r'[A-Za-z]+ \d{1,2}, 20\d{2}', x.text())]
            entries.append(item(target, url, title, title, dates[0] if dates else '', 'Blockchain/cryptography audit',
                                expected_format='pdf', notes='Additional report link in older research-blog article.'))
        print('kudelski-security: research ' + url, flush=True)
    assert entries, 'Empty Blockchain Report Archive'
    return entries, sorted(seen | blogseen)


def resolve_report(fetch, entry):
    url = entry['public_url']
    if '/blockchain-archive/' not in url:
        return entry
    text = fetch.text(url)
    pdfs = [urljoin(url, n.attrs.get('src', n.attrs.get('data', ''))) for n in DOM(text).all()
            if n.tag in ('iframe', 'embed', 'object') and '.pdf' in n.attrs.get('src', n.attrs.get('data', '')).lower()]
    pdfs += [u for u, n in links(text, url) if urlsplit(u).path.lower().endswith('.pdf')]
    if not pdfs:
        raise RuntimeError('No PDF original embedded/linked by archive page: ' + url)
    entry['download_url'] = pdfs[0]
    entry['expected_format'] = 'pdf'
    return entry


if __name__ == '__main__':
    collect('kudelski-security', enumerate_reports, METHOD, NOTES, resolve_fn=resolve_report)
