#!/usr/bin/env python3
"""Collect Ackee's official archive plus PDFs linked by all audit blog pages."""
from web_batch2_common import *

METHOD = 'Commit-pinned full public-audit-reports ZIP manifest, full public-audits blog list, and every audit-category archive page and linked post.'
NOTES = 'ackeeblockchain.com redirects to ackee.xyz. Blog publication timestamps enrich matching PDFs; filename-only dates remain explicitly labelled. Original report links in client repositories are followed.'


def enumerate_reports(fetch):
    entries, repo = repo_entries(fetch, 'Ackee-Blockchain', 'public-audit-reports')
    by_name = {unquote(urlsplit(e['public_url']).path.rsplit('/', 1)[-1]).lower(): e for e in entries}
    start = 'https://ackee.xyz/blog/list-of-our-public-audits/'
    category = 'https://ackee.xyz/blog/category/audits/'
    queue, seen, posts = [start, category], set(), set()
    while queue:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        text = fetch.text(url, fresh=True)
        for target, n in links(text, url):
            if re.fullmatch(r'https://ackee\.xyz/blog/category/audits/page/\d+/', target) and target not in seen:
                queue.append(target)
            if '/blog/' not in target or any(x in target for x in ['/author/', '/category/', '/tag/', '/glossary/', 'Keyword']):
                continue
            if target.rstrip('/') == start.rstrip('/'):
                continue
            if url == start:
                # List content is an article, while recommendations are outside.
                if n.up('article'):
                    posts.add(target.split('#')[0])
            elif any(n.up(tag) for tag in ('article',)):
                posts.add(target.split('#')[0])
        print('ackee-blockchain: listing ' + url, flush=True)
    for i, url in enumerate(sorted(posts), 1):
        try:
            text = fetch.text(url)
            dom = DOM(text)
            article = next(dom.all('article'), dom.root)
            dates = [n.attrs.get('content', '') for n in dom.all('meta') if n.attrs.get('property') == 'article:published_time']
            date = dates[0] if dates else ''
            headings = [h.text() for h in dom.all('h1')]
            title = headings[0] if headings else url.rstrip('/').rsplit('/', 1)[-1]
            for n in article.all('a'):
                target = urljoin(url, n.attrs.get('href', ''))
                drive = re.search(r'https://drive\.google\.com/file/d/([^/?#]+)', target)
                if not urlsplit(target).path.lower().endswith('.pdf') and not (drive and re.search(r'audit|report', n.parent.text(), re.I)):
                    continue
                # Article links (not footer Impressum or unrelated recommendations).
                name = unquote(urlsplit(target).path).rsplit('/', 1)[-1].lower()
                entry = by_name.get(name)
                if entry:
                    entry.update(listing_url=url, title_hint=title, project_hint=title.removesuffix(' Audit Summary'))
                    entry['date_hint'], entry['date_precision'] = date_hint(date)
                    entry['date_basis'] = 'listing' if entry['date_hint'] else 'none'
                    entry['audit_type'] = 'Security audit'
                # Keep independently hosted originals even when their filenames
                # match: they can contain different revisions. A same-repository
                # branch link is already covered by its pinned manifest entry.
                same_repo_file = (entry is not None and '/Ackee-Blockchain/public-audit-reports/' in target
                                  and '/blob/' in target and unquote(target).split('/blob/',1)[-1].split('/',1)[-1]
                                  == unquote(entry['public_url']).split('/blob/',1)[-1].split('/',1)[-1])
                if not same_repo_file:
                    extra = {'download_url': 'https://drive.google.com/uc?export=download&id=' + drive[1]} if drive else {}
                    entries.append(item(target, url, title, title.removesuffix(' Audit Summary'), date, 'Security audit', expected_format='pdf', **extra))
        except Exception as exc:
            # A failed discovery page is evidence of incomplete enumeration; do not silently call it zero reports.
            raise RuntimeError('Cannot enumerate audit blog post ' + url + ': ' + str(exc)) from exc
        if i % 10 == 0:
            print(f'ackee-blockchain: inspected {i}/{len(posts)} audit posts', flush=True)
    assert entries, 'Empty Ackee archive'
    return entries, [repo] + sorted(seen | posts)


if __name__ == '__main__':
    collect('ackee-blockchain', enumerate_reports, METHOD, NOTES)
