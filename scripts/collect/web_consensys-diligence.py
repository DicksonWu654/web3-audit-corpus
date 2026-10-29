#!/usr/bin/env python3
"""Collect the publisher's complete live public audit index and report HTML.

The index's JavaScript pagination only hides rows already in the HTML. No
JavaScript is run. The publisher sitemap is cross-checked for omitted routes.
"""
from __future__ import annotations

import datetime as dt
import json
import re
from urllib.parse import urljoin, urlsplit, urldefrag, unquote
from xml.etree import ElementTree as ET
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bs4 import BeautifulSoup
from web_common import Client, Item, Listing, ROOT, atomic_json, collect, enumeration_failed

FIRM = 'consensys-diligence'
INDEX = 'https://diligence.security/audits/'
LEGACY = 'https://diligence.consensys.io/audits/'
SITEMAP = 'https://diligence.security/sitemap.xml'
SUPPORTING_PDFS = {
    'Formalism_for_Shell_Protocol.pdf': 'Front-page title: Shell Protocol Description; mathematical protocol specification, not audit findings.',
    '1INCH-15499265-101220-1018.pdf': 'Front-page title: Mooniswap V2 (legacy); describes protocol fees/governance, not an audit report.',
    'Deferred-Comp-Release-Schedule.pdf': 'Front-page title: Orchid Treasury OXT Release; token release schedule, not audit findings.',
    'Zer0 DAO Token.pdf': 'Publisher HTML places link beside scope doc in the zDAO token scope list; supporting scope document. Private PDF not requested.',
}


def review_attachments(client, items):
    """Review historical publisher PDFs, preserving their engagement relationship."""
    reviewed = {}
    for page, item in list(items.items()):
        if not page.startswith(INDEX) or urlsplit(page).path.lower().endswith('.pdf'):
            continue
        try:
            soup = BeautifulSoup(client.text(page), 'html.parser')
        except Exception as exc:
            reviewed[page] = dict(url=page, engagement_page=page, decision='blocked', error=str(exc))
            continue
        engagement = INDEX+'2020/02/thesis-tbtc-and-keep/' if 'summary-thesis-tbtc-and-keep' in page else page
        if engagement != page:
            item.notes += ' artifact_role=summary_report; related_engagement='+engagement
        for a in soup.select('a[href]'):
            url = urldefrag(urljoin(page, a['href']))[0]
            if not url.startswith(INDEX) or not urlsplit(url).path.lower().endswith('.pdf'):
                continue
            label = a.get_text(' ', strip=True)
            name = unquote(urlsplit(url).path.rsplit('/', 1)[-1])
            appendix = name in SUPPORTING_PDFS or bool(re.search(r'mythx|appendix|automated.analysis|checklist|audit[ _-]+prep|\bspec\.pdf', name+' '+label, re.I))
            report = label.lower() == 'pdf' or bool(re.search(r'audit|report|summary|review', name+' '+label, re.I))
            role = 'appendix_or_support' if appendix else ('summary_report' if 'summary' in url.lower() else 'alternate_full_report')
            decision = 'exclude_appendix' if appendix else ('collect_alternate' if report else 'unresolved_attachment')
            reviewed[url] = dict(url=url, engagement_page=engagement, source_page=page, link_text=label, artifact_role=role, decision=decision)
            if name in SUPPORTING_PDFS:
                reviewed[url]['classification_evidence'] = SUPPORTING_PDFS[name]
            if report and not appendix:
                items.setdefault(url, Item(url, page, item.title+' (PDF '+role+')', item.project,
                    item.date, item.date_precision, original_format='pdf',
                    notes=f'artifact_role={role}; related_engagement={engagement}; publisher-native HTML/PDF representations of the same review, not additional engagements.'))
                item.notes += ' Alternate report artifact='+url+'; same engagement.'
            elif appendix:
                items.setdefault(url, Item(url, page, name, item.project, doc_kind='non_report',
                    notes=f'artifact_role={role}; related_engagement={engagement}; appendix, checklist or preparation/specification material excluded from audit/finding statistics.'))
    return sorted(reviewed.values(), key=lambda r:r['url'])


def blog_reports(client, sitemap, items):
    blogs = sorted({node.text for node in sitemap.iter() if node.tag.endswith('loc') and
                    node.text and re.search(r'/blog/\d{4}/\d{2}/.+/', node.text)})
    evidence = {'blog_pages': len(blogs), 'new_report_links': [], 'blog_failures': []}
    for n, blog in enumerate(blogs, 1):
        try:
            soup = BeautifulSoup(client.text(blog, refresh='--refresh-blogs' in sys.argv), 'html.parser')
            content = soup.select_one('.blog-content')
            if content is None:
                raise RuntimeError('Expected blog content absent')
            heading = soup.find('h1')
            title = heading.get_text(' ', strip=True) if heading else blog
            for a in content.select('a[href]'):
                url = urldefrag(urljoin(blog, a['href']))[0]
                if re.match(r'https://(?:diligence\.security|diligence\.consensys\.io)/audits/(?:\d{4}/\d{2}/|private/).+', url):
                    url = re.sub(r'https://diligence\.consensys\.io/', 'https://diligence.security/', url)
                    if url in items:
                        continue
                    match = re.search(r'/audits/(\d{4}/\d{2})/', url)
                    date = match[1].replace('/', '-') if match else ''
                    items[url] = Item(url, blog, title=title, project=title, date=date,
                                      date_precision='month' if date else 'none',
                                      date_basis='filename',
                                      notes='Report linked in publisher blog; date from report route, not blog publication.')
                    evidence['new_report_links'].append({'blog': blog, 'url': url})
                    continue
                github = re.match(r'https://github.com/(ConsenSysDiligence)/([^/]+)(?:/(.*))?$', url, re.I)
                if not github or not re.search(r'audit[-_]report', github[2], re.I):
                    continue
                owner, repo, suffix = github.groups()
                if suffix and not re.match(r'blob/[^/]+/.+\.(?:md|pdf)$', suffix, re.I):
                    continue
                try:
                    revision = client.json(f'https://api.github.com/repos/{owner}/{repo}/commits/HEAD')['sha']
                except Exception:
                    html = client.text(url)
                    oid = re.search(r'"currentOid":"([a-f0-9]{40})"', html)
                    if not oid:
                        raise RuntimeError('Cannot establish immutable revision of linked GitHub report: ' + url)
                    revision = oid[1]
                path = suffix.split('/', 2)[2] if suffix else 'README.md'
                public = f'https://github.com/{owner}/{repo}/blob/{revision}/{path}'
                if public in items:
                    continue
                match = re.search(r'(\d{4})[-_](\d{2})', repo)
                date = '-'.join(match.groups()) if match else ''
                items[public] = Item(public, blog, title=title, project=repo,
                                     date=date, date_precision='month' if date else 'none',
                                     date_basis='filename',
                                     download_url=f'https://raw.githubusercontent.com/{owner}/{repo}/{revision}/{path}',
                                     notes='Full official Markdown/PDF report explicitly linked by publisher blog. Date from report repository name.')
                evidence['new_report_links'].append({'blog': blog, 'url': public})
        except Exception as exc:
            evidence['blog_failures'].append({'url': blog, 'error': str(exc)})
        if n % 25 == 0 or n == len(blogs):
            print(f'{FIRM}: inspected publisher blogs {n}/{len(blogs)}', flush=True)
    return blogs, evidence


def enumerate_listing(client):
    response = client.fetch(INDEX, refresh=True)
    soup = BeautifulSoup(response.text, 'html.parser')
    container = soup.select_one('#public-audits-list')
    if container is None:
        raise RuntimeError('Expected public audit list absent; refusing to invent empty enumeration')
    items = {}
    for a in container.select('a.public-audits-row[href]'):
        paragraphs = a.select('p')
        if len(paragraphs) < 2:
            raise RuntimeError('Audit row lacks title/date: ' + str(a)[:200])
        title = paragraphs[0].get_text(' ', strip=True)
        label = paragraphs[1].get_text(' ', strip=True)
        date = dt.datetime.strptime(label, '%B %Y').strftime('%Y-%m')
        url = urljoin(response.url, a['href'])
        items[url] = Item(url, INDEX, title=title, project=title, date=date, date_precision='month',
                          doc_kind='audit_report',
                          notes='Publicly linked by publisher. Listing month is not asserted to be completion date.' +
                          (' Published summary report companion to the full Thesis engagement; not a separate audit.' if title.startswith('Summary - ') else ''))
    if not items:
        raise RuntimeError('Audit list contained no rows')
    sitemap = ET.fromstring(client.text(SITEMAP, refresh=True))
    sitemap_reports = sorted({node.text for node in sitemap.iter()
                              if node.tag.endswith('loc') and node.text and
                              re.search(r'/audits/(?:\d{4}/\d{2}/|private/).+/', node.text)})
    for url in sitemap_reports:
        if url not in items:
            match = re.search(r'/audits/(\d{4}/\d{2})/', url)
            date = match[1].replace('/', '-') if match else ''
            report_soup = BeautifulSoup(client.text(url), 'html.parser')
            heading = report_soup.find('h1')
            title = heading.get_text(' ', strip=True) if heading else urlsplit(url).path.rstrip('/').split('/')[-1].replace('-', ' ')
            items[url] = Item(url, SITEMAP, title=title, project=title,
                              date=date, date_precision='month' if date else 'none',
                              date_basis='filename',
                              notes='Publisher sitemap report absent from visible audit cards; date from dated report route.')
    blogs, blog_evidence = blog_reports(client, sitemap, items)
    attachment_review = review_attachments(client, items)
    notes = ('Index heading: Select Public Audits. All client-side pagination rows are present in response HTML; '
             'publisher sitemap cross-checked. Publicly linked /audits/private/ routes are retained as candidates; robots rules are checked before access. '
             'All dated publisher blogs in sitemap inspected for native report and official GitHub audit-report links. '
             'This measures the live publisher portfolio, not an asserted all-time engagement total. '
             'Legacy host now redirects to canonical diligence.security; previously observed HTTP 403 no longer applies.')
    return Listing(list(items.values()), [INDEX, SITEMAP] + blogs,
                   'All embedded .public-audits-row cards plus public publisher sitemap audit routes', notes), {
        'index_rows': len(container.select('a.public-audits-row[href]')),
        'sitemap_report_routes': len(sitemap_reports),
        'sitemap_only_report_routes': sorted(set(sitemap_reports) - {urljoin(response.url,a['href']) for a in container.select('a.public-audits-row[href]')}),
        'client_pagination': dict(container.attrs), 'canonical_index_url': response.url,
        'blog_archive': blog_evidence, 'attachment_review': attachment_review}


def resolve(client, item):
    if item.doc_kind == 'non_report':
        return item
    response = client.fetch(item.download_url or item.public_url)
    if item.public_url.startswith('https://github.com/') and len(response.body) < 3000:
        # GitHub serves repository symlinks as their path text through raw URLs.
        # Several historical official report repositories use README.md symlinks.
        target = response.text.strip()
        if re.fullmatch(r'[A-Za-z0-9_ .-]+\.(?:md|pdf)', target, re.I):
            item.public_url = item.public_url.rsplit('/', 1)[0] + '/' + target.replace(' ', '%20')
            item.download_url = item.download_url.rsplit('/', 1)[0] + '/' + target.replace(' ', '%20')
            response = client.fetch(item.download_url)
    if response.body.startswith(b'%PDF-') or urlsplit(response.url).path.endswith('.md'):
        if not response.body.startswith(b'%PDF-') and (len(response.text) < 3000 or not re.search(r'findings|issues|summary|assessment', response.text, re.I)):
            raise RuntimeError('Linked Markdown is not a complete report')
        return item
    soup = BeautifulSoup(response.text, 'html.parser')
    text = soup.get_text(' ', strip=True)
    if len(text) < 3000 or not re.search(r'Executive Summary|Security Assessment|Security Audit|Findings|Scope', text, re.I):
        raise RuntimeError('Linked page does not contain a complete audit report')
    item.notes += ' Full native HTML report retained (including findings), rather than a portfolio/announcement page.'
    return item


def normalize_report_metadata():
    reports_path = ROOT / 'data' / 'collect' / FIRM / 'reports.jsonl'
    rows = [json.loads(line) for line in reports_path.read_text().splitlines()]
    for row in rows:
        row['source_kind'] = 'website'
        if row['listing_url'] == SITEMAP or 'Date from report repository name.' in row['notes'] or 'date from report route' in row['notes']:
            row['date_basis'] = 'filename'
    reports_path.write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows))


def main():
    client = Client()
    try:
        listing, evidence = enumerate_listing(client)
    except Exception as exc:
        enumeration_failed(FIRM, [INDEX, SITEMAP], exc)
        raise
    result = collect(FIRM, listing, client, resolve=resolve)
    path = ROOT / 'data' / 'collect' / FIRM / 'listing.json'
    manifest = json.loads(path.read_text()); manifest['enumeration_evidence'] = evidence
    atomic_json(path, manifest)
    normalize_report_metadata()
    if evidence['blog_archive']['blog_failures']:
        result['enumeration_complete'] = False
        result['enumerated_candidates'] = result['listed_count']
        result['listed_count'] = None
        result['enumeration_failures'] = evidence['blog_archive']['blog_failures']
        atomic_json(path.with_name('status.json'), result)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
