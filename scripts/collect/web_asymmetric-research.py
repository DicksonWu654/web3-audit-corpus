#!/usr/bin/env python3
"""Census official Asymmetric publications, explicitly excluding non-audits.

No dedicated public engagement-report archive was found. This collector retains
the complete reviewed publication inventory instead of claiming private audits
are public or treating marketing totals as report counts.
"""
from web_batch2_common import *
import xml.etree.ElementTree as ET

METHOD = 'Full official website sitemap/blog, complete security-advisories README table, and STRIDE findings page; classify publication candidates.'
NOTES = 'No publisher-hosted engagement audit-report listing found. Reviewed public publications are vulnerability disclosures, research/tutorials, or aggregate ecosystem findings, and are explicitly skipped. This is a bounded official-source census, not evidence that no client-hosted audit exists.'


def enumerate_reports(fetch):
    sitemap = 'https://asymmetric.com/sitemap.xml'
    repo = 'https://github.com/asymmetric-research/security-advisories'
    stride = 'https://stride.asymmetric.re/first-findings'
    entries, sources = [], [sitemap, repo, stride]
    urls = [n.text for n in ET.fromstring(fetch.read(sitemap, fresh=True)).iter() if n.tag.endswith('}loc')]
    for url in urls:
        if '/blog/' not in url or url.rstrip('/') == 'https://asymmetric.com/blog':
            continue
        text = fetch.text(url, fresh=True)
        dom = DOM(text)
        title = next((n.text() for n in dom.all('h1')), url)
        # Fail loudly if the publication structure changes to expose full audits.
        if any('.pdf' in u.lower() and 'asymmetric' in u.lower() for u, n in links(text, url)):
            raise RuntimeError('New report candidate needs classification: ' + url)
        entries.append(item(url, sitemap, title, '', '', 'Research/vulnerability disclosure',
                            skip_reason='Research, tutorial or single-vulnerability disclosure; not an engagement audit report.'))
        sources.append(url)
    text = fetch.text(repo, fresh=True)
    sha = github_head(fetch, 'asymmetric-research', 'security-advisories')
    article = next(DOM(text).all('article'))
    for row in article.all('tr'):
        for n in row.all('a'):
            target = urljoin(repo, n.attrs.get('href', ''))
            if '/advisories/' not in target:
                continue
            target = re.sub(r'/blob/[^/]+/', '/blob/' + sha + '/', target)
            entries.append(item(target, repo, n.text(), '', '', 'Vulnerability advisory',
                                skip_reason='Single-vulnerability advisory, not an engagement audit report.'))
    fetch.read(stride, fresh=True)
    entries.append(item(stride, 'https://stride.asymmetric.re/', 'The State of Solana Security: First Findings from STRIDE', '', 'June 2026',
                        'Aggregate ecosystem security assessment', skip_reason='Aggregate ecosystem findings; no individual engagement audit reports published.'))
    assert entries, 'Empty Asymmetric publication census'
    return entries, sources


def main():
    from web_dedaub import Reconcile, pin_github
    g = Reconcile('asymmetric-research')
    entries, urls = enumerate_reports(g.fetch)
    for e in {e['public_url']: e for e in entries}.values():
        public, download = pin_github(g.fetch, e['public_url'])
        text = g.fetch.text(download, fresh=True)
        dom = DOM(text)
        article = next(dom.all('article'), None) or next(dom.all('main'), dom.root)
        content = text if download.endswith('.md') else article.visible_text()
        # Preserve source excerpts and audit-related context for review, rather
        # than treating a blog/advisory index as a report-level denominator.
        e['evidence_excerpt'] = content[:1200]
        e['audit_context'] = [content[max(0,m.start()-100):m.end()+200]
                              for m in re.finditer(r'audit report|assessment report|security review', content, re.I)][:8]
        g.exclude(e, e['skip_reason'])
    g.finish(urls, [METHOD, NOTES,
        f'Fresh source inspection of all {len(entries)} enumerated publications; individual titles, excerpts and audit-related context retained in collection_receipts.json. None is a complete commissioned audit report.',
        'Set listed_count=0 rather than counting research articles, single-bug advisories or an aggregate STRIDE overview as audit reports. Zero reports does not establish coverage of client-hosted or private engagements.'
    ], f'All {len(entries)} publications are research/advisories/aggregate findings; no audit reports on these surfaces. Coverage is n/a.')


if __name__ == '__main__':
    main()
