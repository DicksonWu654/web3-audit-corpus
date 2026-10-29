#!/usr/bin/env python3
"""Collect Veridise's entire audit archive table and linked original PDFs."""
from web_batch2_common import *
import xml.etree.ElementTree as ET

METHOD = 'Full DataTables audit table, full audit-report sitemap, and every blog post from the post sitemap; resolve publisher report PDFs, including older posts outside the audit-announcement category.'
NOTES = 'Audits service page links to /audits-archive/. Table month is retained even when report-page slug differs. Duplicate links merged by stable URL.'


def enumerate_reports(fetch):
    url = 'https://veridise.com/audits-archive/'
    entries = []
    for target, n in links(fetch.text(url, fresh=True), url):
        if n.text().strip() != 'Report' or not n.up('tr'):
            continue
        cells = [c.text() for c in n.up('tr').all('td')]
        # Columns: title, report, date, company, language, tags.
        entries.append(item(target, url, cells[0], cells[3], cells[2], ', '.join(cells[4:])))
    assert entries, 'Empty Veridise archive'
    sources = [url]
    def locations(sitemap):
        sources.append(sitemap)
        root = ET.fromstring(fetch.read(sitemap, fresh=True))
        return [n.text for n in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url/{http://www.sitemaps.org/schemas/sitemap/0.9}loc')]
    known = {e['public_url'].rstrip("/'") for e in entries}
    for target in locations('https://veridise.com/audit-report-sitemap.xml'):
        if target.rstrip('/') in known:
            continue
        text = fetch.text(target)
        dom = DOM(text)
        title = next((n.text() for n in dom.all('h1')), target.rstrip('/').rsplit('/',1)[-1])
        # Report-page visible metadata is listing evidence; URL slug dates are not substituted.
        dates = [n.attrs.get('datetime',n.text()) for n in dom.all('time')]
        completed = re.search(r'\bCOMPLETED\s+(.{0,80}?)\s+View Audit Report', dom.root.visible_text())
        listing_date = dates[0] if dates else completed[1] if completed else ''
        entries.append(item(target, 'https://veridise.com/audit-report-sitemap.xml', title, title.split(':',1)[0], listing_date, 'Security audit'))
    downloads = set()
    for e in entries:
        try:
            resolved = resolve_report(fetch, e)
            e.update(resolved)
            downloads.add(e.get('download_url',e['public_url']))
        except Exception:
            pass  # Collection retries resolution and records a per-link failure.
    for post in locations('https://veridise.com/post-sitemap.xml'):
        if '/blog/' not in post:
            continue
        text = fetch.text(post)
        dom = DOM(text)
        title = next((n.text() for n in dom.all('h1')), post)
        dates = [n.attrs.get('content','') for n in dom.all('meta') if n.attrs.get('property')=='article:published_time']
        sources.append(post)
        for target,n in links(text,post):
            filename=unquote(urlsplit(target).path.rsplit('/',1)[-1]).lower()
            explicit_report=(re.search(r'(?:audit|report).*\.pdf$',filename,re.I)
                             and re.search(r'auditing projects|\bour (?:audit )?report\b|we(?:\W+\w+){0,6}\W+audited',n.parent.text(),re.I))
            if '/blog/audits-archive/' not in post and 'veridise' not in target.lower() and not filename.startswith('var_') and not explicit_report:
                continue  # Other publishers' reports and cited research are not Veridise audits.
            if urlsplit(target).path.lower().endswith('.pdf') and target not in downloads:
                e=item(target,post,title,title.split(':',1)[0],dates[0] if dates else '', 'Security audit',expected_format='pdf')
                label=n.text().strip()
                if label and not label.startswith(('http:','https:')) and not re.fullmatch(r'(?:here|report|audit report|download|read more)',label,re.I):
                    e['project_hint']=re.sub(r'^audited the\s+','',label,flags=re.I)
                if re.match(r'day\d-lecture-|ethcc2024_',filename) or filename=='formal-methods-for-zkp.pdf':
                    e.update(skip_reason='Conference presentation or teaching slides, not an engagement audit report.',doc_kind='non_report',audit_type='Presentation/teaching')
                elif filename in ('multimod.pdf','zequal.pdf'):
                    e.update(skip_reason='Academic research paper, not an engagement audit report.',doc_kind='non_report',audit_type='Academic research')
                entries.append(e)
                downloads.add(target)
    return entries, sources


def resolve_report(fetch, entry):
    url = entry['public_url']
    if entry.get('download_url'):
        return entry
    if urlsplit(url).path.lower().endswith('.pdf'):
        return entry
    text = fetch.text(url)
    pdfs = [u for u, n in links(text, url) if urlsplit(u).path.lower().endswith('.pdf')]
    if not pdfs:
        raise RuntimeError('No original PDF linked by report page: ' + url)
    entry['download_url'] = pdfs[0]
    entry['expected_format'] = 'pdf'
    return entry


if __name__ == '__main__':
    collect('veridise', enumerate_reports, METHOD, NOTES, resolve_fn=resolve_report)
