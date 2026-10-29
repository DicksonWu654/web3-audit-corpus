#!/usr/bin/env python3
"""Shared HTTP, provenance and collection helpers for website batch 2.

Only data is fetched; no downloaded scripts, repositories or report code is run.
HTTP response evidence is local-only under local-cache/web-batch2/.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
from html.parser import HTMLParser
import json
import io
from pathlib import Path
import re
import sys
import time
import zipfile
from urllib.parse import urljoin, urlsplit, unquote, quote
from urllib.robotparser import RobotFileParser

import requests

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / 'local-cache' / 'web-batch2'
UA = 'Web3AuditCorpus/1.0 (public security audit research; rate <=1 request/second/host)'


def utc():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


class Fetcher:
    def __init__(self, refresh=False):
        self.refresh = refresh
        self.robots = {}
        self.session = requests.Session()
        self.session.headers['User-Agent'] = UA
        self.evidence = []
        self.refs = {}
        self.delays = {}
        self.payloads = {}
        self.snapshot_times = {}

    def _request(self, url, payload=None):
        # A shared per-host flock also coordinates simultaneous collectors.
        host = urlsplit(url).netloc.lower()
        lockdir = CACHE / 'rate'
        lockdir.mkdir(parents=True, exist_ok=True)
        with (lockdir / (hashlib.sha256(host.encode()).hexdigest() + '.lock')).open('a+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            lock.seek(0)
            last = float(lock.read() or 0)
            time.sleep(max(0, max(1.05, self.delays.get(host, 0)) - (time.time() - last)))
            lock.seek(0)
            lock.truncate()
            lock.write(str(time.time()))
            lock.flush()
            # Redirects are followed manually so their host policy/rate is checked.
            if payload is None:
                response = self.session.get(url, timeout=(20, 90), allow_redirects=False)
            else:
                response = self.session.post(url, json=payload, timeout=(20, 90), allow_redirects=False)
        return response

    def _policy(self, url):
        p = urlsplit(url)
        origin = p.scheme + '://' + p.netloc
        if origin not in self.robots:
            meta, body = self.get(origin + '/robots.txt', robots=False, fresh=True)
            rp = RobotFileParser()
            if 400 <= meta['status'] < 500 and meta['status'] != 429:
                # RFC 9309 §2.3.1.3: a 4xx robots response is unavailable,
                # not a Disallow directive. Common on object-store CDNs.
                rp.allow_all = True
            elif meta['status'] == 200:
                lines = body.decode('utf-8', errors='replace').splitlines()
                rp.parse(lines)
                # robotparser does not implement RFC 9309 wildcard/end anchors.
                groups, agents, rules, delay = [], [], [], 0
                for line in lines + ['User-agent: __end__']:
                    line = line.split('#', 1)[0].strip()
                    if ':' not in line:
                        continue
                    key, value = [v.strip() for v in line.split(':', 1)]
                    key = key.lower()
                    if key == 'user-agent':
                        if rules or delay:
                            groups.append((agents, rules, delay))
                            agents, rules, delay = [], [], 0
                        agents.append(value.lower())
                    elif key in ('allow', 'disallow') and value:
                        rules.append((key == 'allow', value))
                    elif key == 'crawl-delay':
                        try:
                            delay = float(value)
                        except ValueError:
                            pass
                matching = [(a, r, d) for a, r, d in groups if any(x == '*' or x in UA.lower() for x in a)]
                specific = [(a, r, d) for a, r, d in matching if any(x != '*' and x in UA.lower() for x in a)]
                chosen = specific or matching
                rp.batch_rules = [rule for _, rules, _ in chosen for rule in rules]
                self.delays[p.netloc.lower()] = max([d for _, _, d in chosen] or [0])
            else:
                raise RuntimeError(f"robots.txt unavailable: {origin}: HTTP {meta['status']}")
            self.robots[origin] = rp
        rp = self.robots[origin]
        allowed = rp.can_fetch(UA, url)
        if hasattr(rp, 'batch_rules'):
            path = p.path + ('?' + p.query if p.query else '')
            matches = []
            for allow, rule in rp.batch_rules:
                pattern = re.escape(rule).replace(r'\*', '.*')
                if pattern.endswith(r'\$'):
                    pattern = pattern[:-2] + '$'
                if re.match(pattern, path):
                    matches.append((len(rule.replace('*', '').rstrip('$')), allow))
            allowed = max(matches)[1] if matches else True
        if not allowed:
            raise RuntimeError('robots.txt disallows ' + url)
        return rp

    def get(self, url, robots=True, fresh=False, _redirects=0):
        if _redirects > 10:
            raise RuntimeError('Too many redirects: ' + url)
        if not url.startswith(('https://', 'http://')):
            raise ValueError('unsupported URL: ' + url)
        if robots:
            self._policy(url)
        key = hashlib.sha256(url.encode()).hexdigest()
        folder = CACHE / 'http'
        folder.mkdir(parents=True, exist_ok=True)
        mp, bp = folder / (key + '.json'), folder / (key + '.body')
        if mp.exists() and bp.exists() and not (fresh or self.refresh):
            meta, body = json.loads(mp.read_text()), bp.read_bytes()
            # Only reuse successful responses or permanent absence.
            if meta['status'] in (200, 404, 410):
                self.evidence.append(meta)
                return meta, body
        for attempt in range(3):
            try:
                response = self._request(url)
            except requests.RequestException:
                if attempt == 2:
                    raise
                time.sleep(5 * (attempt + 1))
                continue
            if response.status_code not in (429, 500, 502, 503, 504) or attempt == 2:
                break
            retry = response.headers.get('Retry-After', '')
            time.sleep(min(60, int(retry)) if retry.isdigit() else 5 * (attempt + 1))
        if response.is_redirect:
            target = urljoin(url, response.headers['Location'])
            # This path is data-only. Refuse redirect loops rather than recurse forever.
            if target == url:
                raise RuntimeError('redirect loop: ' + url)
            meta, body = self.get(target, robots=robots, fresh=fresh, _redirects=_redirects + 1)
            meta = dict(meta, requested_url=url)
        else:
            body = response.content
            meta = {'url': url, 'status': response.status_code, 'retrieved_utc': utc(),
                    'content_type': response.headers.get('Content-Type', ''),
                    'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}
        bp.write_bytes(body)
        write_json(mp, meta)
        self.evidence.append(meta)
        return meta, body

    def read(self, url, fresh=False):
        meta, body = self.get(url, fresh=fresh)
        if meta['status'] != 200:
            raise RuntimeError(f"HTTP {meta['status']}: {url}")
        return body

    def text(self, url, fresh=False):
        return self.read(url, fresh).decode('utf-8', errors='replace')

    def json(self, url, fresh=False):
        return json.loads(self.read(url, fresh))

    def public_notion_json(self, url, payload, fresh=False):
        """Read-only public-page APIs used by Notion's own anonymous frontend."""
        assert urlsplit(url).netloc in ('docs.fuzz.land','fuzzland.notion.site')
        assert urlsplit(url).path in ('/api/v3/getPublicPageData','/api/v3/loadPageChunk','/api/v3/getSignedFileUrls')
        self._policy(url)
        key=hashlib.sha256(('POST '+url+' '+json.dumps(payload,sort_keys=True)).encode()).hexdigest()
        folder=CACHE/'http'
        mp,bp=folder/(key+'.json'),folder/(key+'.body')
        if mp.exists() and bp.exists() and not (fresh or self.refresh):
            meta=json.loads(mp.read_text())
            if meta['status']==200:
                self.evidence.append(meta)
                return json.loads(bp.read_bytes())
        response=self._request(url,payload)
        body=response.content
        meta={'url':url,'method':'POST','status':response.status_code,'retrieved_utc':utc(),
              'content_type':response.headers.get('Content-Type',''),'sha256':hashlib.sha256(body).hexdigest(),'bytes':len(body)}
        bp.write_bytes(body)
        write_json(mp,meta)
        self.evidence.append(meta)
        if response.status_code!=200:
            raise RuntimeError(f'Public Notion read API HTTP {response.status_code}: {url}')
        return json.loads(body)


class Node:
    def __init__(self, tag='', attrs=(), parent=None):
        self.tag, self.attrs, self.parent = tag, dict(attrs), parent
        self.children = []

    def all(self, tag=None):
        for child in self.children:
            if isinstance(child, Node):
                if tag is None or child.tag == tag:
                    yield child
                yield from child.all(tag)

    def text(self):
        return ' '.join(' '.join(c.text() if isinstance(c, Node) else c for c in self.children).split())

    def visible_text(self):
        if self.tag in ('script', 'style', 'noscript'):
            return ''
        return ' '.join(' '.join(c.visible_text() if isinstance(c, Node) else c for c in self.children).split())

    def up(self, tag=None, cls=None):
        p = self
        while p is not None:
            if (tag is None or p.tag == tag) and (cls is None or cls in p.attrs.get('class', '').split()):
                return p
            p = p.parent


class DOM(HTMLParser):
    VOID = set('area base br col embed hr img input link meta param source track wbr'.split())

    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.root = Node()
        self.current = self.root
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        n = Node(tag, attrs, self.current)
        self.current.children.append(n)
        if tag not in self.VOID:
            self.current = n

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self.VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        p = self.current
        while p.parent is not None:
            if p.tag == tag:
                self.current = p.parent
                return
            p = p.parent

    def handle_data(self, text):
        self.current.children.append(text)

    def all(self, tag=None):
        return self.root.all(tag)


def links(text, base):
    result = []
    for n in DOM(text).all('a'):
        if not n.attrs.get('href'):
            continue
        try:
            result.append((urljoin(base, n.attrs['href']), n))
        except ValueError:
            # Malformed unrelated links occur in migrated research posts.
            continue
    return result


def date_hint(text):
    text = str(text).strip()
    # Listing values only. Never use a crawl timestamp or a Git commit date.
    m = re.search(r'\b(20\d{2})[-/](0?[1-9]|1[0-2])(?:[-/](0?[1-9]|[12]\d|3[01]))?\b', text)
    if m:
        value = m[1] + '-' + m[2].zfill(2)
        if m[3]:
            value += '-' + m[3].zfill(2)
        return value, 'day' if m[3] else 'month'
    for fmt in ('%b %d, %Y', '%B %d, %Y', '%d %b %Y', '%d %B %Y', '%b %Y', '%B %Y'):
        # Search a short date substring while tolerating surrounding card text.
        pattern = r'(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)(?:\s+\d{1,2},?)?\s+20\d{2}'
        candidates = re.findall(pattern, text, re.I)
        candidates += re.findall(r'\d{1,2}\s+[A-Za-z]+\s+20\d{2}', text)
        for candidate in candidates:
            try:
                d = datetime.strptime(candidate, fmt)
                return d.strftime('%Y-%m-%d' if '%d' in fmt else '%Y-%m'), 'day' if '%d' in fmt else 'month'
            except ValueError:
                pass
    m = re.search(r'\b20\d{2}\b', text)
    return (m[0], 'year') if m else ('', 'none')


def item(url, listing, title='', project='', date='', audit_type='', **extra):
    d, precision = date_hint(date)
    return dict(public_url=url.split('#')[0], listing_url=listing, title_hint=title.strip(),
                project_hint=project.strip(), date_hint=d, date_precision=precision,
                date_basis='listing' if d else 'none', audit_type=audit_type, **extra)


def flight_objects(text):
    """Decode public React Flight JSON data; never evaluate JavaScript."""
    chunks = []
    for block in re.findall(r'self\.__next_f\.push\((.*?)\)</script>', text, re.S):
        try:
            value = json.loads(block)
            if value[0] == 1:
                chunks.append(value[1])
        except (ValueError, IndexError, TypeError):
            continue

    def objects(value):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from objects(child)
        elif isinstance(value, list):
            for child in value:
                yield from objects(child)

    for line in ''.join(chunks).splitlines():
        try:
            yield from objects(json.loads(line.split(':', 1)[1]))
        except (ValueError, IndexError, TypeError):
            continue


def github_tree(fetch, owner, repo):
    base = f'https://api.github.com/repos/{owner}/{repo}'
    info = fetch.json(base)
    branch = info['default_branch']
    tree = fetch.json(base + '/git/trees/' + branch + '?recursive=1')
    if tree.get('truncated'):
        raise RuntimeError('GitHub tree truncated: ' + base)
    return tree['sha'], tree['tree']


def github_head(fetch, owner, repo, ref=''):
    key = (owner.lower(), repo.lower(), ref)
    if key not in fetch.refs:
        url = f'https://github.com/{owner}/{repo}'
        text = fetch.text(url)
        if ref:
            default = re.search(r'"defaultBranch":"([^"]+)"', text)
            if default and ref != default[1]:
                # Blob pages are allowed by GitHub robots; tree/commits are not.
                text = fetch.text(url + '/blob/' + ref + '/README.md')
        match = re.search(r'"currentOid":"([0-9a-f]{40})"', text)
        if not match:
            raise RuntimeError('No public commit SHA in repository page: ' + url)
        fetch.refs[key] = match[1]
    return fetch.refs[key]


def github_snapshot(fetch, owner, repo):
    """Read a pinned ZIP manifest in memory, without extracting repository paths."""
    sha = github_head(fetch, owner, repo)
    url = f'https://codeload.github.com/{owner}/{repo}/zip/{sha}'
    meta, body = fetch.get(url)
    if meta['status'] != 200:
        raise RuntimeError(f"HTTP {meta['status']}: {url}")
    fetch.snapshot_times[sha] = meta['retrieved_utc']
    archive = zipfile.ZipFile(io.BytesIO(body))
    return sha, archive


def repo_entries(fetch, owner, repo, listing=None, skip_prefixes=()):
    """Enumerate every PDF in a publisher's pinned repository archive manifest."""
    root = f'https://github.com/{owner}/{repo}'
    fetch.text(root, fresh=True)
    sha, archive = github_snapshot(fetch, owner, repo)
    rows = {}
    for target, n in links(fetch.text(root), root):
        if '.pdf' in target.lower():
            row = n.up('tr')
            if row:
                rows[unquote(urlsplit(target).path.split('/blob/', 1)[-1].split('/', 1)[-1])] = row
    entries = []
    for member in archive.infolist():
        if member.is_dir() or not member.filename.lower().endswith('.pdf'):
            continue
        path = member.filename.split('/', 1)[1]
        public = root + '/blob/' + sha + '/' + quote(path, safe='/')
        row = rows.get(path)
        title = Path(path).stem.replace('_', ' ')
        date = ''
        audit_type = ''
        if row:
            cells = [n.text() for n in row.all('td')]
            title = cells[0] if cells else title
            date = row.text()
            audit_type = 'Security audit'
        e = item(public, listing or root, title, title, date, audit_type,
                 expected_format='pdf', notes='Original downloaded from commit-pinned publisher repository ZIP manifest: ' + path)
        if not e['date_hint']:
            e['date_hint'], e['date_precision'] = date_hint(path)
            e['date_basis'] = 'filename' if e['date_hint'] else 'none'
        if any(path.startswith(p) for p in skip_prefixes):
            e['skip_reason'] = 'Economic research, not a security audit report'
        else:
            body = archive.read(member)
            fetch.payloads[public] = ({'status': 200, 'content_type': 'application/pdf',
                                       'retrieved_utc': fetch.snapshot_times[sha]}, body)
        entries.append(e)
    return entries, root


def pin_github(fetch, url):
    p = urlsplit(url)
    if p.netloc == 'github.com':
        parts = p.path.strip('/').split('/')
        if len(parts) >= 5 and parts[2] in ('blob', 'raw'):
            owner, repo, _, ref = parts[:4]
            path = '/'.join(parts[4:])
        else:
            return url, url
    elif p.netloc == 'raw.githubusercontent.com':
        owner, repo, ref, path = p.path.strip('/').split('/', 3)
    else:
        return url, url
    if not re.fullmatch('[0-9a-f]{40}', ref):
        ref = github_head(fetch, owner, repo, ref)
    return (f'https://github.com/{owner}/{repo}/blob/{ref}/{path}',
            f'https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}')


def collect(firm, enumerate_fn, method, notes='', refresh=False, resolve_fn=None):
    refresh = refresh or '--refresh' in sys.argv
    fetch = Fetcher(refresh)
    out = ROOT / 'data' / 'collect' / firm
    out.mkdir(parents=True, exist_ok=True)
    entries, listing_urls = enumerate_fn(fetch)
    unique = {}
    all_rows = {}
    for entry in entries:
        key = entry['public_url']
        all_rows.setdefault(key, []).append(entry)
        if key not in unique or (entry['date_hint'] and not unique[key]['date_hint']):
            unique[key] = entry
    entries = [unique[k] for k in sorted(unique)]
    write_json(out / 'listing.json', {'firm_id': firm, 'listing_urls': listing_urls, 'pagination_method': method,
                                     'measured_utc': utc(), 'notes': notes, 'items': entries,
                                     'raw_link_rows': sum(map(len, all_rows.values())),
                                     'duplicate_listing_rows': [dict(public_url=k, rows=v) for k, v in all_rows.items() if len(v)>1]})
    existing = {}
    if (out / 'reports.jsonl').exists():
        existing = {r['public_url']: r for r in map(json.loads, (out / 'reports.jsonl').read_text().splitlines())}
    reports, failures, skipped = [], [], []
    for i, entry in enumerate(entries, 1):
        try:
            if entry.get('skip_reason'):
                skipped.append({'url': entry['public_url'], 'reason': entry['skip_reason']})
                continue
            url = entry['public_url']
            if resolve_fn:
                entry = resolve_fn(fetch, dict(entry))
                url = entry['public_url']
            public, download = pin_github(fetch, entry.get('download_url', url))
            public = public if urlsplit(url).netloc in ('github.com', 'raw.githubusercontent.com') else url
            old = existing.get(public)
            if (old and (ROOT / old['local_path']).exists() and not refresh
                    and (url not in fetch.payloads or hashlib.sha256(fetch.payloads[url][1]).hexdigest()==old['sha256'])
                    and (not entry.get('expected_format') or old['file_format'] == entry['expected_format'])):
                body = (ROOT / old['local_path']).read_bytes()
                if hashlib.sha256(body).hexdigest() == old['sha256']:
                    if (old['file_format'] == 'pdf' or entry.get('expected_format') == 'pdf'
                            or unquote(urlsplit(download).path).lower().endswith('.pdf')) and not body.startswith(b'%PDF'):
                        raise RuntimeError('pdf_magic_ok=false: cached claimed PDF does not start with %PDF: ' + download)
                    updated = dict(old, **{k:entry[k] for k in ('listing_url','title_hint','project_hint','date_hint','date_precision','date_basis')})
                    if url in fetch.payloads:
                        updated['retrieved_utc'] = fetch.payloads[url][0]['retrieved_utc']
                    reports.append(updated)
                    continue
            meta, body = fetch.payloads.get(url) or fetch.get(download)
            if meta['status'] != 200:
                raise RuntimeError(f"HTTP {meta['status']}: {download}")
            if (entry.get('expected_format') == 'pdf' or unquote(urlsplit(download).path).lower().endswith('.pdf')
                    or meta['content_type'].split(';')[0] == 'application/pdf') and not body.startswith(b'%PDF'):
                raise RuntimeError('pdf_magic_ok=false: claimed PDF does not start with %PDF: ' + download)
            if body.startswith(b'%PDF'):
                fmt = 'pdf'
            elif 'html' in meta['content_type'] or body.lstrip().lower().startswith((b'<!doctype html', b'<html')):
                if entry.get('expected_format') == 'pdf' or unquote(urlsplit(download).path).lower().endswith('.pdf'):
                    raise RuntimeError('Expected PDF, received HTML: ' + download)
                text = DOM(body.decode('utf-8', errors='replace')).root.visible_text()
                if len(text) < 300 or ('Executive Summary' not in text and 'audit' not in text.lower() and 'security review' not in text.lower()):
                    raise RuntimeError('HTML is not an identifiable audit report: ' + download)
                fmt = 'html'
            elif urlsplit(download).path.lower().endswith('.md'):
                fmt = 'md'
            else:
                raise RuntimeError('Unrecognized report format: ' + download)
            sha = hashlib.sha256(body).hexdigest()
            path = Path('local-cache/originals') / sha[:2] / (sha + '.' + fmt)
            (ROOT / path).parent.mkdir(parents=True, exist_ok=True)
            if not (ROOT / path).exists():
                (ROOT / path).write_bytes(body)
            report = {k: entry[k] for k in ('listing_url', 'title_hint', 'project_hint', 'date_hint', 'date_precision', 'date_basis')}
            report.update(firm_id=firm, collector='web_' + firm, source_kind='github' if 'github' in urlsplit(public).netloc else 'website',
                          public_url=public, sha256=sha, bytes=len(body), file_format=fmt, local_path=str(path),
                          filename=entry.get('filename_hint') or unquote(urlsplit(download).path.rsplit('/', 1)[-1]),
                          doc_kind=entry.get('doc_kind', 'audit_report'), retrieved_utc=meta['retrieved_utc'],
                          notes='; '.join(filter(None, [entry.get('notes', ''), 'Listing audit type: ' + entry['audit_type'] if entry.get('audit_type') else '',
                                                       'Publisher listing link: ' + url if public != url else '',
                                                       'Download URL: ' + download if download != public else ''])))
            reports.append(report)
        except Exception as exc:
            failures.append({'url': entry['public_url'], 'error': str(exc)})
            print(f'{firm}: FAILED {entry["public_url"]}: {exc}', flush=True)
        finally:
            if i % 10 == 0 or i == len(entries):
                print(f'{firm}: {i}/{len(entries)}; collected={len(reports)} failed={len(failures)} skipped={len(skipped)}', flush=True)
            # Checkpoint report rows so an interrupted collection is idempotent.
            (out / 'reports.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False) + '\n' for r in reports))
    status = dict(firm_id=firm, listing_urls=listing_urls, listed_count=len(entries), collected=len(reports),
                  failed=len(failures), skipped_non_report=len(skipped), failures=failures,
                  collected_utc=utc(), collector_script='scripts/collect/web_' + firm + '.py')
    assert status['collected'] + status['failed'] + status['skipped_non_report'] == status['listed_count']
    write_json(out / 'status.json', status)
    write_json(out / 'evidence.json', {'requests': fetch.evidence, 'skipped': skipped})
    return status


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('urls', nargs='+')
    args = parser.parse_args()
    f = Fetcher()
    for u in args.urls:
        try:
            m, b = f.get(u)
            print(json.dumps(m))
            text = b.decode('utf-8', errors='replace')
            for target, n in links(text, m['url']):
                print(json.dumps({'url': target, 'text': n.text()[:160], 'context': n.parent.text()[:300]}, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({'url': u, 'error': str(e)}))
