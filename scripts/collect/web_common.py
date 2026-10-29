#!/usr/bin/env python3
"""Credential-free website collection: robots, shared host pacing, CAS originals.

Only public response bytes are read; JavaScript and downloaded code never run.
Cache and locks live under the gitignored local-cache directory. Listings must
use refresh=True; report downloads reuse immutable cached bytes on reruns.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / 'local-cache'
UA = 'Web3AuditCorpus/1.0 (public security audit research; metadata and original links)'


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f'.{os.getpid()}.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    tmp.replace(path)


@dataclasses.dataclass
class Response:
    url: str
    body: bytes
    content_type: str = ''
    status: int = 200
    retrieved_utc: str = ''

    @property
    def text(self):
        return self.body.decode('utf-8', errors='replace')


class FetchError(RuntimeError):
    pass


def pdf_magic_ok(body):
    """A claimed PDF must begin at byte zero with the PDF signature."""
    return body.startswith(b'%PDF')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RobotsPolicy:
    """REP groups with wildcard/end anchors and longest-rule allow precedence."""
    def __init__(self, lines):
        self.groups = []
        agents, rules = [], []
        for raw in list(lines) + ['User-agent: __end__']:
            line = raw.split('#', 1)[0].strip()
            if ':' not in line:
                continue
            key, value = (p.strip() for p in line.split(':', 1))
            key = key.lower()
            if key == 'user-agent':
                if rules:
                    self.groups.append((agents, rules))
                    agents, rules = [], []
                agents.append(value.lower())
            elif key in ('allow', 'disallow') and agents and value:
                rules.append((value, key == 'allow'))
        if rules:
            self.groups.append((agents, rules))

    def can_fetch(self, user_agent, url):
        product = user_agent.lower().split('/')[0]
        matches = [(max((len(a) for a in agents if a != '*' and a in product), default=0), rules)
                   for agents, rules in self.groups if any(a == '*' or a in product for a in agents)]
        if not matches:
            return True
        specificity = max(length for length, _ in matches)
        p = urllib.parse.urlsplit(url)
        target = p.path or '/'
        if p.query:
            target += '?' + p.query
        selected = []
        for length, rules in matches:
            if length != specificity:
                continue
            for path, allow in rules:
                end = path.endswith('$')
                expression = re.escape(path[:-1] if end else path).replace(r'\*', '.*')
                if re.match(expression + ('$' if end else ''), target):
                    selected.append((len(path.rstrip('$').replace('*', '')), allow))
        return max(selected, default=(0, True))[1]


class Client:
    def __init__(self):
        self.cache = STORE / 'web-cache'
        self.cache.mkdir(parents=True, exist_ok=True)
        self.locks = STORE / 'web-host-locks'
        self.locks.mkdir(parents=True, exist_ok=True)
        self.robots = {}
        self.host_delays = {}
        self.observations = []
        self.opener = urllib.request.build_opener(NoRedirect())

    def _request(self, url, data=None):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            raise FetchError('Only credential-free HTTPS URLs allowed: ' + url)
        hostkey = hashlib.sha256(parsed.netloc.lower().encode()).hexdigest()
        with (self.locks / hostkey).open('a+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            lock.seek(0)
            last = float(lock.read() or '0')
            interval = max(1.05, self.host_delays.get(parsed.netloc.lower(), 1.05))
            time.sleep(max(0, interval - (time.time() - last)))
            lock.seek(0)
            lock.truncate()
            lock.write(str(time.time()))
            lock.flush()
            try:
                headers = {'User-Agent': UA, 'Accept': '*/*'}
                if data is not None:
                    headers['Content-Type'] = 'application/json'
                req = urllib.request.Request(url, data=data, headers=headers)
                try:
                    response = self.opener.open(req, timeout=45)
                except urllib.error.HTTPError as e:
                    response = e
                with response:
                    body = response.read(80_000_001)
                    if len(body) > 80_000_000:
                        raise FetchError('Response exceeds 80 MB: ' + url)
                    return response.code, dict(response.headers), body
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                raise FetchError(f'{url}: {type(e).__name__}: {e}') from e

    def _allowed(self, url):
        p = urllib.parse.urlsplit(url)
        origin = f'{p.scheme}://{p.netloc}'
        if origin not in self.robots:
            robot_url = origin + '/robots.txt'
            key = hashlib.sha256(robot_url.encode()).hexdigest()
            cache = self.cache / (key + '.robots.json')
            saved = json.loads(cache.read_text()) if cache.exists() else None
            if saved and time.time() - saved['time'] < 3600:
                status, body = saved['status'], saved['body']
            else:
                status, headers, raw = self._request(robot_url)
                # Follow robots redirects only over HTTPS, with the same pacing.
                for _ in range(6):
                    if status not in (301, 302, 303, 307, 308):
                        break
                    robot_url = urllib.parse.urljoin(robot_url, headers.get('Location', headers.get('location', '')))
                    status, headers, raw = self._request(robot_url)
                body = raw.decode('utf-8', errors='replace')
                atomic_json(cache, {'time': time.time(), 'status': status, 'body': body})
            # RFC 9309 section 2.3.1.3: a 4xx robots response means unavailable,
            # so there are no published rules. This does not authorize bypassing
            # an access denial on the requested content. 429 remains a failure.
            if 400 <= status < 500 and status != 429:
                parser = RobotsPolicy([])
            elif status == 200:
                # Section 2.2.4: parse every line and ignore invalid rules. SPAs
                # sometimes return their HTML shell at /robots.txt with no rules.
                parser = RobotsPolicy(body.splitlines())
            else:
                raise FetchError(f'Cannot establish robots policy for {origin}: HTTP {status}')
            self.robots[origin] = parser
            # Also honor publishers' nonstandard pacing hints conservatively,
            # even when they occur under a different crawler's group.
            delays = [float(v) for v in re.findall(r'(?im)^crawl-delay\s*:\s*([0-9.]+)\s*$', body)]
            delays += [float(seconds) / float(requests)
                       for requests, seconds in re.findall(r'(?im)^request-rate\s*:\s*(\d+)\s*/\s*(\d+)', body)
                       if int(requests) > 0]
            self.host_delays[p.netloc.lower()] = max([1.05] + delays)
        if not self.robots[origin].can_fetch(UA, url):
            raise FetchError('robots.txt disallows: ' + url)

    def fetch(self, url, refresh=False, data=None):
        url = urllib.parse.urldefrag(url)[0]
        key = hashlib.sha256(url.encode() + (b'\nPOST\n' + data if data is not None else b'')).hexdigest()
        meta_path, body_path = self.cache / (key + '.json'), self.cache / (key + '.body')
        if not refresh and meta_path.exists() and body_path.exists():
            meta = json.loads(meta_path.read_text())
            body = body_path.read_bytes()
            if hashlib.sha256(body).hexdigest() == meta.get('sha256'):
                return Response(meta['url'], body, meta['content_type'], 200, meta['retrieved_utc'])
        current = url
        for redirect in range(9):
            self._allowed(current)
            for attempt in range(3):
                status, headers, body = self._request(current, data=data)
                if status not in (429, 500, 502, 503, 504) or attempt == 2:
                    break
                retry = headers.get('Retry-After', headers.get('retry-after', '5'))
                time.sleep(min(60, max(5, int(retry) if retry.isdigit() else 5)))
            if status in (301, 302, 303, 307, 308):
                target = headers.get('Location', headers.get('location'))
                if not target:
                    raise FetchError('Redirect without Location: ' + current)
                current = urllib.parse.urljoin(current, target)
                continue
            if status != 200:
                raise FetchError(f'HTTP {status}: {current}')
            content_type = headers.get('Content-Type', headers.get('content-type', '')).split(';')[0]
            meta = {'url': current, 'requested_url': url, 'content_type': content_type,
                    'retrieved_utc': now(), 'sha256': hashlib.sha256(body).hexdigest(), 'bytes': len(body)}
            tmp = body_path.with_name(body_path.name + f'.{os.getpid()}.tmp')
            tmp.write_bytes(body)
            tmp.replace(body_path)
            atomic_json(meta_path, meta)
            self.observations.append(meta)
            return Response(current, body, content_type, status, meta['retrieved_utc'])
        raise FetchError('Too many redirects: ' + url)

    def text(self, url, refresh=False):
        return self.fetch(url, refresh=refresh).text

    def json(self, url, refresh=False):
        return json.loads(self.fetch(url, refresh=refresh).body)

    def post_json(self, url, value, refresh=False):
        payload = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        return json.loads(self.fetch(url, refresh=refresh, data=payload).body)


@dataclasses.dataclass
class Item:
    public_url: str
    listing_url: str
    title: str = ''
    project: str = ''
    date: str = ''
    date_precision: str = 'none'
    doc_kind: str = 'audit_report'
    download_url: str = ''
    notes: str = ''
    original_format: str = ''
    date_basis: str = ''


@dataclasses.dataclass
class Listing:
    items: list[Item]
    urls: list[str]
    method: str
    notes: str = ''


def collect(firm_id, listing, client, resolve=None):
    directory = ROOT / 'data' / 'collect' / firm_id
    directory.mkdir(parents=True, exist_ok=True)
    unique = {}
    for item in listing.items:
        unique.setdefault(item.public_url, item)
    items = [unique[u] for u in sorted(unique)]
    atomic_json(directory / 'listing.json', {
        'firm_id': firm_id, 'listing_urls': listing.urls, 'method': listing.method,
        'notes': listing.notes, 'measured_utc': now(), 'listed_count': len(items),
        'items': [dataclasses.asdict(i) for i in items], 'observations': client.observations})
    old = {}
    report_file = directory / 'reports.jsonl'
    if report_file.exists():
        old = {r['public_url']: r for r in map(json.loads, report_file.read_text().splitlines())}
    rows, failures, skipped = [], [], []

    def checkpoint():
        tmp = report_file.with_suffix('.jsonl.tmp')
        tmp.write_text(''.join(json.dumps(row, ensure_ascii=False) + '\n' for row in rows))
        tmp.replace(report_file)
        status = {'firm_id': firm_id, 'listing_urls': listing.urls,
                  'listed_count': len(items), 'collected': len(rows), 'failed': len(failures),
                  'skipped_non_report': len(skipped), 'failures': failures,
                  'collected_utc': now(), 'collector_script': f'scripts/collect/web_{firm_id}.py',
                  'enumeration_complete': True, 'processed': len(rows) + len(failures) + len(skipped)}
        atomic_json(directory / 'status.json', status)

    for n, original in enumerate(items, 1):
        item = dataclasses.replace(original)
        try:
            if item.doc_kind == 'non_report':
                skipped.append(dataclasses.asdict(item))
                continue
            existing = old.get(item.public_url)
            if existing:
                local = ROOT / existing['local_path']
                if local.exists() and hashlib.sha256(local.read_bytes()).hexdigest() == existing['sha256']:
                    if (existing['file_format'] == 'pdf' or existing.get('filename', '').lower().endswith('.pdf') or item.original_format == 'pdf'
                            or '.pdf' in urllib.parse.urlsplit(item.download_url or item.public_url).path.lower()):
                        if not pdf_magic_ok(local.read_bytes()):
                            raise FetchError('pdf_magic_ok=false: cached claimed PDF does not start with %PDF')
                    existing.update(title_hint=item.title, project_hint=item.project,
                                    date_hint=item.date, date_precision=item.date_precision,
                                    date_basis=(item.date_basis or 'listing') if item.date else 'none',
                                    listing_url=item.listing_url, doc_kind=item.doc_kind)
                    if item.notes and item.notes not in existing.get('notes', ''):
                        existing['notes'] = item.notes + '\n' + existing.get('notes', '')
                    rows.append(existing)
                    checkpoint()
                    continue
            if resolve:
                item = resolve(client, item)
            if item.doc_kind == 'non_report':
                skipped.append(dataclasses.asdict(item))
                continue
            response = client.fetch(item.download_url or item.public_url)
            body = response.body
            if (item.original_format == 'pdf' or response.content_type == 'application/pdf'
                    or '.pdf' in urllib.parse.urlsplit(item.download_url or item.public_url).path.lower()):
                if not pdf_magic_ok(body):
                    raise FetchError('pdf_magic_ok=false: claimed PDF does not start with %PDF; effective_url=' + response.url)
            if pdf_magic_ok(body):
                fmt = 'pdf'
            elif response.content_type in ('text/html', 'application/xhtml+xml') or body.lstrip().lower().startswith((b'<!doctype html', b'<html')):
                fmt = 'html'
                if re.search(r'<title[^>]*>\s*(?:Just a moment|Access denied|Error|404)', response.text, re.I):
                    raise FetchError('HTML access/error page instead of report: ' + response.url)
            elif urllib.parse.urlsplit(response.url).path.endswith('.md'):
                fmt = 'md'
            elif item.original_format == 'other' and response.content_type in (
                    'application/javascript', 'text/javascript', 'application/json', 'text/plain'):
                fmt = 'other'
            else:
                raise FetchError(f'Unrecognized original format ({response.content_type}): {response.url}')
            if '.pdf' in urllib.parse.urlsplit(item.download_url or item.public_url).path.lower() and fmt != 'pdf':
                raise FetchError('Expected PDF but received ' + fmt + ': ' + response.url)
            if item.original_format and fmt != item.original_format:
                raise FetchError('Expected ' + item.original_format + ' but received ' + fmt + ': ' + response.url)
            sha = hashlib.sha256(body).hexdigest()
            local = STORE / 'originals' / sha[:2] / (sha + '.' + fmt)
            local.parent.mkdir(parents=True, exist_ok=True)
            if not local.exists():
                local.write_bytes(body)
            filename = urllib.parse.unquote(Path(urllib.parse.urlsplit(item.download_url or item.public_url).path).name)
            rows.append({'firm_id': firm_id, 'collector': f'web_{firm_id}',
                         'source_kind': 'github' if item.public_url.startswith('https://github.com/') else 'website',
                         'public_url': item.public_url, 'listing_url': item.listing_url, 'sha256': sha,
                         'bytes': len(body), 'file_format': fmt, 'local_path': str(local.relative_to(ROOT)),
                         'filename': filename, 'title_hint': item.title, 'project_hint': item.project,
                         'date_hint': item.date, 'date_precision': item.date_precision,
                         'date_basis': (item.date_basis or 'listing') if item.date else 'none', 'doc_kind': item.doc_kind,
                         'retrieved_utc': response.retrieved_utc,
                         'notes': item.notes})
        except Exception as e:
            failures.append({'url': original.public_url, 'error': str(e)})
        finally:
            checkpoint()
        if n % 20 == 0 or n == len(items):
            print(f'{firm_id}: {n}/{len(items)} collected={len(rows)} failed={len(failures)} skipped={len(skipped)}', flush=True)
    atomic_json(directory / 'skipped.json', skipped)
    checkpoint()
    return json.loads((directory / 'status.json').read_text())


def enumeration_failed(firm_id, urls, error):
    """Unknown listing size is null, never an invented zero or completed census."""
    directory = ROOT / 'data' / 'collect' / firm_id
    directory.mkdir(parents=True, exist_ok=True)
    atomic_json(directory / 'status.json', {
        'firm_id': firm_id, 'listing_urls': urls, 'listed_count': None,
        'collected': 0, 'failed': 0, 'skipped_non_report': 0, 'failures': [],
        'collected_utc': now(), 'collector_script': f'scripts/collect/web_{firm_id}.py',
        'enumeration_complete': False, 'enumeration_error': str(error)})
