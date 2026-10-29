"""Shared, standard-library-only contest collection and provenance helpers.

Remote repositories are data: no checkout, imports, hooks or publisher code run.
HTTP response snapshots and originals live only in the gitignored local-cache.
"""
import argparse
import datetime as dt
import fcntl
import hashlib
import html
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import urllib.robotparser

ROOT = Path(__file__).resolve().parents[2]
STORE = ROOT / 'local-cache'
UA = 'web3-audit-corpus/1.0 (public security audit research; metadata and original links)'


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def iso(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return dt.datetime.fromtimestamp(value, dt.timezone.utc).isoformat().replace('+00:00', 'Z')
    return dt.datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(dt.timezone.utc).isoformat().replace('+00:00', 'Z')


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + '\n')


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(''.join(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n' for r in rows))


def read_jsonl(path):
    return [json.loads(s) for s in path.read_text().splitlines()] if path.exists() else []


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, refresh=False, offline=False, max_bytes=64_000_000):
        self.refresh, self.offline = refresh, offline
        self.max_bytes = max_bytes
        self.cache = STORE / 'contest-http'
        self.cache.mkdir(parents=True, exist_ok=True)
        self.robots = {}
        self.opener = urllib.request.build_opener(NoRedirect())

    def _raw(self, url):
        host = urllib.parse.urlsplit(url).netloc
        # Shared across platforms/processes; request starts at least 1s apart.
        with (self.cache / ('host-' + hashlib.sha256(host.encode()).hexdigest())).open('a+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            lock.seek(0)
            last = float(lock.read() or 0)
            time.sleep(max(0, last + 1.05 - time.time()))
            lock.seek(0)
            lock.truncate()
            lock.write(str(time.time()))
            lock.flush()
            req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': '*/*'})
            try:
                response = self.opener.open(req, timeout=50)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                body = response.read(self.max_bytes + 1)
                if len(body) > self.max_bytes:
                    raise ValueError(f'Response exceeds {self.max_bytes // 1_000_000} MB')
                return response.status, dict(response.headers), body

    def allowed(self, url):
        parts = urllib.parse.urlsplit(url)
        base = parts.scheme + '://' + parts.netloc
        if base not in self.robots:
            robot_url = base + '/robots.txt'
            meta, body = self.get(robot_url, robots=False)
            robot = urllib.robotparser.RobotFileParser()
            if meta['status'] in (404, 410):
                robot.parse([])
            elif meta['status'] == 200:
                robot.parse(body.decode('utf-8', 'replace').splitlines())
            else:
                raise RuntimeError(f'robots.txt unavailable: {robot_url} HTTP {meta["status"]}')
            self.robots[base] = robot
        if not self.robots[base].can_fetch(UA, url):
            raise RuntimeError('robots.txt disallows ' + url)

    def get(self, url, robots=True, redirects=0):
        if redirects > 10:
            raise RuntimeError('Too many redirects: ' + url)
        if not url.startswith('https://'):
            raise ValueError('HTTPS required: ' + url)
        key = hashlib.sha256(url.encode()).hexdigest()
        bp, mp = self.cache / (key + '.body'), self.cache / (key + '.json')
        if not self.refresh:
            if bp.exists() and mp.exists():
                meta, body = json.loads(mp.read_text()), bp.read_bytes()
                if hashlib.sha256(body).hexdigest() != meta['sha256']:
                    raise ValueError('HTTP cache digest mismatch: ' + url)
                return meta, body
            # Same-day, first-party research snapshots avoid re-requesting APIs.
            old = Path('local-cache/tmp/web3-aggregators-http')
            ob, om = old / (key + '.body'), old / (key + '.json')
            if robots and ob.exists() and om.exists():
                meta, body = json.loads(om.read_text()), ob.read_bytes()
                if (meta.get('status') == 200 and meta.get('accessed_at', '').startswith(utc()[:10])
                        and hashlib.sha256(body).hexdigest() == meta['sha256']):
                    bp.write_bytes(body)
                    write_json(mp, meta)
                    return meta, body
        if self.offline:
            raise RuntimeError('Offline cache miss: ' + url)
        if robots:
            self.allowed(url)
        for attempt in range(3):
            status, headers, body = self._raw(url)
            if status not in (429, 500, 502, 503, 504) or attempt == 2:
                break
            time.sleep(2 ** (attempt + 1))
        if status in (301, 302, 303, 307, 308):
            final, body = self.get(urllib.parse.urljoin(url, headers.get('Location', headers.get('location', ''))), robots=robots, redirects=redirects + 1)
            meta = dict(final, url=url, effective_url=final.get('effective_url', final['url']))
            bp.write_bytes(body)
            write_json(mp, meta)
            return meta, body
        meta = dict(url=url, accessed_at=utc(), status=status, bytes=len(body),
                    sha256=hashlib.sha256(body).hexdigest(), content_type=headers.get('Content-Type'))
        bp.write_bytes(body)
        write_json(mp, meta)
        return meta, body

    def body(self, url):
        meta, body = self.get(url)
        if meta['status'] != 200:
            raise RuntimeError(f'HTTP {meta["status"]}: {url}')
        return body

    def json(self, url):
        return json.loads(self.body(url))


def flight_objects(text):
    """Parse React Flight JSON values as data, without evaluating JavaScript."""
    decoder = json.JSONDecoder()
    for match in re.finditer(r'self\.__next_f\.push\((\[.*?\])\)</script>', text, re.S):
        try:
            envelope = json.loads(match[1])
        except ValueError:
            continue
        for payload in envelope:
            if not isinstance(payload, str):
                continue
            for line in payload.splitlines():
                part = line.partition(':')[2]
                try:
                    yield decoder.raw_decode(part)[0]
                except ValueError:
                    continue


def objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from objects(child)


def svelte_data(text):
    for match in re.finditer(r'<script([^>]*)>(.*?)</script>', text, re.S):
        if 'data-sveltekit-fetched' in match[1]:
            envelope = json.loads(match[2])
            yield html.unescape(match[1]), json.loads(envelope['body'])


def repo_tree(client, repo):
    commit = client.json('https://api.github.com/repos/' + repo + '/commits/HEAD')['sha']
    tree = client.json(f'https://api.github.com/repos/{repo}/git/trees/{commit}?recursive=1')
    if tree.get('truncated'):
        raise ValueError('Truncated official tree: ' + repo)
    return commit, [r['path'] for r in tree['tree'] if r['type'] == 'blob']


def github_urls(repo, commit, path):
    path = urllib.parse.quote(path, safe='/')
    return (f'https://github.com/{repo}/blob/{commit}/{path}',
            f'https://raw.githubusercontent.com/{repo}/{commit}/{path}')


def github_root(client, repo):
    """Read a public repository root and its exact revision without an API token.

GitHub's root-page JSON is a file inventory, never executed as JavaScript. Reject
incomplete inventories rather than treating a truncated page as a complete tree.
"""
    text = client.body('https://github.com/' + repo).decode('utf-8')
    for match in re.finditer(r'<script[^>]*type="application/json"[^>]*>(.*?)</script>', text, re.S):
        try:
            data = json.loads(match[1])
        except ValueError:
            continue
        route = data.get('payload', {}).get('codeViewRepoRoute')
        if route:
            tree = route['tree']
            if len(tree['items']) != tree['totalCount']:
                raise ValueError('Incomplete GitHub root inventory: ' + repo)
            return route['refInfo']['currentOid'], tree['items']
    raise ValueError('No GitHub root metadata: ' + repo)


def store_report(client, platform, contest, public_url, download_url=None, fmt=None, notes='', content=None):
    download_url = download_url or public_url
    meta, body = client.get(download_url)
    if meta['status'] != 200:
        raise RuntimeError(f'HTTP {meta["status"]}: {download_url}')
    if content is not None:
        body = content
    claimed_pdf = fmt == 'pdf' or urllib.parse.urlsplit(download_url).path.lower().endswith('.pdf') or meta.get('content_type', '').split(';')[0] == 'application/pdf'
    if claimed_pdf and not body.startswith(b'%PDF'):
        raise ValueError('pdf_magic_ok=false: claimed PDF does not start with %PDF: ' + download_url)
    fmt = fmt or ('pdf' if body.startswith(b'%PDF') else 'md')
    if fmt == 'md' and (b'<html' in body[:500].lower() or not body.strip()):
        raise ValueError('Expected nonempty Markdown: ' + download_url)
    sha = hashlib.sha256(body).hexdigest()
    path = STORE / 'originals' / sha[:2] / (sha + '.' + fmt)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if hashlib.sha256(path.read_bytes()).hexdigest() != sha:
            raise ValueError('Original hash mismatch: ' + str(path))
    else:
        path.write_bytes(body)
    end = contest.get('end_utc')
    return dict(firm_id=platform, collector=f'contest_{platform}.py', source_kind='contest',
                public_url=public_url, listing_url=contest['listing_url'], sha256=sha, bytes=len(body),
                file_format=fmt, local_path=str(path.relative_to(ROOT)),
                filename=urllib.parse.unquote(urllib.parse.urlsplit(download_url).path.rsplit('/', 1)[-1]),
                title_hint=contest['name'], project_hint=contest.get('sponsor/project'),
                date_hint=end[:10] if end else None, date_precision='day' if end else 'none',
                date_basis='contest_end' if end else 'none',
                doc_kind='fix_review' if contest['format'] == 'mitigation' else 'contest_report',
                retrieved_utc=meta['accessed_at'], notes=notes), body


def finish(platform, contests, reports, failures, listing_urls, listed_count, evidence, skipped_non_report=0):
    out = ROOT / 'data' / 'collect' / platform
    contests.sort(key=lambda c: str(c['contest_id']))
    # A single file can serve multiple contests (e.g. mitigation in parent report).
    unique = {(r['public_url'], r['sha256']): r for r in reports}
    reports = sorted(unique.values(), key=lambda r: r['public_url'])
    write_jsonl(out / 'contests.jsonl', contests)
    write_jsonl(out / 'reports.jsonl', reports)
    status = dict(firm_id=platform, listing_urls=listing_urls, listed_count=listed_count,
                  collected=len(reports), failed=len(failures), skipped_non_report=skipped_non_report,
                  failures=failures, collected_utc=utc(), collector_script=f'scripts/collect/contest_{platform}.py')
    write_json(out / 'status.json', status)
    write_json(out / 'reconciliation.json', evidence)
    print(json.dumps(status), flush=True)


def args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--refresh', action='store_true', help='Refresh captured HTTP metadata and bytes')
    parser.add_argument('--offline', action='store_true', help='Rebuild using captured responses only')
    return parser.parse_args()
