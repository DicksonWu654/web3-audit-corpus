#!/usr/bin/env python3
"""Registry-driven, anonymous GitHub report acquisition; never runs fetched code.

Requires Git, PyYAML and pypdf (or pdftotext). Examples, from repository root:
  python3 -I scripts/collect/github_collector.py --stage all
  python3 -I scripts/collect/github_collector.py --stage discover
  python3 -I scripts/collect/github_collector.py --stage collect --only slowmist
  python3 -I scripts/collect/github_collector.py --stage summary
  python3 -I scripts/collect/github_collector.py --stage validate --verify-hashes

Bare shallow snapshots live in local-cache/git/<firm_id>/<owner>__<repo>.git.
Git uses a localhost relay so *each* smart-HTTP request (not just each clone)
passes the same per-host 1 request/second limiter and RFC-style robots rules.
No credentials, checkout, hooks, submodules, LFS smudge, or remote code execution.
Successful HTTP discovery and PDF text are cached locally. Existing snapshots
are frozen unless --refresh is requested. Metadata replay and summary are offline.
"""
import argparse
import base64
import collections
import concurrent.futures
import csv
import datetime as dt
import hashlib
import functools
import fcntl
import html
import http.server
import json
import logging
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
STORE = ROOT / 'local-cache'
CACHE = STORE / 'github-cache'
DATA = ROOT / 'data/collect'
CONFIG = Path(__file__).with_name('github_firms.yaml')
UA = 'Web3AuditCorpus-GitHubCollector/1.0 (public audit research; anonymous; 1 request/sec)'
UTC = dt.timezone.utc
COLLECTOR = 'scripts/collect/github_collector.py'
FIELDS = ('firm_id collector source_kind public_url listing_url sha256 bytes file_format local_path '
          'filename title_hint project_hint date_hint date_precision date_basis doc_kind retrieved_utc notes').split()
REPORT_KINDS = {'audit_report', 'fix_review', 'formal_verification', 'contest_report', 'unknown'}


def now():
    return dt.datetime.now(UTC).isoformat(timespec='seconds')


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + f'.{os.getpid()}.{threading.get_ident()}.tmp')
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n')
    temp.replace(path)


def read_json(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


def scope():
    with (ROOT / 'registry/scope_tier_a.csv').open(newline='') as f:
        return [r for r in csv.DictReader(f) if r['scope_group'] == 'firm' and r['host'] == 'github' and r['firm_id'] != 'certik']


def settings():
    import yaml
    config = yaml.safe_load(CONFIG.read_text())
    if config.get('version') != 1:
        raise ValueError('Unsupported config version')
    return config


def repo_name(value):
    value = re.sub(r'^https://github.com/', '', value).split('#')[0].strip('/')
    name = '/'.join(value.split('/')[:2]).removesuffix('.git')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', name):
        raise ValueError('Invalid GitHub repository: ' + value)
    return name


class Robots:
    """Robots matching including * and $, unsupported by urllib.robotparser."""
    def __init__(self, text):
        groups, agents, rules = [], [], []
        for raw in text.splitlines():
            line = raw.split('#')[0].strip()
            if ':' not in line:
                continue
            key, val = [s.strip() for s in line.split(':', 1)]
            key = key.lower()
            if key == 'user-agent':
                if rules:
                    groups.append((agents, rules))
                    agents, rules = [], []
                agents.append(val.lower())
            elif key in ('allow', 'disallow') and agents and val:
                rules.append((key == 'allow', val))
        groups.append((agents, rules))
        scores = [(max([len(a) for a in aa if a != '*' and a in UA.lower()] or
                       [0 if '*' in aa else -1]), rr) for aa, rr in groups]
        best = max([s for s, _ in scores] or [-1])
        self.rules = [r for s, rr in scores if s == best and s >= 0 for r in rr]

    def allows(self, url):
        p = urllib.parse.urlsplit(url)
        target = urllib.parse.unquote(p.path) + ('?' + p.query if p.query else '')
        matches = []
        for allow, pattern in self.rules:
            end = pattern.endswith('$')
            pat = pattern[:-1] if end else pattern
            regex = '^' + '.*'.join(re.escape(s) for s in pat.split('*')) + ('$' if end else '')
            if re.search(regex, target):
                matches.append((len(pat.replace('*', '')), allow))
        return max(matches)[1] if matches else True


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HTTP:
    def __init__(self, refresh=False):
        self.lock = threading.Lock()
        self.last = {}
        self.robots = {}
        self.blocked_until = {}
        self.refresh = refresh
        self.opener = urllib.request.build_opener(NoRedirect)
        self.log_lock = threading.Lock()

    def pace(self, host):
        # Share request-start pacing with web_common.Client and other workers.
        # A per-client monotonic clock cannot enforce a per-host process limit.
        locks = STORE / 'web-host-locks'
        locks.mkdir(parents=True, exist_ok=True)
        key = hashlib.sha256(host.lower().encode()).hexdigest()
        with self.lock, (locks / key).open('a+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            lock.seek(0)
            last = float(lock.read() or '0')
            time.sleep(max(0, 1.05 - (time.time() - last)))
            lock.seek(0)
            lock.truncate()
            lock.write(str(time.time()))
            lock.flush()

    def log(self, value):
        CACHE.mkdir(parents=True, exist_ok=True)
        with self.log_lock, (CACHE / 'requests.jsonl').open('a') as f:
            f.write(json.dumps(dict(value, utc=now()), sort_keys=True) + '\n')

    def open(self, url, data=None, headers=None, robots=True):
        for _ in range(6):
            parsed = urllib.parse.urlsplit(url)
            host = parsed.hostname
            if parsed.scheme != 'https' or host not in {'github.com', 'api.github.com', 'raw.githubusercontent.com', 'media.githubusercontent.com'}:
                raise ValueError('Unapproved HTTPS host: ' + url)
            if self.blocked_until.get(host, 0) > time.time():
                raise RuntimeError(f'{host} rate limited until {dt.datetime.fromtimestamp(self.blocked_until[host], UTC).isoformat()}')
            if robots:
                self.check_robots(url)
            self.pace(host)
            started = dt.datetime.now(UTC).isoformat(timespec='microseconds')
            req = urllib.request.Request(url, data=data, headers={
                'User-Agent': UA, 'Accept-Encoding': 'identity', **(headers or {})})
            try:
                res = self.opener.open(req, timeout=180)
                self.log({'url': url, 'method': req.get_method(), 'status': res.status, 'started_utc': started,
                          'rate_remaining': res.headers.get('X-RateLimit-Remaining'), 'rate_reset': res.headers.get('X-RateLimit-Reset')})
                return res
            except urllib.error.HTTPError as e:
                self.log({'url': url, 'method': req.get_method(), 'status': e.code, 'started_utc': started,
                          'rate_remaining': e.headers.get('X-RateLimit-Remaining'), 'rate_reset': e.headers.get('X-RateLimit-Reset')})
                if e.code in (301, 302, 303, 307, 308):
                    url = urllib.parse.urljoin(url, e.headers['Location'])
                    e.close()
                    continue
                if e.code == 429 or (e.code == 403 and e.headers.get('X-RateLimit-Remaining') == '0'):
                    reset = e.headers.get('X-RateLimit-Reset')
                    retry = e.headers.get('Retry-After')
                    self.blocked_until[host] = float(reset) + 2 if reset else time.time() + (int(retry) if retry and retry.isdigit() else 60)
                raise
        raise RuntimeError('Too many redirects')

    def check_robots(self, url):
        host = urllib.parse.urlsplit(url).hostname
        if host not in self.robots:
            # Robots data has its own immutable evidence cache; never hide denial.
            rp = CACHE / ('robots-' + host + '.json')
            saved = read_json(rp)
            if not saved or self.refresh:
                robots_url = 'https://' + host + '/robots.txt'
                try:
                    with self.open(robots_url, robots=False) as res:
                        saved = {'url': robots_url, 'status': res.status, 'text': res.read().decode(errors='replace'), 'utc': now()}
                except urllib.error.HTTPError as e:
                    if e.code not in (404, 410):
                        raise RuntimeError(f'robots.txt unavailable: {host}: HTTP {e.code}') from e
                    saved = {'url': robots_url, 'status': e.code, 'text': '', 'utc': now()}
                write_json(rp, saved)
            self.robots[host] = Robots(saved['text'])
        if not self.robots[host].allows(url):
            raise RuntimeError('robots.txt disallows: ' + url)

    def json(self, url):
        p = CACHE / 'http' / (hashlib.sha256(url.encode()).hexdigest() + '.json')
        saved = read_json(p)
        if saved and not self.refresh:
            return saved['body'], saved['utc']
        with self.open(url, headers={'Accept': 'application/vnd.github+json'}) as res:
            body = json.load(res)
        write_json(p, {'url': url, 'utc': now(), 'body': body})
        return body, now()


class Relay:
    """Loopback-only transport: Git cannot forward auth or evade HTTP pacing."""
    def __init__(self, client):
        outer = self
        self.http = client
        self.allowed = set()
        self.errors = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                self.forward()

            def do_POST(self):
                self.forward()

            def forward(self):
                path = urllib.parse.urlsplit(self.path)
                match = re.fullmatch(r'/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\.git/(info/refs|git-upload-pack)', path.path)
                if not match or match[1].lower() not in outer.allowed:
                    self.send_error(403)
                    return
                try:
                    if self.headers.get('Transfer-Encoding'):
                        raise ValueError('Chunked Git requests are not supported')
                    size = int(self.headers.get('Content-Length', '0'))
                    if size > 8 * 1024 * 1024:
                        raise ValueError('Oversized Git request')
                    body = self.rfile.read(size) if self.command == 'POST' else None
                    headers = {k: self.headers[k] for k in ('Accept', 'Content-Type', 'Git-Protocol') if k in self.headers}
                    with outer.http.open('https://github.com' + self.path, data=body, headers=headers) as res:
                        self.send_response(res.status)
                        for k in ('Content-Type', 'Content-Length'):
                            if res.headers.get(k):
                                self.send_header(k, res.headers[k])
                        self.end_headers()
                        shutil.copyfileobj(res, self.wfile, length=1024 * 1024)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except Exception as e:
                    outer.errors[match[1].lower()] = str(e)[:500]
                    outer.http.log({'url': 'https://github.com' + self.path, 'error': str(e)[:500]})
                    self.send_error(502, str(e)[:200])

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()

    def url(self, repo):
        self.allowed.add(repo.lower())
        return f'http://127.0.0.1:{self.server.server_port}/{repo}.git'


def git_env():
    # Deliberately omit HOME, agents, cloud variables, netrc, proxy credentials,
    # user Git config and all Git-provided config/count environment variables.
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'LANG', 'SSL_CERT_FILE', 'GIT_SSL_CAINFO')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
               GIT_ASKPASS='/bin/false', GIT_LFS_SKIP_SMUDGE='1', NO_PROXY='127.0.0.1',
               no_proxy='127.0.0.1')
    return env


def git_args(target=None):
    args = ['git', '-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null',
            '-c', 'init.templateDir=', '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never',
            '-c', 'http.sslVerify=true', '-c', 'http.userAgent=' + UA, '-c', 'http.proxy=',
            '-c', 'http.followRedirects=false', '-c', 'gc.auto=0', '-c', 'maintenance.auto=false',
            '-c', 'protocol.version=0']
    if target:
        args += ['--git-dir=' + str(target)]
    return args


def git(target, args, timeout=120):
    res = subprocess.run(git_args(target) + args, env=git_env(), capture_output=True, timeout=timeout)
    if res.returncode:
        raise RuntimeError(res.stderr.decode(errors='replace')[-1500:])
    return res.stdout


def snapshot(firm_id, repo, relay, refresh=False, revision=None):
    suffix = ('__' + revision[:12]) if revision else ''
    target = STORE / 'git' / firm_id / (repo.replace('/', '__') + suffix + '.git')
    target.parent.mkdir(parents=True, exist_ok=True)
    url = relay.url(repo)
    if not (target / 'HEAD').exists():
        git(None, ['clone', '--bare', '--depth=1', '--no-tags', url, str(target)], timeout=2400)
        git(target, ['config', 'remote.origin.url', 'https://github.com/' + repo + '.git'])
    if refresh or revision:
        git(target, ['fetch', '--depth=1', '--no-tags', url, revision or 'HEAD'], timeout=2400)
        git(target, ['update-ref', 'HEAD', 'FETCH_HEAD'])
    commit = git(target, ['rev-parse', 'HEAD']).decode().strip()
    tree = []
    for line in git(target, ['ls-tree', '-rlz', '--full-tree', commit]).split(b'\0'):
        if not line:
            continue
        info, path = line.split(b'\t', 1)
        mode, kind, oid, size = info.decode().split()
        tree.append({'path': path.decode('utf-8'), 'mode': mode, 'type': kind,
                     'git_blob': oid, 'bytes': int(size) if size != '-' else 0})
    return target, commit, tree


def discover(firm, conf, client):
    fid = firm['firm_id']
    path = DATA / fid / 'github_discovery.json'
    prior = read_json(path, {})
    owners = sorted(set([repo_name(firm['github_reports_url']).split('/')[0]] + conf.get('discovery_owners', [])), key=str.lower)
    owners += [r.split('/')[0] for r in conf.get('repos', []) if r.split('/')[0].lower() not in {o.lower() for o in owners}]
    results, errors = [], []
    for owner in owners:
        old = next((r for r in prior.get('owners', []) if r['owner'].lower() == owner.lower()), None)
        if old and old.get('complete') and not client.refresh:
            results.append(old)
            continue
        entry = {'owner': owner, 'complete': False, 'pages': [], 'repositories': []}
        try:
            for page in range(1, 101):
                # This public endpoint lists owned repositories for both users
                # and organizations, including archived repositories.
                url = f'https://api.github.com/users/{owner}/repos?per_page=100&sort=full_name&page={page}'
                repos, accessed = client.json(url)
                if not isinstance(repos, list):
                    raise ValueError('Unexpected repository listing response')
                entry['pages'].append({'url': url, 'accessed_utc': accessed, 'count': len(repos)})
                for r in repos:
                    entry['repositories'].append({k: r.get(k) for k in
                        ('full_name', 'html_url', 'description', 'fork', 'archived', 'default_branch', 'created_at', 'pushed_at')})
                if len(repos) < 100:
                    entry['complete'] = True
                    break
            else:
                raise ValueError('Repository pagination exceeded 100 pages')
        except Exception as e:
            entry['error'] = str(e)
            errors.append({'url': f'https://api.github.com/users/{owner}/repos', 'error': str(e)})
        results.append(entry)
    selected = {repo_name(firm['github_reports_url']).lower(): repo_name(firm['github_reports_url'])}
    for name in conf.get('repos', []):
        selected[name.lower()] = repo_name(name)
    candidates = []
    ignored = {k.lower(): v for k, v in conf.get('exclude_repos', {}).items()}
    for owner in results:
        for r in owner['repositories']:
            name = r['full_name']
            low = name.lower()
            relevant = re.search(r'audit|report|publication|portfolio|security.?review|assessment', name.split('/')[-1], re.I)
            if not relevant and low not in selected:
                continue
            if low in selected:
                decision, reason = 'include', 'Registry or explicitly configured report source.'
            elif low in ignored:
                decision, reason = 'exclude', ignored[low]
            elif any(re.search(pattern, name, re.I) for pattern in conf.get('exclude_repo_patterns', {})):
                decision, reason = 'exclude', next(why for pattern, why in conf['exclude_repo_patterns'].items() if re.search(pattern, name, re.I))
            elif r.get('fork'):
                decision, reason = 'exclude', 'Fork; no independent publisher report archive established by metadata.'
            elif re.search(r'^(audits?|reports?|publications|portfolio|securityreports)$|audits_public|public.*(?:audit|report)|(?:audit|report).*public|audit.?reports', name.split('/')[-1], re.I):
                decision, reason = 'include', 'Publisher-owned report/archive repository discovered by public account listing.'
                selected[low] = name
            else:
                decision, reason = 'review', 'Name is a discovery lead; inspect metadata/config before inclusion.'
            candidates.append(dict(r, decision=decision, reason=reason))
    result = {'firm_id': fid, 'owners': results, 'candidates': sorted(candidates, key=lambda r: r['full_name'].lower()),
              'repos': sorted(selected.values(), key=str.lower), 'failures': errors,
              'complete': all(o['complete'] for o in results), 'checked_utc': now()}
    write_json(path, result)
    print('discover', fid, 'repos=' + str(len(result['repos'])), 'complete=' + str(result['complete']), flush=True)
    return result


def inspect_sources(firms, client):
    """Review ambiguous repositories through the API, without project execution."""
    for firm in firms:
        fid = firm['firm_id']
        discovery = read_json(DATA / fid / 'github_discovery.json', {})
        pending = [r for r in discovery.get('candidates', []) if r['decision'] == 'review']
        if not pending:
            continue
        reviewed = []
        for r in pending:
            name = r['full_name']
            entry = {'repo': name}
            try:
                url = f'https://api.github.com/repos/{name}/git/trees/HEAD?recursive=1'
                tree, accessed = client.json(url)
                if tree.get('truncated'):
                    raise ValueError('Truncated API tree; inspect via Git instead')
                entry.update(tree_sha=tree['sha'], accessed_utc=accessed,
                             tree=tree['tree'], url=url)
                readme = next((t for t in tree['tree'] if t['path'].lower() == 'readme.md'), None)
                if readme:
                    blob, _ = client.json(f'https://api.github.com/repos/{name}/git/blobs/' + readme['sha'])
                    entry['readme'] = base64.b64decode(blob.get('content', '')).decode(errors='replace')[:30000]
                patterns = settings()['firms'].get(fid, {}).get('inspect_text_paths', [])
                for t in tree['tree']:
                    if t['type'] == 'blob' and any(re.search(pattern, t['path']) for pattern in patterns):
                        blob, _ = client.json(f'https://api.github.com/repos/{name}/git/blobs/' + t['sha'])
                        entry.setdefault('sample_text', {})[t['path']] = base64.b64decode(blob.get('content', '')).decode(errors='replace')[:20000]
                docs = [t['path'] for t in tree['tree'] if re.search(r'\.(pdf|md|html|txt)$', t['path'], re.I)]
                print('review', fid, name, 'documents=' + str(len(docs)), json.dumps(docs[:30]), '\n' + entry.get('readme', '')[:1800], flush=True)
            except Exception as e:
                entry['error'] = str(e)
                print('review-error', name, str(e), flush=True)
            reviewed.append(entry)
        # README/report excerpts are originals, not release metadata.
        write_json(CACHE / 'reviews' / (fid + '.json'), reviewed)


def search_sources(firms, config, client):
    for firm in firms:
        queries = config['firms'].get(firm['firm_id'], {}).get('search_queries', [])
        if not queries:
            continue
        results = []
        for query in queries:
            url = 'https://api.github.com/search/repositories?' + urllib.parse.urlencode({'q': query, 'per_page': 100})
            entry = {'query': query, 'url': url}
            try:
                result, accessed = client.json(url)
                entry.update(accessed_utc=accessed, total_count=result['total_count'],
                             repositories=[{k: r.get(k) for k in ('full_name', 'html_url', 'description', 'fork')} for r in result['items']])
            except Exception as e:
                entry['error'] = str(e)
            results.append(entry)
        write_json(DATA / firm['firm_id'] / 'github_search.json', results)
        print(json.dumps(results, indent=2), flush=True)


def selected_readme_paths(target, tree, sections):
    if not sections:
        return None
    readmes = [r for r in tree if r['path'].lower() == 'readme.md']
    if not readmes:
        raise ValueError('Configured section selection has no root README')
    text = git(target, ['cat-file', 'blob', readmes[0]['git_blob']]).decode(errors='replace')
    paths, active = set(), None
    for line in text.splitlines():
        m = re.match(r'^(#{1,6})\s+(.+?)\s*#*$', line)
        if m:
            level, heading = len(m[1]), m[2].strip()
            if active and level <= active:
                active = None
            if heading in sections:
                active = level
        if active:
            for link in re.findall(r'\]\(([^)]+)\)', line):
                p = urllib.parse.unquote(urllib.parse.urlsplit(link).path)
                if '/reviews/' in p:
                    p = 'reviews/' + p.split('/reviews/', 1)[1]
                p = p.removeprefix('./').lstrip('/')
                if p.lower().endswith(('.pdf', '.md', '.html')):
                    paths.add(p)
    if not paths:
        raise ValueError('Configured README sections selected no report links')
    return paths


def exclusion(item, conf, defaults, readme_paths):
    p = item['path']
    if item['type'] != 'blob' or item['mode'] not in ('100644', '100755'):
        return 'Symlink/submodule/non-regular object; never followed or executed.'
    if conf.get('scope_selector') == 'trail_of_bits':
        from trail_of_bits_scope import scope_reason
        why = scope_reason(p, readme_paths or set())
        if why:
            return why
    elif readme_paths is not None and p not in readme_paths:
        return 'Outside publisher-indexed Web3 review sections.'
    if conf.get('include_paths') and not any(re.search(x, p) for x in conf['include_paths']):
        return 'Outside configured report subdirectories.'
    for pattern, why in conf.get('exclude_paths', {}).items():
        if re.search(pattern, p):
            return why
    if re.search(defaults['non_report_paths'], p, re.I):
        return 'Supporting assets, research, templates, training, slides, or CTF material.'
    if re.search(defaults['non_report_names'], PurePosixPath(p).name, re.I) and p not in conf.get('allow_readme_paths', []) + conf.get('allow_document_paths', []):
        return 'Repository index, metadata sidecar, licence/change log, or other documentation (configured basename rule).'
    if PurePosixPath(p).suffix.lower().lstrip('.') not in defaults['extensions']:
        return 'Non-document asset/source code; extension is not an audit-report format.'
    return None


def pdf_worker(path):
    """Separate bounded process; report content cannot import project code."""
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (18, 18))
    logging.disable(logging.CRITICAL)
    from pypdf import PdfReader
    result = {'text': '', 'title': '', 'error': '', 'extractor': 'pypdf', 'pages_requested': 2}
    try:
        reader = PdfReader(path, strict=False)
        if reader.is_encrypted:
            reader.decrypt('')
        result['title'] = str((reader.metadata or {}).get('/Title', ''))[:500]
        for page in reader.pages[:2]:
            result['text'] += (page.extract_text() or '')[:30000] + '\n'
    except Exception as e:
        result['error'] = type(e).__name__ + ': ' + str(e)[:300]
    print(json.dumps(result, ensure_ascii=False))


def document_text(path, sha, fmt):
    cached = CACHE / 'text' / (sha + '.json')
    old = read_json(cached)
    if old:
        return old
    result = {'text': '', 'title': '', 'error': '', 'extractor': 'none', 'pages_requested': 0}
    if fmt == 'pdf':
        try:
            if shutil.which('pdftotext'):
                limits = ['prlimit', '--as=805306368', '--cpu=18', '--'] if shutil.which('prlimit') else []
                result.update(extractor='pdftotext', pages_requested=2)
                p = subprocess.run(limits + ['pdftotext', '-f', '1', '-l', '2', '-layout', str(path), '-'],
                                   capture_output=True, timeout=25)
                result['text'] = p.stdout.decode(errors='replace')[:60000]
                if p.returncode:
                    result['error'] = p.stderr.decode(errors='replace')[:300]
            else:
                p = subprocess.run([sys.executable, '-I','-B', str(Path(__file__).resolve()), '--pdf-worker', str(path)],
                                   capture_output=True, text=True, timeout=25, env=git_env())
                if p.returncode:
                    raise RuntimeError('PDF worker: ' + p.stderr[-300:] + f' exit={p.returncode}')
                result = json.loads(p.stdout)
        except Exception as e:
            result['error'] = type(e).__name__ + ': ' + str(e)[:300]
    elif fmt in ('md', 'html') or path.suffix.lower() == '.txt':
        with path.open('rb') as f:
            result['text'] = f.read(100000).decode(errors='replace')
        if fmt == 'html':
            result['text'] = html.unescape(re.sub(r'<[^>]+>', ' ', result['text']))
        result['extractor'] = 'text'
    elif path.suffix.lower() == '.docx':
        try:
            with zipfile.ZipFile(path) as z:
                info = z.getinfo('word/document.xml')
                if info.file_size > 5 * 1024 * 1024:
                    raise ValueError('DOCX XML exceeds bounded text limit')
                xml = ET.fromstring(z.read(info))
                result['text'] = '\n'.join(''.join(p.itertext()) for p in xml.iter() if p.tag.endswith('}p'))[:60000]
                result['extractor'] = 'docx-xml'
        except Exception as e:
            result['error'] = str(e)[:300]
    elif path.suffix.lower() == '.rtf':
        with path.open('rb') as f:
            text = f.read(200000).decode(errors='replace')
        result['text'] = re.sub(r'\\[a-zA-Z]+-?\d* ?|[{}]', ' ', text)[:60000]
        result['extractor'] = 'rtf-text'
    else:
        result['error'] = 'Unsupported text extraction format; filename hints only.'
    write_json(cached, result)
    return result


MONTHS = {m.lower(): i for i, m in enumerate(['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'], 1)}
MONTHS.update({m[:3]: n for m, n in list(MONTHS.items())})
MONTHS['sept'] = 9
MONTH = r'(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)'


def dates(text, filename=False):
    text = re.sub(r'(\d)(st|nd|rd|th)\b', r'\1', text, flags=re.I)
    text = text.replace('_', ' ')
    candidates = []
    # Precision first; invalid dates are rejected rather than becoming hints.
    for m in re.finditer(r'(?<!\d)(20\d{2})[-. /]?(0?[1-9]|1[012])[-. /]?(0?[1-9]|[12]\d|3[01])(?!\d)', text):
        candidates.append((m.start(), int(m[1]), int(m[2]), int(m[3])))
    for m in re.finditer(r'(?<!\d)([0-3]?\d)[-. /]([01]?\d)[-. /](20\d{2})(?!\d)', text):
        candidates.append((m.start(), int(m[3]), int(m[2]), int(m[1])))
    for m in re.finditer(r'(?<!\d)(0?[1-9]|1[012])[-. /](1[3-9]|2\d|3[01])[-. /](20\d{2})(?!\d)', text):
        candidates.append((m.start(), int(m[3]), int(m[1]), int(m[2])))
    for m in re.finditer(r'\b(\d{1,2})[\s,.-]+(' + MONTH + r')[\s,.-]+(20\d{2})\b', text, re.I):
        candidates.append((m.start(), int(m[3]), MONTHS[m[2].lower()], int(m[1])))
    for m in re.finditer(r'\b(' + MONTH + r')[\s,.-]+(\d{1,2})[\s,.-]+(20\d{2})\b', text, re.I):
        candidates.append((m.start(), int(m[3]), MONTHS[m[1].lower()], int(m[2])))
    if filename:
        for m in re.finditer(r'(?i)(?:\bv|[-_ ])(\d{2})([01]\d)([0-3]\d)(?!\d)', text):
            candidates.append((m.start(), 2000 + int(m[1]), int(m[2]), int(m[3])))
    for _, y, mo, day in sorted(candidates):
        try:
            d = dt.date(y, mo, day)
            if 2008 <= y <= dt.datetime.now(UTC).year:
                return d.isoformat(), 'day'
        except ValueError:
            pass
    for pattern, reverse in [(r'(?<!\d)(20\d{2})[-. /](0?[1-9]|1[012])(?!\d)', False),
                             (r'\b(' + MONTH + r')[\s,.-]+(20\d{2})\b', True)]:
        for m in re.finditer(pattern, text, re.I):
            y, mo = (int(m[2]), MONTHS[m[1].lower()]) if reverse else (int(m[1]), int(m[2]))
            if 2008 <= y <= dt.datetime.now(UTC).year:
                return f'{y:04d}-{mo:02d}', 'month'
    if filename:
        m = re.search(r'(?<!\d)(20\d{2})(?!\d)', text)
        if m and 2008 <= int(m[1]) <= dt.datetime.now(UTC).year:
            return m[1], 'year'
    return '', 'none'


def hints(filename, doc, defaults, conf):
    stem = PurePosixPath(filename).stem
    clean = re.sub(r'[_]+', ' ', stem)
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', doc['text'])
    title = doc.get('title', '').strip()
    if not title or re.search(r'untitled|microsoft|google docs|^document|^report$|^template|overleaf|typst', title, re.I):
        title = clean
    project = re.sub(r'(?i)\b(?:security|smart[- ]?contracts?|audit|report|review|final|draft|public|assessment|formal|verification)\b', ' ', clean)
    project = re.sub(r'(?<!\d)20\d{2}(?:[-. ]?\d{1,2}){0,2}(?!\d)|\bv\d+(?:\.\d+)*\b', ' ', project)
    project = re.sub(r'\s+', ' ', project).strip(' -_.()[]')
    # A labelled front-page client/project is stronger than an opaque filename.
    label = re.search(r'(?im)^\s*(?:project|client|prepared for)\s*[:：]\s*([^\n]{2,100})', text[:6000])
    if label:
        project = label[1].strip()
    generic = not project or re.fullmatch(r'(?i)(review|report|audit|final|assessment|summary|readme)(?:[-_ ](?:report|review|final))?', clean.strip())
    if generic:
        parents = [p for p in PurePosixPath(filename).parts[:-1] if not re.fullmatch(r'(?i)(reports?|audits?|pdf|md|html|content|public|20\d{2})', p)]
        project = ' / '.join(parents[-2:]) if parents else project
        lines = [re.sub(r'^#+\s*', '', line.strip()) for line in text[:3000].splitlines() if line.strip()]
        headline = next((i for i, line in enumerate(lines[:18]) if re.search(r'(?i)security.*(?:assessment|audit|review)|audit.*report|formal.*verification', line)), None)
        if headline is not None:
            useful = [line for line in lines[max(0, headline-2):headline+1] if len(line) < 250 and not re.search(r'(?i)prepared (by|for)|confidential|https?://', line)]
            title = ' '.join(useful) or title
        elif project:
            title = project + ' ' + clean
    if PurePosixPath(filename).suffix.lower() in ('.md', '.markdown'):
        heading = re.search(r'(?m)^#{1,2}\s+([^\n]{3,250})', text[:4000])
        if heading and not re.fullmatch(r'(?i)(project overview|overview|summary|executive summary|table of contents|audit scope)', heading[1].strip()):
            title = heading[1].strip()
            if stem.lower() == 'readme':
                project = re.sub(r'(?i)\b(?:security|smart[- ]?contracts?|audit|report|review|by|yAcademy|Sigma Prime)\b', ' ', title)
                project = re.sub(r'\s+', ' ', project).strip(' -_')
    date, precision = dates(filename, filename=True)
    basis = 'filename' if date else 'none'
    # Prefer labelled front matter, then the first two pages. Never use Git,
    # HTTP, PDF creation metadata or crawl dates as audit dates. A label on a
    # different line must not suppress the fallback to the actual front matter.
    labelled = '\n'.join(l for l in text[:18000].splitlines() if re.search(r'(?i)date|completed|issued|prepared|review period|assessment period', l))
    text_date, text_precision = dates(labelled)
    if not text_date:
        text_date, text_precision = dates(text[:10000])
    conflict = bool(date and text_date and not (date.startswith(text_date) or text_date.startswith(date)))
    filename_date = date
    if text_date and (not date or (text_date.startswith(date) and len(text_date) > len(date)) or (precision in ('year', 'month') and text_precision == 'day')):
        date, precision, basis = text_date, text_precision, 'document_text'
    front = '\n'.join([stem, title, text[:1800]])
    kind = 'audit_report'
    reason = 'Document in publisher report archive; filename/front-page heuristics.'
    if re.search(conf.get('fix_review_pattern', defaults['fix_review_pattern']), stem, re.I):
        kind, reason = 'fix_review', 'Filename explicitly identifies fix review, follow-up, or retest.'
    elif re.search(defaults['fix_review_pattern'], title, re.I) or re.search(r'(?im)^\s*(fix review|remediation (review|verification)|follow.up (review|report))\s*$', text[:1800]):
        kind, reason = 'fix_review', 'Front-page title explicitly identifies fix/remediation review.'
    elif re.search(defaults['formal_pattern'], stem, re.I) or re.search(r'formal\s+verification\s+(?:report|of)', front, re.I):
        kind, reason = 'formal_verification', 'Filename/front-page title identifies formal verification.'
    elif re.search(r'(?i)contest[-_ ]report|competition[-_ ]report|audit[-_ ]contest', stem + ' ' + title):
        kind, reason = 'contest_report', 'Filename/title explicitly identifies a contest report.'
    elif re.search(r'(?i)letter[-_ ]of[-_ ]attestation|certificate|\bkyc\b|assurance[-_ ]overview|(^|[-_ ])loa($|[-_ ])', stem):
        kind, reason = 'non_report', 'Attestation/certificate/assurance material; not the audit report.'
    for pattern, rule in conf.get('doc_kind_rules', {}).items():
        if re.search(pattern, filename):
            kind, reason = rule['doc_kind'], rule['reason']
            break
    if conflict:
        reason += f' Date hints disagree: filename={filename_date}; document_text={text_date}; selected={date} ({basis}); provisional, verify at engagement reconciliation.'
    return dict(title_hint=title[:500], project_hint=project[:250], date_hint=date,
                date_precision=precision, date_basis=basis, doc_kind=kind), reason


def process_file(fid, repo, commit, target, item, conf, defaults, client):
    p = item['path']
    payload = git(target, ['cat-file', 'blob', item['git_blob']])
    lfs_note = ''
    if payload.startswith(b'version https://git-lfs.github.com/spec/v1'):
        pointer = payload.decode('ascii')
        oid = re.search(r'^oid sha256:([0-9a-f]{64})$', pointer, re.M)
        size = re.search(r'^size (\d+)$', pointer, re.M)
        if not oid or not size:
            raise ValueError('Malformed Git LFS pointer')
        expected_size = int(size[1])
        if expected_size > 500 * 1024 * 1024:
            raise ValueError('LFS report exceeds bounded 500 MiB download limit')
        ext = PurePosixPath(p).suffix.lower().lstrip('.')
        existing = STORE / 'originals' / oid[1][:2] / (oid[1] + '.' + ext)
        media_url = f'https://media.githubusercontent.com/media/{repo}/{commit}/' + urllib.parse.quote(p, safe='/')
        if existing.exists() and existing.stat().st_size == expected_size:
            payload = existing.read_bytes()
        else:
            with client.open(media_url) as res:
                payload = res.read(expected_size + 1)
        if len(payload) != expected_size or hashlib.sha256(payload).hexdigest() != oid[1]:
            raise ValueError('Git LFS object size/SHA-256 does not match pinned pointer')
        lfs_note = f'Git LFS pointer verified: oid=sha256:{oid[1]}; size={expected_size}; media_url={media_url}'
    sha = hashlib.sha256(payload).hexdigest()
    ext = PurePosixPath(p).suffix.lower().lstrip('.') or 'bin'
    fmt = {'pdf': 'pdf', 'md': 'md', 'markdown': 'md', 'html': 'html', 'htm': 'html'}.get(ext, 'other')
    pdf_offset = payload[:1024].find(b'%PDF-') if fmt == 'pdf' else -1
    if fmt == 'pdf' and pdf_offset < 0:
        raise ValueError('pdf_magic_ok=false: claimed PDF has no %PDF- header in first 1024 bytes: ' + p)
    local = STORE / 'originals' / sha[:2] / (sha + '.' + ext)
    local.parent.mkdir(parents=True, exist_ok=True)
    if not local.exists():
        # Publish complete bytes atomically. Simultaneous equal-blob workers
        # may replace this path only with the same SHA-addressed bytes.
        staging = CACHE / 'staging' / (sha + f'.{os.getpid()}.{threading.get_ident()}.tmp')
        staging.parent.mkdir(parents=True, exist_ok=True)
        staging.write_bytes(payload)
        staging.replace(local)
    elif local.stat().st_size != len(payload):
        raise ValueError('Existing SHA-addressed original has incorrect size: ' + str(local))
    doc = document_text(local, sha, fmt)
    extracted, why = hints(p, doc, defaults, conf)
    notes = [f'repo={repo}; commit={commit}; git_blob={item["git_blob"]}; path={p}', why]
    if pdf_offset > 0:
        notes.append(f'PDF header offset={pdf_offset}; publisher original prefix preserved byte-for-byte (reader-compatible first-1024-byte header recognition).')
    if lfs_note:
        notes.append(lfs_note)
    if conf.get('source_notes'):
        notes.append(conf['source_notes'])
    if doc.get('error'):
        notes.append('First-two-page extraction: ' + doc['error'])
    return dict(firm_id=fid, collector=COLLECTOR, source_kind='github',
                public_url=f'https://github.com/{repo}/blob/{commit}/' + urllib.parse.quote(p, safe='/'),
                listing_url='https://github.com/' + repo, sha256=sha, bytes=len(payload), file_format=fmt,
                local_path=local.relative_to(ROOT).as_posix(), filename=p,
                retrieved_utc=now(), notes=' | '.join(notes), **extracted)


def listing_notes(firm, collected, repo_count):
    notes = []
    # Reuse evidence already acquired in Phase 0. Never request website pages.
    for listing in read_json(ROOT / 'data/registry/listings.json', []):
        if listing['firm_id'] != firm['firm_id']:
            continue
        n = listing.get('count', len(listing.get('items', [])))
        if n > collected:
            notes.append(f'Previously enumerated publisher listing has {n} report links versus {collected} collected files from {repo_count} repo snapshots; gap {n-collected} is a link/file comparison, not verified missing unique engagements. Evidence: data/registry/listings.json; {listing.get("scope", "")}')
    if firm.get('website_reports_url'):
        notes.append('Website listing left to the website collector: ' + firm['website_reports_url'] + '; no website fetched by this collector; numerical website-only gap unknown unless prior listing evidence is cited above.')
    return notes


@functools.lru_cache(maxsize=1)
def phase0_counts():
    path = ROOT / 'data/registry/counts.jsonl'
    return {r['firm_id']: r for r in map(json.loads, path.read_text().splitlines())} if path.exists() else {}


def reconcile_phase0(fid, records, exclusions):
    baseline = phase0_counts().get(fid, {})
    covered = {(repo_name(r['listing_url']).lower(), r['filename']) for r in records
               if r.get('listing_url', '').startswith('https://github.com/')}
    excluded = {(r['repo'].lower(), r['path']): r['reason'] for r in exclusions}
    covered_blobs = {m[1]: r['public_url'] for r in records if (m := re.search(r'git_blob=([0-9a-f]{40})', r['notes']))}
    result = {'baseline_selected_files': 0, 'collected': 0, 'explained_exclusions': [], 'not_at_current_snapshot': []}
    for row in baseline.get('items', []):
        if not row.get('path') or not row.get('repo'):
            continue
        result['baseline_selected_files'] += 1
        key = row['repo'].lower(), row['path']
        if key in covered:
            result['collected'] += 1
        elif row.get('sha') in covered_blobs:
            result['collected'] += 1
            result.setdefault('identical_blob_relocations', []).append({'repo': row['repo'], 'path': row['path'], 'current_public_url': covered_blobs[row['sha']]})
        elif key in excluded:
            result['explained_exclusions'].append({'repo': row['repo'], 'path': row['path'], 'reason': excluded[key]})
        else:
            result['not_at_current_snapshot'].append({'repo': row['repo'], 'path': row['path'], 'reason': 'Absent from selected current snapshots (possibly renamed/removed since Phase 0); not a silently skipped current report.'})
    return result


def merge_records(records, previous, preserve=False):
    """Preserve recovered receipts and row order on explicitly configured sources."""
    old = {r['public_url']: r for r in previous}
    if preserve:
        for row in records:
            prior = old.get(row['public_url'])
            if prior and prior['sha256'] != row['sha256']:
                raise ValueError('Pinned URL changed SHA-256: ' + row['public_url'])
        merged = list(previous)
        acquired = {r['sha256'] for r in previous}
        for row in records:
            if row['public_url'] not in old and row['sha256'] not in acquired:
                merged.append(row)
                acquired.add(row['sha256'])
        return merged
    for row in records:
        if old.get(row['public_url'], {}).get('sha256') == row['sha256']:
            row['retrieved_utc'] = old[row['public_url']]['retrieved_utc']
    return records


def collect_firm(firm, conf, defaults, discovery, relay, args):
    fid = firm['firm_id']
    folder = DATA / fid
    folder.mkdir(parents=True, exist_ok=True)
    prior = read_json(folder / 'status.json', {})
    repos = discovery.get('repos') or [repo_name(firm['github_reports_url'])]
    for r in conf.get('repos', []):
        if r.lower() not in {n.lower() for n in repos}:
            repos.append(r)
    records, exclusions, failures, repo_status = [], [], [], []
    listed, candidates = 0, 0
    for repo in sorted(repos, key=str.lower):
        source = {'repo': repo, 'listing_url': 'https://github.com/' + repo}
        repo_conf = dict(conf)
        repo_conf.update(next((v for k, v in conf.get('repo_rules', {}).items() if k.lower() == repo.lower()), {}))
        try:
            target, commit, tree = snapshot(fid, repo, relay, args.refresh)
            source.update(commit=commit, files=len(tree), clone_path=target.relative_to(ROOT).as_posix())
            if repo_conf.get('notes'):
                source['notes'] = repo_conf['notes']
            listed += len(tree)
            allow = selected_readme_paths(target, tree, repo_conf.get('readme_sections'))
            tasks = []
            for item in tree:
                why = exclusion(item, repo_conf, defaults, allow)
                if why:
                    exclusions.append({'repo': repo, 'commit': commit, 'path': item['path'], 'reason': why})
                else:
                    tasks.append(item)
            source['candidate_files'] = len(tasks)
            candidates += len(tasks)
            print('snapshot', fid, repo, commit, f'files={len(tree)} eligible={len(tasks)}', flush=True)
            # PDF subprocesses have individual CPU/memory/wall-clock bounds.
            with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
                future_map = {pool.submit(process_file, fid, repo, commit, target, item, repo_conf, defaults, relay.http): item for item in tasks}
                for future in concurrent.futures.as_completed(future_map):
                    item = future_map[future]
                    try:
                        records.append(future.result())
                    except Exception as e:
                        failures.append({'url': f'https://github.com/{repo}/blob/{commit}/' + urllib.parse.quote(item['path']), 'error': str(e)[:2000]})
        except Exception as e:
            error = ('GitHub retrieval failed: ' + relay.errors[repo.lower()]) if repo.lower() in relay.errors else str(e)
            error = re.sub(r'http://127\.0\.0\.1:\d+/', 'https://github.com/', error.replace(str(ROOT) + '/', ''))[:2000]
            source['error'] = error
            failures.append({'url': 'https://github.com/' + repo, 'error': error})
        repo_status.append(source)
    records.sort(key=lambda r: r['public_url'])
    # Retain acquisition timestamps on idempotent replays of identical bytes/URL.
    previous = []
    if (folder / 'reports.jsonl').exists():
        previous = list(map(json.loads, (folder / 'reports.jsonl').read_text().splitlines()))
    selected_urls = {r['public_url'] for r in records}
    records = merge_records(records, previous, conf.get('preserve_existing_records', False))
    temp = folder / 'reports.jsonl.tmp'
    temp.write_text(''.join(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n' for r in records))
    temp.replace(folder / 'reports.jsonl')
    kinds = collections.Counter(r['doc_kind'] for r in records)
    notes = [conf[k] for k in ('notes', 'scope_note') if conf.get(k)] + listing_notes(firm, len(records), len(repo_status))
    if not discovery.get('complete'):
        notes.append('Additional-repository discovery incomplete; see github_discovery.json. Collection completeness is only over successfully enumerated snapshots.')
    pending = [r['full_name'] for r in discovery.get('candidates', []) if r['decision'] == 'review']
    if pending:
        notes.append('Discovery leads awaiting metadata/config review: ' + ', '.join(pending))
    status = dict(firm_id=fid, listing_urls=[s['listing_url'] for s in repo_status],
                  listed_count=candidates, collected=len(records), failed=len(failures),
                  skipped_non_report=len(exclusions), failures=failures,
                  collected_utc=prior.get('collected_utc') if prior.get('repos') == repo_status and prior.get('collected') == len(records) else now(),
                  collector_script=COLLECTOR, repos=repo_status, tree_files=listed,
                  doc_kind_counts=dict(sorted(kinds.items())), exclusions=exclusions,
                  report_file_coverage_pct=None if any('error' in r for r in repo_status) else (round(100 * len(records) / candidates, 4) if candidates else 100.0),
                  date_hint_coverage_pct=round(100 * sum(bool(r['date_hint']) for r in records if r['doc_kind'] != 'non_report') / max(1, sum(r['doc_kind'] != 'non_report' for r in records)), 2),
                  discovery_complete=discovery.get('complete', False), discovery_pending=pending, notes=notes,
                  phase0_reconciliation=reconcile_phase0(fid, records, exclusions),
                  listed_count_basis='All eligible document files at frozen HEADs before content classification; revisions/translations/renderings are retained, not engagement-deduplicated.')
    if conf.get('preserve_existing_records'):
        for key in ('collector_scripts', 'date_recovery', 'catalogue_refresh_reconciliation'):
            if key in prior:
                status[key] = prior[key]
        status['preserved_manifest_rows_outside_current_selection'] = sum(r['public_url'] not in selected_urls for r in previous)
        status['report_file_coverage_pct'] = None if failures else 100.0
        status['notes'].append('Prior manifest receipts and their order are retained verbatim, including recovered reports outside the pinned tree. collected includes these receipts; listed_count counts eligible tree files only.')
    write_json(folder / 'status.json', status)
    print('collect', fid, f'files={listed} eligible={candidates} collected={len(records)} failed={len(failures)} kinds={dict(kinds)}', flush=True)
    return status


def summary(firms):
    totals = collections.Counter()
    rows, gaps = [], []
    delegated = {f: c['collector_delegate'] for f,c in settings()['firms'].items() if c.get('collector_delegate')}
    for firm in firms:
        fid = firm['firm_id']
        if fid in delegated:
            gaps.append(fid + ': multi-host publisher collection is maintained by scripts/collect/' + delegated[fid] + '; excluded from GitHub-only summary denominator.')
            continue
        s = read_json(DATA / fid / 'status.json')
        if not s:
            gaps.append(fid + ': no status')
            continue
        k = s.get('doc_kind_counts', {})
        for kind, n in k.items():
            totals[kind] += n
        for key in ('tree_files', 'listed_count', 'collected', 'failed', 'skipped_non_report'):
            totals[key] += s.get(key, 0)
        totals['firms'] += 1
        totals['repos'] += len(s['repos'])
        totals['discovery_complete'] += bool(s.get('discovery_complete'))
        totals['source_gap_firms'] += any('error' in r for r in s['repos'])
        totals['firms_meeting_file_coverage'] += s['report_file_coverage_pct'] is not None and s['report_file_coverage_pct'] >= 98
        dated, count = 0, 0
        for line in (DATA / fid / 'reports.jsonl').read_text().splitlines():
            r = json.loads(line)
            if r['doc_kind'] != 'non_report':
                count += 1
                dated += bool(r['date_hint'])
        totals['dated_report_files'] += dated
        totals['report_files'] += count
        repos = '<br>'.join(f'[{r["repo"]}](https://github.com/{r["repo"]})' for r in s['repos'])
        commits = '<br>'.join(f'`{r.get("commit", "unavailable")}`' for r in s['repos'])
        rows.append(f'| {firm["name"] or fid} | {repos} | {commits} | {s["tree_files"]:,} | {k.get("audit_report", 0):,} | {k.get("fix_review", 0):,} | {k.get("formal_verification", 0):,} | {k.get("contest_report", 0):,} | {k.get("unknown", 0):,} | {s["skipped_non_report"] + k.get("non_report", 0):,} | {s["date_hint_coverage_pct"]:.2f} | {s["report_file_coverage_pct"]} |')
        for note in s['notes']:
            gaps.append(fid + ': ' + note)
        for error in s['failures']:
            gaps.append(fid + ': ' + error['url'] + ': ' + error['error'].replace('\n', ' '))
        base = s.get('phase0_reconciliation', {})
        if base.get('explained_exclusions') or base.get('not_at_current_snapshot'):
            gaps.append(f'{fid}: Phase 0 reconciliation: {base.get("collected", 0)}/{base.get("baseline_selected_files", 0)} earlier selected paths collected, {len(base.get("explained_exclusions", []))} explained exclusions, {len(base.get("not_at_current_snapshot", []))} absent/renamed paths; exact paths and reasons in status.json.')
    totals['unique_originals'] = len({json.loads(l)['sha256'] for f in firms if (DATA / f['firm_id'] / 'reports.jsonl').exists() for l in (DATA / f['firm_id'] / 'reports.jsonl').read_text().splitlines()})
    totals['date_hint_coverage_pct'] = round(100 * totals['dated_report_files'] / max(1, totals['report_files']), 2)
    doc = ['# Tier A GitHub collection', '',
           'Generated offline by `scripts/collect/github_collector.py --stage summary` from per-firm manifests and status files. Originals remain in the gitignored SHA-256 store; public links pin the exact Git commit.', '',
           f'{totals["firms"]} firms; {totals["repos"]} repository source attempts; {totals["collected"]:,} collected document files ({totals["unique_originals"]:,} distinct SHA-256 originals). Acquisition failures: {totals["failed"]}. Fully paginated firm account listings: {totals["discovery_complete"]}. Firms meeting the file-coverage target: {totals["firms_meeting_file_coverage"]}; firms with inaccessible source repositories: {totals["source_gap_firms"]}. Date hints on {totals["dated_report_files"]:,}/{totals["report_files"]:,} report files ({totals["date_hint_coverage_pct"]:.2f}%).', '',
           'Counts are source artifacts, not unique engagements. Revisions, translations and PDF/Markdown/HTML renderings remain separate rows. Reports = audit_report; formal verification and contest reports are separate columns. Non-reports includes every explained excluded tree entry plus collected attestations/certificates. Files = all tracked tree entries. Coverage = successfully cached eligible documents / all eligible documents at the recorded snapshots; a missing/inaccessible repo has unknown coverage, never an assumed zero-report denominator.', '',
           '| Firm | Repos | HEAD commit | Files | Reports | Fix reviews | Formal verification | Contest reports | Unknown / chapters | Non-reports / excluded | Date hints % | File coverage % |',
           '|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|'] + rows
    doc += ['', '## Source gaps and scope notes', ''] + ['- ' + x for x in gaps]
    verification = read_json(DATA / 'github_independent_validation.json', {})
    if verification:
        doc += ['', '## Independent validation', '',
                f'`scripts/collect/validate_github_collection.py` independently checked {verification.get("records_checked", 0):,} manifest records and the exact Git-tree/exclusion partition. Original SHA-256/Git-blob verification requested: {verification.get("original_hashes_verified", False)}. See `data/collect/github_independent_validation.json` for per-firm results; the validator exits unsuccessfully while a source repository remains inaccessible.', '']
        doc += ['- ' + e for e in verification.get('errors', [])]
    doc += ['', '## Reproduction and provenance', '',
            'Use Python with PyYAML and either pypdf or pdftotext. Run `--stage all` for discovery, cloning and summary. Re-run `--stage discover` after anonymous API resets if needed, followed by `--stage collect`. `--stage inspect` reviews ambiguous repository leads using GitHub API trees and README text cached locally; put final inclusion/exclusion decisions in the config and replay discovery. `--only firm-id` narrows live stages. Existing successful snapshots and HTTP evidence are reused unless `--refresh` is supplied. `--stage validate --verify-hashes` checks schema, coverage, commit links and original hashes offline. The independent validator additionally checks the exact tree partition and Git/LFS object identity.', '',
            '`scripts/collect/github_firms.yaml` contains publisher path rules, legacy account/repository additions, classification overrides and exclusion reasons. Each status has a path-by-path exclusion ledger. `github_discovery.json` records every account-listing page, repository metadata and candidate decisions. Local HTTP evidence and rate logs live in `local-cache/github-cache/`; bare clones are under `local-cache/git/<firm_id>/`.', '',
            'Date hints use report filenames and the first two PDF pages. They are provisional metadata, not confirmed engagement dates. PDF creation timestamps, Git dates and retrieval times are never audit dates. Text extraction errors are recorded per file and do not silently drop originals. No websites are scraped; earlier publisher-listing evidence is cited where available.', '',
            'READ-ONLY REVIEW OK: publisher repositories are retrieved with clean Git configuration and no credentials, hooks, worktree checkout, submodule recursion, LFS filters or project execution. Git smart-HTTP runs through a loopback-only HTTPS relay enforcing robots rules and at most one request per host per second. PDF parsing uses bounded subprocesses. These controls approve data acquisition only, not execution of publisher code. Workflow adapted from [SEAL developer-targeted intrusions guidance](https://frameworks.securityalliance.org/devsecops/developer-targeted-intrusions/overview/).', '']
    write_json(DATA / 'github_summary.json', dict(totals))
    path = ROOT / 'docs/collect/github.md'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('\n'.join(doc))
    outputs = [Path(COLLECTOR), CONFIG.relative_to(ROOT), Path('scripts/collect/test_github_collector.py'),
               Path('scripts/collect/validate_github_collection.py'), path.relative_to(ROOT),
               Path('data/collect/github_summary.json'), Path('data/collect/github_validation.json'),
               Path('data/collect/github_independent_validation.json'), Path('data/collect/github_outputs.txt')]
    for firm in firms:
        folder = DATA / firm['firm_id']
        outputs.extend(p.relative_to(ROOT) for p in folder.glob('github_*.json'))
        outputs.extend((folder / n).relative_to(ROOT) for n in ('reports.jsonl', 'status.json') if (folder / n).exists())
    (DATA / 'github_outputs.txt').write_text('\n'.join(sorted(set(p.as_posix() for p in outputs))) + '\n')
    print(json.dumps(dict(totals), sort_keys=True), flush=True)


def validate(firms, hashes=False):
    errors, checked, verified = [], 0, set()
    for firm in firms:
        fid = firm['firm_id']
        folder = DATA / fid
        if not (folder / 'status.json').exists() or not (folder / 'reports.jsonl').exists():
            errors.append(fid + ': missing manifest/status')
            continue
        s = read_json(folder / 'status.json')
        records = [json.loads(l) for l in (folder / 'reports.jsonl').read_text().splitlines()]
        if settings()['firms'].get(fid, {}).get('collector_delegate'):
            for r in records:
                checked += 1
                local = ROOT/r['local_path']
                if set(r) != set(FIELDS) or not local.is_file():
                    errors.append(fid + ': invalid delegated manifest record')
                elif hashes:
                    body = local.read_bytes()
                    if hashlib.sha256(body).hexdigest() != r['sha256'] or (r['file_format'] == 'pdf' and not body.startswith(b'%PDF')):
                        errors.append(fid + ': delegated original fails SHA/PDF check')
                    verified.add(r['sha256'])
            if len(records) != s['collected']:
                errors.append(fid + ': delegated collected count mismatch')
            continue
        if len(records) != s['collected']:
            errors.append(fid + ': collected count mismatch')
        if s['failed'] or s['report_file_coverage_pct'] is None or s['report_file_coverage_pct'] < 98:
            errors.append(fid + ': acquisition failure or coverage below 98%')
        if not s['discovery_complete'] or s.get('discovery_pending'):
            errors.append(fid + ': discovery incomplete or unreviewed leads')
        if s['tree_files'] != s['skipped_non_report'] + s['listed_count']:
            errors.append(fid + ': tree/exclusion partition mismatch')
        for r in records:
            checked += 1
            if set(r) != set(FIELDS):
                errors.append(fid + ': collection schema differs: ' + r['filename'])
            if not re.fullmatch(r'https://github\.com/[^/]+/[^/]+/blob/[0-9a-f]{40}/.+', r['public_url']):
                errors.append(fid + ': unpinned link: ' + r['public_url'])
            local = ROOT / r['local_path']
            if not local.is_file() or local.stat().st_size != r['bytes'] or local.name.split('.')[0] != r['sha256']:
                errors.append(fid + ': missing/mis-sized original: ' + r['local_path'])
            elif hashes and r['sha256'] not in verified:
                if hashlib.sha256(local.read_bytes()).hexdigest() != r['sha256']:
                    errors.append(fid + ': SHA mismatch: ' + r['local_path'])
                verified.add(r['sha256'])
            if bool(r['date_hint']) != (r['date_precision'] != 'none' and r['date_basis'] != 'none'):
                errors.append(fid + ': inconsistent date hint')
    result = {'firms': len(firms), 'records_checked': checked, 'original_hashes_verified': len(verified), 'errors': errors}
    write_json(DATA / 'github_validation.json', result)
    print(json.dumps(result, indent=2))
    return 1 if errors else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=['all', 'discover', 'inspect', 'search', 'collect', 'summary', 'validate'], default='all')
    parser.add_argument('--only', action='append', default=[])
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--verify-hashes', action='store_true')
    parser.add_argument('--pdf-worker', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.pdf_worker:
        pdf_worker(args.pdf_worker)
        return 0
    firms, config = scope(), settings()
    chosen = [f for f in firms if not args.only or f['firm_id'] in args.only]
    if not chosen:
        parser.error('No scoped firms selected')
    if args.stage in ('all', 'collect', 'inspect', 'summary'):
        # Preserve early review snapshots locally; never publish original text.
        for firm in chosen:
            old_review = DATA / firm['firm_id'] / 'github_repository_review.json'
            if old_review.exists():
                digest = hashlib.sha256(old_review.read_bytes()).hexdigest()[:12]
                destination = CACHE / 'reviews' / (firm['firm_id'] + '.' + digest + '.json')
                destination.parent.mkdir(parents=True, exist_ok=True)
                old_review.replace(destination)
    if args.stage in ('discover', 'all'):
        client = HTTP(args.refresh)
        for firm in chosen:
            discover(firm, config['firms'].get(firm['firm_id'], {}), client)
    if args.stage == 'inspect':
        inspect_sources(chosen, HTTP(args.refresh))
    if args.stage == 'search':
        search_sources(chosen, config, HTTP(args.refresh))
    if args.stage in ('collect', 'all'):
        client = HTTP()
        with Relay(client) as relay:
            for firm in chosen:
                conf = config['firms'].get(firm['firm_id'], {})
                if conf.get('collector_delegate'):
                    subprocess.run([sys.executable, '-I','-B', str(Path(__file__).with_name(conf['collector_delegate']))], check=True)
                    continue
                discovery = read_json(DATA / firm['firm_id'] / 'github_discovery.json', {})
                collect_firm(firm, conf, config['defaults'], discovery, relay, args)
    if args.stage in ('all', 'summary'):
        summary(firms)
    if args.stage == 'validate':
        return validate(chosen, args.verify_hashes)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
