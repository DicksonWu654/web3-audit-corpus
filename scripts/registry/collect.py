#!/usr/bin/env python3
"""Read-only, credential-free HTTP/tree collection. Never executes fetched code.

python3 scripts/registry/collect.py --cache local-cache/tmp/firm-registry-cache
python3 scripts/registry/collect.py --only firm-id --refresh
Snapshots contain HTTP observations and tree paths, not report contents.
"""
import argparse
import concurrent.futures
import datetime as dt
import hashlib
import html
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'data/registry'
UTC = dt.timezone.utc


def now():
    return dt.datetime.now(UTC).isoformat(timespec='seconds')


def http(url, cache):
    key = hashlib.sha256(url.encode()).hexdigest()
    body = cache / (key + '.body')
    meta = cache / (key + '.json')
    if meta.exists() and body.exists():
        return json.loads(meta.read_text()), body.read_bytes()
    # -q disables ~/.curlrc; no browser cookies, auth, credential helpers, or JS.
    args = ['curl', '-q', '--silent', '--show-error', '--location',
            '--proto', '=https', '--proto-redir', '=https', '--max-redirs', '6',
            '--connect-timeout', '12', '--max-time', '50', '--max-filesize', '35000000',
            '--user-agent', 'Web3AuditCorpus-registry/1.0', '--output', str(body),
            '--write-out', '%{http_code}\n%{url_effective}\n%{content_type}', url]
    p = subprocess.run(args, capture_output=True, text=True, timeout=60)
    out = p.stdout.split('\n')
    payload = body.read_bytes() if body.exists() else b''
    result = {'url': url, 'status': int(out[0] or 0) if out else 0,
              'final_url': out[1] if len(out) > 1 else url,
              'content_type': out[2] if len(out) > 2 else '', 'checked_utc': now(),
              'sha256': hashlib.sha256(payload).hexdigest(), 'bytes': len(payload)}
    if p.returncode:
        result['error'] = p.stderr.strip()[:300]
    meta.write_text(json.dumps(result))
    return result, payload


def git_tree(repo, cache):
    """Bare filtered retrieval; patched host Git, clean configuration, no checkout."""
    safe = re.fullmatch(r'([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)', repo)
    if not safe:
        raise ValueError('Not a GitHub owner/repository: ' + repo)
    env = {k: v for k, v in os.environ.items()
           if k in ('PATH', 'LANG', 'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'NO_PROXY',
                    'https_proxy', 'http_proxy', 'all_proxy', 'no_proxy', 'SSL_CERT_FILE')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
               GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='/bin/false')
    base = ['git', '-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null',
            '-c', 'init.templateDir=', '-c', 'protocol.file.allow=never',
            '-c', 'protocol.ext.allow=never', '-c', 'http.sslVerify=true']
    target = cache / (repo.replace('/', '__') + '.git')
    if not target.exists():
        p = subprocess.run(base + ['clone', '--bare', '--depth=1', '--filter=blob:none',
                                  '--no-tags', 'https://github.com/' + repo + '.git', str(target)],
                           env=env, capture_output=True, timeout=100)
        if p.returncode:
            return {'error': p.stderr.decode(errors='replace')[-500:]}
    def cmd(args):
        return subprocess.check_output(base + ['--git-dir=' + str(target)] + args,
                                       env=env, timeout=30)
    commit = cmd(['rev-parse', 'HEAD']).decode().strip()
    tree_sha = cmd(['rev-parse', 'HEAD^{tree}']).decode().strip()
    # -z avoids Git's quoting of non-ASCII paths. No blob data is retrieved here.
    paths = []
    for item in cmd(['ls-tree', '-rz', 'HEAD']).split(b'\0'):
        if not item:
            continue
        info, path = item.split(b'\t', 1)
        mode, kind, sha = info.decode().split()
        if kind == 'blob':
            paths.append({'path': path.decode('utf-8', errors='replace'), 'sha': sha})
    return {'repo': repo, 'transport': 'git-bare-filtered-tree', 'status': 200,
            'checked_utc': now(), 'commit': commit, 'sha': tree_sha,
            'truncated': False, 'tree': paths}


def collect_candidate(c, cache):
    result = {'firm_id': c['firm_id'], 'urls': [], 'trees': [], 'readmes': []}
    repos = c.get('repos', [])
    for repo in repos:
        api = 'https://api.github.com/repos/' + repo + '/git/trees/HEAD?recursive=1'
        meta, body = http(api, cache)
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            data = {}
        tree = None
        if meta['status'] == 200 and 'tree' in data and not data.get('truncated'):
            tree = dict(meta, repo=repo, transport='github-api', sha=data['sha'],
                        truncated=False, tree=[{'path': x['path'], 'sha': x['sha']}
                                              for x in data['tree'] if x['type'] == 'blob'])
        else:
            tree = git_tree(repo, cache)
            tree['api_observation'] = meta
        if tree.get('status') == 200:
            result['trees'].append(tree)
            # README is public text, parsed only as data. No project code runs.
            for p in ('README.md', 'readme.md', 'profile/README.md'):
                if any(t['path'] == p for t in tree['tree']):
                    rev = tree.get('commit', 'HEAD')
                    url = 'https://raw.githubusercontent.com/' + repo + '/' + rev + '/' + p
                    m, b = http(url, cache)
                    result['readmes'].append(dict(m, repo=repo, text=b.decode(errors='replace')))
                    break
        else:
            result['trees'].append(dict(tree, repo=repo, checked_utc=now()))
    # Website/report URLs are also checked when a GitHub source works.
    for key in ('github_reports_url', 'website_reports_url', 'other_reports_url'):
        for url in c.get(key, '').split(';'):
            if not url:
                continue
            m, b = http(url, cache)
            item = dict(m, field=key)
            # Retain listing text only for selected counters, never PDFs.
            if c.get('listing_pattern') and key == c.get('listing_field', 'website_reports_url'):
                text = html.unescape(b.decode(errors='replace').replace('\\"', '"').replace('\\/', '/'))
                item['listing_pattern'] = c['listing_pattern']
                item['listing_items'] = sorted(set(re.findall(c['listing_pattern'], text)))
            result['urls'].append(item)
    result['listings'] = []
    for spec in c.get('listings', []):
        m, b = http(spec['url'], cache)
        item = dict(m, spec=spec, items=[])
        if m['status'] == 200:
            s = html.unescape(b.decode(errors='replace').replace('\\"', '"').replace('\\/', '/'))
            if spec.get('pattern'):
                item['items'] = sorted(set(re.findall(spec['pattern'], s)))
            elif spec.get('json_field'):
                records = json.loads(b)
                if spec.get('records_key'):
                    records = records[spec['records_key']]
                selected = [r for r in records if r.get(spec['json_field']) and
                            r.get(spec.get('exclude_field')) not in spec.get('exclude_values', [])]
                item['items'] = sorted(set(r[spec['json_field']] for r in selected))
                item['dates'] = sorted(set(str(r.get(spec.get('date_field'), '')) for r in selected))
                item['input_records'] = len(records)
                item['excluded_records'] = len(records) - len(selected)
            elif spec.get('csv_column'):
                import csv
                import io
                records = csv.DictReader(io.StringIO(s))
                links = set()
                for r in records:
                    for u in re.findall(spec['csv_pattern'], r.get(spec['csv_column'], '')):
                        links.add(u)
                item['items'] = sorted(links)
        result['listings'].append(item)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cache', type=Path, default=Path('local-cache/tmp/firm-registry-cache'))
    p.add_argument('--only', action='append', default=[])
    p.add_argument('--workers', type=int, default=10)
    p.add_argument('--refresh', action='store_true')
    a = p.parse_args()
    a.cache.mkdir(parents=True, exist_ok=True)
    DATA.mkdir(parents=True, exist_ok=True)
    candidates = json.loads((ROOT / 'scripts/registry/candidates.json').read_text())
    target = DATA / 'observations.jsonl'
    existing = {}
    if target.exists():
        for line in target.read_text().splitlines():
            x = json.loads(line)
            existing[x['firm_id']] = x
    selected = [c for c in candidates if (not a.only or c['firm_id'] in a.only)
                and (a.refresh or c['firm_id'] not in existing)]
    # A new cache directory is necessary to refetch already cached URLs.
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as executor:
        futures = {executor.submit(collect_candidate, c, a.cache): c for c in selected}
        for f in concurrent.futures.as_completed(futures):
            c = futures[f]
            try:
                x = f.result()
            except Exception as e:
                x = {'firm_id': c['firm_id'], 'error': str(e), 'urls': [], 'trees': [], 'readmes': []}
            existing[c['firm_id']] = x
            # Atomic snapshot after each completion: interruption can be resumed.
            temp = target.with_suffix('.tmp')
            temp.write_text(''.join(json.dumps(existing[k], ensure_ascii=False, sort_keys=True) + '\n'
                                    for k in sorted(existing)))
            temp.replace(target)
            print(c['firm_id'], 'trees=' + str(sum(t.get('status') == 200 for t in x['trees'])),
                  'http=' + ','.join(str(u['status']) for u in x['urls']), flush=True)


if __name__ == '__main__':
    main()
