#!/usr/bin/env python3
"""Read-only, credential-free measurements; external content is never executed.

Run: python3 -I scripts/aggregators/measure.py repos
     python3 -I scripts/aggregators/measure.py urls
Cached HTTP bodies stay in local-cache/tmp/web3-aggregators-http, outside the release.
Delete nothing: use --refresh to request a new snapshot. Counts are deterministic
for a captured body/repository revision; live reruns can of course change.
"""
import argparse
import collections
import concurrent.futures
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[2]
HERE = pathlib.Path(__file__).resolve().parent
CACHE = pathlib.Path('local-cache/tmp/web3-aggregators-http')
REPOS = [
    'gcf3711/audit-report-archive',
    'shenyimings/FORGE-Artifacts', 'shenyimings/FORGE-Curated',
    'agentlisa/bench', 'SunWeb3Sec/DeFiHackLabs',
    'DefiLlama/DefiLlama-Adapters', 'code-423n4/reports',
    'sherlock-protocol/sherlock-reports',
    'slowmist/Knowledge-Base', 'l2beat/l2beat',
    'spearbit/portfolio', 'crytic/not-so-smart-contracts',
    'trailofbits/publications', '0xNazgul/Blockchain-Security-Audit-List',
    'hats-finance/audits', 'Secure3Audit/Secure3Audit',
    'InPlusLab/DAppSCAN', 'munimtechnologies/audit-contest-ai-rules',
    'smartbugs/smartbugs-curated', 'Code4rena/reports', 'Sec3-Service/reports',
    'ashutoshshah1/all-smartcontract-audit-reports',
    'code-423n4/2023-05-base-findings', 'sherlock-audit/2023-02-gmx-judging',
    'hats-finance/ether-fi-0x36c3b77853dec9c4a237a692623293223d4b9bc4',
    'IlhamQasse/SCAR',
]

def public_error(value):
    """Keep failure evidence without publishing the collector's egress address."""
    return re.sub(r'(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)', '[client IP redacted]', str(value))[:450]

def fetch(url, refresh=False):
    CACHE.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha256(url.encode()).hexdigest()
    body, meta, head = [CACHE / (key + s) for s in ('.body', '.json', '.headers')]
    if body.exists() and meta.exists() and not refresh:
        return json.loads(meta.read_text()), body.read_bytes()
    proc = subprocess.run([
        'curl', '-q', '--silent', '--show-error', '--location', '--max-time', '40',
        '--max-filesize', '64000000', '--proto', '=https', '--proto-redir', '=https',
        '--user-agent', 'web3-audit-corpus-research/1.0',
        '--header', 'Accept: application/json, text/html;q=0.9, */*;q=0.8',
        '--dump-header', str(head), '--output', str(body),
        '--write-out', '%{http_code}\n%{url_effective}', url,
    ], capture_output=True, text=True)
    status = proc.stdout.splitlines()
    headers = head.read_text(errors='replace') if head.exists() else ''
    raw = body.read_bytes() if body.exists() else b''
    info = dict(url=url, accessed_at=dt.datetime.now(dt.timezone.utc).isoformat(),
                status=int(status[0]) if status and status[0].isdigit() else 0,
                effective_url=status[1] if len(status) > 1 else url,
                bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                curl_exit=proc.returncode, error=proc.stderr[:400])
    for field in ('last-modified', 'x-ratelimit-limit', 'x-ratelimit-remaining',
                  'x-ratelimit-reset', 'retry-after', 'content-type', 'link'):
        found = re.findall(r'^' + field + r':\s*(.*?)\r?$', headers, re.M | re.I)
        if found:
            info[field] = found[-1]
    meta.write_text(json.dumps(info, indent=2) + '\n')
    return info, raw

def get_json(url, refresh=False):
    info, raw = fetch(url, refresh)
    try:
        return info, json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return info, None

def repo_measure(repo, refresh=False):
    base = 'https://api.github.com/repos/' + repo
    ci, commit = get_json(base + '/commits/HEAD', refresh)
    result = dict(repo=repo, commit_request=ci)
    if ci['status'] != 200 or not isinstance(commit, dict) or 'sha' not in commit:
        result['unmeasured_reason'] = public_error(commit)
        return result
    sha = commit['sha']
    result.update(commit=sha, commit_date=commit['commit']['committer']['date'],
                  commit_url=commit['html_url'])
    ti, tree = get_json(base + '/git/trees/' + sha + '?recursive=1', refresh)
    result['tree_request'] = ti
    if ti['status'] != 200 or not isinstance(tree, dict) or 'tree' not in tree:
        result['unmeasured_reason'] = public_error(tree)
        return result
    files = [x for x in tree['tree'] if x['type'] == 'blob']
    paths = [x['path'] for x in files]
    result.update(tree_sha=tree['sha'], tree_truncated=tree.get('truncated'),
                  file_count=len(files), extensions=dict(collections.Counter(
                      pathlib.PurePosixPath(p).suffix.lower() or '[none]' for p in paths)),
                  directories=dict(collections.Counter(p.split('/')[0] for p in paths)),
                  path_date_years=dict(sorted(collections.Counter(y for p in paths
                      for y in re.findall(r'(?<!\d)(20(?:1\d|2\d))[-_/]', p)).items())),
                  sample_paths=paths[:15])
    # Summary units, not claims that every file is an independent audit.
    result['pdf_paths_count'] = sum(p.lower().endswith('.pdf') for p in paths)
    result['report_markdown_paths_count'] = sum(
        p.startswith('reports/') and p.lower().endswith('.md') for p in paths)
    result['report_firm_directories'] = sorted(set(p.split('/')[1] for p in paths
        if p.startswith('reports/') and len(p.split('/')) > 2))
    doc_paths = paths
    if tree.get('truncated'):
        # Files sorted after huge subdirectories can be absent from a truncated tree.
        _, root_tree = get_json(base + '/git/trees/' + sha, refresh)
        doc_paths = [x['path'] for x in root_tree.get('tree', []) if x['type']=='blob']
    docs = [p for p in doc_paths if p.lower() in ('readme.md', 'license', 'license.md',
                                                  'license.txt', 'copying')]
    result['documents'] = {}
    for path in docs:
        url = 'https://raw.githubusercontent.com/' + repo + '/' + sha + '/' + path
        di, raw = fetch(url, refresh)
        # Do not publish full third-party documents in our measurement snapshot.
        result['documents'][path] = dict(request=di)
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['repos', 'urls'])
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--repo', action='append')
    args = parser.parse_args()
    if args.mode == 'repos':
        output = HERE / 'repo_measurements.json'
        results = json.loads(output.read_text()) if output.exists() else {}
        # Small pool: finite requests, no authentication, no retry on rate limits.
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            for result in pool.map(lambda r: repo_measure(r, args.refresh), args.repo or REPOS):
                results[result['repo']] = result
                print(result['repo'], result.get('file_count', result.get('unmeasured_reason')),
                      'pdf', result.get('pdf_paths_count'), flush=True)
        output.write_text(json.dumps(results, indent=2, ensure_ascii=False) + '\n')
    else:
        catalog = json.loads((HERE / 'urls.json').read_text())
        output = HERE / 'url_measurements.json'
        results = json.loads(output.read_text()) if output.exists() else {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            jobs = {pool.submit(fetch, url, args.refresh): key for key, url in catalog.items()}
            for future in concurrent.futures.as_completed(jobs):
                key = jobs[future]
                info, raw = future.result()
                # Bodies remain in /tmp; stable selector counts can be derived there.
                results[key] = info
                print(key, info['status'], info['bytes'], flush=True)
        output.write_text(json.dumps(results, indent=2, ensure_ascii=False) + '\n')

if __name__ == '__main__':
    main()
