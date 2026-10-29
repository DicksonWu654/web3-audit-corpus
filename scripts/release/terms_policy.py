"""Offline report-level publisher-terms policy, from the reviewed coverage audit.

Inputs are data, never executable configuration. Re-sourcing requires verified
byte or full-text equivalence from a publisher-owned or audited open-licence
pinned public GitHub copy.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

csv.field_size_limit(2**31 - 1)
OWNERS = {
    'code4rena': {'code-423n4', 'code4rena'},
    'chainsecurity': {'chainsecurity'},
    'dedaub': {'dedaub'},
    'immunefi': {'immunefi-team', 'immunefi'},
    'kudelski-security': {'kudelskisecurity'},
    'quantstamp': {'quantstamp'},
    'veridise': {'veridise'},
}


def read_rows(path):
    if not path.exists():
        return []
    with path.open(newline='') as stream:
        return list(csv.DictReader(stream))


def host(url):
    return (urlsplit(url or '').hostname or '').lower()


def own_github(fid, url):
    p = urlsplit(url or '')
    parts = p.path.strip('/').split('/')
    return (p.hostname == 'github.com' and len(parts) >= 5 and
            parts[0].lower() in OWNERS.get(fid, set()) and parts[2] == 'blob' and
            re.fullmatch(r'[0-9a-f]{40}', parts[3]) is not None)


class Policy:
    def __init__(self, root):
        self.root = Path(root)
        self.audit = {r['firm_id']: r for r in read_rows(self.root / 'data/coverage/terms_audit.csv')}
        if not self.audit:
            raise ValueError('Publisher terms audit is required before release')
        self.affected = set()
        self.hosts = defaultdict(set)
        self.denied = defaultdict(set)
        self.alternatives = defaultdict(list)
        self.licensed = defaultdict(set)
        for fid, row in self.audit.items():
            for repo in json.loads(row.get('repositories') or '[]'):
                if repo.get('license') in {'MIT', 'Apache-2.0', 'GPL-3.0', 'GPL-2.0', 'CC-BY-4.0', 'CC-BY-SA-4.0'}:
                    self.licensed[fid].add(repo['repo'].lower())
            self.affected.update((fid, rid) for rid in json.loads(row['affected_report_ids']))
            for h in json.loads(row['hosts']):
                if (h.get('terms') or {}).get('basis') == 'C':
                    self.hosts[fid].add(h['host'])
                for item in (h.get('robots_now') or {}).get('disallowed', []):
                    value = item if isinstance(item, str) else item.get('url') or item.get('path')
                    if value:
                        self.denied[fid].add(value)
            for item in json.loads(row['resourcing_same_sha_copies']):
                for copy in item['copies']:
                    self.alternatives[fid, item['sha256']].append(copy['url'])
        self.manifests = defaultdict(list)
        for fid in self.audit:
            path = self.root / 'data/collect' / fid / 'reports.jsonl'
            if path.exists():
                for line in path.read_text().splitlines():
                    if line.strip():
                        row = json.loads(line)
                        if row.get('sha256'):
                            self.manifests[fid, row['sha256']].append(row)
        self._verified = {}
        if 'hacken' in self.audit:
            self.hosts['hacken'].update({'hacken.io', 'www.hacken.io'})
        equivalence_path = self.root / 'data/coverage/gapfill_v120_equivalence.json'
        self.equivalences = {(r['publisher_id'], r['existing_sha256']): r
                            for r in json.loads(equivalence_path.read_text())
                            if r.get('verified_whitespace_normalized_text_equal')} if equivalence_path.exists() else {}

    def permitted_github(self, fid, url):
        parts = urlsplit(url or '').path.strip('/').split('/')
        pinned = urlsplit(url or '').hostname == 'github.com' and len(parts) >= 5 and parts[2] == 'blob' and re.fullmatch(r'[0-9a-f]{40}', parts[3])
        return bool(pinned and (own_github(fid, url) or '/'.join(parts[:2]).lower() in self.licensed[fid]))

    def cached_original(self, sha):
        return next((p for p in (self.root / 'local-cache/originals' / sha[:2]).glob(sha + '.*')
                     if self.cached_file(p) and hashlib.sha256(p.read_bytes()).hexdigest() == sha), None)

    def cached_file(self, path):
        return (path.is_file() and not path.is_symlink() and
                path.resolve().is_relative_to((self.root / 'local-cache').resolve()))

    def restricted_url(self, fid, url):
        source_host = host(url)
        path = urlsplit(url or '').path.rstrip('/')
        # The reviewed audit classifies GitHub API/raw collection as A. Tree
        # citations are not evidence that a robots-denied HTML page was fetched.
        if source_host in {'github.com', 'api.github.com', 'raw.githubusercontent.com'}:
            return False
        if fid == 'hacken' and source_host in {'hacken.io', 'www.hacken.io'} and (path == '/api/audits' or path.startswith('/api/audits/')):
            return False
        return (host(url) in self.hosts[fid] or url in self.denied[fid] or
                urlsplit(url or '').path in self.denied[fid])

    def replacement(self, fid, sha):
        key = fid, sha
        if key in self._verified:
            return self._verified[key]
        candidates = set(self.alternatives[key])
        candidates.update(r.get('public_url') for r in self.manifests[key] if r.get('public_url'))
        result = None
        for url in sorted(candidates):
            if not self.permitted_github(fid, url):
                continue
            # A manifest records the independently fetched GitHub copy and digest;
            # checking cached bytes prevents treating an unverified URL as equivalence.
            receipts = [r for r in self.manifests[key] if r.get('public_url') == url]
            paths = [self.root / r['local_path'] for r in receipts if r.get('local_path')]
            paths += list((self.root / 'local-cache/originals' / sha[:2]).glob(sha + '.*'))
            if not receipts:
                continue
            for path in paths:
                if self.cached_file(path) and hashlib.sha256(path.read_bytes()).hexdigest() == sha:
                    result = dict(firm_id=fid, report_id=sha, sha256=sha, public_url=url,
                                  source_sha256=sha, equivalence='sha256_equal',
                                  source='publisher_public_github' if own_github(fid, url) else 'audited_open_license_github')
                    break
            if result:
                break
        equivalent = self.equivalences.get(key)
        if not result and equivalent:
            other = equivalent['sha256']
            old_text = self.root / 'local-cache/fulltext' / (sha + '.txt')
            new_text = self.root / 'local-cache/fulltext' / (other + '.txt')
            if self.cached_original(sha) and self.cached_original(other) and self.cached_file(old_text) and self.cached_file(new_text):
                a, b = old_text.read_bytes(), new_text.read_bytes()
                if (hashlib.sha256(a).hexdigest() == equivalent['existing_text_sha256'] and
                    hashlib.sha256(b).hexdigest() == equivalent['text_sha256'] and
                    re.sub(r'\s+', '', a.decode('utf-8')) == re.sub(r'\s+', '', b.decode('utf-8'))):
                    for receipt in self.manifests[fid, other]:
                        url = receipt.get('public_url')
                        if self.permitted_github(fid, url):
                            result = dict(firm_id=fid, report_id=sha, sha256=sha, source_sha256=other,
                                          public_url=url, equivalence='whitespace_normalized_text_equal',
                                          source='audited_open_license_github')
                            break
        self._verified[key] = result
        return result

    def restricted(self, fid, rid, urls=()):
        affected = (fid, rid) in self.affected or any(self.restricted_url(fid, u) for u in urls)
        for row in self.manifests[fid, rid]:
            affected |= any(self.restricted_url(fid, row.get(k)) for k in ('public_url', 'listing_url'))
        return bool(affected and not self.replacement(fid, rid))

    def report_restricted(self, report):
        return self.restricted(report['firm_id'], report['report_id'],
                               (report.get('url'), report.get('permalink')))


def apply(policy, reports, engagements, findings):
    """Keep counts and metadata, omit every restricted per-finding occurrence."""
    restricted = set()
    replacements = []
    for report in reports:
        fid, rid = report['firm_id'], report['report_id']
        blocked = policy.report_restricted(report)
        report.update(text_withheld='publisher_terms' if blocked else None,
                      body_text_status='publisher_terms' if blocked else 'not_restricted_by_terms_audit',
                      text_source_sha256=rid, text_source_equivalence=None)
        if blocked:
            restricted.add(rid)
        else:
            receipt = policy.replacement(fid, rid)
            if receipt and ((fid, rid) in policy.affected or policy.restricted_url(fid, report.get('url'))):
                report.update(url=receipt['public_url'], permalink=receipt['public_url'],
                              url_basis='terms_resourced_sha256' if receipt['equivalence'] == 'sha256_equal' else 'terms_resourced_content_equal',
                              source_kind='github', text_source_sha256=receipt['source_sha256'],
                              text_source_equivalence=receipt['equivalence'])
                replacements.append(receipt)
    withheld = [r for r in findings if r['report_id'] in restricted]
    visible = [r for r in findings if r['report_id'] not in restricted]
    by_eng = defaultdict(list)
    for row in withheld:
        by_eng[row['engagement_id']].append(row)
    visible_eng = Counter(r['engagement_id'] for r in visible)
    counts = defaultdict(Counter)
    for row in withheld:
        c = counts[row['firm_id']]
        c['finding_records_withheld'] += 1
        c['finding_bodies_withheld'] += bool(row.get('body_text'))
        c['initial_findings_withheld'] += bool(row['selected_for_stats'])
    for report in reports:
        if report['report_id'] in restricted:
            counts[report['firm_id']]['reports'] += 1
    for e in engagements:
        rows = by_eng[e['engagement_id']]
        selected = [r for r in rows if r['selected_for_stats']]
        e.update(findings_released=visible_eng[e['engagement_id']],
                 findings_withheld=len(rows), initial_findings_withheld=len(selected),
                 text_withheld='publisher_terms' if any(rid in restricted for rid in e['report_ids']) else None,
                 body_text_status='publisher_terms' if any(rid in restricted for rid in e['report_ids']) else 'not_restricted_by_terms_audit')
        if e['text_withheld']:
            counts[e['firm_id']]['engagements'] += 1
    return visible, [dict(firm_id=fid, **dict(c)) for fid, c in sorted(counts.items())], replacements
