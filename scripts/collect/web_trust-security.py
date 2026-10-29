#!/usr/bin/env python3
"""Measure accessible TrustSec discovery and retain robots-blocked coverage gap."""
import hashlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from web_common import Client, ROOT, atomic_json, now


def main():
    client = Client()
    urls = ['https://trust-security.xyz/', 'https://trustsec.xyz/audits',
            'https://trustsec.xyz/sitemap.xml', 'https://trustsec.xyz/robots.txt',
            'https://api.github.com/repos/Trust1995/Trust',
            'https://api.github.com/users/Trust1995/repos?per_page=100',
            'https://api.github.com/users/TrustSecAudits',
            'https://api.github.com/users/TrustSecAudits/repos?per_page=100']
    evidence, failures = [], []
    for url in urls:
        try:
            response = client.fetch(url, refresh=True)
            entry = dict(url=url, effective_url=response.url, status=response.status,
                         accessed_utc=response.retrieved_utc, sha256=hashlib.sha256(response.body).hexdigest())
            if 'api.github.com/' in url:
                data = json.loads(response.body)
                entry['data'] = ([{k:r.get(k) for k in ('full_name', 'html_url', 'description')} for r in data]
                                 if isinstance(data, list) else {k:data.get(k) for k in ('login', 'name', 'bio', 'blog', 'public_repos')})
            elif url.endswith('/robots.txt'):
                entry['robots_text'] = response.text
            elif url.endswith('/sitemap.xml'):
                entry['urls'] = re.findall(r'<loc>([^<]+)</loc>', response.text)
            evidence.append(entry)
        except Exception as exc:
            failures.append(dict(url=url, error=str(exc)))
    blocked = 'https://trustsec.xyz/api/'
    try:
        # Establish policy only: never send the API request when disallowed.
        client._allowed(blocked)
        policy = 'API path permitted, but no public inventory endpoint established; completeness unresolved.'
    except Exception as exc:
        policy = str(exc)
        failures.append(dict(url=blocked, error=policy))
    out = ROOT/'data/collect/trust-security'
    out.mkdir(parents=True, exist_ok=True)
    if not (out/'reports.jsonl').exists():
        (out/'reports.jsonl').write_text('')
    count = sum(bool(s.strip()) for s in (out/'reports.jsonl').read_text().splitlines())
    atomic_json(out/'discovery_evidence.json', dict(accessed_utc=now(), sources=evidence,
        failures=failures, portfolio_policy=policy, api_requested=False,
        finding='Trust Security is now TrustSec; current identity TrustSecAudits. Public report count unresolved; zero manifest rows is not zero publisher reports.'))
    atomic_json(out/'status.json', dict(firm_id='trust-security', listing_urls=urls,
        listed_count=None, collected=count, failed=len(failures), skipped_non_report=0,
        failures=failures, collected_utc=now(), collector_script='scripts/collect/web_trust-security.py',
        enumeration_complete=False, completeness='blocked', publisher_identity='TrustSec / TrustSecAudits',
        notes='Portfolio is loaded through robots-disallowed /api/. No request made to disallowed route. Accessible site/sitemap and old/current GitHub identities checked; no accessible complete report inventory established.'))


if __name__ == '__main__':
    main()
