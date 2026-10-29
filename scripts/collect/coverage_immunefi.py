#!/usr/bin/env python3
"""Refresh public Immunefi listing evidence without losing enriched manifests.

Only inert public HTML, JSON, Markdown and report bytes are read. No submitted
finding is assumed accepted; submission severity totals remain separate.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import html
import json
from pathlib import Path
import re
import subprocess
import sys
from urllib.parse import quote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from web_common import Client, ROOT, Response, RobotsPolicy, atomic_json, now
from contest_common import flight_objects, objects, iso, github_urls
from contest_immunefi import ALIASES, classify, result_links, summary_document

OUT = ROOT / 'data/collect/immunefi'
EVIDENCE = ROOT / 'docs/coverage/immunefi_evidence.json'


def rows(path):
    return [json.loads(s) for s in path.read_text().splitlines() if s.strip()] if path.exists() else []


def save_rows(path, records):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.jsonl.tmp')
    tmp.write_text(''.join(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n' for r in records))
    tmp.replace(path)


def baseline():
    path = OUT / 'coverage_before.json'
    if not path.exists():
        reports, contests = rows(OUT/'reports.jsonl'), rows(OUT/'contests.jsonl')
        atomic_json(path, dict(status=json.loads((OUT/'status.json').read_text()),
            reports=reports, contests=contests, captured_utc=now()))


def capture(client, url, refresh=False):
    response = client.fetch(url, refresh=refresh)
    return response.text, dict(url=url, effective_url=response.url,
        sha256=hashlib.sha256(response.body).hexdigest(), accessed_utc=response.retrieved_utc)


class ReplayClient(Client):
    """Recompute evidence from SHA-verified public snapshots without any HTTP."""
    def fetch(self,url,refresh=False,data=None):
        key=hashlib.sha256(url.encode()+(b'\nPOST\n'+data if data is not None else b'')).hexdigest()
        mp,bp=self.cache/(key+'.json'),self.cache/(key+'.body')
        if not mp.exists() or not bp.exists():
            raise ValueError('Offline cache miss: '+url)
        meta=json.loads(mp.read_text());body=bp.read_bytes()
        if hashlib.sha256(body).hexdigest()!=meta['sha256']:
            raise ValueError('Offline response digest mismatch: '+url)
        return Response(meta['url'],body,meta['content_type'],200,meta['retrieved_utc'])

    def _allowed(self,url):
        p=urlsplit(url);origin=p.scheme+'://'+p.netloc
        path=self.cache/(hashlib.sha256((origin+'/robots.txt').encode()).hexdigest()+'.robots.json')
        if not path.exists(): raise ValueError('Offline robots cache miss: '+url)
        saved=json.loads(path.read_text())
        if saved['status']==200: policy=RobotsPolicy(saved['body'].splitlines())
        elif 400<=saved['status']<500 and saved['status']!=429: policy=RobotsPolicy([])
        else: raise ValueError('Offline robots unavailable: '+url)
        from web_common import UA
        if not policy.can_fetch(UA,url): raise ValueError('robots.txt disallows: '+url)


class ContestAdapter:
    """Use the shared, wildcard-aware robots policy and host locks everywhere."""
    def __init__(self, client):
        self.client=client

    def get(self, url):
        response=self.client.fetch(url)
        return dict(status=response.status, sha256=hashlib.sha256(response.body).hexdigest(),
                    accessed_at=response.retrieved_utc), response.body

    def allowed(self, url):
        self.client._allowed(url)


def fields_from_html(text):
    fields={}
    decoder=json.JSONDecoder()
    for match in re.finditer(r'self\.__next_f\.push\((\[.*?\])\)</script>', text, re.S):
        for payload in json.loads(match[1]):
            if not isinstance(payload,str): continue
            for field in ('boostedSummaryReport','findingsUrl','boostedIntroFinished'):
                for found in re.finditer('"'+field+r'"\s*:\s*',payload):
                    fields[field]=decoder.raw_decode(payload[found.end():])[0]
    return fields


def enrich(refresh=False,offline=False):
    baseline()
    evidence=json.loads(EVIDENCE.read_text())
    client=ReplayClient() if offline else Client()
    adapter=ContestAdapter(client)
    existing={r['contest_id']:r for r in rows(OUT/'contests.jsonl')}
    reports=rows(OUT/'reports.jsonl')
    by_url={r['public_url']:r for r in reports}
    old_rec=json.loads((OUT/'reconciliation.json').read_text())
    old_summaries={x['contest_id']:x for x in old_rec.get('summary_sources',[])}
    contests, details, failures=[],[],[]
    for slug,o in sorted(evidence['records'].items()):
        fields={}
        c=dict(existing.get(slug,{}))
        fmt=classify(o)
        url='https://immunefi.com'+o['url']
        c.update(contest_id=slug,platform='immunefi',name=o['project'],
            **{'sponsor/project':o['project'].partition(' | ')[2] or o['project']},
            start_utc=iso(o.get('launchDate')),end_utc=iso(o.get('endDate')),format=fmt,
            listing_url=url,finalization_status=o['auditCompetitionStatus'],
            evaluation_end_utc=iso(o.get('evaluationEndDate')),access='invite_only' if fmt=='private' else 'public')
        for key in ('report_url','sha256','findings_high','findings_medium'):
            c.setdefault(key,None)
        try:
            text,src=capture(client,url,refresh)
            fields=fields_from_html(text)
            src.update(contest_id=slug,fields=fields)
            intro_links=fields.get('boostedIntroFinished') or ''
            links=sorted(set(re.findall(r'https://(?:immunefi\.com/blog/|github\.com/)[^\s<>"\\)]+',intro_links)))
            src['public_related_links']=links
            details.append(src)
            summary=fields.get('boostedSummaryReport')
            c['publisher_summary_url']=summary
            if summary and not summary.startswith('https://reports.immunefi.com/'):
                c['report_url']=summary
                held=by_url.get(summary)
                if held and held['doc_kind']!='non_report':
                    c.update(sha256=held['sha256'],final_report_status='summary_pdf_collected')
                else:
                    prior=old_summaries.get(slug,{})
                    download=prior.get('download_url')
                    blocked=None
                    if download:
                        try: client._allowed(download)
                        except Exception as exc: blocked=str(exc)
                    if blocked:
                        info=dict(prior,error=blocked,error_type='robots_disallowed',contest_id=slug)
                        row=None
                    else:
                        row,info=summary_document(adapter,c,summary)
                        info['contest_id']=slug
                    src['summary_evidence']=info
                    if row:
                        if row['public_url'] not in by_url:
                            reports.append(row);by_url[row['public_url']]=row
                        c.update(sha256=row['sha256'],final_report_status='summary_pdf_collected')
                    else:
                        c['final_report_status']='summary_linked_download_failed'
                        failures.append(dict(url=summary,error=info.get('error','Unknown report failure')))
            elif c.get('result_index_url'):
                c.update(report_url=None,final_report_status='results_index_only')
            # Counts in result indexes include submitted/invalid/duplicate reports.
            # Preserve their publisher wording independently from accepted totals.
            intro=fields.get('boostedIntroFinished')
            src['finished_intro_text']=html.unescape(re.sub('<[^>]+>',' ',intro)) if isinstance(intro,str) else intro
        except Exception as exc:
            failures.append(dict(url=url,error=str(exc)))
        # Explicitly join the already-recovered client mirror to its competition.
        if slug=='iop-circuitdao':
            mirror=next((r for r in reports if r['public_url'].startswith('https://github.com/circuitdao/puzzles/blob/')
                and r['filename']=='Immunefi-invite-only-audit.pdf'),None)
            if mirror:
                body=(ROOT/mirror['local_path']).read_bytes()
                if hashlib.sha256(body).hexdigest()!=mirror['sha256']:
                    raise ValueError('Client mirror hash mismatch')
                result=subprocess.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),'--pdf-overview',str(ROOT/mirror['local_path'])],
                    capture_output=True,timeout=30,check=True)
                overview=' '.join(result.stdout.decode().split())
                match=re.search(r'During this event, (\d+) critical, (\d+) high and (\d+) medium reports were found',overview)
                if not match:
                    raise ValueError('CircuitDAO explicit summary overview absent')
                c.update(sha256=mirror['sha256'],report_url=mirror['public_url'],
                    final_report_status='summary_pdf_collected_client_mirror',findings_high=int(match[2]),findings_medium=int(match[3]),
                    findings_count_basis='Official Immunefi summary overview, page 3 of client-hosted original; report totals, not inferred from researcher leaderboard.',
                    findings_counts_evidence=dict(public_url=mirror['public_url'],sha256=mirror['sha256'],page=3))
        c['public_findings_url']=c.get('result_index_url') or fields.get('findingsUrl')
        c['metadata_only']=not bool(c.get('sha256'))
        c['engagement_evidence_url']=c.get('report_url') or c.get('public_findings_url') or url
        c['engagement_evidence_kind']='downloaded_report' if c.get('sha256') else 'publisher_competition_metadata'
        c['eligible_metadata_engagement']=bool(c.get('report_url') or c.get('public_findings_url'))
        c['findings_count_basis']=c.get('findings_count_basis') or 'Accepted findings not explicitly stated on public listing; null is unknown, never zero.'
        contests.append(c)
        print(json.dumps(dict(contest=slug,metadata_only=c['metadata_only'],intro=details[-1].get('finished_intro_text') if details and details[-1]['contest_id']==slug else None)),flush=True)
    # Alternate originals resolve an acquisition gap even when a publisher copy
    # is blocked; keep that denial in the detailed source evidence.
    resolved={c['publisher_summary_url'] for c in contests if c.get('sha256') and c.get('publisher_summary_url')}
    failures=[f for f in failures if f['url'] not in resolved]
    save_rows(OUT/'contests.jsonl',contests)
    save_rows(OUT/'reports.jsonl',reports)
    evidence.update(detail_sources=details,download_failures=failures)
    atomic_json(EVIDENCE,evidence)
    status=json.loads((OUT/'status.json').read_text())
    status.update(listed_count=len(contests),collected=len(reports),failed=len(failures),failures=failures,
        collected_utc=now(),collector_script='scripts/collect/coverage_immunefi.py',
        contests_recorded=len(contests),metadata_only_contests=sum(c['metadata_only'] for c in contests),
        eligible_metadata_engagements=sum(c['eligible_metadata_engagement'] and c['metadata_only'] for c in contests),
        eligible_public_results_contests=sum(c['eligible_metadata_engagement'] for c in contests),
        report_documents=sum(r['doc_kind']!='non_report' for r in reports),
        result_index_documents=sum(r['doc_kind']=='non_report' for r in reports),
        listed_count_basis='Canonical finite competitions on the official listing; collected counts files including non_report submission indexes.')
    atomic_json(OUT/'status.json',status)
    old_rec.update(listed_count=len(contests),collected_contest_count=len(contests),
        contest_count_matches_official_listing=True,downloaded_documents=len(reports),
        collected_final_summaries=sum(bool(c.get('sha256')) for c in contests),
        coverage_audit_evidence=str(EVIDENCE.relative_to(ROOT)),
        coverage_audit_utc=now(),coverage_audit_script='scripts/collect/coverage_immunefi.py')
    old_rec.update(original_files=sorted(r['local_path'] for r in reports),
        downloaded_result_documents=sum(r['doc_kind']=='non_report' for r in reports),
        final_summary_links=sum(bool(c.get('report_url')) for c in contests),
        publisher_summary_field_links=sum(bool(c.get('publisher_summary_url')) for c in contests),
        detail_sources=details,github=evidence.get('archive'),
        per_year_end_utc=dict(sorted(Counter(c['end_utc'][:4] for c in contests).items())),
        formats=dict(sorted(Counter(c['format'] for c in contests).items())),
        finalization_statuses=dict(sorted(Counter(c['finalization_status'] for c in contests).items())))
    old_rec['gaps'].update(contests_without_collected_final_summary=sorted(c['contest_id'] for c in contests if not c.get('sha256')),
        contests_without_accepted_findings_counts=sorted(c['contest_id'] for c in contests if c.get('findings_high') is None or c.get('findings_medium') is None),
        contests_without_linked_final_summary=sorted(c['contest_id'] for c in contests if not c.get('report_url')),
        final_summary_download_failures=[s['summary_evidence'] for s in details if s.get('summary_evidence',{}).get('error') and s['contest_id'] not in {c['contest_id'] for c in contests if c.get('sha256')}])
    atomic_json(OUT/'reconciliation.json',old_rec)
    save_rows(OUT/'metadata_engagements.jsonl',[c for c in contests if c['eligible_metadata_engagement'] and c['metadata_only']])


def verify():
    contests,reports=rows(OUT/'contests.jsonl'),rows(OUT/'reports.jsonl')
    evidence=json.loads(EVIDENCE.read_text())
    status=json.loads((OUT/'status.json').read_text())
    assert {c['contest_id'] for c in contests}==set(evidence['records'])
    assert len(contests)==status['listed_count']==status['contests_recorded']
    assert len(reports)==status['collected']
    for r in reports:
        body=(ROOT/r['local_path']).read_bytes()
        assert len(body)==r['bytes'] and hashlib.sha256(body).hexdigest()==r['sha256']
    held={r['sha256'] for r in reports if r['doc_kind']!='non_report'}
    for c in contests:
        assert c['sha256'] is None or c['sha256'] in held
        assert c['metadata_only']==(not bool(c['sha256']))
        assert c['start_utc']<c['end_utc']
    before=json.loads((OUT/'coverage_before.json').read_text())
    summary=dict(before=dict(status_listed=before['status']['listed_count'],contest_metadata=len(before['contests']),
        report_documents=sum(r['doc_kind']!='non_report' for r in before['reports'])),
        after=dict(status_listed=status['listed_count'],contest_metadata=len(contests),
            report_documents=len(held),contests_with_report=sum(bool(c['sha256']) for c in contests),
            metadata_only=sum(c['metadata_only'] for c in contests),
            eligible_metadata_only=sum(c['eligible_metadata_engagement'] and c['metadata_only'] for c in contests),
            with_public_results=sum(c['eligible_metadata_engagement'] for c in contests),
            without_public_results=[c['contest_id'] for c in contests if not c['eligible_metadata_engagement']],
            with_explicit_high_and_medium=sum(c.get('findings_high') is not None and c.get('findings_medium') is not None for c in contests),
            final_summary_links=sum(bool(c.get('publisher_summary_url')) and not c['publisher_summary_url'].startswith('https://reports.immunefi.com/') for c in contests),
            years=dict(sorted(Counter(c['end_utc'][:4] for c in contests).items()))),verified=True)
    atomic_json(OUT/'coverage_summary.json',summary)
    print(json.dumps(summary,sort_keys=True))


def discover(refresh=False,offline=False):
    baseline()
    client = ReplayClient() if offline else Client()
    text, source = capture(client, 'https://immunefi.com/audit-competition/', refresh)
    records = {o['slug']: o for f in flight_objects(text) for o in objects(f)
               if 'slug' in o and 'endDate' in o and 'auditCompetitionStatus' in o}
    index, index_source = capture(client, 'https://reports.immunefi.com/llms.txt', refresh)
    pages = result_links(index)
    # The organization's public repository inventory is paginated, not searched
    # by code (which would require authentication).
    repos, repo_sources, errors = [], [], []
    for page in range(1, 101):
        url = f'https://api.github.com/users/immunefi-team/repos?per_page=100&page={page}'
        try:
            raw, src = capture(client, url, refresh)
            data = json.loads(raw)
            if not isinstance(data, list):
                raise ValueError('Repository inventory is not a list')
            repos.extend({k: x.get(k) for k in ('full_name','html_url','description','default_branch','pushed_at')} for x in data)
            repo_sources.append(src)
            if len(data) < 100:
                break
        except Exception as exc:
            errors.append(dict(url=url, error=str(exc)))
            break
    evidence = dict(listing_source=source, records=records, result_index_source=index_source,
        result_pages=pages, organization_repositories=repos, repository_sources=repo_sources, errors=errors)
    archive = 'immunefi-team/Past-Audit-Competitions'
    for repo in [archive]:
        try:
            raw, head_source = capture(client, 'https://api.github.com/repos/'+repo+'/commits/HEAD', refresh)
            commit = json.loads(raw)['sha']
            raw, tree_source = capture(client, f'https://api.github.com/repos/{repo}/git/trees/{commit}?recursive=1', refresh)
            tree = json.loads(raw)
            if tree.get('truncated'):
                raise ValueError('Truncated repository tree')
            paths = [r['path'] for r in tree['tree'] if r['type']=='blob']
            evidence['archive'] = dict(repo=repo, commit=commit, head_source=head_source,
                tree_source=tree_source, document_paths=[p for p in paths if p.lower().endswith(('.pdf','.md'))],
                summary_candidates=[p for p in paths if p.lower().endswith('.pdf') or 'summary' in p.lower()],
                top_indexes=[p for p in paths if p.count('/')==1 and p.endswith('/README.md')])
        except Exception as exc:
            errors.append(dict(url='https://github.com/'+repo,error=str(exc)))
    atomic_json(EVIDENCE, evidence)
    print(json.dumps(dict(listed=len(records), result_pages=len(pages), repositories=len(repos),
        archive=evidence.get('archive',{}).get('summary_candidates'), errors=errors)))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--discover', action='store_true')
    parser.add_argument('--refresh', action='store_true')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--enrich', action='store_true')
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--pdf-overview', type=Path, help=argparse.SUPPRESS)
    opts=parser.parse_args()
    if opts.pdf_overview:
        import resource
        resource.setrlimit(resource.RLIMIT_AS,(768*1024*1024,768*1024*1024))
        resource.setrlimit(resource.RLIMIT_CPU,(18,18))
        from pypdf import PdfReader
        print(PdfReader(opts.pdf_overview).pages[2].extract_text()[:30000])
    elif opts.verify: verify()
    elif opts.enrich: enrich(opts.refresh,opts.offline)
    else: discover(opts.refresh,opts.offline)


if __name__=='__main__':
    main()
