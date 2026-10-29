#!/usr/bin/env python3
"""Validate registry requirements against saved item-level evidence; no network.

python3 -I scripts/registry/validate.py --today
"""
import argparse
import collections
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'data/registry'
FIELDS = ['firm_id','name','aliases','website','kind','github_reports_url','website_reports_url',
          'other_reports_url','formats','est_public_report_count','count_evidence_url','count_method',
          'first_report_year','status','chains_focus','in_existing_corpus','existing_corpus_reports',
          'checked_utc','notes']


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--today',action='store_true',help='Require this UTC date rather than replay date.')
    args=parser.parse_args()
    with (ROOT/'registry/firms.csv').open(newline='') as f:
        reader=csv.DictReader(f)
        assert reader.fieldnames==FIELDS,'CSV schema differs from requested columns'
        rows=list(reader)
    assert len(rows)>=250,'Fewer than the required publishers'
    assert len({r['firm_id'] for r in rows})==len(rows),'Duplicate firm IDs'
    observations={r['firm_id']:r for r in map(json.loads,(DATA/'observations.jsonl').read_text().splitlines())}
    counts={r['firm_id']:r for r in map(json.loads,(DATA/'counts.jsonl').read_text().splitlines())}
    listings={r['firm_id']:r for r in json.loads((DATA/'listings.json').read_text())}
    candidates={r['firm_id']:r for r in json.loads((ROOT/'scripts/registry/candidates.json').read_text())}
    assert set(counts)==set(candidates)=={r['firm_id'] for r in rows}
    date=dt.datetime.now(dt.timezone.utc).date().isoformat() if args.today else max(r['checked_utc'][:10] for r in rows)
    failures=[];verified=0;repo_owners=collections.defaultdict(set)
    for r in rows:
        fid=r['firm_id'];c=candidates[fid];o=observations[fid];count=counts[fid]
        assert re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*',fid),fid+' invalid slug'
        assert r['name'] and r['website'],fid+' missing name/website'
        assert r['kind'] in ['firm','solo','collective','contest_platform','bug_bounty_platform']
        assert r['status'] in ['active','defunct','acquired','unknown']
        assert r['in_existing_corpus'] in ['yes','partial','no']
        assert set(filter(None,r['formats'].split(';')))<=set(['pdf','md','html'])
        assert int(r['existing_corpus_reports'])==count['existing_corpus_rows']
        assert (r['in_existing_corpus']=='no')==(int(r['existing_corpus_reports'])==0)
        assert r['checked_utc'].startswith(date),fid+' timestamp is not the checked date'
        declared={u for k in ['github_reports_url','website_reports_url','other_reports_url']
                  for u in r[k].split(';') if u}
        good=[u for u in o.get('urls',[]) if u['status']==200 and u['checked_utc'].startswith(date)
              and u['url'] in declared]
        good_trees=[t for t in o.get('trees',[]) if t.get('status')==200 and t['checked_utc'].startswith(date)]
        if fid in listings:
            good.extend(m for m in listings[fid]['pages'] if m['status']==200 and m['checked_utc'].startswith(date)
                        and m['url'] in declared)
        if good or good_trees:
            verified+=1
        else:
            assert 'No report URL verified HTTP 200 today' in r['notes'],fid+' lacks evidence or gap explanation'
            failures.append(fid)
        if r['est_public_report_count']:
            assert int(r['est_public_report_count'])==len(count['items'])>0,fid+' count differs from items'
            assert r['count_method']==count['method'] in ['counted_repo_files','counted_listing']
            assert r['count_evidence_url'],fid+' missing count evidence'
            assert len({i['url'] for i in count['items']})==len(count['items']),fid+' repeated report URLs'
            if count['method']=='counted_repo_files':
                assert len({i['sha'] for i in count['items']})==len(count['items']),fid+' repeated blob'
                for item in count['items']:
                    assert not re.search(r'(?:^|/)(?:readme|license|changelog)\.md$',item['path'],re.I)
                    assert not re.search(r'(?:^|/)(?:slides|papers|presentations|templates)/',item['path'],re.I)
                    tree=next(t for t in good_trees if t['repo']==item['repo'])
                    assert any(f['path']==item['path'] and f['sha']==item['sha'] for f in tree['tree'])
                    assert item['tree_sha']==tree['sha'] and not tree.get('truncated')
            else:
                assert fid in listings and len(listings[fid]['items'])==len(count['items'])
        else:
            assert not r['count_method'] and not count['items']
            assert 'blank is not zero' in r['notes']
        for rp in c.get('repos',[]):repo_owners[rp.lower()].add(fid)
    duplicates={rp:sorted(ids) for rp,ids in repo_owners.items() if len(ids)>1}
    assert not duplicates,'Unmerged shared repository publishers: '+str(duplicates)
    ranked=sorted([r for r in rows if r['est_public_report_count']],key=lambda r:(-int(r['est_public_report_count']),r['firm_id']))
    assert len(ranked)>=60
    assert all(r['count_method'] in ['counted_repo_files','counted_listing'] for r in ranked[:60])
    firms=[r for r in ranked if r['kind']=='firm']
    assert len(firms)>=60 and all(r['count_method'] in ['counted_repo_files','counted_listing'] for r in firms[:60])
    note=(ROOT/'docs/research/firm_registry.md').read_text()
    missing_block=note.split('## Highest-yield firms absent from attributable corpus rows')[1].split('## Highest measured counts')[0]
    assert len(re.findall(r'^\| \d+ \|',missing_block,re.M))==40,'Missing-firm ranking is not forty entries'
    expected=sorted([r for r in ranked if r['kind'] in ['firm','collective'] and r['in_existing_corpus']=='no'],
                    key=lambda r:(-int(r['est_public_report_count']),r['firm_id']))[:40]
    for i,r in enumerate(expected,1):assert f'| {i} | {r["name"]} |' in missing_block
    summary=json.loads((DATA/'summary.json').read_text())
    assert summary['rows']==len(rows) and sum(summary['source_coverage'].values())==len(rows)
    assert summary['top60_measured']==60
    attributed=sum(summary['corpus']['attribution_methods'].values())
    assert sum(int(r['existing_corpus_reports']) for r in rows)==attributed
    assert attributed+sum(summary['corpus']['unattributed_by_source'].values())==summary['corpus']['parquet_rows']
    for p,digest in summary['corpus']['seed_sha256'].items():
        assert hashlib.sha256((ROOT/p).read_bytes()).hexdigest()==digest,'Seed changed: '+p
    parquet=ROOT/'extracted/audit_analysis/parquet/reports.parquet'
    assert hashlib.sha256(parquet.read_bytes()).hexdigest()==summary['corpus']['parquet_sha256']
    print(json.dumps({'validated_rows':len(rows),'checked_date':date,'verified_report_sources':verified,
                      'documented_source_gaps':len(failures),'measured_rows':len(ranked),
                      'top60_entities_measured':60,'top60_firms_measured':60,
                      'ranked_absent_firms':len(expected),'corpus_rows_reconciled':summary['corpus']['parquet_rows']},indent=2))


if __name__=='__main__':main()
