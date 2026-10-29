#!/usr/bin/env python3
"""Build an offline website demo with synthetic findings and no private inputs."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from make_fixture import dump
ROOT=Path(__file__).resolve().parents[2]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--out',type=Path,default=ROOT/'site/dev-data')
    out=ap.parse_args().out
    dump(out/'taxonomy.json',dict(version='synthetic',classes=[dict(
        id='reentrancy',name='Reentrancy',definition='Synthetic callback example.',
        leaves=[dict(id='reentrancy.single_function',name='Single-function reentrancy',
                     definition='Synthetic state update after an external call.',
                     examples=[dict(finding_uid='example00001',firm_id='example-1')])])]))
    stats=[p.stem for p in (ROOT/'data/analysis').glob('*.csv')]
    for name in stats: dump(out/'stats'/f'{name}.json',[])
    firms=[];shards=[]
    fields=['id','title','project','year','severity','status','leaf','mode','shard','finding_id']
    for k in range(2):
        fid=f'example-{k+1}';uid=f'example{k+1:05}'
        finding=dict(finding_uid=uid,finding_id='H-01',title='Synthetic state update example',
                     project='Example protocol',firm_id=fid,audit_year=2025,severity='high',status='fixed',
                     vuln_leaf='reentrancy.single_function',review_mode='firm_review',page_start=1,
                     report_id='a'*64,url='https://example.org/synthetic-report',
                     body_text=None if k else 'Synthetic example: the state update follows an external call.',
                     body_text_status='withheld_by_notice' if k else 'present',selected_for_stats=True)
        dump(out/'findings'/fid/'0.json',{'findings':[finding]})
        file=f'index-{fid}.json'
        dump(out/'search'/file,dict(firm_id=fid,fields=fields,dicts=dict(severity=['high'],status=['fixed'],leaf=['reentrancy.single_function'],mode=['firm_review']),projects=['Example protocol'],rows=[[uid,finding['title'],0,2025,0,0,0,0,0,'H-01']]))
        shards.append(dict(file=file,firm_id=fid,count=1))
        firms.append(dict(firm_id=fid,name=f'Example Publisher {k+1}',kind='firm',engagements=1,findings=1,findings_released=1,first_year=2025,last_year=2025,coverage_pct=None))
        dump(out/'engagements'/f'{fid}.json',[])
    dump(out/'firms.json',firms)
    dump(out/'search/manifest.json',dict(version=1,fields=fields,shards=shards))
    dump(out/'summary.json',dict(as_of='2025-01-01',counts=dict(publishers=2,firms=2,engagements=2,industry_engagements=2,findings=2,findings_released=2,findings_selected_for_stats=2,reports=2),quality=[]))
    print('Synthetic site fixture built')
if __name__=='__main__':main()
