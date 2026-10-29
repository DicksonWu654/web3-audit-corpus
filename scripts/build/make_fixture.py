#!/usr/bin/env python3
"""Materialize synthetic JSON fixtures into a separate, empty input root."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0,str(Path(__file__).resolve().parent))
from build_db import ROOT, EXPORTS


def materialize(root):
    root=Path(root).resolve()
    if root.is_relative_to(ROOT) or (root.exists() and any(root.iterdir())):
        raise ValueError('Use an empty directory outside the repository for fixture inputs')
    fixture=json.loads((ROOT/'tests/fixtures/foundation.json').read_text())
    def write(rel,text):
        path=root/rel
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(text)
        return path
    def jsonl(rel,rows):
        return write(rel,''.join(json.dumps(r)+'\n' for r in rows))
    scope=write('registry/scope_tier_a.csv','')
    with scope.open('w',newline='') as f:
        w=csv.writer(f)
        w.writerow(['firm_id','name','scope_group','github_reports_url','website_reports_url'])
        for p,name,group in fixture['publishers']:
            w.writerow([p,name,group,'',''])
    exports={}
    for name,(rel,_) in EXPORTS.items():
        data=fixture['exports'][name]
        for kind in ['reports','findings']:
            jsonl('extracted/'+rel+'/'+kind+'.jsonl',data[kind])
        e=data['expected']
        exports[name]=dict(report_rows_total=e['reports'],primary_reports=e['primary_reports'],finding_rows_total=e['findings'],primary_finding_rows=e['primary_findings'],primary_reports_with_finding_rows=1 if e['primary_findings'] else 0,distinct_primary_sha256=e['hashes'],primary_reports_without_sha256=e['missing_hashes'],severity_proposed_article=e['severity'])
    summary={'synthetic_fixture':'foundation-v1','exports':exports,'totals_selected_exports':{'selected':list(EXPORTS),'primary_report_rows':7,'primary_finding_rows':5}}
    write('docs/inventory/firm_datasets_summary.json',json.dumps(summary))
    files=[]
    for kind,key in [('reports','seed_reports'),('findings','seed_findings')]:
        path=root/'extracted/audit_analysis/parquet'/(kind+'.parquet')
        path.parent.mkdir(parents=True,exist_ok=True)
        # Explicit union of keys avoids dropping optional fields absent in the first row.
        keys=set().union(*(r.keys() for r in fixture[key]))
        rows=[{k:r.get(k) for k in sorted(keys)} for r in fixture[key]]
        pq.write_table(pa.Table.from_pylist(rows),path)
        files.append({'path':'parquet/'+path.name,'rows':len(rows),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    write('docs/inventory/audit_analysis_summary.json',json.dumps({'validation':{'reports':{'rows':3},'findings':{'rows':4}},'industry':{'firms':fixture['seed_expected_firms']},'parquet_files':files}))
    for publisher in ['shieldify','code4rena']:
        jsonl('data/collect/'+publisher+'/reports.jsonl',[r for r in fixture['collection_reports'] if r['firm_id']==publisher])
    jsonl('data/collect/code4rena/contests.jsonl',fixture['contests'])
    # Excluded contract rows must not leak their content into the corpus.
    excluded=dict(fixture['collection_reports'][0],firm_id='certik')
    jsonl('data/collect/certik/reports.jsonl',[excluded])
    return root


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    print(materialize(parser.parse_args().root))
