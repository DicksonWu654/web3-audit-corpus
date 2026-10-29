#!/usr/bin/env python3
"""Explain Phase 3 integrity failures without changing source or gold data."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

import duckdb

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/build'))
from build_db import publisher_severity_mapping


def inspect(db):
    held=set((ROOT/'data/holdout/gold_sha256.txt').read_text().split())
    fields=Counter(); firms=Counter(); families=Counter(); examples=[]
    with duckdb.connect(str(db),read_only=True) as con:
        for fid,firm,raw,normalized,kind,original,actual,mapping,family in con.execute('SELECT f.finding_id,f.publisher_id,f.severity_raw,f.severity_source_normalized,f.record_kind,d.sha256,f.severity,f.severity_mapping,f.source_family FROM findings f LEFT JOIN documents d USING(document_id)').fetchall():
            expected=publisher_severity_mapping(raw if raw is not None else normalized,firm,kind=kind,sha256=original,log=False)
            receipt=json.loads(mapping)
            diff={k:[receipt.get(k),v] for k,v in expected.items() if k!='raw' and receipt.get(k)!=v}
            if actual!=expected['normalized']: diff['severity']=[actual,expected['normalized']]
            if diff:
                fields.update(diff.keys()); firms[firm]+=1; families[family]+=1
                if original not in held and len(examples)<4: examples.append(dict(firm=firm,source_family=family,raw=raw,diff=diff))
        contests=[]
        for cid,cp,dp,fmt,name,filename,provenance,metadata in con.execute('SELECT c.contest_id,c.publisher_id,d.publisher_id,c.format,c.name,d.filename,d.provenance,d.metadata FROM contests c JOIN documents d USING(document_id) WHERE c.publisher_id<>d.publisher_id').fetchall():
            meta=json.loads(metadata); prov=json.loads(provenance)
            contests.append(dict(contest=cid,platform=cp,author=dp,format=fmt,name=name,filename=filename,collected_publisher=prov.get('phase3c_collected_publisher_id'),attribution=meta.get('auditor_attribution')))
    return dict(severity_diff_fields=dict(fields),severity_firms=dict(firms),severity_families=dict(families),examples=examples,contest_author_links=contests)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--db',type=Path,default=ROOT/'data/corpus.duckdb')
    args=p.parse_args(); print(json.dumps(inspect(args.db),indent=2))
