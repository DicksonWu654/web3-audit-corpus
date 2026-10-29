#!/usr/bin/env python3
"""Capture L2BEAT project config and its referenced audit-dataset independently.

Reuses the reviewed inert-data parser; writes a separate deterministic snapshot
so a protocol API scan cannot replace the L2BEAT source with a partial output.
"""
from pathlib import Path
import collections
import json
import runpy

ROOT=Path(__file__).resolve().parents[2]

def main():
    h=runpy.run_path(str(ROOT/'scripts/discovery/common.py'))
    e=runpy.run_path(str(ROOT/'scripts/discovery/ecosystem_sources.py'))
    rows=[];status=e['discover_l2beat'](h,h['scope'](),rows,set())
    rows.sort(key=lambda r:(r['firm_id'],r['candidate_url']))
    h['write_jsonl'](h['OUT']/'_sources/l2beat_snapshot_sources.jsonl',rows)
    h['write_json'](h['OUT']/'_sources/l2beat_snapshot_sources.status.json',{
        'collector_script':'scripts/discovery/l2beat_snapshot.py','source':'l2beat',
        'source_rows':len(rows),'by_firm':dict(collections.Counter(r['firm_id'] for r in rows)),**status})
    print(json.dumps({'l2beat_rows':len(rows),'dataset_rows':status.get('audit_dataset',{}).get('tier_a_attributed_report_documents')}))

if __name__=='__main__':main()
