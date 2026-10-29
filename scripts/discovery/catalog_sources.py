#!/usr/bin/env python3
"""Read the supplied Parquet catalog as data; never import its pipeline.

Requires pyarrow from requirements.txt.
python -I scripts/discovery/catalog_sources.py
"""
from __future__ import annotations
import collections
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import runpy
import pyarrow.parquet as pq

ROOT=Path(__file__).resolve().parents[2]
H=runpy.run_path(str(ROOT/'scripts/discovery/common.py'))

def valid_date(value):
    s=str(value or '')
    if not re.fullmatch(r'20\d{2}(?:-\d{2}(?:-\d{2})?)?',s): return None
    try: dt.date.fromisoformat(s+'-01-01' if len(s)==4 else s+'-01' if len(s)==7 else s)
    except ValueError: return None
    return s

def main():
    path=ROOT/'extracted/audit_analysis/parquet/reports.parquet'
    rows=pq.read_table(path).to_pylist(); out=[]; diagnostics=collections.Counter(); rejected=[]
    for r in rows:
        source=r['source']
        if source not in ('gcf3711/audit-report-archive','shenyimings/FORGE-Artifacts'): continue
        diagnostics[source+':input']+=1
        raw=json.loads(r['raw_record_json'] or '{}')
        if source=='gcf3711/audit-report-archive':
            fid=H['firm_name'](r.get('publisher'))
            if not fid:
                diagnostics[source+':outside_scope']+=1;continue
            publisher_url=raw.get('report_url') or r.get('report_url')
            if not publisher_url or not H['public_url'](publisher_url):
                diagnostics[source+':no_report_url']+=1;continue
            candidate=raw.get('download_url') or publisher_url
            if not H['public_url'](candidate): candidate=publisher_url
            basis={'kind':'catalog_explicit_publisher','value':r['publisher'],
                   'evidence_url':r['source_url'],'listing_url':raw.get('listing_url'),
                   'publisher_report_url':publisher_url}
            d=valid_date(raw.get('date'))
            out.append(dict(candidate_url=candidate,original_publisher_url=publisher_url,firm_id=fid,
                            project_hint=raw.get('project') or r.get('project'),date_hint=d,
                            date_basis='catalog_date' if d else 'none',source='gcf_catalog',
                            source_record_id=r['source_record_id'],attribution_basis=basis,
                            notes='Catalog author label must agree with publisher listing/repository identity before inclusion. Catalog date is an unverified hint; no crawl/commit date inferred.'))
        else:
            # FORGE result JSONs name their input PDFs but do not expose a report
            # URL. raw.url is a CONTRACT repository, never a report reference.
            diagnostics[source+':no_report_reference']+=1
            title=r.get('title') or ''
            for alias,fid in H['aliases']().items():
                if len(alias)>=5 and H['norm'](Path(title).name).startswith(alias):
                    rejected.append({'source':'forge','source_record_id':r['source_record_id'],
                                     'firm_id_hint':fid,'filename':Path(title).name,
                                     'reason':'Input PDF filename only; no public report URL. Contract raw.url intentionally excluded.'})
                    break
    output=H['OUT']/'_sources/catalog_sources.jsonl';H['write_jsonl'](output,out)
    H['write_jsonl'](H['OUT']/'_sources/forge_unresolved.jsonl',rejected)
    H['write_json'](H['OUT']/'_sources/catalog_sources.status.json',{
        'input':str(path.relative_to(ROOT)),'input_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
        'counts':dict(sorted(diagnostics.items())), 'output_rows':len(out),
        'output_by_source':dict(collections.Counter(r['source'] for r in out)),
        'forge_named_but_no_report_url':len(rejected)})
    print(json.dumps({'rows':len(out),'sources':dict(collections.Counter(r['source'] for r in out))}))

if __name__=='__main__':main()
