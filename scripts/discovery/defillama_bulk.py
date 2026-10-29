#!/usr/bin/env python3
"""Discover DeFiLlama audit_links from bulk /config metadata, without TVL data.

The documented /protocols response is retained for coverage reconciliation.
The public /config endpoint includes the audit_links omitted by /protocols.
No linked report bodies or third-party code are loaded.
"""
from __future__ import annotations
import collections
import json
from pathlib import Path
import runpy
from urllib.parse import unquote,urlsplit

ROOT=Path(__file__).resolve().parents[2]
H=runpy.run_path(str(ROOT/'scripts/discovery/common.py'))
E=runpy.run_path(str(ROOT/'scripts/discovery/ecosystem_sources.py'))

def main():
    cm,config=H['get_json']('https://api.llama.fi/config',limit=64_000_000)
    lm,listing=H['get_json']('https://api.llama.fi/protocols',limit=64_000_000)
    if cm['status']!=200 or not isinstance(config,dict) or not isinstance(config.get('protocols'),list):
        raise SystemExit('Bulk DeFiLlama config unavailable or schema changed')
    protocols=config['protocols'];rows=[];seen=set();skip=collections.Counter();links=0;firms=H['scope']()
    additional=[p for k,values in config.items() if k!='protocols' and isinstance(values,list)
                for p in values if isinstance(p,dict) and p.get('audit_links')]
    for p in protocols+additional:
        for url in p.get('audit_links') or []:
            links+=1
            if not isinstance(url,str) or not H['public_url'](url):skip['invalid_url']+=1;continue
            if not E['report_specific'](url):skip['not_individual_report_url']+=1;continue
            fid,basis=E['llama_attribution'](url,firms,H['aliases']())
            if not basis or basis['kind']=='named_filename':
                name=unquote(urlsplit(url).path).rstrip('/').rsplit('/',1)[-1]
                hits=H['named_firms'](name)
                fid=next(iter(hits)) if len(hits)==1 else None
                basis={'kind':'named_filename','value':name,'evidence_url':url} if fid else None
            if not fid:skip['unattributed_or_out_of_scope']+=1;continue
            k=(fid,url)
            if k in seen:continue
            seen.add(k);d=E['date_from_url'](url)
            rows.append({'candidate_url':url,'original_publisher_url':None,'firm_id':fid,
                         'project_hint':p.get('name'),'date_hint':d,'date_basis':'filename' if d else 'none',
                         'source':'defillama','source_record_id':str(p.get('id')),
                         'attribution_basis':{**basis,'audit_links_evidence_url':'https://api.llama.fi/config',
                                              'protocol_id':str(p.get('id')),'config_sha256':cm['sha256']},
                         'notes':'Individual report link from full public DeFiLlama bulk config audit_links. Publisher identity or uniquely named author filename supplies attribution; generic audit directories are excluded.'})
    rows.sort(key=lambda r:(r['firm_id'],r['candidate_url']))
    H['write_jsonl'](H['OUT']/'_sources/defillama_bulk_sources.jsonl',rows)
    indexed_ids={str(p.get('id')) for p in protocols};listing_ids={str(p.get('id')) for p in listing} if isinstance(listing,list) else set()
    H['write_json'](H['OUT']/'_sources/defillama_bulk_sources.status.json',{
        'collector_script':'scripts/discovery/defillama_bulk.py','config_url':'https://api.llama.fi/config',
        'checked_utc':cm['checked_utc'],'config_sha256':cm['sha256'],'config_protocols':len(protocols),
        'additional_entities_with_audit_links':len(additional),
        'protocols_with_audit_links':sum(bool(p.get('audit_links')) for p in protocols),'audit_links_examined':links,
        'listing_url':'https://api.llama.fi/protocols','listing_sha256':lm.get('sha256'),
        'listing_protocols':len(listing_ids),'listing_ids_missing_in_config':sorted(listing_ids-indexed_ids),
        'config_ids_not_in_listing':sorted(indexed_ids-listing_ids),'source_rows':len(rows),
        'source_rows_by_firm':dict(collections.Counter(r['firm_id'] for r in rows)),'skipped':dict(skip),
        'coverage':'Complete bulk protocol metadata response; no per-protocol TVL time-series scan required.',
        'limitations':['Links to directories, unscoped publishers and URLs with no named firm evidence are intentionally excluded.']})
    print(json.dumps({'protocols':len(protocols),'links':links,'attributed_report_urls':len(rows),'listing_missing_ids':len(listing_ids-indexed_ids)}))

if __name__=='__main__':main()
