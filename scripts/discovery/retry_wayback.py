#!/usr/bin/env python3
"""Retry transient CDX listing failures once, then rebuild the same census."""
from pathlib import Path
import hashlib
import json
import runpy

ROOT=Path(__file__).resolve().parents[2]

def main():
    h=runpy.run_path(str(ROOT/'scripts/discovery/common.py'))
    status=json.loads((h['OUT']/'_sources/wayback_sources.status.json').read_text())
    eligible=[a for a in status.get('attempts',[]) if a.get('http_status') in (0,429,500,502,503,504)]
    attempts=[];already=set()
    for a in eligible:
        p=h['CACHE']/(hashlib.sha256(('GET '+a['query_url']).encode()).hexdigest()+'.json')
        if not p.exists():continue
        m=json.loads(p.read_text())
        if m.get('checked_utc','')<=a.get('checked_utc',''):continue
        attempts.append({'firm_id':a['firm_id'],'query_url':a['query_url'],
                         'previous_status':a['http_status'],'status':m['status'],
                         'checked_utc':m['checked_utc'],'error':m.get('error'),'reused_recorded_retry':True})
        already.add(a['query_url'])
    attempts.sort(key=lambda a:a['checked_utc'])
    consecutive=0
    for a in attempts:
        consecutive=0 if a['status']==200 else consecutive+1
    for a in eligible:
        if consecutive>=3:break
        if a['query_url'] in already:continue
        m,d=h['get_json'](a['query_url'],refresh=True,timeout=12,limit=8_000_000)
        attempts.append({'firm_id':a['firm_id'],'query_url':a['query_url'],
                         'previous_status':a['http_status'],'status':m['status'],
                         'checked_utc':m['checked_utc'],'error':m.get('error')})
        print(a['firm_id'],a['http_status'],'->',m['status'],flush=True)
        consecutive=0 if m['status']==200 else consecutive+1
    h['write_json'](h['OUT']/'_sources/wayback_retry.status.json',{
        'collector_script':'scripts/discovery/retry_wayback.py','attempts':attempts,
        'retried':len(attempts),'now_successful':sum(a['status']==200 for a in attempts),
        'remaining_failed':sum(a['status']!=200 for a in attempts),
        'not_retried_after_service_failures':len(eligible)-len(attempts),
        'stopped_after_consecutive_failures':consecutive>=3})
    w=runpy.run_path(str(ROOT/'scripts/discovery/wayback_sources.py'));w['main']()

if __name__=='__main__':main()
