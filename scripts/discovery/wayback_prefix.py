#!/usr/bin/env python3
"""Query historical descendants of publisher website report listings.

Complements the exact-listing capture census, which alone cannot discover
individual report pages. CDX timestamps are never used as report dates.
"""
from __future__ import annotations
import json
from pathlib import Path
import runpy
import re
from urllib.parse import urlencode,urlsplit

ROOT=Path(__file__).resolve().parents[2]
H=runpy.run_path(str(ROOT/'scripts/discovery/common.py'))
W=runpy.run_path(str(ROOT/'scripts/discovery/wayback_sources.py'))

def main():
    rows=[];attempts=[];scope=H['scope']()
    for fid,s in scope.items():
        url=s.get('website_reports_url','')
        if not url or urlsplit(url).hostname=='github.com':continue
        url=W['normalize_url'](url)
        query=W['CDX']+'?'+urlencode({'url':url,'matchType':'prefix','output':'json',
              'fl':'original,timestamp,statuscode,mimetype,digest','filter':'statuscode:200','collapse':'urlkey','limit':'2000'})
        m,d=H['get_json'](query,timeout=12,limit=8_000_000)
        captures,error=W['parse_cdx'](d);kept=0
        for cap in captures:
            original=W['normalize_url'](cap.get('original',''));path=urlsplit(original).path.lower()
            if not (path.endswith('.pdf') or re.search(r'/(?:audits?|security-audit|security-reviews?|reports?)/[^/]+/?$',path)):
                continue
            ts=cap.get('timestamp','')
            if not re.fullmatch(r'\d{14}',ts):continue
            dh,_=W['date_from_filename'](original)
            rows.append({'candidate_url':original,'original_publisher_url':original,'firm_id':fid,
                         'project_hint':W['slug_from_url'](original),'date_hint':dh or None,
                         'date_basis':'filename' if dh else 'none','source':'wayback',
                         'source_record_id':original,'wayback_url':'https://web.archive.org/web/'+ts+'/'+original,
                         'attribution_basis':{'kind':'publisher_listing_path','value':url,'evidence_url':query},
                         'notes':'Archived report-like descendant of the publisher report listing; CDX status-200 capture. HTML content has not been classified; candidate remains a discovery lead.'})
            kept+=1
        attempts.append({'firm_id':fid,'query_url':query,'status':m['status'],'checked_utc':m['checked_utc'],
                         'returned_rows':len(captures),'candidate_rows':kept,'truncated':len(captures)>=2000,
                         'error':m.get('error') or (error if m['status']==200 else 'CDX HTTP '+str(m['status']))})
        print(fid,m['status'],len(captures),kept,flush=True)
    H['write_jsonl'](H['OUT']/'_sources/wayback_prefix_sources.jsonl',sorted(rows,key=lambda r:(r['firm_id'],r['candidate_url'])))
    H['write_json'](H['OUT']/'_sources/wayback_prefix_sources.status.json',{
        'collector_script':'scripts/discovery/wayback_prefix.py','queried_firms':len(attempts),'candidate_rows':len(rows),
        'failed_queries':sum(a['status']!=200 or bool(a['error']) for a in attempts),
        'truncated_queries':sum(a['truncated'] for a in attempts),'attempts':attempts,
        'limitations':['One bounded CDX prefix response per website report listing; saturation is reported explicitly.',
                       'CDX service errors remain unobserved history, not evidence of absence.']})

if __name__=='__main__':main()
