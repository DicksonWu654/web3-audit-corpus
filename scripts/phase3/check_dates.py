#!/usr/bin/env python3
"""Validate Phase 3b evidence membership and independent coverage gates."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import duckdb

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/build'))
from metadata_rules import atomic,canonical


def check(root=ROOT,require_coverage=False):
    con=duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True)
    con.execute('SET threads=3')
    counts=Counter();errors=[];texts={}
    def evidence_path(assertion,digest):
        path=root/assertion.get('text_source','local-cache/text')/(digest+'.txt')
        if assertion.get('text_snapshot'):
            expected='local-cache/phase3d/text/'+str(assertion.get('text_sha256'))+'.txt'
            if assertion['text_snapshot']!=expected:
                return None
            path=root/expected
        return path
    rows=con.execute('SELECT dc.claim_id,dc.basis,dc.evidence,dc.eligible_for_audit_year,d.sha256 FROM date_claims dc LEFT JOIN documents d USING(document_id)').fetchall()
    for cid,basis,raw,eligible,digest in rows:
        e=json.loads(raw); a=e.get('assertion') or {}
        if e.get('date_recovery'):
            recovery=e['date_recovery'];proof=recovery['evidence'];source=e['source_record']
            path=(root/source['source_file']).resolve()
            valid=path.is_relative_to(root/'data/phase3/date_recovery/engagement_years')
            if valid:
                line=int(source['source_locator'].removeprefix('line='))
                original=json.loads(path.read_text().split('\n')[line-1])
                payload=json.dumps(original,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
                valid=original==recovery and hashlib.sha256(payload).hexdigest()==source['source_record_sha256']
            if not valid:errors.append('Recovered date differs from reviewed proposal: '+cid)
            if recovery['year_inferred']:
                if recovery['date_value'] is not None or recovery['date_precision']!='year' or not e['year_inferred']:
                    errors.append('Inferred year asserts an exact completion: '+cid)
                counts['labelled_inferred_years']+=1
            else:counts['explicit_recovered_dates']+=1
            if proof['kind']=='report_text':
                path=(root/proof['text_path']).resolve()
                if not path.is_relative_to(root/'local-cache'):
                    errors.append('Recovered evidence outside corpus store: '+cid)
                else:
                    text=path.read_text()
                    if (hashlib.sha256(text.encode()).hexdigest()!=proof['text_sha256']
                            or text[proof['text_start']:proof['text_end']]!=proof['quote']):
                        errors.append('Recovered date text receipt mismatch: '+cid)
                    else:counts['recovered_verbatim_claims_verified']+=1
        if eligible:
            counts['eligible_claims']+=1
            if not basis or not e.get('field'):
                errors.append('Eligible claim lacks basis/source evidence: '+cid)
        if not isinstance(a,dict): continue
        if a.get('text_start') is not None or a.get('method')=='llm':
            folder=a.get('text_source','local-cache/text')
            if folder not in {'local-cache/text','local-cache/fulltext','local-cache/date-text'} or not digest:
                errors.append('Invalid date text source: '+cid);continue
            path=evidence_path(a,digest)
            if path is None:
                errors.append('Invalid pinned text source: '+cid);continue
            key=str(path)
            if key not in texts:
                texts[key]=path.read_text() if path.exists() else ''
            text=texts[key];quote=a.get('evidence');start=a.get('text_start');end=a.get('text_end')
            valid=isinstance(quote,str) and bool(quote.strip()) and quote in text and hashlib.sha256(text.encode()).hexdigest()==a.get('text_sha256')
            if start is not None:
                valid=valid and text[start:end]==quote
            if not valid: errors.append('Date evidence does not match text receipt: '+cid)
            else: counts['verbatim_claims_verified']+=1
            if str(a.get('method','')).startswith('date_evidence_'):
                page=a.get('page')
                raw_value=a.get('raw_value')
                valid_locator=(isinstance(start,int) and isinstance(end,int) and isinstance(page,int)
                               and page==text[:start].count('\f')+1
                               and isinstance(raw_value,str) and raw_value in (quote or ''))
                if not valid_locator:errors.append('Phase 3f date lacks verbatim raw date/page: '+cid)
                else:counts['date_evidence_verbatim_page_claims_verified']+=1
            anchor=a.get('year_anchor')
            if anchor:
                source=anchor.get('text_source','local-cache/text')
                if source not in {'local-cache/text','local-cache/fulltext','local-cache/date-text'}:
                    errors.append('Invalid year anchor source: '+cid)
                else:
                    anchor_path=evidence_path(anchor,digest)
                    if anchor_path is None:
                        errors.append('Invalid pinned year anchor source: '+cid);continue
                    anchor_key=str(anchor_path)
                    if anchor_key not in texts: texts[anchor_key]=anchor_path.read_text() if anchor_path.exists() else ''
                    payload=texts[anchor_key]; quote=anchor.get('evidence')
                    start,end=anchor.get('text_start'),anchor.get('text_end')
                    valid=(isinstance(quote,str) and bool(quote.strip()) and isinstance(start,int) and isinstance(end,int)
                           and payload[start:end]==quote and hashlib.sha256(payload.encode()).hexdigest()==anchor.get('text_sha256')
                           and anchor.get('year_offset',0) in {-1,0}
                           and int(anchor.get('date_value','0000')[:4])+anchor.get('year_offset',0)==int(a.get('date_value','0000')[:4]))
                    if not valid: errors.append('Year anchor does not match source receipt: '+cid)
                    else: counts['verbatim_year_anchors_verified']+=1
            if a.get('method')=='llm':
                counts['llm_claims']+=1
                if a.get('model')!='gpt-6-luna': errors.append('Unsupported model receipt: '+cid)
    all_count,confirmed,known,confirmed_known=con.execute("SELECT count(*),count(*) FILTER(WHERE identity_status='confirmed'),count(audit_year),count(*) FILTER(WHERE identity_status='confirmed' AND audit_year IS NOT NULL) FROM engagements JOIN engagement_years USING(engagement_id)").fetchone()
    coverage=dict(engagements=all_count,confirmed=confirmed,known=known,confirmed_known=confirmed_known,
                  overall_pct=round(100*known/all_count,4),confirmed_pct=round(100*confirmed_known/confirmed,4))
    coverage['target_met']=known/all_count>=.85 and confirmed_known/confirmed>=.95
    if require_coverage and not coverage['target_met']:errors.append('Coverage gate not met')
    con.close()
    result=dict(check='PASS' if not errors else 'FAIL',coverage=coverage,counts=dict(counts),errors=errors)
    atomic(root/'data/phase3/date_check.json',json.dumps(result,indent=2)+'\n')
    print(canonical(result))
    return not errors


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root',type=Path,default=ROOT)
    p.add_argument('--require-coverage',action='store_true')
    a=p.parse_args()
    raise SystemExit(0 if check(a.root,a.require_coverage) else 1)
