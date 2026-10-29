#!/usr/bin/env python3
"""Independent offline checks of Phase 2d output, counts and firm evidence."""
from __future__ import annotations
import collections
import csv
import datetime as dt
import hashlib
import json
from pathlib import Path
import re
import runpy
from urllib.parse import unquote,urlsplit

ROOT=Path(__file__).resolve().parents[2]
H=runpy.run_path(str(ROOT/'scripts/discovery/common.py'))
REQUIRED={'candidate_url','original_publisher_url','firm_id','project_hint','date_hint',
          'date_basis','source','still_live','wayback_url','sha256','notes'}

def main():
    scoped=H['scope']();aliases=H['aliases']();out=H['OUT'];errors=[];counts=collections.Counter();sources=collections.Counter();perfirm={};seen=set()
    filename_cases={'security-audit.pdf':set(),'securityAudit.pdf':set(),'preliminary-audit.pdf':set(),
                    'RiveraMoney_Audit_Report.pdf':set(),'VMEX_yAudit_Reports.pdf':{'electisec'},
                    'PeckShieldAuditReport-Test.pdf':{'peckshield'},'0xmacro-boring-vault.pdf':{'macro'},
                    'Trail_of_Bits_Assessment.pdf':{'trail-of-bits'}}
    for filename,expected in filename_cases.items():
        if H['named_firms'](filename)!=expected:errors.append('filename attribution regression: '+filename)
    for fid in scoped:
        p=out/fid/'candidates.jsonl';sp=out/fid/'status.json'
        if not p.exists():errors.append(f'{fid}: candidates file missing');continue
        if not sp.exists():errors.append(f'{fid}: status missing');continue
        rows=[json.loads(l) for l in p.read_text().splitlines() if l.strip()];status=json.loads(sp.read_text());perfirm[fid]=len(rows)
        if status.get('candidate_count')!=len(rows):errors.append(f'{fid}: status candidate count differs')
        if not rows and not status.get('empty_reason'):errors.append(f'{fid}: empty file without reason')
        for i,r in enumerate(rows,1):
            prefix=f'{fid}:{i}'
            if REQUIRED-set(r):errors.append(prefix+': missing '+','.join(sorted(REQUIRED-set(r))))
            if r['firm_id']!=fid:errors.append(prefix+': wrong firm folder')
            if not H['public_url'](r['candidate_url']):errors.append(prefix+': invalid public candidate URL')
            pair=(fid,r['candidate_url'])
            if pair in seen:errors.append(prefix+': duplicate URL')
            seen.add(pair)
            if 'certik'==r.get('firm_id'):errors.append(prefix+': excluded firm')
            b=r.get('attribution_basis',{})
            if not (b.get('verified') is True and b.get('evidence_url') and b.get('verified_against')):errors.append(prefix+': unverified firm attribution')
            if b.get('kind') in ('explicit_publisher_directory','named_author_directory','explicit_auditor_field','catalog_explicit_publisher'):
                if aliases.get(H['norm'](b.get('value')))!=fid:errors.append(prefix+': author label mismatch')
            if b.get('kind') in ('explicit_publisher_directory','named_author_directory'):
                path=unquote(urlsplit(r['candidate_url']).path)
                label=b.get('value') or ''
                if label not in path:errors.append(prefix+': directory author absent from candidate path')
            if b.get('kind') in ('named_filename','filename_publisher') and H['named_firms'](b.get('value'))!={fid}:
                errors.append(prefix+': filename does not contain a distinct scoped author token')
            d=r.get('date_hint')
            if d:
                if not re.fullmatch(r'20\d{2}(?:-\d{2}(?:-\d{2})?)?',d):errors.append(prefix+': invalid date precision')
                else:
                    try:dt.date.fromisoformat(d+'-01-01' if len(d)==4 else d+'-01' if len(d)==7 else d)
                    except ValueError:errors.append(prefix+': invalid calendar date')
            if r['still_live'] not in (None,True,False):errors.append(prefix+': invalid still_live value')
            check=r.get('head_check')
            if check:
                counts['head_attempted']+=1
                if check.get('method')!='HEAD' or check.get('url')!=r['candidate_url']:errors.append(prefix+': HEAD evidence mismatch')
                code=check['status'];expected=True if 200<=code<300 else False if code in (404,410) else None
                if expected is not r['still_live']:errors.append(prefix+': liveness inconsistent with HTTP status')
            else:counts['head_unattempted']+=1
            counts['live' if r['still_live'] is True else 'dead' if r['still_live'] is False else 'unknown']+=1
            if r.get('archive_status')=='dead_but_archived':
                counts['dead_but_archived']+=1
                if r['still_live'] is not False or not r.get('wayback_url') or not r.get('wayback_check',{}).get('capture_timestamp'):
                    errors.append(prefix+': unsupported dead/archive claim')
            if r.get('sha256'):
                p=ROOT/r.get('local_path','')
                if not str(p).startswith(str(ROOT/'local-cache/originals')+'/') or not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=r['sha256']:
                    errors.append(prefix+': original SHA not evidenced by local cached original')
            if Path(unquote(urlsplit(r['candidate_url']).path)).name.lower() in ('readme.md','license','license.md','package.json'):
                errors.append(prefix+': non-report file')
            counts['candidates']+=1;sources.update(r.get('sources',[r['source']]))
            if r.get('missing_status')=='likely_missing':counts['likely_missing']+=1
    summary=json.loads((out/'summary.json').read_text())
    for k,v in summary['totals'].items():
        if counts[k]!=v:errors.append('summary count mismatch: '+k)
    if dict(sources)!=summary['by_source']:errors.append('summary sources mismatch')
    if set(perfirm)!=set(scoped):errors.append('publisher coverage mismatch')
    if counts['head_unattempted']:errors.append('candidate HEAD checks remain unattempted')
    result={'passed':not errors,'firms_checked':len(perfirm),'filename_regression_cases':len(filename_cases),
            'totals':dict(counts),'by_source':dict(sources),'errors':errors}
    H['write_json'](out/'validation.json',result)
    files=sorted(str(p.relative_to(ROOT)) for folder in [ROOT/'scripts/discovery',out] for p in folder.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    files+=['docs/collect/discovery.md','data/discovery/files_written.json']
    H['write_json'](out/'files_written.json',{'repository_files':sorted(set(files)),
        'ignored_local_cache':'local-cache/discovery-cache/ (HTTP response bodies and request metadata; not report originals)'})
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if not errors else 1)

if __name__=='__main__':main()
