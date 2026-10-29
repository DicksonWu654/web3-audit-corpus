"""Recover layout-triggered OCR losses without dropping existing textual risk badges.

Only frozen, non-holdout reports can be rendered. Replacements require a strict
increase in finding-card markers, preservation of original risk labels, and
source-word overlap. Original page/text receipts are retained locally.
"""
import argparse
from collections import Counter
import csv
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import ROOT,digest,holdouts,original_path,read_snapshot,write_json,write_jsonl
from extract import tool,tool_environment
from layout_support import visible,RISK,STATUS
from variants_study import TARGETS,load


def markers(text):
    # OCR may lose the dash, but must retain an actual severity badge line.
    cards=len(re.findall(r'^\s*(?:[—–|7]+\s*)?'+RISK+r'(?:\s*[-–]\s*\d+(?:\.\d+)*)?(?:\s+'+STATUS+r')?\s*$',visible(text),re.M|re.I))
    cards+=len(re.findall(r'^\s*(?:QSP|KS)(?:[-–][A-Za-z0-9]+)*[-–]\d+\b',text,re.M))
    return cards


def acceptable(before,after):
    old=Counter(x.casefold() for x in re.findall(r'\b'+RISK+r'\b',visible(before),re.I))
    new=Counter(x.casefold() for x in re.findall(r'\b'+RISK+r'\b',visible(after),re.I))
    words=set(re.findall(r'\b[A-Za-z]{3,}\b',visible(before).casefold()))
    recovered=set(re.findall(r'\b[A-Za-z]{3,}\b',visible(after).casefold()))
    overlap=len(words&recovered)/len(words) if words else 1
    reasons=[]
    old_status=len(re.findall(r'^\s*(?:[|7—–]+\s*)?'+RISK+r'\s*[-–]\s*\d+(?:\.\d+)*\s+'+STATUS,visible(before),re.M|re.I))
    new_status=len(re.findall(r'^\s*(?:[|7—–]+\s*)?'+RISK+r'\s*[-–]\s*\d+(?:\.\d+)*\s+'+STATUS,visible(after),re.M|re.I))
    if markers(after)<=markers(before) and new_status<=old_status:reasons.append('no_additional_card_or_status_marker')
    if any(new[k]<v for k,v in old.items()):reasons.append('existing_risk_label_lost')
    if overlap<.70:reasons.append('source_word_loss')
    return not reasons,dict(old_markers=markers(before),new_markers=markers(after),word_overlap=round(overlap,4),rejections=reasons)


def ocr_page(image):
    command=[tool('tesseract',ROOT),str(image),'stdout','-l','eng','--psm','3','tsv']
    result=subprocess.run(command,env=tool_environment(ROOT),capture_output=True,timeout=120,check=True)
    words=list(csv.DictReader(io.StringIO(result.stdout.decode()),delimiter='\t',quoting=csv.QUOTE_NONE))
    lines={}
    for word in words:
        if not word.get('text','').strip() or float(word.get('conf',-1))<0:continue
        key=(word['block_num'],word['par_num'],word['line_num'])
        lines.setdefault(key,[]).append(word)
    out=[]
    for row in lines.values():
        previous=None;value=''
        for w in row:
            left=int(w['left']);width=int(w['width'])
            if previous is not None:value+='  ' if left-previous>25 else ' '
            value+=w['text'];previous=left+width
        out.append(value)
    return '\n'.join(out)+'\n'


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mismatches',action='store_true');p.add_argument('--firms',nargs='*',default=list(TARGETS));p.add_argument('--sha');p.add_argument('--page',type=int)
    p.add_argument('--badge-crops',action='store_true');p.add_argument('--render',action='store_true');p.add_argument('--apply',action='store_true');p.add_argument('--max-pages',type=int,default=40)
    a=p.parse_args();blocked=holdouts();docs=read_snapshot();unique={d['row']['sha256']:d for d in docs if d['row']['firm_id'] in a.firms and (not a.sha or d['row']['sha256'].startswith(a.sha))}
    if a.sha and any(s.startswith(a.sha) for s in blocked):raise ValueError('Holdout OCR denied')
    diags={}
    for f in a.firms:
        path=ROOT/'data/findings/validation'/(f+'.jsonl')
        if path.exists():diags.update({d['sha256']:d for d in map(json.loads,path.read_text().splitlines())})
    jobs=[]
    for sha,d in sorted(unique.items()):
        if sha in blocked:raise ValueError('Holdout OCR denied')
        if d['row']['file_format']!='pdf':continue
        try:text,meta=load(d)
        except FileNotFoundError:continue
        diag=diags.get(sha,{})
        if not a.sha and not(diag.get('validation')=='mismatch' or diag.get('unknown_layout') or not diag.get('findings')):continue
        if a.mismatches and diag.get('validation')!='mismatch':continue
        firm=d['row']['firm_id']
        # Zokyo detail area after the legend; numeric-summary pages are excluded.
        if firm=='zokyo':
            from parsers.zokyo import _region,_summary_pages
            from core import Report
            r=Report(text,meta,firm);lo,hi=_region(r);summary=_summary_pages(r)
            pages=[v for v in meta['pages'] if v['end']>lo and v['start']<hi and v['page'] not in summary]
        else:
            pages=[v for v in meta['pages'] if re.search(r'Findings|Severity|Risk|KS-|OS-|QSP-',v['text'],re.I) or (not diag.get('findings') and len(v['text'].strip())<100)]
        for page in pages:
            if a.page and page['page']!=a.page:continue
            jobs.append((d,meta,page))
    results=[];changed={}
    for d,meta,page in jobs[:a.max_pages]:
        sha=d['row']['sha256'];number=page['page']
        if sha in blocked:raise ValueError('Holdout OCR denied')
        row={'sha256':sha,'firm':d['row']['firm_id'],'page':number,'trigger':'layout_summary_or_marker_gap','before_text_sha256':meta['text_sha256']}
        path=original_path(d['row'])
        if digest(path.read_bytes())!=sha:raise ValueError('Original hash mismatch')
        target=ROOT/'local-cache/phase4d/render'/f'{sha}-p{number}.png';target.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run([tool('pdftoppm',ROOT),'-f',str(number),'-l',str(number),'-r','160','-singlefile','-png',str(path),str(target.with_suffix(''))],env=tool_environment(ROOT),capture_output=True,timeout=120,check=True)
        if a.render:print(target);continue
        if a.badge_crops:
            from badge_ocr import recover
            after,badges=recover(path,number,page['text']);row['badge_receipts']=badges
        else:after=ocr_page(target)
        accepted,proof=acceptable(page['text'],after)
        row.update(proof);row['accepted']=accepted;row['applied']=accepted and a.apply
        row['ocr_text_sha256']=digest(after.encode())
        write_json(ROOT/'local-cache/phase4d/ocr'/f'{sha}-p{number}.json',dict(receipt=row,text=after))
        if row['applied']:
            backup=ROOT/'local-cache/phase4d/pre_ocr'/(sha+'.pages.json')
            if not backup.exists():write_json(backup,meta)
            page['text']=after
            meta['issues'].append({'kind':'layout_triggered_ocr','page':number,'receipt':row})
            changed[sha]=meta
        results.append(row);print(json.dumps(row),flush=True)
    for sha,meta in changed.items():
        offset=0
        for page in meta['pages']:
            page.update(start=offset,end=offset+len(page['text']));offset=page['end']+1
        text='\f'.join(p['text'] for p in meta['pages']);meta.update(characters=len(text),text_sha256=digest(text.encode()),method=meta['method']+'+layout-ocr')
        out=ROOT/'local-cache/fulltext'/(sha+'.txt');tmp=out.with_suffix('.txt.tmp');tmp.write_text(text);tmp.replace(out)
        write_json(out.with_suffix('.pages.json'),meta)
    if changed:
        path=ROOT/'data/fulltext/extractions.jsonl';rows=list(map(json.loads,path.read_text().splitlines()))
        for row in rows:
            if row['sha256'] in changed:
                meta=changed[row['sha256']]
                for key in ('characters','text_sha256','method','issues'):row[key]=meta[key]
        write_jsonl(path,rows)
    if not a.render:write_json(ROOT/'data/findings/variants/ocr_last_run.json',{'eligible_pages':len(jobs),'attempted':len(results),'applied_pages':sum(r['applied'] for r in results),'results':results})

if __name__=='__main__':main()
