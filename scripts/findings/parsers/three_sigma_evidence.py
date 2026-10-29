"""Reproducible development sample review and local parser evaluation (holdouts guarded)."""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, digest, holdouts, read_snapshot
from core import Report, finish, severity
from summary_counts import printed_counts
from importlib import import_module

SAMPLES = {
    'three-sigma': [5,6,7,9,12,14,16,21,29,36,43,55,66,80,96],
    'coinspect': [0,1,2,3,4,5,7,9,12,17,20,24,28,30,33,38],
    'sec3': [0,1,4,6,8,10,13,14,15,16,17,19,22,25,27,28,30,32,34],
}

def documents(firm):
    blocked=holdouts(ROOT)
    docs={d['row']['sha256']:d for d in read_snapshot(ROOT) if d['row']['firm_id']==firm}
    return [d for d in sorted(docs.values(),key=lambda d:(d['row'].get('date_hint') or '',d['row']['filename'])) if d['row']['sha256'] not in blocked]

def load(d):
    sha=d['row']['sha256']
    if sha in holdouts(ROOT):
        raise ValueError('Holdout denied')
    text=(ROOT/'local-cache/fulltext'/(sha+'.txt')).read_bytes().decode('utf-8')
    meta=json.loads((ROOT/'local-cache/fulltext'/(sha+'.pages.json')).read_text())
    if digest(text.encode('utf-8'))!=meta['text_sha256']:
        raise ValueError('Fulltext hash mismatch')
    return Report(text,meta,d['row']['firm_id'])

def printed_index(report):
    """Independent TOC/overview evidence, without using the detailed parser's IDs."""
    if report.firm=='sec3':
        from parsers.sec3 import overview
        rows=overview(report)
        zero=not rows and bool(re.search(r'(?:No\s+issues?\s+(?:were\s+)?found|revealed\s+0\s+issues)',report.text,re.I))
        return rows,zero
    if report.firm=='coinspect':
        heading=re.compile(r'^(?:\d+\.\s*)?(?:Detailed\s+)?Findings$',re.I)
        starts=[l.start for l in report.lines if heading.fullmatch(l.content)]
        if not starts:return [],False
        boundary=max(starts)
        pattern=re.compile(r'^\s*([A-Z][A-Z0-9]*(?:-[A-Z][A-Z0-9]*)*-\d{1,3})(?:\s|$)')
        rows=[];seen=set()
        for line in report.lines:
            if line.start>=boundary:break
            m=pattern.match(line.text.replace('\u200b',''))
            if m and m[1] not in seen and (re.match(r'^\s*[-–—]',line.text[m.end(1):].replace('\u200b','')) or re.search(r'\s{2,}(?:Critical|High|Medium|Low|Info(?:rmational)?|None|Zero|Solved|Fixed|Won.t fix)\b',line.text[m.end(1):],re.I)):
                rows.append({'id':m[1],'page':line.page,'start':line.start,'end':line.end,'text':line.text});seen.add(m[1])
        return rows,False
    pattern=re.compile(r'^\s*(3S[- ].*?-[A-Z0-9]+)[.\s\u200b]+\d+\s*$')
    rows=[]
    for line in report.lines:
        if line.page>7:break
        m=pattern.match(line.text)
        if m:rows.append({'id':m[1],'page':line.page,'start':line.start,'end':line.end,'text':line.text})
    return rows,False


def inspect(firm):
    docs=documents(firm)
    mod=import_module('parsers.'+firm.replace('-','_'))
    for index in SAMPLES[firm]:
        d=docs[index];r=load(d);cards=finish(r,mod.parse(r))
        print('\nSAMPLE',index,d['row']['sha256'],d['row']['filename'])
        print('SUMMARY',json.dumps(getattr(mod,'printed_counts',printed_counts)(r)))
        # Review the title/metadata and body boundaries across the full document.
        for c in cards:
            print('FINDING',c.printed_id,c.severity_raw,c.status_raw,repr(c.title),'BOUNDS',c.start,c.end)
        selected=cards[:1]+cards[len(cards)//2:len(cards)//2+1]+cards[-1:]
        for c in selected:
            print('CARD',r.text[c.start:min(c.end,c.start+1500)])
            print('END',r.text[max(c.start,c.end-500):c.end])
        print('TAIL',r.text[-800:])

def evaluate(firm):
    mod=import_module('parsers.'+firm.replace('-','_'))
    states=Counter(); total=Counter(); mismatch=[]; samples=[]; sequence_states=Counter();sequence_total=Counter();sequence_residuals=[];no_summary=[];unknown_labels=Counter();no_summary_sequence=Counter()
    for index,d in enumerate(documents(firm)):
        r=load(d); cs=finish(r,mod.parse(r)); counts=Counter(c.normalized or severity(c.severity_raw) for c in cs)
        summary=getattr(mod,'printed_counts',printed_counts)(r)
        state='no_counts' if not summary else 'ambiguous' if summary.get('ambiguous') else 'match' if all(counts[k]==v for k,v in summary['counts'].items()) else 'mismatch'
        states[state]+=1;total.update(counts)
        index_rows,explicit_zero=printed_index(r)
        expected=Counter(x['id'] for x in index_rows);actual=Counter(c.printed_id for c in cs)
        index_state='not_comparable'
        if index_rows or explicit_zero:
            index_state='match' if expected==actual else 'mismatch'
            sequence_states[index_state]+=1
            sequence_total['expected']+=sum(expected.values());sequence_total['parsed']+=sum(actual.values())
            sequence_total['matched']+=sum((expected & actual).values())
            if index_state=='mismatch':sequence_residuals.append({'sha256':d['row']['sha256'],'filename':d['row']['filename'],'expected':dict(expected),'actual':dict(actual),'missing':dict(expected-actual),'extra':dict(actual-expected)})
        for c in cs:
            if (c.normalized or severity(c.severity_raw))=='unknown':unknown_labels[c.severity_raw if c.severity_raw is not None else '<absent>']+=1
        if not summary:
            no_summary.append({'sha256':d['row']['sha256'],'filename':d['row']['filename'],'doc_kind':d['row']['doc_kind'],'findings':len(cs),'index_validation':index_state,'source_index_ids':[x['id'] for x in index_rows]})
            if index_rows or explicit_zero:
                no_summary_sequence['documents']+=1;no_summary_sequence['matching_documents']+=int(index_state=='match')
                no_summary_sequence['expected_ids']+=sum(expected.values());no_summary_sequence['matched_ids']+=sum((expected & actual).values())
        if state=='mismatch': mismatch.append({'sha256':d['row']['sha256'],'filename':d['row']['filename'],'summary':summary,'parsed':dict(counts),'ids':[c.printed_id for c in cs]})
        if index in SAMPLES[firm]: samples.append({'sha256':d['row']['sha256'],'filename':d['row']['filename'],'date_hint':d['row']['date_hint'],'findings':len(cs),'ids':[c.printed_id for c in cs],'counts':dict(counts),'validation':state,'index_validation':index_state,'source_index_ids':[x['id'] for x in index_rows]})
    audit_no_summary=[d for d in no_summary if d['doc_kind']=='audit_report']
    comparable=states['match']+states['mismatch']
    return {'firm':firm,'documents':sum(states.values()),'states':dict(states),'findings':sum(total.values()),'counts':dict(total),
            'agreement_percent':round(100*states['match']/comparable,2) if comparable else None,
            'mismatches':mismatch,'samples':samples,'unknown_severity_raw':dict(unknown_labels),
            'sequence_validation':dict(sequence_states),'sequence_totals':dict(sequence_total),'sequence_residuals':sequence_residuals,
            'no_summary_sequence':dict(no_summary_sequence),'no_summary_documents':no_summary,
            'no_summary_audit_nonempty':{'documents':len(audit_no_summary),'nonempty':sum(d['findings']>0 for d in audit_no_summary),
                       'percent':round(100*sum(d['findings']>0 for d in audit_no_summary)/len(audit_no_summary),2) if audit_no_summary else None}}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('firm',choices=SAMPLES);p.add_argument('--inspect',action='store_true');p.add_argument('--output',type=Path);a=p.parse_args()
    if a.inspect:
        inspect(a.firm)
    else:
        result=evaluate(a.firm)
        if a.output:
            from common import write_json
            write_json(a.output,result)
        print(json.dumps(result,indent=2))
