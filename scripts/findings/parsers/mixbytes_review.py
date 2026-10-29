"""Guarded, deterministic development review/evaluation for the three owned parsers."""
import argparse
from collections import Counter, defaultdict
import importlib
import json
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, digest, holdouts, read_snapshot, write_json
from core import Report, finish, severity
from summary_counts import printed_counts


def samples(firm):
    blocked = holdouts(ROOT)
    docs = read_snapshot(ROOT)
    unique = {d['row']['sha256']: d for d in docs if d['row']['firm_id'] == firm}
    ordered = sorted(unique.values(), key=lambda d: (d['row'].get('date_hint') or '', d['row']['filename']))
    selected = [ordered[round(i*(len(ordered)-1)/16)] for i in range(17)]
    return blocked, ordered, selected


def report(d, blocked):
    sha = d['row']['sha256']
    if sha in blocked:
        raise RuntimeError('Holdout denied')
    meta = json.loads((ROOT/'local-cache/fulltext'/(sha+'.pages.json')).read_text())
    text = (ROOT/'local-cache/fulltext'/(sha+'.txt')).read_text()
    return Report(text, meta, d['row']['firm_id'])



def printed_index_ids(r):
    """Read a separately printed TOC; never use candidate rows as expectations."""
    pages=r.meta['pages'];start=next((i for i,p in enumerate(pages) if re.search(r'^\s*(?:TABLE OF CONTENTS|Contents)\s*$',p['text'],re.M|re.I)),None)
    if start is None:return None
    toc=[]
    for p in pages[start:]:
        if toc and re.search(r'^\s*(?:Report Manifest|Chapter 1 Introduction|(?:\[\s*)?1\s*\.?\s*INTRODUCTION(?:\s*\])?)\s*$',p['text'],re.M|re.I):break
        toc.append(p)
    front='\n'.join(p['text'] for p in toc)
    if r.firm=='blocksec' and 'Targets, Scope, and Methodology' in front:return None
    pattern=r'^\s*([23]\.\d+\.\d+)(?=\D)' if r.firm=='blocksec' else r'^\s*((?:CRT|CR|MJR|WRN|CMT|C|H|M|L|I)-\d+)\b'
    ids=[];proof=[]
    for p in toc:
        for m in re.finditer(pattern,p['text'],re.M):
            ids.append(m[1]);proof.append({'page':p['page'],'start':p['start']+m.start(1),'end':p['start']+m.end(1),'printed_id':m[1]})
    return {'ids':ids,'evidence':proof} if ids else None



def native_sequence(r, entries):
    """Continuity within native series, not independent recall or a clean-audit test.

    MixBytes restarts numbered lists at explicit severity/project/observation
    headings. A repeated 1 alone never creates a series: true duplicates remain.
    BlockSec includes formal, recommendation and observation section IDs.
    """
    if not entries:return {'state':'unassessable','reason':'no_findings_or_missing_ids','series':[]}
    if any(not c.printed_id for c in entries):return {'state':'unassessable','reason':'missing_printed_id','series':[]}
    if r.firm=='blocksec' and any(len(c.printed_id.split('.'))>3 for c in entries):
        return {'state':'unassessable','reason':'nested_research_section_numbers_include_nonfinding_subsections','ids':[c.printed_id for c in entries],'series':[]}
    global_legacy=(r.firm=='mixbytes' and bool(re.search(r'^\s*#{1,6}\s*\[SEVERE\]',r.text,re.M)))
    anchors=[]
    if r.firm=='mixbytes':
        for l in r.lines:
            label=l.content.replace('\u200b','').strip('* [] ')
            if re.fullmatch(r'CRITICAL|MAJOR|SERIOUS|WARNINGS?|COMMENTS?|REMARKS?|SEVERE|NOTES?|SUGGESTIONS?|PROPOSALS?|HIGH|MEDIUM|LOW|КРИТИЧНЫЕ|КРИТИЧЕСКИЕ|СЕРЬЕЗНЫЕ|ПРЕДУПРЕЖДЕНИЯ|ЗАМЕЧАНИЯ',label,re.I):
                anchors.append({'start':l.start,'end':l.end,'page':l.page,'text':l.text,'label':label})
    grouped=defaultdict(list);proof={}
    for c in entries:
        pid=str(c.printed_id);m=re.fullmatch(r'(.*?)(\d+)',pid)
        if not m:return {'state':'unassessable','reason':'unrecognized_printed_id','series':[]}
        prefix,number=m[1],int(m[2]);anchor=None
        if global_legacy and not prefix:key='global_legacy_severe_notes'
        elif r.firm=='mixbytes' and not prefix:
            anchor=next((x for x in reversed(anchors) if x['start']<c.start),None)
            if not anchor:return {'state':'unassessable','reason':'numeric_id_without_native_section','series':[]}
            key=str(anchor['start'])+':'+anchor['label']
        else:key=prefix
        grouped[key].append(number)
        if anchor:proof[key]=anchor
    series=[]
    for key,numbers in grouped.items():
        start=0 if 0 in numbers else 1
        gaps=sorted(set(range(start,max(numbers)+1))-set(numbers))
        duplicates=sorted(n for n,count in Counter(numbers).items() if count>1)
        series.append({'key':key,'numbers':numbers,'gaps':gaps,'duplicates':duplicates,'section_evidence':proof.get(key)})
    return {'state':'incomplete' if any(s['gaps'] or s['duplicates'] for s in series) else 'complete','basis':'printed_ID_continuity_within_native_source_sections','record_kinds_included':sorted({c.record_kind for c in entries}),'series':series}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('firm', choices=['mixbytes','blocksec','hexens'])
    ap.add_argument('--review', action='store_true')
    ap.add_argument('--evaluate', action='store_true')
    a=ap.parse_args(); blocked, docs, selected=samples(a.firm)
    if a.review:
        for d in selected:
            r=report(d,blocked)
            print('\nSAMPLE',d['row']['sha256'],d['row'].get('date_hint'),d['row']['filename'])
            print('PAGES',len(r.meta['pages']),'CHARS',len(r.text))
            interesting=[(i,l) for i,l in enumerate(r.lines) if re.search(r'^(?:#{1,5} |\s*(?:[A-Z][A-Z0-9_-]*-\d+|\d+\.\d+\.\d+|Severity|Status|Risk level|Risk Level|Finding|[A-Z]?[a-z]*\s*[Ii]ssues|Appendix|Chapter \d+))',l.text)]
            for i,l in interesting[:12]:
                print(f'p{l.page} {l.text[:160]}')
            # Actual detail narrative, plus final body/appendix boundaries.
            anchors=[i for i,l in interesting if re.search(r'Severity|severity',l.text)]
            if anchors:
                i=anchors[-1]; print('LAST DETAIL CONTEXT', '\n'.join(l.text for l in r.lines[max(0,i-7):i+16])[:650])
            print('END',r.text[-180:])
    if a.evaluate:
        mod=importlib.import_module('parsers.'+a.firm)
        sample_rows=[]; diagnostics=[]
        for d in docs:
            r=report(d,blocked); entries=finish(r,mod.parse(r)); counts=Counter(c.normalized or severity(c.severity_raw) for c in entries if c.record_kind=='formal_finding')
            summary=getattr(mod,'printed_counts',printed_counts)(r)
            comparable=bool(summary and not summary.get('ambiguous'))
            match=comparable and all(counts[k]==n for k,n in summary['counts'].items())
            diag={'sha256':d['row']['sha256'],'filename':d['row']['filename'],'parsed_counts':dict(counts),'findings':len(entries),'summary':summary,'comparable':comparable,'match':bool(match),'ids':[c.printed_id for c in entries]}
            index=printed_index_ids(r)
            if index:diag['printed_id_index']=index;diag['id_sequence_match']=index['ids']==diag['ids']
            if not comparable:diag['native_sequence']=native_sequence(r,entries)
            diagnostics.append(diag)
            if d in selected:sample_rows.append(diag|{'date_hint':d['row'].get('date_hint'),'pages':len(r.meta['pages']),'text_characters':len(r.text)})
        v={'firm_id':a.firm,'sample_method':'17 evenly spaced distinct SHA documents ordered by date_hint then filename; guarded before all text reads','inspected_samples':sample_rows,'id_index_documents':sum('printed_id_index' in d for d in diagnostics),'id_index_matches':sum(d.get('id_sequence_match',False) for d in diagnostics),'id_index_mismatches':[d for d in diagnostics if d.get('id_sequence_match') is False],'unique_documents':len(docs),'comparable':sum(d['comparable'] for d in diagnostics),'matching':sum(d['match'] for d in diagnostics),'findings':sum(d['findings'] for d in diagnostics),'mismatches':[d for d in diagnostics if d['comparable'] and not d['match']],'no_summary':[d for d in diagnostics if not d['comparable']]}
        nonsummary=[d for d in diagnostics if not d['comparable']]
        sequence_counts=Counter(d['native_sequence']['state'] for d in nonsummary)
        assessable=sequence_counts['complete']+sequence_counts['incomplete']
        v['no_summary_native_sequence']={'documents':len(nonsummary),'complete':sequence_counts['complete'],'incomplete':sequence_counts['incomplete'],'unassessable':sequence_counts['unassessable'],'comparable':assessable,'complete_percent_comparable':round(100*sequence_counts['complete']/assessable,2) if assessable else None,'unit':'distinct_original_SHA256','limitation':'Native-series continuity is not independent finding recall; real printed gaps and duplicates remain failures.','unassessable_cases':[{'sha256':d['sha256'],'filename':d['filename'],'reason':d['native_sequence'].get('reason')} for d in nonsummary if d['native_sequence']['state']=='unassessable']}
        # Verify the regenerated interchange against guarded text and receipts.
        receipts={d['document_id']:d for d in read_snapshot(ROOT) if d['row']['firm_id']==a.firm}
        seen=set();cache={};checked=0
        for rawline in (ROOT/'data/findings'/(a.firm+'.jsonl')).open():
            row=json.loads(rawline);sha=row['sha256'];assert sha not in blocked
            d=receipts[row['document_id']]
            assert sha==d['row']['sha256'] and row['source_record_sha256']==d['source_record_sha256']
            if sha not in cache:
                cache.clear();cache[sha]=report(d,blocked)
            r=cache[sha];span=row['body_span'];start,end=span['start'],span['end']
            assert 0<=start<end<=len(r.text) and row['body_text']==r.text[start:end]
            assert digest(r.text.encode())==r.meta['text_sha256']==span['text_sha256']
            assert row['finding_id'] not in seen;seen.add(row['finding_id'])
            assert row['record_kind'] in {'formal_finding','recommendation','remediation_review','observation','summary_excerpt','candidate','unknown'}
            assert row['severity_original']==row['severity_raw'] and row['severity_normalized']==row['severity']
            checked+=1
        v['output_contract']={'ok':True,'rows_checked':checked,'holdout_rows':0,'checks':['parent_receipt','body_slice','text_hash','bounds','finding_id_uniqueness','record_kind','severity_aliases']}
        write_json(ROOT/'data/findings/validation'/(a.firm+'_development.json'),v)
        print(json.dumps({k:v for k,v in v.items() if k not in {'inspected_samples','mismatches','no_summary','id_index_mismatches'}},indent=2))
        for d in v['mismatches'][:35]:print(json.dumps(d))

if __name__=='__main__':main()
