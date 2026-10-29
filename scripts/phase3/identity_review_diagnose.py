#!/usr/bin/env python3
"""Small, holdout-filtered source packets for general-rule development."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

import duckdb

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/build'))
from metadata_rules import read_text
from date_rules import load_date_text


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--firms',nargs='+',default=[])
    p.add_argument('--limit',type=int,default=1)
    p.add_argument('--pattern',default='')
    p.add_argument('--db',type=Path,default=ROOT/'local-cache/phase3d/before.duckdb')
    p.add_argument('--relationships',action='store_true',help='Show non-holdout examples of newly bridged baseline engagements')
    a=p.parse_args()
    held={s.strip() for s in (ROOT/'data/holdout/gold_sha256.txt').read_text().splitlines() if s.strip() and not s.startswith('#')}
    if a.relationships:
        with duckdb.connect(str(a.db),read_only=True) as con:
            before=dict(con.execute('SELECT document_id,engagement_id FROM engagement_documents').fetchall())
        with duckdb.connect(str(ROOT/'data/corpus.duckdb'),read_only=True) as con:
            docs={r[0]:dict(document_id=r[0],filename=r[1],sha256=r[2],metadata=json.loads(r[3]),publisher=r[4])
                  for r in con.execute('SELECT document_id,filename,sha256,metadata,publisher_id FROM documents WHERE NOT is_seed').fetchall()}
            edges={}
            for raw, in con.execute('SELECT evidence FROM engagement_documents').fetchall():
                for edge in json.loads(raw).get('merge_edges',[]):
                    if not edge.get('joins_components',True): continue
                    if len({before.get(d) for d in edge['documents']}-{None})<2: continue
                    edges[(edge['basis'],tuple(sorted(edge['documents'])))]=edge
            counts=Counter(); shown=Counter()
            for (basis,_),edge in sorted(edges.items()):
                counts[basis]+=1
                members=[docs[d] for d in edge['documents']]
                if any(d['sha256'] in held for d in members) or shown[basis]>=a.limit: continue
                shown[basis]+=1
                output=[]
                for d in members:
                    m=d['metadata']; r=m.get('source_relationships',{})
                    output.append(dict(firm=d['publisher'],filename=d['filename'],client=m['client'],
                                       relationships={k:v for k,v in r.items() if k!='sketch'},
                                       dates=[{k:c.get(k) for k in ['date_value','role','method','resolution']} for c in m['dates'] if c.get('confidence',0)>=.8]))
                print(json.dumps(dict(rule=basis,documents=output)))
            print(json.dumps(dict(new_bridges=dict(counts))))
        return
    if not a.firms: p.error('--firms or --relationships is required')
    counts=Counter()
    with duckdb.connect(str(a.db),read_only=True) as con:
        cur=con.execute('SELECT d.* FROM documents d WHERE NOT is_seed AND sha256 IS NOT NULL AND publisher_id IN (SELECT unnest(?)) ORDER BY sha256',[a.firms])
        names=[r[0] for r in cur.description]
        for row in cur.fetchall():
            d=dict(zip(names,row)); firm=d['publisher_id']
            if d['sha256'] in held or counts[firm]>=a.limit: continue
            text,receipt=read_text(ROOT,d)
            complete,receipt=load_date_text(ROOT,d['sha256'],text,receipt)
            if a.pattern and not re.search(a.pattern,complete+' '+str(d['filename']),re.I): continue
            counts[firm]+=1
            meta=json.loads(d['metadata'])
            dates=[{k:c.get(k) for k in ['date_value','role','method','evidence']} for c in meta['dates'] if c.get('confidence',0)>=.8]
            contexts=[]
            for m in re.finditer(a.pattern or r'\b(?:timeline|period|dates|conducted|performed|debrief|initial review|code review|finished|Auditors|engaged|latest audit|version history|signature)\b',complete,re.I):
                lo=max(complete.rfind('\f',0,m.start())+1,complete.rfind('\n',0,max(0,m.start()-100))+1)
                contexts.append(complete[lo:m.end()+320])
                if len(contexts)>=5: break
            print(json.dumps(dict(firm=firm,filename=d['filename'],sha256=d['sha256'],client=meta['client'],dates=dates,opening=text[:1400],contexts=contexts),ensure_ascii=False))


if __name__=='__main__': main()
