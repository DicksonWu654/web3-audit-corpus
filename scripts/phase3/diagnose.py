#!/usr/bin/env python3
"""Holdout-safe development diagnostics. Never show held-out rows or their text."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]


def examples(root, firms, limit, unknown=False):
    path = root/'data/holdout/gold_sha256.txt'
    held = set(path.read_text().split()) if path.exists() else set()
    meta_path = root/'data/phase3/artifact_metadata.jsonl'
    metas = {r['sha256']:r for s in meta_path.read_text().splitlines() if s.strip() for r in [json.loads(s)]} if meta_path.exists() else {}
    counts = Counter()
    for path in sorted((root/'data/collect').glob('*/reports.jsonl')):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            firm = row['firm_id']
            if row['sha256'] in held or (firms and firm not in firms) or counts[firm]>=limit:
                continue
            meta = metas.get(row['sha256'], {})
            if unknown and any(c['date_value'] and c['role'] in {'audit_completion','report_issue'} and c['confidence']>=.8 for c in meta.get('dates',[])):
                continue
            text = root/'local-cache/text'/(row['sha256']+'.txt')
            if not text.exists():
                continue
            counts[firm] += 1
            print(json.dumps({k:row.get(k) for k in ['firm_id','filename','date_hint','date_basis','project_hint','sha256']}, ensure_ascii=False))
            print(text.read_text()[:4500])
            print(json.dumps(meta.get('dates', []), ensure_ascii=False))


def missing_summary(root):
    import duckdb
    con=duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True)
    rows=con.execute("SELECT publisher_id,count(*),count(*) FILTER(WHERE audit_year IS NOT NULL),count(*) FILTER(WHERE year_conflict) FROM engagements JOIN engagement_years USING(engagement_id) GROUP BY 1 ORDER BY count(*) FILTER(WHERE audit_year IS NULL) DESC").fetchall()
    print(json.dumps([dict(zip(['firm','engagements','audit_year_known','conflicts'],r)) for r in rows],indent=2))


def merges(root, firms, limit):
    import duckdb
    path=root/'data/holdout/gold_sha256.txt'
    held=set(path.read_text().split()) if path.exists() else set()
    con=duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True)
    for firm in firms or []:
        rows=con.execute('SELECT e.engagement_id,e.project,list(d.sha256),list(ed.evidence),list(d.filename) FROM engagements e JOIN engagement_documents ed USING(engagement_id) JOIN documents d USING(document_id) WHERE e.publisher_id=? GROUP BY 1,2 HAVING count(*)>1 ORDER BY count(*) DESC',[firm]).fetchall()
        seen=0
        for eid,project,hashes,evidence,filenames in rows:
            if held.intersection(hashes):
                continue
            print(json.dumps(dict(firm=firm,engagement_id=eid,project=project,filenames=filenames,evidence=[json.loads(e) for e in evidence]),ensure_ascii=False))
            seen+=1
            if seen>=limit:
                break


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=ROOT)
    p.add_argument('--firms', nargs='*')
    p.add_argument('--limit', type=int, default=1)
    p.add_argument('--unknown', action='store_true')
    p.add_argument('--summary', action='store_true')
    p.add_argument('--merges', action='store_true')
    args = p.parse_args()
    if args.summary:
        missing_summary(args.root)
    elif args.merges:
        merges(args.root,args.firms,args.limit)
    else:
        examples(args.root,args.firms,args.limit,args.unknown)
