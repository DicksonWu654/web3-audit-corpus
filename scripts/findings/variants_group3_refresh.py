"""Merge current group 3 occurrences/cache receipts, preserving other publishers.

No collection/network changes. Holds the holdout boundary before opening caches
or local originals. Reuses completed fulltext; only missing pairs are extracted.
The merge checks input bytes again before each atomic write to avoid clobbering
concurrent snapshot writers. Framework code and inventory ledgers are unchanged.
"""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import ROOT, canonical, digest, documents, holdouts, write_json
from extract import extract_one
from variants_group3_study import FIRMS


def merge(path, updates, key):
    for _ in range(8):
        before=path.read_bytes()
        rows=[json.loads(l) for l in before.splitlines() if l.strip()]
        seen={r[key]:i for i,r in enumerate(rows)}
        for item in updates:
            if item[key] in seen:rows[seen[item[key]]]=item
            else:seen[item[key]]=len(rows);rows.append(item)
        payload=''.join(canonical(r)+'\n' for r in rows).encode()
        if path.read_bytes()!=before:continue
        tmp=path.with_name(path.name+'.group3.tmp');tmp.write_bytes(payload)
        if path.read_bytes()!=before:continue
        tmp.replace(path)
        return {'before_sha256':digest(before),'after_sha256':digest(payload),'rows':len(rows),'updated_keys':len(updates)}
    raise RuntimeError('Concurrent snapshot writer did not settle; no merge applied')


def main():
    blocked=holdouts();live,_,_=documents()
    selected=[d for d in live if d['row']['firm_id'] in FIRMS]
    assert all(d['row']['sha256'] not in blocked for d in selected)
    unique={d['row']['sha256']:d['row'] for d in selected}
    cached=[];jobs=[]
    for sha,row in unique.items():
        base=ROOT/'local-cache/fulltext';meta=base/(sha+'.pages.json');txt=base/(sha+'.txt')
        if meta.exists() and txt.exists():
            value=json.loads(meta.read_text())
            assert digest(txt.read_bytes())==value['text_sha256']
            cached.append({k:v for k,v in value.items() if k not in {'pages','coordinate_system','structured'}}|
                          {'text_path':str(txt.relative_to(ROOT)),'pages_path':str(meta.relative_to(ROOT))})
        else:jobs.append((sha,row))
    with ThreadPoolExecutor(max_workers=3) as pool:
        fresh=list(pool.map(lambda item:extract_one(item,ROOT,blocked),jobs))
    changes={
        'input_documents':merge(ROOT/'data/fulltext/input_documents.jsonl',selected,'document_id'),
        'extractions':merge(ROOT/'data/fulltext/extractions.jsonl',cached+fresh,'sha256')}
    result={'scope':list(FIRMS),'holdouts_opened':0,'current_occurrences':len(selected),
            'reused_cache_artifacts':len(cached),'new_extractions':fresh,'merges':changes}
    write_json(ROOT/'data/findings/variants/group3_refresh.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='new_extractions'},indent=2))
    for item in fresh:print(item['sha256'],item['status'],item.get('error',''))


if __name__=='__main__':main()
