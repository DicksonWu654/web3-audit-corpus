"""Read-only source diagnostics for the general Phase 3e identity rules."""
import argparse
import json
from pathlib import Path
import re

import duckdb

ROOT = Path(__file__).resolve().parents[2]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('pattern', nargs='?', default='pectra|Parallel3.1|FCT |Turbo|Poodl|USDT (?:TON|OFT)|USDS|Synthetics|basin|notional')
    p.add_argument('--firm')
    p.add_argument('--limit', type=int, default=40)
    p.add_argument('--text', action='store_true')
    p.add_argument('--front', type=int, default=1800)
    p.add_argument('--rules', action='store_true')
    p.add_argument('--match', default=r'asked to split|submodules|deliverable|mitigat\w* code|remediat\w* (?:of|the)|previous engagement|present report focuses|hosted a competition|six teams|additional.*formal|subsequent report')
    p.add_argument('--regressions', action='store_true')
    p.add_argument('--cadence', action='store_true')
    p.add_argument('--canonical', action='store_true', help='Inspect canonical/og:url tags in SHA-verified cached HTML')
    args = p.parse_args()
    if args.cadence:
        import csv
        from collections import Counter
        with (ROOT/'data/analysis/reaudit_cadence_pairs.csv').open() as f:
            pairs=list(csv.DictReader(f))
        print(json.dumps(dict(entities=Counter(r['entity'] for r in pairs).most_common(20),bases=Counter(r['identity_basis'] for r in pairs))))
        with duckdb.connect(str(ROOT/'data/corpus.duckdb'),read_only=True) as con:
            docs={d:dict(project=p,url=u,firm=f) for d,p,u,f in con.execute('SELECT document_id,project,public_url,publisher_id FROM documents WHERE NOT is_seed').fetchall()}
        for r in sorted(pairs,key=lambda r:(int(r['days']),r['project_key']))[:args.limit]:
            print(json.dumps(dict(days=r['days'],entity=r['entity'],basis=r['identity_basis'],
                shared_repositories=r['shared_repositories'],shared_scope_assets=r['shared_scope_assets'],
                left=docs[r['previous_identity_document_id']],right=docs[r['identity_document_id']]),ensure_ascii=False))
        return
    if args.regressions:
        gold=json.loads((ROOT/'docs/verify/phase3_v5.json').read_text())
        with duckdb.connect(str(ROOT/'data/corpus.duckdb'),read_only=True) as con:
            links=dict(con.execute('SELECT document_id,engagement_id FROM engagement_documents').fetchall())
        def ids(eid):
            return {links[did] for did in gold['engagements'][eid]['documents'] if did in links}
        result=[]
        for row in gold['split']['rows']:
            if row['split_error']:
                left,right=ids(row['left']),ids(row['right'])
                result.append(dict(position=row['position'],relation=row['relationship'],resolved=bool(left and right and len(left|right)==1)))
        print(json.dumps(result,indent=2))
        for row in gold['merge']['rows']:
            if row['verdict']!='supported_merge':
                print(json.dumps(dict(position=row['position'],verdict=row['verdict'],successors=sorted(ids(row['engagement_id'])))))
        return
    held = set((ROOT/'data/holdout/gold_sha256.txt').read_text().split())
    with duckdb.connect(str(ROOT/'local-cache/phase3e/before.duckdb'), read_only=True) as con:
        rows = con.execute('SELECT d.document_id,d.publisher_id,d.filename,d.public_url,d.sha256,d.metadata,e.engagement_id FROM documents d JOIN engagement_documents ed USING(document_id) JOIN engagements e USING(engagement_id) WHERE NOT d.is_seed ORDER BY d.publisher_id,d.filename').fetchall()
    seen = set()
    for did, firm, filename, url, digest, raw, eid in rows:
        if not digest or digest in seen or digest in held or args.firm and firm != args.firm:
            continue
        meta = json.loads(raw)
        if not re.search(args.pattern, ' '.join([filename or '', str(meta['client']['value'] or ''), url]), re.I):
            continue
        seen.add(digest)
        if args.canonical:
            import hashlib
            from html.parser import HTMLParser
            class Aliases(HTMLParser):
                def handle_starttag(self,tag,attrs):
                    values=dict(attrs)
                    if tag=='link' and 'canonical' in (values.get('rel') or '').lower().split():
                        print(json.dumps(dict(tag='canonical',url=values.get('href'))))
                    if tag=='meta' and (values.get('property') or values.get('name') or '').lower()=='og:url':
                        print(json.dumps(dict(tag='og:url',url=values.get('content'))))
            print('Original '+str(filename))
            for original in sorted((ROOT/'local-cache/originals'/digest[:2]).glob(digest+'.*')):
                body=original.read_bytes()
                assert hashlib.sha256(body).hexdigest()==digest
                if not body.startswith(b'%PDF'):
                    Aliases().feed(body.decode('utf-8','replace'))
        if args.rules:
            import sys
            sys.path.insert(0, str(ROOT/'scripts/phase3'))
            import identity_rules
            receipt = meta.get('date_text_receipt') or meta['text_receipt']
            path = ROOT/(receipt.get('text_snapshot') or 'local-cache/text/'+digest+'.txt')
            payload = path.read_text() if path.exists() else ''
            meta['client'] = identity_rules.source_client(payload, meta['client'], [firm]) or meta['client']
            print('Processing '+str(filename), flush=True)
            d = dict(document_id=did, publisher_id=firm, filename=filename, public_url=url, metadata=meta)
            print(json.dumps(identity_rules.evidence(payload, d, meta)), flush=True)
        print(json.dumps(dict(document=did, firm=firm, filename=filename, url=url, engagement=eid,
                              client=meta['client'], dates=[(c['date_value'], c['role']) for c in meta['dates'] if c['date_value']],
                              relationships={k:v for k,v in meta.get('source_relationships',{}).items() if k != 'sketch'}), ensure_ascii=False))
        if args.text:
            receipt = meta.get('date_text_receipt') or meta['text_receipt']
            path = ROOT/(receipt.get('text_snapshot') or 'local-cache/text/'+digest+'.txt')
            payload = path.read_text() if path.exists() else ''
            print(payload[:args.front])
            for m in re.finditer(args.match, payload, re.I):
                if m.start() > args.front:
                    print(payload[max(0,m.start()-150):m.end()+500])
        if len(seen) >= args.limit:
            break


if __name__ == '__main__':
    main()
