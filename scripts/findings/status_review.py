"""Reproduce status vocabulary, non-holdout evidence review and coverage census."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, canonical, digest, holdouts, read_snapshot, write_json, write_jsonl

TARGETS = ('neodyme', 'codespect', 'ackee-blockchain', 'sherlock', 'zellic',
           'code4rena', 'certora', 'runtime-verification', 'coinspect', 'trail-of-bits',
           'verichains', 'chainsecurity')
BASE = ROOT / 'local-cache/phase4-status'


def census(firm_filter=None):
    blocked = holdouts()
    result = {}
    for path in sorted((ROOT / 'data/findings').glob('*.jsonl')):
        if path.name.startswith('_'): continue
        if firm_filter and path.stem != firm_filter:continue
        labels, states, variants = Counter(), Counter(), defaultdict(Counter)
        examples = {}
        rows = {}
        for line in path.open():
            row = json.loads(line)
            if row['sha256'] in blocked: raise ValueError('Holdout row denied')
            raw = row.get('status_original', row.get('status_raw'))
            label = json.dumps(raw, ensure_ascii=False)
            labels[label] += 1
            states[str(row.get('status'))] += 1
            known = raw is not None and row.get('status') not in (None, 'unknown', 'other', 'not_stated', 'info', 'invalid')
            variants[row['variant_id']]['rows'] += 1
            variants[row['variant_id']]['raw'] += raw is not None
            variants[row['variant_id']]['known'] += known
            examples.setdefault(label, {'sha256': row['sha256'], 'page': row['page'],
                                       'public_url': row['public_url'], 'finding_id': row['finding_id']})
            rows[row['finding_id']] = [raw, row.get('status'), row['sha256'], row['page']]
        result[path.stem] = {'rows': len(rows), 'raw': sum(n for label, n in labels.items() if label != 'null'),
                             'known': sum(v['known'] for v in variants.values()), 'labels': dict(labels),
                             'states': dict(states), 'variants': dict(variants), 'examples': examples,
                             'findings': rows}
    return result


def pages(firm):
    blocked = holdouts()
    seen = set()
    for doc in read_snapshot():
        row = doc['row']; sha = row['sha256']
        if row['firm_id'] != firm or sha in seen: continue
        if sha in blocked: raise ValueError('Holdout evidence denied')
        seen.add(sha)
        path = ROOT / 'local-cache/fulltext' / (sha + '.pages.json')
        if not path.exists(): continue
        meta = json.loads(path.read_text())
        for page in meta['pages']:
            yield row, meta, page


def search(firm, pattern, limit):
    rx = re.compile(pattern, re.I | re.M)
    n = 0
    for row, meta, page in pages(firm):
        matches = list(rx.finditer(page['text']))
        if not matches: continue
        print(json.dumps({'sha256': row['sha256'], 'page': page['page'], 'url': row['public_url']}, ensure_ascii=False))
        for m in matches[:3]:
            print(page['text'][max(0, m.start()-180):m.end()+800])
        n += 1
        if n >= limit: break


def gaps(firm, limit):
    blocked = holdouts(); seen = set(); n = 0
    for line in (ROOT / 'data/findings' / (firm + '.jsonl')).open():
        row = json.loads(line)
        if row['sha256'] in blocked: raise ValueError('Holdout row denied')
        if row.get('status_raw') or row['record_kind'] == 'summary_excerpt': continue
        key = (row['sha256'], row['body_span']['start'])
        if key in seen: continue
        seen.add(key)
        body = row['body_text']
        matches = list(re.finditer(r'\b(?:status|resolution|remediation|fix(?:ed)?|acknowledged|addressed|resolved|commit|patch|update)\b', body, re.I))
        if not matches: continue
        print(json.dumps({k: row[k] for k in ('sha256', 'page', 'variant_id', 'publisher_finding_id', 'title')}, ensure_ascii=False))
        for m in matches[-4:]: print(body[max(0, m.start()-80):m.end()+300])
        n += 1
        if n >= limit: break


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('before', 'labels', 'search', 'gaps', 'report', 'verify', 'definitions', 'decisions', 'refresh', 'misses', 'view', 'tests', 'scoped-tests', 'stale', 'listed'))
    p.add_argument('--firm'); p.add_argument('--pattern', default=r'status.{0,30}(?:definition|classification)|(?:fixed|acknowledged)\s*[-:]')
    p.add_argument('--sha');p.add_argument('--page',type=int)
    p.add_argument('--limit', type=int, default=6)
    a = p.parse_args()
    if a.command=='scoped-tests':
        import unittest
        names=('test_status_resolve','test_chainlight_neodyme_variants','test_group1_code4rena',
               'test_runtime_dedaub','test_variants_group1_c4_runtime','parsers.test_certora_shieldify_variants',
               'parsers.test_verichains_zokyo','test_group2')
        suite=unittest.defaultTestLoader.loadTestsFromNames(names)
        result=unittest.TextTestRunner(verbosity=1).run(suite)
        write_json(BASE/'scoped_tests.json',{'tests':result.testsRun,'failures':len(result.failures),
                  'errors':len(result.errors),'skipped':len(result.skipped),'ok':result.wasSuccessful(),
                  'modules':names,'command':'python3 -I -S scripts/findings/status_review.py scoped-tests'})
        if not result.wasSuccessful():raise SystemExit(1)
        return
    if a.command=='tests':
        import ast
        import subprocess
        import unittest
        from parsers import module
        from variants_group2 import FIRMS
        suite=unittest.defaultTestLoader.discover(str(ROOT/'scripts/findings'),pattern='test*.py')
        result=unittest.TextTestRunner(verbosity=1).run(suite)
        failures={case.id():detail for case,detail in result.failures+result.errors}
        historical=json.loads((ROOT/'data/findings/severity_canon/preexisting_tests.json').read_text())
        expected=set(historical['baseline']['failure_details'])
        duplicates=[]
        for firm in FIRMS:
            variants=module(firm).VARIANTS
            if len({v.parse.__name__ for v in variants})==len(variants):continue
            path='scripts/findings/parsers/'+firm.replace('-','_')+'.py'
            source=subprocess.check_output(['git','show','HEAD:'+path],cwd=ROOT,text=True)
            original=ast.parse(source)
            names=[]
            for node in original.body:
                if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='VARIANTS' for t in node.targets):
                    names=[ast.unparse(v.args[2]) for v in node.value.elts]
            duplicates.append({'firm':firm,'source':path,'head_source_sha256':digest(source.encode()),
                               'also_duplicate_at_head':len(set(names))<len(names),
                               'current_parsers':[v.parse.__name__ for v in variants]})
        if duplicates and all(d['also_duplicate_at_head'] for d in duplicates):
            expected.add('test_variants_group2.Group2Variants.test_every_variant_has_own_parser_and_executable_fixture')
        receipt={'tests':result.testsRun,'failures':failures,'expected_baseline_failures':sorted(expected),
                 'new_failures':sorted(set(failures)-expected),'skipped':len(result.skipped),
                 'duplicate_variant_contracts':duplicates,
                 'command':'python3 -I -S scripts/findings/status_review.py tests'}
        write_json(BASE/'tests.json',receipt)
        if receipt['new_failures']:raise SystemExit(1)
        return
    if a.command=='view':
        if a.sha in holdouts():raise ValueError('Holdout evidence denied')
        meta=json.loads((ROOT/'local-cache/fulltext'/(a.sha+'.pages.json')).read_text())
        for page in meta['pages']:
            if a.page is not None and page['page']!=a.page:continue
            if a.page is None and not re.search(a.pattern,page['text'],re.I):continue
            print('page',page['page']);print(page['text'])
        return
    if a.command == 'search': return search(a.firm, a.pattern, a.limit)
    if a.command == 'gaps': return gaps(a.firm, a.limit)
    if a.command=='listed':
        from status_resolve import status_policy
        policy,_,_=status_policy()
        for firm,entry in policy['publishers'].items():
            if a.firm and a.firm!=firm:continue
            labels=[(label,m['normalized']) for era in entry['eras'] for label,m in era['labels'].items() if m['review_state']=='listed_unresolved']
            if labels:print(firm,len(labels),json.dumps(labels[:a.limit],ensure_ascii=False))
        return
    if a.command=='stale':
        blocked=holdouts();cache={};result=defaultdict(set);newline_receipts=[]
        for path in sorted((ROOT/'data/findings').glob('*.jsonl')):
            if path.name.startswith('_'):continue
            for line in path.open():
                row=json.loads(line);sha=row['sha256']
                if sha in blocked:raise ValueError('Holdout row denied')
                if sha not in cache:
                    meta=json.loads((ROOT/'local-cache/fulltext'/(sha+'.pages.json')).read_text())
                    cache[sha]=meta['text_sha256']
                    raw=(ROOT/'local-cache/fulltext'/(sha+'.txt')).read_bytes()
                    assert digest(raw)==meta['text_sha256'], ('Current text receipt mismatch',sha)
                    if b'\r' in raw:newline_receipts.append({'firm':path.stem,'sha256':sha})
                if cache[sha]!=row['body_span']['text_sha256']:result[path.stem].add(sha)
        output={firm:sorted(shas) for firm,shas in sorted(result.items())}
        write_json(BASE/'stale_text.json',output)
        write_json(BASE/'newline_receipts.json',{'contains_carriage_returns':newline_receipts})
        print(json.dumps(output))
        return
    if a.command=='misses':
        blocked=holdouts()
        for firm in [a.firm] if a.firm else TARGETS:
            found=[];seen=set()
            for line in (ROOT/'data/findings'/(firm+'.jsonl')).open():
                row=json.loads(line)
                if row['sha256'] in blocked:raise ValueError('Holdout row denied')
                if row.get('status_raw') or (row['sha256'],row['publisher_finding_id']) in seen:continue
                seen.add((row['sha256'],row['publisher_finding_id']))
                body=row['body_text']
                m=re.search(r'(?mi)^[ \t\f]*(?:#{1,6}\s*)?(?:Status|Resolution|Remediation|Solution(?:\s*\([^\n]*\))?)\s*:?\s*\n([\s\S]{0,1200})',body)
                if m:
                    found.append({k:row[k] for k in ('sha256','page','publisher_finding_id','variant_id')}|{'quote':m[0][:1000]})
            print(firm,'status_section_without_label',len(found))
            for row in found[:a.limit]:print(json.dumps(row,ensure_ascii=False))
        return
    if a.command == 'refresh':
        from status_resolve import status_mapping, select_status_era, status_policy
        policy=status_policy()[0]
        blocked=holdouts(); counts={}; eras={}; changed=0
        for path in sorted((ROOT/'data/findings').glob('*.jsonl')):
            if path.name.startswith('_') or a.firm and path.stem!=a.firm:continue
            stamp=path.stat()
            temp=path.with_suffix('.jsonl.status-tmp'); diagnostics=defaultdict(Counter)
            with path.open() as source,temp.open('w') as output:
                for line in source:
                    row=json.loads(line);sha=row['sha256']
                    if sha in blocked:raise ValueError('Holdout row denied')
                    key=(path.stem,sha)
                    if key not in eras:
                        # Future definition-based eras must be selected from
                        # verified text, never collector/filename date hints.
                        text=None
                        if any(e.get('definition_regex') for e in policy['publishers'][path.stem]['eras']):
                            text=(ROOT/'local-cache/fulltext'/(sha+'.txt')).read_bytes().decode('utf-8')
                            assert digest(text.encode())==row['body_span']['text_sha256']
                        eras[key]=select_status_era(path.stem,sha256=sha,report_text=text)
                    raw=row['status_raw']
                    assert raw==row['provenance']['extraction_record']['status_raw']
                    receipt=status_mapping(raw,path.stem,era=eras[key],sha256=sha,log=False)
                    changed+=row['status']!=receipt['normalized']
                    row['status_original']=raw;row['status']=receipt['normalized']
                    row['status_mapping']=receipt;row['evidence']['status_mapping']=receipt
                    if not receipt['mapped']:diagnostics[row['document_id']][json.dumps(raw,ensure_ascii=False)]+=1
                    output.write(canonical(row)+'\n')
            after=path.stat()
            if (stamp.st_size,stamp.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):
                raise RuntimeError('Finding stream changed during status refresh: '+str(path))
            temp.replace(path)
            validation=ROOT/'data/findings/validation'/(path.stem+'.jsonl')
            if validation.exists():
                rows=[]
                for line in validation.open():
                    row=json.loads(line)
                    if row['sha256'] in blocked:raise ValueError('Holdout diagnostic denied')
                    row['unmapped_statuses']=dict(diagnostics[row['document_id']]);rows.append(row)
                write_jsonl(validation,rows)
            counts[path.stem]=sum(diagnostics[d].total() for d in diagnostics)
        write_json(BASE/'refresh.json',{'changed_statuses':changed,'unmapped_or_listed_by_firm':counts,'holdouts_opened':0})
        print(json.dumps({'changed_statuses':changed,'publishers':len(counts)}))
        return
    if a.command == 'decisions':
        from status_resolve import status_policy
        policy,_,_=status_policy()
        for firm,entry in policy['publishers'].items():
            if a.firm and firm != a.firm:continue
            for era in entry['eras']:
                for label,m in era['labels'].items():
                    if re.search(a.pattern,label,re.I):
                        print(json.dumps({'publisher':firm,'label':label,**m},ensure_ascii=False))
        return
    if a.command == 'definitions':
        result = {}
        firms = [a.firm] if a.firm else sorted({d['row']['firm_id'] for d in read_snapshot()})
        for firm in firms:
            candidates = []
            for row, meta, page in pages(firm):
                text = page['text']
                heading = re.search(r'(?m)^[ \t]*(?:#{1,6}\s*|\d+(?:\.\d+)*\.?\s*)?'
                                    r'(?:status(?:es)?\s+(?:level\s+reference|definitions?|classification|description|categor(?:ies|ization))|'
                                    r'(?:finding|issue|remediation)\s+status(?:es)?)\s*[:.]?[ \t]*$', text, re.I)
                if not heading: continue
                score = 20 + 3*len(set(re.findall(r'\b(?:fixed|resolved|acknowledged|unresolved|open|partially)\b', text, re.I)))
                score += 20*bool(re.search(r'(?:means|defined|indicates|refers to|has been|have been|not been)', text, re.I))
                score -= 100*bool(re.search(r'(?:\.\s*){5,}', text) or re.search(r'(?mi)^\s*(?:Table of Contents|Contents)\s*$',text))
                start=max(0,heading.start()-100); end=min(len(text),heading.end()+3000)
                candidates.append(dict(sha256=row['sha256'],page=page['page'],public_url=row['public_url'],
                    page_basis='pdf_page' if row['file_format']=='pdf' else 'logical_text_page',
                    score=score,quote=text[start:end]))
            candidates.sort(key=lambda r:(-r['score'],r['sha256'],r['page']))
            result[firm]=candidates[:5]
            print(firm, json.dumps(candidates[:1],ensure_ascii=False))
        write_json(BASE/'definition_candidates.json',result)
        return
    if a.command == 'verify':
        from status_resolve import status_policy
        policy, _, _ = status_policy()
        blocked = holdouts(); verified = set()
        for firm, entry in policy['publishers'].items():
            for era in entry['eras']:
                for label, mapping in era['labels'].items():
                    for proof in mapping.get('evidence', []):
                        sha = proof['sha256']
                        if sha in blocked: raise ValueError('Holdout definition denied')
                        key = (sha, proof['page'], proof['quote'])
                        if key in verified: continue
                        meta = json.loads((ROOT / 'local-cache/fulltext' / (sha + '.pages.json')).read_text())
                        page = next(p for p in meta['pages'] if p['page'] == proof['page'])
                        assert proof['quote'] in page['text'], (firm, label, proof)
                        verified.add(key)
        receipt={'verified_citations': len(verified), 'holdouts_opened': 0}
        write_json(BASE/'evidence_check.json',receipt)
        print(json.dumps(receipt))
        return
    current = census(a.firm if a.command=='labels' else None)
    if a.command == 'before':
        path = BASE / 'before.json'
        if path.exists(): raise FileExistsError('Baseline already frozen')
        write_json(path, current)
    if a.command in ('before', 'labels'):
        for firm, row in current.items():
            if a.firm and a.firm != firm: continue
            labels = Counter()
            for raw, count in row['labels'].items():
                value = json.loads(raw)
                labels[re.sub(r'\W+', '', value.casefold()) if value else '<missing>'] += count
            print(firm, row['rows'], row['raw'], json.dumps(dict(labels), ensure_ascii=False))
    if a.command == 'report': report(current)


def report(after):
    from status_resolve import status_mapping, status_policy
    before = json.loads((BASE / 'before.json').read_text())
    policy, _, fingerprint = status_policy()
    unmapped = []; listed = []; mapped = 0; distinct = 0
    missing_ids=[];added_ids=[];changed_raw=[];new_raw=[]
    out = ['# Status policy and extraction review', '',
           'Reproduce with `python3 -I scripts/findings/status_review.py report`; '
           'the immutable before census is `local-cache/phase4-status/before.json`. '
           'Coverage measures source labels extracted and canonical remediation states, not held-out accuracy. '
           'No held-out report or text was opened. The all-publisher table includes concurrent regeneration '
           'in iosiro and zokyo; recovered-status and finding-ID comparisons below cover only the assigned publishers.', '',
           '| Publisher | Rows before → after | Raw status before → after | Canonical coverage before → after |',
           '|---|---:|---:|---:|']
    for firm, row in after.items():
        old = before.get(firm, {'rows': 0, 'raw': 0, 'known': 0})
        percent = lambda r: f"{100*r['known']/r['rows']:.2f}%" if r['rows'] else '—'
        out.append(f"| {firm} | {old['rows']} → {row['rows']} | {old['raw']} → {row['raw']} | {percent(old)} → {percent(row)} |")
        previous=before.get(firm,{}).get('findings',{})
        now=row['findings']
        if firm in TARGETS:
            missing_ids.extend(sorted(set(previous)-set(now)));added_ids.extend(sorted(set(now)-set(previous)))
            for fid in sorted(set(previous)&set(now)):
                if previous[fid][0] is None and now[fid][0] is not None:new_raw.append(fid)
                elif previous[fid][0]!=now[fid][0]:changed_raw.append(fid)
        labels = set(row['labels']) | set(before.get(firm, {}).get('labels', {}))
        for label in sorted(labels):
            if label == 'null': continue
            distinct += 1
            m = status_mapping(json.loads(label), firm, log=False)
            if m['mapped']: mapped += 1
            elif m.get('listed'): listed.append({'publisher':firm,'label':json.loads(label),'reason':m['rationale']})
            else: unmapped.append({'publisher': firm, 'label': json.loads(label), 'reason': m['reason']})
    out += ['', f'Publisher/label pairs mapped: **{mapped}/{distinct}**. Explicitly listed: **{len(listed)}**. Unaccounted pairs: **{len(unmapped)}**.', '',
            'Missing labels resolve to `not_stated`. Disputed/invalid/no-issue dispositions do not establish '
            'remediation and also resolve to `not_stated`, retaining their original label and rationale. '
            'Acknowledgement/confirmation/risk acceptance alone never proves a fix.', '',
            'Policy fingerprint: `' + fingerprint + '`.', '', '## Unaccounted labels', '']
    out += [f"- {r['publisher']}: `{r['label']}` ({r['reason']})" for r in unmapped] or ['None.']
    out += ['', '## Reviewed publisher decisions', '',
            '| Publisher | Native label | Canonical status | Evidence and rationale |', '|---|---|---|---|']
    from status_resolve import canonicalize_label
    for firm,raw in [('abdk-consulting','Info'),('code4rena','Confirmed'),('code4rena','Acknowledged'),
                     ('code4rena','Disputed'),('sherlock','Fixed'),('sherlock',"Won't fix"),
                     ('sherlock','Acknowledged'),('oxorio','NO_ISSUE'),('oxorio','Invalid'),
                     ('macro','Wont Do'),('verichains','Acknowledged and fixed'),
                     ('chainsecurity','Code Corrected'),('chainsecurity','Risk Accepted')]:
        choices=[m for era in policy['publishers'][firm]['eras'] for label,m in era['labels'].items()
                 if canonicalize_label(label)==canonicalize_label(raw)]
        m=choices[0];proof=m['evidence'][0] if m['evidence'] else None
        cite=(f"[`{proof['sha256']}`, p. {proof['page']}]({proof['public_url']})" if proof else 'No native definition located')
        out.append(f"| {firm} | {raw} | {m['normalized']} | {cite}. {m['rationale']} |")
    out += ['', '## Extraction changes and verification', '',
            f'Previously missing raw statuses recovered on **{len(new_raw)}** existing rows. '
            f'Other raw assertions changed on **{len(changed_raw)}** rows. '
            f'Finding IDs added: **{len(added_ids)}**; removed: **{len(missing_ids)}**. '
            'Status originals remain verbatim; normalized output is restricted to the five policy buckets.', '',
            'Rebuild the assigned publishers with `python3 scripts/findings/run.py --firms '+ ' '.join(TARGETS)+'`, '
            'then compile `python3 -I -S scripts/findings/status_map_build.py`, '
            'refresh all central receipts with `python3 -I -S scripts/findings/status_review.py refresh`, '
            'verify source citations with `status_review.py verify`, and run `python3 scripts/findings/check.py --statuses-only` '
            'for the status-specific corpus check; the full `check.py` also checks unrelated extraction/layout invariants.', '',
            'The new regression suite is `python3 -I -S scripts/findings/test_status_resolve.py`. '
            'The affected-publisher suite and result are `status_review.py scoped-tests` and '
            '`local-cache/phase4-status/scoped_tests.json`; the all-row status validation receipt is '
            '`data/findings/status_check.json`. '
            'The full-suite receipt is `local-cache/phase4-status/tests.json`; the broad suite retains '
            'the recorded Oxorio/Veridise baseline failures and an unrelated group-2 fixture-contract failure. '
            'The earlier full checker run did not finish successfully during the policy refresh; '
            'the completed status-only check validates the final policy and all current row receipts. '
            'No other publisher’s module was changed by this task. DuckDB build tests require the unavailable '
            '`duckdb` dependency and were not run.', '',
            '## Assigned-publisher layout coverage', '',
            '| Publisher / layout | Rows | Raw status before → after |', '|---|---:|---:|']
    for firm in TARGETS:
        if firm not in after:continue
        old=before.get(firm,{}).get('variants',{})
        for variant,v in after[firm]['variants'].items():
            previous=old.get(variant,{}).get('raw')
            out.append(f"| {variant} | {v['rows']} | {previous if previous is not None else 'new layout'} → {v['raw']} |")
    status_check=json.loads((ROOT/'data/findings/status_check.json').read_text())
    scoped=json.loads((BASE/'scoped_tests.json').read_text())
    evidence_check=json.loads((BASE/'evidence_check.json').read_text())
    out += ['', f"Final status validation: **{status_check['rows']}** rows and **{status_check['source_spans_verified']}** exact source status spans; "
            f"**{evidence_check['verified_citations']}** policy citations verified. "
            f"Affected-publisher/resolver tests: **{scoped['tests']}**, failures **{scoped['failures']}**, errors **{scoped['errors']}**. "
            'No held-out original or text was opened.', '']
    out += ['', '## Evidence limits and listed labels', '',
            'Formal native status legends were located for '+', '.join(sorted({firm for firm,e in policy['publishers'].items() if any(m['definition_basis']=='native_definition' for era in e['eras'] for m in era['labels'].values())}))+'. '
            'Other entries cite native usage and are marked `native_example_only`; these citations are not claimed to be formal definitions. '
            'Unsupported or truncated narrative labels remain `listed_unresolved` and resolve to `not_stated`. '
            'The complete original spellings, citations and per-label rationale are retained in the YAML/JSON, including presentation aliases.', '']
    grouped=defaultdict(list)
    for row in listed:grouped[row['publisher']].append(row['label'])
    for firm,labels in sorted(grouped.items()):
        out += [f'### {firm}', '', *['- '+json.dumps(label,ensure_ascii=False) for label in labels], '']
    (ROOT / 'docs/phase4/status_map.md').write_text('\n'.join(out) + '\n')
    write_json(BASE / 'after.json', after)
    write_json(BASE / 'coverage.json', {'distinct': distinct, 'mapped': mapped, 'listed':listed,'unmapped': unmapped,
                                       'recovered_raw_rows':len(new_raw),'changed_raw_rows':len(changed_raw),
                                       'added_ids':added_ids,'removed_ids':missing_ids,
                                       'holdouts_opened': 0, 'map_sha256': fingerprint})
    sources=['schema/README.md','schema/corpus.sql','schema/status_map.json','schema/status_map.json',
             'scripts/build/build_db.py','scripts/findings/core.py','scripts/findings/run.py','scripts/findings/check.py',
             'scripts/findings/status_resolve.py','scripts/findings/status_map_build.py',
             'scripts/findings/status_review.py','scripts/findings/test_status_resolve.py',
             'docs/phase4/status_map.md','docs/phase4/status_map_files_written.txt']
    sources += ['scripts/findings/parsers/'+firm.replace('-','_')+'.py' for firm in TARGETS]
    generated=['data/findings/_unknown_layouts.jsonl']
    generated += ['data/findings/'+firm+'.jsonl' for firm in after]
    generated += ['data/findings/validation/'+firm+'.jsonl' for firm in after]
    generated += ['data/findings/validation/'+firm+'.json' for firm in TARGETS]
    generated += ['data/findings/status_check.json']
    generated += [str(path.relative_to(ROOT)) for path in BASE.glob('*.json')]
    (ROOT/'docs/phase4/status_map_files_written.txt').write_text('\n'.join(sorted(sources+generated))+'\n')
    print(json.dumps({'distinct': distinct, 'mapped': mapped, 'listed':len(listed),'unmapped': len(unmapped)}))


if __name__ == '__main__': main()
