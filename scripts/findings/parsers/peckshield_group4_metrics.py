"""Reproduce group 4 before/after development metrics and scoped integrity checks.

Run after scoped run.py regeneration. Before executes the original Phase 4a parser
rules against the same frozen inputs; it never uses held-out texts or finding rows.
"""
from collections import Counter, defaultdict
import importlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import ROOT, SEVERITIES, digest, holdouts, read_snapshot, uid, write_json
from core import Candidate, Report, SEV, clean, field_severity, finish, is_toc, numbered_metadata, severity
from parsers import generic
from summary_counts import printed_counts as common_counts

FIRMS = tuple('peckshield verichains zokyo solidified certora pessimistic sigma-prime decurity teamomega movebit ncc-group scalebit'.split())


def baseline_parse(r):
    if r.firm=='peckshield':return numbered_metadata(r,levels=(2,))
    if r.firm=='verichains':
        out=[]
        for i,l in enumerate(r.lines):
            if is_toc(l):continue
            m=re.match(r'^(2\.2\.\d+)\.?(?:\s+)(.+)',l.content)
            if m:out.append(Candidate(l.start,m[2],field_severity(r.near(i,7)),m[1]))
        return out
    if r.firm=='zokyo':
        out=[];active=False
        for i,l in enumerate(r.lines):
            if re.fullmatch(r'complete\s*analysis',l.content.replace('\u200b',''),re.I):active=True
            if is_toc(l):continue
            m=re.match(r'^('+SEV+r')\s*[-–]\s*(\d+)\s+(Resolved|Unresolved|Acknowledged|Fixed|Partially Resolved|Open)\b',l.content,re.I)
            if m:
                title=next((x.content for x in r.lines[i+1:i+8] if x.content),None)
                if title:out.append(Candidate(l.start,title,m[1],m[1]+'-'+m[2],status_raw=m[3]))
                continue
            if active and re.fullmatch(SEV,l.content,re.I):
                title=next((x.content for x in r.lines[i+1:i+10] if x.content),None)
                if title and not re.fullmatch(SEV,title,re.I):out.append(Candidate(l.start,title,l.content))
        return out
    return generic.parse(r)


def reference(r,parser):
    """Separate printed inventory where available; never use parsed rows as expected."""
    if hasattr(parser,'sequence_evidence'):
        seq=parser.sequence_evidence(r)
        if seq:
            return seq
    if r.firm in {'certora','solidified','pessimistic'}:
        from parsers.certora_metrics import expected_sequence
        entries,basis=expected_sequence(r)
        return {'ids':[e['key'] for e in entries],'basis':basis,'mode':'title_or_id'} if entries else None
    if r.firm in {'sigma-prime','decurity','teamomega'}:
        from parsers.sigma_prime_metrics import expected_sequence
        ids,basis=expected_sequence(r)
        ids=[x for x in ids if x not in {'ERC20','ERC721','ERC1155'}]
        return {'ids':ids,'basis':basis,'mode':'printed_id_only'} if ids else None
    if r.firm=='ncc-group':
        active=False;ids=[]
        for l in r.lines:
            if re.search(r'^Title\s+.*\bID\s+Risk\b',l.content):active=True;continue
            if active and re.search(r'Finding Details|^Finding\s+(?!Breakdown)|Overall Risk|^Risk\s',l.content):break
            if active:
                m=re.search(r'\b([A-Z0-9]{3}|\d{1,3})\s+(?:Critical|High|Medium|Low|Informational)\s*$',l.content)
                if m:ids.append(m[1])
        return {'ids':ids,'basis':'printed_finding_index_id_suffixes','mode':'id_suffix'} if ids else None
    if r.firm in {'peckshield','movebit','scalebit'}:
        text=r.text
        if r.firm=='peckshield':
            from parsers.peckshield import match_text
            text=match_text(text);pattern=r'\bPVE-\d+\b'
        else:pattern=r'\b[A-Z][A-Z0-9_]{0,20}-\d{1,3}\b'
        ids=sorted(set(re.findall(pattern,text)) - {'SHA-1','SHA-256','ERC-20','ERC-721'})
        return {'ids':ids,'basis':'all_printed_native_ids_including_overview_and_references','mode':'set_inventory'} if ids else None
    return None


def sequence(rows,ref):
    if not ref:return None
    actual=[c.printed_id or clean(c.title+(' ('+c.status_raw+')' if c.status_raw else '')) for c in rows if c.record_kind=='formal_finding']
    mode=ref.get('mode')
    if mode=='printed_id_only':
        actual=[c.printed_id for c in rows if c.record_kind=='formal_finding' and c.printed_id is not None]
    if mode=='id_suffix':actual=[x.rsplit('-',1)[-1] for x in actual]
    if 'ids' in ref:
        expected=ref['ids']
        # Exact inventory equality detects missing tails as well as interior gaps.
        if mode=='set_inventory':
            ok=set(actual)==set(expected) and len(actual)==len(set(actual))
        elif mode=='subset_inventory':
            # Some numbered TOCs include grouping headers. Require every actual
            # detail ID in the TOC and every TOC ID inside its detail section range.
            sections={'.'.join(x.split('.')[:-1]) for x in actual}
            if sections:
                expected=[x for x in expected if '.'.join(x.split('.')[:-1]) in sections]
            ok=Counter(actual)==Counter(expected)
        else:ok=Counter(actual)==Counter(expected)
        return {'complete':ok,'basis':ref['basis'],'expected':expected,'actual':actual}
    return {'complete':len(actual)==ref['expected_count'] and ref.get('ordinals_complete',True),'basis':ref['basis'],
            'expected_count':ref['expected_count'],'actual_count':len(actual),'limitation':ref.get('limitation')}


def measure(r,candidates,summary,ref):
    rows=finish(r,candidates)
    formal=[c for c in rows if c.record_kind=='formal_finding']
    counts=Counter(c.normalized or severity(c.severity_raw) for c in formal)
    comparable=bool(summary) and not summary.get('ambiguous')
    return {'findings':len(rows),'formal_findings':len(formal),'counts':dict(counts),
            'summary_available':bool(summary),'summary_ambiguous':bool(summary and summary.get('ambiguous')),
            'summary_basis':summary.get('basis') if summary else None,
            'summary_counts':summary['counts'] if comparable else None,
            'summary_match':all(counts[k]==v for k,v in summary['counts'].items()) if comparable else None,
            'sequence':sequence(formal,ref),'missing_title':sum(not clean(c.title or '') for c in rows),
            'missing_severity':sum(not c.severity_raw for c in rows),'unknown_severity':sum((c.normalized or severity(c.severity_raw))=='unknown' for c in rows)}


def aggregate(records,key):
    values=[r[key] for r in records if key in r]
    summaries=[v for v in values if v['summary_match'] is not None]
    no=[(r,r[key]) for r in records if key in r and not r[key]['summary_available']]
    seqs=[v['sequence'] for _,v in no if v['sequence'] is not None]
    audits=[v for r,v in no if r['doc_kind']=='audit_report']
    allaudits=[r[key] for r in records if key in r and r['doc_kind']=='audit_report']
    def ratio(n,d):return round(100*n/d,2) if d else None
    return {'documents':len(records),'readable_documents':len(values),'findings':sum(v['findings'] for v in values),
            'summary_ambiguous':sum(v['summary_ambiguous'] for v in values),'extraction_errors':sum(key not in r for r in records),
            'formal_findings':sum(v['formal_findings'] for v in values),
            'summary_matching':sum(v['summary_match'] for v in summaries),'summary_comparable':len(summaries),
            'summary_agreement_percent':ratio(sum(v['summary_match'] for v in summaries),len(summaries)),
            'all_audit_documents':len(allaudits),'all_audit_with_formal_findings':sum(v['formal_findings']>0 for v in allaudits),
            'all_audit_coverage_percent':ratio(sum(v['formal_findings']>0 for v in allaudits),len(allaudits)),
            'no_summary_documents':len(no),'sequence_complete':sum(v['complete'] for v in seqs),'sequence_comparable':len(seqs),
            'sequence_percent':ratio(sum(v['complete'] for v in seqs),len(seqs)),
            'no_summary_sequence_unavailable':sum(v['sequence'] is None for _,v in no),
            'no_summary_audit_with_findings':sum(v['formal_findings']>0 for v in audits),'no_summary_audit_documents':len(audits),
            'no_summary_audit_coverage_percent':ratio(sum(v['formal_findings']>0 for v in audits),len(audits)),
            'missing_title_rows':sum(v['missing_title'] for v in values),'missing_severity_rows':sum(v['missing_severity'] for v in values),
            'unknown_severity_rows':sum(v['unknown_severity'] for v in values)}


def study_rows(docs):
    unique=sorted({d['row']['sha256']:d for d in docs}.values(),key=lambda d:(d['row'].get('date_hint') or '',d['row']['filename']))
    chosen={d['row']['sha256'] for d in unique} if len(unique)<=15 else {unique[round(i*(len(unique)-1)/14)]['row']['sha256'] for i in range(15)}
    # Include every known calendar era, even if quantiles skip a sparse early year.
    years={}
    for d in unique:years.setdefault((d['row'].get('date_hint') or 'unknown')[:4],d['row']['sha256'])
    return chosen|set(years.values())


def check_outputs(all_docs):
    """Scoped equivalent of the global checker; safe during concurrent publishers' writes."""
    blocked=holdouts();parents={d['document_id']:d for d in all_docs};seen=set();n=0;by_firm=Counter()
    for f in FIRMS:
        bydoc=defaultdict(Counter);rowcounts=Counter();cached=None;text=None;meta=None
        with (ROOT/'data/findings'/(f+'.jsonl')).open() as stream:
            for line in stream:
                row=json.loads(line);sha=row['sha256'];assert sha not in blocked
                d=parents[row['document_id']];assert row['publisher_id']==row['firm_id']==d['row']['firm_id']==f
                assert sha==d['row']['sha256'] and row['source_record_sha256']==d['source_record_sha256']
                assert row['finding_id']==uid('finding',row['source_tag'],row['source_record_id']) and row['finding_id'] not in seen
                seen.add(row['finding_id'])
                if cached!=sha:
                    text=(ROOT/'local-cache/fulltext'/(sha+'.txt')).read_bytes().decode('utf-8')
                    meta=json.loads((ROOT/'local-cache/fulltext'/(sha+'.pages.json')).read_text());cached=sha
                    assert digest(text.encode())==meta['text_sha256']
                a,b=row['body_span']['start'],row['body_span']['end'];assert 0<=a<b<=len(text)
                assert text[a:b]==row['body_text']
                assert row['body_span']['text_sha256']==meta['text_sha256']
                pages=[p['page'] for p in meta['pages'] if p['end']>a and p['start']<b]
                assert row['page']==pages[0] and row['body_span']['pages']==pages
                assert row['severity']==row['severity_normalized'] and row['severity'] in SEVERITIES
                assert row['severity_raw']==row['severity_original']
                assert digest(row['provenance']['extraction_record'])==row['provenance']['extraction_record_sha256']
                rowcounts[row['document_id']]+=1
                if row['record_kind']=='formal_finding':bydoc[row['document_id']][row['severity']]+=1
                n+=1
                by_firm[f]+=1
        diagnostics=[json.loads(l) for l in (ROOT/'data/findings/validation'/(f+'.jsonl')).read_text().split('\n') if l]
        assert {d['document_id'] for d in diagnostics}=={d['document_id'] for d in all_docs if d['row']['firm_id']==f}
        for d in diagnostics:
            assert d['sha256'] not in blocked
            assert d.get('findings',0)==rowcounts[d['document_id']]
            if d['validation'] in {'match','mismatch'}:
                s=d['printed_summary'];counts=bydoc[d['document_id']]
                assert (d['validation']=='match')==all(counts[k]==v for k,v in s['counts'].items())
                for e in s['evidence']:
                    if 'text' in e:
                        sha=d['sha256'];assert sha not in blocked
                        t=(ROOT/'local-cache/fulltext'/(sha+'.txt')).read_bytes().decode('utf-8')
                        assert t[e['start']:e['end']]==e['text'],(f,sha,'summary evidence span')
    return {'ok':True,'finding_rows_checked':n,'finding_rows_by_publisher':dict(by_firm),'holdout_rows':0,'checks':'parent receipts, finding identities, body/text hashes and bounds, pages, severity aliases, diagnostics, exact summary evidence spans'}


def evaluate():
    blocked=holdouts();docs=[d for d in read_snapshot() if d['row']['firm_id'] in FIRMS]
    output={'holdouts_opened':0,'input_snapshot_sha256':digest((ROOT/'data/fulltext/input_documents.jsonl').read_bytes()),
            'holdout_list_sha256':digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes()),'publishers':{}}
    for f in FIRMS:
        parser=importlib.import_module('parsers.'+f.replace('-','_'));records=[];study=[]
        firmdocs=[d for d in docs if d['row']['firm_id']==f];selected=study_rows(firmdocs);sampled=set();cache={}
        for d in firmdocs:
            row=d['row'];sha=row['sha256'];assert sha not in blocked
            rec={k:row.get(k) for k in ('sha256','filename','doc_kind','date_hint','public_url')};rec['document_id']=d['document_id']
            if sha not in cache:
                cache.clear();p=ROOT/'local-cache/fulltext'/(sha+'.txt');mp=p.with_suffix('.pages.json')
                if not p.exists() or not mp.exists():rec['error']='cache_missing';records.append(rec);continue
                meta=json.loads(mp.read_text())
                if meta.get('status') not in {'ok','partial'}:rec['error']=meta.get('error',meta.get('status'));records.append(rec);continue
                text=p.read_bytes().decode('utf-8');assert digest(text.encode())==meta['text_sha256']
                r=Report(text,meta,f);ref=reference(r,parser)
                before=measure(r,baseline_parse(r),common_counts(r),ref)
                summary=getattr(parser,'printed_counts',common_counts)(r)
                after=measure(r,parser.parse(r),summary,ref)
                cache[sha]=(r,before,after)
            r,before,after=cache[sha];rec|={'before':before,'after':after};records.append(rec)
            if sha in selected and sha not in sampled:
                sampled.add(sha)
                headings=[l.content for l in r.lines if re.search(r'ID:|Severity:|Risk Level:|Overall Risk|Rating\s|^## [HML]-|^\s*\d+\.\d+',l.content)]
                study.append({'sha256':sha,'filename':row['filename'],'date_hint':row.get('date_hint'),'pages':len(r.meta['pages']),
                              'evidence_examples':headings[:3]+headings[-3:],'text_sha256':r.meta['text_sha256']})
        output['publishers'][f]={'before':aggregate(records,'before'),'after':aggregate(records,'after'),'distinct_originals':len({d['row']['sha256'] for d in firmdocs}),
                                 'study_manifest':study,'documents':records}
        print(f,{k:output['publishers'][f]['after'][k] for k in ('findings','summary_agreement_percent','sequence_percent','no_summary_audit_coverage_percent')},flush=True)
    output['integrity']=check_outputs(docs)
    for f in FIRMS:
        assert output['publishers'][f]['after']['findings']==output['integrity']['finding_rows_by_publisher'].get(f,0),(f,'regenerate output after parser changes')
    return output


def write_report(data):
    def fraction(d,key1,key2,percent):
        return f"{d[key1]}/{d[key2]} ({d[percent]:.2f}%)" if d[key2] else 'N/A (0 comparable)'
    lines=['# Phase 4b — group 4 development extraction', '',
      'Generated by `python3 scripts/findings/parsers/peckshield_group4_metrics.py`. The frozen Phase 4a snapshot is unchanged. All holdout hashes are removed before cache access. These are development checks, not held-out accuracy or vulnerability deduplication.', '',
      'Before re-executes the original dedicated/generic parser rules against the same cache. After uses the publisher modules and their independent summary readers. Summary denominators can increase when a publisher-specific reader recovers previously unrecognized tables. Equality is required in every printed bucket; no detail rows or severities are changed to force a match.', '',
      '| Publisher | Docs / originals | Rows before → after | Summary before → after | No-summary sequence after | No-summary audit ≥1 finding | Ambiguous / extraction errors | Missing title / raw severity / unknown bucket after |',
      '|---|---:|---:|---|---|---|---:|---:|']
    for f,d in data['publishers'].items():
        b,a=d['before'],d['after']
        lines.append(f"| {f} | {a['documents']} / {d['distinct_originals']} | {b['findings']} → {a['findings']} | {fraction(b,'summary_matching','summary_comparable','summary_agreement_percent')} → {fraction(a,'summary_matching','summary_comparable','summary_agreement_percent')} | {fraction(a,'sequence_complete','sequence_comparable','sequence_percent')} | {fraction(a,'no_summary_audit_with_findings','no_summary_audit_documents','no_summary_audit_coverage_percent')} | {a['summary_ambiguous']} / {a['extraction_errors']} | {a['missing_title_rows']} / {a['missing_severity_rows']} / {a['unknown_severity_rows']} |")
    lines+=['','Sequence checks use a separate printed TOC/index when available. The JSON records each basis, expected inventory, actual inventory and limitation. Zokyo badge censuses check structural coverage when no independent index exists; they are weaker than recall. MoveBit/ScaleBit component IDs can number globally across prefixes or restart per component, so exact printed ID inventory equality avoids imposing the wrong sequence. NCC Group uses opaque identifiers, checked against its printed index rather than a fabricated numeric sequence. Documents without a reference sequence are reported explicitly in JSON and are never counted as sequence-complete. A clean audit may legitimately have zero findings; the requested ≥1 coverage metric keeps it in the raw audit denominator.','',
      'ScaleBit has only the frozen set of local documents shown above; all are studied. It cannot satisfy a requirement to study 15 distinct documents without additional acquisition. Study manifests include date hints, original/text hashes, pages and representative layout evidence; sparse early years are selected in addition to deterministic date quantiles.','',
      '## Residuals and limits','',
      'The following queues retain every mismatch, incomplete sequence, unavailable reference, extraction failure and zero-finding report in `data/findings/group4_metrics.json`. No unresolved class is silently excluded to meet a threshold. Independent summary/detail contradictions remain mismatches. Missing risk labels and icon-only severities remain unknown.','','<!-- GROUP4_NOTES -->','',
      '## Reproduce and verify','',
      '```sh',
      'python3 scripts/findings/run.py --firms '+ ' '.join(FIRMS),
      'python3 scripts/findings/parsers/peckshield_group4_metrics.py',
      'PYTHONPATH=scripts/findings python3 scripts/findings/parsers/test_group4_parent.py',
      'PYTHONPATH=scripts/findings python3 scripts/findings/parsers/test_verichains_zokyo.py',
      'PYTHONPATH=scripts/findings python3 scripts/findings/parsers/test_solidified_certora_pessimistic.py',
      'PYTHONPATH=scripts/findings python3 scripts/findings/parsers/test_sigma_prime_decurity_teamomega.py',
      '```','',
      'The metrics command validates only these publishers, avoiding races with other processes writing outputs. It verifies holdout exclusion, parent receipts, identities, exact source body spans/hashes/pages, severity aliases, count accounting and exact summary evidence spans. Shared changes required by this group: dispatch registrations in `parsers/__init__.py`; the optional per-parser `printed_counts` hook in `run.py`; exact status aliases `acked`, `not resolved`, `in progress`, and footnoted `resolved*` in `core.py`. Other concurrent shared edits are preserved.','',
      'Machine-readable metrics and every per-document residual: [group4_metrics.json](../../data/findings/group4_metrics.json).','']
    # Preserve human-reviewed notes, while every number above is regenerated.
    notes=ROOT/'docs/phase4/group4_notes.md'
    if notes.exists():lines=[x.replace('<!-- GROUP4_NOTES -->',notes.read_text().strip()) for x in lines]
    path=ROOT/'docs/phase4/group4.md';path.parent.mkdir(parents=True,exist_ok=True);path.write_text('\n'.join(lines))


def write_manifest(data):
    files=[f'scripts/findings/parsers/{f.replace("-","_")}.py' for f in FIRMS]
    files += ['scripts/findings/parsers/'+name+'.py' for name in (
        'peckshield_group4_metrics','verichains_metrics','certora_metrics','sigma_prime_metrics',
        'test_group4_parent','test_verichains_zokyo','test_solidified_certora_pessimistic','test_sigma_prime_decurity_teamomega')]
    files += ['scripts/findings/core.py','scripts/findings/run.py','scripts/findings/parsers/__init__.py']
    files += [f'data/findings/{f}.jsonl' for f in FIRMS]
    files += [f'data/findings/validation/{f}.{ext}' for f in FIRMS for ext in ('json','jsonl')]
    files += ['data/findings/group4_metrics.json','docs/phase4/group4.md','docs/phase4/group4_notes.md','docs/phase4/group4_files_written.txt']
    data['files_written']=sorted(files)
    (ROOT/'docs/phase4/group4_files_written.txt').write_text('\n'.join(sorted(files))+'\n')


def main():
    data=evaluate();write_manifest(data);write_json(ROOT/'data/findings/group4_metrics.json',data);write_report(data)

if __name__=='__main__':main()
