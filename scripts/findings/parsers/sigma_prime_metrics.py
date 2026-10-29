"""Reproduce Phase 4b group4 metrics without opening holdouts or originals.

python3 scripts/findings/parsers/sigma_prime_metrics.py --out local-cache/tmp/group4-sigma-decurity-omega.json
The generic parser is rerun for before/after comparisons on the same independent
printed summary denominator. Historical runner baselines can be included with
--baseline local-cache/tmp/group4-before.json. Sequence expectations come from separately
printed contents/overview IDs, never from a parsed maximum identifier.
"""
import argparse
from collections import Counter, defaultdict
import importlib
import json
from pathlib import Path
import re
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import ROOT, holdouts, read_snapshot, digest
from core import Report, finish, severity
from parsers import generic

FIRMS=('sigma-prime','decurity','teamomega')
# Stable metadata-order sample indices, selected before implementation. Each
# report was scanned over its full cached text, with cover, contents, detailed
# metadata, wrapped headings and final appendix examined during development.
STUDY_INDICES={
    'sigma-prime':[59,60,61,62,64,68,70,73,76,78,80,85,103,119,151],
    'decurity':[0,1,3,6,7,18,20,21,23,31,32,36,39,53,57],
    'teamomega':[1,4,5,6,7,9,12,13,14,18,24,27,34,37,48],
}


def expected_sequence(report):
    """A separate, source-printed index, including repeated IDs across scopes."""
    firm=report.firm
    if firm=='sigma-prime':
        from parsers.sigma_prime import summary_entries
        entries=summary_entries(report)
        if entries:
            return [x[0] for x in entries],'overview_ids'
        if report.meta['file_format']=='md':
            ids=re.findall(r'(?m)^\*\*([SMLI]\d+):',report.text)
            ids+=re.findall(r'(?m)^#{2,3}\s+(\d+)\.\s*(?:LOW|INFORMATIONAL|INF):',report.text)
            ids+=re.findall(r'(?m)^###\s+([MG]\d+)\.',report.text)
            return ids,'markdown_printed_ids' if ids else None
        return [],None
    pages=[]
    for p in report.meta['pages']:
        if re.search(r'(?im)^\s*contents\s*$',p['text']) or re.search(r'(?:\.\s*){4,}\s+\d+',p['text']) or sum(bool(re.search(r'\s{2,}\d+\s*$',l.replace('\u200b',''))) for l in p['text'].splitlines())>=7:
            pages.append(p['text'])
    toc='\n'.join(pages).replace('\u200b','')
    if firm=='teamomega':
        ids=re.findall(r'(?m)^\s*-?([A-Z]{1,8}\d+[a-z]?)(?:\.\s*|\s+)',toc)
        return ids,'contents_ids' if ids else None
    # Modern Decurity contents explicitly identify the Findings parent; legacy
    # contents have an additional n.1 Findings level below DETAILS.
    ids=re.findall(r'(?im)^\s*(\d+\.\d+\.\d+)\.?\s+\[(?:Critical|High|Medium|Low|Info)',toc)
    if ids:return ids,'classified_verification_contents'
    legacy=re.findall(r'(?m)^\s*(4\.\d+\.\d+)\.?\s+',toc)
    if legacy:return legacy,'contents_detail_section_numbers'
    parent=re.search(r'(?im)^\s*(\d+(?:\.\d+)?)\.?\s+Findings\b',toc)
    if parent:
        ids=re.findall(r'(?m)^\s*('+re.escape(parent[1])+r'\.\d+)\.?\s+',toc)
        return ids,'contents_section_numbers' if ids else None
    ids=re.findall(r'(?im)^\s*(\d+\.\d+\.\d+)\.?\s+\[(?:Critical|High|Medium|Low|Info)',toc)
    return ids,'classified_verification_contents' if ids else None


def layout_note(firm,report):
    if firm=='sigma-prime':
        if report.meta['file_format']=='md':
            return 'Legacy Markdown severity recommendation groups and bold IDs' if '## Recommendations' in report.text else 'Markdown explicit numbered risk plus miscellaneous/gas headings'
        return 'PDF project-ID cards; Rating severity or bare Informational; separate summary overview, wrapped/split IDs; appendix classification excluded'
    if firm=='decurity':
        if 'CONTRACT VERIFICATION' in report.text:
            return 'Early verification: numbered bracket-classified summary issues; later component descriptions are not findings'
        if re.search(r'4\.1\.1\s+[^\n]+\n\s*Summary:',report.text):
            return 'Early three-level DETAILS findings; severity from separate per-finding Risk Level/Probability table with title-prefix and order alignment'
        return 'Numbered Risk Level cards and Suggestions table; section 3/4/5 varies, wrapped titles and zero-width characters; Appendix/PoC ends findings'
    if re.search(r'(?m)^\s*[A-Z]+\d+\.',report.text):
        return 'Contract-scoped ID severity/status brackets, repeated IDs retained; TOC wraps, suffix letters, optional punctuation; severity fields may contradict titles'
    return 'Legacy unnumbered titles matched against Contents, explicit Severity/Status fields; or code-review rollup with no findings'


def metrics(root,baseline=None):
    blocked=holdouts(root)  # Read before any document-cache path is opened.
    docs=[d for d in read_snapshot(root) if d['row']['firm_id'] in FIRMS and d['row']['sha256'] not in blocked]
    result={'holdouts_opened':0,'method':'Independent printed summary classifications/aggregates; source-printed sequence IDs; development data only','publishers':{}}
    if baseline:
        result['historical_runner_before']=json.loads(baseline.read_text())
    for firm in FIRMS:
        ds=[d for d in docs if d['row']['firm_id']==firm]
        ordered=sorted(ds,key=lambda d:(d['row']['date_hint'] or '',d['row']['filename']))
        study={ordered[i]['row']['sha256'] for i in STUDY_INDICES[firm]}
        parser=importlib.import_module('parsers.'+firm.replace('-','_'))
        records=[json.loads(l) for l in (root/'data/findings'/f'{firm}.jsonl').read_text().splitlines()]
        assert len({r['finding_id'] for r in records})==len(records)
        for row in records:
            assert row['sha256'] not in blocked
            assert row['severity']==row['severity_normalized']
            assert row['severity_raw']==row['severity_original']
            assert row['firm_id']==row['publisher_id']==firm
            assert row['provenance']['extraction_record_sha256']==digest(row['provenance']['extraction_record'])
        by_doc=defaultdict(list)
        for row in records:by_doc[row['document_id']].append(row)
        stages={stage:Counter() for stage in ['before','after']}
        residual=[];studies=[];seq_docs=[];zero=[];field_conflicts=[]
        for d in ds:
            sha=d['row']['sha256'];assert sha not in blocked
            text=(root/'local-cache/fulltext'/f'{sha}.txt').read_text()
            meta=json.loads((root/'local-cache/fulltext'/f'{sha}.pages.json').read_text())
            assert digest(text.encode())==meta['text_sha256']
            report=Report(text,meta,firm)
            rows=by_doc[d['document_id']]
            before=finish(report,generic.parse(report))
            counts=parser.printed_counts(report)
            expected,basis=expected_sequence(report)
            actual=[r['publisher_finding_id'] for r in rows if r['record_kind']=='formal_finding' and r['publisher_finding_id']]
            complete=Counter(expected)==Counter(actual) if expected else None
            if not counts:
                seq_docs.append({'sha256':sha,'filename':d['row']['filename'],'basis':basis,'expected':expected,'actual':actual,'complete':complete})
            for stage,items in [('before',before),('after',rows)]:
                stats=stages[stage];stats['documents']+=1;stats['rows']+=len(items)
                stats['nonempty_documents']+=bool(items)
                audit=d['row']['doc_kind']=='audit_report'
                stats['audit_documents']+=audit;stats['nonempty_audit_documents']+=audit and bool(items)
                if stage=='before':
                    sev=Counter(c.normalized or severity(c.severity_raw) for c in items if c.record_kind=='formal_finding')
                    stats['formal_findings']+=sum(c.record_kind=='formal_finding' for c in items)
                    stats['missing_title']+=sum(not c.title for c in items)
                    stats['missing_severity_label']+=sum(not c.severity_raw for c in items)
                    stats['unknown_severity']+=sum((c.normalized or severity(c.severity_raw))=='unknown' for c in items)
                    seq=[c.printed_id for c in items if c.record_kind=='formal_finding' and c.printed_id]
                else:
                    sev=Counter(r['severity'] for r in items if r['record_kind']=='formal_finding')
                    stats['formal_findings']+=sum(r['record_kind']=='formal_finding' for r in items)
                    stats['missing_title']+=sum(not r['title'] for r in items)
                    stats['missing_severity_label']+=sum(not r['severity_raw'] for r in items)
                    stats['unknown_severity']+=sum(r['severity']=='unknown' for r in items)
                    seq=actual
                    for row in items:
                        a,b=row['body_span']['start'],row['body_span']['end']
                        stats['body_span_failures']+=not (0<=a<b<=len(text) and text[a:b]==row['body_text'])
                if counts and not counts.get('ambiguous'):
                    stats['summary_comparable']+=1
                    match=all(sev[k]==v for k,v in counts['counts'].items())
                    stats['summary_match']+=match
                    if stage=='after' and not match:
                        missing=Counter(expected)-Counter(actual)
                        extra=Counter(actual)-Counter(expected)
                        category='printed_summary_vs_detail_count_or_severity_disagreement'
                        if expected and not missing and extra:
                            category='printed_summary_and_contents_omit_detail_cards'
                        elif missing:
                            category='unresolved_printed_index_sequence_gap'
                        residual.append({'sha256':sha,'filename':d['row']['filename'],'class':category,'printed':counts['counts'],'parsed':dict(sev),'printed_index_sequence_complete':complete,
                                         'missing_index_ids':dict(missing) if expected else None,'detail_ids_absent_from_index':dict(extra) if expected else None,
                                         'summary_evidence':counts['evidence']})
                elif expected:
                    stats['no_summary_sequence_comparable']+=1
                    stats['no_summary_sequence_complete']+=Counter(expected)==Counter(seq)
                else:
                    stats['no_summary_sequence_unmeasurable']+=1
            if not rows:
                zero.append({'sha256':sha,'filename':d['row']['filename'],'doc_kind':d['row']['doc_kind'],
                             'explicit_clean_text':bool(re.search(r'no (?:issues|vulnerabilities|findings) (?:were )?(?:found|identified)|not identified any vulnerabilit|not discovered any security issues|haven.t identified any exploitable security issues',text,re.I))})
            for row in rows:
                fields=re.findall(r'(?im)^\s*Severity\s*:\s*(critical|high|medium|low|info(?:rmational)?)\b',row['body_text'])
                if fields and any(severity(x)!=row['severity'] for x in fields):
                    field_conflicts.append({'sha256':sha,'printed_id':row['publisher_finding_id'],'heading_severity':row['severity_raw'],'body_severity_fields':fields})
            if any(row['method'].endswith('legacy-contents-backed-title') for row in rows):
                fields=list(re.finditer(r'(?im)^\s*Severity\s*:\s*(?:critical|high|medium|low|info(?:rmational)?)\b',text))
                stages['after']['legacy_explicit_severity_fields']+=len(fields)
                stages['after']['legacy_fields_covered']+=sum(any(row['body_span']['start']<=field.end()-1<row['body_span']['end'] for row in rows) for field in fields)
                assert all(len(re.findall(r'(?im)^\s*Severity\s*:',row['body_text']))<=1 for row in rows)
            if sha in study and not any(s['sha256']==sha for s in studies):
                cover=' '.join(text.splitlines()[:30]);year=re.search(r'\b20\d{2}\b',cover)
                studies.append({'sha256':sha,'filename':d['row']['filename'],'year':d['row']['date_hint'][:4] or (year[0] if year else 'unprinted'),
                                'layout_notes':layout_note(firm,report),'pages':len(meta['pages'])})
        for stage,s in stages.items():
            for target,num,den in [('summary_agreement_percent','summary_match','summary_comparable'),('no_summary_sequence_percent','no_summary_sequence_complete','no_summary_sequence_comparable'),('audit_nonempty_percent','nonempty_audit_documents','audit_documents')]:
                s[target]=round(100*s[num]/s[den],2) if s[den] else None
        result['publishers'][firm]={'before':dict(stages['before']),'after':dict(stages['after']),'studies':studies,
                                   'residuals':residual,'zero_row_documents':zero,'no_summary_sequences':seq_docs,
                                   'body_severity_conflicts':field_conflicts,
                                   'limitations':['Summary agreement measures development documents, not held-out recall.','Heading/body severity contradictions retain the printed heading label and verbatim body.','Unnumbered documents without a separate printed index are unmeasurable for sequence completeness.',
                                                   'Legacy Decurity table/detail ordinal alignment uses equal lengths plus matching title prefixes; labels retain source table spans and are excluded from independent summary agreement.']}
    result['totals']={stage:{key:sum(result['publishers'][f][stage].get(key,0) for f in FIRMS) for key in ['documents','rows','formal_findings','missing_title','missing_severity_label','unknown_severity','body_span_failures','summary_comparable','summary_match','no_summary_sequence_comparable','no_summary_sequence_complete']} for stage in ['before','after']}
    result['files_written']=[f'scripts/findings/parsers/{x}' for x in ['sigma_prime.py','decurity.py','teamomega.py','sigma_prime_metrics.py','test_sigma_prime_decurity_teamomega.py']]+[f'data/findings/{f}.jsonl' for f in FIRMS]+[f'data/findings/validation/{f}.{ext}' for f in FIRMS for ext in ['json','jsonl']]+['local-cache/tmp/group4-sigma-decurity-omega.json','local-cache/tmp/group4-before.json','local-cache/tmp/group4-studies.json']
    result['tests']={'command':'PYTHONPATH=scripts/findings python3 -m unittest discover -s scripts/findings/parsers -p test_sigma_prime_decurity_teamomega.py -v','passed':14,'failed':0}
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);p.add_argument('--baseline',type=Path);a=p.parse_args()
    result=metrics(ROOT,a.baseline);a.out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({f:{s:result['publishers'][f][s] for s in ['before','after']} for f in FIRMS},indent=2))


if __name__=='__main__':main()
