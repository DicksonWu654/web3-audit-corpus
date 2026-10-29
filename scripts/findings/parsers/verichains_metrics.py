"""Reproduce bounded Verichains/Zokyo development metrics, never opening holdouts.

python3 -I scripts/findings/parsers/verichains_metrics.py --evidence local-cache/tmp/group4-verichains-zokyo.json
The before rules are an exact frozen copy of the original small publisher parsers.
Comparisons use the same independent printed totals/indices for both rule versions.
"""
import argparse
from collections import Counter
import importlib
import json
from pathlib import Path
import re
import sys

BASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE))
from common import ROOT, holdouts, read_snapshot, digest
from core import Report, Candidate, SEV, finish, severity, is_toc, field_severity
from summary_counts import printed_counts as generic_counts


def load():
    blocked=holdouts(ROOT)  # Load before any report/cache paths are opened.
    seen=set()
    for d in read_snapshot(ROOT):
        row=d['row'];sha=row['sha256']
        if row['firm_id'] not in {'verichains','zokyo'} or sha in seen:continue
        if sha in blocked:raise RuntimeError('holdout denied')
        seen.add(sha)
        textpath=ROOT/'local-cache/fulltext'/(sha+'.txt');metapath=ROOT/'local-cache/fulltext'/(sha+'.pages.json')
        if textpath.exists() and metapath.exists():
            text=textpath.read_bytes().decode('utf-8');meta=json.loads(metapath.read_text())
            if digest(text.encode())!=meta['text_sha256']:raise ValueError('fulltext hash mismatch')
            yield d,Report(text,meta,row['firm_id'])


def baseline_parse(report):
    """Original Phase 4a rules, frozen before development; no changed parser calls."""
    out=[]
    if report.firm=='verichains':
        for i,line in enumerate(report.lines):
            if is_toc(line):continue
            m=re.match(r'^(2\.2\.\d+)\.?(?:\s+)(.+)',line.content)
            if m:
                raw=field_severity(report.near(i,7))
                out.append(Candidate(line.start,m[2],raw,m[1],method='verichains-numbered-detail',confidence=.8,
                    evidence={'severity_availability':'explicit_text' if raw else 'not_textual_or_absent'}))
    else:
        active=False
        for i,line in enumerate(report.lines):
            if re.fullmatch(r'complete\s*analysis',line.content.replace('\u200b',''),re.I):active=True
            if is_toc(line):continue
            m=re.match(r'^('+SEV+r')\s*[-–]\s*(\d+)\s+(Resolved|Unresolved|Acknowledged|Fixed|Partially Resolved|Open)\b',line.content,re.I)
            if m:
                title=next((l.content for l in report.lines[i+1:i+8] if l.content),None)
                if title:out.append(Candidate(line.start,title,m[1],m[1]+'-'+m[2],status_raw=m[3],method='zokyo-risk-card',confidence=.9))
                continue
            if active and re.fullmatch(SEV,line.content,re.I):
                title=next((l.content for l in report.lines[i+1:i+10] if l.content),None)
                if title and not re.fullmatch(SEV,title,re.I):out.append(Candidate(line.start,title,line.content,method='zokyo-legacy-severity-card',confidence=.75))
    return out


def aggregate(records):
    comparable=[r for r in records if r['summary_match'] is not None]
    seqs=[r for r in records if r['summary_match'] is None and r['sequence_match'] is not None]
    indexed=[r for r in seqs if r['sequence']['basis'].startswith('printed_')]
    nonempty=[r for r in records if (r['sequence'] and r['expected_count']>0) or (r['printed_summary'] and sum(r['printed_summary']['counts'].values())>0)]
    def ratio(rows,key):return round(100*sum(r[key] for r in rows)/len(rows),2) if rows else None
    return {'documents':len(records),'findings':sum(r['findings'] for r in records),
        'documents_with_findings':sum(bool(r['findings']) for r in records),'record_kinds':dict(sum((Counter(r['record_kinds']) for r in records),Counter())),
        'formal_missing_severity':sum(r['formal_missing_severity'] for r in records),
        'summary_comparable':len(comparable),'summary_matching':sum(r['summary_match'] for r in comparable),'summary_agreement_percent':ratio(comparable,'summary_match'),
        'sequence_comparable_without_counts':len(seqs),'sequence_matching_without_counts':sum(r['sequence_match'] for r in seqs),'sequence_agreement_percent_without_counts':ratio(seqs,'sequence_match'),
        'independent_printed_index_comparable_without_counts':len(indexed),'independent_printed_index_matching_without_counts':sum(r['sequence_match'] for r in indexed),'independent_printed_index_agreement_percent':ratio(indexed,'sequence_match'),
        'source_supported_nonempty_documents':len(nonempty),'source_supported_nonempty_documents_extracted':sum(bool(r['findings']) for r in nonempty),
        'nonempty_audit_coverage_percent':round(100*sum(bool(r['findings']) for r in nonempty)/len(nonempty),2) if nonempty else None,
        'missing_title':sum(r['missing_title'] for r in records),'missing_severity':sum(r['missing_severity'] for r in records),
        'unknown_severity':sum(r['unknown_severity'] for r in records),'missing_id':sum(r['missing_id'] for r in records),
        'span_validation_failures':sum(r['span_validation_failures'] for r in records),'records':records}


def evaluate(before=False):
    groups={'verichains':[],'zokyo':[]}
    for d,r in load():
        parser=importlib.import_module('parsers.'+r.firm)
        found=finish(r,baseline_parse(r) if before else parser.parse(r));counts=Counter(c.normalized or severity(c.severity_raw) for c in found if c.record_kind=='formal_finding')
        summary=parser.printed_counts(r);seq=parser.sequence_evidence(r)
        ids=seq.get('ids',[]) if seq else [];expected=len(ids) if ids else seq.get('expected_count',0) if seq else 0
        smatch=all(counts[s]==n for s,n in summary['counts'].items()) if summary and not summary.get('ambiguous') else None
        seqfound=[c for c in found if c.record_kind=='formal_finding'] if seq and seq['basis']=='legacy_risk_heading_census' else found
        sequence_counts_match=(Counter(ids)==Counter(c.printed_id for c in seqfound) if ids else len(seqfound)==expected) if seq else None
        seqmatch=(sequence_counts_match and seq.get('ordinals_complete',True)) if seq else None
        clean_match=re.search(r'(?:no (?:security )?(?:vulnerabilities|vulnerability issues?|vulnerable issues?) (?:were |was )?(?:discovered|identified|found)|did not (?:discover|identify) any (?:security )?vulnerability|(?:found|identified|discovered|detected) no (?:security )?(?:vulnerability|vulnerabilities|issues?)\b)',r.text,re.I)
        groups[r.firm].append({'sha256':d['row']['sha256'],'filename':d['row']['filename'],'date_hint':d['row'].get('date_hint'),
            'findings':len(found),'record_kinds':dict(Counter(c.record_kind for c in found)),
            'formal_missing_severity':sum(not c.severity_raw for c in found if c.record_kind=='formal_finding'),'parsed_counts':dict(counts),'printed_summary':summary,'summary_match':smatch,
            'sequence':seq,'expected_count':expected,'sequence_match':seqmatch,'sequence_counts_match':sequence_counts_match,
            'missing_title':sum(not c.title for c in found),'missing_severity':sum(not c.severity_raw for c in found),'unknown_severity':counts['unknown'],
            'missing_id':sum(not c.printed_id for c in found),'layout':parser.layout(r),'pages':len(r.meta['pages']),
            'source_clean_statement':clean_match[0] if clean_match else None,
            'span_validation_failures':sum(not (0<=c.start<c.end<=len(r.text)) for c in found),
            'sample_titles':[c.title for c in found[:3]],
            'unrecognized_risk_labels':sorted({c.severity_raw for c in found if c.severity_raw and (c.normalized or severity(c.severity_raw))=='unknown'})})
    return {firm:aggregate(records) for firm,records in groups.items()}


def residuals(records):
    result={}
    def add(kind,row,detail):result.setdefault(kind,[]).append({'sha256':row['sha256'],'filename':row['filename'],'detail':detail})
    for r in records:
        if r['summary_match'] is False:
            add('printed_aggregate_disagreement',r,{'printed':r['printed_summary']['counts'],'parsed':r['parsed_counts'],
                'classification':('aggregate_and_detail_severity_distribution_disagree' if sum(r['parsed_counts'].values())==sum(r['printed_summary']['counts'].values()) else 'explicit_detail_card_surplus_vs_printed_totals' if all(r['parsed_counts'].get(k,0)>=v for k,v in r['printed_summary']['counts'].items()) else 'printed_totals_exceed_textual_detail_badges_or_source_labels_differ'),
                'source_example':(r['printed_summary']['evidence'][0] if r['printed_summary'].get('evidence') else None),
                'detail_examples':r['sample_titles'],
                'note':'Scoring totals are source-labelled hypothetical; source contradictions and missing OCR card labels are not repaired with invented rows or relabelled severities.'})
        if r['sequence'] and r['sequence'].get('ordinals_complete') is False:
            add('source_summary_numbering_incomplete_or_OCR_omitted',r,{'ordinals':[e['ordinal'] for e in r['sequence'].get('entries',[])],'counts_match':r['sequence_counts_match'],'note':'Strict completeness fails despite equal cardinality when printed source-index ordinals are unreadable or missing.'})
        if r['summary_match'] is None and r['sequence_match'] is False:
            add('heading_or_index_sequence_disagreement',r,{'expected':r['expected_count'],'parsed':r['findings'],'basis':r['sequence']['basis'],'classification':'source_index_vs_textual_detail_sequence_gap','detail_examples':r['sample_titles']})
        if not r['findings']:
            add('zero_rows_with_clean_statement' if r['source_clean_statement'] else 'zero_rows_unvalidated',r,r['source_clean_statement'])
        if r['missing_severity']:add('nontextual_or_absent_severity',r,{'findings':r['missing_severity']})
        if r['unrecognized_risk_labels']:add('unrecognized_source_risk_labels',r,r['unrecognized_risk_labels'])
        if r['missing_title']:add('missing_title',r,r['missing_title'])
        if r['missing_id']:add('source_has_no_printed_id',r,r['missing_id'])
        if r['summary_match'] is None and not r['sequence']:add('no_printed_aggregate_or_sequence_evidence',r,r['findings'])
    return result


def samples(records):
    rows=sorted(records,key=lambda r:(r['date_hint'] or '',r['filename']))
    chosen=[rows[round(i*(len(rows)-1)/17)] for i in range(18)]
    notes={
        'modern-3.n-text-risk':'Modern numbered findings and adjacent issue table; textual risks and remediation labels; excludes overview/history.',
        'legacy-2.n-audit-result':'Legacy direct children of audit-result section; excludes scope, summary and version history.',
        'legacy-2.3-findings':'Contract-description section precedes findings; additional notes are detailed published entries, not contract descriptions.',
        'legacy-risk-heading-or-recommendation-bullets':'Early explicit risk badges and source recommendation bullets; conclusion and appendix material excluded.',
        '2.4-findings-icon-or-text-risk':'Findings section follows expanded scope sections; actual subsection IDs determine inclusion.',
        '2.2-findings-icon-or-text-risk':'Numbered detail headings checked against TOC; icon-only risks remain unknown; source updates retained.',
        'numbered-risk-status-cards':'Risk-number cards, wrapped titles and statuses; summary continuation and code-coverage/test appendices excluded.',
        'unnumbered-risk-status-cards':'Legacy severity/status cards without IDs; leading source narrative retained as title when no separate title exists.',
        'legacy-title-first-risk-cards':'Legacy title-before-severity layout; excludes legend definitions and test sections.',
        'unnumbered-or-unrecognized':'Early unnumbered/clean-audit layout; zero findings remains unvalidated absent source evidence.',
        'unrecognized-or-clean':'Alternate explicit metadata/inline/narrative layout or report without cards; structural checks and residual queues retained.'}
    return [{k:r[k] for k in ('sha256','filename','date_hint','layout','pages','findings','sample_titles')}|{'layout_notes':notes[r['layout']],
             'review_scope':'Full cached report read with holdout guard; all pages scanned for section/index/risk/status/appendix structure. Date is collector metadata.'} for r in chosen]


def validate_outputs():
    blocked=holdouts(ROOT);allowed={d['document_id']:d for d in read_snapshot(ROOT) if d['row']['firm_id'] in {'verichains','zokyo'}}
    result={}
    for firm in ('verichains','zokyo'):
        errors=[];seen=set();rows=0;cache={};proofs=0
        def text(sha):
            if sha in blocked:raise RuntimeError('holdout denied')
            if sha not in cache:cache[sha]=(ROOT/'local-cache/fulltext'/(sha+'.txt')).read_bytes().decode('utf-8')
            return cache[sha]
        for line in (ROOT/'data/findings'/(firm+'.jsonl')).read_text().split('\n'):
            if not line:continue
            r=json.loads(line);rows+=1
            if r['sha256'] in blocked:raise RuntimeError('holdout output denied')
            if r['finding_id'] in seen:errors.append('duplicate_finding_id')
            seen.add(r['finding_id'])
            if r['document_id'] not in allowed:errors.append('unrecognized_document_id')
            span=r['body_span'];source=text(r['sha256'])
            if source[span['start']:span['end']]!=r['body_text']:errors.append('body_slice_mismatch')
            if r['severity']!=r['severity_normalized'] or r['severity_raw']!=r['severity_original']:errors.append('severity_alias_mismatch')
        for line in (ROOT/'data/findings/validation'/(firm+'.jsonl')).read_text().split('\n'):
            if not line:continue
            r=json.loads(line)
            summary=r.get('printed_summary')
            for proof in (summary or {}).get('evidence',[]):
                if 'start' in proof and 'text' in proof:
                    proofs+=1
                    if text(r['sha256'])[proof['start']:proof['end']]!=proof['text']:errors.append('summary_proof_slice_mismatch')
        result[firm]={'rows':rows,'unique_finding_ids':len(seen),'exact_summary_proofs':proofs,'errors':dict(Counter(errors)),'holdout_rows':0}
    return result


def evidence():
    before=evaluate(True);after=evaluate(False)
    blocked=holdouts(ROOT);docs=[d for d in read_snapshot(ROOT) if d['row']['firm_id'] in after]
    ext={r['sha256']:r for r in map(json.loads,(ROOT/'data/fulltext/extractions.jsonl').read_text().splitlines())}
    failures=[{'firm_id':d['row']['firm_id'],'sha256':d['row']['sha256'],'filename':d['row']['filename'],'error':ext.get(d['row']['sha256'],{}).get('error','not_extracted')}
              for d in docs if ext.get(d['row']['sha256'],{}).get('status') not in {'ok','partial'}]
    return {'scope':'Two assigned publishers only; unique original-hash development metrics; occurrence counts remain in standard validation files.',
        'holdout_hashes_loaded':len(blocked),'holdouts_opened':0,'baseline_method':'Exact pre-change Phase 4a parser rules frozen in baseline_parse; initial metrics captured before edits.',
        'before':before,'after':after,'samples':{f:samples(v['records']) for f,v in after.items()},
        'residuals':{f:residuals(v['records']) for f,v in after.items()},'extraction_failures':failures,'output_integrity':validate_outputs(),
        'files_written':['scripts/findings/parsers/verichains.py','scripts/findings/parsers/zokyo.py','scripts/findings/parsers/verichains_metrics.py','scripts/findings/parsers/test_verichains_zokyo.py','data/findings/verichains.jsonl','data/findings/zokyo.jsonl','data/findings/validation/verichains.json','data/findings/validation/verichains.jsonl','data/findings/validation/zokyo.json','data/findings/validation/zokyo.jsonl','local-cache/tmp/group4-verichains-zokyo.json'],
        'scratch_files_written':['local-cache/tmp/group4-baseline.json','local-cache/tmp/group4-baseline-rows.json','local-cache/tmp/group4-samples.txt','local-cache/tmp/group4-after1.json','local-cache/tmp/group4-after2.json','local-cache/tmp/group4-verichains-zokyo-after.json'],
        'limitations':['Printed aggregate agreement is development diagnostics, not precision/recall.',
          'Zokyo scoring totals are labelled hypothetical in source; comparisons preserve all disagreements and never relabel detail risk.',
          'Verichains has no printed aggregate severity totals in reviewed layouts. TOC subsection IDs provide independent sequence evidence.',
          'Zokyo printed summary rows provide independent sequence evidence; risk-badge/metadata censuses provide structural completeness only.',
          'Zero rows without explicit clean-audit wording are not proof of an audit without findings.']}


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path);p.add_argument('--evidence',type=Path);a=p.parse_args()
    result=evidence() if a.evidence else evaluate()
    path=a.evidence or a.output
    if path:path.write_text(json.dumps(result,indent=2)+'\n')
    results=result['after'] if a.evidence else result
    print(json.dumps({f:{k:v for k,v in r.items() if k!='records'} for f,r in results.items()},indent=2))
if __name__=='__main__':main()
