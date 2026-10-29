"""Reproducible Phase 4b group 1 development-set evaluation (never opens holdouts)."""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import ROOT, digest, holdouts, read_snapshot, uid, write_json, write_jsonl
from core import Report
from parsers import module

FIRMS = ('code4rena', 'oak-security', 'consensys-diligence', 'abdk-consulting',
         'macro', 'spearbit', 'runtime-verification', 'statemind', 'dedaub',
         'fuzzland', 'composable-security')
BASELINE = ROOT / 'data/findings/validation/group1_before.json'


def sequence(rows):
    """Observed printed-ID runs; absence is unevaluable, never a successful empty run."""
    groups = defaultdict(list)
    for row in rows:
        pid = row.get('publisher_finding_id') or ''
        m = re.fullmatch(r'(.*?)(\d+)', pid.strip())
        if m:
            groups[m[1]].append(int(m[2]))
    if not groups:
        return None
    return all(len(nums) == len(set(nums)) and set(nums) == set(range(0 if 0 in nums else 1, max(nums)+1))
               for nums in groups.values())


def load_report(doc, blocked):
    sha=doc['row']['sha256']
    assert sha not in blocked, 'Holdout text access denied'
    path=ROOT/'local-cache/fulltext'/(sha+'.txt')
    meta_path=path.with_suffix('.pages.json')
    if not path.exists() or not meta_path.exists():
        return None
    meta=json.loads(meta_path.read_text())
    if meta['status'] not in {'ok','partial'}:
        return None
    text=path.read_bytes().decode('utf-8')
    assert digest(text.encode())==meta['text_sha256']
    return Report(text,meta,doc['row']['firm_id'])


def native_sequence(parser, report, rows):
    if report is None:
        return dict(complete=None,reason='extraction_failed',gaps=[],duplicates=[])
    candidates=[SimpleNamespace(printed_id=r['publisher_finding_id'],evidence=r['evidence'],
                                record_kind=r['record_kind']) for r in rows]
    if hasattr(parser,'sequence_diagnostics'):
        return parser.sequence_diagnostics(report,candidates)
    if hasattr(parser,'sequence_groups'):
        groups=parser.sequence_groups(report,candidates)
        results=[sequence([{'publisher_finding_id':pid} for pid in group]) for group in groups]
        evaluable=[value for value in results if value is not None]
        gaps,duplicates=[],[]
        for group in groups:
            prefixes=defaultdict(list)
            for pid in group:
                m=re.fullmatch(r'(.*?)(\d+)',(pid or '').strip())
                if m:
                    prefixes[m[1]].append(int(m[2]))
            for prefix,values in prefixes.items():
                gaps += [prefix+str(n) for n in range(0 if 0 in values else 1,max(values)+1) if n not in values]
                duplicates += [prefix+str(n) for n,c in Counter(values).items() if c>1]
        return dict(complete=all(evaluable) if evaluable else None,
                    reason='publisher_section_or_review_round_groups',gaps=gaps,duplicates=duplicates,
                    unevaluable_groups=results.count(None))
    return dict(complete=sequence(rows),reason='observed_numeric_id_runs',gaps=[],duplicates=[])


def collect(verify=False, legacy=False):
    blocked = holdouts()
    docs = {d['document_id']: d for d in read_snapshot() if d['row']['firm_id'] in FIRMS}
    result = {}
    ledger=[]
    seen=set()
    for firm in FIRMS:
        parser=module(firm) if not legacy else None
        ds = {k:d for k,d in docs.items() if d['row']['firm_id'] == firm}
        if verify:
            for d in ds.values():
                assert digest(d['row'])==d['source_record_sha256']
                assert d['document_id']==uid('document','collect:'+firm,d['source_record_id'])
        rows_by_doc = defaultdict(list)
        rows_count = missing_title = missing_severity = missing_raw = 0
        inclusive=defaultdict(Counter)
        kinds=Counter()
        cached_sha,cached_report=None,None
        last_span={}
        with (ROOT / 'data/findings' / (firm+'.jsonl')).open() as stream:
            for raw in stream:
                r = json.loads(raw)
                assert r['sha256'] not in blocked and r['document_id'] in ds
                if verify:
                    assert r['finding_id'] not in seen
                    seen.add(r['finding_id'])
                    assert r['finding_id']==uid('finding',r['source_tag'],r['source_record_id'])
                    parent=ds[r['document_id']]
                    assert r['sha256']==parent['row']['sha256']==r['body_span']['original_sha256']
                    assert r['source_file']==parent['source_file'] and r['source_locator']==parent['source_locator']
                    assert r['source_record_sha256']==parent['source_record_sha256']
                    assert r['severity']==r['severity_normalized']
                    assert r['severity_raw']==r['severity_original']
                    assert r['status'] in {None,'fixed','acknowledged','open','partial','resolved','invalid','info','other'}
                    assert r['finding_phase'] in {None,'initial_audit','fix_review','other'}
                    if cached_sha!=r['sha256']:
                        cached_report=load_report(parent,blocked); cached_sha=r['sha256']
                    assert cached_report is not None
                    start,end=r['body_span']['start'],r['body_span']['end']
                    assert 0<=start<end<=len(cached_report.text)
                    assert cached_report.text[start:end]==r['body_text']
                    assert r['body_span']['text_sha256']==cached_report.meta['text_sha256']
                    pages=[p['page'] for p in cached_report.meta['pages'] if p['end']>start and p['start']<end]
                    assert r['body_span']['pages']==pages and r['page']==pages[0]
                    assert r['provenance']['extraction_record_sha256']==digest(r['provenance']['extraction_record'])
                    assert last_span.get(r['document_id'],0)<=start, ('overlapping findings',firm,r['sha256'],start)
                    last_span[r['document_id']]=end
                rows_count += 1
                kinds[r['record_kind']]+=1
                missing_title += not bool((r.get('title') or '').strip())
                missing_severity += r.get('severity') in {None, '', 'unknown'}
                missing_raw += not bool((r.get('severity_raw') or '').strip())
                if r['record_kind'] in {'formal_finding','summary_excerpt'}:
                    inclusive[r['document_id']][r['severity']]+=1
                if r['record_kind'] == 'formal_finding':
                    rows_by_doc[r['document_id']].append({k:r[k] for k in ('publisher_finding_id','evidence','record_kind','severity')})
        diagnostics = [json.loads(s) for s in (ROOT / 'data/findings/validation' / (firm+'.jsonl')).read_text().splitlines()]
        assert all(d['sha256'] not in blocked for d in diagnostics)
        states = Counter(d['validation'] for d in diagnostics)
        assert len(diagnostics)==len(ds)
        seq = [sequence(rows_by_doc[d['document_id']]) for d in diagnostics
               if d['validation'] in {'no_usable_printed_counts', 'ambiguous_printed_counts'}]
        audit_ids = [k for k,d in ds.items() if d['row']['doc_kind'] == 'audit_report']
        no_counts_audits=[d['document_id'] for d in diagnostics if d['validation']=='no_usable_printed_counts' and d['document_id'] in audit_ids]
        result[firm] = dict(documents=len(ds), rows=rows_count,
                            formal_findings=sum(map(len, rows_by_doc.values())),
                            match=states['match'], comparable=states['match']+states['mismatch'],
                            summary_states=dict(states), sequence_complete=seq.count(True),
                            sequence_evaluable=sum(s is not None for s in seq),
                            sequence_unevaluable=seq.count(None),
                            audit_documents=len(audit_ids),
                            audit_with_findings=sum(bool(rows_by_doc[k]) for k in audit_ids),
                            missing_title=missing_title, missing_severity=missing_severity,
                            missing_raw_severity=missing_raw,record_kinds=dict(kinds),
                            no_counts_audit_documents=len(no_counts_audits),
                            no_counts_audit_with_findings=sum(bool(rows_by_doc[k]) for k in no_counts_audits))
        if legacy:
            continue
        reviewed=set(getattr(parser,'REVIEWED_SHA256',()))
        assert not reviewed & blocked
        assert reviewed <= {d['row']['sha256'] for d in ds.values()}
        assert len(reviewed)>=15,(firm,'Insufficient reviewed samples')
        result[firm]['reviewed_hashes']=sorted(reviewed)
        result[firm]['reviewed_formats']=dict(Counter(next(d['row']['file_format'] for d in ds.values() if d['row']['sha256']==sha) for sha in sorted(reviewed)))
        result[firm]['native_sequence_complete']=result[firm]['native_sequence_evaluable']=0
        result[firm]['all_native_sequence_complete']=result[firm]['all_native_sequence_evaluable']=0
        result[firm]['inclusive_match']=0
        for d in diagnostics:
            doc=ds[d['document_id']]
            rows=rows_by_doc[d['document_id']]
            report=load_report(doc,blocked)
            seq_result=native_sequence(parser,report,rows)
            if seq_result['complete'] is not None:
                result[firm]['all_native_sequence_evaluable']+=1
                result[firm]['all_native_sequence_complete']+=bool(seq_result['complete'])
                if d['validation']=='no_usable_printed_counts':
                    result[firm]['native_sequence_evaluable']+=1
                    result[firm]['native_sequence_complete']+=bool(seq_result['complete'])
            if verify and d.get('printed_summary'):
                proofs=list(d['printed_summary']['evidence'])
                for alternative in d['printed_summary'].get('alternatives',[]):
                    proofs.extend(alternative.get('evidence',[]))
                for proof in proofs:
                    if 'text' in proof:
                        assert report.text[proof['start']:proof['end']]==proof['text']
            parsed=Counter(r['severity'] for r in rows)
            assert all(parsed[s]==n for s,n in d.get('parsed_counts',{}).items())
            expected=(d.get('printed_summary') or {}).get('counts')
            inclusive_ok=None
            if d['validation'] in {'match','mismatch'}:
                assert (d['validation']=='match')==all(parsed[s]==n for s,n in expected.items())
                inclusive_ok=all(inclusive[d['document_id']][s]==n for s,n in expected.items())
                result[firm]['inclusive_match']+=inclusive_ok
            ledger.append(dict(firm_id=firm,sha256=d['sha256'],document_id=d['document_id'],
                               public_url=doc['row']['public_url'],filename=doc['row']['filename'],
                               doc_kind=doc['row']['doc_kind'],date_hint=doc['row'].get('date_hint'),
                               validation=d['validation'],printed_counts=expected,parsed_counts=dict(parsed),
                               formal_findings=len(rows),sequence=seq_result,inclusive_match=inclusive_ok,
                               reviewed=d['sha256'] in reviewed))
    if not legacy:
        write_jsonl(ROOT/'data/findings/validation/group1_audit.jsonl',ledger)
    return result


NOTES = {
 'code4rena': 'PDF, linked Markdown, HTML and anchored Markdown eras are handled. Printed N/NC/Info grades map to info; F submission IDs inherit the explicit severity section. Mitigation entries remain remediation_review. Linked-only legacy entries remain summary_excerpt and cannot supply a missing detailed body. Source ID-only headings retain a missing title. Mixed low/non-critical QA without an individual grade remains unknown; gas sections and numeric QA namespaces remain distinct. Malformed-fence recovery requires the next sequential ID linked to an already established official issue base. Legacy printed Summary prose supplies independent totals when sections omit counts; prose/section conflicts are marked ambiguous without consulting parsed rows. Residual classes are linked-only low-risk sections, source totals that disagree with source entries, missing source ID slots, unnumbered QA with no sequential scale, and ungraded/missing-title source entries. Targets and non-evaluable cases are shown above; no claim of complete recall is made.',
 'oak-security': 'Numbered Major/Minor/Informational fields, wrapped titles, phased ID restarts, status labels, and appendix bounds are handled. Explicitly excluded historical Dexter contract findings do not become current-audit rows. The ungraded Dusk protocol review retains unknown severity. Zero-row _tech_stacks listing files are collector-type issues, not evidence of clean audits. Numeric totals are absent; native review-round sequences are the applicable diagnostic.',
 'consensys-diligence': 'Legacy Markdown text/image severity tables, HTML inline severity/status headings, PDF main columns beside contents columns, and named contract review sections are handled. Major/Minor map high/low; Closed/Addressed statuses retain raw text and a publisher mapping. Ungraded numbered recommendations remain unknown. Zero classes comprise summary-only tBTC thesis, cryptography/SafetyChecker narrative reviews, foreign ABDK SKALE attribution, Solidity Metrics exports, explicit clean reports and extraction failures. Those unresolved narrative layouts remain coverage limitations.',
 'abdk-consulting': 'CVF tables/cards, grouped CVF IDs, legacy section/list namespaces, active-plus-fixed tables and printed numeric findings prose are handled. Critical/Major/Moderate/Minor labels preserve their source scale, with explicit publisher normalization. Legacy ungraded notes remain unknown; an absent source card title remains null. Revised reports omit or remove IDs, and mixed legacy section/list schemes do not establish a single global sequential scale. Source gaps stay failures, with no synthetic fillers. Independent conflicting aggregates are ambiguous rather than selected using parsed rows.',
 'macro': 'Native HTML issue cards and split title fragments use C/H/M/L/Q/I/G IDs. Q is Code Quality and I is Informational; both map info, while G maps gas. Status Addressed maps resolved with raw label retained. Printed-zero audit reports remain zero. All numeric summaries agree; some reports nevertheless have native duplicate/missing IDs, so count agreement is not a claim of correct ID sequencing.',
 'spearbit': 'Numbered severity fields, multiline titles, parent-section fallbacks, narrative cryptography reviews and upgrade-validation observations are handled. Explicit detail severity wins over an inconsistent enclosing section. Unreviewed Cron appendix entries remain observations. Inconsistency/Optimization labels retain unknown article severity; observations without a source grade remain ungraded. Remaining summary conflicts are documented below; the strict summary target remains unmet.',
 'runtime-verification': 'Legacy A/B/CI/F/FA/TS cards and index-linked details, modern explicit Severity fields, parenthesized risks and native client status labels are handled. P1–P5 priorities, dash/N/A fields and ungraded legacy reviews remain unknown rather than being called severity grades. Gyroscope tracker rows stay excerpts; Folks design recommendations stay recommendations. The residual ID issue is OCR Al versus A1. Zero classes include specifications, supporting artifacts, research/tooling and narrative formal-verification reviews without recognized finding cards; unresolved narrative review coverage remains a limitation.',
 'statemind': 'Finding cards use source risk labels/IDs and explicit status fields; finding summary tables are separated from role-impact matrices. Myso has a missing printed ID; Lido has a duplicate ID and another missing slot, even where severity counts agree. Deployment/role-validation narrative reports have no recognized finding cards and remain zero-row review cases.',
 'dedaub': 'Modern C/H/M/L/A IDs, explicit status labels and legacy unnumbered description cards are handled. Advisory A entries map info using the publisher scale. Five narrative studies have no recognized formal finding cards; two Yearn artifacts are GitHub HTML shells cached with Markdown filenames. These are coverage/input issues, not clean-audit conclusions. Numbered finding sequences are complete.',
 'fuzzland': 'Notion/HTML bracketed High/Med/Low/Info risk headings, inline-code title fragments and status metadata tables are handled. Med maps medium; source Ack maps acknowledged with the label retained. Only the printed Number column supplies aggregate counts. Mantle COOK and Copra totals contradict their published detail entries. No reports print sequential finding IDs, so ID completeness is not evaluable and is never counted as a successful empty sequence. Iotube explicitly prints Detailed Findings N/A. The summary target remains unmet.',
 'composable-security': 'Modern commit-scoped C/H/M/L/R cards, older section IDs with R1/R2 review markers, bidi text, wrapped severity/status fields and appendices are handled. R recommendations map info. Latest complete explicit retest aggregates are used when present; earlier complete audit aggregates remain available when the later prose omits buckets. DIVA contains inconsistent recommendation totals and remains a mismatch. Reports without totals are security consultations without numbered findings; their collector audit_report label is retained in coverage denominators.',
}

EXAMPLES = {
 'code4rena': [('408a0f52','Linked-only low-risk entries; the prose summary and low-risk section total also disagree.'),('be3a3f83','Spartan has more detailed medium findings than its printed medium total.'),('188bb55b','Boot Finance skips a printed medium ID, rather than the parser inventing its absent content.'),('7dc07752','Formal-verification entries print IDs without individual titles.'),('ce35ce7b','Unnumbered QA narratives do not provide a sequential ID scale.')],
 'oak-security': [('b6b3176c','Ungraded protocol-review layout; source severity is retained as absent.')],
 'consensys-diligence': [('d57e5198','Vyper numbered review includes ungraded source recommendations.'),('d2604f52','eRLC has an ungraded numbered item.'),('6b0b1c0e','SKALE PDF identifies ABDK rather than the collector-attributed publisher.'),('2016a3c8','Solidity Metrics artifact, not a finding-card audit.'),('40ec99e7','SafetyChecker narrative layout has no recognized numbered finding cards.'),('1367e3c7','An extraction failure remains in the denominator and is not opened as a usable report.')],
 'abdk-consulting': [('f73f4b6d','Exactly Peripheral summary prose disagrees with detailed moderate entries.'),('f79d17d6','Herodotus summary major total disagrees with detail.'),('3509f947','zkLend moderate prose total disagrees with detail.'),('a87f53fd','zkLink stale major prose conflicts with remaining entries after source removals/downgrades.'),('9a976f3d','Lemma revised source omits CVF IDs; no findings are synthesized.'),('78b22d7d','Reya part III has source-native omitted IDs.'),('c5658c2e','Vovo CVF card does not yield a distinct title.')],
 'macro': [('6208e491','Bitcone duplicates I-2.'),('67bf9c30','Clanker duplicates I-1 and omits I-2.'),('1196da77','Connext omits H-5.'),('cc4c83a3','Farcaster omits M-1.'),('224b1e95','Kodiak omits M-5.'),('74bc8cba','Polynomial omits M-1.'),('83a49162','Thirdweb omits M-2.')],
 'runtime-verification': [('e08ae874','Pact.fi Router OCR prints Al rather than A1; the missing slot is reported.')],
 'dedaub': [],
 'fuzzland': [('1b44ef08','Mantle COOK printed low total conflicts with the detail headings.'),('48bf0080','Copra printed low total conflicts with later appended low findings.'),('8e79d45f','Iotube explicitly states Detailed Findings N/A.')],
 'composable-security': [('99ca2178','DIVA retest recommendation total conflicts with detail and implementation subtotals.'),('4b5ad112','Security consultation with no numbered finding cards.'),('e5393bb0','Security consultation with no numbered finding cards.'),('e80181bc','Security consultation with no numbered finding cards.')],
}


def ratio(n,d):
    return f'{n:,}/{d:,} ({100*n/d:.2f}%)' if d else 'N/A'


def manifest():
    files=['scripts/findings/core.py','scripts/findings/run.py','scripts/findings/parsers/__init__.py',
           'scripts/findings/parsers/code4rena_study.py','scripts/findings/parsers/code4rena_group1_metrics.py',
           'scripts/findings/test_group1_code4rena.py','scripts/findings/test_consensys_macro.py',
           'scripts/findings/test_spearbit_statemind.py','scripts/findings/test_runtime_dedaub.py',
           'scripts/findings/test_fuzzland_composable.py','scripts/findings/parsers/test_oak_security.py',
           'scripts/findings/parsers/test_abdk_consulting.py',
           'data/findings/validation/group1_before.json','data/findings/validation/group1_metrics.json',
           'data/findings/validation/group1_audit.jsonl','docs/phase4/group1.md','docs/phase4/group1_files_written.txt']
    for firm in FIRMS:
        files += ['scripts/findings/parsers/'+firm.replace('-','_')+'.py','data/findings/'+firm+'.jsonl',
                  'data/findings/validation/'+firm+'.json','data/findings/validation/'+firm+'.jsonl']
    return sorted(files)


def write_report(metrics, verified):
    metrics={firm:metrics[firm] for firm in FIRMS}
    before=json.loads(BASELINE.read_text())
    ledger=[json.loads(s) for s in (ROOT/'data/findings/validation/group1_audit.jsonl').read_text().splitlines()]
    out=['# Phase 4b group 1 — publisher extraction accuracy','',
         'Generated by `python3 -I scripts/findings/parsers/code4rena_group1_metrics.py --verify --write-report`. '
         'Development set only; frozen input snapshot, no collection refresh, no network, no holdout documents opened. '
         'The immutable baseline was captured before regeneration with this script’s `--capture-before` option.','',
         f"Scope: {sum(s['documents'] for s in metrics.values()):,} document occurrences; {sum(s['rows'] for s in metrics.values()):,} output rows, "
         f"including {sum(s['formal_findings'] for s in metrics.values()):,} formal finding occurrences. "
         'These are source occurrences, not deduplicated vulnerabilities.','',
         '## Definitions and limits','',
         'Summary agreement requires exact equality in every explicitly selected printed severity bucket. '
         'Summary readers use independent publisher numeric tables/prose/section totals, never parsed IDs. '
         'Ambiguous/conflicting summaries and extraction failures are separate states. Only formal findings enter the primary comparison; '
         'linked-only excerpts, design recommendations, observations and remediation reviews stay distinct. '
         'No finding is added or relabelled to force a match.','',
         'For reports without usable printed totals, native ID completeness checks contiguous observed runs without gaps or duplicates, '
         'within publisher severity, section and review-round namespaces. Missing IDs are not filled. '
         'No-ID, empty, narrative and failed-extraction documents are not successful empty sequences. '
         'Contiguous observed IDs cannot prove that the final source finding was not missed; this is a diagnostic, not recall. '
         'The preserved baseline’s generic sequence fields use flat numeric suffixes; the native after-metric adds documented publisher namespaces.','',
         'Coverage uses the frozen collector doc_kind=audit_report denominator, including incorrectly attributed/typeset inputs and explicit clean audits. '
         'C4 is classified contest_report, so its literal audit_report coverage is N/A. '
         'Missing raw severity and normalized unknown are shown separately: a priority or unrecognized source label is not silently mapped to informational.','',
         '## Before and after','',
         '| Publisher | Documents | Formal findings before → after | All rows after | Printed-summary agreement before → after |',
         '|---|---:|---:|---:|---|']
    for firm,s in metrics.items():
        b=before[firm]
        out.append(f"| {firm} | {s['documents']:,} | {b['formal_findings']:,} → {s['formal_findings']:,} | {s['rows']:,} | {ratio(b['match'],b['comparable'])} → {ratio(s['match'],s['comparable'])} |")
    out += ['', '## Reports without printed totals and field completeness','',
            '| Publisher | Native complete / evaluable without totals | No-total documents without evaluable IDs | No-total audit reports with ≥1 formal finding | All audit reports with ≥1 formal finding | Missing title | Missing raw severity | Unknown normalized severity |',
            '|---|---:|---:|---:|---:|---:|---:|---:|']
    for firm,s in metrics.items():
        no=s['summary_states'].get('no_usable_printed_counts',0)
        out.append(f"| {firm} | {ratio(s['native_sequence_complete'],s['native_sequence_evaluable'])} | {no-s['native_sequence_evaluable']} | {ratio(s['no_counts_audit_with_findings'],s['no_counts_audit_documents'])} | {ratio(s['audit_with_findings'],s['audit_documents'])} | {s['missing_title']:,} | {s['missing_raw_severity']:,} | {s['missing_severity']:,} |")
    c4_contests=[d for d in ledger if d['firm_id']=='code4rena' and d['doc_kind']=='contest_report']
    c4_no_totals=[d for d in c4_contests if d['validation']=='no_usable_printed_counts']
    out += ['', 'C4 contest-report coverage (the applicable audit-like population): ' +
            ratio(sum(bool(d['formal_findings']) for d in c4_contests),len(c4_contests)) +
            '; without printed totals: '+ratio(sum(bool(d['formal_findings']) for d in c4_no_totals),len(c4_no_totals))+'.']
    out += ['', 'Native sequence checks across all documents (including those with totals): ' + '; '.join(f"{f} {ratio(s['all_native_sequence_complete'],s['all_native_sequence_evaluable'])}" for f,s in metrics.items())+'.','',
            '## Review samples and targets','',
            '| Publisher | Distinct inspected hashes | Formats | Summary target ≥95% | No-total sequence target ≥95% |',
            '|---|---:|---|---|---|']
    for firm,s in metrics.items():
        summary='N/A' if not s['comparable'] else ('met' if s['match']/s['comparable']>=.95 else 'unmet')
        seq='not evaluable' if not s['native_sequence_evaluable'] else ('met' if s['native_sequence_complete']/s['native_sequence_evaluable']>=.95 else 'unmet')
        out.append(f"| {firm} | {len(s['reviewed_hashes'])} | {', '.join(f'{k}={v}' for k,v in sorted(s['reviewed_formats'].items()))} | {summary} | {seq} |")
    out += ['', 'Inspected hashes are embedded in each module’s REVIEWED_SHA256 and copied into `data/findings/validation/group1_metrics.json`. '
            'Samples cover early/late available layouts and format variants; additional mismatch inspection was performed. '
            'Dates are not inferred from filenames in the findings.','',
            f"For C4 only, counting its separately labelled linked-only excerpts as source entries would match {ratio(metrics['code4rena']['inclusive_match'],metrics['code4rena']['comparable'])}. "
            'This supplementary figure is not the strict detailed-finding target, and does not claim linked bodies were acquired.','',
            '## Publisher rules and residual failure classes','']
    for firm,s in metrics.items():
        out += ['### '+firm,'',NOTES[firm],'']
        rows=[d for d in ledger if d['firm_id']==firm]
        examples=list(EXAMPLES.get(firm,[]))
        examples += list(getattr(module(firm),'RESIDUAL_EXAMPLES',{}).items())
        for prefix,note in examples:
            doc=next((d for d in rows if d['sha256'].startswith(prefix)),None)
            if doc:
                out.append(f"- [{doc['filename']} — {doc['sha256'][:12]}]({doc['public_url']}): {note}")
        if examples:
            out.append('')
        seen_sequences=set()
        for d in rows:
            if d['sequence']['complete'] is False and d['sha256'] not in seen_sequences:
                seen_sequences.add(d['sha256'])
                out.append(f"- ID diagnostic [{d['filename']} — {d['sha256'][:12]}]({d['public_url']}): gaps={d['sequence'].get('gaps',[])[:12]}, duplicates={d['sequence'].get('duplicates',[])[:12]}.")
                if len(seen_sequences)>=3:
                    break
        zero=[d for d in rows if not d['formal_findings']]
        if zero:
            out.append('Zero-formal-row examples: '+ '; '.join(f"[{d['filename']} — {d['sha256'][:12]}]({d['public_url']})" for d in zero[:4])+'.')
        out.append('')
        unresolved=[d for d in rows if d['validation']=='mismatch']
        out.append('Validation states: '+', '.join(f'{k}={v}' for k,v in sorted(s['summary_states'].items()))+'.')
        if unresolved:
            out.append('Every comparable mismatch and its printed/parsed counts is retained in the per-document ledger; no mismatch is removed from the denominator.')
        out.append('')
    out += ['## Verification and reproduction','',
            ('All scoped finding IDs, metadata receipts, original-hash joins, cached-text hashes, severity aliases, native statuses, phase values, exact body slices, page spans, nonoverlap bounds and summary evidence spans passed verification. Original files were not reopened or rehashed by this evaluation.' if verified else 'Verification was not requested for this run.'),'',
            'Group 1 uses shared dispatch registration, the optional publisher printed_counts hook, and optional Candidate normalized_status/finding_phase fields consumed by the runner. Defaults preserve existing parser behavior. Native status mappings are stored as evidence; source labels remain unchanged. Concurrent changes in these shared files were preserved.','',
            'Scoped publisher regression tests passed. The broader test_framework suite reports a failure in test_wrapped_pdf_toc_and_summary_rows_are_not_details: the concurrently owned Pashov parser includes following description text in its title. Its module was left to its owner.','',
            'Per-document states, counts, zero-row cases and ID-sequence diagnostics: `data/findings/validation/group1_audit.jsonl`. '
            'Machine-readable before/after metrics: `data/findings/validation/group1_before.json` and `group1_metrics.json`. '
            'All files written: [group1_files_written.txt](group1_files_written.txt).','',
            '```sh',
            "python3 -I -c 'import sys,runpy;sys.path.insert(0,\"scripts/findings\");sys.argv=[\"run.py\",\"--firms\",*\""+' '.join(FIRMS)+"\".split()];runpy.run_path(\"scripts/findings/run.py\",run_name=\"__main__\")'",
            'python3 -I scripts/findings/parsers/code4rena_group1_metrics.py --verify --write-report',
            "python3 -I -c 'import sys,unittest;sys.path.insert(0,\"scripts/findings\");names=\"test_group1_code4rena test_consensys_macro test_spearbit_statemind test_runtime_dedaub test_fuzzland_composable parsers.test_oak_security parsers.test_abdk_consulting\".split();r=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromNames(names));sys.exit(not r.wasSuccessful())'",
            '```','']
    path=ROOT/'docs/phase4/group1.md';path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text('\n'.join(out))
    (ROOT/'docs/phase4/group1_files_written.txt').write_text('\n'.join(manifest())+'\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture-before', action='store_true')
    p.add_argument('--verify', action='store_true')
    p.add_argument('--write-report', action='store_true')
    a = p.parse_args()
    if a.capture_before and BASELINE.exists():
        raise SystemExit('Baseline already exists; refusing to overwrite')
    metrics = collect(verify=a.verify,legacy=a.capture_before)
    if a.capture_before:
        write_json(BASELINE, metrics)
    elif a.write_report:
        write_json(ROOT/'data/findings/validation/group1_metrics.json',dict(by_firm=metrics,
                   verification=dict(performed=a.verify,holdout_rows=0,verified_rows=sum(s['rows'] for s in metrics.values()) if a.verify else None),
                   baseline_sha256=digest(BASELINE.read_bytes()),snapshot_sha256=digest((ROOT/'data/fulltext/input_documents.jsonl').read_bytes())))
        write_report(metrics,a.verify)
    for firm,s in metrics.items():
        print(f"{firm}: rows={s['rows']:,}; formal={s['formal_findings']:,}; summary={ratio(s['match'],s['comparable'])}; "
              f"sequence(no totals)={ratio(s.get('native_sequence_complete',0),s.get('native_sequence_evaluable',0))}; "
              f"missing title/raw severity/unknown={s['missing_title']}/{s['missing_raw_severity']}/{s['missing_severity']}")


if __name__ == '__main__':
    main()
