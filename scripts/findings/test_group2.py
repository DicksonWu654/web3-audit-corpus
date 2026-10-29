"""Group 2 development diagnostics; all document reads pass the holdout guard.

Run --inspect FIRM for deterministic layout samples, --metrics for per-firm
measurements, and --baseline once before modifying the publisher modules.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import importlib.util
import unittest
from types import SimpleNamespace
from common import ROOT, SEVERITIES, digest, holdouts, read_snapshot, uid, write_json
from core import Report

FIRMS = ('pashov-audit-group', 'slowmist', 'mixbytes', 'blocksec', 'least-authority',
         'hexens', 'iosiro', 'three-sigma', 'informalsystems', 'coinspect', 'sec3',
         'chainlight', 'secure3')


def load_report(doc):
    sha = doc['row']['sha256']
    if sha in holdouts(ROOT):
        raise RuntimeError('Holdout inspection denied')
    base = ROOT / 'local-cache/fulltext'
    meta = json.loads((base / (sha + '.pages.json')).read_text())
    text = (base / (sha + '.txt')).read_bytes().decode('utf-8')
    if digest(text.encode()) != meta['text_sha256']:
        raise ValueError('Fulltext hash mismatch')
    return Report(text, meta, doc['row']['firm_id'])


def samples(firm, count=18):
    docs = {d['row']['sha256']: d for d in read_snapshot() if d['row']['firm_id'] == firm}
    ordered = sorted(docs.values(), key=lambda d: (d['row'].get('date_hint') or '', d['row']['filename'], d['row']['sha256']))
    if len(ordered) <= count:
        return ordered
    return [ordered[round(i * (len(ordered)-1) / (count-1))] for i in range(count)]


def sequence(ids):
    """Continuity of printed IDs, never an independent recall claim.

    Separate each severity/project/section prefix. Empty IDs and unrecognised
    schemes are unassessable, rather than counted as complete. A singleton 7
    fails because its missing prefix cannot be inferred from the output.
    """
    if not ids or any(not x for x in ids):
        return {'state': 'unassessable', 'reason': 'no_findings_or_missing_ids'}
    groups = defaultdict(list)
    for pid in ids:
        m = re.fullmatch(r'(.*?)(\d+)', str(pid).strip().replace('М', 'M'))
        if m:
            groups[m[1]].append(int(m[2]))
        elif re.fullmatch(r'(?:Issue\s+)?[A-Z]', str(pid)):
            groups['letters'].append(ord(str(pid)[-1])-64)
        else:
            return {'state': 'unassessable', 'reason': 'non_numeric_printed_ids'}
    problems = []
    for prefix, numbers in groups.items():
        start = 0 if 0 in numbers else 1
        missing = sorted(set(range(start, max(numbers)+1)) - set(numbers))
        duplicates = sorted(n for n,c in Counter(numbers).items() if c > 1)
        if missing or duplicates:
            problems.append({'prefix': prefix, 'gaps': missing, 'duplicates': duplicates})
    return {'state': 'incomplete' if problems else 'complete', 'problems': problems}


def native_sequence(doc, rows):
    """Use the publisher's printed ID hierarchy/index when one exists.

    Global contiguity is unsuitable when numbering restarts by severity, project
    or review round. Source index equality also exposes a missing final ID that
    simple 1..n contiguity cannot detect. Expectations never use parsed rows.
    """
    firm = doc['row']['firm_id']
    formal = [r for r in rows if r['record_kind'] == 'formal_finding']
    actual = [r['publisher_finding_id'] for r in formal if r['publisher_finding_id']]
    if firm == 'pashov-audit-group':
        return sequence(actual) | {'basis': 'printed_id_prefix_contiguity'}
    if firm == 'slowmist':
        from parsers.slowmist_review import native_sequence as publisher_sequence
        return publisher_sequence(formal) | {'basis': 'printed_id_contiguity_within_source_risk_sections'}
    report = load_report(doc)
    expected, zero, as_sets = None, False, False
    if firm in {'mixbytes', 'blocksec', 'hexens'}:
        from parsers.mixbytes_review import native_sequence as publisher_sequence
        entries = [SimpleNamespace(printed_id=r['publisher_finding_id'], start=r['body_span']['start'], record_kind=r['record_kind']) for r in rows]
        return publisher_sequence(report, entries)
    elif firm in {'least-authority', 'iosiro', 'informalsystems'}:
        from parsers.least_authority_evaluate import source_ids
        expected = source_ids(report) or None
        as_sets = firm in {'least-authority', 'informalsystems'}
    elif firm in {'three-sigma', 'coinspect', 'sec3'}:
        from parsers.three_sigma_evidence import printed_index
        index, zero = printed_index(report)
        expected = [r['id'] for r in index] if index or zero else None
    elif firm in {'chainlight', 'secure3'}:
        from parsers.chainlight_secure3_test import SAMPLES
        sample = next((s for s in SAMPLES[firm] if s[0] == doc['row']['sha256']), None)
        if sample:
            _, prefix, n, _, _ = sample
            expected = [prefix+str(i) if prefix.endswith('#') else prefix+'-'+(str(i).zfill(3) if firm=='chainlight' else str(i)) for i in range(1,n+1)]
            zero = not expected
    if expected is None:
        return sequence(actual) | {'basis': 'printed_id_contiguity_no_separate_index'}
    counts = Counter(set(expected)) if as_sets else Counter(expected)
    observed = Counter(set(actual)) if as_sets else Counter(actual)
    missing, extra = counts-observed, observed-counts
    return {'state': 'incomplete' if missing or extra else 'complete', 'basis': 'publisher_source_index',
            'source_ids': sum(counts.values()), 'parsed_ids': sum(observed.values()),
            'matched_ids': sum((counts & observed).values()), 'explicit_zero': zero,
            'missing': dict(missing), 'extra': dict(extra)}


def metrics():
    blocked = holdouts()
    docs = read_snapshot()
    result = {}
    for firm in FIRMS:
        selected = {d['document_id']: d for d in docs if d['row']['firm_id'] == firm}
        rows = defaultdict(list)
        for line in (ROOT / f'data/findings/{firm}.jsonl').open():
            row = json.loads(line)
            if row['sha256'] in blocked:
                raise ValueError('Holdout found in findings output')
            if row['document_id'] in selected:
                rows[row['document_id']].append(row)
        diagnostics = []
        for line in (ROOT / f'data/findings/validation/{firm}.jsonl').open():
            d = json.loads(line)
            if d['document_id'] not in selected or d['sha256'] in blocked:
                continue
            findings = [r for r in rows[d['document_id']] if r['record_kind'] == 'formal_finding']
            ids = [r['publisher_finding_id'] for r in findings]
            diagnostics.append({**d, 'sequence': sequence(ids),
                                'native_sequence': native_sequence(selected[d['document_id']], rows[d['document_id']]),
                                'audit_report': selected[d['document_id']]['row']['doc_kind'] == 'audit_report',
                                'missing_title': sum(not r.get('title') for r in rows[d['document_id']]),
                                'missing_severity': sum(not r.get('severity_raw') for r in rows[d['document_id']]),
                                'unknown_severity': sum(r.get('severity') == 'unknown' for r in rows[d['document_id']])})
        states = Counter(d['validation'] for d in diagnostics)
        no_summary = [d for d in diagnostics if d['validation'] in {'no_usable_printed_counts', 'ambiguous_printed_counts'}]
        seq = Counter(d['sequence']['state'] for d in no_summary)
        native = Counter(d['native_sequence']['state'] for d in no_summary)
        audit = [d for d in no_summary if d['audit_report']]
        comparable = states['match'] + states['mismatch']
        n = len(no_summary)
        result[firm] = {'documents': len(diagnostics), 'distinct_hashes': len({d['sha256'] for d in diagnostics}),
                        'findings': sum(len(rs) for rs in rows.values()),
                        'formal_findings': sum(d.get('formal_findings', 0) for d in diagnostics),
                        'summary_matches': states['match'], 'summary_comparable': comparable,
                        'summary_agreement': round(100*states['match']/comparable, 2) if comparable else None,
                        'no_summary_documents': n, 'sequence_states': dict(seq),
                        'native_sequence_states': dict(native),
                        'native_sequence_complete_percent_all': round(100*native['complete']/n, 2) if n else None,
                        'native_sequence_complete_percent_assessable': round(100*native['complete']/(native['complete']+native['incomplete']), 2) if native['complete']+native['incomplete'] else None,
                        'sequence_complete_percent_all': round(100*seq['complete']/n, 2) if n else None,
                        'sequence_complete_percent_assessable': round(100*seq['complete']/(seq['complete']+seq['incomplete']), 2) if seq['complete']+seq['incomplete'] else None,
                        'no_summary_audit_reports': len(audit),
                        'no_summary_audits_with_findings': sum(d.get('formal_findings', 0) > 0 for d in audit),
                        'no_summary_audits_with_any_row': sum(d.get('findings', 0) > 0 for d in audit),
                        'audit_any_row_percent': round(100*sum(d.get('findings', 0) > 0 for d in audit)/len(audit), 2) if audit else None,
                        'audit_nonempty_percent': round(100*sum(d.get('formal_findings', 0) > 0 for d in audit)/len(audit), 2) if audit else None,
                        'missing_title': sum(d['missing_title'] for d in diagnostics),
                        'missing_severity': sum(d['missing_severity'] for d in diagnostics),
                        'unknown_severity': sum(d['unknown_severity'] for d in diagnostics),
                        'validation_states': dict(states), 'documents_detail': diagnostics}
    return result


def verify():
    """Check only our publisher outputs; never rewrite global checker state."""
    blocked = holdouts()
    docs = {d['document_id']:d for d in read_snapshot() if d['row']['firm_id'] in FIRMS}
    seen, by_firm, cache = set(), Counter(), {}
    for firm in FIRMS:
        parsed = defaultdict(Counter)
        for line in (ROOT / f'data/findings/{firm}.jsonl').open():
            row = json.loads(line)
            assert row['sha256'] not in blocked
            doc = docs[row['document_id']]
            assert row['firm_id'] == row['publisher_id'] == firm == doc['row']['firm_id']
            assert row['sha256'] == doc['row']['sha256']
            assert row['source_record_sha256'] == doc['source_record_sha256']
            assert row['finding_id'] == uid('finding', row['source_tag'], row['source_record_id'])
            assert row['finding_id'] not in seen
            seen.add(row['finding_id'])
            assert row['severity'] == row['severity_normalized'] and row['severity'] in SEVERITIES
            assert row['severity_raw'] == row['severity_original']
            assert row['provenance']['extraction_record_sha256'] == digest(row['provenance']['extraction_record'])
            sha = row['sha256']
            if sha not in cache:
                cache.clear()
                cache[sha] = load_report(doc)
            report = cache[sha]
            start, end = row['body_span']['start'], row['body_span']['end']
            assert 0 <= start < end <= len(report.text)
            assert report.text[start:end] == row['body_text']
            pages = [p['page'] for p in report.meta['pages'] if p['end'] > start and p['start'] < end]
            assert row['body_span']['pages'] == pages and row['page'] == pages[0]
            assert row['body_span']['text_sha256'] == report.meta['text_sha256']
            if row['record_kind'] == 'formal_finding':
                parsed[row['document_id']][row['severity']] += 1
            by_firm[firm] += 1
        for line in (ROOT / f'data/findings/validation/{firm}.jsonl').open():
            diag = json.loads(line)
            assert diag['document_id'] in docs and diag['sha256'] not in blocked
            if diag['validation'] in {'match', 'mismatch'}:
                observed = parsed[diag['document_id']]
                expected = diag['printed_summary']['counts']
                assert all(observed[s] == diag['parsed_counts'][s] for s in SEVERITIES)
                assert (diag['validation'] == 'match') == all(observed[s] == n for s,n in expected.items())
            if diag.get('printed_summary'):
                report = load_report(docs[diag['document_id']])
                for proof in diag['printed_summary']['evidence']:
                    if 'text' in proof:
                        assert report.text[proof['start']:proof['end']] == proof['text']
        stats = json.loads((ROOT / f'data/findings/validation/{firm}.json').read_text())
        assert stats['findings'] == by_firm[firm]
    result = {'ok': True, 'documents': len(docs), 'findings': sum(by_firm.values()),
              'findings_by_firm': dict(by_firm), 'holdout_rows': 0,
              'checks': ['identity', 'parent_receipts', 'unique_finding_ids', 'severity_aliases',
                         'extraction_record_digest', 'exact_body_slices', 'page_bounds',
                         'text_hashes', 'summary_evidence_slices', 'summary_count_accounting']}
    write_json(ROOT / 'data/findings/validation/group2_check.json', result)
    print(json.dumps(result, indent=2))


def tests():
    paths = [ROOT / ('scripts/findings/parsers/' + name + '_test.py') for name in
             ('pashov_audit_group', 'least_authority', 'iosiro', 'informalsystems', 'chainlight_secure3')]
    paths += [ROOT / ('tests/' + name) for name in
              ('test_mixbytes.py', 'test_blocksec.py', 'test_hexens.py', 'test_findings_three_sigma_coinspect_sec3.py')]
    paths += sorted((ROOT / 'scripts/findings/parsers').glob('slowmist*_test.py'))
    paths += sorted((ROOT / 'tests').glob('test_slowmist*.py'))
    if (ROOT/'scripts/findings/parsers/slowmist_review.py').exists():
        paths.append(ROOT/'scripts/findings/parsers/slowmist_review.py')
    suite = unittest.TestSuite()
    for i, path in enumerate(paths):
        spec = importlib.util.spec_from_file_location('group2_regression_'+str(i), path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(mod))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    receipt = {'ok': result.wasSuccessful(), 'tests': result.testsRun,
               'failures': len(result.failures), 'errors': len(result.errors),
               'files': [str(p.relative_to(ROOT)) for p in paths]}
    write_json(ROOT / 'data/findings/validation/group2_tests.json', receipt)
    if not receipt['ok']:
        raise SystemExit(1)


RULES = {
 'pashov-audit-group': 'Solo/team Markdown and PDF templates, including the latest same-page index/detail layout. Severity-coded IDs retain their source spelling, including Cyrillic М; the prefix maps to medium. Detail sections exclude continued contents/index pages. Wrapped and ID-only titles, explicit index statuses and appendix boundaries are handled. A narrowly scoped recovery handles malformed Solidity fences around top-level finding headings.',
 'slowmist': 'Modern Nn/bracket-risk cards and legacy English/Chinese severity sections. Native Suggestion/Weakness labels remain unknown under article-v1. Passed checklist items are not findings; explicitly labelled status assertions and post-audit boundaries remain distinct from detail narratives.',
 'mixbytes': 'Legacy Markdown severity parents, numbered PDF findings and redesigned cards/charts. Serious/Major maps to high, printed Warning to medium and Comment/Remark to info according to publisher definitions. IDs can restart by severity, contract or round; status/index rows and methodology lists are excluded from details.',
 'blocksec': 'Legacy numbered sections, early severity labels in indexes, later explicit metadata cards, Chapter 3 and nested research layouts. Recommendation and observation rows stay separately typed when the source supplies no severity. The sequence check includes these printed sections and does not mistake them for risk findings. Bodies stop before subsequent report chapters, appendices and signatures.',
 'least-authority': 'Issue, Known Issue and Suggestion cards with alphabetic/numeric IDs. Only printed index/Impact severity is used; unrated source cards remain unknown. Final Verification/Status labels are preserved. Wrapped headings containing Contents are allowed in detail bodies; publisher appendices and activity logs are excluded.',
 'hexens': 'Case-sensitive symbolic IDs, lowercase risk labels, wrapped titles and explicitly printed statuses across certificate/card layouts. NFKC is used only to normalize status matching, preserving source ligatures in status_raw. Numbered appendices and signature material do not enter finding bodies.',
 'iosiro': 'Numbered website risk sections and native HTML metadata cards. Closed-section title suffixes retain original severity; repeated source ID occurrences remain distinct. Code-quality rows without titles or risk labels remain recommendation rows with null titles and unknown severity. Site footers are excluded.',
 'three-sigma': 'Legacy numeric and modern 3S IDs, project components containing spaces/symbols or empty values, and page-spanning statuses. Final Classification overrides the impact-like Severity field. None remains unknown. Bodies retain labelled status sections and stop at report appendices.',
 'informalsystems': 'Legacy IF identifiers and modern metadata cards without IDs. Informative maps to info; Potentially High, Recommendation, Unknown, conditional severity and unrated cards remain unknown. Native Risk Accepted/Patched Without Reaudit statuses are retained. Summary/issue-link artifacts are not expanded into fabricated findings.',
 'coinspect': 'Inline Total Risk reports, older metadata grids/OCR damage and modern Status/Risk/Resolution cards. Compound IDs and single-digit IDs are preserved. None and Zero remain unknown. Conclusions/appendices terminate body spans.',
 'sec3': 'Soteria/Sec3 eras, Findings in Detail isolation, Helium compound IDs and P1/P2 IDs. Explicit overview statuses are preserved; Question and unlabelled team findings stay unknown. Contents, overview repetitions and console arrays are excluded from details.',
 'chainlight': 'Legacy Issue # headings, THE-prefixed cards, later project IDs and bilingual ORB cards. Wrapped Informationa l maps to info. Separate recommendation rows are retained without invented severity. Nested Recommendations/Fix sections stay within their finding; analysis/revision/appendix sections terminate bodies.',
 'secure3': 'Project-prefixed detail cards with wrapped or separately printed IDs/titles. Information maps to info. Summary charts are read independently of detail metadata; category/severity matrices and definitions are not numeric totals. Explicit status labels and disclaimer boundaries are retained.'
}

LIMITATIONS = {
 'pashov-audit-group': 'The former Markdown gaps were parser errors: ParcelPayroll uses Cyrillic М-02 and Hyperhyper has malformed code fences. Both are covered by regressions. Latest Pare contents page numbers are no longer treated as severity totals.',
 'slowmist': 'Assure Android/iOS and sx.curve print totals/index rows without separate detailed findings. MoreLogin is an example of conclusion counts contradicting detail labels. Anyswap has shortened result titles that limit exact detail/classification joins; this remains a parser linkage limitation. Image-link Markdown wrappers cache no linked page content; passed checklists and unrated narrative risks do not establish clean audits. Native sequence failures are the duplicated printed finding ID in SmoothyV1; section references and unnumbered tables are unassessable. Suggestion/Weakness counts stay in the unknown bucket. The original table-comparison set now matches completely; the expanded independent conclusion comparison remains below target.',
 'mixbytes': 'Printed numbering may restart across projects/review rounds. The remaining incomplete refactor/report.md (041e713…) actually prints remarks IDs 2,3,7,8,9,10, so the omitted IDs remain a source gap. Global ID contiguity is retained as a diagnostic, while publisher-scoped sequence evidence is the relevant check. Methodology/narrative-list false positives and no-space numbered headings were corrected and covered by regressions.',
 'blocksec': 'Residual numeric conflicts include a Low=3 aggregate with two low details (495764…), a remaining-risk zero aggregate with three fixed medium details (70f99a…), H2/M1/L2 versus H2/L3 details (f195e1…), and H2/M5 versus H2/M4/L1 details (25cac6…). Recommendation/observation rows account for most unprinted severities. Nested MegaETH research sections (d60f885…) mix finding/subsection numbers and remain sequence-unassessable.',
 'least-authority': 'Ethereum 2.0 lists Issue F as Invalid Issue in its index without a detailed card. It is not manufactured. Older Issue/Suggestion cards often do not print severity; these missing values remain explicit. Two reports have no recoverable Issue/Suggestion IDs.',
 'hexens': 'Report bf3b20… prints Low=12 but has six low cards; report 4015e4… prints Info=5 but has four info cards. Zharta February 2026 (89bfe4…) has displaced text columns and no recognized cards. Bahamut/Deposit (ff345d…) has conflicting certificate summaries and remains ambiguous.',
 'iosiro': 'Three aggregate tables count unlabelled code-quality advice as informational, while the advice rows print no severity. They remain recommendation/unknown. Infinex accounts prints seven low issues versus six detailed low cards. Reports without printed IDs cannot be called sequence-complete solely because they produce no rows.',
 'three-sigma': 'Tradable 98b560… has M04 explicitly classified High; InfiniFi July 3916a1… has four medium/four low details against two/two in its summary and repeats L03; Keyring July f8571d… has four medium classifications against summary high=2/medium=2. Ordiswap 7cfb24… ends before detailed findings. The no-summary zero cases are Layer3 (explicitly no vulnerabilities) and Liquity (narrative fix verification).',
 'informalsystems': 'Namada Governance 8844f7… prints twelve cards including conditional severities against a seven-item summary. Ripple 52a5908… lists zero medium/two low, but IF-FINDING-002 explicitly prints Medium. Many other Markdown artifacts contain coverage or issue links rather than full finding cards; modern cards often have no printed ID.',
 'coinspect': 'Three empty Aragon reviews explicitly state no issues. None/Zero are native labels outside the article severity mapping. Numeric ID gaps are checked against independent overview IDs rather than assumed to imply missing rows.',
 'sec3': 'Hyperlane 1a0d0f… repeats L-1 in its overview while the two detail sections correctly print L-1 and L-2. The overview ID mismatch stays visible. The three empty reports explicitly print zero issues. Two team findings omit severity, and Question is not silently normalized to info.',
 'chainlight': 'Theori audit revision 2.0 (89e479…) lists four issues in its contents, but cached body text loses the heading/risk glyphs. It remains an extraction limitation with zero manufactured formal rows. This prevents the no-summary subset from reaching the sequence target, despite the overall sequence census reaching its target.',
 'secure3': 'ClearDAO d51882… labels CLD-5 Low in its summary but Informational on detail page 14. P12 0de1be… labels P12-17 Medium in the index but Critical on detail page 33; its numeric chart also conflicts with detailed critical counts. The summary target remains unmet. Only nine eligible documents exist, and all were inspected.'
}


def write_report():
    data = json.loads((ROOT / 'data/findings/validation/group2_metrics.json').read_text())
    before = json.loads((ROOT / 'data/findings/validation/group2_baseline_metrics.json').read_text())
    docs = {d['document_id']:d for d in read_snapshot() if d['row']['firm_id'] in FIRMS}
    manifests = {}
    for firm in FIRMS:
        path = ROOT / f'data/findings/validation/{firm}_development.json'
        if firm == 'pashov-audit-group':
            entries = []
            for d in samples(firm):
                r = load_report(d)
                entries.append({'sha256':d['row']['sha256'], 'filename':d['row']['filename'],
                                'date_hint':d['row'].get('date_hint'), 'text_sha256':r.meta['text_sha256']})
            write_json(path, {'firm_id':firm, 'inspected_samples':entries,
                             'sample_method':'18 date/filename-spread distinct hashes, plus targeted regression documents',
                             'residuals':LIMITATIONS[firm]})
        if path.exists():
            dev = json.loads(path.read_text())
            manifests[firm] = dev.get('inspected_samples', dev.get('samples', dev.get('manifest', [])))
        elif firm in {'chainlight', 'secure3'}:
            dev = json.loads((ROOT / 'data/findings/validation/chainlight_secure3_development.json').read_text())
            manifests[firm] = dev[firm]['manifest']
        else:
            manifests[firm] = []
    def pct(value):
        return 'N/A' if value is None else f'{value:.2f}%'
    lines = ['# Phase 4b — group 2', '',
             'Generated by `python3 scripts/findings/test_group2.py --metrics --report`. All corpus reads are local and guarded by `data/holdout/gold_sha256.txt`; holdouts are excluded before cached text is opened. The frozen Phase 4 snapshot is preserved.', '',
             f"Scope: {sum(x['documents'] for x in data.values()):,} document occurrences; {sum(x['findings'] for x in data.values()):,} extracted rows ({sum(x['formal_findings'] for x in data.values()):,} formal finding occurrences). Duplicate original/source occurrences remain distinct. Before figures are the preserved pre-edit diagnostics in `group2_baseline_metrics.json`; after figures use the regenerated publisher outputs.", '',
             'Printed-summary agreement requires equality in every explicitly printed severity bucket. Expectations come from printed numeric tables/charts or stated aggregates, independently of detailed finding rows. Non-numeric indexes are used for ID checks, not invented severity totals. Repaired summary readers can change comparability; the before/after percentages are therefore reported with their own denominators. Source contradictions are retained, rather than changing detailed labels to force a match.', '',
             '| Publisher | Docs | Reviewed distinct texts | Rows before → after | Summary before | Summary after |',
             '|---|---:|---:|---:|---:|---:|']
    for firm in FIRMS:
        x,b = data[firm], before[firm]
        lines.append(f"| {firm} | {x['documents']} | {len(manifests[firm])} | {b['findings']:,} → {x['findings']:,} | {b['summary_matches']}/{b['summary_comparable']} ({pct(b['summary_agreement'])}) | {x['summary_matches']}/{x['summary_comparable']} ({pct(x['summary_agreement'])}) |")
    lines += ['', '## Documents without usable numeric totals', '',
              'The sequence column uses each publisher’s source index/ID hierarchy where available; plain prefix continuity is a fallback. Missing final IDs, source gaps and repeated source IDs remain explicit. “Unassessable” includes reports with no printed IDs or no recoverable finding text; these are not counted as successes. Ambiguous numeric summaries enter this subset. Explicitly clean reports are included in the raw nonempty percentages, so a low nonempty percentage is not itself evidence of a missed finding. The JSON also retains simple global-contiguity diagnostics and formal-only nonempty percentages.', '',
              '| Publisher | Sequence complete / subset | Complete among assessable | Unassessable | Audit reports with ≥1 row / subset | Missing title | Missing source severity | Unknown mapped severity |',
              '|---|---:|---:|---:|---:|---:|---:|---:|']
    for firm in FIRMS:
        x=data[firm]; seq=x['native_sequence_states']
        lines.append(f"| {firm} | {seq.get('complete',0)}/{x['no_summary_documents']} | {pct(x['native_sequence_complete_percent_assessable'])} | {seq.get('unassessable',0)} | {x['no_summary_audits_with_any_row']}/{x['no_summary_audit_reports']} ({pct(x['audit_any_row_percent'])}) | {x['missing_title']} | {x['missing_severity']} | {x['unknown_severity']} |")
    lines += ['', 'Missing source severity counts null/empty severity_raw; unknown mapped severity also includes native labels outside article-v1. Missing titles are retained when source code-quality advice has no title. These fields are not filled with invented values. Secure3’s no-summary documents are not classified audit_report in the frozen metadata, hence its audit-only denominator is empty.', '',
              'The 95% target is not universally met. The table exposes the shortfalls and denominator coverage; source conflicts, missing text, source ID gaps and absent ID schemes are documented below. No held-out accuracy or semantic precision/recall claim follows from count/ID agreement.', '',
              '## Publisher rules and residual classes', '']
    for firm in FIRMS:
        lines += [f'### {firm}', '', RULES[firm], '', LIMITATIONS[firm], '']
        failures = [d for d in data[firm]['documents_detail'] if d['validation'] in {'mismatch','parser_error','extraction_failed','ambiguous_printed_counts'}]
        for d in failures:
            row=docs[d['document_id']]['row']
            summary=(d.get('printed_summary') or {}).get('counts')
            parsed={k:v for k,v in d.get('parsed_counts',{}).items() if v}
            lines.append(f"- `{d['sha256']}` — [{row['filename']}]({row['public_url']}): {d['validation']}; printed `{summary}`, parsed `{parsed}`.")
        if failures:
            lines.append('')
        lines.append(f"Inspection/proof manifest: `data/findings/validation/{firm}_development.json`" if firm not in {'chainlight','secure3'} else 'Inspection/proof manifest: `data/findings/validation/chainlight_secure3_development.json`.')
        lines.append('')
    lines += ['## Validation and reproduction', '', '```sh',
              'python3 scripts/findings/run.py --firms '+ ' '.join(FIRMS),
              'python3 scripts/findings/test_group2.py --tests',
              'python3 scripts/findings/test_group2.py --metrics --verify --report',
              '```', '',
              'Publisher development evaluators retain independent printed-ID checks and reviewed SHA/name lists. `mixbytes_review.py FIRM --evaluate`, `least_authority_evaluate.py --write`, `three_sigma_evidence.py FIRM --output PATH`, and `chainlight_secure3_test.py --evaluate` regenerate their scoped evidence. The SlowMist evaluator is listed in the written-file manifest.', '',
              'Shared changes owned by group 2 are restricted to publisher dispatch in `scripts/findings/parsers/__init__.py` and source-preserving status normalization in `scripts/findings/core.py` (Unicode ligatures; explicit fixed-in/at, closed, partially resolved, patched and risk-accepted labels). The runner’s optional publisher printed_counts hook is a concurrent shared framework change used by these parsers. No database, collector, original, full-text cache, holdout, or other publisher parser was edited.', '',
              'All repository files written by this group are listed in `docs/phase4/group2_files.txt`. No commit or push was made.', '']
    test_path=ROOT/'data/findings/validation/group2_tests.json'
    check_path=ROOT/'data/findings/validation/group2_check.json'
    if test_path.exists() and check_path.exists():
        test_receipt=json.loads(test_path.read_text()); check_receipt=json.loads(check_path.read_text())
        lines += [f"Validation receipt: {test_receipt['tests']} regression tests; {test_receipt['failures']} failures and {test_receipt['errors']} errors. Scoped interchange validation checked {check_receipt['findings']:,} rows across {check_receipt['documents']:,} document occurrences, with {check_receipt['holdout_rows']} holdout rows. Receipts: `group2_tests.json` and `group2_check.json`.", '']
    (ROOT / 'docs/phase4/group2.md').write_text('\n'.join(lines))
    files = {'scripts/findings/test_group2.py', 'scripts/findings/core.py', 'scripts/findings/parsers/__init__.py',
             'docs/phase4/group2.md', 'docs/phase4/group2_files.txt'}
    for firm in FIRMS:
        files.add(f'data/findings/{firm}.jsonl')
        for p in (ROOT/'data/findings/validation').glob(firm+'*'):
            if p.is_file() and p.suffix in {'.json','.jsonl'}:
                files.add(str(p.relative_to(ROOT)))
        for p in (ROOT/'scripts/findings/parsers').glob(firm.replace('-','_')+'*.py'):
            files.add(str(p.relative_to(ROOT)))
    for p in (ROOT/'data/findings/validation').glob('group2*.json'):
        files.add(str(p.relative_to(ROOT)))
    for p in (ROOT/'data/findings/validation').glob('group2*.log'):
        files.add(str(p.relative_to(ROOT)))
    files.add('data/findings/validation/chainlight_secure3_development.json')
    for p in (ROOT/'tests').glob('test_*.py'):
        if p.name in {'test_mixbytes.py','test_blocksec.py','test_hexens.py','test_findings_three_sigma_coinspect_sec3.py'} or p.name.startswith('test_slowmist'):
            files.add(str(p.relative_to(ROOT)))
    (ROOT/'docs/phase4/group2_files.txt').write_text('\n'.join(sorted(files))+'\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--inspect', choices=FIRMS)
    p.add_argument('--sha')
    p.add_argument('--lines', type=int, default=35)
    p.add_argument('--pattern')
    p.add_argument('--context', type=int, default=0)
    p.add_argument('--failures', choices=FIRMS)
    p.add_argument('--metrics', action='store_true')
    p.add_argument('--baseline', action='store_true')
    p.add_argument('--verify', action='store_true')
    p.add_argument('--tests', action='store_true')
    p.add_argument('--report', action='store_true')
    a = p.parse_args()
    if a.inspect:
        docs = samples(a.inspect)
        if a.sha:
            if a.sha in holdouts():
                raise RuntimeError('Holdout inspection denied')
            docs = [d for d in read_snapshot() if d['row']['firm_id'] == a.inspect and d['row']['sha256'] == a.sha][:1]
        for d in docs:
            r = load_report(d)
            print('\nFILE', d['row']['sha256'], d['row']['filename'], d['row'].get('date_hint'))
            indices = set()
            for i, line in enumerate(r.lines):
                if re.search(a.pattern or r'severity|summary|findings|\[[^\]]+\]|^\s*\d+\.\d+\s|^\s*#{1,6} ', line.text, re.I):
                    indices.update(range(max(0, i-a.context), min(len(r.lines), i+a.context+1)))
            matches = [f'p{r.lines[i].page}: {r.lines[i].text[:250]}' for i in sorted(indices)]
            print('\n'.join(matches[:a.lines]))
    if a.failures:
        selected = {d['document_id']: d for d in read_snapshot() if d['row']['firm_id'] == a.failures}
        for line in (ROOT / f'data/findings/validation/{a.failures}.jsonl').open():
            d = json.loads(line)
            if d['document_id'] in selected and (d['validation'] == 'mismatch' or not d.get('findings')):
                print(d['sha256'], selected[d['document_id']]['row']['filename'], d['validation'], d.get('parsed_counts'), (d.get('printed_summary') or {}).get('counts'))
    if a.metrics or a.baseline:
        data = metrics()
        path = ROOT / ('data/findings/validation/group2_baseline_metrics.json' if a.baseline else 'data/findings/validation/group2_metrics.json')
        if a.baseline and path.exists():
            raise RuntimeError('Preserving existing baseline')
        write_json(path, data)
        for firm, row in data.items():
            print(firm, json.dumps({k:v for k,v in row.items() if k != 'documents_detail'}))
    if a.verify:
        verify()
    if a.tests:
        tests()
    if a.report:
        write_report()


if __name__ == '__main__':
    main()
