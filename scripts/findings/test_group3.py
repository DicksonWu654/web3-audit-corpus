"""Group 3 regression tests and deterministic, holdout-guarded development review.

Run from the repository: python3 scripts/findings/test_group3.py study FIRM ...
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import unittest
from common import ROOT, holdouts, read_snapshot, write_json, digest
from core import Report, finish, severity
from parsers import module
from summary_counts import printed_counts

FIRMS = ('sherlock', 'guardianaudits', 'halborn', 'shieldify', 'code4rena-zenith',
         'veridise', 'ackee-blockchain', 'bailsec', 'immunefi', 'oxorio', 'neodyme',
         'obsidian-audits', 'hats-finance')

GROUP_NOTES={
 'sherlock': 'Eras: early private-review PDF cards (including mini-audits and invalid-issue annotations), later PDF Issue headers, and official Markdown Issue headers. Explicit Severity fields take priority over ID prefixes; printed IDs are retained. Wrapped titles end before Source/Summary/Severity, not at the first physical line. Discussion references without detail metadata do not create findings. Residual classes: source severity/summary disagreements (Flux, `401cca64`); original ID gaps (`d2c1ef10`, M-2/M-3 absent); explicit clean reports or reports with no recoverable Issue sections (PinLink, `df08d461`); and one full-text extraction failure. Zero rows are not counted as a passed clean audit.',
 'guardianaudits': 'Eras: early project IDs (including mixed-case Global-1, numeric-prefix 20A-1 and bracketed SQD[1-F]-1), Markdown anchors around or before titles, pipe metadata tables with optional Commit columns, and modern letter-spaced severity/status cards with explicit review rounds. Category words such as Gas Optimization never set risk. Discussion entries remain observations with unknown article severity. Resolution-only continuation headers stay inside the preceding finding; distinct repeated IDs across review rounds remain distinct. Residual classes: stale front totals after remediation additions (Gamma MultiPositionManager `d1b077a0`, Unilaunch `956bcbf4`, Universal `f45b32ab`); table/detail severity conflicts (PariFi `b5ffa41a`, Peapods `24463757`, Yellow `01b2ce25`, whose four I-prefixed details explicitly say Low); absent detailed entries/count discrepancies (Ambit `1f505d1d`, Bridges 2 `0c44e191`, Poolshark Cover `38f5659f`); a native ID gap in PariFi Summary `3a1d9022`, where the index M-11 title is labelled M-12 in the detail; and consortium material without supported cards (Impermax `fa432a50`). Source contradictions remain mismatches.',
 'halborn': 'Eras: unnumbered 2020 wallet pentest titles, numbered legacy sections (including trailing dots), HAL IDs, Markdown-style HAL-only headings embedded in PDFs, and BVSS score suffixes. Running footers between title fragments are skipped; numbered Remediation Plan sections are not findings. Very Low maps to low and Information to info. SOLVED, PARTIALLY SOLVED and RISK ACCEPTED retain native status with explicit normalization. Residual classes: executive summaries with counts but no detailed findings (C3 `4f55a669`, Truffles `3b8840d8`); source charts that disagree with detailed risks/counts (Base `06c5b98e`/`7fd48705`, FinanceDotVote `3bf717da`, LID `ac3bf25f`); and the Anatha `e1754ae1` chart listing one medium although its four details are high/low/informational/informational. Incident analyses and summary-only files with no cards stay zero; they are not treated as clean audits.',
 'shieldify': 'Eras: Markdown severity-ID headings, PDF detail cards sharing an index page, severity/status badges above wrapped titles (including missing status), and OCR FINDING-prefixed headers with the title above or below the ID. Explicit risk takes priority over the ID; Information maps to info and gas stays gas. Explicit badges, fields and unambiguous ID/status overviews supply status. Residual classes: printed buckets without embedded corresponding details (GlueX gas `30f546a7`, Hlos info `22533d72`, Spellborne info `4e3386cb`); stale or contradictory totals (Shiny `af543de2`/`95661866`, Berabot `9655b89e`); damaged OCR that prevents reliable card recovery (Pear offchain `8b5d2421`, e.g. native header extracted as `(6-(0)1]`, with critical badges conflicting with a summary whose highest bucket is medium); and uncertain OCR IDs (Bankroll `9ca70978`, retaining I-O and 1-02/1-04 rather than inventing I-01 or rewriting a source character). Bankroll therefore fails the strict sequence diagnostic. Genuine clean reviews such as Ambire `3bf0a650`, Beef Finance `0458610e` and Pantheon `18410e8e` stay empty.',
 'code4rena-zenith': 'Eras: compact Severity/Status cards and later uppercase Severity/Impact/Likelihood cards. Only bracketed detail cards count; numbered severity section parents do not. Explicit Severity governs, never Impact. Titles can include a standalone zero and can cross physical page boundaries. Every comparable numeric summary matches. The sole no-total report is Swell `57066775`, which has no finding details or usable numeric severity totals; its empty output is not counted as a sequence pass.',
 'veridise': 'Eras: legacy numbered issues with Difficulty/Target/Finding ID metadata, V-project IDs with Commit/Type/Status fields, metadata above or below the heading, and later chapter-number changes. Moderate maps to medium and Warning remains unknown. Native -Severity Issues totals are independent of category counts. A detailed card missing its metadata can use an unambiguous exact-ID overview row (venture23 V-ORC-VUL-033 `ca79a022`); overview span evidence is retained. Multiple property IDs in one legacy issue card stay together in evidence rather than duplicating the shared finding. Residual classes: dashboard/detail classification conflicts (both Circom versions `b213e145`/`016dff8b`); compound/subset totals (Lombard `634a6e86` prints totals for its first 10 issues but embeds another 25); grouped native IDs (Dogechain `8fe8ced7` groups FV-003/FV-004/FV-005 in one Incorrect timeouts detail); stale totals (Untangled `c9927c60` low 3 vs four low details; Ziren `c7eed886` critical 8 vs seven critical details); and incompatible native summaries (Malda `50602899`/`90be009b`), reported as ambiguous.',
 'ackee-blockchain': 'Eras: 2021 narrative letter-ID findings, older numbered Impact/Likelihood cards, hyphenated H1 - titles, colon H1: titles, Info/Warning cards without a severity sentence, and F-suffixed follow-up IDs. Prefix risks are used only where the native ID is authoritative; impact is not silently used as risk for exploitable numbered legacy findings. Those reports retain null scalar severity when only separate impact/likelihood dimensions are printed. Overview statuses are recovered by exact ID. Residual classes: legacy section-number gaps (EverSOL `98f9fe98`, Axelar `19848ec6`), F-suffixed follow-ups outside simple numeric sequences (Helio `faad0de4`), and source-only impact dimensions without a scalar risk. Every cached audit has detailed rows; strict ID-gap failures are retained.',
 'bailsec': 'Eras: unnumbered Issue tables, Issue_nn tables with vertically centred IDs, qualified High* and split Severity fields, and compound initial/post-audit/extension reports. Compound numeric summaries are independently summed across separate printed report sections; repeated generic titles are not semantically deduplicated. Governance, Quality assurance and conditional-only risk labels remain unknown, distinct from ordinary informational findings. Residual classes: source severity-summary shifts (Camelot `eb0922d9`, Smardex `b38c5410`), source totals not updated for appended/post-audit detail (Liquify `482b9e43`, Usual/Redacted `ce757352`/`6dca0b61`), and a source count discrepancy (Kuma `e9cc48b2`). Formal-verification, non-disclosed, forensic and clean update documents without supported issue tables are explicitly zero/unevaluable. The summary target is not claimed where these contradictions persist.',
 'immunefi': 'Eras: early links containing SC - Low/Insight labels, Boost/IOP project-prefixed links, and newer bare submission-number lists. Only the Reports by Severity section is extracted; repeated Reports by Type and GitBook agent boilerplate are excluded. Insight remains unknown rather than being silently renamed informational. Titles truncated by the publisher remain truncated. There are no cached individual submission bodies or printed numeric per-severity totals, so formal-detail agreement and sequential-ID completeness are unavailable.',
 'oxorio': 'Eras: numbered section IDs, zero-width-prefixed headings, centred ID/title cards, and displaced chapter digits. For example, Lido Polygon `f678f08e` extracts .2.1 followed by 6 and a title continuation; the parser reconstructs source ID 6.2.1 and records both source fragments. Native Major maps high and Warning stays unknown. Numeric checks use the labelled Total/Amount column, not fixed-only counts. Every actual numeric summary and every evaluable no-total ID sequence matches. Marketing `811c5c6f` and deployment verification `a5dbce55` contain no vulnerability cards and remain empty. Fix reviews may use a source subset of the original numbering.',
 'neodyme': 'Eras: early severity-prefixed peer-review headings, unnumbered title-suffix risk/status (Anker `6debd89b`), wrapped Informational I01 headings (SPL Single Stake Pool `993d0a24`), C01 IDs and modern ND-project-risk-number tables. Split Affected/Component headers are excluded from titles. Status comes from a printed table cell or title annotation. Native prose totals supplement numeric summary tables. Appendices and severity definitions end the final body. Every comparable summary and evaluable sequence matches. Residual empty outputs are genuine clean reviews or technical design reviews without finding cards: Marinade Native Staking Proxy `ec285bd3`, Validator Bonds 2 `1115695b`, Validator Bonds 3 `ace34388`, and SPL Stake Pool 2023 `a79962f0`; zero rows still reduce nonempty coverage.',
 'obsidian-audits': 'Eras: wrapped severity-ID headings, Description/Summary cards and post-fix diff-review labels. Remediation labels are explicit; they do not change the finding severity. The sole strict ID-sequence failure is Oku (`cfa8c613`), which prints I-05 twice for different titles: generateOrderId() callable by any address and Unnecessary zero-approval of tokens. Both source occurrences are retained without renumbering. The resulting strict completeness falls below the target; this is a source numbering defect, not a missing finding.',
 'hats-finance': 'Eras: the early BFX PDF L01–L10 findings; numbered Ether.fi Markdown findings; and unnumbered bold bullet findings under severity headings. Indented Reported By/Summary bullets are not additional findings. Conclusion/disclaimer sections end the final body. The BFX prose aggregate and explicit zero high/medium counts are independently reconciled. Most Markdown reports intentionally have no printed IDs, so sequential-ID completeness is unavailable for them. All available reports contain findings; the sampling requirement cannot reach fifteen with only the available cache.'
}


def documents(firms=FIRMS):
    return [d for d in read_snapshot() if d['row']['firm_id'] in firms]


def load(d):
    sha = d['row']['sha256']
    if sha in holdouts():
        raise RuntimeError('Holdout inspection denied')
    base = ROOT / 'local-cache/fulltext'
    meta = json.loads((base / (sha + '.pages.json')).read_text())
    if meta.get('status') not in {'ok', 'partial'}:
        raise ValueError(meta.get('error', 'extraction_failed'))
    text = (base / (sha + '.txt')).read_bytes().decode('utf-8')
    assert digest(text.encode()) == meta['text_sha256']
    return Report(text, meta, d['row']['firm_id'])


def samples(ds):
    unique = {d['row']['sha256']: d for d in ds}
    ordered = sorted(unique.values(), key=lambda d: (d['row']['date_hint'] or '', d['row']['filename'], d['row']['sha256']))
    n = min(15, len(ordered))
    return [ordered[round(i * (len(ordered)-1) / max(1, n-1))] for i in range(n)]


def sequence(rows):
    """Check each printed numeric ID family, retaining review-round namespaces.

    IDs absent or not sequentially numbered are unevaluable, never automatic passes.
    A one-entry sequence still needs to begin at 0 or 1.
    """
    groups = defaultdict(list)
    for c in rows:
        pid = c.printed_id if hasattr(c, 'printed_id') else c.get('publisher_finding_id')
        ev = c.evidence if hasattr(c, 'evidence') else c.get('evidence', {})
        if ev.get('id_scheme')=='global_submission_id_noncontiguous':
            return None
        m = re.fullmatch(r'(.*?)(\d+)', pid or '')
        if m:
            groups[(ev.get('round', ''), m[1])].append(int(m[2]))
    if not groups:
        return None
    # The cardinality condition is equivalent to constructing a contiguous range,
    # but remains bounded for native timestamp-like IDs (L-1778070638067).
    return all(len(ns) == len(set(ns)) and min(ns) in {0, 1} and
               max(ns)-min(ns)+1 == len(ns) for ns in groups.values())


def baseline():
    existing=ROOT/'data/findings/validation/group3_before.json'
    if existing.exists() and all('row_quality' in s for s in json.loads(existing.read_text()).values()):
        raise SystemExit('Incoming baseline is frozen; refusing to replace it with current outputs.')
    out = {}
    for firm in FIRMS:
        stats = json.loads((ROOT / f'data/findings/validation/{firm}.json').read_text())
        counts,bydoc=output_metrics(firm)
        stats['row_quality']=counts
        diag={r['document_id']:r for r in map(json.loads,(ROOT/f'data/findings/validation/{firm}.jsonl').read_text().splitlines())}
        no_summary=[d for d in documents([firm]) if diag[d['document_id']]['validation'] in {'no_usable_printed_counts','ambiguous_printed_counts'}]
        checks=[sequence(bydoc.get(d['document_id'],[])) for d in no_summary]
        stats['sequence_evaluable']=sum(s is not None for s in checks)
        stats['sequence_complete']=sum(s is True for s in checks)
        out[firm] = stats
    write_json(ROOT / 'data/findings/validation/group3_before.json', out)
    print(json.dumps({f: {k: s[k] for k in ('documents', 'findings', 'matching_documents', 'comparable_documents', 'agreement_percent')} for f, s in out.items()}, indent=2))


def output_metrics(firm):
    counts=Counter()
    bydoc=defaultdict(list)
    blocked=holdouts()
    with (ROOT/f'data/findings/{firm}.jsonl').open() as stream:
        for line in stream:
            row=json.loads(line)
            assert row['sha256'] not in blocked
            counts['rows']+=1
            counts['formal']+=row['record_kind']=='formal_finding'
            counts['missing_title']+=not bool(row['title'])
            counts['missing_severity_raw']+=not bool(row['severity_raw'])
            counts['unknown_severity']+=row['severity']=='unknown'
            bydoc[row['document_id']].append({k:row[k] for k in ('publisher_finding_id','evidence','record_kind','severity')})
    return dict(counts),bydoc


def fraction(n,d):
    return f'{n}/{d} ({100*n/d:.2f}%)' if d else 'N/A (0 comparable)'


def report_results():
    """Verify every generated span and write the complete development audit ledger."""
    before=json.loads((ROOT/'data/findings/validation/group3_before.json').read_text())
    ds=documents()
    byfirm={f:[d for d in ds if d['row']['firm_id']==f] for f in FIRMS}
    all_results={}
    blocked=holdouts()
    for firm in FIRMS:
        docs=byfirm[firm]
        metadata={d['document_id']:d for d in docs}
        stats=json.loads((ROOT/f'data/findings/validation/{firm}.json').read_text())
        diagnostics={r['document_id']:r for r in map(json.loads,(ROOT/f'data/findings/validation/{firm}.jsonl').read_text().splitlines())}
        quality,bydoc=output_metrics(firm)
        evidence_rows=defaultdict(list)
        with (ROOT/f'data/findings/{firm}.jsonl').open() as stream:
            for line in stream:
                row=json.loads(line)
                assert row['sha256'] not in blocked
                d=metadata[row['document_id']]
                assert row['sha256']==d['row']['sha256']
                assert row['source_record_sha256']==d['source_record_sha256']
                assert row['severity']==row['severity_normalized']
                assert row['severity_raw']==row['severity_original']
                assert row['publisher_id']==firm
                assert digest(row['provenance']['extraction_record'])==row['provenance']['extraction_record_sha256']
                evidence_rows[row['document_id']].append(row)
        ids=[]
        residual=[]
        coverage=Counter()
        inventory=[]
        for d in docs:
            did=d['document_id']
            diag=diagnostics[did]
            rows=evidence_rows[did]
            formal=[r for r in rows if r['record_kind']=='formal_finding']
            coverage['audit_reports']+=d['row']['doc_kind']=='audit_report'
            coverage['audit_reports_with_formal']+=d['row']['doc_kind']=='audit_report' and bool(formal)
            coverage['documents_with_rows']+=bool(rows)
            no_counts=diag['validation'] in {'no_usable_printed_counts','ambiguous_printed_counts'}
            if no_counts:
                coverage['without_totals']+=1
                coverage['without_totals_audits']+=d['row']['doc_kind']=='audit_report'
                coverage['without_totals_audits_with_formal']+=d['row']['doc_kind']=='audit_report' and bool(formal)
                seq=sequence(formal)
                coverage['sequence_evaluable']+=seq is not None
                coverage['sequence_complete']+=seq is True
                item={'document_id':did,'sha256':d['row']['sha256'],'filename':d['row']['filename'],
                      'formal_findings':len(formal),'ids':[r['publisher_finding_id'] for r in formal],
                      'sequence_complete':seq,'summary_state':diag['validation']}
                ids.append(item)
                if seq is False or not rows:
                    residual.append(item|{'class':'printed_id_gap_or_duplicate' if seq is False else 'zero_rows_without_numeric_totals'})
            if diag['validation'] in {'mismatch','parser_error','extraction_failed','ambiguous_printed_counts'}:
                residual.append({'document_id':did,'sha256':d['row']['sha256'],'filename':d['row']['filename'],
                                 'class':diag['validation'],'parsed_counts':diag.get('parsed_counts'),
                                 'printed_summary':diag.get('printed_summary'),'error':diag.get('error')})
            if not rows and diag['validation']=='extraction_failed':
                continue
            r=load(d)
            for row in rows:
                span=row['body_span']
                assert 0<=span['start']<span['end']<=len(r.text)
                assert row['body_text']==r.text[span['start']:span['end']]
                assert span['text_sha256']==r.meta['text_sha256']
                assert span['original_sha256']==d['row']['sha256']
                pages=[p['page'] for p in r.meta['pages'] if p['end']>span['start'] and p['start']<span['end']]
                assert pages==span['pages'] and row['page']==pages[0]
            for proof in (diag.get('printed_summary') or {}).get('evidence',[]):
                if 'start' in proof and 'text' in proof:
                    assert proof['text']==r.text[proof['start']:proof['end']]
            if firm=='immunefi':
                # Independent of the severity/title parser: inventory all submission
                # IDs before the duplicate Reports by Type section.
                part=re.split(r'^## Reports by Type\s*$',r.text,flags=re.M)[0]
                expected=set()
                for bullet in part.splitlines():
                    if not bullet.startswith('* '):
                        continue
                    pm=re.search(r'\b(\d{4,})\s*-?\s*\[',bullet.replace('\\',''))
                    if pm:
                        expected.add(pm[1])
                actual=[row['publisher_finding_id'] for row in rows]
                inventory.append({'sha256':d['row']['sha256'],'expected_ids':len(expected),'parsed_ids':len(actual),
                                  'missing_ids':sorted(expected-set(actual)),'extra_ids':sorted(set(actual)-expected),
                                  'duplicates':len(actual)-len(set(actual))})
        sample=[{'sha256':d['row']['sha256'],'filename':d['row']['filename'],'date_hint':d['row']['date_hint'],
                 'public_url':d['row']['public_url']} for d in samples(docs)]
        all_results[firm]={'stats':stats,'quality':quality,'coverage':dict(coverage),'sample':sample,
                           'id_checks_without_totals':ids,'residuals':residual,'listing_id_checks':inventory,
                           'targets':{'summary_95_percent':stats['matching_documents']*100>=95*stats['comparable_documents'] if stats['comparable_documents'] else None,
                                      'sequence_95_percent':coverage['sequence_complete']*100>=95*coverage['sequence_evaluable'] if coverage['sequence_evaluable'] else None,
                                      'fifteen_reviewed_originals':len(sample)>=15},
                           'output_sha256':digest((ROOT/f'data/findings/{firm}.jsonl').read_bytes())}
        print(firm,stats['findings'],fraction(stats['matching_documents'],stats['comparable_documents']),
              'sequence',fraction(coverage['sequence_complete'],coverage['sequence_evaluable']),flush=True)
    result={'holdouts_opened':0,'scope':list(FIRMS),'by_firm':all_results,
            'holdout_list_sha256':digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes()),
            'snapshot_sha256':digest((ROOT/'data/fulltext/input_documents.jsonl').read_bytes()),
            'parser_sources':{f:digest(Path(module(f).__file__).read_bytes()) for f in FIRMS},
            'shared_framework_sources':{p:digest((ROOT/p).read_bytes()) for p in ('scripts/findings/core.py','scripts/findings/parsers/__init__.py')},
            'method':'Frozen development snapshot; occurrence counts, independent numeric severity summaries; exact source spans checked.'}
    write_json(ROOT/'data/findings/validation/group3_review.json',result)
    lines=['# Phase 4b group 3 — publisher findings extraction','',
           'Reproduce: `python3 scripts/findings/test_group3.py test`, then `python3 scripts/findings/run.py --firms '+ ' '.join(FIRMS)+'`, then `python3 scripts/findings/test_group3.py report`. No collection refresh or network access is used.', '',
           'All figures exclude the holdout list before text access. Counts refer to source document occurrences, not unique audits or vulnerabilities. Every output body and numeric-summary proof was verified against its content-addressed full-text slice. `group3_before.json` freezes the incoming Phase 4a statistics and row-quality/ID diagnostics; do not overwrite it with a post-change baseline. `group3_review.json` records current metrics, selected samples, every residual document, exact numeric summary proofs and output hashes.', '',
           'Agreement requires equality in every explicitly printed severity bucket. Missing buckets remain unspecified. Native Veridise and Oxorio Warning labels remain `unknown`, and are compared as a separate printed bucket when the table includes them. Conflicting summaries and extraction failures are reported separately. Veridise category counts are excluded; Oxorio uses the labelled Total/Amount column. Bailsec compound audits use the sum of independently printed Found tables only when intervening detail sections establish separate report sections. No detail finding is added or relabelled using a numeric total.', '',
           'Sequence completeness below is strict contiguous numbering starting at zero or one, with no duplicates, within each printed ID prefix and explicit review-round namespace. The denominator includes only documents without usable numeric totals that expose sequential IDs. Empty outputs and absent/nonsequential ID schemes are unevaluable, never passes; the coverage table shows those denominators. This is a development diagnostic, not gold precision/recall.', '',
           'Verification: '+str(unittest.defaultTestLoader.loadTestsFromTestCase(Group3Tests).countTestCases())+' focused regression tests pass, including every assigned publisher, negative TOC/code/reference cases, appendix bounds and holdout denial. The wider `test_framework.py` suite retains an unrelated failure in `test_wrapped_pdf_toc_and_summary_rows_are_not_details` in the concurrently edited Pashov parser; this group did not alter that module.', '',
           '| Publisher | Docs | Rows before → after | Summary before | Summary after | Sequence without totals (before → after) |',
           '|---|---:|---:|---:|---:|---:|']
    for firm,res in all_results.items():
        b=before[firm];s=res['stats'];c=res['coverage']
        lines.append(f"| {firm} | {s['documents']} | {b['findings']} → {s['findings']} | {fraction(b['matching_documents'],b['comparable_documents'])} | {fraction(s['matching_documents'],s['comparable_documents'])} | {fraction(b.get('sequence_complete',0),b.get('sequence_evaluable',0))} → {fraction(c.get('sequence_complete',0),c.get('sequence_evaluable',0))} |")
    lines+=['','| Publisher | Without totals | Sequence unevaluable | Audit reports ≥1 formal finding (without totals) | Audit reports ≥1 formal finding (all) | All documents ≥1 row | Missing title / raw severity | Unknown article severity |',
            '|---|---:|---:|---:|---:|---:|---:|---:|']
    for firm,res in all_results.items():
        c=res['coverage'];q=res['quality']
        lines.append(f"| {firm} | {c.get('without_totals',0)} | {c.get('without_totals',0)-c.get('sequence_evaluable',0)} | {fraction(c.get('without_totals_audits_with_formal',0),c.get('without_totals_audits',0))} | {fraction(c.get('audit_reports_with_formal',0),c.get('audit_reports',0))} | {fraction(c.get('documents_with_rows',0),res['stats']['documents'])} | {q.get('missing_title',0)} / {q.get('missing_severity_raw',0)} | {q.get('unknown_severity',0)} |")
    unmet=[f+': '+', '.join(k for k,v in res['targets'].items() if v is False) for f,res in all_results.items() if any(v is False for v in res['targets'].values())]
    lines+=['','## Acceptance gates','',
            'The requested gates are not all met. The remaining failed gates are listed explicitly; no summary contradiction or source numbering defect was hidden to meet a threshold. A null gate means no comparable source data, not a pass.','']
    lines+=['- '+item for item in unmet]
    lines+=['','Hats has only twelve unique available development originals; all twelve were reviewed. Immunefi has indexes rather than acquired finding bodies: all published IDs are reconciled, but formal-detail summary/sequence gates are unavailable. The per-publisher table above reports missing titles/severities and audit nonempty coverage without treating empty outputs as successful clean findings.','',
            '## Layouts, scale and residual classes','']
    for firm,res in all_results.items():
        lines += ['### '+firm,'',module(firm).DESCRIPTION+'.','',
                  'Reviewed '+str(len(res['sample']))+' distinct development originals selected across metadata date hints and filenames; the complete sample ledger follows. '+('Only twelve originals are available in the frozen Hats cache, so reviewing fifteen is impossible without new collection; all available originals were reviewed.' if firm=='hats-finance' else ''),'',
                  GROUP_NOTES.get(firm,''),'']
        if res['listing_id_checks']:
            checks=res['listing_id_checks']
            ok=sum(not c['missing_ids'] and not c['extra_ids'] and not c['duplicates'] for c in checks)
            lines+=['Immunefi global submission IDs do not form per-contest sequences. Independent listing-ID inventory agreement: '+fraction(ok,len(checks))+'. Every extracted row is a `summary_excerpt`; linked detail reports were not acquired or invented.','']
        failures=res['residuals']
        if failures:
            lines+=['Residual document ledger (all occurrences; repeated hashes can have distinct metadata occurrences):','',
                    '| Class | SHA-256 | Source filename |','|---|---|---|']
            for issue in failures:
                filename=issue['filename'].replace('|','\\|')
                lines.append(f"| {issue['class']} | `{issue['sha256']}` | {filename} |")
            lines.append('')
        lines+=['Sampled originals:','']
        for d in res['sample']:
            lines.append(f"- `{d['sha256']}` — {d['filename']} (date hint: {d['date_hint'] or 'absent'}).")
        lines.append('')
    lines+=['## Files written','',
            'Shared-framework edits by this group: publisher registration in `scripts/findings/parsers/__init__.py`, and a backward-compatible exception to the 45-character detail filter in `scripts/findings/core.py` for nonempty, explicitly bounded `summary_excerpt` rows with titles. The latter preserves short Immunefi source lines without including the next listing item. The filter for detailed findings is unchanged. Existing optional summary/status/phase hooks supplied by concurrent framework work are used without editing their implementations. No other publisher module, source collection, original, full-text cache, holdout or database was changed.','']
    paths=[f'scripts/findings/parsers/{f.replace("-","_")}.py' for f in FIRMS]
    paths+=['scripts/findings/parsers/__init__.py','scripts/findings/core.py','scripts/findings/test_group3.py','docs/phase4/group3.md',
            'data/findings/validation/group3_before.json','data/findings/validation/group3_review.json']
    paths += [p for f in FIRMS for p in (f'data/findings/{f}.jsonl',f'data/findings/validation/{f}.jsonl',f'data/findings/validation/{f}.json')]
    lines += ['- `'+p+'`' for p in paths]
    (ROOT/'docs/phase4/group3.md').write_text('\n'.join(lines)+'\n')


def fixture(text, firm, fmt='pdf'):
    if fmt=='pdf':
        text='Front matter\n\f'*4+text
    pages=[]
    start=0
    for i,page in enumerate(text.split('\f'),1):
        pages.append({'page':i,'text':page,'start':start,'end':start+len(page)})
        start+=len(page)+1
    return Report(text,{'pages':pages,'text_sha256':digest(text.encode()),'file_format':fmt},firm)


class Group3Tests(unittest.TestCase):
    def parsed(self, text, firm, fmt='pdf'):
        r=fixture(text,firm,fmt)
        return r,finish(r,module(firm).parse(r))

    def test_halborn_wrapped_title_ends_in_information_word(self):
        r,cs=self.parsed('3.1 (HAL-01) OUTDATED INFORMATION\nDISPLAYED TO USERS - INFORMATIONAL (0.0)\nDescription:\n'+ 'Evidence.\n'*8,'halborn')
        self.assertEqual(len(cs),1)
        self.assertEqual(cs[0].title,'OUTDATED INFORMATION DISPLAYED TO USERS')
        self.assertEqual(cs[0].severity_raw,'INFORMATIONAL')

    def test_halborn_title_word_impacts_is_not_metadata(self):
        r,cs=self.parsed('3.4 (HAL-04) PARAMETER UPDATE\nIMPACTS ALL USERS - MEDIUM\nDescription:\n'+'Evidence.\n'*8,'halborn')
        self.assertEqual(cs[0].title,'PARAMETER UPDATE IMPACTS ALL USERS')

    def test_halborn_toc_is_not_detail(self):
        r,cs=self.parsed('3.1 (HAL-01) TITLE - HIGH\nDescription                   12\n\f3.1 (HAL-01) TITLE - HIGH\nDescription:\n'+'Evidence.\n'*8,'halborn')
        self.assertEqual(len(cs),1)

    def test_halborn_running_header_can_split_title_and_risk(self):
        r,cs=self.parsed('3.5 (HAL-05) INFINITE ALLOWANCE -\nFINDINGS & TECH DETAILS\n\n\n\n\nINFORMATIONAL\nDescription:\n'+'Evidence.\n'*8,'halborn')
        self.assertEqual(cs[0].title,'INFINITE ALLOWANCE')
        self.assertEqual(cs[0].severity_raw,'INFORMATIONAL')

    def test_halborn_inline_status_and_hal_only_heading(self):
        r,cs=self.parsed('3.4 (HAL-04) DELETED POOL -\nLOW LowRISK ACCEPTED\nDescription:\n'+'Evidence.\n'*8+'## (HAL-30) ZERO CHECK - INFORMATIONAL\nDescription:\n'+'Evidence.\n'*8,'halborn')
        self.assertEqual([c.printed_id for c in cs],['HAL-04','HAL-30'])
        self.assertEqual(cs[0].title,'DELETED POOL')
        self.assertEqual(cs[0].severity_raw,'LOW')

    def test_halborn_unnumbered_pentest_heading(self):
        r,cs=self.parsed('Insecure Use of\nDocument.Location - LOW\nDescription:\n'+'Evidence.\n'*8,'halborn')
        self.assertEqual(cs[0].title,'Insecure Use of Document.Location')

    def test_halborn_numbered_remediation_is_not_an_extra_finding(self):
        text='3.11 Remediation Plan\nPARTIALLY SOLVED: updated code\n3.12 (HAL-11) IMPRECISION - INFORMATIONAL\nDescription:\n'+'Evidence.\n'*8
        r,cs=self.parsed(text,'halborn')
        self.assertEqual([c.printed_id for c in cs],['HAL-11'])

    def test_halborn_uncoloned_remediation_status(self):
        text='3.1 (HAL-01) ACTUAL ISSUE - LOW\nDescription:\n'+'Evidence.\n'*8+'3.11 Remediation Plan\nPARTIALLY SOLVED: updated code\n'
        r,cs=self.parsed(text,'halborn')
        self.assertEqual(cs[0].status_raw,'PARTIALLY SOLVED')
        self.assertEqual(cs[0].normalized_status,'partial')

    def test_pdf_fence_does_not_hide_next_zenith_card(self):
        r,cs=self.parsed('```\n[H-1] Wrapped title\ncontinued\nSEVERITY: High     IMPACT: Low\nSTATUS: Resolved\n'+'Evidence.\n'*8,'code4rena-zenith')
        self.assertEqual(cs[0].title,'Wrapped title continued')
        self.assertEqual(cs[0].severity_raw,'High')

    def test_zenith_section_parent_is_not_finding(self):
        r,cs=self.parsed('4.1 High\nA total of 1 high findings were identified.\n[H-1] Actual issue\nSEVERITY: High    IMPACT: High\n'+'Evidence.\n'*8,'code4rena-zenith')
        self.assertEqual([c.printed_id for c in cs],['H-1'])

    def test_zenith_numeric_title_continuation_is_not_page_number(self):
        r,cs=self.parsed('[L-10] Graduation fee is\n0\nSEVERITY: Low    IMPACT: Low\n'+'Evidence.\n'*8,'code4rena-zenith')
        self.assertEqual(cs[0].title,'Graduation fee is 0')

    def test_zenith_detail_card_can_cross_page_boundary(self):
        text='[L-1] Actual title\n 21\n\fPROJECT   SMART CONTRACT SECURITY ASSESSMENT   VERSION 1.1\nSEVERITY: Low    IMPACT: Low\n'+'Evidence.\n'*8
        r,cs=self.parsed(text,'code4rena-zenith')
        self.assertEqual(cs[0].title,'Actual title')

    def test_shieldify_index_page_can_also_have_detail(self):
        r,cs=self.parsed('ID   Title   Severity   Status\n[L-01]  Title  Low  Fixed\n[L-01] Actual issue\nSeverity\nLow Risk\nDescription\n'+'Evidence.\n'*8,'shieldify')
        self.assertEqual(len(cs),1)
        self.assertEqual(cs[0].title,'Actual issue')

    def test_shieldify_new_badge_above_id(self):
        r,cs=self.parsed('MEDIUM       FIXED\nM-01       Actual issue\ncontinued title\nDescription\n'+'Evidence.\n'*8,'shieldify')
        self.assertEqual(cs[0].status_raw,'FIXED')
        self.assertEqual(cs[0].title,'Actual issue continued title')

    def test_shieldify_badge_can_omit_status(self):
        r,cs=self.parsed('INFO\nI-12  A Scheduled Exit Never Expires\nDescription\n'+'Evidence.\n'*8,'shieldify')
        self.assertEqual(cs[0].severity_raw,'INFO')
        self.assertIsNone(cs[0].status_raw)

    def test_shieldify_finding_prefix_keeps_uncertain_ocr_id(self):
        r,cs=self.parsed('FINDING I-O\nNew depositors capture fees\nDescription\n'+'Evidence.\n'*8,'shieldify')
        self.assertEqual(cs[0].printed_id,'I-O')
        self.assertEqual(cs[0].title,'New depositors capture fees')
        self.assertTrue(cs[0].evidence['ocr_id_uncertain'])

    def test_shieldify_title_above_finding_id(self):
        r,cs=self.parsed('Position Key Is Recomputed Instead of Cached\nFINDING I-09\nDescription\n'+'Evidence.\n'*8,'shieldify')
        self.assertEqual(cs[0].title,'Position Key Is Recomputed Instead of Cached')

    def test_shieldify_uncertain_ocr_code_is_not_a_severity_label(self):
        r,cs=self.parsed('FINDING 1-02\nActual issue\nDescription\n'+'Evidence.\n'*8,'shieldify')
        self.assertIsNone(cs[0].severity_raw)
        self.assertEqual(cs[0].normalized,'unknown')

    def test_shieldify_md_missing_severity_uses_printed_id(self):
        r,cs=self.parsed('# [I-02] Missing event\nA short published issue.\n'+'Evidence.\n'*8,'shieldify','md')
        self.assertEqual(cs[0].normalized,'info')

    def test_guardian_continued_header_not_new_issue(self):
        r,cs=self.parsed('LOW  L-01  RESOLVED\nActual title\nCATEGORY  Logic\n'+'Evidence.\n'*8+'L-01 Actual title  CONTINUED\n'+'Continuation.\n'*8,'guardianaudits')
        self.assertEqual(len(cs),1)
        self.assertEqual(cs[0].title,'Actual title')

    def test_guardian_empty_status_in_remediation_round(self):
        r,cs=self.parsed('MEDIUM\n M-01\nNew issue\nC AT EG O RY  Logical Error\nREVIEW Remediation Review\n'+'Evidence.\n'*8,'guardianaudits')
        self.assertEqual(len(cs),1)
        self.assertIsNone(cs[0].status_raw)

    def test_guardian_commit_column_and_category_do_not_set_risk(self):
        r,cs=self.parsed('GMX-1 | Actual issue\n Category       Severity   Commit      Location    Status\n Gas Optimization   High   abcdef      file.sol    Resolved\nDescription\n'+'Evidence.\n'*8,'guardianaudits')
        self.assertEqual(severity(cs[0].severity_raw),'high')

    def test_guardian_legacy_contract_ids_and_native_unresolved_status(self):
        text=''
        for pid in ('Global-1','20A-1','721A-1','SQD[1-F]-1'):
            text+=pid+' | Actual issue\n Category              Severity       Location       Status\n Logic Error           Medium         file.sol       Unresolved\nDescription\n'+'Evidence.\n'*8
        r,cs=self.parsed(text,'guardianaudits')
        self.assertEqual([c.printed_id for c in cs],['Global-1','20A-1','721A-1','SQD[1-F]-1'])
        self.assertTrue(all(c.severity_raw=='Medium' and c.status_raw=='Unresolved' for c in cs))

    def test_guardian_anchor_can_wrap_id_and_title(self):
        r,cs=self.parsed('### <a id="H02"> H-02 Missing access control </a>\n### Description:\n'+'Evidence.\n'*8,'guardianaudits','md')
        self.assertEqual(cs[0].printed_id,'H-02')
        self.assertEqual(cs[0].title,'Missing access control')

    def test_halborn_risk_diagram_ids_are_not_detail_cards(self):
        r,cs=self.parsed('(HAL-01) (HAL-02)\n3 - 1 - VERY LOW AND INFORMATIONAL\nDescription:\n'+'Evidence.\n'*8,'halborn')
        self.assertEqual(cs,[])

    def test_veridise_gas_category_is_not_risk_count(self):
        r=fixture('Critical-Severity Issues 0 0\nHigh-Severity Issues 1 1\nWarning-Severity Issues 2 1\nGas Optimization 9\n','veridise')
        s=module('veridise').printed_counts(r)
        self.assertEqual(s['counts'],{'critical':0,'high':1,'info':2})
        self.assertEqual(module('veridise').parse(r),[])

    def test_veridise_warning_and_status(self):
        r,cs=self.parsed('4.1.1 V-ABC-VUL-001: Wrapped title\ncontinued\nSeverity Warning    Commit abcdef\nType Logic Error    Status Partially Fixed\n'+'Evidence.\n'*8,'veridise')
        self.assertEqual(cs[0].severity_raw,'Warning')
        self.assertEqual(cs[0].status_raw,'Partially Fixed')
        self.assertEqual(cs[0].title,'Wrapped title continued')

    def test_veridise_missing_card_metadata_uses_explicit_id_overview(self):
        text='V-ORC-VUL-033     Defensive Programming Gaps    Warning    Fixed\n4.1.33 V-ORC-VUL-033: Defensive Programming Gaps\nDescription Across the repositories\n'+'Evidence.\n'*8
        r,cs=self.parsed(text,'veridise')
        self.assertEqual(cs[0].severity_raw,'Warning')
        self.assertEqual(cs[0].status_raw,'Fixed')
        self.assertEqual(cs[0].title,'Defensive Programming Gaps')
        self.assertEqual(cs[0].evidence['severity_basis'],'explicit_issue_overview')
        proof=cs[0].evidence['status_evidence']
        self.assertEqual(r.text[proof['start']:proof['end']],'Fixed')
        self.assertEqual(proof['basis'],'explicit_issue_overview')

    def test_veridise_title_type_word_and_legacy_native_id(self):
        r,cs=self.parsed('4.1.1 Calls WriteHeader before setting\nContent-Type\nSeverity Warning    Difficulty Easy\nType Logic    Finding ID V-DOGE-VUL-001\nStatus Open\n'+'Evidence.\n'*8,'veridise')
        self.assertEqual(cs[0].title,'Calls WriteHeader before setting Content-Type')
        self.assertEqual(cs[0].printed_id,'V-DOGE-VUL-001')

    def test_veridise_metadata_can_precede_detail_heading(self):
        text='Severity High    Difficulty Medium\nType Logic   Finding ID V-DOGE-VUL-002\nStatus Fixed\n\n4.1.2 Missing validation\nDescription A detailed issue.\n'+'Evidence.\n'*8
        r,cs=self.parsed(text,'veridise')
        self.assertEqual(cs[0].printed_id,'V-DOGE-VUL-002')
        self.assertEqual(cs[0].title,'Missing validation')
        self.assertEqual(cs[0].status_raw,'Fixed')

    def test_ackee_hyphen_title_uses_id_not_impact(self):
        r,cs=self.parsed('H1 - Actual issue\nImpact: Medium   Likelihood: High\nTarget: file.sol  Type: Logic\nDescription\n'+'Evidence.\n'*8,'ackee-blockchain')
        self.assertEqual(cs[0].normalized,'high')
        self.assertEqual(cs[0].title,'Actual issue')

    def test_ackee_summary_last_row_is_not_detail(self):
        r,cs=self.parsed('I1: Summary title     Info  1.0  Fixed\n\fI1: Actual issue\nImpact: Info    Likelihood: N/A\nTarget: file.sol   Type: Logic\n'+'Evidence.\n'*8,'ackee-blockchain')
        self.assertEqual(len(cs),1)

    def test_bailsec_centered_id_title_and_split_severity(self):
        r,cs=self.parsed('                  First title line\nIssue_01\n                  continued\nSeverity\nInformational\nDescription  Details\n'+'Evidence.\n'*8,'bailsec')
        self.assertEqual(cs[0].title,'First title line continued')
        self.assertEqual(cs[0].severity_raw,'Informational')

    def test_bailsec_independent_appendix_tables(self):
        r=fixture('Severity Found\nHigh 1 1\nLow 2 2\nIssue_01  Detailed issue\n'+'Evidence.\n'*8+'Extension\nSeverity Found\nHigh 2 2\nLow 3 3\n','bailsec')
        self.assertEqual(module('bailsec').printed_counts(r)['counts'],{'high':3,'low':5})

    def test_oxorio_zero_width_heading_and_total_column(self):
        r,cs=self.parsed('\u200b2.1.1 Actual issue\nSeverity   MA JOR\nStatus   NO_ISSUE\nDescription\n'+'Evidence.\n'*8+'Severity   FIXED   ACKNOWLEDGED   Total\nCRITICAL   0   0   0\nMAJOR   0   1   1\nINFO   1   2   3\n','oxorio')
        self.assertEqual(cs[0].title,'Actual issue')
        self.assertEqual(severity(cs[0].severity_raw,'oxorio'),'high')
        self.assertEqual(module('oxorio').printed_counts(r)['counts']['info'],3)

    def test_neodyme_split_affected_header(self):
        r,cs=self.parsed('No fees for failed bundles (Informational; Acknowledged)\n   Affected\nSeverity     Impact    Component    Status\nInformational   Spam   Validator   Acknowledged\n'+'Evidence.\n'*8,'neodyme')
        self.assertEqual(cs[0].title,'No fees for failed bundles')

    def test_neodyme_early_title_risk_and_wrapped_coded_title(self):
        r,cs=self.parsed('Missing validation (Critical; Resolved)\n'+'Evidence.\n'*8+'Informational I01 - Pools cannot be\ndeposited into until stake is activated\n\n'+'Evidence.\n'*8,'neodyme')
        self.assertEqual([c.title for c in cs],['Missing validation','Pools cannot be deposited into until stake is activated'])
        self.assertEqual(cs[0].status_raw,'Resolved')
        self.assertEqual(cs[1].printed_id,'I01')

    def test_neodyme_printed_prose_totals(self):
        r=fixture('The audit team reported a total of 0 findings, of which\n • 0 were high,\n • 0 were medium,\n • 0 were low, and\n • 0 were informational.\n','neodyme')
        self.assertEqual(module('neodyme').printed_counts(r)['counts'],{'high':0,'medium':0,'low':0,'info':0})

    def test_oxorio_displaced_chapter_digit(self):
        r,cs=self.parsed('\u200b .2.1 Incorrect state if validator becomes\n6\nUnstaked\nSeverity   MAJOR\nStatus   FIXED\nDescription\n'+'Evidence.\n'*8,'oxorio')
        self.assertEqual(cs[0].printed_id,'6.2.1')
        self.assertEqual(cs[0].title,'Incorrect state if validator becomes Unstaked')
        self.assertEqual(len(cs[0].evidence['id_fragments']),2)

    def test_immunefi_listings_are_excerpts_and_not_duplicated(self):
        text='## Reports by Severity\n<summary>Low</summary>\n* [Boost ABC 12345 - \\[SC - Low\\] Actual title](/detail.md)\n## Reports by Type\n* [12345 - \\[SC - Low\\] Actual title](/detail.md)\n'
        r,cs=self.parsed(text,'immunefi','md')
        self.assertEqual(len(cs),1)
        self.assertEqual(cs[0].printed_id,'12345')
        self.assertEqual(cs[0].record_kind,'summary_excerpt')
        self.assertNotIn('Reports by Type',r.text[cs[0].start:cs[0].end])

    def test_immunefi_short_excerpt_keeps_exact_source_line(self):
        text='## Reports by Severity\n<summary>Low</summary>\n* \\#58575 \\[SC-Low] Operator Limit Bypass\n## Reports by Type\n'
        r,cs=self.parsed(text,'immunefi','md')
        self.assertEqual([c.printed_id for c in cs],['58575'])
        self.assertEqual(r.text[cs[0].start:cs[0].end],'* \\#58575 \\[SC-Low] Operator Limit Bypass')

    def test_hats_nested_summary_is_not_another_finding(self):
        r,cs=self.parsed('## Medium severity issues\n1. **Actual title**\n   - **Summary:** A description.\n'+'Details.\n'*8+'## Conclusion\nNo more findings.\n','hats-finance','md')
        self.assertEqual(len(cs),1)
        self.assertEqual(cs[0].title,'Actual title')
        self.assertNotIn('Conclusion',r.text[cs[0].start:cs[0].end])

    def test_obsidian_duplicate_printed_ids_are_retained(self):
        text='[I-05] First published title\nDescription\n'+'Evidence.\n'*8+'[I-05] Second published title\nDescription\n'+'Evidence.\n'*8
        r,cs=self.parsed(text,'obsidian-audits')
        self.assertEqual(len(cs),2)
        self.assertFalse(sequence(cs))

    def test_sherlock_wrapped_title_and_id_annotation(self):
        r,cs=self.parsed('Issue I-09 (from mini-audit)\nActual title\ncontinued\nSeverity\nInformational\n'+'Evidence.\n'*8,'sherlock')
        self.assertEqual(cs[0].title,'Actual title\ncontinued')
        self.assertEqual(cs[0].printed_id,'I-09')

    def test_sherlock_body_reference_without_metadata_is_not_heading(self):
        r,cs=self.parsed('Issue M-1: Actual title\nSource: https://example.org/1\n'+'Evidence.\n'*20+'Issue M-6: Discussion reference\n'+'Prose.\n'*20,'sherlock')
        self.assertEqual([c.printed_id for c in cs],['M-1'])

    def test_holdout_denied_before_fulltext_open(self):
        from unittest.mock import patch
        sha='a'*64
        with patch(__name__+'.holdouts',return_value={sha}),patch.object(Path,'read_text',side_effect=AssertionError('Opened cache')):
            with self.assertRaisesRegex(RuntimeError,'Holdout'):
                load({'row':{'sha256':sha}})

    def test_timestamp_like_printed_id_is_a_gap_without_large_allocation(self):
        self.assertFalse(sequence([{'publisher_finding_id':'L-01','evidence':{}},
                                   {'publisher_finding_id':'L-1778070638067','evidence':{}}]))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('baseline', 'study', 'peek', 'dump', 'gaps', 'evaluate', 'report', 'test'))
    p.add_argument('firms', nargs='*')
    p.add_argument('--sha')
    p.add_argument('--match')
    p.add_argument('--page', type=int)
    p.add_argument('--lines', type=int, default=14)
    p.add_argument('--start', type=int, default=0)
    p.add_argument('--trace',action='store_true',help='Print document hashes before parsing for local performance diagnosis')
    a = p.parse_args()
    if a.trace:
        import faulthandler
        faulthandler.dump_traceback_later(5)
    if a.action == 'baseline':
        baseline()
        return
    if a.action == 'test':
        unittest.main(argv=['test_group3'])
        return
    if a.action == 'report':
        report_results()
        return
    ds = documents(a.firms or FIRMS)
    if a.sha:
        ds=[d for d in ds if d['row']['sha256'].startswith(a.sha)]
    if a.action in {'study', 'peek', 'dump','gaps'}:
        if a.action in {'peek','dump','gaps'}:
            ds = [d for d in ds if d['row']['sha256'].startswith(a.sha or 'INVALID')]
            ds = list({d['row']['sha256']: d for d in ds}.values())
        else:
            ds = [d for f in (a.firms or FIRMS) for d in samples([d for d in ds if d['row']['firm_id'] == f])]
        pattern = re.compile(a.match or r'(?:severity|risk|finding|issue|^\s*#{1,4} |^\s*(?:\d+[.)]|[A-Z]{1,8}[-_]\d+)|\b(?:CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)\b)', re.I)
        for d in ds:
            print('\nDOC', d['row']['firm_id'], d['row']['sha256'], d['row']['date_hint'], d['row']['filename'])
            try:
                r = load(d)
            except (ValueError, FileNotFoundError) as e:
                print('EXTRACTION FAILURE', str(e))
                continue
            if a.action=='dump':
                parser=module(d['row']['firm_id'])
                cs=finish(r,parser.parse(r))
                print('SUMMARY',getattr(parser,'printed_counts',printed_counts)(r))
                for c in cs[a.start:a.start+a.lines]:
                    print(c.start,c.printed_id,repr(c.title),repr(c.severity_raw),repr(c.status_raw))
                continue
            if a.action=='gaps':
                cs=finish(r,module(d['row']['firm_id']).parse(r))
                actual={c.printed_id for c in cs}
                for i,l in enumerate(r.lines):
                    m=re.match(r'^(?:\[)?((?:R\d+-)?[A-Z][A-Z0-9]*-\d+(?:\.\d+)?)(?:\])?',l.content)
                    if m and m[1] not in actual:
                        print(l.page,l.start,repr(r.near(i,4)))
                continue
            if a.action == 'study' and not a.match:
                try:
                    parser = module(d['row']['firm_id'])
                except ModuleNotFoundError:
                    from parsers import generic as parser
                cs = finish(r, parser.parse(r))
                summary = getattr(parser, 'printed_counts', printed_counts)(r)
                print('COUNTS', len(cs), 'SUMMARY', summary['counts'] if summary else None)
                for c in (cs[:1] + cs[-1:] if len(cs)>1 else cs):
                    print('DETAIL', c.printed_id, repr(c.title), c.severity_raw, c.status_raw,
                          repr(r.text[c.start:min(c.end,c.start+140)]))
                if cs:
                    continue
            selected = [l for l in r.lines if (not a.page or l.page == a.page) and pattern.search(l.text)]
            for l in selected[a.start:a.start+a.lines]:
                print(f'{l.page}:{l.start}: {l.text[:230]}')
        return
    if a.action == 'evaluate':
        for f in a.firms or FIRMS:
            counts = Counter()
            unknown = Counter()
            mismatches = []
            for d in ds:
                if d['row']['firm_id'] != f:
                    continue
                if a.trace:
                    print('PARSING',d['row']['sha256'],flush=True)
                try:
                    r = load(d)
                except (FileNotFoundError, ValueError):
                    counts['extraction_failed'] += 1
                    continue
                parser = module(f)
                rows = finish(r, parser.parse(r))
                summary = getattr(parser, 'printed_counts', printed_counts)(r)
                counts['documents'] += 1
                counts['findings'] += len(rows)
                counts['nonempty'] += bool(rows)
                counts['missing_title'] += sum(not c.title for c in rows)
                counts['missing_severity'] += sum((c.normalized or severity(c.severity_raw)) == 'unknown' for c in rows)
                unknown.update(c.severity_raw for c in rows if (c.normalized or severity(c.severity_raw))=='unknown')
                if a.match:
                    for c in rows:
                        if re.search(a.match,c.severity_raw or 'MISSING'):
                            print('LABEL_CASE',d['row']['sha256'],c.printed_id,repr(c.title),c.start,repr(c.severity_raw))
                seq = sequence(rows)
                if not summary or summary.get('ambiguous'):
                    counts['sequence_evaluable'] += seq is not None
                    counts['sequence_complete'] += seq is True
                    counts['no_summary'] += 1
                    counts['no_summary_nonempty'] += bool(rows)
                if summary and not summary.get('ambiguous'):
                    actual = Counter(c.normalized or severity(c.severity_raw) for c in rows if c.record_kind == 'formal_finding')
                    ok = all(actual[k] == n for k,n in summary['counts'].items())
                    counts['comparable'] += 1
                    counts['match'] += ok
                    if not ok:
                        mismatches.append({'sha': d['row']['sha256'], 'file': d['row']['filename'], 'expected': summary['counts'], 'actual': dict(actual)})
                elif not rows:
                    mismatches.append({'sha': d['row']['sha256'], 'file': d['row']['filename'], 'zero_without_counts': True})
                if seq is False and (not summary or summary.get('ambiguous')):
                    mismatches.append({'sha':d['row']['sha256'],'file':d['row']['filename'],'sequence_incomplete':[c.printed_id for c in rows]})
            print(f, json.dumps(counts), flush=True)
            print('UNKNOWN_LABELS',dict(unknown), flush=True)
            print(json.dumps(mismatches[:a.lines], indent=2), flush=True)


if __name__ == '__main__':
    main()
