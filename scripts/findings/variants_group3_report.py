"""Write the scoped Phase 4e report from variants_report.metric receipts."""
from collections import Counter
from dataclasses import asdict
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import ROOT, digest, read_snapshot, write_json
from parsers import module
from variants_report import cell
from variants_group3_study import FIRMS

NOTES={
 'verichains':'Legacy risk headings and recommendation bullets; nested audit-result subsections; title-linked status indexes; chapter-three findings. Status uses explicit issue updates, heading tags and complete-title index joins. Icon-only grades remain unknown. Empty nested reports often explicitly publish no issues; they still reduce coverage.',
 'halborn':'Unnumbered pentest risk titles, numbered sections, HAL identifiers, BVSS suffixes and newer slash-risk cards with optional HAL IDs and spaced section digits. Remediation sections, ID-linked overview cells and title badges supply status. The early original-risk overview can conflict with a remediation aggregate; independent source-table evidence marks those conflicts ambiguous. Executive summaries without embedded details remain comparable mismatches. Dates and counts never select a variant.',
 'solidified':'Ungraded and graded early issue chapters, issue-index tables, one-level Severity fields and later standalone Status fields. Status joins complete index rows and explicit amendment statements. Warning and informational prose totals are added through the authoritative crosswalk. Source numbering can restart at a graded chapter; explicit sequence namespaces preserve that reset. Moderate is retained unmapped instead of receiving an invented risk grade.',
 'dedaub':'Early unnumbered and numbered PDF columns, HTML severity cards, later extended centralization classes, ungraded Markdown lists, design focus points and research studies. HTML navigation is excluded before actual cards. Status columns, resolution headings and noncontiguous PDF status fragments retain exact source evidence. Dismissed is a client disposition, mapped to acknowledged. Centralization and other new unmapped grades stay unknown. Website filename years are sampling hints, not audit dates.',
 'macro':'The HTML card grammar is stable through both the original template and the later Trust Model/accepted-risk sections. Printed HTML PDFs use their own card and aligned status-column grammar. Each era has an explicit entry point and status reader; accepted-risk prose before Issue Details does not create findings or status. Split title fragments and inline headings are supported. Native missing/duplicate IDs remain unchanged.',
 'ackee-blockchain':'Narrative colon IDs, dash/Impact metadata, numbered Impact cards, explicit severity cards and revision/status overviews. Status uses exact-ID joins and labelled client responses; conflicting index claims do not fill missing status. Numbered details link to unique native overview IDs by their first-column titles, retaining the printed section number separately. Exploitable numbered legacy entries with only Impact/Likelihood retain no scalar grade. Unmatched native section numbering is retained.',
 'bailsec':'Unnumbered Issue cells, Issue_nn cells, and clean detection overviews. The split Comments / Resolution response cell and successive review rounds carry status. Explicit Quality assurance entries remain recommendations. Compound source totals, appended post-audit findings and source risk changes leave some summary disagreements; those remain in the denominator.',
 'teamomega':'Unnumbered contents-backed entries, scoped bracket headings and later status-only headings. Status prioritizes explicit resolution responses over earlier header tags. Fixes from older reports are excluded by source provenance. Heading/body severity disagreements are retained as evidence without regrading. Missing grades, stale aggregates, suffix IDs, reused IDs and native numbering gaps remain visible.',
 'sec3':'Single-digit overview IDs, independent program-prefixed IDs, zero-padded IDs and explicitly clean reviews. Only Findings in Detail emits cards. Exact-ID Result Overview rows supply status, with labelled detail updates taking precedence. Unlabelled team questions retain unknown risk.',
 'ncc-group':'Recovered 2016 Vulnerability/Risk cards, legacy Finding/Risk cards, modern Overall Risk/Finding ID cards and narrative cryptographic reviews. Reported maps to open; False Positive maps to invalid. One source dashboard excludes invalidated cards that remain in its complete index; both populations and their conflict are retained. Native subset and nonsequential IDs are not renumbered.'}

UNKNOWN={
 '7625409b':'Bybit incident investigation; no supported audit finding-card layout.',
 'e96fd316':'Standalone fastMPC vulnerability advisory; not a numbered audit report.',
 '7fb04358':'Deployment/configuration review with reviewed-contract tables, not vulnerability cards.',
 'dd271786':'Malware threat/incident analysis; no audit finding cards.',
 'e5a19906':'MyAlgo incident executive summary; no detailed audit cards.',
 'ed7b62f1':'Thorchain incident analysis; no audit finding-card layout.',
 '3f283f1a':'Cached GitHub HTML wrapper instead of the linked Markdown report; recovered Markdown has a separate occurrence.',
 '57fc0590':'Cached GitHub HTML wrapper instead of the linked Markdown report; recovered Markdown has a separate occurrence.',
 '5a406e2f':'Non-disclosed/empty report artifact; finding content is unavailable.',
 'a2c28153':'Forensic transaction-tracing report; no vulnerability finding cards.',
 'c7594eb0':'Short Hop update/fix verification without supported graded issue cards.',
 '8920b70f':'Clean Backed follow-up with no individual finding cards.',
 'ff4b6c62':'Toucan update/review history with no individual finding cards.',
 '141cb71a':'NCC website announcement/navigation wrapper; linked PDF is a separate occurrence.'}


def main():
    data=json.loads((ROOT/'data/findings/variants/group3.json').read_text())
    metrics=data['metrics'];docs=read_snapshot();byid={d['document_id']:d for d in docs}
    refresh=json.loads((ROOT/'data/findings/variants/group3_refresh.json').read_text())
    checkpath=ROOT/'data/findings/variants/group3_verification.json'
    check=json.loads(checkpath.read_text())
    assert set(check['scope'])==set(FIRMS),'Run evidence verification for the complete group'
    for path,sha in check['finding_stream_sha256'].items():
        assert digest((ROOT/path).read_bytes())==sha,'Finding output changed since evidence verification: '+path
    lines=['# Phase 4e — layout variants, group 3','',
        'Reproduce the scoped refresh, extraction, tests, evidence verification and metrics with:','',
        '```sh','python3 -I scripts/findings/variants_group3_refresh.py',
        'python3 -I -c \'import runpy,sys;sys.path.insert(0,"scripts/findings");runpy.run_path("scripts/findings/run.py",run_name="__main__")\' --firms '+' '.join(FIRMS),
        'python3 -I scripts/findings/test_variants_group3.py',
        'python3 -I scripts/findings/variants_group3_study.py --verify',
        'python3 -I scripts/findings/variants_group3_study.py --metrics',
        'python3 -I scripts/findings/variants_group3_report.py','```','',
        'Metrics call the unchanged `scripts/findings/variants_report.py:metric` and `sequence` functions. All figures are document occurrences, not distinct audits. Comparable summary agreement requires equality in every printed comparable bucket; retained mismatches remain in the denominator. ID completeness is the existing native-namespace contiguity diagnostic, not finding recall. Status coverage is known normalized status / detailed rows, not an independently measured accuracy. N/A is unevaluable, not a passed gate. Holdouts are denied before original or fulltext access; no gold documents were opened or tuned on.','',
        f"The scoped merge refreshed {refresh['current_occurrences']} current collection occurrences and extracted {len(refresh['new_extractions'])} missing cache pairs. Other publishers' snapshot rows and extraction receipts were preserved. No shared framework code, collection data, severity map, original report, or other publisher module was edited by this group. The input-document and extraction-receipt data streams were merged to include assigned-publisher additions.",'',
        f"Evidence verification passed for {check['counts']['documents_checked']} documents and {check['counts']['finding_rows_checked']} rows. Exact status spans: {check['counts'].get('status_spans_checked',0)}; noncontiguous status-fragment sets: {check['counts'].get('status_fragment_sets_checked',0)}. Holdouts opened: {check['holdouts_opened']}. Output hashes and the crosswalk receipt are in `data/findings/variants/group3_verification.json`.",'',
        '| Publisher / variant | Docs | Summary agreement | ID completeness | Docs with findings | Status coverage |',
        '|---|---:|---:|---:|---:|---:|']
    for m in metrics:
        lines.append('| '+m['variant_id']+' | '+str(m['documents'])+' | '+' | '.join((cell(m['summary_matching'],m['summary_comparable']),cell(m['sequence_complete'],m['sequence_comparable']),cell(m['documents_with_findings'],m['documents']),cell(m['known_status_rows'],m['detailed_rows'])))+' |')
    lines+=['','## Fingerprints and fixtures','',
        'Date windows are weak template-era hints. Text signatures dominate and an old template used later remains eligible. Research/clean variants emit no invented findings. Shared grammar primitives are reused within a publisher when a template retained the same heading grammar; each declaration has its own named parse entry point, status reader and fixture.','',
        '| Variant | Date window | Text signatures | Parse / status readers | Fixtures |','|---|---|---|---|---|']
    catalog=[]
    for firm in FIRMS:
        for v in module(firm).VARIANTS:
            catalog.append({'firm':firm,'variant_id':v.variant_id,'fingerprint':asdict(v.fingerprint),'parse':v.parse.__name__,'status_parser':v.status_parser.__name__,'fixtures':v.fixtures})
            lines.append('| '+v.variant_id+' | '+'–'.join(x or 'open' for x in v.fingerprint.date_range)+' | '+', '.join(s[0] for s in v.fingerprint.signatures)+' | `'+v.parse.__name__+'` / `'+v.status_parser.__name__+'` | '+', '.join(v.fixtures)+' |')
    lines+=['','## Residual failure classes','']
    for firm in FIRMS:lines+=['- **'+firm+'**: '+NOTES[firm]]
    lines+=['','The following variant gates remain below the requested threshold. They are reported without renumbering source IDs, filling absent grades, or changing rows to match totals.','',
        '| Variant | Gate | Result |','|---|---|---:|']
    for m in metrics:
        if m['summary_comparable']:
            if m['summary_agreement_percent']<95:lines.append('| '+m['variant_id']+' | summary agreement | '+cell(m['summary_matching'],m['summary_comparable'])+' |')
        elif m['sequence_comparable'] and m['id_sequence_completeness_percent']<95:
            lines.append('| '+m['variant_id']+' | ID completeness | '+cell(m['sequence_complete'],m['sequence_comparable'])+' |')
    lines+=['','| Residual class | Document occurrences |','|---|---:|']
    for cls,n in sorted(Counter(c for r in data['residuals'] for c in r['classes']).items()):lines.append(f'| {cls} | {n} |')
    lines+=['','Per-document diagnostics, native sequence gaps/duplicates and early/late examples from each represented year are retained in `data/findings/variants/group3.json`. Unknown-year website receipts are additionally sampled by filename year during development; those hints never become audit dates.','',
        '## Explained unknown layouts','',
        f"The auxiliary queue contains {len(data['unknown_layouts'])} group-3 artifact/publisher pairs. Every pair is explained below; unfamiliar material remains a genuine fallback instead of receiving an unconditional legacy fingerprint.",'',
        '| Publisher | SHA-256 | Filename | Explanation |','|---|---|---|---|']
    unknown=[]
    for q in data['unknown_layouts']:
        d=byid[q['document_ids'][0]];reason=next((v for k,v in UNKNOWN.items() if q['sha256'].startswith(k)),None)
        assert reason,'Unexplained unknown layout: '+q['sha256']
        unknown.append(q|{'explanation':reason})
        lines.append('| '+q['firm']+' | `'+q['sha256']+'` | '+d['row']['filename'].replace('|','\\|')+' | '+reason+' |')
    paths=[f'scripts/findings/parsers/{f.replace("-","_")}.py' for f in FIRMS]
    paths+=['scripts/findings/parsers/group3_status.py','scripts/findings/fixtures_group3_variants.py','scripts/findings/test_variants_group3.py',
        'scripts/findings/variants_group3_study.py','scripts/findings/variants_group3_refresh.py','scripts/findings/variants_group3_report.py',
        'docs/phase4/variants_group3.md','docs/phase4/variants_group3_files.txt',
        'data/fulltext/input_documents.jsonl','data/fulltext/extractions.jsonl','data/findings/_unknown_layouts.jsonl',
        'data/findings/variants/group3.json','data/findings/variants/group3_refresh.json','data/findings/variants/group3_verification.json','data/findings/variants/group3_catalog.json']
    paths += [p for firm in FIRMS for p in (f'data/findings/{firm}.jsonl',f'data/findings/validation/{firm}.jsonl',f'data/findings/validation/{firm}.json')]
    for ext in refresh['new_extractions']:
        paths += [p for p in (ext.get('text_path'),ext.get('pages_path')) if p]
    paths=list(dict.fromkeys(paths))
    lines+=['','## Files written','', 'Shared framework code changes: none. Shared generated-data changes: the two scoped snapshot/receipt merges and the runner-maintained unknown-layout queue. No commits or pushes were made.','']
    lines+=['- `'+p+'`' for p in paths]
    write_json(ROOT/'data/findings/variants/group3_catalog.json',{'variants':catalog,'unknown_layout_explanations':unknown})
    (ROOT/'docs/phase4/variants_group3.md').write_text('\n'.join(lines)+'\n')
    (ROOT/'docs/phase4/variants_group3_files.txt').write_text('\n'.join(paths)+'\n')
    print('Wrote docs/phase4/variants_group3.md and complete file manifest.')


if __name__=='__main__':main()
