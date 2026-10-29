"""Local, holdout-excluded census and reproducible recall diagnostics for seven firms.

The collection census is frozen separately from the Phase 4 extraction snapshot.
Never append new collection occurrences to that older snapshot implicitly.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import re
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest, documents, holdouts, read_snapshot, write_json, write_jsonl
from streams import finding_rows, supplemental_only
from core import Report, finish
from parsers import module
from variants_report import sequence

FIRMS = ('theori', 'zokyo', 'quantstamp', 'composable-security', 'hats-finance', 'iosiro', 'fuzzland')
LOCAL = ROOT / 'local-cache/phase4-recall-push'
FLAGS = ('summary_mismatch', 'below_printed_summary', 'id_gaps', 'duplicate_ids', 'zero_finding_audit', 'error')


def inputs():
    frozen = json.loads((LOCAL / 'inputs.json').read_text())
    assert frozen['holdout_list_sha256'] == digest((ROOT / 'data/holdout/gold_sha256.txt').read_bytes())
    blocked = holdouts()
    assert not {d['row']['sha256'] for d in frozen['documents']} & blocked
    return frozen['documents']


def load(doc):
    sha = doc['row']['sha256']
    assert sha not in holdouts(), 'Holdout text access denied'
    base = ROOT / 'local-cache/fulltext' / sha
    meta = json.loads(base.with_suffix('.pages.json').read_text())
    text = base.with_suffix('.txt').read_bytes().decode('utf-8')
    assert digest(text.encode()) == meta['text_sha256']
    assert '\f'.join(p['text'] for p in meta['pages']) == text
    return Report(text, meta | {'date_hint': doc['row'].get('date_hint')}, doc['row']['firm_id'])


def freeze():
    if (LOCAL / 'inputs.json').exists():
        raise ValueError('Refusing to replace frozen census')
    current, ledger, excluded = documents()
    # Include every occurrence in either census, retaining the original receipts.
    union = {d['document_id']: d for d in read_snapshot() if d['row']['firm_id'] in FIRMS}
    union.update({d['document_id']: d for d in current if d['row']['firm_id'] in FIRMS})
    docs = sorted(union.values(), key=lambda d: (d['row']['firm_id'], d['row']['sha256'], d['document_id']))
    write_json(LOCAL / 'inputs.json', dict(documents=docs, collection_files=ledger,
        holdout_list_sha256=digest((ROOT / 'data/holdout/gold_sha256.txt').read_bytes()), excluded=excluded))
    for firm in FIRMS:
        path = ROOT / 'scripts/findings/parsers' / (firm.replace('-', '_') + '.py')
        dest = LOCAL / 'before_parsers' / path.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(path.read_bytes())
    print(json.dumps({'occurrences': dict(Counter(d['row']['firm_id'] for d in docs)),
        'artifacts': {f: len({d['row']['sha256'] for d in docs if d['row']['firm_id'] == f}) for f in FIRMS}}, indent=2))


def diagnose(doc):
    r = load(doc)
    parser = module(r.firm)
    cs = finish(r, parser.parse(r))
    summary = parser.printed_counts(r)
    formal = Counter(c.normalized for c in cs if c.record_kind == 'formal_finding')
    rows = [dict(record_kind=c.record_kind, publisher_finding_id=c.printed_id, evidence=c.evidence) for c in cs]
    seq = sequence(rows, r.firm)
    compare = (summary or {}).get('counts', {})
    mismatch = bool(compare and not summary.get('ambiguous') and any(formal[k] != n for k, n in compare.items()))
    below = bool(compare and any(formal[k] < n for k, n in compare.items()))
    return dict(firm=r.firm, sha256=doc['row']['sha256'], document_id=doc['document_id'],
        filename=doc['row']['filename'], public_url=doc['row']['public_url'], doc_kind=doc['row']['doc_kind'],
        variant_id=r.layout_selection['variant_id'], findings=len(cs), formal_findings=sum(formal.values()),
        record_kinds=dict(Counter(c.record_kind for c in cs)), parsed_counts=dict(formal), printed_summary=summary,
        summary_mismatch=mismatch, below_printed_summary=below,
        id_sequence=seq, id_gaps=bool(seq and seq['gaps']), duplicate_ids=bool(seq and seq['duplicates']),
        zero_finding_audit=not cs and doc['row']['doc_kind'] not in {'non_report', 'formal_verification'},
        disposition=getattr(r, 'layout_disposition', None), text_sha256=r.meta['text_sha256'],
        entries=[dict(id=c.printed_id, title=c.title, severity_raw=c.severity_raw, severity=c.normalized,
                      kind=c.record_kind, start=c.start, end=c.end, method=c.method) for c in cs])


def metrics(rows):
    return {f: dict(documents=len(rs), occurrences=sum(r['occurrences'] for r in rs),
        summary_mismatch=sum(r.get('summary_mismatch', False) for r in rs),
        below_printed_summary=sum(r.get('below_printed_summary', False) for r in rs),
        id_gaps=sum(r.get('id_gaps', False) for r in rs), duplicate_ids=sum(r.get('duplicate_ids', False) for r in rs),
        zero_finding_audit=sum(r.get('zero_finding_audit', False) for r in rs),
        findings=sum(r.get('findings', 0) for r in rs), formal_findings=sum(r.get('formal_findings', 0) for r in rs),
        errors=sum(bool(r.get('error')) for r in rs), variants=dict(Counter(r.get('variant_id', 'extraction_failed') for r in rs)))
        for f in FIRMS for rs in [[r for r in rows if r['firm'] == f]]}


def regenerate(selected=FIRMS):
    """Regenerate snapshot streams and put later occurrences in a separate stream."""
    from run import main as run_main, finding_rows
    from unittest.mock import patch
    frozen=read_snapshot();frozen_ids={d['document_id'] for d in frozen}
    firms=sorted({d['row']['firm_id'] for d in frozen}&set(selected))
    with patch.object(sys,'argv',['run.py','--firms',*firms]):run_main()
    grouped=defaultdict(list)
    for doc in inputs():
        if doc['document_id'] not in frozen_ids and doc['row']['firm_id'] in selected:grouped[doc['row']['firm_id']].append(doc)
    old_path=ROOT/'data/findings/validation/recall_push_supplemental.json'
    extra_stats=[s for s in json.loads(old_path.read_text())['by_firm'] if s['firm_id'] not in selected] if old_path.exists() else []
    for firm,docs in sorted(grouped.items()):
        rows=[]
        for doc in docs:
            r=load(doc);parser=module(firm);cs=finish(r,parser.parse(r))
            rows+=list(finding_rows(doc,r,cs,firm.replace('-','_')))
        rows=supplemental_only(rows,ROOT/'data/findings',firm)
        write_jsonl(ROOT/'data/findings/supplemental'/(firm+'.jsonl'),rows)
        extra_stats.append(dict(firm_id=firm,documents=len(docs),findings=len(rows),
                               document_ids=[d['document_id'] for d in docs]))
    write_json(ROOT/'data/findings/validation/recall_push_supplemental.json',
        dict(by_firm=extra_stats,holdouts_opened=0,
             note='Later collector occurrences; separate from the unchanged frozen extraction snapshot.'))
    # Preserve all current per-firm statistics, including concurrent status work.
    stats=[]
    for path in sorted((ROOT/'data/findings/validation').glob('*.json')):
        value=json.loads(path.read_text())
        if isinstance(value,dict) and value.get('firm_id')==path.stem and 'findings' in value:stats.append(value)
    path=ROOT/'data/findings/summary.json';summary=json.loads(path.read_text())
    summary.update(by_firm=stats,findings=sum(s['findings'] for s in stats),documents=sum(s['documents'] for s in stats))
    write_json(path,summary)
    print(json.dumps(extra_stats,indent=2))


def source_evidence(doc, row):
    r=load(doc);proof=[]
    # Include exact source statements and heading/index evidence, not report
    # bodies. These quotes make clean outcomes and source numbering auditable.
    patterns=[r'\bno\b[^\n.]{0,110}\b(?:issues|flaws|vulnerabilities)\b[^\n.]{0,100}',
              r'did not identify any vulnerabilities',r'^\s*N/A\s*$',
              r'Auditor:\s*Adam Levi',r'Security consultation summary',
              r'\bTotal Issues\s+0\b']
    if row.get('id_gaps') or row.get('duplicate_ids'):
        patterns += [r'^\s*#{1,6}\s+\d+\.\d+\.\d+[^\n]*',
                     r'^\s*[^\n]{0,7}(?:Critical|High|Medium|Low|Info(?:rmational)?)\s*[-–]\s*\d+(?:\.\d+)*[^\n]*',
                     r'<td>\s*IO-[A-Z0-9-]+\s*</td>']
    for m in re.finditer('|'.join('(?:'+p+')' for p in patterns),r.text,re.I|re.M):
        proof.append(dict(start=m.start(),end=m.end(),text=m[0],
            page=next((p['page'] for p in r.meta['pages'] if p['start']<=m.start()<p['end']),None)))
    if row['firm']=='quantstamp' and r.native:
        content=r.native['report'].get('reportContent',{})
        data=content.get('breakdownAndAutomatedAnalysis') or {}
        proof.append(dict(json_pointer='/reportContent/breakdownAndAutomatedAnalysis',
            vulnerabilities=len(data.get('vulnerabilitiesArray') or []),suggestions=len(data.get('suggestionsArray') or [])))
    return proof


def review():
    before=json.loads((LOCAL/'before.json').read_text())['documents']
    after=json.loads((LOCAL/'after.json').read_text())['documents']
    old={(d['firm'],d['sha256']):d for d in before}
    docs={(d['row']['firm_id'],d['row']['sha256']):d for d in inputs()}
    for row in after:
        b=old[row['firm'],row['sha256']]
        if not any(row.get(k) or b.get(k) for k in FLAGS):continue
        print(row['firm'],row['sha256'][:12],b['findings'],'->',row['findings'],row['filename'])
        print('summary',(row.get('printed_summary') or {}).get('counts'),'parsed',row.get('parsed_counts'),'ids',row.get('id_sequence'))
        print('entries',[(c['id'],c['kind'],c['title']) for c in row.get('entries',[])])
        for e in source_evidence(docs[row['firm'],row['sha256']],row):
            print('source',e)


SUMMARY_NOTES={
 '99ca21781f65':'The DIVA retest says 6 recommendations, but its disjoint disposition subtotals and the detailed cards describe 14. The contradictory printed aggregate is retained.',
 '1b44ef08cee4':'The Number column and separately graded Low detail headings disagree. Both Low cards have their own description and disposition; neither is a duplicate container.',
 '48bf00806f93':'The Number column understates the independently titled Low detail cards. All graded detail headings are retained, including the separately described centralization and configuration risks.',
 'd696da54b78a':'The aggregate says seven Low issues, while the complete native index and detail metadata say six Low and one Informational. Every index ID is present; no grade is changed to match the aggregate.',
 'f1acd6409186':'The native summary is all zero while vulnerabilitiesArray contains a Medium finding and suggestionsArray contains separate recommendations. The source JSON contradiction is retained.',
 '945475c33a3b':'This is a summary certificate with numeric totals but no individual issue titles or detailed findings. Totals cannot manufacture finding rows.',
 '2a827c9ab7a6':'The source summary/scoring risk labels disagree with the detail badges (including the first Critical/High classification). The full numbered inventory is present; detail grades are retained.',
 '2eb1d7e8d426':'The scoring totals disagree with the complete detail-card census, which includes additional cards and repeated IDs. Distinct source cards remain separate; totals and native numbering are preserved.',
 '2f28ca6e678b':'An additional separately graded Informational card (Redundant Check for Zero Address) is present in the details but absent from the numbered summary. It is retained as a source finding.',
 '5a1259a5de91':'The details contain an additional separately graded Informational card (Redundant Check for Zero Address) and repeat Informational-2 for a different issue. The summary omits the extra card.',
 '6a58f565da3b':'The scoring total counts the style-guide group once, while three independently graded child cards use INFORMATIONAL-10.1 through 10.3. Emit the leaves without adding an extra container finding.',
 '71fb42a26592':'The scoring totals and the complete numbered summary/detail grades disagree, including High and Informational buckets. Every printed detail card is retained with its own badge grade.',
 '8e46ba73aec2':'Printed scoring totals disagree with the detailed card census; the source also has skipped/repeated native labels. All readable graded cards are retained; no missing severity slots are synthesized.',
 '9d2c2e60b187':'The source index and detail badges classify some entries differently, including repeated Medium-3/Low-3 labels. The complete set of distinct detail cards is retained with detail grades.',
}
ID_NOTES={
 '490134328d67':'INFO-3 and INFO-9 are parent slots represented by separately graded decimal child IDs, without extra parent findings.',
 '4e003f707010':'The INFO-3/INFO-9 parents have graded children; the source also prints 8.3/8.5 among the 9.x children. The leaf cards are retained without inventing parent rows.',
 '496a66b79e17':'Issue numbering continues the executive-summary subsections: the twelve actual finding cards start at 1.5; sections 1.1–1.4 are background, scope, timeline and results.',
 '6a58f565da3b':'INFORMATIONAL-10 is represented by graded children 10.1, 10.2 and 10.3; no additional parent card is printed.',
 '7ce3f0de322f':'Both native text and badge OCR print the sole Medium card as medium-2, with no medium-1 detail card in the complete analysis.',
 '8a88fd871f99':'The report mixes bare-grade cards and retained numbered cards from audit iterations; missing numeric slots have no additional distinct title/card in the source census. Unreadable IDs stay absent rather than inferred.',
 '8b20e02d7f5e':'This revision retains earlier-iteration finding numbers in a short subset; the printed detail cards do not restart every severity prefix at one.',
 'a2eb88ca7c36':'This layout mixes bare-grade and numbered OCR badges; any residual sequence gap is an unavailable/damaged identifier on an already represented card, not a synthesized finding slot.',
 'a9d4ecd52e09':'The source repeats Informational-2 and labels the Floating Pragma card INFORMATIONAL-3 among later informational cards; all separately titled cards are present.',
 'b1afe62daa9d':'Printed audit iterations define separate namespaces; the second iteration starts its informational cards at Info-2. Distinct cards in both iterations are retained.',
 'd5616bf459c5':'The source badge sequence jumps from Low-13 to Low-16; native text and full-page badge OCR agree. No additional Low-14/Low-15 title appears in the complete index or analysis.',
 'd85d4978d1f1':'The publisher prints Informational-1 and Informational-3 for its two informational detail cards; their printed summary counts two.',
}


def explanation(doc,b,a,proof):
    reasons=[];remaining=any(a.get(k) for k in FLAGS)
    if a['findings']>b['findings']:reasons.append('Recovered source cards/rows with the variant grammar or title-anchored badge receipts.')
    elif a['findings']<b['findings']:reasons.append('Removed duplicate representations of the same source card; exact title/badge associations and original spans are retained.')
    if a.get('summary_mismatch') or a.get('below_printed_summary'):
        note=next((v for k,v in SUMMARY_NOTES.items() if a['sha256'].startswith(k)),None)
        if note is None:raise ValueError('Unadjudicated summary discrepancy: '+a['sha256'])
        reasons.append(note)
    if a.get('zero_finding_audit'):
        if a['firm']=='hats-finance':reasons.append('Client-side archive: the report names Adam Levi as auditor and Hats DAO as client; it is not a Hats-authored contest report. Stored attribution is unchanged.')
        elif a['firm']=='composable-security':reasons.append('Consultation/retest of prior issues and covered scenarios, with an explicit no-new-vulnerabilities outcome; no new graded finding cards.')
        elif a['firm']=='quantstamp':
            if a['variant_id'].endswith('native_json'):reasons.append('The publisher native finding/suggestion arrays are empty and the printed summary is zero.')
            elif not (a.get('printed_summary') or {}).get('counts') or any((a.get('printed_summary') or {}).get('counts',{}).values()):reasons.append('Summary certificate without individually printed finding cards; numeric totals are not finding records.')
            else:reasons.append('The publisher explicitly reports zero issues; there are no detailed finding cards.')
        else:
            assert proof or a.get('printed_summary'), 'Zero outcome lacks evidence: '+a['sha256']
            reasons.append('The source explicitly reports no issues (or a zero aggregate/N/A detail section); no finding is invented.')
    if a.get('id_gaps') or a.get('duplicate_ids'):
        if a['firm']=='iosiro':
            if a['variant_id'].endswith(('native_html','classless_html')):reasons.append('Formal-only sequence gaps also cover ungraded code-quality IDs, omitted/retired IDs and source prefix typos; the native detail headings and quality rows are all censused. Recommendations remain separate from formal findings.')
            else:reasons.append('The source itself skips or repeats the numbered detail headings shown in the evidence. Distinct headings are retained verbatim; missing numbers do not create findings.')
        elif a['firm']=='zokyo':
            note=next((v for k,v in ID_NOTES.items() if a['sha256'].startswith(k)),None)
            reasons.append(note or 'Source ID repetitions/numbering differences remain visible in the complete detail-card census and badge receipts. They do not create expected finding slots; distinct graded cards are retained.')
        else:raise ValueError('Unadjudicated ID diagnostic: '+a['sha256'])
    if a.get('error'):raise ValueError(a['error'])
    if not reasons:reasons.append('Resolved by explicit layout/section namespace handling; native IDs and finding cardinality are preserved.')
    return dict(state='explained' if remaining else 'resolved',notes=reasons)


def report_result():
    before=json.loads((LOCAL/'before.json').read_text());after=json.loads((LOCAL/'after.json').read_text())
    old={(r['firm'],r['sha256']):r for r in before['documents']}
    docs={(d['row']['firm_id'],d['row']['sha256']):d for d in inputs()}
    records=[];issues=[]
    for a in after['documents']:
        k=(a['firm'],a['sha256']);b=old[k]
        flagged=any(a.get(f) or b.get(f) for f in FLAGS)
        proof=source_evidence(docs[k],a) if flagged else []
        resolution=explanation(docs[k],b,a,proof) if flagged else None
        compact=lambda r:{k:v for k,v in r.items() if k not in {'entries','printed_summary','public_url','filename','document_ids','occurrences'}}
        record=dict(firm=a['firm'],sha256=a['sha256'],filename=a['filename'],public_url=a['public_url'],
            document_ids=a['document_ids'],occurrences=a['occurrences'],before=compact(b),after=compact(a),
            before_summary=b.get('printed_summary'),after_summary=a.get('printed_summary'),
            before_entries=b.get('entries',[]),after_entries=a.get('entries',[]),resolution=resolution,
            source_evidence=proof)
        records.append(record)
        if flagged:issues.append(record)
    result=dict(before=before['per_publisher'],after=after['per_publisher'],documents=records,
        holdout_list_sha256=after['holdout_list_sha256'],holdouts_opened=0,
        definitions=dict(unit='distinct (stored publisher, original SHA-256); alias occurrences are listed separately',
            summary_mismatch='formal finding severity buckets differ from independently printed non-ambiguous aggregate',
            below_printed_summary='at least one formal severity bucket below a printed total, including retained ambiguous totals',
            id_gaps='unchanged formal-only native namespace diagnostic from variants_report.sequence; hierarchical and ungraded namespaces can explain gaps',
            zero_finding_audit='no emitted entries in a collector audit/unknown/fix-review occurrence; source-clean and client-side artifacts remain visible',
            findings='all emitted record kinds; not unique vulnerabilities'))
    write_json(ROOT/'data/findings/validation/recall_push.json',result)
    lines=['# Phase 4 recall push','',
        'Generated by `scripts/findings/recall_push.py --report`; local source review on 2026-10-21. No network or model calls. The holdout list is unchanged, and hashes are rejected before original, text, render or OCR access.','',
        'The census is the union of the frozen extraction inventory and current non-holdout collector records for the seven requested publishers. Each row below counts a distinct (stored publisher, original SHA-256) pair; aliases do not inflate document or finding totals. Later occurrences are staged separately under `data/findings/supplemental/`, preserving the frozen snapshot and attribution. The complete document-by-variant census, URLs, before/after diagnostics, native IDs and evidence are in [recall_push.json](../../data/findings/validation/recall_push.json).','',
        '| Publisher | Documents | Summary mismatch before → after | Below printed summary before → after | ID gaps before → after | Zero-finding audits before → after | Findings before → after |',
        '|---|---:|---:|---:|---:|---:|---:|']
    for firm in FIRMS:
        b=before['per_publisher'][firm];a=after['per_publisher'][firm]
        values=[f"{b[k]} → {a[k]}" for k in ('summary_mismatch','below_printed_summary','id_gaps','zero_finding_audit','findings')]
        lines.append('| '+firm+' | '+str(a['documents'])+' | '+' | '.join(values)+' |')
    lines+=['',f"Total emitted entries: {sum(r['findings'] for r in before['per_publisher'].values())} → {sum(r['findings'] for r in after['per_publisher'].values())}. Counts include recommendations and summary excerpts when present; these are not unique vulnerabilities. Summary mismatches and source numbering gaps are retained after explanation, not removed from their denominator. Zero-finding rows remain visible when the publisher reports a clean outcome or the artifact has no individual findings.",'',
        '## Variant census','', '| Publisher / selected variant | Documents | Findings |', '|---|---:|---:|']
    groups=defaultdict(list)
    for r in after['documents']:groups[r['variant_id']].append(r)
    for variant,rows in sorted(groups.items()):lines.append(f"| {variant} | {len(rows)} | {sum(r['findings'] for r in rows)} |")
    lines+=['','## Grammar and evidence changes','',
        '- Theori: prevent a card with missing metadata from taking a grade from the next card. The live Theori original still yields its Issue and Recommendation cards. Officially reconciled ChainLight aliases are replayed separately below, with stored attribution and finding streams preserved.',
        '- Zokyo: accept complete OCR-backed numbered badges with fused icons/status glyphs, read colored strips separately, and anchor image claims to existing source titles. Native cards and image receipts are deduplicated. Printed audit iterations and severity sections define separate namespaces. Independently graded children are emitted without an extra container. Visually checked digit repairs retain the rejected OCR label and render hash.',
        '- Quantstamp: recognize project IDs with damaged PDF separator glyphs, require the Findings region, preserve wrapped titles and stop at Definitions. Summary-only certificates retain their totals without invented detailed findings; grouped children remain inside their graded container.',
        '- Composable Security: consultation variants now explain their absence of new graded findings. DIVA\'s contradictory retest aggregate remains a mismatch.',
        '- Hats Finance: split contest-section, letter-ID PDF and external-client-archive variants. Restarted numeric lists use their printed severity-section namespace. The external client archive remains attributed as collected and is explicitly explained.',
        '- iosiro: parse classless code-quality tables only within their explicit section, and read ID/Issue/Risk/Status indexes by their printed headers. Ungraded advice remains recommendations; the source aggregate/detail severity contradiction is retained.',
        '- Fuzzland: declare bracket-heading, Number/Resolved-table and explicit N/A variants, including Critical headings. Source tables that disagree with distinct graded detail headings remain mismatches.','',
        'OCR additions require a matching existing source title. Unassociated image candidates and unreadable labels remain in local review receipts; aggregate totals never manufacture findings. This is a complete structural census of the development cohort, not an independent estimate of recall.','',
        '## Every flagged document','',
        'This ledger includes every document flagged before or after by summary mismatch, below-summary buckets, native ID gaps/repetitions, or zero parsed findings. `M` = summary mismatch, `B` = below a printed severity total, `G` = ID gap, `D` = repeated ID, `Z` = zero-finding audit. Full exact-text/page and OCR evidence is in the JSON census.','']
    codes=dict(summary_mismatch='M',below_printed_summary='B',id_gaps='G',duplicate_ids='D',zero_finding_audit='Z',error='E')
    for firm in FIRMS:
        lines+=['### '+firm,'','| Document / original | Variant after | Findings before → after | Flags before → after | Resolution / explanation |','|---|---|---:|---|---|']
        subset=[r for r in issues if r['firm']==firm]
        for r in subset:
            flags=lambda x:','.join(codes[k] for k in FLAGS if x.get(k)) or '—'
            title=r['filename'].replace('|','\\|')
            note=' '.join(r['resolution']['notes']).replace('|','\\|')
            lines.append(f"| [{title}]({r['public_url']}) `{r['sha256'][:12]}` | {r['after']['variant_id']} | {r['before']['findings']} → {r['after']['findings']} | {flags(r['before'])} → {flags(r['after'])} | {note} |")
        if not subset:lines.append('| No flagged development documents | — | — | — | Complete corpus census retained in JSON. |')
        lines+=['']
    alias_path=ROOT/'data/findings/validation/recall_push_theori_aliases.json'
    if alias_path.exists():
        aliases=json.loads(alias_path.read_text())
        lines+=['## Official Theori aliases','',
            f"The separate grammar-validation cohort includes {len(aliases['documents'])} eligible originals: {aliases['before']} → {aliases['after']} entries, with {aliases['zero_findings']} zero-finding document. These counts overlap the main Theori row and stored ChainLight originals; they are not added to publisher totals. Holdouts were filtered before cache access. [Alias receipts](../../data/findings/validation/recall_push_theori_aliases.json).",'',
            '| Original | Stored publisher | Variant | Before → after | Explanation |','|---|---|---|---:|---|']
        for r in aliases['documents']:
            note=(r.get('disposition') or {}).get('reason') or 'All source cards retained; no unresolved structural diagnostic.'
            if note=='missing_narrative_glyphs':note='Narrative and issue-heading glyphs are missing from the original rendering as well as the text layer (documented in hard_layouts.md); formula/code fragments cannot establish findings.'
            lines.append(f"| [{r['sha256'][:12]}]({r['public_url']}) | {r['stored_publisher']} | {r['variant_id']} | {r['before']} → {r['after']} | {note} |")
        lines+=['']
    lines+=['## Validation and reproduction','',
        'The scoped checker verifies every staged target occurrence, row count, stable identity, source/text hash, body/status span, severity mapping and OCR render/crop receipt. It reconciles the staged streams against the complete after census and rejects holdout hashes. The baseline is immutable under `local-cache/phase4-recall-push/`; no originals or shared extraction caches were changed.','',
        '```sh',
        '# One-time baseline; refuses replacement:',
        'python3 -I -S scripts/findings/recall_push.py --freeze',
        'python3 -I -S scripts/findings/recall_push.py --phase before',
        'python3 -I scripts/findings/recall_ocr.py --prepare',
        'python3 -I scripts/findings/recall_ocr.py',
        'python3 -I -S scripts/findings/recall_ocr.py --export',
        'python3 -I -S scripts/findings/recall_push.py --phase after',
        'python3 -I -S scripts/findings/recall_push.py --regenerate',
        'python3 -I -S scripts/findings/recall_push.py --verify',
        'python3 -I -S scripts/findings/recall_push.py --theori-aliases',
        'python3 -I -S scripts/findings/recall_push.py --tests',
        'python3 -I -S scripts/findings/recall_push.py --global-check',
        'python3 -I -S scripts/findings/recall_push.py --report',
        'python3 -I -S scripts/findings/test_recall_push.py',
        '```','',
        'This job\'s shared code changes are limited to the new fixture entry/metadata in `scripts/findings/test_variants.py`; this job did not edit a shared parser, dispatcher, status handling, schema, severity policy or another publisher module. The concurrent status migration in shared files is preserved. Shared generated outputs are the runner\'s unknown-layout queue and merged summary (and the integrity checker receipt when successful). All written repository paths, including ignored local evidence, are listed in [recall_push_files_written.txt](../../data/findings/validation/recall_push_files_written.txt).','']
    receipt=ROOT/'data/findings/validation/recall_push_check.json'
    if receipt.exists():
        checked=json.loads(receipt.read_text())
        if checked.get('after_census_sha256')==digest((LOCAL/'after.json').read_bytes()):
            lines+=['Scoped verification: '+('pass' if checked['ok'] else 'FAIL')+f"; {checked['occurrences']} occurrences, {checked['findings']} staged entries, {checked['ocr_claims']} image claims; no holdout access.",'']
        else:lines+=['Scoped verification pending the final regeneration; the earlier receipt is not used for this census.','']
    receipt=ROOT/'data/findings/validation/recall_push_tests.json'
    if receipt.exists():
        checked=json.loads(receipt.read_text());lines += [f"Scoped regression suite: {checked['tests']} tests; "+('pass' if checked['ok'] else 'FAIL')+'. The suite includes synthetic boundary/container cases and local source-document fixtures.','']
    receipt=LOCAL/'global_check.json'
    if receipt.exists():
        checked=json.loads(receipt.read_text());lines += ['Full shared checker: '+('pass.' if checked['returncode']==0 else 'did not pass: '+checked['error']) ,'']
    (ROOT/'docs/phase4/recall_push.md').write_text('\n'.join(lines))
    print(json.dumps(dict(before=result['before'],after=result['after'],flagged_documents=len(issues)),indent=2))


def verify():
    from common import uid, SEVERITIES
    from core import severity_mapping, select_severity_era, severity_policy
    after=json.loads((LOCAL/'after.json').read_text())
    expected={(r['firm'],r['sha256']):r for r in after['documents']}
    docs={d['document_id']:d for d in inputs()};blocked=holdouts();seen=set();by_doc=defaultdict(list)
    current,_,_=documents()
    new={d['document_id'] for d in current if d['row']['firm_id'] in FIRMS}-set(docs)
    assert not new,'New target collector occurrences require an extended census'
    cache={};map_sha=severity_policy()[2]
    for path, row in finding_rows(ROOT/'data/findings', firms=set(FIRMS)):
        firm=path.stem;sha=row['sha256'];assert sha not in blocked
        d=docs[row['document_id']];assert d['row']['firm_id']==row['publisher_id']==firm
        assert d['row']['sha256']==sha and d['source_record_sha256']==row['source_record_sha256']
        assert row['finding_id']==uid('finding',row['source_tag'],row['source_record_id'])
        assert row['finding_id'] not in seen;seen.add(row['finding_id'])
        if sha not in cache:
            cache.clear();r=load(d);cache[sha]=r
        r=cache[sha];a,b=row['body_span']['start'],row['body_span']['end']
        assert 0<=a<b<=len(r.text) and r.text[a:b]==row['body_text']
        assert row['body_span']['text_sha256']==r.meta['text_sha256']
        assert row['severity_mapping']['map_sha256']==map_sha
        era=select_severity_era(firm,sha256=sha,report_text=r.text)
        norm=severity_mapping(row['severity_raw'],firm,era=era,
            kind=(row['severity_mapping'].get('rule') or '').removeprefix('unrated_'),log=False)
        assert row['severity']==norm['normalized']
        for name in ('status_evidence',):
            proof=row['evidence'].get(name)
            if proof:assert r.text[proof['start']:proof['end']]==proof['text']==proof['raw']==row['status_raw']
        assert row['variant_id']==expected[firm,sha]['variant_id']
        by_doc[row['document_id']].append(row)
    for did,doc in docs.items():
        exp=expected[doc['row']['firm_id'],doc['row']['sha256']]
        rows=by_doc[did]
        assert len(rows)==exp['findings'], ('stale staged count',did,len(rows),exp['findings'])
        observed=[dict(id=r['publisher_finding_id'],title=r['title_raw'],severity_raw=r['severity_raw'],
            severity=r['severity'],kind=r['record_kind'],start=r['body_span']['start'],end=r['body_span']['end']) for r in rows]
        wanted=[{k:v for k,v in r.items() if k!='method'} for r in exp['entries']]
        assert observed==wanted, ('stale staged content',did)
    fixture=json.loads((ROOT/'scripts/findings/parsers/fixtures/recall_zokyo_badges.json').read_text())
    files={};claims=fixture['claims']
    for claim in claims:
        sha=claim['sha256'];assert sha not in blocked
        d=next(d for d in docs.values() if d['row']['sha256']==sha and d['row']['firm_id']=='zokyo')
        r=load(d);assert claim['original_sha256']==sha and claim['text_sha256']==r.meta['text_sha256']
        for key in ('source_span','title_span'):
            proof=claim[key];assert r.text[proof['start']:proof['end']]==proof['text']
        folder=LOCAL/'ocr'/sha
        if sha not in files:
            files[sha]={digest(p.read_bytes()) for p in folder.glob('*.ppm')}
        render=folder/(str(claim['page'])+'.png')
        assert digest(render.read_bytes())==claim['render_sha256']
        assert claim['image_sha256'] in files[sha]|{claim['render_sha256']} and claim['title_image_sha256'] in files[sha]|{claim['render_sha256']}
    result=dict(ok=True,occurrences=len(docs),artifacts=len(expected),findings=len(seen),ocr_claims=len(claims),
        holdout_list_sha256=digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes()),holdouts_opened=0,
        after_census_sha256=digest((LOCAL/'after.json').read_bytes()),
        parser_sources={f:digest((ROOT/'scripts/findings/parsers'/(f.replace('-','_')+'.py')).read_bytes()) for f in FIRMS})
    write_json(ROOT/'data/findings/validation/recall_push_check.json',result)
    print(json.dumps(result,indent=2))


def manifest():
    paths=['scripts/findings/recall_push.py','scripts/findings/recall_ocr.py','scripts/findings/test_recall_push.py',
        'scripts/findings/test_variants.py','scripts/findings/parsers/fixtures/recall_zokyo_badges.json',
        'docs/phase4/recall_push.md','data/findings/validation/recall_push.json',
        'data/findings/validation/recall_push_check.json','data/findings/validation/recall_push_supplemental.json',
        'data/findings/validation/recall_push_tests.json',
        'data/findings/validation/recall_push_theori_aliases.json',
        'data/findings/validation/recall_push_files_written.txt','data/findings/_unknown_layouts.jsonl',
        'data/findings/summary.json','data/findings/check.json']
    for firm in FIRMS:
        paths+=['scripts/findings/parsers/'+firm.replace('-','_')+'.py']
        for p in (ROOT/'data/findings'/(firm+'.jsonl'),ROOT/'data/findings/validation'/(firm+'.jsonl'),ROOT/'data/findings/validation'/(firm+'.json'),ROOT/'data/findings/supplemental'/(firm+'.jsonl')):
            if p.exists():paths.append(str(p.relative_to(ROOT)))
    paths += [str(p.relative_to(ROOT)) for p in LOCAL.rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    path=ROOT/'data/findings/validation/recall_push_files_written.txt'
    path.write_text('\n'.join(sorted(set(paths)))+'\n')


def tests():
    import unittest
    names=['test_recall_push','test_fuzzland_composable','test_variants','test_group2',
           'test_group3.Group3Tests.test_hats_nested_summary_is_not_another_finding']
    suite=unittest.defaultTestLoader.loadTestsFromNames(names)
    result=unittest.TextTestRunner(verbosity=1).run(suite)
    write_json(ROOT/'data/findings/validation/recall_push_tests.json',dict(
        ok=result.wasSuccessful(),tests=result.testsRun,failures=[str(t) for t,_ in result.failures],
        errors=[str(t) for t,_ in result.errors],skipped=[str(t) for t,_ in result.skipped],suites=names))
    if not result.wasSuccessful():raise SystemExit(1)


def global_check():
    import subprocess
    command='import sys;sys.path.insert(0,'+repr(str(ROOT/'scripts/findings'))+');import check;check.main()'
    result=subprocess.run([sys.executable,'-I','-B','-S','-c',command],cwd=ROOT,capture_output=True,text=True)
    (LOCAL/'global_check.log').write_text(result.stdout+result.stderr)
    error=(result.stderr.strip().splitlines() or [''])[ -1 ]
    write_json(LOCAL/'global_check.json',dict(returncode=result.returncode,error=error))
    print('Full checker return code:',result.returncode,error,flush=True)


def theori_aliases():
    """Replay officially reconciled aliases without changing their attribution."""
    import importlib.util
    from variants import dispatch
    source=LOCAL/'before_parsers/theori.py'
    spec=importlib.util.spec_from_file_location('recall_theori_before',source)
    previous=importlib.util.module_from_spec(spec);spec.loader.exec_module(previous)
    reconciliation=json.loads((ROOT/'data/collect/chainlight/identity_reconciliation.json').read_text())
    official={r['sha256'] for r in reconciliation.get('source_links',[]) if r['source_firm_id']=='theori'}
    current,_,_=documents();chosen={}
    for d in current:
        if d['row']['firm_id']=='theori' or d['row']['firm_id']=='chainlight' and d['row']['sha256'] in official:
            chosen[d['row']['sha256']]=d
    result=[]
    for sha,d in sorted(chosen.items()):
        assert sha not in holdouts()
        stored=d['row']['firm_id'];test=d|{'row':d['row']|{'firm_id':'theori'}}
        r=load(test);b=finish(r,dispatch(r,previous.VARIANTS))
        r=load(test);a=finish(r,module('theori').parse(r))
        result.append(dict(sha256=sha,document_id=d['document_id'],public_url=d['row']['public_url'],
            stored_publisher=stored,parser_publisher='theori',variant_id=r.layout_selection['variant_id'],
            before=len(b),after=len(a),id_sequence=sequence([dict(record_kind=c.record_kind,publisher_finding_id=c.printed_id,evidence=c.evidence) for c in a],'theori'),
            printed_summary=module('theori').printed_counts(r),disposition=getattr(r,'layout_disposition',None)))
    value=dict(documents=result,holdouts_opened=0,validation_only=True,
        before=sum(r['before'] for r in result),after=sum(r['after'] for r in result),
        zero_findings=sum(r['after']==0 for r in result),
        note='Official Theori aliases retain their stored ChainLight attribution and existing finding streams; this grammar-validation cohort is not added to publisher totals.')
    write_json(ROOT/'data/findings/validation/recall_push_theori_aliases.json',value)
    print(json.dumps(value,indent=2))


def residuals():
    for r in json.loads((LOCAL/'after.json').read_text())['documents']:
        if r.get('id_gaps') or r.get('duplicate_ids'):
            print(r['firm'],r['sha256'][:12],r['findings'],r['id_sequence'])
            print([(c['id'],c['title']) for c in r['entries']])


def changes():
    old={(r['firm'],r['sha256']):r for r in json.loads((LOCAL/'before.json').read_text())['documents']}
    for r in json.loads((LOCAL/'after.json').read_text())['documents']:
        b=old[r['firm'],r['sha256']]
        if r['findings']!=b['findings']:
            print(r['firm'],r['sha256'][:12],b['findings'],'->',r['findings'],r['filename'])


def survey(phase,selected=FIRMS):
    grouped = defaultdict(list)
    for doc in inputs():
        if doc['row']['firm_id'] in selected:grouped[(doc['row']['firm_id'], doc['row']['sha256'])].append(doc)
    path=LOCAL/(phase+'.json')
    rows=[r for r in json.loads(path.read_text())['documents'] if r['firm'] not in selected] if phase=='after' and path.exists() else []
    for (firm, sha), docs in grouped.items():
        print('survey', phase, firm, sha[:12], flush=True)
        try:
            row = diagnose(docs[0])
        except (FileNotFoundError, ValueError) as exc:
            row = dict(firm=firm, sha256=sha, filename=docs[0]['row']['filename'],
                       public_url=docs[0]['row']['public_url'], error=str(exc), findings=0,
                       zero_finding_audit=docs[0]['row']['doc_kind'] not in {'non_report', 'formal_verification'})
        row['occurrences'] = len(docs)
        row['document_ids'] = [d['document_id'] for d in docs]
        rows.append(row)
    rows.sort(key=lambda r:(r['firm'],r['sha256']))
    result = dict(per_publisher=metrics(rows), documents=rows, holdouts_opened=0,
                  holdout_list_sha256=digest((ROOT / 'data/holdout/gold_sha256.txt').read_bytes()))
    target = LOCAL / (phase + '.json')
    if phase == 'before' and target.exists(): raise ValueError('Refusing to overwrite baseline')
    write_json(target, result)
    print(json.dumps(result['per_publisher'], indent=2))
    for r in rows:
        flags = [k for k in ('summary_mismatch', 'below_printed_summary', 'id_gaps', 'duplicate_ids', 'zero_finding_audit', 'error') if r.get(k)]
        if flags: print(r['firm'], r['sha256'][:12], r['findings'], ','.join(flags), r['filename'])


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--freeze', action='store_true')
    p.add_argument('--phase', choices=('before', 'after'))
    p.add_argument('--inspect')
    p.add_argument('--start', type=int, default=1)
    p.add_argument('--end', type=int, default=250)
    p.add_argument('--match', help='Show matching source lines with two context lines')
    p.add_argument('--flags', choices=FIRMS)
    p.add_argument('--parse-one')
    p.add_argument('--regenerate',action='store_true')
    p.add_argument('--review',action='store_true')
    p.add_argument('--badges')
    p.add_argument('--report',action='store_true')
    p.add_argument('--verify',action='store_true')
    p.add_argument('--manifest',action='store_true')
    p.add_argument('--residuals',action='store_true')
    p.add_argument('--page',type=int)
    p.add_argument('--firms',nargs='+',choices=FIRMS,default=FIRMS)
    p.add_argument('--tests',action='store_true')
    p.add_argument('--global-check',action='store_true')
    p.add_argument('--debug-shape')
    p.add_argument('--changes',action='store_true')
    p.add_argument('--theori-aliases',action='store_true')
    a = p.parse_args()
    if a.freeze: freeze()
    elif a.phase: survey(a.phase,a.firms)
    elif a.regenerate:regenerate(a.firms)
    elif a.review:review()
    elif a.report:report_result()
    elif a.verify:verify()
    elif a.manifest:manifest()
    elif a.residuals:residuals()
    elif a.tests:tests()
    elif a.global_check:global_check()
    elif a.changes:changes()
    elif a.theori_aliases:theori_aliases()
    elif a.debug_shape:
        from parsers import zokyo
        from layout_support import view
        doc=next(d for d in inputs() if d['row']['sha256'].startswith(a.debug_shape));r=load(doc)
        for kind,cs in [('native',zokyo._card_parse(view(r))),('merged',zokyo._with_visual_cards(r))]:
            print(kind,len(cs))
            for c in cs:print(c.start,c.end,len(r.text[c.start:c.end].strip()),c.printed_id,c.title)
    elif a.badges:
        rows=json.loads((ROOT/'scripts/findings/parsers/fixtures/recall_zokyo_badges.json').read_text())['claims']
        for c in rows:
            if c['sha256'].startswith(a.badges):
                print(c['page'],c.get('printed_id'),c['title_span']['text'],c['title_match_score'])
                print(LOCAL/'ocr'/c['sha256']/(str(c['page'])+'.png'))
    elif a.flags:
        for d in json.loads((LOCAL / 'before.json').read_text())['documents']:
            if d['firm'] == a.flags and any(d.get(k) for k in ('summary_mismatch', 'below_printed_summary', 'id_gaps', 'duplicate_ids', 'zero_finding_audit', 'error')):
                print(d['sha256'][:12], d['filename'], d.get('variant_id'))
                print('summary', (d.get('printed_summary') or {}).get('counts'), 'parsed', d.get('parsed_counts'), 'sequence', d.get('id_sequence'), d.get('disposition'))
                print('entries', [(c['id'], c['severity_raw'], c['title']) for c in d.get('entries', [])])
    elif a.parse_one:
        doc=next(d for d in inputs() if d['row']['sha256'].startswith(a.parse_one))
        print(json.dumps(diagnose(doc),indent=2))
    elif a.inspect:
        doc = next(d for d in inputs() if d['row']['sha256'].startswith(a.inspect))
        r = load(doc)
        if a.page:
            for line in r.lines:
                if line.page==a.page:print(line.start,line.content)
            return
        lines = r.text.splitlines()
        selected = {i for i in range(len(lines)) if a.start <= i + 1 <= a.end}
        if a.match:
            selected = {k for i, s in enumerate(lines) if re.search(a.match, s, re.I)
                        for k in range(max(0, i - 2), min(len(lines), i + 3))}
        for i in sorted(selected): print(f'{i+1:5} {lines[i]}')


if __name__ == '__main__': main()
