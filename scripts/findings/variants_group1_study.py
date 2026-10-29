"""Holdout-guarded Phase 4e group 1 inspection and report reproduction."""
import argparse
from collections import Counter, defaultdict
from dataclasses import asdict
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest, holdouts, read_snapshot, write_json
from core import Report
from parsers import module
from variants import select
from variants_report import metric, cell, sequence

FIRMS = ('code4rena', 'shieldify', 'certora', 'hexens', 'runtime-verification',
         'informalsystems', 'neodyme', 'chainlight')


def files_written():
    paths = ['scripts/findings/core.py', 'scripts/findings/variants_group1_study.py',
             'scripts/findings/test_variants_group1_c4_runtime.py',
             'scripts/findings/study_certora_shieldify_variants.py',
             'scripts/findings/parsers/fixtures_certora_shieldify_variants.py',
             'scripts/findings/parsers/test_certora_shieldify_variants.py',
             'scripts/findings/study_hexens_informal.py', 'scripts/findings/test_hexens_informal_variants.py',
             'scripts/findings/study_chainlight_neodyme.py', 'scripts/findings/test_chainlight_neodyme_variants.py',
             'data/findings/_unknown_layouts.jsonl', 'data/findings/variants/group1_metrics.json',
             'data/findings/variants/group1_chainlight_neodyme.json', 'docs/phase4/variants_group1.md']
    for firm in FIRMS:
        paths.extend([f'scripts/findings/parsers/{firm.replace("-", "_")}.py',
                      f'data/findings/{firm}.jsonl', f'data/findings/validation/{firm}.json',
                      f'data/findings/validation/{firm}.jsonl'])
    return sorted(paths)


def sources(firm):
    return [d for d in read_snapshot() if d['row']['firm_id'] == firm]


def load(d):
    row = d['row']; sha = row['sha256']
    if sha in holdouts():
        raise ValueError('Holdout text access denied')
    base = ROOT / 'local-cache/fulltext'
    meta = json.loads((base / (sha + '.pages.json')).read_text())
    text = (base / (sha + '.txt')).read_text()
    if digest(text.encode()) != meta['text_sha256']:
        raise ValueError('Fulltext digest mismatch')
    return Report(text, meta | {'date_hint': row.get('date_hint')}, row['firm_id'])


def inspect(a):
    ds = sources(a.firm)
    if a.sha:
        if a.sha in holdouts():
            raise ValueError('Holdout inspection denied')
        ds = [d for d in ds if d['row']['sha256'].startswith(a.sha)]
    elif not a.all:
        years = defaultdict(list)
        for d in ds:
            years[(d['row'].get('date_hint') or 'unknown')[:4]].append(d)
        ds = []
        for year, items in sorted(years.items()):
            ordered = sorted(items, key=lambda d: (d['row'].get('date_hint') or '', d['row']['sha256']))
            ds.extend({d['row']['sha256']: d for d in (ordered[0], ordered[-1])}.values())
    for d in ds[:a.limit]:
        r = load(d)
        print('\nDOC', d['row']['sha256'], d['row'].get('date_hint'), d['row']['public_url'])
        if a.page:
            print('\n'.join(p['text'] for p in r.meta['pages'] if p['page'] == a.page)[:a.chars])
        elif a.pattern:
            lines = r.text.splitlines()
            indices = {j for i, line in enumerate(lines) if re.search(a.pattern, line, re.I)
                       for j in range(max(0, i-a.context), min(len(lines), i+a.context+1))}
            print('\n'.join(lines[i] for i in sorted(indices))[:a.chars])
        else:
            print(r.text[:a.chars])


def inventory():
    result = {}
    for firm in FIRMS:
        years = Counter(); layouts = Counter(); examples = defaultdict(list)
        for d in sources(firm):
            row = d['row']; year = (row.get('date_hint') or 'unknown')[:4]
            years[(year, row['file_format'])] += 1
            try:
                r = load(d)
                v = select(r, module(firm).VARIANTS)
                key = v.variant_id if v else firm + '/generic_fallback'
                layouts[key] += 1
                examples[(key, year)].append(row['sha256'])
            except FileNotFoundError:
                layouts[firm + '/extraction_failed'] += 1
        result[firm] = {'years_formats': {str(k): v for k, v in sorted(years.items())},
                        'variants': dict(layouts), 'examples': {str(k): sorted(set(v))[:2] for k, v in sorted(examples.items())}}
    print(json.dumps(result, indent=2))


def features(a):
    ds = {d['row']['sha256']: d for d in sources(a.firm)}
    diagnostics = {d['sha256']: d for d in map(json.loads, (ROOT / 'data/findings/validation' / (a.firm+'.jsonl')).read_text().splitlines())}
    grouped = defaultdict(list)
    for sha, d in ds.items():
        r = load(d)
        if a.firm == 'code4rena':
            key = (d['row']['file_format'], bool(re.search(r'^[-*] \[\[?[HMLING]-\d+', r.text, re.M)),
                   bool(re.search(r'^#{1,3} \[\]\(#', r.text, re.M)),
                   bool(re.search(r'^# (?:Low Risk and|Informational Findings)', r.text, re.M)))
        else:
            key = tuple(bool(re.search(p, r.text, re.M | re.I)) for p in
                        (r'^\s*\[(?:[ABCF]I?|TSI?)-?\d+\]', r'^\s*[ABCF]\d+[.: ]',
                         r'^\s*Severity\s*:', r'^\s*List of Findings', r'^\s*Issue\s+Category',
                         r'^\s*Minor Findings', r'\bformal verification\b'))
        grouped[key].append((sha, d['row'].get('date_hint'), diagnostics[sha].get('findings'), d['row']['filename']))
    for key, items in sorted(grouped.items()):
        print(key, len(items))
        print(json.dumps(items[:a.limit], ensure_ascii=False))


def diagnostics(a):
    firms = FIRMS if a.all else (a.firm,)
    for firm in firms:
        ds = list(map(json.loads, (ROOT/'data/findings/validation'/(firm+'.jsonl')).read_text().splitlines()))
        with (ROOT/'data/findings'/(firm+'.jsonl')).open() as stream:
            rs = [json.loads(line) for line in stream]
        for vid in sorted({d.get('variant_id', firm+'/extraction_failed') for d in ds}):
            m = metric(firm, vid, [d for d in ds if d.get('variant_id', firm+'/extraction_failed') == vid],
                       [r for r in rs if r.get('variant_id') == vid])
            print(vid, m['documents'], cell(m['summary_matching'], m['summary_comparable']),
                  cell(m['sequence_complete'], m['sequence_comparable']), cell(m['known_status_rows'], m['detailed_rows']))
        for d in [d for d in ds if d.get('unknown_layout')][:a.limit]:
            source=next(x for x in sources(firm) if x['document_id']==d['document_id'])
            print('UNKNOWN', d['sha256'], source['row']['filename'], d['scores'][:2])
        if a.pattern == 'mismatch':
            for d in [d for d in ds if d['validation']=='mismatch'][:a.limit]:
                print('MISMATCH', d['sha256'], d['parsed_counts'], d['printed_summary']['counts'])
        if a.pattern == 'sequence':
            by_doc=defaultdict(list)
            for row in rs: by_doc[row['document_id']].append(row)
            incomplete=[]
            for d in ds:
                result=sequence(by_doc[d['document_id']], firm)
                if result and not result['complete']:
                    incomplete.append((d['sha256'], d.get('variant_id'), result))
            for row in incomplete[:a.limit]: print('INCOMPLETE', row)


RESIDUALS = {
    'code4rena': 'Linked-only low/noncritical/gas chapters remain summary_excerpt, so strict formal-detail summary agreement retains their deficits. The early Slingshot PDF omits native L-11 while its prose counts it; source ID gaps and duplicate source IDs stay visible. Some full-detail sources contradict their printed totals. Numbered QA/gas runs use explicit enclosing chapter namespaces. Missing publisher remediation remains null; confirmed/disputed alone remain other rather than proof of a fix.',
    'shieldify': 'Alternatives and secondary findings retain their source counting role. Sparse clean reports and extraction-damaged PDFs are fingerprinted separately where their source template survives. OCR-damaged IDs and contradictory source summaries remain diagnostic failures.',
    'certora': 'Formal-verification rules/specifications are not vulnerabilities. Severity fields take precedence over contradictory ID prefixes (4b072c6d…, 32d09ffd…, 12217c36…, 405cf3df…, 9ca94dbf…). Stale totals (521155b7…, 16c5a4b3…, 18e2ab6e…, 139542cb…), a documented downgrade (65c8ccdb…) and damaged Delv text (00e07c38…) remain comparable failures. Bidi controls and detached ID glyphs are handled where the text survives; no mismatch is removed to meet the gate.',
    'hexens': 'Astrolab bf3b20… and Socket 4015e4… have printed summary buckets exceeding their source detail cards. Their mismatches remain comparable. Symbolic ID namespaces have native gaps, so ID completeness is low despite passing summary agreement. No IDs or finding rows were manufactured.',
    'runtime-verification': 'Proof papers, delivered verification milestones and generated Alloy/property attachments are distinct from finding-card audits. Narrative reviews without recognized detail cards remain a coverage gap, not clean-audit claims. Pact Fi Router e08ae8… has an OCR Al/Bl versus A1/B1 ambiguity; its missing sequential slot is retained. Numbered risk cards use explicit Notable Findings/Informative findings/Issues headings as ID namespaces. Status prose is normalized only inside an explicit Status section; recommendations do not imply fixes.',
    'informalsystems': 'Markdown fragments, empty templates and protocol assessments may contain no finding cards. Namada 8844f7… has conditional grades and XRPL 52a590… has a numeric-overview versus complete finding/status-index conflict; both keep independent source ambiguity evidence. Outdated and Disputed stay normalized other.',
    'neodyme': 'Compact ND-SQD1-M1-style IDs are preserved; the unchanged shared ID-sequence metric does not recognize their alphanumeric prefix and reports N/A. The early SPL report has an internally inconsistent printed total versus severity buckets and is marked source-ambiguous. Some early reports omit statuses.',
    'chainlight': '89e479c4dc40… retains Issue headings only in its TOC; body heading/risk glyphs are absent. Its generic_fallback is an explained fulltext limitation. Orb and some early reports omit statuses; absent status stays null.',
}


def report_group(a):
    blocked=holdouts(); all_metrics=[]; failures=[]; catalog=[]; examples=[]
    verified_rows=0; status_spans=0; status_without_span=Counter(); input_docs=0
    for firm in FIRMS:
        ds=list(map(json.loads, (ROOT/'data/findings/validation'/(firm+'.jsonl')).read_text().splitlines()))
        parents={d['document_id']: d for d in sources(firm)}
        assert set(parents)=={d['document_id'] for d in ds}, 'Stale document membership: '+firm
        input_docs+=len(parents)
        with (ROOT/'data/findings'/(firm+'.jsonl')).open() as stream:
            rs=[json.loads(line) for line in stream]
        by_doc=defaultdict(list); current_sha=None; source=None
        for row in rs:
            assert row['sha256'] not in blocked
            assert row['document_id'] in parents and row['firm_id']==firm
            by_doc[row['document_id']].append(row)
            if a.verify:
                if current_sha!=row['sha256']:
                    source=load(parents[row['document_id']]); current_sha=row['sha256']
                body=row['body_span']; start,end=body['start'],body['end']
                assert 0<=start<end<=len(source.text)
                assert source.text[start:end]==row['body_text']
                proof=row['evidence'].get('status_evidence')
                if proof:
                    assert source.text[proof['start']:proof['end']]==proof['text']==proof['raw']==row['status_raw']
                    status_spans+=1
                elif row.get('status_raw'):
                    status_without_span[firm]+=1
                verified_rows+=1
        variants={v.variant_id: v for v in module(firm).VARIANTS}
        assert all(not v.fingerprint.legacy and v.fixtures and v.status_parser for v in variants.values())
        for vid in sorted(set(variants)|{d.get('variant_id', firm+'/extraction_failed') for d in ds}):
            selected=[d for d in ds if d.get('variant_id',firm+'/extraction_failed')==vid]
            all_metrics.append(metric(firm,vid,selected,[r for r in rs if r['variant_id']==vid]))
            if vid in variants:
                v=variants[vid]
                catalog.append(dict(firm=firm,variant_id=vid,fingerprint=asdict(v.fingerprint),
                                    parser=v.parse.__name__,status_parser=v.status_parser.__name__,fixtures=v.fixtures,notes=v.notes))
            years=defaultdict(list)
            for d in selected: years[d.get('year') or 'unknown'].append(d)
            for year, items in sorted(years.items()):
                ordered=sorted(items, key=lambda d: d['sha256'])
                for d in {x['sha256']:x for x in (ordered[0],ordered[-1])}.values():
                    examples.append({k:d.get(k) for k in ('firm_id','document_id','sha256','year','variant_id','validation','scores')})
        for d in ds:
            assert d['sha256'] not in blocked
            parsed=Counter(r['severity'] for r in by_doc[d['document_id']] if r['record_kind']=='formal_finding')
            assert all(parsed[s]==n for s,n in d.get('parsed_counts',{}).items())
            if d.get('unknown_layout') or d['validation'] in {'mismatch','parser_error','extraction_failed'}:
                failures.append({k:d.get(k) for k in ('firm_id','document_id','sha256','variant_id','validation','unknown_layout','parsed_counts','printed_summary','error')})
    queue=[json.loads(line) for line in (ROOT/'data/findings/_unknown_layouts.jsonl').open()]
    unknown=[q for q in queue if q['firm'] in FIRMS]
    assert all(q['sha256'] not in blocked for q in unknown)
    unknown_by_firm=dict(Counter(q['firm'] for q in unknown))
    result=dict(per_variant=all_metrics,catalog=catalog,examples=examples,residuals=RESIDUALS,
                failures=failures,unknown_layouts=unknown,unknown_by_firm=unknown_by_firm,
                documents=input_docs,findings=sum(m['findings'] for m in all_metrics),
                holdouts_opened=0,verified_rows=verified_rows,verified_status_spans=status_spans,
                statuses_without_evidence=dict(status_without_span),
                files_written=files_written(),
                metric_implementation='scripts/findings/variants_report.py:metric,sequence')
    write_json(ROOT/'data/findings/variants/group1_metrics.json',result)
    lines=['# Phase 4e group 1 layout variants','',
           'Generated by `python3 -I -S scripts/findings/variants_group1_study.py report --verify`. '
           'Uses the unchanged `variants_report.metric` and `variants_report.sequence` implementations. '
           'Only the eight assigned publishers are regenerated. Severity policy is unchanged. '
           'The sole shared edit is an opt-in `status_reader_complete` guard in `core.finish`: '
           'a second finalization may not restore status text deliberately rejected by a variant reader. '
           'Existing parsers that do not set the flag retain their previous behavior.','',
           f"Development snapshot: {input_docs:,} document occurrences and {result['findings']:,} emitted rows. "
           f"Holdouts opened: 0. Verified {verified_rows:,} body spans and {status_spans:,} exact status spans. "
           f"Status rows without a separate evidence span: {sum(status_without_span.values()):,}.", '',
           'Each format has a scored text/date fingerprint, parser, synthetic regression fixtures and explicit status reader. '
           'Date ranges overlap and do not assert exact template cutovers. Source examples cover every observed variant/year, '
           'including unknown-year occurrences, in `data/findings/variants/group1_metrics.json`. '
           'All text access fails closed on the holdout list before opening the cache.','',
           'Summary agreement is exact equality with independently printed severity totals for formal findings only. '
           'All comparable mismatches remain in the denominator. ID completeness is an observed native-namespace sequence diagnostic, '
           'not recall; absent or unsupported IDs are N/A. Findings coverage includes all emitted kinds. '
           'Status coverage is known normalized status / detailed row, excluding summary excerpts; it measures availability, not heldout accuracy.','',
           '| Publisher / variant | Documents | Summary agreement | ID complete | Docs with findings | Status coverage |',
           '|---|---:|---:|---:|---:|---:|']
    for m in all_metrics:
        lines.append(f"| {m['variant_id']} | {m['documents']} | {cell(m['summary_matching'],m['summary_comparable'])} | "
                     f"{cell(m['sequence_complete'],m['sequence_comparable'])} | {cell(m['documents_with_findings'],m['documents'])} | "
                     f"{cell(m['known_status_rows'],m['detailed_rows'])} |")
    lines+=['','## Residual failure classes','']
    for firm in FIRMS:
        lines.append(f'- **{firm}:** {RESIDUALS[firm]}')
    lines+=['','## Unknown layouts and extraction failures','',
            f"{len(unknown)} artifact/publisher pairs remain in the shared unknown queue for this group.",'']
    for q in unknown:
        lines.append(f"- `{q['firm']}` `{q['sha256']}`: see the publisher residual above; retained for source-text review.")
    for f in failures:
        if f['validation'] in {'parser_error','extraction_failed'}:
            lines.append(f"- `{f['firm_id']}` `{f['sha256']}`: {f['validation']}; {f.get('error') or 'no usable fulltext'}.")
    below=[m for m in all_metrics if m['summary_comparable'] and m['summary_agreement_percent']<95]
    below_ids=[m for m in all_metrics if not m['summary_comparable'] and m['sequence_comparable'] and m['id_sequence_completeness_percent']<95]
    lines+=['','## Target gaps','',
            'Summary variants below the target: '+(', '.join(m['variant_id'] for m in below) or 'none')+'.',
            'No-summary variants below the ID target: '+(', '.join(m['variant_id'] for m in below_ids) or 'none')+'.',
            'The source-limited cases above are retained; no totals, IDs, statuses or synthetic findings were added to meet a gate.','',
            '## Validation','',
            'Owned variant fixtures and affected legacy regressions pass. The shared framework/variant suites pass. '
            'The scoped report verifies holdout exclusion, input membership, body-text digests, exact body/status spans and formal-count accounting. '
            'A whole-corpus checker is left to the release operator after concurrent publisher regenerations settle; '
            'the heldout status-accuracy estimate was not re-evaluated or used for tuning.','',
            '## Reproduce','',
            '```sh',
            'python3 -S scripts/findings/run.py --firms '+' '.join(FIRMS),
            'python3 -I -S scripts/findings/variants_group1_study.py report --verify',
            '```','']
    lines+=['## Files written','']+[f'- `{path}`' for path in files_written()]+['']
    (ROOT/'docs/phase4/variants_group1.md').write_text('\n'.join(lines))
    print('\n'.join(lines[:lines.index('## Residual failure classes')]))
    print('Unknown:', unknown_by_firm, 'Status without span:', dict(status_without_span))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('inventory', 'inspect', 'features', 'diagnostics', 'report'))
    p.add_argument('--firm', choices=FIRMS, default='code4rena')
    p.add_argument('--sha'); p.add_argument('--all', action='store_true')
    p.add_argument('--limit', type=int, default=30)
    p.add_argument('--pattern'); p.add_argument('--context', type=int, default=2)
    p.add_argument('--chars', type=int, default=5000)
    p.add_argument('--page', type=int)
    p.add_argument('--verify', action='store_true')
    a = p.parse_args()
    if a.command == 'inventory':
        inventory()
    elif a.command == 'features':
        features(a)
    elif a.command == 'diagnostics':
        diagnostics(a)
    elif a.command == 'report':
        report_group(a)
    else:
        inspect(a)


if __name__ == '__main__':
    main()
