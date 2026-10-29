"""Holdout-safe Phase 4e group 4 development, regeneration and reporting."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, canonical, digest, documents, holdouts, write_json, write_jsonl
from core import Report, finish
from parsers import module
from variants_study import load

FIRMS = ('oak-security', 'consensys-diligence', 'mixbytes', 'abdk-consulting',
         'veridise', 'sigma-prime', 'three-sigma', 'oxorio', 'movebit', 'scalebit')


def warm(args):
    """Extract only missing caches for this group's acquired, non-holdout files."""
    # Isolated Python disables the already installed user package directory.
    # Add that directory explicitly without processing site startup/.pth hooks.
    import site
    sys.path.append(site.getusersitepackages())
    import fitz
    print('Existing PyMuPDF', fitz.VersionBind, flush=True)
    from extract import extract_one
    blocked = holdouts()
    docs, _, _ = documents()
    jobs = {d['row']['sha256']: d['row'] for d in docs if d['row']['firm_id'] in args.firms
            and not ((ROOT / 'local-cache/fulltext' / (d['row']['sha256']+'.txt')).exists()
                     and (ROOT / 'local-cache/fulltext' / (d['row']['sha256']+'.pages.json')).exists())}
    assert not set(jobs) & blocked
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(pool.map(lambda item: extract_one(item, ROOT, blocked), sorted(jobs.items())))
    receipt = ROOT / 'data/findings/variants/group4_new_extractions.json'
    prior = {r['sha256']: r for r in json.loads(receipt.read_text())} if receipt.exists() else {}
    prior.update({r['sha256']: r for r in rows})
    write_json(receipt, [prior[sha] for sha in sorted(prior)])
    for row in rows:
        print(row['sha256'], row['status'], row.get('characters'), row.get('error'))


def tests(args):
    import importlib.util
    paths = [
        'scripts/findings/test_group4_oak_consensys.py',
        'scripts/findings/test_group4_abdk_sigma_prime_variants.py',
        'scripts/findings/test_group4_movebit_scalebit.py',
        'scripts/findings/test_group4_veridise_oxorio.py',
        'tests/test_group4_mixbytes_three_sigma_variants.py',
        'scripts/findings/test_framework.py',
    ]
    suite = unittest.TestSuite()
    for index, path in enumerate(paths):
        spec = importlib.util.spec_from_file_location('group4_test_'+str(index), ROOT/path)
        loaded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(loaded)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(loaded))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    write_json(ROOT/'data/findings/variants/group4_tests.json', {
        'tests_run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
        'successful': result.wasSuccessful(), 'files': paths,
    })
    if not result.wasSuccessful():
        raise SystemExit(1)


def audit_stage(args):
    if not args.stage:
        raise ValueError('audit requires --stage')
    blocked = holdouts(args.stage)
    bad = []
    cached_sha = None
    for path in sorted((args.stage/'data/findings').glob('*.jsonl')):
        if path.name.startswith('_'):
            continue
        for row in map(json.loads, path.open()):
            proof = row['evidence'].get('status_evidence')
            if not proof:
                continue
            sha = row['sha256']
            assert sha not in blocked
            if sha != cached_sha:
                source = (args.stage/'local-cache/fulltext'/(sha+'.txt')).read_text()
                cached_sha = sha
            actual = source[proof['start']:proof['end']]
            if actual != proof['text'] or proof['text'] != proof['raw'] or proof['raw'] != row['status_raw']:
                bad.append({'firm': path.stem, 'sha256': sha, 'id': row['publisher_finding_id'],
                            'status_raw': row['status_raw'], 'proof': proof, 'actual': actual})
    write_json(ROOT/'data/findings/variants/group4_span_audit.json', bad)
    print('Status receipt failures by publisher:', dict(Counter(r['firm'] for r in bad)))
    for row in bad[:2]:
        print(canonical(row))


def report_results(args):
    from variants_report import cell, sequence
    result = json.loads((ROOT/'data/findings/variants/group4_metrics.json').read_text())
    stage = Path(result['stage_root'])
    docs = {d['document_id']: d for d in map(json.loads,
            (stage/'data/fulltext/input_documents.jsonl').read_text().splitlines())}
    fresh = {d['document_id']: d for d in documents()[0] if d['row']['firm_id'] in FIRMS}
    if {key: d['source_record_sha256'] for key,d in fresh.items()} != {key: d['source_record_sha256'] for key,d in docs.items()}:
        raise RuntimeError('Group 4 collector membership changed after regeneration; rerun before reporting')
    blocked = holdouts()
    diagnostics = []
    years = defaultdict(Counter)
    id_failures = []
    for firm in FIRMS:
        ds = list(map(json.loads, (ROOT/'data/findings/validation'/(firm+'.jsonl')).read_text().splitlines()))
        diagnostics.extend(ds)
        by_doc = defaultdict(list)
        for row in map(json.loads, (ROOT/'data/findings'/(firm+'.jsonl')).read_text().splitlines()):
            assert row['sha256'] not in blocked
            by_doc[row['document_id']].append(row)
        for d in ds:
            assert d['sha256'] not in blocked
            years[d.get('variant_id', firm+'/extraction_failed')][d.get('year') or 'unknown'] += 1
            value = sequence(by_doc[d['document_id']], firm)
            if value and not value['complete']:
                id_failures.append({k: d.get(k) for k in ('document_id','firm_id','sha256','variant_id')} | value)
    ms = result['per_variant']
    failed = [d for d in diagnostics if d['validation']=='extraction_failed']
    mismatches = [d for d in diagnostics if d['validation']=='mismatch']
    unknown = [d for d in diagnostics if d.get('unknown_layout')]
    write_json(ROOT/'data/findings/variants/group4_residuals.json', {
        'mismatches': mismatches, 'id_sequences': id_failures, 'extraction_failures': failed,
        'unknown_layouts': unknown, 'observed_years_by_variant': years,
    })
    checks = json.loads((ROOT/'data/findings/variants/group4_check.json').read_text())
    test_result = json.loads((ROOT/'data/findings/variants/group4_tests.json').read_text())
    lines = ['# Phase 4e group 4 layout variants', '',
        'Generated by `python3 -I -S scripts/findings/group4_tools.py report`. '
        'Regenerate with `python3 -I -S scripts/findings/group4_tools.py regenerate --publish`; '
        'run `warm --firms three-sigma` first when new originals lack text caches.', '',
        f"Fresh collector membership: {len(docs)} source occurrences, {checks['artifacts']} original hashes, "
        f"{checks['findings']} finding rows. Holdouts excluded before cache/original access; "
        f"{checks['holdout_rows_found']} holdout output rows. Existing runner, checker and variants reporter "
        'ran against the same scoped snapshot. Shared input snapshots, global summary and other publishers’ findings were preserved.', '',
        f"Verification: {test_result['tests_run']} focused/framework tests, {test_result['failures']} failures, "
        f"{test_result['errors']} errors; provenance, body/status spans, severity crosswalk, layout selection and summary accounting checked. "
        'Status coverage measures extraction availability, not independent accuracy; no holdout accuracy claim is made.', '',
        '| Publisher / variant | Docs | Summary agreement | ID completeness | Docs with findings | Status coverage |',
        '|---|---:|---:|---:|---:|---:|']
    for m in ms:
        lines.append('| '+m['variant_id']+' | '+str(m['documents'])+' | '+
            cell(m['summary_matching'],m['summary_comparable'])+' | '+
            cell(m['sequence_complete'],m['sequence_comparable'])+' | '+
            cell(m['documents_with_findings'],m['documents'])+' | '+
            cell(m['known_status_rows'],m['detailed_rows'])+' |')
    lines += ['', '## Era contracts and development census', '',
        'Date ranges are overlapping template hints. Text signatures choose a layout; dates alone cannot. '
        'Severity-policy eras remain independent and unchanged. Every variant declares its own parser, status reader and synthetic fixtures. '
        'Counts never select variants or manufacture findings.', '',
        '| Variant | Date hints | Text signatures | Observed source hint years |',
        '|---|---|---|---|']
    for c in result['catalog']:
        fp=c['fingerprint']
        signatures='; '.join(name for name,pattern,weight in fp['signatures'])
        observed=', '.join(f'{y}: {n}' for y,n in sorted(years[c['variant_id']].items())) or 'none'
        lines.append('| '+c['variant_id']+' | '+'–'.join(str(v or 'open') for v in fp['date_range'])+' | '+signatures+' | '+observed+' |')
    lines += ['', 'Full fingerprints and fixture names: [group4_metrics.json](../../data/findings/variants/group4_metrics.json). '
        'Per-document comparison evidence, native ID gaps and year census: [group4_residuals.json](../../data/findings/variants/group4_residuals.json).', '',
        '## Residual failure classes', '',
        'The target is not met in every era. Retained source disagreements and unmeasurable formats are reported explicitly:', '',
        '- ABDK section lists mix numbered section identifiers, local lists, restarts and source gaps. The unchanged structural ID diagnostic remains below target. '
        'Combined CVF member IDs remain linked in evidence; they are not fabricated as independent descriptions. '
        'Some severity-group summaries contradict source detail grades or omit printed detail rows.',
        '- Three Sigma retains source classification/summary conflicts (including both Tradable renderings, Ordiswap Token, Felix, InfiniFi and Keyring), '
        'and the original Ordiswap AMM cache stops before its detail section. The recovered complete AMM rendering is separate and reconciles. '
        'Maple’s source ID punctuation changes its namespace in the structural diagnostic.',
        '- MoveBit MovEx has matching numeric/index summaries but a conflicting detail grade for POL-11; retain the mismatch. '
        'MoveBit and ScaleBit native component IDs use global or sparse ordinals, making per-prefix sequence diagnostics incomplete.',
        '- Veridise retains source severity-summary contradictions, a combined multi-round rendering and a source-duplicated native ID. '
        'Grouped legacy native vulnerability IDs share exact card evidence. No source ID is silently renumbered.',
        '- Oxorio native IDs can be sparse and some reports contain no findings. Verification-only reports and the publisher service brochure emit no new audit findings. '
        'Its recovered Markdown badge format has no printed numeric summary or native finding IDs.',
        '- Oak protocol-review findings are ungraded and lack publisher remediation. Diligence supporting specifications, intake forms, narrative reviews '
        'and raw MythX scanner exports emit no reviewed findings. Absent or ambiguous status remains missing/other. '
        'Status claims in recommendations and prospective developer fixes are not treated as verified fixes.', '',
        f"There are {len(mismatches)} retained comparable mismatches, {len(failed)} extraction failures and {len(unknown)} explained unknown-layout occurrences.", '',
        '| Publisher | SHA-256 | File | Printed severity counts | Extracted severity counts |',
        '|---|---|---|---|---|']
    for d in mismatches:
        row=docs[d['document_id']]['row']
        values=lambda x: ', '.join(f'{k}={v}' for k,v in sorted(x.items()) if v)
        lines.append('| '+d['firm_id']+' | `'+d['sha256']+'` | '+row['filename'].replace('|','\\|')+' | '+
                     values(d['printed_summary']['counts'])+' | '+values(d['parsed_counts'])+' |')
    lines += ['', '## Explained unknown layouts and extraction failures', '',
              '| Publisher | SHA-256 | Characters | Reason |', '|---|---|---:|---|']
    for d in unknown:
        path=ROOT/'local-cache/fulltext'/(d['sha256']+'.txt')
        assert d['sha256'] not in blocked
        n=len(path.read_text()) if path.exists() else 0
        reason='Cover/contact text and page counters only; no finding-body text or format signature.' if d['firm_id']=='movebit' else 'Unsupported source structure; top scores retained in queue.'
        lines.append('| '+d['firm_id']+' | `'+d['sha256']+'` | '+str(n)+' | '+reason+' |')
    for d in failed:
        lines.append('| '+d['firm_id']+' | `'+d['sha256']+'` | N/A | '+str(d.get('error','not_extracted')).replace('|','\\|')+' |')
    lines += ['', '## Shared change and files written', '',
        '`scripts/findings/core.py::finish` adds an opt-in, backward-compatible exception for nonempty, explicitly bounded, '
        'source-confirmed short formal details (`publisher_explicit_short_detail=True`). ABDK alone opts in, preserving genuinely brief numbered issues. '
        'Unmarked short candidates retain prior behavior. No other shared framework changes were made by this group.', '',
        'Complete source/generated/local-output manifest: [variants_group4_files_written.txt](variants_group4_files_written.txt).', '']
    (ROOT/'docs/phase4/variants_group4.md').write_text('\n'.join(lines))
    sources=[f'scripts/findings/parsers/{f.replace("-","_")}.py' for f in FIRMS]
    sources += ['scripts/findings/core.py','scripts/findings/group4_tools.py',
                'scripts/findings/fixtures_group4_abdk_sigma_prime.py',
                'scripts/findings/fixtures/group4_veridise_oxorio.json',
                *('scripts/findings/group4_'+name+'_study.py' for name in ('oak_consensys','abdk_sigma_prime','movebit_scalebit')),
                'scripts/findings/group4_mixbytes_three_sigma.py',
                *test_result['files'][:-1]]
    outputs=['docs/phase4/variants_group4.md','docs/phase4/variants_group4_files_written.txt',
             'data/findings/_unknown_layouts.jsonl']
    for firm in FIRMS:
        outputs += [f'data/findings/{firm}.jsonl',f'data/findings/validation/{firm}.json',f'data/findings/validation/{firm}.jsonl']
    outputs += [str(p.relative_to(ROOT)) for p in sorted((ROOT/'data/findings/variants').glob('group4_*.json'))]
    receipt=ROOT/'data/findings/variants/group4_new_extractions.json'
    if receipt.exists():
        for e in json.loads(receipt.read_text()):
            if e['status'] in {'ok','partial'}:
                outputs += [f'local-cache/fulltext/{e["sha256"]}.txt',f'local-cache/fulltext/{e["sha256"]}.pages.json']
    stages=[]
    for parent in sorted(Path('/tmp').glob('phase4e-group4-*')):
        if parent.is_dir():
            stages.extend(str(p) for p in parent.rglob('*') if p.is_file() and not p.is_symlink())
    logs=[str(p) for pattern in ('phase4e-group4-*.log','group4_oak_consensys*',
                                'group4_abdk_sigma_prime*','group4_movebit_scalebit*',
                                'group4_mixbytes_three_sigma*')
          for p in Path('/tmp').glob(pattern) if p.is_file()]
    manifest=['# Group 4 files written','', 'Source files:']+sorted(set(sources))+['','Generated outputs:']+sorted(set(outputs))+['','Retained temporary stages/logs:']+sorted(set(stages+logs))+['']
    (ROOT/'docs/phase4/variants_group4_files_written.txt').write_text('\n'.join(manifest))
    print('WROTE docs/phase4/variants_group4.md and exhaustive file manifest')


def regenerate(args):
    """Run the existing runner/checker/reporter against fresh scoped metadata.

    Shared snapshots, global metrics and another group's findings are untouched.
    The stage is retained so every reported metric and receipt is reviewable.
    """
    from parsers import FIRMS as REQUIRED, CONTESTS
    from variants_report import cell
    docs, ledger, excluded = documents()
    selected = [d for d in docs if d['row']['firm_id'] in args.firms]
    blocked = holdouts()
    if args.stage:
        stage = args.stage.resolve()
    else:
        stage = Path(tempfile.mkdtemp(prefix='phase4e-group4-'))
        for rel in ('data/fulltext', 'data/holdout', 'data/findings/validation',
                    'registry', 'local-cache', 'docs/phase4'):
            (stage / rel).mkdir(parents=True, exist_ok=True)
        for rel in ('data/holdout/gold_sha256.txt', 'registry/scope_tier_a.csv',
                    'local-cache/fulltext', 'data/collect'):
            (stage / rel).symlink_to(ROOT / rel, target_is_directory=(ROOT / rel).is_dir())
        write_jsonl(stage / 'data/fulltext/input_documents.jsonl', selected)
        prior = {r['sha256']: r for r in map(json.loads,
                 (ROOT / 'data/fulltext/extractions.jsonl').read_text().splitlines())}
        receipts = []
        for sha in sorted({d['row']['sha256'] for d in selected}):
            assert sha not in blocked
            path = ROOT / 'local-cache/fulltext' / (sha + '.pages.json')
            if path.exists():
                meta = json.loads(path.read_text())
                receipts.append({k: v for k, v in meta.items() if k != 'pages'} | {'sha256': sha})
            else:
                receipts.append(prior.get(sha, {'sha256': sha, 'status': 'failed', 'error': 'not_extracted'}))
        write_jsonl(stage / 'data/fulltext/extractions.jsonl', receipts)
        write_json(stage / 'data/fulltext/inventory.json', {
            'scope_sha256': digest((ROOT / 'registry/scope_tier_a.csv').read_bytes()),
            'holdout_list_sha256': digest((ROOT / 'data/holdout/gold_sha256.txt').read_bytes()),
            'collection_files': ledger,
        })
        for firm in REQUIRED + CONTESTS:
            (stage / 'data/findings' / (firm + '.jsonl')).touch()
    for script in ('run.py', 'check.py', 'variants_report.py'):
        if script == 'run.py' and args.stage and not args.rerun_firms:
            continue
        location = ROOT / 'scripts/findings'
        bootstrap = ('import runpy,sys;sys.path.insert(0,' + repr(str(location)) + ');'
                     'runpy.run_path(' + repr(str(location / script)) + ',run_name="__main__")')
        command = [sys.executable, '-I','-B', '-S', '-c', bootstrap, '--root', str(stage)]
        if script == 'run.py':
            command += ['--firms', *(args.rerun_firms if args.stage else args.firms), '--live-cache']
        subprocess.run(command, check=True)
    metrics = json.loads((stage / 'data/findings/variants/metrics.json').read_text())
    metrics['per_variant'] = [m for m in metrics['per_variant'] if m['firm'] in args.firms]
    metrics['catalog'] = [m for m in metrics['catalog'] if m['firm'] in args.firms]
    print('STAGE', stage)
    for m in metrics['per_variant']:
        print(m['variant_id'], m['documents'],
              cell(m['summary_matching'], m['summary_comparable']),
              cell(m['sequence_complete'], m['sequence_comparable']),
              cell(m['documents_with_findings'], m['documents']),
              cell(m['known_status_rows'], m['detailed_rows']))
    if args.publish:
        if set(args.firms) != set(FIRMS):
            raise ValueError('Publish the complete group together')
        for firm in args.firms:
            for rel in (f'data/findings/{firm}.jsonl', f'data/findings/validation/{firm}.json',
                        f'data/findings/validation/{firm}.jsonl'):
                target = ROOT / rel
                tmp = target.with_name(target.name + '.group4.tmp')
                shutil.copyfile(stage / rel, tmp)
                tmp.replace(target)
        # Preserve every other publisher's current queue receipts.
        queue = ROOT / 'data/findings/_unknown_layouts.jsonl'
        other = [r for r in map(json.loads, queue.read_text().splitlines()) if r['firm'] not in FIRMS]
        ours = list(map(json.loads, (stage / 'data/findings/_unknown_layouts.jsonl').read_text().splitlines()))
        write_jsonl(queue, sorted(other + ours, key=lambda r: (r['firm'], r['sha256'])))
        metrics['stage_root'] = str(stage)
        metrics['snapshot_basis'] = 'fresh common.documents(); holdouts excluded before fulltext access'
        metrics['excluded_input_occurrences'] = excluded
        metrics['target_firms'] = []
        metrics['totals']['variants'] = len(metrics['catalog'])
        write_json(ROOT / 'data/findings/variants/group4_metrics.json', metrics)
        write_json(ROOT / 'data/findings/variants/group4_check.json',
                   json.loads((stage / 'data/findings/check.json').read_text()))
        print('PUBLISHED group 4 only')


def study(args):
    docs, _, _ = documents()
    for firm in args.firms:
        unique = {d['row']['sha256']: d for d in docs if d['row']['firm_id'] == firm}
        years = defaultdict(Counter)
        failures = []
        for sha, doc in sorted(unique.items()):
            if args.sha and not sha.startswith(args.sha):
                continue
            try:
                text, meta = load(doc)
            except FileNotFoundError:
                failures.append(sha)
                continue
            report = Report(text, meta | {'date_hint': doc['row'].get('date_hint')}, firm)
            parser = module(firm)
            candidates = finish(report, parser.parse(report))
            year = (doc['row'].get('date_hint') or 'unknown')[:4]
            years[year][report.layout_selection['variant_id']] += 1
            if args.sha:
                print('DOC', sha, doc['row'].get('date_hint'), doc['row']['filename'])
                if args.candidates:
                    for c in candidates:
                        print(c.printed_id, c.severity_raw, c.status_raw, c.title, c.start, c.end)
                else:
                    for page in meta['pages']:
                        if args.page and page['page'] != args.page:
                            continue
                        lines = page['text'].splitlines()
                        if args.match:
                            lines = [l for l in lines if re.search(args.match, l, re.I)]
                        if lines:
                            print('PAGE', page['page'], '\n' + '\n'.join(lines[:args.limit]))
        print(firm, 'unique artifacts', len(unique), 'year/layout census',
              json.dumps(years, sort_keys=True), 'missing cache', failures)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=('study', 'regenerate', 'warm', 'tests', 'report', 'audit'))
    p.add_argument('--firms', nargs='+', choices=FIRMS, default=list(FIRMS))
    p.add_argument('--sha')
    p.add_argument('--page', type=int)
    p.add_argument('--match')
    p.add_argument('--candidates', action='store_true')
    p.add_argument('--limit', type=int, default=150)
    p.add_argument('--publish', action='store_true')
    p.add_argument('--stage', type=Path, help='Resume a retained scoped stage without rebuilding its snapshot')
    p.add_argument('--rerun-firms', nargs='+', choices=FIRMS)
    args = p.parse_args()
    {'study': study, 'regenerate': regenerate, 'warm': warm, 'tests': tests,
     'report': report_results, 'audit': audit_stage}[args.command](args)


if __name__ == '__main__':
    main()
