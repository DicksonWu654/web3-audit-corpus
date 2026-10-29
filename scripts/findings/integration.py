"""Local parser-freeze gate: isolated full tests, cold parser replay and census.

Run with python3 -I. Collector tests use the local
Python with PyYAML; no dependencies are installed and no network is used.
Existing findings are archived, never deleted. Full-text/OCR evidence is
hash-verified and retained; each parser pass gets a fresh bytecode directory.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, SEVERITIES, digest, holdouts, read_snapshot, write_json
from streams import finding_rows
from status_resolve import STATUSES, status_mapping

LOCAL = ROOT / 'local-cache/findings-integration'


def command(name, args, *, python=None, isolated=True):
    LOCAL.mkdir(parents=True, exist_ok=True)
    prefix = tempfile.mkdtemp(prefix='bytecode-', dir=LOCAL)
    arguments = list(map(str,args))
    if isolated and arguments[0].endswith('.py'):
        bootstrap = ('import runpy,sys,faulthandler;from pathlib import Path;'
                     'trace=open('+repr(str(LOCAL/(name+'.trace')))+',"w");'
                     'faulthandler.enable(file=trace);'
                     'p=Path(sys.argv[1]).resolve();sys.path.insert(0,str(p.parent));'
                     'sys.argv=sys.argv[1:];runpy.run_path(str(p),run_name="__main__")')
        arguments = ['-c',bootstrap,*arguments]
    cmd = [python or sys.executable, *(['-I'] if isolated else []),
           '-X', 'pycache_prefix='+prefix, *arguments]
    env = os.environ | {'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    print(name+': running', flush=True)
    with (LOCAL/(name+'.log')).open('w') as log:
        result = subprocess.run(cmd, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
    write_json(LOCAL/(name+'.json'), {'returncode': result.returncode, 'command': cmd})
    if result.returncode:
        print((LOCAL/(name+'.log')).read_text()[-12000:], flush=True)
        raise RuntimeError(name+' failed; see '+str(LOCAL/(name+'.log')))
    print(name+': passed', flush=True)


def test_files():
    return sorted(str(p.relative_to(ROOT)) for base in ('scripts', 'tests')
                  for p in (ROOT/base).rglob('*.py')
                  if p.name.startswith('test_') or p.name.endswith('_test.py'))


def test_sources():
    return {str(p.relative_to(ROOT)):digest(p.read_bytes())
            for base in ('scripts','tests') for p in sorted((ROOT/base).rglob('*.py'))
            if p != Path(__file__).resolve()}


def tests(collector_python):
    files = test_files()
    sources = test_sources()
    LOCAL.mkdir(parents=True,exist_ok=True)
    write_json(LOCAL/'tests_attempt_sources.json',sources)
    groups = defaultdict(list)
    for path in files:
        parts = Path(path).parts
        key = 'findings_and_tests' if parts[0]=='tests' or parts[1]=='findings' else parts[1]
        groups[key].append(path)
    counts = []
    failures = []
    for group, paths in sorted(groups.items()):
        name = 'tests_'+group
        try:
            command(name, ['-m','pytest','-q',*paths,'--junitxml='+str(LOCAL/(name+'.xml'))],
                    python=collector_python if group=='collect' else None,
                    isolated=group!='collect')
        except RuntimeError:
            failures.append(group)
        suite = ET.parse(LOCAL/(name+'.xml')).getroot()
        text = (LOCAL/(name+'.log')).read_text()
        def count(pattern):
            hit = re.search(pattern, text)
            return int(hit[1]) if hit else 0
        counts.append(dict(group=group, files=len(paths),
            passed=count(r'(\d+) passed(?:,| in)'),
            subtests_passed=count(r'(\d+) subtests passed'),
            failures=sum(int(s.get('failures',0)) for s in suite.findall('testsuite')),
            errors=sum(int(s.get('errors',0)) for s in suite.findall('testsuite')),
            skipped=sum(int(s.get('skipped',0)) for s in suite.findall('testsuite'))))
    assert files == test_files(), 'Test membership changed during the full suite; rerun'
    after = test_sources()
    changed=[p for p in sorted(set(sources)|set(after)) if sources.get(p)!=after.get(p)]
    write_json(LOCAL/'tests_source_changes.json',changed)
    assert not changed, 'Source code changed during the full suite; rerun: '+repr(changed)
    write_json(LOCAL/'tests.json', dict(ok=not failures, groups=counts, files=files,
        source_sha256=digest(sources),sources=sources,
        totals={key:sum(r[key] for r in counts) for key in
                ('files','passed','subtests_passed','failures','errors','skipped')}))
    if failures:
        raise RuntimeError('Failed test groups: '+', '.join(failures))


def fingerprints():
    base = ROOT/'data/findings'
    firms = sorted({d['row']['firm_id'] for d in read_snapshot()})
    paths = [base/'summary.json', base/'_unknown_layouts.jsonl']
    for firm in firms:
        paths += [base/(firm+'.jsonl'),base/'validation'/(firm+'.jsonl'),
                  base/'validation'/(firm+'.json')]
    paths += sorted((base/'supplemental').glob('*.jsonl'))
    if (base/'validation/recall_push_supplemental.json').exists():
        paths.append(base/'validation/recall_push_supplemental.json')
    return {str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in sorted(paths)}


def source_fingerprints():
    paths = [p for p in (ROOT/'scripts/findings').rglob('*.py') if p != Path(__file__).resolve()]
    paths += list((ROOT/'schema').glob('*map.*'))
    paths += [ROOT/'data/fulltext/input_documents.jsonl', ROOT/'data/fulltext/extractions.jsonl',
              ROOT/'data/holdout/gold_sha256.txt', ROOT/'registry/scope_tier_a.csv']
    return {str(p.relative_to(ROOT)):digest(p.read_bytes()) for p in sorted(paths)}


def regenerate():
    if (LOCAL/'findings_before').exists():
        raise RuntimeError('Existing integration baseline; use replay after reviewing it')
    LOCAL.mkdir(parents=True, exist_ok=True)
    # Only the frozen, non-holdout extraction membership is reconciled.
    command('cache_sync',['scripts/findings/severity_canon.py','sync-cache-receipts'])
    sources = source_fingerprints()
    write_json(LOCAL/'inputs.json',sources)
    (ROOT/'data/findings').rename(LOCAL/'findings_before')
    replay(first=True)


def replay(first=False):
    name = 'regeneration' if first else 'replay'
    assert source_fingerprints()==json.loads((LOCAL/'inputs.json').read_text()), 'Parser inputs changed'
    command(name,['scripts/findings/run.py'])
    # Later occurrences remain separate from the immutable full-text snapshot.
    command(name+'_supplemental',['scripts/findings/recall_push.py','--regenerate'])
    current = fingerprints()
    assert source_fingerprints()==json.loads((LOCAL/'inputs.json').read_text()), 'Parser inputs changed'
    if first:
        write_json(LOCAL/'first_hashes.json',current)
    else:
        prior = json.loads((LOCAL/'first_hashes.json').read_text())
        changed = [p for p in sorted(set(prior)|set(current)) if prior.get(p)!=current.get(p)]
        write_json(LOCAL/'determinism.json',dict(ok=not changed, files=len(current),
            changed=changed, manifest_sha256=digest(current), hashes=current))
        assert not changed, 'Nondeterministic outputs: '+repr(changed)
    print(name+': '+str(len(current))+' output hashes',flush=True)


def resume():
    """Complete an interrupted cold pass, retaining only committed firm streams."""
    from severity_canon import refresh_receipts
    assert not (LOCAL/'first_hashes.json').exists(), 'First pass already complete; use replay'
    assert source_fingerprints()==json.loads((LOCAL/'inputs.json').read_text()), 'Parser inputs changed'
    firms=sorted({d['row']['firm_id'] for d in read_snapshot()})
    remaining=[f for f in firms if not all((ROOT/p).exists() for p in
        ['data/findings/'+f+'.jsonl','data/findings/validation/'+f+'.jsonl','data/findings/validation/'+f+'.json'])]
    if remaining:
        command('regeneration_resume',['scripts/findings/run.py','--firms',*remaining])
    refresh_receipts(ROOT)
    command('regeneration_supplemental',['scripts/findings/recall_push.py','--regenerate'])
    assert source_fingerprints()==json.loads((LOCAL/'inputs.json').read_text()), 'Parser inputs changed'
    write_json(LOCAL/'first_hashes.json',fingerprints())


def checks():
    command('findings_check',['scripts/findings/check.py'])
    command('status_check',['scripts/findings/check.py','--statuses-only'])
    command('recall_check',['scripts/findings/recall_push.py','--verify'])
    command('build_db',['scripts/build/build_db.py','--json'])
    command('check_db',['scripts/build/check_db.py','--json'])
    command('analysis',['scripts/analysis/run.py'])
    command('analysis_check',['scripts/analysis/check.py'])


def census():
    blocked = holdouts()
    result = {}
    seen = set()
    for path, row in finding_rows(ROOT/'data/findings'):
        cohort = 'supplemental' if path.parent.name=='supplemental' else 'snapshot'
        key = path.stem
        counts = result.setdefault(key,dict(rows=0,formal_findings=0,snapshot=0,supplemental=0,
            source_status=0,known_status=0,unmapped_status=0,unmapped_severity=0,
            severities=Counter(),statuses=Counter()))
        assert row['sha256'] not in blocked, 'Holdout row denied'
        assert row['finding_id'] not in seen, 'Duplicate finding identity'
        seen.add(row['finding_id'])
        counts['rows'] += 1
        counts[cohort] += 1
        counts['formal_findings'] += row['record_kind']=='formal_finding'
        counts['source_status'] += bool((row['status_raw'] or '').strip())
        counts['known_status'] += row['status']!='not_stated'
        counts['unmapped_status'] += not row['status_mapping']['mapped']
        counts['unmapped_severity'] += not row['severity_mapping']['mapped']
        assert row['severity'] in SEVERITIES and row['status'] in STATUSES
        if cohort=='supplemental':
            text=(ROOT/'local-cache/fulltext'/(row['sha256']+'.txt')).read_bytes().decode('utf-8')
            assert digest(text.encode())==row['body_span']['text_sha256']
            expected=status_mapping(row['status_raw'],key,sha256=row['sha256'],report_text=text,log=False)
            assert expected==row['status_mapping']==row['evidence']['status_mapping']
            assert row['status']==expected['normalized']
            proof=row['evidence'].get('status_evidence')
            if proof:
                assert text[proof['start']:proof['end']]==proof['text']==proof['raw']==row['status_raw']
        counts['severities'][row['severity']] += 1
        counts['statuses'][row['status']] += 1
    totals = {key:sum(r[key] for r in result.values()) for key in
              ('rows','formal_findings','snapshot','supplemental','source_status','known_status',
               'unmapped_status','unmapped_severity')}
    totals['severities'] = dict(sum((Counter(r['severities']) for r in result.values()),Counter()))
    totals['statuses'] = dict(sum((Counter(r['statuses']) for r in result.values()),Counter()))
    return dict(by_publisher=result,totals=totals,holdout_hashes=len(blocked),
        holdout_list_sha256=digest((ROOT/'data/holdout/gold_sha256.txt').read_bytes()))


def report():
    measured = census()
    tested = json.loads((LOCAL/'tests.json').read_text())
    replayed = json.loads((LOCAL/'determinism.json').read_text())
    checked = json.loads((ROOT/'data/findings/check.json').read_text())
    statuses = json.loads((ROOT/'data/findings/status_check.json').read_text())
    assert tested['ok'] and replayed['ok'] and checked['ok'] and statuses['ok']
    assert not checked['validation_states'].get('parser_error',0), 'Unresolved parser failures'
    assert tested['sources']==test_sources(), 'Source code changed since the full suite; rerun tests'
    assert measured['totals']['snapshot']==checked['findings']==statuses['rows']
    assert fingerprints()==replayed['hashes'], 'Findings changed after replay'
    assert source_fingerprints()==json.loads((LOCAL/'inputs.json').read_text()), 'Parser inputs changed after replay'
    names=('findings_check','status_check','recall_check','build_db','check_db','analysis','analysis_check')
    for name in names:
        assert json.loads((LOCAL/(name+'.json')).read_text())['returncode']==0, name
    database=json.loads((LOCAL/'check_db.log').read_text())
    analysis=json.loads((LOCAL/'analysis_check.log').read_text())
    measured.update(tests=tested,determinism=replayed,checker=checked,status_checker=statuses,
                    database=database,analysis=analysis)
    write_json(LOCAL/'census.json',measured)
    total=measured['totals']; t=tested['totals']
    lines=['# Findings integration','',
        'Generated by `scripts/findings/integration.py report`. Local-only integration gate; no model or network calls.','',
        '## Gate results','',
        f"Full suite: **{t['passed']:,} tests passed**, **{t['subtests_passed']:,} subtests passed**, {t['failures']} failures, {t['errors']} errors, {t['skipped']} skips across {t['files']} test files. Every test under `scripts/` and `tests/` is discovered; standalone tool groups run in fresh interpreters to prevent `common`/`run` import collisions.",'',
        '| Suite | Files | Tests passed | Subtests passed |','|---|---:|---:|---:|']
    lines += [f"| {r['group']} | {r['files']} | {r['passed']} | {r['subtests_passed']} |" for r in tested['groups']]
    lines += ['',f"Full findings checker: **pass**; {checked['documents']:,} document occurrences, {checked['artifacts']:,} original hashes, {checked['findings']:,} staged snapshot rows; {checked['summary_matching']:,}/{checked['summary_comparable']:,} comparable summaries match ({checked['summary_agreement_percent']}%). Summary mismatches remain source/parser review diagnostics, not manufactured agreement.",'',
        'Extraction occurrence states: `'+json.dumps(checked['documents_fulltext'],sort_keys=True)+'`. Parser validation states: `'+json.dumps(checked['validation_states'],sort_keys=True)+'`. Source extraction failures remain explicit diagnostics; they are not silently dropped or counted as clean reports.','',
        f"The checker reports {len(checked['collection_files_changed_since_snapshot'])} collector files changed since the frozen inventory and {len(checked['collection_files_new_since_snapshot'])} new collector files. Phase 4 retains its original source-row receipts and membership; the recall push's later occurrences remain supplemental. Unknown-layout queue: {checked['unknown_layout_artifacts']} artifacts / {checked['unknown_layout_occurrences']} occurrences.",'',
        f"Status checker: **pass**; {statuses['rows']:,} snapshot rows and {statuses['source_spans_verified']:,} source status spans verified. Supplemental recall checker: **pass**. Database rebuild and `check_db.py`: **pass**. Analysis regeneration and `scripts/analysis/check.py`: **pass**. Exact command lines and complete logs are retained in `local-cache/findings-integration/`.",'',
        f"Database checker totals: {database['publishers']} publishers, {database['documents']:,} documents, {database['engagements']:,} engagements, {database['counted_engagements']:,} counted engagements, {database['findings']:,} imported findings and {database['contests']:,} contests. The database finding count covers firm exports and audit-analysis seeds; Phase 4 streams enter the analysis through staged files.",'',
        f"Analysis reconciliation: {analysis['industry_engagements']:,} industry engagements, {analysis['publisher_engagements']:,} publisher engagements, {analysis['formal_findings']:,} selected formal findings, {analysis['csv_tables']} CSV tables and {analysis['svg_png_pairs']} SVG/PNG pairs. Incident manual-review completeness: `{analysis['manual_review_complete']}`; the default analysis checker was used, without asserting a newly completed manual incident review.",'',
        f"Deterministic replay: **pass**; {replayed['files']} canonical findings/diagnostic/supplemental files have identical SHA-256 hashes across both passes. Manifest digest: `{replayed['manifest_sha256']}`. Parser invocations use new empty bytecode caches and new processes; the cold pass starts from an empty findings tree. The first pass resumed committed publisher streams after a Python process exited with SIGSEGV during a periodic stack dump; Certora alone and the full replay passed. Monitoring now records fatal errors only. Old findings are preserved at `local-cache/findings-integration/findings_before/`. Full-text/OCR evidence is retained, hash-verified, and extraction receipts reconciled before parsing; PDF/OCR extraction is not repeated.",'',
        f"Holdout list unchanged: {measured['holdout_hashes']} blocked hashes; `{measured['holdout_list_sha256']}`. Findings regeneration, corpus diagnostics and parser checks reject holdout hashes before original/text access; no held-out findings are parsed, inspected or used for tuning. The requested database build retains Phase 3's existing uniform metadata extraction policy, including held-out metadata; it does not run finding parsers on them. Frozen Phase 4 input membership is unchanged; supplemental occurrences remain a separate cohort.",'',
        '## Root causes and fixes','',
        '- Veridise’s status reader cleared an unambiguous native-ID overview status. Preserve the exact overview status span when card metadata is absent; explicit card fields retain precedence.',
        '- Oxorio’s card parser accepted spaced severity labels but its fingerprint did not. Apply the same publisher vocabulary, including letter spacing, during layout selection.',
        '- Layout selection used a backtracking table-of-contents suffix regex on long PDF padding. Replace it with a linear scan preserving the same exclusion rule; retain padded-prose and TOC regressions.',
        '- The iosiro classless HTML variant lacked its declared executable fixture and era. Supply both. Update the old unique-parser-function expectation to require the exact intentional shared-grammar pair; every other variant still has a distinct parser and all fixtures execute.',
        '- Database fixture expectations predated the status crosswalk: Movebit Confirmed is now acknowledged (acceptance, no repair assertion), and Neodyme Resolved is fixed under its publisher policy. Retain raw labels and all rights/missing-field assertions.',
        '- Analysis counted canonical not_stated as known remediation and omitted partially_fixed/unresolved counters. Exclude not_stated from coverage/rate denominators, expose the canonical counters, and verify their reconciliation.',
        '- Analysis read only top-level findings, omitting later collected occurrences staged by the recall push. Include supplemental streams with the same identity, publisher, phase and source-receipt checks; missing summaries still cannot prove zero findings.',
        '- Run all standalone tool suites separately to prevent module-name collisions; disable unrelated auto-loaded user pytest plugins. Collector tests use local Python/PyYAML, while corpus tests/build/analysis use the existing pinned Phase 3 environment. No dependency installation is required.','',
        '## Publisher totals and status coverage','',
        f"All emitted record kinds: **{total['rows']:,} rows** = {total['snapshot']:,} frozen-snapshot + {total['supplemental']:,} supplemental; **{total['formal_findings']:,} formal findings**. Occurrences are retained, so these are not unique-vulnerability totals. Status coverage = canonical status other than not_stated / all emitted rows. Source-label coverage also includes labels whose meaning remains unresolved. Unmapped labels are retained, never silently converted to fixes.",'',
        '| Publisher | Snapshot rows | Supplemental rows | All rows | Formal findings | Source status labels | Known status | Status coverage | Unmapped status |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for firm,r in sorted(measured['by_publisher'].items()):
        coverage=f"{100*r['known_status']/r['rows']:.2f}%" if r['rows'] else 'n/a'
        lines.append(f"| {firm} | {r['snapshot']} | {r['supplemental']} | {r['rows']} | {r['formal_findings']} | {r['source_status']} | {r['known_status']} | {coverage} | {r['unmapped_status']} |")
    lines += ['',f"Total known status: {total['known_status']:,}/{total['rows']:,} ({100*total['known_status']/total['rows']:.2f}%); source status labels: {total['source_status']:,}. Unmapped status rows: {total['unmapped_status']:,}; unmapped severity rows: {total['unmapped_severity']:,}.",'',
        '## Severity distribution','', '| Severity | Rows | Share |','|---|---:|---:|']
    for severity in SEVERITIES:
        n=total['severities'].get(severity,0)
        lines.append(f"| {severity} | {n:,} | {100*n/total['rows']:.2f}% |")
    lines += ['', '## Reproduce','', '```sh',
        'python3 -I scripts/findings/integration.py tests',
        '# First run only: archives existing findings and reconciles full-text receipts.',
        'python3 -I scripts/findings/integration.py regenerate',
        '# If a pass is interrupted with unchanged inputs: integration.py resume',
        'python3 -I scripts/findings/integration.py replay',
        'python3 -I scripts/findings/integration.py checks',
        'python3 -I scripts/findings/integration.py report',
        '```','',
        'Per-file hashes, complete test membership, commands, logs and machine-readable census: `local-cache/findings-integration/`. Generated analysis ownership is enumerated in `docs/analysis/files_written.txt`. Integration-owned files are listed in `docs/phase4/integration_files_written.txt`. No commits or pushes.','']
    path=ROOT/'docs/phase4/integration.md'
    path.write_text('\n'.join(lines))
    manifest()
    print(json.dumps(dict(tests=t,findings=total['rows'],severity=total['severities'],deterministic_files=replayed['files']),indent=2))


def manifest():
    sources = '''scripts/analysis/check.py scripts/analysis/model.py scripts/analysis/run.py scripts/analysis/test_analysis.py
scripts/findings/fixtures_group2_variants.py scripts/findings/integration.py
scripts/findings/core.py scripts/findings/prior_findings.py scripts/findings/text_patterns.py
scripts/findings/parsers/abdk_consulting.py scripts/findings/parsers/iosiro.py scripts/findings/parsers/oxorio.py scripts/findings/parsers/veridise.py
scripts/findings/test_group3.py scripts/findings/test_variants.py scripts/findings/test_variants_group2.py
scripts/findings/variants.py tests/test_build.py
docs/phase4/integration.md docs/phase4/integration_files_written.txt
data/fulltext/extractions.jsonl data/fulltext/failures.jsonl data/fulltext/summary.json data/corpus.duckdb
data/phase3/artifact_metadata.jsonl data/phase3/relationship_checks.jsonl data/phase3/identity_map.json
data/phase3/identity_scope_merge_edges.jsonl data/phase3/identity_scope_rejected_edges.jsonl'''.split()
    paths = {ROOT/p for p in sources if (ROOT/p).exists() or p.endswith('integration_files_written.txt')}
    paths.update(p for p in (ROOT/'data/findings').rglob('*') if p.is_file())
    paths.update(p for p in LOCAL.rglob('*') if p.is_file()
                 and not any(part.startswith('bytecode-') or part.startswith('findings_') for part in p.relative_to(LOCAL).parts[:-1]))
    analysis = ROOT/'docs/analysis/files_written.txt'
    paths.update(ROOT/p for p in analysis.read_text().splitlines()
                 if p.startswith(('data/analysis/','docs/analysis/')))
    # Runtime bytecode and preserved, unchanged archives are not release outputs.
    (ROOT/'docs/phase4/integration_files_written.txt').write_text(
        '\n'.join(sorted(str(p.relative_to(ROOT)) for p in paths))+'\n')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=('tests','regenerate','resume','replay','checks','report'))
    p.add_argument('--collector-python',default=shutil.which('python3'))
    a=p.parse_args()
    if a.command=='tests': tests(a.collector_python)
    elif a.command=='regenerate': regenerate()
    elif a.command=='resume': resume()
    elif a.command=='replay': replay()
    elif a.command=='checks': checks()
    else: report()


if __name__=='__main__': main()
