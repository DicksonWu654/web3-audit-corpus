"""Validate the Phase 3e checkpoint without consuming concurrent status edits.

The base is the repository revision at task intake. Only the explicit identity
changes and the pre-existing analysis projection are overlaid. No worktree files
are reverted, and no network/dependency installation is performed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/phase3'))
from validate_identity_scope import fingerprint

BASE='404586e7b9fa9ea7609b27a879c5c62dd3300c1b'
OWN=['scripts/build/phase3_engagements.py','scripts/phase3/identity_rules.py',
     'scripts/phase3/report.py','scripts/phase3/identity_scope_diagnose.py','scripts/phase3/identity_scope_report.py',
     'scripts/phase3/validate_identity_scope.py','scripts/phase3/validate_identity_scope_frozen.py','tests/test_phase3e.py']


def digest(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f,'sha256').hexdigest()


def source_snapshot(folder,replay):
    code=folder/'code'
    manifest=folder/'source_manifest.json'
    if manifest.exists():
        result=json.loads(manifest.read_text())
        assert all(digest(code/p)==h for p,h in result['files'].items()),'Frozen code changed'
        relative='registry/scope_tier_a.csv'
        if not (code/relative).exists():
            (code/relative).parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(replay/relative,code/relative)
            result['files'][relative]=digest(code/relative)
            result['captured_test_inputs']=[relative]
            manifest.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        return code,result
    command=['git','ls-tree','-r','--name-only',BASE,'--','scripts/build','scripts/phase3',
             'scripts/analysis','scripts/findings/core.py','scripts/findings/severity_resolve.py','schema','tests']
    paths=subprocess.run(command,cwd=ROOT,check=True,capture_output=True,text=True).stdout.splitlines()
    for relative in paths:
        target=code/relative;target.parent.mkdir(parents=True,exist_ok=True)
        body=subprocess.run(['git','show',BASE+':'+relative],cwd=ROOT,check=True,capture_output=True).stdout
        target.write_bytes(body)
    overlay=OWN+[str(p.relative_to(ROOT)) for p in (ROOT/'scripts/analysis').iterdir() if p.is_file()]
    for relative in overlay:
        target=code/relative;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/relative,target)
    relative='registry/scope_tier_a.csv'
    (code/relative).parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(replay/relative,code/relative)
    result=dict(base_revision=BASE,overlay=sorted(overlay),files={str(p.relative_to(code)):digest(p) for p in sorted(code.rglob('*')) if p.is_file()})
    manifest.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    return code,result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resume',action='store_true',help='Reuse a successful replay only after both database fingerprints are rechecked')
    args=parser.parse_args()
    folder=ROOT/'local-cache/phase3e/frozen-validation';folder.mkdir(parents=True,exist_ok=True)
    receipt=ROOT/'data/phase3/fixes_identity_scope_validation.json'
    prior=json.loads(receipt.read_text())
    assert prior['build']['exit_code']==0,'No successful Phase 3e build checkpoint'
    replay=Path(prior['repeat_build']['command'][-1])
    # Preserve this successful identity checkpoint before another task rebuilds
    # the shared database with a different finding-status schema.
    sealed=ROOT/'local-cache/phase3e/after_identity.duckdb'
    if not sealed.exists():
        shutil.copyfile(ROOT/'data/corpus.duckdb',sealed)
    code,source=source_snapshot(folder,replay)
    results={k:v for k,v in prior.items() if k=='build'}
    results['source_snapshot']=dict(exit_code=0,base_revision=BASE,
        source_manifest=str((folder/'source_manifest.json').relative_to(ROOT)),
        source_manifest_sha256=digest(folder/'source_manifest.json'),
        validator_sha256=digest(Path(__file__)),
        after_database=str(sealed.relative_to(ROOT)),after_database_sha256=digest(sealed),
        reason='Concurrent unrelated status-normalization code/schema edits during the first replay; preserve them and validate the intake dependency versions.')
    env=os.environ.copy();env['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'
    def save():
        receipt.write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
    def run(name,args):
        command=[sys.executable,'-I','-B',*map(str,args)]
        log=folder/(name+'.log')
        print('Running '+name,flush=True)
        with log.open('w') as f:
            proc=subprocess.run(command,cwd=ROOT,env=env,stdout=f,stderr=subprocess.STDOUT)
        results[name]=dict(exit_code=proc.returncode,command=command,log=str(log.relative_to(ROOT)),tail=log.read_text()[-6000:])
        save();print(f'{name}: exit {proc.returncode}',flush=True)
        return proc.returncode==0
    save()
    if args.resume:
        assert prior['repeat_build']['exit_code']==prior['idempotence']['exit_code']==0,'A successful replay is required'
        before,after=fingerprint(sealed),fingerprint(replay/'data/corpus.duckdb')
        assert before==prior['idempotence']['before'] and after==prior['idempotence']['after'],'Validated database changed'
        results['repeat_build']=prior['repeat_build']
    else:
        if not run('repeat_build',[code/'scripts/build/build_db.py','--root',replay]):
            return 1
        before,after=fingerprint(sealed),fingerprint(replay/'data/corpus.duckdb')
    changed=sorted(k for k in before if before[k]!=after[k])
    results['idempotence']=dict(exit_code=int(bool(changed)),changed_tables=changed,before=before,after=after)
    save()
    if changed:
        print('Changed logical tables: '+', '.join(changed),flush=True)
        return 1
    steps=[
        ('database_integrity',[code/'scripts/build/check_db.py','--root',ROOT,'--db',sealed,'--as-of','2026-10-21']),
        ('source_dates',[code/'scripts/phase3/check_dates.py','--root',replay]),
        ('phase3_exports',[code/'scripts/phase3/report.py','--root',ROOT,'--db',sealed]),
        ('regression_tests',['-m','pytest','-q','--tb=short',*[code/p for p in ['tests/test_build.py','tests/test_phase3.py','tests/test_dates.py','tests/test_phase3c.py','tests/test_phase3d.py','tests/test_phase3e.py','scripts/analysis/test_analysis.py']]]),
        ('analysis_regenerate',[code/'scripts/analysis/run.py','--root',ROOT,'--db',sealed,'--as-of','2026-10-20']),
        ('analysis_integrity',[code/'scripts/analysis/check.py','--root',ROOT])]
    for name,args in steps:
        if not run(name,args):
            return 1
        if name=='source_dates':
            shutil.copyfile(replay/'data/phase3/date_check.json',ROOT/'data/phase3/date_check.json')
    if not run('comparison',[ROOT/'scripts/phase3/identity_scope_report.py']):
        return 1
    data=json.loads((ROOT/'data/phase3/fixes_identity_scope.json').read_text())
    passed=(data['import_ledger_unchanged'] and all(r['resolved'] for r in data['v5_split_regressions'])
            and all(r['split'] for r in data['v5_merge_regressions'] if r['verdict']=='false_merge')
            and not any(r['retained'] for r in data['v5_cadence_regressions'] if r['project_collision']))
    results['v5_regressions']=dict(exit_code=int(not passed));save()
    from identity_scope_report import write_report
    write_report()
    return int(not passed)


if __name__=='__main__':
    raise SystemExit(main())
