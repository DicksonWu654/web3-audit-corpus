"""Run the Phase 3e build/check/tests, deterministic replay and Phase 5 refresh."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import duckdb

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/phase3'))


def fingerprint(db):
    keys={'documents':'document_id','engagements':'engagement_id','engagement_documents':'engagement_id,document_id',
          'document_exclusions':'document_id','engagement_identity_crosswalk':'previous_engagement_id',
          'date_claims':'claim_id','contests':'contest_id','findings':'finding_id','import_sources':'source_file'}
    result={}
    with duckdb.connect(str(db),read_only=True) as con:
        for table,key in keys.items():
            digest=hashlib.sha256(); count=0
            cur=con.execute(f'SELECT * FROM {table} ORDER BY {key}')
            while rows:=cur.fetchmany(1000):
                for row in rows:
                    digest.update((json.dumps(row,sort_keys=True,separators=(',',':'),default=str)+'\n').encode())
                    count+=1
            result[table]=dict(rows=count,sha256=digest.hexdigest())
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',action='store_true')
    p.add_argument('--repeat',action='store_true',help='Requires --build; replay the captured inputs and compare logical tables')
    p.add_argument('--require-date-coverage',action='store_true',help='Also enforce the separate date-recovery coverage target')
    p.add_argument('--finalize',action='store_true',help='Verify successful existing receipts and unchanged logical tables, then refresh the report')
    args=p.parse_args()
    if args.repeat and not args.build:
        p.error('--repeat requires --build')
    folder=ROOT/'local-cache/phase3e/validation'; folder.mkdir(parents=True,exist_ok=True)
    receipt=ROOT/'data/phase3/fixes_identity_scope_validation.json'
    results={}
    if args.finalize:
        if args.build or args.repeat or args.require_date_coverage:
            p.error('--finalize cannot be combined with validation/build flags')
        prior=json.loads(receipt.read_text())
        assert prior and all(v['exit_code']==0 for v in prior.values()),'Existing validation steps did not all pass'
        assert prior['idempotence']['before']==fingerprint(ROOT/'data/corpus.duckdb'),'Database changed after validation'
        from identity_scope_report import write_report
        write_report()
        return 0
    env=os.environ.copy();env['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'
    def save():
        receipt.write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
    def run(name,arguments):
        cmd=[sys.executable,'-I','-B',*arguments]
        log=folder/(name+'.log')
        print('Running '+name,flush=True)
        with log.open('w') as output:
            proc=subprocess.run(cmd,cwd=ROOT,env=env,stdout=output,stderr=subprocess.STDOUT)
        results[name]=dict(exit_code=proc.returncode,command=cmd,log=str(log.relative_to(ROOT)),tail=log.read_text()[-6000:])
        save();print(f'{name}: exit {proc.returncode}',flush=True)
        return proc.returncode==0
    replay=None
    if args.build:
        cmd=['scripts/build/build_db.py']
        if args.repeat:
            serial=1
            while (folder.parent/f'replay-final-{serial:02}').exists():
                serial+=1
            replay=folder.parent/f'replay-final-{serial:02}'
            cmd+=['--snapshot-inputs',str(replay)]
        if not run('build',cmd):
            return 1
    ok=True
    for name,cmd in [
        ('database_integrity',['scripts/build/check_db.py','--as-of','2026-10-21']),
        ('source_dates',['scripts/phase3/check_dates.py']+(['--require-coverage'] if args.require_date_coverage else [])),
        ('phase3_exports',['scripts/phase3/report.py']),
        ('regression_tests',['-m','pytest','-q','--tb=short','tests/test_build.py','tests/test_phase3.py','tests/test_dates.py','tests/test_phase3c.py','tests/test_phase3d.py','tests/test_phase3e.py','scripts/analysis/test_analysis.py'])]:
        ok=run(name,cmd) and ok
    if replay:
        before=fingerprint(ROOT/'data/corpus.duckdb')
        for relative in ['data/phase3/identity_map.json','data/phase3/artifact_metadata.jsonl','data/phase3/llm_dates.jsonl','data/holdout/gold_sha256.txt']:
            source=ROOT/relative
            if source.exists():
                dest=replay/relative;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
        store=replay/'local-cache';store.mkdir(parents=True,exist_ok=True)
        for name in ['originals','phase3d']:
            (store/name).symlink_to(ROOT/'local-cache'/name,target_is_directory=True)
        if not run('repeat_build',['scripts/build/build_db.py','--root',str(replay)]):
            return 1
        after=fingerprint(replay/'data/corpus.duckdb')
        changed=sorted(k for k in before if before[k]!=after[k])
        results['idempotence']=dict(exit_code=int(bool(changed)),changed_tables=changed,before=before,after=after)
        save();ok=not changed and ok
        print('Idempotence: '+('FAIL '+str(changed) if changed else 'PASS'),flush=True)
    ok=run('analysis_regenerate',['scripts/analysis/run.py','--as-of','2026-10-20']) and ok
    ok=run('analysis_integrity',['scripts/analysis/check.py']) and ok
    if not run('comparison',['scripts/phase3/identity_scope_report.py']):
        return 1
    result=json.loads((ROOT/'data/phase3/fixes_identity_scope.json').read_text())
    passed=(result['import_ledger_unchanged']
            and all(r['resolved'] for r in result['v5_split_regressions'])
            and all(r['split'] for r in result['v5_merge_regressions'] if r['verdict']=='false_merge')
            and not any(r['retained'] for r in result['v5_cadence_regressions'] if r['project_collision']))
    results['v5_regressions']=dict(exit_code=int(not passed))
    save();ok=passed and ok
    # Include this comparison's receipt and regression verdict in the document.
    from identity_scope_report import write_report
    write_report()
    return 0 if ok else 1


if __name__=='__main__':
    raise SystemExit(main())
