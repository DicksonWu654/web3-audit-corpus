"""Build and validate the integrated Phase 3f checkpoint and a frozen replay."""
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
sys.path.insert(0,str(ROOT/'scripts/build'))
from validate_identity_scope import fingerprint
from date_evidence_dates import capture, report


def new_date_evidence(root,before):
    """Every newly dated stable engagement needs source-text/page evidence."""
    after=capture(root)
    old={r['engagement_id']:r for r in before['engagements']}
    recovered={r['engagement_id'] for r in after['engagements'] if r['identity_status']=='confirmed' and r['audit_year'] is not None and r['engagement_id'] in old and old[r['engagement_id']]['audit_year'] is None}
    years={r['engagement_id']:r['audit_year'] for r in after['engagements']}
    verified=set();errors=[];texts={}
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        for eid,basis,role,raw,digest in con.execute("SELECT ed.engagement_id,dc.basis,dc.role,dc.evidence,d.sha256 FROM date_claims dc JOIN engagement_documents ed USING(document_id) JOIN documents d USING(document_id) WHERE eligible_for_audit_year").fetchall():
            if eid not in recovered:continue
            c=json.loads(raw).get('assertion') or {}
            path=c.get('text_snapshot')
            if not path:continue
            if path not in texts:texts[path]=(root/path).read_text()
            text=texts[path];start,end=c.get('text_start'),c.get('text_end')
            valid=(basis=='document_text' and isinstance(start,int) and isinstance(end,int)
                   and str(c.get('date_value','')).startswith(str(years[eid]))
                   and c.get('page')==text[:start].count('\f')+1
                   and text[start:end]==c.get('evidence')
                   and hashlib.sha256(text.encode()).hexdigest()==c.get('text_sha256')
                   and c.get('raw_value') in text[start:end])
            if valid:verified.add(eid)
    errors=sorted(recovered-verified)
    return dict(exit_code=int(bool(errors)),recovered=len(recovered),source_text_and_page_verified=len(verified),errors=errors)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--checks-only',action='store_true')
    p.add_argument('--skip-replay',action='store_true')
    args=p.parse_args();folder=ROOT/'local-cache/phase3f'
    before=capture(ROOT,folder/'before.duckdb')
    before['holdout_sha256']=json.loads((folder/'before.json').read_text())['holdout_sha256']
    receipt=folder/'validation.json';results={}
    if args.checks_only and receipt.exists():results=json.loads(receipt.read_text())
    def save():receipt.write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
    env=os.environ.copy();env['PYTEST_DISABLE_PLUGIN_AUTOLOAD']='1'
    def run(name,arguments):
        command=[sys.executable,'-I','-B',*map(str,arguments)]
        log=folder/(name+'.log');print('Running '+name,flush=True)
        with log.open('w') as out:proc=subprocess.run(command,cwd=ROOT,env=env,stdout=out,stderr=subprocess.STDOUT)
        results[name]=dict(exit_code=proc.returncode,command=command,log=str(log.relative_to(ROOT)),tail=log.read_text()[-4500:]);save()
        print(f'{name}: exit {proc.returncode}',flush=True)
        return proc.returncode==0
    replay=None
    if not args.checks_only:
        n=1
        while (folder/f'replay-{n:02}').exists():n+=1
        replay=folder/f'replay-{n:02}'
        if not run('build',['scripts/build/build_db.py','--snapshot-inputs',replay]):return 1
    for name,arguments in [
        ('database_integrity',['scripts/build/check_db.py','--as-of','2026-10-21']),
        ('source_dates',['scripts/phase3/check_dates.py','--require-coverage']),
        ('regression_tests',['-m','pytest','-q','--tb=short','tests/test_build.py','tests/test_phase3.py','tests/test_dates.py','tests/test_phase3c.py','tests/test_phase3d.py','tests/test_phase3e.py','scripts/phase3/test_date_evidence_dates.py'])]:
        if not run(name,arguments):return 1
    results['new_date_evidence']=new_date_evidence(ROOT,before);save()
    if results['new_date_evidence']['exit_code']:return 1
    after=capture(ROOT)
    results['source_and_holdout_integrity']=dict(exit_code=int(before['input_ledger']!=after['input_ledger'] or before['holdout_sha256']!=after['holdout_sha256']))
    save()
    if results['source_and_holdout_integrity']['exit_code']:return 1
    if replay and not args.skip_replay:
        original=fingerprint(ROOT/'data/corpus.duckdb')
        for relative in ['data/phase3/identity_map.json','data/phase3/artifact_metadata.jsonl','data/phase3/llm_dates.jsonl','data/holdout/gold_sha256.txt']:
            source=ROOT/relative
            if source.exists():
                target=replay/relative;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
        for name in ['originals','phase3d']:
            (replay/'local-cache'/name).symlink_to(ROOT/'local-cache'/name,target_is_directory=True)
        if not run('repeat_build',['scripts/build/build_db.py','--root',replay]):return 1
        repeated=fingerprint(replay/'data/corpus.duckdb')
        changed=sorted(t for t in original if original[t]!=repeated[t])
        results['idempotence']=dict(exit_code=int(bool(changed)),changed_tables=changed,before=original,after=repeated);save()
        if changed:return 1
    if not run('phase3_exports',['scripts/phase3/report.py','--data-only']):return 1
    from metadata_rules import atomic,canonical
    report(ROOT)
    sources=['scripts/build/date_layout_rules.py','scripts/build/date_rules.py','scripts/build/metadata_rules.py','scripts/build/period_rules.py','scripts/build/phase3_engagements.py','scripts/phase3/check_dates.py','scripts/phase3/dates.py','scripts/phase3/date_evidence_dates.py','scripts/phase3/date_evidence_html_dates.py','scripts/phase3/test_date_evidence_dates.py','scripts/phase3/validate_date_evidence.py','scripts/phase3/report.py','docs/phase3/dates_date_evidence.md','data/corpus.duckdb','data/phase3/artifact_metadata.jsonl','data/phase3/identity_map.json','data/phase3/date_check.json',*['data/phase3/'+n for n in ['summary.json','engagements.jsonl','engagement_documents.jsonl','document_exclusions.jsonl','date_claims.jsonl']]]
    sources+=['scripts/phase3/date_evidence_visual.py']
    sources += [str(p.relative_to(ROOT)) for p in folder.rglob('*') if p.is_file()]
    started=(folder/'before.json').stat().st_mtime
    sources += [str(p.relative_to(ROOT)) for p in (ROOT/'local-cache/phase3d/text').glob('*.txt') if p.stat().st_mtime>=started]
    sources += [str(p.relative_to(ROOT)) for p in (ROOT/'local-cache/date-text').glob('*') if p.is_file() and p.stat().st_mtime>=started]
    atomic(folder/'files_written.json',canonical(sorted(set(sources)|{'local-cache/phase3f/files_written.json'}))+'\n')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
