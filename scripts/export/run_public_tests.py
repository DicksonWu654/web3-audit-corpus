#!/usr/bin/env python3
"""Run offline tests in separate processes to isolate standalone module names."""
from pathlib import Path
import argparse
import json
import os
import re
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[2]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--report',type=Path)
    args=parser.parse_args()
    root=args.root.resolve()
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
    files=sorted((root/'tests').glob('test_*.py'))
    for folder in ('collect','build','phase3','findings','classify','analysis','release'):
        files+=sorted((root/'scripts'/folder).rglob('test_*.py'))
        files+=sorted((root/'scripts'/folder).rglob('*_test.py'))
    files=sorted(set(files))
    failures=[]
    results=[]
    ran=0
    for path in files:
        if path.name == 'test_group2.py':
            print('LOCAL-INPUT CHECK scripts/findings/test_group2.py: diagnostics command; run with --tests after reconstructing local corpus inputs',flush=True)
            continue
        ran+=1
        rel=path.relative_to(root)
        proc=subprocess.run([sys.executable,'-I','-B','-B','-m','pytest','-q','-p','no:cacheprovider',str(path)],cwd=root,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        summary=proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ''
        results.append(dict(path=str(rel),exit_code=proc.returncode,summary=summary))
        if proc.returncode:
            failures.append(str(rel));print(f'FAIL {rel}\n{proc.stdout}',flush=True)
        else:
            print(f'PASS {rel}: {proc.stdout.strip().splitlines()[-1]}',flush=True)
    print(f'{ran} test modules; {len(failures)} failed',flush=True)
    if args.report:
        counts={key:sum(int(m[1]) for r in results for m in [re.search(r'(\d+) '+key,r['summary'])] if m)
                for key in ('passed','skipped','failed')}
        args.report.write_text(json.dumps(dict(modules=ran,failures=failures,counts=counts,results=results),indent=2)+'\n')
    return bool(failures)
if __name__=='__main__':raise SystemExit(main())
