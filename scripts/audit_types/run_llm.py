#!/usr/bin/env python3
"""Launch frozen batches through the default model CLI-lb provider; fail closed.

The first uncached batch runs alone to exercise the normal usage guard before
opening a pool of at most three calls. No reset, alternate executable/provider,
model fallback or automatic retry is available. Resume skips verified caches.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import threading
import tomllib

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_types.common import file_sha
from audit_types.llm import (EFFORT, MODEL, PROVIDER, Merger, config, load_manifest,
                             parse_answers, promote, receipt_path, status, under, work, write_json)


def host_command(root):
    return ('cd ' + shlex.quote(str(root)) + ' && N=3 PYTHON=' +
            shlex.quote(str(root/'python3 -I')) +
            ' bash scripts/audit_types/run_batches.sh')


def guard_failure(log, prompt):
    # Remove the verbatim input echo, then inspect launcher errors/tracebacks.
    # A nonzero launch always stops even if its guard wording is unrecognized.
    diagnostics = log.replace(prompt.strip(), '')
    lines = [line for line in diagnostics.splitlines() if re.search(
        r'ERROR|PermissionError|Permission denied|Operation not permitted|co[d]ex:|Traceback|FileNotFoundError', line)]
    return bool(re.search(r'usage.?limit|quota|usage[-_ ]?reset|reset[-_ ]?(guard|credit|mechanism)|'
                          r'guard|unknown.*reset|credits?.*(exhausted|depleted)', '\n'.join(lines), re.I))


def verify_provider():
    raise RuntimeError("Supply model responses separately; public tools validate audit-type evidence.")


def runtime_headers(log):
    return {key: value.strip() for key, value in re.findall(
        r'(?m)^(model|provider|reasoning effort):\s*([^\n]+)', log)}


def record_launch_files(root, paths):
    target = root/'data/audit_types/llm_files_written.txt'
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.with_suffix('.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        names = set(target.read_text().splitlines()) if target.exists() else set()
        names.add(str(target.relative_to(root)))
        names.add(str(target.with_suffix('.lock').relative_to(root)))
        names.update(str(path.relative_to(root)) for path in paths if path.exists())
        target.write_text('\n'.join(sorted(names))+'\n')


def run_one(root, batch, stop, manifest):
    raise RuntimeError("Supply model responses separately; public tools validate audit-type evidence.")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    p.add_argument('--workers', type=int, default=3)
    p.add_argument('--status', action='store_true')
    args = p.parse_args(); root = args.root.resolve()
    if not 1 <= args.workers <= 3:
        p.error('workers must be between 1 and 3')
    if os.getpriority(os.PRIO_PROCESS, 0) < 19:
        os.nice(19 - os.getpriority(os.PRIO_PROCESS, 0))
    if args.status:
        result = status(root); write_json(root/'data/audit_types/llm_status.json', result)
        print(json.dumps(result, sort_keys=True)); return
    verify_provider()
    base = work(root); base.mkdir(parents=True, exist_ok=True)
    with (base/'.run.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('Another audit-type runner holds the coordinator lock')
        manifest = load_manifest(root); merger = Merger(root, manifest=manifest)
        pending = [batch for batch in manifest['batches'] if not all(merger.cached(i['payload']) for i in batch['items'])]
        stop = threading.Event()
        if pending and not run_one(root, pending.pop(0), stop, manifest):
            raise SystemExit(1)
        # At most workers in flight; a failure stops scheduling immediately.
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = set()
            while pending or futures:
                while pending and len(futures) < args.workers and not stop.is_set():
                    futures.add(pool.submit(run_one, root, pending.pop(0), stop, manifest))
                if not futures:
                    break
                finished, futures = wait(futures, return_when=FIRST_COMPLETED)
                for future in finished:
                    try:
                        if not future.result():
                            stop.set()
                    except Exception as exc:
                        stop.set(); print(str(exc), file=sys.stderr)
            if stop.is_set():
                raise SystemExit(1)
        result = status(root); write_json(root/'data/audit_types/llm_status.json', result)
        print(json.dumps(result, sort_keys=True))
        if result['pending']:
            raise SystemExit('Pending inputs remain')


if __name__ == '__main__':
    main()
