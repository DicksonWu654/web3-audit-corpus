#!/usr/bin/env python3
"""Reproducible Phase 3b baseline, holdout-safe diagnosis and coverage report."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sys
import duckdb

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts/build'))
from metadata_rules import DATE, atomic, canonical, date_claims


def holdouts(root):
    values = {s.strip() for s in (root/'data/holdout/gold_sha256.txt').read_text().splitlines()
              if s.strip() and not s.startswith('#')}
    if not values or any(not re.fullmatch('[0-9a-f]{64}', s) for s in values):
        raise ValueError('Missing/invalid holdout boundary')
    return values


def snapshot(root, db=None):
    con = duckdb.connect(str(db or root/'data/corpus.duckdb'), read_only=True)
    cols = ['engagement_id','publisher_id','identity_status','audit_year','year_conflict']
    rows = [dict(zip(cols,r)) for r in con.execute('SELECT e.engagement_id,e.publisher_id,e.identity_status,y.audit_year,y.year_conflict FROM engagements e JOIN engagement_years y USING(engagement_id) ORDER BY 1').fetchall()]
    methods = Counter()
    for eid, method in con.execute("WITH linked AS (SELECT ed.engagement_id,dc.evidence,dc.basis FROM engagement_documents ed JOIN date_claims dc USING(document_id) WHERE eligible_for_audit_year UNION ALL SELECT engagement_id,evidence,basis FROM date_claims WHERE eligible_for_audit_year AND engagement_id IS NOT NULL) SELECT DISTINCT engagement_id,coalesce(json_extract_string(evidence,'$.assertion.method'),basis) FROM linked").fetchall():
        methods[method] += 1
    missing = con.execute("SELECT DISTINCT e.engagement_id,d.document_id,d.publisher_id,d.sha256,d.filename,d.public_url,d.wayback_url,d.file_format,d.metadata,d.provenance FROM engagements e JOIN engagement_years y USING(engagement_id) JOIN engagement_documents ed USING(engagement_id) JOIN documents d USING(document_id) WHERE y.audit_year IS NULL ORDER BY 1,2").fetchall()
    missing_cols = ['engagement_id','document_id','publisher_id','sha256','filename','public_url','wayback_url','file_format','metadata','provenance']
    docs = [dict(zip(missing_cols, r)) for r in missing]
    for d in docs:
        for key in ['metadata','provenance']:
            d[key] = json.loads(d[key])
    ledger = [list(r) for r in con.execute('SELECT source_file,file_sha256 FROM import_sources ORDER BY 1').fetchall()]
    con.close()
    return dict(engagements=rows, methods=dict(sorted(methods.items())), missing_documents=docs,
                input_ledger=ledger)


def totals(rows):
    return dict(all=len(rows), confirmed=sum(r['identity_status']=='confirmed' for r in rows),
                dated=sum(r['audit_year'] is not None for r in rows),
                confirmed_dated=sum(r['audit_year'] is not None and r['identity_status']=='confirmed' for r in rows))


def diagnose(root, snap, samples=0, firms=None):
    blocked = holdouts(root)
    causes, confirmed_causes, examples = defaultdict(Counter), defaultdict(Counter), []
    confirmed={r['engagement_id'] for r in snap['engagements'] if r['identity_status']=='confirmed'}
    seen = set()
    for d in snap['missing_documents']:
        firm, digest = d['publisher_id'], d['sha256']
        if (firm,digest or d['document_id']) in seen:
            continue
        seen.add((firm,digest or d['document_id']))
        if digest in blocked:
            causes[firm]['holdout_uninspected'] += 1
            if d['engagement_id'] in confirmed: confirmed_causes[firm]['holdout_uninspected']+=1
            continue
        if not digest:
            causes[firm]['original_not_acquired'] += 1
            continue
        full = root/'local-cache/fulltext'/(digest+'.txt')
        old = root/'local-cache/text'/(digest+'.txt')
        text = (full if full.exists() else old).read_text() if full.exists() or old.exists() else ''
        if not text.strip():
            cause = 'empty_or_unavailable_text'
        elif not re.search(r'\b20\d{2}\b',text):
            cause = 'commit_only_no_year' if re.search(r'\b[a-f0-9]{40}\b',text) else 'no_year_in_text'
        else:
            claimed = date_claims(text, {'pages':list(range(1,len(text.split('\f'))+1))})
            if any(c['date_value'] and c['role'] in {'audit_completion','report_issue'} and c['confidence']>=.8 for c in claimed):
                cause='fulltext_or_ocr_layout_miss'
            elif DATE.search(text):
                cause='date_semantics_or_position'
            else:
                cause='odd_format_or_year_only'
        causes[firm][cause] += 1
        if d['engagement_id'] in confirmed: confirmed_causes[firm][cause]+=1
        if samples and (not firms or firm in firms) and sum(e['publisher_id']==firm for e in examples)<samples:
            excerpts=[]
            for p,body in enumerate(text.split('\f'),1):
                if p<=2 or p>len(text.split('\f'))-2:
                    excerpts.append({'page':p,'text':body[:2800]})
            examples.append({k:d[k] for k in ['publisher_id','sha256','filename']} | dict(cause=cause, excerpts=excerpts))
    return dict(causes={k:dict(v) for k,v in sorted(causes.items())},
                confirmed_causes={k:dict(v) for k,v in sorted(confirmed_causes.items())},examples=examples)


def report(root):
    before=json.loads((root/'data/phase3/dates_before.json').read_text())
    after=snapshot(root)
    diagnosis=diagnose(root,after)
    atomic(root/'data/phase3/dates_after.json', canonical(after)+'\n')
    atomic(root/'data/phase3/dates_diagnosis_after.json',canonical(diagnosis)+'\n')
    b,a=totals(before['engagements']),totals(after['engagements'])
    lines=['# Phase 3b engagement dates','','Generated by `scripts/phase3/dates.py report`. Completion takes priority over issue; publication, filename, catalog, commit and crawl dates never supply audit years. Unknowns remain in the denominator.','',
           '| Population | Before | After |','|---|---:|---:|',
           f"| Overall | {b['dated']:,}/{b['all']:,} ({100*b['dated']/b['all']:.2f}%) | {a['dated']:,}/{a['all']:,} ({100*a['dated']/a['all']:.2f}%) |",
           f"| Confirmed | {b['confirmed_dated']:,}/{b['confirmed']:,} ({100*b['confirmed_dated']/b['confirmed']:.2f}%) | {a['confirmed_dated']:,}/{a['confirmed']:,} ({100*a['confirmed_dated']/a['confirmed']:.2f}%) |",'',
           '**Finish line: '+('PASS' if a['dated']/a['all']>=.85 and a['confirmed_dated']/a['confirmed']>=.95 else 'NOT MET')+'** (85% overall; 95% confirmed).','',
           'The baseline preserves engagement IDs, unknown-document receipts and the input ledger. Counts can change when new collector inputs enter the build. Method counts below are distinct engagements with an eligible claim, so methods can overlap. Holdout originals are excluded from development examples and LLM requests; uniform deterministic rules still process their existing text cache.','',
           '## By firm','','| Firm | Before known/all | Before known/confirmed | After known/all | After known/confirmed |','|---|---:|---:|---:|---:|']
    firms=sorted({r['publisher_id'] for r in before['engagements']+after['engagements']})
    for f in firms:
        x,y=[totals([r for r in s['engagements'] if r['publisher_id']==f]) for s in [before,after]]
        lines.append(f"| {f} | {x['dated']}/{x['all']} | {x['confirmed_dated']}/{x['confirmed']} | {y['dated']}/{y['all']} | {y['confirmed_dated']}/{y['confirmed']} |")
    lines += ['','## By method','','| Method | Before | After |','|---|---:|---:|']
    for m in sorted(before['methods'].keys()|after['methods'].keys()|{'llm'}):
        lines.append(f"| {m} | {before['methods'].get(m,0)} | {after['methods'].get(m,0)} |")
    lines += ['','## Missing-date diagnosis','','Counts are distinct missing-date artifact occurrences per firm, with repeated identical hashes removed. They are diagnostic signals, not manual labels. No held-out text is inspected.','', '| Firm | Cause | Before | After |','|---|---|---:|---:|']
    prev=json.loads((root/'data/phase3/dates_diagnosis_before.json').read_text())['causes']
    for f in sorted(prev.keys()|diagnosis['causes'].keys()):
        x,y=prev.get(f,{}),diagnosis['causes'].get(f,{})
        for c in sorted(x.keys()|y.keys()):
            lines.append(f'| {f} | {c} | {x.get(c,0)} | {y.get(c,0)} |')
    lines += ['','## Undated confirmed artifacts after the change','','This table excludes unacquired discovery candidates. Repeated hashes within a firm count once, so these artifact counts differ from engagement counts.','',
              '| Firm | Cause | Artifacts |','|---|---|---:|']
    for f,counts in diagnosis['confirmed_causes'].items():
        lines += [f'| {f} | {c} | {v} |' for c,v in sorted(counts.items())]
    conflicts=[]
    for snap in [before,after]:
        conflicts.append(Counter(r['publisher_id'] for r in snap['engagements'] if r['identity_status']=='confirmed' and r['year_conflict']))
    lines += ['','## Conflicting completion/issue years','','These are confirmed engagements whose preferred-role claims disagree across years. They remain unknown; no later date is silently selected.','',
              '| Firm | Before | After |','|---|---:|---:|']
    for f in sorted(conflicts[0].keys()|conflicts[1].keys()):
        lines.append(f'| {f} | {conflicts[0].get(f,0)} | {conflicts[1].get(f,0)} |')
    recovery=root/'data/phase3/date_recovery_summary.json'
    if recovery.exists():
        recovered=json.loads(recovery.read_text())
        lines += ['','## Original recovery','',f"Attempted **{recovered['candidates']:,} candidate occurrences**: **{recovered['statuses'].get('collected',0):,} acquired**; **{recovered['statuses'].get('failed',0):,} failed/skipped**. Candidate occurrences can share an engagement or original hash. Per-URL attempts and reasons are in `data/phase3/date_recovery/`; collector contract rows are appended under `data/collect/<firm>/`. Reports retain pinned GitHub permalinks and SHA-256 originals. Shared host locks enforce robots policy and at least one second between requests."]
        lines += ['','| Firm | Acquired candidates | Failed/skipped |','|---|---:|---:|']
        for f,c in sorted(recovered['by_firm'].items()):
            lines.append(f"| {f} | {c.get('collected',0)} | {c.get('failed',0)} |")
    notes=root/'data/phase3/dates_notes.txt'
    if notes.exists():
        lines += ['',notes.read_text().strip()]
    general_path=root/'data/phase3/check.json'
    date_path=root/'data/phase3/date_check.json'
    if general_path.exists() and date_path.exists():
        general=json.loads(general_path.read_text()); checked=json.loads(date_path.read_text())
        lines += ['','## Verification','',
                  f"General integrity checker: **{general['check']}**. Date evidence and coverage checker: **{checked['check']}**.",
                  f"Exact quote/text-hash claims verified: **{checked['counts'].get('verbatim_claims_verified',0):,}**. Eligible claims with basis and source-field evidence: **{checked['counts'].get('eligible_claims',0):,}**."]
        tests=root/'data/phase3/dates_tests.txt'
        if tests.exists():
            passed=re.search(r'(\d+) passed',tests.read_text())
            if passed:
                lines += [f"Relevant build, metadata and date regression tests: **{passed[1]} passed** (`tests/test_build.py`, `tests/test_phase3.py`, `tests/test_dates.py`)."]
    atomic(root/'docs/phase3/dates.md','\n'.join(lines)+'\n')
    written=set('schema/README.md scripts/build/metadata_rules.py scripts/build/date_rules.py scripts/build/phase3_engagements.py scripts/collect/recover_dates.py scripts/phase3/dates.py scripts/phase3/check_dates.py scripts/phase3/llm_dates.py scripts/phase3/recovery_text.py scripts/phase3/report.py tests/test_dates.py docs/phase3/dates.md docs/phase3/engagements.md data/corpus.duckdb data/phase3/dates_files_written.txt'.split())
    names=['artifact_metadata.jsonl','identity_map.json','summary.json','engagements.jsonl','engagement_documents.jsonl','document_exclusions.jsonl','date_claims.jsonl','files_written.txt','check.json','date_check.json','date_recovery_summary.json','date_recovery_text.json']
    names += [p.name for p in (root/'data/phase3').glob('dates_*') if p.is_file()]
    for name in names:
        if (root/'data/phase3'/name).exists(): written.add('data/phase3/'+name)
    for folder in ['date_recovery','llm_date_batches']:
        for path in (root/'data/phase3'/folder).glob('*.json'):
            written.add(str(path.relative_to(root)))
            if folder=='date_recovery':
                r=json.loads(path.read_text())
                firm=r['firm_id']
                for name in ['reports.jsonl','status.json']:
                    target=root/'data/collect'/firm/name
                    if target.exists(): written.add(str(target.relative_to(root)))
                if r.get('row'):
                    written.add(r['row']['local_path'])
    # Include local cache artifacts changed during this task, without copying
    # original bytes, report text or temporary test fixtures into the manifest.
    started=(root/'data/phase3/dates_before.json').stat().st_mtime
    for folder in ['text','fulltext','date-recovery-input-format','web-cache','web-host-locks']:
        for path in (root/'local-cache'/folder).glob('*'):
            if path.is_file() and path.stat().st_mtime>=started:
                written.add(str(path.relative_to(root)))
    written.update(str(p.relative_to(root)) for p in (root/'local-cache').glob('date_classification-append-*.lock'))
    atomic(root/'data/phase3/dates_files_written.txt','\n'.join(sorted(written))+'\n')
    print(canonical(dict(before=b,after=a)))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('command',choices=['baseline','baseline-methods','diagnose','report'])
    p.add_argument('--root',type=Path,default=ROOT)
    p.add_argument('--firms',nargs='*')
    p.add_argument('--samples',type=int,default=0)
    a=p.parse_args()
    if a.command=='baseline':
        path=a.root/'data/phase3/dates_before.json'
        if path.exists():
            raise SystemExit('Baseline exists; refusing to overwrite')
        snap=snapshot(a.root)
        atomic(path,canonical(snap)+'\n')
        atomic(a.root/'data/phase3/dates_diagnosis_before.json',canonical(diagnose(a.root,snap))+'\n')
        print(canonical(totals(snap['engagements'])))
    elif a.command=='baseline-methods':
        path=a.root/'data/phase3/dates_before.json'
        before=json.loads(path.read_text()); current=snapshot(a.root)
        if before['engagements']!=current['engagements'] or before['input_ledger']!=current['input_ledger']:
            raise SystemExit('Original DB changed; cannot repair method labels')
        before['methods']=current['methods']
        atomic(path,canonical(before)+'\n')
    elif a.command=='diagnose':
        print(json.dumps(diagnose(a.root,snapshot(a.root),a.samples,a.firms),indent=2))
    else:
        report(a.root)
