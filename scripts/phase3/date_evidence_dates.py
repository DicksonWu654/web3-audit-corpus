#!/usr/bin/env python3
"""Offline, holdout-safe Phase 3f date diagnosis and reproducible coverage receipt."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import shutil
import sys

import duckdb

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts/phase3'))
sys.path.insert(0, str(ROOT/'scripts/build'))
from dates import snapshot, totals, holdouts
from metadata_rules import atomic, canonical
from date_rules import load_date_text


def capture(root, db=None):
    # snapshot() is intentionally shared with the original coverage denominator.
    snap = snapshot(root,db)
    with duckdb.connect(str(db or root/'data/corpus.duckdb'), read_only=True) as con:
        claims = defaultdict(list)
        for eid, raw in con.execute("SELECT ed.engagement_id,dc.evidence FROM engagement_documents ed JOIN date_claims dc USING(document_id) WHERE dc.eligible_for_audit_year UNION ALL SELECT engagement_id,evidence FROM date_claims WHERE engagement_id IS NOT NULL AND eligible_for_audit_year").fetchall():
            claims[eid].append(json.loads(raw))
        for row in snap['engagements']:
            row['methods'] = sorted({(c.get('assertion') or {}).get('method') or c.get('field') for c in claims[row['engagement_id']]})
    with (db or root/'data/corpus.duckdb').open('rb') as stream:
        snap['database_sha256'] = hashlib.file_digest(stream,'sha256').hexdigest()
    snap['holdout_sha256'] = hashlib.sha256((root/'data/holdout/gold_sha256.txt').read_bytes()).hexdigest()
    return snap


def documents(root, snap, firms=None):
    blocked = holdouts(root)
    confirmed = {r['engagement_id'] for r in snap['engagements'] if r['identity_status']=='confirmed'}
    for d in snap['missing_documents']:
        if d['engagement_id'] not in confirmed or firms and d['publisher_id'] not in firms:
            continue
        if d['sha256'] in blocked:
            yield d, '', {}, 'holdout_uninspected'
            continue
        meta=d['metadata']
        receipt=meta.get('date_text_receipt') or meta.get('text_receipt') or {}
        path=receipt.get('text_snapshot')
        if path and (root/path).exists():
            text=(root/path).read_text()
        else:
            path=root/'local-cache/text'/str(d['sha256']+'.txt') if d['sha256'] else None
            text=path.read_text() if path and path.exists() else ''
            text,receipt=load_date_text(root,d['sha256'],text,receipt)
        yield d,text,receipt,None


def diagnose(root, snap, firms=None, samples=0, pattern=None):
    import re
    by_engagement=defaultdict(set)
    conflicts={r['engagement_id'] for r in snap['engagements'] if r['year_conflict']}
    examples=[]; seen=set(); by_firm=defaultdict(Counter)
    for d,text,receipt,cause in documents(root,snap,firms):
        if not cause:
            # Distinguish a source year from calendar-looking code, copyright,
            # bibliography and URL tokens without treating any of them as dates.
            substantive=re.split(r'(?im)^\s*(?:#{1,6}\s*)?References\s*$',text)[0]
            substantive=re.sub(r'https?://\S+|\b[a-f0-9]{12,}\b','',substantive,flags=re.I)
            substantive='\n'.join(s for s in substantive.splitlines() if not re.search(r'©|copyright|all rights|FILE ARCHIVED|INTERNET ARCHIVE|RETRIEVED FROM',s,re.I))
            if not d['sha256']: cause='original_not_acquired'
            elif not text.strip(): cause='empty_or_unavailable_text'
            elif any(c.get('date_value') and c['role'] in {'audit_completion','report_issue'} and c['confidence']>=.8 for c in d['metadata'].get('dates',[])):
                cause='source_year_conflict' if d['engagement_id'] in conflicts else 'followup_only_or_ineligible_initial_claims'
            elif re.search(r'\*\*\d+ reports\*\*',text) and len(re.findall(r'https?://',text))>=3:
                cause='report_listing_without_own_dateline'
            elif re.search(r'20\d{2}',text) and not re.search(r'(?<![a-z0-9])20\d{2}(?![a-z0-9])',substantive,re.I):
                cause='copyright_reference_link_or_code_years_only'
            elif not re.search(r'20\s*\d\s*\d',text):
                cause='commit_only_no_year' if re.search(r'\b[a-f0-9]{40}\b',text) else 'no_year_in_text'
            elif any(c.get('date_value') and c['role']=='publication' for c in d['metadata'].get('dates',[])):
                cause='publication_claims_only_no_eligible_issue_or_completion'
            elif any(c.get('date_value') and c['role'] in {'audit_start','retest'} for c in d['metadata'].get('dates',[])):
                cause='start_or_followup_claims_only'
            elif re.search(r'(?im)^.{0,60}(?:date|version|revision|issued|report|审计|日期).{0,60}20\d{2}',text): cause='label_or_version_layout'
            elif re.search(r'20\d{2}',text): cause='year_present_semantics_or_format'
            else: cause='typographic_year_layout'
        by_engagement[(d['publisher_id'],d['engagement_id'])].add(cause)
        key=(d['publisher_id'],d['sha256'] or d['document_id'])
        if key in seen: continue
        seen.add(key)
        if cause!='holdout_uninspected' and samples and (not pattern or re.search(pattern,(d['filename'] or '')+' '+text,re.I)) and sum(e['publisher_id']==d['publisher_id'] for e in examples)<samples:
            excerpts=[]
            for p,body in enumerate(text.split('\f'),1):
                hits=[m for m in re.finditer(r'[^\n]*20\s*\d\s*\d[^\n]*',body)]
                if p<=2 or hits:
                    excerpts.append(dict(page=p,text=(body[:600]+'\n' if p==1 else '')+'\n'.join(body[max(0,m.start()-120):m.end()+120] for m in hits[:6])))
            examples.append({k:d[k] for k in ['engagement_id','publisher_id','sha256','filename','public_url']} | dict(cause=cause,excerpts=excerpts))
    # One row per missing confirmed engagement. Multiple causes remain explicit.
    for (firm,eid),causes in sorted(by_engagement.items()):
        by_firm[firm][' + '.join(sorted(causes))]+=1
    return dict(causes={f:dict(sorted(c.items())) for f,c in sorted(by_firm.items())}, examples=examples)


def report(root):
    folder=root/'local-cache/phase3f'
    before=capture(root,folder/'before.duckdb');after=capture(root)
    before['holdout_sha256']=json.loads((folder/'before.json').read_text())['holdout_sha256']
    b,a=totals(before['engagements']),totals(after['engagements'])
    old={r['engagement_id']:r for r in before['engagements']}
    recovered={r['engagement_id'] for r in after['engagements'] if r['identity_status']=='confirmed' and r['audit_year'] is not None and r['engagement_id'] in old and old[r['engagement_id']]['audit_year'] is None}
    lost={r['engagement_id'] for r in after['engagements'] if r['identity_status']=='confirmed' and r['audit_year'] is None and r['engagement_id'] in old and old[r['engagement_id']]['audit_year'] is not None}
    methods=defaultdict(set);recovery_methods=defaultdict(set);counts=Counter();resolutions=defaultdict(set)
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        for eid,role,eligible,raw in con.execute("SELECT ed.engagement_id,dc.role,dc.eligible_for_audit_year,dc.evidence FROM date_claims dc JOIN engagement_documents ed USING(document_id) JOIN engagements e ON e.engagement_id=ed.engagement_id WHERE e.identity_status='confirmed'").fetchall():
            c=json.loads(raw).get('assertion') or {};method=c.get('method') or ''
            if c.get('resolution'):resolutions[c['resolution']].add(eid)
            if method.startswith('date_evidence_'):counts[method+':'+role+(' eligible' if eligible else ' ineligible')]+=1
            if eligible:
                methods[method].add(eid)
                if eid in recovered:recovery_methods[method].add(eid)
        links={d:e for d,e in con.execute('SELECT document_id,engagement_id FROM engagement_documents').fetchall()}
    diagnosis_before=diagnose(root,before);diagnosis_after=diagnose(root,after)
    firms=sorted({r['publisher_id'] for r in before['engagements']+after['engagements']})
    per_firm={f:dict(before=totals([r for r in before['engagements'] if r['publisher_id']==f]),after=totals([r for r in after['engagements'] if r['publisher_id']==f])) for f in firms}
    result=dict(before=b,after=a,per_firm=per_firm,recovered_stable_ids=sorted(recovered),lost_stable_ids=sorted(lost),
                additional_confirmed_dates_for_96pct=max(0,(96*a['confirmed']+99)//100-a['confirmed_dated']),
                import_ledger_unchanged=before['input_ledger']==after['input_ledger'],holdout_unchanged=before['holdout_sha256']==after['holdout_sha256'],
                before_database_sha256=before['database_sha256'],after_database_sha256=after['database_sha256'],
                by_rule={m:len(e) for m,e in sorted(methods.items()) if m.startswith('date_evidence_')},
                recovery_methods={m:len(e) for m,e in sorted(recovery_methods.items())},claim_counts=dict(sorted(counts.items())),
                semantic_resolutions={m:len(e) for m,e in sorted(resolutions.items())},
                diagnosis_before=diagnosis_before['causes'],diagnosis_after=diagnosis_after['causes'])
    validation=folder/'validation.json'
    for method in ['report_title_dateline','audit_conclusion_dateline','wrapped_cover_dateline','cover_author_year',
                   'cover_date_column','retrospective_work_month','header_footer_date_field','control_date_field',
                   'report_revision_control_table','report_revision_wrapped_year','closing_author_dateline',
                   'localized_date_label','day_first_shared_month_period','document_contest_end',
                   'html_report_issue_meta','html_completion_meta','html_publication_meta','html_modified_meta']:
        result['by_rule'].setdefault('date_evidence_'+method,0)
    result['by_rule']=dict(sorted(result['by_rule'].items()))
    result['validation']=json.loads(validation.read_text()) if validation.exists() else {}
    date_check=root/'data/phase3/date_check.json'
    result['date_evidence_check']=json.loads(date_check.read_text()) if date_check.exists() else {}
    atomic(folder/'after.json',canonical(after)+'\n')
    atomic(folder/'results.json',canonical(result)+'\n')
    def coverage(t,confirmed=False):
        known,total=(t['confirmed_dated'],t['confirmed']) if confirmed else (t['dated'],t['all'])
        return f'{known:,}/{total:,} ({100*known/max(total,1):.4f}%)'
    lines=['# Phase 3f — deterministic date recovery','',
           'Offline rebuild at the 2026-10-20 analytical cutoff. Completion precedes current report issue; unknowns remain in the denominator. All counts are reproduced by `scripts/phase3/date_evidence_dates.py report`.','',
           '| Population | Before | After |','|---|---:|---:|',f'| All engagements | {coverage(b)} | {coverage(a)} |',f'| Confirmed engagements | {coverage(b,True)} | {coverage(a,True)} |','',
           f"Confirmed target ≥95%: **{'PASS' if a['confirmed_dated']/a['confirmed']>=.95 else 'FAIL'}**. Margin aim ≥96%: **{'MET' if a['confirmed_dated']/a['confirmed']>=.96 else 'NOT MET'}**. Additional dated confirmed engagements needed at this denominator: **{result['additional_confirmed_dates_for_96pct']}**.",
           f"Stable identities recovered: **{len(recovered)}**; newly unknown stable identities: **{len(lost)}**. Confirmed denominator change: **{a['confirmed']-b['confirmed']:+}**. New date evidence also participates in the existing identity rules; no identity rule was added or relaxed.",'',
           '## Rules and evidence','',
           'Rules recover title/conclusion datelines, wrapped cover dates, document-control/version rows (including a year wrapped past the author column), labelled header/footer dates, finite month spelling and language variants, localized Chinese audit tables, closing author datelines, and source-text contest endpoints. Bare cover ranges assign their first endpoint to audit start. Wrapped digital signatures and primary-review start rows cannot create completion/issue conflicts. Every build revalidates cached date proposals and year anchors against dependency-advisory record context; advisory dates stay non-eligible.',
           '','Every new `date_evidence_` claim has a verbatim quote, original-text SHA-256, half-open offsets, a semantic basis, and a page. PDF pages are physical; HTML/Markdown page 1 is explicitly logical. Date normalization does not supply missing years. Publication metadata, upload/git times, code commits, references, copyright, application dates and ongoing-work starts remain separate from completion/issue dates. HTML metadata is eligible only when its source field explicitly means report issue or audit/contest completion; publication and modified fields retain their own roles.','',
           '| New rule | Confirmed engagements with eligible claim | Recovered stable engagements with eligible claim |','|---|---:|---:|']
    for m in sorted(result['by_rule']):lines.append(f"| `{m}` | {result['by_rule'][m]} | {result['recovery_methods'].get(m,0)} |")
    lines+=['','Methods can overlap within one engagement. These are observed eligible-claim counts, not causal ablations. Zero means no eligible source instance in this rebuild; publication/modified metadata never qualifies. HTML metadata recovery receipts are in `local-cache/phase3f/html_metadata.json`. Existing methods contributing to newly dated engagements follow.','', '| Existing rule | Recovered stable engagements |','|---|---:|']
    for m,n in result['recovery_methods'].items():
        if not m.startswith('date_evidence_'):lines.append(f'| `{m}` | {n} |')
    lines+=['','| Semantic resolution | Confirmed engagements with retained resolution receipt |','|---|---:|']
    for m,n in result['semantic_resolutions'].items():lines.append(f'| `{m}` | {n} |')
    lines+=['','## Coverage per firm','', '| Firm/platform | Before all | After all | Before confirmed | After confirmed |','|---|---:|---:|---:|---:|']
    for f,rs in per_firm.items():
        x,y=rs['before'],rs['after'];lines.append(f'| {f} | {coverage(x)} | {coverage(y)} | {coverage(x,True)} | {coverage(y,True)} |')
    lines+=['','## Remaining undated confirmed engagements by firm and cause','',
            'Each missing engagement counts once in its firm; multiple document signals are joined explicitly. These are deterministic diagnostic signals, not independent manual truth labels. Held-out originals are never inspected for diagnosis or examples. Listings/reference material already counted as confirmed stay in this denominator; this task does not reclassify them.','',
            '| Firm/platform | Cause | Before | After |','|---|---|---:|---:|']
    for f in firms:
        x,y=diagnosis_before['causes'].get(f,{}),diagnosis_after['causes'].get(f,{})
        for c in sorted(x.keys()|y.keys()):lines.append(f'| {f} | {c} | {x.get(c,0)} | {y.get(c,0)} |')
    lines+=['','## Validation and reproduction','',
            f"Imported source file/hash ledger unchanged: **{result['import_ledger_unchanged']}**. Holdout hash list unchanged: **{result['holdout_unchanged']}**. No holdout development examples, new labels, LLM calls or network requests were used. Uniform rules still process existing held-out text caches. Genuine contradictory source years remain unknown.",'',
            '| Check | Result |','|---|---|']
    for name,check in result['validation'].items():lines.append(f"| {name} | {'PASS' if check['exit_code']==0 else 'FAIL'} |")
    checked=result['date_evidence_check'].get('counts',{})
    verified=result['validation'].get('new_date_evidence',{})
    lines+=['',f"Verbatim `date_evidence_` quote/page receipts verified: **{checked.get('date_evidence_verbatim_page_claims_verified',0):,} claim occurrences** (including repeated and semantically rejected claims). Newly dated stable engagements with a year-matching document quote and page: **{verified.get('source_text_and_page_verified',0)} / {verified.get('recovered',0)}**."]
    lines+=['','The checks establish evidence membership, practical regression behavior and reproducibility; they are not a new independent extraction-accuracy estimate. The independent 13/50 result motivates recovery but is not a training fixture or a claimed post-fix accuracy score.','',
            '```sh','python3 -I scripts/phase3/date_evidence_dates.py baseline  # once, before changes',
            'python3 -I scripts/phase3/date_evidence_html_dates.py',
            'python3 -I scripts/phase3/extract_metadata.py --workers 6',
            'python3 -I scripts/phase3/validate_date_evidence.py',
            'python3 -I scripts/phase3/date_evidence_dates.py report','```','',
            f"Baseline database SHA-256: `{before['database_sha256']}`. After: `{after['database_sha256']}`. Frozen baseline, diagnostics, per-claim counts and command logs are local under `local-cache/phase3f/`.",'',
            '## Files written','',
            'Source: `scripts/build/date_layout_rules.py`, `scripts/build/date_rules.py`, `scripts/build/metadata_rules.py`, `scripts/build/period_rules.py`, `scripts/build/phase3_engagements.py`, `scripts/phase3/check_dates.py`, `scripts/phase3/dates.py`, `scripts/phase3/date_evidence_dates.py`, `scripts/phase3/date_evidence_html_dates.py`, `scripts/phase3/date_evidence_visual.py`, `scripts/phase3/report.py`, `scripts/phase3/test_date_evidence_dates.py`, `scripts/phase3/validate_date_evidence.py`. Report: `docs/phase3/dates_date_evidence.md`. Generated outputs and local validation artifacts are enumerated in `local-cache/phase3f/files_written.json`. Originals, collection rows, holdout labels and verifier files are unchanged.']
    atomic(root/'docs/phase3/dates_date_evidence.md','\n'.join(lines)+'\n')
    manifest=folder/'files_written.json'
    if manifest.exists():
        written=set(json.loads(manifest.read_text()))
        written.update(str(p.relative_to(root)) for p in folder.rglob('*') if p.is_file())
        started=(folder/'before.json').stat().st_mtime
        written.update(str(p.relative_to(root)) for p in (root/'local-cache/text').glob('*')
                       if p.is_file() and p.stat().st_mtime>=started)
        written.update(str(p) for p in Path('local-cache/tmp/date_evidence-visual').glob('*.png'))
        atomic(manifest,canonical(sorted(written))+'\n')
    print(canonical(dict(before=b,after=a,recovered=len(recovered),lost=len(lost))))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['baseline','diagnose','probe','claims','scan','changes','rule-evidence','report'])
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--firms',nargs='*')
    parser.add_argument('--samples',type=int,default=0)
    parser.add_argument('--pattern')
    args=parser.parse_args();root=args.root
    folder=root/'local-cache/phase3f';folder.mkdir(parents=True,exist_ok=True)
    if args.command=='baseline':
        target=folder/'before.json'
        if target.exists(): raise SystemExit('Phase 3f baseline exists; refusing to overwrite')
        snap=capture(root)
        atomic(target,canonical(snap)+'\n')
        atomic(folder/'diagnosis_before.json',canonical(diagnose(root,snap))+'\n')
        shutil.copyfile(root/'data/corpus.duckdb',folder/'before.duckdb')
        print(canonical(totals(snap['engagements'])))
    elif args.command=='diagnose':
        print(json.dumps(diagnose(root,capture(root),args.firms,args.samples,args.pattern),indent=2,ensure_ascii=False))
    elif args.command=='probe':
        from date_layout_rules import layout_date_claims
        seen=set();found=defaultdict(set);methods=defaultdict(set)
        for d,payload,receipt,cause in documents(root,capture(root),args.firms):
            if cause or not d['sha256'] or d['sha256'] in seen:continue
            seen.add(d['sha256'])
            claims=layout_date_claims(payload,receipt)
            valid=[c for c in claims if c['role'] in {'report_issue','audit_completion'}]
            for c in valid:
                found[d['publisher_id']].add(d['engagement_id']);methods[c['method']].add(d['engagement_id'])
            if valid and args.samples:
                print(canonical(dict(firm=d['publisher_id'],filename=d['filename'],claims=[{k:c[k] for k in ['date_value','role','method','page','raw_value']} for c in valid])))
        print(canonical(dict(by_firm={f:len(e) for f,e in sorted(found.items())},by_rule={f:len(e) for f,e in sorted(methods.items())})))
    elif args.command=='rule-evidence':
        import re
        before=capture(root,folder/'before.duckdb')
        missing={r['engagement_id'] for r in before['engagements'] if r['audit_year'] is None}
        held=holdouts(root);seen=set()
        with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
            rows=con.execute('SELECT ed.engagement_id,d.publisher_id,d.filename,d.sha256,d.metadata FROM engagement_documents ed JOIN documents d USING(document_id) JOIN engagement_years y ON y.engagement_id=ed.engagement_id WHERE y.audit_year IS NOT NULL ORDER BY d.sha256,ed.engagement_id').fetchall()
        for eid,firm,filename,digest,raw in rows:
            if eid not in missing or digest in held or digest in seen:continue
            seen.add(digest);meta=json.loads(raw)
            for c in meta.get('dates',[]):
                if not re.search(args.pattern or '^date_evidence_',c['method']):continue
                if c.get('role') not in {'report_issue','audit_completion'} or c['confidence']<.8:continue
                path=c.get('text_snapshot')
                text=(root/path).read_text() if path else ''
                start=c.get('text_start',0);end=c.get('text_end',start)
                print(canonical(dict(firm=firm,filename=filename,value=c['date_value'],method=c['method'],page=c.get('page'),context=text[max(0,start-200):end+100])))
    elif args.command=='changes':
        before=capture(root,folder/'before.duckdb');after=capture(root)
        old={r['engagement_id']:r for r in before['engagements']}
        affected={r['engagement_id'] for r in after['engagements'] if r['engagement_id'] in old and old[r['engagement_id']]['audit_year'] is not None and old[r['engagement_id']]['audit_year']!=r['audit_year'] and (args.pattern!='lost' or r['audit_year'] is None)}
        blocked=holdouts(root)
        with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
            rows=con.execute('SELECT ed.engagement_id,d.publisher_id,d.filename,d.sha256,d.metadata FROM engagement_documents ed JOIN documents d USING(document_id) ORDER BY ed.engagement_id,d.document_id').fetchall()
        for eid,firm,filename,digest,raw in rows:
            if eid not in affected or digest in blocked:continue
            meta=json.loads(raw)
            def detail(c):
                result={k:c.get(k) for k in ['date_value','role','method','page','evidence','resolution']}
                if args.pattern=='lost' and c.get('text_snapshot'):
                    text=(root/c['text_snapshot']).read_text();lo=c.get('text_start',0);hi=c.get('text_end',lo)
                    result['context']=text[max(0,lo-500):hi+150]
                return result
            print(canonical(dict(engagement_id=eid,before=old[eid]['audit_year'],firm=firm,filename=filename,claims=[detail(c) for c in meta.get('dates',[]) if c.get('date_value') and (c.get('resolution') or c['role'] in {'audit_completion','report_issue'} and c['confidence']>=.8)])))
    elif args.command=='scan':
        from date_layout_rules import CALENDAR
        import re
        seen=set()
        for d,text,receipt,cause in documents(root,capture(root),args.firms):
            if cause or not d['sha256'] or d['sha256'] in seen:continue
            seen.add(d['sha256']);snippets=[]
            if any(c.get('date_value') and c['role'] in {'audit_completion','report_issue'} and c['confidence']>=.8 for c in d['metadata'].get('dates',[])):continue
            for m in CALENDAR.finditer(text):
                start=max(text.rfind('\n',0,m.start())+1,text.rfind('\f',0,m.start())+1)
                end=text.find('\n',m.end());end=end if end>=0 else len(text)
                line=text[start:end]
                if re.search(r'http|copyright|©|all rights|\b[a-f0-9]{12,}\b|\b(?:available|accessed|timestamp)\b',line,re.I):continue
                if not any(s['text_start']==start for s in snippets):snippets.append(dict(page=text[:start].count('\f')+1,text_start=start,text=text[max(text.rfind('\f',0,start)+1,start-150):min(len(text),end+100)]))
            if snippets:print(canonical(dict(firm=d['publisher_id'],filename=d['filename'],snippets=snippets[:8])))
    elif args.command=='claims':
        import re
        seen=set();counts=Counter()
        for d,payload,receipt,cause in documents(root,capture(root),args.firms):
            if cause or d['sha256'] in seen or args.pattern and not re.search(args.pattern,d['filename'] or '',re.I):continue
            if counts[d['publisher_id']]>=args.samples:continue
            seen.add(d['sha256']);counts[d['publisher_id']]+=1
            print(canonical(dict(firm=d['publisher_id'],filename=d['filename'],claims=[{k:c.get(k) for k in ['date_value','role','method','page','evidence','resolution']} for c in d['metadata'].get('dates',[]) if c.get('date_value') and (c['role'] in {'report_issue','audit_completion'} or c.get('resolution'))])))
    else:
        report(root)


if __name__=='__main__':
    main()
