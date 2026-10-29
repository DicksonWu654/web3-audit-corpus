"""Reproduce Phase 3e before/after tables, rule counts and v5 regressions."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import statistics

import duckdb

ROOT = Path(__file__).resolve().parents[2]


def csv_rows(path):
    with path.open(newline='') as f:
        return list(csv.DictReader(f))


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def snapshot(path):
    with duckdb.connect(str(path), read_only=True) as c:
        totals = dict(all_engagements=c.execute('SELECT count(*) FROM engagements').fetchone()[0],
                      publisher_engagements=c.execute('SELECT count(*) FROM counted_engagements').fetchone()[0],
                      industry_engagements=c.execute('SELECT count(DISTINCT industry_engagement_id) FROM counted_engagements').fetchone()[0])
        docs = {did:dict(engagement_id=eid, industry_engagement_id=iid, project=project, metadata={'client':json.loads(meta).get('client',{})}, sha256=h)
                for did,eid,iid,project,meta,h in c.execute('SELECT d.document_id,e.engagement_id,e.industry_engagement_id,d.project,d.metadata,d.sha256 FROM documents d LEFT JOIN engagement_documents ed USING(document_id) LEFT JOIN engagements e USING(engagement_id) WHERE NOT d.is_seed').fetchall()}
        ledger = c.execute('SELECT source_file,file_sha256 FROM import_sources ORDER BY source_file').fetchall()
    return dict(totals=totals, documents=docs, ledger=ledger, sha256=sha(path))


def write_report():
    folder=ROOT/'local-cache/phase3e'
    validation=ROOT/'data/phase3/fixes_identity_scope_validation.json'
    validation_data=json.loads(validation.read_text()) if validation.exists() else {}
    source_snapshot=validation_data.get('source_snapshot',{})
    after_path=ROOT/source_snapshot.get('after_database','data/corpus.duckdb')
    before=snapshot(folder/'before.duckdb')
    after=snapshot(after_path)
    phase3_summary=json.loads((ROOT/'data/phase3/summary.json').read_text())
    assert phase3_summary['engagements']==after['totals']['all_engagements']
    assert phase3_summary['counted_engagements']==after['totals']['publisher_engagements']
    assert phase3_summary['industry_engagements']==after['totals']['industry_engagements']
    annual_before=csv_rows(folder/'engagements_year.before.csv')
    annual_after=csv_rows(ROOT/'data/analysis/engagements_year.csv')
    pairs_before=csv_rows(folder/'cadence.before.csv')
    pairs_after=csv_rows(ROOT/'data/analysis/reaudit_cadence_pairs.csv')
    for snap,manifest,annual,db_path in [(before,folder/'inputs.before.csv',annual_before,'data/corpus.duckdb'),
                                 (after,ROOT/'data/analysis/input_manifest.csv',annual_after,str(after_path.relative_to(ROOT)))]:
        db_receipts=[r for r in csv_rows(manifest) if r['path']==db_path]
        assert len(db_receipts)==1 and db_receipts[0]['sha256']==snap['sha256'], 'Analysis/database receipt mismatch'
        for axis in ['audit','publication']:
            assert sum(int(r['industry_engagements']) for r in annual if r['series']==axis)==snap['totals']['industry_engagements']
            assert sum(int(r['publisher_engagements']) for r in annual if r['series']==axis)==snap['totals']['publisher_engagements']
    for snap,pairs in [(before,pairs_before),(after,pairs_after)]:
        snap['totals'].update(reaudit_pairs=len(pairs), median_gap_days=statistics.median(int(r['days']) for r in pairs) if pairs else None,
                              short_gap_pairs=sum(int(r['days'])<60 for r in pairs))
    def jsonl(path):
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    edges=jsonl(ROOT/'data/phase3/identity_scope_merge_edges.jsonl')
    rejected=jsonl(ROOT/'data/phase3/identity_scope_rejected_edges.jsonl')
    rules=defaultdict(lambda:dict(accepted_edges=0,component_joins=0,previous_identity_joins=0,documents=set()))
    for edge in edges:
        item=rules[edge['basis']]
        item['accepted_edges']+=1
        item['component_joins']+=bool(edge['joins_components'])
        old={before['documents'].get(d,{}).get('engagement_id') for d in edge['documents']}-{None}
        item['previous_identity_joins']+=bool(edge['joins_components'] and len(old)>1)
        item['documents'].update(edge['documents'])
    rules={k:dict(**{key:value for key,value in v.items() if key!='documents'},documents=len(v['documents'])) for k,v in sorted(rules.items())}
    repairs=Counter()
    for did,d in after['documents'].items():
        old=before['documents'].get(did)
        if old and old['metadata'].get('client',{}).get('value')!=d['metadata'].get('client',{}).get('value'):
            repairs[d['metadata'].get('client',{}).get('method','unavailable')]+=1
    # Verifier data is used only here, after production extraction/grouping.
    # No sampled IDs, source hashes, labels or expected outcomes enter the rules.
    gold=json.loads((ROOT/'docs/verify/phase3_v5.json').read_text())
    def successors(old_eid, industry=False):
        field='industry_engagement_id' if industry else 'engagement_id'
        return {after['documents'][did][field] for did in gold['engagements'][old_eid]['documents']
                if did in after['documents'] and after['documents'][did][field]}
    splits=[]
    for row in gold['split']['rows']:
        if row['split_error']:
            left,right=successors(row['left']),successors(row['right'])
            splits.append(dict(position=row['position'],publisher=row['publisher_id'],relationship=row['relationship'],
                               resolved=bool(left and right and len(left|right)==1),left=sorted(left),right=sorted(right)))
    merges=[]
    for row in gold['merge']['rows']:
        if row['verdict'] in {'false_merge','unsupported_merge'}:
            ids=successors(row['engagement_id'])
            merges.append(dict(position=row['position'],verdict=row['verdict'],split=len(ids)>1,successors=sorted(ids)))
    cadence_set={(r['previous_industry_engagement_id'],r['industry_engagement_id']) for r in pairs_after}
    reaudits=[]
    for row in gold['reaudit']['rows']:
        left=set().union(*(successors(e,True) for e in row['left']))
        right=set().union(*(successors(e,True) for e in row['right']))
        retained=any((a,b) in cadence_set or (b,a) in cadence_set for a in left for b in right if a!=b)
        reaudits.append(dict(position=row['position'],project_collision=row['project_collision'],valid_reaudit=row['valid_reaudit'],relationship=row['relationship'],retained=retained))
    old_components=defaultdict(set)
    new_components=defaultdict(set)
    for did,old in before['documents'].items():
        new=after['documents'].get(did)
        if new and old['engagement_id'] and new['engagement_id']:
            old_components[old['engagement_id']].add(new['engagement_id'])
            new_components[new['engagement_id']].add(old['engagement_id'])
    result=dict(before=before['totals'],after=after['totals'],database_sha256=dict(before=before['sha256'],after=after['sha256']),
                import_ledger_unchanged=before['ledger']==after['ledger'],phase3_exports_reconciled=True,
                annual_before=annual_before,annual_after=annual_after,rules=rules,client_repair_occurrences=dict(sorted(repairs.items())),
                rejected_scope_edges=len(rejected),rejected_scope_pairs=len({tuple(sorted(r['documents'])) for r in rejected}),
                previous_identities_split=sum(len(ids)>1 for ids in old_components.values()),
                current_groups_joining_previous_identities=sum(len(ids)>1 for ids in new_components.values()),
                v5_split_regressions=splits,v5_merge_regressions=merges,v5_cadence_regressions=reaudits,
                cadence_rules=csv_rows(ROOT/'data/analysis/cadence_identity_rules.csv'))
    result['validation']=validation_data
    result['after_database']=str(after_path.relative_to(ROOT))
    date_log=ROOT/validation_data.get('source_dates',{}).get('log','local-cache/phase3e/validation/source_dates.log')
    date_result=json.loads(date_log.read_text().splitlines()[-1]) if date_log.exists() else {}
    result['source_date_coverage']=date_result.get('coverage',{})
    target=ROOT/'data/phase3/fixes_identity_scope.json'
    target.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    lines=['# Phase 3e — report families and evidence-based project chronology','',
           'Analytical cutoff: **2026-10-20**. Offline deterministic rebuild; source reports, holdout labels and verifier files are unchanged. No sampled IDs, source hashes or expected outcomes are encoded in production rules. The v5 judgments below are regression checks, not a new independent accuracy estimate.','',
           '## Before / after','',
           '| Metric | Before | After | Change |','|---|---:|---:|---:|']
    for k,label in [('all_engagements','All engagement rows (including provisional)'),('publisher_engagements','Confirmed publisher engagements'),('industry_engagements','Confirmed industry engagements'),('reaudit_pairs','Re-audit pairs'),('median_gap_days','Median gap, days'),('short_gap_pairs','Pairs below 60 days')]:
        a,b=result['before'][k],result['after'][k]
        lines.append(f'| {label} | {a:,} | {b:,} | {b-a:+,} |')
    for axis,title in [('audit','Audit completion / issue year'),('publication','Publication year')]:
        lines += ['',f'## {title}','',
                  '| Year | Industry before | Industry after | Change | Publisher before | Publisher after | Change |',
                  '|---|---:|---:|---:|---:|---:|---:|']
        a={r['year']:r for r in annual_before if r['series']==axis}
        b={r['year']:r for r in annual_after if r['series']==axis}
        for y in sorted(a.keys()|b.keys()):
            ai,bi,ap,bp=(int(r.get(k,0)) for r,k in [(a.get(y,{}),'industry_engagements'),(b.get(y,{}),'industry_engagements'),(a.get(y,{}),'publisher_engagements'),(b.get(y,{}),'publisher_engagements')])
            lines.append(f'| {y+" YTD" if y=="2026" else y} | {ai:,} | {bi:,} | {bi-ai:+,} | {ap:,} | {bp:,} | {bp-ap:+,} |')
    lines += ['','## General rules and counts','',
              'Cover/client extraction binds the actual name to its label and keeps component scopes. A separate project-identity record stores source-named entities, explicitly audited repositories/files and explicitly labelled project domains. It rejects author banners and numeric/prose headings. Filename-only names cannot authorize cadence.','',
              'Report grouping adds native report routes across hosts, SHA-verified HTML canonical/og:url aliases with matching date and scope evidence, source-explicit competition implementation parts, cohort/team components, split-submodule declarations, additional formal-verification deliverables, translations and scoped-version/finding revisions. Canonical report links stay separate from protocol-domain evidence. Mitigation-only reviews attach to their explicitly linked parent or latest preceding source-supported scope; their dates/findings remain follow-up evidence. A component-wide scope guard blocks indirect merges of disjoint substantive implementation assets; proxy/library overlap is insufficient.','',
              '| Merge rule | Accepted evidence edges | Component joins | Joins of previous identities | Distinct documents |',
              '|---|---:|---:|---:|---:|']
    for rule,item in rules.items():
        lines.append(f'| `{rule}` | {item["accepted_edges"]:,} | {item["component_joins"]:,} | {item["previous_identity_joins"]:,} | {item["documents"]:,} |')
    lines += ['', 'Edges can repeat within a component; only component joins reduce the rebuild component count. The previous-identity column counts joining edges whose endpoints belonged to different baseline identities. These are deterministic attribution counts in processing order, not independent causal ablations.', '',
              f'Scope guard: **{result["rejected_scope_edges"]:,} rejected attempts / {result["rejected_scope_pairs"]:,} distinct document pairs**. **{result["previous_identities_split"]:,}** previous identities split; **{result["current_groups_joining_previous_identities"]:,}** current groups combine previous identities. Multiple joins/splits can affect one group, so these counts cannot simply be subtracted from totals.','',
              '| Client repair method | Changed document occurrences |','|---|---:|']
    lines += [f'| `{k}` | {v:,} |' for k,v in sorted(repairs.items())]
    lines += ['','## Corrected cadence','',
              'Cadence requires direct evidence for each pair: the same complete normalized source-named project/client entity plus an overlapping audited repository or substantive scope asset, or the same explicitly recorded protocol domain. Report-host domains and shared libraries are excluded. Strong evidence partitions the chronology before adjacency is rebuilt; a transitive bridge alone cannot qualify an adjacent pair. Same-day genuinely separate work remains eligible. Coarse/conflicting dates are excluded, and issue-date fallback remains labelled.','',
              '| Cadence rule | Pairs / rejected candidates |','|---|---:|']
    lines += [f'| `{r["rule"]}` | {int(r["count"]):,} |' for r in result['cadence_rules']]
    lines += ['', 'The verifier’s 99–130-day values were conditional screening estimates that retained long-gap pairs and did not reconnect chronology. The rebuilt median above is measured on the conservative source-supported subset; it is not calibrated to that estimate. Missing aliases, incomplete scope evidence, unresolved date extraction and unpublished/intervening reports still affect coverage and gaps. Pair evidence is exported in `data/analysis/reaudit_cadence_pairs.csv`; exclusions are in `cadence_identity_eligibility.csv`.','',
              '## v5 regression checks','', '| Split sample | Publisher | Relationship | Now one engagement |','|---|---|---|---|']
    lines += [f'| S{r["position"]} | {r["publisher"]} | {r["relationship"]} | {r["resolved"]} |' for r in splits]
    collisions=[r for r in reaudits if r['project_collision']]
    lines += ['',f'Resolved split/relationship examples: **{sum(r["resolved"] for r in splits)}/{len(splits)}**. Unrelated-project cadence collisions retained: **{sum(r["retained"] for r in collisions)}/{len(collisions)}**. Previously valid sampled re-audits retained as direct current neighbours: **{sum(r["retained"] for r in reaudits if r["valid_reaudit"])}/{sum(r["valid_reaudit"] for r in reaudits)}**; conservative evidence exclusions and changed adjacency can remove valid pairs too.','',
              '| Merge sample | Prior verdict | Now split into separate scopes |','|---|---|---|']
    lines += [f'| M{r["position"]} | {r["verdict"]} | {r["split"]} |' for r in merges]
    commands=(['python3 -I scripts/phase3/validate_identity_scope_frozen.py --resume'] if source_snapshot else [
              'python3 -I scripts/build/build_db.py',
              'python3 -I scripts/phase3/report.py',
              'python3 -I scripts/analysis/run.py --as-of 2026-10-20',
              'python3 -I scripts/phase3/validate_identity_scope.py'])
    lines += ['','## Reproduction and validation','',
              f'Baseline database SHA-256: `{before["sha256"]}`. Current: `{after["sha256"]}`. Imported source file/hash ledger unchanged: **{result["import_ledger_unchanged"]}**. Regenerated Phase 3 export totals reconcile with the database: **{result["phase3_exports_reconciled"]}**. Baseline DB and analysis CSVs are frozen under `local-cache/phase3e/`; bulk metadata, originals and caches remain local.','',
              '```sh',*commands,
              'python3 -I scripts/phase3/identity_scope_report.py','```','',
              '| Check | Result |','|---|---|']
    for name,item in result['validation'].items():
        lines.append(f'| {name} | {"PASS" if item["exit_code"]==0 else "FAIL"} |')
    if source_snapshot:
        lines += ['',f'Concurrent finding-status code/schema edits appeared during validation. The worktree edits are preserved. These checks use the intake dependency revision `{source_snapshot["base_revision"]}` plus the explicit task overlay and the pre-existing analysis projection, frozen in `{source_snapshot["source_manifest"]}`. Manifest SHA-256: `{source_snapshot["source_manifest_sha256"]}`. The after database is sealed at `{result["after_database"]}`. Validation covers this identity-fix checkpoint; integration with the concurrent status migration is not claimed. Reproduce the isolated validation with `python3 -I scripts/phase3/validate_identity_scope_frozen.py`.']
    coverage=result['source_date_coverage']
    if coverage:
        lines += ['',f'Confirmed date coverage: **{coverage["confirmed_known"]:,}/{coverage["confirmed"]:,} ({coverage["confirmed_pct"]:.4f}%)**. Separate date-recovery coverage target met: **{coverage["target_met"]}**. Identity merges change the dated-engagement denominator. `validate_identity_scope.py` checks source-date integrity; add `--require-date-coverage` to also enforce the existing date-recovery target. The target and source-date checker are unchanged. Retrieval timestamps are validated through **2026-10-21**; the analysis cutoff stays **2026-10-20**.']
    lines += ['', 'The general analysis integrity check does not certify the separate incident-link AI-assisted review. Changed incident metadata invalidates those earlier reviews; no new incident-link precision is claimed here. No new independent gold labeling or full date-repair accuracy claim is made.','']
    lines += ['## Files written','',
              'The complete source/generated-output list is `docs/phase3/files_written_identity_scope.txt`. Local snapshots and validation logs are enumerated separately in `local-cache/phase3e/files_written.local.txt`; originals are never copied into release documentation.','']
    (ROOT/'docs/phase3/fixes_identity_scope.md').write_text('\n'.join(lines))
    files=['scripts/build/phase3_engagements.py','scripts/phase3/identity_rules.py','scripts/phase3/identity_scope_diagnose.py',
           'scripts/phase3/identity_scope_report.py','scripts/phase3/validate_identity_scope.py','scripts/phase3/validate_identity_scope_frozen.py','scripts/phase3/report.py','scripts/analysis/cadence.py',
           'scripts/analysis/run.py','scripts/analysis/check.py','scripts/analysis/README.md','tests/test_phase3e.py',
           'data/corpus.duckdb','data/phase3/artifact_metadata.jsonl','data/phase3/identity_map.json',
           'data/phase3/relationship_checks.jsonl','data/phase3/identity_scope_merge_edges.jsonl','data/phase3/identity_scope_rejected_edges.jsonl',
           'data/phase3/fixes_identity_scope.json','data/phase3/fixes_identity_scope_validation.json','docs/phase3/fixes_identity_scope.md','docs/phase3/files_written_identity_scope.txt',
           'data/phase3/engagements.jsonl','data/phase3/engagement_documents.jsonl','data/phase3/document_exclusions.jsonl',
           'data/phase3/date_claims.jsonl','data/phase3/date_check.json','data/phase3/summary.json','data/phase3/files_written.txt','docs/phase3/engagements.md']
    files += [p for p in (ROOT/'docs/analysis/files_written.txt').read_text().splitlines() if p.startswith(('data/analysis/','docs/analysis/'))]
    (ROOT/'docs/phase3/files_written_identity_scope.txt').write_text('\n'.join(sorted(set(files)))+'\n')
    local=folder/'files_written.local.txt'
    local.write_text('\n'.join(sorted({str(p.relative_to(ROOT)) for p in folder.rglob('*') if p.is_file()}|{str(local.relative_to(ROOT))}))+'\n')
    print(json.dumps({k:result[k] for k in ['before','after','import_ledger_unchanged','previous_identities_split']},sort_keys=True))
    print(json.dumps(dict(split_regressions=splits,merge_regressions=merges),indent=2))
    return result


if __name__=='__main__':
    argparse.ArgumentParser(description=__doc__).parse_args()
    write_report()
