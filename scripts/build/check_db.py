#!/usr/bin/env python3
"""Read-only integrity and frozen-inventory reconciliation for a corpus snapshot."""
from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from datetime import date
import hashlib
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit

import duckdb

# Explicit sibling import also works with python -I; nothing from extracted is imported.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_db import ROOT, EXPORTS, count_summary, load_publishers, norm, publisher_aliases, print_summary
try:
    from build_db import publisher_severity_mapping
except ImportError:
    publisher_severity_mapping=None  # The foundation's article-v1 importer.


class CheckError(ValueError):
    pass


def certik_public_copy(family, kind, url):
    """Permit public project/mirror copies, never a CertiK-controlled host."""
    host=(urlsplit(url or '').hostname or '').lower()
    forbidden=re.search(r'(?:^|\.)(?:certik\.(?:com|org|io)|certik-skynet[^/]*|certik[^/]*\.s3[^/]*\.amazonaws\.com)$',host)
    return family=='collected' and kind in {'github','website'} and bool(host) and not forbidden


def metadata_receipts(evidence):
    """Deduplicate API rows whose evidence can link several report versions."""
    candidates=list(evidence.get('competition_metadata',[]))
    if evidence.get('metadata_only') and evidence.get('source_record'):
        candidates.append(evidence['source_record'])
    for field in ('sca_api_matches','sca_api_unresolved_overlap'):
        candidates.extend(r['source_record'] for r in evidence.get(field,[]))
    return {(r['source_file'],r['source_locator'],r['source_record_sha256']) for r in candidates}


def check(root=ROOT, db=None, as_of=None):
    root=Path(root).resolve()
    as_of=as_of or date.today()
    con=duckdb.connect(str(db or root/"data/corpus.duckdb"),read_only=True)
    con.execute('SET threads=3')
    con.execute("SET TimeZone='UTC'")
    errors=[]
    def require(ok,message):
        if not ok:
            errors.append(message)
    def zero(sql,message):
        n=con.execute(sql).fetchone()[0]
        require(n==0,f"{message}: {n}")
    try:
        publishers=load_publishers(root)
        aliases=publisher_aliases(publishers)
        actual={r[0] for r in con.execute("SELECT publisher_id FROM publishers").fetchall()}
        require(actual==set(publishers),"Publisher table differs from active Tier A scope")
        require(actual <= set(publishers),"Out-of-scope publisher present")
        certik_manifest=root/'data/collect/certik/reports.jsonl'
        certik_sources={hashlib.sha256(json.dumps(r,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest():r
            for r in (json.loads(line) for line in certik_manifest.open() if line.strip())} if certik_manifest.exists() else {}
        for did,family,kind,url,sha,receipt in con.execute("SELECT document_id,source_family,source_kind,public_url,sha256,source_record_sha256 FROM documents WHERE publisher_id='certik'").fetchall():
            source=certik_sources.get(receipt,{})
            require(certik_public_copy(family,kind,url) and source.get('public_url')==url and source.get('sha256')==sha,
                'CertiK provenance must match a reviewed third-party public copy: '+did)
        zero("SELECT count(*) FROM counted_engagements e JOIN engagement_documents ed USING(engagement_id) JOIN documents d USING(document_id) WHERE json_extract_string(d.provenance,'$.source_row.firm_id')='certik' AND json_extract_string(d.provenance,'$.source_row.doc_kind')='unknown'",'Unvalidated public copy counted')
        scope_review=root/'registry/hacken_report_scope.csv'
        if scope_review.exists():
            for r in csv.DictReader(scope_review.open()):
                if r['include_in_audit_counts']=='no':
                    n=con.execute('SELECT count(*) FROM counted_engagements JOIN engagement_documents USING(engagement_id) JOIN documents USING(document_id) WHERE sha256=?',[r['sha256']]).fetchone()[0]
                    require(n==0,'Non-SCA Hacken service counted: '+r['sha256'])
        # Explicit anti-joins also detect corruption in DBs created without constraints.
        fks={"documents":[("publisher_id","publishers","publisher_id")],
             "engagements":[("publisher_id","publishers","publisher_id")],
             "engagement_documents":[("engagement_id","engagements","engagement_id"),("document_id","documents","document_id")],
             "document_exclusions":[("document_id","documents","document_id")],
             "engagement_identity_crosswalk":[("engagement_id","engagements","engagement_id")],
             "findings":[("publisher_id","publishers","publisher_id"),("document_id","documents","document_id")],
             "date_claims":[("document_id","documents","document_id"),("engagement_id","engagements","engagement_id"),("finding_id","findings","finding_id")],
             "contests":[("publisher_id","publishers","publisher_id"),("document_id","documents","document_id"),("engagement_id","engagements","engagement_id")]}
        for table,refs in fks.items():
            for col,parent,key in refs:
                zero(f"SELECT count(*) FROM {table} c LEFT JOIN {parent} p ON c.{col}=p.{key} WHERE c.{col} IS NOT NULL AND p.{key} IS NULL",f"FK {table}.{col}")
        # Re-evaluate every CHECK expression, including all enum and structural checks.
        for table,expression in con.execute("SELECT table_name,expression FROM duckdb_constraints() WHERE constraint_type='CHECK'").fetchall():
            zero(f'SELECT count(*) FROM "{table}" WHERE NOT ({expression})',f"CHECK {table}: {expression}")
        for table in ["documents","findings","contests","import_sources"]:
            cols=[r[0] for r in con.execute(f"DESCRIBE {table}").fetchall() if r[0].endswith("sha256")]
            for col in cols:
                zero(f"SELECT count(*) FROM {table} WHERE {col} IS NOT NULL AND NOT regexp_full_match({col}, '[0-9a-f]{{64}}')",f"SHA-256 {table}.{col}")
        for did,url,kind,family in con.execute("SELECT document_id,public_url,source_kind,source_family FROM documents").fetchall():
            u=urlsplit(url or '')
            require(u.scheme in {'http','https'} and bool(u.netloc),f"Invalid public_url {did}")
            if family=='collected' and u.netloc.lower() in {'github.com','raw.githubusercontent.com'}:
                parts=u.path.split('/')
                revision=parts[4] if u.netloc=='github.com' and len(parts)>4 and parts[3]=='blob' else parts[3] if u.netloc=='raw.githubusercontent.com' and len(parts)>3 else ''
                require(bool(re.fullmatch('[0-9a-f]{40}',revision)),f"Unpinned collected GitHub URL: {did}")
        zero("SELECT count(*) FROM findings f JOIN documents d USING(document_id) WHERE f.publisher_id<>d.publisher_id", "Finding/document publisher mismatch")
        zero("SELECT count(*) FROM engagement_documents ed JOIN engagements e USING(engagement_id) JOIN documents d USING(document_id) WHERE e.publisher_id<>d.publisher_id", "Engagement/document publisher mismatch")
        zero("SELECT count(*) FROM engagement_documents ed JOIN documents d USING(document_id) WHERE d.is_seed", "Seed has an engagement link")
        zero("SELECT count(*) FROM engagements e WHERE e.identity_basis NOT IN ('publisher_competition_metadata','publisher_sca_api_metadata') AND NOT EXISTS (SELECT 1 FROM engagement_documents ed JOIN documents d USING(document_id) WHERE ed.engagement_id=e.engagement_id AND NOT d.is_seed)", "Engagement lacks non-seed evidence")
        zero("SELECT count(*) FROM engagements e WHERE e.identity_basis='publisher_sca_api_metadata' AND (e.publisher_id<>'hacken' OR json_extract_string(e.evidence,'$.audit_type')<>'SCA' OR NOT coalesce(json_extract(e.evidence,'$.metadata_only')::BOOLEAN,false) OR NOT starts_with(json_extract_string(e.evidence,'$.source_url'),'https://hacken.io/a/') OR EXISTS(SELECT 1 FROM engagement_documents ed WHERE ed.engagement_id=e.engagement_id))", "Metadata SCA lacks official identity/public evidence")
        zero("SELECT count(*) FROM engagements e WHERE e.identity_basis='publisher_competition_metadata' AND (e.publisher_id<>'immunefi' OR NOT coalesce(json_extract(e.evidence,'$.metadata_only')::BOOLEAN,false) OR EXISTS (SELECT 1 FROM engagement_documents ed WHERE ed.engagement_id=e.engagement_id) OR NOT EXISTS (SELECT 1 FROM contests c WHERE c.engagement_id=e.engagement_id AND c.publisher_id=e.publisher_id AND c.platform_contest_id=json_extract_string(e.evidence,'$.contest_id') AND json_extract_string(c.provenance,'$.source_row.engagement_evidence_url')=json_extract_string(e.evidence,'$.source_url')))", "Metadata competition lacks exact official identity/public evidence")
        zero("SELECT count(*) FROM engagements WHERE identity_status='confirmed' AND industry_engagement_id IS NULL", "Confirmed engagement lacks industry identity")
        if con.execute("SELECT count(*) FROM document_exclusions").fetchone()[0] or con.execute("SELECT count(*) FROM engagements WHERE identity_basis='phase3_deterministic_evidence_group'").fetchone()[0]:
            zero("SELECT count(*) FROM (SELECT d.document_id FROM documents d LEFT JOIN engagement_documents ed USING(document_id) LEFT JOIN document_exclusions x USING(document_id) GROUP BY d.document_id HAVING count(ed.engagement_id) + count(DISTINCT x.document_id) <> 1)", "Document must map to exactly one engagement or exclusion")
            zero("SELECT count(*) FROM (SELECT engagement_id FROM engagement_documents GROUP BY engagement_id HAVING count(*) FILTER(WHERE role='primary')<>1)", "Engagement must have exactly one primary document")
            zero("SELECT count(*) FROM (SELECT e.engagement_id,json_array_length(e.evidence,'$.documents') AS recorded,count(ed.document_id) AS linked FROM engagements e JOIN engagement_documents ed USING(engagement_id) WHERE e.identity_basis='phase3_deterministic_evidence_group' GROUP BY e.engagement_id,e.evidence HAVING recorded<>linked)", "Engagement identity evidence/link count mismatch")
            zero("SELECT count(*) FROM documents WHERE source_family='discovery' AND (json_extract(provenance,'$.attribution_basis.kind') IS NULL OR url_kind<>'discovery')", "Discovery lacks attribution evidence")
            zero("SELECT count(*) FROM date_claims dc JOIN documents d USING(document_id) WHERE d.doc_kind='fix_review' AND dc.eligible_for_audit_year", "Fix review supplies an initial audit date")
            eligible_claims=defaultdict(list)
            for eid,cid,value,role in con.execute("SELECT ed.engagement_id,dc.claim_id,dc.date_value,dc.role FROM date_claims dc JOIN engagement_documents ed USING(document_id) WHERE eligible_for_audit_year UNION ALL SELECT engagement_id,claim_id,date_value,role FROM date_claims WHERE engagement_id IS NOT NULL AND eligible_for_audit_year").fetchall():
                eligible_claims[eid].append((cid,value,role))
            for eid,raw in con.execute("SELECT engagement_id,evidence FROM engagements WHERE identity_basis='phase3_deterministic_evidence_group'").fetchall():
                resolved=json.loads(raw).get('resolved_date')
                if resolved is None: continue  # Earlier reproducible snapshots predate Phase 3c.
                preferred=eligible_claims[eid]
                priorities={'audit_completion':0,'report_issue':1,'review_year':2,'audit_year_inference':3}
                role=min((c[2] for c in preferred),key=lambda r:priorities[r],default='report_issue')
                preferred=[c for c in preferred if c[2]==role]
                values={c[1] for c in preferred}
                value=next(iter(values)) if len(values)==1 else None
                require(resolved['value']==value and resolved['claim_ids']==sorted(c[0] for c in preferred) and resolved['conflict']==(len(values)>1),f"Resolved date disagrees with preferred source claims: {eid}")
            for field in ['firm','client','report_title','version','audit_type','chains','languages','repositories','commits','co_auditors']:
                zero(f"SELECT count(*) FROM documents WHERE NOT is_seed AND (json_extract(metadata,'$.{field}.method') IS NULL OR json_extract(metadata,'$.{field}.confidence') IS NULL)", f"Phase 3 field method/confidence missing: {field}")
        zero("SELECT count(*) FROM contests c JOIN publishers p USING(publisher_id) WHERE p.publisher_kind<>'contest_platform'", "Contest publisher is not a platform")
        zero("SELECT count(*) FROM contests WHERE (timing_status='source_conflict') IS DISTINCT FROM (start_utc IS NOT NULL AND end_utc IS NOT NULL AND start_utc>end_utc)","Unflagged or spurious contest timing conflict")
        zero("SELECT count(*) FROM date_claims dc JOIN contests c ON json_extract_string(dc.evidence,'$.assertion.contest_id')=c.contest_id WHERE c.timing_status='source_conflict' AND dc.eligible_for_audit_year","Conflicting contest interval used as audit date")
        zero("SELECT count(*) FROM date_claims dc JOIN contests c ON json_extract_string(dc.evidence,'$.assertion.contest_id')=c.contest_id WHERE c.format='mitigation' AND (dc.eligible_for_audit_year OR dc.role<>'retest')","Mitigation contest end used as initial audit date")
        # A private/other platform listing can host another scoped firm's
        # authored report. Keep the platform row and require the exact retained
        # collector attribution plus the source-named author receipt. A bare
        # publisher mismatch or a wrong report hash still fails.
        zero("SELECT count(*) FROM contests c JOIN documents d USING(document_id) WHERE (c.publisher_id<>d.publisher_id AND NOT coalesce(c.format IN ('private','other') AND json_extract_string(d.provenance,'$.phase3c_collected_publisher_id')=c.publisher_id AND json_extract_string(d.metadata,'$.auditor_attribution.value')=d.publisher_id AND json_extract_string(d.metadata,'$.auditor_attribution.method')='source_named_auditor_brand_policy_v2',false)) OR (c.sha256 IS NOT NULL AND d.sha256 IS NOT NULL AND c.sha256<>d.sha256)", "Contest/document mismatch")
        zero("SELECT count(*) FROM documents WHERE is_seed AND (sha256 IS NOT NULL OR counting_role<>'seed')", "Seed promoted to original or report denominator")
        flagged_date_conflicts=0
        for cid,value,end,precision,eligible,evidence in con.execute("SELECT claim_id,date_value,date_end,precision,eligible_for_audit_year,evidence FROM date_claims").fetchall():
            for v in [value,end]:
                if v is None:
                    continue
                try:
                    require(bool(re.fullmatch(r'\d{4}(?:-\d{2}(?:-\d{2})?)?',v)),f"Invalid ISO date {cid}")
                    day=date.fromisoformat(v+{4:'-01-01',7:'-01',10:''}[len(v)])
                    require(date(2000,1,1)<=day<=as_of,f"Date outside corpus range {cid}: {v}")
                except (ValueError,KeyError):
                    require(False,f"Invalid date {cid}: {v}")
            require((value is None and precision=='none') or (value is not None and {4:'year',7:'month',10:'day'}.get(len(value))==precision),f"Date precision mismatch {cid}")
            if value and end:
                if value>end:
                    issues=(json.loads(evidence).get('assertion') or {}).get('issues',[])
                    require('end_precedes_start_in_source' in issues and not eligible,f"Unflagged reversed date interval {cid}")
                    flagged_date_conflicts+=1
        for table,col in [('documents','retrieved_utc'),('contests','start_utc'),('contests','end_utc')]:
            completed="(report_url IS NOT NULL OR document_id IS NOT NULL)" if table=='contests' else 'true'
            n=con.execute(f"SELECT count(*) FROM {table} WHERE {col} IS NOT NULL AND (CAST({col} AS DATE) < DATE '2000-01-01' OR (CAST({col} AS DATE)> ? AND {completed}))",[as_of]).fetchone()[0]
            require(n==0,f"Timestamp outside corpus range {table}.{col}: {n}")

        firm=json.loads((root/'docs/inventory/firm_datasets_summary.json').read_text())
        require(set(firm['totals_selected_exports']['selected'])==set(EXPORTS),"Kept exports differ from inventory")
        reconciled=[]
        for name in EXPORTS:
            expected=firm['exports'][name]
            tag='firm:'+name
            metrics={
                'report_rows_total':con.execute("SELECT count(*) FROM documents WHERE source_tag=?",[tag]).fetchone()[0],
                'primary_reports':con.execute("SELECT count(*) FROM documents WHERE source_tag=? AND counting_role='primary'",[tag]).fetchone()[0],
                'finding_rows_total':con.execute("SELECT count(*) FROM findings WHERE source_tag=?",[tag]).fetchone()[0],
                'primary_finding_rows':con.execute("SELECT count(*) FROM findings f JOIN documents d USING(document_id) WHERE f.source_tag=? AND d.counting_role='primary'",[tag]).fetchone()[0],
                'primary_reports_with_finding_rows':con.execute("SELECT count(DISTINCT document_id) FROM findings f JOIN documents d USING(document_id) WHERE f.source_tag=? AND d.counting_role='primary'",[tag]).fetchone()[0],
                'distinct_primary_sha256':con.execute("SELECT count(DISTINCT sha256) FROM documents WHERE source_tag=? AND counting_role='primary'",[tag]).fetchone()[0],
                'primary_reports_without_sha256':con.execute("SELECT count(*) FROM documents WHERE source_tag=? AND counting_role='primary' AND sha256 IS NULL",[tag]).fetchone()[0],
            }
            for key,value in metrics.items():
                require(value==expected[key],f"{name}.{key}: imported {value}, triage {expected[key]}")
            # The inventory froze the article-v1 buckets. Reconcile those from
            # retained labels, then validate the current publisher policy below.
            historical={'critical':'critical','high':'high','major':'high','medium':'medium','low':'low','minor':'low',
                        'info':'info','informational':'info','nitpick':'info','best_practice':'info','gas':'gas','gas_optimization':'gas'}
            distribution=Counter()
            for raw,normalized in con.execute("SELECT severity_raw,severity_source_normalized FROM findings f JOIN documents d USING(document_id) WHERE f.source_tag=? AND d.counting_role='primary'",[tag]).fetchall():
                value=normalized if normalized is not None else raw
                key=re.sub(r'[\s-]+','_',str(value or '').strip().lower())
                distribution[historical.get(key,'unknown')]+=1
            require(distribution==expected['severity_proposed_article'],f"{name} severity distribution: {distribution} != {expected['severity_proposed_article']}")
            if publisher_severity_mapping is None:
                actual_distribution=dict(con.execute("SELECT severity,count(*) FROM findings f JOIN documents d USING(document_id) WHERE f.source_tag=? AND d.counting_role='primary' GROUP BY 1",[tag]).fetchall())
                require(actual_distribution==expected['severity_proposed_article'],f"{name} severity distribution: {actual_distribution} != {expected['severity_proposed_article']}")
            reconciled.append({'export':name,'primary_reports':metrics['primary_reports'],'primary_findings':metrics['primary_finding_rows']})
        require(sum(r['primary_reports'] for r in reconciled)==firm['totals_selected_exports']['primary_report_rows'],"Firm primary report grand total")
        require(sum(r['primary_findings'] for r in reconciled)==firm['totals_selected_exports']['primary_finding_rows'],"Firm primary finding grand total")
        severity_errors=0
        for fid,publisher,raw,normalized,kind,original,actual,mapping in con.execute("SELECT f.finding_id,f.publisher_id,f.severity_raw,f.severity_source_normalized,f.record_kind,d.sha256,f.severity,f.severity_mapping FROM findings f LEFT JOIN documents d USING(document_id)").fetchall():
            if publisher_severity_mapping is None:
                if json.loads(mapping).get('policy')!='article-v1': severity_errors+=1
                continue
            value=raw if raw is not None else normalized
            expected_map=publisher_severity_mapping(value,publisher,kind=kind,sha256=original,log=False)
            receipt=json.loads(mapping)
            if actual!=expected_map['normalized'] or any(receipt.get(k)!=v for k,v in expected_map.items() if k!='raw'):
                severity_errors+=1
        require(severity_errors==0,f"Current publisher severity distribution/receipt mismatch: {severity_errors}")

        audit=json.loads((root/'docs/inventory/audit_analysis_summary.json').read_text())
        # Reconcile the entire input census, then the independently triaged scoped subset.
        for kind in ['reports','findings']:
            n=con.execute("SELECT coalesce(sum(source_rows),0) FROM import_sources WHERE source_family='audit_analysis' AND row_kind=?",[kind]).fetchone()[0]
            require(n==audit['validation'][kind]['rows'],f"audit_analysis input {kind}: {n} != {audit['validation'][kind]['rows']}")
            expected=Counter()
            for row in audit['industry']['firms']:
                p=aliases.get(norm(row['normalized_firm']))
                if p:
                    expected[p]+=row[kind]
            expected=+expected
            actual=Counter(dict(con.execute(f"SELECT publisher_id,count(*) FROM {'documents' if kind=='reports' else 'findings'} WHERE source_family='audit_analysis' GROUP BY 1").fetchall()))
            require(actual==expected,f"audit_analysis scoped {kind} differences: "+str({p:(actual[p],expected[p]) for p in actual.keys()|expected.keys() if actual[p]!=expected[p]}))

        changed_collection=[]
        ledger_columns=[r[0] for r in con.execute('DESCRIBE import_sources').fetchall()]
        ledgers=[dict(zip(ledger_columns,r)) for r in con.execute('SELECT * FROM import_sources').fetchall()]
        frozen_files={r['path']:r for r in audit.get('parquet_files',[])}
        metadata_sources=set()
        for raw, in con.execute('SELECT evidence FROM engagements').fetchall():
            metadata_sources.update(metadata_receipts(json.loads(raw)))
        for entry in ledgers:
            path=root/entry['source_file']
            if not path.is_file():
                require(False,f"Missing input snapshot source: {entry['source_file']}")
                continue
            observed=hashlib.sha256(path.read_bytes()).hexdigest()
            if observed!=entry['file_sha256']:
                if entry['source_family'] in {'collected','discovery'}:
                    changed_collection.append(entry['source_file'])
                else:
                    require(False,f"Frozen source hash changed: {entry['source_file']}")
            if entry['row_kind']=='date_overrides':
                n=con.execute("SELECT count(*) FROM date_claims WHERE json_extract_string(evidence,'$.source_record.source_file')=?",[entry['source_file']]).fetchone()[0]
            elif entry['row_kind']=='engagement_metadata':
                actual_receipts={(locator,sha) for source,locator,sha in metadata_sources if source==entry['source_file']}
                eligible={(f'line={i}',hashlib.sha256(json.dumps(r,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest())
                    for i,line in enumerate(path.read_text().split('\n'),1) if line.strip()
                    for r in [json.loads(line)] if entry['source_tag']!='audit_metadata:hacken' or r.get('audit_type')=='SCA'}
                require(actual_receipts==eligible,'Metadata source receipts differ: '+entry['source_file'])
                n=len(actual_receipts)
            else:
                table={'reports':'documents','findings':'findings','contests':'contests'}[entry['row_kind']]
                n=con.execute(f'SELECT count(*) FROM {table} WHERE source_file=?',[entry['source_file']]).fetchone()[0]
            require(n==entry['imported_rows'],f"Import ledger/table mismatch: {entry['source_file']}")
            if entry['source_family']=='audit_analysis':
                rel=entry['source_file'].removeprefix('extracted/audit_analysis/')
                frozen=frozen_files.get(rel)
                require(frozen is not None,f"Parquet absent from triage inventory: {rel}")
                if frozen:
                    require(entry['file_sha256']==frozen['sha256'] and entry['source_rows']==frozen['rows'],f"Parquet differs from triage snapshot: {rel}")
        collected_snapshot={r['source_file'] for r in ledgers if r['source_family'] in {'collected','discovery'}}
        current={p.relative_to(root).as_posix() for pattern in ['*/reports.jsonl','*/contests.jsonl'] for p in (root/'data/collect').glob(pattern) if p.parent.name in publishers}
        current |= {p.relative_to(root).as_posix() for p in (root/'data/discovery').glob('*/candidates.jsonl')}
        summary=count_summary(con)
        summary['flagged_source_date_conflicts']=flagged_date_conflicts
        summary['flagged_collector_date_hints']=con.execute("SELECT count(*) FROM date_claims WHERE source_tag LIKE 'collect:%' AND json_contains(evidence, '\"invalid_date_hint_or_precision\"')").fetchone()[0]
        summary['flagged_contest_timing_conflicts']=con.execute("SELECT count(*) FROM contests WHERE timing_status='source_conflict'").fetchone()[0]
        summary['scheduled_contests_without_reports']=con.execute("SELECT count(*) FROM contests WHERE report_url IS NULL AND document_id IS NULL AND (start_utc::DATE>? OR end_utc::DATE>?)",[as_of,as_of]).fetchone()[0]
        summary['reconciliation']=reconciled
        summary['collection_files_new_or_changed']=sorted(set(changed_collection)|(current-collected_snapshot))
        if errors:
            raise CheckError('\n'.join(errors))
        summary['check']='PASS'
        return summary
    finally:
        con.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=ROOT)
    parser.add_argument('--db',type=Path)
    parser.add_argument('--as-of',type=date.fromisoformat)
    parser.add_argument('--json',action='store_true',help='Print full machine-readable counts and reconciliation')
    args=parser.parse_args()
    try:
        summary=check(args.root,args.db,args.as_of)
        print(json.dumps(summary,indent=2)) if args.json else print_summary(summary)
    except CheckError as exc:
        print('FAIL\n'+str(exc),file=sys.stderr)
        raise SystemExit(1)


if __name__=='__main__':
    main()
