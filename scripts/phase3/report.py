#!/usr/bin/env python3
"""Generate Phase 3 counts and coverage from a checked DuckDB snapshot."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

import duckdb

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'scripts/build'))
from metadata_rules import atomic, canonical


def report(root=ROOT, db=None, data_only=False):
    con = duckdb.connect(str(db or root/'data/corpus.duckdb'), read_only=True)
    def scalar(sql):
        return con.execute(sql).fetchone()[0]
    stats = {t:scalar('SELECT count(*) FROM '+t) for t in ['documents','engagements','engagement_documents','document_exclusions','counted_engagements','industry_engagements']}
    stats['collected_occurrences'] = scalar("SELECT count(*) FROM documents WHERE source_family='collected'")
    stats['collected_unique_sha256'] = scalar("SELECT count(DISTINCT sha256) FROM documents WHERE source_family='collected'")
    stats['discovery_added'] = scalar("SELECT count(*) FROM documents WHERE source_family='discovery'")
    stats['discovery_already_represented'] = scalar("SELECT coalesce(sum(duplicate_rows),0) FROM import_sources WHERE source_family='discovery'")
    stats['engagements_without_acquired_document'] = scalar("SELECT count(*) FROM engagements e WHERE NOT EXISTS(SELECT 1 FROM engagement_documents ed JOIN documents d USING(document_id) WHERE ed.engagement_id=e.engagement_id AND d.source_family<>'discovery')")
    stats['maximum_audit_year_pct_if_all_acquired_dated'] = round((stats['engagements']-stats['engagements_without_acquired_document'])/max(stats['engagements'],1)*100,2)
    stats['audit_year_known'] = scalar('SELECT count(*) FROM engagements JOIN engagement_years USING(engagement_id) WHERE audit_year IS NOT NULL')
    stats['confirmed_audit_year_known'] = scalar('SELECT count(*) FROM counted_engagements JOIN engagement_years USING(engagement_id) WHERE audit_year IS NOT NULL')
    stats['publication_year_known'] = scalar('SELECT count(*) FROM engagements JOIN engagement_publication_years USING(engagement_id) WHERE publication_year IS NOT NULL')
    stats['any_claim_year_known'] = scalar("SELECT count(DISTINCT e.engagement_id) FROM engagements e JOIN engagement_documents ed USING(engagement_id) JOIN date_claims dc USING(document_id) WHERE date_value IS NOT NULL")
    stats['unmapped_or_multiply_mapped'] = scalar("SELECT count(*) FROM (SELECT d.document_id FROM documents d LEFT JOIN engagement_documents ed USING(document_id) LEFT JOIN document_exclusions x USING(document_id) GROUP BY d.document_id HAVING count(ed.engagement_id)+count(DISTINCT x.document_id)<>1)")
    stats['link_roles'] = dict(con.execute('SELECT role,count(*) FROM engagement_documents GROUP BY role ORDER BY role').fetchall())
    stats['collected_identical_byte_excess_occurrences'] = scalar("SELECT count(*)-count(DISTINCT (publisher_id,sha256)) FROM documents WHERE source_family='collected' AND sha256 IS NOT NULL")
    stats['multi_document_engagements'] = scalar('SELECT count(*) FROM (SELECT engagement_id FROM engagement_documents GROUP BY 1 HAVING count(*)>1)')
    stats['cross_format_engagements'] = scalar('SELECT count(*) FROM (SELECT engagement_id FROM engagement_documents JOIN documents USING(document_id) GROUP BY 1 HAVING count(DISTINCT file_format)>1)')
    stats['fix_reviews_linked'] = scalar("SELECT count(*) FROM engagement_documents JOIN documents USING(document_id) WHERE doc_kind='fix_review'")
    stats['exclusions'] = dict(con.execute('SELECT reason,count(*) FROM document_exclusions GROUP BY reason ORDER BY reason').fetchall())
    stats['text_status'] = dict(con.execute("SELECT json_extract_string(metadata,'$.text_receipt.status'),count(*) FROM documents WHERE source_family='collected' GROUP BY 1 ORDER BY 1").fetchall())
    stats['identity_status'] = dict(con.execute('SELECT identity_status,count(*) FROM engagements GROUP BY 1 ORDER BY 1').fetchall())
    stats['field_coverage'] = {}
    for key in ['firm','client','report_title','version','audit_type','chains','languages','repositories','commits','co_auditors']:
        count = con.execute("SELECT count(DISTINCT ed.engagement_id) FROM engagement_documents ed JOIN documents d USING(document_id) WHERE json_extract(d.metadata, ?) IS NOT NULL AND json_extract(d.metadata, ?) <> 'null'::JSON", ['$.%s.value'%key]*2).fetchone()[0]
        stats['field_coverage'][key] = {'engagements':count,'pct':round(count/max(stats['engagements'],1)*100,2)}
    for metric, num, den in [('audit_year_pct','audit_year_known','engagements'),('confirmed_audit_year_pct','confirmed_audit_year_known','counted_engagements'),('publication_year_pct','publication_year_known','engagements'),('any_claim_year_pct','any_claim_year_known','engagements')]:
        stats[metric] = round(stats[num]/max(stats[den],1)*100,2)
    stats['year_target_met'] = (stats['audit_year_known']*100 >= stats['engagements']*85 and
                                stats['confirmed_audit_year_known']*100 >= stats['counted_engagements']*95)
    stats['firm_counts'] = [dict(zip(['publisher_id','engagements','confirmed','completion_or_issue_known','publication_known'],r)) for r in con.execute("SELECT p.publisher_id,count(e.engagement_id),count(e.engagement_id) FILTER(WHERE identity_status='confirmed'),count(audit_year),count(publication_year) FROM publishers p LEFT JOIN engagements e USING(publisher_id) LEFT JOIN engagement_years y USING(engagement_id) LEFT JOIN engagement_publication_years py USING(engagement_id) GROUP BY 1 ORDER BY 1").fetchall()]
    stats['year_counts'] = {}
    for table,col in [('engagement_years','audit_year'),('engagement_publication_years','publication_year')]:
        stats['year_counts'][col] = [dict(zip(['year','all_engagements','confirmed'],r)) for r in con.execute(f"SELECT coalesce({col}::VARCHAR,'unknown'),count(*),count(*) FILTER(WHERE identity_status='confirmed') FROM {table} JOIN engagements USING(engagement_id) GROUP BY 1 ORDER BY 1").fetchall()]
    # Exports permit reproducible review without shipping report text or originals.
    outputs = {
        'engagements.jsonl': "SELECT e.*,y.audit_year,y.year_conflict,py.publication_year FROM engagements e JOIN engagement_years y USING(engagement_id) JOIN engagement_publication_years py USING(engagement_id) ORDER BY engagement_id",
        'engagement_documents.jsonl': "SELECT ed.*,d.publisher_id,d.sha256,d.public_url,d.wayback_url,d.source_family AS source,d.title,d.project,d.metadata FROM engagement_documents ed JOIN documents d USING(document_id) ORDER BY engagement_id,document_id",
        'document_exclusions.jsonl': 'SELECT * FROM document_exclusions ORDER BY document_id',
        'date_claims.jsonl': "SELECT dc.* FROM date_claims dc LEFT JOIN documents d USING(document_id) WHERE dc.engagement_id IS NOT NULL OR (dc.document_id IS NOT NULL AND NOT d.is_seed) ORDER BY claim_id",
    }
    for name,sql in outputs.items():
        cursor = con.execute(sql)
        columns = [c[0] for c in cursor.description]
        json_columns={i for i,c in enumerate(cursor.description) if str(c[1])=='JSON'}
        atomic(root/'data/phase3'/name, ''.join(canonical(dict(zip(columns,[json.loads(v) if i in json_columns and v is not None else v for i,v in enumerate(r)])))+'\n' for r in cursor.fetchall()))
    atomic(root/'data/phase3/summary.json', json.dumps(stats,indent=2,sort_keys=True)+'\n')
    if data_only:
        con.close()
        return stats
    lines = ['# Phase 3 engagement metadata and deduplication', '',
             'Generated offline by `scripts/phase3/report.py` from the current database input snapshot. Rebuild with `python -I scripts/build/build_db.py`, run `check_db.py`, then rerun this script. All counts include explicit unknown buckets.', '',
             f"Documents: **{stats['documents']:,}**; collected occurrences: **{stats['collected_occurrences']:,}**, unique collected SHA-256: **{stats['collected_unique_sha256']:,}**. Documents linked: **{stats['engagement_documents']:,}**; explicitly excluded: **{stats['document_exclusions']:,}**; unmapped/multiply mapped: **{stats['unmapped_or_multiply_mapped']:,}**.", '',
             f"Engagements per publisher: **{stats['engagements']:,}**, including **{stats['counted_engagements']:,} confirmed** and **{stats['identity_status'].get('provisional',0):,} provisional**. Confirmed industry identities: **{stats['industry_engagements']:,}**. Discovery: **{stats['discovery_added']:,}** additional occurrences and **{stats['discovery_already_represented']:,}** candidates already represented.", '',
             f"Completion/issue year coverage: **{stats['audit_year_pct']:.2f}%** of all engagements; **{stats['confirmed_audit_year_pct']:.2f}%** of confirmed engagements. Publication year coverage: **{stats['publication_year_pct']:.2f}%**. Any dated claim (including filename/catalog hints): **{stats['any_claim_year_pct']:.2f}%**; this is not audit-year coverage.", '',
             f"**Phase 3b audit-year finish line (85% overall; 95% confirmed): {'PASS' if stats['year_target_met'] else 'NOT MET'}.** Undated reports and discovery-only evidence remain in the denominator. No crawl/commit timestamp, filename date, or catalog claim is promoted into an audit date.", '',
             f"There are **{stats['engagements_without_acquired_document']:,} engagements without an acquired original**. Even if every acquired group received a usable date, current discovery-only evidence would limit overall audit-year coverage to **{stats['maximum_audit_year_pct_if_all_acquired_dated']:.2f}%**.", '',
             'Metadata extraction uses the opening pages; date extraction always uses the verified complete text/OCR cache when available, including source-explicit timelines and revision tables. A cover issue date cannot hide a later explicit completion. Cached findings text is preserved; date-page OCR has separate receipts. Each extracted field records method and evidence; PDF dates retain pages and text offsets. Missing locators stay null. `engagements.evidence.resolved_date` records the preferred date, precision, role and any conflict. Confidence scores are rule strength, not measured accuracy. See `docs/phase3/fixes_identity_review.md` for the current before/after report.', '',
             'Merges use original-byte identity, source-explicit alternatives, canonical report routes, normalized report stems/text with date or audited-commit support, matching audited scope and substantive content, or explicit report-family declarations. Implementation/team components, split submodules, additional deliverables, revisions and translations retain their evidence. A component-wide scope guard rejects disjoint substantive implementation assets; proxy/library overlap is insufficient. Fix and mitigation reviews attach as supporting documents to a supported parent and cannot supply initial audit dates. Independent audit rounds are retained. Source-named project entities and scope/domain evidence for cadence are stored separately from display names. See `docs/phase3/fixes_identity_scope.md` for the current identity and chronology changes. Identity anchors and merge redirects persist in `data/phase3/identity_map.json`; later merges retain the earliest allocated identity. Wrong-source/non-report artifacts are excluded explicitly; unacquired or unsupported report leads stay provisional. Legacy audit-analysis seeds never count as acquisitions.', '',
             'The holdout hash list suppresses development examples and LLM requests. Deterministic extraction applies the same rules to available caches, including held-out artifacts. No independent labelled accuracy evaluation is claimed.', '',
             '## Engagements per publisher', '', '| Publisher | All | Confirmed | Completion/issue year known | Publication year known |','|---|---:|---:|---:|---:|']
    lines += ['| {publisher_id} | {engagements} | {confirmed} | {completion_or_issue_known} | {publication_known} |'.format(**r) for r in stats['firm_counts']]
    for key,title in [('audit_year','Completion year (issue year when completion is absent)'),('publication_year','Publication year')]:
        lines += ['', '## '+title, '', '| Year | All engagements | Confirmed |','|---|---:|---:|']
        lines += [f"| {r['year']} | {r['all_engagements']} | {r['confirmed']} |" for r in stats['year_counts'][key]]
        if not any(r['year']=='unknown' for r in stats['year_counts'][key]):
            lines += ['| unknown | 0 | 0 |']
    lines += ['', '## Field coverage', '', 'An engagement is covered if at least one linked occurrence has a supported non-null value. Mention-based chain/language fields retain their lower confidence and do not establish an audited deployment.', '', '| Field | Engagements | Coverage |','|---|---:|---:|']
    lines += [f"| {k} | {v['engagements']} | {v['pct']:.2f}% |" for k,v in stats['field_coverage'].items()]
    lines += ['', '## Deduplication and exclusions', '',
              f"Collected same-publisher byte-identical excess occurrences: **{stats['collected_identical_byte_excess_occurrences']:,}**. Multi-document engagements: **{stats['multi_document_engagements']:,}**; groups containing multiple formats: **{stats['cross_format_engagements']:,}**; fix reviews linked to parents: **{stats['fix_reviews_linked']:,}**.", '',
              '| Link role | Documents |','|---|---:|']
    lines += [f'| {k} | {v} |' for k,v in stats['link_roles'].items()]
    lines += ['', '| Exclusion reason | Documents |','|---|---:|']
    lines += [f'| {k} | {v} |' for k,v in stats['exclusions'].items()]
    lines += ['', '| Text status (collected occurrences) | Documents |','|---|---:|']
    lines += [f'| {k} | {v} |' for k,v in stats['text_status'].items()]
    atomic(root/'docs/phase3/engagements.md', '\n'.join(lines)+'\n')
    # Deliverable/source inventory plus locally generated cache and environment paths.
    written = set('schema/README.md schema/corpus.sql scripts/build/build_db.py scripts/build/check_db.py scripts/build/metadata_rules.py scripts/build/phase3_engagements.py scripts/phase3/requirements.txt scripts/phase3/profile_inputs.py scripts/phase3/diagnose.py scripts/phase3/extract_metadata.py scripts/phase3/report.py tests/test_build.py tests/test_phase3.py docs/phase3/engagements.md data/corpus.duckdb data/phase3/files_written.txt'.split())
    written.update(p.relative_to(root).as_posix() for p in (root/'data/phase3').glob('*') if p.is_file())
    for receipt in (root/'local-cache/text').glob('*.receipt.json'):
        written.add(receipt.relative_to(root).as_posix())
        text_path=receipt.with_name(receipt.name.removesuffix('.receipt.json')+'.txt')
        if text_path.exists():
            written.add(text_path.relative_to(root).as_posix())
    written.update(p.relative_to(root).as_posix() for p in (root/'local-cache/phase3-venv').rglob('*') if p.is_file())
    written.update(p.relative_to(root).as_posix() for p in (root/'local-cache').glob('phase3-*') if p.is_file())
    atomic(root/'data/phase3/files_written.txt','\n'.join(sorted(written))+'\n')
    con.close()
    print(canonical({k:v for k,v in stats.items() if k not in {'firm_counts','year_counts'}}))
    return stats


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=ROOT)
    p.add_argument('--db', type=Path)
    p.add_argument('--data-only',action='store_true',help='Refresh data without rewriting existing phase documentation')
    args = p.parse_args()
    report(args.root,args.db,args.data_only)
