"""Synthetic tests for metadata semantics and evidence-based identity changes."""
from copy import deepcopy
from datetime import date
import hashlib
import json
from pathlib import Path
import sys

import duckdb
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/build'))
from build_db import build
from check_db import check, CheckError
from make_fixture import materialize
from metadata_rules import date_claims, extract_intrinsic, embedded_report, parse_date, read_text


def add_report(root, filename, text, kind='audit_report'):
    path=root/'data/collect/shieldify/reports.jsonl'
    row=json.loads(path.read_text().splitlines()[0])
    digest=hashlib.sha256(text.encode()).hexdigest()
    row.update(filename=filename, public_url='https://example.org/'+filename, sha256=digest,
               file_format='md', project_hint='Protocol', title_hint='Protocol Review', doc_kind=kind)
    cache=root/'local-cache/text'/(digest+'.txt')
    cache.parent.mkdir(parents=True,exist_ok=True)
    cache.write_text(text)
    with path.open('a') as f:
        f.write(json.dumps(row)+'\n')
    return digest


def test_date_semantics_and_pages():
    text='Protocol Security Assessment\nJanuary 3, 2024\fAudit completed: December 30, 2023\nPublication date: January 6, 2024\n© 2022 Vendor'
    claims=date_claims(text, {'pages':[1,2]})
    assert {(c['date_value'],c['role'],c['page']) for c in claims}=={
        ('2024-01-03','report_issue',1),('2023-12-30','audit_completion',2),('2024-01-06','publication',2)}
    assert parse_date('04/05/2024')==(None,'none')
    assert parse_date('25/05/2024')==('2024-05-25','day')
    assert parse_date('2099-01-01')==(None,'none')
    unrelated=date_claims('The compiler was released in October 2015.\nOn 2024.01.03 the team received an audit application.', {'pages':[1]})
    assert all(c['role']=='other' for c in unrelated)


def test_embedded_report_is_data():
    content={'reportContent':{'setup':{'projectName':'Test', 'repos':[{'repoLink':'https://github.com/test/project','commit':'a'*40}]},
                              'summary':{'timeline':{'start':'2024-01-01','end':'2024-01-10'},'languages':{'Rust':True,'Go':False}}}}
    literal=json.dumps(content).replace('\\','\\\\').replace("'","\\'")
    meta=extract_intrinsic("untrusted(); JSON.parse('"+literal+"'); also_untrusted();", {'status':'ok','method':'utf8_text'})
    assert meta['structured_report']
    assert meta['client']['value']=='Test'
    assert meta['languages']['value']==['Rust']
    assert meta['commits']['value']==['a'*40]
    assert any(c['date_value']=='2024-01-10' and c['role']=='audit_completion' for c in meta['dates'])
    assert embedded_report("JSON.parse(fetch('/private'))") is None


def test_abbreviated_period_and_dated_heading():
    claims=date_claims('Date of Engagement: May 19th-31st, 2021\fAudit Report for Project. May 20, 2021.\nAmended [28.05.2021]',{'pages':[1,2]})
    assert {(c['date_value'],c['role']) for c in claims} >= {('2021-05-19','audit_start'),('2021-05-31','audit_completion'),('2021-05-20','report_issue')}
    assert all(c['role']=='other' for c in claims if c['date_value']=='2021-05-28')
    claims=date_claims('Timeline: 2026-01-12 → 2026-02-02',{'pages':[1]})
    assert [c['role'] for c in claims]==['audit_start','audit_completion']


def test_discovery_merge_attribution_and_wayback(tmp_path):
    root=materialize(tmp_path/'input')
    source=json.loads((root/'data/collect/shieldify/reports.jsonl').read_text().splitlines()[0])
    rows=[{'firm_id':'shieldify','candidate_url':source['public_url'],'attribution_basis':{'kind':'publisher_canonical_url'}},
          {'firm_id':'shieldify','candidate_url':'https://example.org/lost.pdf','project_hint':'Lost','wayback_url':'https://web.archive.org/web/20240101000000/https://example.org/lost.pdf','attribution_basis':{'kind':'named_filename'},'date_hint':'2024','date_basis':'filename'},
          {'firm_id':'shieldify','candidate_url':'https://example.org/unattributed.pdf'}]
    path=root/'data/discovery/shieldify/candidates.jsonl'
    path.parent.mkdir(parents=True)
    path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
    build(root)
    assert check(root,as_of=date(2026,10,20))['check']=='PASS'
    with duckdb.connect(str(root/'data/corpus.duckdb')) as con:
        assert con.execute("SELECT count(*) FROM documents WHERE source_family='discovery'").fetchone()[0]==1
        assert con.execute("SELECT wayback_url FROM documents WHERE source_family='discovery'").fetchone()[0]==rows[1]['wayback_url']
        assert con.execute("SELECT identity_status FROM engagements JOIN engagement_documents USING(engagement_id) JOIN documents USING(document_id) WHERE source_family='discovery'").fetchone()[0]=='provisional'
        assert con.execute("SELECT imported_rows,duplicate_rows,excluded_scope_rows FROM import_sources WHERE source_family='discovery'").fetchone()==(1,1,1)


def test_renderings_versions_and_stable_append(tmp_path):
    root=materialize(tmp_path/'input')
    first=add_report(root,'Protocol-review-v1.0.md','# Protocol Security Audit\nAudit completed: March 3, 2024\nCommit: '+'a'*40)
    build(root)
    def identities():
        with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
            return dict(con.execute('SELECT sha256,engagement_id FROM documents JOIN engagement_documents USING(document_id) WHERE sha256 IS NOT NULL').fetchall())
    before=identities()
    second=add_report(root,'Protocol-review-v2.0.md','# Protocol Security Audit\nVersion: 2.0\nAudit completed: March 3, 2024\nCommit: '+'a'*40)
    third=add_report(root,'Protocol-review-v3.0.md','# Protocol Security Audit\nAudit completed: March 3, 2025\nCommit: '+'b'*40)
    build(root)
    after=identities()
    assert before[first]==after[first]==after[second]
    assert after[third]!=after[first]
    rendering=add_report(root,'Protocol-audit-report-v2.0.md','# Protocol Security Audit\nDifferent rendering\nAudit completed: March 3, 2024\nCommit: '+'a'*40)
    build(root)
    assert identities()[rendering]==after[first]
    assert check(root,as_of=date(2026,10,20))['check']=='PASS'
    with duckdb.connect(str(root/'data/corpus.duckdb')) as con:
        assert con.execute("SELECT count(*) FROM (SELECT document_id FROM engagement_documents GROUP BY 1 HAVING count(*)>1)").fetchone()[0]==0


def test_fix_review_parent_and_unmatched_exclusion(tmp_path):
    root=materialize(tmp_path/'input')
    parent=add_report(root,'Parent-review.md','# Parent Security Audit\nAudit completed: May 3, 2024')
    fix=add_report(root,'Parent-fixes.md','# Parent Fix Review\nOriginal audit report: https://example.org/Parent-review.md\nRetest: June 2, 2024','fix_review')
    orphan=add_report(root,'Other-fixes.md','# Other Fix Review\nRetest: June 3, 2024','fix_review')
    build(root)
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        rows=dict(con.execute('SELECT sha256,engagement_id FROM documents JOIN engagement_documents USING(document_id)').fetchall())
        assert rows[parent]==rows[fix]
        assert con.execute('SELECT role FROM engagement_documents JOIN documents USING(document_id) WHERE sha256=?',[fix]).fetchone()[0]=='supporting'
        assert con.execute('SELECT reason FROM document_exclusions JOIN documents USING(document_id) WHERE sha256=?',[orphan]).fetchone()[0]=='fix_review_parent_not_identified'
    assert check(root,as_of=date(2026,10,20))['check']=='PASS'


def test_shared_report_industry_identity(tmp_path):
    root=materialize(tmp_path/'input')
    digest=add_report(root,'Joint-review.md','# Joint Security Audit\nAudit completed: May 3, 2024')
    source=root/'data/collect/shieldify/reports.jsonl'
    row=json.loads(source.read_text().splitlines()[-1])
    row.update(firm_id='codespect',public_url='https://example.org/client-copy.md')
    path=root/'data/collect/codespect/reports.jsonl'
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(row)+'\n')
    build(root)
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        rows=con.execute('SELECT e.publisher_id,e.engagement_id,e.industry_engagement_id FROM engagements e JOIN engagement_documents ed USING(engagement_id) JOIN documents d USING(document_id) WHERE sha256=?',[digest]).fetchall()
        assert len(rows)==2
        assert len({r[1] for r in rows})==2
        assert len({r[2] for r in rows})==1
    assert check(root,as_of=date(2026,10,20))['check']=='PASS'


def test_first_three_page_cache(tmp_path):
    pdf_module=pytest.importorskip('pymupdf')
    root=tmp_path/'input'
    with pdf_module.open() as pdf:
        for i in range(4):
            page=pdf.new_page()
            page.insert_text((50,50),'Page '+str(i+1)+' sentinel')
        body=pdf.tobytes()
    digest=hashlib.sha256(body).hexdigest()
    path=root/'local-cache/originals'/digest[:2]/(digest+'.pdf')
    path.parent.mkdir(parents=True)
    path.write_bytes(body)
    text,receipt=read_text(root,{'sha256':digest,'file_format':'pdf','local_path':str(path.relative_to(root))})
    assert 'Page 3 sentinel' in text and 'Page 4 sentinel' not in text
    assert receipt['pages']==[1,2,3]
    cache=root/'local-cache/text'/(digest+'.txt')
    before=cache.stat().st_mtime_ns
    assert read_text(root,{'sha256':digest})[0]==text
    assert cache.stat().st_mtime_ns==before


def test_registry_split_has_distinct_stable_ids(tmp_path,monkeypatch):
    import phase3_engagements
    root=materialize(tmp_path/'input')
    a=add_report(root,'Split-protocol-review-v1.0.md','# Protocol Security Audit\nDraft\nAudit completed: May 3, 2024\nCommit: '+'a'*40)
    b=add_report(root,'Split-protocol-review-v2.0.md','# Protocol Security Audit\nFinal\nAudit completed: May 3, 2024\nCommit: '+'a'*40)
    build(root)
    monkeypatch.setattr(phase3_engagements,'stem',lambda doc:doc['document_id'])
    def snapshot():
        with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
            return dict(con.execute('SELECT sha256,engagement_id FROM documents JOIN engagement_documents USING(document_id) WHERE sha256 IN (?,?)',[a,b]).fetchall())
    build(root)
    first=snapshot()
    assert first[a]!=first[b]
    assert check(root,as_of=date(2026,10,20))['check']=='PASS'
    build(root)
    assert snapshot()==first


def test_undated_product_versions_are_not_rendering_aliases(tmp_path):
    root=materialize(tmp_path/'input')
    a=add_report(root,'Protocol-component-v1.0.md','# Protocol Security Audit\nOld product scope')
    b=add_report(root,'Protocol-component-v2.0.pdf','# Protocol Security Audit\nNew product scope')
    path=root/'data/collect/shieldify/reports.jsonl'
    rows=[json.loads(s) for s in path.read_text().splitlines()]
    rows[-1]['file_format']='pdf'
    path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
    build(root)
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        assert con.execute('SELECT count(DISTINCT engagement_id) FROM engagement_documents JOIN documents USING(document_id) WHERE sha256 IN (?,?)',[a,b]).fetchone()[0]==2
