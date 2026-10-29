"""Offline import, provenance, counting and corruption tests using synthetic inputs."""
from datetime import date
import hashlib
import json
from pathlib import Path
import sys

import duckdb
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/build'))
from build_db import Builder, build
from check_db import CheckError, check
from make_fixture import materialize

AS_OF=date(2026,10,20)


@pytest.fixture
def source(tmp_path):
    return materialize(tmp_path/'input')


@pytest.fixture
def built(source):
    build(source)
    return source


def connect(root):
    return duckdb.connect(str(root/'data/corpus.duckdb'))


def test_full_contract_and_reconciliation(built):
    result=check(built,as_of=AS_OF)
    assert result['check']=='PASS'
    assert (result['documents'],result['findings'],result['engagements'],result['contests'])==(12,8,8,1)
    assert result['flagged_source_date_conflicts']==1
    fixture=json.loads((ROOT/'tests/fixtures/foundation.json').read_text())
    with connect(built) as c:
        rows=c.execute("SELECT provenance FROM documents WHERE source_family='collected'").fetchall()
        imported=[json.loads(r[0])['source_row'] for r in rows]
        assert sorted(imported,key=lambda r:r['public_url'])==sorted(fixture['collection_reports'],key=lambda r:r['public_url'])
        contest=c.execute('SELECT findings_high,findings_medium,document_id,engagement_id,provenance FROM contests').fetchone()
        assert contest[:2]==(2,3) and all(contest[2:4])
        assert json.loads(contest[4])['source_row']==fixture['contests'][0]


def test_scope_and_seed_isolation(built):
    with connect(built) as c:
        assert c.execute("SELECT count(*) FROM publishers WHERE publisher_id='certik'").fetchone()[0]==0
        assert c.execute("SELECT count(*) FROM documents WHERE publisher_id='fuzzland'").fetchone()[0]==0
        assert c.execute("SELECT count(*) FROM findings WHERE publisher_id='fuzzland'").fetchone()[0]==0
        assert c.execute("SELECT count(*) FROM documents WHERE is_seed AND sha256 IS NOT NULL").fetchone()[0]==0
        assert c.execute("SELECT count(*) FROM findings WHERE is_seed AND document_id IS NULL").fetchone()[0]==1
        assert c.execute("SELECT count(*) FROM engagement_documents ed JOIN documents d USING(document_id) WHERE d.is_seed").fetchone()[0]==0
        # This foundation fixture has metadata only, without acquired originals.
        assert c.execute('SELECT count(*) FROM counted_engagements').fetchone()[0]==0


def test_alternates_aliases_and_joint_audit_counting(source):
    b=Builder(source)
    b.import_firms()
    b.import_seeds()
    b.import_collections()
    # Simulate reviewed identities before insertion, as a future Phase 3 input would.
    for e in b.tables['engagements'].values():
        if e['publisher_id'] in {'shieldify','codespect'}:
            e.update(identity_status='confirmed',industry_engagement_id='joint-example')
    b.write(source/'data/corpus.duckdb')
    with connect(source) as c:
        assert c.execute("SELECT count(*) FROM engagements WHERE publisher_id='shieldify'").fetchone()[0]==1
        assert c.execute("SELECT count(*) FROM engagement_documents ed JOIN engagements e USING(engagement_id) WHERE e.publisher_id='shieldify'").fetchone()[0]==4
        assert c.execute("SELECT count(*) FROM engagement_documents WHERE role='alternate'").fetchone()[0]==1
        assert c.execute('SELECT count(*) FROM counted_engagements').fetchone()[0]==2
        assert c.execute('SELECT count(*) FROM industry_engagements').fetchone()[0]==1


def test_competing_dates_and_completion_precedence(built):
    with connect(built) as c:
        dates=c.execute("SELECT date_value FROM date_claims WHERE source_tag='firm:codespect' AND role='report_issue' ORDER BY date_value").fetchall()
        assert dates==[('2024-12-31',),('2025-01-01',)]
        assert c.execute("SELECT audit_year,year_conflict FROM engagement_years JOIN engagements USING(engagement_id) WHERE publisher_id='codespect'").fetchone()==(None,True)
        assert c.execute("SELECT audit_year,year_conflict FROM engagement_years JOIN engagements USING(engagement_id) WHERE publisher_id='composable-security'").fetchone()==(2024,False)
        assert c.execute("SELECT count(*) FROM date_claims WHERE source_tag LIKE 'collect:%' AND basis='filename' AND eligible_for_audit_year").fetchone()[0]==0
        assert c.execute("SELECT count(*) FROM date_claims WHERE source_tag='firm:neodyme_v1' AND role='publication'").fetchone()[0]==1


def test_status_rights_and_missing_findings(built):
    with connect(built) as c:
        assert c.execute("SELECT severity_raw,severity,status,description FROM findings WHERE source_tag='firm:movebit'").fetchone()==('Major','high','acknowledged',None)
        assert c.execute("SELECT status FROM findings WHERE source_tag='firm:neodyme_v1'").fetchone()[0]=='fixed'
        assert c.execute("SELECT count(*) FROM findings WHERE publisher_id IN ('obsidian-audits','teamomega')").fetchone()[0]==0
        assert c.execute("SELECT sha256,title,project FROM documents WHERE source_tag='firm:omega_resume'").fetchone()==(None,None,None)
        response=json.loads(c.execute("SELECT attributed_responses FROM findings WHERE source_record_id='shieldify-f'").fetchone()[0])
        assert response[0]['actor']=='Team'
        fields=json.loads(c.execute("SELECT field_state FROM findings WHERE source_tag='firm:movebit'").fetchone()[0])
        assert fields['description']['state']=='withheld_rights_unresolved'


def test_idempotence_and_read_only_sources(source):
    def fingerprints():
        return {str(p.relative_to(source)):hashlib.sha256(p.read_bytes()).hexdigest() for directory in ['extracted','data/collect'] for p in (source/directory).rglob('*') if p.is_file()}
    def snapshot():
        with connect(source) as c:
            return {t:c.execute(f'SELECT * FROM {t} ORDER BY 1,2').fetchall() for t in ['publishers','documents','findings','engagements','engagement_documents','date_claims','contests','import_sources']}
    before=fingerprints()
    first=build(source)
    content=snapshot()
    assert build(source)==first
    assert snapshot()==content
    assert fingerprints()==before
    assert check(source,as_of=AS_OF)['check']=='PASS'


@pytest.mark.parametrize('sql,message',[
    ("UPDATE documents SET sha256='bad' WHERE source_record_id='codespect-main'",'SHA-256'),
    ("UPDATE date_claims SET date_value='2099-01-01' WHERE source_tag='firm:neodyme_v1' AND role='report_issue'",'Date outside'),
    ("UPDATE findings SET severity='low' WHERE source_record_id='shieldify-f'",'severity distribution'),
    ("INSERT INTO publishers VALUES ('outsider','Outsider','firm',NULL,NULL,'{}')",'Tier A scope')
])
def test_checker_detects_corruption(built,sql,message):
    with connect(built) as c:
        c.execute(sql)
    with pytest.raises(CheckError,match=message):
        check(built,as_of=AS_OF)


@pytest.mark.parametrize('sql',[
    "UPDATE findings SET document_id='missing' WHERE source_record_id='shieldify-f'",
    "UPDATE findings SET severity='severe' WHERE source_record_id='shieldify-f'",
    "UPDATE documents SET public_url=NULL WHERE source_record_id='codespect-main'"
])
def test_schema_constraints(built,sql):
    with connect(built) as c, pytest.raises(duckdb.ConstraintException):
        c.execute(sql)


def test_missing_contract_field_rejected(source):
    path=source/'data/collect/shieldify/reports.jsonl'
    rows=[json.loads(line) for line in path.read_text().splitlines()]
    rows[0].pop('listing_url')
    path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
    with pytest.raises(ValueError,match='Missing contract fields'):
        build(source)


def test_impossible_filename_date_stays_raw(source):
    path=source/'data/collect/shieldify/reports.jsonl'
    rows=[json.loads(line) for line in path.read_text().splitlines()]
    rows[0].update(date_hint='2023-13-04',date_precision='day',date_basis='filename')
    path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
    build(source)
    with connect(source) as c:
        assert c.execute("SELECT raw_value,date_value,precision,eligible_for_audit_year FROM date_claims WHERE raw_value='2023-13-04'").fetchone()==('2023-13-04',None,'none',False)
    assert check(source,as_of=AS_OF)['flagged_collector_date_hints']==1


def test_conflicting_contest_timing_preserved(source):
    path=source/'data/collect/code4rena/contests.jsonl'
    row=json.loads(path.read_text())
    row['end_utc']='2024-01-01T00:00:00Z'
    path.write_text(json.dumps(row)+'\n')
    build(source)
    with connect(source) as c:
        assert c.execute('SELECT timing_status FROM contests').fetchone()[0]=='source_conflict'
        assert c.execute("SELECT eligible_for_audit_year FROM date_claims WHERE engagement_id IS NOT NULL").fetchone()[0] is False
    assert check(source,as_of=AS_OF)['flagged_contest_timing_conflicts']==1


def test_scheduled_contest_without_report_is_metadata(source):
    path=source/'data/collect/code4rena/contests.jsonl'
    row=json.loads(path.read_text())
    row.update(start_utc='2026-10-06T00:00:00Z',end_utc='2026-11-03T00:00:00Z',report_url=None,sha256=None)
    path.write_text(json.dumps(row)+'\n')
    build(source)
    with connect(source) as c:
        assert c.execute('SELECT document_id,engagement_id FROM contests').fetchone()==(None,None)
    assert check(source,as_of=AS_OF)['scheduled_contests_without_reports']==1


def test_live_collector_changes_enter_next_build(built):
    path=built/'data/collect/shieldify/reports.jsonl'
    row=json.loads(path.read_text().splitlines()[0])
    row['public_url']='https://example.org/new.pdf'
    with path.open('a') as f:
        f.write(json.dumps(row)+'\n')
    result=check(built,as_of=AS_OF)
    assert result['collection_files_new_or_changed']==['data/collect/shieldify/reports.jsonl']
    assert build(built)['documents']==13
    assert check(built,as_of=AS_OF)['collection_files_new_or_changed']==[]


def test_identical_contract_row_deduplicated(source):
    path=source/'data/collect/shieldify/reports.jsonl'
    with path.open('a') as f:
        f.write(path.read_text().splitlines()[0]+'\n')
    assert build(source)['documents']==12
    with connect(source) as c:
        assert c.execute("SELECT duplicate_rows FROM import_sources WHERE source_file='data/collect/shieldify/reports.jsonl'").fetchone()[0]==1
    assert check(source,as_of=AS_OF)['check']=='PASS'


def test_same_artifact_competing_listing_claims_preserved(source):
    path=source/'data/collect/shieldify/reports.jsonl'
    row=json.loads(path.read_text().splitlines()[0])
    row.update(title_hint='A different listing assertion',date_hint='2024-03-10')
    with path.open('a') as f:
        f.write(json.dumps(row)+'\n')
    assert build(source)['documents']==13
    with connect(source) as c:
        assert c.execute("SELECT count(*) FROM engagements WHERE publisher_id='shieldify'").fetchone()[0]==1
        assert c.execute("SELECT count(DISTINCT date_value) FROM date_claims WHERE source_tag='collect:shieldify'").fetchone()[0]==3
        before=c.execute("SELECT document_id FROM documents WHERE source_tag='collect:shieldify' ORDER BY 1").fetchall()
    build(source)
    with connect(source) as c:
        assert c.execute("SELECT document_id FROM documents WHERE source_tag='collect:shieldify' ORDER BY 1").fetchall()==before
    assert check(source,as_of=AS_OF)['check']=='PASS'
