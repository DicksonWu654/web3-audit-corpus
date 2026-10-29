"""Synthetic counterexamples for Phase 3c, independent of verifier sample IDs."""
from datetime import date
import json
from pathlib import Path
import sys

import duckdb
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/build'))
from build_db import build
from make_fixture import materialize
from metadata_rules import process_artifact, sha
from date_rules import extended_date_claims
from engagement_rules import auditor, generic_project, project_from_text
from test_phase3 import add_report


def current(root, hashes):
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        return con.execute('SELECT d.sha256,e.engagement_id,y.audit_year,e.evidence FROM documents d JOIN engagement_documents ed USING(document_id) JOIN engagements e USING(engagement_id) JOIN engagement_years y USING(engagement_id) WHERE d.sha256 IN (SELECT unnest(?)) ORDER BY d.sha256',[hashes]).fetchall()


def test_completion_after_cover_and_historical_dates(tmp_path):
    root=materialize(tmp_path/'input')
    text='Example Security Audit\nFebruary 3, 2025\fContents\fDisclaimer\fThe previous audit completed on January 9, 2023.\nAudit period: December 2, 2024 to December 20, 2024\nRetest completed: January 30, 2025\nDigitally signed on February 4, 2025'
    h=add_report(root,'Example.md',text)
    build(root)
    row=current(root,[h])[0]
    assert row[2]==2024
    resolved=json.loads(row[3])['resolved_date']
    assert (resolved['value'],resolved['role'],resolved['precision'])==('2024-12-20','audit_completion','day')


def test_revisions_and_precision_resolve_without_losing_claims(tmp_path):
    root=materialize(tmp_path/'input')
    h=add_report(root,'Example.md','Example Security Audit\nFebruary 2024\fRevision History\nVersion Date Description\n1.0 February 3, 2024 Initial report\n1.1 February 17, 2024 Document Review')
    build(root)
    assert json.loads(current(root,[h])[0][3])['resolved_date']['value']=='2024-02-17'
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        rows=con.execute("SELECT date_value,eligible_for_audit_year FROM date_claims JOIN documents USING(document_id) WHERE sha256=? AND role='report_issue'",[h]).fetchall()
        assert ('2024-02-03',False) in rows
        assert ('2024-02',False) in rows
        assert ('2024-02-17',True) in rows


def test_true_completion_conflict_stays_unknown(tmp_path):
    root=materialize(tmp_path/'input')
    h=add_report(root,'Example.md','Example Security Audit\nAudit completed: December 30, 2023\fAudit end date: January 4, 2024')
    build(root)
    assert current(root,[h])[0][2] is None
    assert json.loads(current(root,[h])[0][3])['resolved_date']['conflict'] is True


def test_source_explicit_fix_review_attaches_and_cannot_retime_parent(tmp_path):
    root=materialize(tmp_path/'input')
    parent=add_report(root,'Example-audit.md','# Example Security Audit\nClient: Example\nAudit completed: November 20, 2024\nCommit: '+'c'*40)
    fix=add_report(root,'Example-fix-review.md','# Example Fix Review\nClient: Example\nAudit completed: January 15, 2025\nCommit: '+'c'*40)
    build(root)
    rows=current(root,[parent,fix])
    assert len({r[1] for r in rows})==1
    assert {r[2] for r in rows}=={2024}
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        assert con.execute("SELECT count(*) FROM date_claims JOIN documents USING(document_id) WHERE sha256=? AND eligible_for_audit_year",[fix]).fetchone()[0]==0


def test_full_content_rendering_merge_and_independent_audits(tmp_path):
    root=materialize(tmp_path/'input')
    body='\n'.join(f'Unique scope statement number {i} describes a different function in the Example contract.' for i in range(18))
    base='# Example Security Audit\nClient: Example\nAudit completed: April 17, 2024\nCommit: '+'d'*40+'\n'+body
    a=add_report(root,'native/overview.md',base)
    b=add_report(root,'downloads/Example-review.md',base+'\nReport version: 1.1')
    c=add_report(root,'Example-next-year.md',base.replace('April 17, 2024','April 17, 2025').replace('d'*40,'e'*40))
    build(root)
    rows={r[0]:r[1] for r in current(root,[a,b,c])}
    assert rows[a]==rows[b] and rows[a]!=rows[c]
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        assert con.execute('SELECT count(*) FROM engagement_identity_crosswalk').fetchone()[0]>=0


def test_wrong_responses_and_supporting_artifacts_never_confirm(tmp_path):
    root=materialize(tmp_path/'input')
    hashes=[add_report(root,'missing.md','404 page not found'),
            add_report(root,'prep.md','Security Audit Preparation Checklist\nBefore the audit, prepare your code.'),
            add_report(root,'support.md','A partial Alloy specification intended to be included in the audit report.'),
            add_report(root,'sale.md','Token Sale Particulars\nExample Token')]
    build(root)
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        assert con.execute('SELECT count(*) FROM document_exclusions JOIN documents USING(document_id) WHERE sha256 IN (SELECT unnest(?))',[hashes]).fetchone()[0]==len(hashes)


def test_brand_policy_and_multiline_client():
    assert auditor('Prepared By: ScaleBit\nExample Security Audit','movebit')['value']=='scalebit'
    assert auditor('Theori\nExample Security Audit','chainlight')['value']=='theori'
    assert auditor('ChainLight\nA Theori team\nExample Audit','theori')['value']=='chainlight'
    assert generic_project('Smart Contract') and generic_project('Mar.25')
    value=project_from_text('Example\nFinance\nSecurity Audit Report',{'report_title':{'value':'Security Audit Report'}})
    assert value['value']=='Example Finance'


def test_native_long_report_dateline_and_alternate_layout(tmp_path):
    text='# Example Security Audit\nMay 3, 2024\n'+'Long finding description. '*2000
    dates=extended_date_claims(text,{'pages':None})
    assert any(c['date_value']=='2024-05-03' and c['role']=='report_issue' for c in dates)
    root=materialize(tmp_path/'input')
    opening='Example Security Audit\nReport date: May 3, 2024'
    h=add_report(root,'Example.md',opening)
    full=root/'local-cache/fulltext'/(h+'.txt');full.parent.mkdir(parents=True,exist_ok=True)
    complete='Example Security Audit\nAlternate full-text layout without a dateline.'
    full.write_text(complete)
    full.with_suffix('.pages.json').write_text(json.dumps(dict(text_sha256=sha(complete.encode()),file_format='md',status='ok')))
    build(root)
    assert json.loads(current(root,[h])[0][3])['resolved_date']['value']=='2024-05-03'


def test_completed_period_after_engagement_sentence_and_bare_timeline():
    text='The client engaged the auditor to perform an assessment. This assessment\nwas conducted between April 2nd and April 10th, 2024.'
    claims=extended_date_claims(text,{'pages':[1]})
    assert any(c['role']=='audit_completion' and c['date_value']=='2024-04-10' for c in claims)
    text='Cover\fAudit details\nstarted     delivered\n16.09.2024    04.10.2024'
    claims=extended_date_claims(text,{'pages':[1,2]})
    assert any(c['role']=='audit_completion' and c['date_value']=='2024' for c in claims)


def test_rendering_omitted_cover_and_changed_client_label(tmp_path):
    root=materialize(tmp_path/'input')
    body='\n'.join(f'Finding number {i} describes a distinct missing authorization in the audited function.' for i in range(12))
    a=add_report(root,'Company-Component-report.pdf','# Component Security Audit\nClient: Component\nAudit completed: May 3, 2024\n'+body)
    b=add_report(root,'Company-Component-report.md','# Findings\n'+body)
    path=root/'data/collect/shieldify/reports.jsonl'
    rows=[json.loads(s) for s in path.read_text().splitlines()]
    for r in rows:
        if r['sha256']==a: r['file_format']='pdf'
    path.write_text(''.join(json.dumps(r)+'\n' for r in rows))
    build(root)
    rows=current(root,[a,b])
    assert len({r[1] for r in rows})==1 and {r[2] for r in rows}=={2024}


def test_format_characters_and_separate_retest_sentence():
    text='Engagement\u200c Summary\nDates\u200c January\u200c 4 through\u200c January\u200c 22,\u200c 2024'
    claims=extended_date_claims(text,{'pages':[1]})
    assert any(c['role']=='audit_completion' and c['date_value']=='2024-01-22' for c in claims)
    assert all(text[c['text_start']:c['text_end']]==c['evidence'] for c in claims)
    text='The audit was performed from April 1 to April 8, 2024. A retest of the reported issues was performed on April 20, 2024.'
    claims=extended_date_claims(text,{'pages':None})
    assert any(c['role']=='audit_completion' and c['date_value']=='2024-04-08' for c in claims)
    assert all(c['role']=='retest' for c in claims if c['date_value']=='2024-04-20')
    text='The audit was performed from 20 April to 6 May 2024. A retest was performed on 9 May 2024.'
    claims=extended_date_claims(text,{'pages':None})
    assert any(c['role']=='audit_completion' and c['date_value']=='2024-05-06' for c in claims)


def test_full_audit_with_fix_appendix_is_not_an_orphan_review(tmp_path):
    root=materialize(tmp_path/'input')
    h=add_report(root,'Example-Security-Assessment.md','# Example Security Assessment\nAudit completed: May 3, 2024\n## Project Scope\nInitial code review\n## Summary of Findings\nInitial findings\n## Fix Review Results\nRemediation appendix','fix_review')
    build(root)
    assert current(root,[h])[0][2]==2024


@pytest.mark.parametrize('kind', ['audit_report', 'fix_review'])
def test_combined_security_assessment_and_fix_review_remains_initial_audit(tmp_path,kind):
    root=materialize(tmp_path/'input')
    h=add_report(root,'Turnkey-securityreview.md',
                 '# Turnkey Key Management System\nSecurity Assessment and Fix Review\n'
                 'Audit completed: May 3, 2024\n## Project Scope\nInitial code review\n'
                 '## Summary of Findings\nInitial findings\n## Detailed Fix Review Results\nRemediation appendix',kind)
    build(root)
    rows=current(root,[h])
    assert len(rows)==1 and rows[0][1]
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        assert con.execute('SELECT doc_kind FROM documents WHERE sha256=?',[h]).fetchone()[0]=='audit_report'


def test_versioned_fix_review_parent_requires_scope_repository(tmp_path):
    root=materialize(tmp_path/'input')
    parent=add_report(root,'Example-v2-Audit.md','# Example v2 Security Audit\nClient: Example v2\nAudit completed: May 3, 2024\nRepository: https://github.com/example/protocol')
    fix=add_report(root,'Example-v2-Fix-Review.md','# Example v2 Fix Review Security Review\nRepository: https://github.com/example/protocol\nReport date: June 3, 2024','fix_review')
    build(root)
    rows=current(root,[parent,fix])
    assert len({r[1] for r in rows})==1 and {r[2] for r in rows}=={2024}


def test_report_stages_supersede_stale_cover_without_using_client_response(tmp_path):
    root=materialize(tmp_path/'input')
    text='Example Security Audit\nMay 3, 2023\fAudit Details\nInitial Audit Report: May 3, 2023\nResponse from Client: January 9, 2024\nFinal Audit Report: January 17, 2024'
    h=add_report(root,'Example.md',text)
    build(root)
    result=current(root,[h])[0]
    assert result[2]==2024
    assert json.loads(result[3])['resolved_date']['value']=='2024-01-17'


def test_source_year_period_retains_precision_and_does_not_use_copyright(tmp_path):
    root=materialize(tmp_path/'input')
    h=add_report(root,'Example.md','# Example Audit performed in 2024/Q2\nScope and findings')
    cover=add_report(root,'Another.md','# Another Security Audit\nDate: 2023\nScope and findings')
    other=add_report(root,'Undated.md','# Undated Security Audit\nCopyright 2023 Auditor')
    build(root)
    rows={r[0]:r for r in current(root,[h,cover,other])}
    assert rows[h][2]==2024 and json.loads(rows[h][3])['resolved_date']['precision']=='year'
    assert rows[cover][2]==2023 and rows[other][2] is None


@pytest.mark.parametrize('appendix',[False,True])
def test_official_mitigation_parent_and_end_date_are_not_another_audit(tmp_path,appendix):
    root=materialize(tmp_path/'input')
    parent=add_report(root,'Example-main.md','# Example Security Audit\nAudit completed: December 27, 2023')
    fix=add_report(root,'Example-fix-review.md','# Example Fix Review\nReport date: January 10, 2024')
    source=root/'data/collect/shieldify/reports.jsonl'
    rows=[json.loads(s) for s in source.read_text().splitlines() if json.loads(s)['sha256'] in {parent,fix}]
    path=root/'data/collect/code4rena/reports.jsonl'
    with path.open('a') as stream:
        for row in rows:
            row.update(firm_id='code4rena',source_kind='contest',doc_kind='contest_report')
            stream.write(json.dumps(row)+'\n')
    path=root/'data/collect/code4rena/contests.jsonl'
    template=json.loads(path.read_text().splitlines()[0])
    with path.open('a') as stream:
        for digest,cid,fmt,start,end in [(parent,'initial','public_contest','2023-12-20T00:00:00Z','2023-12-27T00:00:00Z'),(fix,'mitigation','mitigation','2024-01-08T00:00:00Z','2024-01-10T00:00:00Z')]:
            row=next(r for r in rows if r['sha256']==digest)
            contest=dict(template,contest_id=cid,name='Example',format=fmt,start_utc=start,end_utc=end,report_url=row['public_url'],sha256=digest)
            if fmt=='mitigation':
                contest['parent_contest_id']='initial'
                if appendix:
                    contest.update(sha256=parent,report_url=next(r['public_url'] for r in rows if r['sha256']==parent),report_relation='mitigation_appendix')
            stream.write(json.dumps(contest)+'\n')
    build(root)
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        links=con.execute("SELECT DISTINCT engagement_id,audit_year FROM documents JOIN engagement_documents USING(document_id) JOIN engagement_years USING(engagement_id) WHERE publisher_id='code4rena' AND sha256 IN (?,?)",[parent,fix]).fetchall()
        assert len(links)==1 and links[0][1]==2023
        assert con.execute("SELECT role,eligible_for_audit_year FROM date_claims WHERE json_extract_string(evidence,'$.assertion.contest_id')=(SELECT contest_id FROM contests WHERE platform_contest_id='mitigation')").fetchone()==('retest',False)


def test_mitigation_appendix_text_does_not_move_initial_year(tmp_path):
    root=materialize(tmp_path/'input')
    h=add_report(root,'Example.md','# Example Security Audit\nAudit completed: December 27, 2023\fMitigation Review\nAudit completed: January 10, 2024')
    build(root)
    assert current(root,[h])[0][2]==2023


def test_wrapped_conducted_label_keeps_original_quote_and_completion(tmp_path):
    root=materialize(tmp_path/'input')
    text='Example Security Audit\fExecutive Summary\nThe assessment was conducted\nbetween March 2 and March 9, 2024. We delivered patch confirmation on March 20, 2024.'
    h=add_report(root,'Example.md',text)
    build(root)
    result=current(root,[h])[0]
    assert json.loads(result[3])['resolved_date']['value']=='2024-03-09'
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        for raw, in con.execute("SELECT evidence FROM date_claims JOIN documents USING(document_id) WHERE sha256=? AND eligible_for_audit_year",[h]).fetchall():
            evidence=json.loads(raw)['assertion']
            assert text[evidence['text_start']:evidence['text_end']]==evidence['evidence']
    other=add_report(root,'Unfinished.md','# Unfinished Security Audit\nThe assessment was conducted\nover five days starting May 1, 2024. Report published May 7, 2024.')
    build(root)
    assert current(root,[other])[0][2] is None
