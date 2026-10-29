"""Synthetic regression tests for date semantics and verbatim evidence gates."""
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/build'))
sys.path.insert(0,str(ROOT/'scripts/phase3'))
from date_rules import extended_date_claims
from metadata_rules import canonical
from llm_dates import validate


def eligible(text):
    return [c for c in extended_date_claims(text,{'pages':list(range(1,20))})
            if c['role'] in {'audit_completion','report_issue'}]


def test_multiline_period_and_closing_table():
    text='Cover\fContents\fSummary\fAppendix\fAudit Number     Audit Date     Result\n\n0042   2023.02.01 - 2023.02.08   Passed'
    claims=eligible(text)
    assert any(c['date_value']=='2023-02-08' and c['role']=='audit_completion' and c['page']==5 for c in claims)
    for c in claims:
        assert text[c['text_start']:c['text_end']]==c['evidence']
    text='Assessment conducted between January 16th and February 3rd,\n2023 by three engineers.'
    assert any(c['date_value']=='2023-02-03' and c['role']=='audit_completion' for c in eligible(text))


def test_publication_filename_application_history_never_completion():
    for text in ['---\ntitle: 2025-11-Protocol\ndescription: Security Audit\n---\n<object src="2025-11-Protocol.pdf">',
                 'Security Audit\n© 2023 Vendor',
                 'On 2023.02.01, the team received a security audit application.',
                 'The previous audit was completed on January 3, 2024.']:
        assert eligible(text)==[]
    claims=extended_date_claims('Publication date: May 3, 2024',{'pages':[1]})
    assert claims and all(c['role']=='publication' for c in claims)


def test_delivery_ambiguous_year_and_verbatim_llm():
    assert any(c['date_value']=='2025-03-31' and c['role']=='report_issue'
               for c in eligible('Security Audit Report\nDelivered: March 31, 2025'))
    assert any(c['date_value']=='2024' and c['precision']=='year'
               for c in eligible('Audit end date: 04/05/2024'))
    text='Audit completed: May 3, 2024'
    answer=dict(sha256='a'*64,date='2024-05-03',kind='audit_completion',evidence=text)
    assert validate(answer,text,{'pages':[1]})['method']=='llm'
    assert validate(answer|{'evidence':'Audit completed: May 4, 2024'},text,{}) is None
    assert validate(answer|{'date':'2025-05-03'},text,{}) is None
    assert validate(answer|{'date':'2024-02-30'},text,{}) is None


def test_exact_evidence_line_separators_survive_jsonl():
    value={'evidence':'a\u0085b\u2028c\u2029d'}
    serialized=canonical(value)
    assert len(serialized.splitlines())==1
    assert json.loads(serialized)==value


def test_odd_formats_chinese_and_native_dateline():
    cases=[('Security Assessment\nM a y 3 0 t h , 2 0 2 4 — P r e p a r e d b y A u d i t o r','2024-05-30'),
           ('FINAL REPORT\nMarch ‘2025','2025-03'),
           ('Security Audit Report\n(May 23, 2022)','2022-05-23'),
           ('审计时间 : 2021 年 03 月 18 日','2021-03-18'),
           ('# Protocol Audit\n\nJan 13, 2020January 13, 2020','2020-01-13'),
           ('# Protocol\n\nSmart Contract Security Assessment\n\nMar 07, 2024','2024-03-07'),
           ('Smart Contracts\nDate July 24, 2026','2026-07-24'),
           ('SECURITY REVIEW · MARCH 2025','2025-03'),
           ('S E C U R I T Y R E V I E W · M AY 2 0 2 6','2026-05'),
           ('Audit Summary\nDelivery Date       June 18th, 2024','2024-06-18'),
           ('Date of Engagement by: July 22nd, 2024 - July 26th, 2024','2024-07-26'),
           ('审计时间：2023.09.02 - 2023.09.08','2023-09-08'),
           ('Logo\fContents\fSMART CONTRACT AUDIT REPORT\nPrepared By: Auditor\nFeb. 26, 2020','2020-02-26'),
           ('Logo\fSECURITY AUDIT OF Protocol\nVersion: 1.1\nJuly 1, 2026','2026-07-01'),
           ('Logo\fExecutive summary\nAuditor    Auditor name\nTime period    23/12/2024-\n               29/12/2024','2024-12-29'),
           ('Smart Contracts Review\nJune, 27th 2022 | v. 1.0','2022-06-27'),
           ('Summary\fAudit Date : April 01, 2021','2021-04-01'),
           ('Cover\fContents\fIntro\fAudit Starting Date   Audit Completion Date\n16.10.2023    06.11.2023','2023'),
           ('Summary\fThe audit was conducted by the team in the period from\n03/25/2024 to 03/27/2024.','2024-03-27'),
           ('Summary\fThe audit was conducted on\n29/04/2025.','2025-04-29')]
    for text,value in cases:
        assert any(c['date_value']==value for c in eligible(text)),text
    assert eligible('Logo\fResearch Report\nAuthors\nFebruary 2021\nIntroduction')==[]


def test_explicit_embedded_pdf_supplies_its_own_date(tmp_path):
    import duckdb
    from build_db import build
    from test_phase3 import add_report
    from make_fixture import materialize
    root=materialize(tmp_path/'input')
    wrapper=add_report(root,'content/Protocol.md','# Protocol\n<object data="pdf/Protocol.pdf"></object>')
    original=add_report(root,'public/pdf/Protocol.pdf','# Protocol Security Audit\nAudit completed: May 3, 2024')
    path=root/'data/collect/shieldify/reports.jsonl'
    rows=[json.loads(s) for s in path.read_text().splitlines()]
    for row in rows:
        if row['sha256'] in {wrapper,original}:
            row['public_url']='https://github.com/example/reports/blob/'+'a'*40+'/'+row['filename']
        if row['sha256']==original: row['file_format']='pdf'
    path.write_text(''.join(canonical(r)+'\n' for r in rows))
    build(root)
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        result=con.execute('SELECT DISTINCT engagement_id,audit_year FROM documents JOIN engagement_documents USING(document_id) JOIN engagement_years USING(engagement_id) WHERE sha256 IN (?,?)',[wrapper,original]).fetchall()
        assert len(result)==1 and result[0][1]==2024


def test_build_revalidates_llm_evidence_and_holdout(tmp_path):
    import duckdb
    import pytest
    from build_db import build
    from make_fixture import materialize
    from test_phase3 import add_report
    root=materialize(tmp_path/'input')
    text='# Protocol Security Audit\nThe work ended on 4 May 2024.'
    digest=add_report(root,'Protocol.md',text)
    claim=validate(dict(sha256=digest,date='2024-05-04',kind='audit_completion',evidence='The work ended on 4 May 2024.'),text,{})
    held=root/'data/holdout/gold_sha256.txt'
    held.parent.mkdir(parents=True)
    held.write_text('f'*64+'\n')
    path=root/'data/phase3/llm_dates.jsonl'
    path.parent.mkdir(parents=True)
    path.write_text(canonical(claim)+'\n')
    build(root)
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        assert con.execute("SELECT count(*) FROM date_claims WHERE json_extract_string(evidence,'$.assertion.method')='llm' AND eligible_for_audit_year").fetchone()[0]==1
    path.write_text(canonical(claim|{'evidence':'Fabricated date evidence 2024'})+'\n')
    with pytest.raises(ValueError,match='Invalid or stale LLM'):
        build(root)
    path.write_text(canonical(claim)+'\n')
    held.write_text(digest+'\n')
    with pytest.raises(ValueError,match='held-out'):
        build(root)


def test_boilerplate_pages_and_same_month_do_not_merge(tmp_path):
    import duckdb
    from build_db import build
    from make_fixture import materialize
    from test_phase3 import add_report
    root=materialize(tmp_path/'input')
    front='Security Audit\fDisclaimer\fCommon table of contents\n'+'Boilerplate '*30
    a=add_report(root,'Alpha-protocol.pdf',front+'\fAlpha review\nAudit period: May 1, 2024 to May 3, 2024')
    b=add_report(root,'Other-protocol.pdf',front+'\fOther review\nAudit period: May 5, 2024 to May 8, 2024')
    build(root)
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        assert con.execute('SELECT count(DISTINCT engagement_id) FROM documents JOIN engagement_documents USING(document_id) WHERE sha256 IN (?,?)',[a,b]).fetchone()[0]==2


def test_git_scope_dates_never_become_report_issue():
    from metadata_rules import date_claims
    text='Audit Report\n**Date:** January 11th 2019\n**GitHub :** Vendor/Protocol-2018-12\n8e8eb4c7 2024-08-09 package.json version 3.1.1'
    claims=date_claims(text,{'pages':[1]})
    assert [(c['date_value'],c['role']) for c in claims]==[('2019-01-11','report_issue')]
    claims=date_claims('Report date: May 3, 2024. Scope: https://github.com/example/project-2023-09',{'pages':[1]})
    assert [(c['date_value'],c['role']) for c in claims]==[('2024-05-03','report_issue')]
