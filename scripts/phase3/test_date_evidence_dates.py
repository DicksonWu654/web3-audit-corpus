"""Synthetic evidence and semantic regressions; no corpus/holdout examples."""
import hashlib
from pathlib import Path
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/build'))
sys.path.insert(0,str(ROOT/'scripts/phase3'))
from metadata_rules import date_claims
from period_rules import reconcile_source_periods
from phase3_engagements import reject_software_advisory_dates
from date_evidence_html_dates import DateMetadata


def extract(text):
    receipt=dict(pages=list(range(1,len(text.split('\f'))+1)),text_sha256=hashlib.sha256(text.encode()).hexdigest())
    claims=date_claims(text,receipt)
    reconcile_source_periods(claims,[(text,receipt)])
    reject_software_advisory_dates(claims,[(text,receipt)])
    for c in claims:
        if c['method'].startswith('date_evidence_'):
            assert text[c['text_start']:c['text_end']]==c['evidence']
            assert c['raw_value'] in c['evidence']
            assert c['page']==text[:c['text_start']].count('\f')+1
    return [c for c in claims if c['role'] in {'report_issue','audit_completion'} and c['confidence']>=.8]


@pytest.mark.parametrize('raw,value',[
    ('Ferbruary 7, 2023','2023-02-07'),('2d July 2023','2023-07-02'),
    ('7 février 2023','2023-02-07'),('7 de março de 2023','2023-03-07'),
    ('7 März 2023','2023-03-07'),('7 июля 2023','2023-07-07'),
    ('2023 年 7 月 7 日','2023-07-07')])
def test_title_calendar_variants(raw,value):
    assert any(c['date_value']==value for c in extract('Security Audit Report\n'+raw))


def test_late_version_table_and_wrapped_year():
    text='Security Audit\fContents\fScope\fAppendix\fDocument properties\nVersion     Date       Author      Description\n0.1  May 7, 2022   A. Author  Initial draft\n1.0  June 8,       A. Author  Release\n     2023\nContact\nA. Author'
    claims=extract(text)
    assert any(c['date_value']=='2023-06-08' and c['page']==5 for c in claims)
    # A year in the NEXT version row cannot fill an incomplete first row.
    bad='Security Audit\fDocument control\nVersion Date Author\n0.1 May 7, A. Author\n1.0 June 8, 2023 A. Author'
    assert not any(c['date_value']=='2023-05-07' for c in extract(bad))


def test_footer_localized_table_and_contest_end():
    assert any(c['date_value']=='2023-06-08' and c['page']==4 for c in extract('Security Audit\fScope\fFindings\fSecurity Audit Report\nConclusion\nDate: June 8, 2023'))
    text='Security Audit\fScope\f审计结果\n审计编号  审计团队  审计⽇期  审计结果\n\n42 Team 2023.06.01 - 2023.06.08 Pass'
    assert any(c['date_value']=='2023-06-08' and c['role']=='audit_completion' for c in extract(text))
    assert any(c['date_value']=='2023-06-08' and c['role']=='audit_completion' for c in extract('Contest report\nCompetition ended on June 8, 2023'))
    assert any(c['date_value']=='2023-06-08' and c['role']=='audit_completion' for c in extract('Security review conducted during 1-8 June,\n2023.'))


def test_year_boundary_cover_start_and_wrapped_signature():
    claims=extract('Security Audit Report\nDecember 28, 2022 - January 5, 2023')
    assert {c['date_value'] for c in claims if c['role']=='audit_completion'}=={'2023-01-05'}
    text='Security Audit Report\nReport Date: December 18, 2022\fDocument revisions\nVersion Date Notes\n1.0 December 18, 2022 First release\n\nDigitally signed by Auditor\nAuthority certificate\n\nDate: 2023-02-19 04:13:39+0000'
    assert {c['date_value'] for c in extract(text)}=={'2022-12-18'}


def test_primary_start_does_not_conflict_with_completion_but_two_ends_do():
    text='Security Audit Report\nMarch 3, 2023\fProject Timeline\nFebruary 27, 2022 Start of primary review period\nMarch 3, 2023 End of primary review period'
    assert {c['date_value'] for c in extract(text) if c['role']=='audit_completion'}=={'2023-03-03'}
    text='Security Audit Report\nMarch 3, 2023\fProject Timeline\nMarch 3, 2022 End of primary review period\nMarch 3, 2023 End of primary review period'
    assert {c['date_value'] for c in extract(text) if c['role']=='audit_completion'}=={'2022-03-03','2023-03-03'}


def test_passive_review_is_not_re_review_and_prior_sources_are_not_current_work():
    text='Security Audit Report\nThe contracts were reviewed by two auditors from June 29 to July 12, 2022.'
    assert any(c['date_value']=='2022-07-12' and c['role']=='audit_completion' for c in extract(text))
    text='Security Audit Report\nNovember 14, 2024\fAudit Reports\n- Other module: This audit was conducted in October 2023 by AnotherFirm for several contracts.'
    assert not any(c['role']=='audit_completion' for c in extract(text))


def test_repeated_git_dates_and_software_releases_are_not_issue_dates():
    git='Security Audit Report\nExample commit history\ncommit '+'a'*40+'\nAuthor: Developer\nDate: 2020-11-18'
    text='Security Audit Report\nJanuary 17, 2023\fScope\fFindings\f'+git+'\f'+git
    assert not any(c['date_value']=='2020-11-18' for c in extract(text))
    text='Security Audit Report\nJuly 24, 2017\nThe latest version of the language was released 2 years ago, and since October 2015 there have been very few commits to the repository.'
    assert {c['date_value'] for c in extract(text)}=={'2017-07-24'}


def test_wrapped_cover_requires_a_dateline_not_a_wrapped_start_or_publication():
    assert any(c['date_value']=='2023-05-03' for c in extract('Security Audit Report\nMAY 3\n2023'))
    for label in ['Audit started on','Publication date:','Previous audit completed on']:
        text='Security Audit Report\n'+label+'\nMay 3,\n2023'
        assert not any(c['method']=='date_evidence_wrapped_cover_dateline' for c in extract(text))


def test_repeated_dependency_advisory_dates_cannot_authorize_report_years():
    advisory='Crate: time\nVersion: 0.1.45\nTitle: Vulnerability in dependency\nDate: 2020-11-18\nID: RUSTSEC-2020-0001'
    text='Security Audit Report\nJanuary 17, 2023\fScope\fFindings\f'+advisory+'\f'+advisory
    assert {c['date_value'] for c in extract(text)}=={'2023-01-17'}
    # A cached, already-derived year must not survive an invalid advisory anchor.
    start=text.index('Date:');end=text.index('\nID:',start)
    receipt={'text_sha256':hashlib.sha256(text.encode()).hexdigest()}
    claim=dict(role='audit_completion',confidence=.97,date_value='2020-05-03',
               year_anchor=dict(text_start=start,text_end=end,text_sha256=receipt['text_sha256']))
    reject_software_advisory_dates([claim],[(text,receipt)])
    assert claim['role']=='other' and claim['resolution']=='software_advisory_is_not_report_date'


def test_author_dateline_requires_source_semantics():
    text='Security Analysis\fFindings\fThis analysis was performed by Example:\nA. Author, Security Engineer\nJune 8, 2023\nBlockchain Security Analysis by Example'
    assert any(c['date_value']=='2023-06-08' and c['method']=='date_evidence_closing_author_dateline' for c in extract(text))
    for text in ['Security Audit\n© 2023 Auditor','Security Audit\nPublished: June 8, 2023',
                 'Security Audit\nAudit application received June 8, 2023',
                 'Security Audit\fFindings\nTransaction example\nDate: June 8, 2023',
                 'Security Audit\fAppendix\nJune 8, 2023']:
        assert not any(c['method'].startswith('date_evidence_') for c in extract(text))


def test_html_literal_metadata_separates_publication_and_completion():
    text='<meta property="article:published_time" content="2023-07-01T00:00:00Z">\n<meta name="reportDate" content="2023-06-09">\n<meta itemprop="auditEndDate" content="2023-06-08">'
    parser=DateMetadata();parser.feed(text)
    items=[]
    for c in parser.dates:
        start=text.index(c['evidence']);items.append(c|dict(text_start=start,text_end=start+len(c['evidence'])))
    from date_layout_rules import layout_date_claims
    claims=layout_date_claims(text,dict(html_metadata_dates=items))
    assert {(c['date_value'],c['role']) for c in claims}=={('2023-07-01','publication'),('2023-06-09','report_issue'),('2023-06-08','audit_completion')}
    assert all(c['page']==1 and c['page_kind']=='logical' for c in claims)
    with pytest.raises(ValueError,match='receipt'):
        layout_date_claims(text+'x',dict(html_metadata_dates=[items[0]|dict(text_start=1)]))
