"""Synthetic regressions for scope precision and explicitly related reports."""
from copy import deepcopy
from datetime import date
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts/phase3'))
from identity_rules import evidence, family_relation, scope_conflict, source_client, mitigation_parent, report_aliases


def document(name, text, client='Example', url=None, end='2025-03-27', commits=()):
    meta = dict(client=dict(value=client, method='named_client_field', confidence=.98),
                dates=[dict(date_value=end, role='audit_completion', confidence=.99)],
                source_relationships=dict(initial_commits=list(commits)))
    d = dict(document_id=name, publisher_id='firm', filename=name, file_format='pdf', doc_kind='audit_report',
             public_url=url or 'https://reports.example/'+name, metadata=meta)
    meta['project_identity'] = evidence(text, d, meta)
    return d


def group(d, day):
    return dict(publishers=[dict(documents=[d])], audit=dict(year=day.year, date_min=day, date_max=day, basis='audit_completion'))


def test_cover_binds_actual_name_and_keeps_component_scope():
    for text, expected in [('Acme: Wrapped Token\nSecurity Review\nVendor Managed review by:\nSomeone', 'Acme: Wrapped Token'),
                           ('Acme Bridge\nAudit\nPresented by:\nVendor', 'Acme Bridge'),
                           ('REPORT FOR\nAcme Lending', 'Acme Lending')]:
        assert source_client(text, dict(value='Presented by'), ['Vendor'])['value'] == expected


def test_explicit_implementation_parts_can_have_different_findings_and_repositories():
    base = ('Medium: Global losses <10% or losses to a subset of users.\n'
            'From Feb 21st to Mar 27th Vendor hosted a competition based on the Example upgrade. The present report focuses in the {} implementation.\n'
            'Finding: count > 0 is checked incorrectly.')
    a = document('alpha.pdf', base.format('alpha'), 'Example Alpha')
    b = document('beta.pdf', base.format('beta'), 'Example Beta')
    assert family_relation(a, b) == 'explicit_competition_implementation_parts'
    b['metadata']['dates'][0]['date_value'] = '2026-03-27'
    assert family_relation(a, b) is None


def test_split_submodules_require_common_history_commit_and_edition():
    text = 'The developers asked us to split these reports into seven submodules. Each report covers a submodule.'
    a, b = (document(n, text, n, commits=['a'*40]) for n in ['Core', 'Extensions'])
    for d in [a, b]:
        d['metadata']['dates'].append(dict(date_value='2025-04-01', role='report_issue', confidence=.99))
    assert family_relation(a, b) == 'explicit_split_submodule_report_family'
    b['metadata']['source_relationships']['initial_commits'] = ['b'*40]
    assert family_relation(a, b) is None


def test_additional_fv_requires_explicit_source_statement():
    a = document('2025-04-01-acme-v2.0.pdf', 'A formal verification suite & associated report was created and provided as an additional deliverable with the audit.')
    b = document('2025-04-01-acme-FV-v2.0.pdf', 'Formal Verification Report')
    assert family_relation(a, b) == 'explicit_additional_formal_verification_deliverable'
    a['metadata']['project_identity']['declarations'] = []
    assert family_relation(a, b) is None


def test_proxy_and_zero_findings_do_not_merge_distinct_implementations():
    a = document('a.pdf', '2 Security Review Summary\nFile Commit Hash\nERC1967Proxy.sol @ abcdef01\nCoin.sol @ abcdef02\nNo issues were identified.', 'Example: Coin')
    b = document('b.pdf', '2 Security Review Summary\nFile Commit Hash\nERC1967Proxy.sol @ abcdef01\nStakedCoin.sol @ abcdef03\nNo issues were identified.', 'Example: Staked Coin')
    assert scope_conflict(a, b)
    assert family_relation(a, b) is None


def test_halborn_website_github_exact_project_day_is_one_engagement():
    a=document('legacy.pdf','Halborn Security Report',client='Example Protocol',url='https://github.com/HalbornSecurity/PublicReports/blob/'+'a'*40+'/legacy.pdf')
    b=document('site.html','Halborn Website Report',client='Example Protocol',url='https://www.halborn.com/audits/example/report')
    for d in (a,b):d['publisher_id']='halborn'
    assert family_relation(a,b)=='halborn_website_github_same_project_and_engagement_day'
    b['metadata']['dates'][0]['date_value']='2025-03-28'
    assert family_relation(a,b) is None
    b['metadata']['dates'][0]['date_value']='2025-03-27'
    b['metadata']['client']['value']='Example Other Protocol'
    b['metadata']['project_identity']['entities']=[]
    assert family_relation(a,b) is None
    b['metadata']['client']['value']='Example Protocol'
    for d in (a,b):d['metadata']['dates'][0]['date_value']='2025-03'
    assert family_relation(a,b) is None


def test_fellowship_cohort_is_scoped_to_program_and_week():
    url = 'https://github.com/example/fellowship-audits/blob/'+'a'*40+'/block_010/week_2/'
    a = document('1-team-one.pdf', 'Alpha Lending Audit Findings', 'Alpha Lending', url+'one.pdf')
    b = document('2-team-two.pdf', 'Alpha Lending Audit by Team2', 'Alpha Lending', url+'two.pdf')
    assert family_relation(a, b) == 'source_fellowship_cohort_report_parts'
    b['metadata']['project_identity']['cohort'] += '/other'
    assert family_relation(a, b) is None


def test_mitigation_only_attaches_to_latest_preceding_supported_scope():
    text = 'Client Firm Acme\nAcme engaged Vendor to review the remediation of issues surfaced during a prior engagement.\nRepository: https://github.com/acme/protocol'
    review = document('fix.pdf', text, 'Acme', end='2025-05-28')
    review['doc_kind'] = 'fix_review'
    parents = [document(n, 'Client Firm Acme\nRepository: https://github.com/acme/protocol', 'Acme', end=d) for n, d in [('old', '2025-04-04'), ('latest', '2025-05-11'), ('future', '2025-06-01')]]
    assert mitigation_parent(review, parents) == ['latest']
    review['metadata']['project_identity']['mitigation_only'] = None
    assert mitigation_parent(review, parents) is None










def test_scoped_version_and_numbered_finding_revision():
    text = ('2.3. Scope\nRepository: https://github.com/acme/bridge\nVersion '+'c'*40+
            '\nBridge.sol\n3. Detailed Findings   3.1. Owner can bypass the recovery timelock\n4. Discussion')
    a = document('initial.pdf', text)
    b = document('expanded.pdf', text+'\nAdditional discussion')
    for d in [a,b]:
        d['metadata']['source_relationships']['sketch'] = [str(i) for i in range(32)]
    assert family_relation(a,b) == 'source_scoped_version_and_findings_revision'
    b['metadata']['project_identity']['substantive_titles'] = []
    assert family_relation(a,b) is None


def test_scope_guard_applies_before_shared_template_merge(tmp_path):
    sys.path.insert(0, str(ROOT/'scripts/build'))
    from build_db import build
    from make_fixture import materialize
    from test_phase3 import add_report
    import duckdb
    root=materialize(tmp_path/'input')
    boilerplate='\n'.join(f'Shared report sentence {i} describing the methodology and standard assessment procedure in detail.' for i in range(25))
    template=('# Example Security Audit\nAudit completed: May 3, 2025\n2 Security Review Summary\n'
              'ERC1967Proxy.sol @ '+'c'*40+'\n{} @ '+'d'*40+'\nNo issues were identified.\n'+boilerplate)
    a=add_report(root,'Coin.pdf',template.format('Coin.sol'))
    b=add_report(root,'StakedCoin.pdf',template.format('StakedCoin.sol'))
    build(root)
    with duckdb.connect(str(root/'data/corpus.duckdb'),read_only=True) as con:
        ids=con.execute('SELECT DISTINCT engagement_id FROM engagement_documents JOIN documents USING(document_id) WHERE sha256 IN (?,?)',[a,b]).fetchall()
    assert len(ids)==2


def test_language_variants_require_same_source_git_ref_and_edition():
    text='Client: Acme\nAudited files Git repository:\nhttps://github.com/acme/protocol/tree/main/contracts (abcdef1)'
    a=document('review-en-2025-119.pdf',text,'Acme')
    b=document('review-cn-2025-119.pdf',text,'Acme')
    assert family_relation(a,b)=='source_language_variant_same_scope'
    b['metadata']['project_identity']['scope_git_refs'][0]['commit']='abcdef2'
    assert family_relation(a,b) is None


def test_legal_prose_and_publisher_service_headings_cannot_be_entities():
    for value in ['and shall not construe any legal relationship towards third', 'Oak Security has been', 'Methodology', 'Reported Issues', 'Vendor Managed', 'https']:
        d=document('report', 'Repository: https://github.com/acme/protocol\nClient\nand shall not construe any legal relationship towards third', value)
        assert not d['metadata']['project_identity']['entities']
    d=document('report', 'Client      Acme Labs\nRepository: https://github.com/acme/protocol', 'Methodology')
    assert [e['value'] for e in d['metadata']['project_identity']['entities']]==['acmelabs']
    assert source_client('Wallet Application',dict(value='E EXAMPLEISECURITY Wallet Application'),['Example Security']) is None


def test_canonical_html_alias_requires_original_hash_and_scope(tmp_path):
    import hashlib
    import pytest
    body=b'<html><link rel="canonical" href="https://publisher.example/reports/acme"><meta property="og:url" content="https://publisher.example/reports/acme"></html>'
    digest=hashlib.sha256(body).hexdigest()
    path=tmp_path/'local-cache/originals'/digest[:2]/(digest+'.html')
    path.parent.mkdir(parents=True);path.write_bytes(body)
    a=document('copy.html','Scope\nAcmeVault.sol\nAcmeRouter.sol','Acme',url='https://github.com/client/reports/blob/commit/copy.html')
    b=document('original.html','Scope\nAcmeVault.sol\nAcmeRouter.sol','Acme',url='https://publisher.example/reports/acme')
    a.update(file_format='html',sha256=digest)
    aliases=report_aliases(tmp_path,a)
    assert {x['kind'] for x in aliases}=={'canonical','og:url'}
    a['metadata']['project_identity']=evidence('Scope\nAcmeVault.sol\nAcmeRouter.sol',a,a['metadata'],aliases)
    assert family_relation(a,b)=='source_canonical_report_alias_and_scope'
    assert not a['metadata']['project_identity']['domains']
    b['metadata']['project_identity']['scope_assets']=[]
    assert family_relation(a,b) is None
    path.write_bytes(body+b'changed')
    with pytest.raises(ValueError,match='hash mismatch'):
        report_aliases(tmp_path,a)
