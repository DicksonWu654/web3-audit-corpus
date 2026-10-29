"""Group 2 era selection, source-status semantics, bounds and holdout boundary."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import digest
from core import Report, Candidate
from fixtures_group2_variants import BODY, FIXTURES
from parsers import module
from variants_group2 import FIRMS
from parsers.group2_layouts import statuses


def report(text,firm,date=None):
    offset=0;pages=[]
    for n,value in enumerate(text.split('\f'),1):
        pages.append(dict(page=n,start=offset,end=offset+len(value),text=value))
        offset+=len(value)+1
    return Report(text,dict(file_format='md',pages=pages,text_sha256=digest(text.encode()),date_hint=date),firm)


class Group2Variants(unittest.TestCase):
    def test_every_variant_has_explicit_parser_and_executable_fixture(self):
        declared=set()
        for firm in FIRMS:
            variants=module(firm).VARIANTS
            # Classed/classless HTML share the same ID-linked card grammar.
            # Fingerprints may distinguish exports without duplicating parsing.
            shared={tuple(v.variant_id for v in variants if v.parse is parser)
                    for parser in {v.parse for v in variants}
                    if sum(v.parse is parser for v in variants)>1}
            self.assertEqual(shared,{('iosiro/v2026_classless_html','iosiro/v2024_native_html')}
                             if firm=='iosiro' else set())
            for v in variants:
                self.assertFalse(v.fingerprint.legacy)
                self.assertNotEqual(v.fingerprint.date_range,(None,None))
                self.assertTrue(v.fingerprint.signatures)
                self.assertIsNotNone(v.status_parser)
                for name in v.fixtures:
                    declared.add(name)
                    f=FIXTURES[name]
                    with self.subTest(fixture=name):
                        r=report(f['text'],firm)
                        cs=module(firm).parse(r)
                        self.assertEqual(r.layout_selection['variant_id'],f['variant_id'])
                        self.assertEqual([(c.printed_id,c.severity_raw,c.normalized_status) for c in cs],f['expected'])
                        for c in cs:
                            self.assertTrue(0<=c.start<c.end<=len(r.text))
                            if c.normalized_status:
                                e=c.evidence['status_evidence'];self.assertEqual(r.text[e['start']:e['end']],e['text'])
        self.assertEqual(declared,set(FIXTURES))

    def test_date_alone_never_recognizes_a_layout(self):
        for firm in FIRMS:
            r=report('Unfamiliar unrelated document without a publisher template.',firm,'2024-01-01')
            module(firm).parse(r)
            self.assertTrue(r.layout_selection['unknown_layout'],firm)

    def test_recommendations_do_not_claim_a_fix(self):
        r=report('Actual vulnerability\n'+BODY+'Recommendation: This should be fixed.\n','decurity')
        c=Candidate(0,'Actual vulnerability',end=len(r.text))
        statuses(r,[c],headings=True,narrative=True)
        self.assertIsNone(c.status_raw)

    def test_conflicting_id_index_is_not_a_status(self):
        r=report('Actual vulnerability\n'+BODY+'\nAppendix\nPVE-001    Fixed\nPVE-001    Open\n','peckshield')
        c=Candidate(0,'Actual vulnerability',printed_id='PVE-001',end=r.text.index('Appendix'))
        statuses(r,[c],index_id=r'\bPVE-\d+\b')
        self.assertIsNone(c.status_raw)
        self.assertTrue(c.evidence['status_conflict'])

    def test_status_word_in_index_title_is_not_a_disposition(self):
        r=report('Actual vulnerability\n'+BODY+'\nAppendix\nPVE-001    Low    Fixed compiler version    Coding Practices\n','peckshield')
        c=Candidate(0,'Actual vulnerability',printed_id='PVE-001',end=r.text.index('Appendix'))
        statuses(r,[c],index_id=r'\bPVE-\d+\b')
        self.assertIsNone(c.status_raw)

    def test_fix_review_index_fills_only_the_matching_id(self):
        r=report('Actual vulnerability\n'+BODY+'\nAppendix\nFix Review\nPVE-001    Fixed\nPVE-002    Open\n','peckshield')
        c=Candidate(0,'Actual vulnerability',printed_id='PVE-001',end=r.text.index('Appendix'))
        statuses(r,[c],index_id=r'\bPVE-\d+\b')
        self.assertEqual(c.normalized_status,'fixed')
        self.assertEqual(c.evidence['status_evidence']['basis'],'printed_id_status_index')

    def test_explicit_fix_review_supersedes_initial_card_status(self):
        r=report('Actual vulnerability\nStatus: Open\n'+BODY+'\nAppendix\nFix Review\nPVE-001    Fixed\n','peckshield')
        c=Candidate(0,'Actual vulnerability',printed_id='PVE-001',end=r.text.index('Appendix'),status_raw='Open')
        statuses(r,[c],index_id=r'\bPVE-\d+\b',headings=True)
        self.assertEqual(c.normalized_status,'fixed')
        self.assertEqual(c.evidence['status_evidence']['basis'],'fix_review_id_status_table')

    def test_final_verification_overrides_initial_open_status(self):
        f=FIXTURES['least_status_cards'];r=report(f['text'],'least-authority')
        c=module(r.firm).parse(r)[0]
        self.assertEqual(c.normalized_status,'resolved')
        self.assertGreater(c.evidence['status_evidence']['start'],r.text.index('Verification'))

    def test_spearbit_fix_verified_is_contextual(self):
        r=report('5.1 Low Risk\n5.1.1 Improper permission check\nSeverity: Low Risk\n'+BODY+'Client: This should be fixed.\nSpearbit: Verified.\n','spearbit')
        self.assertEqual(module(r.firm).parse(r)[0].normalized_status,'resolved')

    def test_iosiro_closed_means_acknowledged_risk(self):
        f=FIXTURES['iosiro_html'];r=report(f['text'],'iosiro')
        self.assertEqual(module(r.firm).parse(r)[0].normalized_status,'acknowledged')

    def test_reported_date_is_not_a_status(self):
        text='Issue A: Improper permission check    Reported:\nIssue A: Improper permission check\nLocation\nVault\nSynopsis\n'+BODY+'Reported: 2017-01-01\n'
        r=report(text,'least-authority');c=module(r.firm).parse(r)[0]
        self.assertIsNone(c.status_raw)

    def test_secure3_wrapped_identifier(self):
        f=FIXTURES['secure3_chart'];r=report(f['text'].replace('TST-1:','TST-\n1:'),'secure3')
        c=module(r.firm).parse(r)[0]
        self.assertEqual(c.printed_id,'TST-1')
        self.assertIsNotNone(c.evidence['wrapped_id_span'])

    def test_legacy_bidi_status_receipt_keeps_original_offsets(self):
        text='5.1. Improper permission check\nSeverity\nHIGH\n'+BODY+'Status 2023-06-02    \u202dPARTIALLY\u202c\n'+(' '*95)+'\u202dIMPLEMENTED\u202c\n'
        r=report(text,'composable-security');c=module(r.firm).parse(r)[0]
        self.assertEqual(c.normalized_status,'partial')
        e=c.evidence['status_evidence']
        self.assertEqual(r.text[e['start']:e['end']],e['text'])
        self.assertIn('\u202c',e['text'])

    def test_clean_spl_compliance_report_is_recognized(self):
        r=report('PeckShield Audit Report\nOur findings indicate that the given token contract conforms to SPL standards without\ncompliance issues or security vulnerabilities.','peckshield')
        self.assertEqual(module(r.firm).parse(r),[])
        self.assertEqual(r.layout_selection['variant_id'],'peckshield/v2021_compliance')

    def test_blocksec_recommendation_total_is_a_separate_kind(self):
        r=report('Chapter 2 Findings\nHigh Risk: 1\nMedium Risk: 0\nRecommendation: 2\nNote: 3\n'+FIXTURES['blocksec_version']['text'],'blocksec')
        module(r.firm).parse(r)
        summary=module(r.firm).printed_counts(r)
        self.assertEqual(summary['counts'],{'high':1,'medium':0})
        self.assertIn('excluded_nonseverity_totals',summary)

    def test_blocksec_versioned_card_can_omit_risk_but_print_it_in_index(self):
        text='Chapter 2 Findings\nID    Severity    Description\n1     High        Improper permission check\n2.1 Security Issue\n2.1.1 Improper permission check\nStatus Fixed in Version 2\nIntroduced by Version 1\n'+BODY
        r=report(text,'blocksec');c=module(r.firm).parse(r)[0]
        self.assertEqual(r.layout_selection['variant_id'],'blocksec/v2025_version_fields')
        self.assertEqual(c.severity_raw,'High')
        self.assertEqual(c.evidence['severity_basis'],'printed_issue_index_row')

    def test_detail_risk_is_preserved_when_summary_disagrees(self):
        f=FIXTURES['peckshield_pve'];r=report('Severity Count\nHigh 0\nLow 1\n'+f['text'],'peckshield')
        c=module(r.firm).parse(r)[0]
        self.assertEqual(c.severity_raw,'High')
        self.assertEqual(module(r.firm).printed_counts(r)['counts']['high'],0)

    def test_toc_known_issues_does_not_exclude_new_least_authority_cards(self):
        text='Table of Contents\nKnown Issues\n\f'+FIXTURES['least_status_cards']['text']
        r=report(text,'least-authority');cs=module(r.firm).parse(r)
        self.assertEqual([c.printed_id for c in cs],['Issue A'])

    def test_iosiro_informational_scope_comes_from_explicit_source_section(self):
        table='<table class="findings-count"><tr><th>High</th><th>Informational</th></tr><tr><td>Open</td><td>1</td><td>3</td></tr></table>'
        scope='<h1 id="code-quality-improvement-suggestions">Code quality improvement suggestions</h1><p>Code improvement suggestions without security implications are listed below.</p>'
        r=report(table+scope,'iosiro');module(r.firm).parse(r)
        summary=module(r.firm).printed_counts(r)
        self.assertEqual(summary['counts'],{'high':1})
        self.assertEqual(summary['publisher_totals_outside_detail_scope'],{'info':3})
        r=report(table,'iosiro');module(r.firm).parse(r)
        self.assertEqual(module(r.firm).printed_counts(r)['counts']['info'],3)

    def test_loader_denies_holdout_before_any_cache_open(self):
        from variants_study import load
        with patch('variants_study.holdouts',return_value={'a'*64}),patch.object(Path,'read_text',side_effect=AssertionError('cache opened')):
            with self.assertRaisesRegex(ValueError,'Holdout'):load({'row':{'sha256':'a'*64}})


if __name__=='__main__':unittest.main()
