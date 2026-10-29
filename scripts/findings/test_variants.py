"""Layout selection, era grammar, remediation and compatibility regressions."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from dataclasses import asdict
from core import severity_context,candidate_severity
from prior_findings import exclude_prior_findings
from importlib import import_module
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import digest
from core import Report, Candidate, finish
from parsers import module
from variants import Variant, Fingerprint, dispatch, select, legacy, index_line
from layout_support import attach_status
from structured import render_report

D='\nDescription: Source evidence explains the affected path and the impact.\n'*3
FIXTURES={
 'chainsecurity_inline':('chainsecurity','3 Details of the Findings\n3.1 Actual vulnerability High Ë Fixed'+D,'v2017_inline',1),
 'chainsecurity_classification':('chainsecurity','5 Findings\n5.1 Actual vulnerability\nSecurity High\n'+D,'v2018_classification',1),
 'chainsecurity_version':('chainsecurity','5.1 Actual vulnerability\nCorrectness Medium Version 1 Code Partially Corrected\n'+D,'v2021_version_cards',1),
 'ottersec_bracket':('ottersec','OS-TST-ADV-00 [High] [Resolved] | Actual vulnerability'+D,'v2022_brackets',1),
 'ottersec_general':('ottersec','OS-TST-SUG-00 [resolved] | Supplementary observation'+D,'v2022_brackets',1),
 'ottersec_title':('ottersec','Actual vulnerability    H I G H    OS-TST-ADV-00'+D,'v2023_title_badges',1),
 'ottersec_table':('ottersec','Test Security Assessment\n\nActual vulnerability\n\nID      Severity      Status\nOS-TST-ADV-00   High   ✓ Resolved'+D,'v2025_metadata_tables',1),
 'quantstamp_qsp':('quantstamp','QSP-1 Actual vulnerability\nSeverity: High Risk'+D,'v2019_qsp_cards',1),
 'quantstamp_fields':('quantstamp','Findings\nActual vulnerability\nSeverity: Informational\nStatus: Fixed'+D+'Test Results\nOther text','v2018_unnumbered_fields',1),
 'quantstamp_columns':('quantstamp','Findings\nLeft title'+(' '*65)+'Right title\nSeverity: High'+(' '*60)+'Severity: Low\n'+D,'v2018_columns',2),
 'quantstamp_native':('quantstamp','NATIVE','v2020_native_json',1),
 'cantina_nested':('cantina','3.1.1 High Risk\n3.1.1.1 Actual vulnerability    Severity: High Risk'+D,'v2024_nested_sections',1),
 'cantina_major_minor':('cantina','3.1 Major Risk\n3.1.1 Actual vulnerability\nSeverity: Major Risk'+D,'v2023_major_minor',1),
 'cantina_limited_competition':('cantina','This report only outlines the high and medium risk issues.\n3.1 High Risk\n3.1.1 Actual vulnerability\nSeverity: High Risk'+D,'v2023_competition_numbered',1),
 'cantina_numbered':('cantina','3.1 High Risk\n3.1.1 Actual vulnerability\nSeverity: High Risk'+D+'Cantina: Fixed.\n','v2023_numbered_reviews',1),
 'cantina_competition':('cantina','## [H-01] Actual vulnerability'+D,'v2023_competition',1),
 'kudelski_summary':('kudelski-security','Table 2: Findings Overview\nTechnical Findings\nKS-TST-F-01   High   Actual issue description    Resolved\n'+D,'v2022_summary_only',1),
 'kudelski_matrix':('kudelski-security','3.1 KS-TST-F-01 Actual vulnerability\nSeverity    Impact    Likelihood    Status\nMedium    High    Low    Resolved'+D,'v2025_risk_matrix',1),
 'kudelski_ks':('kudelski-security','2.1 KS-TST-F-01: Actual vulnerability\nSeverity: High\nStatus: Fixed'+D,'v2022_ks_fields',1),
 'kudelski_numbered':('kudelski-security','TECHNICAL FINDINGS\n2.1 Actual vulnerability\nSeverity: High'+D,'v2020_numbered_fields',1),
 'kudelski_title_before_id':('kudelski-security','TECHNICAL FINDINGS\n\nActual vulnerability\nFinding ID: KS-TST-F-01\nSeverity: [High]\nStatus: [Remediated]'+D,'v2021_title_before_id',1),
 'kudelski_architecture':('kudelski-security','Architectural Security Review\n5 GENERAL FINDINGS AND CLAIMS\n5.1 General observation'+D,'v2019_architecture',1),
 'kudelski_threat':('kudelski-security','Threat Model\nSeverity Potential: High'+D,'v2021_threat_model',0),
 'theori_issue':('theori','Issue #1: Actual vulnerability\nSummary    Severity\nAn explicit summary    High\nDescription\n'+D,'v2021_issue_cards',1),
 'theori_vertical':('theori','Issue #1:\nActual vulnerability\nSummary\nSeverity\nAn explicit summary\nFixed (High)\nDescription\n'+D,'v2021_vertical_issue_cards',1),
 'theori_modern':('theori','#1 THE-TST-001 Actual vulnerability\nSummary    Severity\nAn explicit summary    High\nDescription\n'+D,'v2023_the_cards',1),
 'theori_bilingual':('theori','4.2.1. ORB-001: Actual vulnerability\nID Code    Severity\nORB-001     High\nDescription\n'+D,'v2022_bilingual',1),
 'zokyo_numbered':('zokyo','Complete Analysis\nHigh-1 Resolved\nActual vulnerability\n\n'+D,'v2022_numbered_cards',1),
 'zokyo_status':('zokyo','Complete Analysis\nHigh Resolved\nActual vulnerability\n\n'+D,'v2021_status_cards',1),
 'zokyo_title_first':('zokyo','Complete Analysis\n\nActual vulnerability\n\nHIGH\n\n'+D,'v2020_title_first',1),
 'zokyo_metadata':('zokyo','Findings\nActual vulnerability\nSeverity Medium\nStatus FIXED'+D,'v2021_metadata',1),
 'chainsecurity_risk_codes':('chainsecurity','Security Issues\nActual vulnerability H 3 Fixed'+D,'v2018_risk_codes',1),
 'chainsecurity_overview':('chainsecurity','1.1 Overview of the Findings\n5 Findings\nNo graded issues were found.','v2021_overview',0),
 'chainsecurity_supporting':('chainsecurity','Management Summary\nA summary letter without finding details.','v2019_supporting',0),
 'ottersec_spaced':('ottersec','A c t u a l   v u l n e r a b i l i t y    H I G H    O S - T S T - A D V - 0 0'+D,'v2024_letter_spaced',1),
 'ottersec_supporting':('ottersec','K-Lend Formal Verification Audit\nFramework Usage','v2022_supporting',0),
 'cantina_deployment':('cantina','4.1 Deployment Validation Results\nBytecode and configuration checklist.','v2024_deployment_checks',0),
 'cantina_scope_only':('cantina','About Cantina\nRisk assessment\n2.1 Scope\nNo issues were identified.','v2023_scope_only',0),
 'kudelski_retest':('kudelski-security','Retest Report\n1 – Earlier issue\nSeverity    Resolved'+D,'v2022_retest',0),
 'quantstamp_project':('quantstamp','Findings\nMAR-1\nActual vulnerability    • High    Fixed\nUpdate\nMarked as Fixed by the client.'+D,'v2024_project_cards',1),
 'quantstamp_outcome':('quantstamp','Total Issues 0\nThere are no issues to report.','v2019_outcome_only',0),
 'quantstamp_sparse':('quantstamp','Architecture Review, Unit Testing, Functional\nTesting, Computer-Aided Verification, Manual\nReview','v2021_sparse_text',0),
 'zokyo_outcome':('zokyo','zokyo\nThere were no critical issues found during the audit.\nNo detailed cards were published.','v2021_outcome_only',0),
 'zokyo_image_badges':('zokyo','Issues are tagged Resolved or Unresolved.\nComplete Analysis\nThe badge images have no textual labels.','v2021_image_badges',0),
 'theori_missing_glyphs':('theori','rewardPerBlock totalDeposit\n_calcNewRewardLane','v2021_missing_glyphs',0),
 'zokyo_sectioned':('zokyo','Detailed Findings\nLow-Severity Issues\n1. Actual vulnerability'+D,'v2024_sectioned_findings',1),
 'zokyo_ocr_numbered':('zokyo','Complete Analysis\n=F) CRITICAL-1\nActual vulnerability\n\n'+D,'v2022_ocr_badges',1),
}


def report(text,firm,fmt='pdf',date=None):
    pages=[];offset=0
    for i,p in enumerate(text.split('\f'),1):
        pages.append(dict(page=i,start=offset,end=offset+len(p),text=p));offset+=len(p)+1
    return Report(text,dict(file_format=fmt,pages=pages,text_sha256=digest(text.encode()),date_hint=date),firm)


def fixture(name):
    firm,text,era,count=FIXTURES[name]
    r=report(text,firm)
    if name=='zokyo_ocr_numbered':r.meta['issues']=[dict(kind='ocr_page',page=1)]
    if name=='quantstamp_native':
        text,native=render_report({'reportContent':{'breakdownAndAutomatedAnalysis':{'vulnerabilitiesArray':[{'id':'QSP-1','title':'Actual vulnerability','severity':'High','status':'Fixed','description':D}]}}})
        r=report(text,firm,'other');r.native=native
    return r,era,count


class VariantTests(unittest.TestCase):
    def test_index_padding_does_not_hide_prose_or_stall_layout_selection(self):
        for text in ('Title .... 12','Title . . . . 12','Title   12',
                     'Title\t\t\t１２','Title'+' '*20000+'12'):
            self.assertTrue(index_line(text),repr(text[:60]))
        for text in ('Title ... 12','Title  12','Title 12','12',
                     'Title'+' '*20000+'Actual vulnerability'):
            self.assertFalse(index_line(text),repr(text[:60]))
        r=report('Title'+' '*20000+'Actual vulnerability\n', 'test')
        fingerprint=Fingerprint((('actual prose',r'Actual vulnerability',6),))
        self.assertEqual(fingerprint.score(r)['score'],6)
        self.assertFalse(index_line('Title   12',padded=False))
        self.assertTrue(index_line('Title .... 12',padded=False))

    def test_every_declared_fixture_selects_and_parses_its_variant(self):
        declared=set()
        for firm in ('chainsecurity','ottersec','quantstamp','cantina','kudelski-security','theori','zokyo'):
            for variant in module(firm).VARIANTS:
                self.assertTrue(variant.fixtures)
                for name in variant.fixtures:
                    declared.add(name)
                    with self.subTest(name=name):
                        r,era,count=fixture(name);out=module(firm).parse(r)
                        self.assertEqual(r.layout_selection['variant_id'],firm+'/'+era)
                        self.assertEqual(len(out),count)
                        for c in out:self.assertTrue(0<=c.start<c.end<=len(r.text))
        self.assertEqual(declared,set(FIXTURES))

    def test_whitespace_heavy_report_has_bounded_fingerprints(self):
        r=report((' '*6000+'\n')*4,'ottersec')
        self.assertEqual(module('ottersec').parse(r),[])

    def test_date_hint_cannot_outvote_a_specific_numbered_card(self):
        r,_,_=fixture('zokyo_numbered')
        r.meta['date_hint']='2021-01-01'
        module(r.firm).parse(r)
        self.assertEqual(r.layout_selection['variant_id'],'zokyo/v2022_numbered_cards')

    def test_date_cannot_select_unknown_layout(self):
        r=report('A completely unfamiliar document.','ottersec',date='2023-01-01')
        self.assertEqual(module('ottersec').parse(r),[])
        self.assertTrue(r.layout_selection['unknown_layout'])

    def test_summary_caption_cannot_override_actual_detail_fields(self):
        r=report('Table 2: Findings Overview\nTECHNICAL FINDINGS\n2.1 KS-TST-F-01: Actual vulnerability\nSeverity: High'+D,'kudelski-security')
        cs=module(r.firm).parse(r)
        self.assertEqual(r.layout_selection['variant_id'],'kudelski-security/v2022_ks_fields')
        self.assertEqual(len(cs),1)

    def test_best_score_and_stable_order_tie(self):
        r=report('card title','test')
        variants=(Variant('test/one',Fingerprint((('word','card',6),)),lambda r:[],()),Variant('test/two',Fingerprint((('word','card',8),)),lambda r:[],()))
        self.assertEqual(select(r,variants).variant_id,'test/two')
        self.assertEqual(select(r,(variants[0],variants[0].__class__('test/tie',variants[0].fingerprint,lambda r:[],()))).variant_id,'test/one')

    def test_generic_fallback_is_flagged_without_changing_spans(self):
        r=report('## [H-01] An unknown layout'+D,'chainsecurity','md')
        c=module('chainsecurity').parse(r)[0]
        self.assertEqual(c.method,'generic_fallback')
        self.assertEqual(c.evidence['variant_id'],'chainsecurity/generic_fallback')
        self.assertTrue(c.evidence['unknown_layout'])
        self.assertEqual(c.start,0)

    def test_all_legacy_contracts_match_the_existing_grammar(self):
        from parsers import FIRMS,GROUP1,GROUP2,GROUP3,CONTESTS
        texts=['## [H-01] Actual vulnerability'+D,'2.1 Actual vulnerability\nSeverity: High\nStatus: Fixed'+D]
        for firm in FIRMS+GROUP1+GROUP2+GROUP3+CONTESTS+('nethermind','codespect'):
            adapter=module(firm)
            if not adapter.VARIANTS[0].fingerprint.legacy:continue
            self.assertEqual(adapter.VARIANTS[0].fixtures,('legacy_contract',))
            raw=import_module(adapter.__name__)
            for text in texts:
                with self.subTest(firm=firm,text=text[:15]):
                    r=report(text,firm,'md')
                    with severity_context(r):
                        expected=exclude_prior_findings(r,raw.parse(r))
                        for c in expected:c.normalized=candidate_severity(r,c)['normalized']
                    actual=adapter.parse(report(text,firm,'md'))
                    for c in actual:c.evidence.pop('variant_id',None)
                    self.assertEqual([asdict(c) for c in actual],[asdict(c) for c in expected])

    def test_legacy_wrapper_preserves_raw_parser_behavior(self):
        c=Candidate(0,'Short','High',end=12)
        r=report('Short body','legacy')
        self.assertEqual(dispatch(r,(legacy('legacy',lambda r:[c]),)),[c])

    def test_status_resolution_is_not_inferred_from_recommendation(self):
        r=report('QSP-1 Actual vulnerability\nSeverity: High'+D+'Recommendation: This should be fixed.','quantstamp')
        self.assertIsNone(module('quantstamp').parse(r)[0].status_raw)

    def test_status_index_and_fix_review_reference(self):
        r=report('QSP-1 Actual vulnerability\nSeverity: High'+D+'\nAppendix\nFix Review\nQSP-1    Fixed\n','quantstamp')
        c=module('quantstamp').parse(r)[0]
        self.assertEqual(c.status_raw,'Fixed')
        e=c.evidence['status_evidence'];self.assertEqual(r.text[e['start']:e['end']],e['text'])

    def test_conflicting_index_does_not_infer_status(self):
        r=report('QSP-1 Actual vulnerability\nSeverity: High'+D+'\nAppendix\nQSP-1    Fixed\nQSP-1    Open\n','quantstamp')
        c=module('quantstamp').parse(r)[0]
        self.assertIsNone(c.status_raw)
        self.assertTrue(c.evidence['status_conflict'])

    def test_container_children_are_not_additional_quantstamp_findings(self):
        r=report('Findings\nOther issues\nSeverity: Informational'+D+'1. Child issue\n2. Another child\n'+D,'quantstamp')
        self.assertEqual(len(module('quantstamp').parse(r)),1)

    def test_toc_and_index_are_not_ottersec_cards(self):
        r=report('Contents\nOS-TST-ADV-00 [High] [Resolved] | Actual issue ..... 3\n\fID  Severity  Status  Description\nOS-TST-ADV-00    High    Resolved    Actual issue\n'+D,'ottersec')
        cs=module('ottersec').parse(r)
        self.assertEqual(len(cs),1)
        self.assertEqual(cs[0].record_kind,'summary_excerpt')
        self.assertEqual(cs[0].method,'summary_inventory')
        self.assertEqual(cs[0].title,'Actual issue')

    def test_container_children_do_not_duplicate_parent_counts(self):
        r=report('3.1 Low Risk\n3.1.1 Minor issues\nSeverity: Low Risk\nDescription/Recommendation:\n  1. First small issue\n'+D+'  2. Second small issue\n'+D,'cantina')
        cs=module(r.firm).parse(r)
        self.assertEqual(sum(c.record_kind=='formal_finding' for c in cs),1)
        self.assertEqual(sum(c.record_kind=='recommendation' for c in cs),2)

    def test_glyph_spaced_label_preserves_source_spelling(self):
        r=report('Actual vulnerability    H I G H    OS-TST-ADV-00'+D,'ottersec')
        c=module('ottersec').parse(r)[0]
        self.assertEqual(c.severity_raw,'H I G H')
        self.assertEqual(c.normalized,'high')

    def test_cantina_comparison_uses_only_explicit_publisher_scope(self):
        text='Severity Count\nHigh 1\nMedium 2\nLow 3\nInformational 4\nThis report only outlines the high and medium risk issues.'
        r=report(text,'cantina');module(r.firm).parse(r)
        summary=module(r.firm).printed_counts(r)
        self.assertEqual(summary['counts'],{'high':1,'medium':2})
        self.assertEqual(summary['publisher_totals_outside_detail_scope'],{'low':3,'info':4})
        r=report(text.split('This report')[0],'cantina');module(r.firm).parse(r)
        self.assertIn('low',module(r.firm).printed_counts(r)['counts'])

    def test_conflicting_independent_zokyo_summaries_are_ambiguous(self):
        from parsers.zokyo import printed_counts
        text='Scoring Calculation\nStarting with a perfect score\n- 0 High issues: 1 resolved\n- 1 Low issue: 1 resolved\n\fFindings summary\n1 Actual issue    High    Resolved\n'
        r=report(text,'zokyo')
        summary=printed_counts(r)
        self.assertTrue(summary['ambiguous'])
        self.assertTrue(summary['summary_conflict'])
        self.assertEqual(summary['counts']['high'],0)

    def test_ocr_rejects_loss_of_existing_risk_badge(self):
        from layout_ocr import acceptable
        ok,proof=acceptable('High-1 Resolved\nOld title\n','Low-1 Resolved\nOld title\nLow-2 Fixed\n')
        self.assertFalse(ok)
        self.assertIn('existing_risk_label_lost',proof['rejections'])

    def test_sequence_keeps_pdf_case_changes_in_one_namespace(self):
        from variants_report import sequence
        rows=[{'publisher_finding_id':pid,'record_kind':'formal_finding'} for pid in ('LOW-1','Low-2')]
        self.assertTrue(sequence(rows,'zokyo')['complete'])

    def test_opaque_native_ids_do_not_create_numeric_sequence(self):
        from variants_report import sequence
        row={'publisher_finding_id':'461571b7-78ba-4796-a1ce-4b1a9ba32665','record_kind':'formal_finding'}
        self.assertIsNone(sequence([row],'quantstamp'))

    def test_verified_zokyo_badge_does_not_infer_remediation(self):
        r=report('Complete Analysis\nInfo-1 Verified\nActual title\n\n'+D,'zokyo')
        c=module(r.firm).parse(r)[0]
        self.assertEqual(c.status_raw,'Verified')
        self.assertEqual(c.normalized_status,'other')

    def test_auxiliary_queue_is_not_a_classifier_finding_stream(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('variant_classifier_common',Path(__file__).resolve().parents[1]/'classify/common.py')
        classifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(classifier)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/'data/holdout').mkdir(parents=True)
            (root/'data/holdout/gold_sha256.txt').write_text('a'*64+'\n')
            (root/'registry').mkdir()
            (root/'registry/scope_tier_a.csv').write_text('firm_id,scope_group\nzokyo,firm\n')
            (root/'data/findings').mkdir()
            row=dict(sha256='b'*64,firm_id='zokyo',finding_id='finding:fixture',document_id='document:fixture',title='Title',body_text='Body',severity='low')
            (root/'data/findings/zokyo.jsonl').write_text(json.dumps(row)+'\n')
            (root/'data/findings/_unknown_layouts.jsonl').write_text(json.dumps({'sha256':'b'*64,'firm':'zokyo','document_ids':[]})+'\n')
            rows,ledger,_=classifier.load_findings(root)
            self.assertEqual(len(rows),1)
            self.assertEqual([r['path'] for r in ledger],['data/findings/zokyo.jsonl'])

    def test_partial_queue_rebuild_preserves_other_firms_and_denies_holdouts(self):
        from run import rebuild_unknown_queue
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);folder=root/'data/findings/validation';folder.mkdir(parents=True)
            diag=dict(document_id='document:fixture',sha256='b'*64,firm_id='old',unknown_layout=True,year='2020',scores=[])
            (folder/'old.jsonl').write_text(json.dumps(diag)+'\n')
            docs=[{'row':{'firm_id':'old'}}]
            with patch('run.read_snapshot',return_value=docs),patch('run.holdouts',return_value=set()):rebuild_unknown_queue(root)
            queued=json.loads((root/'data/findings/_unknown_layouts.jsonl').read_text())
            self.assertEqual(queued['firm'],'old')
            with patch('run.read_snapshot',return_value=docs),patch('run.holdouts',return_value={'b'*64}):
                with self.assertRaisesRegex(ValueError,'Holdout'):rebuild_unknown_queue(root)

    def test_native_status_keeps_json_pointer(self):
        r,_,_=fixture('quantstamp_native');c=module(r.firm).parse(r)[0]
        self.assertEqual(c.status_raw,'Fixed');self.assertIn('json_pointer',c.evidence)

if __name__=='__main__':unittest.main()
