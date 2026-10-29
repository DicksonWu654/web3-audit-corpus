"""Recall regressions: layout boundaries, source IDs, OCR and container cardinality."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import digest
from core import Report
from parsers import module
from test_variants import report, D


class RecallTests(unittest.TestCase):
    def test_soullycanto_retained_ocr_boundaries_and_ordinals(self):
        from common import ROOT, holdouts
        from core import finish
        sha='9412317ce1b293aee09b94dce1fda17dcfb5d74992320fb38025d2161b361faa'
        if not (ROOT/'data/holdout/gold_sha256.txt').is_file():
            self.skipTest('Requires locally acquired corpus and holdout inputs')
        self.assertNotIn(sha,holdouts())
        path=ROOT/'local-cache/fulltext'/sha
        if not path.with_suffix('.pages.json').exists():
            self.skipTest('Retained source cache is local only')
        text=path.with_suffix('.txt').read_bytes().decode()
        meta=json.loads(path.with_suffix('.pages.json').read_text())
        self.assertEqual(digest(text.encode()),meta['text_sha256'])
        r=Report(text,meta,'zokyo');cs=finish(r,module('zokyo').parse(r))
        ids=[c.printed_id for c in cs]
        self.assertEqual(len(ids),20)
        self.assertEqual(ids[:2],['HIGH-1','MEDIUM-1'])
        self.assertEqual(ids[15:],['INFO-10','INFO-11','INFO-13','INFO-14','INFO-15'])
        medium=cs[1];info10,info11=cs[15:17]
        self.assertEqual(medium.start,9685)
        self.assertEqual(info11.start,19315)
        self.assertEqual(cs[0].end,medium.start)
        self.assertEqual(info10.end,info11.start)
        self.assertNotIn('Variables are being re-initialized',text[info10.start:info10.end])

    def test_quantstamp_damaged_separator_and_wrapped_title(self):
        r=report('ID    DESCRIPTION    SEVERITY    STATUS\nSWP�1 Inventory row    • High    Fixed\n\f'
                 'Findings\nSWP�1 Wrapped\nactual title    • Medium    Acknowledged\n'+D+
                 'SWP�2 Second title    • Low    Fixed\n'+D+'Definitions\nOther material.','quantstamp')
        cs=module('quantstamp').parse(r)
        self.assertEqual([c.printed_id for c in cs],['SWP-1','SWP-2'])
        self.assertEqual(cs[0].title,'Wrapped actual title')
        self.assertEqual(cs[0].severity_raw,'Medium')
        self.assertNotIn('Definitions',r.text[cs[-1].start:cs[-1].end])

    def test_quantstamp_container_is_not_split_into_children(self):
        r=report('Findings\nOther issues\nSeverity: Informational\n'+D+
                 '1. First child\n'+D+'2. Second child\n'+D,'quantstamp')
        self.assertEqual(len(module('quantstamp').parse(r)),1)

    def test_hats_bold_sections_restart_numbers_in_their_own_namespace(self):
        r=report('## **Findings**\n### **Medium severity findings:**\n1. **One finding**\n'+D+
                 '### **Low severity finding:**\n1. **Another finding**\n'+D,'hats-finance')
        r.meta['file_format']='md'
        cs=module(r.firm).parse(r)
        self.assertEqual(len(cs),2)
        self.assertEqual([c.printed_id for c in cs],['1','1'])
        self.assertEqual([c.evidence['container_id'] for c in cs],['medium','low'])

    def test_iosiro_classless_quality_table_has_explicit_section_bounds(self):
        text='<h1>Audit findings</h1><table><tr><th>ID</th><th>Issue</th><th>Risk</th><th>Status</th></tr>'
        text+='<tr><td>IO-TEST-001</td><td>Real suggestion</td><td>Informational</td><td>Resolved</td></tr></table>'
        text+='<h1>Code quality improvement suggestions</h1><p>Code improvement suggestions without security implications are listed below.</p>'
        text+='<table><tr><td>IO-TEST-001</td><td>test.sol</td><td>A complete code improvement suggestion.</td></tr></table>'
        text+='<h1>Specification</h1><table><tr><td>IO-TEST-002</td><td>Other</td><td>Not a finding row.</td></tr></table>'
        r=report(text,'iosiro');cs=module('iosiro').parse(r)
        self.assertEqual([c.printed_id for c in cs],['IO-TEST-001'])
        self.assertEqual(cs[0].record_kind,'formal_finding')
        self.assertEqual(cs[0].severity_raw,'Informational')

    def test_zokyo_ocr_numbered_badge_icon_and_fused_status(self):
        text='Complete Analysis\n=F) CRITICAL-1\nFirst title\n\n'+D+'7 INFORMATIONAL-2veer\nSecond title\n\n'+D
        r=report(text,'zokyo');r.meta['issues']=[dict(kind='ocr_page',page=1)]
        cs=module('zokyo').parse(r)
        self.assertEqual([c.printed_id for c in cs],['CRITICAL-1','INFORMATIONAL-2'])
        r=report(text,'zokyo')
        self.assertFalse(module('zokyo').parse(r))

    def test_zokyo_image_grade_without_readable_status_is_a_finding(self):
        from parsers import zokyo
        text='Actual printed title\n\n'+D;r=report(text,'zokyo')
        span=dict(start=0,end=len('Actual printed title'),text='Actual printed title')
        claim=dict(card_start=0,source_span=span,title_span=span,risk_raw='High',status_raw=None,
                   printed_id='HIGH-1',review_method='recall_badge_ocr')
        with patch.object(zokyo,'visual_receipts',return_value=[claim]):
            cs=zokyo.image_badges(r)
        self.assertEqual(len(cs),1);self.assertEqual(cs[0].printed_id,'HIGH-1')
        self.assertEqual(cs[0].evidence['severity_ocr_evidence'],claim)

    def test_zokyo_duplicate_image_receipts_do_not_zero_the_body_span(self):
        from parsers import zokyo
        from core import finish
        r=report('Actual printed title\n\n'+D,'zokyo');span=dict(start=0,end=20,text='Actual printed title')
        old=dict(card_start=0,source_span=span,title_span=span,risk_raw='High',status_raw='Resolved')
        fresh=old|dict(printed_id='HIGH-1',review_method='recall_badge_ocr',title_match_score=1.0)
        with patch.object(zokyo,'visual_receipts',return_value=[old,fresh]):
            cs=finish(r,zokyo.image_badges(r))
        self.assertEqual(len(cs),1);self.assertEqual(cs[0].printed_id,'HIGH-1')
        self.assertEqual(cs[0].end,len(r.text))

    def test_zokyo_native_card_and_its_image_receipt_are_one_entry(self):
        from parsers import zokyo
        text='Complete Analysis\nHigh-1 Resolved\nActual printed title\n\n'+D
        r=report(text,'zokyo');a=text.index('Actual printed title');span=dict(start=a,end=a+20,text=text[a:a+20])
        claim=dict(card_start=a,source_span=span,title_span=span,risk_raw='High',status_raw='Resolved',printed_id='High-1')
        with patch.object(zokyo,'visual_receipts',return_value=[claim]):
            self.assertEqual(len(module('zokyo').parse(r)),1)

    def test_zokyo_repeated_ids_on_distinct_native_cards_are_retained(self):
        from parsers import zokyo
        text='Complete Analysis\nHigh-1 Resolved\nFirst source finding\n\n'+D+'High-1 Resolved\nSecond source finding\n\n'+D
        r=report(text,'zokyo');a=text.index('Second source finding');span=dict(start=a,end=a+21,text=text[a:a+21])
        claim=dict(card_start=a,source_span=span,title_span=span,risk_raw='High',status_raw='Resolved',printed_id='High-1')
        with patch.object(zokyo,'visual_receipts',return_value=[claim]):
            self.assertEqual(len(module('zokyo').parse(r)),2)

    def test_zokyo_audit_iterations_have_independent_ids(self):
        r=report('Complete Analysis\n1ST AUDIT ITERATION COMPLETE ANALYSIS\nHigh-1 Resolved\nFirst finding\n\n'+D+
                 '2ND AUDIT ITERATION COMPLETE ANALYSIS\nHigh-1 Resolved\nSecond finding\n\n'+D,'zokyo')
        cs=module('zokyo').parse(r)
        self.assertEqual(len(cs),2)
        self.assertNotEqual(cs[0].evidence['container_id'],cs[1].evidence['container_id'])

    def test_fuzzland_critical_and_container_subheadings(self):
        r=report('## Detailed Findings\n### [Critical] Parent finding\n\n'+D+
                 '#### Child recommendation\n'+D+'### Appendix\n'+D,'fuzzland')
        r.meta['file_format']='html'
        cs=module('fuzzland').parse(r)
        self.assertEqual(len(cs),1);self.assertEqual(cs[0].severity_raw,'Critical')
        self.assertNotIn('Appendix',r.text[cs[0].start:cs[0].end])

    def test_theori_vertical_card_does_not_steal_next_grade(self):
        r=report('Issue #1\nFirst title\nSummary\nSeverity\nDescription\n'+D+
                 'Issue #2\nSecond title\nSummary\nSeverity\nHigh\nDescription\n'+D,'theori')
        cs=module('theori').parse(r)
        self.assertEqual([c.printed_id for c in cs],['Issue #2'])

    def test_theori_horizontal_card_does_not_steal_next_grade(self):
        r=report('Issue #1: Missing grade\nSummary    Severity\nUnclassified summary\n'
                 'Issue #2: Classified issue\nSummary    Severity\nExplicit summary    High\nDescription\n'+D,'theori')
        cs=module('theori').parse(r)
        self.assertEqual([c.printed_id for c in cs],['Issue #2'])

    def test_live_development_layouts(self):
        from recall_push import LOCAL,inputs,load
        if not (LOCAL/'inputs.json').exists():self.skipTest('Local development corpus unavailable')
        cases=(('120cd202dbd0',36),('6a58f565da3b',21),('f00cfcd3386e',34),
               ('21b1ab2c3fe2',8),('6d4abe6b1232',22),('9d2c2e60b187',37),
               ('8e46ba73aec2',45),('f2138467621b',33),('e09814e92ebc',11))
        docs=inputs()
        for prefix,count in cases:
            with self.subTest(original=prefix):
                d=next(d for d in docs if d['row']['sha256'].startswith(prefix));r=load(d)
                cs=module(r.firm).parse(r)
                if prefix=='8e46ba73aec2':
                    self.assertGreaterEqual(len(cs),count)
                    ids={c.printed_id.casefold() for c in cs if c.printed_id}
                    self.assertTrue({'medium-9','low-9','informational-12'}<=ids)
                else:self.assertEqual(len(cs),count)
                if prefix=='21b1ab2c3fe2':self.assertEqual([c.printed_id for c in cs],[f'SWP-{i}' for i in range(1,9)])


if __name__=='__main__':unittest.main()
