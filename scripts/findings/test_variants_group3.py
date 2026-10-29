"""Group 3 era selection, bounded finding extraction and explicit status tests."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import digest
from core import Report
from parsers import module
from fixtures_group3_variants import FIXTURES, D
from variants_group3_study import FIRMS


def report(text,firm,date=None):
    text='\f'*7+text
    pages=[];offset=0
    for i,part in enumerate(text.split('\f'),1):
        pages.append(dict(page=i,start=offset,end=offset+len(part),text=part))
        offset+=len(part)+1
    fmt='html' if (firm=='halborn' and '## Halborn Website Finding Records' in text) or (firm=='dedaub' and ('## VULNERABILITIES' in text or '## FOCUS POINTS' in text)) else 'md' if firm=='dedaub' and '# Findings / items' in text else 'pdf'
    return Report(text,dict(file_format=fmt,pages=pages,text_sha256=digest(text.encode()),date_hint=date),firm)


class Group3Variants(unittest.TestCase):
    def test_every_variant_fixture_selects_parses_and_records_exact_status(self):
        declared=set()
        for firm in FIRMS:
            for variant in module(firm).VARIANTS:
                self.assertFalse(variant.fingerprint.legacy)
                self.assertIsNotNone(variant.status_parser)
                self.assertTrue(variant.fixtures)
                for name in variant.fixtures:
                    declared.add(name)
                    with self.subTest(fixture=name):
                        publisher,text,era,n,state=FIXTURES[name]
                        self.assertEqual(publisher,firm)
                        r=report(text,firm)
                        cs=module(firm).parse(r)
                        self.assertEqual(r.layout_selection['variant_id'],firm+'/'+era)
                        self.assertEqual(len(cs),n)
                        for c in cs:
                            self.assertTrue(0<=c.start<c.end<=len(r.text))
                            self.assertEqual(c.normalized_status,state)
                            if state is not None:
                                ev=c.evidence['status_evidence']
                                self.assertEqual(r.text[ev['start']:ev['end']],ev['text'])
                                self.assertEqual(ev['text'],c.status_raw)
        self.assertEqual(declared,set(FIXTURES))

    def test_date_does_not_select_unknown_document(self):
        for firm in FIRMS:
            r=report('An unfamiliar report without a recognized layout.',firm,'2023-01-01')
            module(firm).parse(r)
            self.assertTrue(r.layout_selection['unknown_layout'])

    def test_recommendation_or_unrelated_fixed_keyword_is_not_status(self):
        for name in ('bailsec_identified','solidified_grouped','ackee_severity','macro_html','ncc_modern'):
            firm,text,_,_,_=FIXTURES[name]
            import re
            text=re.sub(r'(?im)^(?:Comments /.*|Resolution.*|Update.*|Status.*|Fixed.*|Not Fixed.*)$','',text)
            r=report(text+'\nRecommendation: This should be fixed; no fix has been reviewed.\n',firm)
            cs=module(firm).parse(r)
            self.assertTrue(cs,name)
            self.assertIsNone(cs[0].status_raw,name)

    def test_omega_preserves_conflicting_body_severity_without_regrading(self):
        firm,text,_,_,_=FIXTURES['omega_scoped']
        c=module(firm).parse(report(text,firm))[0]
        self.assertEqual(c.severity_raw,'low')
        self.assertEqual(c.normalized,'low')
        self.assertEqual(c.evidence['body_severity_raw'],'Critical')
        self.assertEqual(c.evidence['heading_severity_raw'],'low')

    def test_conflicting_ackee_index_does_not_fill_status(self):
        firm,text,_,_,_=FIXTURES['ackee_revision']
        text='H1: Unauthorized operation    High    1.0    Fixed\n'+text
        c=module(firm).parse(report(text,firm))[0]
        self.assertIsNone(c.status_raw)
        self.assertIn('status_index_conflict',c.evidence)

    def test_multiple_bailsec_response_rounds_use_last_explicit_cell(self):
        firm,text,_,_,_=FIXTURES['bailsec_identified']
        text+='Comments /       Resolved following another fix review.\nResolution\n'
        c=module(firm).parse(report(text,firm))[0]
        self.assertEqual(c.status_raw,'Resolved')
        self.assertEqual(len(c.evidence['status_claims']),2)

    def test_holdout_denied_before_any_text_open(self):
        from variants_study import load
        with patch('variants_study.holdouts',return_value={'0'*64}), patch.object(Path,'read_text',side_effect=AssertionError('opened text')):
            with self.assertRaisesRegex(ValueError,'Holdout'):
                load({'row':{'sha256':'0'*64}})

    def test_description_followed_by_page_footer_is_not_halborn_toc(self):
        r=report('FINDINGS & TECH DETAILS\n3.1 Actual issue - HIGH\nDescription\n'+D+'\n3.2 Another issue - LOW\nDescription\n\n9\f'+D,'halborn')
        self.assertEqual([c.printed_id for c in module(r.firm).parse(r)],['3.1','3.2'])

    def test_prior_omega_fix_section_is_excluded(self):
        firm,text,_,_,_=FIXTURES['omega_scoped']
        text+='\nFixes from older reports\nG2. Prior audit issue [low] [resolved]\n'+D
        cs=module(firm).parse(report(text,firm))
        self.assertEqual([c.printed_id for c in cs],['G1'])

    def test_bailsec_quality_advice_remains_separate_from_security_findings(self):
        r=report('Issue       Minor coding suggestions\nSeverity      Quality assurance\n'+D+'Comments      Acknowledged\n','bailsec')
        c=module(r.firm).parse(r)[0]
        self.assertEqual(c.record_kind,'recommendation')
        self.assertEqual(c.normalized,'info')

    def test_split_dedaub_status_has_exact_column_fragments(self):
        text='HIGH SEVERITY:\nID   Description                                                     STATUS\n\n'
        text+='      First title fragment'.ljust(77)+'PARTLY\n'
        text+='H1    Second title fragment'.ljust(77)+'RESOLVED\n\n'+D
        r=report(text,'dedaub');c=module(r.firm).parse(r)[0]
        self.assertEqual(c.normalized_status,'partial')
        for proof in c.evidence['status_fragments']:
            self.assertEqual(r.text[proof['start']:proof['end']],proof['text'])

    def test_dedaub_web_control_glyph_does_not_hide_native_id(self):
        firm,text,_,_,_=FIXTURES['dedaub_web']
        text=text.replace('### H1','### H1\x00\x00')
        c=module(firm).parse(report(text,firm))[0]
        self.assertEqual(c.printed_id,'H1')
        self.assertIn('\x00',c.evidence['id_raw'])

    def test_halborn_slash_cards_allow_spaced_sections_without_hal_id(self):
        text='7. 2 Caller validation is missing\n// LOW\nDescription\n'+D+'BVSS\nAO:A (3.1)\nRemediation\nSOLVED: caller validation was added.\n'
        c=module('halborn').parse(report(text,'halborn'))[0]
        self.assertEqual(c.printed_id,'7.2')
        self.assertEqual(c.normalized_status,'fixed')

    def test_macro_pdf_counts_skip_repeated_navigation(self):
        from parsers.macro import counts_printed_html
        text='Overall Assessment\nSpecification\n\fOverall Assessment\nMedium   4   -  4\nLow   1   -  1\nSpecification\n'
        self.assertEqual(counts_printed_html(report(text,'macro'))['counts'],{'medium':4,'low':1})

    def test_solidified_requirements_do_not_consume_real_issue_ids(self):
        text='Issues Found\nMinor\n\n1. First vulnerability\n\n'+D
        text+='10. A contract MUST follow a requirement\n11. It MUST follow another requirement\n\n'
        text+='2. Second vulnerability\n\n'+D
        cs=module('solidified').parse(report(text,'solidified'))
        self.assertEqual([c.printed_id for c in cs],['1','2'])


if __name__=='__main__': unittest.main()
