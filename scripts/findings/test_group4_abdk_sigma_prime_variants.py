"""Publisher-only synthetic variant/status regressions; no document-cache reads."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import digest
from core import Report
from fixtures_group4_abdk_sigma_prime import D, FIXTURES
from parsers import module
from parsers import abdk_consulting, sigma_prime


def report(text, firm='abdk-consulting', date='2023-01', fmt='pdf'):
    pages = []
    start = 0
    for i, value in enumerate(text.split('\f'), 1):
        pages.append({'page': i, 'start': start, 'end': start+len(value), 'text': value})
        start += len(value)+1
    return Report(text, {'file_format': fmt, 'date_hint': date, 'text_sha256': digest(text.encode()),
                        'pages': pages}, firm)


def fixture(name):
    firm, date, fmt, era, text, n = FIXTURES[name]
    r = report(text, firm, date, fmt)
    return r, module(firm).parse(r)


class VariantTests(unittest.TestCase):
    def test_each_declared_fixture_selects_its_variant(self):
        for firm in ('abdk-consulting', 'sigma-prime'):
            for variant in module(firm).VARIANTS:
                self.assertFalse(variant.fingerprint.legacy)
                self.assertTrue(variant.fingerprint.date_range)
                self.assertIsNotNone(variant.status_parser)
                for name in variant.fixtures:
                    with self.subTest(firm=firm, fixture=name):
                        source_firm, date, fmt, era, text, n = FIXTURES[name]
                        r, cs = fixture(name)
                        self.assertEqual(source_firm, firm)
                        self.assertEqual(r.layout_selection['variant_id'], firm+'/'+era)
                        self.assertEqual(len(cs), n)
                        for c in cs:
                            if c.evidence.get('status_evidence'):
                                e = c.evidence['status_evidence']
                                self.assertEqual(r.text[e['start']:e['end']], e['text'])
                                self.assertEqual(e['text'], c.status_raw)

    def test_abdk_empty_status_field_uses_matching_inventory_id(self):
        r, cs = fixture('abdk_empty_status_table')
        self.assertEqual(cs[0].status_raw, 'Fixed')
        self.assertEqual(cs[0].normalized_status, 'fixed')
        self.assertEqual(cs[0].evidence['status_evidence']['basis'], 'printed_id_status_table')

    def test_abdk_info_status_is_independent_of_severity(self):
        text = '6 Major Issues\nCVF-1 INFO\n • Category Flaw • Source A.sol\nDescription '+D
        r = report(text)
        c = module(r.firm).parse(r)[0]
        self.assertEqual((c.normalized, c.normalized_status), ('high', 'info'))

    def test_abdk_spaced_status_preserves_exact_evidence(self):
        r, cs = fixture('abdk_spaced_grouped')
        self.assertEqual(cs[0].status_raw, 'F I X E D')
        self.assertEqual(cs[0].normalized_status, 'fixed')

    def test_abdk_conflicting_inventory_does_not_fill_empty_field(self):
        text = FIXTURES['abdk_empty_status_table'][4].replace('CVF-1    Major      Flaw        Fixed',
            'CVF-1    Major      Flaw        Fixed\nCVF-1    Major      Flaw        Opened')
        r = report(text)
        c = module(r.firm).parse(r)[0]
        self.assertIsNone(c.status_raw)
        self.assertTrue(c.evidence['status_conflict'])

    def test_abdk_parent_fixed_section_has_evidence(self):
        r, cs = fixture('abdk_bullets')
        self.assertEqual(cs[0].normalized_status, 'fixed')
        self.assertIsNone(cs[1].status_raw)

    def test_abdk_local_numeric_ids_have_section_namespaces(self):
        r, cs = fixture('abdk_legacy_lists')
        self.assertEqual([c.evidence['container_id'] for c in cs], ['2.1', '2.2'])

    def test_abdk_short_native_item_retains_exact_span(self):
        text = 'ABDK Review\n2.1 Other Issues\n 1. Address should not be public.\n 2. '+D
        r = report(text, date='2018-01')
        cs = module(r.firm).parse(r)
        self.assertEqual([c.printed_id for c in cs], ['1', '2'])
        self.assertEqual(r.text[cs[0].start:cs[0].end], ' 1. Address should not be public.\n')
        self.assertTrue(cs[0].evidence['publisher_explicit_short_detail'])

    def test_abdk_standalone_section_inherits_own_status(self):
        text = 'ABDK Review\n2.1 Fixed Major Flaw\n'+D+'2.2 Unfixed Minor Issue\n'+D
        r = report(text, date='2019-01')
        cs = module(r.firm).parse(r)
        self.assertEqual([c.normalized_status for c in cs], ['fixed', 'open'])

    def test_abdk_numbered_attack_steps_are_one_singular_issue(self):
        text = 'ABDK Review\n3.1 Fixed Major Issue\nThe following attack is possible:\n 1. Alice deposits funds.\n 2. Alice withdraws funds.\n 3. Alice repeats the attack and drains funds.\n'
        r = report(text, date='2020-01')
        cs = module(r.firm).parse(r)
        self.assertEqual(len(cs), 1)
        self.assertEqual((cs[0].printed_id, cs[0].normalized, cs[0].normalized_status), ('3.1', 'high', 'fixed'))

    def test_abdk_direct_contract_items_use_their_own_scope(self):
        text = 'ABDK Review\n2.1 Other Issues\n 1. A short issue.\n3. AContract\nIn this section we describe issues related to AContract.\n 1. A different issue.\n 2. Another issue.\n4. BContract\nIn this section we describe issues related to BContract.\n4.1 Major Flaws\n 1. A major issue.\n'
        r = report(text, date='2018-01')
        cs = module(r.firm).parse(r)
        self.assertEqual([c.evidence['container_id'] for c in cs], ['2.1', '3', '3', '4.1'])

    def test_abdk_resolved_as_label_is_a_resolution_assertion(self):
        text = 'ABDK Review\n2.1 Major Flaws\n 1. A missing validation.\n'+D+'Resolved as: A validation check was added.\n'
        r = report(text, date='2020-01')
        c = module(r.firm).parse(r)[0]
        self.assertEqual(c.status_raw, 'Resolved')
        self.assertEqual(c.evidence['status_evidence']['basis'], 'publisher_resolved_as_section')

    def test_sigma_checked_response_reads_actual_outcome(self):
        r, cs = fixture('sigma_legacy_checked')
        self.assertEqual([c.printed_id for c in cs], ['S1', 'G1'])
        self.assertEqual([c.normalized_status for c in cs], ['fixed', 'resolved'])
        r, cs = fixture('sigma_legacy_comment')
        self.assertEqual(cs[0].normalized_status, 'open')

    def test_sigma_recommendation_under_resolution_stays_unknown(self):
        r, cs = fixture('sigma_numbered_notes')
        self.assertIsNone(cs[0].status_raw)

    def test_sigma_card_field_wins_over_narrative(self):
        r, cs = fixture('sigma_rating_card')
        self.assertEqual(cs[0].status_raw, 'Closed')
        self.assertEqual(cs[0].evidence['status_evidence']['basis'], 'labelled_status_field')

    def test_sigma_missing_card_status_uses_explicit_fix_review(self):
        text = 'TST-01 Actual issue\nAsset A.sol\nRating Severity: High\n\nDescription\n'+D+'Fix Review\nThis issue has been fixed in the reviewed revision.\n'
        r = report(text, 'sigma-prime')
        c = module(r.firm).parse(r)[0]
        self.assertEqual(c.status_raw, 'fixed')
        self.assertEqual(c.normalized_status, 'fixed')


if __name__ == '__main__':
    unittest.main()
