"""Per-era MoveBit/ScaleBit fixtures and explicit remediation regressions."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import digest
from core import Report
from parsers import module

D = '\nDescriptions: The source explains the affected operation and its impact on users.\n'
LEGEND = ('1.4 Issue Status\nConfirmed: The issue has been acknowledged by the code owner, and the code owner\n'
          "confirms it's as designed, and decides to keep it.\n")
FIXTURES = {
    'movebit_numbered': ('movebit', LEGEND + '5 Findings\n5.1 Invalid configuration\nSeverity: Medium\nStatus: Confirmed' + D,
                         'movebit/v2022_numbered_fields', 'acknowledged'),
    'movebit_component': ('movebit', '1.4 MoveBit Audit BreakDown\nBUK-01 Invalid configuration\nSeverity: Major\nStatus: Partially Fixed' + D +
                          'Resolution: The client partially fixed this issue according to the suggestion.\n',
                          'movebit/v2023_component_cards', 'partial'),
    'scalebit_numbered': ('scalebit', '1.4 Issue Status\n6 Findings\n6.1 Invalid configuration\nSeverity: Minor\nStatus: Fixed' + D,
                          'scalebit/v2023_numbered_fields', 'fixed'),
    'scalebit_component': ('scalebit', '1.4 ScaleBit Audit BreakDown\nIDO-01 Invalid configuration\nSeverity: Medium\nStatus: Acknowledged' + D,
                           'scalebit/v2023_component_cards', 'acknowledged'),
    'movebit_component_modern': ('movebit', 'Example Audit Report\ncontact@bitslab.xyz\nWed Sep 23 2026\n'
                                'BTR1-1 Invalid configuration\nSeverity: Medium\nStatus: Fixed' + D,
                                'movebit/v2023_component_cards', 'fixed'),
    'scalebit_component_modern': ('scalebit', 'Example Audit Report\ncontact@bitslab.xyz\nMon Nov 11 2024\n'
                                 'CTO-1 Invalid configuration\nSeverity: Major\nStatus: Acknowledged' + D,
                                 'scalebit/v2023_component_cards', 'acknowledged'),
}


def report(text, firm='movebit', date='2023-01-01'):
    pages = []
    offset = 0
    for i, p in enumerate(text.split('\f'), 1):
        pages.append(dict(page=i, start=offset, end=offset + len(p), text=p))
        offset += len(p) + 1
    return Report(text, dict(file_format='pdf', pages=pages, text_sha256=digest(text.encode()), date_hint=date), firm)


def card(tail='', pid='ABC-01', firm='movebit'):
    r = report(pid + ' Actual vulnerability\nSeverity: Major' + D + tail, firm)
    cs = module(firm).parse(r)
    return r, cs


class Group4MovebitScalebitTests(unittest.TestCase):
    def test_every_declared_fixture_selects_its_era(self):
        declared = set()
        for firm in ('movebit', 'scalebit'):
            for variant in module(firm).VARIANTS:
                self.assertFalse(variant.fingerprint.legacy)
                self.assertIsNotNone(variant.status_parser)
                self.assertIsNotNone(variant.printed_counts)
                for fixture in variant.fixtures:
                    declared.add(fixture)
                    publisher, text, expected, normalized = FIXTURES[fixture]
                    with self.subTest(fixture=fixture):
                        r = report(text, publisher, date=None if fixture.endswith('_modern') else '2023-01-01')
                        cs = module(publisher).parse(r)
                        self.assertEqual(r.layout_selection['variant_id'], expected)
                        self.assertEqual(len(cs), 1)
                        self.assertEqual(cs[0].normalized_status, normalized)
                        evidence = cs[0].evidence['status_evidence']
                        self.assertEqual(r.text[evidence['start']:evidence['end']], evidence['text'])
        self.assertEqual(declared, set(FIXTURES))

    def test_date_and_brand_are_insufficient_to_clear_unknown(self):
        r = report('MoveBit Audit Report\ncontact@movebit.xyz\n\f1/13\f2/13')
        self.assertEqual(module('movebit').parse(r), [])
        self.assertTrue(r.layout_selection['unknown_layout'])

    def test_component_signature_outvotes_old_date(self):
        r, cs = card('Status: Fixed\n')
        r.meta['date_hint'] = '2022-01-01'
        module('movebit').parse(r)
        self.assertEqual(r.layout_selection['variant_id'], 'movebit/v2023_component_cards')

    def test_overview_and_detail_on_one_page_do_not_duplicate(self):
        r = report('ID       Title          Severity     Status\n'
                   'ABC-01   Actual issue   Major        Fixed\n'
                   'ABC-01 Actual issue\nSeverity: Major\nStatus: Fixed' + D)
        cs = module('movebit').parse(r)
        self.assertEqual(len(cs), 1)
        self.assertEqual(cs[0].title, 'Actual issue')

    def test_wrapped_title_and_status_on_next_page(self):
        r = report('MAV-01 Actual vulnerability with a\nwrapped title\nSeverity: Major\n\fStatus: Fixed' + D)
        c = module('movebit').parse(r)[0]
        self.assertEqual(c.title, 'Actual vulnerability with a wrapped title')
        self.assertEqual(c.normalized_status, 'fixed')

    def test_status_legend_is_outside_final_finding(self):
        r, cs = card('\nAppendix 1\nIssue Status\nStatus: Fixed\n')
        self.assertIsNone(cs[0].status_raw)
        self.assertNotIn('Appendix', r.text[cs[0].start:cs[0].end])

    def test_confirmed_requires_publisher_definition(self):
        r, cs = card('Status: Confirmed\n')
        self.assertEqual(cs[0].normalized_status, 'other')
        r, cs = card('Status: Confirmed\n\nAppendix 1\n' + LEGEND)
        self.assertEqual(cs[0].normalized_status, 'acknowledged')
        self.assertIn('status_definition_evidence', cs[0].evidence)

    def test_id_linked_fix_review_table(self):
        r, cs = card('\nAppendix 1\nFix Review\nABC-01    Fixed\n')
        self.assertEqual(cs[0].normalized_status, 'fixed')
        self.assertEqual(cs[0].evidence['status_evidence']['basis'], 'printed_id_status_table')

    def test_conflicting_id_table_is_not_status(self):
        r, cs = card('\nAppendix 1\nABC-01    Fixed\nABC-01    Open\n')
        self.assertIsNone(cs[0].status_raw)
        self.assertTrue(cs[0].evidence['status_conflict'])

    def test_metadata_status_has_priority_over_old_index(self):
        r, cs = card('Status: Fixed\n\nAppendix 1\nABC-01    Open\n')
        self.assertEqual(cs[0].normalized_status, 'fixed')

    def test_resolution_only_status_and_exact_receipt(self):
        r, cs = card('Resolution: The client followed our suggestion and fixed this issue.\n')
        self.assertEqual(cs[0].normalized_status, 'fixed')
        self.assertIn('fixed this issue', cs[0].resolution)
        evidence = cs[0].evidence['status_evidence']
        self.assertEqual(evidence['text'], 'fixed')
        self.assertEqual(r.text[evidence['start']:evidence['end']], 'fixed')

    def test_future_fix_is_open(self):
        r, cs = card('Resolution: The client plans to fix this issue in the near future.\n')
        self.assertEqual(cs[0].normalized_status, 'open')

    def test_status_words_in_table_title_are_not_status_cells(self):
        r, cs = card('\nAppendix 1\nABC-01    Open Access Restriction    Unspecified\n')
        self.assertIsNone(cs[0].status_raw)
        r, cs = card('\nAppendix 1\nABC-01    Open Access Restriction    Fixed\n')
        self.assertEqual(cs[0].normalized_status, 'fixed')

    def test_resolution_declining_fix_is_acknowledged(self):
        r, cs = card('Resolution: The client decided not to fix it, since this is intentional.\n')
        self.assertEqual(cs[0].normalized_status, 'acknowledged')

    def test_recommendation_or_negated_fix_does_not_claim_remediation(self):
        for tail in ('Suggestion: The client should have fixed this issue.\n',
                     'Resolution: The client has not fixed this issue.\n',
                     'Resolution: The client has not partially fixed this issue.\n',
                     'Resolution: The client will have partially fixed this issue.\n',
                     'Resolution: The client should have fixed this issue.\n'):
            with self.subTest(tail=tail):
                r, cs = card(tail)
                self.assertIsNone(cs[0].status_raw)

    def test_printed_totals_do_not_change_detail_severity(self):
        r = report('1.3 Issue Statistic\nMinor 1\nMajor 0\n\nABC-01 Actual vulnerability\nSeverity: Major' + D)
        cs = module('movebit').parse(r)
        self.assertEqual(cs[0].normalized, 'high')
        self.assertEqual(module('movebit').printed_counts(r)['counts'], {'info': 1, 'high': 0})


if __name__ == '__main__':
    unittest.main()
