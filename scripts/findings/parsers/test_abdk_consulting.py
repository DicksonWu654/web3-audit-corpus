"""Synthetic regressions for ABDK layout eras; no cached documents or holdouts."""
import unittest
from common import digest
from core import Report, finish
from parsers import abdk_consulting as parser


def report(text):
    return Report(text, {'pages': [{'page': 1, 'start': 0, 'end': len(text), 'text': text}], 'file_format': 'pdf', 'text_sha256': digest(text.encode())}, 'abdk-consulting')


class ABDKTests(unittest.TestCase):
    def test_explicit_moderate_card_has_description_title_and_open_status(self):
        text = '3 Detailed Results\n3.1 CVF-1\n • Severity Moderate  • Status Opened\n • Category Flaw • Source Example.sol\nDescription No limit is enforced.\nRecommendation Add a limit.\n'
        r = report(text)
        row = finish(r, parser.parse(r))[0]
        self.assertEqual(row.printed_id, 'CVF-1')
        self.assertEqual(row.title, 'No limit is enforced.')
        self.assertEqual(row.severity_raw, 'Moderate')
        self.assertEqual(row.normalized, 'medium')
        self.assertEqual(row.normalized_status, 'open')
        self.assertEqual(row.evidence['title_basis'], 'description_excerpt')

    def test_info_is_status_and_parent_recommendations_is_severity(self):
        text = '6 Major Issues\nCVF-2 INFO\n • Category Flaw • Source A.sol\nDescription Accounted value can be incorrect.\n7 Recommendations\nCVF-1 FIXED\n • Category Style • Source A.sol\nRecommendation Remove an unused variable.\n'
        rows = parser.parse(report(text))
        self.assertEqual([r.normalized for r in rows], ['high', 'info'])
        self.assertEqual([r.status_raw for r in rows], ['INFO', 'FIXED'])
        self.assertEqual(rows[0].normalized_status, 'info')

    def test_spaced_letters_and_hierarchical_cvf_id(self):
        text = '6 M a j o r I s s u e s\nC V F - 2 . 1 . F I X E D\n • C a t e g o r y Flaw • S o u r c e A.sol\nD e s c r i p t i o n A limit is missing.\n'
        rows = parser.parse(report(text))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].printed_id, 'CVF-2.1')
        self.assertEqual(rows[0].normalized, 'high')
        self.assertEqual(rows[0].normalized_status, 'fixed')
        self.assertEqual(rows[0].title, 'A limit is missing.')

    def test_toc_dotted_cvf_entry_is_not_a_detail(self):
        text = '6 Major Issues 9\nCVF-1 FIXED . . . . . . . . 9\n'
        self.assertEqual(parser.parse(report(text)), [])

    def test_legacy_list_preserves_scope_local_ids_and_unknown_labels(self):
        text = '2.1 Major Flaws\n   1. A transfer can fail.\n      The transfer leaves accounting state inconsistent.\n   2. A value is unchecked.\n      This causes the operation to behave incorrectly.\n2.2 Documentation Issues\n   1. A method has no documentation.\n      The missing text makes its expected semantics unclear.\nOur Recommendations\n   1. Fix all issues.\n'
        rows = finish(report(text), parser.parse(report(text)))
        self.assertEqual([r.printed_id for r in rows], ['1', '2', '1'])
        self.assertEqual([r.normalized for r in rows], ['high', 'high', 'unknown'])
        self.assertEqual(parser.sequence_groups(report(text), rows), [['1', '2'], ['1']])
        self.assertNotIn('Our Recommendations', text[rows[-1].start:rows[-1].end])

    def test_reported_status_is_open(self):
        text = '6 Major Issues\nCVF-1 Reported\n • Category Flaw • Source A.sol\nDescription A check is missing from the operation.\n'
        self.assertEqual(parser.parse(report(text))[0].normalized_status, 'open')

    def test_summary_is_independent_of_parsed_rows(self):
        r = report('5 Our findings\nWe found 2 major, and a few less important issues.\n6 Major Issues\nCVF-1 FIXED\n • Category Flaw • Source A.sol\nDescription Only one finding is included in this test.\n')
        self.assertEqual(parser.printed_counts(r)['counts'], {'high': 2})
        self.assertEqual(len(parser.parse(r)), 1)

    def test_combined_cvf_ids_are_one_card_with_both_sequence_members(self):
        r = report('6 Minor Issues\nC V F - 2 , 3 . F I X E D\n • Category Suboptimal • Source A.sol\nDescription The same unnecessary code occurs twice.\n')
        rows = parser.parse(r)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].printed_id, 'CVF-2,3')
        self.assertEqual(parser.sequence_groups(r, rows), [['CVF-2', 'CVF-3']])

    def test_page_continuation_cannot_borrow_next_cards_metadata(self):
        r = report('CVF-1.\nListing 1: code excerpt only.\n3.2 CVF-2\n • Severity Major • Status Opened\nDescription The second card has its own metadata.\n')
        self.assertEqual([row.printed_id for row in parser.parse(r)], ['CVF-2'])

    def test_printed_table_adds_active_and_fixed_and_marks_source_conflict(self):
        r = report('5 Our findings\nWe found 4 major, and a few less important issues.\n                 Active   Fixed\nMajor            1        2\n                 Active   Fixed\nModerate         2        4\nFixed 6 out of 9 issues\n')
        summary = parser.printed_counts(r)
        self.assertEqual(summary['counts'], {'high': 3, 'medium': 6})
        self.assertTrue(summary['ambiguous'])

    def test_impossible_printed_subtotal_is_source_ambiguity(self):
        r = report('5 Our findings\nWe found 1 critical, 6 major, and a few less important issues.\nFixed 6 out of 6 issues\n')
        self.assertTrue(parser.printed_counts(r)['ambiguous'])

    def test_legacy_bullets_are_not_invented_numeric_ids(self):
        r = report('2. Remaining Minor Issue\n • An input should be validated.\n   The missing validation has an explicit description.\n')
        row = parser.parse(r)[0]
        self.assertEqual(row.normalized, 'low')
        self.assertIsNone(row.printed_id)


if __name__ == '__main__':
    unittest.main()
