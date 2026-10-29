"""Synthetic regressions for Oak layout eras; no cached documents or holdouts."""
import unittest
from common import digest
from core import Report, finish
from parsers import oak_security as parser


def report(text):
    pages, start = [], 0
    for i, page in enumerate(text.split('\f'), 1):
        pages.append({'page': i, 'start': start, 'end': start + len(page), 'text': page})
        start += len(page) + 1
    return Report(text, {'pages': pages, 'file_format': 'pdf', 'text_sha256': digest(text.encode())}, 'oak-security')


class OakTests(unittest.TestCase):
    def test_unindented_wrapped_title_blank_and_native_status(self):
        text = 'Detailed Findings\n1. Long issue title\nwrapped onto another line\n\nSeverity: Major\n\nDetailed explanation of the actual issue.\nStatus: Partially\nResolved\n'
        r = report(text)
        rows = finish(r, parser.parse(r))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].title, 'Long issue title wrapped onto another line')
        self.assertEqual(rows[0].severity_raw, 'Major')
        self.assertEqual(rows[0].normalized_status, 'partial')
        self.assertEqual(rows[0].status_raw, 'Partially Resolved')
        self.assertEqual(r.text[rows[0].start:rows[0].end], text[text.index('1. Long'):])

    def test_nearby_numbered_link_is_not_a_finding(self):
        text = 'Detailed Findings\n 3. https://example.org/docs\n\n 33. Actual issue\nSeverity: Informational\nDetailed explanation of the actual issue.\n'
        self.assertEqual([r.printed_id for r in parser.parse(report(text))], ['33'])

    def test_appendix_and_excluded_past_findings_are_outside_span(self):
        text = 'Detailed Findings\n1.\u200b Actual issue\nSeverity: Minor\nDetailed explanation of the actual issue.\nStatus: Reported\nAppendix A\n1. Test case\nPast Findings for Contracts Excluded\n1. Old issue\nSeverity: Critical\nDetailed historical explanation.\n'
        r = report(text)
        rows = finish(r, parser.parse(r))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].normalized_status, 'open')
        self.assertEqual(rows[0].end, text.index('Appendix A'))

    def test_phase_ids_can_restart_or_continue(self):
        text = ''
        for phase, number in [(1, 1), (2, 2), (3, 1)]:
            text += f'Detailed Findings for Phase {phase}\n{number}. Actual issue\nSeverity: Minor\nDetailed explanation of the actual issue.\n'
        r = report(text)
        self.assertEqual(parser.sequence_groups(r, parser.parse(r)), [['1', '2'], ['1']])

    def test_separate_router_contract_details_keep_continuing_ids(self):
        text = 'Detailed Findings\n1. Main contract issue\nSeverity: Major\nA detailed explanation of the first actual issue.\nSummary of Findings For Router Contract\nNo Description Severity Status\n2 Example Minor Resolved\nDetailed Findings For Router Contract\n2. Router contract issue\nSeverity: Minor\nA detailed explanation of the second actual issue.\n'
        r = report(text)
        rows = parser.parse(r)
        self.assertEqual([x.printed_id for x in rows], ['1', '2'])
        self.assertEqual(rows[0].end, text.index('Summary of Findings For Router Contract'))

    def test_ungraded_protocol_findings_keep_missing_severity(self):
        r = report('Protocol Security Review\nDetailed Findings\n   1. A protocol issue\n      with wrapped title\nThe prose explains the protocol issue in detail.\nRecommendation\nA recommendation.\n')
        rows = parser.parse(r)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].title, 'A protocol issue with wrapped title')
        self.assertIsNone(rows[0].severity_raw)

    def test_summary_index_does_not_become_numeric_totals(self):
        r = report('Summary of Findings\nNo Description Severity Status\n1 Example Critical Resolved\n')
        self.assertIsNone(parser.printed_counts(r))
        self.assertEqual(parser.parse(r), [])


if __name__ == '__main__':
    unittest.main()
