"""Synthetic regressions for Fuzzland and Composable publisher layouts."""
import unittest

from common import digest
from core import Report, finish, severity, status
from parsers import composable_security as composable
from parsers import fuzzland


def report(text, firm="fuzzland", fmt="html"):
    pages, start = [], 0
    for n, text_page in enumerate(text.split("\f"), 1):
        pages.append({"page": n, "start": start, "end": start + len(text_page), "text": text_page})
        start += len(text_page) + 1
    return Report(text, {"pages": pages, "text_sha256": digest(text.encode()), "file_format": fmt}, firm)


class FuzzlandTests(unittest.TestCase):
    def test_split_inline_code_heading_and_native_med_label(self):
        r = report("[Med] TOC only\n\n## Findings\n### [Med] \nlockPosition\n overcharges ETH\n\n"
                   "Detailed explanation of the problem.\nStatus：Acknowledged\n### Additional Test\n"
                   "Additional checks are not part of the finding.\n")
        rows = finish(r, fuzzland.parse(r))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].title, "lockPosition overcharges ETH")
        self.assertEqual(rows[0].severity_raw, "Med")
        self.assertEqual(rows[0].normalized, "medium")
        self.assertEqual(rows[0].status_raw, "Acknowledged")
        self.assertNotIn("Additional Test", r.text[rows[0].start:rows[0].end])

    def test_split_status_and_appendix(self):
        r = report("#### [LOW] Real finding\n\nDetails of the issue and its implications.\nStatus\n\nFixed\n"
                   "### Appendix\n#### Invariants Checked\nExample invariant text.\n")
        row = finish(r, fuzzland.parse(r))[0]
        self.assertEqual(row.status_raw, "Fixed")
        self.assertNotIn("Appendix", r.text[row.start:row.end])

    def test_summary_number_not_resolved_and_no_manufactured_rows(self):
        r = report("Number\n\n | \nResolved\n\n | \nHigh Severity Issues\n\n | \n2\n | \n1\n"
                   "Medium Severity Issues\n | \n0\n | \n0\n## Findings\n"
                   "### [High] The sole real detailed finding\n\n" + "Detailed evidence.\n" * 4)
        self.assertEqual(fuzzland.printed_counts(r)["counts"], {"high": 2, "medium": 0})
        self.assertEqual(len(finish(r, fuzzland.parse(r))), 1)

    def test_no_ids_is_not_a_sequence_pass(self):
        r = report("## Detailed Findings\n\nN/A\n")
        self.assertIsNone(fuzzland.sequence_diagnostics(r, [])['complete'])
        self.assertEqual(fuzzland.sequence_diagnostics(r, [])['reason'], "explicit_no_findings_na")

    def test_horizontal_metadata_status_and_unrecognized_publisher_response(self):
        cells = ["Severity", "Category", "Code Location", "Status", "Fix Commit",
                 "HIGH", "DOS", "context.go", "Fixed", "deadbeef"]
        text = "#### [HIGH] Proper bounds check\n\n | \n\n" + "\n\n | \n\n".join(cells)
        text += "\n\nDetailed explanation of the problem.\n### [Low] Second issue\n\n"
        text += "Detailed explanation of the second issue.\nStatus: Team disputes this condition.\n"
        rows = finish(report(text), fuzzland.parse(report(text)))
        self.assertEqual([c.status_raw for c in rows], ["Fixed", "Team disputes this condition."])

    def test_native_ack_keeps_source_label_and_normalizes(self):
        cells = ["Severity", "Category", "Code Location", "Status", "Fix Commit",
                 "HIGH", "DOS", "context.go", "Ack", "deadbeef"]
        text = "#### [HIGH] Proper bounds check\n\n | \n\n" + "\n\n | \n\n".join(cells)
        row = fuzzland.parse(report(text))[0]
        self.assertEqual(row.status_raw, "Ack")
        self.assertEqual(row.normalized_status, "acknowledged")


class ComposableTests(unittest.TestCase):
    def test_wrapped_modern_card_uses_explicit_major_and_partial_status(self):
        r = report("Contents\n[ABC-deadbeef-H01] False TOC . . . . . . 5\n\f"
                   "[ABC-deadbeef-H01] Wrapped\ncard title\nMAJOR  PARTIALLY FIXED\n\n"
                   "Detailed description and supporting evidence.\n"
                   "7. Impact on risk classification\nRisk definitions here.\n",
                   "composable-security", "pdf")
        rows = finish(r, composable.parse(r))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].title, "Wrapped card title")
        self.assertEqual(rows[0].printed_id, "ABC-deadbeef-H01")
        self.assertEqual(severity(rows[0].severity_raw, "composable-security"), "high")
        self.assertEqual(status(rows[0].status_raw), "partial")
        self.assertNotIn("risk classification", r.text[rows[0].start:rows[0].end])

    def test_legacy_bidi_round_and_distant_severity(self):
        text = "\u202d5.1.\u202c \u202d[R1] Incorrect allowance\u202c\ncalculation\n\n"
        text += "Status 2023-06-02    PARTIALLY\n    IMPLEMENTED\n\n" + "Retest explanation.\n" * 30
        text += "\fSeverity\nMEDIUM\n\nDescription\nDetailed evidence of the issue.\n"
        r = report(text, "composable-security", "pdf")
        rows = finish(r, composable.parse(r))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].title, "Incorrect allowance calculation")
        self.assertEqual(rows[0].printed_id, "5.1")
        self.assertEqual(rows[0].evidence['round_labels'], "R1")
        self.assertEqual(status(rows[0].status_raw), "partial")

    def test_sequence_reports_gaps_and_duplicates(self):
        text = ""
        for pid in ["M01", "M03", "M03"]:
            text += f"[ABC-deadbeef-{pid}] A detailed issue\nMEDIUM FIXED\n\n" + "Evidence.\n" * 8
        r = report(text, "composable-security", "pdf")
        rows = finish(r, composable.parse(r))
        result = composable.sequence_diagnostics(r, rows)
        self.assertFalse(result['complete'])
        self.assertEqual(result['gaps'], ["ABC-deadbeef-M:2"])
        self.assertEqual(result['duplicates'], ["ABC-deadbeef-M:3"])

    def test_retest_numeric_totals_precede_earlier_audit_totals(self):
        r = report("The current status of detected issues is as follows:\n"
                   "6 vulnerabilities with a medium impact on risk were handled as follows:\n"
                   "10 security recommendations were handled as follows:\n1.2. Scope\n"
                   "The summary of findings is as follows:\n"
                   "5 vulnerabilities with a medium impact on risk were identified.\n"
                   "10 recommendations have been proposed.\nComposable Security recommends actions.\n",
                   "composable-security", "pdf")
        summary = composable.printed_counts(r)
        self.assertEqual(summary['counts'], {"medium": 6, "info": 10})
        self.assertEqual(summary['basis'], "publisher_current_retest_aggregate_prose")
        self.assertEqual(composable.parse(r), [])

    def test_nonnumeric_retest_uses_audit_totals_not_referenced_id(self):
        r = report("The current status of detected issues is as follows:\n"
                   "All recommendations were implemented.\nThe recommendation ABC-deadbeef-R01 was fixed.\n"
                   "1.2. Scope\nThe summary of findings is as follows:\n"
                   "2 vulnerabilities with a medium impact on risk were identified.\n"
                   "Three recommendations have been proposed.\nComposable Security recommends actions.\n",
                   "composable-security", "pdf")
        self.assertEqual(composable.printed_counts(r)['counts'], {"medium": 2, "info": 3})

    def test_round_totals_are_added_without_detail_ids(self):
        r = report("During the first round the following issues were identified:\n"
                   "No critical or major risk impact vulnerability was identified.\n"
                   "4 vulnerabilities with a medium impact on risk were identified.\n"
                   "The second round added the following issues:\n"
                   "2 vulnerabilities with a major impact on risk were identified.\n"
                   "3 vulnerabilities with a medium impact on risk were identified.\n"
                   "Composable Security recommends actions.\n", "composable-security", "pdf")
        self.assertEqual(composable.printed_counts(r)['counts'], {"critical": 0, "high": 2, "medium": 7})

    def test_consultation_is_not_a_vacuous_sequence_pass(self):
        r = report("1. Security consultation summary\nCovered scenarios and previous fixes.\n",
                   "composable-security", "pdf")
        self.assertEqual(composable.parse(r), [])
        self.assertIsNone(composable.sequence_diagnostics(r, [])['complete'])


if __name__ == '__main__':
    unittest.main()
