"""Synthetic layout regressions for the Phase 4b Runtime/Dedaub parsers."""
import unittest
from common import digest
from core import Report, finish
from parsers import dedaub, runtime_verification as rv


def report(text, firm):
    pages, start = [], 0
    for i, text_page in enumerate(text.split("\f"), 1):
        pages.append({"page": i, "start": start, "end": start + len(text_page), "text": text_page})
        start += len(text_page) + 1
    return Report(text, {"pages": pages, "file_format": "pdf", "text_sha256": digest(text.encode())}, firm)


BODY = "A detailed description of the actual finding and its impact.\n" * 5


class RuntimeVerificationTests(unittest.TestCase):
    def test_index_and_checked_properties_do_not_add_findings(self):
        r = report("A01: Actual finding\n\nB01: Another finding\n\fFindings\nA01: Actual finding\nSeverity: High\n" + BODY + "\nB01: Another finding\nSeverity: Low\n" + BODY + "\nChecked properties\nC01: A property we verified\n" + BODY, "runtime-verification")
        rows = finish(r, rv.parse(r))
        self.assertEqual([c.printed_id for c in rows], ["A01", "B01"])
        self.assertEqual([c.normalized for c in rows], ["high", "low"])

    def test_bracketed_wrapped_title_and_native_status(self):
        r = report("[CI1] Informative finding with\na wrapped title\n Severity: Informative    Addressed by client\n" + BODY + "\nAppendix A: Severity definitions\n" + BODY, "runtime-verification")
        c = finish(r, rv.parse(r))[0]
        self.assertEqual(c.title, "Informative finding with a wrapped title")
        self.assertEqual(c.severity_raw, "Informative")
        self.assertEqual(c.normalized, "info")
        self.assertEqual(c.status_raw, "Addressed by client")
        self.assertEqual(c.normalized_status, "resolved")
        self.assertNotIn("Appendix", r.text[c.start:c.end])

    def test_parenthesized_risk_overrides_b_category(self):
        r = report("B01: Some finding (Critical)\nContext\n" + BODY, "runtime-verification")
        c = finish(r, rv.parse(r))[0]
        self.assertEqual(c.normalized, "critical")
        self.assertEqual(c.severity_raw, "Critical")
        self.assertEqual(c.title, "Some finding (Critical)")

    def test_defined_native_priority_maps_and_missing_risk_stays_missing(self):
        r = report("A1. Priority issue\nSeverity: P3\n" + BODY + "\nA2. No printed risk\n\n" + BODY, "runtime-verification")
        rows = finish(r, rv.parse(r))
        self.assertEqual([c.normalized for c in rows], ["medium", "unknown"])
        self.assertEqual([c.severity_raw for c in rows], ["P3", None])

    def test_split_id_line_and_invariants(self):
        r = report("[SLP1] This is an invariant\n" + BODY + "\nA01:\nAn actual wrapped finding\nSeverity: Medium\n" + BODY, "runtime-verification")
        rows = finish(r, rv.parse(r))
        self.assertEqual([c.printed_id for c in rows], ["A01"])
        self.assertEqual(rows[0].title, "An actual wrapped finding")

    def test_sequence_gap_is_failure_and_no_rows_are_not_clean(self):
        r = report("A01: First\nSeverity: Low\n" + BODY + "\nA03: Third\nSeverity: Low\n" + BODY, "runtime-verification")
        diagnostic = rv.sequence_diagnostics(r, finish(r, rv.parse(r)))
        self.assertFalse(diagnostic["complete"])
        self.assertEqual(diagnostic["gaps"], ["A2"])
        self.assertIsNone(rv.sequence_diagnostics(r, [])["complete"])

    def test_risk_card_title_does_not_cross_physical_page(self):
        text = "Status: This belongs to the previous finding.\n\f3. A wrapped title on\nthe new page\n[ Severity: Medium | Difficulty: Low ]\n" + BODY
        r = report(text, "runtime-verification")
        c = finish(r, rv.parse(r))[0]
        self.assertEqual(c.title, "A wrapped title on the new page")
        self.assertEqual(c.printed_id, "3")
        self.assertNotIn("previous finding", r.text[c.start:c.end])

    def test_legacy_list_links_to_differently_worded_detail(self):
        text = "List of Findings\nHigh\n  1. Errors, typos, etc\n\fErrors, etc\n\n" + BODY
        r = report(text, "runtime-verification")
        c = finish(r, rv.parse(r))[0]
        self.assertEqual(c.title, "Errors, etc")
        self.assertEqual(c.printed_id, "1")
        self.assertEqual(c.normalized, "high")

    def test_tracker_category_is_not_risk_and_excerpt_stays_distinct(self):
        text = "           Issue                                                       Category    Status\n\n   #45     A title in the actual issue tracker                         Bug         Addressed by\n           continued title                                                         client in this\n                                                                                   commit\n"
        r = report(text, "runtime-verification")
        c = finish(r, rv.parse(r))[0]
        self.assertEqual(c.printed_id, "#45")
        self.assertEqual(c.record_kind, "summary_excerpt")
        self.assertIsNone(c.severity_raw)
        self.assertEqual(c.title, "A title in the actual issue tracker continued title")
        self.assertEqual(c.normalized_status, "resolved")

    def test_design_discussion_is_a_recommendation_without_invented_risk(self):
        text = "Findings\nNone\nof these points represented a design flaw or a security vulnerability.\n\n1. A design recommendation\n" + BODY
        r = report(text, "runtime-verification")
        c = finish(r, rv.parse(r))[0]
        self.assertEqual(c.record_kind, "recommendation")
        self.assertIsNone(c.severity_raw)


class DedaubTests(unittest.TestCase):
    def test_vertically_centered_id_and_status_are_separate_from_title(self):
        text = "HIGH SEVERITY:\n ID   Description                                                            STATUS\n\n      First line of a wrapped title                                           PARTLY\n H1   second line                                                             RESOLVED\n\n" + BODY
        c = finish(report(text, "dedaub"), dedaub.parse(report(text, "dedaub")))[0]
        self.assertEqual(c.title, "First line of a wrapped title second line")
        self.assertEqual(c.status_raw, "PARTLY RESOLVED")
        self.assertEqual(c.normalized_status, "partial")
        self.assertEqual(c.severity_raw, "HIGH")
        self.assertEqual(c.normalized, "high")

    def test_advisory_info_status_is_not_its_severity(self):
        text = "OTHER / ADVISORY ISSUES:\n ID   Description                                                            STATUS\n\n A1   Compiler bugs                                                            INFO\n\n" + BODY
        c = finish(report(text, "dedaub"), dedaub.parse(report(text, "dedaub")))[0]
        self.assertEqual(c.title, "Compiler bugs")
        self.assertEqual(c.normalized, "info")
        self.assertEqual(c.status_raw, "INFO")
        self.assertEqual(c.severity_raw, "OTHER / ADVISORY ISSUES")

    def test_legacy_unnumbered_description_card_has_no_invented_id(self):
        text = "High Severity\nDescription                                                                                    Status\n\nThe opening description of an old unnumbered finding.                                        Resolved\n\n" + BODY
        c = finish(report(text, "dedaub"), dedaub.parse(report(text, "dedaub")))[0]
        self.assertIsNone(c.printed_id)
        self.assertEqual(c.title, "The opening description of an old unnumbered finding.")
        self.assertEqual(c.evidence["title_basis"], "opening_description_excerpt")

    def test_no_critical_issues_and_study_prose_are_not_findings(self):
        r = report("Critical Severity\n[No critical severity issues]\n\nExperimental Findings and Study\n" + BODY, "dedaub")
        self.assertEqual(dedaub.parse(r), [])
        self.assertIsNone(dedaub.sequence_diagnostics(r, [])["complete"])


if __name__ == "__main__":
    unittest.main()
