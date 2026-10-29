"""Synthetic regressions for the two group-1 publisher layouts; no gold access."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import Report, finish, severity
from parsers import consensys_diligence as diligence
from parsers import macro


def report(text, firm, file_format="html", pages=None):
    if pages is None:
        pages = [text]
    offset, entries = 0, []
    for number, value in enumerate(pages, 1):
        entries.append({"page": number, "start": offset, "end": offset + len(value), "text": value})
        offset += len(value) + 1
    return Report(text, {"pages": entries, "file_format": file_format}, firm)


class MacroTests(unittest.TestCase):
    def test_detail_cards_exclude_navigation_and_impact_is_not_severity(self):
        text = """## Issue Descriptions and Recommendations
H-1
##
The navigation title
## Issue Details
H-1
##
The real finding title
Topic
Accounting
Status
Addressed
Impact
Medium
Likelihood
Low
The full finding body is long enough to establish a detailed formal finding.
Q-1
##
Improve clarity
Topic
Code quality
Status
Acknowledged
Quality Impact
High
The source still classifies this as code quality despite its quality impact.
## Disclaimer
This text is outside the final finding.
"""
        r = report(text, "macro")
        entries = finish(r, macro.parse(r))
        self.assertEqual([c.title for c in entries], ["The real finding title", "Improve clarity"])
        self.assertEqual([(c.severity_raw, c.normalized) for c in entries], [("H", "high"), ("Q", "info")])
        self.assertEqual(entries[0].status_raw, "Addressed")
        self.assertEqual(entries[0].normalized_status, "resolved")
        self.assertNotIn("Disclaimer", text[entries[-1].start:entries[-1].end])

    def test_count_column_sums_quality_and_information_without_using_cards(self):
        text = """## Overall Assessment
Severity
Count
Acknowledged
Addressed
Critical
0
-
-
High
2
1
1
Code Quality
4
-
4
Informational
3
3
-
Gas Optimization
5
-
5
## Specification
High
999
"""
        summary = macro.printed_counts(report(text, "macro"))
        self.assertEqual(summary["counts"], {"critical": 0, "high": 2, "info": 7, "gas": 5})
        self.assertEqual(len(macro.parse(report(text, "macro"))), 0)

    def test_native_duplicate_ids_are_preserved_and_diagnosed(self):
        text = "## Issue Details\n" + "".join(
            f"I-{number}\n##\nTitle {j}\nStatus\nFixed\nThe description is long enough to retain this real detail occurrence.\n"
            for j, number in enumerate((1, 1, 3)))
        r = report(text, "macro")
        entries = finish(r, macro.parse(r))
        self.assertEqual(len(entries), 3)
        self.assertEqual(macro.sequence_diagnostics(r, entries)["gaps"], ["I-2"])
        self.assertEqual(macro.sequence_diagnostics(r, entries)["duplicates"], ["I-1"])

    def test_blank_status_does_not_consume_the_next_field(self):
        text = """## Issue Details
I-1
##
Observation with no printed status
Topic
Design
Status
Impact
Informational
This finding has a blank status cell; the response does not populate that cell.
"""
        entries = finish(report(text, "macro"), macro.parse(report(text, "macro")))
        self.assertEqual(len(entries), 1)
        self.assertIsNone(entries[0].status_raw)


class DiligenceTests(unittest.TestCase):
    def test_web_details_native_risk_status_and_ungraded_recommendations(self):
        text = """4 Findings
4.1 Navigation only Major ✓ Fixed
## 3 Security Specification
### 3.1 Actors
This paragraph describes actors and is not a finding.
## 4 Findings
### 4.1 First issue Major ✓ Addressed
#### Description
This is a real detailed issue with sufficient evidence in the body.
### 4.2 Optional improvement Acknowledged
This recommendation has no publisher-assigned severity and remains ungraded.
## 5 Recommendations
### 5.1 Documentation improvement
This is an explicitly numbered recommendation in the report proper.
## Appendix 1 - Disclosure
### 4.3 Not a finding
"""
        r = report(text, "consensys-diligence")
        entries = finish(r, diligence.parse(r))
        self.assertEqual([c.printed_id for c in entries], ["4.1", "4.2", "5.1"])
        self.assertEqual(entries[0].severity_raw, "Major")
        self.assertEqual(entries[0].normalized_status, "resolved")
        self.assertEqual(entries[1].status_raw, "Acknowledged")
        self.assertIsNone(entries[1].severity_raw)
        self.assertEqual(severity(entries[1].severity_raw), "unknown")
        self.assertTrue(diligence.sequence_diagnostics(r, entries)["complete"])
        self.assertNotIn("Appendix", text[entries[-1].start:entries[-1].end])

    def test_legacy_icons_and_inconsistent_parent_number(self):
        text = """#### Number of issues per severity
| | <img src="static/minor.png"/> | <img src="static/major.png"/> |
| <img src="static/open.png"/> | **0** | **1** |
| <img src="static/closed.png"/> | **1** | **0** |
## 4 Issue Detail
### 3.1 Critical transfer failure
| Severity | Status | Link |
| ---- | ---- | ---- |
| <img src="static/major.png"/> | <img src="static/open.png"/> | source |
#### Description
The bug is documented here in sufficient detail for a formal finding.
### 3.2 Minor validation failure
| Severity | Status | Link |
| ---- | ---- | ---- |
| <img src="static/minor.png"/> | <img src="static/closed.png"/> | source |
#### Description
The second bug has its own detail section and source-native status icon.
"""
        r = report(text, "consensys-diligence", "md")
        entries = finish(r, diligence.parse(r))
        self.assertEqual([c.printed_id for c in entries], ["3.1", "3.2"])
        self.assertEqual([c.severity_raw for c in entries], ["major", "minor"])
        self.assertEqual(entries[1].normalized_status, "resolved")
        self.assertEqual(diligence.printed_counts(r)["counts"], {"low": 1, "high": 1})

    def test_pdf_sidebar_columns_and_exact_heading_offsets(self):
        first = "\n".join([
            "1 Executive Summary", "2 Scope", "3 Findings", " 3.1 Navigation title Major",
            " " * 40 + "1 Executive Summary", " " * 40 + "This review concerns a smart contract system.",
            " " * 40 + "2 Scope", " " * 40 + "Only the agreed contracts are in scope.",
            " " * 40 + "3 Findings", " " * 40 + "3.1 Actual first issue Major ✓ Fixed", "",
            " " * 40 + "Description", " " * 40 + "The first detailed issue starts beside the navigation tree.",
            "Appendix 1 - Files in Scope", " " * 40 + "A second explanatory line remains inside the detailed finding.",
        ]) + "\n"
        second = "3.2 Actual second issue Minor\n\nDescription\nThe second detailed issue follows on a normal full-width report page.\nAppendix 1 - Files in Scope\n"
        text = first + "\n" + second
        r = report(text, "consensys-diligence", "pdf", [first, second])
        entries = finish(r, diligence.parse(r))
        self.assertEqual([c.printed_id for c in entries], ["3.1", "3.2"])
        self.assertEqual(entries[0].title, "Actual first issue")
        self.assertEqual(entries[0].start, text.index("3.1 Actual first issue"))
        self.assertTrue(diligence.sequence_diagnostics(r, entries)["complete"])

    def test_pdf_wrapped_title_and_prose_references(self):
        text = """3 Findings

3.1 External callbacks can trigger
an unwanted state transition Major ✓ Fixed

Description
This is the first finding with a wrapped heading and explicit risk badge.
Client response:

    3.1 ‑ always display the original payload

3.2 Consider additional documentation
The recommendation intentionally has no severity label in the publisher report.
The preceding vulnerability is also described in issue
3.1 finding for stealing funds.

Appendix 1 - Disclosure
"""
        r = report(text, "consensys-diligence", "pdf")
        entries = finish(r, diligence.parse(r))
        self.assertEqual([c.printed_id for c in entries], ["3.1", "3.2"])
        self.assertEqual(entries[0].title, "External callbacks can trigger an unwanted state transition")
        self.assertEqual(entries[1].title, "Consider additional documentation")
        self.assertEqual(entries[1].severity_raw, None)

    def test_named_contract_sections_are_findings(self):
        text = """## 4 1inch Contract
### 4.1 Invalid deployment constant Minor
The detail explains why this constant should be reviewed for other chains.
## 5 Limit Order Protocol
### 5.1 Unexpected order payment Major
The second detail belongs to a separate protocol section with its own IDs.
## Appendix 1 - Files in Scope
"""
        r = report(text, "consensys-diligence")
        entries = finish(r, diligence.parse(r))
        self.assertEqual([c.printed_id for c in entries], ["4.1", "5.1"])

    def test_arbitrary_native_status_badges_do_not_hide_severity(self):
        text = """## 4 Findings
### 4.1 Callback issue Major ✓ Fix Unverified
The report names an unverified fix; it does not establish resolution of the issue.
### 4.2 Proposal issue Critical ✓ Fixed in Pull Pattern
The publisher identifies a particular remediation strategy in the status badge.
## Appendix 1 - Disclosure
"""
        entries = finish(report(text, "consensys-diligence"), diligence.parse(report(text, "consensys-diligence")))
        self.assertEqual([c.severity_raw for c in entries], ["Major", "Critical"])
        self.assertEqual(entries[0].status_raw, "Fix Unverified")
        self.assertIsNone(entries[0].normalized_status)
        self.assertEqual(entries[1].normalized_status, "fixed")


if __name__ == "__main__":
    unittest.main()
