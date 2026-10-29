"""Synthetic era/status regressions for Phase 4e group 4 Oak and Diligence."""
import unittest

from common import digest
from core import Report
from parsers import module
from variants import select
from variants_report import sequence

D = "\nThe detailed source describes the affected behavior and its security impact.\n"
SIDEBAR = "\n".join([
    "1 Executive Summary" + " " * 25 + "This review concerns a smart contract system.",
    "2 Scope", "3 Findings", " 3.1 Navigation title Major",
    " " * 40 + "1 Executive Summary", " " * 40 + "The agreed code was reviewed.",
    " " * 40 + "2 Scope", " " * 40 + "Only the named contracts are in scope.",
    " " * 40 + "3 Findings", " " * 40 + "3.1 Actual source issue Major ✓ Fixed", "",
    " " * 40 + "Description", " " * 40 + "This detailed source explains the issue and impact.",
]) + "\n"

FIXTURES = {
    "diligence_contract_sections": ("consensys-diligence", "pdf", "2022", "5 Smart Contracts\nEach issue has an assigned severity:\n5.1 Actual source issue Major ✓ Fixed\n" + D + "6 Other Code\n6.1 Additional source issue Minor\n" + D, "v2022_contract_sections", 2),
    "diligence_mythx_export": ("consensys-diligence", "pdf", "2020", "REPORT 5F6C8980492A590019ABC23D\nNumber of analyses     30\nClient Tool    Mythx-Cli-0.6.21\nDETECTED VULNERABILITIES\nHIGH MEDIUM LOW\n1 2 3\nISSUES\nHIGH Source scanner warning\n" + D, "v2020_mythx_exports", 0),
    "diligence_intake_checklist": ("consensys-diligence", "pdf", "2021", "Essential items:\nThe URL of a repo containing the source code\nA list of the files in scope and out of scope\n", "v2020_supporting_inputs", 0),
    "diligence_specification": ("consensys-diligence", "pdf", "2021", "zAuction\nOVERVIEW\nAn auctioning system for exchange of NFTs\nSPECIFICATIONS\n", "v2020_supporting_inputs", 0),
    "oak_numbered_cards": ("oak-security", "pdf", "2021", "Detailed Findings\n1. Actual source issue\nSeverity: Major" + D + "Status: Resolved\nResolved by changing the relevant guard.\n", "v2021_numbered_cards", 1),
    "oak_wrapped_status": ("oak-security", "pdf", "2025", "Detailed Findings\n1.\u200b Actual source issue\nSeverity: Minor" + D + "Status: Partially\nResolved\n", "v2021_numbered_cards", 1),
    "oak_status_index": ("oak-security", "pdf", "2021", "Summary of Findings\nNo Description Severity Status\n1 Actual source issue   Minor   Pending\nDetailed Findings\n1. Actual source issue\nSeverity: Minor" + D, "v2021_numbered_cards", 1),
    "oak_phased_cards": ("oak-security", "pdf", "2025", "Detailed Findings for Phase 1\n1. Actual first issue\nSeverity: Major" + D + "Status: Resolved\nDetailed Findings for Phase 2\n1. Actual second issue\nSeverity: Minor" + D + "Status: Acknowledged\n", "v2025_phased_cards", 2),
    "oak_protocol_review": ("oak-security", "pdf", "2024", "Protocol Security Review\nDetailed Findings\n   1. Actual protocol issue\n      with a wrapped title\n" + D, "v2024_protocol_review", 1),
    "oak_catalog_links": ("oak-security", "md", "2022", "# Technology\n**1 report**\n- [Project report](https://github.com/oak-security/audit-reports/blob/main/report.pdf)\n", "v2022_catalog_links", 0),
    "diligence_markdown_icons": ("consensys-diligence", "md", "2018", "## 3 Issues\n### 3.1 Actual source issue\n| Severity | Status | Link |\n| --- | --- | --- |\n| <img src=\"static/major.png\"/> | <img src=\"static/closed.png\"/> | source |\n" + D, "v2018_markdown_tables", 1),
    "diligence_markdown_text": ("consensys-diligence", "md", "2019", "## 3 Issues\n### 3.1 Actual source issue\n| Severity | Status | Remediation Comment |\n| --- | --- | --- |\n| Minor | Fix Not Reviewed | The proposed fix was not reviewed. |\n" + D, "v2018_markdown_tables", 1),
    "diligence_markdown_inline_fence": ("consensys-diligence", "md", "2019", "## 3 Issues\n### 3.1 Actual first issue\n| Severity | Status |\n| --- | --- |\n| Major | Closed |\n" + D + "```contract Example {}```\n### 3.2 Actual second issue\n| Severity | Status |\n| --- | --- |\n| Minor | Closed |\n" + D, "v2018_markdown_tables", 2),
    "diligence_web_badges": ("consensys-diligence", "html", "2024", "## 3 Findings\n### 3.1 Actual source issue Major ✓ Fixed\n" + D, "v2019_web_badges", 1),
    "diligence_web_resolution": ("consensys-diligence", "html", "2020", "## 3 Issues\n### 3.1 Actual source issue Medium\n#### Resolution\nThis was partially addressed in the linked change.\n#### Description\n" + D, "v2019_web_badges", 1),
    "diligence_web_update": ("consensys-diligence", "html", "2020", "## 3 Issues\n### 3.1 Actual source issue Major\nUPDATE: This issue has been fixed in the published change.\n\n" + D, "v2019_web_badges", 1),
    "diligence_fullwidth_pdf": ("consensys-diligence", "pdf", "2020", "3 Issues\n3.1 Actual source issue Major ✓ Fixed\n" + D, "v2020_fullwidth_pdf", 1),
    "diligence_sidebar_pdf": ("consensys-diligence", "pdf", "2021", SIDEBAR, "v2019_sidebar_pdf", 1),
    "diligence_supporting_narrative": ("consensys-diligence", "html", "2020", "# Cryptographic Review\nNo significant issues were found in the cryptographic review.\n" + D, "v2020_narrative_supporting", 0),
    "diligence_clean_review": ("consensys-diligence", "html", "2023", "# Executive Summary\nNo issues are found, however the deployment parameters require caution.\n" + D, "v2020_narrative_supporting", 0),
    "diligence_safetychecker": ("consensys-diligence", "pdf", "2021", "1 SafetyChecker Summary\nThe report discusses future safety concerns and gas considerations.\n" + D, "v2020_narrative_supporting", 0),
}


def report(text, firm, fmt="pdf", date=None):
    pages, start = [], 0
    for number, page in enumerate(text.split("\f"), 1):
        pages.append(dict(page=number, start=start, end=start + len(page), text=page))
        start += len(page) + 1
    return Report(text, dict(file_format=fmt, pages=pages, text_sha256=digest(text.encode()), date_hint=date), firm)


def fixture(name):
    firm, fmt, date, text, era, count = FIXTURES[name]
    result = report(text, firm, fmt, date)
    return result, era, count


class Group4OakConsensysTests(unittest.TestCase):
    def test_all_declared_era_fixtures(self):
        names = set()
        for firm in ("oak-security", "consensys-diligence"):
            adapter = module(firm)
            for variant in adapter.VARIANTS:
                self.assertFalse(variant.fingerprint.legacy)
                self.assertIsNotNone(variant.status_parser)
                for name in variant.fixtures:
                    names.add(name)
                    with self.subTest(fixture=name):
                        source, era, count = fixture(name)
                        rows = adapter.parse(source)
                        self.assertEqual(source.layout_selection["variant_id"], firm + "/" + era)
                        self.assertEqual(len(rows), count)
                        for row in rows:
                            self.assertTrue(0 <= row.start < row.end <= len(source.text))
                            proof = row.evidence.get("status_evidence")
                            if proof:
                                self.assertEqual(source.text[proof["start"]:proof["end"]], proof["text"])
                                self.assertEqual(row.status_raw, proof["text"])
        self.assertEqual(names, set(FIXTURES))

    def test_oak_does_not_append_resolution_prose_to_status(self):
        source, _, _ = fixture("oak_numbered_cards")
        row = module(source.firm).parse(source)[0]
        self.assertEqual(row.status_raw, "Resolved")
        self.assertEqual(row.normalized_status, "resolved")

    def test_oak_wrapped_status_retains_exact_source_label(self):
        source, _, _ = fixture("oak_wrapped_status")
        row = module(source.firm).parse(source)[0]
        self.assertEqual(row.status_raw, "Partially\nResolved")
        self.assertEqual(row.normalized_status, "partial")

    def test_oak_index_and_conflict(self):
        source, _, _ = fixture("oak_status_index")
        row = module(source.firm).parse(source)[0]
        self.assertEqual(row.status_raw, "Pending")
        self.assertEqual(row.normalized_status, "open")
        self.assertEqual(row.evidence["status_evidence"]["basis"], "same_phase_printed_id_status_table")
        text = source.text.replace("Detailed Findings", "1 Actual source issue   Minor   Resolved\nDetailed Findings")
        row = module(source.firm).parse(report(text, source.firm))[0]
        self.assertIsNone(row.status_raw)
        self.assertTrue(row.evidence["status_conflict"])

    def test_oak_phase_local_ids_are_structurally_complete(self):
        source, _, _ = fixture("oak_phased_cards")
        rows = module(source.firm).parse(source)
        normalized = [dict(publisher_finding_id=row.printed_id, record_kind=row.record_kind, evidence=row.evidence) for row in rows]
        self.assertTrue(sequence(normalized, source.firm)["complete"])

    def test_oak_protocol_missing_grade_and_status_stay_absent(self):
        source, _, _ = fixture("oak_protocol_review")
        row = module(source.firm).parse(source)[0]
        self.assertIsNone(row.severity_raw)
        self.assertEqual(row.normalized, "unknown")
        self.assertIsNone(row.status_raw)

    def test_diligence_unreviewed_fix_is_preserved_as_other(self):
        source, _, _ = fixture("diligence_markdown_text")
        row = module(source.firm).parse(source)[0]
        self.assertEqual(row.severity_raw, "Minor")
        self.assertEqual(row.status_raw, "Fix Not Reviewed")
        self.assertEqual(row.normalized_status, "other")

    def test_diligence_numeric_text_dashboard_accepts_missing_trailing_pipe(self):
        from parsers.consensys_diligence import printed_counts
        source = report("#### Number of issues by severity\n| | **Minor** | **Medium** | **Major** | **Critical** |\n| --- | --- | --- | --- | --- |\n | **Open** | **0** | **0** | **0** | **0**\n | **Closed** | **2** | **2** | **1** | **2**\n", "consensys-diligence", "md")
        self.assertEqual(printed_counts(source)["counts"], {"low": 2, "medium": 2, "high": 1, "critical": 2})

    def test_diligence_resolution_and_update(self):
        for name, state in (("diligence_web_resolution", "partial"), ("diligence_web_update", "fixed")):
            source, _, _ = fixture(name)
            row = module(source.firm).parse(source)[0]
            self.assertEqual(row.normalized_status, state)
            self.assertIsNotNone(row.resolution)
            self.assertIn("resolution_evidence", row.evidence)

    def test_diligence_latest_resolution_and_description_boundary(self):
        source = report("## 3 Issues\n### 3.1 Actual source issue Major\n" + D + "#### Resolution\nIssue was partly addressed in an initial change.\nUpdated remediation response: It is fully resolved.\n#### Description and Recommendation\nThe recommendation should be fixed before release.\n", "consensys-diligence", "html")
        row = module(source.firm).parse(source)[0]
        self.assertEqual(row.normalized_status, "resolved")
        self.assertNotIn("Description", row.resolution)

    def test_diligence_badge_wins_with_conflict_receipt(self):
        source, _, _ = fixture("diligence_web_badges")
        source = report(source.text + "#### Resolution\nThis was partially addressed in a first change.\n", source.firm, "html")
        row = module(source.firm).parse(source)[0]
        self.assertEqual(row.status_raw, "Fixed")
        self.assertTrue(row.evidence["status_conflict"])
        self.assertEqual(row.evidence["alternate_status_claims"][0]["raw"], "partially addressed")

    def test_diligence_recommendation_prose_does_not_establish_status(self):
        for text in (
            "#### Recommendation\nThis should be fixed before release.",
            "#### Resolution\nThe client said this will be fixed before release.",
            "UPDATE: We recommend that this issue is fixed before release.",
            "UPDATE: The team will have implemented a fix before release.",
        ):
            source = report("## 3 Issues\n### 3.1 Actual source issue Major\n" + D + text + "\n", "consensys-diligence", "html")
            self.assertIsNone(module(source.firm).parse(source)[0].status_raw)

    def test_date_does_not_select_an_unfamiliar_document(self):
        for firm in ("oak-security", "consensys-diligence"):
            source = report("A completely unfamiliar document.", firm, date="2024")
            self.assertIsNone(select(source, module(firm).VARIANTS))

    def test_fullwidth_blank_lines_do_not_become_a_sidebar_signature(self):
        source = report("3 Findings" + "\n" * 12 + "3.1 Actual source issue Major ✓ Fixed\n" + D, "consensys-diligence", "pdf", "2024")
        module(source.firm).parse(source)
        self.assertEqual(source.layout_selection["variant_id"], "consensys-diligence/v2020_fullwidth_pdf")


if __name__ == "__main__":
    unittest.main()
