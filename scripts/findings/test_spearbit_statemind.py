"""Synthetic era/layout regressions, with no report originals or holdouts."""
import unittest
from core import Report, finish
from parsers import spearbit, statemind


def report(text, firm):
    pages, offset = [], 0
    for index, value in enumerate(text.split("\f"), 1):
        pages.append({"page": index, "start": offset, "end": offset + len(value), "text": value})
        offset += len(value) + 1
    return Report(text, {"file_format": "pdf", "pages": pages}, firm)


class Spearbit(unittest.TestCase):
    def test_does_not_extract_parent_or_toc(self):
        text = "Contents\n5.1 High Risk . . . . . . . . 5\n5.1.1 Wrapped heading . . . . . . . . 5\f5 Findings\n5.1 High Risk\n5.1.1 Wrapped heading\n     continued title\nSeverity: High Risk\nContext: File.sol\nDescription: This is a sufficiently detailed explanation.\nSpearbit: Verified.\n"
        values = finish(report(text, "spearbit"), spearbit.parse(report(text, "spearbit")))
        self.assertEqual([(c.title, c.severity_raw, c.normalized, c.printed_id) for c in values], [("Wrapped heading continued title", "High Risk", "high", "5.1.1")])
        self.assertEqual(values[0].status_raw, "Verified")

    def test_parent_label_missing_field_and_redaction(self):
        text = "5 Findings\n5.1 Medium Risk\n5.1.1 Missing field\nContext: a.sol\nDescription: This card omits its severity field but has an explicit severity section.\n5.1.2 REDACTED\nThe issue was identified by Spearbit, resolved by the client and verified as resolved by Spearbit.\n"
        values = finish(report(text, "spearbit"), spearbit.parse(report(text, "spearbit")))
        self.assertEqual([c.normalized for c in values], ["medium", "medium"])
        self.assertEqual(values[1].title, "REDACTED")

    def test_explicit_label_is_preserved_when_section_disagrees(self):
        text = "5 Findings\n5.1 Informational\n5.1.1 Conflicting labels\nSeverity: Low Risk\nContext: a.sol\nDescription: Explicit risk labels must survive independently of summary totals.\n"
        values = spearbit.parse(report(text, "spearbit"))
        self.assertEqual((values[0].severity_raw, values[0].normalized), ("Low Risk", "low"))

    def test_post_engagement_appendix_observation(self):
        text = "5 Findings\n5.1 Low Risk\n5.1.1 Initial issue\nSeverity: Low Risk\nContext: a.sol\nDescription: The main review finding is described in this section.\n6 Appendix\nThe following issues were raised post-engagement and have yet to be scrutinized.\n6.1 Update\n6.1.1 Client-raised issue\nContext: a.sol\nDescription: This observation is preserved separately from formal reviewed findings.\n"
        values = spearbit.parse(report(text, "spearbit"))
        self.assertEqual([c.record_kind for c in values], ["formal_finding", "observation"])
        self.assertIsNone(values[1].severity_raw)

    def test_numeric_summary_totals_are_independent_and_include_gas(self):
        text = "4 Executive Summary\nCritical Risk     0   0   0\nHigh Risk     1   1   0\nMedium Risk     0   0   0\nLow Risk     2   0   2\nGas Optimizations     3   2   1\nInformational     4   1   3\n"
        summary = spearbit.printed_counts(report(text, "spearbit"))
        self.assertEqual(summary["counts"], {"critical": 0, "high": 1, "medium": 0, "low": 2, "gas": 3, "info": 4})
        self.assertEqual(spearbit.parse(report(text, "spearbit")), [])

    def test_cryptography_narrative_labels_are_not_all_gas(self):
        text = "4 Findings\n4.1 Protocol Documentation / White Paper Review\n4.1.2 Documentation\nMissing polynomial commitment (Informa-\ntional) The preprocessed inputs are missing in the description.\n\nUnnecessary verifier arithmetic (Optimization) The verifier repeats a calculation.\n"
        values = spearbit.parse(report(text, "spearbit"))
        self.assertEqual([(c.title, c.normalized) for c in values], [("Missing polynomial commitment", "info"), ("Unnecessary verifier arithmetic", "unknown")])
        self.assertTrue(all(c.printed_id is None for c in values))

    def test_upgrade_validation_is_observation_and_excludes_child_sections(self):
        text = "5 Findings\n5.1 Upgrade Proposal #15a - Mainnet\n    and other chains\nSeverity: Informational\n\n5.1.1 Validation\nThis document validates the inputs and result of the execution of an upgrade transaction.\n5.1.2 Expected hashes\nThe expected message hashes belong to the validation assessment above.\n"
        values = spearbit.parse(report(text, "spearbit"))
        self.assertEqual(len(values), 1)
        self.assertEqual((values[0].printed_id, values[0].record_kind), ("5.1", "observation"))


class Statemind(unittest.TestCase):
    def test_legacy_status_word_inside_title(self):
        text = "5. Findings report\nInformational\n\nPending old observations sending DoS            Acknowledged\n\nDescription\nThis is a sufficiently detailed description of the observed issue.\n6. Appendix A. Slither\nHigh/High/external-call\n"
        values = finish(report(text, "statemind"), statemind.parse(report(text, "statemind")))
        self.assertEqual([(c.title, c.severity_raw, c.printed_id) for c in values], [("Pending old observations sending DoS", "Informational", None)])
        self.assertEqual(values[0].status_raw, "Acknowledged")
        self.assertNotIn("Slither", text[values[0].start:values[0].end])

    def test_card_header_pagebreak_before_description(self):
        text = "5. Findings report\n\nMEDIUM-01       Wrapped issue title        Fixed at abcd123\n\n" + " " * 70 + "5\n\fDescription\nThe description starts on the following page and remains part of the finding.\n"
        values = statemind.parse(report(text, "statemind"))
        self.assertEqual(len(values), 1)
        self.assertEqual((values[0].title, values[0].printed_id), ("Wrapped issue title", "MEDIUM-01"))

    def test_multiline_centered_id_and_status(self):
        text = "5. Findings report\n\n                  The whole title has a\nINFORMATIONAL-\n                  second line                  Acknowledged\n12\n                  final line\n\nDescription\nThe split ID must join the numeric suffix without changing any body text.\n"
        values = statemind.parse(report(text, "statemind"))
        self.assertEqual(values[0].printed_id, "INFORMATIONAL-12")
        self.assertEqual(values[0].title, "The whole title has a second line final line")

    def test_role_matrix_is_not_a_findings_summary(self):
        text = "5. Role analysis\nRole impact severity    HIGH\nCritical 0\nHigh 1\nMedium 0\n"
        self.assertIsNone(statemind.printed_counts(report(text, "statemind")))
        self.assertEqual(statemind.parse(report(text, "statemind")), [])


if __name__ == "__main__":
    unittest.main()
