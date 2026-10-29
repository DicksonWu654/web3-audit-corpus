"""Cross-publisher, era, provenance and previous-engagement regressions.

Synthetic text only: no holdout or original document is opened by these tests.
"""
import json
from pathlib import Path
import tempfile
import unittest

from common import ROOT, digest
from core import (Candidate, Report, candidate_severity, finish, severity,
                  severity_context, severity_mapping, severity_policy)
from parsers import module
from prior_findings import exclude_prior_findings
from run import finding_rows
from summary_counts import printed_counts


def report(text, firm, fmt="pdf"):
    pages, start = [], 0
    for i, value in enumerate(text.split("\f"), 1):
        pages.append({"page": i, "start": start, "end": start+len(value), "text": value})
        start += len(value)+1
    return Report(text, {"pages": pages, "file_format": fmt,
                         "text_sha256": digest(text.encode())}, firm)


BODY = "Description\nAn engagement finding with enough source evidence to retain its original span.\n"


class SeverityPolicyTests(unittest.TestCase):
    def test_publisher_semantics_are_not_universal_aliases(self):
        cases = [("ackee-blockchain", "Warning", "info"), ("ackee-blockchain", "W", "info"),
                 ("oxorio", "WARNING", "medium"), ("mixbytes", "Warning", "medium"),
                 ("veridise", "Warning", "info"), ("abdk-consulting", "Moderate", "medium"),
                 ("consensys-diligence", "Major", "high"), ("solidified", "Minor", "low"),
                 ("solidified", "Notes", "info"), ("halborn", "VERY LOW", "info"),
                 ("slowmist", "Weakness", "info"), ("three-sigma", "None", "info"),
                 ("runtime-verification", "P1", "critical"), ("runtime-verification", "P4", "info"),
                 ("movebit", "Medium", "info"), ("scalebit", "Minor", "info"),
                 ("macro", "Q", "info"), ("code4rena", "QA", "low"),
                 ("code4rena", "NC", "info"), ("code4rena", "G", "gas")]
        for firm, raw, expected in cases:
            with self.subTest(firm=firm, raw=raw):
                self.assertEqual(severity(raw, firm), expected)

    def test_era_definitions_override_familiar_label_spelling(self):
        r = report("Medium issues are objective in nature but are not security vulnerabilities.\n", "consensys-diligence")
        mapping = candidate_severity(r, Candidate(0, "Advice", "Medium"))
        self.assertEqual((mapping["normalized"], mapping["era"]), ("info", "nonsecurity-advice"))
        r = report("WARNING\nHigh severity issues will probably bring problems.\n", "oxorio")
        mapping = candidate_severity(r, Candidate(0, "Old risk scale", "WARNING"))
        self.assertEqual((mapping["normalized"], mapping["era"]), ("high", "legacy-explicit-high-low"))
        self.assertEqual(severity("INFO", "oxorio", era="legacy-explicit-high-low"), "low")

    def test_raw_case_spacing_and_null_are_never_rewritten(self):
        raw = "  M A J O R  "
        r = report(BODY, "oxorio")
        c = Candidate(0, "Raw label", raw, end=len(BODY), normalized="critical")
        doc = {"document_id": "document:synthetic", "source_file": "fixture.jsonl", "source_locator": "line=1",
               "source_record_sha256": "a"*64, "row": {"sha256": "b"*64, "file_format": "pdf",
               "doc_kind": "audit_report", "public_url": "https://example.test/audit"}}
        row = list(finding_rows(doc, r, [c], "fixture"))[0]
        self.assertEqual((row["severity_original"], row["severity_raw"]), (raw, raw))
        self.assertEqual(row["severity"], "high")
        self.assertEqual(row["severity_mapping"]["input"], raw)
        self.assertEqual(row["severity_mapping"]["map_sha256"], severity_policy()[2])

    def test_unrated_source_kind_controls_advice_without_inventing_a_label(self):
        r = report(BODY, "least-authority")
        for kind, expected in [("Issue", "unknown"), ("Suggestion", "info"), ("recommendation", "info")]:
            c = Candidate(0, "Untyped native label", evidence={"kind": kind})
            self.assertIsNone(c.severity_raw)
            self.assertEqual(candidate_severity(r, c)["normalized"], expected)
        r = report(BODY, "consensys-diligence")
        c = Candidate(0, "Improve docs", evidence={"parent_title": "Recommendations and Advice"})
        self.assertEqual(candidate_severity(r, c)["normalized"], "info")

    def test_unmapped_labels_log_and_do_not_inherit_generic_or_parser_hints(self):
        with self.assertLogs("findings.severity", level="WARNING"):
            mapping = severity_mapping("Never-seen-severity-192", "oxorio")
        self.assertEqual(mapping["normalized"], "unknown")
        self.assertFalse(mapping["mapped"])
        self.assertEqual(severity("Major", "ackee-blockchain"), "unknown")
        self.assertEqual(severity("High", "unregistered-publisher"), "unknown")

    def test_context_is_restored_on_error_and_does_not_leak_between_publishers(self):
        with self.assertRaises(ValueError):
            with severity_context(report(BODY, "oxorio")):
                self.assertEqual(severity("Warning"), "medium")
                raise ValueError("synthetic failure")
        with severity_context(report(BODY, "ackee-blockchain")):
            self.assertEqual(severity("Warning"), "info")
        self.assertEqual(severity("Warning", log=False), "unknown")

    def test_conflicting_aliases_and_invalid_buckets_fail_closed(self):
        policy = json.loads((ROOT / "schema/severity_map.yaml").read_text())
        era = policy["publishers"]["oxorio"]["eras"][-1]
        era["labels"]["w a r n i n g"] = {"normalized": "critical", "rationale": "Deliberate conflict."}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "map.yaml"
            path.write_text(json.dumps(policy))
            with self.assertRaisesRegex(ValueError, "Conflicting"):
                severity_policy(path)

    def test_export_has_identical_content_and_only_the_yaml_is_authoritative(self):
        self.assertEqual(json.loads((ROOT / "schema/severity_map.json").read_text()),
                         json.loads((ROOT / "schema/severity_map.yaml").read_text()))

    def test_collapsed_native_summary_classes_add_without_overwriting(self):
        r = report("Medium issues are objective in nature but are not security vulnerabilities.\n"
                   "Severity Count\nCritical 0\nMajor 1\nMedium 2\nMinor 3\n", "consensys-diligence")
        self.assertEqual(printed_counts(r)["counts"], {"critical": 0, "high": 1, "info": 5})
        r = report("Warning-Severity Issues 2\nInfo-Severity Issues 3\n", "veridise")
        self.assertEqual(module("veridise").printed_counts(r)["counts"], {"info": 5})
        r = report("Issue Statistic\nMedium 2\nMinor 3\nInformational 4\n", "movebit")
        self.assertEqual(module("movebit").printed_counts(r)["counts"], {"info": 9})


class PreviousAuditTests(unittest.TestCase):
    def test_cantina_previous_known_section_is_excluded_and_next_section_survives(self):
        text = ("3 Findings\n3.1 High\n3.1.1 New exploit\n"+BODY+
                "3.2 Previously-known issues\n3.2.1 Old exploit under re-check\n"+BODY+
                "3.3 Low\n3.3.1 New small issue\n"+BODY)
        r = report(text, "cantina")
        rows = finish(r, module("cantina").parse(r))
        self.assertEqual([c.printed_id for c in rows], ["3.1.1", "3.3.1"])
        self.assertEqual(len(r.excluded_prior_findings), 1)
        self.assertNotIn("Previously-known", r.text[rows[0].start:rows[0].end])

    def test_recheck_table_and_detail_are_excluded_by_structural_section(self):
        text = "# Findings from the previous audit\n## [H-01] Earlier exploit\n"+BODY+"# New Findings\n## [L-01] Newly found bug\n"+BODY
        r = report(text, "codespect", "md")
        rows = finish(r, module("codespect").parse(r))
        self.assertEqual([c.printed_id for c in rows], ["L-01"])

    def test_fixed_status_and_prior_audit_mentions_do_not_remove_a_new_finding(self):
        text = "## [H-01] Current exploit\nStatus: Fixed\nThe previous audit checked another component.\n"+BODY
        r = report(text, "codespect", "md")
        rows = finish(r, module("codespect").parse(r))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].status_raw, "Fixed")

    def test_new_mitigation_vulnerability_survives_original_finding_recheck(self):
        text = ("# Medium Risk Findings (1)\n## [M-01] Initial issue\n"+BODY+
                "# Mitigation Review\n## [M-01] Recheck of initial issue\n"+BODY+
                "## [MR-H-01] New vulnerability introduced by the fix\n"+BODY)
        r = report(text, "code4rena", "md")
        rows = finish(r, module("code4rena").parse(r))
        self.assertEqual([c.printed_id for c in rows], ["M-01", "MR-H-01"])
        self.assertEqual(rows[1].record_kind, "formal_finding")
        self.assertEqual(rows[1].finding_phase, "fix_review")

    def test_guardian_duplicate_id_requires_explicit_remediation_provenance(self):
        r = report(BODY*3, "guardianaudits")
        initial = Candidate(0, "Initial issue", "High", "H-01", end=len(BODY))
        new = Candidate(len(BODY), "New issue", "Low", "L-01", end=2*len(BODY), finding_phase="fix_review")
        old = Candidate(2*len(BODY), "Recheck", "High", "H-01", end=3*len(BODY), evidence={"previous_audit_finding": True})
        self.assertEqual(exclude_prior_findings(r, [initial, new, old]), [initial, new])

    def test_guardian_restarted_ids_for_new_remediation_bugs_are_preserved(self):
        text = ("HIGH H-01 RESOLVED\nInitial bug\nCATEGORY\nLogical Error\nREVIEW Main Review\n"+BODY+
                "HIGH H-01 RESOLVED\nNew bug introduced by the fix\nCATEGORY\nLogical Error\nREVIEW Remediation Review\n"+BODY)
        r = report(text, "guardianaudits")
        rows = finish(r, module("guardianaudits").parse(r))
        self.assertEqual([c.title for c in rows], ["Initial bug", "New bug introduced by the fix"])
        self.assertEqual(rows[1].finding_phase, "fix_review")


if __name__ == "__main__":
    unittest.main()
