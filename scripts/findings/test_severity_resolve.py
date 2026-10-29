"""Synthetic canonicalization regressions; no report originals or gold access."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from common import ROOT, digest
from core import Candidate, Report, severity, severity_mapping
from run import finding_rows
from severity_resolve import canonicalize_label, severity_mapping as standalone_mapping


PUBLISHERS = ("code4rena", "cantina", "pessimistic", "informalsystems",
              "runtime-verification", "kudelski-security", "blocksec")


class CanonicalSeverityTests(unittest.TestCase):
    def test_presentation_variants_for_every_affected_publisher(self):
        cases = [("Low", "low"), ("Low Risk", "low"), ("Low severity", "low"),
                 ("Low severity issues", "low"), ("Medium Risk", "medium"),
                 ("0 INFORMATIONAL", "info"), ("INFORMATIONAL", "info"),
                 ("Gas Optimizations", "gas"), ("gas", "gas"),
                 ("• (03) ＬＯＷ risk findings!", "low"),
                 ("3.2.1. **Medium severity issues:**", "medium"),
                 ("(ii) Low Risk", "low"), ("a) Low Risk", "low"),
                 ("[02] L O W   R I S K   I S S U E S", "low"),
                 ("Gas Optimizations (56)", "gas"), ("Gas-Optimization", "gas"),
                 ("Low(s)", "low"), ("Informational findings", "info")]
        for publisher in PUBLISHERS:
            for raw, expected in cases:
                with self.subTest(publisher=publisher, raw=raw):
                    self.assertEqual(severity(raw, publisher), expected)

    def test_informative_is_publisher_specific(self):
        for publisher in ("informalsystems", "runtime-verification"):
            for raw in ("Informative", "Informative findings", "Informative findings.", "In-\nformative findings"):
                with self.subTest(publisher=publisher, raw=raw):
                    self.assertEqual(severity(raw, publisher), "info")
        self.assertFalse(severity_mapping("Informative findings", "blocksec", log=False)["mapped"])

    def test_abbreviations_use_only_the_selected_publishers_definitions(self):
        defined = {"code4rena": {"H": "high", "M": "medium", "L": "low", "I": "info", "G": "gas", "QA": "low"},
                   "pessimistic": {"C": "critical", "H": "high", "M": "medium", "L": "low"}}
        for publisher in PUBLISHERS:
            for code in ("C", "H", "M", "L", "I", "G", "QA"):
                expected = defined.get(publisher, {}).get(code, "unknown")
                with self.subTest(publisher=publisher, code=code):
                    self.assertEqual(severity(code, publisher, log=False), expected)
                    self.assertEqual(severity("• 2. "+code.lower()+" severity issues.", publisher, log=False), expected)
                    self.assertEqual(severity("["+code+"] Risk", publisher, log=False), expected)
                    self.assertEqual(severity("("+code+") severity findings", publisher, log=False), expected)
        for code in ("C", "H", "M", "L", "I", "G", "QA", "N", "NC"):
            self.assertFalse(severity_mapping(code, log=False)["mapped"])

    def test_canonicalization_is_idempotent_and_keeps_risk_qualifiers(self):
        for raw in ("Low Risk", "0 INFORMATIONAL", "Informative findings", "Gas Optimizations",
                    "Potentially High", "High/Low", "P1", "Non-Critical Findings", "N/A", "-"):
            key = canonicalize_label(raw)
            self.assertEqual(canonicalize_label(key), key)
        for raw in ("Potentially High", "High/Low", "High or Low", "P1", "Low confidence"):
            self.assertEqual(severity(raw, "code4rena", log=False), "unknown")
        self.assertEqual(severity("Potentially High", "informalsystems"), "unknown")
        self.assertEqual(severity("P1", "runtime-verification"), "critical")
        self.assertEqual(severity("P4", "runtime-verification"), "info")

    def test_canonicalization_uses_the_selected_era(self):
        for publisher in ("cantina", "consensys-diligence"):
            for raw in ("Medium Risk", "medium severity issues", "Low Risk Findings"):
                base = "Low" if raw.startswith("Low") else "Medium"
                self.assertEqual(severity(raw, publisher, era="nonsecurity-advice"),
                                 severity(base, publisher, era="nonsecurity-advice"))
            self.assertEqual(severity("Medium Risk", publisher, era="nonsecurity-advice"), "info")
            self.assertEqual(severity("Low Risk", publisher, era="absent", log=False), "unknown")
        self.assertEqual(severity("WARNING issues", "oxorio", era="legacy-explicit-high-low"), "high")
        self.assertEqual(severity("WARNING issues", "oxorio", era="published-scale"), "medium")

    def test_base_definition_wins_over_old_decorated_unknown_entries(self):
        self.assertEqual(severity("0 M i n o r", "abdk-consulting"), "low")
        self.assertEqual(severity("Minor", "abdk-consulting"), "low")

    def test_json_export_and_parser_wrapper_use_identical_resolution(self):
        policy = json.loads((ROOT / "schema/severity_map.yaml").read_text())
        for publisher, entry in policy["publishers"].items():
            for era in entry["eras"]:
                for raw in (*era["labels"], "• 0 Low Risk Findings", "Gas Optimizations", None):
                    with self.subTest(publisher=publisher, era=era["id"], raw=raw):
                        parsed = severity_mapping(raw, publisher, era=era["id"], log=False)
                        external = standalone_mapping(raw, publisher, era=era["id"], log=False,
                                                      policy_path=ROOT / "schema/severity_map.json")
                        self.assertEqual({k: v for k, v in parsed.items() if k != "map_sha256"},
                                         {k: v for k, v in external.items() if k != "map_sha256"})

    def test_standalone_import_has_no_repository_or_path_side_effects(self):
        # Copy just the module and JSON artifact, then run in an unrelated cwd.
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            module = directory / "severity_resolve.py"
            policy = directory / "severity_map.json"
            shutil.copyfile(ROOT / "scripts/findings/severity_resolve.py", module)
            shutil.copyfile(ROOT / "schema/severity_map.json", policy)
            program = '''import importlib.util, pathlib, sys
before = list(sys.path)
spec = importlib.util.spec_from_file_location("external_resolver", sys.argv[1])
resolver = importlib.util.module_from_spec(spec)
original = pathlib.Path.read_bytes
def denied(*args, **kwargs):
    raise AssertionError("Import attempted a file read")
pathlib.Path.read_bytes = denied
try:
    spec.loader.exec_module(resolver)
finally:
    pathlib.Path.read_bytes = original
assert sys.path == before
assert "common" not in sys.modules and "core" not in sys.modules
assert resolver.severity("Low Risk", "code4rena", policy_path=sys.argv[2]) == "low"
'''
            result = subprocess.run([sys.executable, "-I", "-B", "-S", "-c", program, str(module), str(policy)],
                                    cwd=directory, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_emitted_original_labels_stay_verbatim(self):
        body = "A finding description with a source span.\n"
        for publisher in PUBLISHERS:
            raw = "  • ０ ＬＯＷ Severity findings!  "
            report = Report(body, {"pages": [{"page": 1, "start": 0, "end": len(body), "text": body}],
                                   "file_format": "pdf", "text_sha256": digest(body.encode())}, publisher)
            doc = {"document_id": "document:synthetic", "source_file": "fixture.jsonl", "source_locator": "line=1",
                   "source_record_sha256": "a"*64, "row": {"sha256": "b"*64, "file_format": "pdf",
                   "doc_kind": "audit_report", "public_url": "https://example.test/audit"}}
            candidate = Candidate(0, "Original label", raw, end=len(body), normalized="critical")
            row = list(finding_rows(doc, report, [candidate], "fixture"))[0]
            self.assertEqual((row["severity_original"], row["severity_raw"]), (raw, raw))
            self.assertEqual((row["severity_mapping"]["input"], row["severity_mapping"]["raw"]), (raw, raw))
            self.assertEqual(row["severity"], "low")


if __name__ == "__main__":
    unittest.main()
