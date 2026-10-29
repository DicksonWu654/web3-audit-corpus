"""In-memory regression cases for provenance, holdout isolation and summary independence."""
import unittest
from unittest.mock import patch
from pathlib import Path
from common import digest
from core import Report, finish, severity, status
from extract import HTMLText, extract_one
from parsers import module
from structured import quantstamp_payload, render_report
from summary_counts import printed_counts


def report(text, firm="code4rena", fmt="md"):
    pages, start = [], 0
    for i,page in enumerate(text.split("\f"),1):
        pages.append({"page":i,"start":start,"end":start+len(page),"text":page})
        start += len(page)+1
    return Report(text,{"pages":pages,"text_sha256":digest(text.encode()),"file_format":fmt},firm)


class FrameworkTests(unittest.TestCase):
    def test_holdout_denied_before_original_or_cache_access(self):
        sha = "a"*64
        with patch("extract.original_path",side_effect=AssertionError("Original opened")):
            with self.assertRaisesRegex(RuntimeError,"Holdout"):
                extract_one((sha,{"file_format":"pdf"}),Path("unopened-root"),{sha})

    def test_toc_code_fence_and_prose_do_not_create_findings(self):
        text = "- [H-01] linked TOC title\n\n```md\n## [H-99] Exploit example heading\n```\nH-88 ordinary prose\n\n## [H-01] Real finding\n" + "Evidence and a detailed explanation.\n"*4
        r = report(text)
        rows = finish(r,module("code4rena").parse(r))
        self.assertEqual([c.printed_id for c in rows],["H-01"])
        self.assertEqual(r.text[rows[0].start:rows[0].end],text[text.index("## [H-01]"):])

    def test_wrapped_pdf_toc_and_summary_rows_are_not_details(self):
        r = report("Contents\n[L-01] A title wrapped across\nlines    5\n\fID  Title  Severity  Status\nL-01  Another wrapped title\n\f[L-01] Actual finding\nDescription\n"+"Real description.\n"*5,"pashov-audit-group","pdf")
        rows = finish(r,module("pashov-audit-group").parse(r))
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0].title,"Actual finding")

    def test_summary_counts_cannot_manufacture_missing_findings(self):
        text = "# High Risk Findings (2)\n## [H-01] One detailed issue\n" + "Details of the actual issue.\n"*4
        r = report(text)
        self.assertEqual(printed_counts(r)["counts"],{"high":2})
        self.assertEqual(len(finish(r,module("code4rena").parse(r))),1)

    def test_c4_link_wrapped_detail_heading(self):
        r=report("## [[H-01] Actual issue](https://example.org/issues/1)\n"+"Evidence.\n"*8)
        c=module("code4rena").parse(r)[0]
        self.assertEqual(c.title,"Actual issue")
        self.assertEqual(c.printed_id,"H-01")

    def test_c4_nested_reference_heading_is_not_a_second_finding(self):
        r=report("# High Risk Findings\n## [H-01] Final issue\n### [H-1] Nested issue reference\n"+"Evidence.\n"*8)
        rows=module("code4rena").parse(r)
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0].printed_id,"H-01")

    def test_sherlock_pdf_split_title(self):
        r=report("Issue M-03 (previously M-05)\nActual issue title\ncontinued\n\nSeverity\nMedium\n"+"Evidence.\n"*8,"sherlock","pdf")
        c=module("sherlock").parse(r)[0]
        self.assertEqual(c.title,"Actual issue title\ncontinued")

    def test_c4_printed_id_beats_narrative_severity(self):
        r = report("# Medium Risk Findings\n## [M-01] Incorrect accounting\n### Severity\nHigh Risk\n"+"Description of the submitted issue.\n"*3)
        c = module("code4rena").parse(r)[0]
        self.assertEqual(c.normalized,"medium")
        self.assertEqual(c.severity_raw,"M")

    def test_unknown_status_words_are_not_severities(self):
        self.assertEqual(severity("Resolved"),"unknown")
        self.assertEqual(severity("Suggestion"),"unknown")
        self.assertEqual(status("Accepted"),"other")
        self.assertEqual(status("AC K N OW L E D G E D"),"acknowledged")

    def test_page_spans_use_formfeed_not_splitlines_offsets(self):
        text = "Page one\n\f## [M-01] Second page issue\n"+"Evidence on page two.\n"*3
        r = report(text)
        c = finish(r,module("code4rena").parse(r))[0]
        self.assertEqual(c.start,len("Page one\n\f"))
        self.assertEqual(next(l.page for l in r.lines if l.start==c.start),2)

    def test_horizontal_summary_ignores_risk_matrix(self):
        r = report("| Severity | Critical | High | Medium | Low |\n|---|---|---|---|---|\n| | 0 | 1 | 2 | 3 |\n")
        self.assertEqual(printed_counts(r)["counts"],{"critical":0,"high":1,"medium":2,"low":3})
        self.assertIsNone(printed_counts(report("| Likelihood | High | Medium | Low |\n| High | Critical | High | Medium |\n")))

    def test_split_html_severity_counts_and_notes(self):
        r=report("Critical Severity Issues\n0 (0 resolved)\n\nHigh Severity Issues\n1 (1 resolved)\nNotes & Additional Information\n2 (0 resolved)\n","openzeppelin","html")
        self.assertEqual(printed_counts(r)["counts"],{"critical":0,"high":1,"info":2})

    def test_html_preserves_headings_and_suppresses_active_content(self):
        p = HTMLText()
        p.feed("<h2>High Severity</h2><script>fake issue</script><h3>Finding title</h3><p>Details</p>")
        self.assertIn("## High Severity",p.text())
        self.assertIn("### Finding title",p.text())
        self.assertNotIn("fake issue",p.text())

    def test_static_json_only_no_executable_expression(self):
        data = {"reportContent":{"setup":{},"summary":{}}}
        import json
        source = "JSON.parse(" + repr(json.dumps(data)) + ")"
        self.assertEqual(quantstamp_payload(source),data)
        with self.assertRaises(ValueError):
            quantstamp_payload("JSON.parse(loadSecrets())")
        text, native = render_report({"reportContent":{"items":[{"title":"real title"}]}})
        span = native["spans"]["/reportContent/items/0"]
        self.assertIn("real title",text[span["start"]:span["end"]])

    def test_js_utf16_surrogate_pairs_become_utf8_unicode(self):
        import json
        source="JSON.parse("+repr(json.dumps({"reportContent":{"title":"\ud83d\ude80"}}))+")"
        value=quantstamp_payload(source)
        text,_=render_report(value)
        self.assertIn("🚀",text)
        text.encode("utf-8")

    def test_quantstamp_preserves_full_source_risk_label(self):
        r=report("QSP-1 Actual issue\nSeverity: High Risk\n"+"Evidence.\n"*8,"quantstamp","pdf")
        c=module("quantstamp").parse(r)[0]
        self.assertEqual(c.severity_raw,"High Risk")
        self.assertEqual(c.normalized,"high")

    def test_quantstamp_null_optional_arrays_are_empty_not_parser_errors(self):
        text,native=render_report({"reportContent":{"breakdownAndAutomatedAnalysis":{"vulnerabilitiesArray":None,"suggestionsArray":None}}})
        r=report(text,"quantstamp","other")
        r.native=native
        self.assertEqual(module("quantstamp").parse(r),[])

    def test_repeated_guardian_ids_are_distinct_rounds(self):
        r = report("MEDIUM  M-01    ACKNOWLEDGED\nFirst round title\n"+"Evidence.\n"*6+"MEDIUM  M-01    RESOLVED\nSecond round title\n"+"Evidence.\n"*6,"guardianaudits","pdf")
        rows = finish(r,module("guardianaudits").parse(r))
        self.assertEqual(len(rows),2)
        self.assertNotEqual(rows[0].start,rows[1].start)

    def test_guardian_dotted_id_and_spaced_label(self):
        r=report("I N FO R M AT I O N A L  I-01.2    R E S O LV E D\nActual title\n"+"Evidence.\n"*8,"guardianaudits","pdf")
        c=module("guardianaudits").parse(r)[0]
        self.assertEqual(c.printed_id,"I-01.2")
        self.assertEqual(severity(c.severity_raw),"info")

    def test_otter_id_does_not_backtrack_into_numeric_suffix(self):
        r=report("OS-SBLK-ADV-00   High   Resolved   A wrapped summary row\n"+"Text.\n"*10,"ottersec","pdf")
        self.assertEqual(module("ottersec").parse(r),[])

    def test_zellic_parallel_chapter_and_metadata_columns(self):
        r=report("3. Detailed Findings  3.1. Actual vulnerability\n Target   Vault\n Category   Business Logic   Severity   High\n Likelihood   High   Impact   Critical\n"+"Evidence.\n"*10,"zellic","pdf")
        c=module("zellic").parse(r)[0]
        self.assertEqual(c.title,"Actual vulnerability")
        self.assertEqual(c.severity_raw,"Critical")


if __name__ == "__main__":
    unittest.main()
