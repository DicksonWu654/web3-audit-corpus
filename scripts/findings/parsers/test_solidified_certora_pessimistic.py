"""Synthetic regression tests; no original, cached report or holdout is read."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import Report, finish
from parsers import solidified, certora, pessimistic


def report(text, firm):
    return Report(text,{"file_format":"pdf","pages":[{"page":1,"start":0,"end":len(text),"text":text}]},firm)


class Solidified(unittest.TestCase):
    def test_detail_table_and_singular_note(self):
        text="""Issues Found
Issue #   Description   Severity   Status
1   A lengthy finding title here   Major   Resolved
2   A second lengthy finding title   Minor   Acknowledged
Major Issues

1. A lengthy finding title here

Description of the actual issue with a proper narrative.

Note
This supplementary note does not change the issue's severity.

Minor Issues

2. A second lengthy finding title

Description of another actual issue with a proper narrative.
Disclaimer
No finding may leak into this disclaimer.
"""
        rows=finish(report(text,'solidified'),solidified.parse(report(text,'solidified')))
        self.assertEqual([(c.printed_id,c.severity_raw) for c in rows],[('1','Major'),('2','Minor')])
        self.assertNotIn('Disclaimer',text[rows[-1].start:rows[-1].end])

    def test_numbering_gaps_and_no_space_after_dot(self):
        text="Issues Found\nInformational Notes\n\n1. First sufficiently lengthy finding\n\nAn adequately long first finding body.\n\n4.Second sufficiently lengthy finding\n\nAn adequately long second finding body.\n"
        rows=finish(report(text,'solidified'),solidified.parse(report(text,'solidified')))
        self.assertEqual([x.printed_id for x in rows],['1','4'])

    def test_bounty_appendix_does_not_add_rows(self):
        text="Issues Found\nMajor Issues\n\n1. First lengthy detail title\n\nAn adequately lengthy first finding narrative.\n\nBug Bounty Results\n\n2. A separate bounty item\n\nThis is not an audit finding in the main report.\n"
        rows=finish(report(text,'solidified'),solidified.parse(report(text,'solidified')))
        self.assertEqual(len(rows),1)
        self.assertNotIn('Bug Bounty',text[rows[0].start:rows[0].end])

    def test_overview_index_source_conflict(self):
        text="Issues Found\nContracts contain no critical issues, no major issues, 1 minor issue and 2 informational notes.\nIssue #   Description   Severity   Status\n1   A finding title   Minor   Fixed\n2   Another finding title   Note   Fixed\nMinor Issues\n"
        summary=solidified.printed_counts(report(text,'solidified'))
        self.assertTrue(summary['ambiguous'])
        self.assertEqual(summary['counts']['info'],2)
        self.assertEqual(summary['issue_index_tally']['info'],1)


class Certora(unittest.TestCase):
    def test_punctuation_and_wrapped_titles(self):
        text="""Table of Contents
L-01 First title with a wrapped
line..................................................................................7
Project Summary
Detailed Findings
Low Severity Issues
L-01. First title with a wrapped
line

Severity: Low
Status: Fixed
Description: A sufficiently lengthy and detailed issue body.
Informational Severity Issues
I-01: Another informational title

Description: A sufficiently lengthy informational issue body.
"""
        rows=finish(report(text,'certora'),certora.parse(report(text,'certora')))
        self.assertEqual([c.printed_id for c in rows],['L-01','I-01'])
        self.assertEqual(rows[0].title,'First title with a wrapped line')
        self.assertEqual(rows[0].status_raw,'Fixed')

    def test_issue_card_and_critical_prefix_variants(self):
        text="Main Issues Discovered\nCrit-1. A critical issue title\nSeverity: Critical\nDescription: A sufficiently lengthy finding narrative.\n\nNote-2. A note with a long title\nSeverity: Informational\nDescription: A sufficiently lengthy finding narrative.\n"
        rows=finish(report(text,'certora'),certora.parse(report(text,'certora')))
        self.assertEqual([c.printed_id for c in rows],['Crit-1','Note-2'])
        self.assertEqual([c.normalized for c in rows],['critical','info'])

    def test_verification_references_are_not_findings(self):
        text="Detailed Findings\nLow Severity Issues\nL-01 A sufficiently lengthy issue title\nSeverity: Low\nDescription: A sufficiently lengthy finding narrative.\nFormal Verification\nL-01 Reference to a previously reported issue\nDescription: A verification rule explanation is not another finding.\n"
        rows=finish(report(text,'certora'),certora.parse(report(text,'certora')))
        self.assertEqual(len(rows),1)
        self.assertNotIn('Formal Verification',text[rows[0].start:rows[0].end])

    def test_bare_reference_id_cannot_backtrack_into_title(self):
        text="Detailed Findings\nInformational Severity Issues\nI-01 A sufficiently lengthy issue title\n\nA sufficiently lengthy finding narrative which cites another finding.\nI-06\nThis is a source reference without a title, not a finding.\n"
        rows=finish(report(text,'certora'),certora.parse(report(text,'certora')))
        self.assertEqual([c.printed_id for c in rows],['I-01'])

    def test_explicit_field_contradiction_is_preserved(self):
        text="Findings Summary\nSeverity   Discovered   Confirmed   Fixed\nCritical   1   1   1\nHigh   -   -   -\nLow   -   -   -\nDetailed Findings\nCritical Severity Issues\nC-01 A critical-coded detail title\nSeverity: High\nDescription: A sufficiently lengthy finding narrative.\n"
        rep=report(text,'certora');summary=certora.printed_counts(rep)
        self.assertFalse(summary.get('ambiguous',False))
        self.assertTrue(summary['severity_conflicts'])
        c=finish(rep,certora.parse(rep))[0]
        self.assertEqual(c.printed_id,'C-01')
        self.assertEqual(c.severity_raw,'High')
        self.assertEqual(c.normalized,'high')

    def test_wrapped_discovered_count(self):
        text="Findings Summary\nSeverity   Discovered   Confirmed   Fixed\nCritical   -   -   -\nHigh   -   -   -\nInformational                 1 full, 2 partial, 1\n                     4     4\nSeverity Matrix\nHigh 9\nMedium 9\n"
        s=certora.printed_counts(report(text,'certora'))
        self.assertEqual(s['counts'],{'critical':0,'high':0,'info':4})


class Pessimistic(unittest.TestCase):
    def test_gapped_ids_native_status_and_appendix(self):
        text="Manual analysis\nMedium severity issues\n\nM02. First sufficiently lengthy title (partially fixed, commented)\nA sufficiently lengthy finding body describing the actual issue.\n\nM05. Second sufficiently lengthy title (fixed)\nA sufficiently lengthy finding body describing the actual issue.\nAppendix A\nA01. Automated check\nThe automated check should not become another formal finding.\n"
        rows=finish(report(text,'pessimistic'),pessimistic.parse(report(text,'pessimistic')))
        self.assertEqual([c.printed_id for c in rows],['M02','M05'])
        self.assertEqual(rows[0].status_raw,'partially fixed, commented')
        self.assertNotIn('Appendix',text[rows[-1].start:rows[-1].end])

    def test_legacy_titles_toc_status_can_differ(self):
        text="Abstract ..................2\nCritical issues ..................5\n  New contract setup ..................5\nLow severity issues ..................6\n  Code quality ..................6\nAbstract\nCritical issues\n\nNew contract setup (fixed)\nA sufficiently lengthy finding body describing the actual issue.\nLow severity issues\n\nCode quality\nA sufficiently lengthy finding body describing the actual issue.\n"
        rows=finish(report(text,'pessimistic'),pessimistic.parse(report(text,'pessimistic')))
        self.assertEqual([c.title for c in rows],['New contract setup','Code quality'])
        self.assertEqual([c.normalized for c in rows],['critical','low'])

    def test_rust_manual_section_precedes_appendix(self):
        text="Manual analysis\nAppendix A: Check for unsafe Rust code.\nManual analysis\nM01. A sufficiently lengthy issue title (commented)\nA sufficiently lengthy finding body describing the actual issue.\nAppendix A\nA01. Not a finding\nThis must remain excluded from formal findings.\n"
        rows=finish(report(text,'pessimistic'),pessimistic.parse(report(text,'pessimistic')))
        self.assertEqual([c.printed_id for c in rows],['M01'])


if __name__=='__main__':
    unittest.main()
