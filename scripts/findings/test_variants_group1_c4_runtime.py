"""Synthetic source-layout/status fixtures for C4 and Runtime Verification."""
import unittest
from core import Report, finish
from common import digest
from parsers import module
from variants_report import sequence

D = '\nDescription\nAn actual issue with source evidence and enough detail to establish a finding.\n' * 3
FIXTURES = {
    'c4_pdf': ('code4rena', 'pdf', 'v2021_pdf', 'Findings & Analysis Report\nSeverity Criteria\n\f[H-01] Actual issue\n'+D, 1),
    'c4_linked': ('code4rena', 'md', 'v2021_linked_markdown', '# Overview\n# High Risk Findings (1)\n## [[H-01] Actual issue](https://example.org/1)\n'+D, 1),
    'c4_linked_index': ('code4rena', 'md', 'v2021_linked_summary_sections', '# Overview\n# Low Risk Findings (1)\n\n- [[L-01] Actual issue](https://example.org/1)\n', 1),
    'c4_web': ('code4rena', 'html', 'v2021_web_sections', '# Overview\n# High Risk Findings (1)\n## [H-01] Actual issue\n'+D, 1),
    'c4_plain': ('code4rena', 'md', 'v2021_plain_markdown', '# High Risk Findings (1)\n## [H-01] Actual issue\n'+D, 1),
    'c4_anchored': ('code4rena', 'md', 'v2024_anchored_markdown', '# [](#high-risk-findings)High Risk Findings (1)\n## [](#issue)[H-01] Actual issue\n'+D, 1),
    'c4_verification': ('code4rena', 'html', 'v2023_formal_verification', '# Formal Verification Report\n# Medium Risk Findings (1)\n## [F-01] Actual verification issue\n'+D, 1),
    'rv_brackets': ('runtime-verification', 'pdf', 'v2024_bracket_cards', '[A1] Actual issue\nSeverity: High\n'+D, 1),
    'rv_letters': ('runtime-verification', 'pdf', 'v2021_letter_cards', 'Findings\nA01: Actual issue\nSeverity: High\n'+D, 1),
    'rv_risk': ('runtime-verification', 'pdf', 'v2022_risk_cards', '1. Actual issue\n[ Severity: High | Difficulty: Low ]\n'+D, 1),
    'rv_index': ('runtime-verification', 'pdf', 'v2019_indexed_findings', 'List of Findings\nHigh\n  1. An actual issue\n\fAn actual issue\n\n'+D, 1),
    'rv_minor': ('runtime-verification', 'pdf', 'v2019_indexed_findings', 'Contents\nUse safer arithmetic\n\fMinor Findings\nUse safer arithmetic\n\n'+D, 1),
    'rv_tracker': ('runtime-verification', 'pdf', 'v2022_tracker', 'Issue                Category    Status\n#45  Actual issue    Bug         Addressed by client\n', 1),
    'rv_design': ('runtime-verification', 'pdf', 'v2021_design_review', 'Design Review\nNone of these points represented a design flaw or a security vulnerability\n1. Actual recommendation\n'+D, 1),
    'rv_proof': ('runtime-verification', 'pdf', 'v2018_verification_papers', 'Formal Verification Report\nAbstract. We prove the safety theorem of this protocol.\n'+D, 0),
    'rv_specification': ('runtime-verification', 'md', 'v2022_specification_attachments', 'module tinyman\nassert Safety { all_transactions_for[OpTransfer] }\n'+D, 0),
    'rv_milestone': ('runtime-verification', 'pdf', 'v2026_verification_milestones', 'ZK Rust Verification with Hax\nMilestone 1: Field Arithmetic\n'+D, 0),
    'rv_narrative': ('runtime-verification', 'pdf', 'v2022_narrative_reviews', 'Security Review Report\nSuggestions and Issues\n'+D, 0),
    'rv_named': ('runtime-verification', 'pdf', 'v2021_named_sections', 'Contents\nInitialization (Race Condition) . . . . . . 4\n'
                 'A minor observation . . . . . . 5\n\fFindings\nInitialization (Race Condition)\n'+D+
                 '\nInformative Findings\nA minor observation\n'+D+'\nOptimization\n', 2),
}


def report(text, firm, fmt='md', date=None):
    pages=[]; start=0
    for n, page in enumerate(text.split('\f'), 1):
        pages.append(dict(page=n, start=start, end=start+len(page), text=page))
        start += len(page)+1
    return Report(text, dict(pages=pages, text_sha256=digest(text.encode()), file_format=fmt, date_hint=date), firm)


class LayoutTests(unittest.TestCase):
    def test_every_variant_fixture_selects_its_parser(self):
        declared = set()
        for firm in ('code4rena', 'runtime-verification'):
            for v in module(firm).VARIANTS:
                self.assertFalse(v.fingerprint.legacy)
                self.assertIsNotNone(v.status_parser)
                for name in v.fixtures:
                    declared.add(name)
                    with self.subTest(fixture=name):
                        firm, fmt, era, text, count = FIXTURES[name]
                        r=report(text, firm, fmt); cs=module(firm).parse(r)
                        self.assertEqual(r.layout_selection['variant_id'], firm+'/'+era)
                        self.assertEqual(len(cs), count)
                        for c in cs: self.assertTrue(0 <= c.start < c.end <= len(text))
        self.assertEqual(declared, set(FIXTURES))

    def test_date_alone_does_not_recognize_a_layout(self):
        for firm in ('code4rena', 'runtime-verification'):
            r=report('Unfamiliar publisher content.', firm, date='2024-06-01')
            self.assertEqual(module(firm).parse(r), [])
            self.assertTrue(r.layout_selection['unknown_layout'])

    def test_c4_status_is_exact_source_label(self):
        _, fmt, _, text, _=FIXTURES['c4_linked']
        r=report(text+'\n**Status:** Mitigation confirmed. Full report linked.\n', 'code4rena', fmt)
        c=module(r.firm).parse(r)[0]
        self.assertEqual((c.status_raw, c.normalized_status), ('Mitigation confirmed', 'resolved'))
        proof=c.evidence['status_evidence']
        self.assertEqual(r.text[proof['start']:proof['end']], proof['raw'])

    def test_c4_fix_review_table_joins_on_original_id(self):
        _, fmt, _, text, _=FIXTURES['c4_linked']
        r=report(text+'\n# Mitigation Review\n| H-01 | Mitigation confirmed |\n', 'code4rena', fmt)
        c=module(r.firm).parse(r)[0]
        self.assertEqual(c.normalized_status, 'resolved')
        self.assertEqual(c.evidence['status_evidence']['basis'], 'mitigation_review_id_table')

    def test_recommendation_never_establishes_fixed_status(self):
        for name in ('c4_plain', 'rv_brackets'):
            firm, fmt, _, text, _=FIXTURES[name]
            c=module(firm).parse(report(text+'\nRecommendation: this should be fixed.\n', firm, fmt))[0]
            self.assertIsNone(c.status_raw)

    def test_code_example_status_stays_rejected_after_runner_finalizes_again(self):
        for name in ('c4_plain', 'rv_brackets'):
            firm, _, _, text, _=FIXTURES[name]
            r=report(text+'\n```text\nStatus: Fixed\n```\n', firm, 'md')
            c=finish(r, module(firm).parse(r))[0]
            self.assertIsNone(c.status_raw)

    def test_runtime_final_status_beats_the_summary_badge(self):
        _, fmt, _, text, _=FIXTURES['rv_brackets']
        r=report(text.replace('Severity: High', 'Severity: High    Addressed by client')+'\nStatus\nNot addressed by client.\n', 'runtime-verification', fmt)
        c=module(r.firm).parse(r)[0]
        self.assertEqual((c.status_raw, c.normalized_status), ('Not addressed by client.', 'open'))
        proof=c.evidence['status_evidence']
        self.assertEqual(r.text[proof['start']:proof['end']], proof['raw'])

    def test_runtime_status_does_not_search_an_arbitrary_paragraph(self):
        _, fmt, _, text, _=FIXTURES['rv_brackets']
        c=module('runtime-verification').parse(report(text+'\nThis code was fixed during development.\n', 'runtime-verification', fmt))[0]
        self.assertIsNone(c.status_raw)

    def test_runtime_named_resolution_response_carries_exact_evidence(self):
        firm,fmt,_,text,_=FIXTURES['rv_named']
        text=text.replace('\nInformative Findings', '\nResponse: The client fixed this issue.\n\nInformative Findings')
        r=report(text,firm,fmt); c=module(firm).parse(r)[0]
        self.assertEqual(c.normalized_status,'fixed')
        proof=c.evidence['status_evidence']
        self.assertEqual(r.text[proof['start']:proof['end']],proof['raw'])


if __name__ == '__main__':
    unittest.main()
