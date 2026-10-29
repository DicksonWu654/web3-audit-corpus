"""C4 regression tests for independently printed evidence and report eras."""
import unittest
from core import finish
from parsers import code4rena
from test_framework import report

BODY = '\nActual published description and mitigation evidence.\n' * 3


class Code4renaTests(unittest.TestCase):
    def test_anchor_prefix_and_unicode_noncritical_id(self):
        r=report('# [](#low-risk-and-non-critical-issues)Low Risk and Non-Critical Issues\n'
                 '## [](#n-01-title)[N‑01] Complete title\n'+BODY)
        c=finish(r,code4rena.parse(r))[0]
        self.assertEqual((c.printed_id,c.title,c.normalized),('N‑01','Complete title','info'))
        self.assertEqual(r.text[c.start:c.end],r.text[r.text.index('## []'):])

    def test_mitigation_round_cannot_inflate_initial_summary(self):
        r=report('# Medium Risk Findings (1)\n## [M-01] Initial finding\n'+BODY+
                 '# Mitigation Review\n## [M-01] Unmitigated\n'+BODY+'# Disclosures\nLegal text')
        cs=finish(r,code4rena.parse(r))
        self.assertEqual([c.record_kind for c in cs],['formal_finding'])
        self.assertNotIn('Mitigation Review',r.text[cs[0].start:cs[0].end])
        self.assertEqual(code4rena.printed_counts(r)['counts'],{'medium':1})

    def test_component_totals_add_without_reading_detail_ids(self):
        r=report('# Component A\n# High Risk Findings (2)\n# Medium Risk Findings (3)\n'
                 '# Component B\n# High Risk Findings (4)\n# Medium Risk Findings (5)\n')
        self.assertEqual(code4rena.printed_counts(r)['counts'],{'high':6,'medium':8})
        self.assertEqual(code4rena.parse(r),[])

    def test_legacy_link_only_entries_are_excerpts(self):
        r=report('# Low Risk Findings (2)\n'
                 '- [[L-01] Actual published linked issue title](https://example.org/issues/1)\n'
                 '- [[L-02] Another published linked issue title](https://example.org/issues/2)\n')
        cs=finish(r,code4rena.parse(r))
        self.assertEqual([c.record_kind for c in cs],['summary_excerpt','summary_excerpt'])
        self.assertEqual(cs[0].title,'Actual published linked issue title')

    def test_html_backtick_text_cannot_hide_later_headings(self):
        r=report('# Medium Risk Findings (2)\n## [M-01] First finding\n'+BODY+
                 '```unmatched literal\n# output log:\n## [M-02] Second finding\n'+BODY,fmt='html')
        self.assertEqual([c.printed_id for c in code4rena.parse(r)],['M-01','M-02'])

    def test_bare_native_id_keeps_missing_title(self):
        r=report('# Medium Risk Findings (1)\n## [M-01]\n'+BODY)
        cs=finish(r,code4rena.parse(r))
        self.assertEqual(len(cs),1)
        self.assertIsNone(cs[0].title)

    def test_f_submission_id_inherits_printed_section_severity(self):
        r=report('# Medium Risk Findings (2)\n## [F-50] First issue\n'+BODY+
                 '## [F-118] Second issue\n'+BODY)
        cs=finish(r,code4rena.parse(r))
        self.assertEqual([(c.printed_id,c.normalized) for c in cs],[('F-50','medium'),('F-118','medium')])

    def test_pdf_toc_page_numbers_are_not_severity_totals(self):
        r=report('Contents\nHigh Severity       9\nMedium Severity     11\nLow Severity  14\n\f'
                 'Summary\n1 received a risk rating of HIGH severity, 5 received a risk rating of\n'
                 'MEDIUM severity, and 12 received a risk rating of LOW severity.\n',fmt='pdf')
        self.assertEqual(code4rena.printed_counts(r)['counts'],{'high':1,'medium':5,'low':12})

    def test_markdown_fenced_example_is_ignored(self):
        r=report('```md\n## [H-99] Example\n'+BODY+'```\n## [H-01] Actual finding\n'+BODY)
        self.assertEqual([c.printed_id for c in code4rena.parse(r)],['H-01'])

    def test_uncoded_mixed_qa_keeps_unprinted_grade_and_uses_platform_bucket(self):
        r=report('# Low Risk and Non-Critical Issues\n## Actual title without printed ID\n'
                 '### Impact\n'+BODY+'## [01] Numbered source title\n'+BODY)
        cs=finish(r,code4rena.parse(r))
        self.assertEqual(len(cs),2)
        self.assertEqual([c.normalized for c in cs],['low','low'])
        self.assertEqual([c.printed_id for c in cs],[None,'01'])

    def test_inline_triple_backticks_do_not_hide_later_findings(self):
        r=report('# Medium Risk Findings (2)\n## [M-01] First issue\n'+BODY+
                 '```require(token != 0);```\n## [M-02] Second issue\n'+BODY)
        self.assertEqual([c.printed_id for c in code4rena.parse(r)],['M-01','M-02'])

    def test_numbered_gas_entries_have_distinct_source_namespace(self):
        r=report('# Low Risk and Non-Critical Issues\n## [01] Ungraded issue\n'+BODY+
                 '# Gas Optimizations\n## [01] Gas issue\n'+BODY)
        cs=finish(r,code4rena.parse(r))
        self.assertEqual([c.normalized for c in cs],['low','gas'])
        self.assertTrue(code4rena.sequence_diagnostics(r,cs)['complete'])

    def test_malformed_fence_recovery_requires_same_official_issue_base(self):
        r=report('## [[H-01] First issue](https://github.com/code-423n4/example-findings/issues/1)\n'+BODY+
                 '```solidity\nuint value = 1;\n'
                 '## [[H-02] Second issue](https://github.com/code-423n4/example-findings/issues/2)\n'+BODY+
                 '## [[H-03] Example from another report](https://github.com/code-423n4/other-findings/issues/3)\n'+BODY+'```\n')
        cs=code4rena.parse(r)
        self.assertEqual([c.printed_id for c in cs],['H-01','H-02'])
        self.assertTrue(cs[1].evidence['malformed_fence_recovery'])

    def test_legacy_markdown_numeric_summary_prose_is_comparable(self):
        r=report('# Summary\n2 received a risk rating in the category of HIGH severity, '
                 '3 received a risk rating of MEDIUM severity.\n# Scope\nDocumentation.\n')
        self.assertEqual(code4rena.printed_counts(r)['counts'],{'high':2,'medium':3})
        self.assertEqual(code4rena.parse(r),[])

    def test_printed_prose_section_conflict_is_independently_ambiguous(self):
        r=report('# Summary\n2 received a risk rating of HIGH severity.\n# Scope\nCode.\n'
                 '# High Risk Findings (3)\n')
        counts=code4rena.printed_counts(r)
        self.assertTrue(counts['ambiguous'])
        self.assertEqual(counts['counts'],{'high':3})
        self.assertEqual(counts['alternatives'][0]['counts'],{'high':2})


if __name__=='__main__':
    unittest.main()
