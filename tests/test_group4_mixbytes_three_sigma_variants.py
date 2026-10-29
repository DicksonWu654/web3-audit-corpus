"""Phase 4e publisher era, exact status receipt, and independent-total regressions."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts/findings'))
from common import digest
from core import Report
from parsers import module
from parsers import mixbytes, three_sigma
from variants_report import sequence

D = '\nDescription\nThe publisher describes the affected path and its consequences in detail.\n'
FIXTURES = {
    'mixbytes_markdown': ('mixbytes', 'md', 'v2018_markdown_sections',
                         '## Detected Issues\n### [MAJOR]\n##### 1. Incomplete check' + D + '*Fixed in PR 12*\n', 1),
    'mixbytes_numbered': ('mixbytes', 'pdf', 'v2019_numbered_sections',
                         'DETECTED ISSUES\nMAJOR\n1. Incomplete check' + D + 'Acknowledged\n', 1),
    'mixbytes_stacked': ('mixbytes', 'pdf', 'v2020_stacked_cards',
                        '2.FINDINGS REPORT\nMJR-1 Incomplete check\nSeverity   Major\nStatus   No issue\n' + D, 1),
    'mixbytes_parallel': ('mixbytes', 'pdf', 'v2025_parallel_cards',
                         '2. Findings Report\nH-1 Incomplete check\nSeverity   High     Status   Fixed in ab1234\n' + D, 1),
    'mixbytes_parallel_clean': ('mixbytes', 'pdf', 'v2025_parallel_cards',
                               '1.6 Summary of Findings\nSeverity   Count\nCritical   0\nHigh   0\nMedium   0\nLow   0\n2. Findings Report\nNot Found\n', 0),
    'mixbytes_badge': ('mixbytes', 'pdf', 'v2026_badge_cards',
                      '[ 2 FINDINGS REPORT ]\nH-1   Incomplete check      HIGH\n     on withdrawal         PARTIALLY FIXED\n\nDESCRIPTION\nThe publisher describes the affected path and its consequences in detail.\n', 1),
    'three_sigma_severity_sections': ('three-sigma', 'pdf', 'v2022_severity_sections',
                                      '3S-CLIENT-01\nIncomplete check\n Id     3S-CLIENT-01\n Severity      Low\n Difficulty   Low\n' + D + '\nStatus\nFixed in commit abc123.\n', 1),
    'three_sigma_classification_sections': ('three-sigma', 'pdf', 'v2023_classification_sections',
                                            '3S-CLIENT-L01\nIncomplete check\n Id    3S-CLIENT-L01\n Classification    Low\n Severity    High\n' + D + '\nStatus\nAcknowledged by the team.\n', 1),
    'three_sigma_matrix_metadata': ('three-sigma', 'pdf', 'v2023_matrix_metadata',
                                    '3S-CLIENT-L01\nIncomplete check\n Id    3S-CLIENT-L01\n Classification    Low\n Severity    High\n Status    Addressed in #abc123.\n' + D, 1),
    'three_sigma_classification_metadata': ('three-sigma', 'pdf', 'v2023_classification_metadata',
                                            '3S-CLIENT-L01\nIncomplete check\n Id    3S-CLIENT-L01\n Classification    Low\n Status    Currently being reviewed by the team.\n' + D, 1),
    'three_sigma_dashboard': ('three-sigma', 'pdf', 'v2023_dashboard_only',
                              'Project Dashboard\nVulnerability Summary\nIssue Classification   Found   Addressed   Acknowledged\nCritical   0   0   0\nHigh   0   0   0\nMedium   0   0   0\nLow   0   0   0\nNone   0   0   0\n', 0),
    'three_sigma_fix_review': ('three-sigma', 'pdf', 'v2025_fix_review',
                               'Breakdown of PRs\nPR #4: Precision correction\nThe implementation replaces the earlier precision calculation.\nConclusion\nThe issue has been fully fixed across all PRs.\n', 1),
}


def report(text, firm, fmt='pdf', date=None):
    pages = []
    start = 0
    for number, text_page in enumerate(text.split('\f'), 1):
        pages.append(dict(page=number, start=start, end=start + len(text_page), text=text_page))
        start += len(text_page) + 1
    return Report(text, dict(pages=pages, file_format=fmt, text_sha256=digest(text.encode()), date_hint=date), firm)


class Group4MixBytesThreeSigmaVariants(unittest.TestCase):
    def test_each_declared_fixture_selects_and_parses_era(self):
        declared = set()
        for firm in ('mixbytes', 'three-sigma'):
            for variant in module(firm).VARIANTS:
                self.assertFalse(variant.fingerprint.legacy)
                self.assertIsNotNone(variant.status_parser)
                self.assertTrue(variant.fingerprint.date_range)
                for name in variant.fixtures:
                    declared.add(name)
                    with self.subTest(fixture=name):
                        owner, fmt, era, text, count = FIXTURES[name]
                        r = report(text, owner, fmt)
                        rows = module(owner).parse(r)
                        self.assertEqual(r.layout_selection['variant_id'], owner + '/' + era)
                        self.assertEqual(len(rows), count)
                        for c in rows:
                            self.assertLess(c.start, c.end)
                            if c.normalized_status:
                                evidence = c.evidence['status_evidence']
                                self.assertEqual(r.text[evidence['start']:evidence['end']], evidence['text'])
        self.assertEqual(declared, set(FIXTURES))

    def test_date_hint_alone_never_selects_layout(self):
        for firm in ('mixbytes', 'three-sigma'):
            r = report('An unfamiliar publisher format with no findings signatures.', firm, date='2026-01-01')
            module(firm).parse(r)
            self.assertTrue(r.layout_selection['unknown_layout'])

    def test_wrong_date_does_not_override_card_signatures(self):
        _, fmt, era, text, _ = FIXTURES['three_sigma_classification_metadata']
        r = report(text, 'three-sigma', fmt, '2022-01-01')
        rows = module(r.firm).parse(r)
        self.assertEqual(r.layout_selection['variant_id'], 'three-sigma/' + era)
        self.assertEqual(rows[0].normalized_status, 'open')

    def test_three_sigma_found_counts_ignore_methodology_matrix(self):
        text = ('Severity / Likelihood   Low    Medium    High\nNone   9   9   9\n'
                'Issue Classification   Found   Addressed   Acknowledged\n'
                'Critical   0   0   0\nHigh   0   0   0\nMedium   1   1   0\nLow   2   0   2\nNone   14   11   3\n')
        summary = three_sigma.printed_counts(report(text, 'three-sigma'))
        self.assertEqual(summary['counts'], dict(critical=0, high=0, medium=1, low=2, info=14))
        self.assertEqual(summary['basis'], 'three_sigma_dashboard_found_column')

    def test_classification_overrides_impact_without_inferring_from_id(self):
        _, fmt, _, text, _ = FIXTURES['three_sigma_matrix_metadata']
        rows = module('three-sigma').parse(report(text, 'three-sigma', fmt))
        self.assertEqual((rows[0].severity_raw, rows[0].normalized_status), ('Low', 'resolved'))

    def test_classification_era_can_contain_explicit_legacy_severity_card(self):
        _, fmt, _, text, _ = FIXTURES['three_sigma_classification_sections']
        text += ('3S-CLIENT-N01\nAdditional observation\n Id   3S-CLIENT-N01\n Severity   None\n'
                 + D + '\nStatus\nAcknowledged.\n')
        rows = module('three-sigma').parse(report(text, 'three-sigma', fmt))
        self.assertEqual([c.severity_raw for c in rows], ['Low', 'None'])
        self.assertEqual([c.normalized_status for c in rows], ['acknowledged', 'acknowledged'])

    def test_wrapped_three_sigma_status_keeps_source_span(self):
        text = ('3S-CLIENT-M01\nIncomplete check\n Id              3S-CLIENT-M01\n Classification  Medium\n'
                ' Status          Infinite shares addressed by disabling taxes.\n'
                '                 Zero shares is acknowledged.\n' + D)
        c = module('three-sigma').parse(report(text, 'three-sigma'))[0]
        self.assertEqual(c.normalized_status, 'partial')
        self.assertIn('Zero shares', c.status_raw)
        self.assertIn('\n', c.evidence['status_evidence']['text'])
        self.assertEqual(c.status_raw, c.evidence['status_evidence']['text'])

    def test_page_footer_after_status_is_skipped(self):
        text = ('3S-CLIENT-L01\nIncomplete check\n Id  3S-CLIENT-L01\n Classification   Low\n Severity   High\n'
                + D + '\nStatus\n42\n\f43\nAddressed in PR #123.\n')
        c = module('three-sigma').parse(report(text, 'three-sigma'))[0]
        self.assertEqual(c.status_raw, 'Addressed in PR #123.')
        self.assertEqual(c.normalized_status, 'resolved')

    def test_status_recommendation_cannot_supply_remediation(self):
        text = ('3S-CLIENT-L01\nIncomplete check\n Id  3S-CLIENT-L01\n Classification   Low\n Severity   High\n'
                + D + '\nRecommendation\nThis should be fixed in the next release.\n')
        c = module('three-sigma').parse(report(text, 'three-sigma'))[0]
        self.assertIsNone(c.status_raw)

    def test_fix_review_rows_are_supporting_remediation(self):
        _, fmt, _, text, _ = FIXTURES['three_sigma_fix_review']
        c = module('three-sigma').parse(report(text, 'three-sigma', fmt))[0]
        self.assertEqual((c.record_kind, c.finding_phase, c.normalized_status), ('remediation_review', 'fix_review', 'fixed'))

    def test_mixbytes_bold_number_and_explicit_proposals(self):
        text = ('### [COMMENTS]\n**1**. Incomplete check\n' + D + '*Acknowledged*\n'
                '**2.** Another check\n' + D + '\n### [PROPOSALS]\n##### 1. A design proposal\n' + D)
        rows = module('mixbytes').parse(report(text, 'mixbytes', 'md'))
        self.assertEqual([c.printed_id for c in rows], ['1', '2', '1'])
        self.assertEqual([c.record_kind for c in rows], ['formal_finding', 'formal_finding', 'recommendation'])

    def test_mixbytes_legacy_remediation_responses_keep_exact_quotes(self):
        text = ('### [COMMENTS]\n##### 1. A missing guard\n' + D +
                '*A check has been added in PR 138.*\n'
                '##### 2. An implementation issue\n' + D +
                'Реализовано в https://example.test/commit/abc123\n')
        r = report(text, 'mixbytes', 'md')
        cs = module(r.firm).parse(r)
        self.assertEqual([c.normalized_status for c in cs], ['fixed', 'fixed'])
        for c in cs:
            e=c.evidence['status_evidence']
            self.assertEqual(e['text'],r.text[e['start']:e['end']])
            self.assertEqual(e['raw'], e['text'])
            self.assertEqual(c.status_raw, e['raw'])

    def test_mixbytes_severity_parent_defines_independent_id_series(self):
        text = ('### [MAJOR]\n##### 1. Incomplete check\n' + D +
                '### [COMMENTS]\n##### 1. Other check\n' + D)
        cs = module('mixbytes').parse(report(text, 'mixbytes', 'md'))
        rows = [dict(record_kind=c.record_kind, publisher_finding_id=c.printed_id, evidence=c.evidence) for c in cs]
        self.assertTrue(sequence(rows, 'mixbytes')['complete'])

    def test_mixbytes_severe_scale_uses_global_printed_sequence(self):
        text = ('### [CRITICAL]\n##### 1. Incomplete check\n' + D +
                '### [SEVERE]\n##### 2. Other check\n' + D +
                '### [NOTES]\n##### 3. Documentation check\n' + D)
        cs = module('mixbytes').parse(report(text, 'mixbytes', 'md'))
        rows = [dict(record_kind=c.record_kind, publisher_finding_id=c.printed_id, evidence=c.evidence) for c in cs]
        self.assertTrue(sequence(rows, 'mixbytes')['complete'])

    def test_mixbytes_source_table_fills_absent_status(self):
        text = ('ID    Finding    Severity   Status\nH-1    Incomplete check   High   Fixed\n\f'
                '2. Findings Report\nH-1 Incomplete check\nSeverity   High\n' + D)
        c = module('mixbytes').parse(report(text, 'mixbytes'))[0]
        self.assertEqual(c.normalized_status, 'fixed')
        self.assertEqual(c.evidence['status_evidence']['basis'], 'id_status_table')

    def test_mixbytes_conflicting_status_table_stays_unknown(self):
        text = ('ID    Finding    Severity   Status\nH-1    Incomplete check   High   Fixed\nH-1    Incomplete check   High   Open\n\f'
                '2. Findings Report\nH-1 Incomplete check\nSeverity   High\n' + D)
        c = module('mixbytes').parse(report(text, 'mixbytes'))[0]
        self.assertIsNone(c.status_raw)
        self.assertTrue(c.evidence['status_conflict'])

    def test_negative_status_labels_do_not_match_fixed_substring(self):
        for raw, normalized in [('No issue', 'invalid'), ('Not fixed', 'open'), ('Partially fixed', 'partial'), ('*Fixed at PR 1*', 'fixed')]:
            self.assertEqual(mixbytes._state(raw), normalized)
        for raw, normalized in [('Not addressed', 'open'), ('Partially addressed', 'partial'), ('Acknowledged by the team.', 'acknowledged'), ('Acknowledged by the team, will be addressed at a later date.', 'acknowledged')]:
            self.assertEqual(three_sigma._state(raw), normalized)

    def test_holdout_is_denied_before_text_read(self):
        import group4_mixbytes_three_sigma as study
        with patch.object(study, 'holdouts', return_value={'a' * 64}), patch.object(Path, 'read_text') as read:
            with self.assertRaisesRegex(ValueError, 'Holdout'):
                study.load({'row': {'sha256': 'a' * 64}})
            read.assert_not_called()


if __name__ == '__main__':
    unittest.main()
