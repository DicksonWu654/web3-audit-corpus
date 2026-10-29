"""Owned Phase 4e fixtures: layout selection, exact status receipts, and negatives."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import digest
from core import Report
from parsers import module

D = '\nDescription\nThe source describes the affected path, its impact and reproducible conditions.\n' * 3
FIXTURES = {
    'chainlight_issue': ('chainlight', 'Issue #1: Unsafe transfer\nSummary    Severity\nExplicit impact    High\n' + D + '\nFix\nFixed in commit abc123.\n', 'v2021_issue_cards', 1),
    'chainlight_issue_missing_glyphs': ('chainlight', 'Contents\nIssue #1: Unsafe transfer .....................10\n\f_calcNewRewardLane\nregisteredPoints\n', 'generic_fallback', 0),
    'chainlight_numbered': ('chainlight', '#1 THE-TST-001 Unsafe transfer\nID    Summary    Severity\nTHE-TST-001    Explicit impact    High\n' + D + '\nRemediation\n\n© 2025 ChainLight, Theori. All rights reserved | 9\n\fPatched\nThe issue has been patched.\n', 'v2023_numbered_cards', 1),
    'chainlight_numbered_zero': ('chainlight', 'Severity Categories\nStatus Categories\nFinding Breakdown by Severity\nCritical 0\nHigh 0\nMedium 0\nLow 0\nInformational 0\n', 'v2023_numbered_cards', 0),
    'chainlight_bilingual': ('chainlight', '\u202d4.2.1. WORLDCOIN-ORB-001: Unsafe transfer\u202c\n\u202dID Code\u202c WORLDCOIN-ORB-001    Severity    Low\nType\n' + D, 'v2025_bilingual_orb', 1),
    'neodyme_peer': ('neodyme', 'Low: Unsafe transfer\n' + D + '\nResolution\nThe client acknowledged the finding and added a check.\n', 'v2021_peer_titles', 1),
    'neodyme_peer_zero': ('neodyme', 'Peer review result: Overview\nThe audit team reported a total of 0 findings, of which\n• 0 were critical,\n• 0 were high,\n• 0 were medium,\n• 0 were low,\n• 0 were informational.\n', 'v2021_peer_titles', 0),
    'neodyme_peer_coded': ('neodyme', 'Informational I01 - Unsafe transfer\n\n' + D, 'v2021_peer_titles', 1),
    'neodyme_unnumbered': ('neodyme', 'Unsafe transfer\n\nSeverity   Impact   Affected Component   Status\nHigh   Loss of funds   Transfer   Resolved\n' + D, 'v2021_unnumbered_tables', 1),
    'neodyme_suffix': ('neodyme', 'Unsafe transfer (Critical; Resolved)\n\n' + D, 'v2021_unnumbered_tables', 1),
    'neodyme_short': ('neodyme', 'C01: Unsafe transfer wrapped\ntitle [resolved]\n\nSeverity   Impact   Affected Component\nCritical   Loss of funds   Transfer\n' + D, 'v2023_short_ids', 1),
    'neodyme_compact': ('neodyme', 'ND-TST-H1 – Unsafe transfer\n\nSeverity   Impact   Affected Component   Status\nHigh   Loss of funds   Transfer   Accepted\n' + D, 'v2023_nd_compact', 1),
    'neodyme_compact_zero': ('neodyme', '1 | Introduction\nSummary of Findings\nNo issues were found.\n', 'v2023_nd_compact', 0),
    'neodyme_expanded': ('neodyme', '[ND-TST-HI-01] Unsafe transfer\n\nSeverity   Impact   Affected Component   Status\nHIGH   Loss of funds   Transfer   Fixed\n' + D, 'v2024_nd_expanded', 1),
    'neodyme_expanded_zero': ('neodyme', '1 Executive Summary\nNo issues were found.\nFigure 1: Overview of Findings\n', 'v2024_nd_expanded', 0),
}


def report(text, firm, date=None):
    # Early peer reviews start their detailed section on physical page four.
    text = '\f\f\f' + text
    pages = []
    offset = 0
    for i, p in enumerate(text.split('\f'), 1):
        pages.append(dict(page=i, start=offset, end=offset + len(p), text=p))
        offset += len(p) + 1
    return Report(text, dict(file_format='pdf', pages=pages,
                            text_sha256=digest(text.encode()), date_hint=date), firm)


class OwnedVariants(unittest.TestCase):
    def test_declared_fixtures_select_and_parse(self):
        declared = set()
        for firm in ('chainlight', 'neodyme'):
            for v in module(firm).VARIANTS:
                self.assertFalse(v.fingerprint.legacy)
                self.assertTrue(v.fingerprint.date_range)
                self.assertIsNotNone(v.status_parser)
                for name in v.fixtures:
                    declared.add(name)
                    f, text, era, count = FIXTURES[name]
                    with self.subTest(name=name):
                        r = report(text, f)
                        cs = module(f).parse(r)
                        self.assertEqual(r.layout_selection['variant_id'], f + '/' + era)
                        self.assertEqual(len(cs), count)
                        for c in cs:
                            self.assertTrue(0 <= c.start < c.end <= len(r.text))
                            if c.status_raw:
                                p = c.evidence['status_evidence']
                                self.assertEqual(r.text[p['start']:p['end']], p['text'])
                                self.assertEqual(c.status_raw, p['text'])
        self.assertEqual(declared, set(FIXTURES))

    def test_chainlight_cross_page_remediation_is_authoritative(self):
        _, text, _, _ = FIXTURES['chainlight_numbered']
        r = report('ID   Title   Severity   Status\nTHE-TST-001   Unsafe transfer   High   Reported\n\f' + text, 'chainlight')
        c = module(r.firm).parse(r)[0]
        self.assertEqual(c.status_raw, 'Patched')
        self.assertEqual(c.normalized_status, 'fixed')
        self.assertEqual(c.evidence['status_evidence']['basis'], 'remediation_status_badge')

    def test_chainlight_wrapped_status_index(self):
        _, text, _, _ = FIXTURES['chainlight_numbered']
        text = text.split('\nRemediation')[0]
        r = report('ID   Title   Severity   Status\nTHE-TST-001\n Unsafe transfer    High    Mitigated\n\f' + text, 'chainlight')
        c = module(r.firm).parse(r)[0]
        self.assertEqual(c.status_raw, 'Mitigated')
        self.assertEqual(c.normalized_status, 'resolved')
        self.assertEqual(c.evidence['status_evidence']['basis'], 'printed_id_status_table')

    def test_conflicting_index_is_not_a_fix(self):
        _, text, _, _ = FIXTURES['chainlight_numbered']
        text = text.split('\nRemediation')[0]
        r = report('ID   Title   Severity   Status\nTHE-TST-001   Issue    High    Fixed\nTHE-TST-001   Issue    High    Reported\n\f' + text, 'chainlight')
        c = module(r.firm).parse(r)[0]
        self.assertIsNone(c.status_raw)
        self.assertTrue(c.evidence['status_conflict'])

    def test_recommendation_future_tense_does_not_create_status(self):
        for firm, name in [('chainlight', 'chainlight_issue'), ('neodyme', 'neodyme_peer')]:
            _, text, _, _ = FIXTURES[name]
            text = text.split('\nFix\n')[0].split('\nResolution\n')[0]
            r = report(text + '\nRecommendation\nThis should be fixed.\n\nResolution\nThis will be fixed later.\n', firm)
            self.assertIsNone(module(firm).parse(r)[0].status_raw)

    def test_title_status_and_accepted_metadata_are_retained(self):
        for name, raw, normalized in [('neodyme_short', 'resolved', 'resolved'), ('neodyme_compact', 'Accepted', 'acknowledged')]:
            f, text, _, _ = FIXTURES[name]
            c = module(f).parse(report(text, f))[0]
            self.assertEqual((c.status_raw, c.normalized_status), (raw, normalized))

    def test_severity_is_not_title_status(self):
        r = report('Unsafe transfer (Critical)\n\nSeverity   Impact   Affected Component\nCritical   Loss of funds   Transfer\n' + D, 'neodyme')
        self.assertIsNone(module(r.firm).parse(r)[0].status_raw)

    def test_date_cannot_outvote_native_id(self):
        f, text, era, _ = FIXTURES['neodyme_expanded']
        r = report(text, f, '2021-01-01')
        module(f).parse(r)
        self.assertEqual(r.layout_selection['variant_id'], f + '/' + era)

    def test_resolution_cannot_leak_to_previous_finding(self):
        text = 'Low: First issue\n' + D + '\nInformational: Second issue\n' + D + '\nResolution\nThe client acknowledged the second issue.\n'
        cs = module('neodyme').parse(report(text, 'neodyme'))
        self.assertEqual([c.status_raw for c in cs], [None, 'acknowledged'])

    def test_chainlight_fix_commit_and_incomplete_followup(self):
        _, text, _, _ = FIXTURES['chainlight_issue']
        text = text.split('\nFix\n')[0]
        for response, expected in [
            ('Replace the unsafe operation (commit a1b2c3d4).', 'fixed'),
            ('Replace the unsafe operation (commit a1b2c3d4).\n\nThe fix was incomplete.', 'partial'),
            ('The team proposed replacing the operation (commit a1b2c3d4).', None),
        ]:
            r = report(text + '\nFix\n' + response + '\n', 'chainlight')
            c = module(r.firm).parse(r)[0]
            self.assertEqual(c.normalized_status, expected)
            if expected:
                proof = c.evidence['status_evidence']
                self.assertEqual(r.text[proof['start']:proof['end']], proof['text'])

    def test_neodyme_extended_native_labels(self):
        _, text, _, _ = FIXTURES['neodyme_expanded']
        for raw, expected in [('WIP', 'open'), ('Fixed before report', 'fixed')]:
            c = module('neodyme').parse(report(text.replace('Transfer   Fixed', 'Transfer   ' + raw), 'neodyme'))[0]
            self.assertEqual((c.status_raw, c.normalized_status), (raw, expected))

    def test_neodyme_peer_wrapped_title(self):
        r = report('Medium: A long issue wraps onto the next\nline\n\nDescription\n' + D, 'neodyme')
        cs = module(r.firm).parse(r)
        self.assertEqual([c.title for c in cs], ['A long issue wraps onto the next line'])

    def test_printed_summary_conflict_is_independent_of_parsed_rows(self):
        text = ('Peer review result: Overview\nThe audit team reported a total of ten findings, of which\n'
                '• 1 were critical,\n• 1 were high,\n• 5 were medium,\n• 0 were low,\n• 4 were informational.\n')
        r = report(text, 'neodyme')
        module(r.firm).parse(r)
        summary = module(r.firm).printed_counts(r)
        self.assertTrue(summary['ambiguous'])
        self.assertEqual(summary['summary_conflict']['declared_total'], 10)
        self.assertEqual(summary['counts']['medium'], 5)
        clean_report = report(text.replace('ten findings', 'eleven findings'), 'neodyme')
        module(clean_report.firm).parse(clean_report)
        self.assertNotIn('ambiguous', module(clean_report.firm).printed_counts(clean_report))


if __name__ == '__main__':
    unittest.main()
