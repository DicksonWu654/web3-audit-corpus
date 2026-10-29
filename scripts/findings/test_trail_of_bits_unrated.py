"""Source-based narrative finding completeness and exact-span regressions."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest, holdouts
from core import Report, finish
from parsers import module
from trail_of_bits_unrated import PROFILES, parse

# Counts transcribed from the publisher's named body sections; Iron Fish's
# fix-review introduction independently confirms seven original issues.
EXPECTED = {
    'aaef2eb5188943c05ecacd3a6c7573e083c348d0e7d8cf78630a3f9e8cc24986': (4, None),
    '4281cc667cc5c6f2f61a67cd6a1a09ae6fa7f5f03efd14598643726f91d57987': (7, None),
    '29506d8eca78deea27605baf3bd31e7f548f70e60d5413ada551955ee2d95ea8': (4, ['1', '2', '3', '4']),
    '17dccbf464c72a4d92046086b3e8401b5393c9215799b434311000361ac6bb0f': (14, [str(n) for n in range(1, 15)]),
}


class NarrativeFindings(unittest.TestCase):
    @unittest.skipUnless((ROOT/'data/holdout/gold_sha256.txt').is_file(), 'Requires locally acquired corpus and holdout inputs')
    def test_all_reviewed_source_narratives_preserve_unrated_labels_and_exact_spans(self):
        blocked = holdouts(ROOT)
        for sha, (count, ids) in EXPECTED.items():
            with self.subTest(sha=sha):
                self.assertNotIn(sha, blocked)
                text = (ROOT / 'local-cache/fulltext' / (sha + '.txt')).read_bytes().decode()
                meta = json.loads((ROOT / 'local-cache/fulltext' / (sha + '.pages.json')).read_text())
                self.assertEqual(digest(text.encode()), meta['text_sha256'])
                report = Report(text, meta, 'trail-of-bits')
                candidates = finish(report, module('trail-of-bits').parse(report))
                self.assertEqual(len(candidates), count)
                if ids:
                    self.assertEqual([c.printed_id for c in candidates], ids)
                else:
                    self.assertTrue(all(c.printed_id is None for c in candidates))
                for c in candidates:
                    self.assertIsNone(c.severity_raw)
                    self.assertEqual(c.normalized, 'unknown')
                    self.assertEqual(c.record_kind, 'formal_finding')
                    proof = c.evidence['heading_span']
                    self.assertEqual(text[proof['start']:proof['end']], proof['text'])
                    self.assertGreater(c.end - c.start, len(proof['text']) + 40)
                    self.assertNotIn('Detailed Fix Review Results', text[c.start:c.end])
                if ids == ['1', '2', '3', '4']:
                    self.assertEqual([c.status_raw for c in candidates], ['Resolved'] * 3 + [None])
                    for c in candidates[:3]:
                        proof = c.evidence['status_evidence']
                        self.assertEqual(text[proof['start']:proof['end']], 'Resolved')

    def test_unknown_original_cannot_use_a_reviewed_profile(self):
        text = 'Summary of Findings\nForget-and-Forgive Issues in Resharing\nNarrative.'
        report = Report(text, {'sha256': 'a' * 64, 'file_format': 'pdf',
                              'pages': [{'page': 1, 'start': 0, 'end': len(text), 'text': text}]}, 'trail-of-bits')
        self.assertEqual(parse(report), [])

    def test_missing_reviewed_heading_fails_closed(self):
        sha = next(iter(PROFILES))
        text = 'Summary of Findings\nA changed or missing heading\nNarrative.'
        report = Report(text, {'sha256': sha, 'file_format': 'pdf',
                              'pages': [{'page': 1, 'start': 0, 'end': len(text), 'text': text}]}, 'trail-of-bits')
        with self.assertRaisesRegex(ValueError, 'heading missing'):
            parse(report)


if __name__ == '__main__':
    unittest.main()
