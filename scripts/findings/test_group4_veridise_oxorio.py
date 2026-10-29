"""Publisher-local layout and status regressions, using synthetic source snippets."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import digest
from core import Report, Candidate, finish
from parsers import module

FIXTURES = json.loads((Path(__file__).parent / 'fixtures/group4_veridise_oxorio.json').read_text())


def report(fixture):
    text = fixture['text']
    return Report(text, {'file_format': fixture.get('format', 'pdf'), 'date_hint': '2026-01-01',
                        'text_sha256': digest(text.encode()),
                        'pages': [{'page': 1, 'start': 0, 'end': len(text), 'text': text}]}, fixture['firm'])


class Group4VeridiseOxorioTests(unittest.TestCase):
    def test_every_declared_fixture(self):
        seen = set()
        for firm in ('veridise', 'oxorio'):
            parser = module(firm)
            for variant in parser.VARIANTS:
                self.assertFalse(variant.fingerprint.legacy)
                self.assertIsNotNone(variant.status_parser)
                for name in variant.fixtures:
                    seen.add(name)
                    with self.subTest(fixture=name):
                        fixture = FIXTURES[name]
                        r = report(fixture)
                        cs = parser.parse(r)
                        self.assertEqual(r.layout_selection['variant_id'], firm+'/'+fixture['variant'])
                        self.assertEqual([c.printed_id for c in cs], fixture['ids'])
                        self.assertEqual([c.normalized_status for c in cs], fixture['statuses'])
                        for c in cs:
                            self.assertLess(c.start, c.end)
                            if c.status_raw:
                                proof = c.evidence['status_evidence']
                                self.assertEqual(r.text[proof['start']:proof['end']], c.status_raw)
        self.assertEqual(seen, set(FIXTURES))

    def test_short_card_cannot_inherit_the_next_status(self):
        fixture = dict(FIXTURES['veridise_blank_status'])
        fixture['text'] += FIXTURES['veridise_named_card']['text'].replace('001', '002')
        cs = module('veridise').parse(report(fixture))
        self.assertEqual([c.normalized_status for c in cs], [None, 'acknowledged'])

    def test_oxorio_recommendation_does_not_set_status(self):
        fixture = dict(FIXTURES['oxorio_native'])
        fixture['text'] = fixture['text'].replace('Status • NO_ISSUE\n', '') + '\nRecommendation This should be FIXED.\n'
        cs = module('oxorio').parse(report(fixture))
        self.assertIsNone(cs[0].status_raw)

    def test_confirmed_commit_can_fill_an_empty_status(self):
        fixture = dict(FIXTURES['veridise_fix_commit'])
        fixture['text'] = fixture['text'].replace('Status Fixed', 'Status')
        cs = module('veridise').parse(report(fixture))
        self.assertEqual(cs[0].normalized_status, 'fixed')
        self.assertEqual(cs[0].evidence['status_evidence']['basis'], 'confirmed_fix_commit')

    def test_status_example_in_description_is_not_a_card_field(self):
        fixture = dict(FIXTURES['oxorio_native'])
        fixture['text'] = fixture['text'].replace('Status • NO_ISSUE\n', '') + '\nStatus FIXED\nThis is an example inside the description.\n'
        self.assertIsNone(module('oxorio').parse(report(fixture))[0].status_raw)
        fixture = dict(FIXTURES['veridise_blank_status'])
        fixture['text'] = fixture['text'].replace('Description The card', '\nThe card')
        fixture['text'] = fixture['text'].replace('Recommendation This should be fixed.', 'Status Fixed\nThis is example input, not a metadata field.')
        self.assertIsNone(module('veridise').parse(report(fixture))[0].status_raw)

    def test_unfamiliar_layout_stays_unknown(self):
        for firm in ('veridise', 'oxorio'):
            r = report({'firm': firm, 'text': 'This document contains no known finding layout.'})
            module(firm).parse(r)
            self.assertTrue(r.layout_selection['unknown_layout'])

    def test_short_native_detail_exception_is_explicit_and_bounded(self):
        r = report({'firm': 'abdk-consulting', 'text': '1. The value should be constant.\n'})
        candidate = Candidate(0, 'The value should be constant.', end=len(r.text))
        self.assertEqual(finish(r, [candidate]), [])
        candidate.evidence['publisher_explicit_short_detail'] = True
        self.assertEqual(finish(r, [candidate]), [candidate])
        candidate.end = None
        self.assertEqual(finish(r, [candidate]), [])


if __name__ == '__main__':
    unittest.main()
