"""Status families, short publisher excerpts and synthetic layout regressions."""
from importlib import import_module
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest, holdouts
from core import Candidate, candidate_status, finish
from parsers import module
from status_families import GENERIC_FALLBACK
from status_resolve import status, status_mapping, status_policy
from test_framework import report


class GenericStatusTests(unittest.TestCase):
    def test_families_and_original_receipts(self):
        cases = {
            'Fixed in Version 5':'fixed', 'Resolved in commit abc123':'fixed',
            'will not be fixed':'acknowledged', "won't fix":'acknowledged',
            'not fixed':'unresolved', 'Addressed by client':'fixed',
            'not-fixed in Version 5':'unresolved', 'not_fixed in Version 5':'unresolved',
            'will-not-be-fixed in Version 5':'acknowledged',
            'partially_fixed in Version 5':'partially_fixed',
            'Partially addressed by client':'partially_fixed', 'Mitigated':'fixed',
            'PARTIALLY SOLVED':'partially_fixed', 'Fixed in PR #12':'fixed',
            'This finding has been addressed by the client in PR #67.':'fixed',
            'This issue has been confirmed by the team.':'acknowledged',
            'This issue has been confirmed and fixed in commit abc123.':'fixed',
            'This finding was partially addressed in PR #12.':'partially_fixed',
            'Not yet fixed in Version 5':'unresolved', 'Will be fixed in PR #12':'unresolved',
            'This issue is being addressed in PR #12.':'unresolved',
            '1. **Fixed** in PR #12':'fixed', 'Ｆｉｘｅｄ in Version 5':'fixed',
        }
        for firm in ('new-publisher', 'code4rena', 'halborn'):
            for raw, expected in cases.items():
                # Existing native labels retain their explicitly defined meaning.
                if raw in ('not fixed',) and firm != 'new-publisher':continue
                with self.subTest(firm=firm, raw=raw):
                    receipt=status_mapping(raw,firm,log=False)
                    self.assertEqual(receipt['normalized'],expected)
                    self.assertEqual(receipt['input'],raw)
                    self.assertEqual(receipt['raw'],raw)

    def test_recommendations_and_incidental_words_never_prove_fixes(self):
        for raw in ('This issue should be fixed by the client.',
                    'This issue can be fixed by upgrading the contract.',
                    'This issue could be partially fixed in PR #12.',
                    'Not partially fixed', 'not confirmed', 'unconfirmed',
                    'fixed values for updateInterval', 'resolved batch:',
                    'pending withdrawal request', 'Closed', 'Verified',
                    'Addressed and Partially Verified', 'unknown client response'):
            with self.subTest(raw=raw):
                self.assertEqual(status(raw,'new-publisher',log=False),'not_stated')

    def test_publisher_policy_and_ambiguous_eras_win(self):
        self.assertEqual(status('Not fixed','trail-of-bits'),'unresolved')
        self.assertEqual(status('Closed','iosiro'),'fixed')
        self.assertEqual(status('Info','abdk-consulting'),'acknowledged')
        receipt=status_mapping('Fixed in PR #12','sigma-prime',era='<ambiguous>',log=False)
        self.assertFalse(receipt['mapped'])
        self.assertEqual(receipt['normalized'],'not_stated')
        self.assertEqual(status('Fixed in PR #12','new-publisher'),'fixed')

    def test_build_and_runtime_policy_parity(self):
        self.assertEqual(status_policy()[0]['generic_fallback'],GENERIC_FALLBACK)
        for family in GENERIC_FALLBACK['rules']:
            for raw in family['corpus_examples']:
                with self.subTest(family=family['id'],raw=raw):
                    self.assertEqual(status(raw,'new-publisher',log=False),family['normalized'])


class StatusTextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases=json.loads((Path(__file__).parent/'fixtures/status2.json').read_text())

    def test_short_excerpts_and_synthetic_source_spans(self):
        for fixture in self.cases:
            with self.subTest(fixture=fixture['name']):
                if (ROOT/'data/holdout/gold_sha256.txt').is_file():
                    self.assertNotIn(fixture['sha256'],holdouts())
                self.assertEqual(digest(fixture['text'].encode()),fixture['text_sha256'])
                if fixture.get('synthetic'):
                    self.assertLess(len(fixture['text']), 2000)
                r=report(fixture['text'],fixture['publisher'],'md' if fixture['publisher']=='pashov-audit-group' else 'pdf')
                r.meta['sha256']=fixture['sha256']
                if fixture.get('reader'):
                    c=Candidate(0,fixture['title'],fixture['severity'],fixture['id'],end=len(r.text))
                    reader=getattr(import_module('parsers.'+fixture['publisher'].replace('-','_')),fixture['reader'])
                    reader(r,[c])
                    self.assertEqual(c.status_raw,fixture['expected_raw'])
                    self.assertEqual(candidate_status(r,c)['normalized'],fixture['expected_status'])
                    proof=c.evidence['status_evidence']
                    self.assertEqual(r.text[proof['start']:proof['end']],c.status_raw)
                else:
                    cs=finish(r,module(r.firm).parse(r))
                    by_id={c.printed_id:c for c in cs}
                    for pid,raw in fixture['expected_bindings'].items():
                        self.assertEqual(by_id[pid].status_raw,raw,(fixture['name'],pid))
                        proof=by_id[pid].evidence['status_evidence']
                        self.assertEqual(r.text[proof['start']:proof['end']],raw)

    def test_wrapped_index_alone_never_borrows_the_previous_title(self):
        from parsers import verichains
        fixture=next(f for f in self.cases if f['name']=='verichains_wrapped_index')
        r=report(fixture['text'],'verichains','pdf')
        cs=verichains.parse_status_index(r)
        for c in cs:
            # Exercise the native overview fallback using only the synthetic card's
            # pre-update portion as its body. The table must join the complete wrapped title.
            c.status_raw=None
            marker=r.text.find('UPDATES',c.start,c.end)
            if marker>=0:c.end=marker
        verichains.status_index(r,cs)
        by_id={c.printed_id:c for c in cs}
        self.assertEqual([by_id[pid].status_raw for pid in ('2.2.8','2.2.9','2.2.10')],
                         ['ACKNOWLEDGED','ACKNOWLEDGED','FIXED'])


if __name__ == '__main__':
    unittest.main()
