"""Real public Halborn HTML regressions; gold hashes are denied before reads."""
import hashlib
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from common import ROOT,holdouts,original_path
from core import Report
from extract import HTMLText
from halborn_website import extract, applies
from parsers import module


def real_report(source):
    assert source['sha256'] not in holdouts(ROOT)
    data=original_path(source,ROOT).read_bytes()
    assert hashlib.sha256(data).hexdigest()==source['sha256']
    html=data.decode();reader=HTMLText();reader.feed(html)
    supplement,native=extract(html);text=reader.text()+supplement
    return Report(text,{'file_format':'html','pages':[{'page':1,'start':0,'end':len(text),'text':text}],
                       'text_sha256':hashlib.sha256(text.encode()).hexdigest(),'halborn_website':native},'halborn')


@unittest.skipUnless((ROOT/'data/collect/halborn/reports.jsonl').is_file() and (ROOT/'data/holdout/gold_sha256.txt').is_file(), 'Requires locally acquired corpus and holdout inputs')
class HalbornWebsiteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p=ROOT/'data/collect/halborn/reports.jsonl'
        cls.sources={r['sha256']:r for r in map(json.loads,p.read_text().splitlines()) if applies(r)}
        cls.parser=module('halborn')

    def test_real_cvss_and_matrix_labels_ignore_unused_bvss_default(self):
        # Public on-page counts are independent of the serialized detail cards.
        for sha,expected in (
            ('963a76534a1d5a966cb5774be97e12407d081204d2af767d06ca7d2bced0b6e8',{'critical':0,'high':0,'medium':3,'low':2,'info':2}),
            ('93d94f871593eed6fbd68f0465988711c7d5485a014a81db3dc904e1416a9865',{'critical':0,'high':0,'medium':5,'low':8,'info':3})):
            with self.subTest(sha=sha):
                r=real_report(self.sources[sha]);cs=self.parser.parse(r)
                self.assertEqual(self.parser.printed_counts(r)['counts'],expected)
                self.assertEqual({k:sum(c.normalized==k for c in cs) for k in expected},expected)
                self.assertEqual(r.layout_selection['variant_id'],'halborn/v2025_website')

    def test_real_bvss_cards_have_full_descriptions_and_exact_status_spans(self):
        r=real_report(self.sources['5822d1bf5d738184621dc577aca70e3af64add053e638bd0850808c594106b0e'])
        cs=self.parser.parse(r)
        self.assertEqual([c.printed_id for c in cs],['HAL-01','HAL-02','HAL-03'])
        self.assertEqual(cs[0].title,'Lack of wsol mint validation')
        for c in cs:
            self.assertEqual(c.severity_raw,'Informational');self.assertEqual(c.status_raw,'Solved')
            proof=c.evidence['status_evidence'];self.assertEqual(r.text[proof['start']:proof['end']],c.status_raw)
            self.assertIn('#### Description\n',r.text[c.start:c.end])
        self.assertIn('wsol_mint_account',r.text[cs[0].start:cs[0].end])

    def test_every_real_website_record_is_emitted_once_with_body_and_native_status(self):
        for sha,source in self.sources.items():
            with self.subTest(sha=sha):
                r=real_report(source);cs=self.parser.parse(r);native=r.meta['halborn_website']
                self.assertFalse(native['issues']);self.assertFalse(native['unresolved_references'])
                self.assertEqual(len(cs),native['finding_count'])
                self.assertEqual(len(cs),len({c.printed_id for c in cs}))
                provenance={f['identifier']:f for f in native['findings']}
                for c in cs:
                    # Some newly collected historical cards publish remediation
                    # only, or just severity/status. Source absence remains absent.
                    has_description=provenance[c.printed_id]['has_public_description']
                    self.assertEqual('#### Description\n' in r.text[c.start:c.end],has_description)
                summary=self.parser.printed_counts(r)
                if summary:
                    self.assertFalse(summary['ambiguous'])
                    self.assertEqual({k:sum(c.normalized==k for c in cs) for k in summary['counts']},summary['counts'])


if __name__=='__main__':unittest.main()
