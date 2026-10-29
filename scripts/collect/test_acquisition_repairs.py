#!/usr/bin/env python3
"""Offline regression tests for failed PDF acquisition and publisher identity."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import web_common as web
import github_collector as github
import contest_common as contest
import publisher_identity as identity


class CollectionFixes(unittest.TestCase):
    def test_html_200_at_pdf_url_is_failed_and_not_stored(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            client = Mock(observations=[])
            client.fetch.return_value = web.Response('https://example.org/', b'<html>homepage</html>', 'text/html')
            item = web.Item('https://example.org/report.pdf', 'https://example.org/list')
            with patch.multiple(web, ROOT=root, STORE=root/'store'):
                status = web.collect('firm', web.Listing([item], [item.listing_url], 'fixture'), client)
            self.assertEqual((status['collected'], status['failed']), (0, 1))
            self.assertIn('pdf_magic_ok=false', status['failures'][0]['error'])
            self.assertEqual((root/'data/collect/firm/reports.jsonl').read_text(), '')
            self.assertFalse((root/'store/originals').exists())

    def test_cached_claimed_pdf_is_rechecked(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            body = b' \n%PDF-1.7 invalid byte-zero signature'
            local = root/'cached.pdf'
            local.write_bytes(body)
            out = root/'data/collect/firm'
            out.mkdir(parents=True)
            url = 'https://example.org/report.pdf'
            row = dict(public_url=url, local_path='cached.pdf', sha256=hashlib.sha256(body).hexdigest(), file_format='pdf')
            (out/'reports.jsonl').write_text(json.dumps(row)+'\n')
            client = Mock(observations=[])
            with patch.multiple(web, ROOT=root, STORE=root/'store'):
                status = web.collect('firm', web.Listing([web.Item(url,url)], [url], 'fixture'), client)
            self.assertEqual((status['collected'],status['failed']), (0,1))
            client.fetch.assert_not_called()

    def test_github_claimed_pdf_cannot_be_downgraded_to_other(self):
        with patch.object(github, 'git', return_value=b'not a PDF'):
            with self.assertRaisesRegex(ValueError, 'pdf_magic_ok=false'):
                github.process_file('firm','owner/repo','a'*40,Path('/tmp'),
                    dict(path='report.pdf',git_blob='b'*40),{}, {}, Mock())

    def test_contest_application_pdf_mime_cannot_be_saved_as_markdown(self):
        client = Mock()
        client.get.return_value = (dict(status=200,content_type='application/pdf'), b'<html>no report</html>')
        with self.assertRaisesRegex(ValueError, 'pdf_magic_ok=false'):
            contest.store_report(client,'firm',{},'https://example.org/download')

    def test_alias_dedup_preserves_source_links_on_replay(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for firm,url in [('chainlight','https://new.example/report.pdf'),('theori','https://old.example/report.pdf')]:
                out = root/'data/collect'/firm
                out.mkdir(parents=True)
                (out/'reports.jsonl').write_text(json.dumps(dict(firm_id=firm,public_url=url,
                    listing_url=url,sha256='a'*64,notes='publisher evidence'))+'\n')
                (out/'status.json').write_text(json.dumps(dict(collected=1)))
            with patch.object(identity,'ROOT',root):
                first = identity.reconcile('chainlight',['theori'],merge_all=True)
                second = identity.reconcile('chainlight',['theori'],merge_all=True)
            self.assertEqual(first['unique_originals'],1)
            self.assertEqual(second['unique_originals'],1)
            self.assertEqual((root/'data/collect/theori/reports.jsonl').read_text(),'')
            self.assertIn('theori',{r['source_firm_id'] for r in second['source_links']})

    def test_host_dedup_does_not_turn_cantina_into_publisher_alias(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            for firm,hashes in [('spearbit',['a'*64]),('cantina',['a'*64,'b'*64])]:
                out=root/'data/collect'/firm
                out.mkdir(parents=True)
                (out/'reports.jsonl').write_text(''.join(json.dumps(dict(firm_id=firm,public_url='https://example.org/'+sha,
                    listing_url='https://example.org/'+firm,sha256=sha,notes=''))+'\n' for sha in hashes))
                (out/'status.json').write_text(json.dumps(dict(collected=len(hashes))))
            with patch.object(identity,'ROOT',root):
                identity.reconcile('spearbit',['cantina'])
            status=json.loads((root/'data/collect/cantina/status.json').read_text())
            self.assertEqual(status['collected'],1)
            self.assertNotIn('canonical_publisher',status)
            self.assertIn('cantina', (root/'data/collect/spearbit/reports.jsonl').read_text())


if __name__ == '__main__':
    unittest.main()
