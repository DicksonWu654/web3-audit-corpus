"""Offline regressions for Halborn catalogue replacement boundaries."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from web_halborn import is_catalogue_row, retained_collection_rows

class RetentionTests(unittest.TestCase):
    def test_catalogue_refresh_retains_third_party_recoveries(self):
        github={'source_kind':'github','file_format':'pdf','public_url':'https://github.com/example/reports/blob/abc/report.pdf'}
        gitbook={'source_kind':'website','file_format':'pdf','public_url':'https://files.gitbook.io/audit.pdf?alt=media'}
        s3={'source_kind':'website','file_format':'pdf','public_url':'https://example.s3.amazonaws.com/Halborn.pdf'}
        third_party_html={'source_kind':'website','file_format':'html','public_url':'https://example.org/audits/report'}
        catalogue={'source_kind':'website','file_format':'html','public_url':'https://www.halborn.com/audits/project/security-review'}
        rows=[github,gitbook,s3,third_party_html,catalogue]
        retained=retained_collection_rows(rows)
        self.assertEqual(retained,[github,gitbook,s3,third_party_html])
        self.assertIs(retained[1],gitbook)
        self.assertEqual(retained_collection_rows(retained),retained)
    def test_replacement_requires_actual_catalogue_host_and_html_document(self):
        base={'source_kind':'website','file_format':'html'}
        for url in ['https://halborn.com.example/audits/x','https://www.halborn.com/research/x','https://example.org/audits/x']:
            with self.subTest(url=url):self.assertFalse(is_catalogue_row(base|{'public_url':url}))
        self.assertTrue(is_catalogue_row(base|{'public_url':'https://halborn.com/audits/x'}))
        self.assertFalse(is_catalogue_row(base|{'file_format':'pdf','public_url':'https://halborn.com/audits/archive.pdf'}))

if __name__=='__main__':unittest.main()
