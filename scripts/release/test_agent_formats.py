"""Agent-format regressions using synthetic bodies, rights and missing-text states."""
import csv
import gzip
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent_formats as formats


class AgentFormats(unittest.TestCase):
    def fixture(self, root):
        def write(name, rows):
            with (root / name).open('w', newline='') as stream:
                writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator='\n')
                writer.writeheader(); writer.writerows(rows)
        write('firms.csv', [dict(firm_id='oak-security', name='Oak Security')])
        engagements = [dict(engagement_id='e' + str(i), firm_id='oak-security', project='Project / ' + str(i),
                            audit_year='2025' if i == 1 else '', audit_date_min='2025-01', audit_date_max='2025-02',
                            audit_type='protocol', languages='["Solidity"]', chain_families='["EVM"]') for i in (1, 2)]
        write('engagements.csv', engagements)
        write('reports.csv', [dict(report_id=str(i) * 64, firm_id='oak-security', engagement_id='e' + str(i),
                                  url='https://example.test/' + str(i), permalink='') for i in (1, 2)])
        rows = []
        for i, (body, status, withheld) in enumerate([
                ('Exact Oak excerpt.\n  Keep spacing.\n', 'present', None),
                ('WITHHELD-BODY-SENTINEL', 'present', 'publisher_notice'),
                ('UNAVAILABLE-BODY-SENTINEL', 'not_in_source', None),
                ('UNKNOWN-STATUS-SENTINEL', None, None)]):
            rows.append(dict(finding_uid='finding:' + str(i), finding_id='F-' + str(i), engagement_id='e1',
                             report_id='1' * 64, firm_id='oak-security', title='Title\nwith quotes " and ##',
                             severity='critical', status='fixed', vuln_group='oracle', vuln_leaf='oracle.price',
                             body_text=body, body_text_status=status, text_withheld=withheld,
                             text_attribution='Oak Security', text_license='CC BY-ND 4.0',
                             text_license_url='https://creativecommons.org/licenses/by-nd/4.0/',
                             text_source_url='https://example.test/1', body_truncated=True))
        pq.write_table(pa.Table.from_pylist(list(reversed(rows))), root / 'findings.parquet')
        return rows

    def test_rights_withholding_empty_reports_and_determinism(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); source = base / 'source'; source.mkdir()
            rows = self.fixture(source)
            first, second = base / 'first', base / 'second'
            result = formats.build(source, first)
            self.assertEqual(result, dict(findings=4, full_text=1, withheld_or_unavailable=3, reports=2))
            pq.write_table(pa.Table.from_pylist(rows), source / 'findings.parquet')
            formats.build(source, second)
            for name in ('audits-markdown.zip', 'findings.jsonl.gz'):
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            with gzip.open(first / 'findings.jsonl.gz', 'rt') as stream:
                objects = [json.loads(line) for line in stream]
            self.assertEqual(len(objects), len(rows))
            self.assertEqual(objects[0]['body_text'], rows[0]['body_text'])
            self.assertTrue(all(row['body_text'] is None for row in objects[1:]))
            for original, actual in zip(rows, objects):
                for field in formats.RIGHTS:
                    self.assertEqual(actual[field], original[field])
                self.assertEqual(actual['firm'], 'Oak Security')
                self.assertEqual(actual['languages'], ['Solidity'])
            with zipfile.ZipFile(first / 'audits-markdown.zip') as archive:
                self.assertEqual(archive.namelist(), sorted(archive.namelist()))
                self.assertTrue(all(info.date_time == formats.ZIP_DATE for info in archive.infolist()))
                index = list(csv.DictReader(io.StringIO(archive.read('INDEX.csv').decode())))
                self.assertEqual(sum(int(row['finding_records']) for row in index), len(rows))
                self.assertEqual(len(index), 2)
                self.assertIn('/unknown/', index[1]['path'])
                text = archive.read(index[0]['path']).decode()
                self.assertIn(rows[0]['body_text'], text)
                self.assertIn('Text unavailable. See original report:', text)
                self.assertIn('text_license: "CC BY-ND 4.0"', text)
                self.assertEqual(text.count('\nfinding_uid: '), len(rows))
                for sentinel in ('WITHHELD-BODY-SENTINEL', 'UNAVAILABLE-BODY-SENTINEL', 'UNKNOWN-STATUS-SENTINEL'):
                    self.assertNotIn(sentinel, text)
                self.assertEqual(json.loads(archive.read(index[1]['path']).decode().split('finding_records: ')[1].splitlines()[0]), 0)

    def test_rejects_out_of_scope_and_path_collisions(self):
        self.assertEqual(formats.short_id('unhashed:' + 'a' * 64), 'unhashed')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); self.fixture(root)
            (root / 'firms.csv').write_text('firm_id,name\ncertik,CertiK\n')
            with self.assertRaisesRegex(ValueError, 'Out-of-scope'):
                formats.build(root, root / 'out')


if __name__ == '__main__':
    unittest.main()
