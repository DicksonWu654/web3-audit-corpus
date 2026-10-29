"""Database edition is an explicit descriptive subset of the existing release."""
import csv
import io
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from database_policy import STATS, descriptive_csv, held_path, stats_schema

ROOT = Path(__file__).resolve().parents[2]


class DatabaseContract(unittest.TestCase):
    def test_future_or_interpretive_tables_fail_closed(self):
        for name in ('projection_2026', 'trends_2026_inputs', 'firm_momentum', 'self_reported_volume',
                     'incident_precision', 'key_results', 'top20_firms', 'concentration_year',
                     'firm_shares_year', 'entrants_last_observed_year', 'reaudit_cadence_year',
                     'cadence_identity_rules', 'run_summary', 'future_table'):
            with self.assertRaisesRegex(ValueError, 'outside database contract'):
                descriptive_csv(name, 'value\n1\n')
        for name in ('REPORT.md', 'docs/analysis/research.md', 'data/analysis/count.csv', 'scripts/analysis/run.py'):
            self.assertTrue(held_path(name))
        self.assertFalse(held_path('docs/AGENTS_GUIDE.md'))

    def test_firm_counts_drop_rankings_keep_counts(self):
        source = 'publisher_id,engagements,rank,rank_excluding_token_only\nb,20,1,1\na,10,2,2\n'
        rows = list(csv.DictReader(io.StringIO(descriptive_csv('firm_counts', source))))
        self.assertEqual(rows, [dict(publisher_id='a', engagements='10'), dict(publisher_id='b', engagements='20')])
        with self.assertRaisesRegex(ValueError, 'Out-of-scope'):
            descriptive_csv('firm_counts', 'publisher_id,engagements\ncertik,1\n')

    @unittest.skipUnless((ROOT / 'release/stats').exists(), 'Requires downloaded release statistics')
    def test_published_schema_matches_every_projected_table(self):
        text = stats_schema(ROOT / 'release')
        schema = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual({r['table'] for r in schema}, set(STATS))
        self.assertEqual((ROOT / 'docs/STATS_SCHEMA.csv').read_text(), text)
        for row in schema:
            columns = json.loads(row['columns'])
            self.assertTrue(set(json.loads(row['key_columns'])) <= set(columns))


if __name__ == '__main__':
    unittest.main()
