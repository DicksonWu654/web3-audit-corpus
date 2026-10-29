"""Publisher-request exclusions cannot be undone by registry or source drift."""
import csv
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C
from database_policy import descriptive_csv
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'analysis/launch'))
from launch_policy import row_allowed


class PublisherRequestExclusions(unittest.TestCase):
    def test_registry_cannot_reenable_a_removed_publisher(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'registry').mkdir()
            (root / 'registry/scope_tier_a.csv').write_text(
                'firm_id,scope_group\ncyfrin,firm\ncodehawks,contest_platform\nsafe,firm\n')
            self.assertEqual(C.allowed_firms(root), {'safe'})

    def test_sources_and_lookalikes(self):
        for value in (None, {}, [], 0):
            self.assertFalse(C.is_excluded_publisher(value))
        for url in ('https://CYFRIN.io/a.pdf', 'https://codehawks.cyfrin.io/c/a',
                    'https://solodit.xyz/issues/1', 'https://docs.solodit.cyfrin.io/a',
                    'https://github.com/Cyfrin/reports/blob/main/a.pdf',
                    'https://raw.githubusercontent.com/Cyfrin/reports/main/a.pdf',
                    'https://api.github.com/repos/Cyfrin/reports',
                    'https://github.com/solodit/solodit_content/blob/main/a.md'):
            self.assertTrue(C.is_excluded_url(url), url)
        for url in ('https://github.com/GuardianAudits/Audits/Cyfrin/a.pdf',
                    'https://cyfrin.io.example.test/a', 'https://example.test/?name=Cyfrin'):
            self.assertFalse(C.is_excluded_url(url), url)

    def test_nested_evidence_and_quoted_links(self):
        self.assertTrue(C.contains_excluded_url('{"evidence":{"url":"https://solodit.xyz/1"}}'))
        text = 'Use the Cyfrin Aderyn tool. Reference https://solodit.xyz/1'
        clean, removed = C.remove_excluded_links(text)
        self.assertEqual(removed, 1)
        self.assertIn('Cyfrin Aderyn tool', clean)
        self.assertFalse(C.contains_excluded_url(clean))

    def test_descriptive_stats_fail_closed(self):
        for publisher in C.EXCLUDED_AT_PUBLISHER_REQUEST:
            with self.assertRaisesRegex(ValueError, 'Publisher-request'):
                descriptive_csv('firm_counts', 'publisher_id,engagements\n' + publisher + ',1\n')
        with self.assertRaisesRegex(ValueError, 'Publisher-request'):
            descriptive_csv('firm_counts', 'publisher_id,url\nsafe,https://solodit.xyz/1\n')

    def test_historical_aggregates_allow_names_but_never_examples(self):
        self.assertTrue(row_allowed({'firm_id': 'cyfrin', 'audits': 235}))
        self.assertFalse(row_allowed({'firm_id': 'cyfrin', 'title': 'removed title'}))
        self.assertFalse(row_allowed({'public_url': 'https://solodit.xyz/1', 'audits': 1}))
        uid = 'finding:' + 'a' * 64
        with patch('launch_policy.excluded_ids', return_value={uid}):
            self.assertFalse(row_allowed({'finding_uid': uid}, Path('/tmp')))
            self.assertTrue(row_allowed({'finding_uid': 'finding:' + 'b' * 64}, Path('/tmp')))

    def test_agent_formats_reject_excluded_evidence_in_other_firms_text(self):
        from agent_formats import joined
        row = dict(firm_id='safe', finding_uid='finding:1', report_id='r', engagement_id='e',
                   body_text_status='present', text_withheld=None, body_text='See https://solodit.xyz/1')
        with patch('agent_formats.metadata', return_value={'original_url':'https://safe.example/report'}):
            with self.assertRaisesRegex(ValueError, 'Publisher-request'):
                joined(row, {'r':{}}, {'e':{'firm_id':'safe'}}, {'safe':{}})


if __name__ == '__main__':
    unittest.main()
