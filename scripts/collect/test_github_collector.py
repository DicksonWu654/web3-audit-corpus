#!/usr/bin/env python3
"""Offline regression checks for provenance, exclusions, dates and doc classes.

Run: python3 -I scripts/collect/test_github_collector.py
"""
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('github_collector', Path(__file__).with_name('github_collector.py'))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class MetadataChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.defaults = collector.settings()['defaults']

    def test_robots_wildcards_and_git_transport(self):
        rules = collector.Robots('User-agent: *\nDisallow: /*/tree/\nDisallow: /*.git$\nAllow: /ok/tree/\n')
        self.assertFalse(rules.allows('https://github.com/firm/repo/tree/main/'))
        self.assertFalse(rules.allows('https://github.com/firm/repo.git'))
        self.assertTrue(rules.allows('https://github.com/firm/repo.git/info/refs?service=git-upload-pack'))
        self.assertTrue(rules.allows('https://github.com/ok/tree/main/'))

    def test_robots_specific_group_and_allow_tie(self):
        rules = collector.Robots('User-agent: *\nDisallow: /\nUser-agent: Web3AuditCorpus\nDisallow: /x\nAllow: /x\n')
        self.assertTrue(rules.allows('https://github.com/y'))
        self.assertTrue(rules.allows('https://github.com/x'))

    def test_date_formats_and_precision(self):
        for value, expected in [
            ('2024-02-29-report.pdf', ('2024-02-29', 'day')),
            ('review_20250615.pdf', ('2025-06-15', 'day')),
            ('report-v230915.pdf', ('2023-09-15', 'day')),
            ('23 September 2024', ('2024-09-23', 'day')),
            ('March 2nd, 2025', ('2025-03-02', 'day')),
            ('2025-05-project.pdf', ('2025-05', 'month')),
            ('September 2024', ('2024-09', 'month')),
            ('2023-project.pdf', ('2023', 'year')),
            ('undated-report.pdf', ('', 'none')),
        ]:
            with self.subTest(value=value):
                self.assertEqual(collector.dates(value, filename=True), expected)

    def test_front_matter_date_on_next_line_and_refinement(self):
        result, _ = collector.hints('2025-project.pdf', {'text': 'Security Audit\nReport date:\nMarch 2, 2025\n', 'title': ''}, self.defaults, {})
        self.assertEqual((result['date_hint'], result['date_basis']), ('2025-03-02', 'document_text'))

    def test_no_git_or_retrieval_date_fabrication(self):
        result, _ = collector.hints('Undated.pdf', {'text': 'Security Audit\n', 'title': ''}, self.defaults, {})
        self.assertEqual((result['date_hint'], result['date_precision'], result['date_basis']), ('', 'none', 'none'))

    def test_exact_cover_date_refines_conflicting_filename_month(self):
        result, notes = collector.hints('2022-10-client.pdf', {'text': 'Security Review\nNovember 2, 2022', 'title': ''}, self.defaults, {})
        self.assertEqual((result['date_hint'], result['date_basis']), ('2022-11-02', 'document_text'))
        self.assertIn('filename=2022-10', notes)

    def test_generic_basename_uses_client_path_and_cover(self):
        result, _ = collector.hints('reports/aave/aave-gho-core/review.pdf', {'text': 'AAVE\nGHO Stablecoin\nSmart Contract Security Assessment Report\n', 'title': ''}, self.defaults, {})
        self.assertIn('aave-gho-core', result['project_hint'])
        self.assertIn('GHO Stablecoin', result['title_hint'])

    def test_classification_uses_titles_not_incidental_remediation(self):
        base = {'text': 'Security Audit\nThe remediation process follows the review.', 'title': ''}
        for name, kind in [('Project.pdf', 'audit_report'), ('Project-fix-review.pdf', 'fix_review'),
                           ('Project-FV.pdf', 'formal_verification'), ('Project-letter-of-attestation.pdf', 'non_report')]:
            with self.subTest(name=name):
                self.assertEqual(collector.hints(name, base, self.defaults, {})[0]['doc_kind'], kind)

    def test_scope_and_symlink_exclusions(self):
        regular = {'path': 'reports/client.pdf', 'type': 'blob', 'mode': '100644'}
        self.assertIsNone(collector.exclusion(regular, {}, self.defaults, None))
        self.assertIsNotNone(collector.exclusion(dict(regular, mode='120000'), {}, self.defaults, None))
        self.assertIsNotNone(collector.exclusion(dict(regular, path='images/client.png'), {}, self.defaults, None))
        self.assertIsNotNone(collector.exclusion(dict(regular, path='README.md'), {}, self.defaults, None))
        self.assertIsNotNone(collector.exclusion(regular, {}, self.defaults, {'reports/other.pdf'}))

    def test_repo_identity_rejects_non_github_or_shell_input(self):
        self.assertEqual(collector.repo_name('https://github.com/owner/repo/tree/main/reports'), 'owner/repo')
        for value in ['https://evil.example/owner/repo', 'owner/repo;curl', 'owner/$(id)']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                collector.repo_name(value)

    def test_independent_tree_parser_accepts_padded_submodule_size(self):
        spec = importlib.util.spec_from_file_location('independent_validator', Path(__file__).with_name('validate_github_collection.py'))
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        raw = (b'160000 commit ' + b'a' * 40 + b'       -\t.audit-report\0' +
               b'100644 blob ' + b'b' * 40 + b'    2048\treport.pdf\0')
        with mock.patch.object(validator, 'git_local', return_value=raw):
            tree = validator.ls_tree(Path('/tmp'), 'c' * 40)
        self.assertIsNone(tree['.audit-report']['size'])
        self.assertEqual(tree['report.pdf']['size'], 2048)


if __name__ == '__main__':
    unittest.main()
