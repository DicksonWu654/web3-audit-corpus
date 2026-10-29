"""Offline scope, frozen-tree coverage, and receipt-preservation regressions."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import github_collector as collector
from trail_of_bits_scope import BRON_PATH, BRON_REASON, CONTENT_SCOPE_EVIDENCE, README_SECTIONS


class TrailOfBitsSelector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        settings = collector.settings()
        cls.conf = settings['firms']['trail-of-bits']
        cls.defaults = settings['defaults']

    def reason(self, path, selected=(), **extra):
        return collector.exclusion({'path': path, 'mode': '100644', 'type': 'blob', **extra},
                                   self.conf, self.defaults, set(selected))

    def test_readme_sections_and_nested_heading_boundaries(self):
        text = ('## Blockchain Reviews\n### Wallets\n[x](reviews/wallet.pdf)\n'
                '## Cryptography\n[x](reviews/generic.pdf)\n'
                '## Uniswap\n[x](./reviews/uni%20swap.pdf)\n'
                '## Technology\n[x](reviews/software.pdf)\n')
        with patch.object(collector, 'git', return_value=text.encode()):
            selected = collector.selected_readme_paths(None, [{'path': 'README.md', 'git_blob': 'a'*40}], README_SECTIONS)
        self.assertEqual(selected, {'reviews/wallet.pdf', 'reviews/uni swap.pdf'})

    def test_web3_products_outside_readme_sections(self):
        for path in ('2022-09-aleosystems-snarkvm', '2023-08-worldcoin-orb',
                     '2025-03-near-one-mpc-chain-signatures', '2026-06-turnkey-keymanagementsystem',
                     'Galoy', 'SpruceID', 'renvm'):
            with self.subTest(path=path):
                self.assertIsNone(self.reason('reviews/' + path + '.pdf'))

    def test_document_evidenced_exceptions(self):
        for path in CONTENT_SCOPE_EVIDENCE:
            with self.subTest(path=path):
                self.assertIsNone(self.reason(path))

    def test_generic_crypto_and_non_web3_remain_excluded(self):
        for path in ('openssl-securityreview.pdf', 'signal-securityreview.pdf', 'google-cryptography.pdf',
                     'kubernetes-securityreview.pdf', 'random-mpc-securityreview.pdf'):
            with self.subTest(path=path):
                self.assertIsNotNone(self.reason('reviews/' + path))

    def test_supporting_and_attestation_files_override_readme(self):
        for path in ('reviews/celo_bugfixes.md', 'reviews/uniswap-invariant-development.pdf',
                     'reviews/2026-09-yonlabs-whitepaper-letterofattestation.pdf',
                     'reviews/2026-07-polygon-loa.pdf'):
            with self.subTest(path=path):
                self.assertIsNotNone(self.reason(path, [path]))

    def test_bron_is_resolved_excluded_even_if_linked_in_web3_section(self):
        self.assertEqual(self.reason(BRON_PATH, [BRON_PATH]), BRON_REASON)

    def test_symlinks_and_code_cannot_enter_through_product_name(self):
        self.assertIsNotNone(self.reason('reviews/aleo.pdf', mode='120000'))
        self.assertIsNotNone(self.reason('reviews/aleo.py'))
        self.assertIsNotNone(self.reason('papers/aleo.pdf'))


    def test_preserve_receipts_row_order_and_recovered_external_reports(self):
        previous = [{'public_url': 'pinned', 'sha256': 'a', 'date_hint': '2024-01-02'},
                    {'public_url': 'recovered', 'sha256': 'b'}]
        acquired = [{'public_url': 'new', 'sha256': 'c'},
                    {'public_url': 'pinned', 'sha256': 'a', 'date_hint': '2024'}]
        merged = collector.merge_records(acquired, previous, preserve=True)
        self.assertEqual(merged[:2], previous)
        self.assertEqual(collector.merge_records(acquired, merged, preserve=True), merged)

    def test_pinned_url_hash_conflict_fails_closed(self):
        with self.assertRaises(ValueError):
            collector.merge_records([{'public_url': 'pinned', 'sha256': 'b'}],
                                    [{'public_url': 'pinned', 'sha256': 'a'}], preserve=True)

    def test_content_identity_skips_new_urls_for_acquired_bytes(self):
        prior = [{'public_url': 'recovered', 'sha256': 'a'}]
        selected = [{'public_url': 'canonical', 'sha256': 'a'},
                    {'public_url': 'new', 'sha256': 'b'},
                    {'public_url': 'new-copy', 'sha256': 'b'}]
        self.assertEqual(collector.merge_records(selected, prior, preserve=True), prior + selected[1:2])

    def test_phase0_reconciliation_accepts_retained_external_listing(self):
        row = {'listing_url': 'https://raw.githubusercontent.com/client/reports/commit/index.json',
               'filename': 'client.pdf', 'notes': ''}
        with patch.object(collector, 'phase0_counts', return_value={}):
            self.assertEqual(collector.reconcile_phase0('trail-of-bits', [row], [])['collected'], 0)


if __name__ == '__main__':
    unittest.main()
