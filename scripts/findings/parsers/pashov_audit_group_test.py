"""Regression cases for Pashov layout eras and shared source-status matching."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import digest
from core import Report, finish, status
from parsers.pashov_audit_group import parse, printed_counts


def report(text, fmt='pdf'):
    pages, offset = [], 0
    for n, text_page in enumerate(text.split('\f'), 1):
        pages.append({'page': n, 'start': offset, 'end': offset+len(text_page), 'text': text_page})
        offset += len(text_page)+1
    return Report(text, {'pages': pages, 'file_format': fmt, 'text_sha256': digest(text.encode())}, 'pashov-audit-group')


class PashovTests(unittest.TestCase):
    def test_continued_toc_and_index_are_not_detail_rows(self):
        r = report('Cover\fContents\n[L-01] Wrapped TOC title\f[L-02] Continued TOC title\n\fSummary of Findings\n[L-01] First issue  Low  Resolved\n[L-02] Second issue  Low  Fixed\f8. Findings\n8.1. Low Findings\n[L-01] First issue\n'+('  Actual detail prose.\n'*5)+'[L-02] Second issue\n'+('  More detail prose.\n'*5))
        entries = finish(r, parse(r))
        self.assertEqual([c.printed_id for c in entries], ['L-01', 'L-02'])
        self.assertEqual(entries[0].status_raw, 'Resolved')
        self.assertEqual(entries[0].title, 'First issue')

    def test_id_and_title_on_separate_lines(self):
        r = report('Cover\fContents\f8.1. High Findings\n[H-01]\nThe long title\ncontinues here\nSeverity\nImpact: High\n'+('Evidence.\n'*8))
        c = finish(r, parse(r))[0]
        self.assertEqual(c.title, 'The long title continues here')
        self.assertEqual(c.printed_id, 'H-01')

    def test_detail_on_same_page_as_index(self):
        r = report('Cover\fExecutive summary\fFindings\nSEVERITY  COUNT\nLow  1\nTotal  1\nID  TITLE  SEVERITY  STATUS\nL-01  Title  Low  Fixed\nLow Severity\n[L-01] The actual issue\ncontinued title\n  Low  Fixed\nSUMMARY\n'+('Evidence.\n'*8))
        self.assertEqual([c.printed_id for c in finish(r, parse(r))], ['L-01'])
        self.assertEqual(printed_counts(r)['counts'], {'low': 1})

    def test_page_numbers_are_not_summary_totals(self):
        r = report('Cover\fContents\nMedium Severity  8\nLow Severity  15\nInfo Severity  26\fMedium Severity\n[M-01] A finding\n'+('Evidence.\n'*8))
        self.assertIsNone(printed_counts(r))

    def test_markdown_status_preserved_from_publisher_index(self):
        r = report('| ID | Title | Severity | Status |\n| [M-01] | An issue | Medium | Acknowledged |\n# [M-01] An issue\n'+('Evidence.\n'*8), 'md')
        self.assertEqual(finish(r, parse(r))[0].status_raw, 'Acknowledged')

    def test_source_status_normalization(self):
        self.assertEqual(status('ﬁxed'), 'fixed')
        self.assertEqual(status('Fixed in commit 1234'), 'fixed')
        self.assertEqual(status('Partially Resolved'), 'partial')
        self.assertEqual(status('Closed'), 'resolved')
        self.assertEqual(status('Risk Accepted'), 'acknowledged')
        self.assertEqual(status('Patched Without Reaudit'), 'fixed')
        self.assertEqual(status('An unrelated source label'), 'other')

    def test_malformed_solidity_fence_and_cyrillic_id(self):
        r = report('# [L-01] First issue\n````solidity\ncode();\n```\n# [L-02] Second issue\n'+('Details.\n'*9)+'# [М-01] Cyrillic source code\n'+('Details.\n'*9), 'md')
        rows = finish(r, parse(r))
        self.assertEqual([c.printed_id for c in rows], ['L-01', 'L-02', 'М-01'])
        self.assertEqual(rows[-1].normalized, 'medium')
        r = report('```markdown\n# [H-99] Quoted heading\n'+('Fake quoted details.\n'*9)+'```\n# [L-01] Actual issue\n'+('Details.\n'*9), 'md')
        self.assertEqual([c.printed_id for c in finish(r, parse(r))], ['L-01'])


if __name__ == '__main__':
    unittest.main()
