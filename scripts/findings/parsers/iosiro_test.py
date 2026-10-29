"""Run: python3 scripts/findings/parsers/iosiro_test.py"""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import Report, finish, severity
from parsers.iosiro import parse, printed_counts

def report(text):
    return Report(text,{'file_format':'html','pages':[{'start':0,'end':len(text),'page':1,'text':text}]},'iosiro')

class IosiroTests(unittest.TestCase):
    def test_parent_risk_closed_override_and_footer(self):
        text='# 5. Detailed Findings\n## 5.4 Informational\n### 5.4.1 Design comments\nSome concrete observations about the design and its limitations.\n## 5.5 Closed\n### 5.5.1 Invalid transfer (High Risk)\nThe transfer function is vulnerable in this specific situation.\nSecure your system.\nfooter\n'
        rows=finish(report(text),parse(report(text)))
        self.assertEqual([severity(r.severity_raw) for r in rows],['info','high'])
        self.assertEqual(rows[1].status_raw,'Closed')
        self.assertNotIn('Secure your system',text[rows[1].start:rows[1].end])
    def test_real_fences_and_inline_fences(self):
        text='# 6. Detailed Findings\n## 6.1 High Risk\n### 6.1.1 First issue\n```solidity\n~~~ pretend separator ~~~\n### 6.1.99 Fake issue inside code\n```\n```inline code```\n### 6.1.2 Second issue\nThe real second issue has a complete, detailed description here.\n'
        rows=finish(report(text),parse(report(text)))
        self.assertEqual([r.printed_id for r in rows],['6.1.1','6.1.2'])
    def test_html_card_and_unlabeled_advice(self):
        text='<h1>Audit findings</h1><h2><strong>IO-TEST-001</strong> Bad transfer</h2><table class="metadata"><tr><td class="rating-low">Low</td><td class="status-resolved">Resolved</td></tr></table><p>A long description of the erroneous transfer and its impact.</p><h1>Code quality improvement suggestions</h1><table class="codequality"><tr><th>#</th><th>Location</th><th>Details</th></tr><tr><td>2</td><td>contract.sol</td><td>Remove unused state variables to simplify the code and reduce overhead.</td></tr></table>'
        rows=finish(report(text),parse(report(text)))
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[0].severity_raw,'Low')
        self.assertEqual(rows[1].record_kind,'recommendation')
        self.assertIsNone(rows[1].title)
        self.assertEqual(severity(rows[1].severity_raw),'unknown')
    def test_independent_aggregate(self):
        text='<table class="findings-count"><tr><th></th><th>High</th><th>Low</th></tr><tr><td>Open</td><td>1</td><td>2</td></tr><tr><td>Resolved</td><td>3</td><td>4</td></tr></table>'
        self.assertEqual(printed_counts(report(text))['counts'],{'high':4,'low':6})

if __name__=='__main__':unittest.main()
