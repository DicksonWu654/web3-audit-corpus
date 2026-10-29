"""Run: python3 scripts/findings/parsers/least_authority_test.py"""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import Report, finish, severity
from parsers.least_authority import parse

def report(text):
    return Report(text,{'file_format':'pdf','pages':[{'start':0,'end':len(text),'page':1,'text':text}]},'least-authority')

class LeastAuthorityTests(unittest.TestCase):
    def test_wrapped_contents_is_not_a_toc(self):
        text='Suggestion 2: Validate Chunk\nContents\n\nLocation\ncontract.rs\n\nSynopsis\nThe declared number is not checked against the actual content.\nVerification\nResolved.\n'
        rows=finish(report(text),parse(report(text)))
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0].title,'Validate Chunk Contents')
        self.assertEqual(rows[0].status_raw,'Resolved')
        self.assertIsNone(rows[0].severity_raw)
    def test_toc_continuation(self):
        text='Suggestion 4: Test more\n\nRecommendations\n\nAbout Least Authority\n\nOur Methodology\n'
        self.assertEqual(parse(report(text)),[])
    def test_index_severity_and_appendix_boundary(self):
        text='Issue A: Invalid input                    High     Resolved\n\nIssue A: Invalid input\n\nLocation\ncontract.rs\nSynopsis\nAn invalid input causes loss of the stored assets and halts transactions.\nStatus\nThe team implemented the change.\nVerification\nResolved.\n\nAppendix 1 - Activity Log\nNot part of the finding.\n'
        rows=finish(report(text),parse(report(text)))
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0].severity_raw,'High')
        self.assertEqual(rows[0].status_raw,'Resolved')
        self.assertNotIn('Appendix',text[rows[0].start:rows[0].end])
    def test_legacy_inline_fields_and_known_issue(self):
        text='Known Issue A: Untrusted assets\nReported: 2017-12-20\n\nSynopsis: Third-party assets can run arbitrary code while being called.\nImpact: The fund can become frozen.\nStatus: Not addressed.\n'
        r=report(text)
        rows=finish(r,parse(r))
        self.assertEqual(rows,[])
        self.assertEqual(next(iter(r.excluded_prior_findings.values()))['publisher_finding_id'],'Known Issue A')

if __name__=='__main__':unittest.main()
