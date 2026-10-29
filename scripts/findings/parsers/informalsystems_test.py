"""Run: python3 scripts/findings/parsers/informalsystems_test.py"""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import Report, finish, severity
from parsers.informalsystems import parse, printed_counts

def report(text):
    return Report(text,{'file_format':'pdf','pages':[{'start':0,'end':len(text),'page':1,'text':text}]},'informalsystems')

class InformalTests(unittest.TestCase):
    def test_legacy_id_and_native_informative(self):
        text='IF-IBC-05\n\nRestructure the protocol\nSeverity: Informative\nType: Specification\nDescription\nThis is a detailed recommendation about restructuring the protocol.\n'
        rows=finish(report(text),parse(report(text)))
        self.assertEqual(rows[0].printed_id,'IF-IBC-05')
        self.assertEqual(rows[0].title,'Restructure the protocol')
        self.assertEqual(rows[0].normalized,'info')
    def test_duplicate_title_field(self):
        text='VerifyNamespace panics\n Title                 VerifyNamespace panics\n\n Project               Celestia\n Type                  Implementation\n Severity              2 MEDIUM\n Impact                3 HIGH\n Description\nAn empty input can cause a panic while verifying the proof.\n'
        rows=finish(report(text),parse(report(text)))
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0].title,'VerifyNamespace panics')
        self.assertEqual(rows[0].severity_raw,'MEDIUM')
    def test_unknown_and_conditional_are_not_upgraded(self):
        text='Unknown impact issue\n Project Namada\n Type Implementation\n Severity 0X UNKNOWN\n Status RESOLVED\nDescription\nThe issue has an explicitly unknown security impact in the report.\n\nConditional issue\n Project Namada\n Type Implementation\n Severity With whitelisted transactions: 0 NONE\n          With arbitrary transactions: 4 CRITICAL\n Impact 3 HIGH\n Status ACKNOWLEDGED\nDescription\nThe severity depends on transaction policy and remains conditional.\n'
        rows=finish(report(text),parse(report(text)))
        self.assertEqual(len(rows),2)
        self.assertEqual([severity(r.severity_raw) for r in rows],['unknown','unknown'])
        self.assertIn('arbitrary transactions',rows[1].severity_raw)
    def test_compact_status_and_appendix(self):
        text='Migrate5to6 not registered\n Severity Low          Impact 1 - Low          Exploitability 1 - Low\n Type Implementation       Status Patched Without Reaudit\nDescription\nThe missing migration handler prevents the upgrade from being applied.\nAppendix A: Methodology\nThis is not part of the finding.\n'
        rows=finish(report(text),parse(report(text)))
        self.assertEqual(rows[0].status_raw,'Patched Without Reaudit')
        self.assertNotIn('Appendix',text[rows[0].start:rows[0].end])
    def test_native_unmapped_labels_preserved(self):
        for label in ['Potentially High','Recommendation']:
            text='IF-TEST-01: Native label finding\n Severity '+label+'\n Type Protocol\n Status Unresolved\nDescription\nA complete description of the observation and its consequences.\n'
            rows=finish(report(text),parse(report(text)))
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0].severity_raw,label)
            self.assertEqual(severity(rows[0].severity_raw),'unknown')
    def test_summary_independent_of_details(self):
        text='Total High-Severity Issues      4\nTotal Medium-Severity Issues    5\nTotal Informative-Severity Issues  3\n'
        self.assertEqual(printed_counts(report(text))['counts'],{'high':4,'medium':5,'info':3})

if __name__=='__main__':unittest.main()
