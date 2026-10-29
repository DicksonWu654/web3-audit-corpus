import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/findings'))
from core import Report, finish
from parsers import mixbytes


def report(text, fmt='pdf'):
    return Report(text,{'file_format':fmt,'pages':[{'page':1,'start':0,'end':len(text),'text':text}]},'mixbytes')


class MixBytesTests(unittest.TestCase):
    def test_explicit_card_wrap_status_and_tail(self):
        text='L-1    First wrapped\n       title\n\nFile  token.sol\nSeverity   Low\nStatus    Fixed in abc123\n\nDescription\nDetailed actual vulnerability narrative.\n3. ABOUT MIXBYTES\nAdvertising content.'
        rows=finish(report(text),mixbytes.parse(report(text)))
        self.assertEqual([(c.printed_id,c.title,c.severity_raw,c.status_raw) for c in rows],[('L-1','First wrapped title','Low','Fixed in abc123')])
        self.assertNotIn('Advertising',text[rows[0].start:rows[0].end])

    def test_summary_is_independent_and_not_a_finding(self):
        text='Findings Count\n0    1    0    0    1\nCRITICAL    HIGH    MEDIUM    LOW    TOTAL\n\nFindings Statuses\nID FINDING SEVERITY STATUS\nH-1    Example title     HIGH FIXED\n'
        r=report(text)
        self.assertEqual(mixbytes.parse(r),[])
        self.assertEqual(mixbytes.printed_counts(r)['counts'],{'critical':0,'high':1,'medium':0,'low':0})

    def test_redesigned_card_explicit_labels(self):
        text='[ 2 FINDINGS REPORT ]\n2.2 High\nH-1   Miscalculation of token       HIGH\n      accounting                  FIXED\n\nDESCRIPTION\nDetailed vulnerability narrative independent of summary.\n3. About MixBytes\nFooter'
        c=finish(report(text),mixbytes.parse(report(text)))[0]
        self.assertEqual((c.title,c.severity_raw,c.status_raw),('Miscalculation of token accounting','HIGH','FIXED'))

    def test_legacy_source_labels_and_repeated_numeric_ids(self):
        text='## Identified issues\n### [SERIOUS]\n##### 1. Serious issue\nDetailed serious vulnerability body.\n### [WARNINGS]\n##### 1. Warning issue\nDetailed warning vulnerability body.\n### [REMARKS]\n##### 1. Remark issue\nDetailed remark body with recommendation.\n## Conclusion\nNo more findings.'
        rows=finish(report(text,'md'),mixbytes.parse(report(text,'md')))
        self.assertEqual([c.normalized for c in rows],['high','medium','info'])
        self.assertEqual([c.printed_id for c in rows],['1','1','1'])
        self.assertNotIn('Conclusion',text[rows[-1].start:rows[-1].end])

class MixBytesSequenceTests(unittest.TestCase):
    def test_methodology_appendix_and_missing_space(self):
        text='COMMENTS\nSECURITY ASSESSMENT METHODOLOGY\n1. Manual review\n2. Automated review\nDETECTED ISSUES\nMAJOR\n1.The arguments are missing\nA detailed actual finding narrative with enough description.\nAPPENDIX TO REPORT\n1. External library check\nAn unrelated review appendix.'
        cs=finish(report(text),mixbytes.parse(report(text)))
        self.assertEqual([(c.printed_id,c.title) for c in cs],[('1','The arguments are missing')])
        self.assertNotIn('APPENDIX',text[cs[0].start:cs[0].end])

    def test_narrative_lists_do_not_become_markdown_findings(self):
        text='### MAJOR\n##### 1. Missing validation\nDetailed actual vulnerability narrative. The attack works as follows:\n1. A user first deposits funds and then withdraws.\n2. A user repeats the action to take funds.\n##### 2. Another actual issue\nDetailed actual vulnerability narrative.'
        cs=finish(report(text,'md'),mixbytes.parse(report(text,'md')))
        self.assertEqual([c.printed_id for c in cs],['1','2'])

    def test_source_sections_allow_restarts_but_preserve_real_duplicates(self):
        from core import Candidate
        from parsers.mixbytes_review import native_sequence
        text='### COMMENTS\n1. First project\n### COMMENTS\n1. Second project\n'
        cs=[Candidate(text.index('1. First'),'one',printed_id='1'),Candidate(text.index('1. Second'),'two',printed_id='1')]
        self.assertEqual(native_sequence(report(text,'md'),cs)['state'],'complete')
        cs.append(Candidate(text.index('1. Second')+1,'duplicate',printed_id='1'))
        seq=native_sequence(report(text,'md'),cs)
        self.assertEqual(seq['state'],'incomplete')
        self.assertEqual(seq['series'][-1]['duplicates'],[1])

if __name__=='__main__':unittest.main()
