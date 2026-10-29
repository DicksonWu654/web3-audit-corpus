import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/findings'))
from core import Report, finish
from parsers import blocksec


def report(pages):
    text=''; meta=[]
    for n,p in enumerate(pages,1):
        meta.append({'page':n,'start':len(text),'end':len(text)+len(p),'text':p});text+=p
    return Report(text,{'file_format':'pdf','pages':meta},'blocksec')


class BlockSecTests(unittest.TestCase):
    def test_summary_page_also_has_first_detail(self):
        r=report(['Chapter 2 Findings\n- Low Risk: 1\nID  Severity  Description  Category Status\n1 Low Wrapped finding Software Security Fixed\n2.1 Software Security\n2.1.1 Wrapped finding\n\nSeverity Low\nStatus Fixed in Version 2\nDescription Detailed actual vulnerability narrative.\n2.2 Additional Recommendation\n2.2.1 Better logs\n\nStatus Confirmed\nDescription Recommendation narrative.\n2.3 Note\n2.3.1 Admin trust\n\nDescription Explicitly published note narrative.'])
        cs=finish(r,blocksec.parse(r))
        self.assertEqual([c.record_kind for c in cs],['formal_finding','recommendation','observation'])
        self.assertEqual(cs[0].status_raw,'Fixed in Version 2')
        self.assertEqual(blocksec.printed_counts(r)['counts'],{'low':1})

    def test_split_toc_and_index_only_severity(self):
        r=report(['Contents\n2.1.1 Long title\n\n','  continued . . . . . . . 4\n2.1.2 Second title . . . . . . 5\n\n','Report Manifest\n1 Medium Long title Software Security Fixed\n2 Low Second title Software Security Fixed\n2.1 Software Security\n2.1.1 Long title\n\nStatus Fixed\nDescription Detailed first finding narrative.\n2.1.2 Second title\n\nStatus Confirmed\nDescription Detailed second finding narrative.'])
        cs=finish(r,blocksec.parse(r))
        self.assertEqual([c.printed_id for c in cs],['2.1.1','2.1.2'])
        self.assertEqual([c.severity_raw for c in cs],['Medium','Low'])

    def test_chapter_three_and_wrapped_title(self):
        r=report(['Chapter 3 Findings\n3.1 DeFi Security\n3.1.1 Missing validation for\n      supplied token\n\nSeverity Medium\nStatus Acknowledged\nDescription Detailed vulnerability narrative.\nChapter 4 Automated Testing\nUnrelated results'])
        c=finish(r,blocksec.parse(r))[0]
        self.assertEqual(c.title,'Missing validation for supplied token')
        self.assertNotIn('Unrelated',r.text[c.start:c.end])

    def test_nested_research_skips_methodology(self):
        r=report(['2.3.2.1 Overall Results\n\nNo issue, just a methodology discussion.\n2.3.2.2 Crash in VM\n\nStatus Confirmed\nDescription Detailed security issue body.\n2.4.1.1 Overall Results\n\nOther unrelated testing narrative.'])
        cs=finish(r,blocksec.parse(r))
        self.assertEqual([c.printed_id for c in cs],['2.3.2.2'])
        self.assertNotIn('Other unrelated',r.text[cs[0].start:cs[0].end])

class BlockSecSequenceTests(unittest.TestCase):
    def test_recommendations_and_observations_participate_in_sequence(self):
        from core import Candidate
        from parsers.mixbytes_review import native_sequence
        r=report(['Source report'])
        cs=[Candidate(0,'recommendation',printed_id='2.1.1',record_kind='recommendation'),Candidate(1,'observation',printed_id='2.2.1',record_kind='observation')]
        seq=native_sequence(r,cs)
        self.assertEqual(seq['state'],'complete')
        self.assertEqual(seq['record_kinds_included'],['observation','recommendation'])

if __name__=='__main__':unittest.main()
