import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/findings'))
from core import Report, finish
from parsers import hexens


def report(pages):
    text=''; meta=[]
    for n,p in enumerate(pages,1):
        meta.append({'page':n,'start':len(text),'end':len(text)+len(p),'text':p});text+=p
    return Report(text,{'file_format':'pdf','pages':meta},'hexens')


class HexensTests(unittest.TestCase):
    def test_lowercase_legacy_symbolic_code(self):
        r=report(['toke5-2\nNo restrictions on\ninitialize function\nSEVERITY: Medium\nPATH: token.sol\nREMEDIATION: Add initializer.\nSTATUS: Fixed\nDESCRIPTION:\nDetailed actual vulnerability narrative.'])
        c=finish(r,hexens.parse(r))[0]
        self.assertEqual((c.printed_id,c.title,c.severity_raw,c.status_raw),('toke5-2','No restrictions on initialize function','Medium','Fixed'))

    def test_new_card_status_removed_from_wrapped_title(self):
        r=report(['ROYCO3-9 | Redundant capping of                  Acknowledged\n_computeCurrentJtYieldShare\n\nSeverity: Informational Probability: Rare Impact: Informational\nPath: token.sol\nDescription:\nDetailed actual vulnerability narrative.'])
        c=finish(r,hexens.parse(r))[0]
        self.assertEqual((c.title,c.status_raw),('Redundant capping of _computeCurrentJtYieldShare','Acknowledged'))

    def test_numeric_body_list_does_not_steal_next_card_severity(self):
        r=report(['1. REAL NUMBERED FINDING\nSEVERITY: High\nSTATUS:\nDESCRIPTION:\nDetailed actual narrative.\n2. In this example a user sends a token.\n','2. SECOND REAL FINDING\nSEVERITY: Low\nDESCRIPTION:\nDetailed actual second vulnerability narrative.'])
        cs=finish(r,hexens.parse(r))
        self.assertEqual([c.printed_id for c in cs],['1','2'])
        self.assertIsNone(cs[0].status_raw)

    def test_missing_detail_never_created_from_summary(self):
        r=report(['Findings Summary\nSeverity Number of Findings\nCritical 0\nHigh 1\nMedium 0\nLow 0\nInformational 0\n'])
        self.assertEqual(hexens.parse(r),[])
        self.assertEqual(hexens.printed_counts(r)['counts']['high'],1)

if __name__=='__main__':unittest.main()
