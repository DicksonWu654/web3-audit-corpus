"""Run with python3 -I -S scripts/findings/test_hexens_informal_variants.py."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from core import Report
from common import digest
from parsers import module
from parsers.informalsystems import printed_counts

D='\nDescription:\nThe source describes the affected path, the demonstrated impact and the recommended correction.\n'
FIXTURES={
 'hexens_numbered':('hexens','1. Missing authorization\nSeverity: Critical\nResolution: add an authorization modifier'+D,'v2021_numbered',1),
 'hexens_symbolic_dot':('hexens','HEX-1. Missing authorization\nSEVERITY: High\nSTATUS: partially ﬁxed'+D,'v2023_symbolic_dot',1),
 'hexens_symbolic_stacked':('hexens','HEX-1\nMissing authorization\nSEVERITY: High\nSTATUS: Acknowledged, see commentary'+D,'v2023_symbolic_stacked',1),
 'hexens_pipe_badge':('hexens','HEX-1 | Missing authorization                          Fixed\n  Severity: High    Probability: Likely    Impact: High'+D,'v2025_pipe_badges',1),
 'informal_legacy':('informalsystems','IF-IBC-01: Refund logic differs\nSeverity: High\nType: Specification'+D,'v2021_legacy_metadata',1),
 'informal_numeric':('informalsystems','Refund logic differs\n Project Namada\n Type Protocol\n Severity 2 MEDIUM\n Status ACKNOWLEDGED'+D,'v2022_numeric_metadata',1),
 'informal_conditional':('informalsystems','Conditional impact\n Project Namada\n Type Protocol\n Severity With whitelisted transactions: 0 NONE\n With arbitrary transactions: 4 CRITICAL\n Status ACKNOWLEDGED'+D,'v2022_numeric_metadata',1),
 'informal_stacked':('informalsystems','Refund logic differs\n ID IF-FINDING-001\n Severity High\n Impact 3 - High\n Type Implementation\n Status Resolved'+D,'v2025_stacked_cards',1),
 'informal_compact':('informalsystems','Refund logic differs\n Severity Low    Impact 1 - Low    Exploitability 1 - Low\n Type Implementation    Status Patched Without Reaudit'+D,'v2025_compact_cards',1),
 'informal_ungraded':('informalsystems','Skip: mev-tendermint\n\nRefund logic differs\nDescription\nThe source describes the affected path and demonstrated impact.\nRecommendation\nReview the affected path.\nStatus Update\nFixed in skip-mev/mev-tendermint#126.\n','v2023_ungraded',1),
 'informal_protocol':('informalsystems','Formal Methods Assessment Report\nInformal Systems\nThis report presents a protocol assessment without security finding metadata.\n','v2022_protocol_assessment',0),
 'informal_markdown_index':('informalsystems','# Findings\n| **#** | **Title** | **Type** | **Severity** | **Code or Spec** |\n| IF-IBC-01 | [Refund logic differs](./IF-IBC-01.md) | Specification | Medium | Spec |\n','v2020_markdown_index',1),
 'informal_markdown_fragment':('informalsystems','# Audit overview\nInformal Systems reviewed the implementation. Detailed findings are linked in separate documents.\n','v2020_markdown_fragments',0),
}


def report(text,firm,fmt='pdf',date=None):
    pages=[];offset=0
    for n,page in enumerate(text.split('\f'),1):
        pages.append(dict(page=n,start=offset,end=offset+len(page),text=page));offset+=len(page)+1
    return Report(text,{'file_format':fmt,'date_hint':date,'text_sha256':digest(text.encode()),
                        'pages':pages},firm)


class LayoutTests(unittest.TestCase):
    def test_declared_fixture_coverage_and_selection(self):
        declared={name for firm in ('hexens','informalsystems') for v in module(firm).VARIANTS for name in v.fixtures}
        self.assertEqual(declared,set(FIXTURES))
        for name,(firm,text,era,count) in FIXTURES.items():
            with self.subTest(name=name):
                r=report(text,firm,'md' if 'markdown' in name else 'pdf')
                cs=module(firm).parse(r)
                self.assertEqual(r.layout_selection['variant_id'],firm+'/'+era)
                self.assertEqual(len(cs),count)
                self.assertFalse(r.layout_selection['unknown_layout'])
                for c in cs:
                    self.assertTrue(0<=c.start<c.end<=len(text))
                    if c.status_raw:
                        span=c.evidence['status_evidence']
                        self.assertEqual(span['text'],text[span['start']:span['end']])
                        self.assertEqual(span['raw'],c.status_raw)

    def test_status_values_and_full_qualifiers(self):
        expected={'hexens_symbolic_dot':('partially ﬁxed','partial'),
                  'hexens_symbolic_stacked':('Acknowledged','acknowledged'),
                  'hexens_pipe_badge':('Fixed','fixed'),
                  'informal_numeric':('ACKNOWLEDGED','acknowledged'),
                  'informal_stacked':('Resolved','resolved'),
                  'informal_compact':('Patched Without Reaudit','fixed'),
                  'informal_ungraded':('Fixed','fixed')}
        for name,(raw,norm) in expected.items():
            firm,text,_,_=FIXTURES[name]
            c=module(firm).parse(report(text,firm))[0]
            self.assertEqual((c.status_raw,c.normalized_status),(raw,norm))

    def test_recommendations_and_free_text_never_assert_status(self):
        for name in ('hexens_numbered','informal_legacy'):
            firm,text,_,_=FIXTURES[name]
            c=module(firm).parse(report(text+'We recommend that the issue should be fixed.\n',firm))[0]
            self.assertIsNone(c.status_raw)

    def test_later_labelled_resolution_supersedes_initial_card(self):
        for name in ('hexens_symbolic_stacked','informal_stacked'):
            firm,text,_,_=FIXTURES[name]
            r=report(text+'\nFix Review\nResolved\nThe fix review confirms the revised implementation.\n',firm)
            c=module(firm).parse(r)[0]
            self.assertEqual(c.status_raw,'Resolved')
            self.assertEqual(c.evidence['status_evidence']['basis'],'resolution_section')

    def test_date_hint_is_weak_and_no_unconditional_contract(self):
        for firm in ('hexens','informalsystems'):
            self.assertTrue(all(not v.fingerprint.legacy for v in module(firm).VARIANTS))
            r=report('Unfamiliar document with no known structural signatures.',firm,date='2025-01-01')
            module(firm).parse(r)
            self.assertTrue(r.layout_selection['unknown_layout'])
        firm,text,era,_=FIXTURES['hexens_pipe_badge']
        r=report(text,firm,date='2021-01-01');module(firm).parse(r)
        self.assertEqual(r.layout_selection['variant_id'],firm+'/'+era)

    def test_index_is_an_excerpt_not_manufactured_detail(self):
        firm,text,_,_=FIXTURES['informal_markdown_index']
        c=module(firm).parse(report(text,firm,'md'))[0]
        self.assertEqual(c.record_kind,'summary_excerpt')
        self.assertEqual(c.printed_id,'IF-IBC-01')

    def test_conditional_severity_is_preserved(self):
        firm,text,_,_=FIXTURES['informal_conditional']
        c=module(firm).parse(report(text,firm))[0]
        self.assertEqual(c.normalized,'unknown')
        self.assertIn('arbitrary transactions',c.severity_raw)

    def test_status_tables_match_only_explicit_identity(self):
        cases=[('hexens',
                'ID    Severity    Status\nHEX-1    High    Fixed\n\n',
                'HEX-1\nMissing authorization\nSEVERITY: High'+D,
                'printed_id_status_table'),
               ('informalsystems',
                'Finding                         Type            Severity    Status\nRefund logic differs            Protocol        High        Acknowledged\n\n',
                'Refund logic differs\n ID IF-FINDING-001\n Severity High\n Type Protocol'+D,
                'printed_title_status_table')]
        for firm,index,detail,basis in cases:
            with self.subTest(firm=firm):
                r=report(index+'\f'+detail,firm)
                c=module(firm).parse(r)[0]
                self.assertEqual(c.evidence['status_evidence']['basis'],basis)
                s=c.evidence['status_evidence'];self.assertEqual(r.text[s['start']:s['end']],c.status_raw)
                altered=index.replace('HEX-1','HEX-2').replace('Refund logic differs','Different finding')+'\f'+detail
                self.assertIsNone(module(firm).parse(report(altered,firm))[0].status_raw)

    def test_printed_summary_conflict_is_independent_of_detail_counts(self):
        text=('Severity summary\nCritical 0\nHigh 0\nMedium 0\nLow 1\nInformational 0\n\n'
              'Finding                         Type            Severity    Status\n'
              'Refund logic differs            Protocol        Medium      Resolved\n')
        summary=printed_counts(report(text,'informalsystems'))
        self.assertTrue(summary['ambiguous'])
        self.assertEqual(summary['counts']['low'],1)
        self.assertEqual(summary['alternatives'][0]['counts'],{'medium':1})
        # A disagreeing detail card alone must never make a summary ambiguous.
        text=text.split('Finding                         Type')[0]+FIXTURES['informal_numeric'][1]
        self.assertFalse(printed_counts(report(text,'informalsystems')).get('ambiguous',False))

    def test_symbolic_methodology_examples_cannot_override_real_cards(self):
        firm,text,era,_=FIXTURES['hexens_symbolic_stacked']
        r=report('Symbolic code example: HEX-1.\nA reference to the printed code structure.\n'+text,firm)
        module(firm).parse(r)
        self.assertEqual(r.layout_selection['variant_id'],firm+'/'+era)

if __name__=='__main__':unittest.main()
