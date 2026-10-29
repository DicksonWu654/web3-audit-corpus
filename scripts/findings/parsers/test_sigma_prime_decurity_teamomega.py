"""Synthetic regressions for the three Phase 4b publisher parsers; no report reads."""
import unittest
from common import digest
from core import Report, finish
from parsers import sigma_prime, decurity, teamomega


def report(text, firm, fmt='pdf'):
    pages=[];start=0
    for i,value in enumerate(text.split('\f'),1):
        pages.append({'page':i,'start':start,'end':start+len(value),'text':value})
        start+=len(value)+1
    return Report(text,{'pages':pages,'file_format':fmt,'text_sha256':digest(text.encode())},firm)


class PublisherTests(unittest.TestCase):
    def test_sigma_split_identifier_and_wrapped_title(self):
        text='TST2-       Wrapped title\n01\nAsset       Token.sol\nStatus      Closed: See Resolution\nRating      Severity: High\n\nDescription\n'+('Details. '*20)
        r=report(text,'sigma-prime');c=finish(r,sigma_prime.parse(r))[0]
        self.assertEqual((c.printed_id,c.title,c.severity_raw,c.status_raw),('TST2-01','Wrapped title','High','Closed'))

    def test_sigma_title_above_identifier(self):
        text='\n    Title before the identifier\nTST-01\n    Continued title\n\nAsset Token.sol\nStatus Open\nRating Informational\n\nDescription\n'+('Details. '*20)
        c=sigma_prime.parse(report(text,'sigma-prime'))[0]
        self.assertEqual(c.title,'Title before the identifier Continued title')

    def test_sigma_summary_uses_risk_column_and_continuation(self):
        text='Summary of Findings\nID  Description  Severity  Status\nTST-01  Critical title  Low  Closed\n\fTST-02  Second  Informational  Resolved\n\fTST-01  Critical title\nAsset Token.sol\nStatus Closed\nRating Severity: Low\n\nDescription\n'+('Details. '*20)
        r=report(text,'sigma-prime')
        self.assertEqual(sigma_prime.printed_counts(r)['counts'],{'low':1,'info':1})
        self.assertEqual(len(sigma_prime.parse(r)),1)

    def test_sigma_summary_cannot_create_detail(self):
        r=report('ID  Description  Severity  Status\nTST-01  Only overview  High  Open\n','sigma-prime')
        self.assertEqual(sigma_prime.parse(r),[])
        self.assertEqual(sigma_prime.printed_counts(r)['counts'],{'high':1})

    def test_sigma_markdown_new_sections(self):
        r=report('## 1. INF: Actual title\n'+('Details. '*20)+'\n## Miscellaneous\n### M1. Minor note\n'+('Details. '*20)+'\n## Gas Optimisations\n### G1. Cache data\n'+('Details. '*20),'sigma-prime','md')
        self.assertEqual([(c.printed_id,c.normalized) for c in sigma_prime.parse(r)],[('1','info'),('M1','unknown'),('G1','gas')])

    def test_decurity_wrapped_title_and_zero_width(self):
        r=report('5.1.\u200b First part of\n    wrapped title\nRisk Level: Medium\nStatus: Fixed\nDescription:\n'+('Details. '*20)+'\n6. Appendix\nboilerplate','decurity')
        c=decurity.parse(r)[0]
        self.assertEqual(c.title,'First part of wrapped title')
        self.assertEqual(c.severity_raw,'Medium')
        self.assertNotIn('boilerplate',r.text[c.start:c.end])

    def test_decurity_no_severity_borrowing(self):
        r=report('4.1. Non-finding\n4.2. Real finding\nRisk Level: High\nDescription:\n'+('Details. '*20),'decurity')
        self.assertEqual([c.printed_id for c in decurity.parse(r)],['4.2'])

    def test_decurity_verification_and_legacy_unknown(self):
        r=report('2.1.3 [Medium] No address check\n'+('Details. '*20),'decurity')
        self.assertEqual(decurity.parse(r)[0].severity_raw,'Medium')
        r=report('4.1.1 Legacy issue\nSummary:\n'+('Details. '*20),'decurity')
        self.assertIsNone(decurity.parse(r)[0].severity_raw)

    def test_decurity_independent_suggestions(self):
        r=report('Issue  Contract  Risk Level  Status\nMissing detail  T.sol  High  Fixed\n3. General Recommendations\nText.','decurity')
        self.assertEqual(decurity.parse(r),[])
        self.assertEqual(decurity.printed_counts(r)['counts'],{'high':1})

    def test_decurity_legacy_risk_probability_columns(self):
        text='Issue                         Risk Level   Probability   Status\nFirst title                   Low          High          Fixed\nSecond title                  Medium       Low           Fixed\n3 GENERAL RECOMMENDATIONS\nText\n4 DETAILS\n4.1.1 First title\nSummary:\n'+('Details. '*20)+'\n4.1.2 Second title\nSummary:\n'+('Details. '*20)
        cs=decurity.parse(report(text,'decurity'))
        self.assertEqual([c.severity_raw for c in cs],['Low','Medium'])
        self.assertTrue(all(c.evidence.get('severity_evidence') for c in cs))

    def test_omega_id_variations_and_status_wrap(self):
        r=report('-IT1b. Repeated scope issue [medium] [partially\nresolved]\n'+('Details. '*20)+'\nDEA1 Missing separator [low] [resolved]\n'+('Details. '*20)+'\nG4.No space [info] [not resolved]\n'+('Details. '*20),'teamomega')
        cs=teamomega.parse(r)
        self.assertEqual([c.printed_id for c in cs],['IT1b','DEA1','G4'])
        self.assertEqual(cs[0].status_raw,'partially resolved')
        self.assertEqual(cs[2].title,'No space')

    def test_omega_wrapped_toc_is_excluded(self):
        toc='Summary  2\nScope  3\nMethods  3\nDisclaimer  4\nFindings  5\nGeneral  5\nG1. Wrapped [high]\n[resolved]  5\nOther  5\n'
        r=report(toc+'\fG1. Wrapped [high] [resolved]\n'+('Details. '*20),'teamomega')
        self.assertEqual(len(teamomega.parse(r)),1)

    def test_omega_same_ids_in_distinct_scopes_retained(self):
        r=report('G1. First [low]\n'+('Details. '*20)+'\nG1. Second [info]\n'+('Details. '*20),'teamomega')
        self.assertEqual([c.title for c in teamomega.parse(r)],['First','Second'])

    def test_omega_legacy_single_space_page_and_stale_status(self):
        toc='Summary  2\nScope  3\nMethods  3\nDisclaimer  4\nFindings  5\nGeneral  5\nFirst issue [resolved] 5\nSecond issue [resolved]  6\n'
        body='First issue [not resolved]\n'+('Details. '*20)+'\nSeverity: Low\nStatus: Not Resolved\n\nSecond issue [resolved]\n'+('Details. '*20)+'\nSeverity: Medium\nStatus: Resolved\n'
        cs=teamomega.parse(report(toc+'\f'+body,'teamomega'))
        self.assertEqual([(c.title,c.severity_raw) for c in cs],[('First issue','Low'),('Second issue','Medium')])


if __name__=='__main__':
    unittest.main()
