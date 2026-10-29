"""Publisher regressions for independently printed risk, detail-only IDs, and body bounds."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/findings'))
from common import ROOT, digest, holdouts, read_snapshot
from core import Report, finish, severity
from parsers import three_sigma, coinspect, sec3


def report(text,firm):
    pages=[];start=0
    for n,value in enumerate(text.split('\f'),1):
        pages.append({'page':n,'start':start,'end':start+len(value),'text':value})
        start+=len(value)+1
    return Report(text,{'file_format':'pdf','text_sha256':digest(text.encode()),'pages':pages},firm)


class ThreeSigmaRegression(unittest.TestCase):
    def test_final_classification_beats_impact_and_id(self):
        text='''Table of Contents
3S-Client Labs-L01       18
\fFindings
3S-Client Labs-L01
Wrapped title about the
withdrawal function
 Id                3S-Client Labs-L01
 Classification    Low
 Severity          High
 Likelihood        Low
 Status            Acknowledged

Description
Sufficient detail to establish the independently printed final classification.
'''
        rows=finish(report(text,'three-sigma'),three_sigma.parse(report(text,'three-sigma')))
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0].severity_raw,'Low')
        self.assertEqual(rows[0].printed_id,'3S-Client Labs-L01')
        self.assertEqual(rows[0].title,'Wrapped title about the withdrawal function')
        self.assertEqual(rows[0].status_raw,'Acknowledged')
        self.assertNotIn('Table of Contents',text[rows[0].start:rows[0].end])

    def test_empty_project_legacy_space_and_unknown_none(self):
        text='''3S--N01
A suggestion
 Id     3S--N01
 Classification      None

Description
This suggestion has no recognized article severity label.
3S MAPLE-02
A legacy title
 Id     3S MAPLE-02
 Severity       Low

Description
A substantive legacy finding with its own printed identifier.

Status
Fixed in commit abcdef.
'''
        r=report(text,'three-sigma');rows=finish(r,three_sigma.parse(r))
        self.assertEqual([c.printed_id for c in rows],['3S--N01','3S MAPLE-02'])
        self.assertEqual(severity(rows[0].severity_raw),'unknown')
        self.assertEqual(rows[1].status_raw,'Fixed in commit abcdef.')

    def test_status_after_page_number_is_not_a_numeric_footer(self):
        text='''3S-Test-M01
A finding whose status crosses a page
 Id            3S-Test-M01
 Classification       Medium

Description
The actual description contains enough context to establish a real finding.

Status
42
\f43

Addressed in PR #123.
'''
        r=report(text,'three-sigma');cs=finish(r,three_sigma.parse(r))
        self.assertEqual(cs[0].status_raw,'Addressed in PR #123.')

    def test_legacy_dashboard_does_not_manufacture_findings(self):
        text='''Project Dashboard
Nº Critical Severity Issues        3
Nº High Severity Issues            0
Nº Medium Severity Issues          1
Nº Low Severity Issues             2
'''
        r=report(text,'three-sigma')
        self.assertEqual(three_sigma.printed_counts(r)['counts'],{'critical':3,'high':0,'medium':1,'low':2})
        self.assertEqual(three_sigma.parse(r),[])


class CoinspectRegression(unittest.TestCase):
    def test_summary_last_id_cannot_borrow_next_page_metadata(self):
        text='''Summary Of Findings
 ID       Description                  Risk
 AAA-02   Second title                 High
\f5. Findings
 AAA-01   First title
 Total Risk      Impact      Location
 Medium          High        Contract.sol

Description
The first real detail is distinct from the final summary-table entry.
'''
        r=report(text,'coinspect');cs=finish(r,coinspect.parse(r))
        self.assertEqual([c.printed_id for c in cs],['AAA-01'])
        self.assertEqual(cs[0].severity_raw,'Medium')

    def test_inline_total_risk_and_appendix_bound(self):
        text=''' ZCA-001     Wrapped title
             continuation
 Category    Availability
 Total Risk  Low | Impact: High | Likelihood: Low

Description
This detailed finding includes genuine prose and recommendations.

6. Appendix: independent tests
Appendix material must not be copied into this finding.
'''
        r=report(text,'coinspect');cs=finish(r,coinspect.parse(r))
        self.assertEqual(cs[0].title,'Wrapped title continuation')
        self.assertEqual(cs[0].severity_raw,'Low')
        self.assertNotIn('Appendix',text[cs[0].start:cs[0].end])

    def test_modern_card_uses_risk_not_impact_and_keeps_resolution(self):
        text=''' GRM-01
 Funds remain locked
 after vesting

       Status                   Risk
       Solved                   Medium

                                Impact
                                High
       Resolution               Likelihood
                                High
       Deferred

Description
The explicit risk differs from impact and the solution is deferred.
'''
        r=report(text,'coinspect');cs=finish(r,coinspect.parse(r))
        self.assertEqual(cs[0].severity_raw,'Medium')
        self.assertEqual(cs[0].status_raw,'Solved')
        self.assertEqual(cs[0].evidence['resolution_raw'],'Deferred')
        self.assertEqual(cs[0].title,'Funds remain locked after vesting')

    def test_zero_risk_survives_as_unknown_and_status_is_explicit(self):
        text='''  WBTC-1       A risk-free suggestion
  Total Risk       Impact      Location
                   Low         Factory.sol
   Zero
                 Likelihood    Status
    Fixed
                   Low         Not Fixed
      ✖

Description
This source labels the finding Zero, which remains an unmapped severity.
'''
        r=report(text,'coinspect');cs=finish(r,coinspect.parse(r))
        self.assertEqual(cs[0].severity_raw,'Zero')
        self.assertEqual(severity(cs[0].severity_raw),'unknown')
        self.assertEqual(cs[0].status_raw,'Not Fixed')

    def test_ocr_grid_headers_are_not_title_continuations(self):
        text=''' LFX-01      An OCR-era title
                Impa t       Lo ation
                High         https://example.test/
 Total Risk     Likelihood   Cate o
 Critical       Low          Validation

Description
The title must stop before the visually separated metadata columns.
'''
        r=report(text,'coinspect');cs=finish(r,coinspect.parse(r))
        self.assertEqual(cs[0].title,'An OCR-era title')


class Sec3Regression(unittest.TestCase):
    def test_compound_ids_status_and_question_remain_unknown(self):
        text='''Table of Contents
[P1-M-01] Main finding ............................... 4
[P2-Q-01] Question ................................... 5
\fResult Overview
Issue                                  Impact        Status
[P1-M-01] Main finding                  Medium        Resolved
[P2-Q-01] Question                      Question      Acknowledged
\fFindings in Detail
[P1-M-01] Main finding
The prose immediately follows and must never enter the title.

[P2-Q-01] Question

The publisher explicitly classified this as a question, not informational.

Appendix: Methodology and Scope of Work
Unrelated appendix material.
'''
        r=report(text,'sec3');cs=finish(r,sec3.parse(r))
        self.assertEqual([c.printed_id for c in cs],['P1-M-01','P2-Q-01'])
        self.assertEqual(cs[0].title,'Main finding')
        self.assertEqual(cs[0].status_raw,'Resolved')
        self.assertEqual(severity(cs[1].severity_raw),'unknown')
        self.assertNotIn('Appendix',text[cs[-1].start:cs[-1].end])

    def test_helium_ids_and_numeric_array_entries(self):
        text='''Result Overview
[L-1-1] Main finding                    Low            Resolved
[01] Additional unlabeled team finding                Resolved
Findings in Detail
[L-1-1] Main finding

The detail contains a console output array and an additional team finding.
[0] account_address_1234567
[1] account_address_7654321

[01] Additional unlabeled team finding

This is explicitly a separate detailed team finding without any source severity.
DISCLAIMER
Separate disclaimer text.
'''
        r=report(text,'sec3');cs=finish(r,sec3.parse(r))
        self.assertEqual([c.printed_id for c in cs],['L-1-1','01'])
        self.assertIsNone(cs[1].severity_raw)
        self.assertEqual(cs[1].normalized,'unknown')


@unittest.skipUnless((ROOT/'data/holdout/gold_sha256.txt').is_file(), 'Requires locally acquired corpus and holdout inputs')
class GuardedDevelopmentRegression(unittest.TestCase):
    """Fixed nonholdout source examples verify actual PDF layouts when the cache exists."""
    @classmethod
    def setUpClass(cls):
        cls.blocked=holdouts(ROOT)
        cls.docs={d['row']['sha256']:d for d in read_snapshot(ROOT)}

    def load(self,sha):
        self.assertNotIn(sha,self.blocked)
        if sha not in self.docs:
            self.skipTest('Development example absent from this frozen snapshot')
        from parsers.three_sigma_evidence import load
        return load(self.docs[sha])

    def test_coinspect_late_appendix_and_ocr_titles(self):
        r=self.load('89798ba3a2d2398da9a3b83c5d08483a7cba57b531b845daa4f827aca336d6cf')
        cs=finish(r,coinspect.parse(r))
        self.assertEqual(len(cs),10)
        self.assertEqual(cs[0].title,'Negative Withdrawal Amount Increments Balance')
        self.assertNotIn('General Conclusions',r.text[cs[-1].start:cs[-1].end])
        r=self.load('42c6eeb699ff79e6982b6c5b8e2267eaa7780618f2a72ef4c238cc18d3d56432')
        cs=finish(r,coinspect.parse(r))
        self.assertEqual(len(cs),9)
        self.assertNotIn('10. Appendix',r.text[cs[-1].start:cs[-1].end])

    def test_sec3_helium_and_multiproject_ids(self):
        r=self.load('67c78cf9df06f298f487a9d130ccffc3963ea4b59fb593b96041e485d0dd4f4a')
        cs=finish(r,sec3.parse(r))
        self.assertEqual(len(cs),25)
        self.assertEqual(next(c for c in cs if c.printed_id=='H-5-2').title,'Self-transfer accounting')
        r=self.load('99900e2858b5905246bbe13e656617c90b053b0bba618f98b99824a913307374')
        cs=finish(r,sec3.parse(r))
        self.assertEqual(len(cs),30)
        self.assertEqual(cs[-1].printed_id,'P2-Q-01')
        self.assertEqual(severity(cs[-1].severity_raw),'unknown')

    def test_three_sigma_preserves_publisher_contradiction(self):
        r=self.load('98b5601dd6e4bb7cae320331ed7537680f5a4348e7fa7f9f3d9d05dcd57ebcc7')
        cs=finish(r,three_sigma.parse(r))
        c=next(c for c in cs if c.printed_id=='3S-TRADE-M04')
        self.assertEqual(c.severity_raw,'High')
        self.assertEqual(three_sigma.printed_counts(r)['counts']['high'],1)
        self.assertEqual(sum(c.severity_raw=='High' for c in cs),2)


if __name__=='__main__':unittest.main()
