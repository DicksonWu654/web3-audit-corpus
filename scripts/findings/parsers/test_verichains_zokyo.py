"""Focused regression tests for publisher layout failures, with in-memory source only."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import digest
from core import Report, finish
from parsers import verichains, zokyo


def report(pages,firm):
    text='\f'.join(pages);start=0;meta=[]
    for i,p in enumerate(pages,1):
        meta.append({'page':i,'start':start,'end':start+len(p),'text':p});start+=len(p)+1
    return Report(text,{'pages':meta,'text_sha256':digest(text.encode()),'file_format':'pdf'},firm)
D='The publisher describes the issue and provides substantial source evidence.\n'*2


class PublisherTests(unittest.TestCase):
    def test_verichains_contracts_excluded_and_notes_retained(self):
        r=report(['2. AUDIT RESULT\n2.2. Contract codes\n2.2.1. SafeMath library\n'+D+'2.3. Findings\n2.3.1. Real issue [HIGH]\n'+D+'2.4. Additional notes and recommendations\n2.4.1. Code style [INFO]\n'+D+'3. VERSION HISTORY\nA later table'], 'verichains')
        rows=finish(r,verichains.parse(r))
        self.assertEqual([c.printed_id for c in rows],['2.3.1','2.4.1'])
        self.assertEqual([c.severity_raw for c in rows],['HIGH','INFO'])
        self.assertNotIn('VERSION HISTORY',r.text[rows[-1].start:rows[-1].end])

    def test_verichains_icon_risk_stays_unknown(self):
        r=report(['2. AUDIT RESULT\n2.2. Findings\n2.2.1. - Missing validation\n'+D], 'verichains')
        c=verichains.parse(r)[0]
        self.assertIsNone(c.severity_raw)
        self.assertEqual(c.title,'Missing validation')

    def test_verichains_modern_heading_and_status(self):
        r=report(['3. Solana Findings\n # Title Severity Status\n 1 Actual issue HIGH Fixed\n3.1. HIGH - Actual issue - FIXED\n'+D+'4. Onchain Overview\nOther text'], 'verichains')
        c=verichains.parse(r)[0]
        self.assertEqual((c.title,c.severity_raw,c.status_raw),('Actual issue','HIGH','FIXED'))
        self.assertNotIn('Onchain Overview',r.text[c.start:c.end])

    def test_verichains_toc_continues_and_unnumbered_body(self):
        r=report(['TABLE OF CONTENTS\n2.2. Findings ........ 6\n2.2.1. First issue ........ 6\n2.2.2. Second issue ........ 6\n2.2.3. Third issue ........ 6',
                  '2.2.4. Fourth issue ........ 7\n2.2.5. Fifth issue ........ 7\n3. VERSION HISTORY ........ 8',
                  '2.2. Findings\nFirst issue\n'+D+'Second issue\n'+D+'Third issue\n'+D+'Fourth issue\n'+D+'Fifth issue\n'+D], 'verichains')
        self.assertEqual(len(verichains.parse(r)),5)
        self.assertEqual(len(verichains.sequence_evidence(r)['ids']),5)

    def test_verichains_legacy_risks_and_recommendations_stay_distinct(self):
        r=report(['VULNERABILITIES FINDINGS\nFIXED CRITICAL\nWRONG DATA LOCATION\n\n'+D+'OTHER RECOMMENDATIONS / SUGGESTIONS\n• Improve compiler version\n'+D+'CONCLUSION\nOther narrative'], 'verichains')
        rows=verichains.parse(r)
        self.assertEqual([c.record_kind for c in rows],['formal_finding','recommendation'])
        self.assertEqual((rows[0].severity_raw,rows[0].status_raw),('CRITICAL','FIXED'))
        self.assertEqual(verichains.sequence_evidence(r)['expected_count'],1)
        self.assertNotIn('CONCLUSION',r.text[rows[-1].start:rows[-1].end])

    def test_zokyo_legacy_title_precedes_risk(self):
        r=report(['Structure\nThe severity of each issue is written below\nMedium\n',
                  'Complete\u200b\u200bAnalysis\n\nAdmin can set any fee\n\n HIGH\n\n'+D], 'zokyo')
        c=zokyo.parse(r)[0]
        self.assertEqual(c.title,'Admin can set any fee')
        self.assertEqual(c.severity_raw,'HIGH')

    def test_zokyo_lowercase_badge_precedes_title(self):
        r=report(['Complete Analysis\nToken.sol\n\n informational\n\nUnused code\n\n'+D+'informational\n\nUnnecessary code\n\n'+D], 'zokyo')
        rows=finish(r,zokyo.parse(r))
        self.assertEqual([c.title for c in rows],['Unused code','Unnecessary code'])

    def test_zokyo_unnumbered_cards_and_test_footer(self):
        r=report(['The severity of each issue is written below\nMedium\n',
                  'Complete Analysis\nMedium RESOLVED\n\nBroken operation\n\n'+D+'Low invalid\n\nInvalid assumption\n\n'+D+'Code Coverage and Test Results\nHigh\nFake test severity'], 'zokyo')
        rows=zokyo.parse(r)
        self.assertEqual([c.status_raw for c in rows],['RESOLVED','invalid'])
        self.assertNotIn('Code Coverage',r.text[rows[-1].start:rows[-1].end])

    def test_zokyo_decimal_id_qualifier_and_repeated_round(self):
        r=report(['Complete Analysis\n7 INFO-3.4 UNRESOLVED\nFirst title\n\n'+D+'Informational-6 (Gas) Acknowledged\nSecond title\n\n'+D+'INFO-3.4 Resolved\nRecheck title\n\n'+D], 'zokyo')
        rows=zokyo.parse(r)
        self.assertEqual([c.printed_id for c in rows],['INFO-3.4','Informational-6','INFO-3.4'])
        self.assertEqual(rows[1].severity_raw,'Informational')
        self.assertEqual(rows[1].evidence['severity_qualifier'],'Gas')

    def test_zokyo_summary_continuation_never_details(self):
        r=report(['Complete Analysis\nFindings summary\n1 First issue    High Resolved\n',
                  '2 Second issue    Low Resolved\n',
                  'High-1 Resolved\nFirst issue\n\n'+D+'Low-1 Resolved\nSecond issue\n\n'+D], 'zokyo')
        self.assertEqual(len(zokyo.parse(r)),2)
        self.assertEqual(zokyo.sequence_evidence(r)['expected_count'],2)

    def test_zokyo_closing_prose_does_not_end_on_we_are_advised(self):
        r=report(['Complete Analysis\nHigh-1 Partially Resolved\nReal issue\n\n'+D+'We are advised to check a value.\nLow-1 Acknowledge\nAnother issue\n\n'+D+'We are grateful for the opportunity.'], 'zokyo')
        rows=zokyo.parse(r)
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[-1].status_raw,'Acknowledge')

    def test_zokyo_aggregate_contradiction_does_not_relabel_details(self):
        r=report(['Hypothetical Scoring Calculation:\nStarting with a perfect score of 100:\nUnicode \u200b stays in source coordinates.\n- 1 Critical issue: 0 points deducted\n- 0 High issues: 0 points deducted\n',
                  'Complete Analysis\nHigh-1 Resolved\nReal issue\n\n'+D], 'zokyo')
        self.assertEqual(zokyo.printed_counts(r)['counts'],{'critical':1,'high':0})
        self.assertEqual(zokyo.parse(r)[0].severity_raw,'High')
        for e in zokyo.printed_counts(r)['evidence']:
            self.assertEqual(e['text'],r.text[e['start']:e['end']])

    def test_zokyo_inline_legacy_and_metadata_fields(self):
        r=report(['Complete Analysis\nLow severity, Unresolved: Missing check\n'+D+'Informational,Unresolved: Excess authority\n'+D], 'zokyo')
        self.assertEqual(len(zokyo.parse(r)),2)
        r=report(['Findings\nHardcoded API key\nSeverity Medium\nStatus FIXED\n'+D], 'zokyo')
        c=zokyo.parse(r)[0]
        self.assertEqual((c.title,c.severity_raw,c.status_raw),('Hardcoded API key','Medium','FIXED'))

if __name__=='__main__':unittest.main()
