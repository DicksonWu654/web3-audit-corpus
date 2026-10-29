"""Regression checks for group 4's parent-owned layout boundaries."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from common import digest, holdouts, read_snapshot, ROOT
from core import Report, finish, status
from parsers import certora, movebit, scalebit, ncc_group, peckshield

def report(text,firm,fmt='pdf'):
    parts=text.split('\f');offset=0;pages=[]
    for n,t in enumerate(parts,1):
        pages.append({'start':offset,'end':offset+len(t),'text':t,'page':n});offset+=len(t)+1
    return Report(text,{'pages':pages,'file_format':fmt},firm)


class Group4LayoutTests(unittest.TestCase):
    def test_certora_detail_conflict_does_not_hide_numeric_summary_mismatch(self):
        r=report('Findings Summary\nCritical 0\nHigh 1\nMedium 0\nLow 0\nInformational 0\nDetailed Findings\nHigh Severity Issues\nH-1. Source has contradictory labels\nSeverity: Medium\nDescription\nThe explicit risk field disagrees with the printed ID prefix.\n','certora')
        summary=certora.printed_counts(r)
        self.assertFalse(summary.get('ambiguous',False))
        self.assertEqual(summary['counts']['high'],1)
        self.assertEqual(certora.parse(r)[0].normalized,'medium')

    def test_native_omega_status_synonyms_keep_existing_interpretations(self):
        self.assertEqual([status(x) for x in ['not resolved','in progress','resolved*','partially resolved','fixed']],['open','open','resolved','partial','fixed'])

    def test_peckshield_appendix_is_not_a_finding_and_title_wraps(self):
        r=report('3.1 Duplicate Validation Avoidance in\n    BlastooorStrategyAgentAccount\n\n • ID: PVE-001     • Target: Account\n • Severity: Low    • Category: Coding Practices\nDescription\nA concrete finding narrative long enough to retain.\nStatus This issue has been fixed in commit abc123.\n\n5 Appendix\n5.1 Basic Coding Bugs\n • Severity: Critical\nThis section describes the checklist rather than a finding.\n','peckshield')
        found=finish(r,peckshield.parse(r));self.assertEqual(len(found),1)
        self.assertEqual(found[0].title,'Duplicate Validation Avoidance in BlastooorStrategyAgentAccount')
        self.assertEqual(found[0].status_raw,'fixed')
        self.assertNotIn('5.1',r.text[found[0].start:found[0].end])

    def test_peckshield_chinese_native_labels_and_legacy_font(self):
        r=report('严重性 发现个数\n严重 0\n高危 1\n中危 0\n低危 0\n参考 0\n\n3.1 不完整创世状态影响后续升级\n • 光兄儺 児兖充儭儰儰儱 • 目标儺 module\n • 危害性儺 高 • 类型儺 test\n描述\n此处保留原文，匹配过程不改变证据字符位置。\n','peckshield')
        found=finish(r,peckshield.parse(r));self.assertEqual(found[0].printed_id,'PVE-001')
        self.assertEqual((found[0].severity_raw,found[0].normalized),('高','high'))
        self.assertEqual(peckshield.printed_counts(r)['counts']['high'],1)

    def test_movebit_component_ids_and_major_minor_are_explicit(self):
        r=report('1.3 Issue Statistic\nMajor 1 1\nMinor 1 0 1\n\nCPG_STAKING-01 Incorrect Variable\nAssignment\nSeverity: Major\nStatus: Partially Fixed\nDescriptions: A real finding with its own narrative.\n\nLPD_STAKING-02 Missing Test\nComments\nSeverity: Minor\nStatus: Acknowledged\nDescriptions: A distinct finding with an independent title.\n\n6 Disclaimer\nLegal text is outside the finding.\n','movebit')
        a=finish(r,movebit.parse(r));b=finish(r,scalebit.parse(r));self.assertEqual([c.printed_id for c in a],['CPG_STAKING-01','LPD_STAKING-02'])
        self.assertEqual([c.title for c in a],[c.title for c in b]);self.assertEqual(a[0].status_raw,'Partially Fixed')
        self.assertEqual(movebit.printed_counts(r)['counts'],{'high':1,'info':1})
        self.assertNotIn('Disclaimer',r.text[b[-1].start:b[-1].end])

    def test_ncc_legacy_and_modern_ids_are_not_sequence_numbers(self):
        text='Finding Wrong List of Peaks\nReturned by get_peaks()\n\nRisk High   Impact: High, Exploitability: Low\nIdentifier NCC-1908_Zcash-002\nStatus Fixed\nDescription A detailed explanation of the actual issue.\n\fLow   Missing Upper Bound\n      on Message Size\n      Overall Risk Low    Finding ID NCC-E024606-RVN\n      Impact Low          Component node\n      Exploitability Low  Status Partially Fixed\nDescription The second issue has a wrapped title and opaque identifier.\nAppendix A: Finding Field Definitions\nRisk Scale\n'
        r=report(text,'ncc-group');a=finish(r,ncc_group.parse(r))
        self.assertEqual([c.printed_id for c in a],['NCC-1908_Zcash-002','NCC-E024606-RVN'])
        self.assertEqual(a[1].title,'Missing Upper Bound on Message Size')
        self.assertEqual(a[1].status_raw,'Partially Fixed')
        self.assertNotIn('Appendix',r.text[a[-1].start:a[-1].end])


if __name__=='__main__':unittest.main()
