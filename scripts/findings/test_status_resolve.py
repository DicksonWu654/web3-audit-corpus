"""Status policy, standalone API, central writer and publisher evidence regressions."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, digest
from core import Candidate, candidate_status
from status_resolve import canonicalize_label, status, status_mapping, status_policy
from test_framework import report
from parsers import module

D = 'Description of the actual vulnerability and its impact.\n' * 4


class StatusResolverTests(unittest.TestCase):
    def test_spelling_and_negation(self):
        for text in ('**FIXED.**', 'F I X E D', '1. Fixed (2)', 'Ｆｉｘｅｄ','• (1) Fixed','a) Fixed'):
            self.assertEqual(canonicalize_label(text), 'fixed')
        self.assertNotEqual(canonicalize_label('Not fixed'), canonicalize_label('Fixed'))
        self.assertNotEqual(canonicalize_label('Partially fixed'), canonicalize_label('Fixed'))
        self.assertEqual(canonicalize_label('NO_ISSUE'), canonicalize_label('No Issue'))

    def test_native_examples(self):
        cases = [('abdk-consulting','Info','acknowledged'), ('abdk-consulting','I N F O','acknowledged'),
                 ('code4rena','confirmed','acknowledged'), ('code4rena','acknowledged','acknowledged'),
                 ('code4rena','disputed','not_stated'), ('code4rena','confirmed and patched','fixed'),
                 ('sherlock','Fixed','fixed'), ('sherlock',"Won’t fix",'acknowledged'),
                 ('sherlock','Acknowledged','acknowledged'), ('oxorio','NO_ISSUE','not_stated'),
                 ('oxorio','Invalid','not_stated'), ('macro','Wont Do','acknowledged'),
                 ('chainsecurity','Code Partially Corrected','partially_fixed'),
                 ('chainsecurity','Risk Accepted','acknowledged'), ('chainsecurity','Code Corrected','fixed'),
                 ('verichains','acknowledged and fixed','fixed')]
        for firm, raw, expected in cases:
            with self.subTest(firm=firm,raw=raw):
                result=status_mapping(raw,firm,log=False)
                self.assertEqual(result['normalized'],expected)
                self.assertEqual(result['input'],raw)

    def test_definition_selected_closed_semantics(self):
        self.assertEqual(status('Closed','iosiro'),'fixed')
        sha='d54806eccfd20e7deb67b55bb0915fa43c1d83bfb060f2e77602be2851a90a37'
        self.assertEqual(status('Closed','sigma-prime',sha256=sha),'acknowledged')
        self.assertEqual(status('Closed','sigma-prime',log=False),'not_stated')

    def test_unknown_missing_and_listed_are_distinct(self):
        missing=status_mapping(None,'sherlock')
        self.assertTrue(missing['mapped']);self.assertEqual(missing['normalized'],'not_stated')
        unknown=status_mapping('A newly invented status','sherlock',log=False)
        self.assertFalse(unknown['mapped']);self.assertEqual(unknown['normalized'],'not_stated')
        self.assertEqual(status('Info','sherlock',log=False),'not_stated')

    def test_json_yaml_parity(self):
        yaml=ROOT/'schema/status_map.json';js=ROOT/'schema/status_map.json'
        self.assertEqual(yaml.read_bytes(),js.read_bytes())
        for firm, entry in status_policy()[0]['publishers'].items():
            for era in entry['eras']:
                for label in era['labels']:
                    self.assertEqual(status_mapping(label,firm,era=era['id'],log=False),
                                     status_mapping(label,firm,era=era['id'],log=False,policy_path=js))

    def test_central_writer_ignores_parser_guess(self):
        from run import finding_rows
        r=report('## [H-01] Actual finding\n'+D+'Status: Fixed\n','code4rena')
        c=module('code4rena').parse(r)[0]
        c.normalized_status='info'
        doc={'document_id':'document:test','row':{'sha256':'a'*64,'file_format':'md',
             'doc_kind':'audit_report','public_url':'https://example.org'},
             'source_file':'test','source_locator':'line=1','source_record_sha256':'b'*64}
        row=list(finding_rows(doc,r,[c],'code4rena'))[0]
        self.assertEqual(row['status'],'fixed')
        self.assertEqual(row['status_original'],c.status_raw)
        self.assertEqual(row['status_mapping']['input'],c.status_raw)

    def test_eras_and_conflicting_aliases_fail_closed(self):
        policy={'policy':'test','unscoped_labels':{},'publishers':{'test':{'eras':[
            {'id':'old','definition_regex':'OLD TEMPLATE','labels':{'X':{'normalized':'acknowledged','rationale':'old'}}},
            {'id':'new','definition_regex':'NEW TEMPLATE','labels':{'X':{'normalized':'fixed','rationale':'new'}}}]}}}
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'policy.json';path.write_text(json.dumps(policy))
            self.assertEqual(status('X','test',report_text='OLD TEMPLATE',policy_path=path),'acknowledged')
            self.assertEqual(status('X','test',report_text='NEW TEMPLATE',policy_path=path),'fixed')
            self.assertEqual(status('X','test',report_text='OLD TEMPLATE NEW TEMPLATE',policy_path=path,log=False),'not_stated')
            self.assertEqual(status('X','test',policy_path=path,log=False),'not_stated')
            conflict=Path(folder)/'conflict.json'
            policy['publishers']['test']['eras']=[{'id':'default','default':True,'labels':{
                'Not_Fixed':{'normalized':'fixed','rationale':'bad alias'},
                'not fixed':{'normalized':'unresolved','rationale':'native negation'}}}]
            conflict.write_text(json.dumps(policy))
            with self.assertRaisesRegex(ValueError,'Conflicting status aliases'):
                status_mapping('not fixed','test',policy_path=conflict)

    def test_standalone_import_has_no_io_or_path_changes(self):
        program='''import builtins, importlib.util, os, sys
from pathlib import Path
path=sys.argv[1]
spec=importlib.util.spec_from_file_location('standalone_status',path)
module=importlib.util.module_from_spec(spec)
before=list(sys.path); cwd=os.getcwd()
def denied(*a,**k): raise AssertionError('import performed file IO')
builtins.open=denied
Path.read_bytes=denied
Path.read_text=denied
spec.loader.exec_module(module)
assert before==sys.path and cwd==os.getcwd()
'''
        subprocess.run([sys.executable,'-I','-B','-S','-c',program,str(ROOT/'scripts/findings/status_resolve.py')],check=True)


class PublisherStatusTests(unittest.TestCase):
    def read(self,firm,text,reader,expected,pid='H-1'):
        from importlib import import_module
        r=report(text,firm,'pdf' if firm not in ('code4rena','sherlock') else 'md')
        c=Candidate(0,'Actual issue','High',pid,end=len(text))
        getattr(import_module('parsers.'+firm.replace('-','_')),reader)(r,[c])
        self.assertEqual(c.status_raw,expected)
        if expected:
            proof=c.evidence['status_evidence']
            self.assertEqual(r.text[proof['start']:proof['end']],expected)
        return r,c

    def test_c4_sponsor_period_and_judge_exclusion(self):
        for suffix in ('.',':','', ' and commented:'):
            self.read('code4rena',D+'**lucas-manuel (Maple) acknowledged'+suffix+'\n','read_status','acknowledged')
        self.read('code4rena',D+'Judge (judge) confirmed.\n','read_status',None)
        self.read('code4rena',D+'```\nSponsor (Maple) confirmed.\n```\n','read_status',None)

    def test_sherlock_team_and_published_outcome(self):
        self.read('sherlock',D+'## Sentiment Team\nFixed as recommended.\n## Lead Senior Watson\nConfirmed fix.\n','read_status','Confirmed fix')
        self.read('sherlock','Source: https://example.org\nThis issue has been acknowledged by the team but won’t be fixed at this time.\n## Found by\nAlice\n'+D,'read_status','acknowledged')
        self.read('sherlock',D+'## Recommendation\nFixed code could avoid the issue.\n','read_status',None)
        self.read('sherlock',D+'## Discussion\n**maarcweiss**\n\nFixed by PR #10.\n','read_status','Fixed')
        self.read('sherlock',D+'## Discussion\n**Sherlock-admin**\n\nEscalations have been resolved successfully!\n','read_status',None)
        self.read('sherlock',D+'## Discussion\n**sherlock-admin2**\n\nThe protocol team fixed this issue in the following PRs/commits:\nhttps://example.org/commit/123\n','read_status','fixed')

    def test_coinspect_resolution_keeps_commit_and_recommendation_distinct(self):
        self.read('coinspect',D+'Resolution\nFixed in commit abcdef0.\n','resolution_status','Fixed')
        self.read('coinspect',D+'Resolution\nThis issue was acknowledged by the team.\n','resolution_status','acknowledged')
        self.read('coinspect',D+'Recommendations\nThe issue should be fixed.\n','resolution_status',None)

    def test_zellic_remediation_vs_recommendation(self):
        self.read('zellic',D+'Remediation\nThe issue has been acknowledged by the team, and they will add documentation.\n','read_status','acknowledged')
        self.read('zellic',D+'Recommendations\nThe issue should be fixed.\n','read_status',None)
        self.read('zellic','Finding    Status\n3.1        Remediated\n'+D,'read_status','Remediated',pid='3.1')

    def test_ackee_revision_solution(self):
        self.read('ackee-blockchain',D+'Solution (Revision 1.2)\n\nAcknowledged. Client response follows.\n','solution_status','Acknowledged')
        self.read('ackee-blockchain',D+'Solution (Revision 1.1)\nInvalidated, the design is intentional.\n','solution_status','Invalidated')
        self.read('ackee-blockchain',D+'Solution (Revision 1.1)\nFunctions have been renamed to safeTransfer.\n','solution_status','Functions have been renamed to safeTransfer.')

    def test_verichains_acknowledged_and_fixed(self):
        r,c=self.read('verichains',D+'UPDATES\nThis issue has been acknowledged and fixed by the team in commit abcdef0.\n','status_nested','acknowledged and fixed')
        self.assertEqual(candidate_status(r,c)['normalized'],'fixed')

    def test_chainsecurity_risk_accepted_is_not_fixed(self):
        r,c=self.read('chainsecurity',D+'Risk Accepted:\nThe team decided to leave the code as it is.\n','remediation_status','Risk Accepted')
        self.assertEqual(candidate_status(r,c)['normalized'],'acknowledged')

    def test_runtime_page_break_status_and_commit(self):
        self.read('runtime-verification',D+'\fStatus\n  Addressed in PR #31.\n','read_status','Addressed in PR #31.')
        self.read('runtime-verification',D+'\fStatus\n  Fix implemented in PR #49.\n','read_status','Fix implemented in PR #49.')
        self.read('runtime-verification',D+'\fStatus\nThe developers were fully aware of the issue and plan improvements.\n','read_status','fully aware of the issue')

    def test_certora_explicit_verified_later_version(self):
        self.read('certora',D+'We confirmed that it was fixed in the July 26 version.\n','status_issue_cards','fixed')

    def test_trail_of_bits_fix_log_links_id(self):
        r,c=self.read('trail-of-bits','1. Actual issue\n'+D+'Appendix C: Fix Log\nID   Title   Severity   Fix Status\n1    Actual issue    High    Fixed\n','read_status','Fixed',pid='1')
        self.assertEqual(c.evidence['status_evidence']['basis'],'trail_of_bits_fix_log_table')
        self.read('trail-of-bits','1. Actual issue\nID: TOB-AAVE-1\n'+D+'Detailed Fix Review Results\nTOB-AAVE-1: Actual issue\nRisk Accepted. The client supplied context.\n','read_status','Risk Accepted',pid='1')

    def test_coinspect_resolution_keeps_negation(self):
        self.read('coinspect',D+'Resolution\nNot fixed.\n','resolution_status','Not fixed')

    def test_codespect_overview_cell(self):
        from parsers.codespect import read_status
        r=report('1    Actual issue title    High    Acknowledged\n','codespect','pdf')
        c=Candidate(0,'Actual issue title','High','1',end=len(r.text),record_kind='summary_excerpt')
        read_status(r,[c]);self.assertEqual(c.status_raw,'Acknowledged')

    def test_neodyme_publisher_verified_fix(self):
        self.read('neodyme',D+'Neodyme verified the fix.\n','peer_status','verified the fix')


if __name__=='__main__':unittest.main()
