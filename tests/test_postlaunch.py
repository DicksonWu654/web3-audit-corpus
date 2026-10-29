"""Source-bound regressions for the post-launch integration."""
from pathlib import Path
import json
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/findings'))
from core import Report, finish
from common import digest
from parsers import module


class HackenDetails(unittest.TestCase):
    def test_parent_grade_and_status_are_source_bound(self):
        text='''Audit overview
Critical
1. Owner can withdraw all pool funds
Contracts: Pool.sol
Recommendation: restrict withdrawals to available funds.
Status: fixed.
High
No high severity issues were found.
Low
1. Unused variable
The variable can be removed without affecting program behavior.
Conclusion
As a result of the audit, security engineers found 1 critical and 1 low issues.
'''
        report=Report(text,dict(file_format='pdf',text_sha256=digest(text.encode()),
            pages=[dict(page=1,start=0,end=len(text),text=text)]),'hacken')
        parser=module('hacken');findings=finish(report,parser.parse(report))
        self.assertEqual([f.severity_raw for f in findings],['Critical','Low'])
        self.assertEqual(findings[0].status_raw,'fixed')
        self.assertNotIn('Conclusion',text[findings[-1].start:findings[-1].end])
        summary=parser.printed_counts(report)
        self.assertEqual(summary['counts'],dict(critical=1,low=1))
        for proof in summary['evidence']:self.assertEqual(text[proof['start']:proof['end']],proof['text'])
        variant=text.replace('Audit overview','Issues overview:')
        report=Report(variant,dict(file_format='pdf',text_sha256=digest(variant.encode()),
            pages=[dict(page=1,start=0,end=len(variant),text=variant)]),'hacken')
        self.assertEqual([f.severity_raw for f in finish(report,parser.parse(report))],['Critical','Low'])
        variant=text.replace('Audit overview','Findings')
        report=Report(variant,dict(file_format='pdf',text_sha256=digest(variant.encode()),
            pages=[dict(page=1,start=0,end=len(variant),text=variant)]),'hacken')
        self.assertEqual([f.severity_raw for f in finish(report,parser.parse(report))],['Critical','Low'])

    def test_summaries_and_definitions_never_become_findings(self):
        text='Severity Definitions\nCritical\nCritical vulnerabilities cause loss.\n1. Example risk\n'
        r=Report(text,dict(file_format='pdf',text_sha256=digest(text.encode()),
            pages=[dict(page=1,start=0,end=len(text),text=text)]),'hacken')
        self.assertEqual(module('hacken').parse(r),[])

    def test_empty_status_does_not_consume_running_footer(self):
        text='Audit overview\nLow\n1. A source finding with an empty status field\nRecommendation: use a constant here.\nStatus:\nwww.hacken.io\nConclusion\n'
        r=Report(text,dict(file_format='pdf',text_sha256=digest(text.encode()),
            pages=[dict(page=1,start=0,end=len(text),text=text)]),'hacken')
        found=finish(r,module('hacken').parse(r))
        self.assertEqual(len(found),1)
        self.assertIsNone(found[0].status_raw)


class SourceNotices(unittest.TestCase):
    def test_report_disclosure_clauses_withhold(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('postlaunch_release_common',ROOT/'scripts/release/common.py')
        common=importlib.util.module_from_spec(spec);spec.loader.exec_module(common)
        clauses=["This report may not be transmitted, disclosed, referred to or relied upon by any person for any purposes without CertiK’s prior written consent.",
            "This document may contain confidential information about IT systems. The report containing confidential information can be used internally by the Customer, or it can be disclosed publicly after all vulnerabilities are fixed — upon a decision of the Customer."]
        for text in clauses:
            self.assertIsNotNone(common.find_notice(text))
        self.assertIsNone(common.find_notice('The contract transmitted tokens before checking the receiver.'))


class JsonlBoundaries(unittest.TestCase):
    def test_certik_enters_the_shared_primary_finding_stream(self):
        from streams import finding_rows
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            row=dict(finding_id='finding:certik-public',document_id='document:public',publisher_finding_id='C-01')
            (root/'certik.jsonl').write_text(json.dumps(row)+'\n')
            self.assertEqual([r for _,r in finding_rows(root)],[row])

    def test_certik_copies_exclude_publisher_controlled_hosts(self):
        sys.path.insert(0,str(ROOT/'scripts/build'))
        from check_db import certik_public_copy
        self.assertTrue(certik_public_copy('collected','website','https://docs.example.org/certik.pdf'))
        self.assertTrue(certik_public_copy('collected','github','https://github.com/project/reports/blob/'+'a'*40+'/report.pdf'))
        for host in ('certik.com','skynet.certik.com','certik.org','certik.io','certik-audits.s3.amazonaws.com'):
            self.assertFalse(certik_public_copy('collected','website','https://'+host+'/report.pdf'))
        self.assertFalse(certik_public_copy('firm_export','website','https://docs.example.org/report.pdf'))

    def test_metadata_rows_linked_to_several_versions_count_once(self):
        sys.path.insert(0,str(ROOT/'scripts/build'))
        from check_db import metadata_receipts
        source=dict(source_file='api.jsonl',source_locator='line=4',source_record_sha256='a'*64)
        evidence=dict(metadata_only=True,source_record=source,sca_api_matches=[dict(source_record=source)])
        self.assertEqual(metadata_receipts(evidence),{('api.jsonl','line=4','a'*64)})

    def test_embedded_unicode_line_separator_is_data(self):
        sys.path.insert(0,str(ROOT/'scripts/build'))
        from build_db import Builder
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);path=root/'records.jsonl'
            path.write_text(json.dumps(dict(project='left\u2028right'),ensure_ascii=False)+'\n')
            builder=Builder.__new__(Builder);builder.root=root;builder.snapshot_inputs=None
            builder.tables=dict(import_sources={})
            result=list(builder.rows(path,'fixture','collected','engagement_metadata'))
            self.assertEqual(len(result),1)
            self.assertEqual(result[0][0]['project'],'left\u2028right')

    def test_historical_policy_bytes_are_bound_to_the_receipt(self):
        from check import status_policy_path
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);payload=b'{"synthetic":"historical policy"}\n';sha=digest(payload)
            target=root/'local-cache/policy-history/status'/(sha+'.json')
            target.parent.mkdir(parents=True);target.write_bytes(payload)
            (root/'schema').mkdir()
            (root/'schema/status_map_compatibility.json').write_text(json.dumps({sha:dict(path=str(target.relative_to(root)))}))
            status_policy_path.cache_clear()
            self.assertEqual(status_policy_path(root,sha),target)
            target.write_bytes(payload+b' ');status_policy_path.cache_clear()
            with self.assertRaisesRegex(AssertionError,'Historical status policy changed'):
                status_policy_path(root,sha)


if __name__=='__main__':unittest.main()
