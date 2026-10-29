"""Formal layout selection and remediation accuracy without corpus text access."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from core import Report, finish
from parsers import module
from parsers.fixtures_certora_shieldify_variants import FIXTURES


def parse_fixture(name):
    firm,fmt,date,expected,text=FIXTURES[name]
    r=Report(text,{'file_format':fmt,'date_hint':date,'pages':[{'page':1,'start':0,'end':len(text),'text':text}]},firm)
    rows=module(firm).parse(r)
    return r,rows,expected


class LayoutVariants(unittest.TestCase):
    def test_every_declared_fixture_selects_its_formal_variant(self):
        for firm in ('certora','shieldify'):
            for v in module(firm).VARIANTS:
                self.assertFalse(v.fingerprint.legacy)
                self.assertIsNotNone(v.status_parser)
                for name in v.fixtures:
                    with self.subTest(name=name):
                        r,rows,expected=parse_fixture(name)
                        self.assertEqual(r.layout_selection['variant_id'],expected)
                        self.assertFalse(r.layout_selection['unknown_layout'])

    def test_status_assertions_have_exact_source_spans(self):
        for name in FIXTURES:
            r,rows,_=parse_fixture(name)
            for row in rows:
                if not row.status_raw:continue
                e=row.evidence['status_evidence']
                self.assertEqual(r.text[e['start']:e['end']],e['text'])
                self.assertEqual(e['text'],row.status_raw)

    def test_detail_status_overrides_stale_index_and_ignores_rule_status(self):
        r,rows,_=parse_fixture('certora_id_card')
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0].normalized_status,'fixed')
        self.assertNotIn('Formal Verification',r.text[rows[0].start:rows[0].end])

    def test_explicit_severity_conflict_is_not_rewritten(self):
        _,rows,_=parse_fixture('certora_id_source_conflict')
        self.assertEqual((rows[0].printed_id,rows[0].severity_raw,rows[0].normalized),('Crit-1','High','high'))

    def test_legacy_response_and_collective_table_remediation(self):
        _,cards,_=parse_fixture('certora_issue_card')
        self.assertEqual(cards[0].normalized_status,'fixed')
        _,table,_=parse_fixture('certora_verification_table')
        self.assertEqual(len(table),1)
        self.assertEqual(table[0].normalized_status,'fixed')

    def test_narrative_references_and_verification_rules_are_not_cards(self):
        _,rows,_=parse_fixture('certora_numbered_narrative')
        self.assertEqual([r.printed_id for r in rows],['1','2'])
        _,rows,_=parse_fixture('certora_verification_only')
        self.assertEqual(rows,[])

    def test_team_response_compound_outcome_is_fixed(self):
        for name in ('shieldify_markdown_card','shieldify_pdf_risk_card'):
            _,rows,_=parse_fixture(name)
            self.assertEqual(len(rows),1)
            self.assertEqual(rows[0].normalized_status,'fixed')
            self.assertEqual(rows[0].status_raw,'Acknowledged and fixed')

    def test_badge_status_and_title_above_identifier(self):
        _,rows,_=parse_fixture('shieldify_pdf_badge')
        self.assertEqual(rows[0].normalized_status,'partial')
        _,rows,_=parse_fixture('shieldify_pdf_finding')
        self.assertEqual(rows[0].title,'A complete finding title')
        self.assertEqual(rows[0].normalized_status,'fixed')

    def test_clean_reports_do_not_invent_findings(self):
        _,rows,_=parse_fixture('shieldify_pdf_zero_findings')
        self.assertEqual(rows,[])

    def test_repeated_native_ids_and_status_tables_respect_project_scopes(self):
        r,rows,_=parse_fixture('certora_scoped_cards')
        self.assertEqual([x.evidence.get('container_id') for x in rows],['Alpha','Beta'])
        self.assertEqual([x.normalized_status for x in rows],['fixed','acknowledged'])

    def test_detached_pdf_ids_and_bare_references(self):
        _,rows,_=parse_fixture('certora_split_ids')
        self.assertEqual([x.printed_id for x in rows],['L-01','I-01','I-02'])

    def test_aligned_issue_cards_have_explicit_collective_fix_receipt(self):
        _,rows,_=parse_fixture('certora_tabular_issue_card')
        self.assertEqual(len(rows),1)
        self.assertEqual((rows[0].printed_id,rows[0].severity_raw,rows[0].normalized_status),('H1','High','fixed'))

    def test_promised_future_fixes_are_open(self):
        firm,fmt,date,_,text=FIXTURES['certora_id_card']
        text=text.replace('Status: Fixed','Status: Will be fixed')
        report=Report(text,{'file_format':fmt,'date_hint':date,'pages':[{'page':1,'start':0,'end':len(text),'text':text}]},firm)
        rows=module(firm).parse(report)
        self.assertEqual(rows[0].normalized_status,'open')
        self.assertEqual(rows[0].status_raw,'Will be fixed')

    def test_code_example_status_stays_rejected_during_finalization(self):
        firm,fmt,date,_,text=FIXTURES['shieldify_markdown_card']
        text=text.replace('## Team Response\nAcknowledged and fixed in the linked commit.','## Recommendation\nFixed is merely a suggested wording, not a publisher outcome.')
        text=text.replace('| [H-01] | A complete finding title | High | Open |','')
        report=Report(text,{'file_format':fmt,'date_hint':date,'pages':[{'page':1,'start':0,'end':len(text),'text':text}]},firm)
        rows=finish(report,module(firm).parse(report))
        self.assertIsNone(rows[0].status_raw)


if __name__=='__main__':unittest.main()
