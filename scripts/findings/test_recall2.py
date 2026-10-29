"""General recall regressions, derived from non-holdout report layouts."""
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from core import finish
from parsers import module, FIRMS, GROUP1, GROUP2, GROUP3, CONTESTS
from test_framework import report
from summary_inventory import inventory
from extraction_normalization import font_mapping_pages, normalize_pdf

D='Description\nThe source explains the affected code and security consequences.\n'*3


class InventoryTests(unittest.TestCase):
    def test_all_publishers_have_zero_detail_inventory_fallback(self):
        text='Findings Summary\nID    Severity    Status    Title\nX-01    High    Resolved\nA missing access check\npermits unauthorized withdrawals\n\nX-02    Low    Open\nIncorrect event data\n'
        firms=FIRMS+GROUP1+GROUP2+GROUP3+CONTESTS+('theori','kudelski-security','nethermind','codespect')
        for firm in firms:
            with self.subTest(firm=firm):
                r=report(text,firm,'pdf'); cs=finish(r,module(firm).parse(r))
                self.assertEqual([c.printed_id for c in cs],['X-01','X-02'])
                self.assertEqual(cs[0].title,'A missing access check permits unauthorized withdrawals')
                self.assertTrue(all(c.method=='summary_inventory' and c.confidence<.7 for c in cs))
                self.assertTrue(all(c.record_kind=='summary_excerpt' for c in cs))
                for c in cs:
                    span=c.evidence['inventory_span'];self.assertEqual(r.text[span['start']:span['end']],span['text'])

    def test_inventory_does_not_supplement_existing_details(self):
        r=report('ID    Title    Severity    Status\nH-01    Inventory title    High    Fixed\n\f[H-01] Actual finding\n'+D,'pashov-audit-group','pdf')
        cs=finish(r,module(r.firm).parse(r))
        self.assertEqual(len(cs),1);self.assertEqual(cs[0].record_kind,'formal_finding')

    def test_inventory_with_columns_after_title_and_continuation_page(self):
        r=report('ID    Title    Severity    Status\nKS-TST-01    High slippage can lose funds    Low    Resolved\ncontinued title\n\fID    Title    Severity    Status\nKS-TST-02    Low    Open\nA second source title\n','kudelski-security','pdf')
        cs=inventory(r)
        self.assertEqual(len(cs),2)
        self.assertEqual(cs[0].title,'High slippage can lose funds continued title')
        self.assertEqual(cs[0].severity_raw,'Low')

    def test_totals_matrix_badges_code_and_toc_are_not_inventory(self):
        for text in ('Findings Summary\nHigh 3\nLow 2\n','Likelihood    Impact\n1 Low Resolved\n'+D,
                     'Complete Analysis\n5 Low RESOLVED\nAn actual card\n'+D,
                     'Contents\nFindings Summary ................ 3\n1. Title .............. 4\n',
                     '```\nID    Severity    Status    Title\n1    High    Fixed    A code example\n```'):
            self.assertEqual(inventory(report(text,'zokyo','pdf')),[])

    def test_markdown_inventory_keeps_short_exact_spans(self):
        r=report('| ID | Title | Severity | Status |\n|---|---|---|---|\n| H-01 | A title | High | Fixed |\n','code4rena','md')
        cs=finish(r,module(r.firm).parse(r));self.assertEqual(len(cs),1)
        self.assertEqual(cs[0].method,'summary_inventory')


class PublisherTests(unittest.TestCase):
    def test_theori_colonless_issue_and_recommendation(self):
        for firm in ('theori','chainlight'):
            r=report('Issue #1 Missing authorization\nSummary    Severity\nA source summary    Minor\n'+D+
                     'Recommendation #1 Validate the input\n'+D,firm,'pdf')
            cs=module(firm).parse(r)
            self.assertEqual([c.printed_id for c in cs],['Issue #1','Recommendation #1'])
            self.assertEqual(cs[0].severity_raw,'Minor')
            if firm=='theori':self.assertEqual(cs[0].normalized,'low')
            self.assertEqual(cs[1].record_kind,'recommendation')

    def test_zokyo_badge_after_summary_is_not_a_continuation(self):
        from parsers.zokyo import _summary_pages
        r=report('Findings summary\nID    Title    Risk    Status\n1    Inventory title    Low    Resolved\n\f'
                 '5 Low RESOLVED\nActual issue title\n\n'+D,'zokyo','pdf')
        r.meta['issues']=[dict(kind='ocr_page',page=2)]
        self.assertEqual(_summary_pages(r),{1})
        cs=module(r.firm).parse(r)
        self.assertEqual(len(cs),1);self.assertEqual(cs[0].title,'Actual issue title')
        self.assertNotEqual(cs[0].record_kind,'summary_excerpt')

    def test_zokyo_real_inventory_continuation_stays_excluded(self):
        from parsers.zokyo import _summary_pages
        r=report('Findings summary\nID    Title    Risk    Status\n1    Inventory title    Low    Resolved\n\f'
                 '2    A second inventory title    Low    Resolved\n3    Third title    High    Fixed\n','zokyo','pdf')
        self.assertEqual(_summary_pages(r),{1,2})

    def test_hats_attack_steps_remain_inside_the_finding(self):
        r=report('## Findings\n### Medium severity findings\n1. **Missing validation**\n'+D+
                 'Attack Scenario:\n1. Alice creates a burner wallet\n2. Alice floods the deposit queue\n'+D+
                 '2. **Incorrect accounting**\n'+D,'hats-finance','md')
        cs=module(r.firm).parse(r)
        self.assertEqual([c.title for c in cs],['Missing validation','Incorrect accounting'])
        self.assertIn('Alice floods',r.text[cs[0].start:cs[0].end])

    def test_non_holdout_corpus_inventories_and_attack_steps(self):
        from recall2 import LOCAL,inputs
        from recall_push import load
        if not (LOCAL/'inputs.json').exists():self.skipTest('Local corpus unavailable')
        docs=inputs()
        cases=(('1f1529cafb53',10),('4ac2a5c1cc43',4),('fd732431c02c',16),('3b8840d82c2c',26),('7435a76bb6dd',10),('02b6cbc53e62',2))
        for prefix,count in cases:
            d=next(d for d in docs if d['row']['sha256'].startswith(prefix));r=load(d)
            cs=module(r.firm).parse(r)
            self.assertEqual(len(cs),count)
            self.assertTrue(all(c.method=='summary_inventory' for c in cs))
            if prefix=='fd732431c02c':
                self.assertIn('Indirect transfers',cs[0].title)
                self.assertIn('Order of interest',cs[1].title)
        d=next(d for d in docs if d['row']['sha256'].startswith('d4d38e84670e'))
        r=load(d)
        self.assertIn('Alice knows the BFX',r.text)
        self.assertFalse(any('Alice' in c.title for c in module(r.firm).parse(r)))
        # Exercise the source's actual scenario in the unindented Markdown
        # serialization that caused the general failure.
        step=next(l.content for l in r.lines if '1. Alice knows the BFX' in l.content)
        adapted=report('## Findings\n### Low severity findings\n1. **Source finding**\n'+D+
                       'Attack Scenario:\n'+step+'\n'+D,'hats-finance','md')
        self.assertEqual(len(module(adapted.firm).parse(adapted)),1)
        d=next(d for d in docs if d['row']['sha256'].startswith('89e479c4dc40'))
        source=load(d)
        import re
        text=re.sub(r'((?:Issue|Recommendation)\s*#\d+)\s*:',r'\1 ',source.text)
        # No colonless original was found in this census. Transform only the
        # punctuation of a real, OCR-recovered non-holdout report.
        adapted=report(text,'theori','pdf')
        cs=module(adapted.firm).parse(adapted)
        self.assertEqual(sum(c.record_kind=='formal_finding' for c in cs),4)
        self.assertEqual(sum(c.record_kind=='recommendation' for c in cs),9)
        d=next(d for d in docs if d['row']['sha256'].startswith('120cd202dbd0'))
        source=load(d)
        c=next(c for c in module(source.firm).parse(source) if c.severity_raw and c.status_raw)
        # Reproduce the adjacent summary/card boundary using a real publisher
        # title and its OCR-backed risk/status labels, plus the leading icon.
        adapted=report('Findings summary\nID    Title    Risk    Status\n1    '+c.title+'    '+c.severity_raw+'    '+c.status_raw+
                       '\n\f5 '+c.severity_raw+' '+c.status_raw+'\n'+c.title+'\n\n'+D,'zokyo','pdf')
        adapted.meta['issues']=[dict(kind='ocr_page',page=2)]
        cs=module(adapted.firm).parse(adapted)
        self.assertEqual(len(cs),1);self.assertEqual(cs[0].record_kind,'formal_finding')


class FontMappingTests(unittest.TestCase):
    def test_font_diagnostics_are_page_local(self):
        from types import SimpleNamespace
        outputs=[SimpleNamespace(stderr=b'',returncode=0),SimpleNamespace(stderr=b"Syntax Error: Missing language pack for 'Adobe-Korea1' mapping",returncode=0)]
        with patch('extraction_normalization.subprocess.run',side_effect=outputs) as run:
            self.assertEqual(font_mapping_pages(Path('source.pdf'),2,'pdftotext',{},10),[2])
            self.assertEqual(run.call_args_list[1].args[0][1:5],['-f','2','-l','2'])

    def test_font_failure_forces_ocr_despite_dense_native_text(self):
        import fitz
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'local-cache/fulltext').mkdir(parents=True)
            source=root/'source.pdf'
            with fitz.open() as pdf:
                pdf.new_page();pdf.new_page();pdf.new_page();pdf.save(source)
            native='Surviving code and numerical formula content. '*20
            complete='Issue #1 Original title\nSeverity: High\nDescriptions:\n'+native
            recovered='Issue #1 Missing authorization\nSummary    Severity\nThe issue summary    High\n'+D
            with patch('extraction_normalization.ocr_page',return_value=(recovered,{})) as ocr:
                texts,issues=normalize_pdf([native,native,complete],source,root,'tesseract',{},10,threading.Lock(),font_pages=[2,3])
            self.assertEqual(ocr.call_count,2);self.assertEqual(texts[0],native)
            self.assertIn('Issue #1',texts[1])
            self.assertEqual(texts[2],complete)
            self.assertEqual([q['page'] for q in issues if q['kind']=='ocr_page'],[2,3])


if __name__=='__main__':unittest.main()
