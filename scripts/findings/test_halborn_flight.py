"""Synthetic regression checks for the data-only Halborn HTML decoder."""
import json
import unittest
from halborn_website import VERSION, extract, flight_records, needs_retry, resolve


def html(stream):
    # A length-prefixed string is allowed to cross arbitrary push boundaries.
    cut = len(stream) // 2
    return ''.join('<script>self.__next_f.push(' + json.dumps([1, part]) + ')</script>' for part in (stream[:cut], stream[cut:]))


class FlightTests(unittest.TestCase):
    def test_utf8_length_and_no_newline_record_boundary(self):
        body = '<p>Résumé — body</p>\n<pre>a &lt; b\nnext</pre>'
        report = {'id': 'report', 'reportType': 'FULL', 'findings': [{'halIndex': 3, 'title': 'Title', 'bvss_grade': ['Low'], 'description': '$a', 'remediation': '<p>Fix</p>', 'remediationState': 'Solved'}]}
        stream = ':HL["style"]\na:T' + format(len(body.encode()), 'x') + ',' + body + 'b:' + json.dumps(report) + '\n'
        text, meta = extract(html(stream))
        self.assertIn('### HAL-03 Title\nSeverity: Low\nStatus: Solved', text)
        self.assertIn('Résumé — body', text)
        self.assertIn('a < b\nnext', text)
        self.assertEqual(meta['finding_count'], 1)
        self.assertEqual(meta['unresolved_references'], [])
        self.assertEqual(meta['issues'], [])
        self.assertEqual(meta['findings'][0]['fields']['description']['source_reference'], '$a')

    def test_reference_paths_and_cycles(self):
        unresolved = set()
        records = {'1': ['$', 'div', None, {'data': ['value']}], '2': '$3', '3': '$2'}
        self.assertEqual(resolve('$1:props:data:0', records, unresolved), 'value')
        self.assertEqual(resolve('$$5', records, unresolved), '$5')
        resolve('$2', records, unresolved)
        self.assertTrue(unresolved)

    def test_does_not_evaluate_script(self):
        text, meta = extract('<script>self.__next_f.push(eval("danger"))</script>')
        self.assertEqual(text, '')
        self.assertEqual(meta['finding_count'], 0)

    def test_cache_scope(self):
        row = {'firm_id': 'halborn', 'source_kind': 'website', 'file_format': 'html'}
        self.assertTrue(needs_retry(row, {}))
        self.assertFalse(needs_retry(row, {'halborn_website': {'version': VERSION}}))
        self.assertFalse(needs_retry(dict(row, firm_id='other'), {}))
        self.assertFalse(needs_retry(dict(row, file_format='pdf'), {}))

if __name__ == '__main__':
    unittest.main()
