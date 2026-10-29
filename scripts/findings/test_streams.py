"""Primary migration must not discard genuinely supplemental findings or raw receipts."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from streams import finding_rows, supplemental_only


class StreamTests(unittest.TestCase):
    def test_precedence_before_filters_and_regeneration(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp)/'data/findings';(base/'supplemental').mkdir(parents=True)
            primary=dict(finding_id='new',document_id='doc',publisher_finding_id='H-1',body='Current',record_kind='recommendation')
            old=primary|dict(body='Old',record_kind='formal_finding')
            shifted=old|dict(finding_id='shifted')
            outside=old|dict(finding_id='outside',publisher_finding_id='H-2')
            no_native=old|dict(finding_id='no-native',publisher_finding_id=None)
            other_doc=old|dict(finding_id='other-doc',document_id='other')
            rows=[old,shifted,outside,no_native,other_doc]
            (base/'firm.jsonl').write_text(json.dumps(primary)+'\n')
            (base/'supplemental/firm.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in rows))
            # An archive under a different tree cannot enter a live loader.
            archive=base/'archive';archive.mkdir();(archive/'firm.jsonl').write_text(json.dumps(old)+'\n')
            diagnostics={};actual=[r for _,r in finding_rows(base,diagnostics=diagnostics)]
            self.assertEqual(actual,[primary,outside,no_native,other_doc])
            self.assertEqual(diagnostics['supplemental_rows_already_in_primary'],2)
            self.assertEqual(supplemental_only(rows,base,'firm'),[outside,no_native,other_doc])


if __name__=='__main__':unittest.main()
