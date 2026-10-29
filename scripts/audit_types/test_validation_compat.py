"""Only reviewed exact producer hashes can reuse frozen audit-type plans."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_types.validation_compat import (source_hashes_match, LEGACY_LLM_SHA256,
    ABSTENTION_LLM_SHA256, LEGACY_RUN_SHA256, INTEGRATION_RUN_SHA256)


class SourceCompatibilityTest(unittest.TestCase):
    def test_reviewed_changes_compose_without_mutating_receipts(self):
        recorded={'llm.py':LEGACY_LLM_SHA256,'run.py':LEGACY_RUN_SHA256,'rules.py':'frozen'}
        current=dict(recorded, **{'llm.py':ABSTENTION_LLM_SHA256,'run.py':INTEGRATION_RUN_SHA256})
        self.assertTrue(source_hashes_match(recorded,current))
        self.assertEqual(recorded['run.py'],LEGACY_RUN_SHA256)
        self.assertFalse(source_hashes_match(current,recorded))

    def test_unreviewed_hashes_and_missing_fields_fail_closed(self):
        recorded={'run.py':LEGACY_RUN_SHA256,'rules.py':'frozen'}
        current={'run.py':INTEGRATION_RUN_SHA256,'rules.py':'frozen'}
        self.assertTrue(source_hashes_match(recorded,current))
        self.assertFalse(source_hashes_match(recorded,dict(current, **{'run.py':'unreviewed'})))
        self.assertFalse(source_hashes_match(recorded,dict(current, **{'rules.py':'changed'})))
        self.assertFalse(source_hashes_match(recorded,{'run.py':INTEGRATION_RUN_SHA256}))


if __name__=='__main__':unittest.main()
