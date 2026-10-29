"""Keep synthetic corpus builds offline without changing production cache gates."""
from pathlib import Path
import json
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from audit_types import run as audit_type_runner


@pytest.fixture(autouse=True)
def synthetic_audit_type_abstentions(monkeypatch, tmp_path):
    original = audit_type_runner.apply_to_builder

    def apply(builder):
        root = Path(builder.root).resolve()
        temporary_root = tmp_path.resolve()
        # Frozen replay stores live beneath their marked synthetic input root.
        for candidate in (root, *root.parents):
            if not candidate.is_relative_to(temporary_root):
                continue
            marker = candidate / 'docs/inventory/firm_datasets_summary.json'
            if marker.is_file() and json.loads(marker.read_text()).get('synthetic_fixture') == 'foundation-v1':
                # Foundation tests exercise dates, grouping and provenance;
                # classifier/cache validation has its own tests and real replay.
                # State abstention without claiming a model or source receipt.
                for engagement in builder.tables['engagements'].values():
                    engagement.update(audit_type='other_or_unclear', audit_type_basis='abstain')
                    engagement['evidence']['audit_type_receipt'] = dict(fixture=True, mode='synthetic_abstention')
                return
        return original(builder)

    monkeypatch.setattr(audit_type_runner, 'apply_to_builder', apply)
