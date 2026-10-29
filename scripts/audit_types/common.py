"""Small shared audit-type contract. No model calls, network, or source execution."""
import hashlib
import json
from pathlib import Path

TYPES = ('token_only', 'protocol', 'infrastructure', 'wallet_or_account', 'nft_or_game', 'other_or_unclear')


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def attach_labels(engagements, root, db_path=None):
    """A hash-bound merged sidecar supersedes legacy native rule columns.

    Accept a mapping keyed by ID or a list of rows. Never silently convert absent
    labels into abstentions: absence means the producer must be rerun. Without
    a merged sidecar, native columns retain the legacy snapshot behavior.
    """
    rows = list(engagements.values()) if isinstance(engagements, dict) else list(engagements)
    missing = [r for r in rows if not r.get('audit_type')]
    base = Path(root) / 'data/audit_types'
    receipt = json.loads((base / 'receipt.json').read_text()) if (base/'receipt.json').exists() else None
    # A completed merged sidecar supersedes legacy native rule columns. Never
    # silently use stale native columns while publishing newer type aggregates.
    if missing or (receipt and receipt.get('merge_version')):
        receipt = receipt or json.loads((base/'receipt.json').read_text())
        if receipt['database_sha256'] != file_sha(db_path or Path(root) / 'data/corpus.duckdb'):
            raise ValueError('Audit-type labels are stale; rerun scripts/audit_types/run.py')
        if receipt['labels_sha256'] != file_sha(base / 'labels.jsonl'):
            raise ValueError('Audit-type label checksum mismatch')
        if receipt['rules_sha256'] != file_sha(Path(root) / 'scripts/audit_types/rules.py'):
            raise ValueError('Audit-type rules changed; rerun scripts/audit_types/run.py')
        if receipt.get('merge_version'):
            for name, expected in receipt['merge_source_hashes'].items():
                if file_sha(Path(root)/'scripts/audit_types'/name) != expected:
                    raise ValueError('Audit-type merger changed; rerun scripts/audit_types/run.py')
        labels = {r['engagement_id']: r for r in map(json.loads, (base / 'labels.jsonl').read_text().splitlines())}
        for row in rows if receipt.get('merge_version') else missing:
            label = labels.get(row['engagement_id'])
            if not label or label['publisher_id'] != row['publisher_id'] or label.get('project') != row.get('project'):
                raise ValueError('Audit-type sidecar lacks matching engagement: ' + row['engagement_id'])
            row.update(audit_type=label['audit_type'], audit_type_basis=label['audit_type_basis'])
    for row in rows:
        if row['audit_type'] not in TYPES or not row.get('audit_type_basis'):
            raise ValueError('Invalid audit-type label: ' + row['engagement_id'])
        if receipt and receipt.get('merge_version') and row['audit_type_basis'] not in ('rule', 'llm', 'abstain'):
            raise ValueError('Invalid merged audit-type basis')
    return engagements
