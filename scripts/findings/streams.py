"""Primary-authoritative finding streams. Standard library only; no archive traversal."""
import json
from pathlib import Path


def native_key(row):
    """Missing native IDs never identify two findings as the same finding."""
    did, native = row.get('document_id'), row.get('publisher_finding_id')
    return (did, native) if did and native else None


class PrimaryIndex:
    def __init__(self):
        self.ids = set()
        self.native = set()

    def add(self, row):
        self.ids.add(row['finding_id'])
        key = native_key(row)
        if key:
            self.native.add(key)

    def match(self, row):
        if row.get('finding_id') in self.ids:
            return 'finding_id'
        if native_key(row) in self.native:
            return 'document_id+publisher_finding_id'
        return None


def finding_paths(base):
    base = Path(base)
    return [p for folder in (base, base / 'supplemental') for p in sorted(folder.glob('*.jsonl'))
            if not p.name.startswith('_')]


def jsonl(path):
    with path.open() as stream:
        for line in stream:
            if line.strip():
                yield json.loads(line)


def supplemental_only(rows, base, firm):
    """Keep regeneration from reintroducing occurrences folded into primary."""
    primary = PrimaryIndex()
    path = Path(base) / (firm + '.jsonl')
    if path.exists():
        for row in jsonl(path):
            primary.add(row)
    return [row for row in rows if not primary.match(row)]


def finding_rows(base, read_jsonl=jsonl, diagnostics=None, firms=None):
    """Yield (path, raw row), ignoring supplemental copies of primary identities.

    Read primary first, before any selection/scope/phase filters. Callers can supply
    their receipt-preserving reader. Conflicts inside either live stream remain the
    caller's validation responsibility; this rule only resolves primary vs supplemental.
    """
    primary = PrimaryIndex()
    for path in finding_paths(base):
        if firms is not None and path.stem not in firms:
            continue
        supplemental = path.parent.name == 'supplemental'
        for row in read_jsonl(path):
            if not row.get('finding_id'):
                raise ValueError(f'Not a finding interchange row: {path}')
            if supplemental:
                match = primary.match(row)
                if match:
                    if diagnostics is not None:
                        key = 'supplemental_rows_already_in_primary'
                        diagnostics[key] = diagnostics.get(key, 0) + 1
                    continue
            else:
                primary.add(row)
            yield path, row
