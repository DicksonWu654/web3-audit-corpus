"""Phase 4a local-only inputs, identity and holdout boundary. Standard library only."""
from __future__ import annotations
import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSION = "phase4a-v1"
SEVERITIES = ("critical", "high", "medium", "low", "info", "gas", "unknown")


def valid_sha(value):
    return isinstance(value,str) and len(value)==64 and all(c in "0123456789abcdef" for c in value)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else canonical(value).encode()).hexdigest()


def uid(kind, *parts):
    return kind + ":" + digest(parts)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("w") as out:
        for row in rows:
            out.write(canonical(row) + "\n")
    tmp.replace(path)


def holdouts(root=ROOT):
    path = root / "data/holdout/gold_sha256.txt"
    # Fail closed: never silently develop on a missing or malformed holdout list.
    values = set()
    for line in path.read_text().splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("Invalid holdout SHA-256")
        values.add(value)
    if not values:
        raise ValueError("Holdout list is empty; refusing extraction/development")
    return values


def documents(root=ROOT):
    """Read metadata only; filter holdouts before any original/text path is opened."""
    blocked = holdouts(root)
    scope = {r["firm_id"] for r in csv.DictReader((root / "registry/scope_tier_a.csv").open())
             if r["scope_group"] in {"firm", "contest_platform"}}
    ledger, docs, excluded = [], [], {"holdout_occurrences": 0, "out_of_scope": 0, "duplicates": 0}
    variants = {}
    for path in sorted((root / "data/collect").glob("*/reports.jsonl")):
        if path.parent.name not in scope:
            continue
        before = path.stat()
        payload = path.read_bytes()
        after = path.stat()
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise RuntimeError(f"Collection changed during snapshot: {path}")
        ledger.append({"path": str(path.relative_to(root)), "sha256": digest(payload), "bytes": len(payload)})
        for line, raw in enumerate(payload.splitlines(), 1):
            if not raw.strip():
                continue
            row = json.loads(raw)
            if not valid_sha(row.get("sha256")):
                raise ValueError(f"Invalid original SHA-256 in {path} line {line}")
            firm = row["firm_id"]
            if firm not in scope:
                excluded["out_of_scope"] += 1
                continue
            if row["sha256"] in blocked:
                excluded["holdout_occurrences"] += 1
                continue
            if firm != path.parent.name:
                raise ValueError(f"Directory/firm mismatch: {path}")
            receipt = digest(row)
            sid = uid("collected", row["collector"], row["public_url"], row["sha256"])
            seen = variants.setdefault((firm, sid), [])
            if receipt in seen:
                excluded["duplicates"] += 1
                continue
            seen.append(receipt)
            if len(seen) > 1:
                sid += ":occurrence:" + str(len(seen))
            docs.append({"row": row, "document_id": uid("document", "collect:" + firm, sid),
                         "source_record_id": sid, "source_record_sha256": receipt,
                         "source_file": str(path.relative_to(root)), "source_locator": f"line={line}"})
    return docs, ledger, excluded


def original_path(row, root=ROOT):
    path = Path(row.get("local_path") or "")
    if not path.is_absolute():
        path = root / path
    path = path.resolve()
    if not path.is_relative_to((root / "local-cache").resolve()):
        raise ValueError("Original path is outside local-cache")
    return path


def read_snapshot(root=ROOT):
    blocked = holdouts(root)
    rows = []
    for line in (root / "data/fulltext/input_documents.jsonl").read_text().splitlines():
        row = json.loads(line)
        if not valid_sha(row["row"].get("sha256")):
            raise ValueError("Invalid SHA-256 in extraction snapshot")
        if row["row"]["sha256"] not in blocked:
            rows.append(row)
    return rows
