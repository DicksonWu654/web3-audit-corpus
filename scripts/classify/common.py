"""Local-only Phase 4c data and output validation. Standard library only."""
from __future__ import annotations

import csv
import hashlib
import json
import math
from pathlib import Path
import re
import unicodedata

ROOT = Path(__file__).resolve().parents[2]
VERSION = "phase4c-v2"
MODEL = "gpt-6-luna"
CONTENT_KEY_VERSION = "sha256-nfkc-whitespace-v1"


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def normalize_text(value):
    """Preserve case (including code identifiers); normalize Unicode and whitespace."""
    return " ".join(unicodedata.normalize("NFKC", value).split())


def content_key_version(max_body_chars=800):
    return CONTENT_KEY_VERSION if max_body_chars == 800 else f"{CONTENT_KEY_VERSION}-body{max_body_chars}"


def work_dir(root, version="v1"):
    base = root / "local-cache/classify"
    return base / version if version != "v1" else base


def classified_dir(root, version="v1"):
    return root / ("data/findings_classified_v2" if version == "v2" else "data/findings_classified")


def content_key(firm_id, title, body, max_body_chars=800):
    """Hash an unambiguous UTF-8 JSON tuple; truncate AFTER normalization."""
    return sha(canonical([firm_id, normalize_text(title), normalize_text(body)[:max_body_chars]]).encode("utf-8"))


def classifier_row(row, max_body_chars=800):
    body = normalize_text(row["body"])
    return {**row, "title": normalize_text(row["title"]),
            "body": body[:max_body_chars], "body_characters": len(body)}


def write_json(path, value):
    write_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")


def write_text(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(value, encoding="utf-8")
    tmp.replace(path)


def write_jsonl(path, rows):
    write_text(path, "".join(canonical(r) + "\n" for r in rows))


def holdouts(root):
    path = root / "data/holdout/gold_sha256.txt"
    values = {v.strip() for v in path.read_text().splitlines() if v.strip() and not v.startswith("#")}
    if not values or any(not re.fullmatch(r"[0-9a-f]{64}", v) for v in values):
        raise ValueError("Missing, empty or invalid gold holdout list; refusing development")
    return values


def load_findings(root, max_body_chars=800):
    """Freeze individual files before parsing; holdout rows never enter returned data."""
    blocked = holdouts(root)
    with (root / "registry/scope_tier_a.csv").open() as stream:
        scope = {r["firm_id"] for r in csv.DictReader(stream)
                 if r["scope_group"] in {"firm", "contest_platform"}}
    rows, ledger, seen = [], [], set()
    excluded = {"holdout": 0, "out_of_scope": 0}
    paths = sorted(p for p in (root / "data/findings").glob("*.jsonl") if not p.name.startswith("_"))
    if not paths:
        raise ValueError("No data/findings/*.jsonl inputs")
    for path in paths:
        data = path.read_bytes()
        if data != path.read_bytes():
            raise ValueError(f"Input changed while snapshotting: {path}")
        count = 0
        for line in data.splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            count += 1
            # Check identities/hashes before accessing title or body.
            digest = row.get("sha256")
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"Finding without original hash: {path}")
            if digest in blocked:
                excluded["holdout"] += 1
                continue
            firm = row.get("firm_id") or row.get("publisher_id")
            if firm not in scope:
                excluded["out_of_scope"] += 1
                continue
            uid = row.get("finding_id")
            if not isinstance(uid, str) or not uid.startswith("finding:") or uid in seen:
                raise ValueError(f"Missing/duplicate finding_id: {uid}")
            seen.add(uid)
            body = row.get("body_text") or row.get("description") or ""
            if not isinstance(body, str) or not isinstance(row.get("title") or "", str):
                raise ValueError(f"Non-text title/body: {uid}")
            rows.append({"finding_uid": uid, "firm_id": firm, "document_id": row["document_id"],
                         "sha256": digest, "severity": row.get("severity", "unknown"),
                         "title": row.get("title") or "", "body": body,
                         "public_url": row.get("public_url"), "source_file": str(path.relative_to(root)),
                         "content_key": content_key(firm, row.get("title") or "", body, max_body_chars),
                         "record_sha256": sha(canonical(row).encode())})
        ledger.append({"path": str(path.relative_to(root)), "sha256": sha(data), "rows": count})
    return sorted(rows, key=lambda r: r["finding_uid"]), ledger, excluded


def load_taxonomy(path):
    # JSON is a YAML 1.2 subset; this avoids an executable/dependency-bearing YAML loader.
    taxonomy = json.loads(path.read_text())
    leaves = {}
    for top in taxonomy["classes"]:
        for leaf in top["leaves"]:
            if leaf["id"] in leaves:
                raise ValueError("Duplicate taxonomy leaf")
            leaves[leaf["id"]] = {**leaf, "top_level": top["id"]}
    return taxonomy, leaves


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key")
        result[key] = value
    return result


def read_jsonl(data):
    return [json.loads(line, object_pairs_hook=unique_object,
                       parse_constant=lambda s: (_ for _ in ()).throw(ValueError(s)))
            for line in data.split(b"\n") if line.strip()]


def classification_issues(row, leaves):
    why = []
    if not isinstance(row.get("leaf"), str) or row["leaf"] not in leaves:
        why.append("unknown_leaf")
    confidence = row.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (float, int)) or not 0 <= confidence <= 1 or not math.isfinite(confidence):
        why.append("invalid_confidence")
    rationale = row.get("rationale")
    if not isinstance(rationale, str) or not rationale.strip() or len(rationale.split()) > 20:
        why.append("invalid_rationale")
    return why


def valid_cached(row, leaves, taxonomy_sha, rules_sha=None, key_version=CONTENT_KEY_VERSION):
    if not isinstance(row, dict) or classification_issues(row, leaves):
        return False
    if row.get("category") != leaves[row["leaf"]]["top_level"]:
        return False
    meta = row.get("classification")
    if not isinstance(meta, dict) or meta.get("fixture") is not False:
        return False
    if (row.get("content_key_version") != key_version or
            meta.get("taxonomy_sha256") != taxonomy_sha or
            not isinstance(row.get("content_key"), str) or
            not re.fullmatch(r"[0-9a-f]{64}", row["content_key"]) or
            not isinstance(row.get("firm_id"), str) or not row["firm_id"] or
            not isinstance(row.get("finding_uid"), str) or not row["finding_uid"]):
        return False
    if meta.get("method") == "rule":
        return bool(meta.get("rule_id")) and (rules_sha is None or meta.get("rules_sha256") == rules_sha)
    if meta.get("method") == "llm":
        return bool(meta.get("model")) and meta.get("batch_id") == meta.get("prompt_sha256") and all(
            isinstance(meta.get(k), str) and re.fullmatch(r"[0-9a-f]{64}", meta[k])
            for k in ("batch_id", "prompt_sha256", "output_sha256"))
    return False


def load_classifications(directory, leaves, taxonomy_sha, rules_sha=None, key_version=CONTENT_KEY_VERSION):
    """Only compatible, structurally valid labels; conflicting leaves are cache misses."""
    grouped, invalid = {}, 0
    for path in sorted(Path(directory).glob("*.jsonl")):
        for line in path.read_bytes().splitlines():
            if not line.strip():
                continue
            try:
                row = read_jsonl(line)[0]
            except (ValueError, TypeError, UnicodeError, IndexError):
                invalid += 1
                continue
            if not valid_cached(row, leaves, taxonomy_sha, rules_sha, key_version):
                invalid += 1
                continue
            key = row["content_key"]
            grouped.setdefault(key, []).append(row)
    cache, conflicts = {}, 0
    for key, values in sorted(grouped.items()):
        if len({(r["firm_id"], r["leaf"]) for r in values}) != 1:
            conflicts += 1
            continue
        cache[key] = max(values, key=lambda r: (r["confidence"], canonical(r)))
    return cache, dict(valid_keys=len(cache), invalid_rows=invalid, conflicting_keys=conflicts)


def error_diagnostics(log_path, prompt_path):
    """Only CLI ERROR lines count; discard the verbatim echo of untrusted inputs."""
    log = log_path.read_text(encoding="utf-8", errors="replace")
    prompt = prompt_path.read_text(encoding="utf-8")
    return "\n".join(line for line in log.replace(prompt.strip(), "").splitlines()
                     if re.match(r"^ERROR\b", line))


def usage_guard_error(diagnostics):
    return bool(re.search(r"usage.?limit|quota|usage[-_ ]?reset|reset[-_ ]?(guard|credit|mechanism)|"
                          r"guard|unknown.*reset|credits?.*(exhausted|depleted)", diagnostics, re.I))


def retryable_capacity(log_path, prompt_path):
    diagnostics = error_diagnostics(log_path, prompt_path)
    return not usage_guard_error(diagnostics) and bool(re.search(r"(?:server|server) is at capacity|server (?:is )?overloaded|"
                          r"\b429\b|503 Service Unavailable|"
                          r"stream.*(?:disconnect|error|fail|reset|abort|interrupt)", diagnostics, re.I))


def batch_expected(batch):
    """Bind short indexes to frozen identities; legacy manifests use exact UIDs."""
    if "index_map" not in batch:
        return set(batch["finding_uids"])
    wanted = [dict(i=i, finding_uid=uid, content_key=key)
              for i, (uid, key) in enumerate(zip(batch["finding_uids"], batch["content_keys"]), 1)]
    if (batch["index_map"] != wanted or
            any(type(row.get("i")) is not int for row in batch["index_map"])):
        raise ValueError("Invalid index/UID/content-key binding")
    return {row["i"]: row["finding_uid"] for row in wanted}


def validate_output(path, expected, leaves, data=None):
    """Accept valid unique rows independently. Return values keyed by frozen UID.

    A dict maps short integer indexes to UIDs; a set denotes a legacy UID prompt.
    Foreign/malformed lines are diagnostics, never a reason to discard other rows.
    """
    indexed = isinstance(expected, dict)
    identities = expected if indexed else {uid: uid for uid in expected}
    field = "i" if indexed else "finding_uid"
    label = "index" if indexed else "uid"
    accepted, reasons, occurrences = {}, {}, {}
    errors = []
    try:
        raw = path.read_bytes() if data is None else data
        lines = raw.split(b"\n")
    except OSError as exc:
        return {}, {uid: ["missing_or_unreadable_output"] for uid in identities.values()}, [str(exc)]
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            line = line.decode("utf-8")
            duplicate_keys = []
            def object_hook(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        duplicate_keys.append(key)
                    result[key] = value
                return result
            row = json.loads(line, object_pairs_hook=object_hook)
        except (ValueError, TypeError, UnicodeError):
            errors.append(f"line {number}: invalid JSONL")
            continue
        if not isinstance(row, dict):
            errors.append(f"line {number}: not an object")
            continue
        identity = row.get(field)
        if ((type(identity) is not int if indexed else not isinstance(identity, str)) or
                identity not in identities):
            errors.append(f"line {number}: unexpected/missing {label}")
            continue
        uid = identities[identity]
        occurrences[uid] = occurrences.get(uid, 0) + 1
        why = classification_issues(row, leaves)
        if duplicate_keys:
            why.append("duplicate_json_key")
        if set(row) != {field, "leaf", "confidence", "rationale"}:
            why.append("invalid_fields")
        if why:
            reasons.setdefault(uid, []).extend(why)
        else:
            accepted[uid] = {"finding_uid": uid, **{k: row[k] for k in ("leaf", "confidence", "rationale")}}
    for uid in identities.values():
        if occurrences.get(uid, 0) > 1:
            reasons.setdefault(uid, []).append("duplicate_" + label)
        if uid not in accepted and uid not in reasons:
            reasons[uid] = ["missing_" + label]
    for uid in reasons:
        accepted.pop(uid, None)
    return accepted, reasons, errors
