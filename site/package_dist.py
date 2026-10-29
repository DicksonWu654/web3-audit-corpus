#!/usr/bin/env python3
"""Copy a built site to a fresh directory with deterministic gzip data files.

  python3 -I site/package_dist.py --source build --out local-cache/tmp/w3a-dist

The size budget measures files after the hosting archive is expanded; the data
files remain gzip files. The source tree is only read. Existing output paths are
refused, and a failed size check leaves the partial output available for inspection.

The public site is the database only. Analysis outputs that the release producer
also writes to build/data (stats tables, trend and momentum summaries, incident
measures) are left out of the package, so they never reach the host.
"""
from __future__ import annotations

import argparse
import gzip
import json
import shutil
from pathlib import Path

MAX_TOTAL_BYTES = 240 * 1024 * 1024
MAX_FILE_BYTES = 25 * 1024 * 1024

# Analysis outputs kept out of the public package (relative to the build root).
ANALYSIS_DIRS = {("data", "stats")}
SUMMARY_DROP = {"headline", "key_results", "momentum_aggregates", "stats", "trends_2026"}
SUMMARY_COUNTS_DROP = {"incidents", "stats_tables"}
FIRM_DROP = {"audit_type_comparison", "momentum", "momentum_excluding_token_only"}


def _json_bytes(obj) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


def strip_analysis(rel: Path, data: bytes) -> bytes:
    """Remove analysis keys from the two shared data files; every other file, and a file with none, passes through unchanged."""
    if rel not in (Path("data/summary.json"), Path("data/firms.json")):
        return data
    obj = json.loads(data)
    if rel.name == "summary.json" and isinstance(obj, dict):
        new = {k: v for k, v in obj.items() if k not in SUMMARY_DROP}
        if isinstance(new.get("counts"), dict):
            new["counts"] = {k: v for k, v in new["counts"].items() if k not in SUMMARY_COUNTS_DROP}
        if isinstance(new.get("quality"), list):
            new["quality"] = [q for q in new["quality"] if not str((q or {}).get("metric", "") if isinstance(q, dict) else "").startswith("incident")]
    elif rel.name == "firms.json" and isinstance(obj, list):
        new = [{k: v for k, v in r.items() if k not in FIRM_DROP} if isinstance(r, dict) else r for r in obj]
    else:
        return data
    return data if new == obj else _json_bytes(new)


def is_analysis(rel: Path) -> bool:
    return any(rel.parts[:len(d)] == d for d in ANALYSIS_DIRS)


def package(source: Path, out: Path) -> dict:
    source, out = source.resolve(), out.absolute()
    if not source.is_dir():
        raise ValueError(f"Source is not a directory: {source}")
    if out.exists() or out.is_symlink():
        raise ValueError(f"Output must be a fresh directory: {out}")
    if out.resolve().is_relative_to(source):
        raise ValueError("Output must be outside the source tree")

    paths = sorted(source.rglob("*"))
    destinations = set()
    files = []
    config = {}
    for path in paths:
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError(f"Only regular files and directories are supported: {path}")
        rel = path.relative_to(source)
        if is_analysis(rel):
            continue
        compressed = rel.parts[0] == "data" and path.suffix == ".json" and path.is_file()
        dest = rel.with_name(rel.name + ".gz") if compressed else rel
        if dest in destinations:
            raise ValueError(f"Output path collision: {dest}")
        destinations.add(dest)
        if path.is_file():
            files.append((path, dest, compressed))
        if rel == Path("config.json"):
            config = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(config, dict):
                raise ValueError("config.json must be an object")
    config["data_compression"] = "gzip"
    config_bytes = (json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")

    out.mkdir(parents=True)
    total = count = gzipped = source_bytes = largest = 0

    def account(path: Path) -> None:
        nonlocal total, count, largest
        size = path.stat().st_size
        total += size
        count += 1
        largest = max(largest, size)
        if size > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds {MAX_FILE_BYTES} bytes: {path.relative_to(out)} ({size} bytes)")
        if total > MAX_TOTAL_BYTES:
            raise ValueError(f"Expanded output exceeds {MAX_TOTAL_BYTES} bytes ({total} bytes so far)")

    for path in paths:
        if path.is_dir() and not is_analysis(path.relative_to(source)):
            (out / path.relative_to(source)).mkdir(parents=True, exist_ok=True)
    for path, rel, compressed in files:
        dest = out / rel
        source_bytes += path.stat().st_size
        if rel == Path("config.json"):
            dest.write_bytes(config_bytes)
        elif compressed:
            body = strip_analysis(rel.with_name(path.name), path.read_bytes())
            with dest.open("wb") as raw:
                with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as gz:
                    gz.write(body)
            gzipped += 1
        else:
            shutil.copy2(path, dest)
        account(dest)
    if not (out / "config.json").exists():
        (out / "config.json").write_bytes(config_bytes)
        account(out / "config.json")
    return {"bytes": total, "files": count, "gzip_files": gzipped,
            "source_bytes": source_bytes, "largest_file_bytes": largest,
            "max_total_bytes": MAX_TOTAL_BYTES, "max_file_bytes": MAX_FILE_BYTES}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("build"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        totals = package(args.source, args.out)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"site-dist: {exc}\n")
    print(json.dumps(totals, sort_keys=True))


if __name__ == "__main__":
    main()
