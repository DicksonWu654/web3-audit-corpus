#!/usr/bin/env python3
"""Discover Tier A report metadata from FORGE and DAppSCAN trees.

The collector reads repository tree metadata only; it never executes upstream
code or downloads report originals. A retained path index makes reruns
reproducible without the temporary HTTP response cache.
"""
from __future__ import annotations

import hashlib
import datetime as dt
import json
import re
import runpy
from pathlib import Path, PurePosixPath
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/discovery/common.py"
CACHE = Path("local-cache/tmp/web3-aggregators-http")
OUT = ROOT / "data/discovery/_sources"
INDEX_PATH = OUT / "repository_sources.index.json"

CACHED = {
    "dappscan": {
        "repo": "InPlusLab/DAppSCAN",
        "commit": "66a56619c44770e05c2db600fa6468115ff0dcd5",
        "head": "25a6a6c39fbcc92959c4e0243b4d1068c625e71c75a2f56df888f14b411d6604",
        "root_tree": "28e26aec2a430c5f74052de6a6f57fac77c57cd40eceb09f616363cee84a96a1",
        "tree": "1e27bf9a9fb379e40ed5ec57c1eb3dd6c156d88d7c2d257f4dd129edfc8cc8a7",
        "tree_url": "https://api.github.com/repos/InPlusLab/DAppSCAN/git/trees/90ae9ba18509c0b6a5d0c186926bae881b2871c3?recursive=1",
        "prefix": "DAppSCAN-source",
        "subtree_sha": "90ae9ba18509c0b6a5d0c186926bae881b2871c3",
    },
    "forge": {
        "repo": "shenyimings/FORGE-Artifacts",
        "commit": "2d6646595e578e26c098e057926cea7905269c6e",
        "head": "a7aea9398fa8a0d6c1238f611adcb3af2c557f0375a06b7fd0cb8433fa0dbc6d",
        "root_tree": "c90ccf52da752e0fac45e6d2586738822e825d8a3790ec65007eb3f053f5de26",
        "dataset_tree": "6ee691863d72d7be089392471611b96c1946fdcca2988dfc36cb68f43f838bd2",
        "tree": "06f92f8c20fa911ebc42c9b527eeef9b2b99c30e36864025dc7ba43cad2f92a5",
        "tree_url": "https://api.github.com/repos/shenyimings/FORGE-Artifacts/git/trees/8869a5f7fe0769b420462ae8bb4677ecb8dbcc8b?recursive=1",
        "prefix": "dataset/results",
        "subtree_sha": "8869a5f7fe0769b420462ae8bb4677ecb8dbcc8b",
    },
}


def cached_json(stem: str, expected_url: str) -> tuple[dict, dict]:
    manifest = json.loads((CACHE / (stem + ".json")).read_text())
    body = (CACHE / (stem + ".body")).read_bytes()
    if manifest.get("status") != 200 or manifest.get("url") != expected_url:
        raise ValueError(f"unexpected cached response manifest: {stem}")
    if hashlib.sha256(body).hexdigest() != manifest.get("sha256"):
        raise ValueError(f"cached response hash mismatch: {stem}")
    return manifest, json.loads(body)


def manifest_record(stem: str, expected_url: str) -> dict:
    info, _ = cached_json(stem, expected_url)
    return {
        "file": stem + ".json",
        "url": info["url"],
        "accessed_at": info.get("accessed_at"),
        "response_sha256": info.get("sha256"),
    }


def entry(nodes: list[dict], path: str) -> dict:
    return next(n for n in nodes if n.get("path") == path)


def verify_cached_snapshot(source: str) -> tuple[dict, list[dict]]:
    spec = CACHED[source]
    head_url = f"https://api.github.com/repos/{spec['repo']}/commits/HEAD"
    head_manifest, head = cached_json(spec["head"], head_url)
    if head.get("sha") != spec["commit"]:
        raise ValueError(f"cached HEAD changed for {spec['repo']}")
    details = {
        "repo": spec["repo"],
        "commit": spec["commit"],
        "method": "same_day_pinned_cache",
        "commit_date": (head.get("commit", {}).get("committer", {}) or {}).get("date"),
        "head_manifest": manifest_record(spec["head"], head_url),
        "truncated": False,
    }

    if source == "dappscan":
        root_url = f"https://api.github.com/repos/{spec['repo']}/git/trees/{spec['commit']}"
        root_manifest, root = cached_json(spec["root_tree"], root_url)
        subtree_sha = entry(root.get("tree", []), "DAppSCAN-source")["sha"]
        if subtree_sha != spec["subtree_sha"]:
            raise ValueError("DAppSCAN source subtree SHA changed")
        tree_manifest, tree = cached_json(spec["tree"], spec["tree_url"])
        if tree.get("sha") != subtree_sha or tree.get("truncated"):
            raise ValueError("DAppSCAN source subtree is not complete")
        nodes = [{**n, "path": "DAppSCAN-source/" + n["path"]} for n in tree.get("tree", [])]
        details.update(tree_sha=tree["sha"], subtree="DAppSCAN-source",
                       enumerated_nodes=len(nodes),
                       root_tree_manifest=manifest_record(spec["root_tree"], root_url),
                       tree_manifest=manifest_record(spec["tree"], spec["tree_url"]))
    else:
        root_url = f"https://api.github.com/repos/{spec['repo']}/git/trees/{spec['commit']}"
        root_manifest, root = cached_json(spec["root_tree"], root_url)
        dataset_sha = entry(root.get("tree", []), "dataset")["sha"]
        if dataset_sha != "40cc847861d3099617434fcc529d01af6e40b9cd":
            raise ValueError("FORGE dataset subtree SHA changed")
        dataset_url = f"https://api.github.com/repos/{spec['repo']}/git/trees/{dataset_sha}"
        dataset_manifest, dataset = cached_json(spec["dataset_tree"], dataset_url)
        results_sha = entry(dataset.get("tree", []), "results")["sha"]
        if results_sha != spec["subtree_sha"]:
            raise ValueError("FORGE results subtree SHA changed")
        tree_manifest, tree = cached_json(spec["tree"], spec["tree_url"])
        if tree.get("sha") != results_sha or tree.get("truncated"):
            raise ValueError("FORGE results subtree is not complete")
        nodes = [{**n, "path": "dataset/results/" + n["path"]} for n in tree.get("tree", [])]
        details.update(tree_sha=tree["sha"], subtree="dataset/results",
                       enumerated_nodes=len(nodes),
                       root_tree_manifest=manifest_record(spec["root_tree"], root_url),
                       dataset_tree_manifest=manifest_record(spec["dataset_tree"], dataset_url),
                       tree_manifest=manifest_record(spec["tree"], spec["tree_url"]))
    return details, nodes


def snapshot_from_index(index: dict) -> tuple[dict, dict]:
    """Rebuild source listings from the retained compact path index."""
    sources, trees = {}, {}
    for name in CACHED:
        spec = index["sources"][name]
        sources[name] = dict(spec["provenance"], method="retained_path_index")
        prefix = CACHED[name]["prefix"]
        paths = spec.get("report_pdf_paths") or spec.get("result_paths") or []
        trees[name] = [{"path": p if p.startswith(prefix + "/") or not prefix else prefix + "/" + p,
                        "type": "blob"} for p in paths]
        if name == "forge":
            sources[name]["enumerated_nodes"] = spec["provenance"]["enumerated_nodes"]
    return sources, trees


def pinned_raw(repo: str, commit: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{commit}/{quote(path, safe='/')}"


def parse_date(text: str) -> tuple[str | None, str]:
    match = re.search(r"(?<!\d)(20\d{2})[-_.](\d{2})[-_.](\d{2})(?!\d)", text)
    if match:
        year, month, day = map(int, match.groups())
        try:
            dt.date(year, month, day)
        except ValueError:
            return None, "none"
        return f"{year:04d}-{month:02d}-{day:02d}", "day"
    match = re.search(r"(?<!\d)(20\d{2})[-_.](\d{2})(?!\d)", text)
    if match:
        year, month = map(int, match.groups())
        if not 1 <= month <= 12:
            return None, "none"
        return f"{year:04d}-{month:02d}", "month"
    match = re.search(r"(?<!\d)(20\d{2})(?!\d)", text)
    return (match.group(1), "year") if match else (None, "none")


def report_row(source: str, repo: str, commit: str, path: str, firm_id: str,
               author: str, project: str, date_hint: str | None, precision: str,
               attribution_kind: str, notes: str) -> dict:
    return {
        "attribution_basis": {
            "kind": attribution_kind,
            "value": author,
            "evidence_url": f"https://github.com/{repo}/tree/{commit}/{quote(str(PurePosixPath(path).parent), safe='/')}",
        },
        "candidate_url": pinned_raw(repo, commit, path),
        "date_basis": "filename" if date_hint else "none",
        "date_hint": date_hint,
        "date_precision": precision,
        "firm_id": firm_id,
        "notes": notes,
        "original_publisher_url": None,
        "project_hint": project or None,
        "source": source,
        "source_record_id": path,
    }


def build_index(sources: dict, trees: dict) -> dict:
    dapp_nodes = trees["dappscan"]
    dapp_labels, dapp_pdfs, dapp_nested_pdfs = set(), [], []
    for n in dapp_nodes:
        p = n.get("path", "")
        parts = PurePosixPath(p).parts
        if len(parts) >= 3 and parts[:2] == ("DAppSCAN-source", "audit_report"):
            dapp_labels.add(parts[2].split("-", 1)[0])
            if n.get("type") == "blob" and PurePosixPath(p).suffix.lower() == ".pdf":
                if len(parts) == 4:
                    dapp_pdfs.append(p)
                elif len(parts) > 4:
                    dapp_nested_pdfs.append(p)

    forge_nodes = trees["forge"]
    forge_paths = sorted(n["path"] for n in forge_nodes if n.get("type") == "blob")
    forge_extensions = {}
    for p in forge_paths:
        ext = PurePosixPath(p).suffix.lower() or "[none]"
        forge_extensions[ext] = forge_extensions.get(ext, 0) + 1
    return {
        "snapshot_date": "2026-10-20",
        "index_version": 1,
        "note": "Compact paths and firm-directory labels from complete, commit-pinned API trees. DAppSCAN report candidates include only PDFs directly inside publisher-project directories; nested PDFs are retained separately as excluded paths. No report bodies or FORGE finding JSON bodies are retained.",
        "sources": {
            "dappscan": {
                "provenance": sources["dappscan"],
                "author_labels": sorted(dapp_labels),
                "report_pdf_paths": sorted(dapp_pdfs),
                "excluded_nested_pdf_paths": sorted(dapp_nested_pdfs),
            },
            "forge": {
                "provenance": sources["forge"],
                "result_paths": forge_paths,
                "result_extensions": dict(sorted(forge_extensions.items())),
            },
        },
    }


def main() -> None:
    h = runpy.run_path(str(HELPER))
    scope = h["scope"]()
    previous_status = {}
    status_path = OUT / "repository_sources.status.json"
    if status_path.exists():
        try:
            previous_status = json.loads(status_path.read_text())
        except ValueError:
            pass

    # Same-day pinned snapshots are the reproducible input. If any are missing,
    # use the retained compact index rather than depending on /tmp cache state.
    try:
        sources, trees = {}, {}
        for name in CACHED:
            sources[name], trees[name] = verify_cached_snapshot(name)
        index = build_index(sources, trees)
        input_mode = "verified_same_day_api_snapshots"
    except (OSError, ValueError, KeyError, StopIteration):
        if not INDEX_PATH.exists():
            raise
        index = json.loads(INDEX_PATH.read_text())
        index = {**index, "sources": {name: index["sources"][name] for name in CACHED}}
        sources, trees = snapshot_from_index(index)
        input_mode = "retained_path_index"

    # Preserve the prior live-query result, which records the helper's 403 robots
    # refusal. This avoids retrying rate-limited GitHub API requests.
    for name in CACHED:
        old = previous_status.get("sources", {}).get(name, {})
        if old.get("live_query"):
            sources[name]["live_query"] = old["live_query"]

    dapp_paths = index["sources"]["dappscan"]["report_pdf_paths"]
    dapp_nested_paths = index["sources"]["dappscan"].get("excluded_nested_pdf_paths", [])
    dapp_labels = index["sources"]["dappscan"]["author_labels"]
    dapp_commit = sources["dappscan"]["commit"]
    dapp_repo = CACHED["dappscan"]["repo"]
    excluded_nested_tier_a = []
    for path in dapp_nested_paths:
        parts = PurePosixPath(path).parts
        author = parts[2].split("-", 1)[0]
        firm_id = h["firm_name"](author)
        if firm_id and firm_id in scope:
            excluded_nested_tier_a.append(path)
    forge_paths = index["sources"]["forge"]["result_paths"]

    rows = []
    unmapped_dapp = sorted(label for label in dapp_labels if not h["firm_name"](label))
    for path in dapp_paths:
        parts = PurePosixPath(path).parts
        folder = parts[2]
        if "-" not in folder:
            continue
        author, project = folder.split("-", 1)
        firm_id = h["firm_name"](author)
        if not firm_id or firm_id not in scope:
            continue
        date_hint, precision = parse_date(PurePosixPath(path).name)
        rows.append(report_row(
            "dappscan", dapp_repo, dapp_commit, path, firm_id, author,
            project.replace("_", " ").strip(), date_hint, precision,
            "named_author_directory",
            "DAppSCAN-source/audit_report publisher-project directory; report PDF metadata only, not downloaded.",
        ))

    rows.sort(key=lambda r: (r["source"], r["firm_id"], r["source_record_id"]))
    OUT.mkdir(parents=True, exist_ok=True)
    h["write_json"](INDEX_PATH, index)
    h["write_jsonl"](OUT / "repository_sources.jsonl", rows)
    dapp_pdf_count = len(dapp_paths)
    forge_pdf_paths = [p for p in forge_paths if PurePosixPath(p).suffix.lower() == ".pdf"]
    forge_report_file_paths = [
        p for p in forge_paths
        if re.search(r"(^|/)(reports?|audits?)(/|$)", p, re.I)
        and PurePosixPath(p).suffix.lower() in {".pdf", ".md", ".html"}
    ]
    status = {
        "collected_utc": h["now"](),
        "script": "scripts/discovery/repository_sources.py",
        "input_mode": input_mode,
        "path_index": "data/discovery/_sources/repository_sources.index.json",
        "row_count": len(rows),
        "source_counts": {s: sum(r["source"] == s for r in rows) for s in CACHED},
        "sources": sources,
        "enumeration": {
            "forge": {
                "subtree": "dataset/results",
                "enumerated_result_files": len(forge_paths),
                "result_extensions": index["sources"]["forge"]["result_extensions"],
                "tree_truncated": sources["forge"].get("truncated"),
                "supplied_pdf_path_count": len(forge_pdf_paths),
                "report_reference_file_path_count": len(forge_report_file_paths),
                "tier_a_rows": 0,
                "limitations": "Complete dataset/results subtree contains 6,454 JSON result/finding metadata files, not supplied report PDFs. No report URL was derived from result-level artifact or contract metadata; these records were not emitted as report candidates.",
            },
            "dappscan": {
                "subtree": "DAppSCAN-source",
                "enumerated_nodes": sources["dappscan"].get("enumerated_nodes"),
                "tree_truncated": sources["dappscan"].get("truncated"),
                "report_author_label_count": len(dapp_labels),
                "report_pdf_path_count": dapp_pdf_count,
                "included_pdf_path_depth_components": 4,
                "included_nested_pdf_path_count": 0,
                "excluded_nested_pdf_path_count": len(dapp_nested_paths),
                "excluded_nested_tier_a_pdf_path_count": len(excluded_nested_tier_a),
                "excluded_nested_tier_a_pdf_path_samples": excluded_nested_tier_a[:8],
                "excluded_nested_pdf_path_samples": dapp_nested_paths[:8],
                "tier_a_rows": sum(r["source"] == "dappscan" for r in rows),
                "unmapped_author_labels": unmapped_dapp,
                "limitations": "Complete DAppSCAN-source subtree at pinned commit; candidates are restricted to PDF blobs immediately under audit_report/<author-project>. Nested PDFs under client source repositories are excluded and indexed separately. No report bodies were downloaded.",
            },
        },
    }
    h["write_json"](status_path, status)
    print(json.dumps({"row_count": len(rows), "source_counts": status["source_counts"],
                      "input_mode": input_mode,
                      "truncated": {s: sources[s].get("truncated") for s in CACHED}}, sort_keys=True))


if __name__ == "__main__":
    main()
