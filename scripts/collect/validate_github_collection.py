#!/usr/bin/env python3
"""Independently validate GitHub collection manifests using local evidence only.

This validator does not import or execute github_collector.py. It reads the
Tier A registry, collector configuration, per-firm JSON/JSONL outputs and bare
Git snapshots. Git is limited to local plumbing reads with system/global
configuration disabled; no worktree is created and no network operation occurs.

Run from any directory:
  python3 -I scripts/collect/validate_github_collection.py
  python3 -I scripts/collect/validate_github_collection.py --verify-hashes
  python3 -I scripts/collect/validate_github_collection.py \
      --verify-hashes --output data/collect/github_independent_validation.json
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import urllib.parse


ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "collect"
CONFIG = ROOT / "scripts" / "collect" / "github_firms.yaml"
REGISTRY = ROOT / "registry" / "scope_tier_a.csv"
FIELDS = {
    "firm_id", "collector", "source_kind", "public_url", "listing_url", "sha256",
    "bytes", "file_format", "local_path", "filename", "title_hint", "project_hint",
    "date_hint", "date_precision", "date_basis", "doc_kind", "retrieved_utc", "notes",
}
DOC_KINDS = {"audit_report", "fix_review", "formal_verification", "contest_report", "non_report", "unknown"}
DATE_PRECISIONS = {"day", "month", "year", "none"}
DATE_BASES = {"listing", "filename", "document_text", "contest_end", "none"}
FORMATS = {"pdf", "md", "html", "other"}


def load_yaml(path: Path):
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required to read github_firms.yaml") from exc
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path):
    rows, errors = [], []
    if not path.exists():
        return rows, [f"missing file: {path.relative_to(ROOT)}"]
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        try:
            rows.append(json.loads(raw))
        except json.JSONDecodeError as exc:
            errors.append(f"{path.relative_to(ROOT)}:{line_number}: invalid JSON: {exc.msg}")
    return rows, errors


def scope_firms():
    with REGISTRY.open(newline="", encoding="utf-8") as f:
        return [row for row in csv.DictReader(f)
                if row.get("scope_group") == "firm" and row.get("host") == "github"]


def repo_from_url(url: str) -> str | None:
    match = re.match(r"^https://github\.com/([^/]+)/([^/#?]+)", url or "", re.I)
    if not match:
        return None
    return f"{match.group(1)}/{match.group(2).removesuffix('.git')}"


def clean_git_env():
    env = {key: value for key, value in os.environ.items()
           if key in {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "SSL_CERT_FILE", "GIT_SSL_CAINFO"}}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0",
               GIT_LFS_SKIP_SMUDGE="1", GIT_NO_LAZY_FETCH="1")
    return env


def git_local(git_dir: Path, args: list[str], *, data: bytes | None = None) -> bytes:
    """Invoke read-only Git plumbing against one explicit bare local snapshot."""
    command = ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
               "-c", "credential.helper=", "--git-dir", str(git_dir), *args]
    result = subprocess.run(command, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=clean_git_env(), check=False)
    if result.returncode:
        message = result.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {message}")
    return result.stdout


def ls_tree(git_dir: Path, commit: str) -> dict[str, dict]:
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit or ""):
        raise ValueError(f"invalid pinned commit ID: {commit!r}")
    raw = git_local(git_dir, ["ls-tree", "-rlz", "--full-tree", commit])
    tree = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        try:
            header, path_bytes = entry.split(b"\t", 1)
            mode_b, kind_b, oid_b, size_b = header.split()
            path = path_bytes.decode("utf-8", "surrogateescape")
            tree[path] = {
                "mode": mode_b.decode("ascii"),
                "type": kind_b.decode("ascii"),
                "oid": oid_b.decode("ascii"),
                "size": int(size_b) if size_b != b"-" else None,
            }
        except (ValueError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"unable to parse git ls-tree output entry: {entry[:200]!r}") from exc
    return tree


def read_blob(git_dir: Path, oid: str) -> bytes:
    return git_local(git_dir, ["cat-file", "blob", oid])


def selected_readme_paths(git_dir: Path, tree: dict[str, dict], sections: list[str] | None):
    if not sections:
        return None
    readmes = [p for p in tree if p.lower() == "readme.md"]
    if not readmes:
        raise ValueError("configured README section selection has no root README")
    text = read_blob(git_dir, tree[readmes[0]]["oid"]).decode("utf-8", "replace")
    paths, active = set(), None
    for line in text.splitlines():
        heading = re.match(r"^(#{1,6})\s+(.+?)\s*#*$", line)
        if heading:
            level, title = len(heading[1]), heading[2].strip()
            if active and level <= active:
                active = None
            if title in sections:
                active = level
        if active:
            for link in re.findall(r"\]\(([^)]+)\)", line):
                path = urllib.parse.unquote(urllib.parse.urlsplit(link).path)
                if "/reviews/" in path:
                    path = "reviews/" + path.split("/reviews/", 1)[1]
                path = path.removeprefix("./").lstrip("/")
                if path.lower().endswith((".pdf", ".md", ".html")):
                    paths.add(path)
    if not paths:
        raise ValueError("configured README sections selected no report links")
    return paths


def exclusion_reason(item: dict, conf: dict, defaults: dict, readme_paths: set[str] | None):
    path = item["path"]
    if item["type"] != "blob" or item["mode"] not in ("100644", "100755"):
        return "Symlink/submodule/non-regular object; never followed or executed."
    if readme_paths is not None and path not in readme_paths:
        return "Outside publisher-indexed Web3 review sections."
    if conf.get("include_paths") and not any(re.search(p, path) for p in conf["include_paths"]):
        return "Outside configured report subdirectories."
    for pattern, reason in conf.get("exclude_paths", {}).items():
        if re.search(pattern, path):
            return reason
    if re.search(defaults["non_report_paths"], path, re.I):
        return "Supporting assets, research, templates, training, slides, or CTF material."
    if (re.search(defaults["non_report_names"], PurePosixPath(path).name, re.I)
            and path not in conf.get("allow_readme_paths", []) + conf.get("allow_document_paths", [])):
        return "Repository index, metadata sidecar, licence/change log, or other documentation (configured basename rule)."
    if PurePosixPath(path).suffix.lower().lstrip(".") not in defaults["extensions"]:
        return "Non-document asset/source code; extension is not an audit-report format."
    return None


def read_repo_paths(repos: list[dict]) -> list[str]:
    return [str(repo.get("repo", "")) for repo in repos]


def pinned_url_parts(url: str):
    match = re.fullmatch(r"https://github\.com/([^/]+)/([^/]+)/blob/([0-9a-f]{40})/(.+)", url or "")
    if not match:
        return None
    return f"{match[1]}/{match[2]}", match[3], urllib.parse.unquote(match[4])


def git_blob_oid(data: bytes, oid_length: int) -> str:
    algorithm = {40: "sha1", 64: "sha256"}.get(oid_length)
    if not algorithm:
        raise ValueError(f"unsupported Git object ID length: {oid_length}")
    h = hashlib.new(algorithm)
    h.update(f"blob {len(data)}\0".encode("ascii"))
    h.update(data)
    return h.hexdigest()


def parse_lfs_pointer(data: bytes):
    if not data.startswith(b"version https://git-lfs.github.com/spec/v1"):
        return None
    text = data.decode("ascii", "strict")
    oid = re.search(r"(?m)^oid sha256:([0-9a-f]{64})$", text)
    size = re.search(r"(?m)^size (\d+)$", text)
    if not oid or not size:
        raise ValueError("malformed Git LFS pointer in snapshot")
    return oid[1], int(size[1])


def validate_firm(firm: dict, config: dict, verify_hashes: bool) -> dict:
    fid = firm["firm_id"]
    folder = DATA / fid
    errors, warnings, missing = [], [], []
    status_path, manifest_path = folder / "status.json", folder / "reports.jsonl"
    discovery_path = folder / "github_discovery.json"
    for required in (status_path, manifest_path, discovery_path):
        if not required.is_file():
            errors.append(f"missing required file: {required.relative_to(ROOT)}")
    if status_path.exists():
        try:
            status = load_json(status_path)
        except Exception as exc:
            status = {}
            errors.append(f"invalid status.json: {exc}")
    else:
        status = {}
    if discovery_path.exists():
        try:
            discovery = load_json(discovery_path)
        except Exception as exc:
            discovery = {}
            errors.append(f"invalid github_discovery.json: {exc}")
    else:
        discovery = {}

    manifest, parse_errors = load_jsonl(manifest_path)
    errors.extend(parse_errors)
    required_status = {"firm_id", "listing_urls", "listed_count", "collected", "failed",
                       "skipped_non_report", "failures", "collected_utc", "collector_script"}
    absent = sorted(required_status - status.keys())
    if absent:
        errors.append("status.json missing contract fields: " + ", ".join(absent))
    if status.get("firm_id") != fid:
        errors.append("status firm_id mismatch")
    if not isinstance(status.get("failures", []), list):
        errors.append("status.failures must be a list")
    if status.get("failed") != len(status.get("failures", [])):
        errors.append("status.failed does not match failures length")
    if status.get("collected") != len(manifest):
        errors.append("status.collected does not match manifest row count")

    if discovery.get("firm_id") != fid:
        errors.append("discovery firm_id mismatch or missing")
    if discovery.get("complete") is not True:
        errors.append("repository discovery is incomplete")
    if discovery.get("failures"):
        errors.append("repository discovery has failures")
    for owner in discovery.get("owners", []):
        if owner.get("complete") is not True:
            errors.append(f"repository owner listing incomplete: {owner.get('owner', 'unknown')}")
    candidates = discovery.get("candidates", [])
    reviews = [c.get("full_name", "unknown") for c in candidates if c.get("decision") == "review"]
    if reviews:
        errors.append("unreviewed repository candidates: " + ", ".join(reviews))
    invalid_decisions = [c.get("full_name", "unknown") for c in candidates
                         if c.get("decision") not in {"include", "exclude"}]
    if invalid_decisions:
        errors.append("repository candidates have invalid decisions: " + ", ".join(invalid_decisions))
    if status.get("discovery_complete") is not True:
        errors.append("status.discovery_complete is not true")
    if status.get("discovery_pending"):
        errors.append("status has unreviewed discovery_pending entries")

    status_repos = status.get("repos")
    if not isinstance(status_repos, list):
        status_repos = []
        errors.append("status.repos must be a list")
    discovered_repos = discovery.get("repos", [])
    configured_repos = config.get("firms", {}).get(fid, {}).get("repos", [])
    registry_repo = repo_from_url(firm.get("github_reports_url", ""))
    expected_repos = {r.lower() for r in discovered_repos if isinstance(r, str)}
    if registry_repo:
        expected_repos.add(registry_repo.lower())
    expected_repos.update(str(r).lower() for r in configured_repos)
    actual_repos = {str(r.get("repo", "")).lower() for r in status_repos if isinstance(r, dict)}
    if expected_repos != actual_repos:
        errors.append("status repository list differs from discovery/registry/configuration")
    for repo in discovered_repos:
        if isinstance(repo, str) and repo.lower() not in actual_repos:
            missing.append({"repo": repo, "reason": "listed by discovery but absent from status"})

    record_by_path = {}
    blob_by_local = {}
    kind_counts = collections.Counter()
    defaults = config.get("defaults", {})
    conf = config.get("firms", {}).get(fid, {})
    for index, row in enumerate(manifest, 1):
        if not isinstance(row, dict):
            errors.append(f"manifest row {index} is not an object")
            continue
        if set(row) != FIELDS:
            missing_fields = sorted(FIELDS - row.keys())
            extra_fields = sorted(row.keys() - FIELDS)
            errors.append(f"manifest row {index} schema mismatch (missing={missing_fields}, extra={extra_fields})")
        if row.get("firm_id") != fid:
            errors.append(f"manifest row {index} firm_id mismatch")
        if row.get("source_kind") != "github":
            errors.append(f"manifest row {index} source_kind is not github")
        if row.get("doc_kind") not in DOC_KINDS:
            errors.append(f"manifest row {index} has invalid doc_kind {row.get('doc_kind')!r}")
        else:
            kind_counts[row["doc_kind"]] += 1
        if row.get("file_format") not in FORMATS:
            errors.append(f"manifest row {index} has invalid file_format {row.get('file_format')!r}")
        if row.get("date_precision") not in DATE_PRECISIONS or row.get("date_basis") not in DATE_BASES:
            errors.append(f"manifest row {index} has invalid date precision/basis")
        if bool(row.get("date_hint")) != (row.get("date_precision") != "none" and row.get("date_basis") != "none"):
            errors.append(f"manifest row {index} has inconsistent date_hint/precision/basis")
        parsed_url = pinned_url_parts(row.get("public_url", ""))
        if parsed_url is None:
            errors.append(f"manifest row {index} public_url is not a commit-pinned GitHub blob URL")
            continue
        repo, commit, path = parsed_url
        key = (repo.lower(), path)
        if key in record_by_path:
            errors.append(f"duplicate manifest path: {repo}:{path}")
        record_by_path[key] = row
        if row.get("filename") != path:
            errors.append(f"manifest row {index} filename does not match pinned URL path")
        repo_status = next((r for r in status_repos if isinstance(r, dict) and str(r.get("repo", "")).lower() == repo.lower()), None)
        if not repo_status:
            errors.append(f"manifest row {index} references repo absent from status: {repo}")
        elif commit != repo_status.get("commit"):
            errors.append(f"manifest row {index} URL commit does not match repo snapshot: {repo}:{path}")
        if row.get("listing_url") != f"https://github.com/{repo}":
            errors.append(f"manifest row {index} listing_url does not match repo")
        repo_rules = dict(conf)
        for configured_repo, rule in conf.get("repo_rules", {}).items():
            if configured_repo.lower() == repo.lower():
                repo_rules.update(rule)
        for pattern, rule in repo_rules.get("doc_kind_rules", {}).items():
            if re.search(pattern, path):
                if row.get("doc_kind") != rule.get("doc_kind"):
                    errors.append(f"manifest row {index} doc_kind does not match configured path rule: {repo}:{path}")
                reason = rule.get("reason", "")
                if reason and reason not in row.get("notes", ""):
                    errors.append(f"manifest row {index} notes omit configured doc_kind rule reason: {repo}:{path}")
                break
        sha = row.get("sha256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            errors.append(f"manifest row {index} has invalid SHA-256")
        local_rel = row.get("local_path", "")
        local_unresolved = ROOT / local_rel
        local = local_unresolved.resolve()
        extension = PurePosixPath(local_rel).suffix.lstrip(".")
        expected_original = f"local-cache/originals/{sha[:2]}/{sha}.{extension}"
        if (PurePosixPath(local_rel).is_absolute() or ".." in PurePosixPath(local_rel).parts
                or local_rel != expected_original):
            errors.append(f"manifest row {index} local_path does not match SHA-addressed store layout: {local_rel}")
        elif os.path.commonpath((str(ROOT), str(local))) != str(ROOT) or not local_rel.startswith("local-cache/originals/"):
            errors.append(f"manifest row {index} local_path is outside the original store")
        elif local_unresolved.is_symlink() or not local.is_file():
            errors.append(f"manifest row {index} original is missing or not a regular file: {local_rel}")
        else:
            if local.stat().st_size != row.get("bytes"):
                errors.append(f"manifest row {index} original size mismatch: {local_rel}")
            if local.name.split(".", 1)[0] != sha or local.parent.name != sha[:2]:
                errors.append(f"manifest row {index} original path does not match SHA-256: {local_rel}")
            blob_by_local.setdefault(local_rel, local)

    stated_kinds = status.get("doc_kind_counts", {})
    if dict(sorted(kind_counts.items())) != dict(sorted(stated_kinds.items())):
        errors.append("status.doc_kind_counts does not match manifest doc_kind values")
    if status.get("failed", 0) != 0:
        errors.append("collection has acquisition failures")

    exclusions = status.get("exclusions", [])
    if not isinstance(exclusions, list):
        exclusions = []
        errors.append("status.exclusions must be a list")
    exclusion_by_path = {}
    for exc in exclusions:
        if not isinstance(exc, dict) or not exc.get("reason") or not exc.get("path") or not exc.get("repo"):
            errors.append("exclusion entry lacks repo/path/reason")
            continue
        key = (str(exc["repo"]).lower(), exc["path"])
        if key in exclusion_by_path:
            errors.append(f"duplicate exclusion path: {exc['repo']}:{exc['path']}")
        exclusion_by_path[key] = exc
    if status.get("skipped_non_report") != len(exclusions):
        errors.append("status.skipped_non_report does not match exclusion entries")

    eligible_paths, expected_exclusions = set(), set()
    tree_files = 0
    accessible_repos = 0
    repo_status_by_name = {str(r.get("repo", "")).lower(): r for r in status_repos if isinstance(r, dict)}
    for repo in sorted(expected_repos):
        repo_status = repo_status_by_name.get(repo)
        if not repo_status:
            continue
        repo_label = repo_status.get("repo", repo)
        clone_path = repo_status.get("clone_path")
        commit = repo_status.get("commit")
        if repo_status.get("error") or not clone_path or not commit:
            missing.append({"repo": repo_label, "reason": repo_status.get("error") or "snapshot commit/path unavailable"})
            continue
        git_dir = (ROOT / clone_path).resolve()
        expected_git_root = (ROOT / "local-cache" / "git").resolve()
        if os.path.commonpath((str(expected_git_root), str(git_dir)) ) != str(expected_git_root):
            errors.append(f"snapshot path outside local-cache/git: {clone_path}")
            missing.append({"repo": repo_label, "reason": "unsafe or invalid snapshot path"})
            continue
        if not git_dir.is_dir():
            missing.append({"repo": repo_label, "reason": f"snapshot missing: {clone_path}"})
            continue
        try:
            tree = ls_tree(git_dir, commit)
            readmes = selected_readme_paths(git_dir, tree, conf.get("readme_sections"))
        except Exception as exc:
            missing.append({"repo": repo_label, "reason": str(exc)})
            continue
        accessible_repos += 1
        tree_files += len(tree)
        if repo_status.get("files") != len(tree):
            errors.append(f"status repo tree file count mismatch for {repo_label}: {repo_status.get('files')} vs {len(tree)}")
        repo_rules = dict(conf)
        for key, value in conf.get("repo_rules", {}).items():
            if key.lower() == str(repo_label).lower():
                repo_rules.update(value)
        for path, obj in tree.items():
            item = {"path": path, **obj}
            why = exclusion_reason(item, repo_rules, defaults, readmes)
            tree_key = (str(repo_label).lower(), path)
            if why:
                expected_exclusions.add(tree_key)
                entry = exclusion_by_path.get(tree_key)
                if not entry:
                    errors.append(f"tree path missing explained exclusion: {repo_label}:{path}")
                elif entry.get("commit") != commit:
                    errors.append(f"exclusion commit does not match snapshot: {repo_label}:{path}")
            else:
                eligible_paths.add(tree_key)
                if tree_key not in record_by_path:
                    errors.append(f"eligible tree path missing from manifest: {repo_label}:{path}")
        for key in exclusion_by_path:
            if key[0] == str(repo_label).lower() and key not in expected_exclusions:
                errors.append(f"exclusion is not justified by config/tree: {repo_label}:{key[1]}")
        for key in record_by_path:
            if key[0] == str(repo_label).lower() and key not in eligible_paths:
                errors.append(f"manifest path is excluded by config/tree: {repo_label}:{key[1]}")
        expected_eligible_here = sum(1 for path in tree
                                     if (str(repo_label).lower(), path) in eligible_paths)
        if repo_status.get("candidate_files") != expected_eligible_here:
            errors.append(f"status repo eligible count mismatch for {repo_label}: {repo_status.get('candidate_files')} vs {expected_eligible_here}")

    for key in record_by_path:
        if key not in eligible_paths:
            # A repo that could not be opened has already been reported under
            # missing_repos; do not turn this into misleading 100% coverage.
            if key[0] not in expected_repos:
                errors.append(f"manifest path refers to undiscovered repo/path: {key[0]}:{key[1]}")
    if status.get("tree_files") != tree_files:
        errors.append(f"status.tree_files={status.get('tree_files')} but accessible snapshots contain {tree_files} tree entries")
    if status.get("listed_count") != len(eligible_paths):
        errors.append(f"status.listed_count={status.get('listed_count')} but config/tree has {len(eligible_paths)} eligible documents")
    if len(exclusions) != len(expected_exclusions):
        errors.append(f"exclusion count does not reconcile with tree/config ({len(exclusions)} recorded, {len(expected_exclusions)} expected)")

    eligible_count = len(eligible_paths)
    collected_count = len(manifest)
    coverage = None if missing else (100.0 if eligible_count == 0 else round(100 * collected_count / eligible_count, 4))
    if coverage is not None and coverage < 98.0:
        errors.append(f"eligible-document coverage below 98%: {coverage}%")
    stated_coverage = status.get("report_file_coverage_pct")
    if coverage is None and stated_coverage is not None:
        errors.append("inaccessible repository has a numeric report_file_coverage_pct")
    elif coverage is not None and (not isinstance(stated_coverage, (int, float)) or abs(stated_coverage - coverage) > 0.001):
        errors.append(f"status.report_file_coverage_pct does not match independent coverage: {stated_coverage} vs {coverage}")
    if missing:
        warnings.append("Coverage is incomplete because one or more repositories are inaccessible; no percentage is reported.")

    if verify_hashes:
        verified = set()
        content_hashes = {}
        oid_by_path = {}
        lfs_by_path = {}
        manifest_paths = set(record_by_path)
        for repo in status_repos:
            if not isinstance(repo, dict) or repo.get("error") or not repo.get("clone_path") or not repo.get("commit"):
                continue
            git_dir = (ROOT / repo["clone_path"]).resolve()
            if not git_dir.is_dir():
                continue
            try:
                for path, obj in ls_tree(git_dir, repo["commit"]).items():
                    oid_by_path[(str(repo["repo"]).lower(), path)] = obj["oid"]
                    if (str(repo["repo"]).lower(), path) not in manifest_paths:
                        continue
                    # LFS pointers are tiny text blobs. Avoid materializing a
                    # full PDF merely to determine whether it is a pointer.
                    if obj["type"] != "blob" or obj["size"] is None or obj["size"] > 1024:
                        continue
                    try:
                        pointer = parse_lfs_pointer(read_blob(git_dir, obj["oid"]))
                    except (UnicodeDecodeError, ValueError):
                        pointer = None
                    if pointer:
                        lfs_by_path[(str(repo["repo"]).lower(), path)] = pointer
            except Exception:
                continue
        for row in manifest:
            parsed = pinned_url_parts(row.get("public_url", "")) if isinstance(row, dict) else None
            if not parsed:
                continue
            repo, _, path = parsed
            local_rel = row.get("local_path", "")
            local_unresolved = ROOT / local_rel
            local = local_unresolved.resolve()
            if (local_unresolved.is_symlink() or not local.is_file()
                    or os.path.commonpath((str(ROOT), str(local))) != str(ROOT)):
                continue
            cache_key = local_rel
            try:
                expected_oid = oid_by_path.get((repo.lower(), path))
                pointer = lfs_by_path.get((repo.lower(), path))
                if cache_key not in content_hashes:
                    data = local.read_bytes()
                    content_hashes[cache_key] = {
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "blob_sha1": git_blob_oid(data, 40),
                        "blob_sha256": git_blob_oid(data, 64),
                        "size": len(data),
                    }
                content = content_hashes[cache_key]
                actual_sha = content["sha256"]
                actual_oid = content["blob_sha1"] if expected_oid and len(expected_oid) == 40 else content["blob_sha256"] if expected_oid else None
                if cache_key not in verified:
                    verified.add(cache_key)
                    if actual_sha != row.get("sha256"):
                        errors.append(f"original SHA-256 mismatch: {local_rel}")
                    if content["size"] != row.get("bytes"):
                        errors.append(f"original size mismatch during hash verification: {local_rel}")
                if pointer:
                    pointer_sha, pointer_size = pointer
                    if row.get("sha256") != pointer_sha or row.get("bytes") != pointer_size:
                        errors.append(f"LFS manifest metadata does not match pinned pointer at {repo}:{path}")
                    if actual_sha != pointer_sha or content["size"] != pointer_size:
                        errors.append(f"original bytes do not match pinned Git LFS object at {repo}:{path}")
                elif expected_oid and actual_oid != expected_oid:
                    errors.append(f"original Git blob ID mismatch at {repo}:{path}")
                elif not expected_oid:
                    errors.append(f"snapshot Git blob ID unavailable for {repo}:{path}")
            except OSError as exc:
                errors.append(f"cannot read original for hash verification {local_rel}: {exc}")

    return {
        "firm_id": fid,
        "tree_files": tree_files,
        "eligible_documents": eligible_count if not missing else None,
        "eligible_documents_in_accessible_snapshots": eligible_count,
        "collected": collected_count,
        "eligible_coverage_pct": coverage,
        "accessible_repositories": accessible_repos,
        "expected_repositories": len(expected_repos),
        "missing_repositories": missing,
        "discovery_complete": discovery.get("complete") is True,
        "unreviewed_candidates": reviews,
        "manifest_kind_counts": dict(sorted(kind_counts.items())),
        "errors": errors,
        "warnings": warnings,
    }


def validate(verify_hashes=False):
    config = load_yaml(CONFIG)
    if config.get("version") != 1:
        raise RuntimeError("unsupported github_firms.yaml version")
    firms = scope_firms()
    firm_results = []
    for index, firm in enumerate(firms, 1):
        fid = firm["firm_id"]
        print(f"[github-validator] {index}/{len(firms)} start {fid}", file=sys.stderr, flush=True)
        firm_result = validate_firm(firm, config, verify_hashes)
        firm_results.append(firm_result)
        summary = "failed" if firm_result["errors"] else "ok"
        print(f"[github-validator] {index}/{len(firms)} {summary} {fid}: "
              f"rows={firm_result['collected']} missing_repos={len(firm_result['missing_repositories'])} "
              f"errors={len(firm_result['errors'])}", file=sys.stderr, flush=True)
    errors = [f"{row['firm_id']}: {error}" for row in firm_results for error in row["errors"]]
    missing_repositories = [dict(firm_id=row["firm_id"], **missing)
                            for row in firm_results for missing in row["missing_repositories"]]
    accessible_eligible = sum(row["eligible_documents_in_accessible_snapshots"] for row in firm_results)
    collected = sum(row["collected"] for row in firm_results)
    all_repositories_accessible = not missing_repositories
    coverage = None if not all_repositories_accessible else (
        100.0 if accessible_eligible == 0 else round(100 * collected / accessible_eligible, 4))
    if coverage is not None and coverage < 98.0:
        errors.append(f"all-firm eligible-document coverage below 98%: {coverage}%")
    result = {
        "validator": "scripts/collect/validate_github_collection.py",
        "offline": True,
        "firms_in_scope": len(firms),
        "firms_checked": len(firm_results),
        "records_checked": collected,
        "original_hashes_verified": bool(verify_hashes),
        "eligible_documents_in_accessible_snapshots": accessible_eligible,
        "eligible_document_coverage_pct": coverage,
        "missing_repositories": missing_repositories,
        "firms": firm_results,
        "errors": errors,
        "ok": not errors and not missing_repositories,
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify-hashes", action="store_true",
                        help="verify SHA-256 and Git blob IDs for every unique cached original")
    parser.add_argument("--output", type=Path,
                        help="write JSON here (no output file is created unless this is supplied)")
    args = parser.parse_args(argv)
    try:
        result = validate(verify_hashes=args.verify_hashes)
    except Exception as exc:
        result = {"validator": "scripts/collect/validate_github_collection.py",
                  "offline": True, "ok": False, "errors": [f"validator failed: {type(exc).__name__}: {exc}"]}
    rendered = json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        output = args.output if args.output.is_absolute() else ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
