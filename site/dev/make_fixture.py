#!/usr/bin/env python3
"""Write a development fixture for the website in the release data-contract shape.

Until `scripts/release/` produces `build/data/`, the site is developed against this fixture. It reads the
Phase 5 aggregates (`data/analysis/*.csv`), a few (or all) `data/findings/*.jsonl` files and their classifications,
and writes `site/dev-data/` (gitignored) in exactly the layout the site reads from `build/data/`:

  summary.json                      {as_of, counts{...}, quality[rows of quality_measurements]}
  stats/<table>.json                one per aggregate CSV: a JSON array of row objects (CSV column names, typed values)
  firms.json                        [{firm_id, name, kind, website, reports_listed, reports_collected, coverage_pct,
                                      first_year, last_year, engagements, findings, severity{}, status{}, classes{}}]
  engagements/<firm_id>.json        [{engagement_id, project, review_mode, audit_year, audit_date_min, audit_date_max,
                                      publication_year, findings_count, report_url, report_sha256, pages}]
  findings/<firm_id>/<n>.json       {firm_id, shard, findings:[{finding_uid, finding_id, title, severity,
                                      severity_original, status, status_original, vuln_group, vuln_leaf,
                                      vuln_confidence, vuln_needs_review, body_text, page_start, page_end,
                                      engagement_id, report_id, url, project, audit_year, review_mode}]}  (<= 2 MB)
  search/manifest.json              {version, fields, shards:[{file, firm_id, count}]}
  search/index-<firm_id>[-k].json   {firm_id, fields, dicts{severity,status,leaf,mode}, projects[], rows[[...]]}
      row = [uid12, title, project_idx, year|0, sev_idx, status_idx, leaf_idx|-1, mode_idx, shard, publisher_id]

Usage:  python3 site/dev/make_fixture.py [--all | --firms a,b,c] [--out site/dev-data]
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANALYSIS = ROOT / "data" / "analysis"
FINDINGS = ROOT / "data" / "findings"
CLASSIFIED = ROOT / "data" / "findings_classified_v2"
DEFAULT_FIRMS = ["ackee-blockchain", "sigma-prime", "code4rena", "trail-of-bits", "openzeppelin",
                 "pashov-audit-group", "cantina", "zellic"]
# Row-level extracts are not part of the published aggregates.
ROW_LEVEL = {"finding_streams", "incident_matches", "vulnerability_class_diagnostics", "engagements",
             "cadence_identity_eligibility", "report_pages", "engagement_review_modes", "incident_events",
             "incident_manual_sample", "reaudit_cadence_pairs", "official_contests", "input_manifest"}
SEVERITIES = ["critical", "high", "medium", "low", "info", "gas", "unknown"]
STATUSES = ["fixed", "partially_fixed", "acknowledged", "unresolved", "not_stated"]
MODES = ["firm_review", "contest"]
SHARD_BYTES = 2_000_000
INDEX_ROWS = 25_000


def typed(v: str):
    if v == "":
        return None
    if v in ("True", "False"):
        return v == "True"
    try:
        i = int(v)
        return i
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        return v


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="") as fh:
        return [{k: typed(v) for k, v in row.items()} for row in csv.DictReader(fh)]


def dump(path: Path, obj) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    path.write_text(data, encoding="utf-8")
    return len(data.encode("utf-8"))


def doc_engagements() -> dict[str, str]:
    """document_id -> engagement_id (primary role preferred)."""
    try:
        import duckdb  # type: ignore
        con = duckdb.connect(str(ROOT / "data" / "corpus.duckdb"), read_only=True)
        rows = con.execute("select document_id, engagement_id, role from engagement_documents").fetchall()
        out: dict[str, str] = {}
        for doc, eng, role in sorted(rows, key=lambda r: r[2] != "primary"):
            out.setdefault(doc, eng)
        return out
    except Exception as exc:  # noqa: BLE001
        print(f"duckdb unavailable ({exc}); falling back to finding_streams.csv", file=sys.stderr)
        out = {}
        with (ANALYSIS / "finding_streams.csv").open(newline="") as fh:
            for row in csv.DictReader(fh):
                out[row["document_id"]] = row["engagement_id"]
        return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--firms", default=",".join(DEFAULT_FIRMS))
    ap.add_argument("--out", default=str(ROOT / "site" / "dev-data"))
    args = ap.parse_args()
    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    # ---- stats -------------------------------------------------------------------------------------------
    for path in sorted(ANALYSIS.glob("*.csv")):
        if path.stem in ROW_LEVEL:
            continue
        dump(out / "stats" / f"{path.stem}.json", read_csv(path))

    # ---- engagements ---------------------------------------------------------------------------------------
    eng_rows = read_csv(ANALYSIS / "engagements.csv")
    streams = {r["engagement_id"]: r for r in read_csv(ANALYSIS / "finding_streams.csv")}
    pages = {r["industry_engagement_id"]: r for r in read_csv(ANALYSIS / "report_pages.csv")}
    engagements: dict[str, dict] = {}
    by_firm_eng: dict[str, list] = defaultdict(list)
    for r in eng_rows:
        s = streams.get(r["engagement_id"], {})
        p = pages.get(r["industry_engagement_id"], {})
        mode = "contest" if r["publisher_kind"] == "contest_platform" else "firm_review"
        e = {
            "engagement_id": r["engagement_id"],
            "project": r["project"],
            "review_mode": mode,
            "audit_year": r["audit_year"] if isinstance(r["audit_year"], int) else None,
            "audit_date_min": r["audit_date_min"],
            "audit_date_max": r["audit_date_max"],
            "publication_year": r["publication_year"] if isinstance(r["publication_year"], int) else None,
            "findings_count": r["formal_findings"] if r["findings_observed"] else None,
            "report_url": s.get("public_url") or p.get("public_url"),
            "report_sha256": p.get("sha256"),
            "pages": p.get("pages"),
        }
        engagements[r["engagement_id"]] = e
        by_firm_eng[r["publisher_id"]].append(e)
    for firm, rows in by_firm_eng.items():
        rows.sort(key=lambda e: (-(e["audit_year"] or 0), e["project"] or ""))
        dump(out / "engagements" / f"{firm}.json", rows)

    # ---- firms (base) -----------------------------------------------------------------------------------
    registry = {r["firm_id"]: r for r in read_csv(ROOT / "registry" / "firms.csv")}
    fbf = {r["publisher_id"]: r for r in read_csv(ANALYSIS / "findings_by_firm.csv")}
    try:
        import duckdb  # type: ignore
        con = duckdb.connect(str(ROOT / "data" / "corpus.duckdb"), read_only=True)
        publishers = {p: (n, k) for p, n, k in con.execute(
            "select publisher_id, name, publisher_kind from publishers").fetchall()}
    except Exception:  # noqa: BLE001
        publishers = {}
    kinds = {r["publisher_id"]: r["publisher_kind"] for r in eng_rows}
    names = {r["publisher_id"]: r["name"] for r in read_csv(ANALYSIS / "firm_first_last_year.csv")}
    for r in read_csv(ANALYSIS / "top20_firms.csv"):
        names[r["publisher_id"]] = r["name"]

    firm_ids = sorted(by_firm_eng)
    selected = firm_ids if args.all else [f for f in args.firms.split(",") if f]

    doc2eng = doc_engagements()
    sev_i = {s: i for i, s in enumerate(SEVERITIES)}
    st_i = {s: i for i, s in enumerate(STATUSES)}
    mode_i = {m: i for i, m in enumerate(MODES)}
    leaves: list[str] = []
    leaf_i: dict[str, int] = {}
    manifest_shards = []
    firm_extra: dict[str, dict] = {}
    total_findings = 0
    reports = set()

    for firm in selected:
        fpath = FINDINGS / f"{firm}.jsonl"
        if not fpath.exists():
            continue
        cls = {}
        cpath = CLASSIFIED / f"{firm}.jsonl"
        if cpath.exists():
            with cpath.open() as fh:
                for line in fh:
                    c = json.loads(line)
                    cls[c["finding_id"]] = c
        items = []
        with fpath.open() as fh:
            for line in fh:
                d = json.loads(line)
                if d.get("record_kind") != "formal_finding":
                    continue
                eng = engagements.get(doc2eng.get(d.get("document_id"), ""), {})
                c = cls.get(d["finding_id"], {})
                span = (d.get("body_span") or {}).get("pages") or []
                leaf = c.get("leaf")
                items.append({
                    "finding_uid": d["finding_id"],
                    "finding_id": d.get("publisher_finding_id"),
                    "title": d.get("title") or d.get("title_raw") or "",
                    "severity": d.get("severity") or "unknown",
                    "severity_original": d.get("severity_original"),
                    "status": d.get("status") or "not_stated",
                    "status_original": d.get("status_original"),
                    "vuln_group": c.get("category") or (leaf.split(".")[0] if leaf else None),
                    "vuln_leaf": leaf,
                    "vuln_confidence": c.get("confidence"),
                    "vuln_needs_review": c.get("needs_review"),
                    "body_text": d.get("body_text") or "",
                    "page_start": min(span) if span else d.get("page"),
                    "page_end": max(span) if span else d.get("page"),
                    "engagement_id": eng.get("engagement_id"),
                    "report_id": d.get("sha256"),
                    "url": d.get("public_url"),
                    "project": eng.get("project"),
                    "audit_year": eng.get("audit_year"),
                    "review_mode": eng.get("review_mode") or (
                        "contest" if kinds.get(firm) == "contest_platform" else "firm_review"),
                })
                if d.get("sha256"):
                    reports.add(d["sha256"])
        items.sort(key=lambda f: (-(f["audit_year"] or 0), f["engagement_id"] or "", f["finding_uid"]))
        # finding shards
        shard, size, buf, shard_of = 0, 0, [], {}
        for f in items:
            n = len(json.dumps(f, ensure_ascii=False).encode("utf-8")) + 1
            if buf and size + n > SHARD_BYTES:
                dump(out / "findings" / firm / f"{shard}.json", {"firm_id": firm, "shard": shard, "findings": buf})
                shard, size, buf = shard + 1, 0, []
            buf.append(f)
            size += n
            shard_of[f["finding_uid"]] = shard
        if buf:
            dump(out / "findings" / firm / f"{shard}.json", {"firm_id": firm, "shard": shard, "findings": buf})
        # search index
        sev_c, st_c, cls_c = Counter(), Counter(), Counter()
        for k in range(0, len(items), INDEX_ROWS):
            part = items[k:k + INDEX_ROWS]
            projects: list[str] = []
            proj_i: dict[str, int] = {}
            rows = []
            for f in part:
                p = f["project"] or ""
                if p not in proj_i:
                    proj_i[p] = len(projects)
                    projects.append(p)
                leaf = f["vuln_leaf"]
                if leaf and leaf not in leaf_i:
                    leaf_i[leaf] = len(leaves)
                    leaves.append(leaf)
                rows.append([
                    f["finding_uid"].split(":")[-1][:12], f["title"], proj_i[p], f["audit_year"] or 0,
                    sev_i.get(f["severity"], 6), st_i.get(f["status"], 4), leaf_i[leaf] if leaf else -1,
                    mode_i[f["review_mode"]], shard_of[f["finding_uid"]], f["finding_id"] or "",
                ])
            name = f"index-{firm}.json" if len(items) <= INDEX_ROWS else f"index-{firm}-{k // INDEX_ROWS}.json"
            manifest_shards.append({"file": name, "firm_id": firm, "count": len(rows)})
            dump(out / "search" / name, {"firm_id": firm, "projects": projects, "rows": rows})
        for f in items:
            sev_c[f["severity"]] += 1
            st_c[f["status"]] += 1
            if f["vuln_group"]:
                cls_c[f["vuln_group"]] += 1
        firm_extra[firm] = {"findings": len(items), "severity": dict(sev_c), "status": dict(st_c),
                            "classes": dict(cls_c.most_common())}
        total_findings += len(items)
        print(f"{firm}: {len(items)} findings, {shard + 1} shards", file=sys.stderr)

    # leaf dictionary is global; write it into every index file header
    fields = ["id", "title", "project", "year", "severity", "status", "leaf", "mode", "shard", "finding_id"]
    dicts = {"severity": SEVERITIES, "status": STATUSES, "leaf": leaves, "mode": MODES}
    for s in manifest_shards:
        p = out / "search" / s["file"]
        obj = json.loads(p.read_text())
        obj = {"firm_id": obj["firm_id"], "fields": fields, "dicts": dicts, **obj}
        dump(p, obj)
    dump(out / "search" / "manifest.json", {"version": 1, "fields": fields, "shards": manifest_shards})

    firms = []
    for firm in firm_ids:
        reg = registry.get(firm, {})
        status_path = ROOT / "data" / "collect" / firm / "status.json"
        listed = collected = None
        if status_path.exists():
            st = json.loads(status_path.read_text())
            listed, collected = st.get("listed_count"), st.get("collected")
        years = [e["audit_year"] for e in by_firm_eng[firm] if e["audit_year"]]
        base = fbf.get(firm, {})
        extra = firm_extra.get(firm, {})
        pub = publishers.get(firm, (None, None))
        firms.append({
            "firm_id": firm,
            "name": names.get(firm) or pub[0] or reg.get("name") or firm,
            "kind": kinds.get(firm) or pub[1] or reg.get("kind"),
            "website": reg.get("website"),
            "reports_listed": listed,
            "reports_collected": collected,
            "coverage_pct": round(100 * collected / listed, 1) if listed and collected is not None else None,
            "first_year": min(years) if years else None,
            "last_year": max(years) if years else None,
            "engagements": len(by_firm_eng[firm]),
            "findings": extra.get("findings", base.get("formal_findings")),
            "severity": extra.get("severity") or {s: base.get(s) for s in SEVERITIES if base.get(s) is not None},
            "status": extra.get("status") or {},
            "classes": extra.get("classes") or {},
        })
    dump(out / "firms.json", firms)

    run = {r["metric"]: r["value"] for r in read_csv(ANALYSIS / "run_summary.csv")}
    summary = {
        "as_of": run.get("as_of"),
        "fixture": True,
        "counts": {
            "industry_engagements": run.get("industry_engagements"),
            "publisher_engagements": run.get("publisher_engagements"),
            "findings": total_findings,
            "findings_analysed": run.get("formal_findings"),
            "reports": len(reports) if args.all else None,
            "publishers": len(firms),
            "firms": sum(1 for f in firms if f["kind"] != "contest_platform"),
            "contest_platforms": sum(1 for f in firms if f["kind"] == "contest_platform"),
        },
        "quality": read_csv(ANALYSIS / "quality_measurements.csv"),
    }
    dump(out / "summary.json", summary)
    print(f"wrote {out} ({total_findings} findings)", file=sys.stderr)


if __name__ == "__main__":
    main()
