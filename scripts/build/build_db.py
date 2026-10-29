#!/usr/bin/env python3
"""Build a local DuckDB snapshot. Never execute export code or fetch originals."""
from __future__ import annotations

import argparse
import csv
from datetime import date, datetime
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import unicodedata
import uuid
from urllib.parse import unquote, urlsplit

import duckdb
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.append(str(Path(__file__).resolve().parents[1] / "findings"))
from core import severity_mapping as publisher_severity_mapping
from status_resolve import status_mapping as publisher_status_mapping

ROOT = Path(__file__).resolve().parents[2]
EXPORTS = {
    "shieldify": ("shieldify/release/data", "shieldify"),
    "codespect": ("codespect", "codespect"),
    "composable_security": ("composable_security", "composable-security"),
    "movebit": ("movebit/movebit_dataset_9f2027e", "movebit"),
    "neodyme_v1": ("neodyme_v1/neodyme_dataset", "neodyme"),
    "obsidian_pilot": ("obsidian_pilot/obsidian_audits_recovery_2026-10-18", "obsidian-audits"),
    "omega_resume": ("omega_resume/omega_dataset_resume", "teamomega"),
}
# Historical names in the inventories; never fuzzy-match an unknown auditor.
ALIASES = {
    "abdk": "abdk-consulting", "ackee": "ackee-blockchain",
    "pashov": "pashov-audit-group", "oaksecurity": "oak-security",
    "sigmaprime": "sigma-prime", "runtimeverification": "runtime-verification",
    "trailofbits": "trail-of-bits", "omegaaudits": "teamomega",
    "composable": "composable-security", "informal": "informalsystems",
    "shieldifysecurity": "shieldify", "code423n4": "code4rena",
    "consensys": "consensys-diligence", "diligence": "consensys-diligence",
    "hatsfinance": "hats-finance", "threesigma": "three-sigma",
    "yaudit": "electisec", "yacademy": "electisec",
    "neodymeag": "neodyme", "codespectsecurity": "codespect",
}
REPORT_FIELDS = set("firm_id collector source_kind public_url listing_url sha256 bytes file_format local_path filename title_hint project_hint date_hint date_precision date_basis doc_kind retrieved_utc notes".split())
CONTEST_FIELDS = set("contest_id platform name start_utc end_utc format report_url findings_high findings_medium sha256".split())


def js(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else js(value).encode()).hexdigest()


def uid(kind, *parts):
    return kind + ":" + digest(parts)


def get(value, path, default=None):
    for key in path.split("."):
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


def first(*values):
    return next((v for v in values if v is not None and v != ""), None)


def label(value):
    return first(value.get("raw"), value.get("normalized")) if isinstance(value, dict) else value


def parsed(value):
    v = json.loads(value) if isinstance(value, str) and value.strip() else value
    return v if isinstance(v, dict) else {}


def norm(value):
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKD", unquote(str(value or ""))).encode("ascii", "ignore").decode().lower())


def publisher_aliases(publishers):
    result = {norm(v): p for p, r in publishers.items() for v in (p, r["name"]) if norm(v)}
    result.update({k: v for k, v in ALIASES.items() if v in publishers})
    return result


def load_publishers(root):
    with (root / "registry/scope_tier_a.csv").open(newline="") as f:
        return {r["firm_id"]: r for r in csv.DictReader(f)
                if r["scope_group"] in {"firm", "contest_platform"}}


def severity(raw, source_normalized=None, publisher=None):
    value = raw if raw is not None else source_normalized
    return publisher_severity_mapping(value, publisher)["normalized"]


def status(raw, publisher=None, **kwargs):
    return publisher_status_mapping(raw, publisher, **kwargs)['normalized']


def iso(value):
    """Keep stated precision, without inventing a day or fixing invalid dates."""
    if not isinstance(value, str) or not value.strip():
        return None, "none"
    text = value.strip()
    if re.fullmatch(r"\d{4}(?:-\d{2}(?:-\d{2})?)?", text):
        try:
            date.fromisoformat(text + {4: "-01-01", 7: "-01", 10: ""}[len(text)])
            return text, {4: "year", 7: "month", 10: "day"}[len(text)]
        except ValueError:
            return None, "none"
    text = re.sub(r"(?<=\d)(st|nd|rd|th)\b", "", text, flags=re.I)
    text = re.sub(r"\s+", " ", text.replace(",", " ")).strip()
    for fmt in ("%d %B %Y", "%d %b %Y", "%B %d %Y", "%b %d %Y"):
        try:
            return datetime.strptime(text, fmt).date().isoformat(), "day"
        except ValueError:
            pass
    return None, "none"


def file_format(value, url=""):
    text = str(value or Path(urlsplit(url).path).suffix.lstrip(".")).lower()
    return {"markdown": "md", "htm": "html"}.get(text, text) if text in {"pdf", "md", "markdown", "html", "htm"} else "other"


class Builder:
    def __init__(self, root, snapshot_inputs=None, allow_uncached_abstentions=False):
        self.root = Path(root).resolve()
        self.allow_uncached_abstentions = bool(allow_uncached_abstentions)
        self.snapshot_inputs=Path(snapshot_inputs).resolve() if snapshot_inputs else None
        if self.snapshot_inputs:
            if not self.snapshot_inputs.is_relative_to(self.root/'local-cache') or self.snapshot_inputs.exists():
                raise ValueError('Input snapshot must be a new directory under local-cache')
            (self.snapshot_inputs/'registry').mkdir(parents=True)
            (self.snapshot_inputs/'registry/scope_tier_a.csv').write_bytes((self.root/'registry/scope_tier_a.csv').read_bytes())
        self.publishers = load_publishers(self.root)
        self.aliases = publisher_aliases(self.publishers)
        self.tables = {t: {} for t in ("documents", "engagements", "engagement_documents", "document_exclusions", "engagement_identity_crosswalk", "findings", "date_claims", "contests", "import_sources")}
        self.report_map = {}
        # Freeze membership before parsing; later collector outputs enter the next build.
        self.collection_files = [p for p in sorted((self.root / "data/collect").glob("*/reports.jsonl")) + sorted((self.root / "data/collect").glob("*/contests.jsonl")) if p.parent.name in self.publishers]
        self.discovery_files = sorted((self.root / 'data/discovery').glob('*/candidates.jsonl'))

    def rows(self, path, tag, family, kind):
        """Read one immutable in-memory snapshot, with a file and row receipt."""
        path = Path(path)
        if path.is_symlink() or not path.resolve().is_relative_to(self.root):
            raise ValueError(f"Input outside root or symlink: {path}")
        before = path.stat()
        data = path.read_bytes()
        after = path.stat()
        if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
            raise ValueError(f"Input changed while reading; rerun: {path}")
        rel = path.relative_to(self.root).as_posix()
        if self.snapshot_inputs:
            target=self.snapshot_inputs/rel
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(data)
        if path.suffix == ".parquet":
            records = pq.read_table(io.BytesIO(data)).to_pylist()
            rows = [(r, f"record_id={r['record_id']}") for r in records]
        else:
            rows = [(json.loads(line), f"line={i}") for i, line in enumerate(data.decode("utf-8").split('\n'), 1) if line.strip()]
        ledger = dict(source_file=rel, source_tag=tag, source_family=family, row_kind=kind,
                      file_sha256=digest(data), bytes=len(data), source_rows=len(rows),
                      imported_rows=0, excluded_scope_rows=0, duplicate_rows=0)
        self.tables["import_sources"][rel] = ledger
        for raw, locator in rows:
            yield raw, dict(source_family=family, source_tag=tag, source_file=rel,
                            source_locator=locator, source_record_sha256=digest(raw)), ledger

    def add(self, table, key, row, ledger=None):
        old = self.tables[table].get(key)
        if old is not None:
            if old.get("source_record_sha256") and old.get("source_record_sha256")==row.get("source_record_sha256"):
                if ledger is not None:
                    ledger["duplicate_rows"] += 1
                return False
            # Identical repeated contract rows are harmless; inconsistent IDs fail loudly.
            ignored = {"source_locator"}
            if {k:v for k,v in old.items() if k not in ignored} != {k:v for k,v in row.items() if k not in ignored}:
                raise ValueError(f"Conflicting {table} identity: {key}")
            if ledger is not None:
                ledger["duplicate_rows"] += 1
            return False
        self.tables[table][key] = row
        if ledger is not None:
            ledger["imported_rows"] += 1
        return True

    def document(self, raw, meta, publisher, source_id, **fields):
        did = uid("document", meta["source_tag"], source_id)
        row = dict(document_id=did, publisher_id=publisher, **meta, source_record_id=source_id,
                   collector=None, source_kind="aggregator", public_url=None, url_kind="original",
                   listing_url=None, sha256=None, hash_verification="unknown", bytes=None,
                   file_format="other", local_path=None, wayback_url=None, metadata={}, filename=None, title=None, project=None,
                   project_basis=None, doc_kind="unknown", counting_role="primary", is_seed=False,
                   retrieved_utc=None, chains=None, languages=None, coverage={}, rights={},
                   relationships=[], notes=[], provenance={"retained_record": meta}, field_state={})
        row.update(fields)
        row["field_state"].update({k: "absent_in_source" for k,v in row.items() if v is None})
        if not row["public_url"]:
            raise ValueError(f"No public URL: {meta['source_file']} {source_id}")
        return row

    def engagement(self, doc):
        if doc["is_seed"] or doc["counting_role"] != "primary" or doc["doc_kind"] in {"non_report", "unknown"}:
            return None
        eid = uid("engagement", doc["publisher_id"], doc["sha256"] or doc["document_id"])
        if eid not in self.tables["engagements"]:
            self.tables["engagements"][eid] = dict(
                engagement_id=eid, publisher_id=doc["publisher_id"], industry_engagement_id=None,
                project=doc["project"], engagement_kind={"contest_report":"contest", "formal_verification":"formal_verification"}.get(doc["doc_kind"], "audit"),
                identity_status="provisional", identity_basis="original_sha256_candidate" if doc["sha256"] else "source_report_candidate",
                evidence={"document_id":doc["document_id"], "sha256":doc["sha256"]},
                notes=["Revision, translation and joint-audit adjudication required before counting."])
        self.link(eid, doc["document_id"], "primary")
        return eid

    def link(self, eid, did, role):
        self.tables["engagement_documents"][(eid,did)] = dict(engagement_id=eid, document_id=did, role=role, evidence={"basis":"source_explicit_alternate" if role == "alternate" else "artifact_candidate"})

    def claim(self, target, source_tag, key, value, role, basis="document_text", authority="publisher", end=None, evidence=None):
        if value is None:
            return
        normalized, precision = iso(value)
        date_end, _ = iso(end)
        row = dict(claim_id=uid("date", target, source_tag, key), document_id=None, engagement_id=None, finding_id=None,
                   source_tag=source_tag, role=role, raw_value=value if isinstance(value,str) else js(value), date_value=normalized,
                   date_end=date_end, precision=precision, basis=basis, authority=authority,
                   eligible_for_audit_year=bool(normalized and role in {"audit_completion", "report_issue"} and basis in {"document_text", "contest_end", "publisher_api"} and authority == "publisher"),
                   evidence={"field":key, "assertion":evidence, "raw_end":end})
        row.update(target)
        self.add("date_claims", row["claim_id"], row)

    def firm_dates(self, name, r, doc):
        target, tag = {"document_id":doc["document_id"]}, doc["source_tag"]
        def add(key, value, role, **kw):
            self.claim(target, tag, key, value, role, **kw)
        if name == "shieldify":
            add("date_published", r.get("date_published"), "report_issue", authority="inherited_unverified")
            for i,v in enumerate(r.get("dates", [])):
                add(f"dates[{i}]", v, "other", authority="inherited_unverified")
        elif name in {"codespect", "omega_resume"}:
            for k,role in [("cover_date_iso","report_issue"),("final_report_iso","report_issue"),("draft_report_iso","other")]:
                add("source_metadata.report_metadata_rights."+k, get(r,"source_metadata.report_metadata_rights."+k), role)
            for k, role in [("filename","filename_hint"),("publication","publication"),("website","publication")]:
                v=get(r,"dates."+k,{})
                add("dates."+k, first(v.get("iso"),v.get("raw")), role, basis="filename" if k=="filename" else "listing", authority="inherited_unverified", evidence=v)
            for i,v in enumerate(get(r,"dates.printed",[])):
                add(f"dates.printed[{i}]",first(v.get("iso"),v.get("raw")),"other", evidence=v)
        elif name in {"composable_security", "movebit"}:
            for i,v in enumerate(get(r,"normalized.dates",[])):
                val=v.get("value") or v
                kind=v.get("role") or v.get("kind")
                role="report_issue" if kind in {"report_date","cover_date","report_cover_date"} else "retest" if kind=="retest_time_period" else "other"
                interval=bool(val.get("start") and val.get("end"))
                add(f"normalized.dates[{i}]",first(val.get("date"),val.get("start")), "audit_start" if interval and kind in {"test_time_period","audit_timeline"} else role, end=val.get("end"), evidence=v)
                if interval and kind in {"test_time_period","audit_timeline"}:
                    add(f"normalized.dates[{i}].end",val.get("end"),"audit_completion",evidence=v)
            for i,v in enumerate(get(r,"publisher.date_assertions",get(r,"publisher.dates",[]))):
                add(f"publisher.dates[{i}]",v.get("value_raw"),"other",evidence=v)
        elif name == "neodyme_v1":
            for k,role,basis in [("index_published_date","publication","listing"),("report_authored_date","report_issue","document_text"),("report_date_standalone","report_issue","document_text"),("report_last_updated_date","retest","document_text")]:
                add(k,r.get(k),role,basis=basis)
            for i,v in enumerate(r.get("review_period_candidates",[])):
                add(f"review_period_candidates[{i}]",v.get("period"),"other", evidence=v)
        elif name == "obsidian_pilot":
            for k,role in [("cover_date","report_issue"),("audit_start_date","audit_start"),("audit_end_date","audit_completion")]:
                add(k,r.get(k),role,authority="inherited_unverified")

    def import_firms(self):
        for name,(rel,publisher) in EXPORTS.items():
            if publisher not in self.publishers:
                raise ValueError(f"Kept firm absent from scope: {publisher}")
            tag="firm:"+name
            native_reports={}
            for r,meta,ledger in self.rows(self.root/"extracted"/rel/"reports.jsonl",tag,"firm_export","reports"):
                project=first(label(r.get("project")),get(r,"publisher.project"))
                fallback=first(label(r.get("client")),get(r,"publisher.client"))
                urls=first(r.get("source_urls"),r.get("all_source_urls"),get(r,"provenance.source_urls"),[])
                url=first(r.get("source_url"),r.get("primary_source_url"),get(r,"source.source_url"),urls[0] if urls else None)
                sha=first(r.get("sha256"),get(r,"artifact.sha256"),get(r,"source.sha256"))
                retrieved=first(r.get("retrieved_at"),r.get("retrieval_timestamp"),get(r,"source.retrieved_at"))
                if not retrieved and get(r,"provenance.retrieval_times"):
                    retrieved=r["provenance"]["retrieval_times"][0]["retrieved_at"]
                role="primary" if name!="shieldify" or r.get("is_counted_audit") else "alternate"
                chain=first(get(r,"normalized.chain"),get(r,"publisher.chain"),get(r,"audited_scope.chains"))
                doc=self.document(r,meta,publisher,r["report_id"],public_url=url,source_kind="github" if "github" in url else "website",
                    sha256=sha,hash_verification="manifest_attested" if sha else "unknown",
                    bytes=first(r.get("byte_size"),r.get("size_bytes"),get(r,"artifact.size_bytes"),get(r,"source.byte_size"),get(r,"source.bytes")),
                    file_format=file_format(r.get("format"),url),filename=Path(urlsplit(url).path).name,
                    title=first(label(r.get("title")),get(r,"publisher.title")),project=first(project,fallback),
                    project_basis="publisher_project" if project else "client_fallback" if fallback else None,
                    doc_kind="audit_report",counting_role=role,retrieved_utc=retrieved,
                    chains=([chain] if isinstance(chain,str) else chain) or None,
                    coverage={k:r[k] for k in ["coverage","coverage_status","extraction","review","finding_summary","finding_counts","extraction_status","record_validation_status","expected_finding_entries_from_prior_review"] if k in r},
                    rights=r.get("rights") or {"full_text":r.get("rights_for_full_text"),"caveats":r.get("rights_confidentiality_caveats")},
                    relationships=first(r.get("revision_relationships"),r.get("version_relationships"),[]),
                    provenance={"retained_record":meta,"source_row":r},notes=r.get("notes") or [])
                self.add("documents",doc["document_id"],doc,ledger)
                self.report_map[(tag,r["report_id"])]=doc["document_id"]
                native_reports[r["report_id"]]=r
                self.engagement(doc)
                self.firm_dates(name,r,doc)
            # Only explicit source links attach alternate renderings to a candidate.
            for rid,r in native_reports.items():
                doc=self.tables["documents"][self.report_map[(tag,rid)]]
                if doc["counting_role"]=="primary":
                    eid=self.engagement(doc)
                    for alt in r.get("alternate_format_ids",[]):
                        did=self.report_map.get((tag,alt))
                        if eid and did:
                            self.link(eid,did,"alternate")
            for f,meta,ledger in self.rows(self.root/"extracted"/rel/"findings.jsonl",tag,"firm_export","findings"):
                did=self.report_map[(tag,f["report_id"])]
                self.import_finding(f,meta,ledger,publisher,did,name)

    def import_finding(self, f, meta, ledger, publisher, did, name=None):
        seed=meta["source_family"]=="audit_analysis"
        sid=f["record_id"] if seed else f["finding_id"]
        raw=first(f.get("severity_raw") if seed else f.get("severity_original"), f.get("severity") if name=="neodyme_v1" else None, get(f,"publisher.severity"),get(f,"original.severity.raw"))
        source_normalized=first(f.get("severity_normalized"),f.get("severity") if name=="neodyme_v1" else None,get(f,"normalized.severity"))
        raw_status=first(f.get("status_raw"),f.get("status_original"),get(f,"publisher.status"),get(f,"original.status.raw"))
        title_raw=first(f.get("title_raw"),get(f,"publisher.title_raw"),get(f,"publisher.title"),get(f,"original.title.raw"),f.get("title"))
        title=first(f.get("title"),get(f,"normalized.title"),get(f,"original.title.normalized"),title_raw)
        native_kind=f.get("record_kind") or f.get("item_type") or "formal_finding"
        kind={"detailed_published_finding":"formal_finding","finding":"formal_finding","unnumbered_remediation_review":"remediation_review"}.get(native_kind,native_kind)
        if kind not in {"formal_finding","recommendation","remediation_review","observation","summary_excerpt","candidate","unknown"}:
            kind="unknown"
        if seed:
            kind="candidate"
        severity_input = raw if raw is not None else source_normalized
        severity_map = publisher_severity_mapping(severity_input, publisher, kind=kind,
            sha256=self.tables["documents"][did].get("sha256") if did else None)
        severity_map.update(raw=raw, source_normalized=source_normalized,
            basis="source_normalized_only" if raw is None and source_normalized is not None else "publisher_raw_label")
        status_map = publisher_status_mapping(raw_status,publisher,
            sha256=self.tables['documents'][did].get('sha256') if did else None)
        category_raw=first(f.get("source_category"),f.get("category_original"),get(f,"publisher.category"),get(f,"original.category.raw"))
        responses=list(f.get("attributed_responses") or [])
        if f.get("response") and f.get("response_attribution"):
            responses.append({"actor":f["response_attribution"],"text":f["response"],"basis":"source_explicit_attribution"})
        for response_key in ["client_response","auditor_response"]:
            response=get(f,"original."+response_key+".raw")
            if response:
                responses.append({"actor":response_key,"text":response,"basis":"source_explicit_label"})
        if f.get("attributed_response"):
            responses.append({"actor":f.get("attributed_response_source_label"),"text":f["attributed_response"],"evidence":f.get("attributed_response_evidence")})
        row=dict(finding_id=uid("finding",meta["source_tag"],sid),publisher_id=publisher,document_id=did,**meta,
            source_record_id=sid,is_seed=seed,publisher_finding_id=first(f.get("publisher_finding_id"),f.get("publisher_id"),get(f,"publisher.publisher_id"),get(f,"publisher.id"),get(f,"original.id.raw")),
            ordinal=first(f.get("ordinal"),get(f,"provenance.source_order"),get(f,"source_anchor.detail_ordinal")),occurrence=f.get("occurrence"),
            record_kind=kind,finding_phase=f.get("finding_phase"),title=title,title_raw=title_raw,severity_raw=raw,severity_source_normalized=source_normalized,
            severity=severity_map["normalized"],severity_mapping=severity_map,
            category_raw=category_raw,category_semantics="section_kind" if name=="composable_security" else "source_category" if seed and category_raw else "unknown",category=None,
            status_raw=raw_status,status=status_map['normalized'],status_authority=first(f.get("status_authority"),f.get("status_source"),"publisher_inherited" if raw_status else None),
            description=first(f.get("description"),f.get("content"),get(f,"publisher.description"),get(f,"original.description.raw"),f.get("raw_text") if seed else None),
            recommendation=first(f.get("recommendation"),get(f,"publisher.recommendation"),get(f,"original.recommendation.raw")),
            resolution=first(f.get("resolution"),get(f,"publisher.resolution"),get(f,"original.resolution.raw")),
            attributed_responses=responses,
            evidence={k:f[k] for k in ["evidence","references","provenance","field_evidence","boundary","source_anchor","status_evidence"] if k in f},
            review={k:f[k] for k in ["review","extraction","counting","extraction_confidence","status_authority"] if k in f},relationships=get(f,"research.duplicate_relationships",[]),
            unique_vulnerability_id=None,public_url=first(f.get("source_url"),f.get("original_source_url"), self.tables["documents"][did]["public_url"] if did else None),
            provenance={"retained_record":meta, "source_row":{k:v for k,v in f.items() if k not in {"raw_text","raw_record_json"}} if seed else f},field_state=dict(f.get("field_availability") or {}))
        row["field_state"].update({k:"absent_in_source" for k,v in row.items() if v is None and k not in row["field_state"]})
        row['evidence']['status_mapping'] = status_map
        self.add("findings",row["finding_id"],row,ledger)

    def seed_publisher(self, r, parents=None):
        """Same attribution strata as the triage; directory owners aren't auditors."""
        src=r["source"]
        raw=parsed(r.get("raw_record_json"))
        firm=None
        if parents is not None:
            firm=parents.get(r.get("report_record_id"))
            if src in {"agentlisa/bench","GiAnt/19325553"}:
                u=unquote(r.get("original_source_url") or "")
                if re.search(r"https?://(?:www\.)?code4rena\.com/(?:reports|contests)/20\d{2}-\d{2}-",u,re.I) or re.search(r"https?://(?:raw\.githubusercontent\.com|github\.com)/code-423n4/20\d{2}-\d{2}-[^/]+-findings(?:/|$)",u,re.I):
                    firm="code4rena"
                else:
                    firm=None
            elif src=="immunefi":
                firm=src
        elif src=="gcf3711/audit-report-archive":
            firm=r.get("publisher")
        elif src=="code4rena":
            firm="code4rena"
        elif str(r.get("extraction_method") or "").startswith("publisher_document") and src not in {"nearbuilders","anza-xyz","monethic","sui-foundation","timimm"}:
            firm=raw.get("publisher") or src
        elif src=="cantina":
            firm=src
        publisher=self.aliases.get(norm(firm))
        # These publishers enter only through the specifically reviewed public
        # collection manifests, never inherited archive/internal seed material.
        return None if publisher in {'certik','hacken'} else publisher

    def import_seeds(self):
        base=self.root/"extracted/audit_analysis/parquet"
        parents={}
        for r,meta,ledger in self.rows(base/"reports.parquet","seed:audit_analysis:reports","audit_analysis","reports"):
            publisher=self.seed_publisher(r)
            parents[r["record_id"]]=publisher
            if not publisher:
                ledger["excluded_scope_rows"]+=1
                continue
            meta["source_tag"]="seed:audit_analysis:"+r["source"]
            url=first(r.get("report_url"),r.get("source_url"))
            doc=self.document(r,meta,publisher,r["record_id"],source_kind="aggregator",public_url=url,url_kind="discovery",is_seed=True,counting_role="seed",
                title=r.get("title"),project=r.get("project"),project_basis="catalog_unverified" if r.get("project") else None,
                listing_url=r.get("source_url"),file_format=file_format(None,url),retrieved_utc=r.get("retrieved_at"),
                coverage={"extraction_method":r.get("extraction_method"),"document_acquired_claim":r.get("document_acquired"),"missing_body":r.get("missing_body")},
                rights={"license_status":r.get("license_status"),"release":"links_only"},
                provenance={"retained_record":meta,"upstream_record_id":r.get("source_record_id"),"raw_sha256":r.get("raw_sha256"),"raw_hash_kind":"container_or_unverified","content_sha256":r.get("content_sha256"),"source_provenance":parsed(r.get("provenance_json"))},
                notes=["Discovery occurrence; no engagement created and no original hash inferred."])
            self.add("documents",doc["document_id"],doc,ledger)
            self.report_map[("seed",r["record_id"])]=doc["document_id"]
            self.claim({"document_id":doc["document_id"]},meta["source_tag"],"publication_date",r.get("publication_date"),"catalog",basis="catalog",authority="catalog_unverified")
        for path in sorted(base.glob("findings*.parquet")):
            for f,meta,ledger in self.rows(path,"seed:audit_analysis:findings","audit_analysis","findings"):
                publisher=self.seed_publisher(f,parents)
                if not publisher:
                    ledger["excluded_scope_rows"]+=1
                    continue
                meta["source_tag"]="seed:audit_analysis:"+f["source"]
                did=self.report_map.get(("seed",f.get("report_record_id")))
                self.import_finding(f,meta,ledger,publisher,did)

    def import_collections(self):
        occurrence_ids={}
        for path in self.collection_files:
            if path.name!="reports.jsonl":
                continue
            for r,meta,ledger in self.rows(path,"collect:"+path.parent.name,"collected","reports"):
                if REPORT_FIELDS-r.keys():
                    raise ValueError(f"Missing contract fields in {path}: {sorted(REPORT_FIELDS-r.keys())}")
                publisher=r["firm_id"]
                if publisher not in self.publishers:
                    ledger["excluded_scope_rows"]+=1
                    continue
                if publisher!=path.parent.name:
                    raise ValueError(f"Collector directory/firm mismatch: {path}")
                if r['date_precision'] not in {'day','month','year','none'} or r['date_basis'] not in {'listing','filename','document_text','contest_end','none'}:
                    raise ValueError(f"Invalid date contract enum: {path}")
                value, precision=iso(r['date_hint'])
                date_issues=[]
                if precision!=r['date_precision'] or (r['date_hint'] and value!=r['date_hint']):
                    date_issues.append('invalid_date_hint_or_precision')
                sid=uid("collected",r["collector"],r["public_url"],r["sha256"])
                # The contract has no upstream row ID. Distinct listing assertions
                # for identical bytes remain separate source occurrences; titles
                # and dates do not define their persistent identity.
                variants=occurrence_ids.setdefault((meta['source_tag'],sid),[])
                if meta['source_record_sha256'] in variants:
                    ledger['duplicate_rows']+=1
                    continue
                variants.append(meta['source_record_sha256'])
                if len(variants)>1:
                    sid+=':occurrence:'+str(len(variants))
                doc=self.document(r,meta,publisher,sid,collector=r["collector"],source_kind=r["source_kind"],public_url=r["public_url"],listing_url=r["listing_url"],sha256=r["sha256"],
                    hash_verification="collector_attested" if r["sha256"] else "unknown",bytes=r["bytes"],file_format=r["file_format"],local_path=r["local_path"],filename=r["filename"],
                    title=r["title_hint"],project=r["project_hint"],project_basis="collector_hint" if r["project_hint"] else None,doc_kind=r["doc_kind"],
                    counting_role="lead" if r["doc_kind"] in {"unknown","non_report"} else "primary",retrieved_utc=r["retrieved_utc"],coverage={"collector_record":True},rights={"release":"links_only"},notes=r["notes"] if r['notes'] is not None else [],provenance={"retained_record":meta,"source_row":r})
                if self.add("documents",doc["document_id"],doc,ledger):
                    self.engagement(doc)
                    self.claim({"document_id":doc["document_id"]},meta["source_tag"],"date_hint",r["date_hint"],"filename_hint" if r["date_basis"]=="filename" else "audit_completion" if r["date_basis"]=="contest_end" else "other" if r["date_basis"]=="document_text" else "publication",basis=r["date_basis"],authority="collector_hint",evidence={"declared_precision":r["date_precision"] ,"issues":date_issues})
        for path in self.collection_files:
            if path.name!="contests.jsonl":
                continue
            for r,meta,ledger in self.rows(path,"collect:"+path.parent.name,"collected","contests"):
                if CONTEST_FIELDS-r.keys() or not any(k in r for k in ["sponsor/project","sponsor_project","project","sponsor"]):
                    raise ValueError(f"Missing contest contract fields in {path}")
                publisher=r["platform"]
                if publisher not in self.publishers:
                    ledger["excluded_scope_rows"]+=1
                    continue
                if publisher!=path.parent.name or self.publishers[publisher]["scope_group"]!="contest_platform":
                    raise ValueError(f"Contest platform mismatch: {path}")
                matches=[d for d in self.tables["documents"].values() if d["publisher_id"]==publisher and not d["is_seed"] and ((r.get("sha256") and d["sha256"]==r["sha256"]) or (r.get("report_url") and d["public_url"]==r["report_url"]))]
                # Preserve contest metadata without fabricating a collected document.
                matches=[d for d in matches if not (r.get('sha256') and d['sha256'] and r['sha256']!=d['sha256'])]
                doc=sorted(matches,key=lambda d:(d["sha256"]!=r.get('sha256'),d["source_family"]!="collected",d["document_id"]))[0] if matches else None
                eid=self.engagement(doc) if doc else None
                timing='unknown'
                if r['start_utc'] and r['end_utc']:
                    start=datetime.fromisoformat(r['start_utc'].replace('Z','+00:00'))
                    end=datetime.fromisoformat(r['end_utc'].replace('Z','+00:00'))
                    timing='source_conflict' if end<start else 'consistent'
                row=dict(contest_id=uid("contest",publisher,r["contest_id"]),publisher_id=publisher,platform_contest_id=str(r["contest_id"]),source_tag=meta["source_tag"],source_file=meta["source_file"],source_locator=meta["source_locator"],source_record_sha256=meta["source_record_sha256"],name=r["name"],sponsor_project=first(r.get("sponsor/project"),r.get("sponsor_project"),r.get("project"),r.get("sponsor")),start_utc=r["start_utc"],end_utc=r["end_utc"],format=r["format"],report_url=r["report_url"],findings_high=r["findings_high"],findings_medium=r["findings_medium"],sha256=r["sha256"],document_id=doc["document_id"] if doc else None,engagement_id=eid,provenance={"source_row":r,"retained_record":meta})
                row['timing_status']=timing
                if row['format'] not in {'public_contest','private','mitigation','bounty_boost','other'}:
                    row['format']='other'  # Preserve the native label verbatim in provenance.
                self.add("contests",row["contest_id"],row,ledger)
                if eid and r["end_utc"]:
                    self.claim({"engagement_id":eid},meta["source_tag"],"contest:"+str(r["contest_id"])+".end_utc",r["end_utc"][:10],"audit_completion",basis="contest_end",authority="inherited_unverified" if timing=='source_conflict' else "publisher",evidence={"contest_id":row["contest_id"],"timing_status":timing})

    def write(self, path):
        path=Path(path).resolve()
        for protected in ("extracted","inbox","data/collect"):
            if path.is_relative_to(self.root/protected):
                raise ValueError(f"Protected output path: {path}")
        if any(not e.get('audit_type') for e in self.tables['engagements'].values()):
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            from audit_types.run import apply_to_builder
            apply_to_builder(self)
        path.parent.mkdir(parents=True,exist_ok=True)
        temporary=path.with_name(path.name+".building."+uuid.uuid4().hex)
        if temporary.exists():
            raise ValueError(f"Build staging file already exists: {temporary}")
        con=duckdb.connect(str(temporary))
        con.execute('SET threads=3')
        try:
            con.execute("SET TimeZone='UTC'")
            con.execute((ROOT/"schema/corpus.sql").read_text())
            con.execute("BEGIN")
            pubs=[dict(publisher_id=p,name=r["name"] or p,publisher_kind=r["scope_group"],github_reports_url=r.get("github_reports_url") or None,website_reports_url=r.get("website_reports_url") or None,registry_record=r) for p,r in sorted(self.publishers.items())]
            for table,rows in [("publishers",pubs)]+[(t,list(self.tables[t].values())) for t in self.tables]:
                if not rows:
                    continue
                column_types={r[0]:r[1] for r in con.execute(f"DESCRIBE {table}").fetchall()}
                values=[{k:js(row[k]) if column_types[k]=='JSON' and row[k] is not None else row[k] for k in column_types} for row in rows]
                con.register("_input_batch",pa.Table.from_pylist(values))
                con.execute(f"INSERT INTO {table} SELECT * FROM _input_batch")
                con.unregister("_input_batch")
            con.execute("COMMIT")
            summary=count_summary(con)
            if hasattr(self, 'audit_type_merge_receipt'):
                summary['audit_type_cache'] = self.audit_type_merge_receipt
            con.execute("CHECKPOINT")
        finally:
            con.close()
        os.replace(temporary,path)
        return summary


def count_summary(con):
    result={t:con.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in ["publishers","documents","engagements","findings","date_claims","contests","counted_engagements"]}
    result["sources"]=[dict(zip(["source_family","reports","findings"],r)) for r in con.execute("SELECT source_family, sum(reports), sum(findings) FROM (SELECT source_family,count(*) reports,0 findings FROM documents GROUP BY 1 UNION ALL SELECT source_family,0,count(*) FROM findings GROUP BY 1) GROUP BY 1 ORDER BY 1").fetchall()]
    result["firm_exports"]=[dict(zip(["source_tag","primary_reports","primary_findings","all_reports","all_findings"],r)) for r in con.execute("SELECT d.source_tag,count(DISTINCT d.document_id) FILTER (WHERE d.counting_role='primary'), count(f.finding_id) FILTER (WHERE d.counting_role='primary'),count(DISTINCT d.document_id), count(f.finding_id) FROM documents d LEFT JOIN findings f USING (document_id) WHERE d.source_family='firm_export' GROUP BY 1 ORDER BY 1").fetchall()]
    return result


def print_summary(summary):
    print(' '.join(f'{k}={summary[k]}' for k in ['publishers','documents','engagements','counted_engagements','findings','date_claims','contests']))
    print('source                 documents  findings')
    for row in summary['sources']:
        print(f"{row['source_family']:22} {row['reports']:9,} {row['findings']:9,}")
    print('kept export              primary reports  primary findings')
    for row in summary['firm_exports']:
        print(f"{row['source_tag'].removeprefix('firm:'):24} {row['primary_reports']:15,} {row['primary_findings']:17,}")
    if summary.get('check'):
        print(f"{summary['check']}; flagged source date conflicts={summary['flagged_source_date_conflicts']}; flagged collector date hints={summary['flagged_collector_date_hints']}; contest timing conflicts={summary['flagged_contest_timing_conflicts']}; new/changed collector files={len(summary['collection_files_new_or_changed'])}")


def build(root=ROOT, db=None, phase3=True, snapshot_inputs=None, allow_uncached_abstentions=False):
    b=Builder(root,snapshot_inputs=snapshot_inputs,allow_uncached_abstentions=allow_uncached_abstentions)
    print('Build: firm exports',file=sys.stderr,flush=True)
    b.import_firms()
    print('Build: legacy discovery seeds',file=sys.stderr,flush=True)
    b.import_seeds()
    print('Build: collection snapshot',file=sys.stderr,flush=True)
    b.import_collections()
    if phase3:
        print('Build: Phase 3 metadata and engagement grouping',file=sys.stderr,flush=True)
        from phase3_engagements import enrich_and_group
        enrich_and_group(b)
        from metadata_contests import import_metadata_contests
        import_metadata_contests(b)
        from metadata_hacken import import_metadata_hacken
        import_metadata_hacken(b)
    print('Build: deterministic audit types',file=sys.stderr,flush=True)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from audit_types.run import apply_to_builder
    apply_to_builder(b)
    print('Build: atomic DuckDB snapshot',file=sys.stderr,flush=True)
    return b.write(db or Path(root)/"data/corpus.duckdb")


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=ROOT)
    parser.add_argument("--db",type=Path)
    parser.add_argument("--json",action="store_true",help="Print full machine-readable counts")
    parser.add_argument('--snapshot-inputs',type=Path,help='Capture exact imported input bytes in a new local-cache directory for reproducibility')
    parser.add_argument('--allow-uncached-abstentions',action='store_true',help='Integration only: record uncached audit-type inputs as explicit abstentions; existing cache receipts remain verified')
    args=parser.parse_args()
    summary=build(args.root,args.db,snapshot_inputs=args.snapshot_inputs,allow_uncached_abstentions=args.allow_uncached_abstentions)
    print(json.dumps(summary,indent=2)) if args.json else print_summary(summary)


if __name__=="__main__":
    main()
