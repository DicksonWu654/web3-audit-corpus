-- DuckDB schema v1. Source occurrences, artifacts and engagements are distinct.
CREATE TABLE publishers (
    publisher_id VARCHAR PRIMARY KEY,
    name VARCHAR NOT NULL,
    publisher_kind VARCHAR NOT NULL CHECK (publisher_kind IN ('firm', 'contest_platform')),
    github_reports_url VARCHAR,
    website_reports_url VARCHAR,
    registry_record JSON NOT NULL
);

CREATE TABLE documents (
    document_id VARCHAR PRIMARY KEY,
    publisher_id VARCHAR NOT NULL REFERENCES publishers(publisher_id),
    source_family VARCHAR NOT NULL CHECK (source_family IN ('collected', 'firm_export', 'audit_analysis', 'discovery')),
    source_tag VARCHAR NOT NULL,
    source_record_id VARCHAR NOT NULL,
    source_file VARCHAR NOT NULL,
    source_locator VARCHAR NOT NULL,
    source_record_sha256 VARCHAR NOT NULL,
    collector VARCHAR,
    source_kind VARCHAR NOT NULL CHECK (source_kind IN ('github', 'website', 'contest', 'aggregator')),
    public_url VARCHAR NOT NULL CHECK (length(trim(public_url)) > 0),
    url_kind VARCHAR NOT NULL CHECK (url_kind IN ('original', 'discovery')),
    listing_url VARCHAR,
    sha256 VARCHAR,
    hash_verification VARCHAR NOT NULL CHECK (hash_verification IN ('collector_attested', 'manifest_attested', 'unknown')),
    bytes BIGINT CHECK (bytes >= 0),
    file_format VARCHAR NOT NULL CHECK (file_format IN ('pdf', 'md', 'html', 'other')),
    local_path VARCHAR,
    wayback_url VARCHAR,
    metadata JSON NOT NULL,
    filename VARCHAR,
    title VARCHAR,
    project VARCHAR,
    project_basis VARCHAR CHECK (project_basis IN ('publisher_project', 'client_fallback', 'collector_hint', 'catalog_unverified')),
    doc_kind VARCHAR NOT NULL CHECK (doc_kind IN ('audit_report', 'fix_review', 'contest_report', 'formal_verification', 'non_report', 'unknown')),
    counting_role VARCHAR NOT NULL CHECK (counting_role IN ('primary', 'alternate', 'lead', 'seed')),
    is_seed BOOLEAN NOT NULL,
    retrieved_utc TIMESTAMPTZ,
    chains JSON,
    languages JSON,
    coverage JSON NOT NULL,
    rights JSON NOT NULL,
    relationships JSON NOT NULL,
    notes JSON NOT NULL,
    provenance JSON NOT NULL,
    field_state JSON NOT NULL,
    UNIQUE (source_tag, source_record_id),
    CHECK (is_seed = (source_family = 'audit_analysis')),
    CHECK ((is_seed AND counting_role = 'seed') OR (NOT is_seed AND counting_role <> 'seed')),
    CHECK (sha256 IS NOT NULL OR hash_verification = 'unknown')
);

CREATE TABLE engagements (
    engagement_id VARCHAR PRIMARY KEY,
    publisher_id VARCHAR NOT NULL REFERENCES publishers(publisher_id),
    industry_engagement_id VARCHAR,
    project VARCHAR,
    engagement_kind VARCHAR NOT NULL CHECK (engagement_kind IN ('audit', 'contest', 'formal_verification', 'other')),
    audit_type VARCHAR NOT NULL CHECK (audit_type IN ('token_only', 'protocol', 'infrastructure', 'wallet_or_account', 'nft_or_game', 'other_or_unclear')),
    audit_type_basis VARCHAR NOT NULL CHECK (audit_type_basis IN ('rule', 'llm', 'abstain')),
    identity_status VARCHAR NOT NULL CHECK (identity_status IN ('provisional', 'confirmed', 'excluded')),
    identity_basis VARCHAR NOT NULL,
    evidence JSON NOT NULL,
    notes JSON NOT NULL,
    UNIQUE (publisher_id, industry_engagement_id),
    CHECK (identity_status <> 'confirmed' OR industry_engagement_id IS NOT NULL)
);

CREATE TABLE engagement_documents (
    engagement_id VARCHAR NOT NULL REFERENCES engagements(engagement_id),
    document_id VARCHAR NOT NULL UNIQUE REFERENCES documents(document_id),
    role VARCHAR NOT NULL CHECK (role IN ('primary', 'revision', 'translation', 'alternate', 'supporting')),
    evidence JSON NOT NULL,
    PRIMARY KEY (engagement_id, document_id)
);

-- Every occurrence is linked once or has an explicit reason for exclusion.
CREATE TABLE document_exclusions (
    document_id VARCHAR PRIMARY KEY REFERENCES documents(document_id),
    reason VARCHAR NOT NULL,
    evidence JSON NOT NULL
);

CREATE TABLE engagement_identity_crosswalk (
    previous_engagement_id VARCHAR PRIMARY KEY,
    engagement_id VARCHAR NOT NULL REFERENCES engagements(engagement_id),
    basis VARCHAR NOT NULL
);

CREATE TABLE findings (
    finding_id VARCHAR PRIMARY KEY,
    publisher_id VARCHAR NOT NULL REFERENCES publishers(publisher_id),
    document_id VARCHAR REFERENCES documents(document_id),
    source_family VARCHAR NOT NULL CHECK (source_family IN ('firm_export', 'audit_analysis')),
    source_tag VARCHAR NOT NULL,
    source_record_id VARCHAR NOT NULL,
    source_file VARCHAR NOT NULL,
    source_locator VARCHAR NOT NULL,
    source_record_sha256 VARCHAR NOT NULL,
    is_seed BOOLEAN NOT NULL,
    publisher_finding_id VARCHAR,
    ordinal INTEGER,
    occurrence INTEGER,
    record_kind VARCHAR NOT NULL CHECK (record_kind IN ('formal_finding', 'recommendation', 'remediation_review', 'observation', 'summary_excerpt', 'candidate', 'unknown')),
    finding_phase VARCHAR CHECK (finding_phase IN ('initial_audit', 'fix_review', 'other')),
    title VARCHAR,
    title_raw VARCHAR,
    severity_raw VARCHAR,
    severity_source_normalized VARCHAR,
    severity VARCHAR NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info', 'gas', 'unknown')),
    severity_mapping JSON NOT NULL,
    category_raw VARCHAR,
    category_semantics VARCHAR NOT NULL CHECK (category_semantics IN ('vulnerability_taxonomy', 'section_kind', 'source_category', 'unknown')),
    category VARCHAR,
    status_raw VARCHAR,
    status VARCHAR CHECK (status IN ('fixed', 'partially_fixed', 'acknowledged', 'unresolved', 'not_stated')),
    status_authority VARCHAR,
    description VARCHAR,
    recommendation VARCHAR,
    resolution VARCHAR,
    attributed_responses JSON NOT NULL,
    evidence JSON NOT NULL,
    review JSON NOT NULL,
    relationships JSON NOT NULL,
    unique_vulnerability_id VARCHAR,
    public_url VARCHAR,
    provenance JSON NOT NULL,
    field_state JSON NOT NULL,
    UNIQUE (source_tag, source_record_id),
    CHECK (is_seed = (source_family = 'audit_analysis')),
    CHECK (is_seed OR document_id IS NOT NULL)
);

CREATE TABLE date_claims (
    claim_id VARCHAR PRIMARY KEY,
    document_id VARCHAR REFERENCES documents(document_id),
    engagement_id VARCHAR REFERENCES engagements(engagement_id),
    finding_id VARCHAR REFERENCES findings(finding_id),
    source_tag VARCHAR NOT NULL,
    role VARCHAR NOT NULL CHECK (role IN ('audit_start', 'audit_completion', 'report_issue', 'review_year', 'audit_year_inference', 'publication', 'retest', 'filename_hint', 'catalog', 'other')),
    raw_value VARCHAR,
    date_value VARCHAR,
    date_end VARCHAR,
    precision VARCHAR NOT NULL CHECK (precision IN ('day', 'month', 'year', 'none')),
    basis VARCHAR NOT NULL CHECK (basis IN ('listing', 'filename', 'document_text', 'contest_end', 'publisher_api', 'catalog', 'none', 'report_text', 'publisher_listing', 'publisher_listing_publication', 'github_report_added', 'publisher_filename')),
    authority VARCHAR NOT NULL CHECK (authority IN ('publisher', 'collector_hint', 'inherited_unverified', 'catalog_unverified')),
    eligible_for_audit_year BOOLEAN NOT NULL,
    evidence JSON NOT NULL,
    CHECK ((document_id IS NOT NULL)::INTEGER + (engagement_id IS NOT NULL)::INTEGER + (finding_id IS NOT NULL)::INTEGER = 1),
    CHECK ((date_value IS NULL AND precision = 'none') OR (date_value IS NOT NULL AND precision <> 'none')),
    CHECK (NOT eligible_for_audit_year OR (date_value IS NOT NULL AND
        ((role IN ('audit_completion', 'report_issue', 'review_year') AND basis IN ('document_text', 'contest_end', 'publisher_api', 'report_text', 'publisher_listing') AND authority = 'publisher')
         OR (role='audit_year_inference' AND precision='year' AND authority='collector_hint'
             AND basis IN ('report_text', 'publisher_listing_publication', 'github_report_added', 'publisher_filename')))))
);

CREATE TABLE contests (
    contest_id VARCHAR PRIMARY KEY,
    publisher_id VARCHAR NOT NULL REFERENCES publishers(publisher_id),
    platform_contest_id VARCHAR NOT NULL,
    source_tag VARCHAR NOT NULL,
    source_file VARCHAR NOT NULL,
    source_locator VARCHAR NOT NULL,
    source_record_sha256 VARCHAR NOT NULL,
    name VARCHAR,
    sponsor_project VARCHAR,
    start_utc TIMESTAMPTZ,
    end_utc TIMESTAMPTZ,
    timing_status VARCHAR NOT NULL CHECK (timing_status IN ('consistent', 'source_conflict', 'unknown')),
    format VARCHAR NOT NULL CHECK (format IN ('public_contest', 'private', 'mitigation', 'bounty_boost', 'other')),
    report_url VARCHAR,
    findings_high INTEGER CHECK (findings_high >= 0),
    findings_medium INTEGER CHECK (findings_medium >= 0),
    sha256 VARCHAR,
    document_id VARCHAR REFERENCES documents(document_id),
    engagement_id VARCHAR REFERENCES engagements(engagement_id),
    provenance JSON NOT NULL,
    UNIQUE (publisher_id, platform_contest_id),
    CHECK (timing_status = 'source_conflict' OR start_utc IS NULL OR end_utc IS NULL OR start_utc <= end_utc)
);

-- Input snapshot ledger makes reconciliation independent of live collector appends.
CREATE TABLE import_sources (
    source_file VARCHAR PRIMARY KEY,
    source_tag VARCHAR NOT NULL,
    source_family VARCHAR NOT NULL CHECK (source_family IN ('collected', 'firm_export', 'audit_analysis', 'discovery')),
    row_kind VARCHAR NOT NULL CHECK (row_kind IN ('reports', 'findings', 'contests', 'date_overrides', 'engagement_metadata')),
    file_sha256 VARCHAR NOT NULL,
    bytes BIGINT NOT NULL,
    source_rows BIGINT NOT NULL,
    imported_rows BIGINT NOT NULL,
    excluded_scope_rows BIGINT NOT NULL,
    duplicate_rows BIGINT NOT NULL,
    CHECK (source_rows = imported_rows + excluded_scope_rows + duplicate_rows)
);

-- These views deliberately require identity adjudication; imports create candidates.
CREATE VIEW counted_engagements AS
SELECT * FROM engagements WHERE identity_status = 'confirmed';
CREATE VIEW industry_engagements AS
SELECT DISTINCT industry_engagement_id FROM counted_engagements
WHERE industry_engagement_id IS NOT NULL;
-- A different role/value at the best priority stays ambiguous, never overwritten.
CREATE VIEW engagement_years AS
WITH claims AS (
    SELECT ed.engagement_id, dc.role, dc.date_value
    FROM engagement_documents ed JOIN date_claims dc USING (document_id)
    WHERE dc.eligible_for_audit_year
    UNION ALL
    SELECT engagement_id, role, date_value FROM date_claims
    WHERE engagement_id IS NOT NULL AND eligible_for_audit_year
), ranked AS (
    SELECT *, CASE role WHEN 'audit_completion' THEN 1 WHEN 'report_issue' THEN 2 WHEN 'review_year' THEN 3 ELSE 4 END AS priority FROM claims
), best AS (
    SELECT * FROM ranked QUALIFY priority = min(priority) OVER (PARTITION BY engagement_id)
)
SELECT e.engagement_id,
    CASE WHEN count(DISTINCT left(b.date_value, 4)) = 1 THEN min(left(b.date_value, 4))::INTEGER END AS audit_year,
    count(DISTINCT left(b.date_value, 4)) > 1 AS year_conflict
FROM engagements e LEFT JOIN best b USING (engagement_id) GROUP BY e.engagement_id;

CREATE VIEW engagement_publication_years AS
WITH claims AS (
    SELECT ed.engagement_id, dc.date_value
    FROM engagement_documents ed JOIN date_claims dc USING (document_id)
    WHERE dc.role='publication' AND dc.date_value IS NOT NULL
      AND dc.authority IN ('publisher', 'collector_hint') AND dc.basis IN ('listing','document_text')
)
SELECT e.engagement_id,
    CASE WHEN count(DISTINCT left(c.date_value,4))=1 THEN min(left(c.date_value,4))::INTEGER END AS publication_year,
    count(DISTINCT left(c.date_value,4))>1 AS year_conflict
FROM engagements e LEFT JOIN claims c USING(engagement_id) GROUP BY e.engagement_id;
