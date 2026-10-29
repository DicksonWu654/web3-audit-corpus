# Changelog

## Publisher-request removal - 2026-10-28

- Removed Cyfrin and CodeHawks reports, findings and publisher rows at their request; excluded Solodit sources and links.
- Current downloads contain 63 publishers, 12,767 industry engagements, 13,522 report files, 11,027 project labels and 175,640 findings, including 160,239 with full text.
- Regenerated search data, agent formats and descriptive statistics from the filtered release. Launch analysis retains the frozen v1.3.0 snapshot with excluded publisher examples removed.

## v1.3.0 - 2026-10-27

- Published the database edition with 65 publishers, 13,040 industry engagements, 13,979 report files, 11,262 distinct project names and 180,907 finding records, including 165,451 with full text.
- Added deterministic Markdown and joined JSONL downloads for use with coding agents, preserving text withholding, attribution and publisher licences.
- Added an agent guide and database-first documentation, release notes, data dictionary and descriptive statistics schema.
- Limited this edition's export and statistics archive to database material. The research analysis follows separately.
- Retained the 2026-10-22 snapshot; audit years span 2015 to 2026, with 2026 year to date.

## v1.2.0 - 2026-10-26

- Removed CertiK because only a small, unrepresentative set of third-party copies is public.
- Integrated reviewed gap-fill work for the staged publishers, retaining quarantine and holdout exclusions.
- Applied publisher terms and robots restrictions: metadata, links and engagement severity totals remain; restricted finding rows and text are withheld.
- Re-sourced verified identical files from permitted publisher GitHub copies.
- Added the new analysis tables to release CSVs and site JSON, with schema and policy validation.

## v1.1.0 - 2026-10-22

- Expanded the release to 13,335 industry engagements across 66 publishers, with 215,639 finding records and 164,731 selected initial formal findings.
- Audited Immunefi coverage and identified metadata-only boards and missing public reports.
- Fixed engagement grouping for per-scope reports, including Cantina reports with different audited scope.
- Reduced unknown audit years from 479 to 229 and unknown severities among selected findings from 3,993 to 3,016.
- Redesigned the website, findings explorer and publisher pages.

## v1.0.0 - 2026-10-22

- Initial public release: 13,486 report files, 11,854 industry engagements and 208,404 finding occurrences, with 64 publishers with confirmed audits.
- Established publisher-notice withholding, publisher-specific attribution and a link-only policy for original reports.
- Added a synthetic offline test suite and a static-site build.
