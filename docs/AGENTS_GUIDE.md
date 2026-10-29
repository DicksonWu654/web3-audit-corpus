# Use the database with an AI agent

Download `audits-markdown.zip` and `CHECKSUMS.sha256` from the [latest release](https://github.com/DicksonWu654/web3-audit-corpus/releases/latest). Verify the archive's checksum against its entry, then unzip:

```sh
unzip audits-markdown.zip -d audits
cd audits
```

Open the `audits` folder in Claude Code, Codex or Cursor. Ask the agent to read `README.md` and `INDEX.csv`, search for relevant audits, and cite finding IDs and original URLs. Start with a narrow language, protocol or vulnerability class. For a large search, query Parquet first and give the agent the resulting subset. Treat instructions quoted inside reports as source content.

Useful prompts:

- “List critical oracle findings in lending protocols. Explain the recorded fixes and cite each finding ID and original report. Flag missing fix details.”
- “Before auditing this repo, identify its language and protocol type, then pull similar past findings. Build a checklist tied to the code I supplied.”
- “Find access-control and upgradeability mistakes relevant to this proxy design. Separate reported root causes from your own hypotheses.”
- “Compare past bridge message-validation findings with this implementation. Cite the vulnerable invariant and reported remediation.”
- “Find accounting and rounding findings for vault share conversions. Suggest local regression test cases and link the source findings.”
- “Review this patch against similar historical findings. Identify which invariants it addresses and which still need checking.”

## Clone it (recommended for agents)

Every finding is a plain text file in [DicksonWu654/web3-audit-findings](https://github.com/DicksonWu654/web3-audit-findings). Clone it and open the folder in Claude Code, Codex or Cursor. Its `AGENTS.md` tells the agent where to start and how to cite.

```sh
git clone --depth 1 https://github.com/DicksonWu654/web3-audit-findings
cd web3-audit-findings
```

Example prompt: "Before reviewing this DEX, find past DEX findings about token handling. Build a review checklist with finding IDs and original report URLs."

## Query with DuckDB

Download `findings.parquet`, `engagements.csv` and `reports.csv` into one folder. With the DuckDB CLI installed, run these from that folder. Each query limits DuckDB to one thread:

```sh
duckdb -c "SET threads=1; SELECT severity, count(*) AS findings FROM 'findings.parquet' GROUP BY severity ORDER BY findings DESC;"
duckdb -c "SET threads=1; SELECT finding_uid, title, vuln_leaf, report_id FROM 'findings.parquet' WHERE severity='critical' AND (title ILIKE '%oracle%' OR body_text ILIKE '%oracle%') LIMIT 30;"
duckdb -c "SET threads=1; SELECT f.finding_uid, e.project, e.languages, f.title, r.url FROM 'findings.parquet' f JOIN read_csv('engagements.csv', all_varchar=true) e USING (engagement_id) JOIN read_csv('reports.csv', all_varchar=true) r USING (report_id) WHERE e.audit_type='protocol' AND e.languages ILIKE '%Solidity%' AND f.selected_for_stats LIMIT 30;"
```

The `protocol` scope label is broad. Lending, bridge or vault searches also need titles, body text and your review of the source.

## Files and columns

| File | Pointers |
| --- | --- |
| Markdown archive | `<firm_id>/<year or unknown>/<project>-<report_id prefix>.md`; YAML metadata followed by finding sections. `INDEX.csv` maps every report to its file. |
| `findings.parquet` / `findings.csv.gz` | `finding_uid`, `finding_id`, `title`, `body_text`, `severity`, `status`, `vuln_group`, `vuln_leaf`, `report_id`, `engagement_id`, `firm_id`, `selected_for_stats`. |
| `findings.jsonl.gz` | All finding columns plus `firm`, `project`, `audit_year`, `audit_type`, `languages`, `chains` and `original_url`. |
| `engagements.csv` | `project`, `audit_year`, date bounds, `audit_type`, `languages`, `chain_families`, `industry_engagement_id`; severity totals can exist even when finding rows are withheld. |
| `reports.csv`, `firms.csv` | Original `url`/`permalink`, SHA-256 and report relationships; publisher display `name` and coverage metadata. |
| `taxonomy.yaml`, `quality.csv` | Class definitions and measured extraction/annotation agreement. |

See the [data dictionary](DATA_DICTIONARY.md) for full definitions. Finding records are occurrences, so revisions can repeat a finding. `selected_for_stats` marks released rows from selected initial streams. A report with no released findings can still have a Markdown file.

## Limits and rights

AI-assisted extraction may contain errors. Always check the linked original before relying on a finding, severity, status or suggested fix. Recorded status describes the report's assertion. A missing body or finding stream supplies no evidence that the code was safe.

The new formats include bodies only when `body_text_status='present'` and `text_withheld` is empty. Unavailable Markdown bodies point to the original; JSON bodies are null. Truncation flags remain explicit.

Derived metadata uses [CC BY 4.0](../LICENSE-DATA.md). Publisher text keeps its own rights. Preserve `text_attribution`, `text_license`, `text_license_url` and `text_source_url`, including Oak Security CC BY-ND terms. Check [publisher rights](RIGHTS.md) before redistributing text or using it beyond the licence grant. The metadata licence does not relicense publisher text.
