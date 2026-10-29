"""Synthetic, publisher-specific layout fixtures; no corpus or holdout text."""

FIXTURES={
 'certora_tabular_issue_card':('certora','pdf','2021-01-01','certora/v2021_tabular_issue_cards', '''Formal Verification of Example
All issues were corrected, and the fixes were verified.
Discovered Issues
Issue          (H1) A complete tabular issue title
               continued onto the next physical line
Severity       High
Description    This is a sufficiently complete vulnerability description.
Fix            The input must now be strictly sorted.
Notations
Rule Name    Status     Description
someRule     Verified   A formal rule is not another issue.
'''),
 'certora_split_ids':('certora','pdf','2024-01-01','certora/v2023_severity_id_cards', '''Detailed Findings
Low Severity Issues
-01. A detailed finding with a detached ID glyph
L
Impact: Low
Description: This is the first complete vulnerability explanation in the source.
Informational Issues
A complete title printed before its identifier
I-01.
Recommendation: Remove this unused value from the contract implementation.
This response cites another finding:
I-99

I-02 A final complete informational finding
Description: This is another detailed explanation with sufficient text.
'''),
 'certora_scoped_cards':('certora','pdf','2025-01-01','certora/v2025_multi_scope_cards', '''Detailed Findings
ID     Title                                     Severity     Status
Alpha
I-01   An alpha finding                           Info         Fixed
Beta
I-01   A beta finding                             Info         Acknowledged
Alpha
Project Overview
The first reviewed contract scope is described here.
Informational Issues
I-01 An alpha finding
Description: This is a complete detailed issue from the alpha project scope.
Beta
Project Overview
The second reviewed contract scope is described here.
Informational Issues
I-01 A beta finding
Description: This is a complete detailed issue from the beta project scope.
'''),
 'certora_id_card':('certora','pdf','2025-01-01','certora/v2023_severity_id_cards', '''Findings Summary
Severity   Discovered   Confirmed   Fixed
High   1   1   1
Medium   -   -   -
Low   -   -   -
Detailed Findings
ID     Title                                     Severity     Status
H-01   A complete finding title                   High         Open
High Severity Issues
H-01 A complete finding title
Severity: High     Impact: Low     Likelihood: High
Files: contract.sol     Status: Fixed
Description: A sufficiently detailed issue narrative occupies this finding.
Formal Verification
Status: Verified
'''),
 'certora_id_source_conflict':('certora','pdf','2024-01-01','certora/v2023_severity_id_cards', '''Main Issues Discovered
Crit-1. A contradictory critical identifier
Severity: High
Status: Acknowledged
Description: The explicit publisher severity field is authoritative for this row.
'''),
 'certora_issue_card':('certora','pdf','2021-01-01','certora/v2020_issue_cards', '''Formal Verification of Example
Severity: High
Issue: A sufficiently descriptive issue title
Description: The actual vulnerability is described with adequate context here.
Example This issue was fixed in commit
Response: abc123
Notations
Issue: This is not a real card in the formal rule appendix
'''),
 'certora_numbered_narrative':('certora','pdf','2018-09-01','certora/v2018_numbered_narrative', '''Compound Verification
Sekura Team
Issues
Issue 1 An ungraded numbered vulnerability
This is the first full finding and its detailed explanation.
Issue 2 Another ungraded vulnerability
This is the second full finding and its detailed explanation.
Verification of Example
We refer to
issue 2 above, which must not become another finding.
'''),
 'certora_bug_advisory':('certora','pdf','2019-01-01','certora/v2019_bug_advisories', '''Example Bug in the Token Contract
General Description
The team identified a concrete scenario allowing an attacker to break the contract.
Technical Description and Example
The attack requires a nested call before accounting is updated.
'''),
 'certora_verification_table':('certora','pdf','2020-01-01','certora/v2019_verification_tables', '''Formal Verification of Example
All the high- and medium issues were promptly corrected.
List of Main Issues Discovered
Issue            Rule broken               Description                       Severity    Mitigation
Unsafe transfer                            An attacker can steal assets.     High        Check recipient.
More text                                  This is the detailed explanation.
Notations
Rule Name    Status     Description
someRule     Verified   The rule is proved, not a finding.
'''),
 'certora_verification_only':('certora','pdf','2020-01-01','certora/v2019_verification_tables', '''Formal Verification of Example
Certora Prover
The formal specifications below describe the verified contract.
Rule Name    Status     Description
someRule     Verified   The rule is proved, not a finding.
'''),
 'shieldify_markdown_card':('shieldify','md','2025-01-01','shieldify/v2023_markdown_cards', '''# 1. About Shieldify
# 6. Findings Summary
| ID | Title | Severity | Status |
| [H-01] | A complete finding title | High | Open |
# 7. Findings
# [H-01] A complete finding title
## Severity
High Risk
## Description
The finding has a detailed explanation and its own publisher response.
```solidity
Status: Fixed
```
## Team Response
Acknowledged and fixed in the linked commit.
'''),
 'shieldify_pdf_risk_card':('shieldify','pdf','2023-01-01','shieldify/v2023_pdf_risk_cards', '''7. Findings
[M-01] A complete finding title
Severity
Medium Risk
Description
The finding has a detailed explanation and its own publisher response.
Team Response
Acknowledged and fixed by checking that the value is nonzero.
'''),
 'shieldify_pdf_badge':('shieldify','pdf','2026-01-01','shieldify/v2026_pdf_badge_cards', '''7
Findings
MEDIUM    PARTIALLY FIXED
M-01 A complete finding title
Description
The finding has a detailed explanation with sufficient text to be retained.
'''),
 'shieldify_pdf_finding':('shieldify','pdf','2026-01-01','shieldify/v2026_pdf_badge_cards', '''LOW    FIXED
A complete finding title
FINDING L-01
Description
The finding has a detailed explanation with sufficient text to be retained.
Team Response
Fixed.
'''),
 'shieldify_pdf_zero_findings':('shieldify','pdf','2025-01-01','shieldify/v2023_pdf_risk_cards', '''5. Security Review Summary
The Shieldify team has not identified any potential security issues.
Your smart contracts, our shielding
'''),
}
