# Publisher rights and corrections

The corpus links every report to its publisher or a documented archive and retains its original SHA-256. Originals are cached locally for research and never re-hosted. Derived metadata and annotations use [CC BY 4.0](../LICENSE-DATA.md); finding text remains its publisher's copyright.

## Withholding rule

An explicit prohibition on reproduction, distribution or disclosure triggers body withholding for that report, keyed by its SHA-256. Finding metadata and the original link remain, with `text_withheld='publisher_notice'` and `body_text_status='publisher_notice'`. The site identifies the publisher notice. A publisher request can trigger the same state while it is reviewed. Licence grants are assessed at report level; conflicting notices inside a report govern withholding.

Oak Security body text uses CC BY-ND 4.0 with attribution and a source link. Released bodies are exact contiguous verbatim excerpts. Boundary, tail, page-furniture and length cuts carry `body_truncated=true`; the truncation note appears outside the quoted text. Required character changes within the kept span, including redaction, trigger `text_withheld='oak_transform_required'`. Annotations occupy separate fields. The current release includes 3,147 truncated Oak excerpts with `body_truncated=true`. Trail of Bits attribution and the canonical Publications link are retained, with restrictive report notices honoured. Broad all-rights-reserved notices identify copyright; specific no-reproduction clauses trigger withholding.

## Publisher terms and robots policy

Reports collected through a host whose terms prohibit automated access, copying or data mining, or whose robots rules disallow the source path, are released as metadata and links only. This applies to restricted sources within mixed-source publishers and to gap-fill additions. Report and engagement rows retain IDs, SHA-256, dates, links, audit type and engagement-level severity counts. `text_withheld='publisher_terms'` and `body_text_status='publisher_terms'` mark affected reports and engagements. No per-finding row, title or body from those reports is released. This state is separate from report-notice body withholding.

The reviewed terms audit supplies the source restrictions. A permitted publisher-owned or audited open-licence GitHub copy can replace the source after its manifest receipt and cached bytes verify the same SHA-256 or fully equivalent text. Different PDF renderings retain both file hashes and their verified text-equivalence basis. Different reports from the same engagement do not establish text equivalence. The export and release validators reject restricted finding rows and text examples.

| Publisher ID | Reports | Engagements | Finding rows withheld | Nonempty bodies withheld | Initial findings withheld |
|---|---|---|---|---|---|
| chainsecurity | 416 | 412 | 6584 | 6531 | 6355 |
| code4rena | 478 | 411 | 13924 | 13924 | 6172 |
| dedaub | 178 | 178 | 2092 | 2092 | 1941 |
| immunefi | 1 | 1 | 4 | 0 | 0 |
| kudelski-security | 35 | 35 | 230 | 108 | 199 |
| quantstamp | 398 | 393 | 4776 | 3026 | 4664 |
| veridise | 170 | 162 | 2628 | 2573 | 2333 |

Verified permitted-source replacements: 347 report files. Counts describe this release and can overlap the notice inventory below.

## Per-publisher notice inventory

Generated at export time from the final `RIGHTS_WITHHELD.csv` ledger, restricted to released report SHA-256 digests and counted once per publisher and digest. These are publisher-notice withholding counts. Notice excerpts remain in the release ledger. “No explicit content licence verified” records the absence of a verified grant. Publisher-specific website terms require review when sources change. Snapshot date for this inventory: 2026-10-22.

| Publisher | Reports withheld by notice | Notice / licence | Release decision |
|---|---|---|---|
| ABDK Consulting | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Ackee Blockchain | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| BailSec | 1 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| BlockSec | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Cantina | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Certora | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| ChainLight | 19 | Reproduction/distribution or confidentiality notices in some reports | Quote finding text with attribution and source link; withhold restricted bodies |
| ChainSecurity | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Code4rena | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| CodeSpect | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Coinspect | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Composable Security | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Consensys Diligence | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Decurity | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Dedaub | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Electisec | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Fuzzland | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Guardian Audits | 176 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Hacken | 415 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Halborn | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Hats Finance | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Hexens | 8 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Immunefi | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Informal Systems | 32 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| iosiro | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Kudelski Security | 19 | Reproduction/distribution or confidentiality notices in some reports | Quote finding text with attribution and source link; withhold restricted bodies |
| Least Authority | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Macro | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| MixBytes | 141 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| MoveBit | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| NCC Group | 5 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Neodyme | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Nethermind | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Oak Security | 0 | CC BY-ND 4.0 | Contiguous verbatim excerpts with attribution and body_truncated flag; withhold required character changes |
| Obsidian Audits | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| OpenZeppelin | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| OtterSec | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Oxorio | 2 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Pashov Audit Group | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| PeckShield | 27 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Pessimistic | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Quantstamp | 162 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Runtime Verification | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| ScaleBit | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Sec3 | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Secure3 | 16 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Sherlock | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Shieldify | 4 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Sigma Prime | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| SlowMist | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Solidified | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Spearbit | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Statemind | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Team Omega | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Theori | 2 | Reproduction/distribution or confidentiality notices in some reports | Quote finding text with attribution and source link; withhold restricted bodies |
| Three Sigma | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Trail of Bits | 279 | Report no-reproduction notices; repository-level CC BY-SA 4.0 | Report notice controls withholding; retain canonical link and attribution |
| Trust Security | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Verichains | 13 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Veridise | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Zellic | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Zenith | 0 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |
| Zokyo | 1 | No explicit content licence verified; report-specific notice screening | Quote finding text with attribution and source link; withhold restricted bodies |

Oak licence: https://creativecommons.org/licenses/by-nd/4.0/ . Trail of Bits canonical source: https://github.com/trailofbits/publications . Every finding's `firm_id` and report URL provide attribution to the named publisher and original document.

## Takedown and correction process

Open a [GitHub issue](https://github.com/DicksonWu654/web3-audit-corpus/issues) with the report URL, finding ID or report digest, the notice or correction evidence and the requested change. Avoid copying credentials or personal details into the issue. Publishers can identify the affected report without reproducing its text.

Requests are acknowledged within seven days. Requested text is withheld within seven days while the request is reviewed. Accepted corrections update the next dataset release and hosted build; the issue records affected versions and completion. Metadata and links are corrected or removed when warranted. Clear reproduction restrictions continue to apply until permission or a source-supported licence change resolves them.

## Third-party components

Code uses the [MIT licence](../LICENSE). Fonts in `site/src/assets/fonts/` retain their SIL Open Font License notices. The BIP39 English word list retains its [vendored MIT licence](../scripts/release/BIP39_WORDLIST_LICENSE.txt). Source and licence screening are ongoing, and publisher corrections are welcome.
