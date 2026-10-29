"""Shared, evidence-based Web3 scope for the mixed ToB publications archive.

Product names are reviewed identities, not a generic cryptography keyword rule.
Evidence refers to trailofbits/publications@89940dfbec07ad03b0989e67d78e84250765366b.
"""
from pathlib import PurePosixPath
import re

README_SECTIONS = {'Blockchain Reviews', 'Frax Finance', 'MobileCoin', 'Offchain Labs',
                   'Reserve Protocol', 'Scroll', 'Uniswap'}
WEB3_PRODUCTS = re.compile(
    r'aleo|dfinity|axiom|chainflip|lisk|spool|thesistss|practicalstealth|ironfish|'
    r'polygonlabs|lit-protocol|kraken|alignedlayer|near-?one|zkonduit|liquidium|'
    r'anza|bsv-association|dv-labs|propellerheads|ripple-labs|turnkey|monerofcmp|'
    r'worldcoin|scopelift|^Galoy\.|^SpruceID\.|^renvm\.', re.I)
CONTENT_SCOPE_EVIDENCE = {
    'reviews/2026-03-hyperlink-awsnitrotee-securityreview.pdf':
        'Executive Summary: privacy-preserving prime broker for Hyperliquid; Solidity contracts on HyperEVM.',
    'reviews/2023-01-ryanshea-noblecurveslibrary-securityreview.pdf':
        'Project Goals asks whether flaws compromise funds or anonymity in stealth wallets.',
    'reviews/2024-02-silencelaboratories-silentshard-securityreview.pdf':
        'Report analyzes a 3-of-5 threshold wallet and availability of transfers of funds from the wallet.',
    'reviews/voatz-securityreview.pdf':
        'Executive Summary: Voatz uses Hyperledger Fabric for auditable voting records; threat model is volume 2.',
    'reviews/voatz-threatmodel.pdf':
        'Companion assessment volume with findings; architecture identifies Hyperledger blockchain ballot storage.',
}
BRON_PATH = 'reviews/2026-01-bron-mcp-securityreview.pdf'
BRON_REASON = (
    'Excluded from confirmed Web3 scope: Bron MPC is a general-purpose threshold-signature library. '
    'The pinned report Executive Summary (printed pp. 4-5), Project Goals (p. 7), and Project Targets '
    '(p. 8, bronlabs/bron-crypto) establish cryptographic primitives, but no blockchain, wallet, '
    'custody product, or Web3 deployment target. Cryptographic applicability alone is insufficient.'
)


def scope_reason(path, readme_paths):
    """Return an exclusion reason or None; exclude supporting artifacts first."""
    base = PurePosixPath(path).name
    if not path.startswith('reviews/'):
        return 'Outside the publisher reviews directory.'
    if 'invariant-development' in base or base == 'celo_bugfixes.md':
        return 'Development/supporting artifact, not a delivered audit report.'
    if re.search(r'letter[-_]?of[-_]?attestation|[-_]loa\.', base, re.I):
        return 'Attestation letter, not a detailed audit report.'
    if path == BRON_PATH:
        return BRON_REASON
    if path in readme_paths or WEB3_PRODUCTS.search(base) or path in CONTENT_SCOPE_EVIDENCE:
        return None
    return 'Outside confirmed Web3 client/product scope; generic cryptography and non-Web3 software reviews excluded.'
