"""Zenith detail cards use explicit severity fields and bracketed IDs."""
from parsers.shieldify import cards
DESCRIPTION = 'Zenith bracketed detail cards with explicit Severity, Impact, Likelihood and Status fields'


def parse(report):
    return cards(report)


# Phase 4d compatibility contract; preserve the existing parser until era review.
from variants import legacy as _legacy_variant
VARIANTS = (_legacy_variant('code4rena-zenith', parse),)
