"""Obsidian numbered detail headings and explicitly stated remediations."""
from parsers.shieldify import cards
DESCRIPTION = 'Obsidian wrapped severity-ID headings with Description/Summary and remediation labels'


def parse(report):
    return cards(report,description=True)


# Phase 4d compatibility contract; preserve the existing parser until era review.
from variants import legacy as _legacy_variant
VARIANTS = (_legacy_variant('obsidian-audits', parse),)
