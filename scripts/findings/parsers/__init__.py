"""Explicit publisher dispatch; modules are trusted repository code, reports are data."""
from importlib import import_module
from functools import lru_cache
from types import SimpleNamespace
from variants import dispatch, legacy
from core import candidate_severity, severity_context
from prior_findings import exclude_prior_findings

FIRMS = ("pashov-audit-group", "peckshield", "electisec", "chainsecurity", "openzeppelin", "zellic",
         "quantstamp", "ottersec", "verichains", "guardianaudits", "slowmist", "oak-security", "trail-of-bits", "zokyo",
         "solidified", "certora", "pessimistic", "sigma-prime", "decurity", "teamomega", "movebit", "ncc-group", "scalebit")
GROUP2 = ("mixbytes", "blocksec", "least-authority", "hexens", "iosiro", "three-sigma", "informalsystems",
          "coinspect", "sec3", "chainlight", "secure3")
CONTESTS = ("code4rena", "sherlock", "cantina")
GROUP1 = ("consensys-diligence", "abdk-consulting", "macro", "spearbit", "runtime-verification", "statemind",
          "dedaub", "fuzzland", "composable-security")
GROUP3 = ("halborn", "shieldify", "code4rena-zenith", "veridise", "ackee-blockchain", "bailsec",
          "immunefi", "oxorio", "neodyme", "obsidian-audits", "hats-finance")


@lru_cache(maxsize=None)
def module(firm):
    name = firm.replace("-", "_") if firm in FIRMS + GROUP1 + GROUP2 + GROUP3 + CONTESTS + ("kudelski-security", "theori", "nethermind", "codespect", "hacken") else "generic"
    parser = import_module("parsers." + name)
    variants = getattr(parser, "VARIANTS", None) or (legacy(firm, parser.parse),)
    def parse(report):
        return dispatch(report, variants)
    def counts(report):
        from summary_counts import printed_counts
        variant = getattr(report, "selected_variant", None)
        reader = variant.printed_counts if variant and variant.printed_counts else getattr(parser, "printed_counts", printed_counts)
        with severity_context(report):
            return reader(report)
    return SimpleNamespace(__name__=parser.__name__, DESCRIPTION=parser.DESCRIPTION,
                           VARIANTS=variants, parse=parse, printed_counts=counts)
