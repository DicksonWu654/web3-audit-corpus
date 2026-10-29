"""ScaleBit's numbered and component-ID report eras, including co-branded PDFs."""
from parsers.movebit import (COMPONENT_ID, SECTION_ID, COMPONENT_SIGNATURE, NUMBERED_SIGNATURE,
                             _cards, _statuses, printed_counts)
from variants import Fingerprint, Variant

DESCRIPTION = "ScaleBit numbered sections and component-ID cards with native status/resolution evidence"


def numbered(report):
    return _cards(report, SECTION_ID, "scalebit-numbered-fields")


def component_cards(report):
    return _cards(report, COMPONENT_ID, "scalebit-component-fields")


def numbered_status(report, candidates):
    return _statuses(report, candidates, SECTION_ID)


def component_status(report, candidates):
    return _statuses(report, candidates, COMPONENT_ID)


def parse(report):
    return component_cards(report) + numbered(report)


VARIANTS = (
    Variant("scalebit/v2023_component_cards", Fingerprint((
        ("component_detail_field", COMPONENT_SIGNATURE, 8),
        ("publisher_methodology", r"(?:ScaleBit|MoveBit) Audit BreakDown", 2)), ("2023", None)),
        component_cards, ("scalebit_component", "scalebit_component_modern"), component_status, printed_counts,
        "Component-ID cards with explicit severity and status; includes MoveBit-branded collector occurrences."),
    Variant("scalebit/v2023_numbered_fields", Fingerprint((
        ("numbered_detail_field", NUMBERED_SIGNATURE, 8),
        ("native_status_legend", r"1\.4 Issue Status", 2)), ("2023", "2023"),
        reject_signatures=(COMPONENT_SIGNATURE,)),
        numbered, ("scalebit_numbered",), numbered_status, printed_counts,
        "Early numbered detail fields, independent numeric statistics and explicit status legend."),
)
