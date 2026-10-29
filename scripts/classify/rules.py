"""Deliberately narrow pre-pass; confidence values are judgements, not measured precision."""
import re

# Abstain when the excerpt describes a security or availability consequence, even if
# the publisher called it informational/gas. These are vetoes, never positive labels.
VETO = re.compile(
    r"\b(attack\w*|exploit\w*|vulnerab\w*|reentran\w*|re.entran\w*|malicious|"
    r"unauthori[sz]\w*|overflow\w*|underflow\w*|sandwich\w*|front.?run\w*|"
    r"steal\w*|stolen|drain\w*|bypass\w*|manipulat\w*|replay\w*|"
    r"DoS|denial.of.service|grief\w*|unbounded|out.of.gas|block.gas|"
    r"insolven\w*|loss.of.funds|lost.funds|funds.at.risk|storage.collision)\b", re.I)
GAS_INTENT = re.compile(r"\bgas\b.{0,45}\b(sav\w*|reduc\w*|optimi[sz]\w*|efficien\w*|cost\w*)\b|"
                        r"\b(sav\w*|reduc\w*|optimi[sz]\w*)\b.{0,45}\bgas\b", re.I | re.S)
GAS_TOPICS = [
    ("gas.representation", re.compile(r"custom.errors?|revert.strings?|\bcalldata\b|bytecode.size", re.I)),
    ("gas.storage", re.compile(r"\b(storage|SLOAD|SSTORE|immutable|constant)\b|pack\w*.{0,20}(variable|struct)", re.I)),
    ("gas.execution", re.compile(r"\b(loop|increment|decrement|unchecked|comparison|calculation)\b|\+\+|--", re.I)),
]
QUALITY_TITLES = [
    ("quality.documentation", re.compile(r"^(?:\[[^\]]+\]\s*)?(?:typos?(?:\s+(?:in|within)\b.*)?|"
                                        r"(?:missing|incomplete)\s+natspec(?:\s+comments?)?|"
                                        r"(?:missing|incomplete)\s+documentation|"
                                        r"naming conventions?|spelling (?:errors?|mistakes?))\s*[.!]?$", re.I)),
    ("quality.maintainability", re.compile(r"^(?:\[[^\]]+\]\s*)?(?:unused (?:imports?|variables?|functions?|constants?)|"
                                           r"dead code|code duplication|redundant imports?)\s*[.!]?$", re.I)),
]


def classify(row):
    title, body = row["title"], row["body"][:800]
    text = title + "\n" + body
    if not title.strip() or VETO.search(text):
        return None
    # A source gas label alone never selects a mechanism. Require stated savings
    # and a recognizable topic in the title, to avoid unrelated body/header tokens.
    if row["severity"] in {"gas", "info"} and GAS_INTENT.search(text):
        topics = [(leaf, pat) for leaf, pat in GAS_TOPICS if pat.search(title)]
        if len(topics) == 1:
            return dict(finding_uid=row["finding_uid"], leaf=topics[0][0], confidence=0.98,
                        rationale="Explicit gas-saving advice with a specific optimization topic and no security-impact wording.",
                        rule_id="gas-explicit-topic-v1")
        if not topics and re.fullmatch(r"(?:\[[^\]]+\]\s*)?gas optimi[sz]ations?[.!]?", title.strip(), re.I):
            # Generic multi-topic optimization sections require an LLM; never guess execution.
            return None
    if row["severity"] == "info" and not GAS_INTENT.search(text):
        for leaf, pattern in QUALITY_TITLES:
            if pattern.fullmatch(title.strip()):
                return dict(finding_uid=row["finding_uid"], leaf=leaf, confidence=0.99,
                            rationale="Informational finding with an exact, purely editorial or dead-code title and no security-impact wording.",
                            rule_id="info-exact-title-v1")
    return None
