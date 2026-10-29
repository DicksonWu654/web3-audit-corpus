"""Exact, bounded source sentences for publisher-selected response fields."""
import re


def sentence_span(text, start, end=None):
    """Stop at the first sentence, paragraph, footer or section boundary.

    Preserve PDF line wrapping inside the sentence. Callers, not this helper,
    establish that the span belongs to a remediation response.
    """
    end = min(len(text) if end is None else end, start+1800)
    tail = text[start:end]
    stop = re.search(r'\n[ \t]*\n|\f|\n[ \t]*(?:\d+\s*/\s*\d+|PeckShield Audit Report|'
                     r'Recommendations?\b|Description\b|Appendix\b|References\b)', tail, re.I)
    if stop:
        end = start+stop.start()
    sentence = re.search(r'[.!。](?=\s|$)', text[start:end])
    if sentence:
        end = start+sentence.end()
    while end > start and text[end-1].isspace():
        end -= 1
    return start, end
