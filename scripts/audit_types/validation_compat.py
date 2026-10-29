"""Exact source compatibility for reviewed cache-preserving producer changes.

This does not alter config, content keys, prompts, or recorded source hashes.
Only the listed predecessor/replacement pairs can share frozen plans. The run
change adds explicit uncached abstentions and leaves validated cache answers,
prompts and payload content keys unchanged. Every other edit must match exactly.
"""

LEGACY_LLM_SHA256 = '46d6d0ec84f98ff49f128327cbd110ddc571a956db77ffb6bc745b539148e568'
ABSTENTION_LLM_SHA256 = '2ff4dad6f77bdcfca7ce48945c1e2e94448fc6f7532fca037ac91beec76a4a43'
LEGACY_RUN_SHA256 = '38f492929556797bfe2908aea4822f5de7fcf35a6fe99f6214250fac485ef61a'
INTEGRATION_RUN_SHA256 = '785d34b4f7934cc78c6c4f72c9472937ee8f582ed27294f4a69743e95a2a45bd'


def source_hashes_match(recorded, current):
    pairs = {'llm.py': (LEGACY_LLM_SHA256, ABSTENTION_LLM_SHA256),
             'run.py': (LEGACY_RUN_SHA256, INTEGRATION_RUN_SHA256)}
    return (set(recorded) == set(current) and all(
        recorded[key] == current[key] or
        key in pairs and (recorded[key], current[key]) == pairs[key]
        for key in recorded))
