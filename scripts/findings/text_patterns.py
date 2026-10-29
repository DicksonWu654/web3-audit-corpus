"""Linear matching helpers for padded PDF text; no parser or policy imports."""


def index_line(text, *, padded=True, dotted=True):
    """Recognize a trailing TOC page number without backtracking over padding."""
    tail = text.rstrip()
    end = len(tail)
    while end and tail[end-1].isdecimal():
        end -= 1
    if end == len(tail):
        return False
    prefix = tail[:end]
    stripped = prefix.rstrip()
    if padded and len(prefix)-len(stripped) >= 3:
        return True
    if not dotted:
        return False
    for _ in range(4):
        if not stripped.endswith('.'):
            return False
        stripped = stripped[:-1].rstrip()
    return True
