"""Decode static report JSON embedded in a JS string literal; never execute JS."""
import ast
import json
import re


def quantstamp_payload(text):
    def unicode_strings(v):
        # JS string literals use UTF-16 code units. Decode surrogate pairs into
        # their displayed Unicode characters before writing a UTF-8 text cache.
        if isinstance(v,str):
            return v.encode("utf-16-le","surrogatepass").decode("utf-16-le","replace")
        if isinstance(v,list):
            return [unicode_strings(x) for x in v]
        if isinstance(v,dict):
            return {unicode_strings(k):unicode_strings(x) for k,x in v.items()}
        return v
    for match in re.finditer(r"JSON\.parse\(('(?:\\.|[^'\\])*')\)", text, re.S):
        try:
            value = json.loads(ast.literal_eval(match.group(1)))
        except (ValueError, SyntaxError):
            continue
        if isinstance(value, dict) and isinstance(value.get("reportContent"), dict):
            return unicode_strings(value)
    raise ValueError("No static Quantstamp report JSON literal")


def heading_text(value, depth=1):
    """Serialize every report value, with key headings and JSON-path list ordinals."""
    if isinstance(value, dict):
        return "\n".join("#" * min(depth, 6) + " " + str(k) + "\n" + heading_text(v, depth + 1) for k, v in value.items())
    if isinstance(value, list):
        return "\n".join("#" * min(depth, 6) + f" [{i}]\n" + heading_text(v, depth + 1) for i, v in enumerate(value))
    return str(value) if value is not None else "null"


def render_report(value):
    parts, spans, size = [], {}, 0
    def append(text):
        nonlocal size
        parts.append(text)
        size += len(text)
    def render(v, path=(), depth=1):
        start = size
        if isinstance(v, dict):
            for k, child in v.items():
                append("#" * min(depth, 6) + " " + str(k) + "\n")
                render(child, path + (str(k),), depth + 1)
        elif isinstance(v, list):
            for i, child in enumerate(v):
                append("#" * min(depth, 6) + f" [{i}]\n")
                render(child, path + (str(i),), depth + 1)
        else:
            append((str(v) if v is not None else "null") + "\n")
        spans["/" + "/".join(path)] = {"start": start, "end": size}
    render(value)
    return "".join(parts), {"report": value, "spans": spans}
