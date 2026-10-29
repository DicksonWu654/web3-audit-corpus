"""Bounded text-only reader for the publishers' simple PDF report summaries.

Handles explicit PDF objects, Flate streams, ToUnicode CMaps and Tj/TJ strings.
Unsupported/compressed-object layouts return missing text rather than guessed
counts. This is intentionally not a general PDF renderer or finding extractor.
"""
import re
import zlib


def pdf_text(body):
    objs = {int(m[1]): m[2] for m in re.finditer(rb'(\d+)\s+\d+\s+obj\b(.*?)\bendobj\b', body, re.S)}

    def stream(obj):
        if b'/Subtype /Image' in obj or b'/Length1' in obj.partition(b'stream')[0]:
            return b''
        match = re.search(rb'\bstream\r?\n(.*?)\r?\nendstream', obj, re.S)
        if not match:
            return b''
        data = match[1]
        if b'/FlateDecode' in obj.partition(b'stream')[0]:
            try:
                inflater = zlib.decompressobj()
                data = inflater.decompress(data, 16_000_000)
                if not inflater.eof:
                    return b''
            except zlib.error:
                return b''
        return data

    # PDF 1.5 can pack resource/font dictionaries into object streams.
    for obj in list(objs.values()):
        if not re.search(rb'/Type\s*/ObjStm\b', obj):
            continue
        first = re.search(rb'/First\s+(\d+)', obj)
        count = re.search(rb'/N\s+(\d+)', obj)
        if not first or not count:
            continue
        data = stream(obj)
        offset = int(first[1])
        indexes = [int(v) for v in re.findall(rb'\d+', data[:offset])]
        if len(indexes) != 2 * int(count[1]):
            continue
        pairs = list(zip(indexes[::2], indexes[1::2]))
        for index, (oid, start) in enumerate(pairs):
            end = pairs[index + 1][1] if index + 1 < len(pairs) else len(data) - offset
            objs[oid] = data[offset + start:offset + end]

    font_maps = {}
    for oid, obj in objs.items():
        ref = re.search(rb'/ToUnicode\s+(\d+)\s+\d+\s+R', obj)
        if not ref:
            continue
        cmap = stream(objs.get(int(ref[1]), b''))
        chars = {}
        for section in re.findall(rb'beginbfchar(.*?)endbfchar', cmap, re.S):
            for src, dst in re.findall(rb'<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>', section):
                chars[bytes.fromhex(src.decode())] = bytes.fromhex(dst.decode()).decode('utf-16-be', 'replace')
        for section in re.findall(rb'beginbfrange(.*?)endbfrange', cmap, re.S):
            for start, end, target in re.findall(rb'<([0-9a-fA-F]+)>\s*<([0-9a-fA-F]+)>\s*(<[^>]+>|\[[^\]]+\])', section):
                lo, hi = int(start, 16), int(end, 16)
                if hi - lo > 65536:
                    continue
                width = len(start) // 2
                if target.startswith(b'<'):
                    offset = int(target[1:-1], 16)
                    for n in range(lo, hi + 1):
                        value = offset + n - lo
                        chars[n.to_bytes(width, 'big')] = value.to_bytes(max(2, (value.bit_length() + 7) // 8), 'big').decode('utf-16-be', 'replace')
                else:
                    for n, dst in zip(range(lo, hi + 1), re.findall(rb'<([^>]+)>', target)):
                        chars[n.to_bytes(width, 'big')] = bytes.fromhex(dst.decode()).decode('utf-16-be', 'replace')
        if chars:
            font_maps[oid] = chars
    resources = {}
    for obj in objs.values():
        for name, oid in re.findall(rb'/([A-Za-z][A-Za-z0-9_+.-]*)\s+(\d+)\s+\d+\s+R', obj.partition(b'stream')[0]):
            if int(oid) in font_maps:
                resources[name] = font_maps[int(oid)]

    def decode(token, font):
        if token.startswith(b'<'):
            raw = bytes.fromhex(re.sub(rb'\s', b'', token[1:-1]).decode())
        else:
            raw = token[1:-1]
            raw = re.sub(rb'\\([0-7]{1,3}|.)', lambda m: bytes([int(m[1], 8)]) if m[1][:1].isdigit()
                         else {b'n': b'\n', b'r': b'\r', b't': b'\t'}.get(m[1], m[1]), raw)
        cmap = resources.get(font)
        if not cmap:
            return raw.decode('cp1252', 'replace')
        widths = sorted({len(k) for k in cmap}, reverse=True)
        result, index = [], 0
        while index < len(raw):
            for width in widths:
                key = raw[index:index + width]
                if key in cmap:
                    result.append(cmap[key])
                    index += width
                    break
            else:
                index += 1
                result.append('�')
        return ''.join(result)

    string = rb'(?:<[^<>]+>|\((?:\\.|[^\\)])*\))'
    tokens = re.compile(rb'/([A-Za-z][A-Za-z0-9_+.-]*)\s+[\d.]+\s+Tf|(' + string + rb')\s*Tj|\[(.*?)\]\s*TJ|\b(ET)\b', re.S)
    text = []
    content_ids = set()
    for obj in objs.values():
        if not re.search(rb'/Type\s*/Page\b', obj):
            continue
        for ref in re.finditer(rb'/Contents\s*(\[.*?\]|\d+\s+\d+\s+R)', obj, re.S):
            content_ids.update(int(m[1]) for m in re.finditer(rb'(\d+)\s+\d+\s+R', ref[1]))
    for oid, obj in objs.items():
        if content_ids and oid not in content_ids:
            continue
        if re.search(rb'/Type\s*/ObjStm\b', obj):
            continue
        data = stream(obj)
        if not re.search(rb'\bBT\b', data):
            continue
        font = b''
        for token in tokens.finditer(data):
            if token[1]:
                font = token[1]
            elif token[2]:
                text.append(decode(token[2], font))
            elif token[3] is not None:
                text.extend(decode(s[0], font) for s in re.finditer(string, token[3]))
            else:
                text.append('\n')
    return ''.join(text)


def sherlock_counts(body):
    text = pdf_text(body)
    headings = re.findall(r'Issue\s*([HM])\s*[-‐‑–]\s*(\d+)\s*:', text)
    if headings:
        return len({n for s, n in headings if s == 'H'}), len({n for s, n in headings if s == 'M'})
    summary = re.search(r'Issues\s*Found\s*(High|Medium)\s*(High|Medium)\s+(\d+)\s+(\d+)\b', text, re.I)
    if summary and summary[1].lower() != summary[2].lower():
        values = {summary[1].lower(): int(summary[3]), summary[2].lower(): int(summary[4])}
        return values['high'], values['medium']
    return None, None
