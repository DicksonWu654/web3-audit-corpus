"""Step 4: finding-text check against independently extracted original text.

  python3 -I scripts/verify/linkcheck_text.py [--n 300]

Sample: stratified random findings from data/findings/<firm>.jsonl and data/findings/supplemental/*.jsonl
(certik and _unknown_layouts excluded); stratum = publisher, min 2 each, remainder proportional; seeded.
Original: re-downloaded from its public/pinned link into a fresh batch dir; if the download does not reproduce the
corpus sha256 the sha-verified local original is used instead (recorded as source=local); if neither is available the
result is FETCH_FAILED. Text: pdftotext -layout (bundled poppler) for PDFs, OCR (tesseract) of the finding's pages only
when the text layer there is empty/sparse; UTF-8 for Markdown; tag-stripped text for HTML.

Classes: PASS_EXACT (title and first 200 chars of body_text found after whitespace collapsing only),
PASS_NORMALIZED (found after NFKC/ligature/quote/dash/hyphenation/case/markup normalisation), FAIL_PARTIAL (only one of
the two, or >= 50% of the body prefix), FAIL_NOT_FOUND, FETCH_FAILED.
"""
from __future__ import annotations

import glob
import html
import json
import random
import re
import subprocess
import sys
import unicodedata
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import linkcheck_common as C  # noqa: E402
from linkcheck_integrity import html_text  # noqa: E402
sys.path.append(str(Path(__file__).resolve().parents[1] / 'findings'))
from streams import finding_rows, finding_paths  # noqa: E402

SAMPLE = C.STATE / "text_sample.json"
RESULTS = C.STATE / "text_results.jsonl"
TOOLS = C.ROOT / "local-cache/fulltext/tools/usr"
PREFIX = 200


def tool_env():
    import os
    env = dict(os.environ)
    lib = TOOLS / "lib/x86_64-linux-gnu"
    env["LD_LIBRARY_PATH"] = str(lib) + (":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
    tess = TOOLS / "share/tesseract-ocr/5/tessdata"
    if tess.exists():
        env["TESSDATA_PREFIX"] = str(tess)
    env["OMP_THREAD_LIMIT"] = "1"
    return env


def tool(name):
    p = TOOLS / "bin" / name
    if p.exists():
        return str(p)
    import shutil
    return shutil.which(name)


# ---------------------------------------------------------------- normalisation

QUOTES = str.maketrans({"‘": "'", "’": "'", "‚": "'", "‛": "'", "′": "'", "`": "'",
                        "“": '"', "”": '"', "„": '"', "‟": '"', "″": '"',
                        "–": "-", "—": "-", "‒": "-", "−": "-", "‐": "-", "‑": "-",
                        "­": None, "​": None, "﻿": None, "‌": None, "‍": None})


def ws(s):
    return re.sub(r"\s+", " ", s or "").strip()


def norm(s):
    s = html.unescape(s or "")
    s = unicodedata.normalize("NFKC", s).translate(QUOTES)
    s = re.sub(r"(\w)-[ \t]*\n\s*(\w)", r"\1\2", s)          # line-end hyphenation
    return s.casefold()


def skeleton(s):
    return re.sub(r"[\W_]+", "", norm(s))


def prefix_fraction(needle, hay):
    """Longest prefix of needle contained in hay, as a fraction of len(needle)."""
    if not needle:
        return 1.0
    lo, hi = 0, len(needle)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if needle[:mid] in hay:
            lo = mid
        else:
            hi = mid - 1
    return lo / len(needle)


def words_in_order(title, text):
    """Title words in order within a short window: a title wrapped across layout lines/columns."""
    words = [w for w in re.split(r"[\W_]+", norm(title)) if w]
    if not words:
        return True
    hay = norm(text)
    limit = 2 * len(norm(title)) + 80
    for m in re.finditer(r"(?<![^\W_])" + re.escape(words[0]), hay):
        pos, ok = m.end(), True
        for w in words[1:]:
            nxt = hay.find(w, pos)
            if nxt < 0 or nxt - m.start() > limit:
                ok = False
                break
            pos = nxt + len(w)
        if ok:
            return True
    return False


def judge(title, body, text):
    t_ws, b_ws, x_ws = ws(title), ws((body or "")[:PREFIX]), ws(text)
    title_exact = (not t_ws) or t_ws in x_ws
    body_exact = b_ws in x_ws
    t_sk, b_sk, x_sk = skeleton(title), skeleton((body or "")[:PREFIX]), skeleton(text)
    title_norm = (not t_sk) or t_sk in x_sk
    title_wrapped = False
    if not title_norm and words_in_order(title, text):
        title_norm = title_wrapped = True
    body_norm = bool(b_sk) and b_sk in x_sk
    frac = prefix_fraction(b_sk, x_sk)
    if title_exact and body_exact:
        cls = "PASS_EXACT"
    elif title_norm and body_norm:
        cls = "PASS_NORMALIZED"
    elif title_norm or body_norm or frac >= 0.5:
        cls = "FAIL_PARTIAL"
    else:
        cls = "FAIL_NOT_FOUND"
    return cls, {"title_exact": title_exact, "body_exact": body_exact, "title_norm": title_norm,
                 "body_norm": body_norm, "body_prefix_fraction": round(frac, 3), "title_empty": not t_ws,
                 "title_wrapped": title_wrapped}


# ---------------------------------------------------------------- sample

def finding_files():
    return [str(p) for p in finding_paths(C.ROOT/'data/findings') if p.stem not in C.EXCLUDED_FIRMS]


def sample(n):
    index = defaultdict(list)
    location = [0]
    def located(path):
        with path.open(encoding='utf-8') as stream:
            for i, line in enumerate(stream):
                if line.strip():
                    location[0] = i
                    yield json.loads(line)
    firms = {Path(p).stem for p in finding_files()}
    for path, row in finding_rows(C.ROOT/'data/findings', read_jsonl=located, firms=firms):
        firm = row.get('firm_id') or path.stem
        if firm not in C.EXCLUDED_FIRMS:
            index[firm].append((str(path), location[0]))
    alloc = C.allocate({k: len(v) for k, v in index.items()}, n)
    rng = random.Random(C.SEED + 1)
    picks = []
    for firm in sorted(index):
        picks += rng.sample(index[firm], alloc[firm])
    wanted = defaultdict(set)
    for f, i in picks:
        wanted[f].add(i)
    recs = []
    for f, lines in wanted.items():
        with open(f, encoding="utf-8") as h:
            for i, line in enumerate(h):
                if i in lines:
                    d = json.loads(line)
                    recs.append({"file": str(Path(f).relative_to(C.ROOT)), "line": i + 1, "firm_id": d.get("firm_id"),
                                 "sha256": d.get("sha256"), "finding_id": d.get("finding_id"),
                                 "publisher_finding_id": d.get("publisher_finding_id"), "title": d.get("title") or "",
                                 "body_text": d.get("body_text") or "", "page": d.get("page"),
                                 "pages": ((d.get("body_span") or {}).get("pages") or []),
                                 "record_kind": d.get("record_kind"), "method": d.get("method"),
                                 "severity": d.get("severity")})
    recs.sort(key=lambda r: (r["firm_id"], r["file"], r["line"]))
    return recs, alloc, {k: len(v) for k, v in index.items()}


# ---------------------------------------------------------------- originals and text

class Originals:
    def __init__(self, batch):
        self.batch = batch
        self.rows = {}
        for row in C.report_rows():
            self.rows.setdefault(row["sha256"], row)
        self.cache = {}
        import threading
        self.locks = defaultdict(threading.Lock)

    def get(self, sha):
        with self.locks[sha]:
            if sha in self.cache:
                return self.cache[sha]
            self.cache[sha] = self._get(sha)
            return self.cache[sha]

    def _get(self, sha):
        row = self.rows.get(sha)
        if not row:
            return {"path": None, "source": "none", "note": "sha256 not in data/collect", "row": None}
        url, how = C.download_url(row)
        sink = self.batch / f"{sha}.bin"
        resp, final, hops = C.fetch(url, "GET", max_bytes=400 << 20, sink=sink)
        web = {"url": url, "how": how, "code": resp.code, "error": resp.error,
               "sha256": resp.headers.get("x-sha256")}
        if resp.headers.get("x-sha256") == sha:
            return {"path": sink, "source": "web", "web": web, "row": row}
        if sink.exists():
            sink.unlink()
        local = C.local_original(row)
        if local and C.sha256_file(local) == sha:
            return {"path": local, "source": "local", "web": web, "row": row}
        return {"path": None, "source": "none", "web": web, "row": row}


def _js_unescape(s):
    out, i = [], 0
    simple = {"n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\0"}
    while i < len(s):
        ch = s[i]
        if ch != "\\" or i + 1 >= len(s):
            out.append(ch)
            i += 1
            continue
        nx = s[i + 1]
        if nx in simple:
            out.append(simple[nx]); i += 2
        elif nx == "x":
            out.append(chr(int(s[i + 2:i + 4], 16))); i += 4
        elif nx == "u" and s[i + 2:i + 3] == "{":
            end = s.index("}", i)
            out.append(chr(int(s[i + 3:end], 16))); i = end + 1
        elif nx == "u":
            out.append(chr(int(s[i + 2:i + 6], 16))); i += 6
        elif nx == "\n":
            i += 2
        else:
            out.append(nx); i += 2
    return "".join(out)


def walk(o, out):
    """In-order flattening of a JSON value: keys, list indices and scalar values."""
    if isinstance(o, dict):
        for k, v in o.items():
            out.append(str(k))
            walk(v, out)
    elif isinstance(o, list):
        for i, v in enumerate(o):
            out.append(f"[{i}]")
            walk(v, out)
    elif o is not None and not isinstance(o, bool):
        out.append(str(o))
    elif isinstance(o, bool):
        out.append("true" if o else "false")


def js_json_strings(raw):
    """Decode JSON.parse('...') payloads of a JS chunk (data only, never executed) and join their string values."""
    parts = []
    for m in re.finditer(r"JSON\.parse\('((?:[^'\\]|\\.)*)'\)", raw, re.S):
        try:
            obj = json.loads(_js_unescape(m.group(1)))
        except (ValueError, IndexError):
            continue
        walk(obj, parts)
    texts = []
    for p in parts:
        texts.append(p)
        if "<" in p and ">" in p:
            texts.append(html_text(p.encode("utf-8")))
    return "\n".join(texts)


class Texts:
    def __init__(self, batch):
        self.batch = batch
        self.cache = {}
        import threading
        self.locks = defaultdict(threading.Lock)
        self.env = tool_env()

    def full(self, sha, path, fmt):
        with self.locks[sha]:
            if sha not in self.cache:
                self.cache[sha] = self._full(path, fmt)
            return self.cache[sha]

    def _full(self, path, fmt):
        data = Path(path).read_bytes()
        if data.startswith(b"%PDF") or fmt == "pdf":
            r = subprocess.run([tool("pdftotext"), "-layout", "-enc", "UTF-8", str(path), "-"], capture_output=True,
                               env=self.env, timeout=300)
            text = r.stdout.decode("utf-8", "replace")
            return {"kind": "pdf", "text": text, "pages": text.split("\f")}
        raw = data.decode("utf-8", "replace")
        if "JSON.parse('" in raw[:200000]:
            payload = js_json_strings(raw)
            if payload:
                return {"kind": "js-json", "text": payload + "\n" + raw, "pages": None}
        if fmt == "md":
            return {"kind": "md", "text": raw, "pages": [raw]}
        if fmt in ("html", "other") or "<html" in raw[:4096].lower():
            return {"kind": "html", "text": html_text(data) + "\n" + raw, "pages": None}
        return {"kind": "text", "text": raw, "pages": [raw]}

    def ocr(self, sha, path, pages):
        out = []
        for p in pages:
            stem = self.batch / f"{sha}.p{p}"
            subprocess.run([tool("pdftoppm"), "-r", "300", "-gray", "-png", "-f", str(p), "-l", str(p), "-singlefile",
                            str(path), str(stem)], capture_output=True, env=self.env, timeout=300)
            img = Path(str(stem) + ".png")
            if img.exists():
                for psm in ("4", "6"):
                    r = subprocess.run([tool("tesseract"), str(img), "-", "-l", "eng", "--psm", psm],
                                       capture_output=True, env=self.env, timeout=300)
                    out.append(r.stdout.decode("utf-8", "replace"))
                img.unlink()
        return "\n".join(out)


def check(rec, originals, texts):
    base = {k: rec[k] for k in ("file", "line", "firm_id", "sha256", "finding_id", "publisher_finding_id",
                                "record_kind", "method", "page")}
    base["title"] = rec["title"][:200]
    orig = originals.get(rec["sha256"])
    if not orig["path"]:
        return dict(base, cls="FETCH_FAILED", source=orig["source"], web=orig.get("web"), note=orig.get("note", ""))
    fmt = (orig["row"] or {}).get("file_format")
    full = texts.full(rec["sha256"], orig["path"], fmt)
    cls, detail = judge(rec["title"], rec["body_text"], full["text"])
    used = full["text"]
    method = "pdftotext-layout" if full["kind"] == "pdf" else full["kind"]
    if full["kind"] == "pdf" and cls not in ("PASS_EXACT", "PASS_NORMALIZED"):
        pages = sorted({p for p in ([rec["page"]] if rec["page"] else []) + list(rec["pages"]) if isinstance(p, int)})
        sparse = (not pages) or all(len(re.sub(r"\W", "", full["pages"][p - 1] if p - 1 < len(full["pages"]) else "")) < 200
                                    for p in pages)
        if pages and sparse:
            ocr_text = texts.ocr(rec["sha256"], orig["path"], pages[:4])
            cls2, detail2 = judge(rec["title"], rec["body_text"], ocr_text)
            order = ["FAIL_NOT_FOUND", "FAIL_PARTIAL", "PASS_NORMALIZED", "PASS_EXACT"]
            if order.index(cls2) > order.index(cls):
                cls, detail, method, used = cls2, detail2, "ocr-tesseract", ocr_text
            else:
                method = "pdftotext-layout(+ocr tried)"
    extra = {}
    if cls.startswith("FAIL") and "\n\n" in rec["body_text"].strip():
        # diagnostic: does the body match once its first block (e.g. a badge/header line) is dropped?
        rest = rec["body_text"].strip().split("\n\n", 1)[1]
        extra["without_first_block_cls"] = judge(rec["title"], rest, used)[0]
        extra["first_block"] = rec["body_text"].strip().split("\n\n", 1)[0][:80]
    return dict(base, cls=cls, source=orig["source"], text_method=method,
                web_code=(orig.get("web") or {}).get("code"), **detail, **extra)


def main():
    n = int(sys.argv[sys.argv.index("--n") + 1]) if "--n" in sys.argv else 300
    recs, alloc, pop = sample(n)
    SAMPLE.write_text(json.dumps({"n": len(recs), "seed": C.SEED + 1, "allocation": alloc, "population": pop,
                                  "items": [[r["file"], r["line"]] for r in recs]}, indent=1))
    batch = C.fresh_batch("textcheck")
    print(f"sample {len(recs)} findings from {len({r['sha256'] for r in recs})} reports; downloads -> {batch}", flush=True)
    originals, texts = Originals(batch), Texts(batch)
    out = []
    with ThreadPoolExecutor(max_workers=8) as ex:
        for i, res in enumerate(ex.map(lambda r: check(r, originals, texts), recs)):
            out.append(res)
            if (i + 1) % 25 == 0:
                print(f"{i + 1}/{len(recs)} {dict(Counter(r['cls'] for r in out))}", flush=True)
    RESULTS.write_text("".join(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n" for r in out))
    print(dict(Counter(r["cls"] for r in out)))


if __name__ == "__main__":
    main()
