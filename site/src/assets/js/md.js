// A small, safe Markdown renderer for finding text, display only.
// Everything is escaped first; raw HTML from reports never reaches the page (a few layout tags are unwrapped).
// Handles headings, lists, block quotes, tables, fenced code, emphasis, inline code and links, and turns
// PDF-extraction line wraps into paragraphs. Unfenced code listings (common in PDF text) are detected and kept as code.
import { esc } from './fmt.js';

const FENCE = /^\s*(```+|~~~+)\s*([\w+#.-]*)\s*$/;
const LIST = /^\s{0,3}(?:[-*+•]|\d{1,3}[.)])\s+/;
const CODEY = /[;{}]\s*$|^\s*(?:function|contract|modifier|require|assert|emit|return|if|else|for|while|uint\d*|int\d*|address|mapping|bytes\d*|bool|struct|pub(?:\(crate\))?\s+fn|fn|let|impl|use|mod|const|var|import|from|def|class|module|public|private|internal|external)\b|^\s*\/\/|^\s*\/?\*|=>|::|\);?$|^\s*[)}\]];?$/;

// Unwrap layout tags; anything else that looks like HTML is left as text and escaped.
function stripHtml(s) {
  return s.replace(/<br\s*\/?>/gi, '\n').replace(/<\/?(?:p|div|span|sup|sub|b|i|em|strong|u|font|center|small|big)(?:\s[^>]*)?>/gi, '');
}

function safeUrl(u) {
  try {
    const x = new URL(u);
    return x.protocol === 'https:' || x.protocol === 'http:' ? x.href : '';
  } catch { return ''; }
}

export function inline(text) {
  // Code spans first, held aside so nothing inside them is formatted.
  const held = [];
  const hold = (html) => `\u0000${held.push(html) - 1}\u0000`;
  let s = String(text).replace(/(`+)([^`]|[^`][\s\S]*?[^`])\1(?!`)/g, (_, __, code) => hold(`<code>${esc(code.trim())}</code>`));
  // Links: [text](https://...) and bare URLs; only http(s) survives.
  s = s.replace(/\[([^\]\n]{1,300})\]\((\S{1,2000}?)\)/g, (m, label, url) => {
    const href = safeUrl(url.replace(/^<|>$/g, ''));
    return href ? hold(`<a href="${esc(href)}" target="_blank" rel="noopener noreferrer nofollow">${inlineText(label)}</a>`) : m;
  });
  s = s.replace(/\bhttps?:\/\/[^\s<>()"'`]+[^\s<>()"'`.,;:!?]/g, (url) => {
    const href = safeUrl(url);
    return href ? hold(`<a href="${esc(href)}" target="_blank" rel="noopener noreferrer nofollow">${esc(url)}</a>`) : url;
  });
  s = inlineText(s);
  return s.replace(/\u0000(\d+)\u0000/g, (_, i) => held[Number(i)]);
}

// Escape, then bold and italics with asterisks. Underscores are left alone: they are mostly identifiers.
function inlineText(t) {
  let s = esc(t);
  s = s.replace(/\*\*(?=\S)([\s\S]*?\S)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/(^|[^*\w])\*(?=[^\s*])([^*\n]*?[^\s*])\*(?![*\w])/g, '$1<em>$2</em>');
  s = s.replace(/(^|\s)__(?=\S)([^_\n]*?\S)__(?=\s|$|[.,;:])/g, '$1<strong>$2</strong>');
  // Leftover markers from broken emphasis read as noise.
  return s.replace(/\*\*/g, '');
}

function codeBlock(lines, lang = '') {
  // Drop the common indentation and blank edges.
  while (lines.length && !lines[0].trim()) lines.shift();
  while (lines.length && !lines[lines.length - 1].trim()) lines.pop();
  const pad = Math.min(...lines.filter((l) => l.trim()).map((l) => l.match(/^\s*/)[0].length));
  const body = lines.map((l) => l.slice(Number.isFinite(pad) ? pad : 0)).join('\n');
  return `<pre class="md-code"${lang ? ` data-lang="${esc(lang)}"` : ''}><code>${esc(body)}</code></pre>`;
}

function looksLikeCode(lines) {
  const real = lines.filter((l) => l.trim());
  if (real.length < 2) return false;
  const hits = real.filter((l) => CODEY.test(l)).length;
  return hits / real.length >= 0.6;
}

function isTableSep(l) { return /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(l); }
function cells(l) { return l.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim()); }

function table(lines) {
  const head = cells(lines[0]);
  const rows = lines.slice(2).map(cells);
  return `<div class="md-table"><table><thead><tr>${head.map((h) => `<th>${inline(h)}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
}

function list(lines) {
  const ordered = /^\s*\d/.test(lines[0]);
  const items = [];
  for (const l of lines) {
    if (LIST.test(l)) items.push(l.replace(LIST, ''));
    else if (items.length) items[items.length - 1] += ` ${l.trim()}`;
  }
  return `<${ordered ? 'ol' : 'ul'}>${items.map((i) => `<li>${inline(i)}</li>`).join('')}</${ordered ? 'ol' : 'ul'}>`;
}

// Join PDF line wraps: a line ending mid-sentence continues on the next; hyphenated breaks rejoin.
function paragraph(lines) {
  let out = '';
  for (const raw of lines) {
    const l = raw.trim();
    if (!l) continue;
    if (!out) out = l;
    else if (/[a-z]-$/.test(out) && /^[a-z]/.test(l)) out = out.slice(0, -1) + l;
    else out += ` ${l}`;
  }
  return out ? `<p>${inline(out)}</p>` : '';
}

function blocks(text) {
  const html = [];
  const lines = text.split('\n');
  let i = 0;
  const prose = (part) => {
    // A paragraph that holds list items part way through is split there.
    const at = part.findIndex((l, k) => k > 0 && LIST.test(l) && !LIST.test(part[k - 1]));
    const head = at > 0 ? part.slice(0, at) : part;
    const tail = at > 0 ? part.slice(at) : [];
    html.push(LIST.test(head[0] || '') ? list(head) : paragraph(head));
    if (tail.length) html.push(list(tail));
  };
  const flushPara = (buf) => {
    if (!buf.length) return;
    if (looksLikeCode(buf)) { html.push(codeBlock(buf)); return; }
    // Unfenced listings inside prose: a run of three or more code-like lines (one-line gaps allowed) is code.
    const code = buf.map((l) => CODEY.test(l));
    let k = 0;
    let start = 0;
    while (k < buf.length) {
      if (!code[k]) { k++; continue; }
      let end = k;
      let run = 0;
      for (let j = k; j < buf.length; j++) {
        if (code[j]) { end = j; run++; } else if (!(code[j + 1] && j + 1 < buf.length)) break;
      }
      if (run >= 3) {
        if (k > start) prose(buf.slice(start, k));
        html.push(codeBlock(buf.slice(k, end + 1)));
        start = end + 1;
      }
      k = end + 1;
    }
    if (start < buf.length) prose(buf.slice(start));
  };
  let buf = [];
  while (i < lines.length) {
    let l = lines[i];
    // PDF text glues fences to code: "```solidity function f() {" opens a block with its first line, and a stray
    // "}```" with no block open just loses its marker.
    const glued = l.match(/^\s*(```+|~~~+)([\w+#.-]*)\s+(\S.*)$/);
    if (glued) { lines.splice(i, 1, `${glued[1]}${glued[2]}`, glued[3]); l = lines[i]; }
    else if ((l.match(/```/g) || []).length === 1 && /\S\s*```\s*\S/.test(l) && lines.slice(i + 1).some((x) => /```\s*$/.test(x))) {
      // "Set the constructor to ```payable" with the block closed on a later line: split out the opening fence.
      const at = l.indexOf('```');
      lines.splice(i, 1, l.slice(0, at), '```', l.slice(at + 3));
      l = lines[i];
    } else if (/\S\s*(?:```+|~~~+)\s*$/.test(l) && !FENCE.test(l)) { l = l.replace(/\s*(?:```+|~~~+)\s*$/, ''); lines[i] = l; }
    const fence = l.match(FENCE);
    if (fence) {
      flushPara(buf); buf = [];
      const code = [];
      i++;
      const mark = fence[1][0] === '`' ? '`' : '~';
      const close = new RegExp(`^\\s*${mark}{${fence[1].length},}\\s*$`);
      const tail = new RegExp(`^(.*\\S)\\s*${mark}{${fence[1].length},}\\s*$`);
      while (i < lines.length && !close.test(lines[i])) {
        const t = lines[i].match(tail);
        if (t) { code.push(t[1]); break; }
        code.push(lines[i++]);
      }
      i++;
      html.push(codeBlock(code, fence[2]));
      continue;
    }
    const h = l.match(/^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (h) {
      flushPara(buf); buf = [];
      const level = Math.min(6, h[1].length + 2); // report headings sit under the page's own h1 and h2
      if (h[2]) html.push(`<h${level}>${inline(h[2])}</h${level}>`);
      i++; continue;
    }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(l) && !buf.length) { html.push('<hr>'); i++; continue; }
    if (l.includes('|') && i + 1 < lines.length && isTableSep(lines[i + 1])) {
      flushPara(buf); buf = [];
      const t = [l, lines[i + 1]];
      i += 2;
      while (i < lines.length && lines[i].includes('|') && lines[i].trim()) t.push(lines[i++]);
      html.push(table(t));
      continue;
    }
    if (/^\s*>/.test(l)) {
      flushPara(buf); buf = [];
      const q = [];
      while (i < lines.length && /^\s*>/.test(lines[i])) q.push(lines[i++].replace(/^\s*>\s?/, ''));
      html.push(`<blockquote>${blocks(q.join('\n'))}</blockquote>`);
      continue;
    }
    if (!l.trim()) { flushPara(buf); buf = []; i++; continue; }
    // A new list starts a new block even without a blank line before it.
    if (LIST.test(l) && buf.length && !LIST.test(buf[buf.length - 1]) && !looksLikeCode(buf)) { flushPara(buf); buf = []; }
    buf.push(l);
    i++;
  }
  flushPara(buf);
  // A heading with nothing after it is the next section's title caught by the extraction; it reads as noise.
  while (html.length && /^<h[3-6]>/.test(html[html.length - 1])) html.pop();
  return html.join('\n');
}

// A heading (or bold line) that only repeats the finding's title is dropped: the page already shows the title.
export function withoutTitle(text, title) {
  const norm = (x) => String(x || '').toLowerCase().replace(/^\s*(?:\[[^\]]{1,12}\]|[a-z]{1,4}-?\d{1,3}[.:)]?)\s*/, '').replace(/[^a-z0-9]+/g, '');
  const lines = String(text || '').split('\n');
  const at = lines.findIndex((l) => l.trim());
  if (at < 0 || !title) return text;
  const m = lines[at].match(/^\s{0,3}(?:#{1,6}\s+(.*?)\s*#*|\*\*(.*?)\*\*)\s*$/);
  const t = norm(title);
  if (m && t && norm(m[1] ?? m[2]) === t) return lines.slice(at + 1).join('\n');
  return text;
}

export function renderMarkdown(text) {
  const src = stripHtml(String(text || ''))
    .replace(/\r\n?/g, '\n')
    .replace(/[ \t]/g, (c) => (c === '\t' ? '    ' : ' '))
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
  return blocks(src);
}

// A short display excerpt for cards and descriptions (display only; the finding page shows the full text).
// Skips the leading id and title echo and label: value metadata (Asset, Status, Severity, Impact, Files and so on),
// starts at the description prose (after a "Description" or "Summary" heading when there is one) and cuts at a
// sentence boundary.
const START = /^(?:#{1,6}\s*)?(?:\d+(?:\.\d+)*\.?\s+)?(description|bug description|issue description|finding description|summary|vulnerability details?|details|problem|overview)\s*:?\s*(.*)$/i;
const STOP = /^(?:#{1,6}\s*)?(?:recommendations?|mitigations?|remediation|proof of concept|poc|resolution|update|fix|exploit scenario|code snippet|tool used|references?|client response|response)\s*:?\s*$|^[^:]{0,40}['’]s response\s*:|^(?:team|client) response\s*:/i;
const META = /^(?:[-*•]\s*)?(?:asset|assets|status|rating|severity|impact|likelihood|probability|difficulty|category|type|target|context|location|locations|files?|file\(s\)|source|found by|submitted by|reported by|resolution|fixed in|fixed at|commit|contracts?|component|risk|labels?|finding id|id|at the lines?|lines?|implications)\b(?:[^:\n]{0,12}:|\s{2,}\S)/i;
const isMeta = (l) => META.test(l) || (l.length < 160 && (l.match(/\b(?:severity|status|category|source|likelihood|impact|difficulty|risk)\b/gi) || []).length >= 2);
const norm = (x) => String(x || '').toLowerCase().normalize('NFKC').replace(/[^a-z0-9]+/g, '');

export function excerpt(text, title = '', max = 280) {
  const lines = stripHtml(String(text || ''))
    .normalize('NFKC')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, '')
    .replace(/```[\s\S]*?(```|$)/g, '\n\n')
    .replace(/\*\*|__/g, '')
    .replace(/\[([^\]\n]+)\]\([^)\s]+\)/g, '$1')
    .replace(/`([^`\n]+)`/g, '$1')
    .split('\n');
  const raw = lines.map((l) => l.trim());
  for (let k = 0; k < lines.length; k++) lines[k] = lines[k].replace(/\s+/g, ' ').trim();
  const t = norm(title);
  // Where the prose starts: after a description heading if there is one, else after the leading metadata.
  let i = lines.findIndex((l) => START.test(l));
  let first = '';
  if (i >= 0) {
    first = lines[i].match(START)[2].replace(/^[-:]\s*/, '');
    i++;
  } else {
    i = 0;
    for (; i < lines.length; i++) {
      const l = lines[i];
      const n = norm(l.replace(/^#+\s*/, ''));
      if (!l || /^#/.test(l) || isMeta(raw[i]) || /^\|/.test(l)) continue;
      if (n && t && (t.includes(n) || (n.includes(t) && n.length < t.length + 40))) continue;
      if (l.split(' ').length < 4 && !/[.!?]$/.test(l)) continue;
      break;
    }
  }
  const paras = [];
  let cur = first ? [first] : [];
  const flush = () => { if (cur.length) paras.push(cur); cur = []; };
  for (; i < lines.length; i++) {
    const l = lines[i];
    if (STOP.test(l)) break;
    if (!l || /^#/.test(l) || START.test(l)) { flush(); continue; }
    if (isMeta(raw[i]) && l.length < 90) continue;
    if ((/^\d+\s{2,}\S/.test(raw[i]) && /[;{}()]|\/\/\//.test(l)) || /^listing \d+:?$/i.test(l)) continue;
    cur.push(l.replace(/^(?:[-*•]|\d{1,2}[.)])\s+/, ''));
    if (paras.reduce((n, p) => n + p.join(' ').length, 0) + cur.join(' ').length > max * 2) break;
  }
  flush();
  // Join paragraphs until there is enough to read; a paragraph without end punctuation gets a full stop.
  let out = '';
  // PDF text often breaks a sentence across a blank line: a paragraph that ends mid-sentence joins the next one.
  for (let k = paras.length - 1; k > 0; k--) {
    const prev = paras[k - 1][paras[k - 1].length - 1];
    if (!/[.!?:;]$/.test(prev) && /^[a-z(]/.test(paras[k][0])) { paras[k - 1].push(...paras[k]); paras.splice(k, 1); }
  }
  for (const p of paras) {
    let s = p.reduce((a, l) => (/[a-z]-$/.test(a) && /^[a-z]/.test(l) ? a.slice(0, -1) + l : a ? `${a} ${l}` : l), '');
    if (!s) continue;
    if (!/[.!?:;]$/.test(s)) s += '.';
    out = out ? `${out} ${s}` : s;
    if (out.length >= 140) break;
  }
  if (!out) out = lines.filter((l) => l && !/^#/.test(l) && !isMeta(l)).join(' ');
  out = out.replace(/\s+/g, ' ').replace(/\s+([,;:.!?])(?=\s|$)/g, '$1').trim();
  if (out.length <= max) return out;
  // Cut at the last sentence end that fits; failing that, at a word, with an ellipsis.
  const ends = [...out.slice(0, max + 1).matchAll(/[.!?](?=\s+["“'(`]?[A-Z0-9])/g)].map((m) => m.index + 1).filter((n) => n >= 90);
  if (ends.length) return out.slice(0, ends[ends.length - 1]);
  return `${out.slice(0, max).replace(/\s+\S*$/, '').replace(/[,;:]$/, '')}…`;
}
