// Small hand-rolled SVG charting for the site. Marks follow one spec everywhere: columns capped at 24px with a 4px
// rounded data end and a 2px surface gap between stacked segments, 2px lines with ringed end dots, hairline grid,
// a crosshair/band hover with tooltip, keyboard stepping with the arrow keys, and a table view for every chart.
import { esc, compact } from './fmt.js';

const NS = 'http://www.w3.org/2000/svg';
let tipEl = null;
const reduceMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

export function tooltip() {
  if (!tipEl) {
    tipEl = document.createElement('div');
    tipEl.className = 'tooltip';
    tipEl.setAttribute('role', 'status');
    tipEl.setAttribute('aria-live', 'polite');
    document.body.appendChild(tipEl);
  }
  return tipEl;
}

export function showTip(html, x, y) {
  const t = tooltip();
  t.innerHTML = html;
  t.classList.add('on');
  const r = t.getBoundingClientRect();
  const vw = document.documentElement.clientWidth;
  let left = x + 14;
  if (left + r.width > vw - 8) left = x - r.width - 14;
  if (left < 8) left = 8;
  let top = y - r.height - 12;
  if (top < 8) top = y + 16;
  t.style.left = `${left}px`;
  t.style.top = `${top}px`;
}
export function hideTip() {
  if (tipEl) tipEl.classList.remove('on');
}

export function tipHTML(title, rows) {
  return `<div class="tt-h">${esc(title)}</div>${rows.map((r) => `<div class="tt-r"><span>${r.color ? `<i class="swatch" style="background:${r.color}"></i>` : ''}${esc(r.label)}</span><b>${esc(r.value)}</b></div>`).join('')}`;
}

export function niceTicks(max, count = 4) {
  if (!(max > 0)) return [0, 1];
  const raw = max / count;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw) || raw;
  const top = Math.ceil(max / step - 1e-9) * step;
  const ticks = [];
  for (let v = 0; v <= top + step / 2; v += step) ticks.push(Number(v.toFixed(10)));
  return ticks;
}

function textWidth(s, px = 12) {
  return String(s).length * px * 0.56;
}

// Re-render on width change.
export function mount(el, render) {
  let last = -1;
  const run = () => {
    const w = Math.floor(el.clientWidth);
    if (w <= 0 || Math.abs(w - last) < 2) return;
    last = w;
    render(w);
  };
  run();
  if ('ResizeObserver' in window) {
    let raf = 0;
    const ro = new ResizeObserver(() => { cancelAnimationFrame(raf); raf = requestAnimationFrame(run); });
    ro.observe(el);
  } else window.addEventListener('resize', run);
}

export function legendHTML(items, kind = 'swatch') {
  return `<ul class="legend">${items.map((s) => `<li>${kind === 'line' ? `<i class="key-line" style="background:${s.color}"></i>` : `<i class="swatch" style="background:${s.color}"></i>`}${esc(s.label)}</li>`).join('')}</ul>`;
}

export function tableHTML(columns, rows, summary = 'Show the numbers') {
  const head = columns.map((c) => `<th scope="col">${esc(c.label)}</th>`).join('');
  const body = rows.map((r) => `<tr>${columns.map((c, i) => (i === 0 ? `<th scope="row">${esc(c.get(r))}</th>` : `<td>${esc(c.get(r))}</td>`)).join('')}</tr>`).join('');
  return `<details class="numbers"><summary>${esc(summary)}</summary><div class="tbl-wrap"><table class="data"><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div></details>`;
}

// Build a <figure> with title, optional tools/legend, plot container, note and table.
export function figure({ id, title, sub, legend, tools, note, table, label }) {
  const f = document.createElement('figure');
  f.className = 'chart';
  if (id) f.id = id;
  f.innerHTML = `
    <figcaption><h3 class="chart-title">${esc(title)}</h3>${sub ? `<p class="chart-sub">${esc(sub)}</p>` : ''}</figcaption>
    ${legend || tools ? `<div class="chart-tools">${tools || ''}${legend || ''}</div>` : ''}
    <div class="plot" tabindex="0" role="img" aria-label="${esc(label || title)}. Use the left and right arrow keys to read values."></div>
    ${note ? `<p class="note">${note}</p>` : ''}
    ${table || ''}`;
  return { root: f, plot: f.querySelector('.plot') };
}

function topRoundedRect(x, y, w, h, r) {
  if (h <= 0) return '';
  r = Math.min(r, h, w / 2);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

function bindBands(plot, svg, n, bandX, onShow, onHide) {
  let idx = -1;
  const hl = svg.querySelector('.band-hl');
  const show = (i, clientX, clientY) => {
    idx = i;
    const [x, w] = bandX(i);
    if (hl) { hl.setAttribute('x', x); hl.setAttribute('width', w); hl.classList.add('on'); }
    onShow(i, clientX, clientY);
  };
  const hide = () => { if (hl) hl.classList.remove('on'); hideTip(); onHide && onHide(); };
  svg.addEventListener('pointermove', (e) => {
    const pt = svg.getBoundingClientRect();
    const scale = svg.viewBox.baseVal.width / pt.width;
    const px = (e.clientX - pt.left) * scale;
    let best = -1;
    for (let i = 0; i < n; i++) {
      const [x, w] = bandX(i);
      if (px >= x && px < x + w) { best = i; break; }
    }
    if (best >= 0) show(best, e.clientX, e.clientY); else hide();
  });
  svg.addEventListener('pointerleave', hide);
  plot.onkeydown = (e) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const next = idx < 0 ? (e.key === 'ArrowRight' ? 0 : n - 1) : Math.max(0, Math.min(n - 1, idx + (e.key === 'ArrowRight' ? 1 : -1)));
      const [x, w] = bandX(next);
      const r = svg.getBoundingClientRect();
      const s = r.width / svg.viewBox.baseVal.width;
      show(next, r.left + (x + w / 2) * s, r.top + 20);
    } else if (e.key === 'Escape') { idx = -1; hide(); }
  };
  plot.onblur = () => { idx = -1; hide(); };
}

function xLabels(cats, labelFn, bandW) {
  // Decide on long/short labels and thinning.
  const long = cats.map((c, i) => labelFn(c, i, false));
  const maxLong = Math.max(...long.map((l) => textWidth(l)));
  if (maxLong + 6 <= bandW) return { labels: long, every: 1 };
  const short = cats.map((c, i) => labelFn(c, i, true));
  const maxShort = Math.max(...short.map((l) => textWidth(l)));
  const every = Math.max(1, Math.ceil((maxShort + 6) / bandW));
  return { labels: short, every };
}

export const shortYear = (c, ytd) => (c === 'unknown' ? '?' : `’${String(c).slice(2)}${ytd ? '*' : ''}`);

/* ------------------------------------------------------------------ columns */
// The last category each chart draws, so checks can match the axis to the data.
const markLast = (plot, cats, ytd) => { const c = cats[cats.length - 1]; plot.dataset.lastX = c == null ? '' : String(c); plot.dataset.lastYtd = c != null && ytd && ytd(c) ? '1' : ''; };
export function columns(plot, o) {
  markLast(plot, o.cats, o.ytd);
  const height = o.height || 260;
  const n = o.cats.length;
  const gap = 2;
  mount(plot, (W) => {
    const totals = o.cats.map((_, i) => o.series.reduce((a, s) => a + (s.values[i] || 0), 0));
    const max = o.percent ? 1 : (o.yMax || Math.max(...totals, 0));
    const ticks = o.percent ? [0, 0.25, 0.5, 0.75, 1] : niceTicks(max, o.tickCount || 4);
    const top = ticks[ticks.length - 1] || 1;
    const fmtY = o.yTick || ((v) => compact(v));
    const ml = Math.max(...ticks.map((t) => textWidth(fmtY(t)))) + 10;
    const mr = 6;
    const mt = o.labelTotals ? 22 : 10;
    const mb = 26;
    const pw = W - ml - mr;
    const ph = height - mt - mb;
    const band = pw / n;
    const bw = Math.max(4, Math.min(o.barMax || 24, band * 0.64));
    const y = (v) => mt + ph - (v / top) * ph;
    const parts = [];
    parts.push(`<rect class="band-hl" x="0" y="${mt}" width="0" height="${ph}"></rect>`);
    for (const t of ticks) {
      const yy = Math.round(y(t)) + 0.5;
      parts.push(`<line class="${t === 0 ? 'base' : 'grid'}" x1="${ml}" x2="${W - mr}" y1="${yy}" y2="${yy}"></line>`);
      parts.push(`<text x="${ml - 8}" y="${yy + 4}" text-anchor="end">${esc(fmtY(t))}</text>`);
    }
    const anim = o.animate && !reduceMotion();
    o.cats.forEach((c, i) => {
      const cx = ml + band * i + band / 2;
      const x = cx - bw / 2;
      let acc = 0;
      const tot = totals[i] || 0;
      const vals = o.series.map((s) => (o.percent ? (tot ? (s.values[i] || 0) / tot : 0) : s.values[i] || 0));
      const lastIdx = vals.reduce((li, v, k) => (v > 0 ? k : li), -1);
      const ytd = o.ytd && o.ytd(c, i);
      const g = [];
      vals.forEach((v, k) => {
        if (!(v > 0)) return;
        const y0 = y(acc);
        const y1 = y(acc + v);
        acc += v;
        let h = y0 - y1;
        let yTop = y1;
        if (k !== lastIdx) { /* leave a surface gap above this segment */ }
        if (k !== 0 && acc - v > 0) { h -= gap; }
        if (h <= 0.4) return;
        const fill = o.series[k].color;
        if (k === lastIdx) g.push(`<path d="${topRoundedRect(x, yTop, bw, h, 4)}" style="fill:${fill}"></path>`);
        else g.push(`<rect x="${x}" y="${yTop}" width="${bw}" height="${h}" style="fill:${fill}"></rect>`);
      });
      parts.push(`<g class="col${ytd ? ' ytd' : ''}"${anim ? ` style="transform-origin:${cx}px ${mt + ph}px;transform:scaleY(0);transition:transform .7s cubic-bezier(.2,.7,.2,1) ${i * 40}ms"` : ''}>${g.join('')}</g>`);
    });
    // x labels
    const { labels, every } = xLabels(o.cats, o.catLabel || ((c) => String(c)), band);
    o.cats.forEach((c, i) => {
      if (i % every !== 0 && i !== n - 1) return;
      const cx = ml + band * i + band / 2;
      parts.push(`<text class="xl" x="${cx}" y="${height - 8}" text-anchor="middle">${esc(labels[i])}</text>`);
    });
    // selective total labels: max and last
    if (o.labelTotals && !o.percent) {
      const maxI = totals.indexOf(Math.max(...totals));
      const set = new Set([maxI, n - 1]);
      for (const i of set) {
        const cx = ml + band * i + band / 2;
        parts.push(`<text class="lbl-strong" x="${cx}" y="${y(totals[i]) - 6}" text-anchor="middle">${esc((o.totalFmt || compact)(totals[i]))}</text>`);
      }
    }
    plot.innerHTML = `<svg viewBox="0 0 ${W} ${height}" width="${W}" height="${height}" xmlns="${NS}" aria-hidden="true">${parts.join('')}</svg>`;
    const svg = plot.querySelector('svg');
    if (anim) requestAnimationFrame(() => requestAnimationFrame(() => svg.querySelectorAll('g.col').forEach((g) => { g.style.transform = 'scaleY(1)'; })));
    o.animate = false;
    bindBands(plot, svg, n, (i) => [ml + band * i, band], (i, cx, cy) => {
      const t = o.tooltip ? o.tooltip(i) : { title: String(o.cats[i]), rows: o.series.map((s) => ({ label: s.label, color: s.color, value: compact(s.values[i]) })) };
      showTip(tipHTML(t.title, t.rows), cx, cy);
    });
  });
}

/* ------------------------------------------------------------------ lines */
export function lines(plot, o) {
  markLast(plot, o.x, o.ytd);
  const height = o.height || 240;
  const n = o.x.length;
  mount(plot, (W) => {
    const all = o.series.flatMap((s) => s.values.filter((v) => v != null));
    const max = o.yMax ?? Math.max(...all, 0);
    const ticks = o.ticks || niceTicks(max, o.tickCount || 4);
    const top = ticks[ticks.length - 1] || 1;
    const fmtY = o.yTick || ((v) => compact(v));
    const fmtV = o.valueFmt || fmtY;
    const ml = Math.max(...ticks.map((t) => textWidth(fmtY(t)))) + 10;
    const endLabels = o.endLabels !== false && o.series.length <= 4;
    const labelTexts = o.series.map((s) => `${fmtV(lastVal(s.values))}${o.series.length > 1 && s.short ? ` ${s.short}` : ''}`);
    const mr = endLabels ? Math.min(W * 0.32, Math.max(...labelTexts.map((t) => textWidth(t))) + 16) : 10;
    const mt = 12;
    const mb = 26;
    const pw = W - ml - mr;
    const ph = height - mt - mb;
    const step = n > 1 ? pw / (n - 1) : pw;
    const xp = (i) => ml + (n > 1 ? step * i : pw / 2);
    const y = (v) => mt + ph - (v / top) * ph;
    const parts = [];
    for (const t of ticks) {
      const yy = Math.round(y(t)) + 0.5;
      parts.push(`<line class="${t === 0 ? 'base' : 'grid'}" x1="${ml}" x2="${ml + pw}" y1="${yy}" y2="${yy}"></line>`);
      parts.push(`<text x="${ml - 8}" y="${yy + 4}" text-anchor="end">${esc(fmtY(t))}</text>`);
    }
    parts.push(`<line class="cross" x1="0" x2="0" y1="${mt}" y2="${mt + ph}"></line>`);
    o.series.forEach((s) => {
      if (s.area) {
        let d = '';
        let open = false;
        let firstX = 0;
        let lastX = 0;
        s.values.forEach((v, i) => {
          if (v == null) return;
          if (!open) { d += `M${xp(i)},${y(0)}L${xp(i)},${y(v)}`; open = true; firstX = xp(i); } else d += `L${xp(i)},${y(v)}`;
          lastX = xp(i);
        });
        if (open) parts.push(`<path d="${d}L${lastX},${y(0)}L${firstX},${y(0)}Z" style="fill:${s.color};opacity:.1"></path>`);
      }
      let d = '';
      let pen = false;
      s.values.forEach((v, i) => {
        if (v == null) { pen = false; return; }
        d += `${pen ? 'L' : 'M'}${xp(i).toFixed(1)},${y(v).toFixed(1)}`;
        pen = true;
      });
      parts.push(`<path d="${d}" fill="none" style="stroke:${s.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"></path>`);
      const li = lastIndex(s.values);
      if (li >= 0) {
        const ytd = o.ytd && o.ytd(o.x[li], li);
        parts.push(`<circle cx="${xp(li)}" cy="${y(s.values[li])}" r="4" style="fill:${ytd ? 'var(--paper)' : s.color};stroke:${ytd ? s.color : 'var(--paper)'}" stroke-width="2"></circle>`);
      }
    });
    // end labels with simple collision handling
    if (endLabels) {
      const items = o.series.map((s, k) => ({ k, li: lastIndex(s.values), v: lastVal(s.values) })).filter((it) => it.li >= 0)
        .map((it) => ({ ...it, y0: y(it.v), y: y(it.v) })).sort((a, b) => a.y - b.y);
      for (let i = 1; i < items.length; i++) if (items[i].y - items[i - 1].y < 14) items[i].y = items[i - 1].y + 14;
      const overflow = items.length ? items[items.length - 1].y - (mt + ph) : 0;
      if (overflow > 0) items.forEach((it) => { it.y -= overflow; });
      for (const it of items) {
        const lx = xp(it.li) + 9;
        if (Math.abs(it.y - it.y0) > 2) parts.push(`<line x1="${xp(it.li) + 5}" y1="${it.y0}" x2="${lx - 2}" y2="${it.y}" style="stroke:var(--axis)" stroke-width="1"></line>`);
        parts.push(`<text class="lbl-strong" x="${lx}" y="${it.y + 4}">${esc(labelTexts[it.k])}</text>`);
      }
    }
    const { labels, every } = xLabels(o.x, o.xLabel || ((c) => String(c)), step || pw);
    o.x.forEach((c, i) => {
      if (i % every !== 0 && i !== n - 1) return;
      if (i !== n - 1 && n - 1 - i < every) return;
      parts.push(`<text class="xl" x="${xp(i)}" y="${height - 8}" text-anchor="middle">${esc(labels[i])}</text>`);
    });
    parts.push(`<g class="hover-dots"></g>`);
    plot.innerHTML = `<svg viewBox="0 0 ${W} ${height}" width="${W}" height="${height}" xmlns="${NS}" aria-hidden="true">${parts.join('')}</svg>`;
    const svg = plot.querySelector('svg');
    const cross = svg.querySelector('.cross');
    const dots = svg.querySelector('.hover-dots');
    bindBands(plot, svg, n, (i) => [xp(i) - (step || pw) / 2, step || pw], (i, cx, cy) => {
      cross.setAttribute('x1', xp(i)); cross.setAttribute('x2', xp(i)); cross.style.opacity = '.45';
      dots.innerHTML = o.series.map((s) => (s.values[i] == null ? '' : `<circle cx="${xp(i)}" cy="${y(s.values[i])}" r="4" style="fill:${s.color};stroke:var(--paper)" stroke-width="2"></circle>`)).join('');
      const t = o.tooltip ? o.tooltip(i) : { title: String(o.x[i]), rows: o.series.map((s) => ({ label: s.label, color: s.color, value: s.values[i] == null ? 'n/a' : fmtV(s.values[i]) })) };
      showTip(tipHTML(t.title, t.rows), cx, cy);
    }, () => { cross.style.opacity = '0'; dots.innerHTML = ''; });
  });
}
function lastIndex(vals) { for (let i = vals.length - 1; i >= 0; i--) if (vals[i] != null) return i; return -1; }
function lastVal(vals) { const i = lastIndex(vals); return i >= 0 ? vals[i] : null; }

/* ------------------------------------------------------------------ horizontal bars (HTML) */
export function hbars(el, { rows, format = compact, color = 'var(--c1)', max }) {
  const m = max || Math.max(...rows.map((r) => r.value)) || 1;
  el.innerHTML = `<ol class="hbars">${rows.map((r) => `
    <li><span class="hb-l">${r.href ? `<a href="${esc(r.href)}">${esc(r.label)}</a>` : esc(r.label)}${r.sub ? ` <span class="hb-sub">${esc(r.sub)}</span>` : ''}</span>
    <span class="hb-t"><i style="width:${(100 * r.value) / m}%;background:${r.color || color}"></i></span>
    <span class="hb-v">${esc(format(r.value))}</span></li>`).join('')}</ol>`;
}

/* ------------------------------------------------------------------ small multiples */
export function multiples(el, { x, panels, yMax, yTick, valueFmt, ytd, color = 'var(--c1)', xLabel }) {
  el.classList.add('multiples');
  el.innerHTML = panels.map((p, k) => `<div class="mp"><div class="mp-h"><span class="mp-t">${esc(p.title)}</span><span class="mp-v">${esc(valueFmt(lastVal(p.values)))}</span></div><div class="plot mp-plot" tabindex="0" role="img" aria-label="${esc(p.title)}: ${esc(p.aria || '')}" data-k="${k}"></div></div>`).join('');
  el.querySelectorAll('.mp-plot').forEach((plot) => {
    const p = panels[Number(plot.dataset.k)];
    lines(plot, {
      x, xLabel: xLabel || ((c, i, short) => (i === 0 || i === x.length - 1 ? (short ? shortYear(c) : String(c)) : '')),
      series: [{ label: p.title, color: p.color || color, values: p.values, area: true }],
      yMax, ticks: niceTicks(yMax, 2), yTick, valueFmt, height: 120, endLabels: false, ytd,
      tooltip: (i) => ({ title: `${p.title}, ${x[i]}${ytd && ytd(x[i]) ? ' YTD' : ''}`, rows: [{ label: 'Share', value: p.values[i] == null ? 'n/a' : valueFmt(p.values[i]) }, ...(p.counts ? [{ label: 'Findings', value: compact(p.counts[i]) }] : [])] }),
    });
  });
}
