// Shell: theme toggle, footer date, page dispatch.
import { summary, SEVERITIES } from './data.js';
import { esc } from './fmt.js';
import { fail } from './ui.js';

function currentTheme() {
  const t = document.documentElement.getAttribute('data-theme');
  if (t) return t;
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function initTheme() {
  const btn = document.querySelector('.theme-toggle');
  if (!btn) return;
  const sync = () => {
    const t = currentTheme();
    btn.setAttribute('aria-label', t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
    btn.title = btn.getAttribute('aria-label');
  };
  sync();
  btn.addEventListener('click', () => {
    const next = currentTheme() === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('theme', next); } catch (e) { /* storage unavailable */ }
    sync();
    document.dispatchEvent(new CustomEvent('themechange'));
  });
}

async function initFooter() {
  const el = document.querySelector('[data-asof]');
  if (!el) return;
  try {
    const s = await summary();
    if (s.as_of) el.innerHTML = `Data as of ${esc(s.as_of)}.`;
  } catch (e) { /* footer date is optional */ }
}

// The strip above the masthead is the corpus's own severity mix, one segment per normalised severity.
async function initStrip() {
  const strips = document.querySelectorAll('[data-sevstrip]');
  if (!strips.length) return;
  try {
    const sev = (await summary()).selected_severity || {};
    const parts = SEVERITIES.filter((k) => sev[k] > 0);
    if (!parts.length) return;
    const html = parts.map((k) => `<i class="sev-${k}" style="flex-grow:${Number(sev[k])}"></i>`).join('');
    strips.forEach((el) => { el.innerHTML = html; });
  } catch (e) { /* the strip is decoration and stays neutral without data */ }
}


initTheme();
initFooter();
initStrip();

const page = document.body.dataset.page;
const modules = { index: './landing.js', explorer: './explorer.js', firms: './firms.js', agents: './agents.js', analysis: './analysis.js', methodology: './methodology.js', finding: './finding.js' };
if (modules[page]) {
  import(modules[page]).then((m) => m.default && m.default()).catch((e) => {
    const main = document.getElementById('main');
    if (main) fail(main, e);
  });
}
