// Copy-to-clipboard for code blocks and share links. The async clipboard can stall or be refused,
// so a selection-based copy is the fallback.
function selectText(el) {
  const range = document.createRange();
  range.selectNodeContents(el);
  const sel = window.getSelection();
  sel.removeAllRanges();
  sel.addRange(range);
}

export async function copyText(text, fallbackEl = null) {
  try {
    if (navigator.clipboard?.writeText) {
      await Promise.race([navigator.clipboard.writeText(text), new Promise((_, no) => setTimeout(() => no(new Error('timeout')), 800))]);
      return true;
    }
  } catch (e) { /* fall through to the selection copy */ }
  let el = fallbackEl;
  let temp = null;
  if (!el) {
    temp = document.createElement('textarea');
    temp.value = text;
    temp.setAttribute('readonly', '');
    temp.style.cssText = 'position:fixed;left:-9999px;top:0';
    document.body.appendChild(temp);
    temp.select();
  } else selectText(el);
  try { return document.execCommand('copy'); } catch (e) { return false; } finally { temp?.remove(); }
}

export function flash(btn, ok, idle) {
  btn.textContent = ok ? 'Copied' : 'Press Ctrl+C';
  clearTimeout(btn._t);
  btn._t = setTimeout(() => { btn.textContent = idle; }, 1800);
}

// Every `.code` block with a `.copy` button inside `root`.
export function bindCodeCopy(root = document) {
  root.querySelectorAll('.code .copy').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const code = btn.parentElement.querySelector('code');
      if (code) flash(btn, await copyText(code.textContent || '', code), 'Copy');
    });
  });
}
