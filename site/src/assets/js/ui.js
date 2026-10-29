import { esc } from './fmt.js';

export function fail(container, err) {
  console.error(err);
  container.innerHTML = `<div class="error-box"><p><strong>This section could not load its data.</strong> ${esc(err.message || err)}. Reload the page to try again; if it keeps failing, the data files may be missing from this build.</p></div>`;
}
