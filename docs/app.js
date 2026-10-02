(() => {
  const $ = (s) => document.querySelector(s);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const today = new Date().toISOString().slice(0, 10);
  const cmp = (a, b) => {
    const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pa[i] || 0) - (pb[i] || 0);
      if (d) return d;
    }
    return 0;
  };
  const LABEL = { eol: 'End of life', security: 'Security fixes only', active: 'Active support', unknown: 'Unknown' };

  let DATA = null;

  function statusOf(b) {
    if (!b.securityUntil) return 'unknown';
    if (b.securityUntil < today) return 'eol';
    if (b.activeUntil && b.activeUntil < today) return 'security';
    return 'active';
  }

  function exposedRange(b) {
    if (statusOf(b) === 'eol') return `All ${b.branch}.x`;
    const patch = Number(b.latest.split('.')[2]);
    return patch === 0 ? 'None' : `${b.branch}.0 – ${b.branch}.${patch - 1}`;
  }

  function newestSupported() {
    return DATA.branches.filter((b) => ['active', 'security'].includes(statusOf(b)));
  }

  // ---------- version table ----------
  let filterText = '', filterStatus = 'all';
  function renderTable() {
    const rows = DATA.branches.filter((b) => {
      const s = statusOf(b);
      return (filterStatus === 'all' || s === filterStatus) && (!filterText || b.branch.startsWith(filterText) || b.latest.startsWith(filterText));
    });
    $('#version-rows').innerHTML = rows.map((b) => {
      const s = statusOf(b);
      const safe = s === 'eol' ? '<span class="muted">none — upgrade branch</span>' : esc(b.latest);
      return `<tr>
        <td class="mono"><strong>${esc(b.branch)}</strong></td>
        <td><span class="pill ${s}">${LABEL[s]}</span></td>
        <td class="mono">${esc(exposedRange(b))}</td>
        <td class="mono">${safe}</td>
        <td class="mono">${esc(b.securityUntil || '?')}</td>
      </tr>`;
    }).join('') || '<tr><td colspan="5" class="muted">No branches match.</td></tr>';
  }

  function renderSummary() {
    const eol = DATA.branches.filter((b) => statusOf(b) === 'eol').map((b) => b.branch);
    const sup = newestSupported().map((b) => `${b.branch} (≥ ${b.latest})`);
    $('#summary').innerHTML = `<strong>${eol.length} branches are end-of-life</strong> (PHP ${esc(eol[eol.length - 1])} through ${esc(eol[0])}) and every release in them is exposed. ` +
      `Only these are safe today: <strong>${esc(sup.join(', '))}</strong>.`;
    const d = DATA.generatedAt ? new Date(DATA.generatedAt) : null;
    $('#data-date').textContent = d ? `Data checked ${d.toISOString().slice(0, 10)}` : '';
  }

  function renderCves() {
    $('#cve-rows').innerHTML = DATA.cves.map((c) => `<tr>
      <td class="mono"><a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener">${esc(c.id)}</a></td>
      <td><span class="pill ${esc(c.severity)}">${esc(c.severity)}</span></td>
      <td>${esc(c.title)}</td>
      <td class="mono">${Object.values(c.fixed).map(esc).join(', ')}</td>
    </tr>`).join('');
  }

  // ---------- exposure check ----------
  function evaluate(version, { fromHeader = false } = {}) {
    const parts = version.split('.');
    const branchId = parts.slice(0, 2).join('.');
    const full = parts.length >= 3;
    const b = DATA.branches.find((x) => x.branch === branchId);
    const upgradeTo = newestSupported()[0];
    const items = [];
    let level, title;

    if (!b) {
      level = 'warn';
      title = `PHP ${version}: unknown branch`;
      items.push('This version is not in the list. It may be a pre-release, a typo, or older than PHP 4.4 (in which case it is badly exposed).');
    } else {
      const s = statusOf(b);
      if (s === 'eol') {
        level = 'bad';
        title = `Exposed — PHP ${b.branch} is end-of-life`;
        items.push(`PHP ${esc(b.branch)} stopped receiving security fixes on ${esc(b.securityUntil)}.`);
        items.push(`Upgrade to PHP ${esc(upgradeTo.branch)} (currently ${esc(upgradeTo.latest)}).`);
      } else if (full && cmp(version, b.latest) < 0) {
        level = 'bad';
        title = `Exposed — PHP ${version} is missing security patches`;
        items.push(`The latest ${esc(b.branch)} release is <strong>${esc(b.latest)}</strong>. Run the auto-updater below or update via your package manager.`);
      } else if (!full) {
        level = 'warn';
        title = `PHP ${b.branch}: ${LABEL[s].toLowerCase()}`;
        items.push(`Only releases older than ${esc(b.latest)} are exposed. Enter the full version (e.g. ${esc(b.latest)}) for an exact answer.`);
      } else {
        level = 'good';
        title = `PHP ${version} is up to date`;
        items.push(`Security support for ${esc(b.branch)} continues until ${esc(b.securityUntil)}.`);
      }

      const cves = DATA.cves.filter((c) => {
        const fixed = c.fixed[b.branch];
        if (fixed) return full && cmp(version, fixed) < 0;
        return s === 'eol' && b.securityUntil < c.date;
      });
      if (cves.length) {
        items.push(`Known vulnerabilities that may apply: ${cves.map((c) => `<a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener">${esc(c.id)}</a> (${esc(c.severity)})`).join(', ')}.`);
      }
    }
    if (fromHeader) {
      items.push('Your server advertises its PHP version in <code>X-Powered-By</code>, which helps attackers pick exploits. Set <code>expose_php = Off</code> in php.ini (PHP Guard also removes it).');
    }
    return `<h3>${esc(title)}</h3><ul>${items.map((i) => `<li>${i}</li>`).join('')}</ul>`;
  }

  function showResult(html, level) {
    const box = $('#check-result');
    box.className = `result ${level || ''}`;
    box.innerHTML = html;
    box.hidden = false;
  }

  function levelOf(html) {
    return /<h3>Exposed/.test(html) ? 'bad' : /up to date/.test(html) ? 'good' : 'warn';
  }

  function findVersion(text) {
    const header = text.match(/PHP\/(\d+\.\d+(?:\.\d+)?)/i);
    if (header) return { version: header[1], fromHeader: true };
    const bare = text.trim().match(/^(?:php\s*)?v?(\d+\.\d+(?:\.\d+)?)\b/i);
    if (bare) return { version: bare[1], fromHeader: false };
    return null;
  }

  function toUrl(text) {
    const t = text.trim();
    if (!/^(https?:\/\/)?[a-z0-9.-]+\.[a-z]{2,}(:\d+)?(\/\S*)?$/i.test(t)) return null;
    try { return new URL(/^https?:\/\//i.test(t) ? t : `https://${t}`); } catch { return null; }
  }

  async function checkUrl(url) {
    showResult(`<h3>Checking ${esc(url.host)}…</h3>`, 'warn');
    let headerVersion = null;
    try {
      const res = await fetch(url.href, { method: 'HEAD', mode: 'cors', cache: 'no-store' });
      const h = res.headers.get('x-powered-by') || '';
      const m = h.match(/PHP\/(\d+\.\d+(?:\.\d+)?)/i);
      if (m) headerVersion = m[1];
    } catch { /* blocked by CORS, as most sites are */ }

    if (headerVersion) {
      const html = evaluate(headerVersion, { fromHeader: true });
      return showResult(html, levelOf(html));
    }

    const cmd = `curl -sI ${url.origin}/ | grep -iE "x-powered-by|^server"`;
    showResult(`
      <h3>Look up ${esc(url.host)}'s PHP version</h3>
      <p>Browsers aren't allowed to read another website's headers, so grab them yourself and paste them here — it takes a few seconds:</p>
      <pre id="cmd">${esc(cmd)}</pre>
      <div class="row-actions">
        <button type="button" id="copy-cmd">Copy command</button>
        <a class="btn" href="https://securityheaders.com/?q=${encodeURIComponent(url.origin)}&followRedirects=on" target="_blank" rel="noopener">View headers online</a>
      </div>
      <textarea id="paste" placeholder="Paste the output here, e.g.  X-Powered-By: PHP/8.1.2"></textarea>
      <p class="muted">No <code>X-Powered-By: PHP/…</code> line? Good — your site doesn't advertise its version. Run the self-check script below on the server to get the exact answer.</p>`, 'warn');
    $('#copy-cmd').onclick = (e) => navigator.clipboard?.writeText(cmd).then(() => { e.target.textContent = 'Copied'; });
    $('#paste').oninput = (e) => {
      const found = findVersion(e.target.value);
      if (found) {
        const html = evaluate(found.version, found);
        showResult(html, levelOf(html));
      }
    };
  }

  function onCheck(e) {
    e.preventDefault();
    const text = $('#check-input').value;
    const found = findVersion(text);
    if (found) {
      const html = evaluate(found.version, found);
      return showResult(html, levelOf(html));
    }
    const url = toUrl(text);
    if (url) return checkUrl(url);
    showResult('<h3>Not recognised</h3><p>Enter a website (example.com), a PHP version (8.2.15) or paste a header line (X-Powered-By: PHP/7.4.3).</p>', 'warn');
  }

  // ---------- boot ----------
  fetch('data/versions.json', { cache: 'no-cache' })
    .then((r) => r.json())
    .then((d) => {
      DATA = d;
      renderSummary();
      renderTable();
      renderCves();
      $('#check-form').addEventListener('submit', onCheck);
      $('#filter').addEventListener('input', (e) => { filterText = e.target.value.trim().replace(/^php\s*/i, ''); renderTable(); });
      document.querySelectorAll('.chip').forEach((c) => c.addEventListener('click', () => {
        document.querySelectorAll('.chip').forEach((x) => x.classList.remove('active'));
        c.classList.add('active');
        filterStatus = c.dataset.status;
        renderTable();
      }));
      const q = new URLSearchParams(location.search).get('q');
      if (q) { $('#check-input').value = q; onCheck(new Event('submit')); }
    })
    .catch(() => { $('#summary').textContent = 'Could not load version data.'; });
})();
