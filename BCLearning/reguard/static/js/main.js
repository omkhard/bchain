/* ============================================================
   static/js/main.js
   =================
   Handles all browser-side logic:
     - Fetching compiler status on load
     - Sending scan requests to Flask
     - Rendering findings with AST vs regex source badges
     - Rendering the new Compiler tab output
   ============================================================ */

let _cachedPatterns = [];
let _compilerInfo = null;

// ── On page load ─────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  loadPatternList();
  updateLineNumbers();
  checkCompilerStatus();
});

document.getElementById('codeInput').addEventListener('input', updateLineNumbers);


// ── Compiler Status ──────────────────────────────────────────
async function checkCompilerStatus() {
  try {
    const res = await fetch('/compiler-status');
    const data = await res.json();
    _compilerInfo = data;

    const badge = document.getElementById('compilerBadge');
    const badgeText = document.getElementById('compilerBadgeText');
    const bar = document.getElementById('compilerBar');
    const barText = document.getElementById('compilerBarText');
    const barIcon = document.getElementById('compilerBarIcon');
    const modeAst = document.getElementById('modeAst');
    const modeRegex = document.getElementById('modeRegex');
    const modeFooter = document.getElementById('modeFooter');

    if (data.available) {
      // solc found — AST mode active
      badge.className = 'compiler-badge ast-active';
      badgeText.textContent = `solc ${data.version} · AST ACTIVE`;

      bar.style.display = 'flex';
      bar.className = 'compiler-bar ast';
      barIcon.textContent = '🔬';
      barText.textContent = `Solidity compiler ${data.version} detected — AST analysis active`;

      modeAst.classList.add('active');
      modeFooter.textContent = `✓ solc ${data.version} loaded — both AST and Regex analysis will run`;
      modeFooter.style.color = 'var(--green)';
    } else {
      // No solc — regex fallback
      badge.className = 'compiler-badge regex-only';
      badgeText.textContent = 'REGEX MODE · NO solc';

      bar.style.display = 'flex';
      bar.className = 'compiler-bar regex';
      barIcon.textContent = '🔍';
      barText.textContent = 'solc not found — running in builtin regex parser mode';
    }
  } catch (err) {
    console.warn('Could not check compiler status:', err);
  }
}


// ── Line numbers ─────────────────────────────────────────────
function updateLineNumbers() {
  const ta = document.getElementById('codeInput');
  const ln = document.getElementById('lineNums');
  const lc = document.getElementById('lineCount');
  const lines = ta.value.split('\n');
  lc.textContent = lines.length + ' LINES';
  ln.innerHTML = lines.map((_, i) => `<span>${i + 1}</span>`).join('');
}


// ── Load pattern checklist ───────────────────────────────────
async function loadPatternList() {
  try {
    const res = await fetch('/patterns');
    const data = await res.json();
    renderPatternList(data.patterns, []);
  } catch (e) { console.error(e); }
}


// ── Load demo ────────────────────────────────────────────────
async function loadDemo(type) {
  try {
    const res = await fetch(`/demo/${type}`);
    const data = await res.json();
    document.getElementById('codeInput').value = data.code;
    updateLineNumbers();
  } catch (e) { console.error(e); }
}


// ── Clear ─────────────────────────────────────────────────────
function clearAll() {
  document.getElementById('codeInput').value = '';
  updateLineNumbers();
  document.getElementById('resultList').innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">⬡</div>
      <div class="empty-text">AWAITING SCAN</div>
      <div class="empty-sub">Paste a contract and click SCAN CONTRACT</div>
    </div>`;
  document.getElementById('compilerOutput').innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">⚙</div>
      <div class="empty-text">NO COMPILATION YET</div>
    </div>`;
  resetScore();
  loadPatternList();
}


// ── Main scan ─────────────────────────────────────────────────
async function scanContract() {
  const code = document.getElementById('codeInput').value.trim();
  if (!code) {
    alert('Please paste a Solidity contract first.');
    return;
  }

  const btn = document.querySelector('.btn-primary');
  const panel = document.getElementById('editorPanel');
  const scanBar = document.createElement('div');
  scanBar.className = 'scan-bar';
  panel.appendChild(scanBar);
  panel.classList.add('scanning');
  btn.textContent = '⬡ SCANNING...';
  btn.disabled = true;

  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code })
    });
    const result = await res.json();

    if (!res.ok) { alert('Error: ' + (result.error || 'Unknown')); return; }

    renderResults(result.findings);
    updateScore(result.score, result.summary);
    renderPatternList(null, result.findings);
    renderCompilerOutput(result.compiler, result.findings);

    // Switch to findings tab
    document.querySelectorAll('.tab')[0].click();

  } catch (err) {
    alert('Could not reach server. Is Flask running?\n' + err.message);
  } finally {
    btn.textContent = '⬡ SCAN CONTRACT';
    btn.disabled = false;
    panel.classList.remove('scanning');
    scanBar.remove();
  }
}


// ── Render findings ───────────────────────────────────────────
function renderResults(findings) {
  const el = document.getElementById('resultList');
  if (!findings || findings.length === 0) {
    el.innerHTML = `<div class="empty-state">
      <div class="empty-icon" style="opacity:0.9">✓</div>
      <div class="empty-text" style="color:var(--green)">NO VULNERABILITIES DETECTED</div>
    </div>`;
    return;
  }

  const order = { critical:0, high:1, medium:2, low:3, error:0, warning:4, info:5 };
  const sorted = [...findings].sort((a,b) => (order[a.severity]||9) - (order[b.severity]||9));

  el.innerHTML = sorted.map((f, i) => buildCard(f, i)).join('');
}

function buildCard(f, index) {
  const sevClass = `sev-${f.severity}`;

  // Source badge: AST findings are more accurate — show which engine caught it
  const sourceBadge = f.source
    ? `<span class="source-badge source-${f.source}">${f.source === 'ast' ? '🔬 AST' : '🔍 REGEX'}</span>`
    : '';

  const snippet = f.snippet
    ? `<div class="finding-snippet">${esc(f.snippet)}</div>` : '';
  const fix = f.fix
    ? `<div class="finding-fix"><div class="fix-label">// RECOMMENDED FIX</div>${esc(f.fix)}</div>` : '';

  return `<div class="finding-card" style="animation-delay:${index*0.07}s">
    <div class="finding-header">
      <span class="sev-badge ${sevClass}">${f.severity.toUpperCase()}</span>
      ${sourceBadge}
      <span class="finding-line">LINE ${f.line}</span>
    </div>
    <div class="finding-title">${f.title}</div>
    <div class="finding-desc">${f.desc}</div>
    ${snippet}${fix}
  </div>`;
}


// ── Render Compiler tab ───────────────────────────────────────
function renderCompilerOutput(compiler, findings) {
  const el = document.getElementById('compilerOutput');
  if (!compiler) return;

  const errors   = findings.filter(f => f.pattern_id === 'syntax_error');
  const warnings = findings.filter(f => f.pattern_id === 'compiler_warning');
  const astFindings = findings.filter(f => f.source === 'ast');
  const regexFindings = findings.filter(f => f.source === 'regex');

  el.innerHTML = `
    <div class="compiler-section">
      <div class="compiler-section-title">// COMPILER INFO</div>
      <div class="compiler-kv">
        <div class="compiler-key">Engine</div>
        <div class="compiler-val ${compiler.source === 'solc' ? 'good' : 'warn'}">
          ${compiler.source === 'solc' ? '🔬 solc (AST mode)' : '🔍 Builtin parser (regex mode)'}
        </div>
      </div>
      <div class="compiler-kv">
        <div class="compiler-key">Version</div>
        <div class="compiler-val">${compiler.version}</div>
      </div>
      <div class="compiler-kv">
        <div class="compiler-key">AST Available</div>
        <div class="compiler-val ${compiler.ast_available ? 'good' : 'warn'}">
          ${compiler.ast_available ? '✓ Yes' : '✗ No'}
        </div>
      </div>
      <div class="compiler-kv">
        <div class="compiler-key">Contracts Parsed</div>
        <div class="compiler-val">${compiler.contract_count}</div>
      </div>
    </div>

    <div class="compiler-section">
      <div class="compiler-section-title">// ANALYSIS BREAKDOWN</div>
      <div class="compiler-kv">
        <div class="compiler-key">AST findings</div>
        <div class="compiler-val ${astFindings.length > 0 ? 'bad' : 'good'}">${astFindings.length} issues</div>
      </div>
      <div class="compiler-kv">
        <div class="compiler-key">Regex findings</div>
        <div class="compiler-val ${regexFindings.length > 0 ? 'warn' : 'good'}">${regexFindings.length} issues</div>
      </div>
      <div class="compiler-kv">
        <div class="compiler-key">Syntax errors</div>
        <div class="compiler-val ${errors.length > 0 ? 'bad' : 'good'}">${errors.length}</div>
      </div>
      <div class="compiler-kv">
        <div class="compiler-key">Warnings</div>
        <div class="compiler-val ${warnings.length > 0 ? 'warn' : 'good'}">${warnings.length}</div>
      </div>
    </div>

    ${errors.length > 0 ? `
    <div class="compiler-section">
      <div class="compiler-section-title" style="color:var(--red)">// SYNTAX ERRORS</div>
      ${errors.map(e => `
        <div class="compiler-kv">
          <div class="compiler-key">Line ${e.line}</div>
          <div class="compiler-val bad">${esc(e.desc)}</div>
        </div>`).join('')}
    </div>` : ''}

    ${warnings.length > 0 ? `
    <div class="compiler-section">
      <div class="compiler-section-title" style="color:var(--yellow)">// COMPILER WARNINGS</div>
      ${warnings.map(w => `
        <div class="compiler-kv">
          <div class="compiler-key">Line ${w.line}</div>
          <div class="compiler-val warn">${esc(w.desc)}</div>
        </div>`).join('')}
    </div>` : ''}

    <div class="compiler-section">
      <div class="compiler-section-title">// HOW TO ENABLE AST MODE</div>
      <div class="compiler-kv">
        <div class="compiler-key">Step 1</div>
        <div class="compiler-val" style="font-size:10px">pip install py-solc-x</div>
      </div>
      <div class="compiler-kv">
        <div class="compiler-key">Step 2</div>
        <div class="compiler-val" style="font-size:10px">python -c "from solcx import install_solc; install_solc('0.8.20')"</div>
      </div>
      <div class="compiler-kv">
        <div class="compiler-key">Step 3</div>
        <div class="compiler-val good">Restart Flask — AST mode activates automatically</div>
      </div>
    </div>
  `;
}


// ── Score ring ────────────────────────────────────────────────
function updateScore(score, summary) {
  const ring = document.getElementById('ringFill');
  const numEl = document.getElementById('scoreNum');
  const statusEl = document.getElementById('scoreStatus');
  const offset = 339 * (1 - score / 100);
  ring.style.strokeDashoffset = offset;
  numEl.textContent = score;

  if (score >= 80)      { ring.style.stroke = numEl.style.color = 'var(--green)';  statusEl.textContent = 'LOW RISK';      statusEl.style.color = 'var(--green)'; }
  else if (score >= 60) { ring.style.stroke = numEl.style.color = 'var(--yellow)'; statusEl.textContent = 'MODERATE RISK'; statusEl.style.color = 'var(--yellow)'; }
  else if (score >= 40) { ring.style.stroke = numEl.style.color = 'var(--orange)'; statusEl.textContent = 'HIGH RISK';     statusEl.style.color = 'var(--orange)'; }
  else                  { ring.style.stroke = numEl.style.color = 'var(--red)';    statusEl.textContent = 'CRITICAL RISK'; statusEl.style.color = 'var(--red)'; }

  document.getElementById('statCritical').textContent = summary.critical || 0;
  document.getElementById('statHigh').textContent     = summary.high     || 0;
  document.getElementById('statMedium').textContent   = summary.medium   || 0;
  document.getElementById('statLow').textContent      = summary.low      || 0;
}

function resetScore() {
  document.getElementById('ringFill').style.strokeDashoffset = 339;
  document.getElementById('ringFill').style.stroke = 'var(--muted)';
  document.getElementById('scoreNum').textContent = '--';
  document.getElementById('scoreNum').style.color = 'var(--text)';
  document.getElementById('scoreStatus').textContent = 'AWAITING SCAN';
  document.getElementById('scoreStatus').style.color = 'var(--muted)';
  ['statCritical','statHigh','statMedium','statLow'].forEach(id =>
    document.getElementById(id).textContent = '0');
}


// ── Pattern checklist ─────────────────────────────────────────
function renderPatternList(patterns, findings) {
  if (patterns) _cachedPatterns = patterns;
  const el = document.getElementById('patternList');
  const detectedIds = new Set(findings.map(f => f.pattern_id));
  const colors = { critical:'var(--red)', high:'var(--orange)', medium:'var(--yellow)', low:'var(--blue)', info:'var(--green)' };

  el.innerHTML = _cachedPatterns.map(p => {
    let cls, txt;
    if (!findings.length) { cls = 'status-pending'; txt = 'PENDING'; }
    else if (p.id === 'reentrancy_guard_present') {
      cls = detectedIds.has(p.id) ? 'status-ok' : 'status-warn';
      txt = detectedIds.has(p.id) ? 'FOUND' : 'ABSENT';
    } else {
      cls = detectedIds.has(p.id) ? 'status-fail' : 'status-ok';
      txt = detectedIds.has(p.id) ? 'DETECTED' : 'CLEAN';
    }
    return `<div class="pattern-item">
      <div class="pattern-dot" style="background:${colors[p.severity]||'var(--muted)'}"></div>
      <div class="pattern-name">${p.name}</div>
      <div class="status-badge ${cls}">${txt}</div>
    </div>`;
  }).join('');
}


// ── Tabs ──────────────────────────────────────────────────────
function switchTab(name, btn) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
}

function toggleLearn(el) {
  el.classList.toggle('open');
  el.nextElementSibling.classList.toggle('open');
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
