/* ============================================================
   static/js/main.js
   =================
   This file handles everything that happens IN THE BROWSER:
     • Reading user input from the textarea
     • Sending HTTP requests to Flask (the Python server)
     • Receiving the JSON response
     • Updating the page with the results

   Key concept — HOW THE BROWSER TALKS TO FLASK:
   ┌─────────────┐   POST /scan + {code: "..."}   ┌──────────────┐
   │   Browser   │ ──────────────────────────────► │  Flask/Python│
   │  (this JS)  │ ◄────────────────────────────── │  (app.py)    │
   └─────────────┘   JSON {findings: [...]}        └──────────────┘

   The browser NEVER runs Python. It asks the Python server
   to do the heavy work, then displays what comes back.
   ============================================================ */


// ── Step 1: When the page loads, fetch the pattern list ─────
//
// We call Flask's /patterns endpoint to get the list of all
// vulnerability patterns. This populates the sidebar checklist.
//
// document.addEventListener('DOMContentLoaded', fn) means:
//   "Wait until the HTML is fully loaded, THEN run fn"
//   This is important — if we ran it immediately, the HTML
//   elements might not exist yet.

document.addEventListener('DOMContentLoaded', () => {
  loadPatternList();
  updateLineNumbers();
});


// ── Line number sync ─────────────────────────────────────────
//
// When the user types, update the line numbers in the gutter.

document.getElementById('codeInput').addEventListener('input', updateLineNumbers);

function updateLineNumbers() {
  const textarea = document.getElementById('codeInput');
  const lineNums = document.getElementById('lineNums');
  const lineCount = document.getElementById('lineCount');

  // Split by newline to count lines
  const lines = textarea.value.split('\n');
  const count = lines.length;

  lineCount.textContent = count + ' LINES';

  // Build a <span> for each line number
  lineNums.innerHTML = lines
    .map((_, i) => `<span>${i + 1}</span>`)
    .join('');
}


// ── Load Pattern Checklist from Flask ───────────────────────
//
// fetch() is the browser's built-in HTTP client.
// It returns a Promise — an object that represents a value
// that will be available in the future (when the server responds).
//
// .then(response => response.json()) converts the response body
// from a JSON string into a real JavaScript object.

async function loadPatternList() {
  try {
    // GET http://localhost:5000/patterns
    const response = await fetch('/patterns');
    const data = await response.json();

    // Render the list with all statuses as "PENDING"
    renderPatternList(data.patterns, []);
  } catch (err) {
    console.error('Could not load patterns:', err);
  }
}


// ── Main Scan Function ───────────────────────────────────────
//
// Called when the user clicks "SCAN CONTRACT".
// This is the core flow:
//   1. Get code from textarea
//   2. Send POST request to Flask /scan
//   3. Receive JSON findings
//   4. Update the UI

async function scanContract() {
  const codeInput = document.getElementById('codeInput');
  const code = codeInput.value.trim();

  // Validate — don't send empty requests
  if (!code) {
    alert('Please paste a Solidity contract first, or click "LOAD VULNERABLE".');
    return;
  }

  // ── Show scanning animation ──────────────────────────────
  const btn = document.querySelector('.btn-primary');
  const panel = document.getElementById('editorPanel');

  btn.textContent = '⬡ SCANNING...';
  btn.disabled = true;

  // Add scan-bar element for the sweeping animation
  const scanBar = document.createElement('div');
  scanBar.className = 'scan-bar';
  panel.appendChild(scanBar);
  panel.classList.add('scanning');

  try {
    // ── Send POST request to Flask ─────────────────────────
    //
    // fetch('/scan', { method: 'POST', ... }) sends an HTTP POST.
    // We put the Solidity code in the request body as JSON.
    //
    // Headers tell the server: "my body is JSON"
    // JSON.stringify() converts the JS object → JSON string

    const response = await fetch('/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',  // Tell Flask it's JSON
      },
      body: JSON.stringify({ code: code }),  // The actual data
    });

    // ── Parse the JSON response ────────────────────────────
    //
    // Flask's jsonify() sends back something like:
    // {
    //   "findings": [ {...}, {...} ],
    //   "score": 45,
    //   "summary": { "critical": 2, "high": 1, ... },
    //   "line_count": 52
    // }

    const result = await response.json();

    if (!response.ok) {
      alert('Error: ' + (result.error || 'Unknown error'));
      return;
    }

    // ── Update the UI with results ─────────────────────────
    renderResults(result.findings);
    updateScore(result.score, result.summary);
    renderPatternList(null, result.findings);  // Update checklist

    // Switch to Findings tab
    document.querySelectorAll('.tab')[0].click();

  } catch (err) {
    // Network error — Flask server might not be running
    alert('Could not reach the server. Is Flask running?\n\n' + err.message);
    console.error(err);
  } finally {
    // Always clean up the animation, even if there was an error
    btn.textContent = '⬡ SCAN CONTRACT';
    btn.disabled = false;
    panel.classList.remove('scanning');
    scanBar.remove();
  }
}


// ── Load Demo Contract from Flask ────────────────────────────
//
// Called by the "LOAD VULNERABLE" / "LOAD SAFE" buttons.
// Fetches from Flask's /demo/<type> route.

async function loadDemo(type) {
  try {
    // GET /demo/vulnerable  or  GET /demo/safe
    const response = await fetch(`/demo/${type}`);
    const data = await response.json();

    // Put the demo code into the textarea
    document.getElementById('codeInput').value = data.code;
    updateLineNumbers();

  } catch (err) {
    console.error('Could not load demo:', err);
  }
}


// ── Clear Everything ─────────────────────────────────────────
function clearAll() {
  document.getElementById('codeInput').value = '';
  updateLineNumbers();

  document.getElementById('resultList').innerHTML = `
    <div class="empty-state">
      <div class="empty-icon">⬡</div>
      <div class="empty-text">AWAITING SCAN</div>
      <div class="empty-sub">Paste a contract and click SCAN CONTRACT</div>
    </div>`;

  resetScore();
  loadPatternList();  // Reset checklist to pending
}


// ── Render Findings ──────────────────────────────────────────
//
// Takes the findings array from Flask and builds HTML for each one.
// Then injects it into the #resultList div.

function renderResults(findings) {
  const container = document.getElementById('resultList');

  if (!findings || findings.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon" style="opacity:0.9">✓</div>
        <div class="empty-text" style="color:var(--green)">NO VULNERABILITIES DETECTED</div>
      </div>`;
    return;
  }

  // Sort by severity: critical first
  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort((a, b) => order[a.severity] - order[b.severity]);

  // Build HTML string for each finding
  const html = sorted.map((finding, index) => buildFindingCard(finding, index)).join('');
  container.innerHTML = html;
}


// ── Build a Single Finding Card ──────────────────────────────
//
// Takes one finding object (from Python) and returns an HTML string.

function buildFindingCard(finding, index) {
  // CSS class for the severity badge color
  const sevClass = `sev-${finding.severity}`;

  // Snippet block (the vulnerable code line)
  const snippetHtml = finding.snippet
    ? `<div class="finding-snippet">${escapeHtml(finding.snippet)}</div>`
    : '';

  // Fix block (recommended code)
  const fixHtml = finding.fix
    ? `<div class="finding-fix">
         <div class="fix-label">// RECOMMENDED FIX</div>${escapeHtml(finding.fix)}
       </div>`
    : '';

  // animation-delay staggers the card slide-in animations
  return `
    <div class="finding-card" style="animation-delay: ${index * 0.07}s">
      <div class="finding-header">
        <span class="sev-badge ${sevClass}">${finding.severity.toUpperCase()}</span>
        <span class="finding-line">LINE ${finding.line}</span>
      </div>
      <div class="finding-title">${finding.title}</div>
      <div class="finding-desc">${finding.desc}</div>
      ${snippetHtml}
      ${fixHtml}
    </div>`;
}


// ── Update Score Ring ────────────────────────────────────────
//
// Animates the SVG ring and updates the score number.
// The ring uses stroke-dashoffset to show a partial circle.

function updateScore(score, summary) {
  const ring = document.getElementById('ringFill');
  const numEl = document.getElementById('scoreNum');
  const statusEl = document.getElementById('scoreStatus');

  // Circumference of the circle (r=54): 2 * π * 54 ≈ 339
  const circumference = 339;
  const offset = circumference * (1 - score / 100);
  ring.style.strokeDashoffset = offset;

  numEl.textContent = score;

  // Color coding by score range
  if (score >= 80) {
    ring.style.stroke = 'var(--green)';
    numEl.style.color = 'var(--green)';
    statusEl.textContent = 'LOW RISK';
    statusEl.style.color = 'var(--green)';
  } else if (score >= 60) {
    ring.style.stroke = 'var(--yellow)';
    numEl.style.color = 'var(--yellow)';
    statusEl.textContent = 'MODERATE RISK';
    statusEl.style.color = 'var(--yellow)';
  } else if (score >= 40) {
    ring.style.stroke = 'var(--orange)';
    numEl.style.color = 'var(--orange)';
    statusEl.textContent = 'HIGH RISK';
    statusEl.style.color = 'var(--orange)';
  } else {
    ring.style.stroke = 'var(--red)';
    numEl.style.color = 'var(--red)';
    statusEl.textContent = 'CRITICAL RISK';
    statusEl.style.color = 'var(--red)';
  }

  // Update stat counters
  document.getElementById('statCritical').textContent = summary.critical || 0;
  document.getElementById('statHigh').textContent     = summary.high || 0;
  document.getElementById('statMedium').textContent   = summary.medium || 0;
  document.getElementById('statLow').textContent      = summary.low || 0;
}

function resetScore() {
  const ring = document.getElementById('ringFill');
  ring.style.strokeDashoffset = 339;
  ring.style.stroke = 'var(--muted)';
  document.getElementById('scoreNum').textContent = '--';
  document.getElementById('scoreNum').style.color = 'var(--text)';
  document.getElementById('scoreStatus').textContent = 'AWAITING SCAN';
  document.getElementById('scoreStatus').style.color = 'var(--muted)';
  document.getElementById('statCritical').textContent = '0';
  document.getElementById('statHigh').textContent = '0';
  document.getElementById('statMedium').textContent = '0';
  document.getElementById('statLow').textContent = '0';
}


// ── Render Pattern Checklist ─────────────────────────────────
//
// patterns: array of pattern definitions (from /patterns endpoint)
// findings: array of detected findings (from /scan endpoint)
//
// If patterns is null, we use the cached list from the first load.

let _cachedPatterns = [];

async function renderPatternList(patterns, findings) {
  if (patterns) {
    _cachedPatterns = patterns;
  }

  const container = document.getElementById('patternList');
  const detectedIds = new Set(findings.map(f => f.pattern_id));

  const severityColors = {
    critical: 'var(--red)',
    high:     'var(--orange)',
    medium:   'var(--yellow)',
    low:      'var(--blue)',
    info:     'var(--green)',
  };

  container.innerHTML = _cachedPatterns.map(pattern => {
    let statusClass, statusText;

    if (findings.length === 0) {
      // No scan run yet
      statusClass = 'status-pending';
      statusText  = 'PENDING';
    } else if (pattern.id === 'reentrancy_guard_present') {
      // This is a positive signal — detected = good
      statusClass = detectedIds.has(pattern.id) ? 'status-ok' : 'status-warn';
      statusText  = detectedIds.has(pattern.id) ? 'FOUND' : 'ABSENT';
    } else {
      // Regular vulnerability — detected = bad
      statusClass = detectedIds.has(pattern.id) ? 'status-fail' : 'status-ok';
      statusText  = detectedIds.has(pattern.id) ? 'DETECTED' : 'CLEAN';
    }

    const dotColor = severityColors[pattern.severity] || 'var(--muted)';

    return `
      <div class="pattern-item">
        <div class="pattern-dot" style="background:${dotColor}"></div>
        <div class="pattern-name">${pattern.name}</div>
        <div class="status-badge ${statusClass}">${statusText}</div>
      </div>`;
  }).join('');
}


// ── Tab Switching ────────────────────────────────────────────
function switchTab(name, btn) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-' + name).classList.add('active');
}


// ── Learn Accordion ──────────────────────────────────────────
function toggleLearn(titleEl) {
  titleEl.classList.toggle('open');
  titleEl.nextElementSibling.classList.toggle('open');
}


// ── Utility: Escape HTML ─────────────────────────────────────
//
// NEVER inject untrusted strings directly into innerHTML —
// it would allow XSS (Cross-Site Scripting) attacks.
// This function converts < > & into safe HTML entities.

function escapeHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
