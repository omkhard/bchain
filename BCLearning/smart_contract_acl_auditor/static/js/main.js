/* ============================================================
   static/js/main.js — AC-GUARD Access Control Auditor
   ============================================================ */

   let _cachedPatterns = [];

   document.addEventListener('DOMContentLoaded', () => {
     loadPatterns();
     updateLineNumbers();
   });
   
   document.getElementById('codeInput').addEventListener('input', updateLineNumbers);
   
   function updateLineNumbers() {
     const ta = document.getElementById('codeInput');
     const ln = document.getElementById('lineNums');
     const lc = document.getElementById('lineCount');
     const lines = ta.value.split('\n');
     lc.textContent = lines.length + ' LINES';
     ln.innerHTML = lines.map((_, i) => `<span>${i + 1}</span>`).join('');
   }
   
   async function loadPatterns() {
     try {
       const res = await fetch('/patterns');
       const data = await res.json();
       _cachedPatterns = data.patterns;
       renderPatternList(_cachedPatterns, []);
     } catch (e) { console.error(e); }
   }
   
   async function loadDemo(name) {
     try {
       const res = await fetch(`/demo/${name}`);
       const data = await res.json();
       document.getElementById('codeInput').value = data.code;
       updateLineNumbers();
     } catch (e) { console.error(e); }
   }
   
   function clearAll() {
     document.getElementById('codeInput').value = '';
     updateLineNumbers();
     document.getElementById('resultList').innerHTML = emptyState('🔒', 'AWAITING AUDIT');
     document.getElementById('functionTable').innerHTML = emptyState('⬡', 'NO SCAN YET');
     document.getElementById('rolesPanel').innerHTML = emptyState('⬡', 'NO SCAN YET');
     resetScore();
     renderPatternList(_cachedPatterns, []);
   }
   
   async function auditContract() {
     const code = document.getElementById('codeInput').value.trim();
     if (!code) { alert('Please paste a Solidity contract first.'); return; }
   
     const btn = document.querySelector('.btn-primary');
     const panel = document.getElementById('editorPanel');
     const scanBar = document.createElement('div');
     scanBar.className = 'scan-bar';
     panel.appendChild(scanBar);
     panel.classList.add('scanning');
     btn.textContent = '🔒 AUDITING...';
     btn.disabled = true;
   
     try {
       const res = await fetch('/audit', {
         method: 'POST',
         headers: { 'Content-Type': 'application/json' },
         body: JSON.stringify({ code })
       });
       const result = await res.json();
       if (!res.ok) { alert('Error: ' + (result.error || 'Unknown')); return; }
   
       renderFindings(result.findings);
       renderFunctionTable(result.functions);
       renderRolesPanel(result.modifiers, result.roles);
       updateScore(result.score, result.summary, result.contract_name);
       renderPatternList(_cachedPatterns, result.findings);
   
       // Switch to findings tab
       document.querySelectorAll('.tab')[0].click();
   
     } catch (err) {
       alert('Could not reach server. Is Flask running?\n' + err.message);
     } finally {
       btn.textContent = '🔒 AUDIT CONTRACT';
       btn.disabled = false;
       panel.classList.remove('scanning');
       scanBar.remove();
     }
   }
   
   // ── Findings ─────────────────────────────────────────────────
   function renderFindings(findings) {
     const el = document.getElementById('resultList');
     if (!findings || findings.length === 0) {
       el.innerHTML = `<div class="empty-state">
         <div class="empty-icon" style="opacity:0.9">✓</div>
         <div class="empty-text" style="color:var(--green)">NO ISSUES DETECTED</div>
       </div>`;
       return;
     }
     const order = { critical:0, high:1, medium:2, low:3, info:4 };
     const sorted = [...findings].sort((a,b) => (order[a.severity]||9)-(order[b.severity]||9));
     el.innerHTML = sorted.map((f,i) => buildCard(f,i)).join('');
   }
   
   function buildCard(f, index) {
     const refBadge = f.ref ? `<span class="ref-badge">${f.ref}</span>` : '';
     const snippet = f.snippet ? `<div class="finding-snippet">${esc(f.snippet)}</div>` : '';
     const fix = f.fix ? `<div class="finding-fix"><div class="fix-label">// RECOMMENDED FIX</div>${esc(f.fix)}</div>` : '';
     return `<div class="finding-card" style="animation-delay:${index*0.07}s">
       <div class="finding-header">
         <span class="sev-badge sev-${f.severity}">${f.severity.toUpperCase()}</span>
         ${refBadge}
         <span class="finding-line">LINE ${f.line}</span>
       </div>
       <div class="finding-title">${f.title}</div>
       <div class="finding-desc">${f.desc}</div>
       ${snippet}${fix}
     </div>`;
   }
   
   // ── Function Table ────────────────────────────────────────────
   function renderFunctionTable(functions) {
     const el = document.getElementById('functionTable');
     if (!functions || functions.length === 0) {
       el.innerHTML = emptyState('⬡', 'NO FUNCTIONS FOUND'); return;
     }
   
     const rows = functions.map(f => {
       const visClass = `vis-${f.visibility}`;
       const mods = f.modifiers.length
         ? f.modifiers.map(m => `<span style="color:var(--accent)">${m}</span>`).join(' ')
         : '<span style="color:var(--red)">none</span>';
       const flags = [
         f.is_sensitive       ? `<span class="flag flag-sensitive">SENSITIVE</span>` : '',
         f.is_payable         ? `<span class="flag flag-payable">PAYABLE</span>` : '',
         f.has_state_write    ? `<span class="flag flag-write">WRITES</span>` : '',
         f.calls_selfdestruct ? `<span class="flag flag-destruct">SELFDESTRUCT</span>` : '',
       ].filter(Boolean).join('');
   
       return `<tr>
         <td class="func-name-cell">${f.name}()</td>
         <td><span class="func-vis ${visClass}">${f.visibility}</span></td>
         <td class="mods-cell">${mods}</td>
         <td>${flags || '—'}</td>
         <td style="font-family:var(--font-mono);font-size:10px;color:var(--muted)">${f.line}</td>
       </tr>`;
     }).join('');
   
     el.innerHTML = `<div style="overflow-x:auto">
       <table class="func-table">
         <thead><tr>
           <th>FUNCTION</th><th>VISIBILITY</th><th>MODIFIERS</th><th>FLAGS</th><th>LINE</th>
         </tr></thead>
         <tbody>${rows}</tbody>
       </table>
     </div>`;
   }
   
   // ── Roles & Modifiers Panel ───────────────────────────────────
   function renderRolesPanel(modifiers, roles) {
     const el = document.getElementById('rolesPanel');
     let html = '';
   
     if (modifiers && modifiers.length > 0) {
       html += `<div class="roles-section">
         <div class="roles-section-title">// MODIFIERS DEFINED</div>
         ${modifiers.map(m => `
           <div class="role-item">
             <span class="role-kind">${m.has_require ? '✓ VALID' : '⚠ WEAK'}</span>
             <span class="role-name">${m.name}()</span>
             <span class="role-line">line ${m.line}</span>
           </div>`).join('')}
       </div>`;
     }
   
     if (roles && roles.length > 0) {
       html += `<div class="roles-section">
         <div class="roles-section-title">// ACCESS CONTROL VARIABLES</div>
         ${roles.map(r => `
           <div class="role-item">
             <span class="role-kind">${r.kind.toUpperCase()}</span>
             <span class="role-name">${r.name}</span>
             <span class="role-line">line ${r.line}</span>
           </div>`).join('')}
       </div>`;
     }
   
     if (!html) {
       html = emptyState('⬡', 'NO ROLES OR MODIFIERS FOUND',
         'No access control variables or modifier definitions detected');
     }
   
     el.innerHTML = html;
   }
   
   // ── Score ─────────────────────────────────────────────────────
   function updateScore(score, summary, contractName) {
     const ring = document.getElementById('ringFill');
     const numEl = document.getElementById('scoreNum');
     const statusEl = document.getElementById('scoreStatus');
     const nameEl = document.getElementById('contractName');
   
     ring.style.strokeDashoffset = 339 * (1 - score / 100);
     numEl.textContent = score;
     nameEl.textContent = contractName ? `contract ${contractName}` : '';
   
     if (score >= 80)      { ring.style.stroke = numEl.style.color = 'var(--green)';  statusEl.textContent = 'WELL PROTECTED'; }
     else if (score >= 60) { ring.style.stroke = numEl.style.color = 'var(--yellow)'; statusEl.textContent = 'PARTIALLY PROTECTED'; }
     else if (score >= 40) { ring.style.stroke = numEl.style.color = 'var(--orange)'; statusEl.textContent = 'POORLY PROTECTED'; }
     else                  { ring.style.stroke = numEl.style.color = 'var(--red)';    statusEl.textContent = 'UNPROTECTED'; }
   
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
     document.getElementById('scoreStatus').textContent = 'AWAITING AUDIT';
     document.getElementById('contractName').textContent = '';
     ['statCritical','statHigh','statMedium','statLow'].forEach(id =>
       document.getElementById(id).textContent = '0');
   }
   
   // ── Pattern Checklist ─────────────────────────────────────────
   function renderPatternList(patterns, findings) {
     const el = document.getElementById('patternList');
     const detectedIds = new Set(findings.map(f => f.pattern_id));
     const colors = { critical:'var(--red)', high:'var(--orange)', medium:'var(--yellow)', low:'var(--blue)', info:'var(--green)' };
   
     el.innerHTML = patterns.map(p => {
       let cls, txt;
       if (!findings.length) { cls = 'status-pending'; txt = 'PENDING'; }
       else if (p.id === 'modifier_present' || p.id === 'openzeppelin_ownable') {
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
   
   // ── Tabs & Utils ──────────────────────────────────────────────
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
   
   function emptyState(icon, text, sub='') {
     return `<div class="empty-state">
       <div class="empty-icon">${icon}</div>
       <div class="empty-text">${text}</div>
       ${sub ? `<div class="empty-sub">${sub}</div>` : ''}
     </div>`;
   }
   
   function esc(s) {
     return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
   }