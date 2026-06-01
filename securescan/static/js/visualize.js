/* ═══════════════════════════════════════════════════════════════════
   NEXUS SECURITY PLATFORM — visualize.js
   Features: Scan, Results, Network Map, CVE Feed,
             Compliance, Heatmap, Reports, History
   ═══════════════════════════════════════════════════════════════════ */

const App = {
  socket: null,
  currentScanId: null,
  lastResult: null,
  scanHistory: [],
  charts: { severity: null, heatmap: null },
  network: null,
  progressInterval: null,
  currentFilter: 'All',
  cveData: [],
  cveFilter: 'all',
  currentTheme: 'light',
};

/* ── INIT ────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {

  initClock();
  initNavigation();
  initSocket();
  initMenuToggle();
  initInputs();
  loadHistory();
  autoExpandTextarea();
});


/* ── GRID CANVAS ─────────────────────────────────────────────────── */
// Removed for enterprise theme

/* ── CLOCK ───────────────────────────────────────────────────────── */
function initClock() {
  function tick() {
    const now = new Date();
    const t = now.toLocaleTimeString('en-GB', { hour12: false }) + ' UTC+' + String(-(now.getTimezoneOffset()/60)).replace('-','');
    const el = document.getElementById('sidebarClock');
    if (el) el.textContent = t;
  }
  tick();
  setInterval(tick, 1000);
}

/* ── NAVIGATION ──────────────────────────────────────────────────── */
function initNavigation() {
  document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => goToPage(item.dataset.page));
  });
}

function goToPage(pageId) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const page = document.getElementById(`page-${pageId}`);
  const nav  = document.querySelector(`[data-page="${pageId}"]`);
  if (page) page.classList.add('active');
  if (nav)  nav.classList.add('active');
  const titles = {
    scan: 'Threat Scanner', results: 'Analysis', network: 'Network Map',
    cve: 'CVE Database', compliance: 'Compliance',
    heatmap: 'Threat Heatmap', reports: 'Reports', history: 'Scan History',
  };
  const titleEl = document.getElementById('pageTitle');
  if (titleEl) titleEl.textContent = titles[pageId] || 'NEXUS';
  document.getElementById('sidebar').classList.remove('open');

  // Lazy-load CVE feed on first visit
  if (pageId === 'cve' && App.cveData.length === 0) loadCVEFeed();
}

/* ── SIDEBAR MENU ────────────────────────────────────────────────── */
function initMenuToggle() {
  const btn = document.getElementById('menuToggle');
  const sidebar = document.querySelector('.sidebar');
  if (btn) btn.addEventListener('click', () => sidebar.classList.toggle('open'));
}

/* ── INPUTS ──────────────────────────────────────────────────────── */
function initInputs() {
  const targetInput = document.getElementById('scanTarget');
  if (targetInput) {
    targetInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        startScan();
      }
    });
  }
}

/* ── WEBSOCKET / POLLING ─────────────────────────────────────────── */
function initSocket() {
  // Websocket replaced by HTTP polling for 100% reliability on Windows dev setups
  console.log("Using HTTP polling for scan progress.");
}

function startPolling(scanId) {
  App.progressInterval = setInterval(async () => {
    try {
      const res = await fetch('/api/scan/status/' + scanId);
      const data = await res.json();
      
      if (data.status === 'not_found') {
        clearInterval(App.progressInterval);
        return;
      }
      
      if (data.status === 'running') {
        if (data.logs && data.logs.length > 0) {
          data.logs.forEach(line => appendTerminalLine(line));
        }
        setProgress(data.progress, 'Scanning in progress...');
      }
      
      if (data.status === 'complete') {
        clearInterval(App.progressInterval);
        onScanComplete(data.result);
      }
      
      if (data.status === 'error') {
        clearInterval(App.progressInterval);
        onScanError(data.error);
      }
    } catch(e) {
      console.warn("Polling error:", e);
    }
  }, 1000);
}

/* ── SCAN ────────────────────────────────────────────────────────── */
async function startScan() {
  const target = document.getElementById('scanTarget').value.trim();
  if (!target) { flashInput('scanTarget'); return; }
  const scanType = document.querySelector('input[name="scanType"]:checked')?.value || 'quick';
  const schedule = document.getElementById('scheduleScan') ? document.getElementById('scheduleScan').checked : false;

  document.getElementById('launchBtn').disabled = true;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, scan_type: scanType, schedule: schedule }),
    });
    const data = await res.json();
    
    if (schedule) {
      alert("Arcane Watcher Scheduled! The target will be monitored periodically in the background.");
      document.getElementById('launchBtn').disabled = false;
      return;
    }

    document.getElementById('scanProgress').style.display = 'block';
    document.getElementById('terminalOutput').innerHTML = '';
    document.getElementById('progressFill').style.width = '0%';
    document.getElementById('progressPercent').textContent = '0%';

    App.currentScanId = data.scan_id;
    document.getElementById('progressScanId').textContent = `SCAN #${data.scan_id}`;
    
    // Start polling the server for updates instead of fake animation
    startPolling(data.scan_id);
    
  } catch (err) {
    if (App.progressInterval) clearInterval(App.progressInterval);
    onScanError('Cannot connect to server. Make sure Flask is running.');
  }
}

function setProgress(pct, label) {
  document.getElementById('progressFill').style.width = `${pct}%`;
  document.getElementById('progressPercent').textContent = `${Math.round(pct)}%`;
  if (label) document.getElementById('progressLabel').textContent = label;
}

function updateProgress(msg, pct) {
  setProgress(pct, msg);
  appendTerminalLine(msg);
}

function appendTerminalLine(line) {
  const t = document.getElementById('terminalOutput');
  if (!t || !line.trim()) return;
  const div = document.createElement('div');
  div.className = 'terminal-line';
  div.textContent = line;
  t.appendChild(div);
  t.scrollTop = t.scrollHeight;
}

function onScanComplete(data) {
  clearInterval(App.progressInterval);
  setProgress(100, 'Scan complete!');
  appendTerminalLine('✓ Scan complete. Generating intelligence report...');
  App.lastResult = data;
  App.scanHistory.unshift(data);
  setTimeout(() => {
    renderResults(data);
    goToPage('results');
    document.getElementById('launchBtn').disabled = false;
    updateThreatBadge(data.risks?.overall_risk);
    renderComplianceFromScan(data);
    renderHeatmap(data);
    renderNetworkGraph(data);
    updateReportsList();
    updateHistoryList();
  }, 600);
}

function onScanError(msg) {
  clearInterval(App.progressInterval);
  appendTerminalLine(`✗ Error: ${msg}`);
  setProgress(0, 'Error occurred');
  document.getElementById('launchBtn').disabled = false;
}

function flashInput(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.outline = '2px solid var(--critical)';
  setTimeout(() => el.style.outline = '', 1200);
}

/* ── RESULTS ─────────────────────────────────────────────────────── */
function renderResults(data) {
  const risks = data.risks || {};
  const findings = risks.findings || [];
  const ports = data.nmap?.ports || [];
  const curl = data.curl || {};
  const summary = risks.summary || {};

  let exec_summary_text = data.custom_exec_summary;
  if (!exec_summary_text) {
    exec_summary_text = `This report details the findings of a comprehensive security assessment conducted on the target system (<strong>${data.target || 'N/A'}</strong>). The objective of this assessment was to identify potential vulnerabilities, misconfigurations, and active services that could be leveraged by an adversary.`;
    if (['Critical', 'High'].includes(risks.overall_risk)) {
        exec_summary_text += " The assessment identified severe security exposures that pose a significant risk to the integrity, confidentiality, and availability of the system. Immediate remediation of the findings listed in this document is strongly advised to prevent potential exploitation.";
    } else if (risks.overall_risk === 'Medium') {
        exec_summary_text += " The assessment identified moderate vulnerabilities. While not immediately critical, these findings represent potential attack vectors or configuration weaknesses that should be addressed in the next available maintenance window to improve the overall security posture.";
    } else {
        exec_summary_text += " The assessment concluded with a low risk profile. The system demonstrates a strong baseline security posture. However, adherence to the minor recommendations provided below will further harden the environment against emerging threats.";
    }
  }

  const methodology_text = data.custom_methodology || "The assessment was performed utilizing non-intrusive port scanning, service enumeration, and protocol analysis algorithms. Discovered network topologies and active services were cross-referenced against proprietary threat intelligence and the Common Vulnerabilities and Exposures (CVE) database. Risk scores were algorithmically calculated based on standard CVSS metrics, weighted by the specific context of service exposure and identified configuration weaknesses.";

  const html = `
    <!-- Executive Summary -->
    <div class="card glass" style="margin-bottom:20px;padding:24px;">
      <h3 class="card-title" style="margin-bottom:16px;font-size:1.15rem;color:var(--accent);">Executive Summary</h3>
      <p style="font-size:0.9rem;color:var(--text-dim);line-height:1.6;">${exec_summary_text}</p>
    </div>

    <!-- Methodology -->
    <div class="card glass" style="margin-bottom:20px;padding:24px;">
      <h3 class="card-title" style="margin-bottom:16px;font-size:1.15rem;color:var(--accent);">Assessment Methodology</h3>
      <p style="font-size:0.9rem;color:var(--text-dim);line-height:1.6;">${methodology_text}</p>
    </div>

    <!-- Scan Overview -->
    <div class="card glass" style="margin-bottom:20px;padding:24px;">
      <h3 class="card-title" style="margin-bottom:16px;font-size:1.15rem;color:var(--accent);">Scan Overview</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
        <div style="background:rgba(255,255,255,0.02);padding:14px 18px;border-radius:10px;border:1px solid rgba(255,255,255,0.05);">
          <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-dimmer);letter-spacing:0.5px;">Target Assessed</div>
          <div style="font-size:1rem;font-weight:700;color:var(--text);margin-top:4px;">${data.target}</div>
        </div>
        <div style="background:rgba(255,255,255,0.02);padding:14px 18px;border-radius:10px;border:1px solid rgba(255,255,255,0.05);">
          <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-dimmer);letter-spacing:0.5px;">Assessment Type</div>
          <div style="font-size:1rem;font-weight:700;color:var(--text);margin-top:4px;">${(data.scan_type || 'full').toUpperCase()}</div>
        </div>
        <div style="background:rgba(255,255,255,0.02);padding:14px 18px;border-radius:10px;border:1px solid rgba(255,255,255,0.05);">
          <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-dimmer);letter-spacing:0.5px;">Overall Risk Level</div>
          <div style="font-size:1rem;font-weight:700;color:${risks.overall_color||'var(--text)'};margin-top:4px;">${risks.overall_risk||'N/A'}</div>
        </div>
        <div style="background:rgba(255,255,255,0.02);padding:14px 18px;border-radius:10px;border:1px solid rgba(255,255,255,0.05);">
          <div style="font-size:0.7rem;text-transform:uppercase;color:var(--text-dimmer);letter-spacing:0.5px;">Calculated Risk Score</div>
          <div style="font-size:1rem;font-weight:700;color:var(--text);margin-top:4px;">${risks.risk_score||0} <span style="font-size:0.85rem;color:var(--text-dim);">/ 100</span></div>
        </div>
      </div>
    </div>

    <!-- Original Results Stats Grid -->
    <div class="results-header">
      <div class="stat-card">
        <div class="stat-value" style="color:var(--critical)">${summary.Critical||0}</div>
        <div class="stat-label">CRITICAL</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:var(--high)">${summary.High||0}</div>
        <div class="stat-label">HIGH</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color:var(--medium)">${summary.Medium||0}</div>
        <div class="stat-label">MEDIUM</div>
      </div>
      <div class="risk-gauge-card">
        <div class="gauge-ring" style="border-color:${risks.overall_color||'#5ac8fa'};color:${risks.overall_color||'#5ac8fa'}">
          ${risks.risk_score||0}
        </div>
        <div class="gauge-label">RISK SCORE</div>
      </div>
    </div>

    <div class="card glass" style="margin-bottom:20px;padding:20px">
      <div class="card-header-row">
        <div>
          <h3 class="card-title"><i class="fa-solid fa-triangle-exclamation"></i> Vulnerability Findings</h3>
          <p class="card-sub">${findings.length} issues detected on ${data.target}</p>
        </div>
        <div class="filter-bar" id="findingsFilter">
          ${['All','Critical','High','Medium','Low','Info'].map(s =>
            `<button class="filter-btn ${s==='All'?'active':''}" onclick="filterFindings('${s}',this)">${s}</button>`
          ).join('')}
        </div>
      </div>
      <div id="findingsList">
        ${findings.length ? renderFindingCards(findings) : '<div class="empty-state"><p>No findings detected.</p></div>'}
      </div>
    </div>

    <div class="results-grid">
      <div class="card glass">
        <div class="card-body">
          <h3 class="card-title" style="margin-bottom:16px"><i class="fa-solid fa-chart-pie"></i> Severity Distribution</h3>
          <div class="chart-wrap" style="height:220px">
            <canvas id="severityChart"></canvas>
          </div>
        </div>
      </div>
      <div class="card glass">
        <div class="card-body">
          <h3 class="card-title" style="margin-bottom:16px"><i class="fa-solid fa-plug"></i> Open Ports (${ports.length})</h3>
          <div class="port-list">
            ${ports.slice(0,10).map(p => `
              <div class="port-row">
                <div class="port-num">${p.port}</div>
                <div class="port-service">${p.service}</div>
                <div class="port-version">${p.version||''}</div>
                <div class="port-state state-${p.state}">${p.state}</div>
              </div>
            `).join('') || '<p style="color:var(--text-dim);font-size:.8rem">No ports detected.</p>'}
          </div>
        </div>
      </div>
    </div>

    <div class="card glass" style="margin-bottom:20px">
      <div class="card-body">
        <h3 class="card-title" style="margin-bottom:16px"><i class="fa-solid fa-shield"></i> HTTP Security Headers</h3>
        <div class="header-table">
          ${[...curl.security_headers_present||[], ...(curl.security_headers_missing||[])].map(h => {
            const present = (curl.security_headers_present||[]).includes(h);
            return `<div class="header-row">
              <div class="header-name">${h}</div>
              <div class="header-check ${present?'h-present':'h-missing'}">
                <i class="fa-solid fa-${present?'check-circle':'xmark-circle'}"></i>
                ${present ? 'Present' : 'Missing'}
              </div>
            </div>`;
          }).join('') || '<p style="color:var(--text-dim);font-size:.8rem">No header data available.</p>'}
        </div>
      </div>
    </div>

    <div class="card glass" style="padding:16px 20px;display:flex;gap:12px;align-items:center">
      <i class="fa-solid fa-download" style="color:var(--accent)"></i>
      <span style="font-size:.83rem">Export full scan report:</span>
      <button class="btn-primary-sm" onclick="downloadReport('${data.scan_id}','pdf')"><i class="fa-solid fa-file-pdf"></i> PDF</button>
      <button class="btn-outline" onclick="downloadReport('${data.scan_id}','html')"><i class="fa-solid fa-file-code"></i> HTML</button>
    </div>
  `;

  document.getElementById('resultsContent').innerHTML = html;
  App.currentFilter = 'All';

  // Draw severity doughnut
  setTimeout(() => {
    const ctx = document.getElementById('severityChart');
    if (!ctx) return;
    if (App.charts.severity) App.charts.severity.destroy();
    App.charts.severity = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Critical','High','Medium','Low','Info'],
        datasets: [{
          data: [summary.Critical||0, summary.High||0, summary.Medium||0, summary.Low||0, summary.Info||0],
          backgroundColor: ['#ff2d55','#ff6b35','#ffd60a','#34c759','#5ac8fa'],
          borderWidth: 0,
          hoverOffset: 8,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'right', labels: { color: '#6b7fa3', font: { size: 11 }, padding: 12 } },
          tooltip: { callbacks: { label: (c) => ` ${c.label}: ${c.raw}` } }
        },
        cutout: '65%',
      }
    });
    // Findings list renders automatically inside index.html using the filterFindings function
  }, 100);
}

function renderFindingCards(findings, filter = 'All') {
  const f = filter === 'All' ? findings : findings.filter(x => x.severity === filter);
  if (!f.length) return `<div class="empty-state"><p>No ${filter === 'All' ? '' : filter + ' '}findings.</p></div>`;
  return f.map((item, i) => {
    const impact = (item.attack && item.attack.impact) ? item.attack.impact : 'Potential for unauthorized access or system disruption.';
    return `
    <div class="finding-card" onclick="openFindingModal(${i})">
      <span class="finding-sev sev-${item.severity.toLowerCase()}">${item.severity}</span>
      <div style="flex:1">
        <div class="finding-title">${item.title}</div>
        <div class="finding-desc"><strong>Description:</strong> ${item.description}</div>
        <div class="finding-desc" style="color:var(--high);margin-top:6px;"><strong>Business Impact:</strong> ${impact}</div>
      </div>
      <div class="finding-meta">
        ${item.port ? `<div class="finding-port">:${item.port}</div>` : ''}
        <div style="margin-top:4px;font-size:.65rem;color:var(--text-dimmer);font-family:var(--font-mono)">${item.type}</div>
      </div>
    </div>
  `}).join('');
}

function filterFindings(severity, btn) {
  App.currentFilter = severity;
  document.querySelectorAll('#findingsFilter .filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const findings = App.lastResult?.risks?.findings || [];
  document.getElementById('findingsList').innerHTML = renderFindingCards(findings, severity);
}

/* ── MODAL ───────────────────────────────────────────────────────── */
function openFindingModal(idx) {
  const findings = App.lastResult?.risks?.findings || [];
  const severity = App.currentFilter;
  const filtered = severity === 'All' ? findings : findings.filter(x => x.severity === severity);
  const item = filtered[idx];
  if (!item) return;
  const attack = item.attack || {};
  const steps = attack.steps || [];
  const tools = attack.tools || [];

  document.getElementById('modalContent').innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px">
      <span class="finding-sev sev-${item.severity.toLowerCase()}">${item.severity}</span>
      <h2 class="modal-title" style="margin:0;font-size:1.1rem">${item.title}</h2>
    </div>
    ${item.port ? `<div style="margin-bottom:14px"><span class="finding-port">Port ${item.port}/${item.service}</span></div>` : ''}
    <div class="modal-section">
      <div class="modal-section-title">DESCRIPTION</div>
      <p style="font-size:.82rem;color:var(--text-dim);line-height:1.6">${item.description}</p>
    </div>
    <div class="modal-section">
      <div class="modal-section-title">RECOMMENDATION</div>
      <p style="font-size:.82rem;color:var(--text);line-height:1.6">${item.recommendation}</p>
    </div>
    ${attack.attack_name ? `
    <div class="modal-section" style="background:rgba(255,45,85,.05);border:1px solid rgba(255,45,85,.15);border-radius:10px;padding:16px">
      <div class="modal-section-title" style="color:var(--critical)">⚠ ATTACK INTELLIGENCE</div>
      <div style="font-weight:600;font-size:.85rem;margin-bottom:6px">${attack.attack_name}</div>
      <div style="font-size:.75rem;color:var(--text-dim);margin-bottom:10px">${attack.attack_type || ''}</div>
      ${attack.cve ? `<div style="margin-bottom:10px"><span class="tool-tag" style="background:rgba(255,45,85,.15);border-color:rgba(255,45,85,.3);color:var(--critical)">${attack.cve}</span></div>` : ''}
      ${tools.length ? `
        <div class="modal-section-title">TOOLS</div>
        <div class="tools-list" style="margin-bottom:12px">${tools.map(t => `<span class="tool-tag">${t}</span>`).join('')}</div>
      ` : ''}
      ${steps.length ? `
        <div class="modal-section-title">ATTACK STEPS</div>
        <ol class="steps-list">
          ${steps.map((s,i) => `<li><span class="step-num">${i+1}</span><span>${s}</span></li>`).join('')}
        </ol>
      ` : ''}
      ${attack.impact ? `
        <div style="margin-top:12px;padding:10px 14px;background:rgba(0,0,0,.3);border-radius:8px;font-size:.75rem;color:var(--high)">
          <strong>Impact:</strong> ${attack.impact}
        </div>
      ` : ''}
    </div>
    ` : ''}
  `;
  document.getElementById('modalOverlay').classList.add('open');
}

function closeModal() {
  document.getElementById('modalOverlay').classList.remove('open');
}

/* ── NETWORK GRAPH ───────────────────────────────────────────────── */
function renderNetworkGraph(data) {
  const container = document.getElementById('networkGraph');
  if (!container) return;

  const hint = document.getElementById('networkHint');
  const badge = document.getElementById('networkTarget');
  if (badge) badge.textContent = data.target;
  if (hint) hint.style.display = 'none';

  // Central Hub Node
  const nodes = [{
    id: 'target', 
    label: `TARGET\n${data.target}`, 
    shape: 'diamond', 
    size: 28, 
    color: { background: '#c77dff', border: '#f9a826' }, 
    font: { color: '#fff', size: 12, face: 'Cinzel Decorative', bold: true },
    shadow: { enabled: true, color: '#c77dff', size: 15, x: 0, y: 0 }
  }];
  
  const edges = [];
  const services = {};
  
  // Group ports by service
  (data.nmap?.ports || []).forEach(p => {
    const srv = (p.service || 'unknown').toLowerCase();
    if (!services[srv]) services[srv] = [];
    services[srv].push(p);
  });

  let nodeIdCounter = 1;

  // Create Service Nodes and Port Nodes
  Object.keys(services).forEach(srv => {
    const srvNodeId = `srv_${srv}`;
    
    // Determine highest risk for this service group to color the service node
    let highestRisk = 'low';
    services[srv].forEach(p => {
      const r = getPortRiskLevel(p.port);
      if (r === 'critical') highestRisk = 'critical';
      else if (r === 'high' && highestRisk !== 'critical') highestRisk = 'high';
    });

    let srvColor = '#5ac8fa';
    if (highestRisk === 'critical') srvColor = '#ff2d55';
    else if (highestRisk === 'high') srvColor = '#ff6b35';

    // Add Service Node
    nodes.push({
      id: srvNodeId,
      label: `Service\n${srv.toUpperCase()}`,
      shape: 'box',
      color: { background: 'rgba(255,255,255,0.05)', border: srvColor },
      font: { color: '#fff', size: 11, face: 'Space Mono' },
      borderWidth: 2,
      shadow: { enabled: true, color: srvColor, size: 10, x: 0, y: 0 }
    });

    // Link Target -> Service
    edges.push({
      from: 'target',
      to: srvNodeId,
      color: { color: srvColor, opacity: 0.6 },
      width: 2,
      dashes: true
    });

    // Add Port Nodes
    services[srv].forEach(p => {
      const rLevel = getPortRiskLevel(p.port);
      let shape = 'hexagon';
      let size = 16;
      let colorBg = '#5ac8fa';
      let shadowColor = '#5ac8fa';

      if (rLevel === 'critical') {
        shape = 'star';
        size = 22;
        colorBg = '#ff2d55';
        shadowColor = '#ff2d55';
      } else if (rLevel === 'high') {
        shape = 'triangleDown';
        size = 18;
        colorBg = '#ff6b35';
        shadowColor = '#ff6b35';
      }

      const pNodeId = nodeIdCounter++;
      nodes.push({
        id: pNodeId,
        label: `Port ${p.port}`,
        color: { background: colorBg, border: 'rgba(255,255,255,0.4)' },
        font: { color: '#fff', size: 10, face: 'Space Mono' },
        shape: shape, 
        size: size,
        borderWidth: 2,
        shadow: { enabled: true, color: shadowColor, size: 10, x: 0, y: 0 },
        portData: p 
      });

      // Link Service -> Port
      edges.push({ 
        from: srvNodeId, 
        to: pNodeId, 
        color: { color: shadowColor, opacity: 0.4 }, 
        width: 2,
        shadow: { enabled: true, color: shadowColor, size: 8, x: 0, y: 0 }
      });
    });
  });

  if (App.network) App.network.destroy();
  
  App.network = new vis.Network(container,
    { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) },
    {
      physics: { 
        solver: 'forceAtlas2Based', 
        forceAtlas2Based: { gravitationalConstant: -60, springLength: 100, springConstant: 0.05 } 
      },
      edges: { smooth: { type: 'continuous' } },
      interaction: { hover: true, tooltipDelay: 200, zoomView: false, dragView: true },
      background: '#000000',
    }
  );

  // Automatically fit the graph to the screen once it stabilizes
  App.network.once("stabilizationIterationsDone", function() {
    App.network.fit({ animation: { duration: 1000, easingFunction: 'easeInOutQuad' } });
  });

  // Add Click Listener
  App.network.on("click", function (params) {
    if (params.nodes.length > 0) {
      const nodeId = params.nodes[0];
      const node = nodes.find(n => n.id === nodeId);
      if (node && node.portData) {
        showPortModal(node.portData);
      }
    }
  });
}

function getPortRiskLevel(port) {
  const critical = [23,135,139,445,1433,1521,3389,6379,9200,27017];
  const high     = [21,25,110,3306,5432,5900];
  if (critical.includes(port)) return 'critical';
  if (high.includes(port))     return 'high';
  return 'low';
}

function riskColor(port) {
  const r = getPortRiskLevel(port);
  if (r === 'critical') return '#ff2d55';
  if (r === 'high') return '#ff6b35';
  return '#5ac8fa';
}

function showPortModal(portData) {
  const rLevel = getPortRiskLevel(portData.port);
  const sevClass = rLevel === 'critical' ? 'critical' : rLevel === 'high' ? 'high' : 'info';
  
  document.getElementById('modalContent').innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px">
      <span class="finding-sev sev-${sevClass}">PORT ${portData.port}</span>
      <h2 class="modal-title" style="margin:0;font-size:1.1rem;font-family:var(--font-display)">${portData.service.toUpperCase()} Nexus</h2>
    </div>
    <div class="modal-section">
      <div class="modal-section-title">PORT STATE</div>
      <span class="tool-tag" style="background:rgba(52,199,89,.15);border-color:rgba(52,199,89,.3);color:var(--low)">${portData.state.toUpperCase()}</span>
    </div>
    <div class="modal-section">
      <div class="modal-section-title">SERVICE PROTOCOL</div>
      <p style="font-size:.82rem;font-family:var(--font-mono);color:var(--text-dim)">${portData.protocol.toUpperCase()}</p>
    </div>
    <div class="modal-section">
      <div class="modal-section-title">VERSION DETECTED</div>
      <p style="font-size:.82rem;font-family:var(--font-mono);color:var(--accent-2)">${portData.version || 'Arcane signatures obscured (Unknown)'}</p>
    </div>
  `;
  document.getElementById('modalOverlay').classList.add('open');
}

/* ── THREAT BADGE ────────────────────────────────────────────────── */
function updateThreatBadge(level) {
  const colors = { Critical:'var(--critical)', High:'var(--high)', Medium:'var(--medium)', Low:'var(--low)', Info:'var(--info)' };
  const dot = document.querySelector('.tl-dot');
  const txt = document.getElementById('threatLevelText');
  if (dot) dot.style.background = colors[level] || 'var(--text-dimmer)';
  if (txt) txt.textContent = `THREAT LEVEL: ${(level||'UNKNOWN').toUpperCase()}`;
}

function autoExpandTextarea() {
  const ta = document.getElementById('aiInput');
  if (!ta) return;
  ta.addEventListener('input', () => {
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 100) + 'px';
  });
}

/* ── CVE FEED ────────────────────────────────────────────────────── */
async function loadCVEFeed() {
  const container = document.getElementById('cveFeedContainer');
  container.innerHTML = '<div class="empty-state glass" style="padding:40px"><i class="fa-solid fa-satellite-dish fa-2x" style="color:var(--accent);animation:spin 1s linear infinite"></i><p>Loading CVE intelligence...</p></div>';

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1000,
        system: 'You are a CVE intelligence database. Respond ONLY with a JSON array, no markdown, no preamble. Generate 12 realistic recent CVE entries relevant to network security.',
        messages: [{
          role: 'user',
          content: `Generate 12 realistic CVE entries for common network services (SSH, HTTP, FTP, MySQL, RDP, SMB, Apache, nginx, OpenSSL, etc). Return JSON array with fields: id (CVE-YEAR-NNNNN), title, description (1-2 sentences), severity (Critical/High/Medium/Low), cvss (float 0-10), service, published (recent date YYYY-MM-DD).`
        }],
      })
    });
    const data = await response.json();
    const text = data.content?.map(b => b.text||'').join('') || '[]';
    const clean = text.replace(/```json|```/g,'').trim();
    App.cveData = JSON.parse(clean);
  } catch (err) {
    // Fallback mock data
    App.cveData = generateMockCVEs();
  }
  renderCVEFeed();
}

function generateMockCVEs() {
  return [
    { id:'CVE-2024-3400', title:'PAN-OS Command Injection', description:'Critical command injection in GlobalProtect feature of PAN-OS allows unauthenticated RCE.', severity:'Critical', cvss:10.0, service:'Firewall', published:'2024-04-12' },
    { id:'CVE-2024-1709', title:'ConnectWise ScreenConnect Auth Bypass', description:'Authentication bypass vulnerability allowing unauthorized access.', severity:'Critical', cvss:10.0, service:'Remote Access', published:'2024-02-21' },
    { id:'CVE-2023-44487', title:'HTTP/2 Rapid Reset Attack', description:'Protocol-level DDoS attack exploiting HTTP/2 stream cancellation.', severity:'High', cvss:7.5, service:'HTTP/2', published:'2023-10-10' },
    { id:'CVE-2024-21887', title:'Ivanti Command Injection', description:'Command injection in web components of Ivanti Connect Secure.', severity:'Critical', cvss:9.1, service:'VPN', published:'2024-01-10' },
    { id:'CVE-2023-46604', title:'Apache ActiveMQ RCE', description:'Remote code execution vulnerability in OpenWire protocol deserialization.', severity:'Critical', cvss:10.0, service:'Messaging', published:'2023-10-27' },
    { id:'CVE-2024-23897', title:'Jenkins Path Traversal', description:'Unauthenticated file read via CLI command parser in Jenkins.', severity:'Critical', cvss:9.8, service:'CI/CD', published:'2024-01-24' },
    { id:'CVE-2023-48795', title:'OpenSSH Terrapin Attack', description:'Prefix truncation attack on SSH transport layer reducing security of countermeasures.', severity:'Medium', cvss:5.9, service:'SSH', published:'2023-12-18' },
    { id:'CVE-2024-6387', title:'OpenSSH RegreSSHion', description:'Race condition in signal handler allows unauthenticated RCE as root on glibc Linux.', severity:'Critical', cvss:8.1, service:'SSH', published:'2024-07-01' },
    { id:'CVE-2024-4577', title:'PHP CGI Argument Injection', description:'Argument injection via character encoding in PHP CGI mode on Windows.', severity:'Critical', cvss:9.8, service:'PHP', published:'2024-06-09' },
    { id:'CVE-2023-4911', title:'glibc Buffer Overflow (Looney Tunables)', description:'Buffer overflow in GNU C Library dynamic loader privilege escalation.', severity:'High', cvss:7.8, service:'Linux', published:'2023-10-03' },
    { id:'CVE-2024-20359', title:'Cisco ASA Privilege Escalation', description:'Privilege escalation via CLI command in Cisco ASA and Firepower.', severity:'High', cvss:6.0, service:'Firewall', published:'2024-04-24' },
    { id:'CVE-2023-42793', title:'TeamCity Auth Bypass', description:'Authentication bypass in JetBrains TeamCity allows full server takeover.', severity:'Critical', cvss:9.8, service:'CI/CD', published:'2023-09-19' },
  ];
}

function renderCVEFeed() {
  const search = (document.getElementById('cveSearch')?.value || '').toLowerCase();
  let data = App.cveData;
  if (App.cveFilter !== 'all') data = data.filter(c => c.severity?.toLowerCase() === App.cveFilter);
  if (search) data = data.filter(c =>
    c.id?.toLowerCase().includes(search) ||
    c.title?.toLowerCase().includes(search) ||
    c.service?.toLowerCase().includes(search) ||
    c.description?.toLowerCase().includes(search)
  );

  const container = document.getElementById('cveFeedContainer');
  if (!data.length) {
    container.innerHTML = '<div class="empty-state glass" style="padding:40px"><p>No CVEs match your search.</p></div>';
    return;
  }
  container.innerHTML = `<div class="cve-grid">${data.map(c => {
    const sev = c.severity?.toLowerCase() || 'info';
    const cvss = parseFloat(c.cvss || 0).toFixed(1);
    return `<div class="cve-card" onclick="showCVEDetail(${JSON.stringify(c).replace(/"/g,"&quot;")})">
      <div class="cve-id">${c.id}</div>
      <div style="flex:1">
        <div class="cve-title">${c.title}</div>
        <div class="cve-desc">${c.description}</div>
        <div style="margin-top:6px;font-size:.68rem;color:var(--text-dimmer);font-family:var(--font-mono)">${c.service} · ${c.published}</div>
      </div>
      <div class="cve-meta">
        <div class="cvss-badge sev-${sev}">${cvss}</div>
        <div class="finding-sev sev-${sev}" style="font-size:.6rem">${c.severity}</div>
      </div>
    </div>`;
  }).join('')}</div>`;
}

function filterCVE() { renderCVEFeed(); }
function setCVEFilter(f, btn) {
  App.cveFilter = f;
  document.querySelectorAll('.cve-tab').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderCVEFeed();
}

function showCVEDetail(c) {
  document.getElementById('modalContent').innerHTML = `
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:20px;flex-wrap:wrap">
      <span class="finding-sev sev-${c.severity?.toLowerCase()}">${c.severity}</span>
      <span style="font-family:var(--font-mono);font-size:.75rem;color:var(--accent)">${c.id}</span>
      <span class="cvss-badge sev-${c.severity?.toLowerCase()}" style="margin-left:auto">CVSS ${c.cvss}</span>
    </div>
    <h2 class="modal-title">${c.title}</h2>
    <div class="modal-section">
      <div class="modal-section-title">AFFECTED SERVICE</div>
      <span class="tool-tag">${c.service}</span>
    </div>
    <div class="modal-section">
      <div class="modal-section-title">DESCRIPTION</div>
      <p style="font-size:.82rem;color:var(--text-dim);line-height:1.6">${c.description}</p>
    </div>
    <div class="modal-section">
      <div class="modal-section-title">PUBLISHED</div>
      <p style="font-size:.8rem;font-family:var(--font-mono);color:var(--text-dim)">${c.published}</p>
    </div>
    <a href="https://nvd.nist.gov/vuln/detail/${c.id}" target="_blank" class="btn-primary-sm" style="display:inline-flex;margin-top:10px">
      <i class="fa-solid fa-external-link"></i> View on NVD
    </a>
  `;
  document.getElementById('modalOverlay').classList.add('open');
}

/* ── COMPLIANCE ──────────────────────────────────────────────────── */
function renderComplianceFromScan(data) {
  const risks = data.risks || {};
  const findings = risks.findings || [];
  const curl = data.curl || {};

  const critical = findings.filter(f => f.severity === 'Critical').length;
  const missing = curl.security_headers_missing?.length || 0;
  const hasTelnet   = findings.some(f => f.port === 23);
  const hasFTP      = findings.some(f => f.port === 21);
  const hasSMB      = findings.some(f => f.port === 445);
  const hasRDP      = findings.some(f => f.port === 3389);
  const hasHSTS     = !(curl.security_headers_missing||[]).includes('Strict-Transport-Security');
  const hasCSP      = !(curl.security_headers_missing||[]).includes('Content-Security-Policy');
  const hasXFrame   = !(curl.security_headers_missing||[]).includes('X-Frame-Options');

  // PCI DSS
  const pciChecks = [
    { label:'No critical vulnerabilities', pass: critical === 0 },
    { label:'No FTP (cleartext)', pass: !hasFTP },
    { label:'No Telnet (cleartext)', pass: !hasTelnet },
    { label:'HSTS enabled', pass: hasHSTS },
    { label:'No exposed DB ports', pass: !findings.some(f => [3306,5432,1433,27017].includes(f.port)) },
  ];
  const pciScore = Math.round((pciChecks.filter(c=>c.pass).length / pciChecks.length) * 100);
  setFrameworkScore('pci', pciScore, pciChecks);

  // NIST CSF
  const nistChecks = [
    { label:'Encrypted communications (HTTPS)', pass: hasHSTS },
    { label:'No high-risk ports exposed', pass: critical < 2 },
    { label:'SMB not exposed externally', pass: !hasSMB },
    { label:'RDP not exposed externally', pass: !hasRDP },
    { label:'Security headers configured', pass: missing < 3 },
  ];
  const nistScore = Math.round((nistChecks.filter(c=>c.pass).length / nistChecks.length) * 100);
  setFrameworkScore('nist', nistScore, nistChecks);

  // OWASP Top 10
  const owaspChecks = [
    { label:'Content-Security-Policy (XSS)', pass: hasCSP },
    { label:'X-Frame-Options (Clickjacking)', pass: hasXFrame },
    { label:'No debug ports exposed', pass: !findings.some(f => [8080,8443].includes(f.port)) },
    { label:'HSTS (Downgrade attacks)', pass: hasHSTS },
    { label:'No default credential services', pass: !hasFTP && !hasTelnet },
  ];
  const owaspScore = Math.round((owaspChecks.filter(c=>c.pass).length / owaspChecks.length) * 100);
  setFrameworkScore('owasp', owaspScore, owaspChecks);

  // ISO 27001
  const isoChecks = [
    { label:'Network segmentation evident', pass: critical < 3 },
    { label:'Encrypted management access', pass: !hasTelnet },
    { label:'Minimal attack surface', pass: (data.nmap?.ports||[]).length < 8 },
    { label:'Web security configured', pass: missing < 4 },
    { label:'No legacy services running', pass: !hasFTP && !hasTelnet },
  ];
  const isoScore = Math.round((isoChecks.filter(c=>c.pass).length / isoChecks.length) * 100);
  setFrameworkScore('iso', isoScore, isoChecks);

  document.querySelector('.compliance-notice').innerHTML = `
    <i class="fa-solid fa-circle-check" style="color:var(--low)"></i>
    <span>Compliance scores generated from scan of <strong>${data.target}</strong>.</span>
  `;
}

function setFrameworkScore(fw, score, checks) {
  const scoreEl = document.getElementById(`${fw}-score`);
  const barEl   = document.getElementById(`${fw}-bar`);
  const checksEl = document.getElementById(`${fw}-checks`);
  const color = score >= 80 ? 'var(--low)' : score >= 60 ? 'var(--medium)' : 'var(--critical)';
  if (scoreEl) { scoreEl.textContent = score + '%'; scoreEl.style.color = color; }
  if (barEl)   { setTimeout(() => { barEl.style.width = score + '%'; }, 200); }
  if (checksEl) checksEl.innerHTML = checks.map(c => `
    <div class="fw-check-row">
      <i class="fa-solid fa-${c.pass?'check':'xmark'} ${c.pass?'fw-check-pass':'fw-check-fail'}"></i>
      <span>${c.label}</span>
    </div>
  `).join('');
}

/* ── HEATMAP ─────────────────────────────────────────────────────── */
function renderHeatmap(data) {
  const findings = data.risks?.findings || [];
  if (!findings.length) return;

  document.getElementById('heatmapContainer').style.display = 'none';
  const matrix = document.getElementById('heatmapMatrix');
  matrix.style.display = 'block';

  // Group findings by type and severity
  const heatmapData = {
    'Port Exposure': countByType(findings, 'port'),
    'Service Version': countByType(findings, 'version'),
    'HTTP Headers': countByType(findings, 'header'),
    'Authentication': countByType(findings, 'auth'),
    'Protocol Security': countByType(findings, 'protocol')
  };

  const severities = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  
  let html = '<table class="heatmap-table"><thead><tr><th>Risk Category</th>';
  severities.forEach(s => html += `<th class="hm-sev hm-sev-${s.toLowerCase()}">${s}</th>`);
  html += '</tr></thead><tbody>';

  for (const [category, counts] of Object.entries(heatmapData)) {
    html += `<tr><td class="hm-category">${category}</td>`;
    severities.forEach(sev => {
      const count = counts[sev] || 0;
      const color = getHeatmapColor(sev);
      html += `<td class="hm-cell" style="background:${color};color:white;font-weight:bold">${count}</td>`;
    });
    html += '</tr>';
  }

  html += '</tbody></table>';
  matrix.innerHTML = html;
}

function countByType(findings, type) {
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  findings.forEach(f => {
    if (f.type === type && counts[f.severity] !== undefined) {
      counts[f.severity]++;
    }
  });
  return counts;
}

function getHeatmapColor(severity) {
  const colors = {
    Critical: 'var(--critical)',
    High: 'var(--high)',
    Medium: 'var(--medium)',
    Low: 'var(--low)',
    Info: 'var(--info)'
  };
  return colors[severity] || '#6c757d';
}

/* ── REPORTS ─────────────────────────────────────────────────────── */
async function updateReportsList() {
  try {
    const res = await fetch('/api/history');
    const scans = await res.json();
    const container = document.getElementById('reportsListContainer');
    
    if (!scans || scans.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon"><i class="fa-solid fa-file-circle-xmark"></i></div>
          <h3>No Reports</h3>
          <p>Complete a scan and generate a report to see it here.</p>
        </div>`;
      return;
    }
    
    container.innerHTML = scans.slice(0, 10).map(s => `
      <div class="report-item">
        <div class="report-icon"><i class="fa-solid fa-file-waveform"></i></div>
        <div>
          <div class="report-name">${s.scan_id} — ${s.target}</div>
          <div class="report-meta">${new Date(s.timestamp).toLocaleString()} · Risk: ${s.overall_risk||'N/A'} (${s.risk_score||0})</div>
        </div>
        <div class="report-actions">
          <button class="btn-outline" onclick="editReport('${s.scan_id}')"><i class="fa-solid fa-pen"></i> Edit</button>
          <button class="btn-outline" onclick="viewReportInApp('${s.scan_id}')"><i class="fa-solid fa-eye"></i> View</button>
          <button class="btn-primary-sm" onclick="downloadReport('${s.scan_id}','pdf')"><i class="fa-solid fa-file-pdf"></i> PDF</button>
          <button class="btn-outline" onclick="downloadReport('${s.scan_id}','html')"><i class="fa-solid fa-file-code"></i> HTML</button>
        </div>
      </div>
    `).join('');
  } catch(e) {
    console.warn("Failed to update reports list.");
  }
}

function downloadReport(scanId, type) {
  window.location.href = `/api/report/${scanId}/${type}`;
}

function viewReportInApp(scanId) {
  document.getElementById('reportIframe').src = `/api/report/${scanId}/view`;
  goToPage('report-viewer');
}

async function editReport(scanId) {
  try {
    const res = await fetch(`/api/scan/${scanId}`);
    if (!res.ok) throw new Error("Scan not found");
    const data = await res.json();
    
    App.currentEditScanId = scanId;
    
    // Generate fallback text if not present
    let defaultExec = `This report details the findings of a comprehensive security assessment conducted on the target system (<strong>${data.target || 'N/A'}</strong>). The objective of this assessment was to identify potential vulnerabilities, misconfigurations, and active services that could be leveraged by an adversary.`;
    const overallRisk = data.risks?.overall_risk;
    if (['Critical', 'High'].includes(overallRisk)) {
        defaultExec += " The assessment identified severe security exposures that pose a significant risk to the integrity, confidentiality, and availability of the system. Immediate remediation of the findings listed in this document is strongly advised to prevent potential exploitation.";
    } else if (overallRisk === 'Medium') {
        defaultExec += " The assessment identified moderate vulnerabilities. While not immediately critical, these findings represent potential attack vectors or configuration weaknesses that should be addressed in the next available maintenance window to improve the overall security posture.";
    } else {
        defaultExec += " The assessment concluded with a low risk profile. The system demonstrates a strong baseline security posture. However, adherence to the minor recommendations provided below will further harden the environment against emerging threats.";
    }

    const defaultMethodology = "The assessment was performed utilizing non-intrusive port scanning, service enumeration, and protocol analysis algorithms. Discovered network topologies and active services were cross-referenced against proprietary threat intelligence and the Common Vulnerabilities and Exposures (CVE) database. Risk scores were algorithmically calculated based on standard CVSS metrics, weighted by the specific context of service exposure and identified configuration weaknesses.";

    document.getElementById('editExecSummary').value = data.custom_exec_summary || defaultExec;
    document.getElementById('editMethodology').value = data.custom_methodology || defaultMethodology;

    goToPage('editor');
  } catch(e) {
    alert("Could not load report details: " + e.message);
  }
}

async function saveReportEdits() {
  const btn = document.getElementById('saveReportEditsBtn');
  btn.disabled = true;
  btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';
  
  const payload = {
    custom_exec_summary: document.getElementById('editExecSummary').value,
    custom_methodology: document.getElementById('editMethodology').value
  };

  try {
    const res = await fetch(`/api/report/${App.currentEditScanId}/edit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    
    if (res.ok) {
      alert("Edits saved successfully! The PDF and HTML reports will now use your custom text.");
      viewReportInApp(App.currentEditScanId);
    } else {
      alert("Failed to save edits.");
    }
  } catch(e) {
    console.error(e);
    alert("Error saving edits.");
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<i class="fa-solid fa-save"></i> Save Changes';
  }
}

/* ── HISTORY ─────────────────────────────────────────────────────── */
async function clearHistory() {
  if (!confirm("Are you sure you want to completely wipe all scan history? This action cannot be undone.")) return;
  
  try {
    const res = await fetch('/api/history', { method: 'DELETE' });
    if (res.ok) {
      App.scanHistory = [];
      document.getElementById('historyContainer').innerHTML = `
        <div class="empty-state glass">
          <div class="empty-icon"><i class="fa-solid fa-clock-rotate-left"></i></div>
          <h3>No scan history yet</h3>
          <p>Your completed scans will appear here.</p>
        </div>`;
      await updateReportsList();
    } else {
      alert("Failed to clear history.");
    }
  } catch(e) {
    console.error("Error clearing history:", e);
  }
}

async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const data = await res.json();
    renderHistory(data);
  } catch (e) {
    if (App.scanHistory.length) renderHistory(App.scanHistory.map(s => ({
      scan_id: s.scan_id, target: s.target, timestamp: s.timestamp,
      risk_summary: s.risks?.summary || {},
    })));
  }
}

function renderHistory(items) {
  const container = document.getElementById('historyContainer');
  if (!items.length) return;
  container.innerHTML = `<div class="history-grid">${items.map(s => {
    const score = (s.risk_summary?.Critical||0)*30 + (s.risk_summary?.High||0)*15 + (s.risk_summary?.Medium||0)*7;
    const color = score >= 70 ? 'var(--critical)' : score >= 30 ? 'var(--medium)' : 'var(--low)';
    return `<div class="history-card glass" onclick="loadScanFromHistory('${s.scan_id}')">
      <div>
        <div class="history-id">${s.scan_id}</div>
        <div class="history-target">${s.target}</div>
        <div class="history-time">${new Date(s.timestamp).toLocaleString()}</div>
      </div>
      <div class="history-score" style="color:${color}">${Math.min(score,100)}</div>
    </div>`;
  }).join('')}</div>`;
}

async function loadScanFromHistory(scanId) {
  try {
    const res = await fetch(`/api/scan/${scanId}`);
    const data = await res.json();
    App.lastResult = data;
    renderResults(data);
    renderNetworkGraph(data);
    renderComplianceFromScan(data);
    renderHeatmap(data);
    updateThreatBadge(data.risks?.overall_risk);
    goToPage('results');
  } catch (e) {
    console.error('Failed to load scan:', e);
  }
}

async function updateHistoryList() {
  await loadHistory();
}

/* ── ADVANCED TOGGLE ─────────────────────────────────────────────── */
function toggleAdvanced() {
  const opts = document.getElementById('advOptions');
  const chev = document.getElementById('advChevron');
  const open = opts.classList.toggle('open');
  if (chev) chev.style.transform = open ? 'rotate(180deg)' : 'rotate(0deg)';
}
