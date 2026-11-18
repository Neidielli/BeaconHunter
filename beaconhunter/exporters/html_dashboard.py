"""
Standalone Interactive HTML Threat Hunting Dashboard Generator.
Renders a 100% air-gapped HTML5 report featuring:
  - Interactive Force-Directed HTML5 Canvas Network Graph (drag, hover, animated C2 pulses)
  - C2 Beaconing Interval & Jitter Distribution Visuals
  - DNS Shannon Entropy & Exfiltration / DGA Table
  - TLS JA3 / JA3S Threat Intelligence Matrix
  - Live Filterable MITRE ATT&CK Alert Stream
"""

import json
from dataclasses import asdict
from pathlib import Path

from jinja2 import Template
from beaconhunter.models import ForensicAnalysisReport


DASHBOARD_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>BeaconHunter — Network Forensics & C2 Threat Hunting Report</title>
  <style>
    :root {
      --bg-dark: #070b14;
      --bg-panel: #0f1629;
      --bg-card: #151f38;
      --border: #233256;
      --neon-green: #00ff66;
      --neon-cyan: #00e5ff;
      --neon-pink: #ff0055;
      --neon-amber: #ffaa00;
      --text-main: #e2e8f0;
      --text-muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-dark);
      color: var(--text-main);
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      line-height: 1.5;
      padding: 24px;
    }
    .mono { font-family: 'Cascadia Code', 'Fira Code', Consolas, monospace; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      background: linear-gradient(135deg, #0f172a 0%, #16203d 100%);
      border: 1px solid var(--border);
      border-left: 4px solid var(--neon-green);
      border-radius: 10px;
      padding: 20px 26px;
      margin-bottom: 24px;
      box-shadow: 0 8px 30px rgba(0, 0, 0, 0.45);
    }
    .brand h1 {
      font-size: 1.65rem;
      letter-spacing: 0.5px;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .brand h1 span.accent { color: var(--neon-green); }
    .brand p { color: var(--text-muted); font-size: 0.9rem; margin-top: 4px; }
    .meta-box {
      text-align: right;
      font-size: 0.82rem;
      color: var(--text-muted);
    }
    .meta-box strong { color: var(--neon-cyan); }

    /* KPI Grid */
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .kpi-card {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 18px 20px;
      position: relative;
      overflow: hidden;
    }
    .kpi-card::after {
      content: "";
      position: absolute;
      top: 0; left: 0; width: 100%; height: 3px;
      background: var(--neon-cyan);
    }
    .kpi-card.crit::after { background: var(--neon-pink); }
    .kpi-card.ok::after { background: var(--neon-green); }
    .kpi-card.warn::after { background: var(--neon-amber); }
    .kpi-label { font-size: 0.78rem; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); }
    .kpi-val { font-size: 2rem; font-weight: 700; margin-top: 6px; color: #fff; }
    .kpi-sub { font-size: 0.8rem; color: var(--text-muted); margin-top: 4px; }

    /* Section Containers */
    .section-panel {
      background: var(--bg-panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 22px;
      margin-bottom: 24px;
    }
    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border);
    }
    .section-title {
      font-size: 1.15rem;
      font-weight: 600;
      color: var(--neon-cyan);
      display: flex;
      align-items: center;
      gap: 8px;
    }

    /* Interactive Graph Canvas */
    .graph-wrapper {
      display: grid;
      grid-template-columns: 1fr 310px;
      gap: 16px;
    }
    @media (max-width: 960px) {
      .graph-wrapper { grid-template-columns: 1fr; }
    }
    #topologyCanvas {
      width: 100%;
      height: 460px;
      background: radial-gradient(circle at center, #111a30 0%, #070b14 100%);
      border: 1px solid var(--border);
      border-radius: 8px;
      cursor: grab;
    }
    #topologyCanvas:active { cursor: grabbing; }
    .graph-sidebar {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .legend-item {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 0.85rem;
      margin-bottom: 10px;
    }
    .dot { width: 13px; height: 13px; border-radius: 50%; display: inline-block; }

    /* Badges */
    .badge {
      display: inline-block;
      padding: 3px 9px;
      border-radius: 4px;
      font-size: 0.73rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-CRITICAL { background: rgba(255, 0, 85, 0.18); color: #ff3377; border: 1px solid #ff0055; }
    .badge-HIGH { background: rgba(255, 170, 0, 0.18); color: #ffbb33; border: 1px solid #ffaa00; }
    .badge-MEDIUM { background: rgba(0, 229, 255, 0.16); color: #00e5ff; border: 1px solid #00e5ff; }
    .badge-INFO, .badge-LOW { background: rgba(148, 163, 184, 0.15); color: #cbd5e1; border: 1px solid #475569; }
    .mitre-tag {
      background: rgba(0, 255, 102, 0.12);
      color: var(--neon-green);
      border: 1px solid rgba(0, 255, 102, 0.4);
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.75rem;
      font-family: monospace;
    }

    /* Beacon Cards */
    .beacon-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(420px, 1fr));
      gap: 16px;
    }
    .beacon-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 18px;
    }
    .beacon-stats {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 10px;
      margin: 14px 0;
      background: rgba(7, 11, 20, 0.55);
      padding: 10px;
      border-radius: 6px;
    }
    .stat-mini span { display: block; font-size: 0.72rem; color: var(--text-muted); }
    .stat-mini strong { font-size: 1rem; color: #fff; }
    .sparkline {
      display: flex;
      align-items: flex-end;
      gap: 4px;
      height: 46px;
      padding-top: 8px;
      border-bottom: 1px solid var(--border);
    }
    .spark-bar {
      flex: 1;
      background: linear-gradient(180deg, var(--neon-pink), var(--neon-cyan));
      border-radius: 2px 2px 0 0;
      min-width: 6px;
      opacity: 0.88;
      transition: opacity 0.15s;
    }
    .spark-bar:hover { opacity: 1.0; background: var(--neon-green); }

    /* Tables & Filters */
    .filter-bar {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }
    input.search-input, select.filter-select {
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 8px 13px;
      border-radius: 6px;
      font-size: 0.88rem;
    }
    input.search-input { min-width: 260px; }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.86rem;
    }
    th, td {
      text-align: left;
      padding: 11px 12px;
      border-bottom: 1px solid var(--border);
    }
    th {
      background: rgba(21, 31, 56, 0.9);
      color: var(--neon-cyan);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.6px;
    }
    tr:hover td { background: rgba(255, 255, 255, 0.025); }
    footer {
      text-align: center;
      margin-top: 32px;
      font-size: 0.82rem;
      color: var(--text-muted);
    }
    footer a { color: var(--neon-green); text-decoration: none; }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <h1>📡 <span class="accent">BeaconHunter</span> // Network Forensics & C2 Threat Hunting</h1>
      <p>Statistical C2 Beaconing • DNS Tunneling & DGA Shannon Entropy • TLS JA3/JA3S Fingerprinting</p>
    </div>
    <div class="meta-box mono">
      <div>PCAP File: <strong>{{ report.pcap_path }}</strong></div>
      <div>SHA-256: <strong>{{ report.pcap_sha256[:24] }}...{{ report.pcap_sha256[-8:] }}</strong></div>
      <div>Analyzed UTC: <strong>{{ report.analysis_timestamp_utc }}</strong> ({{ report.total_packets }} pkts / {{ report.capture_duration_seconds }}s)</div>
    </div>
  </header>

  <!-- KPI Summary Row -->
  <div class="kpi-grid">
    <div class="kpi-card crit">
      <div class="kpi-label">Total Threat Alerts</div>
      <div class="kpi-val mono">{{ report.alerts | length }}</div>
      <div class="kpi-sub">Mapped to MITRE ATT&CK v14</div>
    </div>
    <div class="kpi-card crit">
      <div class="kpi-label">C2 Beaconing Channels</div>
      <div class="kpi-val mono">{{ report.beacons | length }}</div>
      <div class="kpi-sub">Periodic Heartbeat / Jitter Flows</div>
    </div>
    <div class="kpi-card warn">
      <div class="kpi-label">DNS Tunneling & DGA</div>
      <div class="kpi-val mono">{{ report.dns_findings | length }}</div>
      <div class="kpi-sub">High Shannon Entropy / DGA Spikes</div>
    </div>
    <div class="kpi-card ok">
      <div class="kpi-label">Malicious TLS JA3/JA3S</div>
      <div class="kpi-val mono">{{ malicious_ja3_count }} / {{ report.ja3_findings | length }}</div>
      <div class="kpi-sub">Encrypted C2 Handshake Matches</div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Suspicious Graph Nodes</div>
      <div class="kpi-val mono">{{ report.graph_nodes | length }}</div>
      <div class="kpi-sub">{{ report.graph_edges | length }} Active Threat Edges</div>
    </div>
  </div>

  <!-- 1. Interactive Suspicious Communication Topology Graph -->
  <div class="section-panel">
    <div class="section-header">
      <div class="section-title">🕸️ Interactive Suspicious Communication Topology Graph</div>
      <div class="mono" style="font-size: 0.8rem; color: var(--text-muted);">
        Drag nodes to rearrange • Click/Hover node to inspect forensic telemetry
      </div>
    </div>
    <div class="graph-wrapper">
      <canvas id="topologyCanvas" width="950" height="460"></canvas>
      <div class="graph-sidebar">
        <div>
          <h4 style="color: #fff; margin-bottom: 12px; font-size: 0.95rem;">Node Classification Legend</h4>
          <div class="legend-item"><span class="dot" style="background: #00e5ff;"></span> Compromised Internal Host</div>
          <div class="legend-item"><span class="dot" style="background: #ff0055;"></span> External C2 Server (Cobalt Strike / Sliver)</div>
          <div class="legend-item"><span class="dot" style="background: #ffaa00;"></span> DNS Exfiltration Tunnel Domain</div>
          <div class="legend-item"><span class="dot" style="background: #a855f7;"></span> DGA Algorithmic Domain Cluster</div>
          <div class="legend-item"><span class="dot" style="background: #00ff66;"></span> DNS Resolver / Gateway</div>
          <hr style="border: 0; border-top: 1px solid var(--border); margin: 14px 0;" />
          <div id="nodeInspector">
            <div style="font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase;">Selected Node Inspector</div>
            <div id="inspTitle" class="mono" style="font-size: 1rem; color: var(--neon-green); margin-top: 6px; font-weight: 700;">Hover or click any node</div>
            <div id="inspType" style="font-size: 0.83rem; color: var(--text-main); margin-top: 4px;">Interactive C2 & DNS Exfiltration map</div>
            <div id="inspDetails" style="font-size: 0.8rem; color: var(--text-muted); margin-top: 8px;">Animated particles indicate active C2 beacon heartbeat or data exfiltration direction.</div>
          </div>
        </div>
        <button onclick="resetGraphLayout()" style="background: #1e293b; color: var(--neon-cyan); border: 1px solid var(--neon-cyan); padding: 8px 12px; border-radius: 6px; cursor: pointer; font-weight: 600;">
          ⟳ Reset Force Graph Layout
        </button>
      </div>
    </div>
  </div>

  <!-- 2. Statistical C2 Beaconing Analysis -->
  <div class="section-panel">
    <div class="section-header">
      <div class="section-title">🎯 Statistical C2 Beaconing & Jitter Analysis</div>
      <span class="mitre-tag">MITRE ATT&CK: T1071.001 / T1571</span>
    </div>
    <div class="beacon-grid">
      {% for b in report.beacons %}
      <div class="beacon-card">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; gap: 8px;">
          <div>
            <span class="badge badge-{{ b.severity }}">{{ b.severity }}</span>
            <span class="mitre-tag">{{ b.mitre_technique_id }}</span>
            <h3 class="mono" style="font-size: 1rem; color: #fff; margin-top: 8px;">{{ b.src_ip }} ➔ {{ b.dst_ip }}:{{ b.dst_port }} ({{ b.protocol }})</h3>
            <div style="font-size: 0.84rem; color: var(--neon-green); margin-top: 2px;">{{ b.suspected_framework }}</div>
          </div>
          <div style="text-align: right;">
            <div style="font-size: 0.72rem; color: var(--text-muted);">BEACON SCORE</div>
            <div class="mono" style="font-size: 1.5rem; font-weight: 800; color: var(--neon-pink);">{{ b.periodicity_score }}%</div>
          </div>
        </div>

        <div class="beacon-stats mono">
          <div class="stat-mini"><span>Mean Sleep (μ)</span><strong>{{ b.mean_interval }}s</strong></div>
          <div class="stat-mini"><span>Jitter %</span><strong>{{ b.jitter_percent }}%</strong></div>
          <div class="stat-mini"><span>CV (σ/μ)</span><strong>{{ b.cv_ratio }}</strong></div>
          <div class="stat-mini"><span>MAD</span><strong>{{ b.mad_interval }}s</strong></div>
        </div>

        <div style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 4px;">
          Inter-Arrival Delta-t Heartbeat Distribution ({{ b.intervals | length }} intervals, SNI: <span class="mono" style="color: var(--neon-cyan);">{{ b.sni_or_host or 'Direct IP' }}</span>):
        </div>
        <div class="sparkline">
          {% for dt in b.intervals %}
          {% set height_pct = ((dt / (b.mean_interval * 1.4)) * 100) | round | int %}
          <div class="spark-bar" style="height: {{ [15, [height_pct, 100] | min] | max }}%;" title="Δt = {{ dt }}s"></div>
          {% endfor %}
        </div>
        {% if b.ja3_hash %}
        <div class="mono" style="font-size: 0.76rem; color: var(--text-muted); margin-top: 10px;">
          Correlated TLS Client JA3: <span style="color: var(--neon-amber);">{{ b.ja3_hash }}</span>
        </div>
        {% endif %}
      </div>
      {% endfor %}
    </div>
  </div>

  <!-- 3. DNS Forensics: Tunneling, Exfiltration & DGA -->
  <div class="section-panel">
    <div class="section-header">
      <div class="section-title">🧬 DNS Forensics: Shannon Entropy Tunneling & DGA Detection</div>
      <span class="mitre-tag">MITRE ATT&CK: T1071.004 / T1568.002 / T1048.003</span>
    </div>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Detection Type</th>
            <th>Source Host</th>
            <th>Target Domain / Cluster</th>
            <th>Queries (Unique)</th>
            <th>NXDOMAIN</th>
            <th>Shannon Entropy (Avg / Max)</th>
            <th>Detected Encoding / Pattern</th>
            <th>Sample Forensic Queries</th>
          </tr>
        </thead>
        <tbody>
          {% for d in report.dns_findings %}
          <tr>
            <td><span class="badge badge-{{ d.severity }}">{{ d.severity }}</span></td>
            <td class="mono">{{ d.finding_type }}<br/><span class="mitre-tag">{{ d.mitre_technique_id }}</span></td>
            <td class="mono" style="color: var(--neon-cyan);">{{ d.src_ip }}</td>
            <td class="mono" style="font-weight: 600;">{{ d.base_domain }}</td>
            <td class="mono">{{ d.query_count }} ({{ d.unique_subdomains }} uniq)</td>
            <td class="mono" style="color: var(--neon-pink);">{{ d.nxdomain_count }}</td>
            <td class="mono">
              <strong style="color: var(--neon-green);">{{ d.avg_shannon_entropy }}</strong> / {{ d.max_shannon_entropy }} bits
              {% if d.total_exfil_bytes_est > 0 %}
              <br/><span style="font-size: 0.75rem; color: var(--neon-amber);">~{{ d.total_exfil_bytes_est }}B exfiltrated</span>
              {% endif %}
            </td>
            <td>{{ d.encoding_detected }}</td>
            <td class="mono" style="font-size: 0.76rem; color: var(--text-muted); max-width: 340px; word-break: break-all;">
              {{ d.sample_queries[:3] | join('<br/>') | safe }}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- 4. TLS JA3 & JA3S Fingerprinting -->
  <div class="section-panel">
    <div class="section-header">
      <div class="section-title">🔐 TLS/SSL JA3 & JA3S Cryptographic Fingerprints</div>
      <span class="mitre-tag">MITRE ATT&CK: T1573.002</span>
    </div>
    <div style="overflow-x: auto;">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Type</th>
            <th>Source ➔ Destination</th>
            <th>SNI (Server Name)</th>
            <th>JA3 / JA3S MD5 Hash</th>
            <th>Malware / C2 Family</th>
            <th>Threat Intelligence Signature</th>
          </tr>
        </thead>
        <tbody>
          {% for j in report.ja3_findings %}
          <tr>
            <td><span class="badge badge-{{ j.severity }}">{{ j.severity }}</span></td>
            <td class="mono"><strong>{{ j.fingerprint_type }}</strong> ({{ j.tls_version_name }})</td>
            <td class="mono">{{ j.src_ip }}:{{ j.src_port }} ➔ {{ j.dst_ip }}:{{ j.dst_port }}</td>
            <td class="mono" style="color: var(--neon-cyan);">{{ j.sni }}</td>
            <td class="mono" style="color: var(--neon-amber);" title="{{ j.ja3_string }}">{{ j.ja3_hash }}</td>
            <td><strong>{{ j.malware_family }}</strong></td>
            <td>{{ j.matched_signature }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <!-- 5. Unified MITRE ATT&CK Threat Alerts Table with Live Filter -->
  <div class="section-panel">
    <div class="section-header">
      <div class="section-title">🚨 Unified Forensic Alert Timeline (MITRE ATT&CK v14)</div>
      <div class="filter-bar">
        <input type="text" id="alertSearch" class="search-input" placeholder="Search IP, domain, JA3 hash, technique..." oninput="filterAlerts()" />
        <select id="severityFilter" class="filter-select" onchange="filterAlerts()">
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">CRITICAL Only</option>
          <option value="HIGH">HIGH & Above</option>
        </select>
      </div>
    </div>
    <div style="overflow-x: auto;">
      <table id="alertsTable">
        <thead>
          <tr>
            <th>Alert ID</th>
            <th>Severity</th>
            <th>Category</th>
            <th>MITRE ATT&CK</th>
            <th>Source ➔ Target</th>
            <th>Indicator (IOC)</th>
            <th>Confidence</th>
            <th>Forensic Evidence Summary</th>
          </tr>
        </thead>
        <tbody>
          {% for a in report.alerts %}
          <tr data-severity="{{ a.severity }}">
            <td class="mono"><strong>{{ a.alert_id }}</strong></td>
            <td><span class="badge badge-{{ a.severity }}">{{ a.severity }}</span></td>
            <td class="mono">{{ a.category }}</td>
            <td><span class="mitre-tag">{{ a.mitre_technique_id }}</span><br/><small style="color: var(--text-muted);">{{ a.mitre_tactic }}</small></td>
            <td class="mono">{{ a.src_ip }} ➔ {{ a.dst_ip }}:{{ a.dst_port }}</td>
            <td class="mono" style="color: var(--neon-cyan);">{{ a.indicator }}</td>
            <td class="mono"><strong>{{ a.confidence }}%</strong></td>
            <td style="font-size: 0.82rem; color: var(--text-muted);">{{ a.evidence_summary }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  </div>

  <footer>
    Generated by <strong>BeaconHunter v1.0.0</strong> • Developed by <a href="https://github.com/Neidielli" target="_blank">Neidielli Rosado</a> • ISO/IEC 27037 & RFC 3227 Forensic Compliance
  </footer>

  <script>
    // Live Alert Filtering
    function filterAlerts() {
      const q = document.getElementById('alertSearch').value.toLowerCase();
      const sev = document.getElementById('severityFilter').value;
      const rows = document.querySelectorAll('#alertsTable tbody tr');
      rows.forEach(r => {
        const text = r.innerText.toLowerCase();
        const rSev = r.getAttribute('data-severity');
        const matchesQ = text.includes(q);
        let matchesSev = true;
        if (sev === 'CRITICAL') matchesSev = (rSev === 'CRITICAL');
        if (sev === 'HIGH') matchesSev = (rSev === 'CRITICAL' || rSev === 'HIGH');
        r.style.display = (matchesQ && matchesSev) ? '' : 'none';
      });
    }

    // Interactive Force-Directed Topology Graph on HTML5 Canvas
    const rawNodes = {{ graph_nodes_json | safe }};
    const rawEdges = {{ graph_edges_json | safe }};

    const canvas = document.getElementById('topologyCanvas');
    const ctx = canvas.getContext('2d');
    let width = canvas.width;
    let height = canvas.height;

    const NODE_COLORS = {
      'INTERNAL_HOST': '#00e5ff',
      'C2_SERVER': '#ff0055',
      'EXFIL_DOMAIN': '#ffaa00',
      'DGA_DOMAIN': '#a855f7',
      'DNS_SERVER': '#00ff66',
      'EXTERNAL_HOST': '#94a3b8'
    };

    let nodes = [];
    let edges = [];
    let particles = [];

    function initGraph() {
      const cx = width / 2;
      const cy = height / 2;
      nodes = rawNodes.map((n, idx) => {
        const angle = (2 * Math.PI * idx) / Math.max(1, rawNodes.length);
        const radius = n.node_type === 'INTERNAL_HOST' ? 95 : 175;
        return {
          ...n,
          x: cx + Math.cos(angle) * radius,
          y: cy + Math.sin(angle) * radius,
          vx: 0,
          vy: 0,
          r: n.node_type === 'C2_SERVER' || n.node_type === 'INTERNAL_HOST' ? 22 : 18
        };
      });

      const nodeById = {};
      nodes.forEach(n => nodeById[n.node_id] = n);

      edges = rawEdges.map(e => ({
        ...e,
        sourceNode: nodeById[e.source],
        targetNode: nodeById[e.target]
      })).filter(e => e.sourceNode && e.targetNode);

      particles = [];
      edges.forEach(e => {
        particles.push({ edge: e, t: Math.random(), speed: 0.006 + Math.random() * 0.005 });
        particles.push({ edge: e, t: (Math.random() + 0.5) % 1.0, speed: 0.006 + Math.random() * 0.005 });
      });
    }

    function resetGraphLayout() {
      initGraph();
    }

    let draggedNode = null;
    let hoveredNode = null;

    function getMousePos(evt) {
      const rect = canvas.getBoundingClientRect();
      const scaleX = canvas.width / rect.width;
      const scaleY = canvas.height / rect.height;
      return {
        x: (evt.clientX - rect.left) * scaleX,
        y: (evt.clientY - rect.top) * scaleY
      };
    }

    canvas.addEventListener('mousedown', evt => {
      const pos = getMousePos(evt);
      for (const n of nodes) {
        const dx = pos.x - n.x;
        const dy = pos.y - n.y;
        if (Math.sqrt(dx * dx + dy * dy) <= n.r + 6) {
          draggedNode = n;
          updateInspector(n);
          break;
        }
      }
    });

    canvas.addEventListener('mousemove', evt => {
      const pos = getMousePos(evt);
      if (draggedNode) {
        draggedNode.x = Math.max(40, Math.min(width - 40, pos.x));
        draggedNode.y = Math.max(40, Math.min(height - 40, pos.y));
        return;
      }
      hoveredNode = null;
      for (const n of nodes) {
        const dx = pos.x - n.x;
        const dy = pos.y - n.y;
        if (Math.sqrt(dx * dx + dy * dy) <= n.r + 6) {
          hoveredNode = n;
          updateInspector(n);
          break;
        }
      }
    });

    window.addEventListener('mouseup', () => { draggedNode = null; });

    function updateInspector(n) {
      document.getElementById('inspTitle').innerText = n.label.replace('\\n', ' ');
      document.getElementById('inspType').innerHTML =
        `Type: <strong>${n.node_type}</strong> | Severity: <span class="badge badge-${n.severity}">${n.severity}</span> | Risk: <strong>${n.risk_score}/100</strong>`;
      document.getElementById('inspDetails').innerText =
        `Alerts: ${n.alerts_count} | Volume: ${n.total_bytes} bytes | Forensic Notes: ${n.details}`;
    }

    function stepPhysics() {
      // Gentle repulsion between nodes
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i];
          const b = nodes[j];
          let dx = b.x - a.x;
          let dy = b.y - a.y;
          let dist = Math.sqrt(dx * dx + dy * dy) || 1;
          if (dist < 170) {
            const force = (170 - dist) * 0.015;
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            if (a !== draggedNode) { a.x -= fx; a.y -= fy; }
            if (b !== draggedNode) { b.x += fx; b.y += fy; }
          }
        }
      }
      // Keep inside bounds
      for (const n of nodes) {
        n.x = Math.max(60, Math.min(width - 60, n.x));
        n.y = Math.max(50, Math.min(height - 50, n.y));
      }
    }

    function drawGraph() {
      ctx.clearRect(0, 0, width, height);
      stepPhysics();

      // Draw edges
      edges.forEach(e => {
        const s = e.sourceNode;
        const t = e.targetNode;
        ctx.beginPath();
        ctx.moveTo(s.x, s.y);
        ctx.lineTo(t.x, t.y);
        ctx.strokeStyle = e.severity === 'CRITICAL' ? 'rgba(255, 0, 85, 0.55)' : 'rgba(0, 229, 255, 0.45)';
        ctx.lineWidth = 2;
        ctx.stroke();

        // Edge relationship label at midpoint
        const mx = (s.x + t.x) / 2;
        const my = (s.y + t.y) / 2;
        ctx.fillStyle = '#94a3b8';
        ctx.font = '11px Consolas, monospace';
        ctx.textAlign = 'center';
        ctx.fillText(e.relationship, mx, my - 6);
      });

      // Draw animated C2 / Exfil particles
      particles.forEach(p => {
        p.t = (p.t + p.speed) % 1.0;
        const s = p.edge.sourceNode;
        const t = p.edge.targetNode;
        const px = s.x + (t.x - s.x) * p.t;
        const py = s.y + (t.y - s.y) * p.t;
        ctx.beginPath();
        ctx.arc(px, py, 3.5, 0, Math.PI * 2);
        ctx.fillStyle = p.edge.severity === 'CRITICAL' ? '#ff0055' : '#00ff66';
        ctx.fill();
      });

      // Draw nodes
      nodes.forEach(n => {
        const color = NODE_COLORS[n.node_type] || '#00e5ff';
        ctx.save();
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r + 5, 0, Math.PI * 2);
        ctx.fillStyle = color + '22';
        ctx.fill();

        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fillStyle = '#0f172a';
        ctx.fill();
        ctx.lineWidth = (hoveredNode === n || draggedNode === n) ? 3.5 : 2.2;
        ctx.strokeStyle = color;
        ctx.stroke();

        // Node label
        ctx.fillStyle = '#f8fafc';
        ctx.font = 'bold 11.5px Consolas, monospace';
        ctx.textAlign = 'center';
        const lines = n.label.split('\\n');
        lines.forEach((line, idx) => {
          ctx.fillText(line, n.x, n.y + n.r + 15 + idx * 13);
        });
        ctx.restore();
      });

      requestAnimationFrame(drawGraph);
    }

    initGraph();
    requestAnimationFrame(drawGraph);
  </script>
</body>
</html>
"""


def generate_html_dashboard(
    report: ForensicAnalysisReport, output_path: Path
) -> Path:
    """Renders the standalone HTML5 Threat Hunting Dashboard."""
    output_path = Path(output_path).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    template = Template(DASHBOARD_HTML_TEMPLATE)
    malicious_ja3_count = sum(1 for j in report.ja3_findings if j.is_malicious)

    html_content = template.render(
        report=report,
        malicious_ja3_count=malicious_ja3_count,
        graph_nodes_json=json.dumps([asdict(n) for n in report.graph_nodes]),
        graph_edges_json=json.dumps([asdict(e) for e in report.graph_edges]),
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path
