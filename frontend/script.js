/* ──────────────────────────────────────────────────────────────
   ARP Spoofing Virtual Lab — script.js
   Plain ES2020, no frameworks, no build step.
   Talks to backend at API_BASE_URL (port 8000 by default).
   ────────────────────────────────────────────────────────────── */

'use strict';

/* ─── Config ───────────────────────────────────────────────── */
const API_BASE_URL = (window.LAB_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');
const WS_BASE_URL  = API_BASE_URL.replace(/^http/, 'ws');

/* ─── Dynamic MACs learned from backend/network ────────────── */
const realMacs = {
  victim:   '',
  gateway:  '',
  attacker: '',
};

/* ─── Node metadata in SVG (680 × 430 viewBox) ─────────────── */
const NODES = [
  { key: 'victim',   label: 'Victim Target',    ip: '10.10.10.10', x: 125, y: 112 },
  { key: 'gateway',  label: 'Default Gateway',  ip: '10.10.10.1',  x: 555, y: 112 },
  { key: 'attacker', label: 'Attacker Machine', ip: '10.10.10.66', x: 340, y: 327 },
];

/* ─── Application state ─────────────────────────────────────── */
const state = {
  activeTab:    'Simulation',
  socketStatus: 'connecting',   // 'connecting' | 'connected' | 'disconnected'
  labRunning:   false,
  attackActive: false,
  attackMode:   'mitm',
  mitigationOn: false,
  events:       [],             // last 200 LabEvents
  arpTables:    { victim: {}, gateway: {}, attacker: {} }, // node -> { ip: mac }
  realMacs:     { victim: '', gateway: '', attacker: '' },
  pending:      '',             // path of in-flight request
  quizIndex:    0,
  quizAnswer:   null,           // null | number
  quizScore:    0,
  feedbackRating: 0,
  feedbackSubmitted: false,
  controlsOpen: true,
  logOpen:      true,
};

/* ─── Tabs & module icons ───────────────────────────────────── */
const TABS = ['Aim', 'Objective', 'Theory', 'Procedure', 'Simulation', 'Assignment', 'References', 'Feedback'];
const MODULE_ICONS = {
  Aim: 'AI', Objective: 'OB', Theory: 'TH', Procedure: 'PR',
  Simulation: 'SI', Assignment: 'AS', References: 'RE', Feedback: 'FB',
};

/* ─── Quiz data (all 10 questions from content/quiz.json) ───── */
const QUIZ = [
  {
    question: "Which protocol is responsible for resolving an IP address to a MAC address on a local area network?",
    options: [
      "DNS (Domain Name System)",
      "ARP (Address Resolution Protocol)",
      "DHCP (Dynamic Host Configuration Protocol)",
      "ICMP (Internet Control Message Protocol)"
    ],
    correctIndex: 1,
    explanation: "ARP (Address Resolution Protocol) operates at the Layer 2/3 boundary and resolves IP addresses to MAC addresses on a local network segment. DNS resolves hostnames to IPs; DHCP assigns IP configurations; ICMP handles error reporting and diagnostics."
  },
  {
    question: "At which OSI layer does ARP Cache Poisoning primarily operate?",
    options: [
      "Layer 3 — Network",
      "Layer 4 — Transport",
      "Layer 2 — Data Link",
      "Layer 7 — Application"
    ],
    correctIndex: 2,
    explanation: "ARP poisoning is a Layer 2 (Data Link) attack because it manipulates MAC-address-to-IP mappings used by the Ethernet/switching layer. It exploits the lack of authentication in the ARP protocol, which lives at the Data Link layer boundary."
  },
  {
    question: "What is a Gratuitous ARP?",
    options: [
      "An ARP Request broadcasted when a device first joins the network",
      "An ARP Reply sent without a preceding ARP Request, announcing a device's own IP-to-MAC mapping",
      "A special ARP message used only by routers to maintain routing tables",
      "An encrypted ARP packet used in secure networks"
    ],
    correctIndex: 1,
    explanation: "A Gratuitous ARP is an ARP Reply sent unprompted — without any preceding ARP Request. Devices use it legitimately to detect IP conflicts or announce a MAC address change. Attackers exploit it to silently overwrite other devices' ARP caches."
  },
  {
    question: "Why is the ARP protocol inherently vulnerable to spoofing attacks?",
    options: [
      "ARP packets are too large for typical network buffers",
      "ARP uses UDP which is unreliable",
      "ARP has no cryptographic authentication; any device can claim any IP-to-MAC mapping",
      "ARP entries are stored permanently and can never be updated"
    ],
    correctIndex: 2,
    explanation: "ARP was designed in 1982 for trusted small LANs and includes no authentication mechanism. Any host on the network can broadcast an ARP Reply claiming any IP address, and all other hosts will accept and cache the mapping without verification."
  },
  {
    question: "Scenario: You examine the ARP table on a victim machine (10.10.10.10) and find that both 10.10.10.1 (gateway) and 10.10.10.66 (attacker) resolve to the same MAC address. What has most likely happened?",
    options: [
      "The gateway and attacker share a network interface (normal behavior)",
      "The victim has manually configured a static ARP entry",
      "An ARP Cache Poisoning attack has caused the attacker's MAC to be associated with the gateway's IP",
      "The DHCP server assigned the same IP to two devices"
    ],
    correctIndex: 2,
    explanation: "When two different IP addresses resolve to the same MAC address in an ARP table, it strongly indicates ARP poisoning. The attacker sent forged ARP Replies claiming to be the gateway, so the victim's traffic destined for 10.10.10.1 is now delivered to the attacker's NIC."
  },
  {
    question: "In a Man-in-the-Middle ARP attack, what must the attacker do to avoid disrupting the victim's connectivity while intercepting traffic?",
    options: [
      "Disable the victim's network interface",
      "Enable IP forwarding on the attacker's machine so intercepted packets are relayed to the real destination",
      "Block all ARP traffic on the network segment",
      "Assign itself the gateway's IP address permanently"
    ],
    correctIndex: 1,
    explanation: "In MITM mode, the attacker enables IP forwarding. Packets from the victim arrive at the attacker's NIC (because the victim's ARP cache says the gateway's IP = attacker's MAC), the attacker inspects or modifies them, then forwards them to the real gateway — keeping the connection alive while performing interception."
  },
  {
    question: "Scenario: After an ARP poisoning attack begins, the victim can no longer reach any external websites, and all pings to the gateway time out. The attacker's machine is NOT forwarding any packets. What type of attack is this?",
    options: [
      "Man-in-the-Middle (MITM) attack",
      "Denial of Service (DoS) via ARP poisoning",
      "DNS Hijacking",
      "Port Scan"
    ],
    correctIndex: 1,
    explanation: "When an ARP poisoning attack is configured with IP forwarding disabled (or packets actively dropped), the victim's traffic is redirected to the attacker but never forwarded to the real gateway. This results in a Denial of Service — the victim loses all network connectivity — rather than silent interception."
  },
  {
    question: "Which defensive technique involves a managed switch validating ARP packets against a trusted DHCP binding table and dropping those that don't match?",
    options: [
      "Static ARP entries",
      "Port Security",
      "Dynamic ARP Inspection (DAI)",
      "802.1X Network Access Control"
    ],
    correctIndex: 2,
    explanation: "Dynamic ARP Inspection (DAI) is a Cisco/managed-switch feature that inspects every ARP packet on untrusted switch ports. It cross-references the claimed IP-MAC pair against the DHCP Snooping Binding Table. Mismatches are dropped and logged, effectively preventing ARP poisoning at the switch level."
  },
  {
    question: "An attacker successfully executes an ARP Cache Poisoning MITM attack and intercepts all traffic between a victim and their bank's website. The bank uses HTTPS with a valid TLS certificate. What data can the attacker realistically read?",
    options: [
      "Full plaintext usernames, passwords, and account numbers",
      "Only the victim's IP and MAC address",
      "Only the hostname of the bank's website (via SNI) and encrypted ciphertext — not the payload content",
      "Nothing at all, since ARP operates below the network layer"
    ],
    correctIndex: 2,
    explanation: "HTTPS/TLS encrypts the payload end-to-end. Even positioned in-path via ARP poisoning, the attacker only sees encrypted ciphertext and possibly the Server Name Indication (SNI) field in the TLS handshake. Without the server's private key, the attacker cannot decrypt the content."
  },
  {
    question: "How does adding a static ARP entry on the victim protect against ARP Cache Poisoning?",
    options: [
      "It encrypts all ARP traffic leaving the victim",
      "It permanently binds an IP address to a specific MAC in the victim's ARP table, so incoming forged ARP Replies cannot overwrite it",
      "It prevents the victim from receiving any ARP broadcast packets",
      "It notifies the network administrator whenever an ARP Reply is received"
    ],
    correctIndex: 1,
    explanation: "A static ARP entry is a manually configured, permanent IP-to-MAC binding that the operating system treats as authoritative. Unlike dynamic entries, static entries are not overwritten when forged ARP Replies arrive, making ARP poisoning ineffective for those specific entries."
  }
];

/* ─── DOM helpers ───────────────────────────────────────────── */
const $  = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

/* ─── Toast notifications ───────────────────────────────────── */
function showToast(msg, type = 'success') {
  const container = $('#toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3100);
}

/* ─── Fetch full state snapshot from backend ───────────────── */
async function fetchState() {
  try {
    const res = await fetch(`${API_BASE_URL}/api/state`);
    if (!res.ok) return;
    const data = await res.json();
    state.labRunning = Boolean(data.lab_running);
    state.attackActive = Boolean(data.attack_active);
    if (data.attack_mode) state.attackMode = data.attack_mode;
    state.mitigationOn = Boolean(data.mitigation_enabled);
    if (data.real_macs) {
      state.realMacs = { ...state.realMacs, ...data.real_macs };
    }
    if (data.arp_tables) {
      for (const node of ['victim', 'gateway', 'attacker']) {
        if (data.arp_tables[node]) {
          if (!state.arpTables[node]) state.arpTables[node] = {};
          for (const entry of data.arp_tables[node]) {
            state.arpTables[node][entry.ip] = (entry.mac || '').toLowerCase();
          }
        }
      }
    }
    const mitInput = $('#mitigation-toggle');
    if (mitInput) mitInput.checked = state.mitigationOn;
    const modeSelect = $('#attack-mode-select');
    if (modeSelect && state.attackMode) modeSelect.value = state.attackMode;
    renderLabStatus();
    renderDiagram();
  } catch {
    /* Backend offline or file:// */
  }
}

/* ─── API calls ─────────────────────────────────────────────── */
async function callApi(path, body) {
  if (state.pending) return;
  state.pending = path;
  renderButtons();
  try {
    const opts = { method: 'POST' };
    if (body) {
      opts.headers = { 'Content-Type': 'application/json' };
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(`${API_BASE_URL}${path}`, opts);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    showToast('Command executed successfully', 'success');

    if (path === '/api/lab/start') state.labRunning = true;
    if (path === '/api/lab/stop') { state.labRunning = false; state.attackActive = false; }
    if (path === '/api/lab/reset') { state.labRunning = true; state.attackActive = false; state.mitigationOn = false; }
    if (path === '/api/attack/start') state.attackActive = true;
    if (path === '/api/attack/stop') state.attackActive = false;
    if (path === '/api/mitigation/toggle') state.mitigationOn = Boolean(body?.enabled);

    await fetchState();
  } catch (err) {
    showToast(`Backend command failed — ${err.message || 'could not reach API'}`, 'error');
  } finally {
    state.pending = '';
    renderButtons();
    renderLabStatus();
  }
}

/* ─── WebSocket with exponential backoff ────────────────────── */
let _ws        = null;
let _wsAttempt = 0;
let _wsTimer   = null;

function connectWs() {
  state.socketStatus = 'connecting';
  renderWsStatus();

  _ws = new WebSocket(`${WS_BASE_URL}/ws/logs`);

  _ws.onopen = () => {
    _wsAttempt = 0;
    state.socketStatus = 'connected';
    renderWsStatus();
    renderAlert();
    fetchState();
  };

  _ws.onmessage = (msg) => {
    try {
      const event = JSON.parse(msg.data);
      state.events = [...state.events.slice(-199), event];
      if (event.type === 'arp_update') {
        if (!state.arpTables[event.node]) state.arpTables[event.node] = {};
        state.arpTables[event.node][event.ip] = (event.mac || '').toLowerCase();
        renderDiagram();
      } else if (event.type === 'attack_state') {
        state.attackActive = Boolean(event.active);
        if (event.mode) state.attackMode = event.mode;
        renderLabStatus();
        renderDiagram();
        renderLog();
      } else if (event.type === 'mitigation_state') {
        state.mitigationOn = Boolean(event.enabled);
        const mitInput = $('#mitigation-toggle');
        if (mitInput) mitInput.checked = state.mitigationOn;
        renderLabStatus();
        renderDiagram();
        renderLog();
      } else if (event.type === 'log') {
        renderLog();
      }
      renderLabStatus();
    } catch { /* ignore malformed */ }
  };

  _ws.onerror = () => _ws.close();

  _ws.onclose = () => {
    state.socketStatus = 'disconnected';
    renderWsStatus();
    renderAlert();
    const delay = Math.min(30000, 1000 * 2 ** _wsAttempt++);
    _wsTimer = setTimeout(connectWs, delay);
  };
}

/* ─── Derived state helpers ─────────────────────────────────── */
function getLabStatus() {
  if (state.attackActive) {
    return 'Under Attack';
  }
  if (!state.labRunning) {
    return 'Stopped';
  }
  if (state.mitigationOn) {
    return 'Running — Protected';
  }
  return 'Running — Vulnerable';
}

/* ─────────────────────────────────────────────────────────────
   RENDER FUNCTIONS
   ───────────────────────────────────────────────────────────── */

/* Tab switching */
function renderTabs() {
  $$('.tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.tab === state.activeTab);
  });
  $$('.tab-panel').forEach(panel => {
    panel.classList.toggle('active', panel.id === `panel-${state.activeTab}`);
  });
  /* sync module-cards in sidebar */
  $$('.module-card').forEach(card => {
    card.classList.toggle('active', card.dataset.tab === state.activeTab);
  });
}

/* WS connection badge */
function renderWsStatus() {
  const dot  = $('#ws-dot');
  const text = $('#ws-text');
  if (!dot || !text) return;
  dot.style.background = state.socketStatus === 'connected' ? '#2A8C76' : '#E06C62';
  text.textContent = state.socketStatus;
}

/* Lab status badge */
function renderLabStatus() {
  const el = $('#lab-status-text');
  if (el) el.textContent = getLabStatus();
}

/* Alert banner */
function renderAlert() {
  const el = $('#sim-alert');
  if (!el) return;
  const connected = state.socketStatus === 'connected';
  const icon = el.querySelector('.alert-icon');
  const text = el.querySelector('.alert-text');
  if (icon) icon.textContent = connected ? '🛡' : '📡';
  if (text) text.textContent = connected
    ? 'Backend connected — live events enabled.'
    : 'Backend not connected — retrying in the background.';
}

/* Buttons: disabled state when pending */
function renderButtons() {
  $$('[data-api]').forEach(btn => {
    btn.disabled = !!state.pending;
    const spinner = btn.querySelector('.spinner');
    if (spinner) spinner.style.display = (state.pending === btn.dataset.api) ? 'inline-block' : 'none';
  });
}

/* Helper to safely set dynamic SVG content while maintaining proper SVG namespace */
function setSvgContent(svg, markup) {
  let layer = $('#topology-dynamic-layer', svg);
  if (!layer) {
    layer = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    layer.id = 'topology-dynamic-layer';
    svg.appendChild(layer);
  }
  layer.innerHTML = markup;
}

/* SVG topology diagram with animated packet flows and dynamic attack mechanics */
function renderDiagram() {
  const svg = $('#topology-svg');
  if (!svg) return;

  const attackerMac = (state.realMacs.attacker || '').toLowerCase();
  const gatewayRealMac = (state.realMacs.gateway || '').toLowerCase();
  const victimRealMac = (state.realMacs.victim || '').toLowerCase();

  const victimGwMac = state.arpTables.victim?.['10.10.10.1'] || '';
  const gwVictimMac = state.arpTables.gateway?.['10.10.10.10'] || '';

  let isVictimPoisoned = false;
  if (victimGwMac) {
    const norm = victimGwMac.toLowerCase();
    if (attackerMac && norm === attackerMac) isVictimPoisoned = true;
    else if (gatewayRealMac && norm !== gatewayRealMac) isVictimPoisoned = true;
  }

  let isGwPoisoned = false;
  if (gwVictimMac) {
    const norm = gwVictimMac.toLowerCase();
    if (attackerMac && norm === attackerMac) isGwPoisoned = true;
    else if (victimRealMac && norm !== victimRealMac) isGwPoisoned = true;
  }

  const isAttacking = state.attackActive;
  const isMitigated = state.mitigationOn;
  const attackMode = state.attackMode || 'mitm';
  const isMitm = attackMode === 'mitm';
  const isDos = attackMode === 'dos';

  // Node styles
  const vBorder = isMitigated ? '#2563EB' : (isVictimPoisoned ? '#E06C62' : '#2A8C76');
  const vBg = isMitigated ? '#EFF6FF' : (isVictimPoisoned ? '#FEF2F2' : '#F4FAF8');
  const vBadgeText = isMitigated ? '🛡️ Protected (Static)' : (isVictimPoisoned ? '⚠️ POISONED!' : '✓ Authentic Gateway');
  const vBadgeBg = isMitigated ? '#DBEAFE' : (isVictimPoisoned ? '#FEE2E2' : '#E8F5F1');
  const vBadgeColor = isMitigated ? '#1D4ED8' : (isVictimPoisoned ? '#B91C1C' : '#1B6554');
  const vClass = isVictimPoisoned && !isMitigated ? 'node-poison-pulse' : (isMitigated ? 'node-shield-pulse' : '');

  const gBorder = isMitigated ? '#2563EB' : (isGwPoisoned ? '#E06C62' : '#2A8C76');
  const gBg = isMitigated ? '#EFF6FF' : (isGwPoisoned ? '#FEF2F2' : '#F4FAF8');
  const gBadgeText = isMitigated ? '🛡️ Protected (Static)' : (isGwPoisoned ? '⚠️ POISONED!' : '✓ Authentic Victim');
  const gBadgeBg = isMitigated ? '#DBEAFE' : (isGwPoisoned ? '#FEE2E2' : '#E8F5F1');
  const gBadgeColor = isMitigated ? '#1D4ED8' : (isGwPoisoned ? '#B91C1C' : '#1B6554');
  const gClass = isGwPoisoned && !isMitigated ? 'node-poison-pulse' : (isMitigated ? 'node-shield-pulse' : '');

  const aBorder = isAttacking ? '#E06C62' : '#64748B';
  const aBg = isAttacking ? '#FEF2F2' : '#F8FAFC';
  const aBadgeText = !isAttacking ? '💤 Standby / Idle' : (isMitm ? '⚡ MITM: Relaying (ip_forward=1)' : '🚫 DoS: Dropping (ip_forward=0)');
  const aBadgeBg = !isAttacking ? '#F1F5F9' : (isMitm ? '#FEF3C7' : '#FEE2E2');
  const aBadgeColor = !isAttacking ? '#475569' : (isMitm ? '#B45309' : '#B91C1C');
  const aClass = isAttacking ? 'node-poison-pulse' : '';

  let markup = `
    <!-- Background Grid -->
    <rect width="680" height="430" rx="14" fill="#FDFBF9" />

    <!-- ── Direct Communication Channel (Victim ↔ Gateway) ── -->
  `;

  if (!isVictimPoisoned && !isGwPoisoned) {
    markup += `
      <g>
        <line x1="215" y1="112" x2="465" y2="112" stroke="#2A8C76" stroke-width="3" />
        <circle r="5" fill="#10B981" filter="url(#packetGlow)">
          <animateMotion path="M 215 106 L 465 106" dur="2s" repeatCount="indefinite" />
        </circle>
        <circle r="5" fill="#06B6D4" filter="url(#packetGlow)">
          <animateMotion path="M 465 118 L 215 118" dur="2s" begin="1s" repeatCount="indefinite" />
        </circle>
        <rect x="250" y="99" width="180" height="26" rx="13" fill="#FFFFFF" stroke="#2A8C76" stroke-width="1.5" />
        <text x="340" y="116" text-anchor="middle" font-size="10" font-weight="700" fill="#1B6554" font-family="'Noto Sans', sans-serif">Direct IP/ICMP Traffic</text>
      </g>
    `;
  } else {
    if (isMitigated) {
      markup += `
        <g>
          <line x1="215" y1="112" x2="465" y2="112" stroke="#2563EB" stroke-width="3" />
          <circle r="5" fill="#3B82F6" filter="url(#packetGlow)">
            <animateMotion path="M 215 106 L 465 106" dur="2s" repeatCount="indefinite" />
          </circle>
          <circle r="5" fill="#60A5FA" filter="url(#packetGlow)">
            <animateMotion path="M 465 118 L 215 118" dur="2s" begin="1s" repeatCount="indefinite" />
          </circle>
          <rect x="245" y="99" width="190" height="26" rx="13" fill="#EFF6FF" stroke="#2563EB" stroke-width="1.5" />
          <text x="340" y="116" text-anchor="middle" font-size="10" font-weight="700" fill="#1D4ED8" font-family="'Noto Sans', sans-serif">🛡️ Protected Direct Traffic</text>
        </g>
      `;
    } else if (isMitm) {
      markup += `
        <g>
          <line x1="215" y1="112" x2="465" y2="112" stroke="#CBD5E1" stroke-width="2" stroke-dasharray="5 5" />
          <rect x="230" y="99" width="220" height="26" rx="13" fill="#FFFBEB" stroke="#F59E0B" stroke-width="1.5" />
          <text x="340" y="116" text-anchor="middle" font-size="9.5" font-weight="700" fill="#B45309" font-family="'Noto Sans', sans-serif">Direct Path Severed (Traffic Diverted)</text>
        </g>
      `;
    } else {
      markup += `
        <g>
          <line x1="215" y1="112" x2="465" y2="112" stroke="#FCA5A5" stroke-width="2" stroke-dasharray="5 5" />
          <rect x="230" y="99" width="220" height="26" rx="13" fill="#FEF2F2" stroke="#EF4444" stroke-width="1.5" />
          <text x="340" y="116" text-anchor="middle" font-size="9.5" font-weight="700" fill="#B91C1C" font-family="'Noto Sans', sans-serif">❌ Connection Timed Out (Blackholed)</text>
        </g>
      `;
    }
  }

  // ── Poisoning Attacks (Attacker ➔ Victim & Attacker ➔ Gateway) ──
  if (isAttacking) {
    if (!isMitigated) {
      markup += `
        <!-- Left Poisoning Curve (Attacker -> Victim) -->
        <g>
          <path d="M 280 260 Q 200 220 165 180" fill="none" stroke="#E06C62" stroke-width="2.5" stroke-dasharray="6 5" class="flow-dash-fast" marker-end="url(#coral-arrow)" />
          <circle r="5" fill="#EF4444" filter="url(#packetGlow)">
            <animateMotion path="M 280 260 Q 200 220 165 180" dur="1.2s" repeatCount="indefinite" />
          </circle>
          <rect x="120" y="198" width="168" height="20" rx="10" fill="#FEF2F2" stroke="#E06C62" stroke-width="1" />
          <text x="204" y="212" text-anchor="middle" font-size="8" font-weight="700" fill="#B91C1C" font-family="'JetBrains Mono', monospace">⚡ Forged ARP: 10.10.10.1=Attacker</text>
        </g>

        <!-- Right Poisoning Curve (Attacker -> Gateway) -->
        <g>
          <path d="M 400 260 Q 480 220 515 180" fill="none" stroke="#E06C62" stroke-width="2.5" stroke-dasharray="6 5" class="flow-dash-fast" marker-end="url(#coral-arrow)" />
          <circle r="5" fill="#EF4444" filter="url(#packetGlow)">
            <animateMotion path="M 400 260 Q 480 220 515 180" dur="1.2s" repeatCount="indefinite" />
          </circle>
          <rect x="392" y="198" width="168" height="20" rx="10" fill="#FEF2F2" stroke="#E06C62" stroke-width="1" />
          <text x="476" y="212" text-anchor="middle" font-size="8" font-weight="700" fill="#B91C1C" font-family="'JetBrains Mono', monospace">⚡ Forged ARP: 10.10.10.10=Attacker</text>
        </g>
      `;
    } else {
      markup += `
        <!-- Left Poisoning Curve Deflected -->
        <g>
          <path d="M 280 260 Q 200 220 175 195" fill="none" stroke="#E06C62" stroke-width="1.8" stroke-dasharray="4 4" opacity="0.5" />
          <g transform="translate(145, 182)">
            <circle cx="12" cy="12" r="14" fill="#DBEAFE" stroke="#2563EB" stroke-width="2" class="node-shield-pulse" />
            <text x="12" y="17" text-anchor="middle" font-size="12">🛡️</text>
            <rect x="-35" y="28" width="94" height="18" rx="9" fill="#EFF6FF" stroke="#2563EB" stroke-width="0.8" />
            <text x="12" y="40" text-anchor="middle" font-size="7.5" font-weight="700" fill="#1D4ED8" font-family="'Noto Sans', sans-serif">Static ARP Blocked</text>
          </g>
        </g>

        <!-- Right Poisoning Curve Deflected -->
        <g>
          <path d="M 400 260 Q 480 220 505 195" fill="none" stroke="#E06C62" stroke-width="1.8" stroke-dasharray="4 4" opacity="0.5" />
          <g transform="translate(515, 182)">
            <circle cx="12" cy="12" r="14" fill="#DBEAFE" stroke="#2563EB" stroke-width="2" class="node-shield-pulse" />
            <text x="12" y="17" text-anchor="middle" font-size="12">🛡️</text>
            <rect x="-35" y="28" width="94" height="18" rx="9" fill="#EFF6FF" stroke="#2563EB" stroke-width="0.8" />
            <text x="12" y="40" text-anchor="middle" font-size="7.5" font-weight="700" fill="#1D4ED8" font-family="'Noto Sans', sans-serif">Static ARP Blocked</text>
          </g>
        </g>
      `;
    }
  }

  // ── Hijacked Traffic Flows ──
  if (isVictimPoisoned && !isMitigated) {
    markup += `
      <!-- Intercepted Frame: Victim -> Attacker -->
      <g>
        <path d="M 100 180 Q 95 280 230 320" fill="none" stroke="#F59E0B" stroke-width="2.8" stroke-dasharray="7 5" class="flow-dash" marker-end="url(#amber-arrow)" />
        <circle r="5.5" fill="#F59E0B" filter="url(#packetGlow)">
          <animateMotion path="M 100 180 Q 95 280 230 320" dur="1.5s" repeatCount="indefinite" />
        </circle>
        <rect x="25" y="248" width="185" height="20" rx="10" fill="#FEF3C7" stroke="#F59E0B" stroke-width="1" />
        <text x="117" y="262" text-anchor="middle" font-size="8" font-weight="700" fill="#92400E" font-family="'Noto Sans', sans-serif">① Intercepted Frame (Dst MAC=Attacker)</text>
      </g>
    `;

    if (isMitm) {
      markup += `
        <!-- Relayed Frame: Attacker -> Gateway -->
        <g>
          <path d="M 450 320 Q 585 280 580 180" fill="none" stroke="#8B5CF6" stroke-width="2.8" stroke-dasharray="7 5" class="flow-dash" marker-end="url(#purple-arrow)" />
          <circle r="5.5" fill="#8B5CF6" filter="url(#packetGlow)">
            <animateMotion path="M 450 320 Q 585 280 580 180" dur="1.5s" begin="0.3s" repeatCount="indefinite" />
          </circle>
          <rect x="470" y="248" width="185" height="20" rx="10" fill="#EDE9FE" stroke="#8B5CF6" stroke-width="1" />
          <text x="562" y="262" text-anchor="middle" font-size="8" font-weight="700" fill="#5B21B6" font-family="'Noto Sans', sans-serif">② Relayed to Gateway (ip_forward=1)</text>
        </g>
      `;
    } else if (isDos) {
      markup += `
        <!-- Blackhole Drop Zone at Attacker -->
        <g transform="translate(230, 292)">
          <circle cx="14" cy="14" r="14" fill="#FEE2E2" stroke="#EF4444" stroke-width="2" class="node-poison-pulse" />
          <text x="14" y="19" text-anchor="middle" font-size="14" font-weight="900" fill="#DC2626">✕</text>
          <rect x="34" y="4" width="165" height="20" rx="10" fill="#FEF2F2" stroke="#EF4444" stroke-width="1" />
          <text x="116" y="18" text-anchor="middle" font-size="8" font-weight="700" fill="#B91C1C" font-family="'Noto Sans', sans-serif">② BLACKHOLE: Packets Dropped (ip_forward=0)</text>
        </g>
      `;
    }
  }

  // ── Node Cards ──
  markup += `
    <!-- ── VICTIM NODE ── -->
    <g>
      <rect x="35" y="45" width="180" height="135" rx="12" fill="${vBg}" stroke="${vBorder}" stroke-width="2" class="${vClass}" />
      <g transform="translate(48, 56)">
        <rect x="0" y="0" width="28" height="28" rx="6" fill="#FFFFFF" stroke="${vBorder}" stroke-width="1.2" />
        <text x="14" y="19" text-anchor="middle" font-size="14">💻</text>
        <text x="36" y="14" font-size="13" font-weight="700" fill="#1F2937" font-family="'Noto Sans', sans-serif">Victim Target</text>
        <text x="36" y="26" font-size="9" font-family="'JetBrains Mono', monospace" fill="#6B7280">IP: 10.10.10.10</text>
      </g>
      <text x="48" y="99" font-size="8.5" font-family="'JetBrains Mono', monospace" fill="#4B5563">NIC MAC: <tspan font-weight="600" fill="#111827">${state.realMacs.victim || 'detecting...'}</tspan></text>
      <line x1="48" y1="106" x2="202" y2="106" stroke="${vBorder}" stroke-width="0.8" opacity="0.4" />
      <text x="48" y="121" font-size="8" font-weight="700" fill="#6B7280" font-family="'Noto Sans', sans-serif">KERNEL ARP TABLE (10.10.10.1):</text>
      <text x="48" y="136" font-size="9" font-family="'JetBrains Mono', monospace" font-weight="700" fill="${isVictimPoisoned && !isMitigated ? '#DC2626' : '#111827'}">${victimGwMac || 'No ARP entry'}</text>
      <rect x="48" y="146" width="154" height="22" rx="11" fill="${vBadgeBg}" stroke="${vBadgeColor}" stroke-width="0.8" />
      <text x="125" y="161" text-anchor="middle" font-size="8.5" font-weight="700" fill="${vBadgeColor}" font-family="'Noto Sans', sans-serif">${vBadgeText}</text>
    </g>

    <!-- ── GATEWAY NODE ── -->
    <g>
      <rect x="465" y="45" width="180" height="135" rx="12" fill="${gBg}" stroke="${gBorder}" stroke-width="2" class="${gClass}" />
      <g transform="translate(478, 56)">
        <rect x="0" y="0" width="28" height="28" rx="6" fill="#FFFFFF" stroke="${gBorder}" stroke-width="1.2" />
        <text x="14" y="19" text-anchor="middle" font-size="14">🌐</text>
        <text x="36" y="14" font-size="13" font-weight="700" fill="#1F2937" font-family="'Noto Sans', sans-serif">Default Gateway</text>
        <text x="36" y="26" font-size="9" font-family="'JetBrains Mono', monospace" fill="#6B7280">IP: 10.10.10.1</text>
      </g>
      <text x="478" y="99" font-size="8.5" font-family="'JetBrains Mono', monospace" fill="#4B5563">NIC MAC: <tspan font-weight="600" fill="#111827">${state.realMacs.gateway || 'detecting...'}</tspan></text>
      <line x1="478" y1="106" x2="632" y2="106" stroke="${gBorder}" stroke-width="0.8" opacity="0.4" />
      <text x="478" y="121" font-size="8" font-weight="700" fill="#6B7280" font-family="'Noto Sans', sans-serif">KERNEL ARP TABLE (10.10.10.10):</text>
      <text x="478" y="136" font-size="9" font-family="'JetBrains Mono', monospace" font-weight="700" fill="${isGwPoisoned && !isMitigated ? '#DC2626' : '#111827'}">${gwVictimMac || 'No ARP entry'}</text>
      <rect x="478" y="146" width="154" height="22" rx="11" fill="${gBadgeBg}" stroke="${gBadgeColor}" stroke-width="0.8" />
      <text x="555" y="161" text-anchor="middle" font-size="8.5" font-weight="700" fill="${gBadgeColor}" font-family="'Noto Sans', sans-serif">${gBadgeText}</text>
    </g>

    <!-- ── ATTACKER NODE ── -->
    <g>
      <rect x="230" y="260" width="220" height="135" rx="12" fill="${aBg}" stroke="${aBorder}" stroke-width="2" class="${aClass}" />
      <g transform="translate(243, 271)">
        <rect x="0" y="0" width="28" height="28" rx="6" fill="#FFFFFF" stroke="${aBorder}" stroke-width="1.2" />
        <text x="14" y="19" text-anchor="middle" font-size="14">⚡</text>
        <text x="36" y="14" font-size="13" font-weight="700" fill="#1F2937" font-family="'Noto Sans', sans-serif">Attacker Machine</text>
        <text x="36" y="26" font-size="9" font-family="'JetBrains Mono', monospace" fill="#6B7280">IP: 10.10.10.66</text>
      </g>
      <text x="243" y="314" font-size="8.5" font-family="'JetBrains Mono', monospace" fill="#4B5563">NIC MAC: <tspan font-weight="600" fill="#111827">${state.realMacs.attacker || 'detecting...'}</tspan></text>
      <line x1="243" y1="321" x2="437" y2="321" stroke="${aBorder}" stroke-width="0.8" opacity="0.4" />
      <text x="243" y="337" font-size="8" font-weight="700" fill="#6B7280" font-family="'Noto Sans', sans-serif">SCAPY RAW SOCKET ENGINE (arp_spoof.py):</text>
      <text x="243" y="351" font-size="8.5" font-family="'Noto Sans', sans-serif" fill="#4B5563">${!isAttacking ? 'Awaiting attack launch command...' : (isMitm ? 'Intercepting frames & relaying via kernel' : 'Blackholing frames (ip_forward=0)')}</text>
      <rect x="243" y="361" width="194" height="22" rx="11" fill="${aBadgeBg}" stroke="${aBadgeColor}" stroke-width="0.8" />
      <text x="340" y="376" text-anchor="middle" font-size="8.5" font-weight="700" fill="${aBadgeColor}" font-family="'Noto Sans', sans-serif">${aBadgeText}</text>
    </g>
  `;

  setSvgContent(svg, markup);

  // Update topology card header badge & explainer text
  const badgeEl = $('#topology-attack-badge');
  const explainerEl = $('#explainer-status-text');

  if (badgeEl) {
    if (isMitigated) {
      badgeEl.textContent = 'Protected (Static ARP)';
      badgeEl.className = 'badge-tag tag-blue';
    } else if (isAttacking) {
      badgeEl.textContent = isMitm ? 'MITM Attack: Intercepting & Relaying' : 'DoS Attack: Packet Blackhole';
      badgeEl.className = isMitm ? 'badge-tag tag-amber' : 'badge-tag tag-red';
    } else {
      badgeEl.textContent = 'Normal Direct Traffic';
      badgeEl.className = 'badge-tag tag-teal';
    }
  }

  if (explainerEl) {
    if (isMitigated) {
      explainerEl.innerHTML = `<strong>Active Defense:</strong> Static ARP entries are pinned in kernel neighbor tables (<code>PERMANENT</code>). Unsolicited forged ARP replies sent by the attacker are silently ignored by both Victim and Gateway, maintaining authentic direct communication.`;
    } else if (isAttacking && isMitm) {
      explainerEl.innerHTML = `<strong>MITM Attack in Progress:</strong> The Attacker poisoned both victim and gateway ARP caches. When the Victim sends packets to 10.10.10.1, Layer 2 Ethernet frames are physically addressed to the Attacker's MAC. The Attacker's kernel forwards the frames (<code>net.ipv4.ip_forward = 1</code>) to the Gateway, allowing complete eavesdropping without dropping connections.`;
    } else if (isAttacking && isDos) {
      explainerEl.innerHTML = `<strong>Denial of Service in Progress:</strong> The Attacker poisoned the Victim's ARP cache. The Victim transmits frames to the Attacker's MAC, but with kernel forwarding disabled (<code>net.ipv4.ip_forward = 0</code>), the Attacker silently drops all packets. The Victim experiences 100% packet loss and complete network isolation.`;
    } else {
      explainerEl.innerHTML = `<strong>Authentic LAN State:</strong> Legitimate Layer 2 communication. The Victim and Gateway resolve IP-to-MAC addresses through genuine ARP exchanges, and data packets (ICMP ping and TCP probes) flow directly between them.`;
    }
  }
}

/* Activity log */
function renderLog() {
  const box = $('#log-box');
  if (!box) return;
  const logs = state.events
    .filter(e => ['log', 'attack_state', 'mitigation_state'].includes(e.type))
    .slice(-80);

  if (!logs.length) {
    box.innerHTML = `<p style="color:var(--text-secondary)">Waiting for backend events...</p>`;
    return;
  }

  box.innerHTML = logs.map(e => {
    let cls = 'log-entry';
    if (e.type === 'log' && e.level === 'error') cls += ' error';
    if (e.type === 'log' && e.level === 'warn')  cls += ' warn';
    const time = e.ts ? `[${new Date(e.ts * 1000).toLocaleTimeString()}] ` : '';
    let text = '';
    if (e.type === 'log')              text = e.message;
    else if (e.type === 'attack_state')    text = `attack_state active=${e.active} mode=${e.mode}`;
    else if (e.type === 'mitigation_state') text = `mitigation enabled=${e.enabled}`;
    return `<p class="${cls}">${time}${text}</p>`;
  }).join('');

  box.scrollTop = box.scrollHeight;
}

/* Quiz */
function renderQuiz() {
  const panel = $('#panel-Assignment');
  if (!panel) return;

  const done = state.quizIndex >= QUIZ.length;
  if (done) {
    panel.innerHTML = `
      <div class="intro-block">
        <span class="intro-label">ARP / Virtual Lab</span>
        <h2>Assignment</h2>
        <p>Answer each question to check your understanding.</p>
      </div>
      <div class="quiz-score-card">
        <p class="quiz-score">Score: ${state.quizScore} / ${QUIZ.length}</p>
        <button class="btn-primary-pill" id="quiz-restart">Restart quiz</button>
      </div>`;
    $('#quiz-restart').addEventListener('click', () => {
      state.quizIndex = 0; state.quizScore = 0; state.quizAnswer = null;
      renderQuiz();
    });
    return;
  }

  const q = QUIZ[state.quizIndex];
  panel.innerHTML = `
    <div class="intro-block">
      <span class="intro-label">ARP / Virtual Lab</span>
      <h2>Assignment</h2>
      <p>Answer each question to check your understanding.</p>
    </div>
    <div class="quiz-card">
      <p class="quiz-question">${q.question}</p>
      <div class="quiz-options">
        ${q.options.map((opt, idx) => `
          <button class="quiz-option" data-idx="${idx}" ${state.quizAnswer !== null ? 'disabled' : ''}
            style="${state.quizAnswer === idx
              ? idx === q.correctIndex
                ? 'background:#EBF7F4;border:1.5px solid #2A8C76;color:#2A8C76;'
                : 'background:#FDF0EF;border:1.5px solid #E06C62;color:#E06C62;'
              : ''}">
            ${opt}
          </button>`).join('')}
      </div>
      ${state.quizAnswer !== null ? `
        <div class="quiz-explanation">
          ${q.explanation}
          <br>
          <button class="btn-primary-pill" id="quiz-next" style="margin-top:12px">Next question</button>
        </div>` : ''}
    </div>`;

  $$('.quiz-option', panel).forEach(btn => {
    btn.addEventListener('click', () => {
      if (state.quizAnswer !== null) return;
      const idx = parseInt(btn.dataset.idx);
      state.quizAnswer = idx;
      if (idx === q.correctIndex) state.quizScore++;
      renderQuiz();
    });
  });

  const nextBtn = $('#quiz-next', panel);
  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      state.quizIndex++;
      state.quizAnswer = null;
      renderQuiz();
    });
  }
}

/* Feedback */
function renderFeedback() {
  const panel = $('#panel-Feedback');
  if (!panel) return;
  const formEl = panel.querySelector('.feedback-card');
  if (!formEl) return;

  /* rating buttons */
  $$('.rating-btn', formEl).forEach(btn => {
    btn.classList.toggle('selected', parseInt(btn.dataset.v) === state.feedbackRating);
  });
}

/* ─── Collapsible sections ──────────────────────────────────── */
function toggleSection(key, btn, bodyId) {
  state[key] = !state[key];
  const body = $(`#${bodyId}`);
  if (body) body.classList.toggle('hidden', !state[key]);
  const chevron = btn.querySelector('.chevron-circle');
  if (chevron) chevron.textContent = state[key] ? '▾' : '▸';
}

/* ─────────────────────────────────────────────────────────────
   BUILD INITIAL HTML
   ───────────────────────────────────────────────────────────── */
function buildUI() {
  document.body.innerHTML = `
    <!-- Toast container -->
    <div id="toast-container"></div>

    <!-- Header -->
    <header id="app-header">
      <div class="max-w-7xl header-inner">
        <div class="flex items-center gap-3">
          <button class="back-btn-circle" aria-label="Go back" onclick="history.back()">&#8592;</button>
          <div>
            <h1>ARP Spoofing / Virtual Lab</h1>
            <p class="header-sub">• Cybersecurity Teaching Lab • Interactive</p>
          </div>
        </div>
        <div class="header-right">
          <div class="edtech-pill">
            <span class="status-dot" id="ws-dot"></span>
            <span id="ws-text" style="font-family:'JetBrains Mono',monospace;font-size:11px">connecting</span>
          </div>
          <div class="edtech-pill">
            <span id="lab-status-text" style="font-size:11px;font-weight:600">Stopped</span>
          </div>
        </div>
      </div>
    </header>

    <!-- Main content -->
    <main class="max-w-7xl px-5 py-6">

      <!-- Tab bar -->
      <nav id="tab-bar" role="tablist">
        ${TABS.map(t => `<button class="tab-btn" data-tab="${t}" role="tab">${t}</button>`).join('')}
      </nav>

      <!-- ── AIM ── -->
      <section id="panel-Aim" class="tab-panel" role="tabpanel">
        <div class="intro-block">
          <span class="intro-label">ARP / Virtual Lab</span>
          <h2>Aim</h2>
          <p>Demonstrate ARP spoofing and observe its effect on network communication in a controlled Docker-based environment.</p>
        </div>
      </section>

      <!-- ── OBJECTIVE ── -->
      <section id="panel-Objective" class="tab-panel" role="tabpanel">
        <div class="intro-block">
          <span class="intro-label">ARP / Virtual Lab</span>
          <h2>Objective</h2>
          <p>By the end of the lab, you should be able to:</p>
        </div>
        <ul class="objective-list">
          ${[
            'Explain ARP request and reply behavior.',
            'Identify a poisoned ARP cache entry from live events.',
            'Contrast MITM interception with denial of service.',
            'Apply static ARP and Dynamic ARP Inspection defenses.',
          ].map(item => `
            <li class="objective-item">
              <span class="check-icon">✔</span>
              <span>${item}</span>
            </li>`).join('')}
        </ul>
      </section>

      <!-- ── THEORY ── -->
      <section id="panel-Theory" class="tab-panel" role="tabpanel">
        <div class="intro-block">
          <span class="intro-label">ARP / Virtual Lab</span>
          <h2>Theory & Protocol Mechanics</h2>
          <p>Address Resolution Protocol (ARP, RFC 826) bridges the gap between Layer 3 logical IP addresses and Layer 2 physical MAC addresses on local broadcast domains.</p>
        </div>
        <div class="theory-grid">
          ${[
            ['Layer 2 vs Layer 3', 'Ethernet frames require destination MAC addresses. When Host A wishes to transmit an IP packet to Host B on the same subnet, it must first resolve B’s MAC address using an ARP Request.'],
            ['ARP Request / Reply', 'ARP Requests are broadcasted (dst ff:ff:ff:ff:ff:ff) asking "Who has IP X?". The rightful owner responds with a unicast ARP Reply stating "IP X is at MAC Y".'],
            ['The ARP Cache', 'Operating systems cache learned IP-to-MAC associations for 30–120 seconds to prevent constant broadcast storms. Entries are mutable and continuously refreshed.'],
            ['No Authentication', 'Designed in 1982 for trusted networks, ARP has zero cryptographic authentication. Any device on the subnet can claim ownership of any IP address without proof.'],
            ['Gratuitous ARP', 'Unsolicited ARP announcements update neighbors of IP/MAC changes (e.g. NIC failover). Attackers exploit this to silently overwrite remote caches without prior requests.'],
            ['MITM vs DoS', 'In MITM, the attacker enables IP forwarding to invisibly intercept and relay traffic. In DoS, forwarding is disabled, causing all redirected packets to be silently dropped.'],
            ['Static ARP Defense', 'Permanent IP-to-MAC bindings configured manually in the OS cache cannot be overwritten by incoming forged ARP replies, but this approach does not scale easily.'],
            ['Dynamic ARP Inspection', 'Enterprise switches with DAI validate incoming ARP packets against the DHCP Snooping Binding Table, dropping forged packets at the switch-port level.'],
            ['HTTPS / VPN Protections', 'ARP poisoning is a Layer 2 attack. End-to-end encryption (TLS/HTTPS, VPN tunnels) ensures that even if traffic flows through an attacker, the payload remains unreadable ciphertext.']
          ].map(([title, text]) => `
            <div class="theory-card">
              <p class="theory-title">${title}</p>
              <p>${text}</p>
            </div>`).join('')}
        </div>
      </section>

      <!-- ── PROCEDURE ── -->
      <section id="panel-Procedure" class="tab-panel" role="tabpanel">
        <div class="intro-block">
          <span class="intro-label">ARP / Virtual Lab</span>
          <h2>Procedure</h2>
          <p>Follow the sequence in the Simulation tab.</p>
        </div>
        <ol class="procedure-list">
          ${['Start Lab','Start Attack','Observe poisoned ARP entry','Toggle Mitigation','Stop Attack','Reset Lab']
            .map((step, i) => `
              <li class="procedure-item">
                <span class="step-badge">${String(i+1).padStart(2,'0')}</span>
                <span>${step}</span>
              </li>`).join('')}
        </ol>
      </section>

      <!-- ── SIMULATION ── -->
      <section id="panel-Simulation" class="tab-panel" role="tabpanel">

        <!-- Alert banner -->
        <div class="alert-warm" id="sim-alert">
          <span class="alert-icon">📡</span>
          <span class="alert-text">Backend not connected — retrying in the background.</span>
        </div>

        <!-- Two-column grid -->
        <div class="sim-grid">

          <!-- LEFT: Topology diagram -->
          <div class="topology-card">
            <div class="topology-card-header">
              <div style="display:flex;align-items:center;gap:10px">
                <span class="title">Live ARP Network Map</span>
                <span id="topology-attack-badge" class="badge-tag tag-teal">Normal Direct Traffic</span>
              </div>
              <span class="subtitle">10.10.10.0/24 Isolated Bridge</span>
            </div>
            <div class="topology-svg-wrap">
              <svg id="topology-svg" viewBox="0 0 680 430" role="img" aria-label="Live ARP network topology diagram">
                <defs>
                  <marker id="teal-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L7,3 z" fill="#2A8C76"/>
                  </marker>
                  <marker id="coral-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L7,3 z" fill="#E06C62"/>
                  </marker>
                  <marker id="amber-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L7,3 z" fill="#F59E0B"/>
                  </marker>
                  <marker id="purple-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L7,3 z" fill="#8B5CF6"/>
                  </marker>
                  <filter id="packetGlow" x="-30%" y="-30%" width="160%" height="160%">
                    <feGaussianBlur stdDeviation="2" result="blur" />
                    <feMerge>
                      <feMergeNode in="blur" />
                      <feMergeNode in="SourceGraphic" />
                    </feMerge>
                  </filter>
                  <pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse">
                    <path d="M 24 0 L 0 0 0 24" fill="none" stroke="#EAE6E2" stroke-width="0.5"/>
                  </pattern>
                </defs>
                <rect width="680" height="430" fill="url(#grid)" rx="14"/>
                <g id="topology-dynamic-layer"></g>
              </svg>
            </div>
            <div class="topology-explainer" id="topology-explainer">
              <div class="explainer-status" id="explainer-status-text">
                <strong>Current State:</strong> Normal Direct Traffic — Victim and Gateway communicate directly using authentic ARP bindings.
              </div>
              <div class="topology-legend">
                <span class="legend-item"><span class="legend-dot dot-teal"></span> Genuine IP/ICMP Traffic</span>
                <span class="legend-item"><span class="legend-dot dot-coral"></span> Forged ARP Replies (Spoofing)</span>
                <span class="legend-item"><span class="legend-dot dot-amber"></span> Intercepted L2 Frames</span>
                <span class="legend-item"><span class="legend-dot dot-purple"></span> MITM Relayed Frames</span>
                <span class="legend-item"><span class="legend-dot dot-shield"></span> Static ARP Protected</span>
              </div>
            </div>
          </div>

          <!-- RIGHT: Sidebar -->
          <div class="sidebar">

            <!-- Controls collapsible -->
            <div class="controls-panel">
              <button class="section-header-strip flat" id="controls-toggle" aria-expanded="true">
                <span>Controls</span>
                <span class="chevron-circle">▾</span>
              </button>
              <div id="controls-body" class="controls-body">

                <!-- Start / Stop Lab -->
                <div class="btn-2col">
                  <button class="btn-primary-pill" data-api="/api/lab/start" id="btn-start-lab">
                    <span class="spinner" style="display:none"></span>
                    ▶ Start Lab
                  </button>
                  <button class="btn-secondary" data-api="/api/lab/stop" id="btn-stop-lab">
                    ■ Stop Lab
                  </button>
                </div>

                <!-- Reset Lab -->
                <button class="btn-secondary w-full" data-api="/api/lab/reset" id="btn-reset-lab" style="justify-content:center">
                  ↺ Reset Lab
                </button>

                <!-- Attack mode select -->
                <select class="native-select" id="attack-mode-select">
                  <option value="mitm">MITM</option>
                  <option value="dos">DoS</option>
                </select>

                <!-- Start Attack -->
                <button class="btn-primary-pill w-full" data-api="/api/attack/start" id="btn-start-attack" style="justify-content:center">
                  <span class="spinner" style="display:none"></span>
                  Start Attack
                </button>

                <!-- Stop Attack -->
                <button class="btn-danger w-full" data-api="/api/attack/stop" id="btn-stop-attack" style="justify-content:center">
                  Stop Attack
                </button>

                <!-- Mitigation toggle -->
                <div class="mitigation-row">
                  <span style="font-size:13px;font-weight:500;color:var(--text-main)">Mitigation enabled</span>
                  <div class="toggle-wrap">
                    <input type="checkbox" class="toggle-input" id="mitigation-toggle">
                    <label class="toggle-label" for="mitigation-toggle"></label>
                  </div>
                </div>

              </div>
            </div>

            <!-- Activity Log collapsible -->
            <div class="log-panel">
              <button class="section-header-strip flat" id="log-toggle" aria-expanded="true">
                <span>Activity log</span>
                <span class="chevron-circle">▾</span>
              </button>
              <div id="log-body" style="padding:12px">
                <div class="log-box" id="log-box">
                  <p style="color:var(--text-secondary)">Waiting for backend events...</p>
                </div>
              </div>
            </div>

          </div><!-- /sidebar -->
        </div><!-- /sim-grid -->
      </section>

      <!-- ── ASSIGNMENT (quiz rendered dynamically) ── -->
      <section id="panel-Assignment" class="tab-panel" role="tabpanel"></section>

      <!-- ── REFERENCES ── -->
      <section id="panel-References" class="tab-panel" role="tabpanel">
        <div class="intro-block">
          <span class="intro-label">ARP / Virtual Lab</span>
          <h2>References & Further Reading</h2>
          <p>Primary standards, textbook citations, and security documentation covering ARP analysis and defense.</p>
        </div>
        <ul class="references-list">
          <li style="margin-bottom:12px;line-height:1.6">
            <strong>1. RFC 826 — An Ethernet Address Resolution Protocol (Plummer, 1982)</strong><br>
            <span style="color:var(--text-secondary);font-size:13px">The foundational IETF specification defining packet structure, cache algorithms, and resolution mechanics.</span>
          </li>
          <li style="margin-bottom:12px;line-height:1.6">
            <strong>2. Kurose, J. & Ross, K. — <em>Computer Networking: A Top-Down Approach</em>, Chapter 6</strong><br>
            <span style="color:var(--text-secondary);font-size:13px">Covers switched LANs, Ethernet framing, link-layer addressing, and host-to-router ARP cycles.</span>
          </li>
          <li style="margin-bottom:12px;line-height:1.6">
            <strong>3. Forouzan, B. A. — <em>Data Communications and Networking</em>, ARP/RARP Section</strong><br>
            <span style="color:var(--text-secondary);font-size:13px">Detailed packet format diagrams, proxy ARP, and Layer 2/3 address mapping theory.</span>
          </li>
          <li style="margin-bottom:12px;line-height:1.6">
            <strong>4. MITRE ATT&CK — T1557.002: ARP Cache Poisoning</strong><br>
            <span style="color:var(--text-secondary);font-size:13px"><a href="https://attack.mitre.org/techniques/T1557/002/" target="_blank" rel="noopener noreferrer" style="color:var(--accent-blue)">https://attack.mitre.org/techniques/T1557/002/</a> — Adversarial adversary profile, real-world usage, and mitigation strategies.</span>
          </li>
          <li style="margin-bottom:12px;line-height:1.6">
            <strong>5. Cisco Systems — Configuring Dynamic ARP Inspection (DAI) Documentation</strong><br>
            <span style="color:var(--text-secondary);font-size:13px"><a href="https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/12-2SX/configuration/guide/book/dynarp.html" target="_blank" rel="noopener noreferrer" style="color:var(--accent-blue)">Official Cisco Catalyst Switch Guide</a> — DHCP Snooping tables, trusted vs. untrusted ports, and ARP rate limiting.</span>
          </li>
          <li style="margin-bottom:12px;line-height:1.6">
            <strong>6. Wireshark Wiki — Address Resolution Protocol (ARP)</strong><br>
            <span style="color:var(--text-secondary);font-size:13px"><a href="https://wiki.wireshark.org/ARP" target="_blank" rel="noopener noreferrer" style="color:var(--accent-blue)">https://wiki.wireshark.org/ARP</a> — Protocol dissections, sample packet captures, and detecting gratuitous ARP anomalies.</span>
          </li>
        </ul>
      </section>

      <!-- ── FEEDBACK ── -->
      <section id="panel-Feedback" class="tab-panel" role="tabpanel">
        <div class="intro-block">
          <span class="intro-label">ARP / Virtual Lab</span>
          <h2>Feedback</h2>
          <p>Tell us how the lab supported your learning.</p>
        </div>
        <div class="feedback-card">
          <label class="form-label">
            Name (optional)
            <input class="form-input" type="text" id="feedback-name" placeholder="Your name">
          </label>
          <fieldset style="border:none">
            <legend style="font-size:13px;font-weight:500;color:var(--text-main);margin-bottom:8px">Rating</legend>
            <div class="rating-row">
              ${[1,2,3,4,5].map(v => `
                <button class="rating-btn" data-v="${v}" aria-label="${v} stars" type="button">${v}</button>`).join('')}
            </div>
          </fieldset>
          <label class="form-label">
            Comment
            <textarea class="form-input" id="feedback-comment" placeholder="Comment"></textarea>
          </label>
          <button class="btn-primary-pill" id="feedback-submit" style="align-self:flex-start">Submit feedback</button>
        </div>
      </section>

    </main>
  `;
}

/* ─────────────────────────────────────────────────────────────
   EVENT WIRING
   ───────────────────────────────────────────────────────────── */
function wireEvents() {
  /* Tab bar clicks */
  $$('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      state.activeTab = btn.dataset.tab;
      renderTabs();
      if (state.activeTab === 'Assignment') renderQuiz();
    });
  });

  /* Collapsible sections */
  $('#controls-toggle').addEventListener('click', (e) => {
    toggleSection('controlsOpen', e.currentTarget, 'controls-body');
  });
  $('#log-toggle').addEventListener('click', (e) => {
    toggleSection('logOpen', e.currentTarget, 'log-body');
  });

  /* Attack mode select */
  $('#attack-mode-select').addEventListener('change', (e) => {
    state.attackMode = e.target.value;
  });

  /* API buttons */
  $('#btn-start-lab').addEventListener('click',   () => callApi('/api/lab/start'));
  $('#btn-stop-lab').addEventListener('click',    () => callApi('/api/lab/stop'));
  $('#btn-reset-lab').addEventListener('click',   () => callApi('/api/lab/reset'));
  $('#btn-start-attack').addEventListener('click',() => callApi('/api/attack/start', { mode: state.attackMode }));
  $('#btn-stop-attack').addEventListener('click', () => callApi('/api/attack/stop'));

  /* Mitigation toggle */
  $('#mitigation-toggle').addEventListener('change', (e) => {
    state.mitigationOn = e.target.checked;
    callApi('/api/mitigation/toggle', { enabled: state.mitigationOn });
  });

  /* Feedback rating buttons */
  document.addEventListener('click', (e) => {
    const rBtn = e.target.closest('.rating-btn');
    if (!rBtn) return;
    state.feedbackRating = parseInt(rBtn.dataset.v);
    renderFeedback();
  });

  /* Feedback submit */
  document.addEventListener('click', (e) => {
    if (e.target.id !== 'feedback-submit') return;
    const panel = $('#panel-Feedback');
    const card  = panel.querySelector('.feedback-card');
    if (card) card.innerHTML = `<p class="success-msg">Thank you for your feedback.</p>`;
    state.feedbackSubmitted = true;
  });
}

/* ─────────────────────────────────────────────────────────────
   BOOTSTRAP
   ───────────────────────────────────────────────────────────── */
function init() {
  buildUI();
  wireEvents();
  renderTabs();
  renderDiagram();
  renderLog();
  renderQuiz();
  connectWs();
  fetchState();
  setInterval(fetchState, 3000);
  /* set default active tab */
  state.activeTab = 'Simulation';
  renderTabs();
}

document.addEventListener('DOMContentLoaded', init);
