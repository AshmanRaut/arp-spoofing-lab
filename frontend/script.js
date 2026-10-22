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
  simViewMode:  'both',         // 'both' | 'map' | 'tables'
};

/* ─── Tabs & module icons ───────────────────────────────────── */
const TABS = ['Aim', 'Objective', 'Theory', 'Procedure', 'Simulation', 'Assignment', 'References', 'Feedback'];
const MODULE_ICONS = {
  Aim: 'AI', Objective: 'OB', Theory: 'TH', Procedure: 'PR',
  Simulation: 'SI', Assignment: 'AS', References: 'RE', Feedback: 'FB',
};

/* ─── Reference Library Data ───────────────────────────────── */
const REFERENCES = [
  {
    tag: 'IETF Standard',
    tagClass: 'tag-teal',
    title: 'RFC 826 — An Ethernet Address Resolution Protocol',
    author: 'David C. Plummer (1982)',
    desc: 'The foundational IETF standard defining packet structure, cache algorithms, and resolution mechanics for Layer 2/3 translation.',
    url: 'https://datatracker.ietf.org/doc/html/rfc826'
  },
  {
    tag: 'Textbook Citation',
    tagClass: 'tag-blue',
    title: 'Computer Networking: A Top-Down Approach (Ch. 6)',
    author: 'J. Kurose & K. Ross',
    desc: 'Comprehensive coverage of switched local area networks, Ethernet framing, link-layer addressing, and host-to-router ARP cycles.',
    url: ''
  },
  {
    tag: 'Reference Guide',
    tagClass: 'tag-amber',
    title: 'Data Communications and Networking (ARP/RARP Section)',
    author: 'Behrouz A. Forouzan',
    desc: 'Detailed protocol format diagrams, proxy ARP architecture, and Layer 2 broadcast domain address mapping theory.',
    url: ''
  },
  {
    tag: 'MITRE ATT&CK',
    tagClass: 'tag-red',
    title: 'T1557.002: Adversary ARP Cache Poisoning',
    author: 'MITRE Enterprise Framework',
    desc: 'Adversary technique profile, real-world weaponization, detection procedures, and enterprise mitigation strategies.',
    url: 'https://attack.mitre.org/techniques/T1557/002/'
  },
  {
    tag: 'Vendor Security Guide',
    tagClass: 'tag-teal',
    title: 'Cisco Systems — Dynamic ARP Inspection (DAI) Configuration',
    author: 'Cisco Catalyst Switch Security Documentation',
    desc: 'Enterprise switch defense using DHCP snooping binding tables, untrusted port rate limiting, and hardware packet inspection.',
    url: 'https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/12-2SX/configuration/guide/book/dynarp.html'
  },
  {
    tag: 'Packet Analysis',
    tagClass: 'tag-blue',
    title: 'Wireshark Protocol Wiki — Address Resolution Protocol (ARP)',
    author: 'Wireshark Foundation',
    desc: 'Protocol dissections, sample PCAP packet captures, and detecting gratuitous ARP anomaly signatures in network traffic.',
    url: 'https://wiki.wireshark.org/ARP'
  }
];

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

/* ─── Simulation View Mode Controller (Map / Tables / Both) ───────── */
function applySimViewMode() {
  const mode = state.simViewMode || 'both';
  const svgWrap = $('#topology-svg-wrap') || $('.topology-svg-wrap');
  const legendBar = $('#topology-legend-bar');
  const panHint = $('.mobile-pan-hint');
  const tablesSec = $('#topology-arp-tables-section');
  if (!svgWrap || !tablesSec) return;

  if (mode === 'map') {
    svgWrap.style.display = 'block';
    if (legendBar) legendBar.style.display = 'flex';
    if (panHint) panHint.style.display = '';
    tablesSec.style.display = 'none';
  } else if (mode === 'tables') {
    svgWrap.style.display = 'none';
    if (legendBar) legendBar.style.display = 'none';
    if (panHint) panHint.style.display = 'none';
    tablesSec.style.display = 'flex';
  } else {
    svgWrap.style.display = 'block';
    if (legendBar) legendBar.style.display = 'flex';
    if (panHint) panHint.style.display = '';
    tablesSec.style.display = 'flex';
  }

  // Update switcher button active states
  const switcher = $('#sim-view-switcher');
  if (switcher) {
    $$('.view-btn', switcher).forEach(btn => {
      btn.classList.toggle('active', btn.dataset.view === mode);
    });
  }
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
  const vBadgeText = isMitigated ? '🛡️ STATIC' : (isVictimPoisoned ? '⚠️ POISONED' : '✓ AUTHENTIC');
  const vBadgeBg = isMitigated ? '#DBEAFE' : (isVictimPoisoned ? '#FEE2E2' : '#E8F5F1');
  const vBadgeColor = isMitigated ? '#1D4ED8' : (isVictimPoisoned ? '#B91C1C' : '#1B6554');
  const vClass = isVictimPoisoned && !isMitigated ? 'node-poison-pulse' : (isMitigated ? 'node-shield-pulse' : '');

  const gBorder = isMitigated ? '#2563EB' : (isGwPoisoned ? '#E06C62' : '#2A8C76');
  const gBg = isMitigated ? '#EFF6FF' : (isGwPoisoned ? '#FEF2F2' : '#F4FAF8');
  const gBadgeText = isMitigated ? '🛡️ STATIC' : (isGwPoisoned ? '⚠️ POISONED' : '✓ AUTHENTIC');
  const gBadgeBg = isMitigated ? '#DBEAFE' : (isGwPoisoned ? '#FEE2E2' : '#E8F5F1');
  const gBadgeColor = isMitigated ? '#1D4ED8' : (isGwPoisoned ? '#B91C1C' : '#1B6554');
  const gClass = isGwPoisoned && !isMitigated ? 'node-poison-pulse' : (isMitigated ? 'node-shield-pulse' : '');

  const aBorder = isAttacking ? '#E06C62' : '#64748B';
  const aBg = isAttacking ? '#FEF2F2' : '#F8FAFC';
  const aBadgeText = !isAttacking ? '💤 Standby / Idle' : (isMitm ? '⚡ MITM Relaying (ip_forward=1)' : '🚫 DoS Dropping (ip_forward=0)');
  const aBadgeBg = !isAttacking ? '#F1F5F9' : (isMitm ? '#FEF3C7' : '#FEE2E2');
  const aBadgeColor = !isAttacking ? '#475569' : (isMitm ? '#B45309' : '#B91C1C');
  const aClass = isAttacking ? 'node-poison-pulse' : '';

  let markup = `
    <!-- Background Grid -->
    <rect width="1140" height="560" rx="14" fill="#FDFBF9" />

    <!-- ── Direct Communication Channel (Victim ↔ Gateway) ── -->
  `;

  if (!isVictimPoisoned && !isGwPoisoned) {
    markup += `
      <g>
        <line x1="375" y1="92" x2="765" y2="92" stroke="#2A8C76" stroke-width="3" />
        <circle r="6" fill="#10B981" filter="url(#packetGlow)">
          <animateMotion path="M 375 87 L 765 87" dur="2s" repeatCount="indefinite" />
        </circle>
        <circle r="6" fill="#06B6D4" filter="url(#packetGlow)">
          <animateMotion path="M 765 97 L 375 97" dur="2s" begin="1s" repeatCount="indefinite" />
        </circle>
        <rect x="445" y="76" width="250" height="32" rx="16" fill="#FFFFFF" stroke="#2A8C76" stroke-width="1.4" />
        <text x="570" y="96.5" text-anchor="middle" font-size="11.5" font-weight="700" fill="#1B6554" font-family="'Noto Sans', sans-serif">Direct IP/ICMP Traffic</text>
      </g>
    `;
  } else {
    if (isMitigated) {
      markup += `
        <g>
          <line x1="375" y1="92" x2="765" y2="92" stroke="#2563EB" stroke-width="3" />
          <circle r="6" fill="#3B82F6" filter="url(#packetGlow)">
            <animateMotion path="M 375 87 L 765 87" dur="2s" repeatCount="indefinite" />
          </circle>
          <circle r="6" fill="#60A5FA" filter="url(#packetGlow)">
            <animateMotion path="M 765 97 L 375 97" dur="2s" begin="1s" repeatCount="indefinite" />
          </circle>
          <rect x="430" y="76" width="280" height="32" rx="16" fill="#EFF6FF" stroke="#2563EB" stroke-width="1.4" />
          <text x="570" y="96.5" text-anchor="middle" font-size="11.5" font-weight="700" fill="#1D4ED8" font-family="'Noto Sans', sans-serif">🛡️ Protected Direct Traffic</text>
        </g>
      `;
    } else if (isMitm) {
      markup += `
        <g>
          <line x1="375" y1="92" x2="765" y2="92" stroke="#CBD5E1" stroke-width="2.5" stroke-dasharray="6 6" />
          <rect x="420" y="76" width="300" height="32" rx="16" fill="#FFFBEB" stroke="#F59E0B" stroke-width="1.4" />
          <text x="570" y="96.5" text-anchor="middle" font-size="11" font-weight="700" fill="#B45309" font-family="'Noto Sans', sans-serif">Direct Path Severed (Traffic Diverted)</text>
        </g>
      `;
    } else {
      markup += `
        <g>
          <line x1="375" y1="92" x2="765" y2="92" stroke="#FCA5A5" stroke-width="2.5" stroke-dasharray="6 6" />
          <rect x="420" y="76" width="300" height="32" rx="16" fill="#FEF2F2" stroke="#EF4444" stroke-width="1.4" />
          <text x="570" y="96.5" text-anchor="middle" font-size="11" font-weight="700" fill="#B91C1C" font-family="'Noto Sans', sans-serif">❌ Connection Timed Out (Blackholed)</text>
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
          <path d="M 440 360 Q 315 315 260 220" fill="none" stroke="#E06C62" stroke-width="3" stroke-dasharray="7 5" class="flow-dash-fast" marker-end="url(#coral-arrow)" />
          <circle r="6" fill="#EF4444" filter="url(#packetGlow)">
            <animateMotion path="M 440 360 Q 315 315 260 220" dur="1.2s" repeatCount="indefinite" />
          </circle>
          <rect x="185" y="275" width="200" height="28" rx="14" fill="#FEF2F2" stroke="#E06C62" stroke-width="1.2" />
          <text x="285" y="293" text-anchor="middle" font-size="10" font-weight="700" fill="#B91C1C" font-family="'JetBrains Mono', monospace">⚡ Forged: 10.10.10.1=Attacker</text>
        </g>

        <!-- Right Poisoning Curve (Attacker -> Gateway) -->
        <g>
          <path d="M 700 360 Q 825 315 880 220" fill="none" stroke="#E06C62" stroke-width="3" stroke-dasharray="7 5" class="flow-dash-fast" marker-end="url(#coral-arrow)" />
          <circle r="6" fill="#EF4444" filter="url(#packetGlow)">
            <animateMotion path="M 700 360 Q 825 315 880 220" dur="1.2s" repeatCount="indefinite" />
          </circle>
          <rect x="755" y="275" width="200" height="28" rx="14" fill="#FEF2F2" stroke="#E06C62" stroke-width="1.2" />
          <text x="855" y="293" text-anchor="middle" font-size="10" font-weight="700" fill="#B91C1C" font-family="'JetBrains Mono', monospace">⚡ Forged: 10.10.10.10=Attacker</text>
        </g>
      `;
    } else {
      markup += `
        <!-- Left Poisoning Curve Deflected -->
        <g>
          <path d="M 440 360 Q 315 315 265 230" fill="none" stroke="#E06C62" stroke-width="2" stroke-dasharray="4 4" opacity="0.45" />
          <g transform="translate(245, 195)">
            <circle cx="16" cy="16" r="17" fill="#DBEAFE" stroke="#2563EB" stroke-width="2" class="node-shield-pulse" />
            <text x="16" y="22" text-anchor="middle" font-size="15">🛡️</text>
            <rect x="-42" y="34" width="116" height="22" rx="11" fill="#EFF6FF" stroke="#2563EB" stroke-width="1" />
            <text x="16" y="49" text-anchor="middle" font-size="9" font-weight="700" fill="#1D4ED8" font-family="'Noto Sans', sans-serif">Static Blocked</text>
          </g>
        </g>

        <!-- Right Poisoning Curve Deflected -->
        <g>
          <path d="M 700 360 Q 825 315 875 230" fill="none" stroke="#E06C62" stroke-width="2" stroke-dasharray="4 4" opacity="0.45" />
          <g transform="translate(865, 195)">
            <circle cx="16" cy="16" r="17" fill="#DBEAFE" stroke="#2563EB" stroke-width="2" class="node-shield-pulse" />
            <text x="16" y="22" text-anchor="middle" font-size="15">🛡️</text>
            <rect x="-42" y="34" width="116" height="22" rx="11" fill="#EFF6FF" stroke="#2563EB" stroke-width="1" />
            <text x="16" y="49" text-anchor="middle" font-size="9" font-weight="700" fill="#1D4ED8" font-family="'Noto Sans', sans-serif">Static Blocked</text>
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
        <path d="M 95 220 Q 85 440 395 435" fill="none" stroke="#F59E0B" stroke-width="3.2" stroke-dasharray="7 5" class="flow-dash" marker-end="url(#amber-arrow)" />
        <circle r="6" fill="#F59E0B" filter="url(#packetGlow)">
          <animateMotion path="M 95 220 Q 85 440 395 435" dur="1.5s" repeatCount="indefinite" />
        </circle>
        <rect x="42" y="345" width="175" height="28" rx="14" fill="#FEF3C7" stroke="#F59E0B" stroke-width="1.2" />
        <text x="129.5" y="363" text-anchor="middle" font-size="10.5" font-weight="700" fill="#92400E" font-family="'Noto Sans', sans-serif">① Intercepted Frame</text>
      </g>
    `;

    if (isMitm) {
      markup += `
        <!-- Relayed Frame: Attacker -> Gateway -->
        <g>
          <path d="M 745 435 Q 1055 440 1045 220" fill="none" stroke="#8B5CF6" stroke-width="3.2" stroke-dasharray="7 5" class="flow-dash" marker-end="url(#purple-arrow)" />
          <circle r="6" fill="#8B5CF6" filter="url(#packetGlow)">
            <animateMotion path="M 745 435 Q 1055 440 1045 220" dur="1.5s" begin="0.3s" repeatCount="indefinite" />
          </circle>
          <rect x="923" y="345" width="175" height="28" rx="14" fill="#EDE9FE" stroke="#8B5CF6" stroke-width="1.2" />
          <text x="1010.5" y="363" text-anchor="middle" font-size="10.5" font-weight="700" fill="#5B21B6" font-family="'Noto Sans', sans-serif">② Relayed to Gateway</text>
        </g>
      `;
    } else if (isDos) {
      markup += `
        <!-- Blackhole Drop Zone at Attacker -->
        <g transform="translate(395, 526)">
          <rect x="0" y="0" width="350" height="26" rx="13" fill="#FEE2E2" stroke="#EF4444" stroke-width="1.2" class="node-poison-pulse" />
          <text x="175" y="17" text-anchor="middle" font-size="10" font-weight="800" fill="#DC2626" font-family="'Noto Sans', sans-serif">✕ BLACKHOLE: Frames Dropped (ip_forward=0)</text>
        </g>
      `;
    }
  }

  // ── Node Cards with In-Map Integrated ARP Caches ──
  markup += `
    <!-- ── VICTIM NODE ── -->
    <g>
      <rect x="45" y="30" width="330" height="190" rx="14" fill="${vBg}" stroke="${vBorder}" stroke-width="2" class="${vClass}" />
      <g transform="translate(62, 44)">
        <rect x="0" y="0" width="36" height="36" rx="8" fill="#FFFFFF" stroke="${vBorder}" stroke-width="1.2" />
        <text x="18" y="24" text-anchor="middle" font-size="18">💻</text>
        <text x="48" y="16" font-size="15.5" font-weight="700" fill="#1F2937" font-family="'Noto Sans', sans-serif">Victim Target</text>
        <text x="48" y="32" font-size="11" font-family="'JetBrains Mono', monospace" fill="#6B7280">IP: 10.10.10.10</text>
      </g>
      <text x="62" y="100" font-size="11" font-family="'JetBrains Mono', monospace" fill="#4B5563">NIC MAC: <tspan font-weight="700" fill="#111827">${state.realMacs.victim || 'detecting...'}</tspan></text>
      <line x1="62" y1="110" x2="358" y2="110" stroke="${vBorder}" stroke-width="0.8" opacity="0.3" />
      
      <!-- In-Map Live ARP Entry Box (Roomy & Stacked Vertically) -->
      <rect x="60" y="120" width="300" height="84" rx="10" fill="${vBadgeBg}" stroke="${vBadgeColor}" stroke-width="1" />
      <text x="74" y="138" font-size="10" font-weight="700" fill="${vBadgeColor}" font-family="'Noto Sans', sans-serif">KERNEL ARP (10.10.10.1 Gateway):</text>
      <text x="74" y="161" font-size="14" font-family="'JetBrains Mono', monospace" font-weight="700" fill="${isVictimPoisoned && !isMitigated ? '#DC2626' : '#111827'}">${victimGwMac || 'No ARP entry'}</text>
      <rect x="74" y="171" width="126" height="23" rx="11.5" fill="#FFFFFF" stroke="${vBadgeColor}" stroke-width="0.9" />
      <text x="137" y="186.5" text-anchor="middle" font-size="10" font-weight="700" fill="${vBadgeColor}" font-family="'Noto Sans', sans-serif">${vBadgeText}</text>
    </g>

    <!-- ── GATEWAY NODE ── -->
    <g>
      <rect x="765" y="30" width="330" height="190" rx="14" fill="${gBg}" stroke="${gBorder}" stroke-width="2" class="${gClass}" />
      <g transform="translate(782, 44)">
        <rect x="0" y="0" width="36" height="36" rx="8" fill="#FFFFFF" stroke="${gBorder}" stroke-width="1.2" />
        <text x="18" y="24" text-anchor="middle" font-size="18">🌐</text>
        <text x="48" y="16" font-size="15.5" font-weight="700" fill="#1F2937" font-family="'Noto Sans', sans-serif">Default Gateway</text>
        <text x="48" y="32" font-size="11" font-family="'JetBrains Mono', monospace" fill="#6B7280">IP: 10.10.10.1</text>
      </g>
      <text x="782" y="100" font-size="11" font-family="'JetBrains Mono', monospace" fill="#4B5563">NIC MAC: <tspan font-weight="700" fill="#111827">${state.realMacs.gateway || 'detecting...'}</tspan></text>
      <line x1="782" y1="110" x2="1078" y2="110" stroke="${gBorder}" stroke-width="0.8" opacity="0.3" />

      <!-- In-Map Live ARP Entry Box (Roomy & Stacked Vertically) -->
      <rect x="780" y="120" width="300" height="84" rx="10" fill="${gBadgeBg}" stroke="${gBadgeColor}" stroke-width="1" />
      <text x="794" y="138" font-size="10" font-weight="700" fill="${gBadgeColor}" font-family="'Noto Sans', sans-serif">KERNEL ARP (10.10.10.10 Victim):</text>
      <text x="794" y="161" font-size="14" font-family="'JetBrains Mono', monospace" font-weight="700" fill="${isGwPoisoned && !isMitigated ? '#DC2626' : '#111827'}">${gwVictimMac || 'No ARP entry'}</text>
      <rect x="794" y="171" width="126" height="23" rx="11.5" fill="#FFFFFF" stroke="${gBadgeColor}" stroke-width="0.9" />
      <text x="857" y="186.5" text-anchor="middle" font-size="10" font-weight="700" fill="${gBadgeColor}" font-family="'Noto Sans', sans-serif">${gBadgeText}</text>
    </g>

    <!-- ── ATTACKER NODE ── -->
    <g>
      <rect x="395" y="360" width="350" height="160" rx="14" fill="${aBg}" stroke="${aBorder}" stroke-width="2" class="${aClass}" />
      <g transform="translate(413, 374)">
        <rect x="0" y="0" width="36" height="36" rx="8" fill="#FFFFFF" stroke="${aBorder}" stroke-width="1.2" />
        <text x="18" y="24" text-anchor="middle" font-size="18">⚡</text>
        <text x="48" y="16" font-size="15.5" font-weight="700" fill="#1F2937" font-family="'Noto Sans', sans-serif">Attacker Spoofer</text>
        <text x="48" y="32" font-size="11" font-family="'JetBrains Mono', monospace" fill="#6B7280">IP: 10.10.10.66</text>
      </g>
      <text x="413" y="430" font-size="11" font-family="'JetBrains Mono', monospace" fill="#4B5563">NIC MAC: <tspan font-weight="700" fill="#DC2626">${state.realMacs.attacker || 'detecting...'}</tspan></text>
      <!-- Engine Status Box -->
      <rect x="411" y="442" width="318" height="62" rx="10" fill="${aBadgeBg}" stroke="${aBadgeColor}" stroke-width="1" />
      <text x="425" y="462" font-size="10" font-weight="700" fill="${aBadgeColor}" font-family="'Noto Sans', sans-serif">RAW SOCKET ENGINE (arp_spoof.py):</text>
      <text x="425" y="486" font-size="11" font-weight="700" fill="${aBadgeColor}" font-family="'Noto Sans', sans-serif">${aBadgeText}</text>
    </g>
  `;

  setSvgContent(svg, markup);

  // Update topology card header badge
  const badgeEl = $('#topology-attack-badge');
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

  // Update Live Kernel ARP Tables simultaneously
  renderArpTables();
  applySimViewMode();
}

/* ─── Track previous ARP resolution state for live visual deltas ────────── */
const prevArpState = {
  victimGwMac: '',
  gwVictimMac: '',
  init: false
};

/* ─── Render Live Kernel ARP Tables & Resolution Diffs (Spacious Zero-Overlap Layout) ─── */
function renderArpTables() {
  const container = $('#topology-arp-tables-section');
  if (!container) return;

  const attackerMac = (state.realMacs.attacker || '').toLowerCase();
  const gatewayRealMac = (state.realMacs.gateway || '').toLowerCase();
  const victimRealMac = (state.realMacs.victim || '').toLowerCase();

  const victimGwMac = (state.arpTables.victim?.['10.10.10.1'] || '').toLowerCase();
  const victimAttackerMac = (state.arpTables.victim?.['10.10.10.66'] || '').toLowerCase();

  const gwVictimMac = (state.arpTables.gateway?.['10.10.10.10'] || '').toLowerCase();
  const gwAttackerMac = (state.arpTables.gateway?.['10.10.10.66'] || '').toLowerCase();

  let isVictimPoisoned = false;
  if (victimGwMac) {
    if (attackerMac && victimGwMac === attackerMac) isVictimPoisoned = true;
    else if (gatewayRealMac && victimGwMac !== gatewayRealMac) isVictimPoisoned = true;
  }

  let isGwPoisoned = false;
  if (gwVictimMac) {
    if (attackerMac && gwVictimMac === attackerMac) isGwPoisoned = true;
    else if (victimRealMac && gwVictimMac !== victimRealMac) isGwPoisoned = true;
  }

  const isAttacking = state.attackActive;
  const isMitigated = state.mitigationOn;
  const attackMode = state.attackMode || 'mitm';
  const isMitm = attackMode === 'mitm';
  const isDos = attackMode === 'dos';

  // Detect change for live flash animation
  let victimFlash = false;
  let gwFlash = false;
  if (prevArpState.init) {
    if (prevArpState.victimGwMac && prevArpState.victimGwMac !== victimGwMac) {
      victimFlash = true;
    }
    if (prevArpState.gwVictimMac && prevArpState.gwVictimMac !== gwVictimMac) {
      gwFlash = true;
    }
  } else {
    prevArpState.init = true;
  }
  prevArpState.victimGwMac = victimGwMac;
  prevArpState.gwVictimMac = gwVictimMac;

  let html = `
    <!-- Ground Truth Hardware Reference Strip (3-Column Card Grid) -->
    <div class="arp-hardware-grid">
      <div class="hw-card hw-gw">
        <div class="hw-header">
          <span class="hw-icon">🌐</span>
          <span class="hw-title">Default Gateway (10.10.10.1)</span>
        </div>
        <div class="hw-mac-row">
          <span class="hw-label">Physical NIC:</span>
          <code class="hw-mac font-mono text-teal">${gatewayRealMac || 'resolving...'}</code>
        </div>
      </div>

      <div class="hw-card hw-victim">
        <div class="hw-header">
          <span class="hw-icon">💻</span>
          <span class="hw-title">Victim Target (10.10.10.10)</span>
        </div>
        <div class="hw-mac-row">
          <span class="hw-label">Physical NIC:</span>
          <code class="hw-mac font-mono text-blue">${victimRealMac || 'resolving...'}</code>
        </div>
      </div>

      <div class="hw-card hw-attacker">
        <div class="hw-header">
          <span class="hw-icon">⚡</span>
          <span class="hw-title">Attacker Spoofer (10.10.10.66)</span>
        </div>
        <div class="hw-mac-row">
          <span class="hw-label">Rogue NIC:</span>
          <code class="hw-mac font-mono text-red font-bold">${attackerMac || 'resolving...'}</code>
        </div>
      </div>
    </div>

    <!-- Side-by-Side Live ARP Tables (Spacious 2-Column Design) -->
    <div class="arp-side-by-side-grid">

      <!-- ── VICTIM ARP TABLE ── -->
      <div class="arp-table-card ${isVictimPoisoned && !isMitigated ? 'card-poisoned' : (isMitigated ? 'card-mitigated' : '')}">
        <div class="arp-table-card-header">
          <span class="table-header-title">
            <span>💻</span> Victim Host ARP Cache (10.10.10.10)
          </span>
          <span class="badge-tag ${isMitigated ? 'tag-blue' : (isVictimPoisoned ? 'tag-red badge-pulse' : 'tag-teal')}">
            ${isMitigated ? '🛡️ Protected (Static)' : (isVictimPoisoned ? '⚠️ POISONED!' : '✓ Authentic Gateway')}
          </span>
        </div>
        <div class="arp-table-responsive">
          <table class="arp-data-table spacious-table">
            <thead>
              <tr>
                <th style="width:30%">Target Host</th>
                <th style="width:70%">Resolved MAC & Routing</th>
              </tr>
            </thead>
            <tbody>
              <!-- Row for 10.10.10.1 (Gateway) -->
              <tr class="${isVictimPoisoned && !isMitigated ? 'row-poisoned' : ''} ${victimFlash ? 'row-changed-flash' : ''}">
                <td>
                  <div class="ip-cell">
                    <div class="ip-top-row">
                      <span class="ip-address font-mono">10.10.10.1</span>
                      <span class="type-pill ${isMitigated ? 'pill-static' : 'pill-dynamic'}">${isMitigated ? 'Static' : 'Dynamic'}</span>
                    </div>
                    <span class="ip-label">Gateway Router</span>
                  </div>
                </td>
                <td>
                  <div class="binding-cell">
                    <div class="binding-primary-row">
                      <code class="font-mono mac-code ${isVictimPoisoned && !isMitigated ? 'mac-poison-pill' : (isMitigated ? 'mac-static' : 'mac-authentic')}">
                        ${victimGwMac || gatewayRealMac || 'resolving...'}
                      </code>
                      <span class="badge-tag ${isMitigated ? 'tag-blue' : (isVictimPoisoned && !isMitigated ? 'tag-red badge-pulse' : 'tag-teal')}">
                        ${isMitigated ? '🛡️ Protected' : (isVictimPoisoned && !isMitigated ? '⚠️ ATTACKER' : '✓ Authentic')}
                      </span>
                    </div>
                    ${isVictimPoisoned && !isMitigated ? `
                      <div class="binding-diff-row">
                        <span class="diff-expected">True NIC: <code class="font-mono strikethrough">${gatewayRealMac}</code></span>
                        <span class="diff-route text-danger">🚨 Diverted to Attacker</span>
                      </div>
                    ` : `
                      <div class="binding-diff-row">
                        <span class="diff-route text-safe">${isMitigated ? '🛡️ Direct — spoof ignored' : '✓ Direct legitimate delivery'}</span>
                      </div>
                    `}
                  </div>
                </td>
              </tr>

              <!-- Row for 10.10.10.66 (Attacker) -->
              <tr>
                <td>
                  <div class="ip-cell">
                    <div class="ip-top-row">
                      <span class="ip-address font-mono">10.10.10.66</span>
                      <span class="type-pill pill-dynamic">Dynamic</span>
                    </div>
                    <span class="ip-label">Attacker Host</span>
                  </div>
                </td>
                <td>
                  <div class="binding-cell">
                    <div class="binding-primary-row">
                      <code class="font-mono mac-code" style="background:#F1F5F9;color:#334155">${victimAttackerMac || attackerMac || 'unknown'}</code>
                      <span class="badge-tag" style="background:#F1F5F9;color:#475569">Local Neighbor</span>
                    </div>
                    <div class="binding-diff-row">
                      <span class="diff-route text-safe">✓ Direct local delivery</span>
                    </div>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ── GATEWAY ARP TABLE ── -->
      <div class="arp-table-card ${isGwPoisoned && !isMitigated ? 'card-poisoned' : (isMitigated ? 'card-mitigated' : '')}">
        <div class="arp-table-card-header">
          <span class="table-header-title">
            <span>🌐</span> Gateway Host ARP Cache (10.10.10.1)
          </span>
          <span class="badge-tag ${isMitigated ? 'tag-blue' : (isGwPoisoned ? 'tag-red badge-pulse' : 'tag-teal')}">
            ${isMitigated ? '🛡️ Protected (Static)' : (isGwPoisoned ? '⚠️ POISONED!' : '✓ Authentic Victim')}
          </span>
        </div>
        <div class="arp-table-responsive">
          <table class="arp-data-table spacious-table">
            <thead>
              <tr>
                <th style="width:30%">Target Host</th>
                <th style="width:70%">Resolved MAC & Routing</th>
              </tr>
            </thead>
            <tbody>
              <!-- Row for 10.10.10.10 (Victim) -->
              <tr class="${isGwPoisoned && !isMitigated ? 'row-poisoned' : ''} ${gwFlash ? 'row-changed-flash' : ''}">
                <td>
                  <div class="ip-cell">
                    <div class="ip-top-row">
                      <span class="ip-address font-mono">10.10.10.10</span>
                      <span class="type-pill ${isMitigated ? 'pill-static' : 'pill-dynamic'}">${isMitigated ? 'Static' : 'Dynamic'}</span>
                    </div>
                    <span class="ip-label">Victim Workstation</span>
                  </div>
                </td>
                <td>
                  <div class="binding-cell">
                    <div class="binding-primary-row">
                      <code class="font-mono mac-code ${isGwPoisoned && !isMitigated ? 'mac-poison-pill' : (isMitigated ? 'mac-static' : 'mac-authentic')}">
                        ${gwVictimMac || victimRealMac || 'resolving...'}
                      </code>
                      <span class="badge-tag ${isMitigated ? 'tag-blue' : (isGwPoisoned && !isMitigated ? 'tag-red badge-pulse' : 'tag-teal')}">
                        ${isMitigated ? '🛡️ Protected' : (isGwPoisoned && !isMitigated ? '⚠️ ATTACKER' : '✓ Authentic')}
                      </span>
                    </div>
                    ${isGwPoisoned && !isMitigated ? `
                      <div class="binding-diff-row">
                        <span class="diff-expected">True NIC: <code class="font-mono strikethrough">${victimRealMac}</code></span>
                        <span class="diff-route text-danger">🚨 Inbound diverted to Attacker</span>
                      </div>
                    ` : `
                      <div class="binding-diff-row">
                        <span class="diff-route text-safe">${isMitigated ? '🛡️ Direct — spoof ignored' : '✓ Direct legitimate delivery'}</span>
                      </div>
                    `}
                  </div>
                </td>
              </tr>

              <!-- Row for 10.10.10.66 (Attacker) -->
              <tr>
                <td>
                  <div class="ip-cell">
                    <div class="ip-top-row">
                      <span class="ip-address font-mono">10.10.10.66</span>
                      <span class="type-pill pill-dynamic">Dynamic</span>
                    </div>
                    <span class="ip-label">Attacker Host</span>
                  </div>
                </td>
                <td>
                  <div class="binding-cell">
                    <div class="binding-primary-row">
                      <code class="font-mono mac-code" style="background:#F1F5F9;color:#334155">${gwAttackerMac || attackerMac || 'unknown'}</code>
                      <span class="badge-tag" style="background:#F1F5F9;color:#475569">Local Neighbor</span>
                    </div>
                    <div class="binding-diff-row">
                      <span class="diff-route text-safe">✓ Direct local delivery</span>
                    </div>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

    </div>

    <!-- Dynamic Layer 2 Status & Impact Strip -->
    <div class="arp-status-banner ${isMitigated ? 'state-mitigated' : (isAttacking ? 'state-poisoned' : 'state-healthy')}">
      <span class="status-banner-icon">${isMitigated ? '🛡️' : (isAttacking ? (isMitm ? '🚨' : '🚫') : '✓')}</span>
      <span class="status-banner-text">
        ${isMitigated ?
          '<strong>Static Defense Active:</strong> ARP bindings are locked with kernel flag <code>PERMANENT</code>. Forged replies are discarded by the kernel networking stack; authentic direct communication is preserved.' :
          (isAttacking && isMitm ?
            `<strong>MITM Active:</strong> IP-to-MAC resolution poisoned! Packets to <code>10.10.10.1</code> route to Attacker MAC (<code>${attackerMac}</code>), allowing the attacker to intercept and relay traffic.'` :
            (isAttacking && isDos ?
              `<strong>DoS Active:</strong> Victim ARP poisoned to Attacker MAC (<code>${attackerMac}</code>). With kernel forwarding disabled (<code>ip_forward=0</code>), packets are silently dropped (100% loss).` :
              '<strong>Authentic LAN State:</strong> Both hosts resolve true physical NIC MACs. IP/ICMP frames flow directly with authentic ARP resolution.'
            )
          )
        }
      </span>
    </div>
  `;

  container.innerHTML = html;
  applySimViewMode();
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
      <div class="quiz-container">
        <div class="intro-block">
          <span class="intro-label">ARP / Virtual Lab</span>
          <h2>Assignment Completed</h2>
          <p>Review your results and restart whenever you'd like to test your understanding again.</p>
        </div>
        <div class="quiz-score-card">
          <p class="quiz-score">${state.quizScore} / ${QUIZ.length}</p>
          <p style="color:var(--text-main);font-weight:700;font-size:16px;margin-bottom:6px">
            ${state.quizScore >= 8 ? '🎉 Outstanding Result!' : (state.quizScore >= 5 ? '👍 Good Effort!' : '📖 Room for Improvement')}
          </p>
          <p style="color:var(--text-secondary);margin-bottom:24px;font-size:13.5px;line-height:1.6">
            ${state.quizScore >= 8
              ? 'You have demonstrated a comprehensive understanding of ARP mechanics, cache poisoning, and Layer 2 mitigations.'
              : 'Review the Theory and Procedure tabs to reinforce your knowledge of ARP request/reply cycles and DAI defenses.'}
          </p>
          <button class="btn-primary-pill" id="quiz-restart">↺ Restart Quiz</button>
        </div>
      </div>`;
    $('#quiz-restart').addEventListener('click', () => {
      state.quizIndex = 0; state.quizScore = 0; state.quizAnswer = null;
      renderQuiz();
    });
    return;
  }

  const q = QUIZ[state.quizIndex];
  const progressPercent = Math.round(((state.quizIndex + 1) / QUIZ.length) * 100);

  panel.innerHTML = `
    <div class="quiz-container">
      <div class="intro-block">
        <div class="flex items-center justify-between flex-wrap gap-2">
          <span class="intro-label">ARP / Virtual Lab</span>
          <span class="quiz-progress-badge">Question ${state.quizIndex + 1} of ${QUIZ.length}</span>
        </div>
        <h2>Knowledge Assessment</h2>
        <p>Answer each question to test your mastery of ARP protocol fundamentals, cache poisoning mechanics, and mitigation techniques.</p>
        <div class="quiz-progress-track">
          <div class="quiz-progress-fill" style="width:${progressPercent}%"></div>
        </div>
      </div>
      <div class="quiz-card">
        <p class="quiz-question">${q.question}</p>
        <div class="quiz-options">
          ${q.options.map((opt, idx) => `
            <button class="quiz-option" data-idx="${idx}" ${state.quizAnswer !== null ? 'disabled' : ''}
              style="${state.quizAnswer === idx
                ? idx === q.correctIndex
                  ? 'background:#EBF7F4;border:1.5px solid #2A8C76;color:#1B6554;'
                  : 'background:#FDF0EF;border:1.5px solid #E06C62;color:#B91C1C;'
                : ''}">
              <span class="quiz-opt-letter">${String.fromCharCode(65 + idx)}</span>
              <span>${opt}</span>
            </button>`).join('')}
        </div>
        ${state.quizAnswer !== null ? `
          <div class="quiz-explanation">
            <strong style="color:${state.quizAnswer === q.correctIndex ? '#1B6554' : '#B91C1C'}">
              ${state.quizAnswer === q.correctIndex ? '✓ Correct Answer!' : '✕ Incorrect'}
            </strong>
            <p style="margin-top:6px;line-height:1.6">${q.explanation}</p>
            <button class="btn-primary-pill" id="quiz-next" style="margin-top:14px">Next question →</button>
          </div>` : ''}
      </div>
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
        <div class="header-left">
          <button class="back-btn-circle" aria-label="Go back" onclick="history.back()">&#8592;</button>
          <div>
            <h1>ARP Spoofing / Virtual Lab</h1>
            <p class="header-sub">• Cybersecurity Teaching Lab • Interactive</p>
          </div>
        </div>
        <div class="header-right">
          <div class="edtech-pill">
            <span class="status-dot" id="ws-dot"></span>
            <span id="ws-text" style="font-family:'JetBrains Mono',monospace;font-size:11.5px">connecting</span>
          </div>
          <div class="edtech-pill">
            <span id="lab-status-text" style="font-size:11.5px;font-weight:700">Stopped</span>
          </div>
        </div>
      </div>
    </header>

    <!-- Main content container -->
    <main class="max-w-7xl main-content">

      <!-- Navigation Tab Bar -->
      <nav id="tab-bar" role="tablist">
        ${TABS.map(t => `<button class="tab-btn" data-tab="${t}" role="tab">${t}</button>`).join('')}
      </nav>

      <!-- ── AIM ── -->
      <section id="panel-Aim" class="tab-panel" role="tabpanel">
        <div class="intro-block">
          <span class="intro-label">ARP / Virtual Lab</span>
          <h2>Aim of the Experiment</h2>
          <p>Demonstrate the fundamental operation of the Address Resolution Protocol (ARP), analyze why the lack of authentication leaves networks susceptible to ARP Cache Poisoning, and observe how Man-in-the-Middle (MITM) and Denial of Service (DoS) attacks manipulate network communications in a sandboxed Docker environment.</p>
        </div>
        <div class="grid-feature-cards">
          <div class="feature-card">
            <div class="feature-icon-badge">L2</div>
            <h3>OSI Layer 2 Mechanics</h3>
            <p>Understand how Layer 3 logical IP addresses are mapped to physical hardware MAC addresses and stored in operating system kernel ARP tables.</p>
          </div>
          <div class="feature-card">
            <div class="feature-icon-badge">⚡</div>
            <h3>Live Packet Injection</h3>
            <p>Witness real raw-socket Scapy scripts injecting forged Gratuitous ARP frames to overwrite remote caches and hijack legitimate traffic flows.</p>
          </div>
          <div class="feature-card">
            <div class="feature-icon-badge">🛡️</div>
            <h3>Defensive Engineering</h3>
            <p>Evaluate countermeasures including OS-level Static ARP entry enforcement and enterprise switch-level Dynamic ARP Inspection (DAI).</p>
          </div>
        </div>
      </section>

      <!-- ── OBJECTIVE ── -->
      <section id="panel-Objective" class="tab-panel" role="tabpanel">
        <div class="intro-block">
          <span class="intro-label">ARP / Virtual Lab</span>
          <h2>Learning Objectives</h2>
          <p>By completing this laboratory experiment, you will gain the theoretical foundation and practical skills to:</p>
        </div>
        <div class="objective-cards-grid">
          <div class="objective-card">
            <div class="obj-check-circle">✓</div>
            <div class="obj-content">
              <h4>Explain ARP Protocol Mechanics</h4>
              <p>Analyze broadcast ARP Requests (ff:ff:ff:ff:ff:ff), unicast ARP Replies, and dynamic cache retention timers across networked nodes.</p>
            </div>
          </div>
          <div class="objective-card">
            <div class="obj-check-circle">✓</div>
            <div class="obj-content">
              <h4>Identify Poisoned ARP Cache Entries</h4>
              <p>Spot cryptographic and addressing anomalies where multiple distinct IPs (e.g. 10.10.10.1 and 10.10.10.66) resolve to the identical MAC address.</p>
            </div>
          </div>
          <div class="objective-card">
            <div class="obj-check-circle">✓</div>
            <div class="obj-content">
              <h4>Contrast MITM Interception vs. DoS Blackholing</h4>
              <p>Understand the impact of kernel IP forwarding (ip_forward=1 vs. 0) in maintaining transparent eavesdropping versus terminating victim connectivity.</p>
            </div>
          </div>
          <div class="objective-card">
            <div class="obj-check-circle">✓</div>
            <div class="obj-content">
              <h4>Implement and Verify Defensive Mitigations</h4>
              <p>Configure immutable static ARP bindings in Linux kernel caches and examine hardware DAI validation against DHCP snooping tables.</p>
            </div>
          </div>
        </div>
      </section>

      <!-- ── THEORY ── -->
      <section id="panel-Theory" class="tab-panel" role="tabpanel">
        <div class="intro-block">
          <span class="intro-label">ARP / Virtual Lab</span>
          <h2>Theory & Protocol Mechanics</h2>
          <p>Address Resolution Protocol (ARP, RFC 826) operates at the Data Link/Network boundary, enabling IP packets to be encapsulated into Ethernet frames on local broadcast domains.</p>
        </div>
        <div class="theory-grid">
          ${[
            ['Layer 2 vs Layer 3', 'Ethernet frames require destination MAC addresses. When Host A transmits an IP packet to Host B on the same subnet, it must first resolve B’s physical MAC address using an ARP Request.'],
            ['ARP Request / Reply', 'ARP Requests are broadcasted (dst ff:ff:ff:ff:ff:ff) asking "Who has IP X?". The rightful owner responds with a unicast ARP Reply stating "IP X is at MAC Y".'],
            ['The ARP Cache', 'Operating systems cache learned IP-to-MAC associations for 30–120 seconds to prevent broadcast storms. Entries are mutable and continuously updated by incoming frames.'],
            ['Lack of Authentication', 'Designed in 1982 for trusted academic LANs, ARP has zero cryptographic authentication. Any device on the subnet can claim ownership of any IP without proof.'],
            ['Gratuitous ARP', 'Unsolicited ARP announcements update neighbors of IP/MAC changes (e.g. NIC failover). Attackers exploit this to silently overwrite remote caches without prior requests.'],
            ['MITM vs DoS', 'In MITM, the attacker enables kernel IP forwarding to invisibly relay packets. In DoS, forwarding is disabled, causing all redirected packets to be silently dropped.'],
            ['Static ARP Defense', 'Permanent IP-to-MAC bindings configured manually in the OS cache cannot be overwritten by incoming forged ARP replies, though manual deployment does not scale easily.'],
            ['Dynamic ARP Inspection', 'Enterprise switches with DAI validate incoming ARP packets against the DHCP Snooping Binding Table, dropping forged packets at the physical switch-port level.'],
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
          <h2>Step-by-Step Laboratory Procedure</h2>
          <p>Follow this systematic sequence to boot the container network, launch targeted ARP cache poisoning attacks, and evaluate defenses.</p>
        </div>
        <div class="procedure-cards-grid">
          <div class="procedure-card">
            <span class="procedure-step-number">01</span>
            <h4>Start the Lab Environment</h4>
            <p>Navigate to the Simulation tab and click <strong>Start Lab</strong>. This boots the isolated Docker bridge network and initializes Victim, Gateway, and Attacker nodes.</p>
            <span class="procedure-expected">Expected: Status shows "Running — Vulnerable"</span>
          </div>
          <div class="procedure-card">
            <span class="procedure-step-number">02</span>
            <h4>Select Attack Mode & Launch</h4>
            <p>Select either <strong>MITM</strong> (packet relaying) or <strong>DoS</strong> (packet blackhole) from the dropdown and click <strong>Start Attack</strong> to begin transmitting forged ARP packets.</p>
            <span class="procedure-expected">Expected: Scapy engine begins injecting forged frames</span>
          </div>
          <div class="procedure-card">
            <span class="procedure-step-number">03</span>
            <h4>Observe Kernel Cache Poisoning</h4>
            <p>Watch the Live Network Map update in real time. The Victim node turns red as its kernel table maps the Gateway IP (10.10.10.1) to the Attacker's MAC address.</p>
            <span class="procedure-expected">Expected: Traffic flows reroute through the Attacker node</span>
          </div>
          <div class="procedure-card">
            <span class="procedure-step-number">04</span>
            <h4>Toggle Static ARP Mitigation</h4>
            <p>Switch on the <strong>Mitigation enabled</strong> toggle. This installs authoritative static ARP entries in the kernel table, preventing forged replies from overriding bindings.</p>
            <span class="procedure-expected">Expected: Blue shield active; direct legitimate path restored</span>
          </div>
          <div class="procedure-card">
            <span class="procedure-step-number">05</span>
            <h4>Stop Attack & Verify Recovery</h4>
            <p>Click <strong>Stop Attack</strong>. The attacker terminates its packet injection loop and transmits corrective ARP frames to restore authentic hardware bindings.</p>
            <span class="procedure-expected">Expected: Red attack indicators subside to normal green state</span>
          </div>
          <div class="procedure-card">
            <span class="procedure-step-number">06</span>
            <h4>Complete Assessment & Feedback</h4>
            <p>Test your knowledge on the <strong>Assignment</strong> tab with the 10-question quiz, then submit your reflections on the <strong>Feedback</strong> tab.</p>
            <span class="procedure-expected">Expected: Score tracked with detailed explanations</span>
          </div>
        </div>
      </section>

      <!-- ── SIMULATION ── -->
      <section id="panel-Simulation" class="tab-panel" role="tabpanel">

        <!-- Alert banner -->
        <div class="alert-warm" id="sim-alert">
          <span class="alert-icon">📡</span>
          <span class="alert-text">Backend not connected — retrying in the background.</span>
        </div>

        <!-- Responsive Simulation Grid (2 columns on PC, 1 on Mobile) -->
        <div class="sim-grid">

          <!-- LEFT: Topology diagram -->
          <div class="topology-card">
            <div class="topology-card-header">
              <div class="flex items-center gap-2 flex-wrap">
                <span class="title">Live ARP Network Map</span>
                <span id="topology-attack-badge" class="badge-tag tag-teal">Normal Direct Traffic</span>
              </div>
              <div class="sim-view-switcher" id="sim-view-switcher">
                <button type="button" class="view-btn active" data-view="both" title="View Network Map and ARP Tables together">🔀 Map + Tables</button>
                <button type="button" class="view-btn" data-view="map" title="View Network Map Only">🗺️ Map Only</button>
                <button type="button" class="view-btn" data-view="tables" title="View ARP Resolution Tables Only">📋 Tables Only</button>
              </div>
              <span class="subtitle">10.10.10.0/24 Isolated Bridge</span>
            </div>

            <!-- Mobile pan indicator hint -->
            <div class="mobile-pan-hint">↔ Swipe horizontally to explore full network topology</div>

            <div class="topology-svg-wrap" id="topology-svg-wrap">
              <svg id="topology-svg" viewBox="0 0 1140 560" role="img" aria-label="Live ARP network topology diagram">
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
                  <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
                    <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#EAE6E2" stroke-width="0.5"/>
                  </pattern>
                </defs>
                <rect width="1140" height="560" fill="url(#grid)" rx="14"/>
                <g id="topology-dynamic-layer"></g>
              </svg>
            </div>
            <div class="topology-legend-bar" id="topology-legend-bar">
              <span class="legend-item"><span class="legend-dot dot-teal"></span> Genuine IP/ICMP</span>
              <span class="legend-item"><span class="legend-dot dot-coral"></span> Forged ARP Replies</span>
              <span class="legend-item"><span class="legend-dot dot-amber"></span> Intercepted Frames</span>
              <span class="legend-item"><span class="legend-dot dot-purple"></span> MITM Relayed</span>
              <span class="legend-item"><span class="legend-dot dot-shield"></span> Static Protected</span>
            </div>

            <!-- Live Kernel ARP Resolution Tables & Delta Tracker -->
            <div class="topology-arp-tables-section" id="topology-arp-tables-section">
              <!-- Dynamically rendered by renderArpTables() -->
            </div>
          </div>

          <!-- RIGHT: Sidebar Controls & Log -->
          <div class="sidebar">

            <!-- Controls collapsible -->
            <div class="controls-panel">
              <button class="section-header-strip flat" id="controls-toggle" aria-expanded="true">
                <span>Lab Controls</span>
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
                <div>
                  <label for="attack-mode-select" style="display:block;font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:6px">Attack Mode</label>
                  <select class="native-select" id="attack-mode-select">
                    <option value="mitm">Man-in-the-Middle (MITM Interception)</option>
                    <option value="dos">Denial of Service (DoS Blackhole)</option>
                  </select>
                </div>

                <!-- Start Attack -->
                <button class="btn-primary-pill w-full" data-api="/api/attack/start" id="btn-start-attack" style="justify-content:center">
                  <span class="spinner" style="display:none"></span>
                  ⚡ Start Attack
                </button>

                <!-- Stop Attack -->
                <button class="btn-danger w-full" data-api="/api/attack/stop" id="btn-stop-attack" style="justify-content:center">
                  ■ Stop Attack
                </button>

                <!-- Mitigation toggle -->
                <div class="mitigation-row">
                  <div>
                    <span style="font-size:13.5px;font-weight:600;color:var(--text-main);display:block">Static ARP Defense</span>
                    <span style="font-size:11.5px;color:var(--text-secondary)">Lock authoritative IP-MAC bindings</span>
                  </div>
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
                <span>Live Event Stream</span>
                <span class="chevron-circle">▾</span>
              </button>
              <div id="log-body" style="padding:14px">
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
          <p>Official RFC specifications, academic textbooks, threat actor profiles, and enterprise defense guides covering ARP security and Layer 2 mitigations.</p>
        </div>
        <div class="references-grid">
          ${REFERENCES.map(ref => `
            <div class="reference-card">
              <div class="ref-header">
                <span class="badge-tag ${ref.tagClass}">${ref.tag}</span>
                <span class="ref-author">${ref.author}</span>
              </div>
              <h3 class="ref-title">${ref.title}</h3>
              <p class="ref-desc">${ref.desc}</p>
              ${ref.url ? `
                <a href="${ref.url}" target="_blank" rel="noopener noreferrer" class="ref-link-btn">
                  <span>View Documentation</span>
                  <span>→</span>
                </a>` : ''}
            </div>`).join('')}
        </div>
      </section>

      <!-- ── FEEDBACK ── -->
      <section id="panel-Feedback" class="tab-panel" role="tabpanel">
        <div class="intro-block">
          <span class="intro-label">ARP / Virtual Lab</span>
          <h2>Student Feedback & Lab Evaluation</h2>
          <p>Help us improve future cybersecurity laboratory modules by sharing your reflections and feedback on this experiment.</p>
        </div>
        <div class="feedback-container">
          <div class="feedback-card">
            <label class="form-label">
              Your Name (Optional)
              <input class="form-input" type="text" id="feedback-name" placeholder="Enter your name or student ID">
            </label>
            <fieldset style="border:none">
              <legend style="font-size:13.5px;font-weight:600;color:var(--text-main);margin-bottom:10px">Overall Rating</legend>
              <div class="rating-row">
                ${[1,2,3,4,5].map(v => `
                  <button class="rating-btn" data-v="${v}" aria-label="${v} stars" type="button">${v}</button>`).join('')}
              </div>
            </fieldset>
            <label class="form-label">
              Observations & Suggestions
              <textarea class="form-input" id="feedback-comment" placeholder="What concepts were most clear? Did you encounter any difficulties during the simulation?"></textarea>
            </label>
            <button class="btn-primary-pill" id="feedback-submit" style="align-self:flex-start">Submit Feedback</button>
          </div>
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

  /* Sim view switcher (both / map / tables) */
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.view-btn');
    if (!btn || !btn.dataset.view) return;
    state.simViewMode = btn.dataset.view;
    applySimViewMode();
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
