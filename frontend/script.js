/* ──────────────────────────────────────────────────────────────
   ARP Spoofing Virtual Lab — script.js
   Plain ES2020, no frameworks, no build step.
   Talks to backend at API_BASE_URL (port 8000 by default).
   ────────────────────────────────────────────────────────────── */

'use strict';

/* ─── Config ───────────────────────────────────────────────── */
const API_BASE_URL = (window.LAB_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');
const WS_BASE_URL  = API_BASE_URL.replace(/^http/, 'ws');

/* ─── Known MACs for poisoning detection ───────────────────── */
const LEGIT_MACS = {
  victim:   '02:42:0a:0a:0a:0a',
  gateway:  '02:42:0a:0a:0a:01',
  attacker: '02:42:0a:0a:0a:42',
};

/* ─── Node positions in SVG (520 × 320 viewBox) ─────────────── */
const NODES = [
  { key: 'victim',   label: 'Victim',   ip: '10.10.10.10', x: 100, y: 160 },
  { key: 'gateway',  label: 'Gateway',  ip: '10.10.10.1',  x: 420, y:  75 },
  { key: 'attacker', label: 'Attacker', ip: '10.10.10.66', x: 420, y: 245 },
];

/* Maps: from-node → to-node, which mac-slot to check */
const LINKS = [
  { from: NODES[0], to: NODES[1], owner: 'gateway'  },
  { from: NODES[1], to: NODES[0], owner: 'victim'   },
  { from: NODES[0], to: NODES[2], owner: 'attacker' },
];

/* ─── Application state ─────────────────────────────────────── */
const state = {
  activeTab:    'Simulation',
  socketStatus: 'connecting',   // 'connecting' | 'connected' | 'disconnected'
  events:       [],             // last 200 LabEvents
  latestArp:    {},             // node → arp_update event
  attackMode:   'mitm',
  mitigationOn: false,
  pending:      '',             // path of in-flight request
  quizIndex:    0,
  quizAnswer:   null,           // null | number
  quizScore:    0,
  feedbackRating: 0,
  feedbackSubmitted: false,
  modulesOpen:  true,
  controlsOpen: true,
  logOpen:      true,
};

/* ─── Tabs & module icons ───────────────────────────────────── */
const TABS = ['Aim', 'Objective', 'Theory', 'Procedure', 'Simulation', 'Assignment', 'References', 'Feedback'];
const MODULE_ICONS = {
  Aim: 'AI', Objective: 'OB', Theory: 'TH', Procedure: 'PR',
  Simulation: 'SI', Assignment: 'AS', References: 'RE', Feedback: 'FB',
};

/* ─── Quiz data (mirrors lib/quiz-data.ts) ──────────────────── */
const QUIZ = [
  {
    question: 'What does ARP map?',
    options:  ['IP addresses to MAC addresses', 'MAC addresses to passwords', 'Ports to processes', 'DNS names to IP addresses'],
    correctIndex: 0,
    explanation: 'ARP resolves a local network-layer IP address to a link-layer MAC address.',
  },
  {
    question: 'Why is ARP spoofing possible?',
    options:  ['ARP replies are not authenticated', 'Switches encrypt all frames', 'DNS is case-sensitive', 'TCP requires a password'],
    correctIndex: 0,
    explanation: 'Hosts generally accept unsolicited ARP replies, so an attacker can poison their caches.',
  },
  {
    question: 'What is a common MITM defense?',
    options:  ['Dynamic ARP Inspection', 'Disabling HTTPS', 'Using longer hostnames', 'Broadcasting more ARP requests'],
    correctIndex: 0,
    explanation: 'Dynamic ARP Inspection validates ARP packets against trusted DHCP bindings.',
  },
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
    showToast('Command sent', 'success');
  } catch (err) {
    showToast(`Backend not connected — ${err.message || 'could not reach API'}`, 'error');
  } finally {
    state.pending = '';
    renderButtons();
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
  };

  _ws.onmessage = (msg) => {
    try {
      const event = JSON.parse(msg.data);
      state.events = [...state.events.slice(-199), event];
      if (event.type === 'arp_update') {
        state.latestArp = { ...state.latestArp, [event.node]: event };
        renderDiagram();
      }
      if (['log', 'attack_state', 'mitigation_state'].includes(event.type)) {
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
  const rev = [...state.events].reverse();
  const attackState     = rev.find(e => e.type === 'attack_state');
  const mitigationState = rev.find(e => e.type === 'mitigation_state');
  const running = state.events.some(e => e.type === 'log' && e.message?.toLowerCase().includes('started'));

  if (attackState?.active)                    return 'Under Attack';
  if (!running)                               return 'Stopped';
  if (mitigationState?.enabled ?? state.mitigationOn) return 'Running — Protected';
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

/* SVG topology diagram */
function renderDiagram() {
  const svg = $('#topology-svg');
  if (!svg) return;

  /* clear old dynamic elements */
  $$('.dyn', svg).forEach(el => el.remove());

  /* Background grid */
  const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  bg.setAttribute('width', '520'); bg.setAttribute('height', '320');
  bg.setAttribute('fill', '#FDFBF9'); bg.setAttribute('rx', '14');
  bg.classList.add('dyn');
  svg.prepend(bg);

  /* Edges */
  LINKS.forEach(link => {
    const arpEntry  = state.latestArp[link.from.key];
    const currentMac = arpEntry?.mac;
    const poisoned   = Boolean(currentMac && currentMac === LEGIT_MACS.attacker && link.owner !== 'attacker');
    const color      = poisoned ? '#E06C62' : '#2A8C76';
    const midX       = (link.from.x + link.to.x) / 2;
    const midY       = (link.from.y + link.to.y) / 2;
    const markerId   = poisoned ? 'coral-arrow' : 'teal-arrow';

    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.classList.add('dyn');

    /* Line */
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', link.from.x); line.setAttribute('y1', link.from.y);
    line.setAttribute('x2', link.to.x);   line.setAttribute('y2', link.to.y);
    line.setAttribute('stroke', color);
    line.setAttribute('stroke-width', '2');
    if (poisoned) line.setAttribute('stroke-dasharray', '6 5');
    line.setAttribute('marker-end', `url(#${markerId})`);

    /* Label pill background */
    const pill = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    pill.setAttribute('x', midX - 38); pill.setAttribute('y', midY - 16);
    pill.setAttribute('width', '76'); pill.setAttribute('height', '18');
    pill.setAttribute('rx', '9'); pill.setAttribute('fill', '#FFFFFF');
    pill.setAttribute('stroke', color); pill.setAttribute('stroke-width', '1');

    /* Label text */
    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', midX); label.setAttribute('y', midY - 4);
    label.setAttribute('fill', color);
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('font-size', '9');
    label.setAttribute('font-family', "'JetBrains Mono', monospace");
    label.textContent = currentMac ?? 'awaiting ARP';

    g.append(line, pill, label);
    svg.appendChild(g);
  });

  /* Nodes */
  NODES.forEach(node => {
    const isAttacker = node.key === 'attacker';
    const fill   = isAttacker ? '#FDF0EF' : '#EBF7F4';
    const stroke = isAttacker ? '#E06C62' : '#2A8C76';

    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.classList.add('dyn');

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', node.x); circle.setAttribute('cy', node.y); circle.setAttribute('r', '42');
    circle.setAttribute('fill', fill); circle.setAttribute('stroke', stroke); circle.setAttribute('stroke-width', '2.5');

    const nameText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    nameText.setAttribute('x', node.x); nameText.setAttribute('y', node.y - 4);
    nameText.setAttribute('fill', '#1F1F1F'); nameText.setAttribute('text-anchor', 'middle');
    nameText.setAttribute('font-size', '13'); nameText.setAttribute('font-weight', '700');
    nameText.setAttribute('font-family', "'Noto Sans', sans-serif");
    nameText.textContent = node.label;

    const ipText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    ipText.setAttribute('x', node.x); ipText.setAttribute('y', node.y + 13);
    ipText.setAttribute('fill', '#666666'); ipText.setAttribute('text-anchor', 'middle');
    ipText.setAttribute('font-size', '9');
    ipText.setAttribute('font-family', "'JetBrains Mono', monospace");
    ipText.textContent = node.ip;

    g.append(circle, nameText, ipText);
    svg.appendChild(g);
  });
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
          <h2>Theory</h2>
          <p>ARP maps an IP address to a MAC address. A host broadcasts a request asking who owns an IP, and the owner responds with a reply that is cached for later frames.</p>
        </div>
        <div class="theory-grid">
          ${[
            ['ARP cache',        'Entries are mutable and time-bound. A forged reply can replace a legitimate association.'],
            ['No authentication','Classic ARP does not prove that a reply came from the rightful owner.'],
            ['Gratuitous ARP',   'Unsolicited announcements update neighbors quickly and can also be abused for poisoning.'],
            ['MITM vs DoS',      'MITM forwards traffic through the attacker; DoS drops or misroutes traffic so communication fails.'],
            ['Defenses',         'Static ARP entries suit small stable networks. Dynamic ARP Inspection validates switch-port bindings.'],
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
              <span class="title">Live Topology</span>
              <span class="subtitle">ARP Network Map</span>
            </div>
            <div class="topology-svg-wrap">
              <svg id="topology-svg" viewBox="0 0 520 320" role="img" aria-label="Live ARP network diagram">
                <defs>
                  <marker id="teal-arrow"  markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L7,3 z" fill="#2A8C76"/>
                  </marker>
                  <marker id="coral-arrow" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto">
                    <path d="M0,0 L0,6 L7,3 z" fill="#E06C62"/>
                  </marker>
                  <pattern id="grid" width="24" height="24" patternUnits="userSpaceOnUse">
                    <path d="M 24 0 L 0 0 0 24" fill="none" stroke="#EAE6E2" stroke-width="0.5"/>
                  </pattern>
                </defs>
                <!-- static background — dynamic nodes/edges injected by renderDiagram() -->
                <rect width="520" height="320" fill="url(#grid)" rx="14"/>
              </svg>
            </div>
            <p class="topology-footer">Edges update only from backend ARP events. No live data is fabricated.</p>
          </div>

          <!-- RIGHT: Sidebar -->
          <div class="sidebar">

            <!-- Lab Modules collapsible -->
            <div>
              <button class="section-header-strip" id="modules-toggle" aria-expanded="true">
                <span>Lab Modules</span>
                <span class="chevron-circle">▾</span>
              </button>
              <div id="modules-body" class="modules-list">
                ${TABS.map(t => `
                  <button class="module-card" data-tab="${t}">
                    <span class="icon-badge">${MODULE_ICONS[t]}</span>
                    <span style="font-size:13px;font-weight:500">${t}</span>
                  </button>`).join('')}
              </div>
            </div>

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
          <h2>References</h2>
          <p>Placeholder citations for this teaching lab.</p>
        </div>
        <ul class="references-list">
          <li>RFC 826 — An Ethernet Address Resolution Protocol.</li>
          <li>Placeholder: campus network security handbook.</li>
          <li>Placeholder: Dynamic ARP Inspection documentation.</li>
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

  /* Module card clicks (sidebar) */
  document.addEventListener('click', (e) => {
    const card = e.target.closest('.module-card');
    if (!card) return;
    state.activeTab = card.dataset.tab;
    renderTabs();
    if (state.activeTab === 'Assignment') renderQuiz();
  });

  /* Collapsible sections */
  $('#modules-toggle').addEventListener('click', (e) => {
    toggleSection('modulesOpen', e.currentTarget, 'modules-body');
  });
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
  /* set default active tab */
  state.activeTab = 'Simulation';
  renderTabs();
}

document.addEventListener('DOMContentLoaded', init);
