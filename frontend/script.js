/* ──────────────────────────────────────────────────────────────
   ARP Spoofing Virtual Lab — script.js
   Plain ES2020, no frameworks, no build step.
   Talks to backend at API_BASE_URL (port 8000 by default).
   ────────────────────────────────────────────────────────────── */

'use strict';

/* ─── Config ───────────────────────────────────────────────── */
const API_BASE_URL = (window.LAB_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');
const WS_BASE_URL = API_BASE_URL.replace(/^http/, 'ws');

/* ─── Dynamic MACs learned from backend/network ────────────── */
const realMacs = {
  victim: '',
  gateway: '',
  attacker: '',
};

/* ─── Node metadata in SVG (680 × 430 viewBox) ─────────────── */
const NODES = [
  { key: 'victim', label: 'Victim Target', ip: '10.10.10.10', x: 125, y: 112 },
  { key: 'gateway', label: 'Default Gateway', ip: '10.10.10.1', x: 555, y: 112 },
  { key: 'attacker', label: 'Attacker Machine', ip: '10.10.10.66', x: 340, y: 327 },
];

/* ─── Application state ─────────────────────────────────────── */
const state = {
  activeTab: 'Simulation',
  socketStatus: 'connecting',   // 'connecting' | 'connected' | 'disconnected'
  labRunning: false,
  attackActive: false,
  attackMode: 'mitm',
  mitigationOn: false,
  events: [],             // last 200 LabEvents
  arpTables: { victim: {}, gateway: {}, attacker: {} }, // node -> { ip: mac }
  realMacs: { victim: '', gateway: '', attacker: '' },
  pending: '',             // path of in-flight request
  quizIndex: 0,
  quizAnswer: null,           // null | number
  quizScore: 0,
  quizQuestions: [],
  quizLength: 10,
  quizUserAnswers: [],
  feedbackRating: 0,
  feedbackSubmitted: false,
  controlsOpen: true,
  logOpen: true,
  simViewMode: 'both',         // 'both' | 'map' | 'tables'
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

/* ─── Quiz data (content/quiz.json, embedded for the static frontend) ───── */
const QUIZ = [
  {
    "question": "A host knows a same-LAN destination IP but not its hardware address. What should happen next?",
    "options": [
      "The host broadcasts an ARP Request for that IP",
      "The host routes using the destination MAC as an IP",
      "The host encrypts the frame with ARP",
      "DNS supplies a MAC"
    ],
    "correctIndex": 0,
    "explanation": "ARP resolves a local IP to a MAC so an Ethernet frame can be addressed."
  },
  {
    "question": "A frame uses a MAC address while its packet carries an IP address. Which distinction explains this?",
    "options": [
      "Layer 2 delivers local frames; Layer 3 routes using IPs",
      "Layer 2 routes between networks; Layer 3 identifies NICs",
      "Both layers use MAC addresses",
      "MAC addresses are logical and IPs are physical"
    ],
    "correctIndex": 0,
    "explanation": "The theory assigns local delivery to Layer 2 and inter-network routing to Layer 3."
  },
  {
    "question": "A victim broadcasts 'Who has 10.10.10.1?' Which normal exchange follows?",
    "options": [
      "Two encrypted broadcasts",
      "Unicast request, broadcast reply",
      "Broadcast request, unicast reply to the victim",
      "Unicast request and reply to the attacker"
    ],
    "correctIndex": 2,
    "explanation": "ARP Requests use the broadcast MAC; the owner sends a unicast Reply to the requester."
  },
  {
    "question": "A host receives an ARP Reply without asking first. What is the precise implication?",
    "options": [
      "It is necessarily DHCP",
      "Its IP has changed",
      "It must reject it",
      "Its cache may update, but the sender's honesty is unproven"
    ],
    "correctIndex": 3,
    "explanation": "Hosts update caches from ARP packets even without a request, which creates the trust weakness."
  },
  {
    "question": "A dynamic ARP entry disappears after a long idle period. Which explanation fits the theory?",
    "options": [
      "MACs expire every millisecond",
      "Entries are permanent",
      "The IP became a MAC",
      "Entries typically expire after 30-120 seconds"
    ],
    "correctIndex": 3,
    "explanation": "Dynamic ARP cache entries are short-lived and OS-dependent."
  },
  {
    "question": "Why can a forged ARP Reply be accepted without proving IP ownership?",
    "options": [
      "ARP lacks authentication, identity verification, sequence numbers, and challenge-response",
      "DHCP signs every reply",
      "DNS verifies every MAC",
      "MACs cannot be forged"
    ],
    "correctIndex": 0,
    "explanation": "ARP was designed for trusted LANs and has no cryptographic authentication."
  },
  {
    "question": "A capture shows an unsolicited claim that the gateway IP is at the attacker's MAC. What does it prove?",
    "options": [
      "The gateway is offline",
      "Forwarding is active",
      "A gratuitous ARP was sent; successful MITM is not proven",
      "HTTPS was decrypted"
    ],
    "correctIndex": 2,
    "explanation": "An unsolicited Reply is gratuitous ARP; cache state and forwarding require separate evidence."
  },
  {
    "question": "A gateway's NIC changes legitimately. How can it announce the new mapping?",
    "options": [
      "Use DNS to rewrite frames",
      "Disable all ARP",
      "Send a gratuitous ARP for its own IP and new MAC",
      "Change every host's IP"
    ],
    "correctIndex": 2,
    "explanation": "Legitimate gratuitous ARP use includes announcing a MAC change."
  },
  {
    "question": "A victim maps both gateway IP and attacker IP to one MAC. What is the strongest inference?",
    "options": [
      "The victim likely accepted a forged gateway-to-attacker mapping",
      "DHCP duplicated an IP",
      "Both entries are static",
      "They share one NIC"
    ],
    "correctIndex": 0,
    "explanation": "The pattern strongly indicates poisoning, but the table is not proof of every attack outcome."
  },
  {
    "question": "The victim's gateway mapping is poisoned, but the gateway's victim mapping is unchanged. What is not established?",
    "options": [
      "Victim frames can be redirected",
      "A complete bidirectional MITM",
      "The attacker can receive some frames",
      "The victim cache changed"
    ],
    "correctIndex": 1,
    "explanation": "The gateway side must also be poisoned for return traffic to use the attacker MAC."
  },
  {
    "question": "Both caches map the other host to the attacker's MAC. What path is expected?",
    "options": [
      "Only DNS reaches the attacker",
      "Direct victim-gateway traffic",
      "Victim-to-attacker and gateway-to-attacker frames",
      "Only broadcasts"
    ],
    "correctIndex": 2,
    "explanation": "Poisoning both mappings redirects both directions at Ethernet delivery."
  },
  {
    "question": "Why does an attacker resend forged Replies periodically?",
    "options": [
      "The attacker must change MACs",
      "It turns IP into DNS",
      "Dynamic entries can expire and legitimate mappings can return",
      "ARP requires a password every two seconds"
    ],
    "correctIndex": 2,
    "explanation": "Repeated poisoning counters normal cache expiry."
  },
  {
    "question": "The victim's gateway mapping is false but web access continues. What is most likely?",
    "options": [
      "It must be DoS",
      "The gateway became the attacker",
      "ARP stopped",
      "The attacker is forwarding; cache evidence alone does not prove readable payloads"
    ],
    "correctIndex": 3,
    "explanation": "Forwarding explains continuity; encryption and capture evidence determine content visibility."
  },
  {
    "question": "Both sides are poisoned, but communication fails. Which distinction explains this?",
    "options": [
      "Redirecting traffic and forwarding traffic differ; dropping creates DoS",
      "HTTPS always causes DoS",
      "Gratuitous ARP encrypts traffic",
      "Layer 3 prevents ARP effects"
    ],
    "correctIndex": 0,
    "explanation": "Poisoning redirects packets; IP forwarding determines whether they continue."
  },
  {
    "question": "What result is intended when the attacker enables IP forwarding after poisoning?",
    "options": [
      "Automatic static entries",
      "Transparent MITM with traffic relayed after interception",
      "A cache repair",
      "A broadcast-only exchange"
    ],
    "correctIndex": 1,
    "explanation": "Forwarding creates the Victim -> Attacker -> Gateway path."
  },
  {
    "question": "What is the direct outcome when forwarding is disabled but poisoning remains active?",
    "options": [
      "ARP becomes authenticated",
      "The gateway cache is repaired",
      "Redirected packets can be dropped, causing DoS",
      "HTTPS becomes plaintext"
    ],
    "correctIndex": 2,
    "explanation": "Without forwarding, redirected traffic is blackholed rather than relayed."
  },
  {
    "question": "A user says the connection still works during poisoning. What cannot be inferred?",
    "options": [
      "Some frames may reach the attacker",
      "The attacker can read valid HTTPS payloads",
      "The attack is not currently a total DoS",
      "Forwarding may be active"
    ],
    "correctIndex": 1,
    "explanation": "HTTPS can keep content encrypted even when an attacker is in path."
  },
  {
    "question": "A capture shows the attacker receiving victim frames but no onward packets. What remains unresolved?",
    "options": [
      "Whether the attacker forwards them to the gateway",
      "Whether Ethernet uses MACs",
      "Whether ARP contains IPs",
      "Whether the victim has an IP"
    ],
    "correctIndex": 0,
    "explanation": "Receiving redirected frames does not reveal the forwarding decision."
  },
  {
    "question": "Which comparison between MITM and DoS is correct?",
    "options": [
      "They are identical",
      "MITM forwards after interception; DoS drops or fails to forward",
      "MITM needs static ARP; DoS needs HTTPS",
      "MITM changes DNS; DoS changes IPs"
    ],
    "correctIndex": 1,
    "explanation": "Forwarding is the operational distinction in the theory."
  },
  {
    "question": "A static entry binds the gateway IP to its known MAC. What does it directly resist?",
    "options": [
      "All packet modification",
      "A compromised gateway",
      "A received forged Reply overwriting that mapping",
      "The attacker's physical presence"
    ],
    "correctIndex": 2,
    "explanation": "Static entries are authoritative and are not overwritten by received ARP packets."
  },
  {
    "question": "What is the main trade-off of static ARP?",
    "options": [
      "Automatic scaling through DHCP",
      "Central switch validation",
      "Payload encryption",
      "Manual configuration on every device and updates after MAC changes"
    ],
    "correctIndex": 3,
    "explanation": "Static entries are impractical at scale and require maintenance."
  },
  {
    "question": "A victim has a static gateway entry. Which claim is too strong?",
    "options": [
      "The overwrite is blocked",
      "The attacker cannot be on the LAN",
      "The mapping is manually fixed",
      "A legitimate MAC change needs an update"
    ],
    "correctIndex": 1,
    "explanation": "Static ARP protects the mapping, not the physical network or every other threat."
  },
  {
    "question": "A gateway NIC is replaced but its IP stays constant. What can a stale static entry cause?",
    "options": [
      "DAI rewrites the host entry",
      "Hosts keep using the old MAC until it is updated",
      "The new MAC is authenticated automatically",
      "The IP becomes broadcast"
    ],
    "correctIndex": 1,
    "explanation": "Permanent entries do not adapt automatically to hardware changes."
  },
  {
    "question": "Why does a static entry on the victim not protect the gateway's cache?",
    "options": [
      "The gateway has no MAC",
      "Victim entries forward packets",
      "Each device maintains its own ARP cache",
      "Static entries live only in DNS"
    ],
    "correctIndex": 2,
    "explanation": "One host's cache configuration does not configure another host."
  },
  {
    "question": "A switch checks an ARP claim against a DHCP Snooping Binding Table and drops mismatches. What is this?",
    "options": [
      "Port security only",
      "HTTPS",
      "Gratuitous ARP",
      "Dynamic ARP Inspection"
    ],
    "correctIndex": 3,
    "explanation": "DAI validates IP-MAC-port claims against trusted bindings."
  },
  {
    "question": "A binding expects IP V and MAC M on port P, but a frame on P claims a different IP and MAC. What should DAI do?",
    "options": [
      "Allow it because ARP is trusted",
      "Drop and log the violation",
      "Encrypt and forward it",
      "Convert it to DNS"
    ],
    "correctIndex": 1,
    "explanation": "A binding mismatch is dropped and logged."
  },
  {
    "question": "What does DAI add that a host-only static entry does not?",
    "options": [
      "A new victim IP",
      "Switch-level validation across protected ports",
      "End-to-end encryption",
      "A replacement for forwarding"
    ],
    "correctIndex": 1,
    "explanation": "DAI enforces mappings centrally at a managed Layer 2 switch."
  },
  {
    "question": "DAI has an incorrect binding for a legitimate host. What trade-off follows?",
    "options": [
      "The host gains two MACs",
      "The attacker becomes gateway",
      "A valid claim may be dropped as a mismatch",
      "HTTPS decrypts"
    ],
    "correctIndex": 2,
    "explanation": "DAI depends on accurate trusted bindings."
  },
  {
    "question": "Which limitation distinguishes port security from DAI?",
    "options": [
      "Port security encrypts ARP",
      "Port security is Layer 7",
      "Port security needs no switch",
      "Port security limits MAC addresses but does not directly validate ARP IP-MAC claims"
    ],
    "correctIndex": 3,
    "explanation": "Port security constrains MAC use; DAI inspects ARP claims."
  },
  {
    "question": "An attacker uses one permitted MAC but claims the gateway IP. Which defense targets that claim?",
    "options": [
      "DAI",
      "Port security alone",
      "HTTPS alone",
      "VPN alone"
    ],
    "correctIndex": 0,
    "explanation": "A permitted MAC does not make its IP claim valid; DAI checks the binding."
  },
  {
    "question": "A switch shuts a port after too many MACs appear. What is justified?",
    "options": [
      "The victim entry is static",
      "A port-security policy violation occurred, not necessarily ARP poisoning",
      "DAI proved the forged IP",
      "HTTPS was broken"
    ],
    "correctIndex": 1,
    "explanation": "Port security evidence concerns MAC policy, not the precise ARP claim."
  },
  {
    "question": "Valid HTTPS is used while the attacker forwards traffic. What can the attacker read?",
    "options": [
      "Nothing because ARP is Layer 2",
      "The bank's content can be forged silently",
      "Ciphertext, not protected payload without the server private key",
      "Plaintext passwords automatically"
    ],
    "correctIndex": 2,
    "explanation": "TLS protects content even when underlying frames are redirected."
  },
  {
    "question": "Which observation most directly indicates attempted HTTPS interception?",
    "options": [
      "A normal unicast ARP Reply",
      "An expired ARP entry",
      "A port allowing one MAC",
      "A certificate warning from substitution or SSL stripping"
    ],
    "correctIndex": 3,
    "explanation": "Certificate validation can alert the user to substitution or stripping."
  },
  {
    "question": "The attacker sees a TLS ClientHello and encrypted records. What is safest?",
    "options": [
      "Traffic is in path but the payload remains protected",
      "The attacker has the private key",
      "The connection is HTTP",
      "The ARP cache is unchanged"
    ],
    "correctIndex": 0,
    "explanation": "In-path position does not defeat TLS encryption."
  },
  {
    "question": "A VPN tunnel exists before poisoning. What does poisoning most plausibly change?",
    "options": [
      "The MAC becomes a DNS name",
      "Tunnel frames may pass through the attacker while payload remains encrypted",
      "The attacker can read all payloads",
      "The VPN prevents all Layer 2 redirection"
    ],
    "correctIndex": 1,
    "explanation": "VPN limits content exposure but does not stop local redirection."
  },
  {
    "question": "Which comparison between HTTPS/VPN and static ARP is correct?",
    "options": [
      "Static ARP encrypts payloads",
      "Neither addresses the weakness",
      "Encryption limits reading; static ARP helps prevent mapping changes",
      "Both only detect port violations"
    ],
    "correctIndex": 2,
    "explanation": "They mitigate different stages: confidentiality versus mapping integrity."
  },
  {
    "question": "SSH reports a host-key mismatch during redirection. What does that provide?",
    "options": [
      "Automatic cache restoration",
      "Plaintext for the attacker",
      "A DAI binding",
      "Evidence of a possible interception attempt"
    ],
    "correctIndex": 3,
    "explanation": "SSH fingerprint verification is an interception warning, not an ARP repair."
  },
  {
    "question": "An attacker redirects a VPN tunnel but cannot decrypt it. What remains possible?",
    "options": [
      "Disruption or traffic analysis despite limited payload access",
      "Automatic plaintext reading",
      "Authentication of forged ARP",
      "Changing a static entry"
    ],
    "correctIndex": 0,
    "explanation": "Encryption limits confidentiality impact, not necessarily availability or metadata exposure."
  },
  {
    "question": "Why can ARP matter when the destination IP is outside the local network?",
    "options": [
      "IP is replaced end to end by MAC",
      "The victim needs the gateway's local MAC for the next-hop frame",
      "ARP routes across the internet",
      "The remote MAC is broadcast"
    ],
    "correctIndex": 1,
    "explanation": "The local Ethernet frame targets the gateway even for remote Layer 3 destinations."
  },
  {
    "question": "A student says poisoning changes the gateway's IP address. What is the correction?",
    "options": [
      "It changes DNS names",
      "It cannot affect frames",
      "It changes a cached IP-to-MAC association, not necessarily the gateway configuration",
      "It changes every Layer 3 address"
    ],
    "correctIndex": 2,
    "explanation": "The forged association affects local delivery while configured IPs may remain unchanged."
  },
  {
    "question": "A forged Reply claims the gateway IP at the attacker's MAC. What is abused?",
    "options": [
      "DNS name resolution",
      "TCP port ownership",
      "The VPN fingerprint",
      "The receiver's trusted IP-to-MAC cache mapping"
    ],
    "correctIndex": 3,
    "explanation": "ARP populates the mapping that Ethernet delivery consults."
  },
  {
    "question": "Why does a unicast ARP Reply not become authenticated merely because it is unicast?",
    "options": [
      "Delivery mode does not prove the sender owns the claimed IP",
      "Unicast is always encrypted",
      "Only broadcasts can be forged",
      "The switch signs unicast packets"
    ],
    "correctIndex": 0,
    "explanation": "Addressing and authenticity are separate properties."
  },
  {
    "question": "Two different ARP Replies claim the same IP. What should not be concluded without more evidence?",
    "options": [
      "Cache state needs inspection",
      "One is definitely legitimate and the other caused a successful MITM",
      "Conflicting claims exist",
      "ARP permits ambiguity"
    ],
    "correctIndex": 1,
    "explanation": "The capture does not show which mapping was accepted or whether forwarding occurred."
  },
  {
    "question": "What feature do legitimate and malicious gratuitous ARPs share?",
    "options": [
      "They are router-only",
      "They disable forwarding",
      "They are unsolicited Replies; intent and mapping determine use",
      "They are encrypted"
    ],
    "correctIndex": 2,
    "explanation": "Gratuitous describes the unsolicited form, which has both legitimate and malicious uses."
  },
  {
    "question": "An unsolicited claim is accepted and later frames target the attacker MAC. What causal chain fits?",
    "options": [
      "DNS selected the MAC",
      "The gateway changed its IP",
      "DAI necessarily approved it",
      "Unverified ARP updated the cache, which selected the MAC for local delivery"
    ],
    "correctIndex": 3,
    "explanation": "The cache's trust model controls later Ethernet frame destinations."
  },
  {
    "question": "If a cache is corrected but forged Replies continue, what determines persistence?",
    "options": [
      "Whether forged traffic is accepted again before legitimate replacement or expiry",
      "Whether HTTPS is enabled",
      "Whether DNS exists",
      "Whether MACs are 48-bit"
    ],
    "correctIndex": 0,
    "explanation": "The unprotected dynamic mapping can be overwritten repeatedly."
  },
  {
    "question": "Which evidence is strongest for poisoning rather than merely a suspicious packet?",
    "options": [
      "An unrelated static entry",
      "The victim cache maps the gateway to the attacker and traffic follows that path",
      "One unsolicited packet alone",
      "A valid certificate"
    ],
    "correctIndex": 1,
    "explanation": "Correlating the claim, cache, and traffic path is stronger than one packet."
  },
  {
    "question": "Forged Replies repeat, but the victim still uses the real MAC. What is safest?",
    "options": [
      "Gateway forwarding is proven",
      "The cache is static",
      "Sending poison is shown, but successful overwrite is not",
      "MITM is proven"
    ],
    "correctIndex": 2,
    "explanation": "Transmission of poison and acceptance of poison are separate facts."
  },
  {
    "question": "The victim sends frames to the attacker MAC, but no capture shows onward traffic. What would distinguish MITM from misconfiguration?",
    "options": [
      "The victim hostname",
      "The gateway DNS record",
      "MAC length",
      "Evidence that the attacker forwards to the real gateway"
    ],
    "correctIndex": 3,
    "explanation": "Forwarding establishes the intended interception path."
  },
  {
    "question": "The attacker poisons only the gateway side. Which traffic is most directly redirected?",
    "options": [
      "Gateway-to-victim frames",
      "Victim-to-gateway frames",
      "All broadcasts into VPN plaintext",
      "Only internet DNS"
    ],
    "correctIndex": 0,
    "explanation": "The gateway's cache controls its outgoing victim-bound frame destination."
  },
  {
    "question": "The attacker poisons only the victim side and sees no replies. What explains this?",
    "options": [
      "DAI forwarded everything",
      "The gateway may still address replies directly to the victim",
      "The victim IP became a MAC",
      "HTTPS blocked ARP"
    ],
    "correctIndex": 1,
    "explanation": "Bidirectional MITM requires both caches to be altered."
  },
  {
    "question": "Why is the gateway a critical target for the victim's off-LAN traffic?",
    "options": [
      "It authenticates ARP",
      "It is an application server",
      "It is the local next hop whose MAC controls the victim's external frames",
      "It owns every remote MAC"
    ],
    "correctIndex": 2,
    "explanation": "The gateway's local mapping determines the Ethernet destination for routed traffic."
  },
  {
    "question": "A victim can ping the gateway after poisoning while forwarding is off. What is safest?",
    "options": [
      "Full MITM is proven",
      "DAI is proven",
      "HTTPS decrypted ping",
      "That observation alone does not disprove poisoning or establish forwarding"
    ],
    "correctIndex": 3,
    "explanation": "A single connectivity observation does not establish the complete path."
  },
  {
    "question": "Which ARP delivery statement is correct?",
    "options": [
      "Requests are broadcast; normal Replies are unicast",
      "Requests are unicast; Replies are broadcast",
      "Both are Layer 3 broadcasts",
      "Neither uses MACs"
    ],
    "correctIndex": 0,
    "explanation": "The request and reply delivery modes differ as described in the theory."
  },
  {
    "question": "If no host owns the requested IP, what follows from the normal ARP exchange?",
    "options": [
      "The switch creates a permanent entry",
      "The described owner Reply will not occur; the request does not assign ownership",
      "The attacker becomes owner automatically",
      "DNS supplies the MAC"
    ],
    "correctIndex": 1,
    "explanation": "A normal Reply comes from a host recognizing its own IP."
  },
  {
    "question": "A MAC appears for two IPs. Why is that suspicious but not absolute proof?",
    "options": [
      "DHCP definitely duplicated an IP",
      "The IPs must be on different LANs",
      "It is consistent with poisoning, but a snapshot alone does not establish cause",
      "ARP forbids any shared mapping"
    ],
    "correctIndex": 2,
    "explanation": "The theory calls it a strong indicator, not conclusive proof in isolation."
  },
  {
    "question": "Static ARP and DAI both resist forged mappings. Where do they act?",
    "options": [
      "Static ARP acts in DNS; DAI in HTTPS",
      "Both act only in the attacker",
      "Both are browser controls",
      "Static ARP acts in a host cache; DAI acts at a managed switch"
    ],
    "correctIndex": 3,
    "explanation": "Their enforcement points and scope differ."
  },
  {
    "question": "Why might an enterprise prefer DAI to static entries for thousands of changing hosts?",
    "options": [
      "It centralizes validation against bindings instead of manual host configuration",
      "It requires more manual entries",
      "It encrypts payloads",
      "Static entries learn faster"
    ],
    "correctIndex": 0,
    "explanation": "DAI is designed for managed, scalable Layer 2 enforcement."
  },
  {
    "question": "A defense blocks forged mappings but does not encrypt application data. Which category is it?",
    "options": [
      "Gratuitous ARP",
      "Static ARP or DAI",
      "HTTPS or VPN",
      "IP forwarding"
    ],
    "correctIndex": 1,
    "explanation": "Static ARP and DAI protect mapping integrity, not payload confidentiality."
  },
  {
    "question": "A defense encrypts payloads but permits ARP redirection. What remains possible?",
    "options": [
      "The cache becomes static",
      "ARP gains authentication",
      "Redirection, disruption, or metadata observation while protected content stays unreadable",
      "No frames reach the attacker"
    ],
    "correctIndex": 2,
    "explanation": "Encryption limits content exposure without preventing Layer 2 redirection."
  },
  {
    "question": "A DAI log records a dropped claim. What does it not prove?",
    "options": [
      "A binding mismatch was enforced",
      "The ARP claim was rejected",
      "A policy violation was recorded",
      "That application data was exposed"
    ],
    "correctIndex": 3,
    "explanation": "DAI evidence concerns ARP validation, not later traffic inspection."
  },
  {
    "question": "Port security shuts a port after too many MACs appear. Why can this also affect legitimate users?",
    "options": [
      "A policy limit may be exceeded during legitimate hardware or failover changes",
      "It decrypts traffic",
      "It rewrites all caches",
      "It guarantees IP-MAC correctness"
    ],
    "correctIndex": 0,
    "explanation": "Port security limits MAC use and can require policy updates."
  },
  {
    "question": "A report calls a changed victim cache 'MITM successful.' What important condition is missing?",
    "options": [
      "Evidence the request was broadcast",
      "Evidence of forwarding if MITM means transparent interception",
      "Evidence MACs are 48-bit",
      "Evidence DNS exists"
    ],
    "correctIndex": 1,
    "explanation": "A changed mapping redirects traffic; transparent MITM also needs forwarding."
  },
  {
    "question": "Which observation most clearly supports DoS rather than MITM?",
    "options": [
      "HTTPS remains valid",
      "The gateway sends a Reply",
      "Frames reach the attacker but are not forwarded and connectivity fails",
      "The victim reaches the gateway through the attacker"
    ],
    "correctIndex": 2,
    "explanation": "Dropped redirected traffic is the defining DoS outcome."
  },
  {
    "question": "No browser warning appears during suspected HTTPS interception. What should not be concluded?",
    "options": [
      "TLS may still protect content",
      "Redirection and encryption differ",
      "A valid certificate may remain valid",
      "That poisoning did not happen or plaintext was readable"
    ],
    "correctIndex": 3,
    "explanation": "No warning proves neither absence of Layer 2 redirection nor plaintext exposure."
  },
  {
    "question": "A VPN loses connectivity during poisoning. Which interpretation is supported?",
    "options": [
      "The tunnel may be dropped or not forwarded; loss does not imply decryption",
      "The attacker necessarily read it",
      "VPN prevents ARP",
      "The gateway IP changed"
    ],
    "correctIndex": 0,
    "explanation": "VPN encryption limits confidentiality, while forwarding controls availability."
  },
  {
    "question": "A certificate warning appears during suspected ARP interception. Which layers are being distinguished?",
    "options": [
      "Layer 2 authenticating certificates",
      "Layer 2 redirection versus higher-layer TLS validation",
      "Two physical layers",
      "TLS changing MACs"
    ],
    "correctIndex": 1,
    "explanation": "ARP can redirect while TLS validation detects certificate substitution."
  },
  {
    "question": "An administrator can maintain one high-value host after hardware changes. Which defense fits?",
    "options": [
      "Attacker gratuitous ARP",
      "Disabling HTTPS",
      "A static ARP entry for the gateway",
      "Port security without a switch"
    ],
    "correctIndex": 2,
    "explanation": "Static ARP is practical for limited, controlled scope."
  },
  {
    "question": "A managed switch has accurate DHCP bindings and many hosts. Which defense fits?",
    "options": [
      "A manual entry on every host",
      "Plain HTTP",
      "Disabling forwarding",
      "DAI"
    ],
    "correctIndex": 3,
    "explanation": "DAI uses trusted bindings for central validation."
  },
  {
    "question": "Why are port security and DAI not interchangeable?",
    "options": [
      "Port security limits MAC addresses; DAI validates ARP IP-MAC claims",
      "DAI only counts MACs",
      "Both encrypt traffic",
      "Neither logs violations"
    ],
    "correctIndex": 0,
    "explanation": "Their control objectives differ."
  },
  {
    "question": "An ARP Reply has the correct gateway IP but an unexpected MAC. What must be checked before calling it malicious?",
    "options": [
      "Whether DNS returned the IP",
      "Whether the MAC is legitimate and whether the receiver accepted it",
      "Whether HTTPS is enabled",
      "Whether it is Layer 4"
    ],
    "correctIndex": 1,
    "explanation": "Legitimate MAC changes and unsolicited announcements exist."
  },
  {
    "question": "A failover sends a gratuitous ARP with a new MAC. Why is it not inherently poisoning?",
    "options": [
      "Failover is only Layer 3",
      "Clients cannot update from Replies",
      "The mapping may be a legitimate MAC-change announcement",
      "All gratuitous ARP is malicious"
    ],
    "correctIndex": 2,
    "explanation": "Gratuitous ARP has documented legitimate uses."
  },
  {
    "question": "A cache changes immediately after an unsolicited claim. Which property enabled it?",
    "options": [
      "ARP entries never expire",
      "DNS routes MACs",
      "DAI signs every Reply",
      "The OS updates from received ARP even without a request"
    ],
    "correctIndex": 3,
    "explanation": "Unsolicited cache updates are the root of the vulnerability."
  },
  {
    "question": "A poisoned victim cache is observed. Why does that not prove the gateway cache is poisoned?",
    "options": [
      "Each device has its own cache",
      "Gateway caches are unused",
      "Caches are globally shared",
      "Only DAI can change them"
    ],
    "correctIndex": 0,
    "explanation": "Both sides must be separately poisoned for bidirectional interception."
  },
  {
    "question": "A poisoned gateway cache is observed. Why does that not prove victim traffic is intercepted?",
    "options": [
      "Port security must fail",
      "Victim-side poisoning and a forwarding path are also needed",
      "DNS is missing",
      "A certificate key is missing"
    ],
    "correctIndex": 1,
    "explanation": "Gateway-side poisoning redirects gateway replies, not necessarily victim-originated frames."
  },
  {
    "question": "How can poisoning work without changing a host's configured IP?",
    "options": [
      "ARP edits DNS",
      "MACs route globally",
      "Ethernet delivery consults a false cached IP-to-MAC association",
      "IP configuration is irrelevant"
    ],
    "correctIndex": 2,
    "explanation": "The attack changes local frame destination, not necessarily Layer 3 configuration."
  },
  {
    "question": "A capture pairs gateway IP with attacker MAC. What is safest?",
    "options": [
      "The attacker legally owns the gateway IP",
      "DNS replied",
      "TLS is broken",
      "A forged identity claim is plausible; full MITM needs context and forwarding evidence"
    ],
    "correctIndex": 3,
    "explanation": "The mismatch supports spoofing but does not prove every outcome."
  },
  {
    "question": "A mapping reverts after poisoning stops. What explains this?",
    "options": [
      "The dynamic entry expired or was replaced by legitimate ARP information",
      "Static entries are overwritten",
      "HTTPS repaired it",
      "VPN changed hardware"
    ],
    "correctIndex": 0,
    "explanation": "Dynamic entries are short-lived and can be relearned."
  },
  {
    "question": "A static entry remains wrong after a legitimate NIC replacement. What follows?",
    "options": [
      "The attacker caused the replacement",
      "Availability may suffer until the administrator updates it",
      "Static ARP discovers the MAC",
      "DAI accepts the old entry"
    ],
    "correctIndex": 1,
    "explanation": "Static protection trades adaptation for resistance to unsolicited changes."
  },
  {
    "question": "Both-side poisoning uses forwarding enabled. What should the lab expect?",
    "options": [
      "Only ARP Requests pass",
      "The gateway IP disappears",
      "Traffic traverses the attacker while communication continues",
      "All packets drop"
    ],
    "correctIndex": 2,
    "explanation": "That is the MITM path in the theory."
  },
  {
    "question": "The same poisoning uses forwarding disabled. What changes?",
    "options": [
      "ARP becomes authenticated",
      "HTTPS becomes plaintext",
      "Requests become unicast",
      "Availability: redirected traffic is dropped, producing DoS"
    ],
    "correctIndex": 3,
    "explanation": "Forwarding controls relay versus blackholing."
  },
  {
    "question": "Which combination provides complementary mitigation?",
    "options": [
      "DAI or static ARP for mappings plus HTTPS/VPN for confidentiality",
      "Port security alone for encryption",
      "Gratuitous ARP plus HTTP",
      "Disabling cache plus DNS"
    ],
    "correctIndex": 0,
    "explanation": "Mapping controls and encryption address different risks."
  },
  {
    "question": "Why is an inaccurate DAI binding table significant?",
    "options": [
      "Port security fixes the table",
      "It can cause legitimate claims to be dropped as mismatches",
      "DAI stops using ARP",
      "HTTPS supplies bindings"
    ],
    "correctIndex": 1,
    "explanation": "DAI's decision depends on trusted expected bindings."
  },
  {
    "question": "HTTPS is used everywhere but ARP is unprotected. What risk remains?",
    "options": [
      "ARP becomes authenticated",
      "Static entries appear automatically",
      "Traffic can still be redirected, modified at the network level, or disrupted",
      "TLS plaintext is always readable"
    ],
    "correctIndex": 2,
    "explanation": "Encryption limits content exposure, not all redirection or availability effects."
  },
  {
    "question": "DAI is enabled and an encrypted session is captured. Which statement is accurate?",
    "options": [
      "DAI decrypts it",
      "DAI makes certificates unnecessary",
      "DAI disables forwarding",
      "DAI addresses ARP claims; it does not replace HTTPS/VPN confidentiality"
    ],
    "correctIndex": 3,
    "explanation": "DAI and encryption solve different problems."
  },
  {
    "question": "A false mapping immediately changes local frame delivery at which boundary?",
    "options": [
      "Layer 2, even though the claimed identity is a Layer 3 IP",
      "Layer 7 only",
      "The internet routing table",
      "The DHCP database"
    ],
    "correctIndex": 0,
    "explanation": "ARP bridges IP identity and Ethernet delivery."
  },
  {
    "question": "Which summary best captures ARP's weakness?",
    "options": [
      "It authenticates gratuitous Replies",
      "It trusts unauthenticated IP-to-MAC claims and updates short-lived caches",
      "It encrypts too much",
      "It stores mappings permanently"
    ],
    "correctIndex": 1,
    "explanation": "This combines the core facts from the theory."
  },
  {
    "question": "A question shows only a forged Reply and asks whether MITM succeeded. What is correct?",
    "options": [
      "It proves a static entry",
      "It supports an attempt, but cache success and forwarding need more evidence",
      "It proves bidirectional forwarding",
      "It proves HTTPS plaintext"
    ],
    "correctIndex": 1,
    "explanation": "Packet evidence, cache state, and forwarding outcome are distinct."
  },
  {
    "question": "A victim maps the gateway IP to the attacker MAC, but no capture exists. What is defensible?",
    "options": [
      "The gateway cache must match",
      "The victim has no IP",
      "Gateway-bound frames are likely addressed to the attacker; forwarding remains unknown",
      "Passwords were definitely read"
    ],
    "correctIndex": 2,
    "explanation": "The mapping predicts local delivery but not what happens afterward."
  },
  {
    "question": "A gateway maps the victim IP to the attacker MAC while the victim cache is unchanged. What is likely?",
    "options": [
      "Both directions are guaranteed through the attacker",
      "No victim frames can leave",
      "HTTPS must fail",
      "Gateway replies may be redirected while victim frames may go directly to the gateway"
    ],
    "correctIndex": 3,
    "explanation": "Each sender uses its own cache, so one-sided poisoning is asymmetric."
  },
  {
    "question": "DAI drops a forged claim before hosts receive it. What is most directly prevented?",
    "options": [
      "That claim being learned through the protected switch path",
      "The attacker running any process",
      "HTTPS payload decryption",
      "All DNS queries"
    ],
    "correctIndex": 0,
    "explanation": "DAI's direct purpose is to reject invalid ARP claims."
  },
  {
    "question": "Port security rejects a legitimate failover MAC. What trade-off is illustrated?",
    "options": [
      "VPN encryption is lost",
      "A security limit can require updates for legitimate hardware changes",
      "DAI always accepts it",
      "Static ARP updates automatically"
    ],
    "correctIndex": 1,
    "explanation": "MAC-count policy can conflict with legitimate changes."
  },
  {
    "question": "A user ignores an SSH host-key mismatch during ARP interception. What protection is weakened?",
    "options": [
      "Gateway forwarding",
      "The ARP broadcast destination",
      "Detection of an interception attempt at the SSH trust boundary",
      "DAI's binding"
    ],
    "correctIndex": 2,
    "explanation": "Fingerprint checking is the application-level warning mechanism."
  },
  {
    "question": "Which statement best preserves the Layer 2/encryption distinction?",
    "options": [
      "Encryption prevents MAC changes",
      "HTTPS authenticates ARP",
      "Layer 2 always decrypts Layer 7",
      "Encryption does not stop ARP redirection; it reduces what an in-path attacker can read or forge"
    ],
    "correctIndex": 3,
    "explanation": "This is the theory's key insight."
  },
  {
    "question": "The attacker stops sending forged Replies after poisoning the victim. Later the victim's dynamic gateway entry expires and the victim needs to send to the gateway. What happens?",
    "options": [
      "The victim keeps using the attacker's MAC permanently",
      "The victim broadcasts a new ARP Request and learns the real gateway MAC, so traffic returns to the direct path",
      "The victim's IP is reassigned by DHCP",
      "The victim switches automatically to a static entry"
    ],
    "correctIndex": 1,
    "explanation": "Dynamic entries are short-lived; once the forged mapping expires and no new forgeries arrive, normal ARP resolution restores the legitimate mapping."
  },
  {
    "question": "Forged Replies are sent about every 2 seconds, and entries expire after at least 30 seconds. Roughly how many forged Replies arrive during one minimum expiry window?",
    "options": [
      "About 2",
      "About 6",
      "About 15",
      "About 60"
    ],
    "correctIndex": 2,
    "explanation": "30 seconds divided by a 2-second interval is about 15, so the forged entry is refreshed many times before it could expire."
  },
  {
    "question": "Only the victim's cache is poisoned, and the attacker has IP forwarding enabled. Which traffic can the attacker observe?",
    "options": [
      "Both directions between victim and gateway",
      "Victim-to-gateway frames only, because the gateway still replies directly to the victim",
      "Gateway-to-victim frames only",
      "Neither direction, because forwarding hides the traffic"
    ],
    "correctIndex": 1,
    "explanation": "The victim's cache controls only victim-originated frames; the gateway's unpoisoned cache sends its replies straight to the victim."
  },
  {
    "question": "During a successful MITM, a victim loads one site over HTTP and another over HTTPS. What is the attacker's position?",
    "options": [
      "Both sessions are equally readable",
      "Neither session passes through the attacker",
      "HTTP content can be read and modified; HTTPS content appears only as ciphertext",
      "HTTPS content can be read but HTTP content cannot"
    ],
    "correctIndex": 2,
    "explanation": "Plaintext protocols are exposed to reading and modification; TLS protects content without the server's private key."
  },
  {
    "question": "An in-path attacker tries to present a substituted certificate for an HTTPS site. What stops the substitution from being silent?",
    "options": [
      "ARP rejects the forged frame",
      "The gateway signs the connection",
      "Static ARP detects the certificate",
      "Certificate validation (PKI) alerts the user to the substitution"
    ],
    "correctIndex": 3,
    "explanation": "Certificate validation operates at a higher layer than ARP and can warn the user about substitution or SSL stripping."
  },
  {
    "question": "The victim has a static gateway entry, but the attacker poisons only the gateway's cache with forwarding enabled. What is the resulting path?",
    "options": [
      "Victim-to-gateway frames go directly; gateway-to-victim frames pass through the attacker",
      "Victim-to-gateway frames pass through the attacker; gateway-to-victim frames go directly",
      "Both directions pass through the attacker",
      "Neither direction is affected, so no frames can be captured"
    ],
    "correctIndex": 0,
    "explanation": "Each device uses its own cache: the victim's static entry protects outbound frames, while the poisoned gateway cache redirects return frames."
  },
  {
    "question": "A gateway's NIC is replaced, and it sends a gratuitous ARP announcing the new MAC. A victim has a static entry with the old MAC. What happens?",
    "options": [
      "The victim updates immediately because the gratuitous ARP is legitimate",
      "DAI rewrites the victim's static entry",
      "The static entry is not overwritten, so the victim keeps using the stale MAC until updated manually",
      "The victim's entry changes to dynamic automatically"
    ],
    "correctIndex": 2,
    "explanation": "Static entries are not overwritten by received ARP packets, even legitimate ones, so the stale mapping persists until an administrator fixes it."
  },
  {
    "question": "A DHCP Snooping Binding Table lists IP V and MAC M on port P1. A device on port P2 sends an ARP claiming V is at M. What does DAI do?",
    "options": [
      "Allows it because the IP-MAC pair is valid somewhere",
      "Allows it because the MAC is real",
      "Encrypts it and forwards it",
      "Drops and logs it because the claim does not match the binding for port P2"
    ],
    "correctIndex": 3,
    "explanation": "DAI validates the claimed IP-MAC pair against the binding for the specific port the packet arrived on."
  },
  {
    "question": "A legitimate host uses a manually configured IP and never obtained a DHCP lease. Based on how DAI validates claims, what is the likely effect?",
    "options": [
      "No binding exists for it, so its own ARP claims may be dropped as unmatched",
      "DAI creates a binding automatically from its first ARP packet",
      "DAI encrypts its ARP traffic",
      "Port security approves its ARP automatically"
    ],
    "correctIndex": 0,
    "explanation": "DAI compares ARP claims against the DHCP Snooping Binding Table, so a host without a binding can fail validation unless the table is accurate."
  },
  {
    "question": "A host sends a gratuitous ARP for its own IP at startup and receives a reply from a different MAC claiming that IP. What does this indicate?",
    "options": [
      "A successful MITM",
      "An IP address conflict",
      "A static ARP entry",
      "A DAI binding match"
    ],
    "correctIndex": 1,
    "explanation": "Detecting IP conflicts at startup is a legitimate use of gratuitous ARP."
  },
  {
    "question": "Only the gateway's cache is poisoned and forwarding is disabled. What does the victim most likely experience?",
    "options": [
      "Nothing, because the victim's cache is unchanged",
      "Its requests reach the gateway, but replies are redirected to the attacker and dropped, so connectivity appears to fail",
      "The victim's requests are dropped but replies arrive normally",
      "HTTPS content becomes readable"
    ],
    "correctIndex": 1,
    "explanation": "Victim-to-gateway frames still go directly, but the gateway's replies are sent to the attacker's MAC and blackholed."
  },
  {
    "question": "The victim has a full-tunnel VPN and a static gateway entry. An attacker on the LAN poisons the gateway's cache. Which statement is most accurate?",
    "options": [
      "The victim's payload remains encrypted, but the gateway's frames to the victim may still be redirected",
      "The attacker can now decrypt the tunnel",
      "The victim's static entry protects the gateway's cache",
      "No frames can reach the attacker"
    ],
    "correctIndex": 0,
    "explanation": "Static ARP protects only the victim's own cache; the gateway's cache is separate, and the VPN limits content exposure rather than preventing redirection."
  },
  {
    "question": "The attacker poisons both sides and forwards victim-to-gateway packets but drops gateway-to-victim packets. What is the outcome?",
    "options": [
      "A transparent MITM with all traffic relayed",
      "Requests reach the internet but responses never return, so the victim loses connectivity",
      "ARP becomes authenticated",
      "Nothing changes for the victim"
    ],
    "correctIndex": 1,
    "explanation": "Relaying must work in both directions for a transparent MITM; dropping one direction effectively causes DoS."
  },
  {
    "question": "The victim broadcasts an ARP Request for the gateway IP and the attacker answers with its own MAC. Which missing property lets the victim accept this?",
    "options": [
      "The request was unicast",
      "ARP encrypts the Reply",
      "Switches validate every Reply",
      "ARP has no mechanism to verify the sender actually owns the claimed IP"
    ],
    "correctIndex": 3,
    "explanation": "ARP lacks authentication and identity verification, so a forged Reply is accepted like a genuine one."
  },
  {
    "question": "A legitimate failover gratuitous ARP and a malicious gratuitous ARP both appear on the wire. What most reliably separates them?",
    "options": [
      "Their packet format, which always differs",
      "Whether the announced MAC actually belongs to the legitimate owner of that IP",
      "Whether the packet is broadcast",
      "Whether the packet is unsolicited"
    ],
    "correctIndex": 1,
    "explanation": "Both are unsolicited Replies of the same form; legitimacy depends on whether the announced mapping is truthful."
  },
  {
    "question": "An attacker captures a valid HTTPS session. According to the theory, what can they NOT do without the server's private key?",
    "options": [
      "Redirect the frames",
      "See that traffic exists",
      "Read or forge the protected content",
      "Poison the ARP caches"
    ],
    "correctIndex": 2,
    "explanation": "Without the server's private key the attacker sees only ciphertext and cannot read or forge TLS-protected content."
  },
  {
    "question": "Static entries for each other exist on both the victim and the gateway. The attacker sends forged Replies to both. What is the expected result?",
    "options": [
      "Both caches are overwritten",
      "Only the victim's cache is overwritten",
      "The attacker gains the gateway's IP",
      "Neither mapping is overwritten, so traffic is not redirected through the attacker"
    ],
    "correctIndex": 3,
    "explanation": "Static entries are not overwritten by received ARP packets, so both directions keep using the real MACs."
  },
  {
    "question": "A switch allows only one MAC on the attacker's port, and the attacker poisons using its own single MAC. What follows?",
    "options": [
      "Port security does not directly stop the poisoning, because it does not validate ARP IP-MAC claims",
      "Port security shuts the port immediately",
      "DAI is not needed",
      "The forged Replies are encrypted"
    ],
    "correctIndex": 0,
    "explanation": "Port security limits MAC addresses per port but does not check whether the IP-MAC claim inside an ARP packet is true."
  },
  {
    "question": "Which pairing correctly matches each defense to what it primarily protects?",
    "options": [
      "DAI: payload confidentiality; HTTPS: ARP validation",
      "DAI: IP-MAC mapping integrity at the switch; HTTPS/VPN: content confidentiality",
      "Port security: payload encryption; VPN: MAC limits",
      "Static ARP: certificate validation; DAI: DNS"
    ],
    "correctIndex": 1,
    "explanation": "Mapping-integrity controls and encryption address different stages of the attack."
  },
  {
    "question": "Why does a MITM attacker with forwarding enabled usually go unnoticed, while a DoS attacker is quickly noticed?",
    "options": [
      "MITM traffic is encrypted by ARP",
      "DoS attacks use DNS",
      "Forwarding keeps connections working, whereas dropped traffic breaks connectivity",
      "MITM changes the victim's IP"
    ],
    "correctIndex": 2,
    "explanation": "In a MITM the connection still works, so victim and gateway typically notice nothing; in a DoS connectivity is lost."
  },
  {
    "question": "A victim's cache shows the gateway IP mapped to the attacker's MAC, forwarding is on, and a certificate warning appears for an HTTPS site. What is the best interpretation?",
    "options": [
      "ARP validation failed, so the certificate is invalid by definition",
      "The attacker decrypted TLS successfully",
      "The warning means the attacker is no longer in path",
      "The attacker is in path, and higher-layer certificate validation caught an interception attempt"
    ],
    "correctIndex": 3,
    "explanation": "ARP redirection puts the attacker in path, but TLS certificate validation can still detect substitution or SSL stripping."
  },
  {
    "question": "Which statement about ARP's origin and design assumptions matches the theory?",
    "options": [
      "It was designed in 1982 with built-in cryptographic signatures",
      "It was designed for large untrusted WANs and routes across networks",
      "It was specified in RFC 826 in 1982 for small, trusted LANs",
      "It was designed to replace MAC addresses with IP addresses"
    ],
    "correctIndex": 2,
    "explanation": "ARP (RFC 826, 1982) was designed for small, trusted LANs, which is why it has no authentication."
  },
  {
    "question": "Host A (10.10.10.10) sends an ARP Request for 10.10.10.1. Which field combination is correct?",
    "options": [
      "Source MAC: A's MAC; Destination MAC: ff:ff:ff:ff:ff:ff; Source IP: 10.10.10.10; Target IP: 10.10.10.1",
      "Source MAC: B's MAC; Destination MAC: A's MAC; Source IP: 10.10.10.1; Target IP: 10.10.10.10",
      "Source MAC: A's MAC; Destination MAC: B's MAC; Source IP: 10.10.10.10; Target IP: 10.10.10.1",
      "Source MAC: ff:ff:ff:ff:ff:ff; Destination MAC: A's MAC; Source IP: 10.10.10.1; Target IP: 10.10.10.1"
    ],
    "correctIndex": 0,
    "explanation": "The Request is sent from A's MAC to the broadcast MAC, carrying A's IP as source and B's IP as target."
  },
  {
    "question": "Host B (10.10.10.1) answers Host A's ARP Request. Which field combination does the Reply carry?",
    "options": [
      "Destination MAC: ff:ff:ff:ff:ff:ff; Source IP: 10.10.10.10",
      "Source MAC: A's MAC; Destination MAC: B's MAC",
      "Source IP: 10.10.10.10; Target IP: 10.10.10.1",
      "Source MAC: B's MAC; Destination MAC: A's MAC; Source IP: 10.10.10.1; Target IP: 10.10.10.10"
    ],
    "correctIndex": 3,
    "explanation": "The Reply is a unicast from B to A, with B's IP as source and A's IP as target."
  },
  {
    "question": "Which pair of Linux tools can be used to inspect the ARP cache, according to the theory?",
    "options": [
      "arp -s and ip route",
      "arp -n and ip neigh",
      "arp -a and ip addr",
      "ping and traceroute"
    ],
    "correctIndex": 1,
    "explanation": "The theory lists arp -n (or arp -a on Windows) and ip neigh on Linux."
  },
  {
    "question": "What does 'nud permanent' mean in 'ip neigh add 10.10.10.1 lladdr <MAC> dev eth0 nud permanent'?",
    "options": [
      "The entry is learned automatically and expires after 120 seconds",
      "The entry is broadcast to every host on the LAN",
      "The entry is static and cannot be overwritten by received ARP packets",
      "The entry is encrypted with the gateway's key"
    ],
    "correctIndex": 2,
    "explanation": "Permanent entries are static, so forged ARP Replies cannot overwrite them."
  },
  {
    "question": "In a full ARP poisoning attack, what forged claim is sent to the Gateway?",
    "options": [
      "10.10.10.10 (Victim) is at the attacker's MAC",
      "10.10.10.1 (Gateway) is at the attacker's MAC",
      "The attacker's IP is at the Victim's MAC",
      "The broadcast address is at the Gateway's MAC"
    ],
    "correctIndex": 0,
    "explanation": "The Gateway is told the Victim's IP maps to the attacker's MAC; the Victim is told the Gateway's IP maps to the attacker's MAC."
  },
  {
    "question": "Why does a bidirectional MITM require forged Replies to two targets rather than one?",
    "options": [
      "ARP forbids sending only one Reply",
      "Each device uses its own cache, so both the victim-to-gateway and gateway-to-victim directions must be redirected separately",
      "A single Reply is always rejected by the switch",
      "The Reply must be sent twice to be authenticated"
    ],
    "correctIndex": 1,
    "explanation": "Each device's cache controls only its own outgoing frames, so both caches must be poisoned to capture both directions."
  },
  {
    "question": "Which of the following is NOT listed in the theory as something a MITM attacker can do?",
    "options": [
      "Read plaintext such as HTTP, Telnet, and FTP passwords",
      "Modify packets in transit",
      "Replay captured credentials",
      "Decrypt valid TLS traffic without the server's private key"
    ],
    "correctIndex": 3,
    "explanation": "Without the server's private key the attacker sees only ciphertext; reading, modifying, and replaying apply to plaintext traffic."
  },
  {
    "question": "Why is DoS described as 'disruption, not surveillance'?",
    "options": [
      "Because DoS encrypts all traffic",
      "Because DoS requires DNS changes",
      "Because redirected packets are discarded rather than relayed, so no inspection of the conversation is possible",
      "Because DoS only affects broadcasts"
    ],
    "correctIndex": 2,
    "explanation": "With forwarding disabled, the attacker drops the traffic, so the victim loses connectivity and nothing is passed on."
  },
  {
    "question": "What does the DHCP Snooping Binding Table map for each switch port, according to the theory?",
    "options": [
      "The expected IP, MAC, and VLAN combination",
      "The expected certificate, key, and hostname",
      "The expected DNS name, TTL, and port speed",
      "The expected gateway, subnet mask, and cache timeout"
    ],
    "correctIndex": 0,
    "explanation": "DAI compares ARP claims with the IP/MAC/VLAN combination expected on each port."
  },
  {
    "question": "Which prerequisite does DAI's validation rely on?",
    "options": [
      "A manual static entry on every host",
      "A VPN tunnel between all hosts",
      "A valid TLS certificate on each port",
      "A managed Layer 2 switch maintaining a DHCP Snooping Binding Table"
    ],
    "correctIndex": 3,
    "explanation": "DAI is a managed-switch feature that validates ARP claims against DHCP snooping bindings."
  },
  {
    "question": "Why can encryption at Layers 4-7 not prevent ARP poisoning's redirection?",
    "options": [
      "Because encryption only works on broadcast frames",
      "Because ARP poisoning acts at Layer 2, where frame delivery is decided before payload protection is involved",
      "Because TLS rewrites MAC addresses",
      "Because VPNs disable ARP caches"
    ],
    "correctIndex": 1,
    "explanation": "ARP poisoning changes local frame delivery at Layer 2; encryption protects content but does not stop frames being redirected."
  },
  {
    "question": "Why does ARP poisoning redirect VPN traffic to the attacker without exposing the payload?",
    "options": [
      "The traffic is encrypted inside the tunnel before it is placed in the Layer 2 frame, so the attacker receives only ciphertext",
      "The VPN disables the victim's ARP cache",
      "The attacker has the VPN key by default",
      "The VPN converts MAC addresses into IP addresses"
    ],
    "correctIndex": 0,
    "explanation": "The tunnel payload is encrypted before framing, so redirected frames carry unreadable content."
  },
  {
    "question": "During ARP-based interception of an SSH session, the attacker presents a different server key. What does the user see?",
    "options": [
      "A normal login with no change",
      "A new ARP Request",
      "A host-key mismatch warning that signals a possible interception attempt",
      "An automatic repair of the ARP cache"
    ],
    "correctIndex": 2,
    "explanation": "SSH host key fingerprint verification produces a mismatch warning even when traffic is redirected."
  },
  {
    "question": "Why is the attacker's re-send interval (~2 seconds) much shorter than the minimum cache expiry (30 seconds)?",
    "options": [
      "To make the switch drop legitimate Replies",
      "To change the attacker's MAC regularly",
      "To avoid triggering DHCP",
      "To refresh the forged entry before it can expire and be replaced by the legitimate mapping"
    ],
    "correctIndex": 3,
    "explanation": "Frequent forged Replies keep the poisoned entry fresh so the real mapping cannot be relearned."
  },
  {
    "question": "Both caches are poisoned. On the victim, what does the entry for the gateway IP show?",
    "options": [
      "The gateway IP mapped to the attacker's MAC; the victim's own IP configuration is unchanged",
      "The gateway IP replaced by the attacker's IP",
      "A static entry with the real gateway MAC",
      "No entry, because poisoning deletes the cache"
    ],
    "correctIndex": 0,
    "explanation": "Poisoning changes the IP-to-MAC association, not the configured IP addresses."
  },
  {
    "question": "Which two legitimate uses of gratuitous ARP does the theory list?",
    "options": [
      "Encrypting traffic and authenticating hosts",
      "IP conflict detection on startup and announcing a MAC address change",
      "Routing across networks and resolving DNS names",
      "Disabling forwarding and clearing caches"
    ],
    "correctIndex": 1,
    "explanation": "Gratuitous ARP is used for conflict detection and for announcing MAC changes such as NIC replacement or failover."
  },
  {
    "question": "Which of these is listed in the theory as absent from ARP?",
    "options": [
      "A digital signature on ARP packets",
      "A broadcast request",
      "A 48-bit hardware address",
      "A cache of recent mappings"
    ],
    "correctIndex": 0,
    "explanation": "The theory lists missing signatures, sender identity verification, and sequence numbers or challenge-response."
  },
  {
    "question": "What does port security do about ARP spoofing, according to the theory?",
    "options": [
      "It validates every IP-MAC claim in ARP packets",
      "It encrypts ARP traffic",
      "It does not directly prevent it but limits the attacker's ability to move around the network",
      "It replaces the need for a gateway"
    ],
    "correctIndex": 2,
    "explanation": "Port security limits MAC addresses per port and can shut down the port; it does not inspect ARP claims."
  },
  {
    "question": "Which layered-defense statement is most accurate?",
    "options": [
      "HTTPS makes DAI unnecessary because it encrypts ARP",
      "DAI makes HTTPS unnecessary because it decrypts traffic",
      "Static ARP and port security both encrypt payloads",
      "DAI blocks forged mappings at the switch, while HTTPS/VPN limit what an attacker can read or forge if redirection still occurs"
    ],
    "correctIndex": 3,
    "explanation": "Mapping-integrity controls and encryption address different stages of the attack and complement each other."
  },
  {
    "question": "A victim sends a packet to a remote internet IP. Which statement about the Ethernet frame is correct?",
    "options": [
      "The frame's destination MAC is the remote server's MAC",
      "The frame's destination MAC is the gateway's MAC while the packet's destination IP is the remote IP",
      "The frame's destination MAC is broadcast",
      "The frame's destination IP is replaced by the gateway's MAC"
    ],
    "correctIndex": 1,
    "explanation": "The local frame targets the gateway at Layer 2 while the IP packet keeps the remote Layer 3 destination."
  },
  {
    "question": "According to the theory, why do devices update their ARP caches even from packets they never requested?",
    "options": [
      "By design, for efficiency, and this is the root cause of ARP's vulnerability",
      "Because DHCP requires it",
      "Because TLS demands it",
      "Because switches force the update"
    ],
    "correctIndex": 0,
    "explanation": "Accepting unsolicited ARP saves requests but lets any device inject mappings."
  },
  {
    "question": "Which set of observations together best supports a transparent MITM?",
    "options": [
      "Only one unsolicited ARP packet in a capture",
      "A static entry on the victim and DAI enabled",
      "Both caches map the other host to the attacker's MAC, forwarding is enabled, and connectivity continues",
      "Both caches are correct and forwarding is disabled"
    ],
    "correctIndex": 2,
    "explanation": "Poisoned caches in both directions plus forwarding produce the Victim -> Attacker -> Gateway path with working connectivity."
  },
  {
    "question": "Why can an attacker on a remote network not directly poison a LAN's ARP caches?",
    "options": [
      "ARP is encrypted between networks",
      "ARP operates on the local network segment, so the attacker must be on the same LAN",
      "DNS blocks remote ARP",
      "Gateways sign every ARP packet"
    ],
    "correctIndex": 1,
    "explanation": "ARP resolves addresses within a local segment; a malicious device must be on that segment."
  },
  {
    "question": "Why is static ARP described as impractical at scale?",
    "options": [
      "It encrypts too much traffic",
      "It requires a managed switch",
      "It changes IP addresses automatically",
      "Every device must be configured manually and entries updated whenever a NIC changes"
    ],
    "correctIndex": 3,
    "explanation": "Manual configuration and maintenance on every device does not scale."
  },
  {
    "question": "A MITM attacker with forwarding enabled is on a network where the victim uses Telnet. What can the attacker do?",
    "options": [
      "Read the credentials, modify the traffic, and replay captured credentials",
      "Only observe encrypted ciphertext",
      "Only drop the connection",
      "Nothing, because Telnet uses MAC addresses"
    ],
    "correctIndex": 0,
    "explanation": "Plaintext protocols like Telnet expose credentials to reading, modification, and replay."
  },
  {
    "question": "Why can a victim's OS not distinguish a legitimate gratuitous ARP from a forged one?",
    "options": [
      "Legitimate ones are always encrypted",
      "Forged ones always have a different format",
      "ARP has no authentication, so both are unsolicited Replies that are accepted the same way",
      "Only forged ones update the cache"
    ],
    "correctIndex": 2,
    "explanation": "Without sender verification, the OS cannot tell a truthful mapping from a false one."
  },
  {
    "question": "Assume exactly one forged Reply to the victim and one to the gateway every 2 seconds. How many forged Replies are sent in 60 seconds?",
    "options": [
      "30",
      "60",
      "120",
      "15"
    ],
    "correctIndex": 1,
    "explanation": "60 / 2 = 30 cycles, each sending 2 Replies, so 60 forged Replies."
  },
  {
    "question": "Which MITM capability requires both forwarding and an unencrypted protocol?",
    "options": [
      "Observing which MAC addresses are on the LAN",
      "Sending a gratuitous ARP",
      "Re-sending forged Replies every 2 seconds",
      "Injecting malicious content into a plaintext HTTP response in transit"
    ],
    "correctIndex": 3,
    "explanation": "Modifying packets in transit works on plaintext traffic when the attacker is in path and relaying."
  },
  {
    "question": "Which is a legitimate, non-malicious reason a MAC address associated with an IP might change?",
    "options": [
      "Using HTTPS",
      "Enabling a VPN",
      "A NIC replacement or failover",
      "Running a DNS query"
    ],
    "correctIndex": 2,
    "explanation": "The theory lists NIC replacement or failover as a legitimate reason for a MAC change announced with gratuitous ARP."
  }
];

/* ─── DOM helpers ───────────────────────────────────────────── */
const $ = (sel, ctx = document) => ctx.querySelector(sel);
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
let _ws = null;
let _wsAttempt = 0;
let _wsTimer = null;

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
  const dot = $('#ws-dot');
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
    if (e.type === 'log' && e.level === 'warn') cls += ' warn';
    const time = e.ts ? `[${new Date(e.ts * 1000).toLocaleTimeString()}] ` : '';
    let text = '';
    if (e.type === 'log') text = e.message;
    else if (e.type === 'attack_state') text = `attack_state active=${e.active} mode=${e.mode}`;
    else if (e.type === 'mitigation_state') text = `mitigation enabled=${e.enabled}`;
    return `<p class="${cls}">${time}${text}</p>`;
  }).join('');

  box.scrollTop = box.scrollHeight;
}

/* Quiz */
function createQuizAttempt(length) {
  const shuffledQuestions = [...QUIZ];
  for (let i = shuffledQuestions.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffledQuestions[i], shuffledQuestions[j]] = [shuffledQuestions[j], shuffledQuestions[i]];
  }

  state.quizQuestions = shuffledQuestions.slice(0, length).map(question => {
    const options = question.options.map((option, index) => ({ option, index }));
    for (let i = options.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [options[i], options[j]] = [options[j], options[i]];
    }
    return {
      ...question,
      options: options.map(item => item.option),
      correctIndex: options.findIndex(item => item.index === question.correctIndex)
    };
  });
  state.quizLength = length;
  state.quizIndex = 0;
  state.quizScore = 0;
  state.quizAnswer = null;
  state.quizUserAnswers = [];
}

function renderQuiz() {
  const panel = $('#panel-Assignment');
  if (!panel) return;

  // ─── STATE 1: Test Setup / Launcher Screen ───
  if (!state.quizQuestions.length) {
    panel.innerHTML = `
      <div class="intro-block">
        <div class="flex items-center justify-between flex-wrap gap-2">
          <div>
            <span class="intro-label">ARP / Virtual Lab</span>
            <h2>Knowledge Assessment & Lab Assignment</h2>
          </div>
          <span class="badge-tag tag-standard">Module Evaluation</span>
        </div>
        <p>Test your conceptual understanding of Address Resolution Protocol mechanics, cache poisoning vectors (MITM interception vs. DoS blackholing), Linux kernel neighbor management, and Layer 2 mitigations.</p>
      </div>

      <div class="assignment-overview-grid">
        <div class="assignment-info-card">
          <div class="info-icon-badge">🎲</div>
          <div class="info-content">
            <span class="info-tag">Dynamic Engine</span>
            <h3>Randomized Assessment</h3>
            <p>Questions and multiple-choice options are dynamically shuffled from our verified question repository using the Fisher-Yates algorithm, providing a distinct test each session.</p>
          </div>
        </div>

        <div class="assignment-info-card">
          <div class="info-icon-badge">🎯</div>
          <div class="info-content">
            <span class="info-tag">Curriculum Scope</span>
            <h3>Core Concepts Tested</h3>
            <p>Covers Layer 2/3 addressing boundaries, broadcast vs. unicast frames, Gratuitous ARP manipulation, kernel IP forwarding, static ARP entries, and switch-level DAI.</p>
          </div>
        </div>

        <div class="assignment-info-card">
          <div class="info-icon-badge">⚡</div>
          <div class="info-content">
            <span class="info-tag">Instant Review</span>
            <h3>Immediate Feedback & RFCs</h3>
            <p>Receive instantaneous answer verification, RFC 826 contextual explanations, interactive progress tracking, and a comprehensive end-of-quiz answer breakdown.</p>
          </div>
        </div>
      </div>

      <div class="quiz-launcher-card">
        <div class="launcher-header">
          <div class="launcher-title-group">
            <span class="intro-label">Assessment Setup</span>
            <h3>Configure Your Test Session</h3>
            <p>Select your desired test length below. Your randomized question set will be generated instantly.</p>
          </div>
        </div>

        <div class="quiz-length-selector">
          <div class="length-option-card ${state.quizLength === 10 ? 'selected' : ''}" data-length="10">
            <div class="length-radio-indicator"></div>
            <div class="length-details">
              <div class="flex items-center justify-between">
                <span class="length-title">10 Questions</span>
                <span class="length-badge">Quick Assessment</span>
              </div>
              <p class="length-desc">Ideal for a rapid post-lab concept check (~5–8 minutes).</p>
            </div>
          </div>

          <div class="length-option-card ${state.quizLength === 20 ? 'selected' : ''}" data-length="20">
            <div class="length-radio-indicator"></div>
            <div class="length-details">
              <div class="flex items-center justify-between">
                <span class="length-title">20 Questions</span>
                <span class="length-badge badge-comprehensive">Comprehensive Exam</span>
              </div>
              <p class="length-desc">Deep-dive assessment covering all attack scenarios & defenses (~12–15 minutes).</p>
            </div>
          </div>
        </div>

        <div class="launcher-actions">
          <button class="btn-primary-pill" id="quiz-start">
            <span>Start Assessment Test</span>
            <span>→</span>
          </button>
        </div>
      </div>`;

    $$('.length-option-card', panel).forEach(card => {
      card.addEventListener('click', () => {
        $$('.length-option-card', panel).forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        state.quizLength = parseInt(card.dataset.length, 10);
      });
    });

    $('#quiz-start', panel).addEventListener('click', () => {
      createQuizAttempt(state.quizLength);
      renderQuiz();
    });
    return;
  }

  // ─── STATE 3: Test Completed / Results Dashboard ───
  const done = state.quizIndex >= state.quizQuestions.length;
  if (done) {
    const percentage = Math.round((state.quizScore / state.quizQuestions.length) * 100);
    const isMaster = percentage >= 80;
    const isProficient = percentage >= 50;

    const verdictTitle = isMaster
      ? '🎉 Outstanding Result!'
      : (isProficient ? '👍 Good Effort!' : '📖 Room for Improvement');

    const verdictDesc = isMaster
      ? 'You have demonstrated a comprehensive understanding of ARP mechanics, cache poisoning, and Layer 2 mitigations.'
      : (isProficient
        ? 'Solid foundational grasp. Review the Theory and Procedure tabs to reinforce your knowledge of IP forwarding and switch DAI.'
        : 'Review the Theory and Procedure tabs to reinforce your knowledge of ARP request/reply cycles and DAI defenses.');

    const recommendation = isMaster
      ? 'Ready for advanced defense configurations and network protocol analysis.'
      : (isProficient
        ? 'Recommended: Re-run the Simulation in DoS mode to inspect dropped frames, then retake the 20-question quiz.'
        : 'Recommended: Walk through the Procedure steps 1 through 6 in the Simulation tab, observing the live ARP table diffs.');

    panel.innerHTML = `
      <div class="intro-block">
        <div class="flex items-center justify-between flex-wrap gap-2">
          <div>
            <span class="intro-label">ARP / Virtual Lab</span>
            <h2>Assignment Completed</h2>
          </div>
          <span class="badge-tag ${isMaster ? 'tag-safe' : (isProficient ? 'tag-warning' : 'tag-danger')}">
            ${isMaster ? 'Mastery Achieved' : (isProficient ? 'Proficient' : 'Needs Review')}
          </span>
        </div>
        <p>Review your assessment performance, benchmark score, and examine the detailed explanations for each question below.</p>
      </div>

      <div class="quiz-results-dashboard">
        <div class="results-summary-grid">
          <div class="results-hero-card">
            <div class="hero-score-badge">
              <span class="score-number">${state.quizScore}</span>
              <span class="score-total">/ ${state.quizQuestions.length}</span>
            </div>
            <div class="hero-score-percent">${percentage}% Score</div>
            <h3 class="hero-verdict-title">${verdictTitle}</h3>
            <p class="hero-verdict-desc">${verdictDesc}</p>
            <div class="hero-action-buttons">
              <button class="btn-primary-pill" id="quiz-restart">↺ Retake Quiz</button>
              <button class="btn-secondary" id="quiz-to-sim">← Back to Simulation</button>
            </div>
          </div>

          <div class="results-metrics-card">
            <h4>Performance Breakdown</h4>
            <div class="metrics-grid">
              <div class="metric-box">
                <span class="metric-val text-green">${state.quizScore}</span>
                <span class="metric-lbl">Correct Answers</span>
              </div>
              <div class="metric-box">
                <span class="metric-val text-coral">${state.quizQuestions.length - state.quizScore}</span>
                <span class="metric-lbl">Incorrect Answers</span>
              </div>
              <div class="metric-box">
                <span class="metric-val text-blue">${percentage}%</span>
                <span class="metric-lbl">Accuracy Rate</span>
              </div>
              <div class="metric-box">
                <span class="metric-val text-brand">${state.quizQuestions.length}</span>
                <span class="metric-lbl">Total Questions</span>
              </div>
            </div>
            <div class="metric-note">
              💡 <strong>Actionable Guidance:</strong> ${recommendation}
            </div>
          </div>
        </div>

        <div class="quiz-review-deck">
          <div class="review-deck-header">
            <div>
              <h3>Detailed Question Review</h3>
              <p>Analyze each question, your selected choice, and the official RFC theoretical explanation:</p>
            </div>
            <span class="quiz-progress-badge">${state.quizQuestions.length} Questions Reviewed</span>
          </div>

          <div class="review-cards-list">
            ${state.quizQuestions.map((q, idx) => {
      const ans = state.quizUserAnswers[idx];
      const isCorrect = ans && ans.isCorrect;
      const selectedIdx = ans ? ans.selectedIndex : null;
      return `
                <div class="review-question-card ${isCorrect ? 'review-correct' : 'review-wrong'}">
                  <div class="review-card-top">
                    <div class="review-q-num">
                      <span class="q-badge">Question ${idx + 1}</span>
                      <span class="review-status-tag ${isCorrect ? 'status-correct' : 'status-wrong'}">
                        ${isCorrect ? '✓ Correct (+1 pt)' : '✕ Incorrect (0 pt)'}
                      </span>
                    </div>
                  </div>
                  <h4 class="review-question-text">${q.question}</h4>
                  <div class="review-options-display">
                    ${q.options.map((opt, optIdx) => {
        let optClass = 'review-opt';
        if (optIdx === q.correctIndex) optClass += ' is-correct-answer';
        if (selectedIdx === optIdx && !isCorrect) optClass += ' is-user-wrong';
        return `
                        <div class="${optClass}">
                          <span class="review-opt-letter">${String.fromCharCode(65 + optIdx)}</span>
                          <span class="review-opt-text">${opt}</span>
                          ${optIdx === q.correctIndex ? '<span class="review-opt-tag tag-correct">Correct Answer</span>' : ''}
                          ${selectedIdx === optIdx && !isCorrect ? '<span class="review-opt-tag tag-wrong">Your Choice</span>' : ''}
                        </div>
                      `;
      }).join('')}
                  </div>
                  <div class="review-explanation-box">
                    <strong>Theoretical & Practical Context:</strong>
                    <p>${q.explanation}</p>
                  </div>
                </div>
              `;
    }).join('')}
          </div>
        </div>
      </div>`;

    $('#quiz-restart', panel).addEventListener('click', () => {
      state.quizQuestions = [];
      state.quizUserAnswers = [];
      state.quizIndex = 0;
      state.quizScore = 0;
      state.quizAnswer = null;
      renderQuiz();
    });

    const simBtn = $('#quiz-to-sim', panel);
    if (simBtn) {
      simBtn.addEventListener('click', () => {
        state.activeTab = 'Simulation';
        renderTabs();
      });
    }
    return;
  }

  // ─── STATE 2: Active Question View ───
  const q = state.quizQuestions[state.quizIndex];
  const progressPercent = Math.round(((state.quizIndex + 1) / state.quizQuestions.length) * 100);

  panel.innerHTML = `
    <div class="intro-block">
      <div class="flex items-center justify-between flex-wrap gap-2">
        <div>
          <span class="intro-label">ARP / Virtual Lab • Assignment Evaluation</span>
          <h2>Knowledge Assessment</h2>
        </div>
        <div class="flex items-center gap-2">
          <span class="quiz-progress-badge">Question ${state.quizIndex + 1} of ${state.quizQuestions.length}</span>
          <span class="quiz-score-pill">Score: <strong>${state.quizScore}</strong> / ${state.quizIndex + (state.quizAnswer !== null ? 1 : 0)}</span>
        </div>
      </div>
      <p>Select the single best answer for each question. Theoretical and RFC explanations will be revealed immediately upon selection.</p>
      <div class="quiz-progress-track">
        <div class="quiz-progress-fill" style="width:${progressPercent}%"></div>
      </div>
    </div>

    <div class="quiz-active-grid">
      <!-- Left Column: Question Card -->
      <div class="quiz-main-card">
        <div class="quiz-q-header">
          <div class="quiz-q-tag">
            <span class="quiz-q-num">Q${state.quizIndex + 1}</span>
            <span class="quiz-q-type">Multiple Choice</span>
          </div>
          <span class="quiz-q-points">1 Point</span>
        </div>

        <h3 class="quiz-question">${q.question}</h3>

        <div class="quiz-options-list">
          ${q.options.map((opt, idx) => {
    let optClass = 'quiz-option';
    if (state.quizAnswer !== null) {
      if (idx === q.correctIndex) {
        optClass += ' correct';
      } else if (state.quizAnswer === idx) {
        optClass += ' wrong';
      } else {
        optClass += ' disabled-unselected';
      }
    }
    return `
              <button class="${optClass}" data-idx="${idx}" ${state.quizAnswer !== null ? 'disabled' : ''}>
                <span class="quiz-opt-letter">${String.fromCharCode(65 + idx)}</span>
                <span class="quiz-opt-text">${opt}</span>
                ${state.quizAnswer !== null && idx === q.correctIndex ? '<span class="opt-status-icon">✓</span>' : ''}
                ${state.quizAnswer === idx && idx !== q.correctIndex ? '<span class="opt-status-icon">✕</span>' : ''}
              </button>
            `;
  }).join('')}
        </div>

        ${state.quizAnswer !== null ? `
          <div class="quiz-explanation ${state.quizAnswer === q.correctIndex ? 'exp-correct' : 'exp-wrong'}">
            <div class="exp-header">
              <div class="exp-icon">${state.quizAnswer === q.correctIndex ? '✓' : '✕'}</div>
              <div>
                <strong>${state.quizAnswer === q.correctIndex ? 'Correct Answer!' : 'Incorrect'}</strong>
                <p class="exp-summary">${state.quizAnswer === q.correctIndex ? '+1 point earned' : `Correct choice: Option ${String.fromCharCode(65 + q.correctIndex)}`}</p>
              </div>
            </div>
            <p class="exp-body">${q.explanation}</p>
            <div class="exp-actions">
              <button class="btn-primary-pill" id="quiz-next">
                <span>${state.quizIndex + 1 < state.quizQuestions.length ? 'Next Question →' : 'View Final Results 🏁'}</span>
              </button>
            </div>
          </div>
        ` : ''}
      </div>

      <!-- Right Column: Sidebar Palette & Stats -->
      <div class="quiz-sidebar">
        <div class="quiz-sidebar-card">
          <div class="sidebar-card-header">
            <h4>Question Navigator</h4>
            <span class="palette-counter">${state.quizIndex + 1} / ${state.quizQuestions.length}</span>
          </div>
          <div class="quiz-palette-grid">
            ${state.quizQuestions.map((_, i) => {
    let pillClass = 'palette-pill';
    let icon = i + 1;
    if (i === state.quizIndex) {
      pillClass += ' current';
    }
    if (state.quizUserAnswers[i]) {
      if (state.quizUserAnswers[i].isCorrect) {
        pillClass += ' answered-correct';
        icon = '✓';
      } else {
        pillClass += ' answered-wrong';
        icon = '✕';
      }
    }
    return `<div class="${pillClass}" title="Question ${i + 1}">${icon}</div>`;
  }).join('')}
          </div>
          <div class="palette-legend">
            <span class="legend-item"><span class="legend-dot dot-current"></span> Current</span>
            <span class="legend-item"><span class="legend-dot dot-correct"></span> Correct</span>
            <span class="legend-item"><span class="legend-dot dot-wrong"></span> Wrong</span>
            <span class="legend-item"><span class="legend-dot dot-pending"></span> Pending</span>
          </div>
        </div>

        <div class="quiz-sidebar-card">
          <div class="sidebar-card-header">
            <h4>Session Overview</h4>
          </div>
          <div class="session-stats-list">
            <div class="session-stat-row">
              <span class="stat-label">Total Questions</span>
              <span class="stat-value">${state.quizQuestions.length}</span>
            </div>
            <div class="session-stat-row">
              <span class="stat-label">Answered</span>
              <span class="stat-value">${state.quizIndex + (state.quizAnswer !== null ? 1 : 0)} / ${state.quizQuestions.length}</span>
            </div>
            <div class="session-stat-row">
              <span class="stat-label">Current Score</span>
              <span class="stat-value highlight-score">${state.quizScore}</span>
            </div>
          </div>
          <button class="btn-secondary btn-full" id="quiz-abandon">↺ Restart Test</button>
        </div>
      </div>
    </div>`;

  $$('.quiz-option', panel).forEach(btn => {
    btn.addEventListener('click', () => {
      if (state.quizAnswer !== null) return;
      const idx = parseInt(btn.dataset.idx, 10);
      state.quizAnswer = idx;
      const isCorrect = idx === q.correctIndex;
      if (isCorrect) state.quizScore++;
      state.quizUserAnswers[state.quizIndex] = {
        selectedIndex: idx,
        correctIndex: q.correctIndex,
        isCorrect: isCorrect,
        question: q.question,
        options: q.options,
        explanation: q.explanation
      };
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

  const abandonBtn = $('#quiz-abandon', panel);
  if (abandonBtn) {
    abandonBtn.addEventListener('click', () => {
      if (confirm('Are you sure you want to restart this test? Current progress will be reset.')) {
        state.quizQuestions = [];
        state.quizUserAnswers = [];
        state.quizIndex = 0;
        state.quizScore = 0;
        state.quizAnswer = null;
        renderQuiz();
      }
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
                ${[1, 2, 3, 4, 5].map(v => `
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
  $('#btn-start-lab').addEventListener('click', () => callApi('/api/lab/start'));
  $('#btn-stop-lab').addEventListener('click', () => callApi('/api/lab/stop'));
  $('#btn-reset-lab').addEventListener('click', () => callApi('/api/lab/reset'));
  $('#btn-start-attack').addEventListener('click', () => callApi('/api/attack/start', { mode: state.attackMode }));
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
    const card = panel.querySelector('.feedback-card');
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
