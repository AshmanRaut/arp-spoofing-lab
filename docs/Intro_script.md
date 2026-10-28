# 🎙️ Introduction Script — ARP Spoofing Virtual Lab
### EXP02 | Computer & Systems Security | Fr. CRCE

> **Format:** Spoken presentation / video voiceover  
> **Estimated Duration:** ~5–7 minutes  
> **Tone:** Academic, clear, engaging

---

## 🟢 SEGMENT 1 — Hook & Context
*(Slide / Visual: Network diagram with a mysterious red arrow intercepting traffic)*

---

**[SPEAKER]**

Imagine you're connected to your college Wi-Fi, browsing normally — sending messages, accessing your bank portal. Everything looks fine. But somewhere on that same network, someone is silently reading every packet you send — not by breaking encryption, not by hacking the server — but by exploiting a flaw in a protocol that's been part of every computer network since 1982.

That flaw is in **ARP** — the Address Resolution Protocol.

And today, we're going to break it.

---

## 🔵 SEGMENT 2 — What is ARP?
*(Slide / Visual: OSI Layer 2 diagram, ARP request-reply animation)*

---

**[SPEAKER]**

Before we demonstrate the attack, let's briefly understand *why* ARP exists.

When your computer wants to send data to another device on the same local network — say, a router — it knows the destination's **IP address**, but Ethernet hardware works with **MAC addresses** — the physical hardware IDs burned into every network card.

ARP bridges this gap. Your machine broadcasts a question to the entire network:
> *"Who has IP address 10.10.10.1? Tell me your MAC address."*

The router replies, your machine caches that answer in its **ARP table**, and from that point on, it sends frames directly using that MAC.

Simple, efficient — and critically — **completely unauthenticated**.

There is no verification. No signature. No challenge. Any machine on the network can reply to that broadcast — even with false information — and the receiver will just... believe it.

---

## 🔴 SEGMENT 3 — The Attack: ARP Cache Poisoning
*(Slide / Visual: Attacker injecting forged ARP reply into the network)*

---

**[SPEAKER]**

This is precisely what an attacker exploits in an **ARP Cache Poisoning** or **ARP Spoofing** attack.

The attacker sends **forged ARP reply packets** — unsolicited — to both the victim and the gateway, claiming:
- *"I am the Gateway. My MAC is [attacker's MAC]."* — sent to the Victim.
- *"I am the Victim. My MAC is [attacker's MAC]."* — sent to the Gateway.

Both machines update their ARP tables. Now, all traffic between the victim and the gateway flows through the attacker's machine first.

This enables two devastating scenarios:

1. **Man-in-the-Middle (MITM):** The attacker silently reads — and can even modify — all packets, while forwarding them normally so neither party notices anything wrong.

2. **Denial of Service (DoS):** The attacker simply discards the intercepted packets, cutting off the victim's network access completely.

---

## 🟣 SEGMENT 4 — Introducing the Virtual Lab
*(Screen: Browser opens the ARP Spoofing Lab frontend — Simulation tab visible)*

---

**[SPEAKER]**

To demonstrate this attack safely and interactively, we built the **ARP Spoofing Virtual Lab** — a fully containerized, browser-based cybersecurity teaching environment.

The lab runs entirely inside **Docker containers** on an isolated internal bridge network — IP range `10.10.10.0/24` — with **zero routing** to your host machine or the internet. There is no risk to your actual network.

The environment consists of **three Linux nodes**:

| Node | IP | Role |
|---|---|---|
| 🟦 Gateway | 10.10.10.1 | Simulated router / default gateway |
| 🟩 Victim | 10.10.10.10 | Traffic generator; target of poisoning |
| 🟥 Attacker | 10.10.10.66 | Runs the Scapy-based ARP poisoning engine |

A **FastAPI backend** orchestrates the containers via the Docker SDK and streams real-time events to the browser over **WebSocket**.

And critically — this is **not** a simulation using pre-recorded animations. The attacker container runs **real raw Scapy scripts** that inject actual Ethernet frames and alter the kernel ARP tables of the victim and gateway in real time.

---

## 🟡 SEGMENT 5 — Lab Walkthrough
*(Screen: Live demo — clicking through the lab UI)*

---

**[SPEAKER]**

Let's walk through what a student actually does in this lab.

**Step 1 — Start the Lab.**
Click "Start Lab." The backend spins up the three containers and the live SVG network map comes to life, showing normal ICMP traffic flowing from the victim to the gateway in teal.

**Step 2 — Inspect the ARP tables.**
Each node card displays its live kernel ARP table — the real IP-to-MAC bindings currently stored in Linux's neighbor table. At this stage, everything is legitimate.

**Step 3 — Launch the Attack.**
Click "MITM Attack" or "DoS Attack." The attacker's Scapy engine begins sending forged ARP replies every two seconds. Watch the network map instantly turn red — the node cards update to show the poisoned, incorrect MAC bindings. The animated packet flows change to reflect traffic being diverted through the attacker.

**Step 4 — Apply Mitigation.**
Toggle the "Mitigation" switch. The backend executes `arp -s` on both nodes — creating **permanent static ARP entries** that the kernel will never override with dynamic replies. The poisoning arrows dissolve, replaced by a defense shield symbol. The tables restore to their true values.

**Step 5 — Stop the Attack.**
The attacker script emits corrective ARP packets and the backend forces `ip neigh replace` entries — both a graceful and guaranteed restoration.

---

## 🔵 SEGMENT 6 — Defense Mechanisms
*(Slide / Visual: Security shield diagrams)*

---

**[SPEAKER]**

The lab teaches two key defenses against ARP spoofing:

**1. Static ARP Entries.**
By manually binding an IP address to a known, trusted MAC address using `arp -s`, the kernel creates a `PERMANENT` entry that it never replaces from incoming dynamic ARP replies. This is effective but must be manually maintained — not scalable for large networks.

**2. Dynamic ARP Inspection — DAI.**
Enterprise-grade switches support DAI, which inspects ARP packets against a trusted DHCP snooping database. Only packets whose IP-to-MAC mappings match the database are forwarded. Spoofed packets are silently dropped at the switch level, before they even reach endpoints.

---

## ⚙️ SEGMENT 7 — Technical Architecture Summary
*(Slide / Visual: Architecture block diagram)*

---

**[SPEAKER]**

Under the hood, the project is built on a clean microservices stack:

- **Frontend:** Vanilla HTML5, CSS3, and ES2020 JavaScript — no framework required, runs directly from `file://` without a web server.
- **Backend:** Python FastAPI with async WebSocket broadcasting and Docker SDK integration.
- **Nodes:** Alpine Linux containers with Scapy for raw packet crafting. The attacker holds `NET_RAW` and `NET_ADMIN` Linux capabilities to craft Ethernet frames.
- **Networking:** Docker Compose internal bridge — `10.10.10.0/24` — completely isolated from the host.

No special software is needed on the student's machine beyond Docker Desktop.

---

## 🟢 SEGMENT 8 — Learning Outcomes
*(Slide / Visual: Checklist of outcomes)*

---

**[SPEAKER]**

By completing this lab, students will be able to:

✅ Explain how ARP resolves IP-to-MAC addresses and why it lacks authentication.

✅ Describe how ARP Cache Poisoning redirects traffic at OSI Layer 2.

✅ Distinguish between the MITM and DoS outcomes of an ARP spoofing attack.

✅ Demonstrate how Static ARP entries and Dynamic ARP Inspection prevent poisoning.

✅ Analyze real kernel ARP tables and identify signs of active poisoning.

---

## 🎯 SEGMENT 9 — Closing
*(Slide / Visual: Lab homepage or project logo)*

---

**[SPEAKER]**

ARP spoofing is one of the oldest and most fundamental network attacks. Yet it remains relevant today — it is the foundation of many LAN-based credential stealing and HTTPS downgrade attacks. Understanding it hands-on, at the packet level, is what separates a security practitioner from someone who's merely read about it.

This virtual lab gives students that hands-on experience — safely, repeatably, and completely inside a browser — without touching any real network.

To run the lab yourself, simply clone the repository and run:

```bash
docker compose up -d --build
```

Then open `frontend/index.html` in your browser, and the lab is ready.

Thank you.

---

> **[END OF SCRIPT]**

---

## 📋 Quick Speaker Reference Card

| Segment | Duration | Key Message |
|---|---|---|
| 1 — Hook | ~30 s | ARP flaw is old, dangerous, and real |
| 2 — ARP Basics | ~45 s | IP→MAC resolution, no authentication |
| 3 — The Attack | ~60 s | Forged replies → MITM or DoS |
| 4 — Lab Intro | ~60 s | Docker isolation, three nodes, Scapy |
| 5 — Walkthrough | ~90 s | Live demo of all 5 steps |
| 6 — Defenses | ~45 s | Static ARP + DAI |
| 7 — Tech Stack | ~30 s | FastAPI + WebSocket + Alpine Linux |
| 8 — Outcomes | ~30 s | 5 learning outcomes |
| 9 — Closing | ~30 s | Call-to-action, `docker compose up` |
