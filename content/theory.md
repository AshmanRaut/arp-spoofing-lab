# ARP Spoofing — Theory

## 1. OSI Model Context: Layer 2 vs Layer 3

The OSI model divides network communication into layers. **Layer 3 (Network layer)** uses **IP addresses** to route packets across different networks. **Layer 2 (Data Link layer)** uses **MAC addresses** (Media Access Control) to deliver frames between two directly connected devices on the same local network segment.

Every network interface card (NIC) has a globally unique 48-bit MAC address burned in at manufacture (e.g., `aa:bb:cc:dd:ee:ff`). When a device wants to send a packet to an IP address on the same LAN, it must first discover the corresponding MAC address — because the underlying Ethernet frame only understands MAC addresses, not IPs. This is where ARP comes in.

---

## 2. The Address Resolution Protocol (ARP)

**ARP (RFC 826, 1982)** operates at the boundary of Layer 2 and Layer 3. Its sole job is to map an IP address to a MAC address on a local network segment.

### ARP Request

When Host A (IP `10.10.10.10`) wants to reach Host B (IP `10.10.10.1`) and does not know B's MAC address, it broadcasts an **ARP Request** to the entire LAN:

```
"Who has IP 10.10.10.1? Tell 10.10.10.10."
```

- Source MAC: A's MAC
- Destination MAC: `ff:ff:ff:ff:ff:ff` (broadcast — every device on the LAN receives this)
- Source IP: `10.10.10.10`
- Target IP: `10.10.10.1`

### ARP Reply

Host B recognises its own IP and responds with a **unicast ARP Reply** directly to A:

```
"10.10.10.1 is at aa:bb:cc:dd:ee:ff."
```

- Source MAC: B's MAC
- Destination MAC: A's MAC
- Source IP: `10.10.10.1`
- Target IP: `10.10.10.10`

After receiving the reply, Host A stores the mapping in its **ARP cache** and uses B's MAC for all subsequent frames destined for B's IP — until the cache entry expires.

---

## 3. The ARP Cache

Every operating system maintains an **ARP cache** (also called the ARP table): a short-lived in-memory table of `IP -> MAC` mappings learned from recent ARP traffic.

Key properties:
- Entries typically expire after **30-120 seconds** of inactivity (OS-dependent).
- A device updates its cache whenever it receives an ARP packet, **even if it never sent a request** — this is by design for efficiency, and is the root cause of ARP's vulnerability.
- You can view it with `arp -n` (Linux/Mac) or `arp -a` (Windows), or with `ip neigh` on Linux.

Example ARP cache on a victim machine:

```
Address          HWtype  HWaddress           Flags Mask  Iface
10.10.10.1       ether   aa:bb:cc:00:11:22   C           eth0
```

---

## 4. Why ARP Has No Authentication

ARP was designed in 1982 for small, trusted LANs. It has **no cryptographic authentication** — any device on the LAN can send an ARP packet claiming any IP-to-MAC mapping, and all other devices will accept and cache it without question. There is no:

- Digital signature on ARP packets
- Mechanism to verify the sender's identity
- Sequence number or challenge-response to prevent replay

This trust model means that a malicious device on the same LAN segment can freely inject false ARP information into every other device's cache.

---

## 5. Gratuitous ARP

A **Gratuitous ARP** is an ARP Reply sent without any preceding Request. A device announces its own IP-to-MAC mapping to the entire LAN unprompted:

```
"10.10.10.1 is at aa:bb:cc:00:11:22."   (sent by 10.10.10.1 itself)
```

Legitimate uses:
- IP conflict detection on startup
- Notifying the network of a MAC address change (e.g., after a NIC replacement or failover)

**Malicious use:** An attacker can send a gratuitous ARP with a *false* MAC address to silently overwrite the ARP caches of every device on the LAN without any request to trigger it.

---

## 6. How ARP Poisoning Redirects Traffic

**ARP Cache Poisoning** (also called ARP Spoofing) exploits the trust model described above. The attacker sends forged ARP Replies to two targets simultaneously:

1. **To the Victim:** "10.10.10.1 (Gateway) is at `<attacker's MAC>`"
2. **To the Gateway:** "10.10.10.10 (Victim) is at `<attacker's MAC>`"

Both devices update their ARP caches with the false mappings. From that point on:
- When the Victim tries to send a packet to the Gateway, the Ethernet frame is addressed to the **Attacker's MAC** — the Attacker receives it instead.
- When the Gateway tries to reply to the Victim, the frame is again addressed to the **Attacker's MAC**.

All traffic between Victim and Gateway now flows through the Attacker.

```
Before poisoning:
  Victim ─────────────────────────────► Gateway

After poisoning:
  Victim ──► Attacker ──► Gateway     (MITM)
             Attacker ◄── Gateway
```

The attacker must continuously re-send forged ARP Replies (every ~2 seconds) to prevent the legitimate entries from timing back in as the cache naturally expires.

---

## 7. MITM vs DoS Outcomes

### Man-in-the-Middle (MITM)

The attacker **enables IP forwarding** on their machine. Traffic flows:

```
Victim -> Attacker (intercepts + optionally modifies) -> Gateway -> Internet
```

Consequences:
- The attacker can **read** all plaintext traffic (HTTP, Telnet, FTP passwords)
- The attacker can **modify** packets in transit (injecting malicious content)
- The attacker can **replay** captured credentials
- The victim and gateway typically notice **nothing** — the connection still works

### Denial of Service (DoS)

The attacker **disables IP forwarding** (or drops forwarded packets). Traffic flows:

```
Victim -> Attacker (drops packet) -- x --> Gateway
```

Consequences:
- Victim loses connectivity to the gateway and internet
- Legitimate traffic is silently discarded
- No man-in-the-middle inspection is possible — the goal is disruption, not surveillance

---

## 8. Defenses Against ARP Spoofing

### 8.1 Static ARP Entries

An administrator manually adds permanent IP-to-MAC mappings to a device's ARP cache. These entries cannot be overwritten by received ARP packets.

```bash
# Linux -- add a static entry that cannot be poisoned
arp -s 10.10.10.1 aa:bb:cc:00:11:22
# or:
ip neigh add 10.10.10.1 lladdr aa:bb:cc:00:11:22 dev eth0 nud permanent
```

**Limitation:** Impractical at scale — every device on the network must be configured manually, and entries must be updated whenever a NIC changes.

### 8.2 Dynamic ARP Inspection (DAI)

A managed Layer 2 switch feature (common in Cisco environments). The switch maintains a **DHCP Snooping Binding Table** that maps each port to the expected IP/MAC/VLAN combination. When an ARP packet arrives:

- If the claimed IP-MAC pair matches the binding table entry for that port → **allowed**
- If it does not match → **dropped** and the violation is logged

DAI effectively eliminates ARP poisoning on enterprise switched networks without requiring manual static entries.

### 8.3 Port Security

Managed switches can limit the number of MAC addresses permitted on a single port and alert or shut down the port on violation. This does not directly prevent ARP spoofing but limits the attacker's ability to move around the network.

### 8.4 Why HTTPS and VPN Limit Damage Under MITM

Even when an attacker successfully performs ARP Cache Poisoning and sits in-path between victim and gateway, **encrypted protocols significantly reduce the damage**:

- **HTTPS / TLS:** The attacker sees only encrypted ciphertext. Without the server's private key, they cannot read or forge the content. Certificate validation (PKI) will also alert the user if the attacker attempts SSL stripping or certificate substitution.
- **VPN (IPSec, WireGuard, OpenVPN):** All traffic is encrypted inside the tunnel before it even reaches the Layer 2 frame. ARP poisoning redirects the tunnel traffic to the attacker, but the attacker still cannot decrypt the payload.
- **SSH:** Host key fingerprint verification means that even if traffic is redirected, a key-mismatch warning alerts the user to the interception attempt.

**Key insight:** ARP poisoning is a *Layer 2* attack. Encryption operates at *Layer 4-7*. Encryption does not prevent the redirection, but it does prevent the attacker from reading or tampering with the content.

---

## Summary Table

| Concept | Key Point |
|---|---|
| ARP | Resolves IP to MAC on a local LAN segment |
| ARP Cache | Stores recent mappings; expires after 30-120 s |
| No authentication | Any device can send any ARP claim |
| Gratuitous ARP | Unsolicited reply; can poison caches silently |
| ARP Poisoning | Attacker claims victim's and gateway's IPs |
| MITM | Forwarding enabled; attacker reads/modifies traffic |
| DoS | Forwarding disabled; traffic is dropped |
| Static ARP | Manual fix; impractical at scale |
| DAI | Switch-level validation against DHCP bindings |
| HTTPS / VPN | Encrypts content; limits damage even under MITM |
