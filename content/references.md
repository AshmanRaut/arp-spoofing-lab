# References

1. **RFC 826 — An Ethernet Address Resolution Protocol (Plummer, 1982)**
   The original IETF specification defining ARP request/reply packet format, the ARP cache update algorithm, and the broadcast-based resolution mechanism. Foundational reading for understanding exactly what ARP does and does not guarantee.

2. **Kurose, J. & Ross, K. — *Computer Networking: A Top-Down Approach*, Chapter 6 (Link Layer and LANs), ARP section**
   Explains ARP in the context of switched LANs, the role of the ARP table, how request/reply cycles work, and how ARP interacts with IP routing. Widely used university textbook; the link-layer chapter covers Ethernet framing, switches, and ARP in an accessible way.

3. **Forouzan, B. A. — *Data Communications and Networking*, Chapter on Network Layer: Address Mapping, Error Reporting, and Multicasting (ARP/RARP chapter)**
   Covers the ARP and RARP protocols in detail, including packet format diagrams, the role of the ARP cache, proxy ARP, and inverse ARP. Provides a complementary perspective to Kurose & Ross with a stronger focus on protocol-level detail.

4. **MITRE ATT&CK — T1557.002: ARP Cache Poisoning**
   URL: https://attack.mitre.org/techniques/T1557/002/
   The ATT&CK framework entry for ARP Cache Poisoning as an adversarial technique. Covers the attack in the context of real-world threat actor behaviour, detection opportunities (e.g., monitoring for duplicate IP-MAC mappings), and mitigations including DAI and network segmentation.

5. **Cisco — Configuring Dynamic ARP Inspection (official documentation)**
   URL: https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/12-2SX/configuration/guide/book/dynarp.html
   Official Cisco guide to configuring Dynamic ARP Inspection on Catalyst switches. Covers the DHCP Snooping Binding Table, trusted vs. untrusted ports, ARP ACLs, and rate-limiting ARP traffic — the primary enterprise-grade defence against ARP poisoning.

6. **Wireshark Wiki — ARP**
   URL: https://wiki.wireshark.org/ARP
   Documents how Wireshark dissects ARP packets, including field-by-field breakdown of ARP request and reply frames. Useful for hands-on analysis of captured ARP traffic; also notes how to spot gratuitous ARPs and duplicate IP warnings in a capture.
