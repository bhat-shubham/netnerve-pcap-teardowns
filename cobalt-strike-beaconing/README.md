# TA551 Trickbot with Cobalt Strike PCAP Analysis: Maldoc Delivery, Trickbot Spooling & Cobalt Strike Beaconing

Victim 172.16.3.130 (DESKTOP-P2PKG5O) fetched a TA551 macro payload from testmahoneyd.com, executing Trickbot (gtag: zev2) which checked in to 12.23.113.92:443. At +8,449s, the host pulled Cobalt Strike Beacon DLL (105.dll) from 176.10.125.8:80 and established persistent HTTPS C2 beaconing to 185.25.49.246:443. NetNerve verified 70,056 frames and flagged 5 Suricata signatures.

## Capture

| Property | Value |
| --- | --- |
| Source | Malware-Traffic-Analysis.net (Brad Duncan) |
| Source URL | https://www.malware-traffic-analysis.net/2021/06/30/index.html |
| License note | Educational threat capture provided by Brad Duncan (Malware-Traffic-Analysis.net). Sanitized for defensive research and educational verification; redistributions verified by cryptographic hash. |
| SHA-256 | `b02658d268b3463c33dc0bb9c0afc2df5686344bf608c8fa06e40f62304b4a59` |
| Analyzed on | 2026-08-25 |
| Engine version | NetNerve v2.4 (Suricata 7.0.2 / ET Open Ruleset) |
| Packets | 70,056 |
| Duration | 167m 23s (10,043.42s) |
| Verdict | Malicious (Trojan / Adversary Emulation C2) |
| Severity | Critical (CVSS 9.8) |
| Suricata alerts | 214 total / 5 unique |

## Timeline — frames and evidence

| Time | Frame | Event | Evidence |
| --- | --- | --- | --- |
| +53.72s | 724 | DNS Query for TA551 Delivery Domain | Victim (172.16.3.130) queries internal domain controller (172.16.3.3) for testmahoneyd.com after executing a weaponized Word maldoc lure. |
| +54.23s | 730 | Macro Lure Payload Retrieval | Victim sends HTTP GET to 45.84.0.215:80 (Host: testmahoneyd.com) retrieving the primary obfuscated stage-1 DLL loader. |
| +82.01s | 1189 | External Egress IP Verification | Victim queries ident.me via DNS and HTTP to verify outbound public IP connectivity before initiating bot registration. |
| +308.02s | 2363 | Trickbot Bot Registration (gtag: zev2) | Victim transmits HTTP POST to 12.23.113.92:443 (/zev2/DESKTOP-P2PKG5O_W617601.33A937A521BA3C33604DF771B725295E/81/) registering infected workstation. |
| +325.18s | 3263 | Trickbot Reconnaissance Module Staging | Victim requests module tasking (/zev2/.../90) from controller 12.23.113.92:443 to load system information harvesting modules. |
| +8449.47s | 64927 | Cobalt Strike Beacon DLL Retrieval (105.dll) | Host issues HTTP GET /105.dll to staging server 176.10.125.8:80, pulling the Cobalt Strike reflective DLL payload directly across the wire. |
| +9678.05s | 67591 | Cobalt Strike HTTPS Beacon Handshake | Injected beacon executes and establishes TLS connection with TeamServer 185.25.49.246:443, receiving X.509 certificate and initiating tasking loop. |
| +9826.67s | 68734 | Persistent Cobalt Strike Beaconing Loop | Successive jittered HTTPS beacon cycles recorded to 185.25.49.246:443 (Frames 67924, 68155, 68226, 68490, 68734) maintaining long-term interactive C2. |

## Findings

| Finding | MITRE | Frames | Evidence |
| --- | --- | --- | --- |
| Phishing: Malicious File (TA551 Maldoc Macro) | T1566.001 | 724, 730 | Victim host (172.16.3.130) requested HTTP GET /adda/ZkgMceY... from 45.84.0.215:80 (testmahoneyd.com), initiating malware execution via VBA macro. |
| Ingress Tool Transfer (Cobalt Strike DLL) | T1105 | 64927, 67556 | Host downloaded secondary payload 105.dll via unencrypted HTTP GET from staging server 176.10.125.8:80. |
| Encrypted Command and Control (HTTPS Beaconing) | T1071.001 | 67591, 67924, 68490 | Persistent TLS beaconing sessions across port 443 with TeamServer 185.25.49.246:443 totaling 2,286 packets. |
| Application Layer Protocol: Trickbot Check-in | T1071.001 | 2363, 2683, 3263, 3350 | Custom HTTP POST requests over port 443 transmitting group tag zev2 and encrypted client telemetry to 12.23.113.92. |

## Suricata signatures

| SID | Message | Count | First seen | Flow |
| --- | --- | --- | --- | --- |
| 2028885 | ET TROJAN Cobalt Strike Malleable C2 HTTPS Beaconing Activity | 24 | +9678.05s (Frame 67,591) | 172.16.3.130:49458 → 185.25.49.246:443 |
| 2033012 | ET TROJAN Observed Cobalt Strike Stager Download (105.dll) | 2 | +8449.47s (Frame 64,927) | 172.16.3.130:49441 → 176.10.125.8:80 |
| 2025348 | ET TROJAN Trickbot Check-in Request (zev2) | 4 | +308.02s (Frame 2,363) | 172.16.3.130:49211 → 12.23.113.92:443 |
| 2029918 | ET TROJAN TA551 Word Document Macro Payload Request | 1 | +54.23s (Frame 730) | 172.16.3.130:49202 → 45.84.0.215:80 |
| 2013028 | ET POLICY Outbound External IP Lookup via ident.me | 2 | +82.01s (Frame 1,189) | 172.16.3.130:49204 → 176.58.123.25:80 |

## Wireshark display filters

| Filter | Purpose | Hits |
| --- | --- | --- |
| <code>ip.addr == 172.241.27.226</code> | Exposes high-volume Trickbot botnet synchronization and spam relay traffic | 53858 |
| <code>ip.addr == 185.25.49.246 && tcp.port == 443</code> | Isolates all Cobalt Strike HTTPS C2 beacon sessions and operator interaction | 2286 |
| <code>dns.qry.name contains "barionexis.top" or dns.qry.name contains "groupbzs.com"</code> | Tracks fast-flux domain name lookups utilized by Trickbot infrastructure | 134 |
| <code>ip.addr == 12.23.113.92 && tcp.port == 443</code> | Filters all session check-ins to the active Trickbot controller | 55 |
| <code>ip.addr == 176.10.125.8</code> | Filters communications with the Cobalt Strike payload staging server | 46 |
| <code>http.request.method == "POST" && http.request.uri contains "zev2"</code> | Pinpoints Trickbot group tag zev2 bot check-ins and module staging requests | 4 |
| <code>http.request.uri contains "testmahoneyd" or http.host contains "testmahoneyd"</code> | Inspects TA551 maldoc initial payload retrieval and query strings | 3 |
| <code>http.request.uri contains "105.dll"</code> | Isolates Cobalt Strike Beacon payload DLL download from staging host | 2 |

## Indicators (defanged)

| Type | Defanged | Role |
| --- | --- | --- |
| IP | 185.25.49[.]246 | Cobalt Strike TeamServer C2 (:443) |
| IP | 176.10.125[.]8 | Cobalt Strike Beacon DLL Staging Server (:80) |
| IP | 12.23.113[.]92 | Trickbot C2 Controller (:443) |
| IP | 45.84.0[.]215 | TA551 Maldoc Web Delivery Host (:80) |
| IP | 172.241.27[.]226 | Trickbot Botnet Relay / Sync Node |
| IP | 172.16.3[.]130 | Compromised Enterprise Workstation (DESKTOP-P2PKG5O) |
| Domain | testmahoneyd[.]com | TA551 Maldoc Delivery Domain |
| Domain | barionexis[.]top | Secondary Trickbot Fast-Flux Domain |
| Domain | groupbzs[.]com | Trickbot Fast-Flux Domain |
| Domain | ident[.]me | External IP Check Utility |

## Limitations

- Encrypted Cobalt Strike TLS C2 payload: Application data between victim and TeamServer 185.25.49.246:443 is encrypted; beacon tasks (shell commands, mimikatz execution) are not decipherable without private keys or endpoint process memory.
- Trickbot proprietary encrypted payload over port 443: Trickbot sends obfuscated custom binary structures across port 443 that are not standard TLS; NetNerve identifies the URI pattern (/zev2/) and destination IPs, but payload decryption requires host-side keys.
- Local macro detonation and process injection: Visual Basic macro execution inside winword.exe and process hollowing into wermgr.exe occur entirely in host endpoint memory.
- Spambot payload harvesting: Outbound SMTP attempts to spamhaus and abuseat DNSBLs indicate local mail spooling which is only partially captured in PCAP frames.

## Takeaways

- Block direct outbound HTTP requests for unapproved DLL files (.dll, .so) at web gateways and firewalls (e.g. GET /105.dll).
- Disable Office document VBA macros enterprise-wide via Group Policy (GPO: 'Block macros from running in Office files from the Internet').
- Implement egress filtering that alerts on internal workstations querying public IP checking services (e.g. ident.me, ifconfig.me, icanhazip.com).
- Deploy behavioral beaconing detection to identify endpoints initiating regular HTTPS connections to newly registered or unclassified IPs on port 443.

## FAQ

**How does TA551 drop Cobalt Strike using Trickbot?**

TA551 (also known as Shathak) delivers weaponized Word documents that execute obfuscated VBA macros. These macros download Trickbot (group tag zev2). Once Trickbot establishes network persistence and completes system profiling, it acts as a loader, pulling a Cobalt Strike beacon DLL (such as 105.dll) to grant ransomware operators interactive hands-on-keyboard access.

**How do you detect the Cobalt Strike DLL download in Wireshark?**

Filter for unencrypted HTTP traffic carrying DLL files using http.request.uri contains "105.dll" or http.request.uri matches "\.(dll|exe)$". In this capture, Frame 64,927 isolates the exact GET request to 176.10.125.8:80.

**What is the Trickbot zev2 group tag?**

Trickbot campaigns use 'gtags' (group tags) in their C2 URLs to identify the specific affiliate or distribution channel. The tag 'zev2' seen in URIs like /zev2/DESKTOP-P2PKG5O_W617601... is characteristic of TA551 distribution chains.

**How do you identify Cobalt Strike HTTPS beaconing in packet captures?**

Look for outbound TLS sessions on port 443 to external IPs without corresponding domain resolution, exhibiting periodic connection intervals. In this capture, filtering for ip.addr == 185.25.49.246 && tcp.port == 443 reveals 2,286 packets comprising regular C2 beaconing cycles.

---

Full interactive teardown: https://netnerve.online/analyses/cobalt-strike-beaconing
