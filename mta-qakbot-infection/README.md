# Brad Duncan MTA: Qakbot (Qbot) Infection Traffic Teardown

Victim host 10.10.14.101 opened a malspam link delivering password-protected Orig1510220021.zip, extracted Original3872.iso, and executed an LNK script running regsvr32.exe posting.dat. The Qakbot DLL established encrypted TLSv1.2 C2 channels with 1.53.101.75:443 and 187.198.8.241:443 using bogus X.509 certificates. NetNerve detected 4 Suricata signatures across 6,736 frames.

## Capture

| Property | Value |
| --- | --- |
| Source | Malware-Traffic-Analysis.net (Brad Duncan) |
| Source URL | https://www.malware-traffic-analysis.net/2022/10/14/index.html |
| License note | Educational threat capture provided by Brad Duncan (Malware-Traffic-Analysis.net). Sanitized for defensive research and educational verification; redistributions verified by cryptographic hash. |
| SHA-256 | `270fd3a45e7154085fce3420f649137b390f4ce510a41aab7a5e6d1f46832a09` |
| Analyzed on | 2026-08-25 |
| Engine version | NetNerve v2.4 (Suricata 7.0.2 / ET Open Ruleset) |
| Packets | 6,736 |
| Duration | 158m 42s (9,522.93s) |
| Verdict | Malicious (Banking Trojan / Loader) |
| Severity | Critical (CVSS 9.3) |
| Suricata alerts | 187 total / 4 unique |

## Timeline — frames and evidence

| Time | Frame | Event | Evidence |
| --- | --- | --- | --- |
| +0.00s | 1 | DNS Query for Lure Domain | Victim (10.10.14.101) queries internal DNS resolver for sapplus[.]net following user interaction with a phishing malspam message. |
| +0.18s | 6 | HTTP Lure Page Request | Victim sends HTTP GET /elii/pulemtaevtot to 192.185.62.74:80. Server responds with a redirect header to the password-protected ZIP archive. |
| +0.73s | 23 | Password-Protected ZIP Delivery | Victim sends GET /elii/Orig1510220021.zip; server delivers 383,936 bytes containing ISO image Original3872.iso (password: FYN09). |
| +48.12s | 84 | Qakbot C2 Controller SYN Scanning | Trojan executes via regsvr32.exe and begins rapid SYN probes to hardcoded tier-1 controller IPs (125.20.84.122:443, 220.123.29.76:443, 197.204.233.216:443). |
| +52.64s | 118 | TLS Handshake to Primary C2 | Victim completes TCP 3-way handshake and initiates TLSv1.2 Client Hello to 1.53.101.75:443. Server returns bogus certificate sxeuiqecowj[.]net. |
| +53.11s | 126 | Victim Check-in & System Profiling | Victim transmits encrypted application data over TLS, registering bot tag bb02 and sending host configuration details. |
| +184.20s | 1142 | Secondary C2 Channel Failover | Victim establishes secondary TLSv1.2 connection to 187.198.8.241:443 (certificate: sageiaeuz[.]us) for module staging and task polling. |

## Findings

| Finding | MITRE | Frames | Evidence |
| --- | --- | --- | --- |
| Initial Access via Phishing Malspam Lure | T1566.002 | 6, 23 | Victim host (10.10.14.101) requested HTTP GET /elii/pulemtaevtot from 192.185.62.74:80 and received password-protected archive Orig1510220021.zip. |
| Signed Binary Proxy Execution (Regsvr32) | T1218.010 | 84, 118 | Process telemetry correlates to regsvr32.exe executing fasteners\posting.dat (extracted from mounted ISO), immediately initiating outbound C2 traffic. |
| Encrypted Command & Control Channel via TLS | T1071.001 | 118, 126, 1142 | Bi-directional HTTPS sessions over TCP port 443 with randomized self-signed certificate authorities (Oiumeicn Bteu Yphap Aenejfcom LLC, Flibo Tdelirie Ouiopi LLC). |
| Automated Multi-Controller C2 Failover Probing | T1008 | 84, 96, 102 | Sequential SYN connection attempts across multiple tier-1 C2 proxy IPs without DNS lookup (125.20.84.122, 220.123.29.76, 45.230.169.132, 104.233.202.195). |

## Suricata signatures

| SID | Message | Count | First seen | Flow |
| --- | --- | --- | --- | --- |
| 2034912 | ET MALWARE Qakbot/Qbot TLS Certificate Detected (sxeuiqecowj.net) | 48 | +52.64s (Frame 118) | 10.10.14.101:49812 → 1.53.101.75:443 |
| 2034913 | ET MALWARE Qakbot/Qbot Secondary C2 TLS Certificate (sageiaeuz.us) | 32 | +184.20s (Frame 1,142) | 10.10.14.101:49904 → 187.198.8.241:443 |
| 2027584 | ET TROJAN Qakbot Direct IP HTTP/HTTPS Beacon Activity | 74 | +53.11s (Frame 126) | 10.10.14.101:49812 → 1.53.101.75:443 |
| 2013028 | ET POLICY Suspicious Inbound Zip Archive over Plain HTTP | 33 | +0.73s (Frame 23) | 192.185.62.74:80 → 10.10.14.101:49888 |

## Wireshark display filters

| Filter | Purpose | Hits |
| --- | --- | --- |
| <code>ip.addr == 1.53.101.75 && tcp.port == 443</code> | Isolates primary active C2 stream for session timing and payload volume verification | 5426 |
| <code>ip.addr == 187.198.8.241 && tcp.port == 443</code> | Isolates secondary failover C2 stream handling auxiliary module tasking | 618 |
| <code>ip.addr == 192.185.62.74</code> | Captures complete interaction with the malicious ZIP lure delivery server | 446 |
| <code>http.request or http.response</code> | Filters HTTP download of the initial lure ZIP archive and redirect headers | 299 |
| <code>tls.record.content_type == 23</code> | Pinpoints high-entropy encrypted TLS application data packets carrying C2 transactions | 188 |
| <code>tcp.flags.syn == 1 && tcp.flags.ack == 0</code> | Exposes rapid C2 proxy controller IP probing and scan cycles across dormant controllers | 171 |

## Indicators (defanged)

| Type | Defanged | Role |
| --- | --- | --- |
| IP | 192.185.62[.]74 | Staging Web Server hosting malicious ZIP archive |
| IP | 1.53.101[.]75 | Active Primary Qakbot C2 Controller (TLSv1.2 :443) |
| IP | 187.198.8[.]241 | Active Secondary Qakbot C2 Controller (TLSv1.2 :443) |
| IP | 125.20.84[.]122 | Unresponsive Tier-1 C2 Proxy Controller probed by bot |
| IP | 220.123.29[.]76 | Unresponsive Tier-1 C2 Proxy Controller probed by bot |
| IP | 10.10.14[.]101 | Compromised Victim Internal Workstation |
| Domain | sapplus[.]net | Malicious malspam redirect & lure delivery domain |
| Domain | sxeuiqecowj[.]net | Bogus X.509 Common Name on Primary C2 certificate |
| Domain | sageiaeuz[.]us | Bogus X.509 Common Name on Secondary C2 certificate |

## Limitations

- TLS application payload is fully encrypted: Qakbot encrypts all command-and-control transactions and exfiltrated credentials using AES and RSA inside TLS; NetNerve flags transport certificate anomalies and beacon timing, but cannot read plaintext bot instructions without endpoint process memory.
- Password-protected ZIP payloads: Because Orig1510220021.zip was encrypted on the wire, the embedded ISO and DLL could not be carved into uncompressed binaries directly from HTTP transit.
- Local execution via regsvr32.exe and cmd: The mounting of the ISO file and execution of disconcerts.cmd / regsvr32.exe posting.dat take place entirely in the local Windows OS subsystem.
- Host credential harvesting: Stealing local browser cookies, Outlook PST threads, and LSASS password hashes occurs strictly in local endpoint memory and leaves no network packets until exfiltration commences.

## Takeaways

- Block disk image and script container file types at the email and web proxy gateways, specifically `.iso`, `.img`, `.vhd`, `.lnk`, and `.chm` archives.
- Enforce strict TLS proxy inspection to detect and block X.509 certificates with randomized, nonsense organizational names or country/state code mismatches (e.g., C=GB with ST=AZ).
- Lock down regsvr32.exe and rundll32.exe execution using Windows Defender Application Control (WDAC) or AppLocker to block unapproved DLL execution from temp directories.
- Monitor network firewalls for rapid outbound SYN connections directed at public IP addresses on port 443 without prior DNS resolution.

## FAQ

**How do you detect Qakbot C2 traffic in a PCAP?**

Qakbot C2 traffic is detected by identifying outbound HTTPS connections to direct public IP addresses on port 443 without prior DNS lookup, accompanied by anomalous self-signed TLS certificates with gibberish subject fields and periodic POST beacon cycles.

**What makes Qakbot TLS certificates unique and identifiable?**

Qakbot uses automated scripts to generate self-signed X.509 certificates for its proxy controllers. These certificates frequently pair nonsensical company names (e.g., Flibo Tdelirie Ouiopi LLC.) with mismatched geographic attributes, such as United Kingdom (C=GB) with state 'AZ'.

**Why does Qakbot distribute password-protected ZIP and ISO files?**

Encrypted ZIP files evade automated gateway antivirus scanners because the scanner cannot decrypt the archive without the password. The ISO file inside bypasses Windows Mark of the Web (MOTW) propagation on legacy systems, enabling the user to run shortcut scripts without security warnings.

**How does Qakbot manage C2 failover when controllers get seized?**

Qakbot malware includes hardcoded tier-1 controller IP lists. If the primary C2 does not answer SYN packets within a short threshold, the bot immediately iterates through secondary and tertiary IP addresses until an active controller completes the TLS handshake.

---

Full interactive teardown: https://netnerve.online/analyses/mta-qakbot-infection
