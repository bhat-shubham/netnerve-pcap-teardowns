# Lumma Stealer C2 PCAP Analysis: futupath.cyou Beaconing, MEGA Staging and Command Injection

Host 172.16.1.101 visited a cluster of suspicious software/crack domains, opened TLS sessions to mega.nz over 31.216.144.5, then began resolving futupath.cyou at +6m35s. That domain pointed to 64.89.161.173, which received 13 POST requests to / — including a 50 KB upload and a 546 KB multipart body flagged by NetNerve as command injection — and returned an 11 KB binary payload. NetNerve raised 8 IDS records across 10,172 frames and classified the host as actively compromised.

## Capture

| Property | Value |
| --- | --- |
| Source | Malware-Traffic-Analysis.net (Brad Duncan) |
| Source URL | https://www.malware-traffic-analysis.net/2026/08/10/index.html |
| License note | Educational threat capture provided by Brad Duncan (Malware-Traffic-Analysis.net) under fair-use threat research terms. The capture hash below was computed locally from the original pcap. |
| SHA-256 | `8c4c4fbe2eb489de42ce533fb2767aa2aade283c1e7165fb0d9d6cfebe6dfa63` |
| Analyzed on | 2026-11-23 |
| Engine version | NetNerve (Suricata 7.0.3 / ET Open Ruleset) |
| Packets | 10,172 |
| Duration | 10m 02s (601.99s) |
| Verdict | Confirmed Attack |
| Severity | Critical |
| Suricata alerts | 22 total / 8 unique |

## Timeline — frames and evidence

| Time | Frame | Event | Evidence |
| --- | --- | --- | --- |
| +0.00s | 1 | Suspicious software site resolved | The first packet is a DNS query from 172.16.1.101 to 172.16.1.1 for freeprosoftzs.info — a domain typical of fake software / crack download lures. |
| +0.47s | 8 | TLS to lure domain | ClientHello with SNI freeprosoftzs.info to 172.67.142.13:443, followed within seconds by newlycrack.com (frame 28) and rupatch.com (frame 50). |
| +15.77s | 1224 | More lure domains contacted | TLS SNI for pc4soft.com (frame 1224), pcvision.org (frame 1282) and applicationsformacos.co (frame 1704) — the same fake-software landing-page pattern. |
| +43.61s | 2086 | SYN-FIN protocol anomaly #1 | 172.30.0.1:443 → 172.16.1.101:54014 arrives with FIN+SYN+ACK set. NetNerve SID 3000001 flags it as a protocol validation violation. |
| +44.73s | 2087 | MEGA file-sharing stage begins | DNS lookup for mega.nz, followed by TLS SNI mega.nz to 31.216.144.5:443 at frame 2100. Additional lookups for na.static.mega.co.nz and g.api.mega.co.nz follow. |
| +46.48s | 2118 | SYN-FIN protocol anomaly #2 | 150.171.110.209:443 → 172.16.1.101:54007 also carries FIN+SYN+ACK (SID 3000002). Similar packets recur at frames 2128, 8026, 8055 and 8060. |
| +88.00s | 6022 | MEGA user-storage endpoint | DNS lookup for gfs270n071.userstorage.mega.co.nz; TLS SNI to 89.44.168.212:443 at frame 6049 — consistent with staging or exfiltration of a file through MEGA. |
| +394.56s | 8650 | Lumma C2 domain resolved | First of nine DNS queries for futupath.cyou. The A record at frame 8652 resolves to 64.89.161.173, matching SID 2071487 (ET MALWARE Win32/Lumma Stealer Related CnC Domain). |
| +394.96s | 8653 | C2 TCP connection established | SYN to 64.89.161.173:80 from source port 54239; SYN/ACK at frame 8655. The host opens a fresh source port for each beacon rather than holding one session. |
| +395.32s | 8659 | First C2 POST | POST / to futupath.cyou with Chrome/109 User-Agent and multipart/form-data body. The server answers 200 with application/json at frame 8839. |
| +403.23s | 8903 | First large upload | A POST with Content-Length 50,545 bytes to the same endpoint; C2 replies with text/html at frame 8933. |
| +419.07s | 9016 | Command-injection flow opens | New connection from source port 54254 to 64.89.161.173:80. The request header at frame 9019 declares a 546,706-byte multipart body — the payload NetNerve SID 1000030 flagged as shell execution. |
| +423.03s | 9782 | 546 KB beacon body delivered | The large multipart POST completes on the 54254 flow (795 packets total). This volume is far beyond a normal fingerprint beacon and is consistent with bulk data or a staged binary. |
| +427.25s | 9842 | C2 sends back binary payload | 64.89.161.173 returns HTTP 200 application/octet-stream with an 11,000-byte body — a post-exploitation payload delivered to the infected host. |

## Findings

| Finding | MITRE | Frames | Evidence |
| --- | --- | --- | --- |
| Lumma Stealer C2 Beaconing | T1071.001 | 8650, 8653, 8659, 8903, 9782 | Thirteen POST requests to http://futupath.cyou/ on port 80, each on a fresh TCP source port. The domain is flagged by Emerging Threats SID 2071487 as Lumma Stealer C2 infrastructure and resolves to 64.89.161.173. |
| Cloud Storage Staging via MEGA | T1567.002 | 2087, 2100, 6022, 6049 | DNS and TLS SNI for mega.nz, na.static.mega.co.nz, g.api.mega.co.nz and gfs270n071.userstorage.mega.co.nz, with 149 packets to 31.216.144.5:443. Encrypted content cannot be inspected, but the pattern matches cloud-based staging/exfiltration. |
| Command Injection Heuristic Hit | T1059 | 9016, 9019, 9782 | NetNerve SID 1000030 fired on the 795-packet flow to 64.89.161.173:80 whose multipart body is 546,706 bytes. The body is obfuscated/compressed, so the heuristic is corroborating rather than a recovered plaintext shell command. |
| Fake Software / Crack Lure Activity | T1204.002 | 1, 8, 28, 50, 1224, 1704 | The capture opens with TLS sessions to freeprosoftzs.info, newlycrack.com, rupatch.com, pc4soft.com, pcvision.org and applicationsformacos.co — domains consistent with the malvertising/crack sites Lumma is distributed through. |

## Suricata signatures

| SID | Message | Count | First seen | Flow |
| --- | --- | --- | --- | --- |
| 2071487 | ET MALWARE Win32/Lumma Stealer Related CnC Domain in DNS Lookup (futupath .cyou) | 9 | +394.56s (Frame 8650) | 172.16.1.101:60077 → 172.16.1.1:53 |
| 2400009 | ET DROP Spamhaus DROP Listed Traffic Inbound group 10 | 1 | +395.32s (Frame 8659) | 64.89.161.173:80 → 172.16.1.101:54239 |
| 2039584 | ET FILE_SHARING Observed DNS Query to Filesharing Service (mega .co .nz) | 5 | +47.91s (Frame 2220) | 172.16.1.101:58293 → 172.16.1.1:53 |
| 2049344 | ET FILE_SHARING File Sharing Related Domain in DNS Lookup (mega .nz) | 2 | +44.73s (Frame 2087) | 172.16.1.101:62730 → 172.16.1.1:53 |
| 2049372 | ET FILE_SHARING File Sharing Domain Observed in TLS SNI (mega .nz) | 2 | +45.56s (Frame 2100) | 172.16.1.101:54167 → 31.216.144.5:443 |
| 1000030 | NetNerve Command Injection: Shell Execution command | 1 | +419.50s (Frame 9019) | 172.16.1.101:54254 → 64.89.161.173:80 |
| 3000001 | NetNerve Protocol Validation: SYN-FIN Detected | 1 | +43.61s (Frame 2086) | 172.30.0.1:443 → 172.16.1.101:54014 |
| 3000002 | NetNerve Protocol Validation: SYN-FIN Detected | 1 | +46.48s (Frame 2118) | 150.171.110.209:443 → 172.16.1.101:54007 |

## Wireshark display filters

| Filter | Purpose | Hits |
| --- | --- | --- |
| <code>dns.qry.name contains futupath.cyou</code> | All nine Lumma C2 domain lookups to the internal resolver | 9 |
| <code>http.request</code> | The thirteen C2 POSTs plus one OCSP GET | 14 |
| <code>ip.addr == 64.89.161.173</code> | Complete Lumma C2 conversation, including the 546 KB upload and payload download | 1054 |
| <code>tcp.port == 54254</code> | The multipart POST flow that triggered the command-injection heuristic | 795 |
| <code>ip.addr == 31.216.144.5</code> | TLS session carrying the mega.nz SNI | 149 |
| <code>tls.handshake.extensions_server_name</code> | All ClientHello SNI values — lure sites, MEGA, Microsoft and Google telemetry | 77 |
| <code>tcp.flags == 19</code> | SYN+FIN+ACK protocol-violation packets (two distinct alert rules) | 6 |

## Indicators (defanged)

| Type | Defanged | Role |
| --- | --- | --- |
| IP | 172.16.1[.]101 | Compromised victim host |
| IP | 64.89.161[.]173 | Lumma Stealer C2 (futupath.cyou, port 80) |
| IP | 31.216.144[.]5 | TLS endpoint for mega.nz SNI |
| IP | 172.16.1[.]1 | Internal DNS resolver used by the victim |
| IP | 172.30.0[.]1 | Source of the first SYN-FIN protocol anomaly |
| IP | 150.171.110[.]209 | Source of the second SYN-FIN protocol anomaly |
| Domain | futupath[.]cyou | Lumma Stealer C2 domain (SID 2071487) |
| Domain | mega[.]nz | File-sharing service used for staging (DNS + TLS SNI) |
| Domain | na.static.mega[.]co.nz | MEGA static-content host |
| Domain | g.api.mega[.]co.nz | MEGA API endpoint |
| Domain | gfs270n071.userstorage.mega[.]co.nz | MEGA user-storage endpoint |
| Domain | freeprosoftzs[.]info | Suspicious software/crack lure domain (first connection) |
| Domain | newlycrack[.]com | Crack-site lure domain |
| Domain | rupatch[.]com | Crack/patch-site lure domain |
| Domain | pc4soft[.]com | Fake software lure domain |
| Domain | pcvision[.]org | Fake software lure domain |
| Domain | applicationsformacos[.]co | Fake software lure domain |

## Limitations

- MEGA traffic is TLS-encrypted; only DNS and SNI are visible, so the content staged or exfiltrated through mega.nz cannot be reconstructed from this capture.
- The command-injection finding is a heuristic hit on an obfuscated/compressed multipart body — no plaintext shell command string was recovered and no host-side execution evidence is available.
- The SYN-FIN packets may be spoofed or generated by unrelated scanning rather than Lumma itself; they are reported as protocol anomalies, not attributed C2 activity.
- The lure domains are inferred from DNS/TLS ordering and naming conventions; the capture does not contain the download that actually installed Lumma Stealer.
- No malware hash, persistence mechanism or memory artifact appears in the pcap. Verify those through an endpoint memory dump and disk image.
- The generic sampling disclaimer on the analysis applies to tier limits; this teardown used the full 10,172-packet capture.

## Takeaways

- Block futupath.cyou and 64.89.161.173 at DNS, proxy and firewall layers; add the .cyou domain to threat-intel feeds.
- Alert on repeated POST / requests to newly observed domains with multipart/form-data bodies, especially any body over 50 KB.
- Restrict or log access to mega.nz and other file-sharing services from corporate endpoints; treat MEGA SNI from a non-browser process as suspicious.
- Flag TCP packets with SYN and FIN both set at the perimeter — they are never legitimate in a normal handshake.
- Isolate 172.16.1.101, capture a memory image and disk image, and rotate every credential stored on the host.
- Use DNS filtering to block fake software/crack domains such as freeprosoftzs[.]info, newlycrack[.]com and rupatch[.]com.

## FAQ

**What is Lumma Stealer?**

Lumma Stealer is an information-stealing malware sold as a service. It harvests browser credentials, cookies, cryptocurrency wallets and system information, then exfiltrates it to operator-controlled C2 domains. It is commonly distributed through fake software and crack sites.

**How does Lumma beacon in this capture?**

The host resolves futupath.cyou to 64.89.161.173, then opens a new TCP connection to port 80 for each POST to /. Thirteen such POSTs appear over roughly 31 seconds, with JSON and HTML replies, followed by an 11 KB binary response.

**Why are MEGA domains present?**

Lumma operators frequently use legitimate cloud-storage services to stage payloads and exfiltrate stolen archives. The DNS lookups and TLS SNI for mega.nz, na.static.mega.co.nz and a userstorage endpoint are consistent with that pattern, though the encrypted content cannot be inspected here.

**What does the command-injection alert mean?**

NetNerve's heuristic flagged a 546,706-byte multipart POST from port 54254 as shell-execution-like. The body is obfuscated, so treat this as a strong signal of post-exploitation activity rather than a recovered command line. Correlate with endpoint process telemetry.

**Which Wireshark filters reproduce these findings?**

Use dns.qry.name contains futupath.cyou for the C2 lookups, ip.addr == 64.89.161.173 for the full C2 conversation, tcp.port == 54254 for the large POST, ip.addr == 31.216.144.5 for the MEGA TLS session, and tcp.flags == 19 for the SYN-FIN packets. Hit counts for each are listed above.

---

Full interactive teardown: https://netnerve.online/analyses/lumma-stealer-c2
