# Emotet Epoch 4 PCAP Analysis: JooSee.dll Download, Dridex C2 and Spambot Traffic

Host 10.2.8.102 fetched a PowerShell downloader disguised as image/png from 91.240.118.172, which wrote C:\ProgramData\JooSee.dll after retrieving a 377,856-byte PE from 66.175.58.9. The host then beaconed to four Dridex C2 nodes and, from roughly 1h51m into the capture, began brute-forcing SMTP AUTH logins and sending malspam with Excel attachments. NetNerve raised 13 IDS records across 44,949 frames and classified the host as fully compromised.

## Capture

| Property | Value |
| --- | --- |
| Source | Malware-Traffic-Analysis.net (Brad Duncan) |
| Source URL | https://www.malware-traffic-analysis.net/2022/02/08/index.html |
| License note | Educational threat capture provided by Brad Duncan (Malware-Traffic-Analysis.net) under fair-use threat research terms. The capture hash below was computed locally from the original pcap; the accompanying MTA notes and IOC archive were used only for payload attribution. |
| SHA-256 | `1684763c923ae66384a39b7bd3363ef67ee0fe945d761b73cec6fc5096d97bfe` |
| Analyzed on | 2026-11-23 |
| Engine version | NetNerve (Suricata 7.0.3 / ET Open Ruleset) |
| Packets | 44,949 |
| Duration | 2h 11m (7,873.98s) |
| Verdict | Confirmed Attack |
| Severity | Critical |
| Suricata alerts | 13 total / 10 unique |

## Timeline — frames and evidence

| Time | Frame | Event | Evidence |
| --- | --- | --- | --- |
| +0.00s | 1 | Capture begins | Victim 10.2.8.102 (public NAT address 173.166.146[.]112 in later SMTP EHLO banners) starts with outbound web and Microsoft telemetry traffic. |
| +0.38s | 4 | Emotet loader landing page | GET http://91.240.118.172/hh/hh.html returns a 565-byte text/html page — the first stage referenced by the Epoch 4 Excel macro. |
| +2.23s | 13 | PowerShell dropper requested | GET /hh/hello.png from the same host. Despite the .png extension and Content-Type image/png, the response is a 1,255-byte PowerShell script. |
| +2.74s | 16 | Dropper delivered — JooSee.dll path revealed | HTTP 200, Content-Type image/png, Content-Length 1255. The script builds C:\ProgramData\JooSee.dll and lists three hardcoded download URLs (ttisecurity.com, tonysommers.net, internationalstrategy.org). |
| +4.04s | 23 | First DLL download attempt | GET http://ttisecurity.com/cgi/7RFeiqkgymCs/ to 66.175.58.9:80 following the DNS lookup at frame 18. |
| +103.07s | 109 | Second DLL URL succeeds | GET http://tonysommers.net/eln-images/BowlvMV7raSyx8l/ to 66.175.58.9:80. DNS for tonysommers.net was at frame 104 (+102.82s). |
| +104.47s | 517 | Emotet PE completed — 377,856 bytes | HTTP 200 application/x-msdownload, Content-Disposition attachment; filename="ORoYQZRqYPYg9TKs89OsEl.dll". The body is reassembled across 282 TCP segments (frames 111-517). |
| +117.17s | 520 | First Dridex C2 connection | SYN to 185.248.140.40:443 with Win=65535 — a raw binary C2 channel (no TLS SNI), later matched 46 times by the Abuse.ch Dridex JA3 signature. |
| +683.64s | 4113 | Dridex beaconing begins | Repeated short-lived sessions to 185.248.140.40:443 at regular intervals (683s, 1676s, 1722s, 3550s, 3604s, 3635s...), the classic check-in pattern. |
| +6706.23s | 9072 | Spambot module activates — mail DNS burst | Dozens of A-record lookups for smtp.live.com, mail.aol.com, smtp.zoho.com, pop.rediffmailpro.com and other mail hosts in under a second. |
| +7473.56s | 32836 | Second Dridex C2 node | SYN to 69.64.62.4:8080; 14,683 packets follow on this non-standard port. A third node, 51.68.138.110:8080, is contacted at +7589.80s (frame 33225). |
| +7748.63s | 40105 | Fourth Dridex node contacted | SYN to 144.217.88.125:443, 300 packets total. All four C2 IPs match the Emotet Epoch 4 IOC list in the MTA notes. |
| +7749.70s | 40332 | SMTP credential stuffing | AUTH LOGIN to smtp.gmail.com with base64 user cs@motleyinternational.in / password Motley@Motley; server returns 535 BadCredentials (frame 40396). Many similar attempts follow. |
| +7866.78s | 44651 | Compromised mailbox — spam relay found | AUTH LOGIN to smtp.qq.com (101.32.113.90:25) as yj-gd12@dgyejia.cn succeeds with 235 Authentication successful at frame 44663. |
| +7867.81s | 44881 | Malspam sent with Excel lure | MAIL FROM <yj-gd12@dgyejia.cn>, RCPT TO <meera.v@idctechnologies.com>; SMTP/IMF message carries text/html plus an application/vnd.ms-excel attachment. Queued at frame 44949 — Emotet's spambot module is now spreading the next generation. |

## Findings

| Finding | MITRE | Frames | Evidence |
| --- | --- | --- | --- |
| PowerShell Downloader Disguised as PNG | T1059.001 | 13, 16 | The 1,255-byte body of /hh/hello.png is a PowerShell script that obfuscates the destination path with {MMM} placeholders, resolves to C:\ProgramData\JooSee.dll, and embeds three download URLs. Suricata SID 2035000 fired on this exact response. |
| Emotet Epoch 4 DLL Ingress | T1105 | 109, 111, 517 | 66.175.58.9 served a 377,856-byte MZ/PE file with Content-Type application/x-msdownload and a random .dll filename. The MTA notes identify it as JooSee.dll, SHA-256 2fe031c18972a7575529e516f21e5149c52162f27643d627bfdaa4091cfcb79c. |
| Dridex JA3 C2 Beaconing | T1071.001 | 520, 32836, 33225, 40105 | Eighty JA3 hits for 'ET JA3 Hash - [Abuse.ch] Possible Dridex' across 185.248.140.40:443 (46), 69.64.62.4:8080 (17), 51.68.138.110:8080 (9) and a multi-source group (8). The 443 sessions are raw TLS-looking binary with no SNI; the 8080 sessions use Win=65535. |
| SMTP AUTH Credential Guessing | T1110.001 | 40332, 40439, 44577, 44651 | The host sends base64-encoded USER/PASS pairs to dozens of SMTP servers on 25, 465 and 587. Most are rejected (535); one account on smtp.qq.com is accepted and immediately used as a relay. |
| Malspam Propagation with Excel Lure | T1566.001 | 44674, 44881, 44949 | A queued message from the compromised mailbox carries an application/vnd.ms-excel attachment with a 'Re: Hiring... .Net Developer' subject — Epoch 4's malspam lure family. The MTA notes list the accompanying XLS and ZIP attachment hashes. |

## Suricata signatures

| SID | Message | Count | First seen | Flow |
| --- | --- | --- | --- | --- |
| 2035000 | ET MALWARE PowerShell Script Downloading Emotet DLL | 1 | +2.74s (Frame 16) | 91.240.118.172:80 → 10.2.8.102:49736 |
| 2018959 | ET INFO PE EXE or DLL Windows file download HTTP | 1 | +104.47s (Frame 517) | 66.175.58.9:80 → 10.2.8.102:49740 |
| 2016538 | ET INFO Executable Retrieved With Minimal HTTP Headers - Potential Second Stage Download | 1 | +104.47s (Frame 517) | 66.175.58.9:80 → 10.2.8.102:49740 |
| 2014520 | ET INFO EXE - Served Attached HTTP | 1 | +104.47s (Frame 517) | 66.175.58.9:80 → 10.2.8.102:49740 |
| 2400016 | ET DROP Spamhaus DROP Listed Traffic Inbound group 17 | 1 | Early capture (Frames 1-4) | 91.240.118.172:80 → 10.2.8.102:49730 |
| 2028765 | ET JA3 Hash - [Abuse.ch] Possible Dridex | 46 | +117.17s (Frame 520) | 10.2.8.102:49741 → 185.248.140.40:443 |
| 2028765 | ET JA3 Hash - [Abuse.ch] Possible Dridex (second C2) | 17 | +7473.56s (Frame 32836) | 10.2.8.102:49867 → 69.64.62.4:8080 |
| 2028765 | ET JA3 Hash - [Abuse.ch] Possible Dridex (third C2) | 9 | +7589.80s (Frame 33225) | 10.2.8.102:50111 → 51.68.138.110:8080 |
| 2028765 | ET JA3 Hash - [Abuse.ch] Possible Dridex (multi-source) | 8 | +7748.63s (Frame 40105) | Multiple sources → Multiple destinations |
| 2062715 | ET INFO Observed UA-CPU Header | 1 | +0.38s (Frame 4) | 10.2.8.102:49730 → 91.240.118.172:80 |
| 2031231 | ET INFO Observed ZeroSSL SSL/TLS Certificate | 1 | +7782.09s (Frame 41580) | 103.169.21.110:587 → 10.2.8.102:50222 |
| 1000020 | NetNerve XSS: Script tag detected | 1 | +0.80s (Frame 7) | 91.240.118.172:80 → 10.2.8.102:49730 |
| 1000041 | NetNerve Path Traversal: Directory bypass (windows) | 1 | +104.47s (Frame 517) | 66.175.58.9:80 → 10.2.8.102:49740 |

## Wireshark display filters

| Filter | Purpose | Hits |
| --- | --- | --- |
| <code>http.request</code> | All five HTTP requests — the two loader URLs, the two DLL URLs and one Windows Update check | 5 |
| <code>ip.addr == 91.240.118.172</code> | Complete Emotet stage-1 conversation: hh.html and the disguised PowerShell PNG | 21 |
| <code>ip.addr == 66.175.58.9</code> | DLL delivery traffic, including the 282 reassembled segments of JooSee.dll | 423 |
| <code>ip.addr == 185.248.140.40</code> | Primary Dridex C2 beaconing on port 443 (repeated short sessions) | 8000 |
| <code>tcp.port == 8080</code> | Dridex C2 on the two non-standard 8080 nodes (69.64.62.4 and 51.68.138.110) | 22279 |
| <code>tcp.port == 25 \|\| tcp.port == 465 \|\| tcp.port == 587</code> | Spambot phase: SMTP AUTH attempts and mail relay sessions | 12024 |
| <code>smtp</code> | SMTP-protocol frames only — base64 AUTH LOGIN, MAIL FROM, RCPT TO and DATA | 666 |

## Indicators (defanged)

| Type | Defanged | Role |
| --- | --- | --- |
| IP | 10.2.8[.]102 | Compromised victim (public NAT 173.166.146[.]112) |
| IP | 91.240.118[.]172 | Emotet Epoch 4 stage-1 loader (hh.html / hello.png) |
| IP | 66.175.58[.]9 | Hosted the 377,856-byte Emotet DLL |
| IP | 185.248.140[.]40 | Dridex C2 over TCP 443 (46 JA3 hits) |
| IP | 69.64.62[.]4 | Dridex C2 over TCP 8080 (17 JA3 hits) |
| IP | 51.68.138[.]110 | Dridex C2 over TCP 8080 (9 JA3 hits) |
| IP | 144.217.88[.]125 | Dridex C2 over TCP 443 |
| IP | 101.32.113[.]90 | smtp.qq.com relay that accepted the bot's AUTH LOGIN |
| IP | 103.169.21[.]110 | SMTP relay with ZeroSSL certificate (SID 2031231) |
| Domain | ttisecurity[.]com | Emotet DLL URL in the PowerShell script (first URL) |
| Domain | tonysommers[.]net | Emotet DLL URL that delivered JooSee.dll |
| Domain | internationalstrategy[.]org | Third hardcoded DLL URL in the dropper script |

## Limitations

- NetNerve analysed a 15,000-packet subset of the 44,949-packet capture as indicated by the sampling disclaimer; low-rate background traffic outside that subset may not be represented.
- C2 payloads on 443/tcp and 8080/tcp are a proprietary binary protocol, not standard TLS — no SNI or decryptable application data is available, so command content cannot be reconstructed from this pcap alone.
- The three additional DLL URLs and the full set of Excel attachment hashes come from the accompanying MTA notes, not from observed packets; only ttisecurity.com and tonysommers.net appear on the wire here.
- SMTP AUTH credentials are base64-encoded in cleartext, but they are drawn from the botnet's stolen address list. They are decoded for detector development and deliberately not republished as actionable credentials.
- The NetNerve XSS and Windows path-traversal heuristics fired on binary bytes inside the PE file and the loader page; they are corroborating signals, not evidence of a separate web exploit against the victim.
- Host-side artifacts — the Excel macro, registry persistence, process tree and on-disk DLL — are inferred from the MTA notes and wire traffic, not observed by NetNerve directly.

## Takeaways

- Block outbound connections to the four C2 IPs and alert specifically on TCP/8080 sessions with an initial TCP window of 65,535 and no HTTP or TLS handshake.
- Alert on any HTTP response with Content-Type image/png whose body contains PowerShell tokens such as $path, .replace('{MMM}','') or ProgramData — a high-fidelity Emotet loader signature.
- Restrict SMTP 25/465/587 egress to approved relays, and alert on bursts of AUTH LOGIN attempts followed by MAIL FROM/RCPT TO with attached application/vnd.ms-excel files.
- Hunt endpoints for C:\ProgramData\JooSee.dll and the SHA-256 2fe031c...79c; the same DLL is also dropped as gfbzhbliguxkomh.voj in AppData.
- Enforce Protected View and macro blocking on Office attachments delivered by email; Epoch 4's lure uses XLS and password-protected ZIP attachments.
- Treat any host making JA3-matched Dridex connections as fully compromised: isolate, reimage and rotate every credential that was used in the SMTP phase.

## FAQ

**What is Emotet Epoch 4?**

Epoch 4 was the fourth major reload of the Emotet botnet after its 2021 takedown. It spread through malicious Excel macros and password-protected ZIPs, dropped a DLL loader such as JooSee.dll into ProgramData, and partnered with other malware families — here Dridex — for credential theft and banking fraud.

**How do you spot Emotet in a PCAP?**

Look for a small HTTP response served as image/png that is actually a PowerShell script, typically containing obfuscated paths like C{MMM}:\Pr{MMM}ogramD{MMM}ata and three hardcoded download URLs. Follow that with an application/x-msdownload response of roughly 377 KB and an MZ header, then repeated raw-TCP beaconing to a small set of C2 IPs.

**Why is there Dridex traffic in an Emotet capture?**

Emotet operated as a delivery network for other malware. In this run the loader fetched an Emotet DLL and the host then established Dridex-associated JA3 connections to four C2 nodes. The Dridex JA3 signature (SID 2028765) accounts for 80 of the alerts in this capture.

**What is the spambot traffic near the end of the capture?**

Emotet's spam module brute-forces SMTP accounts using a list of stolen credentials, then uses any successful login to send new malspam. That phase starts around frame 9,072 with a burst of mail-server DNS lookups and culminates in a queued message with an Excel attachment at frame 44,881.

**Which Wireshark filters reproduce these findings?**

Use http.request for the five web requests, ip.addr == 91.240.118.172 for the dropper, ip.addr == 66.175.58.9 for the DLL, ip.addr == 185.248.140.40 and tcp.port == 8080 for C2, and smtp for the credential-stuffing and malspam phase. Each filter's hit count is listed above.

---

Full interactive teardown: https://netnerve.online/analyses/emotet-epoch4-infection
