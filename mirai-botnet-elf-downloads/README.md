# Mirai Botnet PCAP Analysis: /jaws Dropper, Multi-Architecture ELF Downloads and Telnet Scanning

Host 10.12.17.101 fetched /jaws from 158.94.210.88 — a 4,816-byte bash script that wget/curl a hash-named bot binary — then downloaded x86, MIPS and MIPSEL ELF builds (66–97 KB each). Within 18 seconds it resolved the .su C2 domain cnc.504.su and began a high-rate Telnet and port-37215 scan. NetNerve surfaced 29 alert records across 21 SIDs in a 15,000-packet subset of this 118,105-packet capture.

## Capture

| Property | Value |
| --- | --- |
| Source | Malware-Traffic-Analysis.net (Brad Duncan) |
| Source URL | https://www.malware-traffic-analysis.net/2025/12/17/index.html |
| License note | Educational threat capture provided by Brad Duncan (Malware-Traffic-Analysis.net) under fair-use threat research terms. The capture hash below was computed locally from the original pcap. |
| SHA-256 | `c4a670d740317258e7de867b5f2144fab4d1f61cf9981c7b9cc9658408be1738` |
| Analyzed on | 2026-11-23 |
| Engine version | NetNerve (Suricata 7.0.3 / ET Open Ruleset) |
| Packets | 118,105 |
| Duration | 3m 01s (181.33s) |
| Verdict | Confirmed Attack |
| Severity | Critical |
| Suricata alerts | 36 total / 21 unique |

## Timeline — frames and evidence

| Time | Frame | Event | Evidence |
| --- | --- | --- | --- |
| +0.00s | 1 | Dropper host contacted | SYN from 10.12.17.101:58400 to 158.94.210.88:80. The same host serves every subsequent Mirai payload in this capture. |
| +0.57s | 4 | /jaws requested | GET /jaws with User-Agent Wget/1.20.3 (linux-gnu). Suricata later flags the response as a shell-execution payload (SID 1000030). |
| +1.29s | 6 | Bash dropper delivered | 4,816-byte response beginning #!/bin/bash, cd /tmp \|\| cd /var/run \|\| cd /mnt \|\| cd /root \|\| cd /, then wget and curl of http://158.94.210.88/596a96cc.../<hash>.x86. |
| +16.75s | 15 | x86 bot download starts | New connection to source port 55586; GET /596a96cc7bf9108cd896f33c44aedc8a/db0fa4b8db0333367e9bda3ab68b8042.x86 with Wget User-Agent (SID 2025126, 2032924). |
| +17.86s | 73 | First ELF received — 66,544 bytes | HTTP 200 from Apache/2.4.6 on CentOS with ETag 103f0-645f3da024f5f; body starts with the ELF magic 7f 45 4c 46 (SID 2019240). |
| +17.88s | 77 | curl re-fetch of the x86 binary | Second GET for the same .x86 path with User-Agent curl/7.68.0, matching the dropper script's two download commands (SID 2034567). Frame 144 carries the second 66,544-byte ELF. |
| +18.68s | 149 | C2 domain resolved | DNS query to 8.8.8.8 for cnc.504.su — a Soviet Union TLD frequently used by Mirai infrastructure (SID 2014169, 2 hits). |
| +18.68s | 150 | Mass Telnet scanning begins | Immediately after the C2 lookup, the host opens source port 51142 and fires SYN packets to TCP/23 across the Internet at high rate (63,424 packets on port 23 in total). |
| +18.92s | 873 | MIPS build requested | GET ...db0fa4b8db0333367e9bda3ab68b8042.mips with Wget, followed by curl at frame 1717; ELF responses of 96,408 bytes at frames 1189 and 2670 (SID 2025123). |
| +27.66s | 4246 | MIPSEL build requested | GET ...db0fa4b8db0333367e9bda3ab68b8042.mpsl, repeated at frames 28324 and 60047. A 97,224-byte ELF response appears at frame 9948. |
| +181.32s | 117591 | Router RPC scanning phase | Source port 52743 begins SYN sweeps to TCP/37215 — the Huawei Home Gateway RPC port abused by Mirai variants (53,271 packets on that port). |
| +181.33s | 118105 | Capture ends mid-scan | The final frame is another TCP/23 SYN from source port 52999, with the bot still actively scanning when the capture stops. |

## Findings

| Finding | MITRE | Frames | Evidence |
| --- | --- | --- | --- |
| Bash Dropper /jaws | T1059.004 | 4, 6, 9 | The 4,816-byte response to GET /jaws is a shell script that changes into a writable directory and uses both wget and curl to fetch a hash-named binary, then execute it. NetNerve's shell-execution heuristic (SID 1000030) fired on this payload. |
| Multi-Architecture ELF Ingress | T1105 | 73, 144, 1189, 2670, 9948 | Five ELF downloads of 66,544, 66,544, 96,408, 96,408 and 97,224 bytes from 158.94.210.88. The .x86, .mips and .mpsl suffixes let the dropper select the build matching the infected device's CPU. |
| C2 Domain Resolution (.su TLD) | T1071.001 | 149, 2761 | Two DNS lookups for cnc.504.su to 8.8.8.8, flagged by SID 2014169. Only DNS for the C2 domain is visible in the analyzed subset; no plaintext C2 commands were recovered. |
| IoT Exploit & Telnet Scanning | T1190 | 150, 117591, 118105 | 63,424 packets to TCP/23 and 53,271 to TCP/37215. The latter is the Huawei Home Gateway RPC port targeted by Mirai's router exploit; responses from scanned hosts trigger numerous Spamhaus DROP alerts. |

## Suricata signatures

| SID | Message | Count | First seen | Flow |
| --- | --- | --- | --- | --- |
| 2019240 | ET INFO Executable and linking format (ELF) file download Over HTTP | 5 | +17.86s (Frame 73) | 158.94.210.88:80 → 10.12.17.101:* |
| 2034567 | ET HUNTING curl User-Agent to Dotted Quad | 3 | +18.08s (Frame 82) | 10.12.17.101:55588 → 158.94.210.88:80 |
| 2025126 | ET INFO x86 File Download Request from IP Address | 2 | +17.16s (Frame 18) | 10.12.17.101:55586 → 158.94.210.88:80 |
| 2032924 | ET HUNTING Suspicious GET Request for .x86 | 2 | +17.16s (Frame 18) | 10.12.17.101:55586 → 158.94.210.88:80 |
| 2014169 | ET DNS Query for .su TLD (Soviet Union) Often Malware Related | 2 | +18.68s (Frame 149) | 10.12.17.101:53900 → 8.8.8.8:53 |
| 2025123 | ET INFO MIPS File Download Request from IP Address | 2 | +18.92s (Frame 873) | 10.12.17.101:55600 → 158.94.210.88:80 |
| 2400032 | ET DROP Spamhaus DROP Listed Traffic Inbound group 33 | 2 | +0.57s (Frame 6) | 158.94.210.88:80 → 10.12.17.101:58400 / 155.73.245.108:23 → :52999 |
| 2400028 | ET DROP Spamhaus DROP Listed Traffic Inbound group 29 | 1 | +18.7s | 136.230.80.79:23 → 10.12.17.101:52999 |
| 2400025 | ET DROP Spamhaus DROP Listed Traffic Inbound group 26 | 1 | +18.7s | 112.142.12.71:23 → 10.12.17.101:52999 |
| 2400058 | ET DROP Spamhaus DROP Listed Traffic Inbound group 59 | 1 | +18.7s | 204.56.28.230:23 → 10.12.17.101:51142 |
| 2400036 | ET DROP Spamhaus DROP Listed Traffic Inbound group 37 | 2 | +18.7s | 168.206.115.159:23 / 169.129.36.37:23 → 10.12.17.101:* |
| 2400030 | ET DROP Spamhaus DROP Listed Traffic Inbound group 31 | 2 | +18.7s | 145.231.80.197:23 / 145.231.54.66:23 → 10.12.17.101:* |
| 2400004 | ET DROP Spamhaus DROP Listed Traffic Inbound group 5 | 3 | +18.7s | 42.132.187.61 / 42.0.202.170 / 42.212.113.210 :23 → 10.12.17.101:* |
| 2400033 | ET DROP Spamhaus DROP Listed Traffic Inbound group 34 | 1 | +18.7s | 160.122.102.95:23 → 10.12.17.101:52999 |
| 2400034 | ET DROP Spamhaus DROP Listed Traffic Inbound group 35 | 1 | +18.7s | 167.87.27.108:23 → 10.12.17.101:52999 |
| 2400067 | ET DROP Spamhaus DROP Listed Traffic Inbound group 68 | 1 | +18.7s | 209.95.197.217:23 → 10.12.17.101:52999 |
| 2400051 | ET DROP Spamhaus DROP Listed Traffic Inbound group 52 | 1 | +18.7s | 198.196.173.233:23 → 10.12.17.101:52999 |
| 2400056 | ET DROP Spamhaus DROP Listed Traffic Inbound group 57 | 1 | +18.7s | 202.61.185.149:23 → 10.12.17.101:52999 |
| 2400003 | ET DROP Spamhaus DROP Listed Traffic Inbound group 4 | 1 | +18.7s | 36.119.201.33:23 → 10.12.17.101:52999 |
| 2400031 | ET DROP Spamhaus DROP Listed Traffic Inbound group 32 | 1 | +18.7s | 153.14.76.42:23 → 10.12.17.101:52999 |
| 1000030 | NetNerve Command Injection: Shell Execution command | 1 | +0.57s (Frame 6) | 158.94.210.88:80 → 10.12.17.101:58400 |

## Wireshark display filters

| Filter | Purpose | Hits |
| --- | --- | --- |
| <code>http.request</code> | The /jaws dropper plus seven architecture-specific binary requests | 8 |
| <code>ip.addr == 158.94.210.88</code> | All dropper and ELF delivery traffic from the Mirai download host | 1402 |
| <code>tcp.port == 58400</code> | The initial /jaws connection and bash-script response | 14 |
| <code>tcp.port == 23</code> | Mass Telnet scanning and the Spamhaus-listed responses from scanned hosts | 63424 |
| <code>tcp.port == 37215</code> | Huawei Home Gateway RPC exploitation sweep | 53271 |
| <code>dns.qry.name contains cnc.504.su</code> | C2 domain queries and responses to 8.8.8.8 | 4 |
| <code>http.response</code> | Five ELF downloads and the /jaws shell script | 5 |

## Indicators (defanged)

| Type | Defanged | Role |
| --- | --- | --- |
| IP | 10.12.17[.]101 | Compromised host running the Mirai dropper and scanners |
| IP | 158.94.210[.]88 | Mirai payload host (Apache/2.4.6, port 80) |
| IP | 8.8.8[.]8 | Resolver used for the cnc.504.su lookup |
| IP | 155.73.245[.]108 | Spamhaus-listed host responding from TCP/23 |
| IP | 136.230.80[.]79 | Spamhaus-listed host responding from TCP/23 |
| IP | 42.132.187[.]61 | Spamhaus-listed host responding from TCP/23 |
| Domain | cnc.504[.]su | Mirai C2 domain on the .su TLD (SID 2014169) |

## Limitations

- NetNerve analyzed a 15,000-packet subset of the 118,105-packet capture; the scanning counts quoted here were verified against the full local pcap with tshark.
- The ELF binaries were not carved into files or hashed during this analysis; byte lengths and ETags are taken from the HTTP responses, not from a malware sample.
- Only DNS for cnc.504.su is visible in the sampled traffic. No plaintext C2 instructions or bot command channel content were recovered.
- Spamhaus DROP alerts are replies from hosts the victim scanned, not evidence of a separate inbound attack campaign against the VM.
- Persistence, process execution and the compromise that led to the initial /jaws fetch are host-side artifacts not present in a network capture.
- The capture is only 181 seconds long and ends while scanning is still in progress; downstream impact on scanned hosts is not observable.

## Takeaways

- Block 158.94.210.88 and the hash-named URL paths at the proxy and firewall; add the cnc.504.su domain to DNS sinkhole lists.
- Alert on HTTP GETs for /jaws and for .x86, .mips and .mpsl files requested from dotted-quad IP addresses with Wget or curl User-Agents.
- Disable Telnet on IoT devices and block outbound TCP/23 from internal segments unless explicitly required.
- Monitor and rate-limit TCP/37215; patch or retire Huawei Home Gateway devices exposed to the Internet.
- Use egress filtering to prevent infected hosts from scanning the Internet, and alert on a single source port sending thousands of SYNs per second.
- Isolate the host, image the disk and collect memory to confirm which architecture binary was executed and how persistence was established.

## FAQ

**What is Mirai and what does /jaws do?**

Mirai is an IoT botnet that scans for devices with Telnet or known router vulnerabilities, logs in with default credentials and installs an architecture-specific bot binary. /jaws is the small bash dropper: it tries several writable directories, downloads the bot with both wget and curl for redundancy, makes it executable and runs it.

**Why are there x86, MIPS and MIPSEL downloads in one capture?**

Mirai is distributed as separate ELF builds for common CPU architectures. The dropper (or the operator running the test) fetches multiple variants so the correct one can be executed on each victim device. The capture shows 66 KB x86 and 96–97 KB MIPS/MIPSEL builds.

**What is port 37215?**

TCP/37215 is the Huawei Home Gateway RPC service. Several Mirai derivatives exploit it to achieve unauthenticated remote code execution on routers, which is why a SYN sweep to that port so soon after infection is highly characteristic.

**Why are there Spamhaus alerts for inbound traffic?**

Those are replies from IP addresses the newly infected host scanned on TCP/23. Many of the scanned addresses are on the Spamhaus DROP list, so ET classifies the returning traffic as malicious inbound. They are evidence of the bot's scanning, not a separate attacker.

**Which Wireshark filters reproduce these findings?**

Use http.request for the eight downloads, ip.addr == 158.94.210.88 for payload delivery, tcp.port == 58400 for the /jaws script, tcp.port == 23 and tcp.port == 37215 for the scanning phases, and dns.qry.name contains cnc.504.su for the C2 lookups. Exact hit counts are listed above.

---

Full interactive teardown: https://netnerve.online/analyses/mirai-botnet-elf-downloads
