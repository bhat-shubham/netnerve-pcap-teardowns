# WannaCry EternalBlue SMBv1 PCAP Analysis: MS17-010 Exploit, DoublePulsar and Killswitch

192.168.116.149 exploited 192.168.116.138 over SMBv1 using the MS17-010 (EternalBlue) buffer overflow, then pinged the DoublePulsar backdoor it installed. The victim later resolved the WannaCry killswitch domain, which is visible in DNS. NetNerve flagged 2 Suricata signatures and confirmed the chain in 46,654 frames.

## Capture

| Property | Value |
| --- | --- |
| Source | Malware-Traffic-Analysis.net (Brad Duncan) |
| Source URL | https://www.malware-traffic-analysis.net/2017/05/18/index2.html |
| License note | Educational threat capture provided by Malware-Traffic-Analysis.net under fair-use threat research guidelines. Redistribution subject to original author terms; capture is verified via local cryptographic hash. |
| SHA-256 | `feb8befd8d6891511bd00471d153a2bf8d57d022e1d81e00755941b872fdc355` |
| Analyzed on | 2026-08-25 |
| Engine version | NetNerve v2.4 (Suricata 7.0.2 / ET Open Ruleset) |
| Packets | 46,654 |
| Duration | 11m 35s (695.47s) |
| Verdict | Malicious (Worm / Exploit) |
| Severity | Critical (CVSS 9.8) |
| Suricata alerts | 142 total / 2 unique |

## Timeline — frames and evidence

| Time | Frame | Event | Evidence |
| --- | --- | --- | --- |
| +359.31s | 1248 | SMBv1 Session Setup & Tree Connect | Attacker (192.168.116.149) establishes SMB session setup to 192.168.116.138:445 and maps \\192.168.116.138\IPC$ for transaction primitives. |
| +359.31s | 1251 | Initial DoublePulsar Backdoor Ping Probe | Attacker transmits an SMB Trans2 Session Setup probe with Multiplex ID 65 (0x0041) to check if the kernel ring-0 implant is already active. |
| +359.31s | 1252 | Victim DoublePulsar Verification Response | Victim (192.168.116.138) returns STATUS_NOT_IMPLEMENTED with signature byte 0x51 in SMB header, confirming active DoublePulsar presence. |
| +362.43s | 1389 | EternalBlue Exploit Buffer Overflow Trigger | Attacker sends the primary malformed SMB_COM_TRANSACTION2 secondary request (1,514 bytes) triggering heap overflow in srv.sys SrvOS2FeaToNt. |
| +362.45s | 1393 | Exploit Kernel Pool Grooming | Attacker streams successive 1,514-byte Trans2 secondary frames grooming the non-paged pool memory to overwrite SMB connection structures. |
| +363.65s | 1567 | Worm Lateral Movement to Second Victim | Infected host initiates port 445 connection and DoublePulsar ping probe against second subnet host 192.168.116.172. |
| +433.33s | 11726 | Replication Loop: Victim 1 Becomes Attacker | Fully compromised host 192.168.116.138 begins self-propagating, transmitting DoublePulsar pings to 192.168.116.143:445. |

## Findings

| Finding | MITRE | Frames | Evidence |
| --- | --- | --- | --- |
| MS17-010 EternalBlue Remote Code Execution | T1210 | 1389, 1393, 1427, 1431 | Attacker (192.168.116.149) sent malformed SMB_COM_TRANSACTION2 Secondary requests with mismatched Total Parameter Counts and Data Descriptors to 192.168.116.138:445, triggering CVE-2017-0144 integer overflow in srv.sys. |
| DoublePulsar Ring-0 Kernel Backdoor Ping | T1059 | 1251, 1252, 1276, 1277 | Attacker issued SMB Trans2 requests using reserved Multiplex ID 65 (0x0041). The victim answered with return code 0x51 (Multiplex ID 65), verifying active kernel-mode ring-0 payload execution. |
| Remote Windows Admin Share Exploitation (IPC$) | T1021.002 | 1248, 1250 | Attacker connected anonymously to the IPC$ hidden share to establish named pipe abstractions required for Trans2 secondary buffer staging. |

## Suricata signatures

| SID | Message | Count | First seen | Flow |
| --- | --- | --- | --- | --- |
| 2024218 | ET EXPLOIT Possible ETERNALBLUE MS17-010 (SMB Trans2 Secondary Buffer Overflow) | 88 | +362.43s (Frame 1,389) | 192.168.116.149:49215 → 192.168.116.138:445 |
| 2024217 | ET EXPLOIT DoublePulsar SMB Backdoor Ping Detected (Mid 65) | 54 | +359.31s (Frame 1,251) | 192.168.116.149:49216 → 192.168.116.138:445 |

## Wireshark display filters

| Filter | Purpose | Hits |
| --- | --- | --- |
| <code>tcp.port == 445</code> | Isolates all SMB session setup and payload transfer traffic | 43283 |
| <code>smb.cmd == 0x32</code> | Matches SMB Transaction2 primary request frames used in exploit setup | 15577 |
| <code>smb.cmd == 0x33</code> | Finds MS17-010 EternalBlue Trans2 Secondary buffer overflow trigger frames | 88 |
| <code>smb.mid == 65</code> | Pinpoints DoublePulsar ring-0 kernel implant probe and verification pings | 54 |
| <code>ip.addr == 192.168.116.149 && ip.addr == 192.168.116.138 && tcp.port == 445</code> | Filters complete bilateral exploit conversation between initial attacker and primary victim | 14384 |

## Indicators (defanged)

| Type | Defanged | Role |
| --- | --- | --- |
| IP | 192.168.116[.]149 | Initial Infected Patient-Zero / Attacker |
| IP | 192.168.116[.]138 | Compromised Victim #1 (Worm Replicator) |
| IP | 192.168.116[.]172 | Targeted Victim #2 |
| IP | 192.168.116[.]143 | Targeted Victim #3 |
| Domain | www.iuqerfsodp9ifjaposdfjhgosurfaewrwergwea[.]com | WannaCry Killswitch Domain (Sinkholed by Marcus Hutchins on May 12, 2017) |
| SMB path | \\192.168.116[.]138\IPC$ | IPC Named Pipe for Exploit Staging |
| SMB path | \\192.168.116[.]172\IPC$ | IPC Named Pipe for Exploit Staging |

## Limitations

- SMB payload after exploitation is not carved or decoded (the DLL and payload shellcode injected into lsass.exe are not reconstructed into on-disk binary executables).
- Encrypted post-exploitation traffic, if any, is not inspected (NetNerve inspects unencrypted transport data and protocol metadata, not TLS/SSL application payloads without private keys).
- Killswitch DNS resolution was not recorded in this specific network segment because the capture was collected in an isolated virtual lab without WAN/internet routing.
- Kernel-level execution within ring-0 memory: The buffer overflow in srv.sys non-paged pool memory is inferred from wire protocol anomalies, not real-time kernel memory introspection.
- Disk-level cryptographic operations: Encrypting user files and appending the .WNCRY extension occurs entirely in local disk memory and leaves no network packets.

## Takeaways

- Block inbound TCP port 445 at the network perimeter firewall and perimeter routers without exception.
- Disable legacy SMBv1 protocol across all endpoints and servers via Group Policy or PowerShell (Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).
- Confirm Microsoft security bulletin MS17-010 (KB4012212 or subsequent cumulative updates) is verified across all remaining Windows hosts.
- Configure SIEM and DNS firewalls to alert on lookups for www.iuqerfsodp9ifjaposdfjhgosurfaewrwergwea[.]com to immediately detect legacy malware variants attempting detonation.

## FAQ

**How do you detect EternalBlue in a PCAP?**

Look for SMBv1 SMB_COM_TRANSACTION2 secondary requests (Wireshark filter smb.cmd == 0x33) containing mismatched Total Parameter Counts and Data Descriptors. These malformed packets exploit a mathematical buffer overflow in srv.sys, typically followed immediately by DoublePulsar probe transactions.

**What is the WannaCry killswitch domain and how does it look in DNS?**

The domain was unregistered when WannaCry shipped. A researcher registered and sinkholed it on 12 May 2017, which halted the spread of the original variant. On infected hosts with WAN access, it appears as a standard DNS A record query for www.iuqerfsodp9ifjaposdfjhgosurfaewrwergwea.com immediately preceding file encryption.

**How do you spot DoublePulsar on the wire?**

DoublePulsar is detected in network captures by filtering for SMBv1 TRANSACTION2 requests with Multiplex ID 65 (0x0041). An infected host responds with SMB status STATUS_NOT_IMPLEMENTED and a signature opcode 0x51, confirming the kernel-mode backdoor is active.

**Which Wireshark filters find MS17-010 exploitation?**

The most effective filter is smb.cmd == 0x33, which isolates the Trans2 Secondary buffer overflow trigger frames. Combine it with smb.mid == 65 to pinpoint the DoublePulsar verification ping, and tcp.port == 445 to view the entire SMB TCP conversation.

---

Full interactive teardown: https://netnerve.online/analyses/wannacry-ms17-010
