# NetNerve PCAP teardowns

Frame-by-frame forensic breakdowns of real malware captures: timeline evidence, Suricata signatures, Wireshark display filters and defanged IOCs. Generated from the source of truth in NetNerve's `app/analyses/*/data.ts`.

> **IOC handling:** indicators are defanged here (`hxxp`, `[.]`) to prevent accidental clicks. They are stored in plain form in each `indicators.json` for tooling. These are public malware indicators; handle captured traffic responsibly.

## Cases

| Case | Threat | Packets | Suricata SIDs | Filters |
| --- | --- | --- | --- | --- |
| [wannacry-ms17-010](wannacry-ms17-010/README.md) | Malicious (Worm / Exploit) | 46,654 | 2 | 5 |
| [lumma-stealer-c2](lumma-stealer-c2/README.md) | Confirmed Attack | 10,172 | 8 | 7 |
| [emotet-epoch4-infection](emotet-epoch4-infection/README.md) | Confirmed Attack | 44,949 | 13 | 7 |
| [mirai-botnet-elf-downloads](mirai-botnet-elf-downloads/README.md) | Confirmed Attack | 118,105 | 21 | 7 |
| [cobalt-strike-beaconing](cobalt-strike-beaconing/README.md) | Malicious (Trojan / Adversary Emulation C2) | 70,056 | 5 | 8 |
| [mta-qakbot-infection](mta-qakbot-infection/README.md) | Malicious (Banking Trojan / Loader) | 6,736 | 4 | 6 |

## Structure

- `README.md` — human-readable teardown: Timeline → Findings → Suricata → Wireshark filters → IOCs → Limitations → FAQ
- `indicators.json` — machine-readable SIDs, filters and IOCs for one case

## Use

1. Pick a case and copy its Wireshark filters into Display Filter to reproduce the finding.
2. Compare Suricata SIDs against your own sensor output.
3. Feed the defanged IOCs into your blocklist process (re-fang first in a controlled environment).

## Provenance

Each case records its capture source, SHA-256 and engine version in the Capture table. Captures originate from public malware-traffic archives; licensing notes are reproduced verbatim. No customer or private capture data is included.

---

Built by [NetNerve](https://netnerve.online) — AI-assisted PCAP analysis with frame-level evidence. Full interactive versions: https://netnerve.online/analyses
