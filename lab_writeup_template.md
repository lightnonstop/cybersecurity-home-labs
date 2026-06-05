# [Investigation Title — be specific: "Emotet PCAP Analysis — MTA 2023-06-15" not "Lab 1"]

| Field        | Value |
|---|---|
| Date         | YYYY-MM-DD |
| Platform     | Malware Traffic Analysis / CyberDefenders / BTLO / Home Lab |
| Category     | PCAP Analysis / Memory Forensics / Threat Hunting / Detection Engineering |
| Difficulty   | Easy / Medium / Hard |
| ATT&CK TTPs  | T1566.001 · T1059 · T1071.001 (list all that apply) |
| Tools Used   | Wireshark · NetworkMiner · VirusTotal · etc. |
| Time Spent   | X hours |

---

## Executive Summary
<!-- REQUIRED. 2–3 sentences maximum. Written as if briefing a manager who was not present.
     Answer: what happened, who was the victim, what did the attacker do, and what was the outcome.
     
     Example:
     "A Windows host (DESKTOP-HP3Q) on the 10.9.9.0/24 segment was compromised via a drive-by
     download delivering an AsyncRAT payload on 2023-06-15 at approximately 14:22 UTC. The malware
     established persistence via a scheduled task and beaconed to a C2 server at 185.220.101.x
     over port 8808. No lateral movement was observed within the capture window." -->

---

## Artifacts / Environment
<!-- REQUIRED. List exactly what you were given. -->

**Files provided:**
- `YYYY-MM-DD-exercise.pcap` — X MB — MD5: `abc123...`

**Environment (from PCAP / exercise notes):**
- LAN segment: `10.x.x.0/24`
- Domain: `example.local`
- Domain Controller: `10.x.x.x — HOSTNAME-DC`
- Gateway: `10.x.x.1`

**Victim identified:**
- Hostname: 
- IP address: 
- MAC address: 
- Windows user account: 

---

## Scope
<!-- REQUIRED. What were you asked to find? What does a successful investigation look like?
     Write your hypotheses before opening any tool. State at least 2. -->

**Investigation questions / task:**
1. 
2. 
3. 

**Initial hypotheses (written before opening Wireshark):**
- Hypothesis 1: 
- Hypothesis 2: 

---

## Investigation
<!-- REQUIRED. Chronological, first person narrative. Each finding follows this structure:
     ### Finding: [Short title]
     Why I ran this / what I was looking for:
     Command or filter used:
     ```
     code block
     ```
     Screenshot: ![description](../assets/YYYY-MM-DD_finding-name.png)
     Interpretation: what does this tell me? What does it confirm or deny? -->

### Step 1 — Initial Triage (Protocol Hierarchy)

Why: Before anything else, get a top-level view of what protocols are present in the capture.

Filter / action used:
```
Statistics → Protocol Hierarchy
```

![protocol hierarchy](../assets/YYYY-MM-DD_protocol-hierarchy.png)

Interpretation: 

---

### Step 2 — Identify Hosts on the Network

Why: Determine which IPs are active and establish the baseline of what is expected vs. suspicious.

Filter used:
```
nbns or dhcp
```

Findings:
- 

---

### Finding: [Title — e.g., "Suspicious HTTP POST to External IP"]

Why I ran this:

Filter / command:
```

```

Screenshot: ![description](../assets/YYYY-MM-DD_finding.png)

Interpretation: 

---

### Finding: [Title — e.g., "Malware binary extracted from HTTP stream"]

Why I ran this:

Action:
```
File → Export Objects → HTTP → [filename]
```

SHA256 hash: `[run sha256sum on extracted file]`
VirusTotal result: 

Interpretation: 

---

<!-- Add as many Finding subsections as needed. Every notable discovery gets its own finding block. -->

---

## Timeline of Events

<!-- REQUIRED. Build this as you investigate — add rows as you find timestamps.
     All times in UTC. Source = where you found this (PCAP / DHCP log / HTTP header / etc.) -->

| Timestamp (UTC) | Event | Source | ATT&CK TTP |
|---|---|---|---|
| YYYY-MM-DD HH:MM:SS | | | |
| YYYY-MM-DD HH:MM:SS | | | |
| YYYY-MM-DD HH:MM:SS | | | |

---

## Indicators of Compromise (IoCs)

<!-- IF APPLICABLE. Include everything that could be used to detect or block this threat. -->

| Type | Value | Context |
|---|---|---|
| IP | | C2 server — observed outbound beaconing every Xs |
| Domain | | Resolved before C2 connection |
| URL | | Full path of malware download |
| SHA256 | | Malware binary extracted from PCAP |
| User-Agent | | Suspicious UA string in HTTP headers |

---

## ATT&CK Mapping

<!-- REQUIRED. Map every observed behaviour to a MITRE ATT&CK technique.
     Reference: https://attack.mitre.org -->

| Tactic | Technique ID | Technique Name | Observed Behaviour |
|---|---|---|---|
| Initial Access | | | |
| Execution | | | |
| Persistence | | | |
| Defense Evasion | | | |
| Command and Control | | | |
| Exfiltration | | | |

---

## Detection Opportunities

<!-- IF APPLICABLE — Required from Month 7+ of your roadmap.
     What Wazuh rule or Sigma rule would catch this behaviour?
     Even for early PCAP labs, ask yourself: what network signature would a NIDS fire on? -->

**Network-based detection:**
- Suricata/Snort signature for the C2 beacon pattern:
- DNS query for the malicious domain:

**Host-based Sigma rule (add from Month 7+):**

```yaml
title: 
status: experimental
description: 
logsource:
  product: windows
  category: 
detection:
  selection:
    
  condition: selection
falsepositives:
  - 
level: high
tags:
  - attack.t
```

---

## Lessons Learned

<!-- REQUIRED. 3–5 bullets. This is the section a hiring manager reads after the Executive Summary.
     What did you learn technically? What would you do differently?
     What gap did this expose that you will study next? -->

- 
- 
- 
- 

---

## References

<!-- REQUIRED. Link everything you used. -->

- Original exercise: [MTA YYYY-MM-DD](https://www.malware-traffic-analysis.net/YYYY/MM/DD/index.html)
- MITRE ATT&CK techniques referenced:
  - [TXXXX — Technique Name](https://attack.mitre.org/techniques/TXXXX/)
- Tools documentation used:
- Additional reading prompted by this lab:
