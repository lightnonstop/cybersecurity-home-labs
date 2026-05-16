# STRRAT (STR Remote Access Trojan) malware PCAP Analysis

| Field        | Value |
|---|---|
| Date         | 16-05-2026
| Platform     | malware-traffic-analysis.net
| Category     | PCAP Analysis
| Difficulty   | Easy
| ATT&CK TTPs  | T1566.001 · T1204.002 · T1105 · T1016.001 · T1095 · T1082
| Tools Used   | Wireshark, VirusTotal
| Time Spent   | 2 hours 46 minutes

---

## Executive Summary
On Tuesday 30-07-2024 approximately 02:40 UTC, a Windows host used by Clark Collier (DESKTOP-SKBR25F) on the wiresharkworkshop.online domain was infected with STRRAT malware delivered via a malicious Java archive email attachment. Post infection traffic showed the host downloading components from Github and Maven repositories before establishing persistent C2 communication with 141.98.10.69 over TCP port 12132. The host also performed a pubic IP lookup via ip-api.com, consistent with STRRAT's standard reconnaissance behaviour.

---

## Artifacts / Environment
**Files provided:**
- `2024-07-30-traffic-analysis-exercise.pcap` - 11.0MB

**Environment (from PCAP / exercise notes):**
- LAN segment: `172.16.1.0/24`
- Domain: `wiresharkworkshop.online`
- Domain Controller: `172.16.1.4 — WIRESHARK-WS-DC`
- Gateway: `172.16.1.1`

**Victim identified:**
- Hostname: DESKTOP-SKBR25F
- IP address: 172.16.1.66
- MAC address: 00:1e:64:ec:f3:08
- Windows user account: ccollier
- Full name: Clark Collier

---

## Scope

**Investigation questions:**
1. What Windows host was infected — hostname, IP, MAC, user account, full name?
2. What malware family is responsible?
3. What was the infection chain — how did it arrive and what did it do post-infection?
4. What are all indicators of compromise from the traffic?

**Initial hypotheses:**
- Hypothesis 1: A host on the 172.16.1.0/24 segment was compromised and is communicating with an external C2 server. 
- Hypothesis 2: The C2 traffic is likely encrypted (TLS or proprietary protocol) given this is a 2024 sample.

---

## Investigation

### Step 1 — Initial Triage (Protocol Hierarchy)

Why: Before anything else, I got a top-level view of what protocols were present in the capture.

Action:
```
Statistics → Protocol Hierarchy
```

![protocol hierarchy](../assets/2024-07-30_protocol-hierarchy.png)

Interpretation: 

The hierarchy immediately confirmed this is an Active Directory domain environment — the presence of Kerberos (56 packets), LDAP (186 packets), SMB2 (273 packets), DCE/RPC (188 packets), and Active Directory Replication (66 packets) all indicate a domain-joined Windows host communicating with a domain controller. This narrowed the victim identification strategy: NBNS and LDAP filters would be reliable for extracting hostname and username rather than relying solely on DHCP.

TCP dominates at 97.5% (11,276 packets), which is expected for a RAT, persistent TCP sessions for C2 beaconing generate high packet volume. TLS is present at 11.6% (1,344 packets), confirming encrypted outbound traffic that could not be read in plaintext, this immediately suggested the C2 channel would be inside TLS or a proprietary TCP protocol rather than plain HTTP.

HTTP is almost absent, I saw only 4 packets under Hypertext Transfer Protocol. This told me before applying any filter that the infection activity was unlikely to be visible in plain HTTP. That directed me toward the TLS handshake filter and the non-standard port SYN filter rather than spending time on HTTP object exports.

DNS at 1.5% (171 packets) is worth noting that is a moderate number of DNS queries, which would later help identify what domains the infected host was resolving during the infection chain.

### Step 2 — Victim host identified via NBNS/DHCP

Filter used:
```
nbns or dhcp
```

Findings:
- hostname DESKTOP-SKBR25F, IP 172.16.1.66, MAC 00:1e:64:ec:f3:08

![Victim host details identified](../assets/2024-07-30_victim-host-identified.png)

---

### Finding: Full Name found via LDAP

Why I ran this:

Filter / command:
```
ldap contains "CN=Users"
```
I found CN=Clark Collier in the LDAP search request to the DC

![User full name found](../assets/2024-07-30_ldap-serach-request.png)

Interpretation: 

The infected machine queried the domain controller for user inforamtion. This is a normal domain behaviour, anchoring the username to a real person.

### Finding: Suspicious traffic to file sharing domains

Why I ran this:

Filter used:
```
(http.request or tls.handshake.type eq 1) and !(ssdp)
```

![Suspicious traffic to file sharing domains](../assets/2024-07-30_github-maven-checks-.png)

What I found:
TLS connection to github.com, objects.githubusercontent.com, repo1.maven.org all on port 443

Interpretation: 
STRRAT downloads Java dependencies from legitimate repos to avoid network-level blocking. Legitimate domains used as delivery infrastructure, a deliberate evasion technique.

### Finding: Public IP address check by infected Windows host

Why I ran this:

Filter used:
```
http.request
```
![IP address check by victim host machine](../assets/2024-07-30_ip-api-checks-.png)

What I found: GET /json/ to ip-api.com on port 80

Interpretation:
This is a standard STRRAT behaviour, the RAT checks the victim's public IP address immediately after infection.

### Finding: STRRAT C2 beacon on port 12132

Filter used:
```
(http.request or tls.handshake.type eq 1 or (tcp.flags.syn eq 1 and tcp.flags.ack eq 0 and !(ip.dst eq 172.16.1.0/24 or tcp.port eq 443 or tcp.port eq 80))) and !(ssdp)
```
What I found: SYN to and unknown IP's port, 141.98.10.69:12132, a non standard port.
No preceding DNS query. I follow the TCP stream, it shows repeated ```
ping|STRRAT|1BE8292C|DESKTOP-SKBR25F|ccollier|Microsoft Windows 11 Pro|64-bit|Windows Defender||1.6|US:United States|Not Installed|``` every 5 seconds.

Interpretation:
This is a communication to a C2 server. The pipe-delimited format is proprietarty for STRRAT. It reports the victim host's details - OS version, Antiviru Status (Windows Defender present), antivirus product (Not installed = no third party Antivirus), Java version. The regular 5 seconds interval confirms automated beaconing.

![TCP Stream of C2 beaconing](../assets/2024-07-30_report-C2-tcp-stream.png)

## Timeline of Events

| Timestamp (UTC)     | Event                                              | Source | ATT&CK TTP  |
|---|---|---|---|
| 2024-07-30 02:39:23 | TLS connections begin to Microsoft/CDN endpoints   | PCAP   | —           |
| 2024-07-30 02:39:53 | Downloads from github.com and objects.githubusercontent.com | PCAP | T1105  |
| 2024-07-30 02:39:57 | Downloads from repo1.maven.org (Java dependencies) | PCAP  | T1105       |
| 2024-07-30 02:40:05 | First SYN to 141.98.10.69:12132 — STRRAT C2       | PCAP   | T1095       |
| 2024-07-30 02:40:06 | GET /json/ to ip-api.com — public IP check         | PCAP   | T1016.001   |
| 2024-07-30 02:40:12 | Repeated STRRAT ping beacons every ~5 seconds begin | PCAP  | T1095       |


## Indicators of Compromise (IoCs)

| Type    | Value                          | Context                                      |
|---|---|---|
| IP      | 141.98.10.69                   | STRRAT C2 server — TCP port 12132            |
| Domain  | github.com                     | Used to host STRRAT payload components       |
| Domain  | objects.githubusercontent.com  | Used to deliver STRRAT components            |
| Domain  | repo1.maven.org                | Java dependency download                     |
| Domain  | ip-api.com                     | Public IP reconnaissance — GET /json/        |
| Port    | TCP 12132                      | Non-standard C2 port for STRRAT              |
| SHA256  | 4c249b325125235b50d9690560c4197a28fd62901b5e02d9eba7436b29447cdd | PL#40704.jar — STRRAT dropper |
| String  | ping\|STRRAT\|                 | Proprietary C2 beacon string in TCP stream   |

---

## ATT&CK Mapping

| Tactic          | Technique ID | Technique Name                                      | Observed Behaviour                              |
|---|---|---|---|
| Initial Access  | T1566.001    | Phishing: Spearphishing Attachment                  | STRRAT delivered as PL#40704.jar email attachment |
| Execution       | T1204.002    | User Execution: Malicious File                      | Victim opened the JAR file                      |
| C&C             | T1105        | Ingress Tool Transfer                               | JAR downloaded components from GitHub and Maven |
| Discovery       | T1016.001    | System Network Configuration Discovery              | GET /json/ to ip-api.com to retrieve public IP  |
| C&C             | T1095        | Non-Application Layer Protocol                      | Raw TCP beacon to 141.98.10.69:12132            |
| Discovery       | T1082        | System Information Discovery                        | Beacon sends OS, AV, username, hostname, Java version |

## Lessons Learned

1. STRRAT's suspicious traffic on port 443 to domains (Github and Maven) that were on a normal legitimate was actually a deliberate evasion technique.
2. Several legitimate sites could be used by a RAT to check for its victim's public IP address, a domain new to me was used so I added it to my known list - [ip-api.com]
3. STRRAT is a Java written malware delivered through email attachment using a .jar file, this particular one called [PL#40704.jar]
4. I could not derive the filter to isolate non-standar port C2 traffic independently and referenced one in a pdf. The filter structure to remember: exclude ports 80 and 443, filter SYN packets only. This surfaces any TCP C2 channel operating outside normal web traffic.
