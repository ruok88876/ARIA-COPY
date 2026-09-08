# ARIA SDN OpenFlow 1.3 Subsystem

## Overview
The ARIA SDN module controls traffic flows between external attackers, legitimate protected servers, and Cowrie honeypot decoys using OpenFlow 1.3.

---

## Network Architecture & Topology

```
[Attacker: 10.0.0.1, MAC 00:00:00:00:00:01]
                    │
                    ▼ (Switch Port 1)
        [OpenFlow 1.3 Switch: s1]
            │               │
  (Switch   │               │ (Switch
   Port 2)  ▼               ▼  Port 3)
      [Server: 10.0.0.10] [Honeypot: 10.0.0.50]
```

---

## Linux Environment Requirements

* **Operating System:** Ubuntu 20.04 or 22.04 LTS recommended
* **Python:** Python 3.8, 3.9, or 3.10 (Ryu eventlet dependency requires <= 3.10)
* **Packages:**
  * Open vSwitch (`sudo apt-get install -y openvswitch-switch`)
  * Mininet 2.3+ (`sudo apt-get install -y mininet`)
  * Ryu Controller (`pip install ryu eventlet==0.30.2`)

---

## How to Run

### 1. Start Open vSwitch
```bash
sudo service openvswitch-switch start
```

### 2. Launch Ryu Controller
```bash
ryu-manager --verbose sdn/controller.py
```

### 3. Launch Mininet Topology
In a separate terminal:
```bash
sudo python3 sdn/mininet_topo.py
```
Or via Mininet CLI command:
```bash
sudo mn --custom sdn/mininet_topo.py --topo aria --controller=remote,ip=127.0.0.1,port=6653 --switch=ovsk,protocols=OpenFlow13
```

### 4. Test Attack Redirection in Mininet CLI
Simulate attacker initiating SSH connections to the legitimate server:
```mininet
mininet> attacker ssh 10.0.0.10
```
After the threshold is reached (5 attempts), subsequent connections are dynamically redirected to the Cowrie honeypot (`10.0.0.50`), and network telemetry is transmitted to the ARIA backend.
