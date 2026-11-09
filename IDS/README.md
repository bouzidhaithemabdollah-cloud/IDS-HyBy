# HyBu

> A small, modular network intrusion detection system (IDS) written in Python.
> Built step by step for the "Advanced Networks and Architectures" module at ENSCS.

---

## What is this?

Imagine a security guard standing at the door of your network.
He does not stop anyone. He just **watches who comes in, remembers what he sees, and shouts when something looks wrong**.

That is what an IDS does, and that is what this project does.

Right now it can spot one kind of attack: a **port scan** (someone knocking on many doors to find an open one).
More detectors (SSH brute force, floods, machine learning) are coming. The project is built so that adding a new detector means adding **one new file**, nothing else.

---

## How it works (the big picture)

```
 network traffic
       |
       v
+-------------+    +--------------+    +----------+    +-------------+
|   CAPTURE   | -> | FLOW BUILDER | -> |  ENGINE  | -> | ALERT SINK  |
| sniff       |    | group packets|    | asks each|    | print + save|
| packets     |    | into "talks" |    | detector |    | the alerts  |
+-------------+    +--------------+    +----------+    +-------------+
  (or REPLAYER                              |
   reads a file)                            v
                                  [ PortScan, ... ]
                                     the detectors
```

Every box only talks to the next one through a **callback** (a function you hand over).
That is why we can swap any part without touching the others.

| Box | One-line job | File |
|---|---|---|
| Capture | Catch packets from the network | `core/capture.py` |
| Recorder | Save packets to a file with a label (`normal`, `portscan`...) | `core/recorder.py` |
| Replayer | Read a saved file and play the packets back | `core/replayer.py` |
| Flow Builder | Group packets into conversations (flows) | `core/flow_builder.py` |
| Engine | Give each flow to every detector | `core/engine.py` |
| Detector | Decide "is this an attack?" | `detectors/*.py` |
| Alert Sink | Show alerts on screen and save them | `core/alert.py` |

---

## Quick start

**Install**
```bash
pip install scapy colorama
```
- Windows: install [Npcap](https://npcap.com) so Scapy can sniff.
- Linux: run the live capture with `sudo`.

**Try the demo (no network needed)**
```bash
python test_demo_alert.py
```
It feeds fake traffic through the whole pipeline and prints an alert. You should see:

```
=== 1) Normal browsing (same port, many connections) ===
packets: 125 | alerts: 0 | expected: 0 | PASS

=== 2) Fast port scan (20 ports in ~3 seconds) ===
[ALERT] port_scan    | src: 10.0.0.9      | severity: high
packets: 40 | alerts: 1 | expected: 1 | PASS

=== 3) Slow scan (20 ports, one every 3 seconds) ===
packets: 40 | alerts: 0 | expected: 0 | PASS

ALL TESTS PASSED
```

**Watch real traffic**
```bash
python run_capture.py        # see its options with --help
```

---

## Project structure

```
HyBu/
├── core/
│   ├── capture.py        # live sniffing (Scapy)
│   ├── recorder.py       # save packets + label to .jsonl
│   ├── replayer.py       # read .jsonl back as packets
│   ├── flow_builder.py   # packets -> flows
│   ├── engine.py         # runs all detectors on each flow
│   └── alert.py          # print + save alerts
├── detectors/
│   ├── base.py           # the "contract" every detector follows
│   └── port_scan.py      # the first real detector
├── data/                 # recordings (.jsonl) and alerts
├── run_capture.py        # command line runner
├── test_demo_alert.py    # end-to-end demo
└── README.md
```

---

## Each part, explained with an example

### 1. Capture: catching packets

A **packet** is a small envelope of data. It says who sent it, who receives it, which door (port) it is knocking on, and a few flags.

Capture catches packets with Scapy and turns each one into a simple dictionary:

```python
{"time": 1760500000.1, "src_ip": "10.0.0.5", "dst_ip": "20.1.1.1",
 "proto": "TCP", "srcport": 49671, "dstport": 443,
 "flag": "S", "length": 66}
```

This dictionary is the **contract** for the whole project. Everything after Capture only knows this shape.

What we keep and what we ignore:

| Kept | Ignored | Why |
|---|---|---|
| TCP, UDP, ICMP over IPv4 | ARP, IPv6 | Our attacks live in TCP/UDP/ICMP. Less noise, less CPU. |

The filter `ip and (tcp or udp or icmp)` runs inside the operating system, so unwanted packets never even reach Python. Capture also counts what it saw, kept, and ignored, so nothing disappears silently.

**Good to know:** the TCP "flag" tells you the role of the packet. `S` = "hello, I want to connect" (SYN), `SA` = "hello back" (SYN-ACK), `A` = "ok" (ACK), `F` = "goodbye" (FIN), `R` = "stop!" (RST), `P` = "here is data" (PSH).

### 2. Recorder and Replayer: the time machine

- **Recorder** writes every packet as one JSON line and adds a `label`:
  ```json
  {"time": 1760500000.1, "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1", "proto": "TCP", "srcport": 40001, "dstport": 22, "flag": "S", "length": 60, "label": "portscan"}
  ```
- **Replayer** reads that file and gives the packets back, one by one, as if they were live.

Why this matters:
1. We can test without a lab, and get the **same result every time**.
2. Labeled recordings become the **dataset** for the machine learning part later.
3. If the live demo fails, we replay a recording.

> One rule: record one situation per file. Do not browse YouTube while recording a port scan, or normal traffic gets the label "portscan" and confuses the model later.

### 3. Flow Builder: from packets to conversations

One packet tells us almost nothing. A **flow** is a whole conversation summarized in one line.

Example, 3 packets from the same conversation:

| time | flag | size |
|---|---|---|
| 0.00 | S | 66 |
| 0.05 | PA | 54 |
| 0.70 | FA | 54 |

become one flow:

```python
{"src_ip": "10.0.0.5", "srcport": 49671, "dst_ip": "20.1.1.1", "dstport": 443,
 "proto": "TCP", "start": 0.0, "last_seen": 0.7, "first_flag": "S",
 "packets": 3, "bytes": 174,
 "syn": 1, "ack": 2, "fin": 1, "rst": 0, "psh": 1,
 "duration": 0.7}
```

**Which packets belong together?** The flow key is: `(src_ip, srcport, dst_ip, dstport, proto)`. Same key, same conversation.

**When does a flow end?**
1. A `FIN` or `RST` arrives (the conversation was closed).
2. Silence for `timeout` seconds (default 5).
3. `flush()` is called at the end, to release whatever is still open.

**`first_flag`** remembers the very first packet of the flow. `S` means "this side started the connection". `SA` means "this is just the server answering". Detectors use this to avoid confusing replies with attempts.

**Important rule:** time always comes from the packet (`d["time"]`), never from the computer clock. That is what makes replaying an old recording behave exactly like live traffic.

### 4. Detector contract

Every detector follows the same small contract (`detectors/base.py`):

```python
class BaseDetector:
    name = "base"

    def check(self, flow):
        """Return an alert (dict) if an attack is found, otherwise None."""
        raise NotImplementedError
```

If someone forgets to write `check`, Python complains right away. That is on purpose.

### 5. The Port Scan Detector

**The idea:** a normal user talks to a few doors. A scanner knocks on **many different doors in a short time**.

The detector keeps a small notebook for every pair `(attacker IP, target IP)`. Each flow that starts a connection adds one line: `(time, port)`.

| Setting | Meaning | Default |
|---|---|---|
| `window` | How many seconds the guard remembers | 10 |
| `threshold` | How many different ports in the window means "scan" | 15 |

**The 4 steps for each new flow:**

```
1. Write the new line:        (time, port)
2. Forget old lines:          keep only lines newer than (time - window)
3. Count DIFFERENT ports:     ports = {22, 80, 443, ...}
4. Enough ports?              yes -> alert (once), no -> stay quiet
```

**Example of forgetting** (window = 10 seconds, new flow arrives at second 20):

```
notebook = [(1, 22), (3, 80), (9, 443), (20, 25)]
cutoff   = 20 - 10 = 10

(1, 22)   1  >= 10 ?  no  -> forget
(3, 80)   3  >= 10 ?  no  -> forget
(9, 443)  9  >= 10 ?  no  -> forget
(20, 25)  20 >= 10 ?  yes -> keep

notebook = [(20, 25)]
```

Without forgetting, a normal user who visits one new port per hour would look like a scanner after 15 hours. Forgetting makes the detector ask the right question: *many ports in a short time?*

**Smart choices that make it stronger:**

| Choice | Why |
|---|---|
| Count **different** ports, not flows | A browser opens 50 connections to port 443. That is one port, not a scan. |
| Only flows with `first_flag == "S"` | Server replies (`SA`, `RA`) would look like "many ports" otherwise. |
| One notebook per `(src, dst)` pair | One attacker spraying 20 different machines is not a port scan on one machine. |
| Cooldown of one `window` after an alert | One scan gives one alert, not 200. |

### 6. Engine

The Engine takes each finished flow and asks every detector: "anything suspicious?". If a detector answers with an alert, the Engine passes it on.

```python
engine = Engine([PortScanDetector()], on_alert=AlertSink("data/alerts.jsonl"))
flow_builder = FlowBuilder(on_flow=engine)
```

To add a new detector later, you only add it to that list.

### 7. Alert Sink

Alerts have one fixed format, so a dashboard (or a game) can read them later:

```json
{"time": 3.1, "attack": "port_scan", "src_ip": "10.0.0.9", "severity": "high",
 "detector": "PortScan",
 "details": {"dst_ip": "10.0.0.1", "unique_ports": 15, "window": 10}}
```

| Field | Meaning |
|---|---|
| `time` | When it happened (packet time, not computer clock) |
| `attack` | `port_scan`, later `ssh_brute`, `flood` |
| `src_ip` | The attacker |
| `severity` | `low`, `medium` or `high` |
| `detector` | Which detector raised it |
| `details` | The numbers that prove it |

The sink prints a colored line on screen and, if you give it a path, appends the alert to a `.jsonl` file (one alert per line).

---

## Design decisions (and why)

- **Callbacks everywhere.** Each part receives a function to call next. Parts never know about each other.
- **Packet time, not clock time.** Live and replay behave identically.
- **Plugins.** One detector = one file = one class with `check()`.
- **Start narrow, widen later.** We ignore ARP and IPv6 on purpose, and we count the ignored packets so we know the cost.
- **Low resources.** `store=False` in Scapy, a kernel-level filter, and light callbacks. The project is meant to run on a modest laptop.

---

## Limitations (honest list)

- Only IPv4 and TCP/UDP/ICMP. ARP spoofing and IPv6 attacks are invisible for now.
- Flows are **one-directional**: the server's reply is a separate flow. It works, but a two-way flow would be cleaner.
- The port scan detector looks for SYN scans. Stealthy scans that do not start with `S` (FIN, NULL, Xmas) are not detected yet.
- A scanner that hits **one port on 200 machines** (a host sweep) is not a "port scan" for this detector, because it watches one target at a time.
- A flow is only reported when it closes, so alerts can arrive a few seconds late (detection delay).
- Encrypted traffic is fine, because we only look at metadata (who, where, how much), never at the content.
- So far tested on simulated flows. Tests on real `nmap` recordings come next.

---

## Things I learned the hard way

1. A single space inside a dictionary key (`"proto "` instead of `"proto"`) creates a second key and breaks everything quietly. Print `d.keys()` when something feels strange.
2. A color code inside a key name is not a color. Color the printed text, not the lookup.
3. TCP flags come combined (`"SA"`, `"PA"`). Test each flag with its own `if`, not `elif`.
4. `time.time()` has no place inside the logic. Use the packet's own time.
5. Delete from a dictionary only after you finish looping over it.
6. `in None` is a crash. `is None` is a check.

---

## Roadmap

- [x] Capture (live) with filter and stats
- [x] Recorder and Replayer
- [x] Flow Builder
- [x] Detector contract, Engine, Alert Sink
- [x] Port Scan detector (tested with simulated traffic)
- [ ] Test on real recordings (`nmap` vs normal browsing)
- [ ] SSH brute force detector
- [ ] Flood detector (SYN / ICMP)
- [ ] Machine learning detector (Random Forest, trained on our own labeled recordings)
- [ ] Dashboard
- [ ] Evaluation and comparison with Suricata
- [ ] Optional: automatic blocking

---

## License

MIT
