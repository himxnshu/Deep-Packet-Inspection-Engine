# Multi-Threaded Deep Packet Inspection (DPI) Engine & Interactive Dashboard

A high-performance, modular Deep Packet Inspection (DPI) and traffic-filtering engine built in pure Python, complete with a modern interactive Streamlit Web Dashboard.

The engine parses raw PCAP captures across Layer 2 through Layer 7, implements consistent 5-tuple flow hashing across concurrent worker threads, maintains stateful connection tracking, extracts Application-Layer metadata (TLS SNI, HTTP Host, DNS queries), and enforces dynamic packet filtering policies.

---

## Architecture Overview

The system uses a multi-stage producer-consumer pipeline designed to model hardware-accelerated middleboxes and enterprise firewalls:

```text
                  +-------------------+
                  |   PCAP Reader     |
                  +---------+---------+
                            |
           5-Tuple Hash Modulo (LB Selection)
                            v
                  +---------+---------+
                  |   Load Balancers  |  (LB Threads)
                  |   LB0       LB1   |
                  +----+---------+----+
                       |         |
          5-Tuple Hash Modulo (FP Pool Selection)
                       v         v
                  +----+---------+----+
                  | Fast Path Workers |  (FP Inspection Cores)
                  | FP0  FP1 FP2  FP3 |
                  +----+---------+----+
                       |         |
            Rule Match & Output Forwarding
                       v         v
                  +----+---------+----+
                  |   Output Queue    |
                  +---------+---------+
                            |
                            v
                  +---------+---------+
                  |   Output Writer   |  (Filtered PCAP Sink)
                  +-------------------+
```

### Core Components
* **PcapReader & PacketParser**: Decodes raw binary Ethernet frames, IPv4 variable-length headers, and TCP/UDP transport segments using Python's native `struct` and `socket` modules with standard network byte order (`!I`).
* **Consistent Flow Hash**: Canonicalizes bidirectional network conversations ($(SrcIP, DstIP, SrcPort, DstPort, Protocol)$) so both outbound and inbound traffic for any flow map consistently to the exact same Fast Path core.
* **FastPath Processor**: Worker threads that inspect payload bytes, maintain connection state lifecycles (`NEW` → `ESTABLISHED` → `CLASSIFIED` → `CLOSED`/`BLOCKED`), and enforce traffic policy drops.
* **L7 Deep Packet Inspection**:
  * **TLS SNI Extractor**: Parses TLS Client Hello handshake records and extracts the Server Name Indication hostname extension from encrypted HTTPS traffic.
  * **HTTP Host Extractor**: Parses plaintext HTTP headers and isolates targeted request endpoints.
  * **DNS Query Extractor**: Decodes query labels and domain resolution lookups.
* **RuleManager**: Thread-safe policy configuration supporting source IP blocklists, protocol destination port blocks, target application blocks, and wildcard domain filters (e.g., `*.google.com`, `*tiktok*`).
* **ConnectionTracker**: Bidirectional flow state tracking, TCP flags state machine (`SYN`, `SYN-ACK`, `FIN`, `RST`), packet/byte counters, and global throughput metrics.

---

## Project Structure

```text
├── src/
│   ├── app.py                 # Interactive Streamlit Web Dashboard
│   ├── assets/                # Visual themes & UI artwork
│   ├── main_dpi.py            # CLI entry point for multi-threaded DPI engine
│   ├── main_working.py        # Single-pass detailed CLI packet inspector
│   ├── dpi_engine.py          # Multi-threaded pipeline orchestrator
│   ├── load_balancer.py       # Flow distribution workers (LB threads)
│   ├── fast_path.py           # Worker packet inspection threads (FP cores)
│   ├── connection_tracker.py  # 5-tuple flow state tracker & bidirectional accounting
│   ├── rule_manager.py        # Thread-safe firewall rules (App / Domain / IP)
│   ├── packet_parser.py       # Layer 2-4 protocol decoding (Ethernet, IPv4, TCP/UDP)
│   ├── sni_extractor.py       # TLS SNI & HTTP Host payload inspection
│   ├── pcap_reader.py         # Binary PCAP parser and writer
│   ├── platform_utils.py      # Cross-platform CPU core detection
│   ├── thread_safe_queue.py   # Bounded blocking queue implementation
│   └── types_dpi.py           # Core dataclasses, FiveTuple, and enums
│
├── generate_test_pcap.py      # Synthetic test PCAP generator
├── test_dpi.pcap              # Sample network traffic capture
├── requirements.txt           # Python dependencies (Streamlit, Pandas, Altair)
└── README.md                  # Architectural documentation
```

---

## Cloud Deployment Guide

### Option A: Streamlit Community Cloud (Recommended for Live App)

The full interactive DPI studio requires persistent WebSockets and Python concurrency. The official, free, zero-config platform to host it is **Streamlit Community Cloud**:

1. Go to **[share.streamlit.io](https://share.streamlit.io)** and log in with your GitHub account.
2. Click **"New app"** and fill in:
   - **Repository**: `himxnshu/Deep-Packet-Inspection-Engine`
   - **Branch**: `main`
   - **Main file path**: `src/app.py`
3. Click **"Deploy!"** — Your live interactive dashboard will be online in under a minute!

---

### Option B: Vercel (Interactive Web Showcase & Simulator)

Vercel is a serverless platform designed for static sites and serverless APIs. This repository includes a pre-configured Vercel static deployment (`vercel.json`, `.vercelignore`, and `public/index.html`):

1. Import this repository into **[Vercel](https://vercel.com/)**.
2. Leave all build settings at their defaults.
3. Vercel automatically deploys the **Interactive DPI Simulator Showcase** with zero configuration and zero build errors!

---

### Option 1: Interactive Streamlit Web Dashboard (Recommended)

Launch the modern web UI featuring guided scenario presets, interactive firewall rules, packet inspector tables, and flow charts:
```bash
streamlit run src/app.py
```
Open your browser at `http://localhost:8501`.

**Dashboard Features:**
- **Guided Experiment Scenarios**: One-click presets (e.g. *Office Productivity Mode*, *Cafe Social Restrictor*, *Strict Security Enforcer*).
- **Interactive Rule Builder**: Add or remove blocked applications, wildcard domains, and client IPs dynamically.
- **Deep Packet Inspector**: Searchable and filterable table displaying every packet, 5-tuple, protocol, SNI domain, and drop/forward verdict.
- **Live Visual Analytics**: Flow distribution charts, classification rates, and throughput metrics.

---

### Option 2: Multi-Threaded DPI Engine (CLI)

Run the high-performance multi-threaded engine orchestrating Load Balancer (LB) and Fast Path (FP) worker queues:

**Default run (Inspect and forward all):**
```bash
python src/main_dpi.py test_dpi.pcap output.pcap
```

**Block targeted applications:**
```bash
python src/main_dpi.py test_dpi.pcap output.pcap --block-app YouTube --block-app TikTok
```

**Block specific source IPs and wildcard domains:**
```bash
python src/main_dpi.py test_dpi.pcap output.pcap --block-ip 192.168.1.50 --block-domain "*.google.com"
```

**Customize threading concurrency:**
```bash
python src/main_dpi.py test_dpi.pcap output.pcap --lbs 4 --fps 4
# Creates 4 LB threads × 4 FP threads = 16 processing threads
```

---

### Option 3: Detailed Packet & Flow Inspector (CLI)

Run the single-pass detailed inspector with per-packet SNI, HTTP Host, and bidirectional flow accounting:
```bash
python src/main_working.py test_dpi.pcap
```

---

### Generating Synthetic Test PCAP Data

If you don't have a pre-recorded network capture, generate a test capture containing diverse TLS/HTTPS, DNS, and HTTP traffic:
```bash
python generate_test_pcap.py
# Outputs: test_dpi.pcap (77 realistic packets)
```

---

## Sample Execution Output

```text
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked app: TikTok
[Rules] Blocked domain: *.google.com
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets
[FP3] BLOCKED packet: Type.DOMAIN www.google.com
[FP1] BLOCKED packet: Type.APP YouTube (SNI: www.youtube.com)
[DPIEngine] All worker threads terminated cleanly.

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                5738                              ║
║ TCP Packets:                  73                              ║
║ UDP Packets:                   4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    71                              ║
║ Dropped/Blocked:               6                              ║
║ Drop Rate:                  7.79%                             ║
╠══════════════════════════════════════════════════════════════╣
║ Total Connections:            27                              ║
║ Classified Flows:             16 ( 59.3%)                     ║
╚══════════════════════════════════════════════════════════════╝
```
