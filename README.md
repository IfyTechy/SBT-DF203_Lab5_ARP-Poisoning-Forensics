# SBT-DF203-Lab5: ARP Analysis and Anomaly Detection Using TShark/Wireshark

A formal digital forensics investigation analyzing Address Resolution Protocol (ARP) packet captures (`.pcap`/`.pcapng`) to establish operational baselines, extract protocol fields, map IP-to-MAC claims, and construct packet timelines for detection analysis.

---

## 📌 Investigation Overview

- **Lead Examiner:** Nebeuwa Ifeanyichukwu Raphael
- **Course & Lab:** SBT-DF203 — Basic Networking Skills for Digital Forensics (Lab 5)
- **Primary Tools:** `tshark`, `wireshark`, `arping`, `ip`, `sha256sum`
- **Environment:** Kali Linux (`192.168.190.129/24`) and Windows 10 (`192.168.190.128/24`) in an isolated VMware Host-Only network (`192.168.190.0/24`)

### Key Analytical Findings
- **Evidence Integrity:** The original capture (`evidence/arp.pcap`) and working copy (`working/arp_working.pcap`) were verified via SHA-256 (`342a75dc002d090cc7fd108994b6c0c9c8eaa3962cf642159b4507d5615adc3e`).
- **Layer-2 Reachability:** Confirmed Layer-2 ARP resolution via `arping` (3/3 replies from `00:0c:29:77:f3:67`), demonstrating reachability even when ICMP Echo requests were dropped.
- **Protocol Analysis:** Evaluated eight ARP frames. Extracted legitimate request/reply pairs (`136.160.215.15` ↔ `136.160.215.194`).
- **Detection Verdict:** Analysis of the supplied PCAP showed unique, stable IP-to-MAC claims without unsolicited replies or conflicting mappings; no ARP poisoning was detected in the evidence.

---

## 📁 Repository Structure

```text
SBT-DF203-Lab5/
├── evidence/
│   ├── arp.pcap                    # Preserved original ARP capture
│   ├── normal_arp.pcapng           # Baseline normal ARP resolution capture
│   └── partD_arp_simulation.pcapng # Simulation setup artifact
├── working/
│   └── arp_working.pcap            # Verified working copy for analysis
├── reports/
│   ├── arp_capture_hashes.txt      # Cryptographic SHA-256 evidence log
│   ├── normal_arp_fields.tsv       # TShark field extraction from baseline capture
│   ├── arp_replies.tsv             # Extracted ARP reply frames (Opcode 2)
│   ├── ip_mac_claims.txt           # IP-to-MAC mapping summary
│   ├── full_arp_timeline.tsv       # Complete 8-frame packet timeline
│   ├── unicast_arp_replies.tsv     # Unicast ARP reply breakdown
│   ├── arp_table_initial.txt       # Initial neighbor state record
│   └── arp_table_after_ping.txt    # Post-reachability test neighbor state
└── README.md
```

## ⚙️ Execution & Methodology

**1. Evidence Acquisition & Integrity Verification**

Isolate original evidence and generate SHA-256 digests to ensure chain-of-custody compliance:

```bash
mkdir -p ~/SBT-DF203-Lab5/{evidence,working,reports,scripts}
cd ~/SBT-DF203-Lab5

# Create working analysis copy preserving timestamps
cp --preserve=timestamps evidence/arp.pcap working/arp_working.pcap

# Calculate & log cryptographic hashes
sha256sum evidence/arp.pcap working/arp_working.pcap | tee reports/arp_capture_hashes.txt
```

Verification: Confirm both files output `342a75dc002d090cc7fd108994b6c0c9c8eaa3962cf642159b4507d5615adc3e.`

**2. Environment Verification & Layer-2 Testing**
   
Verify IP interfaces and perform direct Layer-2 ARP ping tests:

```bash
# Check interface and route configurations
ip -br address
ip route
ip neigh show | tee reports/arp_table_initial.txt

# Direct ARP reachability check (bypass ICMP filter)
sudo arping -I eth0 -c 3 192.168.190.128
```

**3. Baseline ARP Field Extraction**

Extract key protocol fields from the baseline capture to identify standard operational behavior:

```Bash
tshark -r evidence/normal_arp.pcapng -Y 'arp' -T fields \
  -e frame.number -e frame.time -e eth.src -e eth.dst -e arp.opcode \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
  | tee reports/normal_arp_fields.tsv
```

**4. ARP Reply Extraction & IP-to-MAC Mapping**

Isolate ARP reply frames (Opcode 2) and extract unique IP-to-MAC claims:

```Bash
# Extract all ARP reply frames
tshark -r working/arp_working.pcap -Y 'arp.opcode==2' -T fields \
  -e frame.number -e frame.time_epoch -e eth.src -e eth.dst \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
  | tee reports/arp_replies.tsv

# Summarize unique IP-to-MAC claims
tshark -r working/arp_working.pcap -Y 'arp.opcode==2' -T fields \
  -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  | sort | uniq -c | sort -nr | tee reports/ip_mac_claims.txt
```

**5. Full ARP Timeline & Anomaly Detection**

Construct an end-to-end ARP packet timeline to verify request/reply pairing and detect anomalies:

```Bash
tshark -r working/arp_working.pcap -Y 'arp' -T fields \
  -e frame.number -e arp.opcode -e arp.src.proto_ipv4 -e arp.src.hw_mac \
  -e arp.dst.proto_ipv4 -e arp.dst.hw_mac \
  | column -t | tee reports/full_arp_timeline.tsv
```

## 🔒 Forensic & Anomaly Analysis Summary

| Anomaly Indicator | Observed Evidence | Forensic Interpretation |
| -------- | -------- | -------- | 
|IP-to-MAC Mapping Change | `136.160.215.15` → `00:50:56:86:cb:fc136.160.215.194` → `00:50:56:86:02:65Normal:` | No conflicting MAC claims observed. |
| Unsolicited Replies | Reply frames 4 and 6 directly follow request frames 3 and 5. | Normal: All replies are solicited by legitimate requests.|
| Dual-Claim MAC | No single MAC address claimed multiple IP addresses. |	Normal: No Man-in-the-Middle/Spoofing signature found. |

## ⚠️ Limitations & Notes 

**1.Simulation Status:** Part D (controlled ARP poisoning simulation) was omitted as the required arp.py script was not present in the lab environment. No external attack scripts were introduced to preserve procedural integrity.

**2. ICMP Reachability:** ICMP Echo requests were blocked by default VM host settings; Layer-2 reachability was independently verified via arping.














