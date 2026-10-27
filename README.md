# Qt IDS

![language](https://img.shields.io/badge/language-C%2FC%2B%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-Qt6%2C_libpcap%2C_nlohmann%2Fjson%2C_CMake-blue)
![OS](https://img.shields.io/badge/OS-MacOS%2C%20Linux-blue)
[![getting started](https://img.shields.io/badge/available-features-blue)](#-Features)
[![Free](https://img.shields.io/badge/MIT-license-black)](LICENSE)

## Navigation
- [About](#about)
- [Features](#features)
- [Usage](#usage)
- [How to build](#how-to-build)
- [Notes](#notes)
- [License](LICENSE)

## About

A security tool written in C++ that monitors IPv4 network traffic for floods and port scans.  
>This is an improved UI version of my previous project ([sniffer-packet-analyzer](https://github.com/daniltaro/sniffer-packet-analyzer)),  
>which I created for training and studying how networks work.

## Features

- [Parses payloads](#parsing-payload)
- [Supports TCP, UDP, and ICMP protocols](#protocols)
- [Saves captured packets to JSON files](#save-in-JSON)
- [Displays captured packets](#packets)
- [Allows packet filtering](#filters-packets)
- Detects ICMP / SYN / UDP floods and TCP / UDP port scans

## Usage

1. Run the program.
2. Select the protocols and the network interface to scan.
3. Press the **Start** button (or double-click the interface) to begin capturing packets.
4. Click on a packet to view its payload.
5. Press **Stop** to end packet capturing.
6. Filter captured packets by entering keywords and/or **Show only threats**.
7. Press **Save json** to export the data.
8. Press **Back** to return to the main window.

Capturing needs access to the network devices: run the program as root
or, on macOS, give your user read access to `/dev/bpf*`
(for example with the ChmodBPF script that ships with Wireshark).

## How to build

### Dependencies

To build this project, you need to have the following dependencies installed:

- [Qt](https://www.qt.io/download-dev) (version 6 or higher)
- [libpcap](https://github.com/the-tcpdump-group/libpcap)
- [nlohmann_json](https://github.com/nlohmann/json)

1. Clone the repository:

```bash
git clone https://github.com/daniltaro/Qt_IDS.git
cd Qt_IDS
```

2. Configure and build:

```bash
cmake -S . -B build
cmake --build build
```

3. Run the tests (optional, disable them with `-DQT_IDS_BUILD_TESTS=OFF`):

```bash
ctest --test-dir build --output-on-failure
```

## Notes

- Make sure `libpcap` and `nlohmann_json` are installed.
- Only **Ethernet** and **Loopback** link types are supported.
- Only IPv4 is analysed, IPv6 packets are skipped.
- Threat detection works in 5-second windows per host:
  - ICMP flood: more than 20 echo requests to one host;
  - SYN flood: more than 20 SYNs to one host with less than 20% of them followed by ACKs;
  - UDP flood: more than 5000 packets to one host;
  - port scan: one source probing more than 100 ports of one host
    (TCP counts only connection attempts, UDP ignores replies from well-known ports).
- The packet table keeps the last 20000 packets; the JSON export contains all of them.

---

### Parsing payload

<p align="center">
<img width="600"   src="https://github.com/daniltaro/Qt_IDS/blob/readme/pars.png">
</p>

### Protocols

<p align="center">
<img height="500"   src="https://github.com/daniltaro/Qt_IDS/blob/readme/prot.png">
</p>

### Save in JSON

<p align="center">
<img width="600"   src="https://github.com/daniltaro/Qt_IDS/blob/readme/sav.png">
</p>

### Packets

<p align="center">
<img width="600"   src="https://github.com/daniltaro/Qt_IDS/blob/readme/pack.png">
</p>

### Filters packets

<p align="center">
<img width="600"   src="https://github.com/daniltaro/Qt_IDS/blob/readme/filt.png">
</p>

---
