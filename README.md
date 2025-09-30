# Qt IDS

![language](https://img.shields.io/badge/language-C%2FC%2B%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-Qt6%2C_libpcap%2C_nlohmann%2Fjson%2C_CMake-blue)
![OS](https://img.shields.io/badge/OS-MacOS%2C%20Linux-blue)
[![getting started](https://img.shields.io/badge/available-features-blue)](#-Features)
[![Free](https://img.shields.io/badge/MIT-license-black)](https://github.com/daniltaro/Qt_IDS/blob/readme/LICENSE)

## Navigation
- [About](#about)
- [Features](#features)
- [Usage](#usage)
- [How to build](#how-to-build)
- [Notes](#notes)
- [License](https://github.com/daniltaro/Qt_IDS/blob/readme/LICENSE)

## About

A security tool written in C++ that monitors network traffic and system activity for malicious behavior.  
>This is an improved UI version of my previous project ([sniffer-packet-analyzer](https://github.com/daniltaro/sniffer-packet-analyzer)),  
>which I created for training and studying how networks work.

## Features

- [Parses payloads](#parsing-payload)
- [Supports TCP, UDP, and ICMP protocols](#protocols)
- [Saves captured packets to JSON files](#save-in-JSON)
- [Displays captured packets](#packets)
- [Allows packet filtering](#filters-packets)

## Usage

1. Run the program.
2. Select the protocols and the network interface to scan.
3. Press the **Start** button (or double-click the interface) to begin capturing packets.
4. Click on a packet to view its payload.
5. Press **Back** to return to the main window.
6. Press **Save JSON** to export the data.
7. Press **Stop** to end packet capturing.
8. Filter captured packets by entering keywords.

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

2. Create a build directory and compile:

```bash
mkdir build && cd build
cmake ..
# Use your preferred generator
```

## Notes

- Make sure `libpcap` and `nlohmann_json` are installed.
- Only **Ethernet** and **Loopback** link types are supported.

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
