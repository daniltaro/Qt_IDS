![language](https://img.shields.io/badge/language-C%2FC%2B%2B-blue)
![dependencies](https://img.shields.io/badge/dependencies-Qt6%2C_libpcap%2C_nlohmann%2Fjson%2C_CMake-blue)
![OS](https://img.shields.io/badge/OS-MacOS%2C%20Linux-blue)
[![getting started](https://img.shields.io/badge/available-features-blue)](#-Features)
[![Free](https://img.shields.io/badge/MIT-license-black)](ДОПИШИ)

## Navigation
- [About](#-About)
- [Features](#-Features)
- [Usage](#-Usage)
- [How to build](#-How-to-build)
- [License](https://github.com/daniltaro/ДОПИШИ)

## About
A security tool that monitors network traffic and system activities for malicious activity written in C++.
>This is an improved UI version of my previous project ([sniffer-packet-analyzer](https://github.com/daniltaro/sniffer-packet-analyzer)),
>which I made for the purpose of training and studying the work of networks.


## Features

- [Parsing payload](#-Parsing-payload)
- [Supports TCP, UDP, ICMP protocols](#-Protocols)
- [Saves captured packets to JSON files](#-Save-in-JSON)
- [Shows captured packets](#-Packets)
- [Filters packets](#-Filters-packets)

## Usage

1. Run the program.
2. Choose protocols and your network interface for scan.
3. Press button "Start" or your device two times for packet captuering.
4. Сlick on the package to see it's payload.
5. Press "Back" to back to the main window.
6. Press "Save json" to save data in json format.
7. Press "Stop" to stop captuering.
8. Filter captured packets by writting key words.

## How to build
### dependencies
To build this project, you need to have the following dependencies installed:

- [Qt](https://www.qt.io/download-dev) not less than 6 version
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
USE YOUR GENERATOR
```
---
### Parsing payload
### Protocols
### Save in JSON
### Packets
### Filters packets
---

## Notes

- Ensure libpcap and nlohmann_json are installed.
- Only Ethernet and Loopback link types are supported.
