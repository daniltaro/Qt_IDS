#include "threatdetector.h"

namespace {
constexpr uint8_t ICMP_ECHO_REQUEST = 8;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_ACK = 0x10;
constexpr uint16_t FIRST_UNPRIVILEGED_PORT = 1024;
}

threatDetector::Timestamp threatDetector::toTimestamp(const timeval &tv) {
    return std::chrono::seconds(tv.tv_sec) + std::chrono::microseconds(tv.tv_usec);
}

std::string threatDetector::inspectICMP(const std::string &dstIP, uint8_t type, Timestamp ts) {
    dropExpired(ts);
    std::string labels;
    if (type != ICMP_ECHO_REQUEST) return labels;

    Window &flood = window(icmpFlood, dstIP, ts);
    if (++flood.packets > ICMP_FLOOD_THRESHOLD) report(flood, labels, "[ICMP FLOOD]");
    return labels;
}

std::string threatDetector::inspectTCP(const std::string &srcIP, const std::string &dstIP,
                                       uint16_t dstPort, uint8_t flags, Timestamp ts) {
    dropExpired(ts);
    std::string labels;

    // SYN-ACK is a server reply: neither a new connection attempt nor a completed handshake
    const bool syn = (flags & TCP_SYN) && !(flags & TCP_ACK);
    const bool ack = (flags & TCP_ACK) && !(flags & TCP_SYN);

    if (ack) window(synFlood, dstIP, ts).acks++;
    if (!syn) return labels;

    Window &flood = window(synFlood, dstIP, ts);
    flood.packets++;
    if (flood.packets > SYN_FLOOD_THRESHOLD && flood.acks < SYN_ACK_RATIO * flood.packets) {
        report(flood, labels, "[SYN FLOOD]");
    }

    // only connection attempts count: replies to our own connections arrive on many random ports
    Window &scan = window(tcpScan, srcIP + " -> " + dstIP, ts);
    scan.ports.insert(dstPort);
    if (scan.ports.size() > PORT_SCAN_THRESHOLD) report(scan, labels, "[TCP PORT SCANNING]");

    return labels;
}

std::string threatDetector::inspectUDP(const std::string &srcIP, const std::string &dstIP,
                                       uint16_t srcPort, uint16_t dstPort, Timestamp ts) {
    dropExpired(ts);
    std::string labels;

    Window &flood = window(udpFlood, dstIP, ts);
    if (++flood.packets > UDP_FLOOD_THRESHOLD) report(flood, labels, "[UDP FLOOD]");

    // replies from well-known services (DNS, NTP...) go to random ephemeral ports, that is not a scan
    const bool reply = srcPort < FIRST_UNPRIVILEGED_PORT && dstPort >= FIRST_UNPRIVILEGED_PORT;
    if (reply) return labels;

    Window &scan = window(udpScan, srcIP + " -> " + dstIP, ts);
    scan.ports.insert(dstPort);
    if (scan.ports.size() > PORT_SCAN_THRESHOLD) report(scan, labels, "[UDP PORT SCANNING]");

    return labels;
}

int threatDetector::getThreatCount() const {
    return threatCount;
}

threatDetector::Window &threatDetector::window(WindowMap &map, const std::string &key, Timestamp ts) {
    auto [it, inserted] = map.try_emplace(key);
    if (inserted || ts - it->second.start >= WINDOW) it->second = Window{ts};
    return it->second;
}

void threatDetector::report(Window &w, std::string &labels, const char *label) {
    if (!w.reported) {
        w.reported = true;
        threatCount++;
    }
    if (!labels.empty()) labels += ' ';
    labels += label;
}

void threatDetector::dropExpired(Timestamp ts) {
    if (ts - lastCleanup < WINDOW) return;
    lastCleanup = ts;

    for (WindowMap *map : {&icmpFlood, &synFlood, &udpFlood, &tcpScan, &udpScan}) {
        for (auto it = map->begin(); it != map->end();) {
            if (ts - it->second.start >= WINDOW) it = map->erase(it);
            else ++it;
        }
    }
}
