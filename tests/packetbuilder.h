#ifndef PACKETBUILDER_H
#define PACKETBUILDER_H

#include <arpa/inet.h>
#include <pcap.h>
#include <sys/socket.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

// Builds raw packets byte by byte, the way they come out of pcap.
namespace packet {

using Bytes = std::vector<uint8_t>;
using Address = std::array<uint8_t, 4>;

inline void put16(Bytes &out, uint16_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value & 0xFF));
}

inline Bytes concat(Bytes head, const Bytes &tail) {
    head.insert(head.end(), tail.begin(), tail.end());
    return head;
}

inline Bytes bytes(const char *text) {
    return Bytes(text, text + std::strlen(text));
}

inline Bytes tcp(uint16_t srcPort, uint16_t dstPort, uint8_t flags, const Bytes &payload = {}) {
    Bytes out;
    put16(out, srcPort);
    put16(out, dstPort);
    out.insert(out.end(), 8, 0); // seq, ack
    out.push_back(0x50);         // data offset: 5 words
    out.push_back(flags);
    put16(out, 0xFFFF);          // window
    out.insert(out.end(), 4, 0); // checksum, urgent pointer
    return concat(out, payload);
}

inline Bytes udp(uint16_t srcPort, uint16_t dstPort, const Bytes &payload = {}) {
    Bytes out;
    put16(out, srcPort);
    put16(out, dstPort);
    put16(out, static_cast<uint16_t>(8 + payload.size()));
    put16(out, 0);
    return concat(out, payload);
}

// body is everything after type, code and checksum: rest-of-header and data
inline Bytes icmp(uint8_t type, uint8_t code, const Bytes &body = {}) {
    return concat(Bytes{type, code, 0, 0}, body);
}

inline Bytes ipv4(uint8_t protocol, const Bytes &payload,
                  Address src = {10, 0, 0, 1}, Address dst = {10, 0, 0, 2},
                  uint16_t fragment = 0) {
    Bytes out{0x45, 0};
    put16(out, static_cast<uint16_t>(20 + payload.size()));
    put16(out, 0);        // id
    put16(out, fragment); // flags and fragment offset
    out.push_back(64);    // ttl
    out.push_back(protocol);
    put16(out, 0);        // checksum
    out.insert(out.end(), src.begin(), src.end());
    out.insert(out.end(), dst.begin(), dst.end());
    return concat(out, payload);
}

inline Bytes ethernet(const Bytes &payload, uint16_t etherType = 0x0800) {
    Bytes out(12, 0);
    put16(out, etherType);
    return concat(out, payload);
}

// DLT_NULL keeps the address family in host byte order, DLT_LOOP in network byte order
inline Bytes loopback(const Bytes &payload, uint32_t family, bool networkOrder = false) {
    if (networkOrder) family = htonl(family);
    Bytes out(sizeof(family));
    std::memcpy(out.data(), &family, sizeof(family));
    return concat(out, payload);
}

inline pcap_pkthdr header(const Bytes &data, long seconds = 1000, int micros = 0) {
    pcap_pkthdr h{};
    h.ts.tv_sec = seconds;
    h.ts.tv_usec = micros;
    h.caplen = static_cast<bpf_u_int32>(data.size());
    h.len = h.caplen;
    return h;
}

}

#endif // PACKETBUILDER_H
