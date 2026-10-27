#include "ipv4header.h"

#include <arpa/inet.h>
#include <cstring>

static_assert(sizeof(Ipv4Header) == Ipv4Header::MIN_SIZE, "Ipv4Header must match the wire layout");

namespace {
std::string ipToString(const uint8_t ip[4]) {
    return std::to_string(ip[0]) + "." +
           std::to_string(ip[1]) + "." +
           std::to_string(ip[2]) + "." +
           std::to_string(ip[3]);
}
}

bool Ipv4Header::parse(const uint8_t *data, std::size_t len, Ipv4Header &out) {
    if (data == nullptr || len < MIN_SIZE) return false;
    std::memcpy(&out, data, MIN_SIZE);

    if ((out.versionIHL >> 4) != 4) return false;
    return out.headerLength() >= MIN_SIZE && out.headerLength() <= len;
}

uint8_t Ipv4Header::protocolType() const {
    return protocol;
}

std::size_t Ipv4Header::headerLength() const {
    return static_cast<std::size_t>(versionIHL & 0x0F) * 4;
}

std::size_t Ipv4Header::totalLength() const {
    return ntohs(totalLen);
}

bool Ipv4Header::isLaterFragment() const {
    return (ntohs(fragOffset) & 0x1FFF) != 0;
}

std::string Ipv4Header::getSrcIP() const {
    return ipToString(srcIP);
}

std::string Ipv4Header::getDstIP() const {
    return ipToString(dstIP);
}
