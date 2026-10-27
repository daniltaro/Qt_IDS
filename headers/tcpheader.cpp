#include "tcpheader.h"

#include <arpa/inet.h>
#include <cstring>

static_assert(sizeof(TCPHeader) == TCPHeader::MIN_SIZE, "TCPHeader must match the wire layout");

bool TCPHeader::parse(const uint8_t *data, std::size_t len, TCPHeader &out) {
    if (data == nullptr || len < MIN_SIZE) return false;
    std::memcpy(&out, data, MIN_SIZE);
    return out.headerLength() >= MIN_SIZE && out.headerLength() <= len;
}

std::size_t TCPHeader::headerLength() const {
    return static_cast<std::size_t>(dataOffsetReserved >> 4) * 4;
}

uint16_t TCPHeader::getSrcPort() const {
    return ntohs(srcPort);
}

uint16_t TCPHeader::getDstPort() const {
    return ntohs(dstPort);
}

uint8_t TCPHeader::getFlag() const {
    return flag;
}
