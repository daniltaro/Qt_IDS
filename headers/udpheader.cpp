#include "udpheader.h"

#include <arpa/inet.h>
#include <cstring>

static_assert(sizeof(UDPHeader) == UDPHeader::SIZE, "UDPHeader must match the wire layout");

bool UDPHeader::parse(const uint8_t *data, std::size_t len, UDPHeader &out) {
    if (data == nullptr || len < SIZE) return false;
    std::memcpy(&out, data, SIZE);
    return true;
}

uint16_t UDPHeader::getSrcPort() const {
    return ntohs(srcPort);
}

uint16_t UDPHeader::getDstPort() const {
    return ntohs(dstPort);
}
