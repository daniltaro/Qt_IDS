#include "ethernetheader.h"

#include <arpa/inet.h>
#include <cstring>

static_assert(sizeof(EthernetHeader) == EthernetHeader::SIZE, "EthernetHeader must match the wire layout");

bool EthernetHeader::parse(const uint8_t *data, std::size_t len, EthernetHeader &out) {
    if (data == nullptr || len < SIZE) return false;
    std::memcpy(&out, data, SIZE);
    return true;
}

uint16_t EthernetHeader::type() const {
    return ntohs(etherType);
}
