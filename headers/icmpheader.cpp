#include "icmpheader.h"

#include <cstring>

static_assert(sizeof(ICMPHeader) == ICMPHeader::MIN_SIZE, "ICMPHeader must match the wire layout");

bool ICMPHeader::parse(const uint8_t *data, std::size_t len, ICMPHeader &out) {
    if (data == nullptr || len < MIN_SIZE) return false;
    std::memcpy(&out, data, MIN_SIZE);
    return true;
}

uint8_t ICMPHeader::getType() const {
    return type;
}

uint8_t ICMPHeader::getCode() const {
    return code;
}

std::size_t ICMPHeader::headerLength() const {
    switch (type) {
    case 13: // timestamp
    case 14: // timestamp reply
        return 20;
    case 17: // address mask request
    case 18: // address mask reply
        return 12;
    default: // echo, unreachable, time exceeded, redirect...: 4 bytes of rest-of-header
        return 8;
    }
}
