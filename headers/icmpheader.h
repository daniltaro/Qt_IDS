#ifndef ICMPHEADER_H
#define ICMPHEADER_H

#include <cstddef>
#include <cstdint>

class ICMPHeader {
    uint8_t type = 0;
    uint8_t code = 0;
    uint16_t checksum = 0;

public:
    // type, code and checksum: the part every ICMP message has
    static constexpr std::size_t MIN_SIZE = 4;

    static bool parse(const uint8_t *data, std::size_t len, ICMPHeader &out);

    uint8_t getType() const;
    uint8_t getCode() const;

    // full header length for this message type, the payload starts after it
    std::size_t headerLength() const;
};

#endif //ICMPHEADER_H
