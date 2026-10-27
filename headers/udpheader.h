#ifndef UDPHEADER_H
#define UDPHEADER_H

#include <cstddef>
#include <cstdint>

class UDPHeader {
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;
    uint16_t len = 0;
    uint16_t checksum = 0;

public:
    static constexpr std::size_t SIZE = 8;

    static bool parse(const uint8_t *data, std::size_t len, UDPHeader &out);

    uint16_t getSrcPort() const;
    uint16_t getDstPort() const;
};

#endif //UDPHEADER_H
